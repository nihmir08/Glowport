//! FTP and FTPS for the file manager: the same operations as for SFTP ([`glowport_net::files::Remote`]), with
//! the same shapes for entries and errors.
//!
//! A [`Remote`] holds one connection for commands (read, create, delete folders …). FTP can only carry
//! one transfer per connection; [`Remote::reader`] and [`Remote::writer`] therefore each sign in anew and
//! bring their own connection, which ends with the transfer.
//!
//! **Certificate:** if the system does not trust the certificate and no fingerprint is stored, setup ends
//! before signing in with [`Refusal::Certificate`]; the caller asks the user and connects again with
//! [`Connect::pin`]. The password never goes to a server whose certificate is neither trusted nor confirmed.
//!
//! Passive mode is used: the server opens no connection back to the user.

mod tls;

use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex as StdMutex},
    task::{Context, Poll},
    time::{Duration, UNIX_EPOCH},
};

use glowport_net::files::{Entry, FileError, Kind};
use suppaftp::{
    list::{ListParser, PosixPexQuery},
    tokio::{AsyncFtpStream, AsyncNoTlsStream, AsyncRustlsConnector, AsyncRustlsFtpStream, AsyncRustlsStream, TransferStream},
    types::FileType,
    FtpError, Mode, Status,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::Mutex,
    time::timeout,
};

pub use tls::Fingerprint;

pub const DEFAULT_PORT: u16 = 21;
pub const DEFAULT_IMPLICIT_PORT: u16 = 990;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// How often and at what interval another connection is attempted if the server refuses it because too
/// many are already open.
const EXTRA_TRIES: u32 = 6;
const EXTRA_WAIT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Security {
    /// The connection starts in the clear and switches to TLS before signing in (`AUTH TLS`).
    Explicit,
    /// TLS from the start, usually on port 990.
    Implicit,
    /// Unencrypted: password and files are readable along the way.
    None,
}

#[derive(Clone)]
pub struct Connect {
    pub host: String,
    pub port: u16,
    /// Leer meldet anonym an.
    pub user: String,
    pub password: String,
    pub security: Security,
    /// The fingerprint the user confirmed for this server.
    pub pin: Option<Fingerprint>,
}

impl std::fmt::Debug for Connect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Without the password.
        write!(f, "Connect({}@{}:{}, {:?})", self.user, self.host, self.port, self.security)
    }
}

/// Why no connection was established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    Offline(String),
    /// The server cannot or will not do TLS.
    NoTls(String),
    /// The system does not trust the certificate, and none is stored. No sign-in happened.
    Certificate(Fingerprint),
    /// The certificate is not the one the user confirmed. No sign-in happened.
    CertificateChanged(Fingerprint),
    AuthFailed,
    Failed(String),
}

impl Refusal {
    /// Error code for the interface.
    pub fn code(&self) -> &'static str {
        match self {
            Refusal::Offline(_) => "offline",
            Refusal::NoTls(_) => "ftp_no_tls",
            Refusal::Certificate(_) | Refusal::CertificateChanged(_) => "certificate",
            Refusal::AuthFailed => "auth_failed",
            Refusal::Failed(_) => "ftp_failed",
        }
    }
}

/// The text of a server reply, without line ending.
fn said(body: &[u8]) -> String {
    String::from_utf8_lossy(body).trim().to_string()
}

fn file_error(error: FtpError) -> FileError {
    match error {
        FtpError::ConnectionError(error) => FileError::Lost(error.to_string()),
        FtpError::SecureError(text) => FileError::Lost(text),
        FtpError::UnexpectedResponse(response) => {
            let text = said(&response.body);
            let lower = text.to_lowercase();
            match response.status {
                Status::NotAvailable => FileError::Lost(text),
                Status::BadCommand | Status::NotImplemented | Status::NotImplementedParameter => FileError::Unsupported,
                Status::NotLoggedIn => FileError::PermissionDenied,
                // For “does not exist” and “not allowed” FTP has only one number; the text makes the difference.
                _ if lower.contains("no such") || lower.contains("not found") || lower.contains("does not exist") => FileError::NoSuchFile,
                _ if lower.contains("permission") || lower.contains("denied") || lower.contains("not allowed") => FileError::PermissionDenied,
                _ if lower.contains("exist") => FileError::Exists,
                _ if lower.contains("not a directory") => FileError::NotADirectory,
                _ => FileError::Failure(text),
            }
        }
        FtpError::DataConnectionAlreadyOpen => FileError::Failure("a transfer is still running".into()),
        other => FileError::Failure(other.to_string()),
    }
}

/// A signed-in connection, plain or over TLS. The library keeps both as separate types.
enum Client {
    Plain(AsyncFtpStream),
    Tls(AsyncRustlsFtpStream),
}

macro_rules! each {
    ($client:expr, $c:ident => $body:expr) => {
        match $client {
            Client::Plain($c) => $body,
            Client::Tls($c) => $body,
        }
    };
}

/// The data channel of a running transfer.
enum Data {
    Plain(TransferStream<AsyncNoTlsStream>),
    Tls(TransferStream<AsyncRustlsStream>),
}

impl Data {
    async fn finish(self) -> Result<(), FileError> {
        match self {
            Data::Plain(data) => data.finish().await,
            Data::Tls(data) => data.finish().await,
        }
        .map_err(file_error)
    }
}

impl Client {
    async fn retr(&mut self, path: &str, offset: u64) -> Result<Data, FileError> {
        if offset > 0 {
            each!(self, c => c.resume_transfer(offset as usize).await).map_err(file_error)?;
        }
        match self {
            Client::Plain(c) => c.retr_as_stream(path).await.map(Data::Plain),
            Client::Tls(c) => c.retr_as_stream(path).await.map(Data::Tls),
        }
        .map_err(file_error)
    }

    /// Opens a file for writing: new, appended (`append`) or from a position.
    async fn stor(&mut self, path: &str, offset: u64, append: bool) -> Result<Data, FileError> {
        if offset > 0 && !append {
            each!(self, c => c.resume_transfer(offset as usize).await).map_err(file_error)?;
        }
        match (self, append) {
            (Client::Plain(c), false) => c.put_with_stream(path).await.map(Data::Plain),
            (Client::Plain(c), true) => c.append_with_stream(path).await.map(Data::Plain),
            (Client::Tls(c), false) => c.put_with_stream(path).await.map(Data::Tls),
            (Client::Tls(c), true) => c.append_with_stream(path).await.map(Data::Tls),
        }
        .map_err(file_error)
    }

    async fn quit(mut self) {
        let _ = timeout(Duration::from_secs(3), async { each!(&mut self, c => c.quit().await) }).await;
    }
}

/// What the server can do, as far as the file manager is concerned.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Abilities {
    /// Folder listings in the standard form (`MLSD`); otherwise the output of `LIST`.
    pub mlsd: bool,
    /// Set modification time (`MFMT`).
    pub set_time: bool,
    /// A server connected without encryption would offer TLS.
    pub offers_tls: bool,
}

fn abilities(features: &HashMap<String, Option<String>>) -> Abilities {
    let has = |name: &str| features.keys().any(|key| key.eq_ignore_ascii_case(name));
    let auth_tls = features.iter().any(|(key, value)| key.eq_ignore_ascii_case("AUTH") && value.as_deref().is_some_and(|value| value.to_uppercase().contains("TLS")));
    Abilities { mlsd: has("MLSD") || has("MLST"), set_time: has("MFMT"), offers_tls: auth_tls }
}

async fn dial(connect: &Connect, seen: tls::Seen) -> Result<Client, Refusal> {
    let offline = |error: FtpError| Refusal::Offline(error.to_string());
    let address = match timeout(CONNECT_TIMEOUT, tokio::net::lookup_host((connect.host.as_str(), connect.port))).await {
        Ok(Ok(mut found)) => found.next().ok_or_else(|| Refusal::Offline("the name has no address".into()))?,
        Ok(Err(error)) => return Err(Refusal::Offline(error.to_string())),
        Err(_) => return Err(Refusal::Offline("timed out".into())),
    };
    if connect.security == Security::None {
        return AsyncFtpStream::connect_timeout(address, CONNECT_TIMEOUT).await.map(Client::Plain).map_err(offline);
    }
    let config = tls::config(seen.clone()).map_err(|error| Refusal::Failed(error.to_string()))?;
    let connector = AsyncRustlsConnector::from(tokio_rustls::TlsConnector::from(Arc::new(config)));
    let secured = match connect.security {
        Security::Implicit => match timeout(CONNECT_TIMEOUT, AsyncRustlsFtpStream::connect_secure_implicit(address, connector, &connect.host)).await {
            Ok(result) => result,
            Err(_) => return Err(Refusal::Offline("timed out".into())),
        },
        _ => {
            let plain = AsyncRustlsFtpStream::connect_timeout(address, CONNECT_TIMEOUT).await.map_err(offline)?;
            match timeout(CONNECT_TIMEOUT, plain.into_secure(connector, &connect.host)).await {
                Ok(result) => result,
                Err(_) => return Err(Refusal::Offline("timed out".into())),
            }
        }
    };
    match secured {
        Ok(client) => Ok(Client::Tls(client)),
        Err(FtpError::UnexpectedResponse(response)) => Err(Refusal::NoTls(said(&response.body))),
        Err(FtpError::ConnectionError(error)) => Err(Refusal::Offline(error.to_string())),
        Err(error) => Err(Refusal::NoTls(error.to_string())),
    }
}

/// Asks a server without signing in whether it offers TLS. No server, no answer, or a server that says nothing
/// about itself before sign-in: `false`.
pub async fn offers_tls(host: &str, port: u16) -> bool {
    let connect = Connect { host: host.to_string(), port, user: String::new(), password: String::new(), security: Security::None, pin: None };
    let Ok(mut client) = dial(&connect, Arc::new(StdMutex::new(None))).await else { return false };
    let features = timeout(CONNECT_TIMEOUT, async { each!(&mut client, c => c.feat().await) }).await.ok().and_then(Result::ok).unwrap_or_default();
    client.quit().await;
    abilities(&features).offers_tls
}

/// Establishes a connection, checks the certificate and signs in. `expect` names the certificate that already applies
/// (for a session's further connections); otherwise [`Connect::pin`] or the system decides.
async fn login(connect: &Connect, expect: Option<Fingerprint>) -> Result<(Client, Abilities, Option<Fingerprint>), Refusal> {
    let seen: tls::Seen = Arc::new(StdMutex::new(expect.map(|fingerprint| (fingerprint, true))));
    let mut client = dial(connect, seen.clone()).await?;
    let shown = *seen.lock().unwrap_or_else(|p| p.into_inner());
    // First the certificate, then the password.
    if let (Some((fingerprint, recognised)), None) = (shown, expect) {
        match connect.pin {
            Some(pin) if pin != fingerprint => return Err(Refusal::CertificateChanged(fingerprint)),
            Some(_) => {}
            None if recognised => {}
            None => return Err(Refusal::Certificate(fingerprint)),
        }
    }
    let (user, password) = if connect.user.is_empty() { ("anonymous", "anonymous@") } else { (connect.user.as_str(), connect.password.as_str()) };
    match each!(&mut client, c => c.login(user, password).await) {
        Ok(()) => {}
        Err(FtpError::UnexpectedResponse(response)) if matches!(response.status, Status::NotLoggedIn | Status::StoringNeedAccount) => return Err(Refusal::AuthFailed),
        Err(FtpError::ConnectionError(error)) => return Err(Refusal::Offline(error.to_string())),
        Err(error) => return Err(Refusal::Failed(error.to_string())),
    }
    let features = each!(&mut client, c => c.feat().await).unwrap_or_default();
    let has = |name: &str| features.keys().any(|key| key.eq_ignore_ascii_case(name));
    if has("UTF8") {
        let _ = each!(&mut client, c => c.custom_command("OPTS UTF8 ON", &[Status::CommandOk, Status::CommandNotImplemented]).await);
    }
    // The newer form of passive mode only names a port; the old one also names an address, which behind a
    // router is often the wrong one. Then the address the connection already goes to applies.
    let extended = has("EPSV");
    each!(&mut client, c => {
        c.set_mode(if extended { Mode::ExtendedPassive } else { Mode::Passive });
        c.set_passive_nat_workaround(true);
    });
    each!(&mut client, c => c.transfer_type(FileType::Binary).await).map_err(|error| Refusal::Failed(error.to_string()))?;
    Ok((client, abilities(&features), shown.map(|(fingerprint, _)| fingerprint)))
}

/// The folder something lives in, and its name there.
fn split(path: &str) -> (&str, &str) {
    let path = path.trim_end_matches('/');
    match path.rfind('/') {
        Some(0) => ("/", &path[1..]),
        Some(at) => (&path[..at], &path[at + 1..]),
        None => ("", path),
    }
}

fn join(dir: &str, name: &str) -> String {
    if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

fn entry(file: &suppaftp::list::File) -> Entry {
    let bit = |who, shift: u32| (u32::from(file.can_read(who)) << 2 | u32::from(file.can_write(who)) << 1 | u32::from(file.can_execute(who))) << shift;
    let number = |id: Option<u32>| id.map(|id| id.to_string()).unwrap_or_default();
    Entry {
        name: file.name().to_string(),
        kind: if file.is_directory() {
            Kind::Dir
        } else if file.is_symlink() {
            Kind::Link
        } else {
            Kind::File
        },
        size: file.size() as u64,
        modified: file.modified().duration_since(UNIX_EPOCH).map(|since| since.as_secs()).unwrap_or(0),
        mode: bit(PosixPexQuery::Owner, 6) | bit(PosixPexQuery::Group, 3) | bit(PosixPexQuery::Others, 0),
        uid: file.uid().unwrap_or(0),
        gid: file.gid().unwrap_or(0),
        owner: number(file.uid()),
        group: number(file.gid()),
        target: file.symlink().map(|target| target.to_string_lossy().replace('\\', "/")),
    }
}

/// Reads the lines of a folder listing, standardised (`MLSD`) or as `ls -l` or `dir` write them.
fn entries(lines: &[String], mlsd: bool) -> Vec<Entry> {
    let mut out = Vec::new();
    for line in lines {
        let parsed = if mlsd {
            let lower = line.to_ascii_lowercase();
            // The folder itself and the one above it are also in the listing.
            if lower.contains("type=cdir") || lower.contains("type=pdir") {
                continue;
            }
            ListParser::parse_mlsd(line)
        } else {
            ListParser::parse_posix(line).or_else(|_| ListParser::parse_dos(line))
        };
        if let Ok(file) = parsed {
            if !matches!(file.name(), "." | ".." | "") {
                out.push(entry(&file));
            }
        }
    }
    out
}

/// Does the server refuse another connection because too many are already open? The command connection is up
/// with the same credentials; a refused sign-in can therefore only mean that.
fn crowded(refusal: &Refusal) -> bool {
    match refusal {
        Refusal::AuthFailed => true,
        Refusal::Offline(text) | Refusal::Failed(text) => {
            let text = text.to_lowercase();
            text.contains("421") || text.contains("too many") || text.contains("maximum")
        }
        _ => false,
    }
}

pub struct Remote {
    connect: Connect,
    main: Mutex<Client>,
    abilities: Abilities,
    /// The certificate that applied at sign-in; every further connection must show the same.
    certificate: Option<Fingerprint>,
    home: String,
}

/// Runs something on the command connection. If the server has closed it in the meantime (FTP servers do that
/// after a few minutes of quiet), it signs in again and tries once more.
macro_rules! run {
    ($remote:expr, $client:ident => $body:expr) => {{
        let mut guard = $remote.main.lock().await;
        let first = {
            let $client = &mut *guard;
            $body
        };
        match first {
            Err(FileError::Lost(_)) => {
                *guard = $remote.again().await?;
                let $client = &mut *guard;
                $body
            }
            other => other,
        }
    }};
}

impl Remote {
    pub async fn connect(connect: &Connect) -> Result<Remote, Refusal> {
        let (mut client, abilities, certificate) = login(connect, None).await?;
        let home = each!(&mut client, c => c.pwd().await).unwrap_or_else(|_| "/".into());
        Ok(Remote { connect: connect.clone(), main: Mutex::new(client), abilities, certificate, home })
    }

    pub fn abilities(&self) -> Abilities {
        self.abilities
    }

    /// The server's certificate, if the connection runs over TLS.
    pub fn certificate(&self) -> Option<Fingerprint> {
        self.certificate
    }

    /// Another signed-in connection to the same server, with the same certificate.
    async fn again(&self) -> Result<Client, FileError> {
        let mut connect = self.connect.clone();
        connect.pin = self.certificate;
        login(&connect, self.certificate).await.map(|(client, _, _)| client).map_err(|refusal| FileError::Lost(format!("{refusal:?}")))
    }

    /// Another connection for a transfer. Many servers only allow a few per user or address at the
    /// same time. If the server refuses for that reason, it waits and tries again: so a queue that wants
    /// more at once than the server allows simply works through its files one after another.
    async fn extra(&self) -> Result<Client, FileError> {
        let mut connect = self.connect.clone();
        connect.pin = self.certificate;
        let mut tries = 1;
        loop {
            match login(&connect, self.certificate).await {
                Ok((client, _, _)) => return Ok(client),
                Err(refusal) if crowded(&refusal) && tries < EXTRA_TRIES => {
                    tries += 1;
                    tokio::time::sleep(EXTRA_WAIT).await;
                }
                Err(refusal) => return Err(FileError::Lost(format!("{refusal:?}"))),
            }
        }
    }

    /// The folder the server is in after signing in.
    pub async fn home(&self) -> Result<String, FileError> {
        Ok(self.home.clone())
    }

    pub async fn list(&self, path: &str) -> Result<Vec<Entry>, FileError> {
        let mlsd = self.abilities.mlsd;
        // First into the folder, then list without a name: some servers cannot cope with spaces in the name otherwise.
        run!(self, client => async {
            each!(&mut *client, c => c.cwd(path).await).map_err(|error| match file_error(error) {
                FileError::Failure(text) => if text.to_lowercase().contains("directory") { FileError::NotADirectory } else { FileError::NoSuchFile },
                other => other,
            })?;
            let lines = if mlsd {
                each!(&mut *client, c => c.mlsd(None).await)
            } else {
                // With `-a` the hidden ones too; whoever does not know it gets the ordinary listing.
                match each!(&mut *client, c => c.list(Some("-a")).await) {
                    Ok(lines) if !lines.is_empty() => Ok(lines),
                    _ => each!(&mut *client, c => c.list(None).await),
                }
            }
            .map_err(file_error)?;
            Ok(entries(&lines, mlsd))
        }.await)
    }

    /// `follow` does not exist with FTP: a link stays a link.
    pub async fn stat(&self, path: &str, _follow: bool) -> Result<Entry, FileError> {
        let (dir, name) = split(path);
        if name.is_empty() {
            return Ok(Entry { name: "/".into(), kind: Kind::Dir, size: 0, modified: 0, mode: 0o755, uid: 0, gid: 0, owner: String::new(), group: String::new(), target: None });
        }
        if self.abilities.mlsd {
            let line = run!(self, client => each!(&mut *client, c => c.mlst(Some(path)).await).map_err(file_error));
            if let Ok(file) = line.as_deref().map(str::trim).map(ListParser::parse_mlst).unwrap_or(Err(suppaftp::list::ParseError::SyntaxError)) {
                let mut found = entry(&file);
                found.name = name.to_string();
                return Ok(found);
            }
            if matches!(line, Err(FileError::NoSuchFile | FileError::PermissionDenied)) {
                return line.map(|_| unreachable!());
            }
        }
        self.list(if dir.is_empty() { "." } else { dir }).await?.into_iter().find(|entry| entry.name == name).ok_or(FileError::NoSuchFile)
    }

    pub async fn mkdir(&self, path: &str) -> Result<(), FileError> {
        run!(self, client => each!(&mut *client, c => c.mkdir(path).await).map_err(file_error))
    }

    /// Renames or moves. Never overwrites: many FTP servers would do that silently.
    pub async fn rename(&self, from: &str, to: &str) -> Result<(), FileError> {
        match self.stat(to, false).await {
            Ok(_) => return Err(FileError::Exists),
            Err(FileError::NoSuchFile) => {}
            Err(error) => return Err(error),
        }
        run!(self, client => each!(&mut *client, c => c.rename(from, to).await).map_err(file_error))
    }

    /// Deletes a file or a folder with its content. Links are deleted, not followed.
    pub fn remove<'a>(&'a self, path: &'a str) -> Pin<Box<dyn Future<Output = Result<(), FileError>> + Send + 'a>> {
        Box::pin(async move {
            if self.stat(path, false).await?.kind != Kind::Dir {
                return run!(self, client => each!(&mut *client, c => c.rm(path).await).map_err(file_error));
            }
            for child in self.list(path).await? {
                let inner = join(path, &child.name);
                if child.kind == Kind::Dir {
                    self.remove(&inner).await?;
                } else {
                    run!(self, client => each!(&mut *client, c => c.rm(&inner).await).map_err(file_error))?;
                }
            }
            run!(self, client => each!(&mut *client, c => c.rmdir(path).await).map_err(file_error))
        })
    }

    /// Sets the permissions if the server offers that (`SITE CHMOD`); otherwise [`FileError::Unsupported`].
    pub async fn chmod(&self, path: &str, mode: u32) -> Result<(), FileError> {
        let command = format!("CHMOD {:o} {path}", mode & 0o7777);
        run!(self, client => each!(&mut *client, c => c.site(&command).await).map(|_| ()).map_err(file_error)).map_err(|error| match error {
            FileError::Failure(text) if text.to_lowercase().contains("understood") || text.to_lowercase().contains("unknown") => FileError::Unsupported,
            other => other,
        })
    }

    /// Reads a file up to `limit` bytes; the second value says whether it is longer.
    pub async fn read(&self, path: &str, limit: u64) -> Result<(Vec<u8>, bool), FileError> {
        run!(self, client => async {
            let mut data = client.retr(path, 0).await?;
            let mut bytes = Vec::new();
            let read = match &mut data {
                Data::Plain(data) => data.take(limit + 1).read_to_end(&mut bytes).await,
                Data::Tls(data) => data.take(limit + 1).read_to_end(&mut bytes).await,
            };
            let longer = bytes.len() as u64 > limit;
            bytes.truncate(limit as usize);
            read.map_err(|error| FileError::Lost(error.to_string()))?;
            if longer {
                // Every server answers differently to stopping in the middle of a file. Instead of guessing its
                // answers, this connection ends here, and a fresh one takes its place.
                drop(data);
                *client = self.extra().await?;
            } else {
                data.finish().await?;
            }
            Ok((bytes, longer))
        }.await)
    }

    /// Writes a file anew.
    pub async fn write(&self, path: &str, bytes: &[u8]) -> Result<(), FileError> {
        run!(self, client => async {
            let mut data = client.stor(path, 0, false).await?;
            let written = match &mut data {
                Data::Plain(data) => data.write_all(bytes).await,
                Data::Tls(data) => data.write_all(bytes).await,
            };
            let finished = data.finish().await;
            written.map_err(|error| FileError::Lost(error.to_string()))?;
            finished
        }.await)
    }

    /// Opens a file for reading from position `offset`, on a connection of its own.
    pub async fn reader(&self, path: &str, offset: u64) -> Result<Transfer, FileError> {
        let mut client = self.extra().await?;
        // Some servers accept the order for a file that does not exist and only report that at the end.
        // Asking for the size settles it beforehand; whoever does not know it is not held up.
        if let Err(error @ (FileError::NoSuchFile | FileError::PermissionDenied)) = each!(&mut client, c => c.size(path).await).map_err(file_error) {
            client.quit().await;
            return Err(error);
        }
        match client.retr(path, offset).await {
            Ok(data) => Ok(Transfer::new(data, client)),
            Err(error) => {
                client.quit().await;
                Err(error)
            }
        }
    }

    /// Opens a file for writing, on a connection of its own. From `offset` 0 it starts anew; otherwise writing
    /// continues from there, e.g. to resume an interrupted upload. **The file is only finished after
    /// `shutdown`:** only then does the server confirm it.
    pub async fn writer(&self, path: &str, offset: u64) -> Result<Transfer, FileError> {
        let mut client = self.extra().await?;
        // If the server holds exactly as much as has already been written, it is appended; every server can do that.
        let append = offset > 0 && each!(&mut client, c => c.size(path).await).is_ok_and(|size| size as u64 == offset);
        match client.stor(path, offset, append).await {
            Ok(data) => Ok(Transfer::new(data, client)),
            Err(error) => {
                client.quit().await;
                Err(error)
            }
        }
    }

    /// Sets the modification time if the server offers that (`MFMT`); otherwise [`FileError::Unsupported`].
    pub async fn touch(&self, path: &str, modified: u64) -> Result<(), FileError> {
        if !self.abilities.set_time {
            return Err(FileError::Unsupported);
        }
        let command = format!("MFMT {} {path}", stamp(modified));
        run!(self, client => each!(&mut *client, c => c.custom_command(&command, &[Status::File]).await).map(|_| ()).map_err(file_error))
    }

    /// Keeps the connection awake; FTP servers otherwise close it after a few minutes of quiet.
    pub async fn ping(&self) -> Result<(), FileError> {
        run!(self, client => each!(&mut *client, c => c.noop().await).map_err(file_error))
    }

    pub async fn close(self) {
        self.main.into_inner().quit().await;
    }
}

/// A time as `YYYYMMDDHHMMSS` in UTC, as FTP writes it.
fn stamp(seconds: u64) -> String {
    let (days, rest) = (seconds / 86_400, seconds % 86_400);
    // Days since 1970 into a date; after Howard Hinnant, “days from civil” in reverse.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let (day, month) = (doy - (153 * mp + 2) / 5 + 1, if mp < 10 { mp + 3 } else { mp - 9 });
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}{month:02}{day:02}{:02}{:02}{:02}", rest / 3_600, rest % 3_600 / 60, rest % 60)
}

type Finishing = Pin<Box<dyn Future<Output = std::io::Result<()>> + Send>>;

// There is exactly one of these per transfer; moving the open connection out separately is not worth it.
#[allow(clippy::large_enum_variant)]
enum Stage {
    Open(Data, Client),
    Finishing(Finishing),
    Done,
}

/// A running transfer on its own connection. When reading it ends with the end of the file, when
/// writing with `shutdown`; both times it waits for the server's confirmation and then signs off. If
/// the server says the transfer failed, that is an error.
pub struct Transfer {
    stage: StdMutex<Stage>,
}

impl Transfer {
    fn new(data: Data, client: Client) -> Transfer {
        Transfer { stage: StdMutex::new(Stage::Open(data, client)) }
    }

    fn finish(stage: &mut Stage, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if let Stage::Open(..) = stage {
            let Stage::Open(data, client) = std::mem::replace(stage, Stage::Done) else { unreachable!() };
            *stage = Stage::Finishing(Box::pin(async move {
                let result = data.finish().await;
                client.quit().await;
                result.map_err(|error| std::io::Error::other(format!("{}: {}", error.code(), error.message())))
            }));
        }
        match stage {
            Stage::Finishing(finishing) => {
                let result = finishing.as_mut().poll(cx);
                if result.is_ready() {
                    *stage = Stage::Done;
                }
                result
            }
            _ => Poll::Ready(Ok(())),
        }
    }
}

impl AsyncRead for Transfer {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let mut stage = self.stage.lock().unwrap_or_else(|p| p.into_inner());
        if let Stage::Open(data, _) = &mut *stage {
            let before = buf.filled().len();
            let read = match data {
                Data::Plain(data) => Pin::new(data).poll_read(cx, buf),
                Data::Tls(data) => Pin::new(data).poll_read(cx, buf),
            };
            match read {
                Poll::Ready(Ok(())) if buf.filled().len() == before && buf.remaining() > 0 => {}
                other => return other,
            }
        }
        // At the end of the file: only the server's confirmation makes it a good end.
        Transfer::finish(&mut stage, cx)
    }
}

impl AsyncWrite for Transfer {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<std::io::Result<usize>> {
        match &mut *self.stage.lock().unwrap_or_else(|p| p.into_inner()) {
            Stage::Open(Data::Plain(data), _) => Pin::new(data).poll_write(cx, bytes),
            Stage::Open(Data::Tls(data), _) => Pin::new(data).poll_write(cx, bytes),
            _ => Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self.stage.lock().unwrap_or_else(|p| p.into_inner()) {
            Stage::Open(Data::Plain(data), _) => Pin::new(data).poll_flush(cx),
            Stage::Open(Data::Tls(data), _) => Pin::new(data).poll_flush(cx),
            _ => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Transfer::finish(&mut self.stage.lock().unwrap_or_else(|p| p.into_inner()), cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_split_into_folder_and_name() {
        assert_eq!(split("/home/tester/datei.txt"), ("/home/tester", "datei.txt"));
        assert_eq!(split("/datei.txt"), ("/", "datei.txt"));
        assert_eq!(split("/ordner/"), ("/", "ordner"));
        assert_eq!(split("datei.txt"), ("", "datei.txt"));
        assert_eq!(split("/"), ("", ""));
        assert_eq!(join("/", "a"), "/a");
        assert_eq!(join("/home", "a b"), "/home/a b");
    }

    #[test]
    fn times_are_written_the_way_ftp_wants_them() {
        assert_eq!(stamp(0), "19700101000000");
        assert_eq!(stamp(951_782_400), "20000229000000");
        assert_eq!(stamp(1_791_819_296), "20261012153456");
        assert_eq!(stamp(4_102_444_799), "20991231235959");
    }

    #[test]
    fn listings_are_read_in_all_three_shapes() {
        let lines = |text: &str| text.lines().map(str::to_string).collect::<Vec<_>>();
        // Standardised: the folder itself and the one above it are dropped.
        let found = entries(&lines("type=cdir;modify=20261012120000; .\ntype=pdir;modify=20261012120000; ..\ntype=dir;modify=20261012120000;UNIX.mode=0755; web\ntype=file;size=1234;modify=20200229000000;UNIX.mode=0640;UNIX.uid=1000;UNIX.gid=33; with spaces.txt"), true);
        assert_eq!(found.iter().map(|e| (e.name.as_str(), e.kind, e.size)).collect::<Vec<_>>(), [("web", Kind::Dir, 0), ("with spaces.txt", Kind::File, 1234)]);
        assert_eq!((found[1].modified, found[1].mode, found[1].uid, found[1].owner.as_str(), found[1].group.as_str()), (1_582_934_400, 0o640, 1000, "1000", "33"));
        // Like `ls -l`: the “total” line is dropped, a link names its target.
        let found = entries(&lines("total 12\ndrwxr-xr-x 2 1000 1000 4096 Jan 05 2025 .\ndrwxr-xr-x 2 1000 1000 4096 Jan 05 2025 logs\n-rw-r----- 1 1000 33 77 Jan 05 2025 seite.html\nlrwxrwxrwx 1 0 0 9 Jan 05 2025 aktuell -> /srv/v2"), false);
        assert_eq!(found.iter().map(|e| (e.name.as_str(), e.kind)).collect::<Vec<_>>(), [("logs", Kind::Dir), ("seite.html", Kind::File), ("aktuell", Kind::Link)]);
        assert_eq!((found[1].size, found[1].mode, found[2].target.as_deref()), (77, 0o640, Some("/srv/v2")));
        // Like `dir` on Windows.
        let found = entries(&lines("10-12-26  04:54PM       <DIR>          Bilder\n10-12-26  04:54PM                 2048 bericht.pdf"), false);
        assert_eq!(found.iter().map(|e| (e.name.as_str(), e.kind, e.size)).collect::<Vec<_>>(), [("Bilder", Kind::Dir, 0), ("bericht.pdf", Kind::File, 2048)]);
    }

    #[test]
    fn what_a_server_can_do_is_read_from_its_features() {
        let features = |pairs: &[(&str, Option<&str>)]| pairs.iter().map(|(key, value)| (key.to_string(), value.map(str::to_string))).collect::<HashMap<_, _>>();
        assert_eq!(abilities(&features(&[])), Abilities::default());
        assert_eq!(abilities(&features(&[("MLST", Some("type*;size*;modify*;")), ("MFMT", None), ("AUTH", Some("TLS"))])), Abilities { mlsd: true, set_time: true, offers_tls: true });
        assert_eq!(abilities(&features(&[("auth", Some("SSL")), ("EPSV", None)])), Abilities::default());
    }

    #[test]
    fn answers_of_the_server_become_the_errors_of_the_file_manager() {
        let answer = |status, text: &str| file_error(FtpError::UnexpectedResponse(suppaftp::types::Response { status, body: text.as_bytes().to_vec() }));
        assert_eq!(answer(Status::FileUnavailable, "550 No such file or directory.\r\n"), FileError::NoSuchFile);
        assert_eq!(answer(Status::FileUnavailable, "550 Permission denied.\r\n"), FileError::PermissionDenied);
        assert_eq!(answer(Status::FileUnavailable, "550 File exists\r\n"), FileError::Exists);
        assert_eq!(answer(Status::BadCommand, "500 What?\r\n"), FileError::Unsupported);
        assert_eq!(answer(Status::NotAvailable, "421 Timeout.\r\n"), FileError::Lost("421 Timeout.".into()));
        assert_eq!(answer(Status::ExceededStorage, "552 Quota exceeded\r\n"), FileError::Failure("552 Quota exceeded".into()));
        assert!(matches!(file_error(FtpError::ConnectionError(std::io::ErrorKind::ConnectionReset.into())), FileError::Lost(_)));
    }
}

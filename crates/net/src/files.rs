//! Dateien auf einem Server über SFTP: auflisten, anlegen, umbenennen, löschen, Rechte ändern, lesen, schreiben.
//!
//! Ein [`Remote`] hängt entweder an einer eigenen Verbindung ([`Remote::connect`]) oder an einem zusätzlichen
//! Kanal einer laufenden Sitzung ([`Remote::on`], siehe [`crate::Command::Open`]). Transfers bauen auf
//! [`Remote::reader`] und [`Remote::writer`] auf; die Warteschlange selbst gehört nicht in dieses Crate.

use std::{collections::HashMap, future::Future, pin::Pin, sync::Mutex};

use russh::{client, Channel, ChannelMsg, Disconnect};
use russh_sftp::client::{error::Error as SftpError, fs::File, SftpSession};
use russh_sftp::protocol::{FileAttributes, FileType, OpenFlags, StatusCode};
use tokio::{
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
    sync::mpsc,
    time::timeout,
};

use crate::{capture, closed_early, establish, lost, Command, Connect, End, Event, HostKey, Link, Output, Phase, Session, EXECUTE_TIMEOUT, MAX_EXECUTE_OUTPUT};

/// Ein zusätzlicher Kanal auf einer bestehenden Verbindung, für SFTP oder einen einzelnen Befehl.
pub struct Opened(pub(crate) Channel<client::Msg>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileError {
    NoSuchFile,
    PermissionDenied,
    /// Ein Ordner wurde erwartet.
    NotADirectory,
    /// Unter dem Namen gibt es schon etwas. Der Server selbst meldet das nicht eigens; wer es wissen will, prüft vorher.
    Exists,
    /// Der Server kann oder will das nicht (kein SFTP, Vorgang nicht unterstützt).
    Unsupported,
    /// Die Verbindung besteht nicht mehr.
    Lost(String),
    /// Alles andere, mit der Meldung des Servers.
    Failure(String),
}

impl FileError {
    /// Fehlercode für die Oberfläche.
    pub fn code(&self) -> &'static str {
        match self {
            FileError::NoSuchFile => "no_such_file",
            FileError::PermissionDenied => "permission_denied",
            FileError::NotADirectory => "not_a_directory",
            FileError::Exists => "file_exists",
            FileError::Unsupported => "not_supported",
            FileError::Lost(_) => "not_connected",
            FileError::Failure(_) => "file_failure",
        }
    }

    pub fn message(&self) -> &str {
        match self {
            FileError::Lost(message) | FileError::Failure(message) => message,
            _ => "",
        }
    }
}

impl From<SftpError> for FileError {
    fn from(error: SftpError) -> Self {
        match error {
            SftpError::Status(status) => match status.status_code {
                StatusCode::NoSuchFile => FileError::NoSuchFile,
                StatusCode::PermissionDenied => FileError::PermissionDenied,
                StatusCode::OpUnsupported => FileError::Unsupported,
                StatusCode::NoConnection | StatusCode::ConnectionLost => FileError::Lost(status.error_message),
                _ => FileError::Failure(status.error_message),
            },
            SftpError::Timeout => FileError::Lost("timed out".into()),
            other => FileError::Lost(other.to_string()),
        }
    }
}

impl From<std::io::Error> for FileError {
    fn from(error: std::io::Error) -> Self {
        match error.kind() {
            std::io::ErrorKind::NotFound => FileError::NoSuchFile,
            std::io::ErrorKind::PermissionDenied => FileError::PermissionDenied,
            _ => FileError::Failure(error.to_string()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Dir,
    File,
    Link,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub kind: Kind,
    pub size: u64,
    /// Letzte Änderung in Sekunden seit 1970.
    pub modified: u64,
    /// Rechte ohne die Art der Datei (0o755).
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    /// Name des Besitzers, soweit der Server ihn verrät; sonst die Nummer als Text.
    pub owner: String,
    pub group: String,
    /// Ziel einer Verknüpfung.
    pub target: Option<String>,
}

/// Was an Rechten und Besitz geändert werden soll. `None` lässt den Wert, wie er ist.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Change {
    pub mode: Option<u32>,
    /// Besitzer als Name oder Nummer.
    pub owner: Option<String>,
    pub group: Option<String>,
}

/// Namen zu den Nummern von Benutzern und Gruppen, gelesen aus `/etc/passwd` und `/etc/group`.
#[derive(Default)]
struct Names {
    users: HashMap<u32, String>,
    groups: HashMap<u32, String>,
}

pub struct Remote {
    sftp: SftpSession,
    names: Mutex<Option<std::sync::Arc<Names>>>,
    /// Die eigene Verbindung, falls dieses SFTP nicht an einer Sitzung hängt. Sie bleibt offen, solange es lebt.
    link: Option<Link>,
}

/// Größte Datei, deren Namenstabellen gelesen werden.
const MAX_NAMES: u64 = 512 * 1024;

fn join(dir: &str, name: &str) -> String {
    if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

fn only(permissions: Option<u32>, uid: Option<u32>, gid: Option<u32>, mtime: Option<u32>) -> FileAttributes {
    FileAttributes { size: None, uid, user: None, gid, group: None, permissions, atime: mtime, mtime }
}

impl Remote {
    /// Baut eine eigene Verbindung auf und öffnet SFTP darauf, ohne jede Rückfrage: `trusted` entscheidet über
    /// die Schlüssel der Server auf dem Weg, und reichen die hinterlegten Zugangsdaten nicht, scheitert es
    /// mit [`End::AuthFailed`].
    pub async fn connect(connect: &Connect, trusted: impl Fn(&str, u16, &HostKey) -> bool) -> Result<Remote, End> {
        let (event_tx, mut events) = mpsc::channel(16);
        let answers = async {
            while let Some(event) = events.recv().await {
                match event {
                    Event::HostKey { host, port, key, reply } => drop(reply.send(trusted(&host, port, &key))),
                    Event::Secret { reply, .. } => drop(reply.send(None)),
                    Event::Interactive { reply, .. } => drop(reply.send(None)),
                    _ => {}
                }
            }
        };
        let work = async {
            let link = establish(connect, &event_tx).await.map_err(|end| if end == End::User { End::AuthFailed } else { end })?;
            let channel = link.handle.channel_open_session().await.map_err(lost)?;
            let mut remote = Remote::on(Opened(channel)).await.map_err(|error| End::ConnectFailed(format!("sftp: {}", error.code())))?;
            remote.link = Some(link);
            Ok(remote)
        };
        tokio::select! {
            result = timeout(EXECUTE_TIMEOUT, work) => result.unwrap_or(Err(End::ConnectFailed("timed out".into()))),
            () = answers => Err(End::User),
        }
    }

    /// Öffnet SFTP auf einem zusätzlichen Kanal einer bestehenden Verbindung.
    pub async fn on(opened: Opened) -> Result<Remote, FileError> {
        let mut channel = opened.0;
        channel.request_subsystem(true, "sftp").await.map_err(|e| FileError::Lost(e.to_string()))?;
        // Erst die Antwort des Servers abwarten: Ohne SFTP käme sonst nur das Zeitlimit der ersten Anfrage.
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Success) => break,
                Some(ChannelMsg::Failure) => return Err(FileError::Unsupported),
                Some(_) => {}
                None => return Err(FileError::Lost("the connection was lost".into())),
            }
        }
        let sftp = SftpSession::new(channel.into_stream()).await.map_err(|_| FileError::Unsupported)?;
        Ok(Remote { sftp, names: Mutex::new(None), link: None })
    }

    /// Führt einen Befehl auf der eigenen Verbindung aus. Nur für ein [`Remote`] aus [`Remote::connect`].
    pub async fn run(&self, command: &str) -> Result<Output, FileError> {
        let link = self.link.as_ref().ok_or(FileError::Unsupported)?;
        let channel = link.handle.channel_open_session().await.map_err(|e| FileError::Lost(e.to_string()))?;
        run(Opened(channel), command).await
    }

    /// Heimatverzeichnis: der Ordner, in dem SFTP beginnt.
    pub async fn home(&self) -> Result<String, FileError> {
        Ok(self.sftp.canonicalize(".").await?)
    }

    /// Der Pfad ohne `.` und `..`, wie der Server ihn sieht.
    pub async fn resolve(&self, path: &str) -> Result<String, FileError> {
        Ok(self.sftp.canonicalize(path).await?)
    }

    async fn names(&self) -> std::sync::Arc<Names> {
        if let Some(names) = self.names.lock().ok().and_then(|cached| cached.clone()) {
            return names;
        }
        let table = |text: Vec<u8>| -> HashMap<u32, String> {
            String::from_utf8_lossy(&text)
                .lines()
                .filter_map(|line| {
                    let mut fields = line.split(':');
                    let name = fields.next()?;
                    Some((fields.nth(1)?.parse().ok()?, name.to_string()))
                })
                .collect()
        };
        let read = |path: &'static str| async move { self.read(path, MAX_NAMES).await.map(|(bytes, _)| bytes).unwrap_or_default() };
        let names = std::sync::Arc::new(Names { users: table(read("/etc/passwd").await), groups: table(read("/etc/group").await) });
        if let Ok(mut cached) = self.names.lock() {
            *cached = Some(names.clone());
        }
        names
    }

    fn entry(&self, name: String, attrs: &FileAttributes, names: &Names) -> Entry {
        let uid = attrs.uid.unwrap_or(0);
        let gid = attrs.gid.unwrap_or(0);
        Entry {
            name,
            kind: match attrs.file_type() {
                FileType::Dir => Kind::Dir,
                FileType::Symlink => Kind::Link,
                _ => Kind::File,
            },
            size: attrs.size.unwrap_or(0),
            modified: u64::from(attrs.mtime.unwrap_or(0)),
            mode: attrs.permissions.unwrap_or(0) & 0o7777,
            uid,
            gid,
            owner: attrs.user.clone().or_else(|| names.users.get(&uid).cloned()).unwrap_or_else(|| uid.to_string()),
            group: attrs.group.clone().or_else(|| names.groups.get(&gid).cloned()).unwrap_or_else(|| gid.to_string()),
            target: None,
        }
    }

    /// Inhalt eines Ordners, unsortiert. Verknüpfungen nennen ihr Ziel.
    pub async fn list(&self, path: &str) -> Result<Vec<Entry>, FileError> {
        let names = self.names().await;
        let mut entries = Vec::new();
        for item in self.sftp.read_dir(path).await? {
            let mut entry = self.entry(item.file_name(), &item.metadata(), &names);
            if entry.kind == Kind::Link {
                entry.target = self.sftp.read_link(join(path, &entry.name)).await.ok();
            }
            entries.push(entry);
        }
        Ok(entries)
    }

    /// Angaben zu einem Pfad. Mit `follow` zählt das Ziel einer Verknüpfung, sonst die Verknüpfung selbst.
    pub async fn stat(&self, path: &str, follow: bool) -> Result<Entry, FileError> {
        let attrs = if follow { self.sftp.metadata(path).await? } else { self.sftp.symlink_metadata(path).await? };
        let name = path.trim_end_matches('/').rsplit('/').next().unwrap_or_default().to_string();
        let names = self.names().await;
        Ok(self.entry(name, &attrs, &names))
    }

    pub async fn mkdir(&self, path: &str) -> Result<(), FileError> {
        Ok(self.sftp.create_dir(path).await?)
    }

    pub async fn rename(&self, from: &str, to: &str) -> Result<(), FileError> {
        Ok(self.sftp.rename(from, to).await?)
    }

    /// Löscht eine Datei, eine Verknüpfung oder einen Ordner samt allem darin. Verknüpfungen wird nicht gefolgt.
    pub fn remove<'a>(&'a self, path: &'a str) -> Pin<Box<dyn Future<Output = Result<(), FileError>> + Send + 'a>> {
        Box::pin(async move {
            if self.sftp.symlink_metadata(path).await?.file_type() != FileType::Dir {
                return Ok(self.sftp.remove_file(path).await?);
            }
            for item in self.sftp.read_dir(path).await? {
                self.remove(&join(path, &item.file_name())).await?;
            }
            Ok(self.sftp.remove_dir(path).await?)
        })
    }

    /// Nummer zu einem Benutzer- oder Gruppennamen; eine Zahl gilt als Nummer.
    fn id(wanted: &str, table: &HashMap<u32, String>) -> Result<u32, FileError> {
        let wanted = wanted.trim();
        wanted.parse().ok().or_else(|| table.iter().find(|(_, name)| name.as_str() == wanted).map(|(id, _)| *id)).ok_or_else(|| FileError::Failure(format!("unknown name: {wanted}")))
    }

    /// Ändert Rechte und Besitzer, mit `recursive` auch an allem, was in einem Ordner liegt.
    pub async fn change(&self, path: &str, change: &Change, recursive: bool) -> Result<(), FileError> {
        let names = self.names().await;
        let uid = change.owner.as_deref().map(|owner| Self::id(owner, &names.users)).transpose()?;
        let gid = change.group.as_deref().map(|group| Self::id(group, &names.groups)).transpose()?;
        self.apply(path, change.mode.map(|mode| mode & 0o7777), uid, gid, recursive).await
    }

    fn apply<'a>(&'a self, path: &'a str, mode: Option<u32>, uid: Option<u32>, gid: Option<u32>, recursive: bool) -> Pin<Box<dyn Future<Output = Result<(), FileError>> + Send + 'a>> {
        Box::pin(async move {
            let current = self.sftp.symlink_metadata(path).await?;
            // Rechte einer Verknüpfung gibt es nicht; sie zu setzen träfe ihr Ziel.
            if current.file_type() == FileType::Symlink {
                return Ok(());
            }
            // SFTP setzt Besitzer und Gruppe nur gemeinsam.
            let owners = (uid.is_some() || gid.is_some()).then(|| (uid.or(current.uid).unwrap_or(0), gid.or(current.gid).unwrap_or(0)));
            if mode.is_some() || owners.is_some() {
                self.sftp.set_metadata(path, only(mode, owners.map(|o| o.0), owners.map(|o| o.1), None)).await?;
            }
            if recursive && current.file_type() == FileType::Dir {
                for item in self.sftp.read_dir(path).await? {
                    self.apply(&join(path, &item.file_name()), mode, uid, gid, true).await?;
                }
            }
            Ok(())
        })
    }

    /// Liest höchstens `limit` Bytes vom Anfang einer Datei. Der zweite Wert sagt, ob sie länger ist.
    pub async fn read(&self, path: &str, limit: u64) -> Result<(Vec<u8>, bool), FileError> {
        let file = self.sftp.open(path).await?;
        let mut bytes = Vec::new();
        file.take(limit + 1).read_to_end(&mut bytes).await?;
        let longer = bytes.len() as u64 > limit;
        bytes.truncate(limit as usize);
        Ok((bytes, longer))
    }

    /// Schreibt eine Datei neu. Gibt es sie schon, behält sie Rechte und Besitzer.
    pub async fn write(&self, path: &str, data: &[u8]) -> Result<(), FileError> {
        let mut file = self.sftp.open_with_flags(path, OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE).await?;
        file.write_all(data).await?;
        file.shutdown().await?;
        Ok(())
    }

    /// Öffnet eine Datei zum Lesen ab der Stelle `offset`.
    pub async fn reader(&self, path: &str, offset: u64) -> Result<File, FileError> {
        let mut file = self.sftp.open(path).await?;
        if offset > 0 {
            file.seek(std::io::SeekFrom::Start(offset)).await?;
        }
        Ok(file)
    }

    /// Öffnet eine Datei zum Schreiben. Ab `offset` 0 beginnt sie neu; sonst wird ab dort weitergeschrieben,
    /// etwa um einen abgebrochenen Upload fortzusetzen.
    pub async fn writer(&self, path: &str, offset: u64) -> Result<File, FileError> {
        let flags = if offset == 0 { OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE } else { OpenFlags::WRITE | OpenFlags::CREATE };
        let mut file = self.sftp.open_with_flags(path, flags).await?;
        if offset > 0 {
            file.seek(std::io::SeekFrom::Start(offset)).await?;
        }
        Ok(file)
    }

    /// Setzt die Änderungszeit, damit eine hochgeladene Datei so alt ist wie ihr Original.
    pub async fn touch(&self, path: &str, modified: u64) -> Result<(), FileError> {
        Ok(self.sftp.set_metadata(path, only(None, None, None, Some(modified.min(u64::from(u32::MAX)) as u32))).await?)
    }

    /// Beendet SFTP und, falls es eine eigene Verbindung hatte, auch die.
    pub async fn close(self) {
        let _ = self.sftp.close().await;
        if let Some(link) = self.link {
            let _ = link.handle.disconnect(Disconnect::ByApplication, "", "en").await;
        }
    }
}

/// Verbindet wie [`crate::open`], aber ohne Terminal: Am Ende steht SFTP auf einer eigenen Verbindung.
///
/// Rückfragen (Host-Schlüssel, Passwort, Fragen des Servers) kommen wie bei einer Sitzung als Ereignisse. Gelingt
/// es, kommt als letztes Ereignis [`Event::Files`] mit der Verbindung; scheitert es oder schickt der Aufrufer
/// [`Command::Close`], kommt [`Event::End`]. Danach ist nichts mehr zu erwarten. Der Kanal selbst schließt sich
/// erst mit der Verbindung, weil sie ihn für spätere Meldungen des Servers festhält.
pub fn open(connect: Connect) -> Session {
    let (event_tx, events) = mpsc::channel(64);
    let (commands, mut command_rx) = mpsc::unbounded_channel::<Command>();
    tokio::spawn(async move {
        let _ = event_tx.send(Event::Phase(Phase::Connecting)).await;
        let size = Mutex::new((0, 0));
        let work = async {
            let link = establish(&connect, &event_tx).await?;
            let channel = link.handle.channel_open_session().await.map_err(lost)?;
            let mut remote = Remote::on(Opened(channel)).await.map_err(|error| End::ConnectFailed(format!("sftp: {}", error.code())))?;
            remote.link = Some(link);
            Ok(remote)
        };
        let result = tokio::select! {
            result = work => result,
            () = closed_early(&mut command_rx, &size) => Err(End::User),
        };
        match result {
            Ok(remote) => drop(event_tx.send(Event::Files(remote)).await),
            Err(end) => drop(event_tx.send(Event::End(end)).await),
        }
    });
    Session { commands, events }
}

/// Führt einen Befehl auf einem zusätzlichen Kanal aus und sammelt, was er ausgibt.
pub async fn run(opened: Opened, command: &str) -> Result<Output, FileError> {
    let mut channel = opened.0;
    let work = async {
        channel.exec(true, command).await.map_err(|e| FileError::Lost(e.to_string()))?;
        Ok(capture(&mut channel, MAX_EXECUTE_OUTPUT, false).await)
    };
    timeout(EXECUTE_TIMEOUT, work).await.unwrap_or(Err(FileError::Lost("timed out".into())))
}

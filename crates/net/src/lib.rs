//! SSH connection for a terminal: connect, present the host key, sign in, shell.
//!
//! This crate knows neither vault nor interface. Whoever opens a session gets a stream of
//! [`Event`]s and sends [`Command`]s back. Prompts (host key, password) arrive as an event
//! with a reply channel; whether a host key is already known is decided by the caller.

pub mod agent;
pub mod files;
pub mod forward;
pub mod keys;
mod os;
pub mod manage;
pub mod mosh;
mod proxy;
pub mod stats;

use std::{
    future::Future,
    net::SocketAddr,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use russh::client::{self, AuthResult, Handle, KeyboardInteractiveAuthResponse};
use russh::keys::ssh_key::certificate::CertType;
use russh::keys::{Algorithm, Certificate, EcdsaCurve, HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate};
use russh::{cipher, kex, mac, ChannelMsg, Disconnect, MethodKind, MethodSet, Preferred, SshId};
use tokio::{
    net::TcpStream,
    sync::{mpsc, oneshot},
    time::timeout,
};
use zeroize::Zeroizing;

pub use agent::Agents;
pub use mosh::{Fallback as MoshFallback, Mosh, MoshEvent, Predict as MoshPredict};
pub use os::classify;
pub use proxy::{Login, Proxy};

pub type Secret = Zeroizing<String>;

/// How often to ask for password or passphrase. Servers give up after a few failed attempts (`MaxAuthTries`).
const MAX_SECRET_PROMPTS: u32 = 3;
const MAX_INTERACTIVE_ROUNDS: u32 = 10;
/// Servers count every offered key as an attempt (`MaxAuthTries`, usually 6). Offering more from an agent
/// would block the remaining ways.
const MAX_AGENT_KEYS: usize = 4;
const MAX_BANNER: usize = 4000;
const EXECUTE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_EXECUTE_OUTPUT: usize = 64 * 1024;

#[derive(Clone)]
pub struct Connect {
    pub host: String,
    pub port: u16,
    pub user: String,
    /// Saved password; tried before every prompt.
    pub password: Option<Secret>,
    /// Private key from the vault in OpenSSH format, without passphrase. Tried first.
    pub key: Option<Secret>,
    /// User certificate for `key`. Sign-in is tried with it first, then with the key alone.
    pub certificate: Option<String>,
    pub key_file: Option<PathBuf>,
    /// Agents whose keys are offered for signing in. `None`: no agent.
    pub agent: Option<Agents>,
    /// Forward the agent to the server so connections can continue from there. Only has an effect with `agent`.
    pub agent_forward: bool,
    /// Hop to connect through (jump host). It has its own sign-in and can itself go
    /// through another hop.
    pub jump: Option<Box<Connect>>,
    /// Command typed into the shell after signing in.
    pub startcmd: Option<String>,
    /// Environment variables for the shell. A server only accepts what its `AcceptEnv` allows.
    pub env: Vec<(String, String)>,
    /// The caller's tag for this hop, e.g. the host's ID in the vault. It comes back in the events.
    pub tag: Option<String>,
    /// Public keys of the certificate authorities trusted for this address. If the server shows
    /// a valid certificate from one of them, its key applies without a prompt.
    pub authorities: Vec<String>,
    /// Proxy for the first connection to the outside. Behind a jump host there is none: its tunnel leads there.
    pub proxy: Option<Proxy>,
    /// Interval of the keepalives that keep NAT and firewalls open and notice a silent drop. Zero switches them off.
    pub keepalive: Duration,
    /// How long to wait for the connection to be established.
    pub timeout: Duration,
    /// Terminal type the shell sees as `TERM`.
    pub term: String,
    /// Also offer algorithms considered weak today (SHA-1, CBC, small DH groups), for old devices.
    pub legacy: bool,
    /// Columns and rows of the terminal when connecting, so the width is right from the first byte.
    pub size: (u32, u32),
    /// Determine the operating system after signing in (for the host's icon).
    pub detect_os: bool,
    /// Run the terminal over Mosh instead of an SSH shell. Only applies to the destination, not to jump hosts.
    pub mosh: Option<Mosh>,
}

/// The hop of a connection an event is about: the destination itself or a jump host before it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Station {
    /// `user@address`, with port if it is not 22.
    pub label: String,
    /// The tag from [`Connect::tag`].
    pub tag: Option<String>,
}

impl Default for Connect {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 22,
            user: String::new(),
            password: None,
            key: None,
            certificate: None,
            key_file: None,
            agent: None,
            agent_forward: false,
            jump: None,
            startcmd: None,
            env: Vec::new(),
            tag: None,
            authorities: Vec::new(),
            proxy: None,
            keepalive: Duration::from_secs(30),
            timeout: Duration::from_secs(15),
            term: "xterm-256color".into(),
            legacy: false,
            size: (80, 24),
            detect_os: false,
            mosh: None,
        }
    }
}

/// Kinds of server keys for which a certificate is asked for when a certificate authority applies.
const CERTIFIED_HOST_KEYS: &[Algorithm] = &[
    Algorithm::Ed25519,
    Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 },
    Algorithm::Ecdsa { curve: EcdsaCurve::NistP384 },
    Algorithm::Ecdsa { curve: EcdsaCurve::NistP521 },
    Algorithm::Rsa { hash: Some(HashAlg::Sha512) },
    Algorithm::Rsa { hash: Some(HashAlg::Sha256) },
];

/// The secure algorithms first, the old ones behind them. A server that can do better still gets the better one.
fn legacy_preferred() -> Preferred {
    let safe = Preferred::default();
    // The last entries of the list are not algorithms but markers for extensions; the old ones go before them.
    let marker = |name: &kex::Name| name.as_ref().starts_with("ext-info") || name.as_ref().starts_with("kex-strict");
    let mut exchanges: Vec<kex::Name> = safe.kex.iter().copied().filter(|name| !marker(name)).collect();
    exchanges.extend([kex::ECDH_SHA2_NISTP256, kex::ECDH_SHA2_NISTP384, kex::ECDH_SHA2_NISTP521, kex::DH_GEX_SHA1, kex::DH_G14_SHA1, kex::DH_G1_SHA1].into_iter().filter(|name| !safe.kex.contains(name)));
    exchanges.extend(safe.kex.iter().copied().filter(marker));
    let ciphers = safe.cipher.iter().copied().chain([cipher::AES_256_CBC, cipher::AES_192_CBC, cipher::AES_128_CBC, cipher::TRIPLE_DES_CBC]).collect::<Vec<_>>();
    let macs = safe.mac.iter().copied().chain([mac::HMAC_SHA1_ETM, mac::HMAC_SHA1]).collect::<Vec<_>>();
    Preferred { kex: exchanges.into(), cipher: ciphers.into(), mac: macs.into(), ..safe }
}

impl Connect {
    fn station(&self) -> Station {
        let port = if self.port == 22 { String::new() } else { format!(":{}", self.port) };
        Station { label: format!("{}@{}{port}", self.user, self.host), tag: self.tag.clone() }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Connecting,
    Authenticating,
    Connected,
}

/// Why a session ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum End {
    /// Ended by the user or a prompt was cancelled.
    User,
    /// The shell has exited, e.g. after `exit`.
    Remote { exit_status: Option<u32> },
    ConnectFailed(String),
    HostKeyRejected,
    AuthFailed,
    ConnectionLost(String),
    /// The server refused something that is required, e.g. listening on a port. The text says what.
    Refused(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKey {
    pub algorithm: String,
    /// Fingerprint as in OpenSSH: `SHA256:…`.
    pub fingerprint: String,
    /// Public key in OpenSSH format, for recognising it on the next connection.
    pub openssh: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretKind {
    Password,
    Passphrase { file: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prompt {
    pub text: String,
    /// May the input be visible?
    pub echo: bool,
}

pub enum Event {
    Phase(Phase),
    Banner(String),
    /// The server at `host:port` shows its key. Answer `true` = trust and continue.
    HostKey { host: String, port: u16, key: HostKey, reply: oneshot::Sender<bool> },
    /// Password or passphrase is needed. `None` aborts connecting.
    Secret { station: Station, kind: SecretKind, attempt: u32, reply: oneshot::Sender<Option<Secret>> },
    /// Questions from the server (`keyboard-interactive`), e.g. a one-time code.
    Interactive { station: Station, name: String, instructions: String, prompts: Vec<Prompt>, reply: oneshot::Sender<Option<Vec<Secret>>> },
    /// A freshly typed password worked; the caller can offer to save it.
    PasswordAccepted { station: Station, password: Secret },
    /// Something went wrong without the connection failing because of it.
    Notice { code: &'static str, message: String },
    /// Short name of the detected operating system (see `os::classify`).
    Os(String),
    Output(Vec<u8>),
    /// State of a Mosh session (see [`mosh`]).
    Mosh(MoshEvent),
    /// SFTP is up. Only comes with [`files::open`] and is the last event there.
    Files(files::Remote),
    /// The forward is up. Only comes with [`forward::open`] and is the last event there.
    Forward(forward::Tunnel),
    End(End),
}

pub enum Command {
    Input(Vec<u8>),
    Resize(u32, u32),
    /// Pause or resume reading. While paused, output backs up at the server, not in memory.
    Pause(bool),
    /// Opens an additional channel on the same connection, for SFTP or a single command.
    /// `None` if the server grants no further one or the shell is not up yet.
    Open(oneshot::Sender<Option<files::Opened>>),
    /// Mosh only: re-establish the SSH connection next to it, with prompts if necessary.
    Relink,
    Close,
}

pub struct Session {
    pub commands: mpsc::UnboundedSender<Command>,
    pub events: mpsc::Receiver<Event>,
}

/// Opens a session. Must be called inside a tokio runtime; the work runs in a task of its own.
pub fn open(connect: Connect) -> Session {
    let (event_tx, events) = mpsc::channel(256);
    let (commands, command_rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let end = run(connect, &event_tx, command_rx).await.unwrap_or_else(|end| end);
        let _ = event_tx.send(Event::End(end)).await;
    });
    Session { commands, events }
}

/// What a single command on a host resulted in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub stdout: Vec<u8>,
    pub exit_status: Option<u32>,
    /// The output was longer than allowed; the rest is missing.
    pub truncated: bool,
}

/// Message in [`End::ConnectionLost`] when a command ran longer than allowed (see [`run_command`]).
pub const COMMAND_TIMED_OUT: &str = "command timed out";

/// Collects what a command outputs, up to `max` bytes; with `stderr` also its error output, in the order
/// of arrival.
pub(crate) async fn capture(channel: &mut russh::Channel<client::Msg>, max: usize, stderr: bool) -> Output {
    let mut output = Output { stdout: Vec::new(), exit_status: None, truncated: false };
    while let Some(message) = channel.wait().await {
        let data = match message {
            ChannelMsg::Data { data } => data,
            ChannelMsg::ExtendedData { data, .. } if stderr => data,
            ChannelMsg::ExitStatus { exit_status } => {
                output.exit_status = Some(exit_status);
                continue;
            }
            _ => continue,
        };
        let room = max.saturating_sub(output.stdout.len());
        output.truncated |= data.len() > room;
        output.stdout.extend_from_slice(&data[..data.len().min(room)]);
    }
    output
}

/// Signs in without any prompt, runs a command and disconnects again.
///
/// `trusted` decides about the key of every server along the way (address, port, key). If signing in
/// needed a prompt (password, passphrase, server questions), it counts as failed: nobody sits here
/// who could answer.
pub async fn execute(connect: &Connect, command: &str, trusted: impl Fn(&str, u16, &HostKey) -> bool) -> Result<Output, End> {
    match timeout(EXECUTE_TIMEOUT, silently(connect, command, trusted, EXECUTE_TIMEOUT, MAX_EXECUTE_OUTPUT, false)).await {
        Ok(result) => result,
        Err(_) => Err(End::ConnectFailed("timed out".into())),
    }
}

/// Like [`execute`], for the user's commands: it may run for `limit` and output up to `max` bytes, and its
/// error output is part of the result. If it runs longer, it ends with [`End::ConnectionLost`] and
/// [`COMMAND_TIMED_OUT`]. The command gets no terminal and no input.
pub async fn run_command(connect: &Connect, command: &str, limit: Duration, max: usize, trusted: impl Fn(&str, u16, &HostKey) -> bool) -> Result<Output, End> {
    silently(connect, command, trusted, limit, max, true).await
}

async fn silently(connect: &Connect, command: &str, trusted: impl Fn(&str, u16, &HostKey) -> bool, limit: Duration, max: usize, stderr: bool) -> Result<Output, End> {
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
        // A cancelled prompt ends as “ended by the user”; here that means: the stored credentials are not enough.
        let link = establish(connect, &event_tx).await.map_err(|end| if end == End::User { End::AuthFailed } else { end })?;
        let handle = &link.handle;
        let mut channel = handle.channel_open_session().await.map_err(lost)?;
        channel.exec(true, command).await.map_err(lost)?;
        // Nobody types anything: a command waiting for input should notice right away.
        let _ = channel.eof().await;
        let output = timeout(limit, capture(&mut channel, max, stderr)).await.map_err(|_| End::ConnectionLost(COMMAND_TIMED_OUT.into()));
        let _ = handle.disconnect(Disconnect::ByApplication, "", "en").await;
        output
    };
    tokio::select! {
        result = work => result,
        () = answers => Err(End::User),
    }
}

/// Sends an event. If nobody listens any more, the session ends as if ended by the user.
async fn emit(events: &mpsc::Sender<Event>, event: Event) -> Result<(), End> {
    events.send(event).await.map_err(|_| End::User)
}

async fn ask<T>(events: &mpsc::Sender<Event>, make: impl FnOnce(oneshot::Sender<T>) -> Event) -> Result<Option<T>, End> {
    let (reply, answer) = oneshot::channel();
    emit(events, make(reply)).await?;
    Ok(answer.await.ok())
}

fn lost(error: russh::Error) -> End {
    End::ConnectionLost(error.to_string())
}

async fn run(connect: Connect, events: &mpsc::Sender<Event>, mut commands: mpsc::UnboundedReceiver<Command>) -> Result<End, End> {
    emit(events, Event::Phase(Phase::Connecting)).await?;

    // Until the shell is up, only “close” counts among the commands; the last reported size is remembered.
    let size = Mutex::new(connect.size);
    // With Mosh the session remembers what was confirmed while signing in: so the SSH connection next to it
    // comes back without a prompt after a drop.
    let remembered = Arc::new(Mutex::new(mosh::Memory::default()));
    let memory = connect.mosh.is_some().then_some(&remembered);
    // The hops before it stay open in `link` while the session runs.
    let link = tokio::select! {
        link = establish_with(&connect, events, memory) => link?,
        () = closed_early(&mut commands, &size) => return Err(End::User),
    };

    if let Some(options) = &connect.mosh {
        let now = *size.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let attached = tokio::select! {
            attached = mosh::attach(&link, &connect, options, now) => attached,
            () = closed_early(&mut commands, &size) => return Err(End::User),
        };
        match attached {
            Ok((session, running)) => {
                let resized = *size.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                if resized != now {
                    let _ = session.resize(resized.0.max(1), resized.1.max(1)).await;
                }
                return mosh::drive(Arc::new(connect.clone()), link, remembered, session, running, events, &mut commands).await;
            }
            // Mosh does not work here: the SSH connection stands, so it becomes an ordinary shell.
            Err(Ok(fallback)) => emit(events, Event::Mosh(MoshEvent::Fallback(fallback))).await?,
            Err(Err(end)) => return Err(end),
        }
    }

    let handle = &link.handle;
    let (columns, rows) = *size.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

    let channel = handle.channel_open_session().await.map_err(lost)?;
    channel.request_pty(false, connect.term.as_str(), columns, rows, 0, 0, &[]).await.map_err(lost)?;
    if connect.agent_forward && connect.agent.is_some() {
        // Without an answer: if the server forbids forwarding, the session runs without.
        channel.agent_forward(false).await.map_err(lost)?;
    }
    for (name, value) in &connect.env {
        // Without an answer: if the server refuses a variable, the session should not fail because of it.
        channel.set_env(false, name.as_str(), value.as_str()).await.map_err(lost)?;
    }
    channel.request_shell(true).await.map_err(lost)?;
    if let Some(command) = connect.startcmd.as_deref().map(str::trim).filter(|c| !c.is_empty()) {
        channel.data(format!("{command}\r").as_bytes()).await.map_err(lost)?;
    }
    emit(events, Event::Phase(Phase::Connected)).await?;

    let probe = async {
        if connect.detect_os {
            if let Some(os) = os::probe(handle).await {
                let _ = events.send(Event::Os(os)).await;
            }
        }
    };
    let (end, ()) = tokio::join!(shell(handle, channel, events, &mut commands), probe);
    if end == Ok(End::User) {
        let _ = handle.disconnect(Disconnect::ByApplication, "", "en").await;
    }
    end
}

async fn closed_early(commands: &mut mpsc::UnboundedReceiver<Command>, size: &Mutex<(u32, u32)>) {
    loop {
        match commands.recv().await {
            Some(Command::Close) | None => return,
            Some(Command::Resize(columns, rows)) => *size.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = (columns, rows),
            Some(Command::Input(_) | Command::Pause(_)) => {}
            Some(Command::Open(reply)) => drop(reply.send(None)),
            Some(Command::Relink) => {}
        }
    }
}

/// Passes output and input through until the shell ends, the connection breaks or the user closes.
async fn shell(handle: &Handle<Client>, channel: russh::Channel<client::Msg>, events: &mpsc::Sender<Event>, commands: &mut mpsc::UnboundedReceiver<Command>) -> Result<End, End> {
    // Separate halves: if sending stalls, reading continues anyway.
    let (mut reader, writer) = channel.split();
    let mut paused = false;
    let mut exit_status = None;
    let mut closed_cleanly = false;
    loop {
        tokio::select! {
            message = reader.wait(), if !paused => match message {
                Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => emit(events, Event::Output(data.to_vec())).await?,
                Some(ChannelMsg::ExitStatus { exit_status: status }) => exit_status = Some(status),
                Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) => closed_cleanly = true,
                Some(_) => {}
                None if closed_cleanly || exit_status.is_some() => return Ok(End::Remote { exit_status }),
                None => return Err(End::ConnectionLost("the connection was lost".into())),
            },
            command = commands.recv() => match command {
                Some(Command::Input(bytes)) => writer.data(&bytes[..]).await.map_err(lost)?,
                Some(Command::Resize(columns, rows)) => writer.window_change(columns, rows, 0, 0).await.map_err(lost)?,
                Some(Command::Pause(pause)) => paused = pause,
                Some(Command::Open(reply)) => drop(reply.send(handle.channel_open_session().await.ok().map(files::Opened))),
                Some(Command::Relink) => {}
                Some(Command::Close) | None => return Ok(End::User),
            },
        }
    }
}

struct Client {
    events: mpsc::Sender<Event>,
    rejected: Arc<AtomicBool>,
    /// Address under which this server was reached; trust in its key hangs on it.
    host: String,
    port: u16,
    /// Set if the agent may be forwarded to this server.
    forward: Option<Agents>,
    /// Certificate authorities trusted for this address.
    authorities: Vec<PublicKey>,
    /// Where connections go that the server hands in from one of its ports. Empty as long as no rule
    /// asked for it; then every one is refused.
    forwarded: Forwarded,
    /// With Mosh: records which server key was confirmed.
    memory: Option<mosh::Shared>,
}

/// Acceptor for connections a server hands in (`forwarded-tcpip`).
type Forwarded = Arc<Mutex<Option<mpsc::UnboundedSender<russh::Channel<client::Msg>>>>>;

impl Client {
    /// Has a trusted authority certified that the key under this address belongs to this server?
    fn certified(&self, certificate: &Certificate) -> bool {
        let fingerprints: Vec<_> = self.authorities.iter().map(|ca| ca.fingerprint(HashAlg::Sha256)).collect();
        let named = certificate.valid_principals().is_empty() || certificate.valid_principals().iter().any(|name| name.eq_ignore_ascii_case(&self.host));
        certificate.cert_type() == CertType::Host && named && certificate.validate(&fingerprints).is_ok()
    }
}

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(&mut self, server_key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        if server_key.certificate().is_some_and(|certificate| self.certified(certificate)) {
            return Ok(true);
        }
        // Without a valid certificate only the key itself counts: check whether it is known, otherwise ask.
        let key = server_key.public_key();
        let info = HostKey { algorithm: key.algorithm().to_string(), fingerprint: key.fingerprint(HashAlg::Sha256).to_string(), openssh: key.to_openssh().unwrap_or_default() };
        let (reply, answer) = oneshot::channel();
        // Without an answer the key counts as refused: when in doubt, do not connect.
        let accepted = self.events.send(Event::HostKey { host: self.host.clone(), port: self.port, key: info, reply }).await.is_ok() && answer.await.unwrap_or(false);
        if !accepted {
            self.rejected.store(true, Ordering::Relaxed);
        } else if let Some(memory) = &self.memory {
            mosh::remember_key(memory, &self.host, self.port, &key.fingerprint(HashAlg::Sha256).to_string());
        }
        Ok(accepted)
    }

    // The text comes from a server nobody is signed in to yet: printable characters only, limited length.
    async fn auth_banner(&mut self, banner: &str, _session: &mut client::Session) -> Result<(), Self::Error> {
        let text: String = banner.chars().filter(|c| *c == '\n' || !c.is_control()).take(MAX_BANNER).collect();
        if !text.trim().is_empty() {
            let _ = self.events.send(Event::Banner(text)).await;
        }
        Ok(())
    }

    /// The server wants to use the agent. That only works if it was allowed for this connection.
    async fn server_channel_open_agent_forward(&mut self, channel: russh::Channel<client::Msg>, reply: client::ChannelOpenHandle, _session: &mut client::Session) -> Result<(), Self::Error> {
        let Some(agents) = &self.forward else {
            return Ok(());
        };
        let Some(mut local) = agent::stream(agents).await else {
            return Ok(());
        };
        reply.accept().await;
        tokio::spawn(async move {
            let mut remote = channel.into_stream();
            let _ = tokio::io::copy_bidirectional(&mut remote, &mut local).await;
        });
        Ok(())
    }

    /// The server hands in a connection that arrived on one of its ports. It is only accepted
    /// if a port rule of this connection asked for it.
    #[allow(clippy::too_many_arguments)]
    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: russh::Channel<client::Msg>,
        _connected_address: &str,
        _connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let taker = self.forwarded.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone();
        if let Some(taker) = taker {
            reply.accept().await;
            let _ = taker.send(channel);
        }
        Ok(())
    }
}

/// An established, signed-in connection together with the hops before it. Those must stay open while it lives.
struct Link {
    handle: Handle<Client>,
    /// Address of the peer when connected directly (without proxy and jump host). Mosh sends UDP there.
    peer: Option<SocketAddr>,
    _hops: Vec<Handle<Client>>,
    /// The destination's acceptor for handed-in connections; see [`forward`].
    forwarded: Forwarded,
}

/// Path to the server (direct or through the hops before it), key exchange, present host key, sign in.
/// Returns a `Box` because the function calls itself for every hop.
fn establish<'a>(connect: &'a Connect, events: &'a mpsc::Sender<Event>) -> Pin<Box<dyn Future<Output = Result<Link, End>> + Send + 'a>> {
    establish_with(connect, events, None)
}

/// Like [`establish`]; with `memory` the connection remembers confirmed server keys and accepted passwords
/// (for Mosh, see [`mosh::Memory`]).
fn establish_with<'a>(connect: &'a Connect, events: &'a mpsc::Sender<Event>, memory: Option<&'a mosh::Shared>) -> Pin<Box<dyn Future<Output = Result<Link, End>> + Send + 'a>> {
    Box::pin(async move {
        let config = Arc::new(client::Config {
            client_id: SshId::Standard(concat!("SSH-2.0-Glowport_", env!("CARGO_PKG_VERSION")).into()),
            keepalive_interval: (!connect.keepalive.is_zero()).then_some(connect.keepalive),
            keepalive_max: 3,
            preferred: Preferred {
                // Only if an authority applies to this address: otherwise nobody would know what a certificate is worth.
                host_key_certificates: if connect.authorities.is_empty() { (&[][..]).into() } else { CERTIFIED_HOST_KEYS.into() },
                ..if connect.legacy { legacy_preferred() } else { Preferred::default() }
            },
            ..Default::default()
        });
        let rejected = Arc::new(AtomicBool::new(false));
        let forward = connect.agent.clone().filter(|_| connect.agent_forward);
        let authorities = connect.authorities.iter().filter_map(|ca| PublicKey::from_openssh(ca).ok()).collect();
        let forwarded = Forwarded::default();
        let handler = Client { events: events.clone(), rejected: Arc::clone(&rejected), host: connect.host.clone(), port: connect.port, forward, authorities, forwarded: Arc::clone(&forwarded), memory: memory.cloned() };
        let failed = |e: russh::Error| if rejected.load(Ordering::Relaxed) { End::HostKeyRejected } else { End::ConnectFailed(e.to_string()) };

        let (mut handle, hops, peer) = match &connect.jump {
            None => {
                let open = async {
                    match &connect.proxy {
                        Some(proxy) => proxy::connect(proxy, &connect.host, connect.port).await,
                        None => TcpStream::connect((connect.host.as_str(), connect.port)).await,
                    }
                };
                let stream = timeout(connect.timeout, open).await.map_err(|_| End::ConnectFailed("timed out".into()))?.map_err(|e| End::ConnectFailed(e.to_string()))?;
                let _ = stream.set_nodelay(true);
                let peer = if connect.proxy.is_none() { stream.peer_addr().ok() } else { None };
                (client::connect_stream(config, stream, handler).await.map_err(failed)?, Vec::new(), peer)
            }
            Some(jump) => {
                let Link { handle: via, _hops: mut hops, .. } = establish_with(jump, events, memory).await?;
                // The hop opens the connection to the next server; an SSH connection of its own runs over it.
                let tunnel = timeout(connect.timeout, via.channel_open_direct_tcpip(connect.host.clone(), u32::from(connect.port), "127.0.0.1", 0))
                    .await
                    .map_err(|_| End::ConnectFailed(format!("timed out behind {}", jump.host)))?
                    .map_err(|e| End::ConnectFailed(format!("{} could not reach {}:{} ({e})", jump.host, connect.host, connect.port)))?;
                hops.push(via);
                (client::connect_stream(config, tunnel.into_stream(), handler).await.map_err(failed)?, hops, None)
            }
        };

        emit(events, Event::Phase(Phase::Authenticating)).await?;
        authenticate(connect, events, &mut handle, memory).await?;
        Ok(Link { handle, peer, _hops: hops, forwarded })
    })
}

fn allows(methods: &MethodSet, kind: MethodKind) -> bool {
    methods.contains(&kind)
}

/// Signs in with a key. `None`: accepted. Otherwise the methods the server still allows afterwards.
async fn offer_key(handle: &mut Handle<Client>, user: &str, key: PrivateKey) -> Result<Option<MethodSet>, End> {
    let rsa_hash = handle.best_supported_rsa_hash().await.ok().flatten().flatten();
    match handle.authenticate_publickey(user, PrivateKeyWithHashAlg::new(Arc::new(key), rsa_hash)).await.map_err(lost)? {
        AuthResult::Success => Ok(None),
        AuthResult::Failure { remaining_methods, .. } => Ok(Some(remaining_methods)),
    }
}

/// Order: key from the vault, keys from the agent, key file, saved password,
/// password prompt, server questions.
async fn authenticate(connect: &Connect, events: &mpsc::Sender<Event>, handle: &mut Handle<Client>, memory: Option<&mosh::Shared>) -> Result<(), End> {
    let user = connect.user.as_str();
    let station = connect.station();

    // “none” almost never succeeds, but returns the list of methods the server allows.
    let mut methods = match handle.authenticate_none(user).await.map_err(lost)? {
        AuthResult::Success => return Ok(()),
        AuthResult::Failure { remaining_methods, .. } => remaining_methods,
    };
    // If the server only accepts keys and none is intended for this connection, there is nothing to ask:
    // the sign-in fails right away. Then it should say why.
    let keys_only = !allows(&methods, MethodKind::Password) && !allows(&methods, MethodKind::KeyboardInteractive);
    let without_key = connect.key.is_none() && connect.agent.is_none() && connect.key_file.is_none();

    if let Some(text) = connect.key.as_ref().filter(|_| allows(&methods, MethodKind::PublicKey)) {
        match PrivateKey::from_openssh(text.as_str()) {
            Ok(key) => {
                // With certificate first: a server that trusts a certificate authority does not know the bare key.
                if let Some(certificate) = connect.certificate.as_deref().and_then(|text| Certificate::from_openssh(text).ok()) {
                    match handle.authenticate_openssh_cert(user, Arc::new(key.clone()), certificate).await.map_err(lost)? {
                        AuthResult::Success => return Ok(()),
                        AuthResult::Failure { remaining_methods, .. } => {
                            methods = remaining_methods;
                            emit(events, Event::Notice { code: "certificate_rejected", message: String::new() }).await?;
                        }
                    }
                }
                if allows(&methods, MethodKind::PublicKey) {
                    match offer_key(handle, user, key).await? {
                        None => return Ok(()),
                        Some(remaining) => {
                            methods = remaining;
                            emit(events, Event::Notice { code: "key_rejected", message: String::new() }).await?;
                        }
                    }
                }
            }
            Err(e) => emit(events, Event::Notice { code: "key_unreadable", message: e.to_string() }).await?,
        }
    }

    if let Some(agents) = connect.agent.as_ref().filter(|_| allows(&methods, MethodKind::PublicKey)) {
        let mut offered = 0;
        'agents: for (mut client, keys) in agent::offers(agents).await {
            for key in keys {
                if offered == MAX_AGENT_KEYS || !allows(&methods, MethodKind::PublicKey) {
                    break 'agents;
                }
                offered += 1;
                let rsa_hash = if matches!(key.algorithm(), Algorithm::Rsa { .. }) { handle.best_supported_rsa_hash().await.ok().flatten().flatten() } else { None };
                match handle.authenticate_publickey_with(user, key, rsa_hash, &mut client).await {
                    Ok(AuthResult::Success) => return Ok(()),
                    Ok(AuthResult::Failure { remaining_methods, .. }) => methods = remaining_methods,
                    // The agent does not sign (locked, refused, gone): continue with the next agent.
                    Err(_) => break,
                }
            }
        }
    }

    if let Some(path) = connect.key_file.as_deref().filter(|_| allows(&methods, MethodKind::PublicKey)) {
        if let Some(key) = load_key(path, &station, events).await? {
            match offer_key(handle, user, key).await? {
                None => return Ok(()),
                Some(remaining) => {
                    methods = remaining;
                    emit(events, Event::Notice { code: "key_rejected", message: path.display().to_string() }).await?;
                }
            }
        }
    }

    if allows(&methods, MethodKind::Password) {
        if let Some(saved) = &connect.password {
            match handle.authenticate_password(user, saved.as_str()).await.map_err(lost)? {
                AuthResult::Success => return Ok(()),
                AuthResult::Failure { remaining_methods, .. } => {
                    methods = remaining_methods;
                    emit(events, Event::Notice { code: "saved_password_rejected", message: String::new() }).await?;
                }
            }
        }
        for attempt in 1..=MAX_SECRET_PROMPTS {
            if !allows(&methods, MethodKind::Password) {
                break;
            }
            let Some(Some(password)) = ask(events, |reply| Event::Secret { station: station.clone(), kind: SecretKind::Password, attempt, reply }).await? else {
                return Err(End::User);
            };
            match handle.authenticate_password(user, password.as_str()).await.map_err(lost)? {
                AuthResult::Success => {
                    if let Some(memory) = memory {
                        mosh::remember_password(memory, &station.label, &password);
                    }
                    emit(events, Event::PasswordAccepted { station, password }).await?;
                    return Ok(());
                }
                AuthResult::Failure { remaining_methods, .. } => methods = remaining_methods,
            }
        }
    }

    if allows(&methods, MethodKind::KeyboardInteractive) {
        let mut response = handle.authenticate_keyboard_interactive_start(user, None).await.map_err(lost)?;
        for _ in 0..MAX_INTERACTIVE_ROUNDS {
            match response {
                KeyboardInteractiveAuthResponse::Success => return Ok(()),
                KeyboardInteractiveAuthResponse::Failure { .. } => break,
                KeyboardInteractiveAuthResponse::InfoRequest { name, instructions, prompts } => {
                    let answers = if prompts.is_empty() {
                        Vec::new()
                    } else {
                        let prompts = prompts.into_iter().map(|p| Prompt { text: p.prompt, echo: p.echo }).collect();
                        match ask(events, |reply| Event::Interactive { station: station.clone(), name, instructions, prompts, reply }).await? {
                            Some(Some(answers)) => answers.iter().map(|a| a.to_string()).collect(),
                            _ => return Err(End::User),
                        }
                    };
                    response = handle.authenticate_keyboard_interactive_respond(answers).await.map_err(lost)?;
                }
            }
        }
    }

    if keys_only && without_key {
        emit(events, Event::Notice { code: "key_required", message: String::new() }).await?;
    }
    Err(End::AuthFailed)
}

/// Reads the key file and asks for the passphrase if needed. `None`: the file is unusable,
/// signing in continues with the other ways.
async fn load_key(path: &Path, station: &Station, events: &mpsc::Sender<Event>) -> Result<Option<PrivateKey>, End> {
    match decode_key(path, None).await {
        Ok(key) => return Ok(Some(key)),
        Err(russh::keys::Error::KeyIsEncrypted) => {}
        Err(e) => {
            emit(events, Event::Notice { code: "key_unreadable", message: format!("{}: {e}", path.display()) }).await?;
            return Ok(None);
        }
    }
    for attempt in 1..=MAX_SECRET_PROMPTS {
        let kind = SecretKind::Passphrase { file: path.display().to_string() };
        let Some(Some(passphrase)) = ask(events, |reply| Event::Secret { station: station.clone(), kind, attempt, reply }).await? else {
            return Err(End::User);
        };
        if let Ok(key) = decode_key(path, Some(passphrase)).await {
            return Ok(Some(key));
        }
    }
    emit(events, Event::Notice { code: "key_unreadable", message: path.display().to_string() }).await?;
    Ok(None)
}

// Decrypting (bcrypt-pbkdf) takes noticeable time; not on a runtime thread.
async fn decode_key(path: &Path, passphrase: Option<Secret>) -> Result<PrivateKey, russh::keys::Error> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || russh::keys::load_secret_key(path, passphrase.as_ref().map(|p| p.as_str())))
        .await
        .unwrap_or(Err(russh::keys::Error::CouldNotReadKey))
}

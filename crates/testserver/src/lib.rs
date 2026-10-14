//! Small SSH server for tests. It runs in the test's process on a free port of 127.0.0.1.
//!
//! The “shell” is a piece of text: it echoes input like a terminal and knows a few commands
//! that can be used to check the client's behaviour (`size`, `term`, `env`, `agent`, `exit`, `drop`).
//! With `Options::files` it also speaks SFTP on a folder of this machine (see `sftp`).

pub mod admin;
pub mod ftp;
pub mod mosh;
pub mod pve;
pub mod sftp;

use std::{
    collections::HashMap,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::keys::agent::{client::AgentClient, AgentIdentity};
use russh::keys::{PrivateKey, PublicKey};
use russh::server::{Auth, Handler, Msg, Server, Session};
use russh::{Channel, ChannelId, Disconnect, MethodKind, MethodSet};
use tokio::{net::TcpListener, task::JoinHandle};

pub const PROMPT: &str = "$ ";
pub const GREETING: &str = "Welcome to the test server\r\n";

#[derive(Clone, Default)]
pub struct Options {
    /// User and password with which signing in succeeds. `None` switches password sign-in off.
    pub password: Option<(String, String)>,
    pub authorized_keys: Vec<PublicKey>,
    /// Certificate authority whose user certificates the server accepts (like `TrustedUserCAKeys`).
    pub user_ca: Option<PublicKey>,
    /// Certificate for the server's key. It shows it to clients that ask for it.
    pub host_certificate: Option<russh::keys::Certificate>,
    /// The user's home directory. With it the server reads `.ssh/authorized_keys` inside it anew on every sign-in
    /// and really runs `exec` commands (via `sh`, with this folder as `$HOME`), like a real server.
    pub home: Option<PathBuf>,
    /// May the server forward connections to other machines (`direct-tcpip`), i.e. be a jump host?
    /// Then on request it also listens on a port itself and hands in what arrives there (`tcpip-forward`).
    pub forwarding: bool,
    /// The server only speaks algorithms considered weak today, like an old network device.
    pub legacy_only: bool,
    /// Text the server shows before signing in.
    pub banner: Option<String>,
    /// Fixed answer to `exec` calls, e.g. the content of `/etc/os-release`. With `home` it only applies to
    /// commands that contain `uname -s` (that is how the client asks for the operating system).
    pub exec_output: Option<String>,
    /// Folder of this machine that the server shows over SFTP as its file system. Without it there is no SFTP.
    pub files: Option<PathBuf>,
    /// Paths in the server's file system under which SFTP may change nothing (e.g. `/etc`).
    pub files_read_only: Vec<String>,
    /// A simulated Linux with Docker, systemd and procps: the server then answers management commands
    /// from this state instead of running them (see [`admin`]).
    pub admin: Option<std::sync::Arc<std::sync::Mutex<admin::Admin>>>,
    /// Pause before every SFTP read and write, so a test catches a transfer in the middle.
    pub files_delay: Option<Duration>,
    /// `mosh-server` in WSL with a UDP forwarder (see [`mosh`]). Without it there is no mosh here.
    pub mosh: Option<mosh::Bridge>,
}

/// Certificate for a server key, issued by `ca` for the address `name`, valid for one day.
pub fn host_certificate(ca: &PrivateKey, host_key: &PrivateKey, name: &str) -> Option<russh::keys::Certificate> {
    use russh::keys::ssh_key::certificate::{Builder, CertType};
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
    let mut builder = Builder::new_with_random_nonce(&mut rand::rng(), host_key.public_key().key_data().clone(), now - 60, now + 86_400).ok()?;
    builder.cert_type(CertType::Host).ok()?.key_id("glowport-testserver").ok()?.valid_principal(name).ok()?;
    builder.sign(ca).ok()
}

/// Fixed key from a seed, so tests see the same fingerprint again.
pub fn key(seed: u8) -> PrivateKey {
    PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]))
}

pub struct Running {
    pub address: SocketAddr,
    /// The file system behind SFTP, if the server shows one.
    pub files: Option<sftp::Files>,
    task: JoinHandle<()>,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Starts the server in the running tokio runtime.
pub async fn start(options: Options, host_key: PrivateKey) -> std::io::Result<Running> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let address = listener.local_addr()?;
    let mut methods = MethodSet::empty();
    if options.password.is_some() {
        methods.push(MethodKind::Password);
    }
    if !options.authorized_keys.is_empty() || options.home.is_some() || options.user_ca.is_some() {
        methods.push(MethodKind::PublicKey);
    }
    let config = Arc::new(russh::server::Config {
        methods: methods.clone(),
        // No brake on password guessing: it would only slow down the tests.
        auth_rejection_time: Duration::ZERO,
        auth_rejection_time_initial: Some(Duration::ZERO),
        keys: vec![host_key],
        certificates: options.host_certificate.clone().into_iter().collect(),
        preferred: if options.legacy_only {
            russh::Preferred { kex: vec![russh::kex::DH_G14_SHA1].into(), cipher: vec![russh::cipher::AES_128_CBC].into(), mac: vec![russh::mac::HMAC_SHA1].into(), ..Default::default() }
        } else {
            Default::default()
        },
        ..Default::default()
    });
    let files = options.files.clone().map(|root| sftp::Files::new(root, options.files_read_only.clone(), options.files_delay));
    let shared = files.clone();
    let task = tokio::spawn(async move {
        let mut server = TestServer { options, methods, files: shared };
        let _ = server.run_on_socket(config, &listener).await;
    });
    Ok(Running { address, files, task })
}

struct TestServer {
    options: Options,
    methods: MethodSet,
    files: Option<sftp::Files>,
}

impl Server for TestServer {
    type Handler = Connection;

    fn new_client(&mut self, _peer: Option<SocketAddr>) -> Connection {
        Connection { options: self.options.clone(), methods: self.methods.clone(), files: self.files.clone(), pending: HashMap::new(), shells: HashMap::new(), sizes: HashMap::new(), env: HashMap::new(), agent: Vec::new(), terms: HashMap::new(), listeners: HashMap::new() }
    }
}

struct Connection {
    options: Options,
    methods: MethodSet,
    files: Option<sftp::Files>,
    /// Opened channels, until it is clear what they are needed for.
    pending: HashMap<ChannelId, Channel<Msg>>,
    /// Bisher getippte Zeile je Shell.
    shells: HashMap<ChannelId, Vec<u8>>,
    sizes: HashMap<ChannelId, (u32, u32)>,
    /// Environment variables the client set for a shell.
    env: HashMap<ChannelId, Vec<(String, String)>>,
    /// Channels for which the client forwards its agent.
    agent: Vec<ChannelId>,
    /// Terminal type per channel, as the client requested it.
    terms: HashMap<ChannelId, String>,
    /// Ports on which the server listens for the client (`tcpip-forward`). They end with the connection.
    listeners: HashMap<(String, u32), Listening>,
}

/// Aborts listening as soon as the entry is dropped.
struct Listening(JoinHandle<()>);

impl Drop for Listening {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl Connection {
    /// Like OpenSSH: after a failed attempt all methods stay on offer.
    fn reject(&self) -> Auth {
        Auth::Reject { proceed_with_methods: Some(self.methods.clone()), partial_success: false }
    }

    /// The key itself is compared. The comment from a `.pub` file is not part of it and does not travel
    /// over the line either.
    fn authorised(&self, key: &PublicKey) -> bool {
        let from_file = self.options.home.as_ref().and_then(|home| std::fs::read_to_string(home.join(".ssh").join("authorized_keys")).ok()).unwrap_or_default();
        let listed = from_file.lines().filter_map(|line| PublicKey::from_openssh(line.trim()).ok());
        self.options.authorized_keys.iter().cloned().chain(listed).any(|known| known.key_data() == key.key_data())
    }

    fn run_line(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), russh::Error> {
        let line = String::from_utf8_lossy(&self.shells.insert(channel, Vec::new()).unwrap_or_default()).trim().to_string();
        match line.as_str() {
            "exit" => {
                session.data(channel, b"logout\r\n".to_vec())?;
                session.exit_status_request(channel, 0)?;
                session.eof(channel)?;
                return session.close(channel);
            }
            // Cut the connection without a goodbye, the way a network drop looks from the client's side.
            "drop" => return session.disconnect(Disconnect::ByApplication, "", ""),
            "size" => {
                let (columns, rows) = self.sizes.get(&channel).copied().unwrap_or((0, 0));
                session.data(channel, format!("{columns}x{rows}\r\n").into_bytes())?;
            }
            // Queries the client's forwarded agent and names the fingerprints of its keys.
            "agent" if self.agent.contains(&channel) => {
                let handle = session.handle();
                // As a task of its own: the answer to opening the channel comes over the same connection.
                tokio::spawn(async move {
                    let listed = match handle.channel_open_agent().await {
                        Ok(forwarded) => AgentClient::connect(forwarded.into_stream()).request_identities().await.ok(),
                        Err(_) => None,
                    };
                    let text = match listed {
                        Some(identities) => identities
                            .iter()
                            .map(|identity| match identity {
                                AgentIdentity::PublicKey { key, .. } => format!("{}\r\n", key.fingerprint(Default::default())),
                                AgentIdentity::Certificate { .. } => "Zertifikat\r\n".to_string(),
                            })
                            .collect::<String>(),
                        None => "Agent does not answer\r\n".to_string(),
                    };
                    let _ = handle.data(channel, format!("{text}{PROMPT}").into_bytes()).await;
                });
                return Ok(());
            }
            "agent" => session.data(channel, b"no agent\r\n".to_vec())?,
            "term" => session.data(channel, format!("{}\r\n", self.terms.get(&channel).map_or("", String::as_str)).into_bytes())?,
            "env" => {
                for (name, value) in self.env.get(&channel).into_iter().flatten() {
                    session.data(channel, format!("{name}={value}\r\n").into_bytes())?;
                }
            }
            "" => {}
            other => session.data(channel, format!("unbekannt: {other}\r\n").into_bytes())?,
        }
        session.data(channel, PROMPT.as_bytes().to_vec())
    }
}

impl Handler for Connection {
    type Error = russh::Error;

    async fn authentication_banner(&mut self) -> Result<Option<String>, Self::Error> {
        Ok(self.options.banner.clone())
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        Ok(match &self.options.password {
            Some((expected_user, expected_password)) if user == expected_user && password == expected_password => Auth::Accept,
            _ => self.reject(),
        })
    }

    /// Accepts a certificate if the trusted authority signed it, it is currently valid and it names the user.
    async fn auth_openssh_certificate(&mut self, user: &str, certificate: &russh::keys::Certificate) -> Result<Auth, Self::Error> {
        let trusted = self.options.user_ca.as_ref().is_some_and(|ca| certificate.validate([&ca.fingerprint(Default::default())]).is_ok());
        Ok(if trusted && certificate.valid_principals().iter().any(|principal| principal == user) { Auth::Accept } else { self.reject() })
    }

    // The library also asks here for the key inside a certificate. Whether the certificate is valid is only decided by
    // `auth_openssh_certificate`; a bare key then fails in `auth_publickey`.
    async fn auth_publickey_offered(&mut self, _user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        Ok(if self.authorised(key) || self.options.user_ca.is_some() { Auth::Accept } else { self.reject() })
    }

    async fn auth_publickey(&mut self, _user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        Ok(if self.authorised(key) { Auth::Accept } else { self.reject() })
    }

    async fn channel_open_session(&mut self, channel: Channel<Msg>, reply: russh::server::ChannelOpenHandle, _session: &mut Session) -> Result<(), Self::Error> {
        self.pending.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        columns: u32,
        rows: u32,
        _pixel_width: u32,
        _pixel_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.sizes.insert(channel, (columns, rows));
        self.terms.insert(channel, term.to_string());
        session.channel_success(channel)
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        columns: u32,
        rows: u32,
        _pixel_width: u32,
        _pixel_height: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.sizes.insert(channel, (columns, rows));
        Ok(())
    }

    async fn shell_request(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        self.pending.remove(&channel);
        self.shells.insert(channel, Vec::new());
        session.channel_success(channel)?;
        session.data(channel, format!("{GREETING}{PROMPT}").into_bytes())
    }

    async fn agent_request(&mut self, channel: ChannelId, _session: &mut Session) -> Result<bool, Self::Error> {
        self.agent.push(channel);
        Ok(true)
    }

    async fn env_request(&mut self, channel: ChannelId, variable_name: &str, variable_value: &str, _session: &mut Session) -> Result<(), Self::Error> {
        self.env.entry(channel).or_default().push((variable_name.to_string(), variable_value.to_string()));
        Ok(())
    }

    /// Jump host: forwards the channel to the desired machine if that is allowed and it is reachable.
    #[allow(clippy::too_many_arguments)]
    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: russh::server::ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // For tests: this destination cuts the connection, the way a network drop looks from the client's side.
        if host_to_connect == "disconnect.test" {
            return session.disconnect(Disconnect::ByApplication, "", "");
        }
        let target = match u16::try_from(port_to_connect) {
            Ok(port) if self.options.forwarding => tokio::net::TcpStream::connect((host_to_connect, port)).await.ok(),
            _ => None,
        };
        let Some(mut target) = target else {
            // Without a promise the request counts as refused.
            return Ok(());
        };
        reply.accept().await;
        tokio::spawn(async move {
            let mut stream = channel.into_stream();
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut target).await;
        });
        Ok(())
    }

    /// Listens for the client on a port of this machine and hands every connection back to it as a channel.
    async fn tcpip_forward(&mut self, address: &str, port: &mut u32, session: &mut Session) -> Result<bool, Self::Error> {
        if !self.options.forwarding {
            return Ok(false);
        }
        let Ok(wanted) = u16::try_from(*port) else { return Ok(false) };
        // Like a server without `GatewayPorts`: always only on its own address.
        let Ok(listener) = TcpListener::bind(("127.0.0.1", wanted)).await else { return Ok(false) };
        let bound = listener.local_addr().map(|a| u32::from(a.port())).unwrap_or(*port);
        *port = bound;
        let (handle, address) = (session.handle(), address.to_string());
        let key = (address.clone(), bound);
        let task = tokio::spawn(async move {
            while let Ok((mut stream, peer)) = listener.accept().await {
                let (handle, address) = (handle.clone(), address.clone());
                tokio::spawn(async move {
                    if let Ok(channel) = handle.channel_open_forwarded_tcpip(address, bound, peer.ip().to_string(), u32::from(peer.port())).await {
                        let mut forwarded = channel.into_stream();
                        let _ = tokio::io::copy_bidirectional(&mut forwarded, &mut stream).await;
                    }
                });
            }
        });
        self.listeners.insert(key, Listening(task));
        Ok(true)
    }

    async fn cancel_tcpip_forward(&mut self, address: &str, port: u32, _session: &mut Session) -> Result<bool, Self::Error> {
        Ok(self.listeners.remove(&(address.to_string(), port)).is_some())
    }

    async fn exec_request(&mut self, channel: ChannelId, command: &[u8], session: &mut Session) -> Result<(), Self::Error> {
        self.pending.remove(&channel);
        let command = String::from_utf8_lossy(command).into_owned();
        if let Some(bridge) = self.options.mosh.clone().filter(|_| mosh::Bridge::takes(&command)) {
            let (output, errors, status) = bridge.run(&command).await;
            session.channel_success(channel)?;
            session.data(channel, output)?;
            if !errors.is_empty() {
                session.extended_data(channel, 1, errors)?;
            }
            session.exit_status_request(channel, status)?;
            session.eof(channel)?;
            return session.close(channel);
        }
        let fixed = self.options.exec_output.clone().filter(|_| self.options.home.is_none() || command.contains("uname -s"));
        let managed = self.options.admin.as_ref().and_then(|admin| admin.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).answer(&command));
        let (output, errors, status) = match (fixed, self.options.home.clone()) {
            _ if managed.is_some() => managed.map(|(output, status)| (output.into_bytes(), Vec::new(), status)).unwrap_or_default(),
            (Some(output), _) => (output.into_bytes(), Vec::new(), 0),
            (None, Some(home)) => {
                // Forward slashes, so Git for Windows' shell understands the path too.
                let home = home.to_string_lossy().replace('\\', "/");
                let ran = tokio::task::spawn_blocking(move || std::process::Command::new("sh").arg("-c").arg(command).env("HOME", home).output()).await;
                match ran {
                    Ok(Ok(done)) => (done.stdout, done.stderr, done.status.code().unwrap_or(1) as u32),
                    _ => (b"sh: not available\n".to_vec(), Vec::new(), 127),
                }
            }
            (None, None) => return session.channel_failure(channel),
        };
        session.channel_success(channel)?;
        session.data(channel, output)?;
        if !errors.is_empty() {
            // Error output on its own path, as with a real server.
            session.extended_data(channel, 1, errors)?;
        }
        session.exit_status_request(channel, status)?;
        session.eof(channel)?;
        session.close(channel)
    }

    async fn data(&mut self, channel: ChannelId, data: &[u8], session: &mut Session) -> Result<(), Self::Error> {
        if !self.shells.contains_key(&channel) {
            return Ok(());
        }
        for &byte in data {
            match byte {
                b'\r' | b'\n' => {
                    session.data(channel, b"\r\n".to_vec())?;
                    self.run_line(channel, session)?;
                    if !self.shells.contains_key(&channel) {
                        break;
                    }
                }
                _ => {
                    if let Some(line) = self.shells.get_mut(&channel) {
                        line.push(byte);
                    }
                    session.data(channel, vec![byte])?;
                }
            }
        }
        Ok(())
    }

    async fn subsystem_request(&mut self, channel: ChannelId, name: &str, session: &mut Session) -> Result<(), Self::Error> {
        match (name, self.files.as_ref(), self.pending.remove(&channel)) {
            ("sftp", Some(files), Some(stream)) => {
                session.channel_success(channel)?;
                russh_sftp::server::run(stream.into_stream(), files.session()).await;
            }
            _ => session.channel_failure(channel)?,
        }
        Ok(())
    }

    async fn channel_close(&mut self, channel: ChannelId, _session: &mut Session) -> Result<(), Self::Error> {
        self.pending.remove(&channel);
        self.shells.remove(&channel);
        self.sizes.remove(&channel);
        self.env.remove(&channel);
        Ok(())
    }
}

//! Kleiner SSH-Server für Tests. Er läuft im Prozess des Tests auf einem freien Port von 127.0.0.1.
//!
//! Die „Shell“ ist ein Stück Text: Sie wiederholt Eingaben wie ein Terminal und kennt ein paar Befehle,
//! mit denen sich das Verhalten des Clients prüfen lässt (`size`, `term`, `env`, `agent`, `exit`, `drop`).
//! Mit `Options::files` spricht er außerdem SFTP auf einem Ordner dieses Rechners (siehe `sftp`).

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
pub const GREETING: &str = "Willkommen beim Testserver\r\n";

#[derive(Clone, Default)]
pub struct Options {
    /// Benutzer und Passwort, mit denen die Anmeldung gelingt. `None` schaltet die Passwort-Anmeldung ab.
    pub password: Option<(String, String)>,
    pub authorized_keys: Vec<PublicKey>,
    /// Zertifizierungsstelle, deren Benutzer-Zertifikate der Server annimmt (wie `TrustedUserCAKeys`).
    pub user_ca: Option<PublicKey>,
    /// Zertifikat für den Schlüssel des Servers. Er zeigt es Clients, die danach fragen.
    pub host_certificate: Option<russh::keys::Certificate>,
    /// Heimatverzeichnis des Benutzers. Damit liest der Server `.ssh/authorized_keys` darin bei jeder Anmeldung neu
    /// und führt `exec`-Befehle wirklich aus (über `sh`, mit diesem Ordner als `$HOME`), wie ein echter Server.
    pub home: Option<PathBuf>,
    /// Darf der Server Verbindungen zu anderen Rechnern weiterreichen (`direct-tcpip`), also Sprung-Server sein?
    /// Dann lauscht er auf Wunsch auch selbst an einem Port und reicht herein, was dort ankommt (`tcpip-forward`).
    pub forwarding: bool,
    /// Der Server spricht nur Verfahren, die heute als schwach gelten, wie ein altes Netzwerkgerät.
    pub legacy_only: bool,
    /// Text, den der Server vor der Anmeldung zeigt.
    pub banner: Option<String>,
    /// Feste Antwort auf `exec`-Aufrufe, etwa der Inhalt von `/etc/os-release`. Mit `home` gilt sie nur noch für
    /// Befehle, die `uname -s` enthalten (so fragt der Client nach dem Betriebssystem).
    pub exec_output: Option<String>,
    /// Ordner dieses Rechners, den der Server über SFTP als sein Dateisystem zeigt. Ohne ihn gibt es kein SFTP.
    pub files: Option<PathBuf>,
    /// Pfade im Dateisystem des Servers, unter denen SFTP nichts ändern darf (etwa `/etc`).
    pub files_read_only: Vec<String>,
    /// Ein nachgestelltes Linux mit Docker, systemd und procps: Befehle der Verwaltung beantwortet der Server
    /// dann aus diesem Stand, statt sie auszuführen (siehe [`admin`]).
    pub admin: Option<std::sync::Arc<std::sync::Mutex<admin::Admin>>>,
    /// Pause vor jedem Lesen und Schreiben über SFTP, damit ein Test einen Transfer mittendrin erwischt.
    pub files_delay: Option<Duration>,
    /// `mosh-server` im WSL samt Weiterleitung für UDP (siehe [`mosh`]). Ohne sie gibt es hier kein mosh.
    pub mosh: Option<mosh::Bridge>,
}

/// Zertifikat für einen Server-Schlüssel, ausgestellt von `ca` für die Adresse `name`, einen Tag lang gültig.
pub fn host_certificate(ca: &PrivateKey, host_key: &PrivateKey, name: &str) -> Option<russh::keys::Certificate> {
    use russh::keys::ssh_key::certificate::{Builder, CertType};
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
    let mut builder = Builder::new_with_random_nonce(&mut rand::rng(), host_key.public_key().key_data().clone(), now - 60, now + 86_400).ok()?;
    builder.cert_type(CertType::Host).ok()?.key_id("glowport-testserver").ok()?.valid_principal(name).ok()?;
    builder.sign(ca).ok()
}

/// Fester Schlüssel aus einem Startwert, damit Tests denselben Fingerabdruck wiedersehen.
pub fn key(seed: u8) -> PrivateKey {
    PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]))
}

pub struct Running {
    pub address: SocketAddr,
    /// Das Dateisystem hinter SFTP, falls der Server eines zeigt.
    pub files: Option<sftp::Files>,
    task: JoinHandle<()>,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Startet den Server im laufenden tokio-Runtime.
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
        // Keine Bremse gegen Passwort-Raten: Sie würde nur die Tests verlangsamen.
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
    /// Geöffnete Kanäle, bis feststeht, wofür sie gebraucht werden.
    pending: HashMap<ChannelId, Channel<Msg>>,
    /// Bisher getippte Zeile je Shell.
    shells: HashMap<ChannelId, Vec<u8>>,
    sizes: HashMap<ChannelId, (u32, u32)>,
    /// Umgebungsvariablen, die der Client für eine Shell gesetzt hat.
    env: HashMap<ChannelId, Vec<(String, String)>>,
    /// Kanäle, für die der Client seinen Agenten weiterreicht.
    agent: Vec<ChannelId>,
    /// Terminal-Typ je Kanal, wie ihn der Client angefordert hat.
    terms: HashMap<ChannelId, String>,
    /// Ports, an denen der Server für den Client lauscht (`tcpip-forward`). Sie enden mit der Verbindung.
    listeners: HashMap<(String, u32), Listening>,
}

/// Bricht das Lauschen ab, sobald der Eintrag wegfällt.
struct Listening(JoinHandle<()>);

impl Drop for Listening {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl Connection {
    /// Wie OpenSSH: Nach einem Fehlversuch bleiben alle Methoden im Angebot.
    fn reject(&self) -> Auth {
        Auth::Reject { proceed_with_methods: Some(self.methods.clone()), partial_success: false }
    }

    /// Verglichen wird der Schlüssel selbst. Der Kommentar aus einer `.pub`-Datei gehört nicht dazu und kommt
    /// über die Leitung auch nicht mit.
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
            // Verbindung ohne Abschied kappen, so wie ein Netzabriss aus Sicht des Clients aussieht.
            "drop" => return session.disconnect(Disconnect::ByApplication, "", ""),
            "size" => {
                let (columns, rows) = self.sizes.get(&channel).copied().unwrap_or((0, 0));
                session.data(channel, format!("{columns}x{rows}\r\n").into_bytes())?;
            }
            // Fragt den weitergereichten Agenten des Clients und nennt die Fingerabdrücke seiner Schlüssel.
            "agent" if self.agent.contains(&channel) => {
                let handle = session.handle();
                // Als eigene Aufgabe: Die Antwort auf das Öffnen des Kanals kommt über dieselbe Verbindung.
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
                        None => "Agent antwortet nicht\r\n".to_string(),
                    };
                    let _ = handle.data(channel, format!("{text}{PROMPT}").into_bytes()).await;
                });
                return Ok(());
            }
            "agent" => session.data(channel, b"kein Agent\r\n".to_vec())?,
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

    /// Nimmt ein Zertifikat an, wenn die vertraute Stelle es unterschrieben hat, es gerade gilt und den Benutzer nennt.
    async fn auth_openssh_certificate(&mut self, user: &str, certificate: &russh::keys::Certificate) -> Result<Auth, Self::Error> {
        let trusted = self.options.user_ca.as_ref().is_some_and(|ca| certificate.validate([&ca.fingerprint(Default::default())]).is_ok());
        Ok(if trusted && certificate.valid_principals().iter().any(|principal| principal == user) { Auth::Accept } else { self.reject() })
    }

    // Die Bibliothek fragt hier auch für den Schlüssel in einem Zertifikat. Ob das Zertifikat gilt, entscheidet erst
    // `auth_openssh_certificate`; ein bloßer Schlüssel scheitert danach in `auth_publickey`.
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

    /// Sprung-Server: reicht den Kanal an den gewünschten Rechner weiter, wenn es erlaubt ist und er erreichbar ist.
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
        // Für Tests: Dieses Ziel kappt die Verbindung, so wie ein Netzabriss aus Sicht des Clients aussieht.
        if host_to_connect == "disconnect.test" {
            return session.disconnect(Disconnect::ByApplication, "", "");
        }
        let target = match u16::try_from(port_to_connect) {
            Ok(port) if self.options.forwarding => tokio::net::TcpStream::connect((host_to_connect, port)).await.ok(),
            _ => None,
        };
        let Some(mut target) = target else {
            // Ohne Zusage gilt die Anfrage als abgelehnt.
            return Ok(());
        };
        reply.accept().await;
        tokio::spawn(async move {
            let mut stream = channel.into_stream();
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut target).await;
        });
        Ok(())
    }

    /// Lauscht für den Client an einem Port dieses Rechners und reicht jede Verbindung als Kanal zu ihm zurück.
    async fn tcpip_forward(&mut self, address: &str, port: &mut u32, session: &mut Session) -> Result<bool, Self::Error> {
        if !self.options.forwarding {
            return Ok(false);
        }
        let Ok(wanted) = u16::try_from(*port) else { return Ok(false) };
        // Wie ein Server ohne `GatewayPorts`: immer nur an der eigenen Adresse.
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
                // Vorwärts-Schrägstriche, damit auch die Shell von Git für Windows den Pfad versteht.
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
            // Fehlerausgabe auf ihrem eigenen Weg, wie bei einem echten Server.
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

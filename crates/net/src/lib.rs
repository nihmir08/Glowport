//! SSH-Verbindung für ein Terminal: verbinden, Host-Schlüssel vorlegen, anmelden, Shell.
//!
//! Dieses Crate kennt weder Tresor noch Oberfläche. Wer eine Sitzung öffnet, bekommt einen Strom von
//! [`Event`]s und schickt [`Command`]s zurück. Rückfragen (Host-Schlüssel, Passwort) kommen als Ereignis
//! mit einem Antwortkanal; ob ein Host-Schlüssel schon bekannt ist, entscheidet der Aufrufer.

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

/// Wie oft nach Passwort oder Passphrase gefragt wird. Server brechen nach wenigen Fehlversuchen ab (`MaxAuthTries`).
const MAX_SECRET_PROMPTS: u32 = 3;
const MAX_INTERACTIVE_ROUNDS: u32 = 10;
/// Server zählen jeden angebotenen Schlüssel als Versuch (`MaxAuthTries`, meist 6). Mehr aus einem Agenten
/// anzubieten, würde die übrigen Wege verbauen.
const MAX_AGENT_KEYS: usize = 4;
const MAX_BANNER: usize = 4000;
const EXECUTE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_EXECUTE_OUTPUT: usize = 64 * 1024;

#[derive(Clone)]
pub struct Connect {
    pub host: String,
    pub port: u16,
    pub user: String,
    /// Gespeichertes Passwort; wird vor jeder Rückfrage versucht.
    pub password: Option<Secret>,
    /// Privater Schlüssel aus dem Tresor im OpenSSH-Format, ohne Passphrase. Wird als Erstes versucht.
    pub key: Option<Secret>,
    /// Benutzer-Zertifikat zu `key`. Damit wird zuerst angemeldet, danach mit dem Schlüssel allein.
    pub certificate: Option<String>,
    pub key_file: Option<PathBuf>,
    /// Agenten, deren Schlüssel für die Anmeldung angeboten werden. `None`: kein Agent.
    pub agent: Option<Agents>,
    /// Den Agenten an den Server weiterreichen, damit von dort aus weiterverbunden werden kann. Wirkt nur mit `agent`.
    pub agent_forward: bool,
    /// Station, über die verbunden wird (Sprung-Server). Sie hat ihre eigene Anmeldung und kann selbst wieder
    /// über eine Station gehen.
    pub jump: Option<Box<Connect>>,
    /// Befehl, der nach dem Anmelden in die Shell getippt wird.
    pub startcmd: Option<String>,
    /// Umgebungsvariablen für die Shell. Ein Server nimmt nur an, was sein `AcceptEnv` erlaubt.
    pub env: Vec<(String, String)>,
    /// Marke des Aufrufers für diese Station, etwa die Kennung des Hosts im Tresor. Sie kommt in den Ereignissen zurück.
    pub tag: Option<String>,
    /// Öffentliche Schlüssel der Zertifizierungsstellen, denen für diese Adresse vertraut wird. Zeigt der Server
    /// ein gültiges Zertifikat einer dieser Stellen, gilt sein Schlüssel ohne Rückfrage.
    pub authorities: Vec<String>,
    /// Proxy für die erste Verbindung nach draußen. Hinter einem Sprung-Server gibt es keinen: Dorthin führt sein Tunnel.
    pub proxy: Option<Proxy>,
    /// Abstand der Lebenszeichen, die NAT und Firewalls offen halten und einen stillen Abriss bemerken. Null schaltet sie ab.
    pub keepalive: Duration,
    /// Wie lange auf das Zustandekommen der Verbindung gewartet wird.
    pub timeout: Duration,
    /// Terminal-Typ, den die Shell als `TERM` sieht.
    pub term: String,
    /// Auch Verfahren anbieten, die heute als schwach gelten (SHA-1, CBC, kleine DH-Gruppen), für alte Geräte.
    pub legacy: bool,
    /// Spalten und Zeilen des Terminals beim Verbinden, damit die Breite ab dem ersten Byte stimmt.
    pub size: (u32, u32),
    /// Nach dem Anmelden das Betriebssystem bestimmen (für das Symbol des Hosts).
    pub detect_os: bool,
    /// Das Terminal über Mosh statt über eine SSH-Shell führen. Gilt nur für das Ziel, nicht für Sprung-Server.
    pub mosh: Option<Mosh>,
}

/// Die Station einer Verbindung, um die es in einem Ereignis geht: das Ziel selbst oder ein Sprung-Server davor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Station {
    /// `benutzer@adresse`, mit Port, wenn es nicht 22 ist.
    pub label: String,
    /// Die Marke aus [`Connect::tag`].
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

/// Arten von Server-Schlüsseln, für die nach einem Zertifikat gefragt wird, wenn eine Zertifizierungsstelle gilt.
const CERTIFIED_HOST_KEYS: &[Algorithm] = &[
    Algorithm::Ed25519,
    Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 },
    Algorithm::Ecdsa { curve: EcdsaCurve::NistP384 },
    Algorithm::Ecdsa { curve: EcdsaCurve::NistP521 },
    Algorithm::Rsa { hash: Some(HashAlg::Sha512) },
    Algorithm::Rsa { hash: Some(HashAlg::Sha256) },
];

/// Die sicheren Verfahren zuerst, dahinter die alten. Ein Server, der Besseres kann, bekommt weiterhin das Bessere.
fn legacy_preferred() -> Preferred {
    let safe = Preferred::default();
    // Die letzten Einträge der Liste sind keine Verfahren, sondern Merker für Erweiterungen; die alten kommen davor.
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

/// Warum eine Sitzung endete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum End {
    /// Vom Nutzer beendet oder eine Rückfrage abgebrochen.
    User,
    /// Die Shell hat sich beendet, etwa nach `exit`.
    Remote { exit_status: Option<u32> },
    ConnectFailed(String),
    HostKeyRejected,
    AuthFailed,
    ConnectionLost(String),
    /// Der Server hat etwas abgelehnt, ohne das es nicht geht, etwa das Lauschen an einem Port. Der Text nennt, was.
    Refused(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKey {
    pub algorithm: String,
    /// Fingerabdruck wie bei OpenSSH: `SHA256:…`.
    pub fingerprint: String,
    /// Öffentlicher Schlüssel im OpenSSH-Format, zum Wiedererkennen beim nächsten Verbinden.
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
    /// Darf die Eingabe sichtbar sein?
    pub echo: bool,
}

pub enum Event {
    Phase(Phase),
    Banner(String),
    /// Der Server unter `host:port` zeigt seinen Schlüssel. Antwort `true` = vertrauen und weitermachen.
    HostKey { host: String, port: u16, key: HostKey, reply: oneshot::Sender<bool> },
    /// Passwort oder Passphrase wird gebraucht. `None` bricht das Verbinden ab.
    Secret { station: Station, kind: SecretKind, attempt: u32, reply: oneshot::Sender<Option<Secret>> },
    /// Fragen des Servers (`keyboard-interactive`), etwa ein Einmalcode.
    Interactive { station: Station, name: String, instructions: String, prompts: Vec<Prompt>, reply: oneshot::Sender<Option<Vec<Secret>>> },
    /// Ein frisch eingegebenes Passwort hat funktioniert; der Aufrufer kann anbieten, es zu speichern.
    PasswordAccepted { station: Station, password: Secret },
    /// Etwas ging schief, ohne dass die Verbindung daran scheitert.
    Notice { code: &'static str, message: String },
    /// Kürzel des erkannten Betriebssystems (siehe `os::classify`).
    Os(String),
    Output(Vec<u8>),
    /// Stand einer Mosh-Sitzung (siehe [`mosh`]).
    Mosh(MoshEvent),
    /// SFTP steht. Kommt nur bei [`files::open`] und ist dort das letzte Ereignis.
    Files(files::Remote),
    /// Die Weiterleitung steht. Kommt nur bei [`forward::open`] und ist dort das letzte Ereignis.
    Forward(forward::Tunnel),
    End(End),
}

pub enum Command {
    Input(Vec<u8>),
    Resize(u32, u32),
    /// Lesen anhalten oder fortsetzen. Angehalten staut sich die Ausgabe beim Server, nicht im Speicher.
    Pause(bool),
    /// Öffnet einen zusätzlichen Kanal auf derselben Verbindung, für SFTP oder einen einzelnen Befehl.
    /// `None`, wenn der Server keinen weiteren hergibt oder die Shell noch nicht steht.
    Open(oneshot::Sender<Option<files::Opened>>),
    /// Nur bei Mosh: die SSH-Verbindung daneben neu aufbauen, mit Rückfragen, falls nötig.
    Relink,
    Close,
}

pub struct Session {
    pub commands: mpsc::UnboundedSender<Command>,
    pub events: mpsc::Receiver<Event>,
}

/// Öffnet eine Sitzung. Muss in einem tokio-Runtime aufgerufen werden; die Arbeit läuft in einer eigenen Aufgabe.
pub fn open(connect: Connect) -> Session {
    let (event_tx, events) = mpsc::channel(256);
    let (commands, command_rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let end = run(connect, &event_tx, command_rx).await.unwrap_or_else(|end| end);
        let _ = event_tx.send(Event::End(end)).await;
    });
    Session { commands, events }
}

/// Was ein einzelner Befehl auf einem Host ergeben hat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub stdout: Vec<u8>,
    pub exit_status: Option<u32>,
    /// Die Ausgabe war länger als erlaubt; der Rest fehlt.
    pub truncated: bool,
}

/// Meldung in [`End::ConnectionLost`], wenn ein Befehl länger lief als erlaubt (siehe [`run_command`]).
pub const COMMAND_TIMED_OUT: &str = "command timed out";

/// Sammelt, was ein Befehl ausgibt, bis zu `max` Bytes; mit `stderr` auch seine Fehlerausgabe, in der Reihenfolge
/// des Eintreffens.
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

/// Meldet sich ohne jede Rückfrage an, führt einen Befehl aus und trennt wieder.
///
/// `trusted` entscheidet über den Schlüssel jedes Servers auf dem Weg (Adresse, Port, Schlüssel). Bräuchte die
/// Anmeldung eine Rückfrage (Passwort, Passphrase, Fragen des Servers), gilt sie als gescheitert: Hier sitzt
/// niemand, der antworten könnte.
pub async fn execute(connect: &Connect, command: &str, trusted: impl Fn(&str, u16, &HostKey) -> bool) -> Result<Output, End> {
    match timeout(EXECUTE_TIMEOUT, silently(connect, command, trusted, EXECUTE_TIMEOUT, MAX_EXECUTE_OUTPUT, false)).await {
        Ok(result) => result,
        Err(_) => Err(End::ConnectFailed("timed out".into())),
    }
}

/// Wie [`execute`], für Befehle des Nutzers: Er darf `limit` lang laufen und bis zu `max` Bytes ausgeben, und seine
/// Fehlerausgabe gehört zum Ergebnis. Läuft er länger, endet es mit [`End::ConnectionLost`] und
/// [`COMMAND_TIMED_OUT`]. Der Befehl bekommt kein Terminal und keine Eingabe.
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
        // Eine abgebrochene Rückfrage endet als „vom Nutzer beendet“; hier heißt das: Die hinterlegten Daten reichen nicht.
        let link = establish(connect, &event_tx).await.map_err(|end| if end == End::User { End::AuthFailed } else { end })?;
        let handle = &link.handle;
        let mut channel = handle.channel_open_session().await.map_err(lost)?;
        channel.exec(true, command).await.map_err(lost)?;
        // Niemand tippt etwas ein: Ein Befehl, der auf Eingabe wartet, soll das gleich merken.
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

/// Schickt ein Ereignis. Hört niemand mehr zu, endet die Sitzung wie vom Nutzer beendet.
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

    // Bis die Shell steht, zählt von den Befehlen nur „Schließen“; die letzte gemeldete Größe wird gemerkt.
    let size = Mutex::new(connect.size);
    // Bei Mosh merkt sich die Sitzung, was beim Anmelden bestätigt wurde: Damit kommt die SSH-Verbindung daneben
    // nach einem Abriss ohne Rückfrage wieder.
    let remembered = Arc::new(Mutex::new(mosh::Memory::default()));
    let memory = connect.mosh.is_some().then_some(&remembered);
    // Die Stationen davor bleiben in `link` offen, solange die Sitzung läuft.
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
            // Mosh geht hier nicht: Die SSH-Verbindung steht, also wird es eine gewöhnliche Shell.
            Err(Ok(fallback)) => emit(events, Event::Mosh(MoshEvent::Fallback(fallback))).await?,
            Err(Err(end)) => return Err(end),
        }
    }

    let handle = &link.handle;
    let (columns, rows) = *size.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

    let channel = handle.channel_open_session().await.map_err(lost)?;
    channel.request_pty(false, connect.term.as_str(), columns, rows, 0, 0, &[]).await.map_err(lost)?;
    if connect.agent_forward && connect.agent.is_some() {
        // Ohne Antwort: Verbietet der Server das Weiterreichen, läuft die Sitzung ohne.
        channel.agent_forward(false).await.map_err(lost)?;
    }
    for (name, value) in &connect.env {
        // Ohne Antwort: Lehnt der Server eine Variable ab, soll die Sitzung daran nicht scheitern.
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

/// Reicht Ausgabe und Eingabe durch, bis die Shell endet, die Verbindung abreißt oder der Nutzer schließt.
async fn shell(handle: &Handle<Client>, channel: russh::Channel<client::Msg>, events: &mpsc::Sender<Event>, commands: &mut mpsc::UnboundedReceiver<Command>) -> Result<End, End> {
    // Getrennte Hälften: Stockt das Senden, wird trotzdem weiter gelesen.
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
    /// Adresse, unter der dieser Server angesprochen wurde; an ihr hängt das Vertrauen in seinen Schlüssel.
    host: String,
    port: u16,
    /// Gesetzt, wenn der Agent an diesen Server weitergereicht werden darf.
    forward: Option<Agents>,
    /// Zertifizierungsstellen, denen für diese Adresse vertraut wird.
    authorities: Vec<PublicKey>,
    /// Wohin Verbindungen gehen, die der Server von einem seiner Ports hereinreicht. Leer, solange keine Regel
    /// darum gebeten hat; dann wird jede abgelehnt.
    forwarded: Forwarded,
    /// Bei Mosh: Hier landet, welcher Server-Schlüssel bestätigt wurde.
    memory: Option<mosh::Shared>,
}

/// Annahmestelle für Verbindungen, die ein Server hereinreicht (`forwarded-tcpip`).
type Forwarded = Arc<Mutex<Option<mpsc::UnboundedSender<russh::Channel<client::Msg>>>>>;

impl Client {
    /// Hat eine vertraute Stelle diesem Server bescheinigt, dass ihm der Schlüssel unter dieser Adresse gehört?
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
        // Ohne gültiges Zertifikat zählt nur der Schlüssel selbst: nachsehen, ob er bekannt ist, sonst fragen.
        let key = server_key.public_key();
        let info = HostKey { algorithm: key.algorithm().to_string(), fingerprint: key.fingerprint(HashAlg::Sha256).to_string(), openssh: key.to_openssh().unwrap_or_default() };
        let (reply, answer) = oneshot::channel();
        // Ohne Antwort gilt der Schlüssel als abgelehnt: Im Zweifel wird nicht verbunden.
        let accepted = self.events.send(Event::HostKey { host: self.host.clone(), port: self.port, key: info, reply }).await.is_ok() && answer.await.unwrap_or(false);
        if !accepted {
            self.rejected.store(true, Ordering::Relaxed);
        } else if let Some(memory) = &self.memory {
            mosh::remember_key(memory, &self.host, self.port, &key.fingerprint(HashAlg::Sha256).to_string());
        }
        Ok(accepted)
    }

    // Der Text kommt von einem Server, bei dem noch niemand angemeldet ist: nur druckbare Zeichen, begrenzt lang.
    async fn auth_banner(&mut self, banner: &str, _session: &mut client::Session) -> Result<(), Self::Error> {
        let text: String = banner.chars().filter(|c| *c == '\n' || !c.is_control()).take(MAX_BANNER).collect();
        if !text.trim().is_empty() {
            let _ = self.events.send(Event::Banner(text)).await;
        }
        Ok(())
    }

    /// Der Server möchte den Agenten benutzen. Das geht nur, wenn es für diese Verbindung erlaubt wurde.
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

    /// Der Server reicht eine Verbindung herein, die an einem seiner Ports angekommen ist. Angenommen wird sie nur,
    /// wenn eine Port-Regel dieser Verbindung darum gebeten hat.
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

/// Eine aufgebaute, angemeldete Verbindung samt den Stationen davor. Die müssen offen bleiben, solange sie lebt.
struct Link {
    handle: Handle<Client>,
    /// Adresse der Gegenstelle, wenn direkt verbunden (ohne Proxy und Sprung-Server). Mosh schickt UDP dorthin.
    peer: Option<SocketAddr>,
    _hops: Vec<Handle<Client>>,
    /// Annahmestelle des Ziels für hereingereichte Verbindungen; siehe [`forward`].
    forwarded: Forwarded,
}

/// Weg zum Server (direkt oder durch die Stationen davor), Schlüsselaustausch, Host-Schlüssel vorlegen, anmelden.
/// Liefert einen `Box`, weil sich die Funktion für jede Station selbst aufruft.
fn establish<'a>(connect: &'a Connect, events: &'a mpsc::Sender<Event>) -> Pin<Box<dyn Future<Output = Result<Link, End>> + Send + 'a>> {
    establish_with(connect, events, None)
}

/// Wie [`establish`]; mit `memory` merkt sich die Verbindung bestätigte Server-Schlüssel und angenommene Passwörter
/// (für Mosh, siehe [`mosh::Memory`]).
fn establish_with<'a>(connect: &'a Connect, events: &'a mpsc::Sender<Event>, memory: Option<&'a mosh::Shared>) -> Pin<Box<dyn Future<Output = Result<Link, End>> + Send + 'a>> {
    Box::pin(async move {
        let config = Arc::new(client::Config {
            client_id: SshId::Standard(concat!("SSH-2.0-Glowport_", env!("CARGO_PKG_VERSION")).into()),
            keepalive_interval: (!connect.keepalive.is_zero()).then_some(connect.keepalive),
            keepalive_max: 3,
            preferred: Preferred {
                // Nur wenn eine Stelle für diese Adresse gilt: Sonst wüsste niemand, was ein Zertifikat wert ist.
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
                // Die Station öffnet die Verbindung zum nächsten Server; darüber läuft eine eigene SSH-Verbindung.
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

/// Meldet sich mit einem Schlüssel an. `None`: angenommen. Sonst die Methoden, die der Server danach noch zulässt.
async fn offer_key(handle: &mut Handle<Client>, user: &str, key: PrivateKey) -> Result<Option<MethodSet>, End> {
    let rsa_hash = handle.best_supported_rsa_hash().await.ok().flatten().flatten();
    match handle.authenticate_publickey(user, PrivateKeyWithHashAlg::new(Arc::new(key), rsa_hash)).await.map_err(lost)? {
        AuthResult::Success => Ok(None),
        AuthResult::Failure { remaining_methods, .. } => Ok(Some(remaining_methods)),
    }
}

/// Reihenfolge: Schlüssel aus dem Tresor, Schlüssel aus dem Agenten, Schlüsseldatei, gespeichertes Passwort,
/// Passwort-Rückfrage, Fragen des Servers.
async fn authenticate(connect: &Connect, events: &mpsc::Sender<Event>, handle: &mut Handle<Client>, memory: Option<&mosh::Shared>) -> Result<(), End> {
    let user = connect.user.as_str();
    let station = connect.station();

    // „none“ gelingt fast nie, liefert aber die Liste der Methoden, die der Server zulässt.
    let mut methods = match handle.authenticate_none(user).await.map_err(lost)? {
        AuthResult::Success => return Ok(()),
        AuthResult::Failure { remaining_methods, .. } => remaining_methods,
    };
    // Nimmt der Server nur Schlüssel an und ist für diese Verbindung keiner vorgesehen, gibt es nichts zu fragen:
    // Die Anmeldung scheitert gleich. Dann soll dastehen, woran es liegt.
    let keys_only = !allows(&methods, MethodKind::Password) && !allows(&methods, MethodKind::KeyboardInteractive);
    let without_key = connect.key.is_none() && connect.agent.is_none() && connect.key_file.is_none();

    if let Some(text) = connect.key.as_ref().filter(|_| allows(&methods, MethodKind::PublicKey)) {
        match PrivateKey::from_openssh(text.as_str()) {
            Ok(key) => {
                // Mit Zertifikat zuerst: Ein Server, der einer Zertifizierungsstelle vertraut, kennt den bloßen Schlüssel nicht.
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
                    // Der Agent unterschreibt nicht (gesperrt, abgelehnt, weg): weiter mit dem nächsten Agenten.
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

/// Liest die Schlüsseldatei und fragt bei Bedarf nach der Passphrase. `None`: Die Datei ist unbrauchbar,
/// das Anmelden geht mit den anderen Wegen weiter.
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

// Das Entschlüsseln (bcrypt-pbkdf) rechnet spürbar; nicht auf einem Thread des Runtimes.
async fn decode_key(path: &Path, passphrase: Option<Secret>) -> Result<PrivateKey, russh::keys::Error> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || russh::keys::load_secret_key(path, passphrase.as_ref().map(|p| p.as_str())))
        .await
        .unwrap_or(Err(russh::keys::Error::CouldNotReadKey))
}

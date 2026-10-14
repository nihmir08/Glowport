//! Laufende Sitzungen: bringt Verbindungskern (`glowport-net`), die übrigen Terminals (`glowport-extras`: Shells
//! dieses Rechners, Telnet, serielle Leitung), Tresor und Oberfläche zusammen.
//!
//! Je Sitzung läuft eine Aufgabe, die Ereignisse des Verbindungskerns weiterreicht: Terminal-Ausgabe als rohe
//! Bytes über einen eigenen Kanal, alles andere als Ereignis `session`. Rückfragen warten hier auf die Antwort
//! der Oberfläche. Sitzungen überleben das Sperren des Tresors; nur das Speichern von Host-Schlüsseln und
//! Passwörtern braucht ihn offen.
//!
//! Jede Sitzung gehört einem Fenster. Zieht ihr Tab in ein anderes Fenster um, wird sie angehalten
//! (`session_hold`), die Ausgabe so lange gesammelt und vom neuen Fenster wieder aufgenommen (`session_attach`).
//! Die Verbindung selbst merkt davon nichts.

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex, MutexGuard,
    },
    time::Duration,
};

use encoding_rs::Encoding;

use glowport_core::{
    directory::{ConnectInfo, Directory, Endpoint, MoshInfo, Verdict},
    model::{self, ProxyKind},
};
use glowport_extras::{local, serial, telnet};
use glowport_net::{self as net, Command, Connect, End, Event, MoshEvent, Phase, Secret, SecretKind};
use serde::{Deserialize, Serialize};
use tauri::{
    ipc::{Channel, InvokeResponseBody},
    AppHandle, Emitter, Manager, State, Window,
};
use tokio::sync::{mpsc::UnboundedSender, oneshot};
use zeroize::Zeroizing;

use crate::{
    app::{emit_snapshot, AppState, CmdError, CmdResult},
    recordings::{self, Recorder, Recording},
};

/// Flusskontrolle: Über dieser Menge unbestätigter Ausgabe wird das Lesen angehalten (der Server wird gebremst),
/// darunter geht es weiter. Werte wie bei NexusSSH.
const PAUSE_ABOVE: usize = 1024 * 1024;
const RESUME_BELOW: usize = 256 * 1024;

#[derive(Default)]
pub struct Sessions {
    next: AtomicU64,
    live: Mutex<HashMap<u64, Live>>,
}

struct Live {
    commands: UnboundedSender<Command>,
    /// Fenster, dem die Sitzung gehört. Nur dort kommen ihre Ereignisse an.
    window: String,
    /// Wohin die Terminal-Ausgabe geht. Fehlt, während die Sitzung das Fenster wechselt.
    output: Option<Channel<InvokeResponseBody>>,
    /// Ausgabe, die während des Fensterwechsels angefallen ist.
    backlog: Vec<u8>,
    phase: &'static str,
    /// Die eine Rückfrage, auf deren Antwort die Sitzung gerade wartet.
    pending: Option<Pending>,
    /// Dieselbe Rückfrage in der Form für die Oberfläche, um sie einem neuen Fenster noch einmal zu zeigen.
    asking: Option<SessionEvent>,
    /// Schreibt die Ausgabe in eine Datei mit, solange gesetzt.
    recorder: Option<Recorder>,
    unacked: usize,
    paused: bool,
    /// Der Nutzer will das gerade eingegebene Passwort speichern, falls es funktioniert.
    save_password: bool,
    /// Der Nutzer will die Schlüsseldatei, deren Passphrase er gerade eingegeben hat, in den Tresor übernehmen.
    adopt_key: Option<AdoptKey>,
    /// Zeichensatz des Servers, wenn er nicht UTF-8 ist. Eingaben werden dann vor dem Senden umgewandelt.
    charset: Option<&'static Encoding>,
    /// Kennung des gespeicherten Hosts, zu dem die Sitzung führt; fehlt bei einer eingetippten Adresse.
    host_id: Option<String>,
    /// Name des Hosts oder die Adresse, zum Anzeigen etwa in der Liste der Transfers.
    label: String,
    /// Das Terminal läuft über Mosh.
    mosh: bool,
}

/// Eine Schlüsseldatei, die nach geglückter Anmeldung in den Tresor soll, und der Host, der sie dann benutzt.
struct AdoptKey {
    file: String,
    host: String,
    passphrase: Zeroizing<String>,
}

enum Pending {
    HostKey { reply: oneshot::Sender<bool>, key: net::HostKey, host: String, port: u16 },
    /// `key_file`: Die Frage gilt der Passphrase dieser Datei, verlangt für den gespeicherten Host mit dieser Kennung.
    Secret { reply: oneshot::Sender<Option<Secret>>, key_file: Option<(String, String)> },
    Interactive(oneshot::Sender<Option<Vec<Secret>>>),
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum Target {
    /// Gespeicherter Host aus dem Tresor.
    Host { id: String },
    /// Schnellverbindung ohne gespeicherten Host. `identity` und `key` nennen wahlweise eine Identität oder einen
    /// Schlüssel aus dem Tresor, mit denen sie sich anmeldet (so verbindet die Seite „Proxmox“ zu einer Maschine,
    /// die noch kein Host ist); mit einer Identität gilt deren Benutzer.
    Direct {
        user: String,
        host: String,
        port: u16,
        #[serde(default)]
        identity: Option<String>,
        #[serde(default)]
        key: Option<String>,
        /// `mosh benutzer@host`: angemeldet per SSH, das Terminal über Mosh.
        #[serde(default)]
        mosh: bool,
    },
    /// Schnellverbindung über Telnet.
    Telnet { host: String, port: u16 },
    /// Eine Shell dieses Rechners; `shell` ist ihre Kennung aus `local_shells`.
    Local { shell: String },
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum Answer {
    HostKey {
        accept: bool,
    },
    /// `value` fehlt, wenn der Nutzer abgebrochen hat.
    Secret {
        value: Option<String>,
        #[serde(default)]
        save: bool,
    },
    Interactive {
        values: Option<Vec<String>>,
    },
    /// Das Zertifikat eines FTP-Servers.
    Certificate {
        accept: bool,
    },
    /// Die Warnung vor einer unverschlüsselten FTP-Verbindung. `remember` bestellt sie für den Host ab, `secure`
    /// stellt ihn stattdessen auf FTPS um.
    Plain {
        accept: bool,
        #[serde(default)]
        remember: bool,
        #[serde(default)]
        secure: bool,
    },
}

#[derive(Serialize, Clone)]
pub(crate) struct PromptView {
    text: String,
    echo: bool,
}

#[derive(Serialize, Clone)]
#[serde(tag = "type", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub(crate) enum SessionEvent {
    Phase { phase: &'static str },
    Banner { text: String },
    Notice { code: &'static str, message: String },
    HostKey { host: String, port: u16, algorithm: String, fingerprint: String, changed: bool, known: Vec<String> },
    /// `station` ist gesetzt, wenn nicht das Ziel fragt, sondern ein Sprung-Server davor (`benutzer@adresse`).
    Secret { kind: &'static str, attempt: u32, file: Option<String>, can_save: bool, station: Option<String> },
    Interactive { name: String, instructions: String, prompts: Vec<PromptView>, station: Option<String> },
    /// Das Zertifikat eines FTP-Servers, dem dieser Rechner nicht von sich aus traut (`changed`: ein anderes als das bestätigte).
    Certificate { host: String, port: u16, fingerprint: String, changed: bool },
    /// Vor einer unverschlüsselten FTP-Verbindung. `can_remember`: Die Frage lässt sich für diesen Host abbestellen.
    Plain { host: String, offers_tls: bool, can_remember: bool },
    /// Mosh: `active` (das Terminal läuft darüber) oder `fallback` (per SSH, `reason` sagt warum).
    Mosh {
        state: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<&'static str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },
    /// Mosh: Sekunden ohne Nachricht vom Server; `None`, sobald er wieder antwortet.
    Reach { silent: Option<u32> },
    /// Mosh: Steht die SSH-Verbindung daneben für Seitenleiste und Dateien?
    Side { linked: bool },
    End { reason: &'static str, message: Option<String>, exit_status: Option<u32> },
}

#[derive(Serialize, Clone)]
struct Envelope {
    id: u64,
    /// Fenster, dem die Sitzung gehört. Die anderen Fenster übergehen das Ereignis.
    window: String,
    #[serde(flatten)]
    event: SessionEvent,
}

impl Sessions {
    fn live(&self) -> MutexGuard<'_, HashMap<u64, Live>> {
        self.live.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn send(&self, id: u64, command: Command) {
        if let Some(live) = self.live().get(&id) {
            let _ = live.commands.send(command);
        }
    }
}

/// Eine neue Nummer für etwas, das wie eine Sitzung Ereignisse schickt und Antworten bekommt.
pub(crate) fn number(app: &AppHandle) -> u64 {
    app.state::<Sessions>().next.fetch_add(1, Ordering::Relaxed) + 1
}

pub(crate) fn emit_to(app: &AppHandle, window: String, id: u64, event: SessionEvent) {
    let _ = app.emit("session", Envelope { id, window, event });
}

fn emit(app: &AppHandle, id: u64, event: SessionEvent) {
    let window = app.state::<Sessions>().live().get(&id).map(|live| live.window.clone());
    if let Some(window) = window {
        emit_to(app, window, id, event);
    }
}

/// Beendet alle Sitzungen eines Fensters, das geschlossen wurde. Ohne Fenster sähe niemand mehr ihre Ausgabe.
pub fn close_window(app: &AppHandle, window: &str) {
    crate::ftp::close_window(app, window);
    for live in app.state::<Sessions>().live().values().filter(|live| live.window == window) {
        let _ = live.commands.send(Command::Close);
    }
}

fn end_event(end: End) -> SessionEvent {
    let (reason, message, exit_status) = match end {
        End::User => ("user", None, None),
        End::Remote { exit_status } => ("remote", None, exit_status),
        End::ConnectFailed(message) => ("connect_failed", Some(message), None),
        End::HostKeyRejected => ("host_key_rejected", None, None),
        End::AuthFailed => ("auth_failed", None, None),
        End::ConnectionLost(message) => ("connection_lost", Some(message), None),
        End::Refused(message) => ("remote_refused", Some(message), None),
    };
    SessionEvent::End { reason, message, exit_status }
}

pub(crate) fn safe_token(text: &str, max: usize) -> bool {
    !text.is_empty() && text.chars().count() <= max && !text.starts_with('-') && !text.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// Adresse und Port aus einer Schnellverbindung: dieselben Regeln wie für gespeicherte Hosts.
pub(crate) fn check_address(host: &str, port: u16) -> Result<(), CmdError> {
    if !safe_token(host, 255) {
        return Err(CmdError::invalid("address_invalid"));
    }
    if port == 0 {
        return Err(CmdError::invalid("port_invalid"));
    }
    Ok(())
}

/// Adresse, Port und Benutzer aus der Schnellverbindung über SSH.
fn check_direct(user: &str, host: &str, port: u16) -> Result<(), CmdError> {
    check_address(host, port)?;
    if !safe_token(user, 64) {
        return Err(CmdError::invalid("user_invalid"));
    }
    Ok(())
}

/// Verbindungsdaten einer Schnellverbindung. Ohne Identität und Schlüssel bleibt nur das Passwort, nach dem der
/// Verbindungskern fragt; mit ihnen kommen Benutzer, Schlüssel und Passwort aus dem Tresor.
fn direct_connect(app: &AppHandle, user: String, host: String, port: u16, identity: Option<&str>, key: Option<&str>) -> CmdResult<Connect> {
    let login = if identity.is_some() || key.is_some() { app.state::<AppState>().session().directory()?.login(identity, key)? } else { Default::default() };
    Ok(Connect {
        host,
        port,
        user: login.user.unwrap_or(user),
        password: login.password.map(|p| Zeroizing::new(p.expose().to_string())),
        key: login.key.map(|k| Zeroizing::new(k.expose().to_string())),
        certificate: login.certificate,
        ..Connect::default()
    })
}

/// Die Leitung eines seriellen Hosts in der Form, die `glowport-extras` erwartet.
fn line_of(line: model::Serial) -> serial::Line {
    serial::Line {
        baud: line.baud,
        data_bits: line.data_bits,
        parity: match line.parity {
            model::Parity::None => serial::Parity::None,
            model::Parity::Odd => serial::Parity::Odd,
            model::Parity::Even => serial::Parity::Even,
        },
        stop_bits: line.stop_bits,
        flow: match line.flow {
            model::Flow::None => serial::Flow::None,
            model::Flow::Software => serial::Flow::Software,
            model::Flow::Hardware => serial::Flow::Hardware,
        },
    }
}

/// Eine Shell dieses Rechners, wie die Oberfläche sie zur Wahl stellt.
#[derive(Serialize)]
pub struct ShellView {
    id: String,
    name: String,
    kind: &'static str,
    detail: String,
}

/// Die Shells, die sich als lokales Terminal öffnen lassen. Nachgesehen wird bei jedem Aufruf neu.
#[tauri::command(async)]
pub fn local_shells() -> Vec<ShellView> {
    local::shells().into_iter().map(|shell| ShellView { id: shell.id, name: shell.name, kind: shell.kind.as_str(), detail: shell.detail }).collect()
}

#[derive(Serialize)]
pub struct PortView {
    name: String,
    label: String,
}

/// Die seriellen Ports, die es gerade gibt.
#[tauri::command(async)]
pub fn serial_ports() -> Vec<PortView> {
    serial::ports().into_iter().map(|port| PortView { name: port.name, label: port.label }).collect()
}

/// Verbindungsdaten eines gespeicherten Hosts in der Form, die der Verbindungskern erwartet.
pub(crate) fn connect_for(info: ConnectInfo) -> Connect {
    Connect {
        host: info.address,
        port: info.port,
        user: info.user,
        password: info.password.map(|p| Zeroizing::new(p.expose().to_string())),
        key: info.key.map(|k| Zeroizing::new(k.expose().to_string())),
        certificate: info.certificate,
        key_file: info.key_file.map(PathBuf::from),
        agent: info.agent.then(net::Agents::system),
        agent_forward: info.agent_forward,
        startcmd: info.startcmd,
        env: info.env,
        authorities: info.authorities,
        proxy: info.proxy.map(|proxy| {
            // Ein Benutzer ohne hinterlegtes Passwort meldet sich mit leerem Passwort an.
            let password = info.proxy_password.map_or_else(String::new, |p| p.expose().to_string());
            let login = proxy.user.map(|user| net::Login { user, password: Zeroizing::new(password) });
            match proxy.kind {
                ProxyKind::Http => net::Proxy::Http { host: proxy.host, port: proxy.port, login },
                ProxyKind::Socks5 => net::Proxy::Socks5 { host: proxy.host, port: proxy.port, login },
            }
        }),
        keepalive: Duration::from_secs(u64::from(info.keepalive)),
        timeout: Duration::from_secs(u64::from(info.timeout)),
        term: info.term,
        legacy: info.legacy,
        ..Connect::default()
    }
}

/// Mosh-Einstellungen eines Hosts in der Form, die `glowport-net` erwartet.
fn mosh_of(info: MoshInfo) -> net::Mosh {
    let predict = match info.predict.as_str() {
        "always" => net::MoshPredict::Always,
        "never" => net::MoshPredict::Never,
        _ => net::MoshPredict::Adaptive,
    };
    net::Mosh { predict, port: info.port, server: info.server }
}

/// Der Zeichensatz, in den umgewandelt werden muss; `None` bei UTF-8, das unverändert durchgeht.
fn charset_of(label: &str) -> Option<&'static Encoding> {
    Encoding::for_label(label.as_bytes()).filter(|encoding| *encoding != encoding_rs::UTF_8)
}

/// Ausgabe des Servers als UTF-8 für das Terminal. Der Umwandler merkt sich angefangene Zeichen: Eines aus
/// mehreren Bytes kann auf zwei Pakete verteilt ankommen.
fn to_terminal(decoder: &mut encoding_rs::Decoder, bytes: &[u8]) -> Vec<u8> {
    let mut text = String::with_capacity(decoder.max_utf8_buffer_length(bytes.len()).unwrap_or(bytes.len() * 3));
    let _ = decoder.decode_to_string(bytes, &mut text, false);
    text.into_bytes()
}

/// Eingabe aus dem Terminal im Zeichensatz des Servers.
fn to_server(charset: Option<&'static Encoding>, text: String) -> Vec<u8> {
    match charset {
        Some(encoding) => encoding.encode(&text).0.into_owned(),
        None => text.into_bytes(),
    }
}

/// Mehr Stationen hintereinander braucht niemand; die Grenze fängt auch Kreise in beschädigten Daten ab.
/// Bittet eine laufende Sitzung um einen zusätzlichen Kanal auf ihrer Verbindung, für SFTP oder einen Befehl.
/// Zu welchem gespeicherten Host eine Sitzung führt und wie sie heißt.
pub(crate) fn origin(app: &AppHandle, id: u64) -> Option<(Option<String>, String)> {
    app.state::<Sessions>().live().get(&id).map(|live| (live.host_id.clone(), live.label.clone()))
}

pub(crate) async fn extra_channel(app: &AppHandle, id: u64) -> Option<net::files::Opened> {
    let (reply, opened) = oneshot::channel();
    app.state::<Sessions>().live().get(&id)?.commands.send(Command::Open(reply)).ok()?;
    opened.await.ok().flatten()
}

const MAX_STATIONS: usize = 8;

/// Verbindungsdaten eines gespeicherten Hosts samt aller Sprung-Server davor. Jede Station trägt ihre Kennung als Marke.
pub(crate) fn connect_chain(directory: &Directory, id: &str) -> CmdResult<Connect> {
    fn build(directory: &Directory, id: &str, seen: &mut Vec<String>) -> CmdResult<Connect> {
        if seen.len() >= MAX_STATIONS || seen.iter().any(|s| s == id) {
            return Err(CmdError::invalid("jump_loop"));
        }
        seen.push(id.to_string());
        let info = directory.connect_info(id)?;
        let jump = info.jump.clone().map(|via| build(directory, &via, seen)).transpose()?.map(Box::new);
        Ok(Connect { jump, tag: Some(id.to_string()), ..connect_for(info) })
    }
    build(directory, id, &mut Vec::new())
}

/// Öffnet eine Sitzung und liefert ihre Nummer. `output` bekommt die Terminal-Ausgabe als rohe Bytes.
#[tauri::command]
pub async fn session_open(app: AppHandle, window: Window, target: Target, columns: u32, rows: u32, output: Channel<InvokeResponseBody>) -> Result<u64, CmdError> {
    let size = (columns, rows);
    // Jede Art liefert dieselbe Sitzung: Ab hier ist gleich, ob SSH, Telnet, ein Port oder eine Shell dahintersteckt.
    let (session, host_id, charset, label) = match target {
        Target::Host { id } => {
            let state = app.state::<AppState>();
            let mut vault = state.session();
            let directory = vault.directory()?;
            match directory.endpoint(&id)? {
                Endpoint::Ssh => {
                    let info = directory.connect_info(&id)?;
                    let charset = charset_of(&info.charset);
                    let chain = connect_chain(directory, &id)?;
                    // Mosh gilt nur für das Terminal des Ziels, nicht für Dateien, Befehle und Sprung-Server.
                    let mosh = info.mosh.map(mosh_of);
                    (net::open(Connect { size, detect_os: true, mosh, ..chain }), Some(id), charset, info.name)
                }
                Endpoint::Telnet(info) => {
                    let charset = charset_of(&info.charset);
                    let telnet = telnet::Telnet { host: info.address, port: info.port, user: info.user, term: info.term, timeout: Duration::from_secs(u64::from(info.timeout)), size };
                    (telnet::open(telnet), Some(id), charset, info.name)
                }
                Endpoint::Serial(info) => (serial::open(info.port, line_of(info.line)), Some(id), charset_of(&info.charset), info.name),
                // Ein FTP-Host hat kein Terminal.
                Endpoint::Ftp => return Err(CmdError::invalid("protocol_invalid")),
            }
        }
        Target::Direct { user, host, port, identity, key, mosh } => {
            check_direct(&user, &host, port)?;
            let label = host.clone();
            let mosh = mosh.then(net::Mosh::default);
            (net::open(Connect { size, mosh, ..direct_connect(&app, user, host, port, identity.as_deref(), key.as_deref())? }), None, None, label)
        }
        Target::Telnet { host, port } => {
            check_address(&host, port)?;
            let label = host.clone();
            (telnet::open(telnet::Telnet { host, port, size, ..telnet::Telnet::default() }), None, None, label)
        }
        Target::Local { shell } => {
            // Gestartet wird nur, was auf diesem Rechner als Shell gefunden wurde; die Oberfläche nennt nie ein Programm.
            let shell = local::shell(&shell).ok_or_else(|| CmdError::new("shell_missing", "Diese Shell gibt es auf diesem Rechner nicht"))?;
            let label = shell.name.clone();
            (local::open(shell, size), None, None, label)
        }
    };

    let sessions = app.state::<Sessions>();
    let id = sessions.next.fetch_add(1, Ordering::Relaxed) + 1;
    let live = Live {
        commands: session.commands,
        window: window.label().to_string(),
        output: Some(output),
        backlog: Vec::new(),
        phase: "connecting",
        pending: None,
        asking: None,
        recorder: None,
        unacked: 0,
        paused: false,
        save_password: false,
        adopt_key: None,
        charset,
        host_id: host_id.clone(),
        label,
        mosh: false,
    };
    sessions.live().insert(id, live);
    tauri::async_runtime::spawn(pump(app.clone(), id, session.events, host_id, charset, None));
    Ok(id)
}

/// Lässt den Aufbau einer Port-Regel als Eintrag der Sitzungsverwaltung laufen, damit er dieselben Rückfragen
/// stellen kann wie ein Terminal. `rule` nennt die Regel und ihren Einschalt-Vorgang; an sie geht das Ergebnis.
/// Liefert die Nummer, unter der die Ereignisse `session` kommen.
pub(crate) fn connect_forward(app: &AppHandle, window: &str, host_id: String, label: String, link: net::Session, rule: (String, u64)) -> u64 {
    let sessions = app.state::<Sessions>();
    let number = sessions.next.fetch_add(1, Ordering::Relaxed) + 1;
    let live = Live {
        commands: link.commands,
        window: window.to_string(),
        output: None,
        backlog: Vec::new(),
        phase: "connecting",
        pending: None,
        asking: None,
        recorder: None,
        unacked: 0,
        paused: false,
        save_password: false,
        adopt_key: None,
        charset: None,
        host_id: Some(host_id.clone()),
        label,
        mosh: false,
    };
    sessions.live().insert(number, live);
    tauri::async_runtime::spawn(pump(app.clone(), number, link.events, Some(host_id), None, Some(rule)));
    number
}

/// Bricht einen Verbindungsaufbau oder eine Sitzung ab.
pub(crate) fn close(app: &AppHandle, id: u64) {
    app.state::<Sessions>().send(id, Command::Close);
}

/// Baut für die Seite „Dateien“ eine Verbindung zu einem gespeicherten Host auf, mit denselben Rückfragen wie ein
/// Terminal (unbekannter Server, Passwort, Fragen des Servers). Liefert die Nummer, unter der die Ereignisse
/// `session` kommen und `session_answer` die Antworten annimmt. Bei „verbunden“ steht die Verbindung bereit;
/// scheitert es, kommt ein Ende mit dem Grund.
#[tauri::command]
pub fn fs_connect(app: AppHandle, window: Window, id: String) -> CmdResult<u64> {
    // Ein FTP-Host geht seinen eigenen Weg, mit denselben Ereignissen.
    if app.state::<AppState>().session().directory()?.is_ftp(&id) {
        return crate::ftp::connect(&app, window.label().to_string(), crate::ftp::Who::Host(id));
    }
    let (connect, label) = {
        let state = app.state::<AppState>();
        let mut session = state.session();
        let directory = session.directory()?;
        (connect_chain(directory, &id)?, directory.connect_info(&id)?.name)
    };
    let sessions = app.state::<Sessions>();
    let number = sessions.next.fetch_add(1, Ordering::Relaxed) + 1;
    let link = tauri::async_runtime::block_on(async move { net::files::open(connect) });
    let live = Live {
        commands: link.commands,
        window: window.label().to_string(),
        output: None,
        backlog: Vec::new(),
        phase: "connecting",
        pending: None,
        asking: None,
        recorder: None,
        unacked: 0,
        paused: false,
        save_password: false,
        adopt_key: None,
        charset: None,
        host_id: Some(id.clone()),
        label,
        mosh: false,
    };
    sessions.live().insert(number, live);
    tauri::async_runtime::spawn(pump(app.clone(), number, link.events, Some(id), None, None));
    Ok(number)
}

/// Reicht die Ereignisse einer Sitzung weiter, bis sie endet. `rule` ist gesetzt, wenn hier keine Sitzung, sondern
/// eine Port-Regel verbindet: die Regel und ihr Einschalt-Vorgang.
async fn pump(app: AppHandle, id: u64, mut events: tokio::sync::mpsc::Receiver<Event>, host_id: Option<String>, charset: Option<&'static Encoding>, rule: Option<(String, u64)>) {
    let sessions = app.state::<Sessions>();
    let mut decoder = charset.map(Encoding::new_decoder_without_bom_handling);
    let ask = |pending: Pending, event: SessionEvent| {
        if let Some(live) = sessions.live().get_mut(&id) {
            live.pending = Some(pending);
            live.asking = Some(event.clone());
        }
        emit(&app, id, event);
    };

    // Meldet, wie weit die Verbindung ist. Hat die Anmeldung geklappt, wandert jetzt die Schlüsseldatei in den
    // Tresor, wenn das gewünscht war.
    let reached = |phase: &'static str| {
        let adopt = sessions.live().get_mut(&id).and_then(|live| {
            live.phase = phase;
            if phase == "connected" { live.adopt_key.take() } else { None }
        });
        emit(&app, id, SessionEvent::Phase { phase });
        if let Some(adopt) = adopt {
            match crate::keyring::adopt_file(&app.state::<AppState>(), &adopt.file, &adopt.passphrase, &adopt.host) {
                Ok(()) => emit_snapshot(&app),
                Err(error) => emit(&app, id, SessionEvent::Notice { code: "key_not_adopted", message: error.code().to_string() }),
            }
        }
    };

    // Fragt ein Sprung-Server statt des Ziels, bekommt die Oberfläche seinen Namen dazu.
    let named = |station: &net::Station| (station.tag.is_some() && station.tag != host_id).then(|| station.label.clone());

    while let Some(event) = events.recv().await {
        match event {
            Event::Phase(phase) => reached(match phase {
                Phase::Connecting => "connecting",
                Phase::Authenticating => "authenticating",
                Phase::Connected => "connected",
            }),
            Event::Banner(text) => emit(&app, id, SessionEvent::Banner { text }),
            Event::Mosh(event) => emit(
                &app,
                id,
                match event {
                    MoshEvent::Active => {
                        if let Some(live) = sessions.live().get_mut(&id) {
                            live.mosh = true;
                        }
                        SessionEvent::Mosh { state: "active", reason: None, detail: None }
                    }
                    MoshEvent::Fallback(fallback) => SessionEvent::Mosh { state: "fallback", reason: Some(fallback.code()), detail: fallback.detail().map(str::to_string) },
                    MoshEvent::Silent(silent) => SessionEvent::Reach { silent },
                    MoshEvent::Side(linked) => SessionEvent::Side { linked },
                },
            ),
            Event::Notice { code, message } => emit(&app, id, SessionEvent::Notice { code, message }),
            Event::HostKey { host, port, key, reply } => {
                // Ist der Tresor gesperrt, lässt sich nichts nachschlagen: Dann wird gefragt wie bei einem unbekannten Server.
                let verdict = app.state::<AppState>().session().directory().map(|d| d.judge_host_key(&host, port, &key.openssh)).unwrap_or(Verdict::Unknown);
                let (changed, known) = match verdict {
                    Verdict::Trusted => {
                        let _ = reply.send(true);
                        continue;
                    }
                    Verdict::Unknown => (false, Vec::new()),
                    Verdict::Changed { known } => (true, known),
                };
                let view = SessionEvent::HostKey { host: host.clone(), port, algorithm: key.algorithm.clone(), fingerprint: key.fingerprint.clone(), changed, known };
                ask(Pending::HostKey { reply, key, host, port }, view);
            }
            Event::Secret { station, kind, attempt, reply } => {
                let (kind, file) = match kind {
                    SecretKind::Password => ("password", None),
                    SecretKind::Passphrase { file } => ("passphrase", Some(file)),
                };
                // Speichern lässt sich nur für einen gespeicherten Host, auch für einen Sprung-Server: sein Passwort,
                // oder bei einer Passphrase die Schlüsseldatei selbst (sie wandert dann in den Tresor).
                let can_save = station.tag.is_some();
                let key_file = file.clone().zip(station.tag.clone());
                ask(Pending::Secret { reply, key_file }, SessionEvent::Secret { kind, attempt, file, can_save, station: named(&station) });
            }
            Event::Interactive { station, name, instructions, prompts, reply } => {
                let prompts = prompts.into_iter().map(|p| PromptView { text: p.text, echo: p.echo }).collect();
                ask(Pending::Interactive(reply), SessionEvent::Interactive { name, instructions, prompts, station: named(&station) });
            }
            Event::PasswordAccepted { station, password } => {
                let wanted = sessions.live().get(&id).is_some_and(|live| live.save_password);
                if let (true, Some(host_id)) = (wanted, &station.tag) {
                    let saved = app.state::<AppState>().session().directory().map_err(drop).and_then(|d| d.set_host_password(host_id, model::Secret::new(password.to_string())).map_err(drop));
                    match saved {
                        Ok(()) => emit_snapshot(&app),
                        Err(()) => emit(&app, id, SessionEvent::Notice { code: "password_not_saved", message: String::new() }),
                    }
                }
            }
            Event::Os(os) => {
                if let Some(host_id) = &host_id {
                    let changed = app.state::<AppState>().session().directory().ok().and_then(|d| d.set_host_os(host_id, &os).ok()).unwrap_or(false);
                    if changed {
                        emit_snapshot(&app);
                    }
                }
            }
            Event::Output(bytes) => {
                let bytes = match &mut decoder {
                    Some(decoder) => to_terminal(decoder, &bytes),
                    None => bytes,
                };
                if let Some(live) = sessions.live().get_mut(&id) {
                    if let Some(recorder) = &mut live.recorder {
                        recorder.feed(&bytes);
                    }
                    live.unacked += bytes.len();
                    match &live.output {
                        Some(output) => drop(output.send(InvokeResponseBody::Raw(bytes))),
                        // Die Sitzung wechselt gerade das Fenster: sammeln, bis das neue sie aufnimmt.
                        None => live.backlog.extend_from_slice(&bytes),
                    }
                    if !live.paused && live.unacked > PAUSE_ABOVE {
                        live.paused = true;
                        let _ = live.commands.send(Command::Pause(true));
                    }
                }
            }
            // Eine Verbindung nur für Dateien steht: Die Seite „Dateien“ benutzt sie ab jetzt für diesen Host.
            // Sie ist das letzte Ereignis; die Oberfläche hört erst „verbunden“, wenn die Verbindung bereitliegt.
            Event::Files(remote) => {
                if let Some(host) = &host_id {
                    crate::files::adopt(&app, crate::files::Place::Host { id: host.clone() }, crate::store::Store::Sftp(remote)).await;
                }
                reached("connected");
                break;
            }
            // Die Weiterleitung einer Port-Regel steht: Ab jetzt gehört sie der Verwaltung der Regeln. Auch das ist
            // das letzte Ereignis; die Verbindung selbst läuft dort weiter.
            Event::Forward(tunnel) => {
                if let Some((rule, turn)) = &rule {
                    crate::forwards::adopt(&app, rule, *turn, tunnel);
                }
                reached("connected");
                break;
            }
            Event::End(end) => {
                if let Some((rule, turn)) = &rule {
                    crate::forwards::ended(&app, rule, *turn, &end);
                }
                // Mit der Sitzung endet auch ihr Mitschnitt; die Datei wird dabei abgeschlossen.
                let gone = sessions.live().remove(&id);
                crate::files::session_ended(&app, id);
                if let Some(live) = gone {
                    emit_to(&app, live.window, id, end_event(end));
                }
                return;
            }
        }
    }
    sessions.live().remove(&id);
    crate::files::session_ended(&app, id);
}

/// Mosh: die SSH-Verbindung neben dem Terminal neu aufbauen, mit Rückfragen, falls nötig.
#[tauri::command]
pub fn session_relink(sessions: State<'_, Sessions>, id: u64) {
    sessions.send(id, Command::Relink);
}

#[tauri::command]
pub fn session_write(sessions: State<'_, Sessions>, id: u64, text: String) {
    let charset = sessions.live().get(&id).and_then(|live| live.charset);
    sessions.send(id, Command::Input(to_server(charset, text)));
}

#[tauri::command]
pub fn session_resize(sessions: State<'_, Sessions>, id: u64, columns: u32, rows: u32) {
    sessions.send(id, Command::Resize(columns, rows));
}

/// Die Oberfläche bestätigt, wie viele Bytes sie gezeichnet hat.
#[tauri::command]
pub fn session_ack(sessions: State<'_, Sessions>, id: u64, bytes: usize) {
    if let Some(live) = sessions.live().get_mut(&id) {
        live.unacked = live.unacked.saturating_sub(bytes);
        if live.paused && live.unacked < RESUME_BELOW {
            live.paused = false;
            let _ = live.commands.send(Command::Pause(false));
        }
    }
}

#[tauri::command]
pub fn session_close(app: AppHandle, sessions: State<'_, Sessions>, id: u64) {
    if crate::ftp::cancel(&app, id) {
        return;
    }
    sessions.send(id, Command::Close);
}

/// Antwort der Oberfläche auf die offene Rückfrage einer Sitzung.
#[tauri::command]
pub fn session_answer(app: AppHandle, sessions: State<'_, Sessions>, id: u64, answer: Answer) {
    let Some(answer) = crate::ftp::answer(&app, id, answer) else { return };
    let Some(pending) = sessions.live().get_mut(&id).and_then(|live| {
        live.asking = None;
        live.pending.take()
    }) else {
        return;
    };
    match (pending, answer) {
        (Pending::HostKey { reply, key, host, port }, Answer::HostKey { accept }) => {
            if accept {
                // Lässt sich die Entscheidung nicht speichern, gilt sie für diese Verbindung trotzdem.
                let saved = app.state::<AppState>().session().directory().map_err(drop).and_then(|d| d.trust_host_key(&host, port, &key.algorithm, &key.fingerprint, &key.openssh).map_err(drop));
                match saved {
                    Ok(()) => emit_snapshot(&app),
                    Err(()) => emit(&app, id, SessionEvent::Notice { code: "host_key_not_saved", message: String::new() }),
                }
            }
            let _ = reply.send(accept);
        }
        (Pending::Secret { reply, key_file }, Answer::Secret { value, save }) => {
            if let Some(live) = sessions.live().get_mut(&id) {
                match key_file {
                    Some((file, host)) => live.adopt_key = value.clone().filter(|_| save).map(|passphrase| AdoptKey { file, host, passphrase: Zeroizing::new(passphrase) }),
                    None => live.save_password = save && value.is_some(),
                }
            }
            let _ = reply.send(value.map(Zeroizing::new));
        }
        (Pending::Interactive(reply), Answer::Interactive { values }) => {
            let _ = reply.send(values.map(|v| v.into_iter().map(Zeroizing::new).collect()));
        }
        // Eine Antwort, die nicht zur Frage passt: Die Antwortkanäle fallen weg, das gilt als abgelehnt.
        _ => {}
    }
}

/// Anzahl laufender Sitzungen in allen Fenstern, für die Warnung beim Schließen des Hauptfensters.
#[tauri::command]
pub fn session_count(sessions: State<'_, Sessions>) -> usize {
    sessions.live().len()
}

/// Hält Sitzungen an, deren Tab das Fenster wechselt: Ab jetzt wird ihre Ausgabe gesammelt statt gezeichnet.
#[tauri::command]
pub fn session_hold(sessions: State<'_, Sessions>, ids: Vec<u64>) {
    let mut live = sessions.live();
    for id in ids {
        if let Some(session) = live.get_mut(&id) {
            session.output = None;
        }
    }
}

/// Übergibt angehaltene Sitzungen einem anderen Fenster. Aufgenommen werden sie dort mit `session_attach`.
pub(crate) fn hand_over(app: &AppHandle, ids: &[u64], window: &str) {
    let sessions = app.state::<Sessions>();
    let mut live = sessions.live();
    for id in ids {
        if let Some(session) = live.get_mut(id) {
            session.window = window.to_string();
        }
    }
}

#[derive(Serialize)]
pub struct Attached {
    phase: &'static str,
    /// Läuft das Terminal über Mosh? Das neue Fenster zeigt es wie das alte.
    mosh: bool,
}

/// Ein Fenster nimmt eine laufende Sitzung auf: Es bekommt, was inzwischen angefallen ist, und danach alles Weitere.
#[tauri::command]
pub fn session_attach(app: AppHandle, window: Window, sessions: State<'_, Sessions>, id: u64, columns: u32, rows: u32, output: Channel<InvokeResponseBody>) -> CmdResult<Attached> {
    let (phase, asking, mosh) = {
        let mut live = sessions.live();
        let session = live.get_mut(&id).ok_or_else(|| CmdError::new("session_gone", "Die Sitzung gibt es nicht mehr"))?;
        session.window = window.label().to_string();
        let backlog = std::mem::take(&mut session.backlog);
        // Was das alte Fenster nicht mehr bestätigt hat, gilt als gezeichnet; offen ist nur das Gesammelte.
        session.unacked = backlog.len();
        if !backlog.is_empty() {
            let _ = output.send(InvokeResponseBody::Raw(backlog));
        }
        session.output = Some(output);
        if session.paused && session.unacked < RESUME_BELOW {
            session.paused = false;
            let _ = session.commands.send(Command::Pause(false));
        }
        let _ = session.commands.send(Command::Resize(columns, rows));
        (session.phase, session.asking.clone(), session.mosh)
    };
    // Eine Rückfrage, die beim Wechsel offen war, erscheint im neuen Fenster noch einmal.
    if let Some(event) = asking {
        emit(&app, id, event);
    }
    Ok(Attached { phase, mosh })
}

/// Schaltet den Mitschnitt einer Sitzung. `name` und `address` stehen später in der Liste der Mitschnitte.
#[tauri::command]
pub fn session_record(app: AppHandle, sessions: State<'_, Sessions>, id: u64, on: bool, name: String, address: String) -> CmdResult<()> {
    let mut live = sessions.live();
    let Some(session) = live.get_mut(&id) else { return Ok(()) };
    if !on {
        session.recorder = None;
    } else if session.recorder.is_none() {
        let dir = crate::data_dir(&app).map_err(|e| CmdError::new("io", e))?;
        session.recorder = Some(Recorder::start(&dir, &name, &address).map_err(|e| CmdError::new("io", e.to_string()))?);
    }
    Ok(())
}

/// Dateien, in die gerade geschrieben wird.
fn recording_now(sessions: &Sessions) -> Vec<String> {
    sessions.live().values().filter_map(|live| live.recorder.as_ref().map(|recorder| recorder.id().to_string())).collect()
}

#[tauri::command(async)]
pub fn log_list(app: AppHandle, sessions: State<'_, Sessions>) -> CmdResult<Vec<Recording>> {
    let dir = crate::data_dir(&app).map_err(|e| CmdError::new("io", e))?;
    Ok(recordings::list(&dir, &recording_now(&sessions)))
}

#[tauri::command(async)]
pub fn log_read(app: AppHandle, id: String) -> CmdResult<String> {
    let dir = crate::data_dir(&app).map_err(|e| CmdError::new("io", e))?;
    recordings::read(&dir, &id).map_err(|e| CmdError::new(if e.kind() == std::io::ErrorKind::NotFound { "not_found" } else { "io" }, e.to_string()))
}

/// Löscht einen Mitschnitt samt Datei. Einer, der noch läuft, muss erst beendet werden.
#[tauri::command(async)]
pub fn log_delete(app: AppHandle, sessions: State<'_, Sessions>, id: String) -> CmdResult<Vec<Recording>> {
    let dir = crate::data_dir(&app).map_err(|e| CmdError::new("io", e))?;
    let running = recording_now(&sessions);
    if running.contains(&id) {
        return Err(CmdError::new("log_running", "Der Mitschnitt läuft noch"));
    }
    recordings::delete(&dir, &id).map_err(|e| CmdError::new(if e.kind() == std::io::ErrorKind::NotFound { "not_found" } else { "io" }, e.to_string()))?;
    Ok(recordings::list(&dir, &running))
}

#[derive(Serialize)]
pub struct Renamed {
    /// Die Kennung des Mitschnitts nach dem Umbenennen; sie folgt dem Dateinamen.
    id: String,
    list: Vec<Recording>,
}

/// Gibt einem fertigen Mitschnitt einen eigenen Namen; ein leerer nimmt ihn wieder weg.
#[tauri::command(async)]
pub fn log_rename(app: AppHandle, sessions: State<'_, Sessions>, id: String, title: String) -> CmdResult<Renamed> {
    let dir = crate::data_dir(&app).map_err(|e| CmdError::new("io", e))?;
    let running = recording_now(&sessions);
    if running.contains(&id) {
        return Err(CmdError::new("log_running", "Der Mitschnitt läuft noch"));
    }
    let id = recordings::rename(&dir, &id, &title).map_err(|e| CmdError::new(if e.kind() == std::io::ErrorKind::NotFound { "not_found" } else { "io" }, e.to_string()))?;
    Ok(Renamed { id, list: recordings::list(&dir, &running) })
}

/// Zeigt die Datei eines Mitschnitts im Dateimanager; ohne Kennung den Ordner aller Mitschnitte.
#[tauri::command(async)]
pub fn log_reveal(app: AppHandle, id: Option<String>) -> CmdResult<()> {
    let dir = crate::data_dir(&app).map_err(|e| CmdError::new("io", e))?;
    let target = recordings::reveal_target(&dir, id.as_deref()).map_err(|e| CmdError::new("not_found", e.to_string()))?;
    let mut command = if cfg!(windows) {
        let mut explorer = std::process::Command::new("explorer");
        if id.is_some() {
            explorer.arg("/select,");
        }
        explorer.arg(&target);
        explorer
    } else {
        // Andere Systeme kennen kein einheitliches „Datei markieren“; dort öffnet sich der Ordner.
        let mut opener = std::process::Command::new(if cfg!(target_os = "macos") { "open" } else { "xdg-open" });
        opener.arg(if id.is_some() { target.parent().unwrap_or(&target) } else { &target });
        opener
    };
    command.spawn().map(drop).map_err(|e| CmdError::new("io", e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn other_character_sets_are_converted_both_ways() {
        assert!(charset_of("utf-8").is_none() && charset_of("UTF-8").is_none() && charset_of("klingonisch").is_none());
        for label in model::CHARSETS.iter().skip(1) {
            assert!(charset_of(label).is_some(), "{label} steht zur Wahl, also muss die Umwandlung ihn kennen");
        }

        let latin = charset_of("iso-8859-1").unwrap();
        let mut decoder = latin.new_decoder_without_bom_handling();
        assert_eq!(to_terminal(&mut decoder, &[b'G', 0xFC, b'n', 0xE4]), "Günä".as_bytes());
        assert_eq!(to_server(Some(latin), "Größe".into()), [b'G', b'r', 0xF6, 0xDF, b'e']);
        assert_eq!(to_server(None, "ä".into()), "ä".as_bytes());

        // Ein Zeichen aus zwei Bytes, auf zwei Pakete verteilt, kommt heil an.
        let mut decoder = charset_of("gbk").unwrap().new_decoder_without_bom_handling();
        let first = to_terminal(&mut decoder, &[b'a', 0xC4]);
        let second = to_terminal(&mut decoder, &[0xE3, b'b']);
        assert_eq!([first, second].concat(), "a你b".as_bytes());
    }
}

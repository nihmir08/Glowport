//! Running sessions: brings together the connection core (`glowport-net`), the other terminals (`glowport-extras`: shells
//! on this machine, Telnet, serial line), vault and interface.
//!
//! Per session one task runs that passes on the connection core's events: terminal output as raw
//! bytes over a channel of its own, everything else as the `session` event. Prompts wait here for the
//! interface's answer. Sessions survive locking the vault; only saving host keys and
//! passwords needs it open.
//!
//! Every session belongs to a window. If its tab moves into another window, it is paused
//! (`session_hold`), the output collected meanwhile and picked up again by the new window (`session_attach`).
//! The connection itself notices nothing.

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

/// Flow control: above this amount of unacknowledged output reading is paused (the server is slowed down),
/// below it continues. Values as in NexusSSH.
const PAUSE_ABOVE: usize = 1024 * 1024;
const RESUME_BELOW: usize = 256 * 1024;

#[derive(Default)]
pub struct Sessions {
    next: AtomicU64,
    live: Mutex<HashMap<u64, Live>>,
}

struct Live {
    commands: UnboundedSender<Command>,
    /// Window the session belongs to. Its events only arrive there.
    window: String,
    /// Where the terminal output goes. Missing while the session changes windows.
    output: Option<Channel<InvokeResponseBody>>,
    /// Output that accumulated during the window change.
    backlog: Vec<u8>,
    phase: &'static str,
    /// The one prompt whose answer the session is currently waiting for.
    pending: Option<Pending>,
    /// The same prompt in the interface's form, to show it once more to a new window.
    asking: Option<SessionEvent>,
    /// Records the output into a file while set.
    recorder: Option<Recorder>,
    unacked: usize,
    paused: bool,
    /// The user wants to save the password just typed, if it works.
    save_password: bool,
    /// The user wants to take the key file whose passphrase they just typed into the vault.
    adopt_key: Option<AdoptKey>,
    /// The server's character set if it is not UTF-8. Input is then converted before sending.
    charset: Option<&'static Encoding>,
    /// ID of the saved host the session leads to; missing for a typed address.
    host_id: Option<String>,
    /// Name of the host or the address, for display e.g. in the list of transfers.
    label: String,
    /// The terminal runs over Mosh.
    mosh: bool,
}

/// A key file that should go into the vault after a successful sign-in, and the host that then uses it.
struct AdoptKey {
    file: String,
    host: String,
    passphrase: Zeroizing<String>,
}

enum Pending {
    HostKey { reply: oneshot::Sender<bool>, key: net::HostKey, host: String, port: u16 },
    /// `key_file`: the question is about this file's passphrase, asked for the saved host with this ID.
    Secret { reply: oneshot::Sender<Option<Secret>>, key_file: Option<(String, String)> },
    Interactive(oneshot::Sender<Option<Vec<Secret>>>),
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum Target {
    /// Saved host from the vault.
    Host { id: String },
    /// Quick connect without a saved host. `identity` and `key` optionally name an identity or a
    /// key from the vault to sign in with (that is how the Proxmox page connects to a machine
    /// that is not a host yet); with an identity, its user applies.
    Direct {
        user: String,
        host: String,
        port: u16,
        #[serde(default)]
        identity: Option<String>,
        #[serde(default)]
        key: Option<String>,
        /// `mosh user@host`: signed in over SSH, the terminal over Mosh.
        #[serde(default)]
        mosh: bool,
    },
    /// Quick connect over Telnet.
    Telnet { host: String, port: u16 },
    /// A shell on this machine; `shell` is its ID from `local_shells`.
    Local { shell: String },
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum Answer {
    HostKey {
        accept: bool,
    },
    /// `value` is missing if the user cancelled.
    Secret {
        value: Option<String>,
        #[serde(default)]
        save: bool,
    },
    Interactive {
        values: Option<Vec<String>>,
    },
    /// An FTP server's certificate.
    Certificate {
        accept: bool,
    },
    /// The warning about an unencrypted FTP connection. `remember` switches it off for the host, `secure`
    /// moves the host to FTPS instead.
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
    /// `station` is set if not the destination asks, but a jump host before it (`user@address`).
    Secret { kind: &'static str, attempt: u32, file: Option<String>, can_save: bool, station: Option<String> },
    Interactive { name: String, instructions: String, prompts: Vec<PromptView>, station: Option<String> },
    /// The certificate of an FTP server this machine does not trust on its own (`changed`: different from the confirmed one).
    Certificate { host: String, port: u16, fingerprint: String, changed: bool },
    /// Before an unencrypted FTP connection. `can_remember`: the question can be switched off for this host.
    Plain { host: String, offers_tls: bool, can_remember: bool },
    /// Mosh: `active` (the terminal runs over it) or `fallback` (over SSH, `reason` says why).
    Mosh {
        state: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<&'static str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },
    /// Mosh: seconds without a message from the server; `None` as soon as it answers again.
    Reach { silent: Option<u32> },
    /// Mosh: is the SSH connection next to it up for sidebar and files?
    Side { linked: bool },
    End { reason: &'static str, message: Option<String>, exit_status: Option<u32> },
}

#[derive(Serialize, Clone)]
struct Envelope {
    id: u64,
    /// Window the session belongs to. The other windows ignore the event.
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

/// A new number for something that sends events and gets answers like a session.
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

/// Ends all sessions of a window that was closed. Without a window nobody would see their output any more.
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

/// Address and port from quick connect: the same rules as for saved hosts.
pub(crate) fn check_address(host: &str, port: u16) -> Result<(), CmdError> {
    if !safe_token(host, 255) {
        return Err(CmdError::invalid("address_invalid"));
    }
    if port == 0 {
        return Err(CmdError::invalid("port_invalid"));
    }
    Ok(())
}

/// Address, port and user from quick connect over SSH.
fn check_direct(user: &str, host: &str, port: u16) -> Result<(), CmdError> {
    check_address(host, port)?;
    if !safe_token(user, 64) {
        return Err(CmdError::invalid("user_invalid"));
    }
    Ok(())
}

/// Connection details of a quick connection. Without identity and key only the password remains, which the
/// connection core asks for; with them, user, key and password come from the vault.
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

/// A serial host's line in the form `glowport-extras` expects.
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

/// A shell on this machine, as the interface offers it for choice.
#[derive(Serialize)]
pub struct ShellView {
    id: String,
    name: String,
    kind: &'static str,
    detail: String,
}

/// The shells that can be opened as a local terminal. Checked anew on every call.
#[tauri::command(async)]
pub fn local_shells() -> Vec<ShellView> {
    local::shells().into_iter().map(|shell| ShellView { id: shell.id, name: shell.name, kind: shell.kind.as_str(), detail: shell.detail }).collect()
}

#[derive(Serialize)]
pub struct PortView {
    name: String,
    label: String,
}

/// The serial ports that exist right now.
#[tauri::command(async)]
pub fn serial_ports() -> Vec<PortView> {
    serial::ports().into_iter().map(|port| PortView { name: port.name, label: port.label }).collect()
}

/// A saved host's connection details in the form the connection core expects.
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
            // A user without a stored password signs in with an empty password.
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

/// A host's Mosh settings in the form `glowport-net` expects.
fn mosh_of(info: MoshInfo) -> net::Mosh {
    let predict = match info.predict.as_str() {
        "always" => net::MoshPredict::Always,
        "never" => net::MoshPredict::Never,
        _ => net::MoshPredict::Adaptive,
    };
    net::Mosh { predict, port: info.port, server: info.server }
}

/// The character set to convert to; `None` for UTF-8, which passes through unchanged.
fn charset_of(label: &str) -> Option<&'static Encoding> {
    Encoding::for_label(label.as_bytes()).filter(|encoding| *encoding != encoding_rs::UTF_8)
}

/// The server's output as UTF-8 for the terminal. The converter remembers started characters: a multi-byte one
/// can arrive spread over two packets.
fn to_terminal(decoder: &mut encoding_rs::Decoder, bytes: &[u8]) -> Vec<u8> {
    let mut text = String::with_capacity(decoder.max_utf8_buffer_length(bytes.len()).unwrap_or(bytes.len() * 3));
    let _ = decoder.decode_to_string(bytes, &mut text, false);
    text.into_bytes()
}

/// Input from the terminal in the server's character set.
fn to_server(charset: Option<&'static Encoding>, text: String) -> Vec<u8> {
    match charset {
        Some(encoding) => encoding.encode(&text).0.into_owned(),
        None => text.into_bytes(),
    }
}

/// Nobody needs more hops in a row; the limit also catches cycles in damaged data.
/// Asks a running session for an additional channel on its connection, for SFTP or a command.
/// Which saved host a session leads to and what it is called.
pub(crate) fn origin(app: &AppHandle, id: u64) -> Option<(Option<String>, String)> {
    app.state::<Sessions>().live().get(&id).map(|live| (live.host_id.clone(), live.label.clone()))
}

pub(crate) async fn extra_channel(app: &AppHandle, id: u64) -> Option<net::files::Opened> {
    let (reply, opened) = oneshot::channel();
    app.state::<Sessions>().live().get(&id)?.commands.send(Command::Open(reply)).ok()?;
    opened.await.ok().flatten()
}

const MAX_STATIONS: usize = 8;

/// A saved host's connection details including all jump hosts before it. Every hop carries its ID as tag.
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

/// Opens a session and returns its number. `output` gets the terminal output as raw bytes.
#[tauri::command]
pub async fn session_open(app: AppHandle, window: Window, target: Target, columns: u32, rows: u32, output: Channel<InvokeResponseBody>) -> Result<u64, CmdError> {
    let size = (columns, rows);
    // Every kind returns the same session: from here on it does not matter whether SSH, Telnet, a port or a shell is behind it.
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
                    // Mosh only applies to the destination's terminal, not to files, commands and jump hosts.
                    let mosh = info.mosh.map(mosh_of);
                    (net::open(Connect { size, detect_os: true, mosh, ..chain }), Some(id), charset, info.name)
                }
                Endpoint::Telnet(info) => {
                    let charset = charset_of(&info.charset);
                    let telnet = telnet::Telnet { host: info.address, port: info.port, user: info.user, term: info.term, timeout: Duration::from_secs(u64::from(info.timeout)), size };
                    (telnet::open(telnet), Some(id), charset, info.name)
                }
                Endpoint::Serial(info) => (serial::open(info.port, line_of(info.line)), Some(id), charset_of(&info.charset), info.name),
                // An FTP host has no terminal.
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
            // Only what was found as a shell on this machine is started; the interface never names a program.
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

/// Lets the setup of a port rule run as an entry of the session manager, so it can ask the same prompts
/// as a terminal. `rule` names the rule and its switch-on run; the result goes to it.
/// Returns the number under which the `session` events arrive.
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

/// Cancels a connection setup or a session.
pub(crate) fn close(app: &AppHandle, id: u64) {
    app.state::<Sessions>().send(id, Command::Close);
}

/// Sets up a connection to a saved host for the Files page, with the same prompts as a
/// terminal (unknown server, password, server questions). Returns the number under which the
/// `session` events arrive and `session_answer` takes the answers. On “connected” the connection is ready;
/// if it fails, an end with the reason comes.
#[tauri::command]
pub fn fs_connect(app: AppHandle, window: Window, id: String) -> CmdResult<u64> {
    // An FTP host goes its own way, with the same events.
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

/// Passes on a session's events until it ends. `rule` is set if not a session but a port rule
/// connects here: the rule and its switch-on run.
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

    // Reports how far the connection is. If signing in worked, the key file now moves into the
    // vault, if that was wanted.
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

    // If a jump host asks instead of the destination, the interface gets its name too.
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
                // If the vault is locked, nothing can be looked up: then the user is asked as for an unknown server.
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
                // Saving only works for a saved host, also for a jump host: its password,
                // or for a passphrase the key file itself (it then moves into the vault).
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
                        // The session is changing windows right now: collect until the new one picks it up.
                        None => live.backlog.extend_from_slice(&bytes),
                    }
                    if !live.paused && live.unacked > PAUSE_ABOVE {
                        live.paused = true;
                        let _ = live.commands.send(Command::Pause(true));
                    }
                }
            }
            // A connection for files only is up: from now on the Files page uses it for this host.
            // It is the last event; the interface only hears “connected” when the connection is ready.
            Event::Files(remote) => {
                if let Some(host) = &host_id {
                    crate::files::adopt(&app, crate::files::Place::Host { id: host.clone() }, crate::store::Store::Sftp(remote)).await;
                }
                reached("connected");
                break;
            }
            // A port rule's forward is up: from now on it belongs to the rule manager. That too is
            // the last event; the connection itself keeps running there.
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
                // With the session its recording ends too; the file is finished on the way.
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

/// Mosh: re-establish the SSH connection next to the terminal, with prompts if necessary.
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

/// The interface confirms how many bytes it has drawn.
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

/// The interface's answer to a session's open prompt.
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
                // If the decision cannot be saved, it still applies to this connection.
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
        // An answer that does not fit the question: the reply channels are dropped, which counts as refused.
        _ => {}
    }
}

/// Number of running sessions in all windows, for the warning when closing the main window.
#[tauri::command]
pub fn session_count(sessions: State<'_, Sessions>) -> usize {
    sessions.live().len()
}

/// Pauses sessions whose tab changes windows: from now on their output is collected instead of drawn.
#[tauri::command]
pub fn session_hold(sessions: State<'_, Sessions>, ids: Vec<u64>) {
    let mut live = sessions.live();
    for id in ids {
        if let Some(session) = live.get_mut(&id) {
            session.output = None;
        }
    }
}

/// Hands paused sessions to another window. They are picked up there with `session_attach`.
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
    /// Does the terminal run over Mosh? The new window shows it like the old one.
    mosh: bool,
}

/// A window picks up a running session: it gets what accumulated in the meantime, and everything after that.
#[tauri::command]
pub fn session_attach(app: AppHandle, window: Window, sessions: State<'_, Sessions>, id: u64, columns: u32, rows: u32, output: Channel<InvokeResponseBody>) -> CmdResult<Attached> {
    let (phase, asking, mosh) = {
        let mut live = sessions.live();
        let session = live.get_mut(&id).ok_or_else(|| CmdError::new("session_gone", "Die Sitzung gibt es nicht mehr"))?;
        session.window = window.label().to_string();
        let backlog = std::mem::take(&mut session.backlog);
        // What the old window no longer acknowledged counts as drawn; only what was collected is open.
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
    // A prompt that was open during the change appears once more in the new window.
    if let Some(event) = asking {
        emit(&app, id, event);
    }
    Ok(Attached { phase, mosh })
}

/// Switches a session's recording. `name` and `address` later appear in the list of recordings.
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

/// Files currently being written.
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

/// Deletes a recording together with its file. One that is still running must be ended first.
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
    /// The recording's ID after renaming; it follows the file name.
    id: String,
    list: Vec<Recording>,
}

/// Gives a finished recording a name of its own; an empty one takes it away again.
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

/// Shows a recording's file in the file manager; without an ID the folder of all recordings.
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
        // Other systems know no uniform “select file”; there the folder opens.
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

        // A two-byte character spread over two packets arrives intact.
        let mut decoder = charset_of("gbk").unwrap().new_decoder_without_bom_handling();
        let first = to_terminal(&mut decoder, &[b'a', 0xC4]);
        let second = to_terminal(&mut decoder, &[0xE3, b'b']);
        assert_eq!([first, second].concat(), "a你b".as_bytes());
    }
}

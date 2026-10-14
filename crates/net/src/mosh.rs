//! Mosh: signing in happens over SSH, then the terminal runs over UDP (`mosh-client`) and survives network changes
//! and dropouts. The SSH connection stays open next to it for the sidebar's channels (files, server info);
//! if it drops, it is re-established the next time it is needed, without asking, with what was
//! confirmed and entered the first time. If Mosh does not work (missing, IPv6 only, UDP blocked), the session continues over SSH.
//!
//! Beschreibung: `docs/mosh.md`.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use mosh_client::{Bootstrap, PredictionMode, Session, SessionExit, SessionReachability, SessionState};
use russh::{client, ChannelMsg, Disconnect};
use tokio::{
    net::lookup_host,
    sync::{mpsc, oneshot},
    time::timeout,
};

use crate::{emit, establish, establish_with, files, lost, os, Command, Connect, End, Event, Link, Phase, SecretKind, Secret};

/// How long `mosh-server new` may take until it names port and key.
const START_LIMIT: Duration = Duration::from_secs(15);
/// How long to wait for the first screen over UDP. If none comes, a firewall usually blocks the ports.
const ATTACH_LIMIT: Duration = Duration::from_secs(10);
/// Glowport reads at most this much of `mosh-server`'s answer.
const MAX_START_OUTPUT: usize = 16 * 1024;
/// From this much silence on, the library reports an interruption (`NO_RECENT_CONTACT_MS` in `mosh-client`).
const SILENT_AFTER: Duration = Duration::from_millis(6_500);
/// The SSH connection next to it is re-established by itself at most this often.
const RELINK_PAUSE: Duration = Duration::from_secs(15);
/// Opening a channel on the SSH connection next to it may take this long before it counts as dropped.
const OPEN_LIMIT: Duration = Duration::from_secs(5);
/// Largest input per command to the library (`MAX_INPUT_COMMAND_BYTES`).
const MAX_INPUT: usize = 64 * 1024;
const MAX_DETAIL: usize = 160;

/// Local echo: shows typed text before the server confirms it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Predict {
    /// Only on a slow line, like the original.
    #[default]
    Adaptive,
    Always,
    Never,
}

/// Mosh instead of an SSH shell. Set in [`Connect::mosh`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Mosh {
    pub predict: Predict,
    /// UDP port or range for `mosh-server -p`, e.g. `60001` or `60001:60010`. Checked by the caller.
    pub port: Option<String>,
    /// Path to `mosh-server` if it is not on the search path. Checked by the caller (no spaces, no
    /// characters the shell interprets).
    pub server: Option<String>,
}

/// Why the session runs over SSH instead of Mosh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fallback {
    /// `mosh-server` does not exist on the server.
    Missing,
    /// The host has no IPv4 address; the library can only do IPv4.
    Ipv6,
    /// No answer came over UDP.
    Udp,
    /// `mosh-server` reported an error; its first line.
    Server(String),
}

impl Fallback {
    pub fn code(&self) -> &'static str {
        match self {
            Fallback::Missing => "missing",
            Fallback::Ipv6 => "ipv6",
            Fallback::Udp => "udp",
            Fallback::Server(_) => "server",
        }
    }

    pub fn detail(&self) -> Option<&str> {
        match self {
            Fallback::Server(line) => Some(line),
            _ => None,
        }
    }
}

/// What a Mosh session reports about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MoshEvent {
    /// The terminal runs over Mosh.
    Active,
    /// Mosh did not come about; the session runs over SSH.
    Fallback(Fallback),
    /// Seconds without a message from the server; `None` as soon as it answers again.
    Silent(Option<u32>),
    /// Is the SSH connection next to it up (for sidebar and files)?
    Side(bool),
}

/// What was confirmed and entered at the first sign-in, so the SSH connection next to it comes back without
/// a prompt. Lives only in this session's memory.
#[derive(Default)]
pub(crate) struct Memory {
    /// Confirmed servers: address and port → fingerprint.
    keys: HashMap<(String, u16), String>,
    /// Entered passwords per hop (`user@address`).
    passwords: HashMap<String, Secret>,
}

pub(crate) type Shared = Arc<Mutex<Memory>>;

fn memory(shared: &Shared) -> std::sync::MutexGuard<'_, Memory> {
    shared.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Remembers a confirmed server key.
pub(crate) fn remember_key(shared: &Shared, host: &str, port: u16, fingerprint: &str) {
    memory(shared).keys.insert((host.to_string(), port), fingerprint.to_string());
}

/// Remembers an accepted password for a hop.
pub(crate) fn remember_password(shared: &Shared, station: &str, password: &Secret) {
    memory(shared).passwords.insert(station.to_string(), password.clone());
}

/// Re-establishes the SSH connection next to it without asking anyone: only to servers confirmed the
/// first time, and only with what is stored or was entered the first time.
async fn relink_quietly(connect: &Connect, shared: &Shared) -> Result<Link, End> {
    let (event_tx, mut events) = mpsc::channel(16);
    let answers = async {
        while let Some(event) = events.recv().await {
            match event {
                Event::HostKey { host, port, key, reply } => {
                    let known = memory(shared).keys.get(&(host, port)).is_some_and(|fingerprint| *fingerprint == key.fingerprint);
                    let _ = reply.send(known);
                }
                Event::Secret { station, kind: SecretKind::Password, attempt: 1, reply } => {
                    let _ = reply.send(memory(shared).passwords.get(&station.label).cloned());
                }
                Event::Secret { reply, .. } => drop(reply.send(None)),
                Event::Interactive { reply, .. } => drop(reply.send(None)),
                _ => {}
            }
        }
    };
    tokio::select! {
        link = establish(connect, &event_tx) => link,
        () = answers => Err(End::User),
    }
}

/// The IPv4 address UDP goes to: that of the SSH connection, otherwise as this PC resolves the name.
async fn udp_address(link: &Link, connect: &Connect) -> Result<Ipv4Addr, Fallback> {
    if let Some(SocketAddr::V4(address)) = link.peer {
        return Ok(*address.ip());
    }
    if let Ok(IpAddr::V4(address)) = connect.host.parse() {
        return Ok(address);
    }
    let found = lookup_host((connect.host.as_str(), connect.port)).await.map_err(|_| Fallback::Ipv6)?;
    found
        .filter_map(|address| match address {
            SocketAddr::V4(v4) => Some(*v4.ip()),
            SocketAddr::V6(_) => None,
        })
        .next()
        .ok_or(Fallback::Ipv6)
}

/// Language for `mosh-server`: as set on the host, otherwise a UTF-8 locale almost every system knows.
fn language(connect: &Connect) -> String {
    connect
        .env
        .iter()
        .find(|(name, _)| name == "LC_ALL" || name == "LANG")
        .map(|(_, value)| value.clone())
        .filter(|value| !value.is_empty() && value.chars().all(|c| c.is_ascii_alphanumeric() || "._-@".contains(c)))
        .unwrap_or_else(|| "C.UTF-8".into())
}

/// The command that starts the counterpart on the server.
pub(crate) fn server_command(mosh: &Mosh, lang: &str) -> String {
    let program = mosh.server.as_deref().filter(|path| !path.is_empty()).unwrap_or("mosh-server");
    let mut command = format!("{program} new -s -c 256 -l LANG={lang}");
    if let Some(port) = mosh.port.as_deref().filter(|port| !port.is_empty()) {
        command.push_str(" -p ");
        command.push_str(port);
    }
    command
}

/// First readable line of an error message, shortened and without control characters.
fn first_line(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let line = text.lines().map(str::trim).find(|line| !line.is_empty()).unwrap_or("");
    line.chars().filter(|c| !c.is_control()).take(MAX_DETAIL).collect()
}

/// Reads what `mosh-server` answers: output and error output separately, both limited.
async fn start_server(handle: &client::Handle<crate::Client>, command: &str) -> Result<(Vec<u8>, Vec<u8>, Option<u32>), End> {
    let mut channel = handle.channel_open_session().await.map_err(lost)?;
    channel.exec(true, command).await.map_err(lost)?;
    let _ = channel.eof().await;
    let (mut stdout, mut stderr, mut status) = (Vec::new(), Vec::new(), None);
    let read = async {
        while let Some(message) = channel.wait().await {
            let (target, data) = match message {
                ChannelMsg::Data { data } => (&mut stdout, data),
                ChannelMsg::ExtendedData { data, .. } => (&mut stderr, data),
                ChannelMsg::ExitStatus { exit_status } => {
                    status = Some(exit_status);
                    continue;
                }
                _ => continue,
            };
            let room = MAX_START_OUTPUT.saturating_sub(target.len());
            target.extend_from_slice(&data[..data.len().min(room)]);
        }
    };
    // If the answer does not come, what arrived until then decides.
    let _ = timeout(START_LIMIT, read).await;
    Ok((stdout, stderr, status))
}

/// The library's running task: it drives UDP, synchronisation and prediction.
pub(crate) type Running = tokio::task::JoinHandle<Result<SessionExit, mosh_client::SessionError>>;

/// Starts `mosh-server` and sets up the Mosh session. `Err(Ok(Fallback))`: Mosh does not work here, but the SSH connection
/// stands; `Err(Err(End))`: the connection itself is gone.
pub(crate) async fn attach(link: &Link, connect: &Connect, mosh: &Mosh, size: (u32, u32)) -> Result<(Session, Running), Result<Fallback, End>> {
    let address = udp_address(link, connect).await.map_err(Ok)?;
    let (stdout, stderr, status) = start_server(&link.handle, &server_command(mosh, &language(connect))).await.map_err(Err)?;
    let bootstrap = match Bootstrap::parse(address, &stdout) {
        Ok(bootstrap) => bootstrap,
        Err(_) => {
            let message = if stderr.is_empty() { &stdout } else { &stderr };
            let said = String::from_utf8_lossy(message).to_lowercase();
            let missing = status == Some(127) || said.contains("not found") || said.contains("no such file");
            return Err(Ok(if missing { Fallback::Missing } else { Fallback::Server(first_line(message)) }));
        }
    };
    let mode = match mosh.predict {
        Predict::Adaptive => PredictionMode::Adaptive,
        Predict::Always => PredictionMode::Always,
        Predict::Never => PredictionMode::Never,
    };
    let (mut session, task) = Session::connect_with_prediction_mode(bootstrap, size.0.max(1), size.1.max(1), mode).await.map_err(|e| Err(End::ConnectFailed(e.to_string())))?;
    let mut running = tokio::spawn(task.run());
    let deadline = tokio::time::Instant::now() + ATTACH_LIMIT;
    while session.state() != SessionState::Active {
        tokio::select! {
            _ = &mut running => return Err(Ok(Fallback::Udp)),
            _ = session.state_changed() => {}
            () = tokio::time::sleep_until(deadline) => {
                session.cancel();
                return Err(Ok(Fallback::Udp));
            }
        }
    }
    Ok((session, running))
}

/// What the helper tasks of the SSH connection next to it report to the loop.
enum Side {
    /// The connection no longer answers; it is re-established the next time it is needed.
    Gone,
    /// A new connection is up.
    Back(Link),
}

/// Passes input and output between caller and Mosh until the shell ends or the user closes. Channels
/// for the sidebar come from the SSH connection next to it; everything that would have to wait for it runs in
/// tasks of its own, so the terminal never stalls.
pub(crate) async fn drive(connect: Arc<Connect>, link: Link, shared: Shared, mut session: Session, mut running: Running, events: &mpsc::Sender<Event>, commands: &mut mpsc::UnboundedReceiver<Command>) -> Result<End, End> {
    emit(events, Event::Mosh(MoshEvent::Active)).await?;
    emit(events, Event::Phase(Phase::Connected)).await?;
    if let Some(command) = connect.startcmd.as_deref().map(str::trim).filter(|c| !c.is_empty()) {
        let _ = session.send_input(format!("{command}\r").into_bytes()).await;
    }
    let mut side = Some(Arc::new(link));
    if connect.detect_os {
        let (link, events) = (side.clone(), events.clone());
        tokio::spawn(async move {
            let found = match &link {
                Some(link) => os::probe(&link.handle).await,
                None => None,
            };
            if let Some(os) = found {
                let _ = events.send(Event::Os(os)).await;
            }
        });
    }
    let (side_tx, mut side_rx) = mpsc::channel::<Side>(4);
    let mut side_up = true;
    let mut relinking = false;
    let mut last_relink: Option<Instant> = None;

    let mut reach = session.subscribe_reachability();
    let mut reach_open = true;
    let mut silent_since: Option<Instant> = None;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let mut paused = false;
    let mut output_open = true;

    let end = loop {
        tokio::select! {
            output = session.next_output(), if output_open && !paused => match output {
                Some(bytes) => emit(events, Event::Output(bytes)).await?,
                // The task has ended; its result follows shortly.
                None => output_open = false,
            },
            change = reach.changed(), if reach_open => match change {
                Some(SessionReachability::Interrupted { .. }) if silent_since.is_none() => {
                    let since = Instant::now().checked_sub(SILENT_AFTER).unwrap_or_else(Instant::now);
                    silent_since = Some(since);
                    emit(events, Event::Mosh(MoshEvent::Silent(Some(seconds(since))))).await?;
                }
                Some(SessionReachability::Responsive) if silent_since.take().is_some() => emit(events, Event::Mosh(MoshEvent::Silent(None))).await?,
                Some(_) => {}
                None => reach_open = false,
            },
            _ = tick.tick(), if silent_since.is_some() => {
                if let Some(since) = silent_since {
                    emit(events, Event::Mosh(MoshEvent::Silent(Some(seconds(since))))).await?;
                }
            }
            news = side_rx.recv() => match news {
                Some(Side::Gone) => {
                    relinking = false;
                    side = None;
                    if std::mem::replace(&mut side_up, false) {
                        emit(events, Event::Mosh(MoshEvent::Side(false))).await?;
                    }
                }
                Some(Side::Back(link)) => {
                    relinking = false;
                    side = Some(Arc::new(link));
                    if !std::mem::replace(&mut side_up, true) {
                        emit(events, Event::Mosh(MoshEvent::Side(true))).await?;
                    }
                }
                None => {}
            },
            command = commands.recv() => match command {
                Some(Command::Input(bytes)) => {
                    for chunk in bytes.chunks(MAX_INPUT) {
                        if session.send_input(chunk.to_vec()).await.is_err() {
                            break;
                        }
                    }
                }
                Some(Command::Resize(columns, rows)) => drop(session.resize(columns.max(1), rows.max(1)).await),
                Some(Command::Pause(pause)) => paused = pause,
                Some(Command::Open(reply)) => match &side {
                    Some(link) => open_side(Arc::clone(link), reply, side_tx.clone()),
                    None => {
                        drop(reply.send(None));
                        // Re-establish without a prompt, but not on every glance of the sidebar.
                        if !relinking && last_relink.is_none_or(|at| at.elapsed() >= RELINK_PAUSE) {
                            relinking = true;
                            last_relink = Some(Instant::now());
                            let (connect, shared, side_tx) = (Arc::clone(&connect), Arc::clone(&shared), side_tx.clone());
                            tokio::spawn(async move {
                                let link = relink_quietly(&connect, &shared).await;
                                let _ = side_tx.send(link.map_or(Side::Gone, Side::Back)).await;
                            });
                        }
                    }
                },
                Some(Command::Relink) => {
                    // At the user's request: with prompts if necessary.
                    if side.is_none() && !relinking {
                        relinking = true;
                        last_relink = Some(Instant::now());
                        let (connect, shared, side_tx, events) = (Arc::clone(&connect), Arc::clone(&shared), side_tx.clone(), events.clone());
                        tokio::spawn(async move {
                            let link = establish_with(&connect, &events, Some(&shared)).await;
                            let _ = side_tx.send(link.map_or(Side::Gone, Side::Back)).await;
                        });
                    }
                }
                Some(Command::Close) | None => {
                    session.close();
                    let _ = timeout(Duration::from_secs(5), &mut running).await;
                    break Ok(End::User);
                }
            },
            result = &mut running => break match result {
                Ok(Ok(SessionExit::RemoteClosed)) => Ok(End::Remote { exit_status: None }),
                Ok(Ok(_)) => Ok(End::User),
                Ok(Err(error)) => Err(End::ConnectionLost(error.to_string())),
                Err(error) => Err(End::ConnectionLost(error.to_string())),
            },
        }
    };
    // What still arrived on screen before the end belongs to the session.
    while let Ok(Some(bytes)) = timeout(Duration::from_millis(200), session.next_output()).await {
        emit(events, Event::Output(bytes)).await?;
    }
    if let Some(link) = side {
        let _ = link.handle.disconnect(Disconnect::ByApplication, "", "en").await;
    }
    end
}

fn seconds(since: Instant) -> u32 {
    u32::try_from(since.elapsed().as_secs()).unwrap_or(u32::MAX)
}

/// Opens a channel on the SSH connection next to it, in a task of its own. If it does not answer, it counts as gone.
fn open_side(link: Arc<Link>, reply: oneshot::Sender<Option<files::Opened>>, side_tx: mpsc::Sender<Side>) {
    tokio::spawn(async move {
        if link.handle.is_closed() {
            let _ = reply.send(None);
            let _ = side_tx.send(Side::Gone).await;
            return;
        }
        match timeout(OPEN_LIMIT, link.handle.channel_open_session()).await {
            Ok(Ok(channel)) => drop(reply.send(Some(files::Opened(channel)))),
            // Refused (e.g. too many channels): the connection stands nevertheless.
            Ok(Err(_)) if !link.handle.is_closed() => drop(reply.send(None)),
            _ => {
                let _ = reply.send(None);
                let _ = side_tx.send(Side::Gone).await;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_the_server_command() {
        assert_eq!(server_command(&Mosh::default(), "C.UTF-8"), "mosh-server new -s -c 256 -l LANG=C.UTF-8");
        let custom = Mosh { predict: Predict::Never, port: Some("60001:60010".into()), server: Some("~/.local/bin/mosh-server".into()) };
        assert_eq!(server_command(&custom, "de_DE.UTF-8"), "~/.local/bin/mosh-server new -s -c 256 -l LANG=de_DE.UTF-8 -p 60001:60010");
    }

    #[test]
    fn language_comes_from_the_host_or_defaults_to_utf8() {
        let mut connect = Connect::default();
        assert_eq!(language(&connect), "C.UTF-8");
        connect.env = vec![("LANG".into(), "de_DE.UTF-8".into())];
        assert_eq!(language(&connect), "de_DE.UTF-8");
        // Whatever the shell could interpret does not go into the command.
        connect.env = vec![("LANG".into(), "x; rm -rf /".into())];
        assert_eq!(language(&connect), "C.UTF-8");
    }

    #[test]
    fn error_lines_are_short_and_printable() {
        assert_eq!(first_line(b"\n  mosh-server needs a UTF-8 native locale to run.\x1b[0m\nmore"), "mosh-server needs a UTF-8 native locale to run.[0m");
        assert_eq!(first_line(&[b'x'; 500]).len(), MAX_DETAIL);
    }
}

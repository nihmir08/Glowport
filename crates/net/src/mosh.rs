//! Mosh: Angemeldet wird per SSH, danach läuft das Terminal über UDP (`mosh-client`) und übersteht Netzwechsel
//! und Aussetzer. Die SSH-Verbindung bleibt daneben offen für die Kanäle der Seitenleiste (Dateien, Server-Info);
//! reißt sie ab, baut sie sich beim nächsten Bedarf neu auf, ohne zu fragen, mit dem, was beim ersten Mal
//! bestätigt und eingegeben wurde. Geht Mosh nicht (fehlt, nur IPv6, UDP gesperrt), läuft die Sitzung per SSH weiter.
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

/// Wie lange `mosh-server new` brauchen darf, bis es Port und Schlüssel nennt.
const START_LIMIT: Duration = Duration::from_secs(15);
/// Wie lange auf das erste Bild über UDP gewartet wird. Kommt keins, sperrt meist eine Firewall die Ports.
const ATTACH_LIMIT: Duration = Duration::from_secs(10);
/// So viel liest Glowport höchstens aus der Antwort von `mosh-server`.
const MAX_START_OUTPUT: usize = 16 * 1024;
/// Ab so viel Stille meldet die Bibliothek eine Unterbrechung (`NO_RECENT_CONTACT_MS` in `mosh-client`).
const SILENT_AFTER: Duration = Duration::from_millis(6_500);
/// Die SSH-Verbindung daneben wird höchstens so oft von selbst neu aufgebaut.
const RELINK_PAUSE: Duration = Duration::from_secs(15);
/// So lange darf das Öffnen eines Kanals auf der SSH-Verbindung daneben dauern, bevor sie als abgerissen gilt.
const OPEN_LIMIT: Duration = Duration::from_secs(5);
/// Größte Eingabe je Befehl an die Bibliothek (`MAX_INPUT_COMMAND_BYTES`).
const MAX_INPUT: usize = 64 * 1024;
const MAX_DETAIL: usize = 160;

/// Lokales Echo: zeigt Getipptes, bevor der Server es bestätigt.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Predict {
    /// Nur bei langsamer Leitung, wie das Original.
    #[default]
    Adaptive,
    Always,
    Never,
}

/// Mosh statt einer SSH-Shell. Gesetzt in [`Connect::mosh`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Mosh {
    pub predict: Predict,
    /// UDP-Port oder Bereich für `mosh-server -p`, etwa `60001` oder `60001:60010`. Vom Aufrufer geprüft.
    pub port: Option<String>,
    /// Pfad zu `mosh-server`, wenn er nicht im Suchpfad liegt. Vom Aufrufer geprüft (keine Leerzeichen, keine
    /// Zeichen, die die Shell deutet).
    pub server: Option<String>,
}

/// Warum die Sitzung statt über Mosh per SSH läuft.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fallback {
    /// `mosh-server` gibt es auf dem Server nicht.
    Missing,
    /// Der Host hat keine IPv4-Adresse; die Bibliothek kann nur IPv4.
    Ipv6,
    /// Über UDP kam keine Antwort.
    Udp,
    /// `mosh-server` hat einen Fehler gemeldet; seine erste Zeile.
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

/// Was eine Mosh-Sitzung über sich meldet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MoshEvent {
    /// Das Terminal läuft über Mosh.
    Active,
    /// Mosh kam nicht zustande; die Sitzung läuft per SSH.
    Fallback(Fallback),
    /// Sekunden ohne Nachricht vom Server; `None`, sobald er wieder antwortet.
    Silent(Option<u32>),
    /// Steht die SSH-Verbindung daneben (für Seitenleiste und Dateien)?
    Side(bool),
}

/// Was beim ersten Anmelden bestätigt und eingegeben wurde, damit die SSH-Verbindung daneben ohne Rückfrage
/// wiederkommt. Lebt nur im Speicher dieser Sitzung.
#[derive(Default)]
pub(crate) struct Memory {
    /// Bestätigte Server: Adresse und Port → Fingerabdruck.
    keys: HashMap<(String, u16), String>,
    /// Eingegebene Passwörter je Station (`benutzer@adresse`).
    passwords: HashMap<String, Secret>,
}

pub(crate) type Shared = Arc<Mutex<Memory>>;

fn memory(shared: &Shared) -> std::sync::MutexGuard<'_, Memory> {
    shared.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Merkt sich einen bestätigten Server-Schlüssel.
pub(crate) fn remember_key(shared: &Shared, host: &str, port: u16, fingerprint: &str) {
    memory(shared).keys.insert((host.to_string(), port), fingerprint.to_string());
}

/// Merkt sich ein angenommenes Passwort für eine Station.
pub(crate) fn remember_password(shared: &Shared, station: &str, password: &Secret) {
    memory(shared).passwords.insert(station.to_string(), password.clone());
}

/// Baut die SSH-Verbindung daneben neu auf, ohne jemanden zu fragen: nur zu Servern, die beim ersten Mal bestätigt
/// wurden, und nur mit dem, was gespeichert ist oder beim ersten Mal eingegeben wurde.
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

/// Die IPv4-Adresse, an die UDP geht: die der SSH-Verbindung, sonst wie dieser PC den Namen auflöst.
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

/// Sprache für `mosh-server`: wie am Host eingestellt, sonst eine UTF-8-Sprache, die fast jedes System kennt.
fn language(connect: &Connect) -> String {
    connect
        .env
        .iter()
        .find(|(name, _)| name == "LC_ALL" || name == "LANG")
        .map(|(_, value)| value.clone())
        .filter(|value| !value.is_empty() && value.chars().all(|c| c.is_ascii_alphanumeric() || "._-@".contains(c)))
        .unwrap_or_else(|| "C.UTF-8".into())
}

/// Der Befehl, der auf dem Server die Gegenstelle startet.
pub(crate) fn server_command(mosh: &Mosh, lang: &str) -> String {
    let program = mosh.server.as_deref().filter(|path| !path.is_empty()).unwrap_or("mosh-server");
    let mut command = format!("{program} new -s -c 256 -l LANG={lang}");
    if let Some(port) = mosh.port.as_deref().filter(|port| !port.is_empty()) {
        command.push_str(" -p ");
        command.push_str(port);
    }
    command
}

/// Erste lesbare Zeile einer Fehlermeldung, gekürzt und ohne Steuerzeichen.
fn first_line(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let line = text.lines().map(str::trim).find(|line| !line.is_empty()).unwrap_or("");
    line.chars().filter(|c| !c.is_control()).take(MAX_DETAIL).collect()
}

/// Liest, was `mosh-server` antwortet: Ausgabe und Fehlerausgabe getrennt, beides begrenzt.
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
    // Bleibt die Antwort aus, entscheidet, was bis dahin kam.
    let _ = timeout(START_LIMIT, read).await;
    Ok((stdout, stderr, status))
}

/// Die laufende Aufgabe der Bibliothek: Sie treibt UDP, Synchronisation und Vorhersage.
pub(crate) type Running = tokio::task::JoinHandle<Result<SessionExit, mosh_client::SessionError>>;

/// Startet `mosh-server` und baut die Mosh-Sitzung auf. `Err(Ok(Fallback))`: Mosh geht hier nicht, die SSH-Verbindung
/// steht aber; `Err(Err(End))`: die Verbindung selbst ist weg.
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

/// Was die Hilfsaufgaben der SSH-Verbindung daneben der Schleife melden.
enum Side {
    /// Die Verbindung antwortet nicht mehr; sie wird beim nächsten Bedarf neu aufgebaut.
    Gone,
    /// Eine neue Verbindung steht.
    Back(Link),
}

/// Reicht Ein- und Ausgabe zwischen Aufrufer und Mosh durch, bis die Shell endet oder der Nutzer schließt. Kanäle
/// für die Seitenleiste kommen von der SSH-Verbindung daneben; alles, was auf sie warten müsste, läuft in eigenen
/// Aufgaben, damit das Terminal nie stockt.
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
                // Die Aufgabe ist am Ende; ihr Ergebnis kommt gleich.
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
                        // Ohne Rückfrage neu aufbauen, aber nicht bei jedem Blick der Seitenleiste.
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
                    // Auf Wunsch des Nutzers: mit Rückfragen, falls nötig.
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
    // Was vor dem Ende noch auf dem Bildschirm ankam, gehört zur Sitzung.
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

/// Öffnet einen Kanal auf der SSH-Verbindung daneben, in eigener Aufgabe. Antwortet sie nicht, gilt sie als weg.
fn open_side(link: Arc<Link>, reply: oneshot::Sender<Option<files::Opened>>, side_tx: mpsc::Sender<Side>) {
    tokio::spawn(async move {
        if link.handle.is_closed() {
            let _ = reply.send(None);
            let _ = side_tx.send(Side::Gone).await;
            return;
        }
        match timeout(OPEN_LIMIT, link.handle.channel_open_session()).await {
            Ok(Ok(channel)) => drop(reply.send(Some(files::Opened(channel)))),
            // Abgelehnt (etwa zu viele Kanäle): Die Verbindung steht trotzdem.
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
        // Was die Shell deuten könnte, kommt nicht in den Befehl.
        connect.env = vec![("LANG".into(), "x; rm -rf /".into())];
        assert_eq!(language(&connect), "C.UTF-8");
    }

    #[test]
    fn error_lines_are_short_and_printable() {
        assert_eq!(first_line(b"\n  mosh-server needs a UTF-8 native locale to run.\x1b[0m\nmore"), "mosh-server needs a UTF-8 native locale to run.[0m");
        assert_eq!(first_line(&[b'x'; 500]).len(), MAX_DETAIL);
    }
}

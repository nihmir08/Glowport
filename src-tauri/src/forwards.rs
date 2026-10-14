//! Port rules in operation: switch on, switch off, report state, reconnect after a drop.
//!
//! The rules themselves live in the vault. Only which ones are switched on right now is kept here. They belong to the program,
//! not to a window, and keep running when no terminal is open; they end when the program ends.
//!
//! Switching on establishes a connection of its own and may ask like a terminal while doing so (unknown server,
//! password): setup runs as an entry of the session manager until the forward stands. If the connection drops
//! later, it reconnects without prompts; if that would need one, the rule stays marked as failed.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, MutexGuard,
    },
    time::Duration,
};

use glowport_core::{
    directory::{ForwardInput, ForwardView, Verdict},
    model::ForwardKind,
};
use glowport_net::{
    forward::{self, Counters, Rule, Tunnel},
    Connect, End, Event,
};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State, Window};
use tokio::{net::TcpListener, sync::oneshot};

use crate::{
    app::{AppState, Changed, CmdError, CmdResult},
    sessions,
};

/// Waiting times before the attempts to reconnect after a drop, in seconds. After that the last one stays.
const BACKOFF: [u32; 5] = [2, 5, 10, 20, 30];

#[derive(Default)]
pub struct Forwards {
    turns: AtomicU64,
    rules: Mutex<HashMap<String, Running>>,
}

/// A switched-on rule.
struct Running {
    /// Tells apart switch-on runs of the same rule. Whoever is no longer the current one changes nothing more.
    turn: u64,
    phase: Phase,
    /// Error code and message while it has failed or is reconnecting.
    error: Option<(String, String)>,
    counters: Arc<Counters>,
    /// Since when the forward stands, in milliseconds since 1970.
    since: Option<i64>,
    retry_in: Option<u32>,
    /// Number of the connection setup in the session manager while it runs; it can be cancelled with it.
    connecting: Option<u64>,
    /// Ends the task that watches over the standing forward.
    stop: Option<oneshot::Sender<()>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Starting,
    Running,
    Retrying,
    Failed,
}

/// State of a switched-on rule for the interface.
#[derive(Serialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ForwardState {
    id: String,
    phase: &'static str,
    error: Option<String>,
    message: Option<String>,
    open: u32,
    total: u64,
    sent: u64,
    received: u64,
    since: Option<i64>,
    retry_in: Option<u32>,
}

impl Forwards {
    fn rules(&self) -> MutexGuard<'_, HashMap<String, Running>> {
        self.rules.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn list(&self) -> Vec<ForwardState> {
        let mut list: Vec<ForwardState> = self
            .rules()
            .iter()
            .map(|(id, rule)| ForwardState {
                id: id.clone(),
                phase: match rule.phase {
                    Phase::Starting => "starting",
                    Phase::Running => "running",
                    Phase::Retrying => "retrying",
                    Phase::Failed => "failed",
                },
                error: rule.error.as_ref().map(|(code, _)| code.clone()),
                message: rule.error.as_ref().map(|(_, message)| message.clone()).filter(|message| !message.is_empty()),
                open: rule.counters.open.load(Ordering::Relaxed),
                total: rule.counters.total.load(Ordering::Relaxed),
                sent: rule.counters.sent.load(Ordering::Relaxed),
                received: rule.counters.received.load(Ordering::Relaxed),
                since: rule.since,
                retry_in: rule.retry_in,
            })
            .collect();
        list.sort_by(|a, b| a.id.cmp(&b.id));
        list
    }

    /// Changes a rule if `turn` is still its current switch-on run. Returns whether that was the case.
    fn update(&self, id: &str, turn: u64, change: impl FnOnce(&mut Running)) -> bool {
        match self.rules().get_mut(id) {
            Some(rule) if rule.turn == turn => {
                change(rule);
                true
            }
            _ => false,
        }
    }
}

fn publish(app: &AppHandle) {
    let _ = app.emit("forwards", app.state::<Forwards>().list());
}

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |since| since.as_millis() as i64)
}

/// Error code and message for what a setup failed on.
fn reason(end: &End) -> (String, String) {
    let (code, message) = match end {
        End::User => ("needs_prompt", ""),
        End::Remote { .. } => ("connection_lost", ""),
        End::ConnectFailed(message) => ("connect_failed", message.as_str()),
        End::HostKeyRejected => ("host_key_rejected", ""),
        End::AuthFailed => ("auth_failed", ""),
        End::ConnectionLost(message) => ("connection_lost", message.as_str()),
        End::Refused(message) => ("remote_refused", message.as_str()),
    };
    (code.to_string(), message.to_string())
}

/// What the connection core should set up for a rule.
fn rule_of(view: &ForwardView) -> Rule {
    match view.kind {
        ForwardKind::Local => Rule::Local { host: view.dest_host.clone(), port: view.dest_port },
        ForwardKind::Dynamic => Rule::Dynamic,
        ForwardKind::Remote => Rule::Remote { bind: view.bind_address.clone(), bind_port: view.bind_port, host: view.dest_host.clone(), port: view.dest_port },
    }
}

/// Opens the port on this machine that a local or dynamic rule listens on. `None` for a rule
/// where the server listens. That way a port in use shows at once and not only after signing in.
async fn listen(view: &ForwardView) -> CmdResult<Option<TcpListener>> {
    if view.kind == ForwardKind::Remote {
        return Ok(None);
    }
    match TcpListener::bind((view.bind_address.as_str(), view.bind_port)).await {
        Ok(listener) => Ok(Some(listener)),
        Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => Err(CmdError::new("port_in_use", error.to_string())),
        Err(error) => Err(CmdError::new("bind_failed", error.to_string())),
    }
}

/// Reads rule and connection details from the vault.
fn plan(app: &AppHandle, id: &str) -> CmdResult<(ForwardView, Connect, String)> {
    let state = app.state::<AppState>();
    let mut session = state.session();
    let directory = session.directory()?;
    let view = directory.forward(id)?;
    let connect = sessions::connect_chain(directory, &view.host)?;
    let label = directory.connect_info(&view.host)?.name;
    Ok((view, connect, label))
}

/// Switches a rule on. Returns the number of the connection setup: prompts arrive under it as the event
/// `session`, and `session_answer` takes the answers. The `forwards` event reports how the rule is doing.
#[tauri::command]
pub async fn forward_start(app: AppHandle, window: Window, id: String) -> CmdResult<u64> {
    let (view, connect, label) = plan(&app, &id)?;
    halt(&app, &id);
    let listener = listen(&view).await?;
    let forwards = app.state::<Forwards>();
    let turn = forwards.turns.fetch_add(1, Ordering::Relaxed) + 1;
    let counters = Arc::new(Counters::default());
    let link = forward::open(connect, rule_of(&view), listener, Arc::clone(&counters));
    let number = sessions::connect_forward(&app, window.label(), view.host.clone(), label, link, (id.clone(), turn));
    forwards.rules().insert(id, Running { turn, phase: Phase::Starting, error: None, counters, since: None, retry_in: None, connecting: Some(number), stop: None });
    publish(&app);
    Ok(number)
}

#[tauri::command]
pub fn forward_stop(app: AppHandle, id: String) {
    halt(&app, &id);
    publish(&app);
}

#[tauri::command]
pub fn forward_list(forwards: State<'_, Forwards>) -> Vec<ForwardState> {
    forwards.list()
}

/// Takes a rule out of operation: a running setup is cancelled, a standing forward disconnected.
fn halt(app: &AppHandle, id: &str) {
    let Some(mut rule) = app.state::<Forwards>().rules().remove(id) else { return };
    if let Some(number) = rule.connecting.take() {
        sessions::close(app, number);
    }
    if let Some(stop) = rule.stop.take() {
        let _ = stop.send(());
    }
}

/// The setup succeeded: the forward stands and is watched from now on.
pub(crate) fn adopt(app: &AppHandle, id: &str, turn: u64, tunnel: Tunnel) {
    let (stop, stopped) = oneshot::channel();
    let current = app.state::<Forwards>().update(id, turn, |rule| {
        rule.phase = Phase::Running;
        rule.error = None;
        rule.since = Some(now_ms());
        rule.connecting = None;
        rule.stop = Some(stop);
    });
    // Switched off in the meantime: the tunnel is dropped and thereby disconnects.
    if current {
        tauri::async_runtime::spawn(supervise(app.clone(), id.to_string(), turn, tunnel, stopped));
        publish(app);
    }
}

/// The setup failed or was cancelled.
pub(crate) fn ended(app: &AppHandle, id: &str, turn: u64, end: &End) {
    let forwards = app.state::<Forwards>();
    let current = if *end == End::User {
        // The user cancelled the prompt: the rule is off again.
        let mut rules = forwards.rules();
        let mine = rules.get(id).is_some_and(|rule| rule.turn == turn);
        if mine {
            rules.remove(id);
        }
        mine
    } else {
        forwards.update(id, turn, |rule| {
            rule.phase = Phase::Failed;
            rule.error = Some(reason(end));
            rule.connecting = None;
        })
    };
    if current {
        publish(app);
    }
}

/// Watches over a standing forward. If the connection drops, it reconnects until it works, the rule
/// is switched off or it is clear that it does not work without a prompt.
async fn supervise(app: AppHandle, id: String, turn: u64, mut tunnel: Tunnel, mut stopped: oneshot::Receiver<()>) {
    loop {
        let end = tokio::select! {
            end = tunnel.closed() => end,
            _ = &mut stopped => return,
        };
        drop(tunnel);
        if end == End::User || !app.state::<Forwards>().update(&id, turn, |rule| (rule.phase, rule.error, rule.since) = (Phase::Retrying, Some(reason(&end)), None)) {
            return;
        }
        let mut attempt = 0;
        tunnel = loop {
            let wait = BACKOFF[attempt.min(BACKOFF.len() - 1)];
            attempt += 1;
            for left in (1..=wait).rev() {
                if !app.state::<Forwards>().update(&id, turn, |rule| rule.retry_in = Some(left)) {
                    return;
                }
                publish(&app);
                tokio::select! {
                    () = tokio::time::sleep(Duration::from_secs(1)) => {}
                    _ = &mut stopped => return,
                }
            }
            let forwards = app.state::<Forwards>();
            if !forwards.update(&id, turn, |rule| rule.retry_in = None) {
                return;
            }
            publish(&app);
            let counters = match forwards.rules().get(&id) {
                Some(rule) => Arc::clone(&rule.counters),
                None => return,
            };
            let outcome = tokio::select! {
                outcome = reconnect(&app, &id, counters) => outcome,
                _ = &mut stopped => return,
            };
            match outcome {
                Ok(tunnel) => break tunnel,
                // Temporary: try again right away, with a longer pause.
                Err(error) if matches!(error.0.as_str(), "connect_failed" | "connection_lost" | "port_in_use" | "bind_failed" | "locked") => {
                    if !forwards.update(&id, turn, |rule| rule.error = Some(error)) {
                        return;
                    }
                }
                Err(error) => {
                    if forwards.update(&id, turn, |rule| (rule.phase, rule.error, rule.stop) = (Phase::Failed, Some(error), None)) {
                        publish(&app);
                    }
                    return;
                }
            }
        };
        if !app.state::<Forwards>().update(&id, turn, |rule| (rule.phase, rule.error, rule.since) = (Phase::Running, None, Some(now_ms()))) {
            return;
        }
        publish(&app);
    }
}

/// Sets up the forward once more without asking anyone: only known servers, only stored credentials.
async fn reconnect(app: &AppHandle, id: &str, counters: Arc<Counters>) -> Result<Tunnel, (String, String)> {
    let failed = |error: CmdError| (error.code().to_string(), String::new());
    let (view, connect, _) = plan(app, id).map_err(failed)?;
    let listener = listen(&view).await.map_err(failed)?;
    let mut link = forward::open(connect, rule_of(&view), listener, counters);
    loop {
        match link.events.recv().await {
            Some(Event::HostKey { host, port, key, reply }) => {
                let trusted = app.state::<AppState>().session().directory().is_ok_and(|d| d.judge_host_key(&host, port, &key.openssh) == Verdict::Trusted);
                let _ = reply.send(trusted);
            }
            // Nobody there who could answer: cancel. That ends as “ended by the user” and is called `needs_prompt` here.
            Some(Event::Secret { reply, .. }) => drop(reply.send(None)),
            Some(Event::Interactive { reply, .. }) => drop(reply.send(None)),
            Some(Event::Forward(tunnel)) => return Ok(tunnel),
            Some(Event::End(end)) => return Err(reason(&end)),
            Some(_) => {}
            None => return Err(("connection_lost".into(), String::new())),
        }
    }
}

/// Reports the state every second while something happens (counters, connections), and switches off rules that no longer
/// exist in the vault, e.g. because their host was deleted. Call once at startup.
pub fn watch(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        let mut last = Vec::new();
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let forwards = app.state::<Forwards>();
            let on: Vec<String> = forwards.rules().keys().cloned().collect();
            if on.is_empty() && last.is_empty() {
                continue;
            }
            // With a locked vault nothing can be checked; then everything stays as it is.
            let gone: Vec<String> = match app.state::<AppState>().session().directory() {
                Ok(directory) => on.into_iter().filter(|id| directory.forward(id).is_err()).collect(),
                Err(_) => Vec::new(),
            };
            for id in &gone {
                halt(&app, id);
            }
            let list = forwards.list();
            if list != last {
                let _ = app.emit("forwards", &list);
                last = list;
            }
        }
    });
}

#[tauri::command]
pub fn forward_save(app: AppHandle, state: State<'_, AppState>, rule: ForwardInput, vault: Option<String>) -> CmdResult<Changed> {
    let mut session = state.session();
    let id = session.directory()?.in_vault(vault.as_deref(), |directory| directory.save_forward(rule))?;
    // A changed rule does not keep running with the old values.
    halt(&app, &id);
    publish(&app);
    session.changed(Some(id))
}

#[tauri::command]
pub fn forward_delete(app: AppHandle, state: State<'_, AppState>, id: String) -> CmdResult<Changed> {
    let mut session = state.session();
    session.directory()?.delete_forward(&id)?;
    halt(&app, &id);
    publish(&app);
    session.changed(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ends_become_codes_the_interface_knows() {
        let code = |end: End| reason(&end).0;
        assert_eq!(code(End::User), "needs_prompt", "a cancelled prompt during a silent reconnect");
        assert_eq!(code(End::AuthFailed), "auth_failed");
        assert_eq!(code(End::HostKeyRejected), "host_key_rejected");
        assert_eq!(reason(&End::ConnectFailed("timed out".into())), ("connect_failed".into(), "timed out".into()));
        assert_eq!(reason(&End::Refused("127.0.0.1:8080".into())), ("remote_refused".into(), "127.0.0.1:8080".into()));
        assert_eq!(code(End::ConnectionLost(String::new())), "connection_lost");
    }

    #[test]
    fn rules_turn_into_what_the_connection_core_expects() {
        let view = |kind| ForwardView { id: "x".into(), name: "n".into(), kind, host: "h".into(), bind_address: "127.0.0.1".into(), bind_port: 8080, dest_host: "10.0.0.5".into(), dest_port: 80 };
        assert_eq!(rule_of(&view(ForwardKind::Local)), Rule::Local { host: "10.0.0.5".into(), port: 80 });
        assert_eq!(rule_of(&view(ForwardKind::Dynamic)), Rule::Dynamic);
        assert_eq!(rule_of(&view(ForwardKind::Remote)), Rule::Remote { bind: "127.0.0.1".into(), bind_port: 8080, host: "10.0.0.5".into(), port: 80 });
    }

    #[tokio::test]
    async fn a_taken_port_is_reported_before_anything_connects() {
        let taken = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = taken.local_addr().unwrap().port();
        let view = |kind, bind_port| ForwardView { id: "x".into(), name: "n".into(), kind, host: "h".into(), bind_address: "127.0.0.1".into(), bind_port, dest_host: "127.0.0.1".into(), dest_port: 80 };
        assert_eq!(listen(&view(ForwardKind::Local, port)).await.unwrap_err().code(), "port_in_use");
        assert_eq!(listen(&view(ForwardKind::Dynamic, port)).await.unwrap_err().code(), "port_in_use");
        assert!(listen(&view(ForwardKind::Remote, port)).await.unwrap().is_none(), "for a remote rule the server listens");
        drop(taken);
        assert!(listen(&view(ForwardKind::Local, port)).await.unwrap().is_some());
    }

    #[test]
    fn only_the_current_turn_changes_a_rule() {
        let forwards = Forwards::default();
        forwards.rules().insert("regel".into(), Running { turn: 2, phase: Phase::Starting, error: None, counters: Arc::default(), since: None, retry_in: None, connecting: None, stop: None });
        assert!(!forwards.update("regel", 1, |rule| rule.phase = Phase::Failed), "an outdated operation changes nothing");
        assert!(forwards.update("regel", 2, |rule| (rule.phase, rule.error) = (Phase::Retrying, Some(("connection_lost".into(), String::new())))));
        assert!(!forwards.update("andere", 2, |_| {}));
        let list = forwards.list();
        assert_eq!((list[0].phase, list[0].error.as_deref(), list[0].message.as_deref()), ("retrying", Some("connection_lost"), None));
        assert_eq!(serde_json::to_value(&list[0]).unwrap()["retryIn"], serde_json::Value::Null);
    }
}

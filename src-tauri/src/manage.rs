//! Management in a session's sidebar: Docker, services, processes (`docs/management.md`).
//!
//! The commands and reading their output come from `glowport_net::manage`; here they run on the session's
//! connection, and here is the order of permissions: first as the signed-in user, then with `sudo -n`.
//! If `sudo` wants a password, the command goes back to the interface, which writes it into the terminal. Glowport
//! does not ask for a sudo password.

use glowport_net::manage::{self, docker, processes, services, As, Verdict};
use serde::{Deserialize, Serialize};
use tauri::AppHandle;

use crate::app::{CmdError, CmdResult};
use crate::files::{self, Place};

/// Runs a command on the session's connection: whether it succeeded and what it printed.
async fn run(app: &AppHandle, session: u64, command: &str) -> CmdResult<(bool, String)> {
    let output = files::run_at(app, &Place::Session { id: session }, command).await?;
    Ok((output.exit_status == Some(0), String::from_utf8_lossy(&output.stdout).into_owned()))
}

fn failed(message: String) -> CmdError {
    CmdError::new("manage_failed", message)
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AbilitiesView {
    root: bool,
    docker: bool,
    services: bool,
    processes: bool,
    sudo: bool,
}

/// What there is to manage on a session's server.
#[tauri::command]
pub async fn manage_probe(app: AppHandle, session: u64) -> CmdResult<AbilitiesView> {
    let (_, text) = run(&app, session, manage::PROBE).await?;
    let found = manage::abilities(&text);
    Ok(AbilitiesView { root: found.root, docker: found.docker, services: found.services, processes: found.processes, sudo: found.sudo })
}

/// A list, or why there is none (`Listed` in `types.ts`).
#[derive(Debug, Serialize, PartialEq)]
#[serde(tag = "state", rename_all = "camelCase")]
pub enum Listed<T> {
    Ok { items: T, sudo: bool },
    Password,
    Failed { message: String },
}

/// Ausgang einer Aktion (`ManageDone` in `types.ts`).
#[derive(Debug, Serialize, PartialEq)]
#[serde(tag = "outcome", rename_all = "camelCase")]
pub enum Done {
    Done,
    /// `sudo` will ein Passwort: Diesen Befehl schickt der Nutzer selbst im Terminal ab.
    Password { command: String },
}

/// Führt eine Aktion aus: als Benutzer, und wenn dem die Rechte fehlen, mit `sudo -n`.
async fn act(app: &AppHandle, session: u64, command: impl Fn(As) -> Option<String>, typed: Option<String>) -> CmdResult<Done> {
    let invalid = || CmdError::new("manage_failed", "Ungültige Angabe");
    let typed = typed.ok_or_else(invalid)?;
    for how in [As::User, As::Sudo] {
        let (ok, text) = run(app, session, &command(how).ok_or_else(invalid)?).await?;
        match manage::verdict(ok, &text, how) {
            Verdict::Done => return Ok(Done::Done),
            Verdict::NeedsRoot => continue,
            Verdict::NeedsPassword => return Ok(Done::Password { command: manage::typed(&typed) }),
            Verdict::Failed(message) => return Err(failed(message)),
        }
    }
    // Auch mit sudo abgelehnt, ohne dass es ein Passwort wollte: Das meldet schon der zweite Durchlauf als Fehler.
    Err(failed(String::new()))
}

// ── Docker ───────────────────────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, PartialEq)]
pub struct MemoryView {
    used: u64,
    limit: u64,
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ContainerView {
    id: String,
    name: String,
    image: String,
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    health: Option<&'static str>,
    ports: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    since: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cpu: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    memory: Option<MemoryView>,
}

fn container(c: docker::Container) -> ContainerView {
    ContainerView {
        id: c.id,
        name: c.name,
        image: c.image,
        state: c.state.name(),
        health: c.health.map(docker::Health::name),
        ports: c.ports,
        since: c.since,
        exit_code: c.exit_code,
        cpu: c.cpu,
        memory: c.memory.map(|(used, limit)| MemoryView { used, limit }),
    }
}

/// Was aus der Ausgabe eines Versuchs wird. `None`: Dem Benutzer fehlen die Rechte, der nächste Versuch gilt.
fn containers(text: &str, how: As) -> Option<Listed<Vec<ContainerView>>> {
    match docker::parse(text) {
        docker::Listing::Containers(list) => Some(Listed::Ok { items: list.into_iter().map(container).collect(), sudo: how == As::Sudo }),
        docker::Listing::Refused(text) => match manage::verdict(false, &text, how) {
            Verdict::NeedsRoot => None,
            Verdict::NeedsPassword => Some(Listed::Password),
            Verdict::Failed(message) => Some(Listed::Failed { message }),
            Verdict::Done => Some(Listed::Failed { message: String::new() }),
        },
    }
}

#[tauri::command]
pub async fn docker_list(app: AppHandle, session: u64) -> CmdResult<Listed<Vec<ContainerView>>> {
    for how in [As::User, As::Sudo] {
        let (_, text) = run(&app, session, &docker::list_command(how)).await?;
        if let Some(listed) = containers(&text, how) {
            return Ok(listed);
        }
    }
    Ok(Listed::Password)
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DockerAction {
    Start,
    Stop,
    Restart,
}

impl From<DockerAction> for docker::Action {
    fn from(action: DockerAction) -> Self {
        match action {
            DockerAction::Start => docker::Action::Start,
            DockerAction::Stop => docker::Action::Stop,
            DockerAction::Restart => docker::Action::Restart,
        }
    }
}

#[tauri::command]
pub async fn docker_action(app: AppHandle, session: u64, container: String, action: DockerAction) -> CmdResult<Done> {
    let action = docker::Action::from(action);
    act(&app, session, |how| action.command(&container, how), action.typed(&container)).await
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DockerTab {
    Logs,
    Shell,
}

/// Was in einen neuen Tab getippt wird, damit dort die Logs mitlaufen oder eine Shell im Container aufgeht.
#[tauri::command]
pub fn docker_line(container: String, kind: DockerTab, sudo: bool) -> CmdResult<String> {
    match kind {
        DockerTab::Logs => docker::logs_line(&container, sudo),
        DockerTab::Shell => docker::shell_line(&container, sudo),
    }
    .ok_or_else(|| failed("Ungültige Kennung".into()))
}

// ── Dienste ──────────────────────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, PartialEq)]
pub struct ServiceView {
    unit: String,
    description: String,
    active: &'static str,
    sub: String,
    enabled: &'static str,
}

#[tauri::command]
pub async fn service_list(app: AppHandle, session: u64) -> CmdResult<Listed<Vec<ServiceView>>> {
    let (_, text) = run(&app, session, services::LIST).await?;
    Ok(match services::parse(&text) {
        Some(list) => Listed::Ok {
            items: list.into_iter().map(|s| ServiceView { unit: s.unit, description: s.description, active: s.active.name(), sub: s.sub, enabled: s.enabled.name() }).collect(),
            sudo: false,
        },
        None => Listed::Failed { message: String::new() },
    })
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceAction {
    Start,
    Stop,
    Restart,
    Enable,
    Disable,
}

impl From<ServiceAction> for services::Action {
    fn from(action: ServiceAction) -> Self {
        match action {
            ServiceAction::Start => services::Action::Start,
            ServiceAction::Stop => services::Action::Stop,
            ServiceAction::Restart => services::Action::Restart,
            ServiceAction::Enable => services::Action::Enable,
            ServiceAction::Disable => services::Action::Disable,
        }
    }
}

#[tauri::command]
pub async fn service_action(app: AppHandle, session: u64, unit: String, action: ServiceAction) -> CmdResult<Done> {
    let action = services::Action::from(action);
    act(&app, session, |how| action.command(&unit, how), action.typed(&unit)).await
}

/// Zustand und letzte Meldungen eines Dienstes als Text. Ein Dienst, der nicht läuft, ist dabei kein Fehler.
#[tauri::command]
pub async fn service_status(app: AppHandle, session: u64, unit: String) -> CmdResult<String> {
    let command = services::status_command(&unit, As::User).ok_or_else(|| failed("Ungültiger Name".into()))?;
    Ok(run(&app, session, &command).await?.1.trim_end().to_string())
}

/// Was in einen neuen Tab getippt wird, damit dort das Journal des Dienstes mitläuft.
#[tauri::command]
pub fn service_line(unit: String, sudo: bool) -> CmdResult<String> {
    services::journal_line(&unit, sudo).ok_or_else(|| failed("Ungültiger Name".into()))
}

// ── Prozesse ─────────────────────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, PartialEq)]
pub struct ProcessView {
    pid: u32,
    parent: u32,
    user: String,
    name: String,
    command: String,
    memory: u64,
    elapsed: u64,
    ticks: u64,
    kernel: bool,
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SampleView {
    ticks_per_second: u32,
    uptime: f64,
    memory_total: u64,
    processes: Vec<ProcessView>,
}

fn sample(sample: processes::Sample) -> SampleView {
    SampleView {
        ticks_per_second: sample.ticks_per_second,
        uptime: sample.uptime,
        memory_total: sample.memory_total,
        processes: sample.processes.into_iter().map(|p| ProcessView { pid: p.pid, parent: p.parent, user: p.user, name: p.name, command: p.command, memory: p.memory, elapsed: p.elapsed, ticks: p.ticks, kernel: p.kernel }).collect(),
    }
}

/// Eine Messung der Prozesse. `None`: Der Server gibt die Liste nicht her.
#[tauri::command]
pub async fn process_list(app: AppHandle, session: u64) -> CmdResult<Option<SampleView>> {
    let (_, text) = run(&app, session, processes::LIST).await?;
    Ok(processes::parse(&text).map(sample))
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KillSignal {
    Term,
    Kill,
}

#[tauri::command]
pub async fn process_kill(app: AppHandle, session: u64, pid: u32, signal: KillSignal) -> CmdResult<Done> {
    let signal = match signal {
        KillSignal::Term => processes::Signal::Term,
        KillSignal::Kill => processes::Signal::Kill,
    };
    act(&app, session, |how| signal.command(pid, how), signal.typed(pid)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ID: &str = "4c01db0b339c4c01db0b339c4c01db0b339c4c01db0b339c4c01db0b339c4c01";

    #[test]
    fn lists_and_outcomes_take_the_shape_the_interface_reads() {
        let text = format!("@now\n100\n@ps\n{ID}|web|nginx:1.27|0.0.0.0:8080->80/tcp\n@inspect\n{ID}|running|healthy|1970-01-01T00:00:40Z|0001-01-01T00:00:00Z|0\n@stats\n{ID}|1.50%|10MiB / 1GiB\n");
        assert_eq!(
            serde_json::to_value(containers(&text, As::Sudo)).unwrap(),
            json!({ "state": "ok", "sudo": true, "items": [{ "id": ID, "name": "web", "image": "nginx:1.27", "state": "running", "health": "healthy", "ports": ["8080->80/tcp"], "since": 60, "cpu": 1.5, "memory": { "used": 10_485_760, "limit": 1_073_741_824 } }] })
        );
        // Abgelehnt: als Benutzer geht es mit sudo weiter, unter sudo ist es ein Passwort oder ein Fehler.
        let denied = "@error\npermission denied while trying to connect to the Docker daemon socket\n";
        assert_eq!(containers(denied, As::User), None);
        assert_eq!(serde_json::to_value(containers("@error\nsudo: a password is required\n", As::Sudo)).unwrap(), json!({ "state": "password" }));
        assert_eq!(serde_json::to_value(containers("@error\nCannot connect to the Docker daemon. Is the docker daemon running?\n", As::User)).unwrap(), json!({ "state": "failed", "message": "Cannot connect to the Docker daemon. Is the docker daemon running?" }));

        assert_eq!(serde_json::to_value(Done::Done).unwrap(), json!({ "outcome": "done" }));
        assert_eq!(serde_json::to_value(Done::Password { command: "sudo kill -TERM 4711".into() }).unwrap(), json!({ "outcome": "password", "command": "sudo kill -TERM 4711" }));

        let processes = processes::parse("@clock\n100\n50.5 1.0\n@mem\nMemTotal: 2048 kB\n@ps\n  7  1 alex  1024  30 /usr/bin/python3 bot.py\n@stat\n7 (python3) S 1 7 7 0 -1 0 0 0 0 0 250 50 0 0 20 0 1 0 0 0 0 0\n").map(sample);
        assert_eq!(
            serde_json::to_value(processes).unwrap(),
            json!({ "ticksPerSecond": 100, "uptime": 50.5, "memoryTotal": 2_097_152, "processes": [{ "pid": 7, "parent": 1, "user": "alex", "name": "python3", "command": "/usr/bin/python3 bot.py", "memory": 1_048_576, "elapsed": 30, "ticks": 300, "kernel": false }] })
        );
    }

    #[test]
    fn what_the_interface_sends_is_understood() {
        assert!(matches!(serde_json::from_value::<DockerAction>(json!("restart")).unwrap(), DockerAction::Restart));
        assert!(matches!(serde_json::from_value::<DockerTab>(json!("shell")).unwrap(), DockerTab::Shell));
        assert!(matches!(serde_json::from_value::<ServiceAction>(json!("disable")).unwrap(), ServiceAction::Disable));
        assert!(matches!(serde_json::from_value::<KillSignal>(json!("kill")).unwrap(), KillSignal::Kill));
        assert!(serde_json::from_value::<ServiceAction>(json!("mask")).is_err());
        // Was keine Kennung und kein Name ist, wird gar nicht erst zu einem Befehl.
        assert!(docker_line("web; reboot".into(), DockerTab::Logs, false).is_err());
        assert!(service_line("cron.service; reboot".into(), false).is_err());
        assert_eq!(docker_line(ID.into(), DockerTab::Logs, true).unwrap(), "sudo docker logs --tail 200 -f 4c01db0b339c");
        assert_eq!(service_line("cron.service".into(), false).unwrap(), "journalctl -n 100 -f -u 'cron.service'");
    }
}

//! Snippets: save, delete and run on several hosts. Plus the measurement for the server info.
//!
//! In the terminal the interface simply types a snippet into the session; nothing is needed here for that. “Run on
//! hosts”, however, runs without a terminal: per host a connection of its own, no prompts, one command, disconnect.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use glowport_core::directory::{SnippetInput, Verdict};
use glowport_net::{self as net, stats, End};
use serde::Serialize;
use tauri::{ipc::Channel, AppHandle, Manager, State};
use tokio::sync::{watch, Semaphore};

use crate::{
    app::{AppState, Changed, CmdResult},
    files::{self, Place},
    sessions::connect_chain,
};

/// This many hosts are served at the same time.
const PARALLEL: usize = 4;
/// This long the command may run on a host.
const RUN_LIMIT: Duration = Duration::from_secs(600);
/// This much output per host is shown.
const MAX_OUTPUT: usize = 256 * 1024;

/// Running “run on hosts” jobs, so they can be cancelled: number of the run → cancel signal.
#[derive(Default)]
pub struct Runs(Mutex<HashMap<u64, watch::Sender<bool>>>);

#[tauri::command]
pub fn snippet_save(state: State<'_, AppState>, snippet: SnippetInput, vault: Option<String>) -> CmdResult<Changed> {
    let mut session = state.session();
    let id = session.directory()?.in_vault(vault.as_deref(), |directory| directory.save_snippet(snippet))?;
    session.changed(Some(id))
}

#[tauri::command]
pub fn snippet_delete(state: State<'_, AppState>, id: String) -> CmdResult<Changed> {
    let mut session = state.session();
    session.directory()?.delete_snippet(&id)?;
    session.changed(None)
}

/// State or result of a command on a host.
#[derive(Clone, Serialize)]
pub struct RunResult {
    host: String,
    /// `running`, `done` (see `exit`) or `failed` (see `error`).
    state: &'static str,
    exit: Option<u32>,
    output: String,
    truncated: bool,
    /// Reason for the failure as a code the interface translates.
    error: Option<&'static str>,
    ms: u64,
}

impl RunResult {
    fn failed(host: String, error: &'static str, ms: u64) -> Self {
        Self { host, state: "failed", exit: None, output: String::new(), truncated: false, error: Some(error), ms }
    }
}

/// A command's output as text for display: line ends unified, without colors and control characters.
fn readable(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes).replace("\r\n", "\n");
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            // Colors and cursor commands: `ESC [ … letter`. Everything else after ESC is dropped with it.
            '\x1b' => {
                if chars.next_if_eq(&'[').is_some() {
                    while chars.next_if(|c| !c.is_ascii_alphabetic()).is_some() {}
                    chars.next();
                }
            }
            '\n' | '\t' => out.push(c),
            // A lone carriage return redraws the line (progress bars); here a new one begins.
            '\r' => out.push('\n'),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

/// Runs the command on a host. It signs in with what is stored for the host, without prompts;
/// the key of every server on the way must already be known.
async fn run_on(app: &AppHandle, host: &str, command: &str) -> Result<net::Output, &'static str> {
    let state = app.state::<AppState>();
    let connect = match state.session().directory() {
        Ok(directory) => connect_chain(directory, host).map_err(|_| "not_found")?,
        Err(_) => return Err("locked"),
    };
    let trusted = |address: &str, port: u16, shown: &net::HostKey| state.session().directory().is_ok_and(|d| d.judge_host_key(address, port, &shown.openssh) == Verdict::Trusted);
    match net::run_command(&connect, command, RUN_LIMIT, MAX_OUTPUT, trusted).await {
        Ok(output) => Ok(output),
        Err(End::AuthFailed) => Err("auth_failed"),
        Err(End::HostKeyRejected) => Err("host_key"),
        Err(End::ConnectionLost(message)) if message == net::COMMAND_TIMED_OUT => Err("timeout"),
        Err(_) => Err("connect_failed"),
    }
}

/// Runs a command on several hosts, some at once, and reports every host through `results` as soon as it
/// starts and as soon as it is done. `run` is the number under which `snippet_cancel` cancels the run.
#[tauri::command]
pub async fn snippet_run(app: AppHandle, run: u64, command: String, hosts: Vec<String>, results: Channel<RunResult>) -> CmdResult<()> {
    let (cancel, cancelled) = watch::channel(false);
    app.state::<Runs>().0.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).insert(run, cancel);
    let command: Arc<str> = command.into();
    let slots = Arc::new(Semaphore::new(PARALLEL));
    let mut tasks = tokio::task::JoinSet::new();
    for host in hosts {
        let (app, command, slots, results, mut cancelled) = (app.clone(), Arc::clone(&command), Arc::clone(&slots), results.clone(), cancelled.clone());
        tasks.spawn(async move {
            let _slot = slots.acquire().await;
            if *cancelled.borrow() {
                return drop(results.send(RunResult::failed(host, "cancelled", 0)));
            }
            let _ = results.send(RunResult { host: host.clone(), state: "running", exit: None, output: String::new(), truncated: false, error: None, ms: 0 });
            let started = Instant::now();
            let outcome = tokio::select! {
                outcome = run_on(&app, &host, &command) => outcome,
                _ = cancelled.wait_for(|stop| *stop) => Err("cancelled"),
            };
            let ms = started.elapsed().as_millis() as u64;
            let _ = results.send(match outcome {
                Ok(output) => RunResult { host, state: "done", exit: output.exit_status, output: readable(&output.stdout), truncated: output.truncated, error: None, ms },
                Err(error) => RunResult::failed(host, error, ms),
            });
        });
    }
    while tasks.join_next().await.is_some() {}
    app.state::<Runs>().0.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).remove(&run);
    Ok(())
}

#[tauri::command]
pub fn snippet_cancel(runs: State<'_, Runs>, run: u64) {
    if let Some(cancel) = runs.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).get(&run) {
        let _ = cancel.send(true);
    }
}

// ---------- Server-Info ----------

#[derive(Serialize)]
pub struct Cpu {
    total: u64,
    idle: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Memory {
    total: u64,
    available: u64,
    swap_total: u64,
    swap_free: u64,
}

#[derive(Serialize)]
pub struct Disk {
    mount: String,
    device: String,
    total: u64,
    used: u64,
}

#[derive(Serialize)]
pub struct Net {
    rx: u64,
    tx: u64,
}

/// A measurement in the form the interface reads (`StatsSample` in `types.ts`).
#[derive(Serialize)]
pub struct StatsView {
    /// Time of the measurement in milliseconds since 1970.
    at: u64,
    cpu: Cpu,
    cores: u32,
    mem: Memory,
    load: [f64; 3],
    disks: Vec<Disk>,
    net: Net,
    uptime: u64,
    system: String,
    kernel: String,
    hostname: String,
}

fn view(sample: stats::Sample, at: u64) -> StatsView {
    StatsView {
        at,
        cpu: Cpu { total: sample.cpu_total, idle: sample.cpu_idle },
        cores: sample.cores,
        mem: Memory { total: sample.mem_total, available: sample.mem_available, swap_total: sample.swap_total, swap_free: sample.swap_free },
        load: sample.load,
        disks: sample.disks.into_iter().map(|disk| Disk { mount: disk.mount, device: disk.device, total: disk.total, used: disk.used }).collect(),
        net: Net { rx: sample.net_rx, tx: sample.net_tx },
        uptime: sample.uptime,
        system: sample.system,
        kernel: sample.kernel,
        hostname: sample.hostname,
    }
}

/// Measures a session's server over an additional channel of its connection. `None` if it does not provide the
/// numbers (not Linux) or the session is not connected.
#[tauri::command]
pub async fn session_stats(app: AppHandle, id: u64) -> Option<StatsView> {
    let output = files::run_at(&app, &Place::Session { id }, stats::COMMAND).await.ok()?;
    let at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |since| since.as_millis() as u64);
    stats::parse(&String::from_utf8_lossy(&output.stdout)).map(|sample| view(sample, at))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_is_shown_without_colours_and_control_characters() {
        assert_eq!(readable(b"eins\r\nzwei\n"), "eins\nzwei\n");
        assert_eq!(readable(b"\x1b[1;32mgr\xc3\xbcn\x1b[0m ok\x07\n"), "grün ok\n");
        assert_eq!(readable(b"10 %\r50 %\r100 %\n"), "10 %\n50 %\n100 %\n", "a redrawn line becomes several");
        assert_eq!(readable(b"a\tb\x00c\x1bXd"), "a\tbcXd");
        assert_eq!(readable(&[0xff, b'x']), "\u{fffd}x", "not UTF-8: the character is replaced, the rest stays");
    }

    #[test]
    fn measurements_take_the_shape_the_interface_reads() {
        let sample = stats::parse("@cpu\ncpu 100 0 50 800 10\n@cores\n4\n@mem\nMemTotal: 2000 kB\nMemAvailable: 500 kB\nSwapTotal: 100 kB\nSwapFree: 40 kB\n@load\n0.5 0.25 0.1\n@uptime\n90.4\n@net\neth0: 10 0 0 0 0 0 0 0 20 0\n@disk\nFilesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 1000 400 600 40% /\n@kernel\n6.8\n@host\nweb\n@os\nPRETTY_NAME=\"Debian\"\n").unwrap();
        let json = serde_json::to_value(view(sample, 1234)).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "at": 1234, "cpu": { "total": 960, "idle": 810 }, "cores": 4,
                "mem": { "total": 2_048_000, "available": 512_000, "swapTotal": 102_400, "swapFree": 40_960 },
                "load": [0.5, 0.25, 0.1], "disks": [{ "mount": "/", "device": "/dev/sda1", "total": 1_024_000, "used": 409_600 }],
                "net": { "rx": 10, "tx": 20 }, "uptime": 90, "system": "Debian", "kernel": "6.8", "hostname": "web"
            })
        );
    }
}

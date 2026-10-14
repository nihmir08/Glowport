//! Local terminal: a shell on this machine in a pseudo terminal (ConPTY on Windows).
//!
//! Only what [`shells`] found is started: the caller names an ID, never a program.

use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

use glowport_net::{End, Event, Phase, Session};
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use tokio::sync::{mpsc, oneshot};

use crate::{channels, pump, Wires};

/// When a shell starts, Windows asks the terminal where the cursor is and waits for the answer.
const CURSOR_QUESTION: &[u8] = b"\x1b[6n";
/// The answer “top left”, in case the terminal owes it.
const CURSOR_ANSWER: &[u8] = b"\x1b[1;1R";
/// This is how long the terminal has to answer before the core does it in its place.
const CURSOR_PATIENCE: Duration = Duration::from_millis(1500);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// PowerShell ab Version 6 (`pwsh`).
    Pwsh,
    /// Windows PowerShell 5, which is part of Windows.
    PowerShell,
    Cmd,
    GitBash,
    Wsl,
    /// The user's shell on other systems.
    Shell,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pwsh => "pwsh",
            Self::PowerShell => "powershell",
            Self::Cmd => "cmd",
            Self::GitBash => "gitbash",
            Self::Wsl => "wsl",
            Self::Shell => "shell",
        }
    }
}

/// A shell that can be opened as a local terminal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shell {
    /// Stays the same across restarts: `pwsh`, `powershell`, `cmd`, `gitbash`, `wsl:<distribution>`.
    pub id: String,
    pub name: String,
    pub kind: Kind,
    /// For display: path of the program, for WSL the name of the distribution.
    pub detail: String,
    program: PathBuf,
    args: Vec<String>,
}

impl Shell {
    fn new(id: &str, name: &str, kind: Kind, program: PathBuf, args: &[&str]) -> Self {
        Self { id: id.into(), name: name.into(), kind, detail: program.display().to_string(), program, args: args.iter().map(|a| (*a).to_string()).collect() }
    }
}

/// Does this file exist? Also for the placeholders Windows creates for programs from the Store, which
/// cannot be opened like ordinary files.
fn present(path: PathBuf) -> Option<PathBuf> {
    std::fs::symlink_metadata(&path).is_ok_and(|meta| !meta.is_dir()).then_some(path)
}

/// Looks for a program in the folders of `PATH`.
fn on_path(name: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?).filter(|dir| !dir.as_os_str().is_empty()).find_map(|dir| present(dir.join(name)))
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).filter(|value| !value.is_empty()).map(PathBuf::from)
}

/// The folder a local terminal starts in.
fn home() -> Option<PathBuf> {
    env_path(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).filter(|dir| dir.is_dir())
}

/// The shells of this machine, in the order they are offered.
#[cfg(windows)]
pub fn shells() -> Vec<Shell> {
    use winreg::{
        enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE},
        RegKey,
    };

    let mut found = Vec::new();
    let system = env_path("SystemRoot").unwrap_or_else(|| PathBuf::from("C:\\Windows")).join("System32");
    let program_files: Vec<PathBuf> = ["ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"].iter().filter_map(|name| env_path(name)).collect();

    // PowerShell 6 and later lives in a folder named after its major version; otherwise it is on the PATH (Store, winget, dotnet).
    let installed = program_files.iter().find_map(|dir| {
        let mut versions: Vec<(u32, PathBuf)> = std::fs::read_dir(dir.join("PowerShell")).ok()?.flatten().filter_map(|entry| Some((entry.file_name().to_str()?.parse().ok()?, entry.path().join("pwsh.exe")))).collect();
        versions.sort();
        versions.into_iter().rev().find_map(|(version, program)| present(program).map(|program| (Some(version), program)))
    });
    if let Some((version, program)) = installed.or_else(|| on_path("pwsh.exe").map(|program| (None, program))) {
        let name = version.map_or_else(|| "PowerShell".to_string(), |v| format!("PowerShell {v}"));
        found.push(Shell::new("pwsh", &name, Kind::Pwsh, program, &[]));
    }
    if let Some(program) = present(system.join("WindowsPowerShell\\v1.0\\powershell.exe")) {
        found.push(Shell::new("powershell", "Windows PowerShell", Kind::PowerShell, program, &[]));
    }
    if let Some(program) = env_path("ComSpec").and_then(present).or_else(|| present(system.join("cmd.exe"))) {
        // The interface knows what it is called in the user's language.
        found.push(Shell::new("cmd", "Command Prompt", Kind::Cmd, program, &[]));
    }

    // Git for Windows registers its folder in the registry; otherwise it is in the usual places or next to `git.exe`.
    let from_registry = [HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER]
        .into_iter()
        .filter_map(|root| RegKey::predef(root).open_subkey("SOFTWARE\\GitForWindows").ok()?.get_value::<String, _>("InstallPath").ok())
        .map(PathBuf::from);
    let usual = program_files.iter().map(|dir| dir.join("Git")).chain(env_path("LOCALAPPDATA").map(|dir| dir.join("Programs\\Git")));
    let beside_git = on_path("git.exe").and_then(|git| Some(git.parent()?.parent()?.to_path_buf()));
    if let Some(program) = from_registry.chain(usual).chain(beside_git).find_map(|dir| present(dir.join("bin\\bash.exe"))) {
        found.push(Shell::new("gitbash", "Git Bash", Kind::GitBash, program, &["--login", "-i"]));
    }

    // WSL: every distribution is listed by name under `Lxss`. Those of Docker Desktop are not a working environment.
    if let Some(wsl) = present(system.join("wsl.exe")) {
        let mut distributions: Vec<String> = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey("Software\\Microsoft\\Windows\\CurrentVersion\\Lxss")
            .map(|lxss| lxss.enum_keys().flatten().filter_map(|key| lxss.open_subkey(key).ok()?.get_value::<String, _>("DistributionName").ok()).collect())
            .unwrap_or_default();
        distributions.retain(|name| !name.is_empty() && !name.starts_with("docker-desktop") && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')));
        distributions.sort_by_key(|name| name.to_lowercase());
        for name in distributions {
            // `~` as the first argument starts in the distribution's home directory instead of the Windows folder.
            let mut shell = Shell::new(&format!("wsl:{name}"), &name, Kind::Wsl, wsl.clone(), &["~", "-d", &name]);
            shell.detail = name;
            found.push(shell);
        }
    }
    found
}

/// The shells of this machine: the user's, plus whatever else is common.
#[cfg(not(windows))]
pub fn shells() -> Vec<Shell> {
    let mut found: Vec<Shell> = Vec::new();
    let usual = ["/bin/zsh", "/bin/bash", "/usr/bin/fish", "/bin/sh"].map(PathBuf::from);
    for program in env_path("SHELL").into_iter().chain(usual).filter_map(present) {
        let name = program.file_name().and_then(|n| n.to_str()).unwrap_or("sh").to_string();
        if !found.iter().any(|shell| shell.id == name) {
            found.push(Shell::new(&name, &name, Kind::Shell, program, &["-l"]));
        }
    }
    found
}

/// The shell with this ID, if it exists on this machine.
pub fn shell(id: &str) -> Option<Shell> {
    shells().into_iter().find(|shell| shell.id == id)
}

fn pty_size(columns: u32, rows: u32) -> PtySize {
    let fit = |n: u32| u16::try_from(n.clamp(2, 1000)).unwrap_or(80);
    PtySize { rows: fit(rows), cols: fit(columns), pixel_width: 0, pixel_height: 0 }
}

/// Starts a shell as a session. It starts in the user's home directory. Must be called inside a tokio
/// runtime.
pub fn open(shell: Shell, size: (u32, u32)) -> Session {
    let (session, events, mut commands) = channels();
    tokio::spawn(async move {
        let _ = events.send(Event::Phase(Phase::Connecting)).await;
        // Creating the pseudo terminal waits for the system; not on a runtime thread.
        let end = match tokio::task::spawn_blocking(move || start(&shell.program, &shell.args, size)).await.unwrap_or_else(|e| Err(e.to_string())) {
            Ok(wires) => {
                let _ = events.send(Event::Phase(Phase::Connected)).await;
                pump(wires, &events, &mut commands).await
            }
            Err(message) => End::ConnectFailed(message),
        };
        let _ = events.send(Event::End(end)).await;
    });
    session
}

fn start(program: &Path, args: &[String], (columns, rows): (u32, u32)) -> Result<Wires, String> {
    let fail = |e: &dyn std::fmt::Display| e.to_string();
    let pair = native_pty_system().openpty(pty_size(columns, rows)).map_err(|e| fail(&e))?;
    let mut command = CommandBuilder::new(program);
    command.args(args);
    if let Some(dir) = home() {
        command.cwd(dir);
    }
    command.env("TERM", "xterm-256color");
    command.env("COLORTERM", "truecolor");
    let mut child = pair.slave.spawn_command(command).map_err(|e| fail(&e))?;
    // Nobody needs the child's side here any more; if it stayed open, reading would never end.
    drop(pair.slave);
    let mut reader = pair.master.try_clone_reader().map_err(|e| fail(&e))?;
    let mut writer = pair.master.take_writer().map_err(|e| fail(&e))?;
    let mut killer = child.clone_killer();
    let master = Arc::new(Mutex::new(Some(pair.master)));

    // Writing can stall if the program reads nothing; hence on a thread of its own.
    let (input_tx, input_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    thread::spawn(move || {
        for bytes in input_rx {
            if writer.write_all(&bytes).and_then(|()| writer.flush()).is_err() {
                break;
            }
        }
    });

    // Has the terminal sent anything yet? Its first input is the answer to the question about the cursor.
    let answered = Arc::new(AtomicBool::new(false));
    let (data_tx, data) = mpsc::channel::<Vec<u8>>(32);
    let (rescue, heard) = (input_tx.clone(), Arc::clone(&answered));
    thread::spawn(move || {
        let mut buffer = [0u8; 16 * 1024];
        let mut wanted = true;
        let mut first = true;
        // Even if nobody listens any more, reading continues to the end: otherwise closing the pseudo terminal would hang.
        while let Ok(n @ 1..) = reader.read(&mut buffer) {
            // If the answer never comes (no terminal, or it is unreachable right now), the shell would stand still forever.
            if std::mem::take(&mut first) && buffer[..n].windows(CURSOR_QUESTION.len()).any(|window| window == CURSOR_QUESTION) {
                let (rescue, heard) = (rescue.clone(), Arc::clone(&heard));
                thread::spawn(move || {
                    thread::sleep(CURSOR_PATIENCE);
                    if !heard.load(Ordering::Relaxed) {
                        let _ = rescue.send(CURSOR_ANSWER.to_vec());
                    }
                });
            }
            wanted = wanted && data_tx.blocking_send(buffer[..n].to_vec()).is_ok();
        }
    });

    let (end_tx, end) = oneshot::channel();
    let closing = Arc::clone(&master);
    thread::spawn(move || {
        let status = child.wait();
        // Only with the pseudo terminal does the line being read close; the rest still comes before that.
        drop(closing.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).take());
        let _ = end_tx.send(End::Remote { exit_status: status.ok().map(|status| status.exit_code()) });
    });

    Ok(Wires {
        data,
        end,
        write: Box::new(move |bytes| {
            answered.store(true, Ordering::Relaxed);
            let _ = input_tx.send(bytes);
        }),
        resize: Box::new(move |columns, rows| {
            if let Some(master) = master.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).as_ref() {
                let _ = master.resize(pty_size(columns, rows));
            }
        }),
        close: Box::new(move || drop(killer.kill())),
    })
}

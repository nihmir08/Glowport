//! Lokales Terminal: eine Shell dieses Rechners in einem Pseudo-Terminal (unter Windows ConPTY).
//!
//! Gestartet wird nur, was [`shells`] gefunden hat: Der Aufrufer nennt eine Kennung, nie ein Programm.

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

/// Windows fragt beim Start einer Shell das Terminal, wo die Schreibmarke steht, und wartet auf die Antwort.
const CURSOR_QUESTION: &[u8] = b"\x1b[6n";
/// Die Antwort „oben links“, falls das Terminal sie schuldig bleibt.
const CURSOR_ANSWER: &[u8] = b"\x1b[1;1R";
/// So lange hat das Terminal Zeit zu antworten, bevor der Kern es an seiner Stelle tut.
const CURSOR_PATIENCE: Duration = Duration::from_millis(1500);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// PowerShell ab Version 6 (`pwsh`).
    Pwsh,
    /// Windows PowerShell 5, das zu Windows gehört.
    PowerShell,
    Cmd,
    GitBash,
    Wsl,
    /// Die Shell des Benutzers auf anderen Systemen.
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

/// Eine Shell, die sich als lokales Terminal öffnen lässt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shell {
    /// Bleibt über Neustarts gleich: `pwsh`, `powershell`, `cmd`, `gitbash`, `wsl:<Distribution>`.
    pub id: String,
    pub name: String,
    pub kind: Kind,
    /// Zum Anzeigen: Pfad des Programms, bei WSL der Name der Distribution.
    pub detail: String,
    program: PathBuf,
    args: Vec<String>,
}

impl Shell {
    fn new(id: &str, name: &str, kind: Kind, program: PathBuf, args: &[&str]) -> Self {
        Self { id: id.into(), name: name.into(), kind, detail: program.display().to_string(), program, args: args.iter().map(|a| (*a).to_string()).collect() }
    }
}

/// Gibt es diese Datei? Auch für die Platzhalter, die Windows für Programme aus dem Store anlegt und die sich
/// nicht wie gewöhnliche Dateien öffnen lassen.
fn present(path: PathBuf) -> Option<PathBuf> {
    std::fs::symlink_metadata(&path).is_ok_and(|meta| !meta.is_dir()).then_some(path)
}

/// Sucht ein Programm in den Ordnern von `PATH`.
fn on_path(name: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?).filter(|dir| !dir.as_os_str().is_empty()).find_map(|dir| present(dir.join(name)))
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).filter(|value| !value.is_empty()).map(PathBuf::from)
}

/// Der Ordner, in dem ein lokales Terminal beginnt.
fn home() -> Option<PathBuf> {
    env_path(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).filter(|dir| dir.is_dir())
}

/// Die Shells dieses Rechners, in der Reihenfolge, in der sie angeboten werden.
#[cfg(windows)]
pub fn shells() -> Vec<Shell> {
    use winreg::{
        enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE},
        RegKey,
    };

    let mut found = Vec::new();
    let system = env_path("SystemRoot").unwrap_or_else(|| PathBuf::from("C:\\Windows")).join("System32");
    let program_files: Vec<PathBuf> = ["ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"].iter().filter_map(|name| env_path(name)).collect();

    // PowerShell ab 6 liegt in einem Ordner mit seiner Hauptversion; sonst steht es im PATH (Store, winget, dotnet).
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
        // Wie sie in der Sprache des Nutzers heißt, weiß die Oberfläche.
        found.push(Shell::new("cmd", "Command Prompt", Kind::Cmd, program, &[]));
    }

    // Git für Windows trägt seinen Ordner in die Registry ein; sonst liegt es an den üblichen Stellen oder neben `git.exe`.
    let from_registry = [HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER]
        .into_iter()
        .filter_map(|root| RegKey::predef(root).open_subkey("SOFTWARE\\GitForWindows").ok()?.get_value::<String, _>("InstallPath").ok())
        .map(PathBuf::from);
    let usual = program_files.iter().map(|dir| dir.join("Git")).chain(env_path("LOCALAPPDATA").map(|dir| dir.join("Programs\\Git")));
    let beside_git = on_path("git.exe").and_then(|git| Some(git.parent()?.parent()?.to_path_buf()));
    if let Some(program) = from_registry.chain(usual).chain(beside_git).find_map(|dir| present(dir.join("bin\\bash.exe"))) {
        found.push(Shell::new("gitbash", "Git Bash", Kind::GitBash, program, &["--login", "-i"]));
    }

    // WSL: Jede Distribution steht mit ihrem Namen unter `Lxss`. Die von Docker Desktop sind keine Arbeitsumgebung.
    if let Some(wsl) = present(system.join("wsl.exe")) {
        let mut distributions: Vec<String> = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey("Software\\Microsoft\\Windows\\CurrentVersion\\Lxss")
            .map(|lxss| lxss.enum_keys().flatten().filter_map(|key| lxss.open_subkey(key).ok()?.get_value::<String, _>("DistributionName").ok()).collect())
            .unwrap_or_default();
        distributions.retain(|name| !name.is_empty() && !name.starts_with("docker-desktop") && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')));
        distributions.sort_by_key(|name| name.to_lowercase());
        for name in distributions {
            // `~` als erste Angabe beginnt im Heimatverzeichnis der Distribution statt im Ordner von Windows.
            let mut shell = Shell::new(&format!("wsl:{name}"), &name, Kind::Wsl, wsl.clone(), &["~", "-d", &name]);
            shell.detail = name;
            found.push(shell);
        }
    }
    found
}

/// Die Shells dieses Rechners: die des Benutzers, dazu was sonst üblich ist.
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

/// Die Shell mit dieser Kennung, wenn es sie auf diesem Rechner gibt.
pub fn shell(id: &str) -> Option<Shell> {
    shells().into_iter().find(|shell| shell.id == id)
}

fn pty_size(columns: u32, rows: u32) -> PtySize {
    let fit = |n: u32| u16::try_from(n.clamp(2, 1000)).unwrap_or(80);
    PtySize { rows: fit(rows), cols: fit(columns), pixel_width: 0, pixel_height: 0 }
}

/// Startet eine Shell als Sitzung. Sie beginnt im Heimatverzeichnis des Benutzers. Muss in einem tokio-Runtime
/// aufgerufen werden.
pub fn open(shell: Shell, size: (u32, u32)) -> Session {
    let (session, events, mut commands) = channels();
    tokio::spawn(async move {
        let _ = events.send(Event::Phase(Phase::Connecting)).await;
        // Das Anlegen des Pseudo-Terminals wartet auf das System; nicht auf einem Thread des Runtimes.
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
    // Die Seite des Kindes braucht hier niemand mehr; bliebe sie offen, endete das Lesen nie.
    drop(pair.slave);
    let mut reader = pair.master.try_clone_reader().map_err(|e| fail(&e))?;
    let mut writer = pair.master.take_writer().map_err(|e| fail(&e))?;
    let mut killer = child.clone_killer();
    let master = Arc::new(Mutex::new(Some(pair.master)));

    // Schreiben kann stocken, wenn das Programm nichts liest; deshalb auf einem eigenen Thread.
    let (input_tx, input_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    thread::spawn(move || {
        for bytes in input_rx {
            if writer.write_all(&bytes).and_then(|()| writer.flush()).is_err() {
                break;
            }
        }
    });

    // Hat das Terminal schon etwas geschickt? Seine erste Eingabe ist die Antwort auf die Frage nach der Schreibmarke.
    let answered = Arc::new(AtomicBool::new(false));
    let (data_tx, data) = mpsc::channel::<Vec<u8>>(32);
    let (rescue, heard) = (input_tx.clone(), Arc::clone(&answered));
    thread::spawn(move || {
        let mut buffer = [0u8; 16 * 1024];
        let mut wanted = true;
        let mut first = true;
        // Auch wenn niemand mehr zuhört, wird zu Ende gelesen: Sonst hinge das Schließen des Pseudo-Terminals.
        while let Ok(n @ 1..) = reader.read(&mut buffer) {
            // Bleibt die Antwort aus (kein Terminal, oder es ist gerade nicht erreichbar), stünde die Shell für immer.
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
        // Erst mit dem Pseudo-Terminal schließt sich die Leitung, an der gelesen wird; vorher kommt noch der Rest.
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

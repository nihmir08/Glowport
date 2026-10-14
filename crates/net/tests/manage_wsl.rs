//! The management commands on a real Linux: the Ubuntu in this machine's WSL. Only runs by hand:
//! `cargo test -p glowport-net --test manage_wsl -- --ignored --nocapture`
//!
//! The commands go to `sh -c`, the way an SSH server hands them to the user's shell. Nothing is changed in
//! WSL: the one action (starting a running service) fails for lack of permissions, and exactly that is checked.

use std::process::Command;

use glowport_net::manage::{self, processes, services, As, Verdict};

/// Runs a command in WSL: whether it succeeded and what it printed.
fn run(command: &str) -> (bool, String) {
    let output = Command::new("wsl.exe").args(["-e", "sh", "-c", command]).output().expect("wsl.exe");
    (output.status.success(), String::from_utf8_lossy(&output.stdout).into_owned())
}

#[test]
#[ignore = "braucht das Ubuntu im WSL"]
fn the_commands_work_on_a_real_linux() {
    let abilities = manage::abilities(&run(manage::PROBE).1);
    println!("{abilities:?}");
    assert!(abilities.services && abilities.processes && !abilities.root, "Ubuntu mit systemd und procps, als gewöhnlicher Benutzer");

    // Services: the list, a service's state, and an action for which permissions are missing.
    let list = services::parse(&run(services::LIST).1).expect("Liste der Dienste");
    let running = list.iter().filter(|s| s.active == services::Active::Active).count();
    println!("{} Dienste, {running} aktiv, die ersten: {:?}", list.len(), list.iter().take(4).map(|s| (&s.unit, s.active, &s.sub, s.enabled)).collect::<Vec<_>>());
    let journal = list.iter().find(|s| s.unit == "systemd-journald.service").expect("das Journal läuft überall");
    assert!(list.len() > 20 && running > 3 && journal.active == services::Active::Active && !journal.description.is_empty());
    assert!(list.iter().all(|s| services::valid_unit(&s.unit)), "jeder gelistete Name taugt für einen Befehl");

    let (_, status) = run(&services::status_command(&journal.unit, As::User).unwrap());
    assert!(status.contains("Active: active (running)"), "{status}");

    let start = |how| {
        let (ok, text) = run(&services::Action::Start.command(&journal.unit, how).unwrap());
        (manage::verdict(ok, &text, how), text)
    };
    let (as_user, text) = start(As::User);
    println!("als Benutzer: {as_user:?}  ({})", text.trim().lines().next().unwrap_or_default());
    assert_eq!(as_user, Verdict::NeedsRoot, "{text}");
    // If sudo is set up without a password here, it succeeds; otherwise it wants one.
    let (with_sudo, text) = start(As::Sudo);
    println!("mit sudo: {with_sudo:?}  ({})", text.trim().lines().next().unwrap_or_default());
    assert_eq!(with_sudo, if abilities.sudo { Verdict::Done } else { Verdict::NeedsPassword }, "{text}");

    // Processes: two measurements apart, the load from them.
    let first = processes::parse(&run(processes::LIST).1).expect("Liste der Prozesse");
    std::thread::sleep(std::time::Duration::from_millis(1200));
    let second = processes::parse(&run(processes::LIST).1).expect("Liste der Prozesse");
    let init = second.processes.iter().find(|p| p.pid == 1).expect("Prozess 1");
    println!("{} Prozesse, Takt {}, Speicher {} MiB, Prozess 1: {init:?}", second.processes.len(), second.ticks_per_second, second.memory_total >> 20);
    assert!(second.processes.len() > 5 && second.ticks_per_second > 0 && second.memory_total > 0 && second.uptime > first.uptime);
    assert!(init.memory > 0 && init.elapsed > 0 && init.ticks > 0 && !init.kernel && init.user == "root", "{init:?}");
    assert!(second.processes.iter().all(|p| !p.name.is_empty() && !p.user.is_empty()));
    let load = processes::cpu_between(&first, &second, 1).expect("Auslastung von Prozess 1");
    assert!((0.0..=400.0).contains(&load), "{load}");
    println!("Auslastung von Prozess 1: {load:.1} %");
}

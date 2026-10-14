//! Die Befehle der Verwaltung gegen das nachgestellte Linux des Testservers: Der Testserver versteht genau die
//! Befehle, die `manage` baut, und `manage` liest, was er antwortet. Damit stimmt, worauf die Ende-zu-Ende-Prüfung
//! der Seitenleiste aufbaut.

use glowport_net::manage::{self, docker, processes, services, As, Verdict};
use glowport_testserver::admin::Admin;

fn ask(admin: &mut Admin, command: &str) -> (bool, String) {
    let (text, status) = admin.answer(command).unwrap_or_else(|| panic!("der Testserver kennt den Befehl nicht: {command}"));
    (status == 0, text)
}

#[test]
fn the_test_server_speaks_the_commands_of_the_sidebar() {
    let mut admin = Admin::default();
    let abilities = manage::abilities(&ask(&mut admin, manage::PROBE).1);
    assert_eq!(abilities, manage::Abilities { root: false, docker: true, services: true, processes: true, sudo: false });

    // Docker: der Benutzer gehört zur Gruppe, es geht ohne sudo.
    let list = |admin: &mut Admin| match docker::parse(&ask(admin, &docker::list_command(As::User)).1) {
        docker::Listing::Containers(list) => list,
        docker::Listing::Refused(text) => panic!("abgelehnt: {text}"),
    };
    let before = list(&mut admin);
    assert_eq!(before.iter().map(|c| (c.name.as_str(), c.state, c.exit_code)).collect::<Vec<_>>(), [("e2e-db", docker::State::Running, None), ("e2e-web", docker::State::Running, None), ("e2e-job", docker::State::Exited, Some(1))]);
    let web = before[1].clone();
    assert_eq!((web.ports, web.since, web.cpu, web.memory), (vec!["8080->80/tcp".to_string()], Some(3600), Some(2.5), Some((64 << 20, 2 << 30))));
    let (ok, text) = ask(&mut admin, &docker::Action::Stop.command(&web.id, As::User).unwrap());
    assert_eq!(manage::verdict(ok, &text, As::User), Verdict::Done);
    let after = list(&mut admin);
    let stopped = after.iter().find(|c| c.id == web.id).unwrap();
    assert_eq!((stopped.state, stopped.exit_code, stopped.cpu, stopped.since.map(|s| s < 5)), (docker::State::Exited, Some(0), None, Some(true)));
    let (ok, text) = ask(&mut admin, &docker::Action::Start.command("abcdef012345", As::User).unwrap());
    assert!(matches!(manage::verdict(ok, &text, As::User), Verdict::Failed(message) if message.contains("No such container")));

    // Dienste: lesen darf jeder, steuern nur root, und sudo will ein Passwort.
    let units = services::parse(&ask(&mut admin, services::LIST).1).unwrap();
    assert_eq!(units.iter().map(|s| (s.unit.as_str(), s.active, s.enabled)).collect::<Vec<_>>(), [
        ("e2e-backup.service", services::Active::Failed, services::Enabled::Static),
        ("e2e-web.service", services::Active::Active, services::Enabled::Enabled),
        ("ssh.service", services::Active::Active, services::Enabled::Enabled),
        ("e2e-idle.service", services::Active::Inactive, services::Enabled::Disabled),
    ]);
    let start = |admin: &mut Admin, how| {
        let (ok, text) = ask(admin, &services::Action::Start.command("e2e-idle.service", how).unwrap());
        manage::verdict(ok, &text, how)
    };
    assert_eq!((start(&mut admin, As::User), start(&mut admin, As::Sudo)), (Verdict::NeedsRoot, Verdict::NeedsPassword));
    assert!(ask(&mut admin, &services::status_command("e2e-web.service", As::User).unwrap()).1.contains("Active: active (running)"));
    assert!(!ask(&mut admin, &services::status_command("e2e-idle.service", As::User).unwrap()).0, "ein Dienst, der nicht läuft, endet mit 3");

    // Prozesse: zwei Messungen ergeben die Auslastung; eigene darf der Benutzer beenden, fremde nicht.
    let first = processes::parse(&ask(&mut admin, processes::LIST).1).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(400));
    let second = processes::parse(&ask(&mut admin, processes::LIST).1).unwrap();
    assert_eq!(second.processes.iter().map(|p| (p.pid, p.name.as_str(), p.kernel)).collect::<Vec<_>>(), [(1, "init", false), (2, "kthreadd", true), (300, "sshd", false), (4711, "python3", false), (4712, "sleep", false)]);
    let load = processes::cpu_between(&first, &second, 4711).unwrap();
    assert!((30.0..=70.0).contains(&load), "ein halber Kern, gemessen {load}");
    let kill = |admin: &mut Admin, pid, how| {
        let (ok, text) = ask(admin, &processes::Signal::Term.command(pid, how).unwrap());
        manage::verdict(ok, &text, how)
    };
    assert_eq!((kill(&mut admin, 300, As::User), kill(&mut admin, 300, As::Sudo)), (Verdict::NeedsRoot, Verdict::NeedsPassword));
    assert_eq!(kill(&mut admin, 4712, As::User), Verdict::Done);
    assert!(processes::parse(&ask(&mut admin, processes::LIST).1).unwrap().processes.iter().all(|p| p.pid != 4712));

    // Alles andere führt der Testserver aus wie bisher.
    assert!(admin.answer("uname -s").is_none() && admin.answer("ls -la").is_none());
}

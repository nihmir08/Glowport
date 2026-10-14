//! Mosh gegen den eigenen Testserver. Ohne mosh gibt es den Rückfall auf SSH; mit `mosh-server` im WSL-Ubuntu
//! dieses Rechners (über die Brücke des Testservers) den ganzen Weg samt Aussetzer. Fehlt das WSL-mosh, werden
//! diese Fälle mit einer Meldung übersprungen.

use std::{path::PathBuf, sync::atomic::Ordering, time::Duration};

use glowport_net::{open, Command, Connect, End, Event, Mosh, MoshEvent, MoshFallback, Phase, Secret, Session};
use glowport_testserver::{self as server, mosh::Bridge, Options, PROMPT};
use tokio::time::timeout;

const DISTRO: &str = "Ubuntu";

/// Spielt die Oberfläche: nimmt jeden Server an, merkt sich Ausgabe und Mosh-Meldungen.
struct Driver {
    session: Session,
    output: String,
    phases: Vec<Phase>,
    mosh: Vec<MoshEvent>,
}

impl Driver {
    fn new(connect: Connect) -> Self {
        Self { session: open(connect), output: String::new(), phases: Vec::new(), mosh: Vec::new() }
    }

    async fn until(&mut self, wait: Duration, done: impl Fn(&Driver) -> bool) -> Option<End> {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            if done(self) {
                return None;
            }
            let event = timeout(deadline.saturating_duration_since(tokio::time::Instant::now()), self.session.events.recv()).await.expect("nichts geschah").expect("Sitzung verschwand ohne Ende");
            match event {
                Event::Phase(phase) => self.phases.push(phase),
                Event::HostKey { reply, .. } => drop(reply.send(true)),
                Event::Secret { reply, .. } => drop(reply.send(None)),
                Event::Interactive { reply, .. } => drop(reply.send(None)),
                Event::Mosh(event) => self.mosh.push(event),
                Event::Output(bytes) => self.output.push_str(&String::from_utf8_lossy(&bytes)),
                Event::End(end) => return Some(end),
                _ => {}
            }
        }
    }

    fn send(&self, command: Command) {
        self.session.commands.send(command).expect("Sitzung nimmt keine Befehle mehr an");
    }

    fn typed(&self, line: &str) {
        self.send(Command::Input(format!("{line}\r").into_bytes()));
    }
}

fn connect(address: std::net::SocketAddr, mosh: Mosh) -> Connect {
    Connect { host: address.ip().to_string(), port: address.port(), user: "tester".into(), password: Some(Secret::new("richtig".into())), mosh: Some(mosh), ..Connect::default() }
}

fn with_password() -> Options {
    Options { password: Some(("tester".into(), "richtig".into())), ..Options::default() }
}

/// Leerer Ordner als Heimat des Testservers: Dann laufen Befehle wirklich über `sh`, und dort gibt es kein mosh.
struct Home(PathBuf);
impl Home {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("glowport-mosh-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn bridge() -> Option<Bridge> {
    let found = Bridge::find(DISTRO);
    if found.is_none() {
        eprintln!("übersprungen: kein mosh-server im WSL „{DISTRO}“");
    }
    found
}

#[tokio::test]
async fn without_mosh_server_the_session_falls_back_to_ssh() {
    let home = Home::new("ohne");
    let running = server::start(Options { home: Some(home.0.clone()), ..with_password() }, server::key(1)).await.unwrap();
    let mut driver = Driver::new(connect(running.address, Mosh::default()));
    assert_eq!(driver.until(Duration::from_secs(30), |d| d.output.ends_with(PROMPT)).await, None);
    assert_eq!(driver.mosh, [MoshEvent::Fallback(MoshFallback::Missing)]);
    assert!(driver.phases.contains(&Phase::Connected));
    driver.send(Command::Close);
    assert_eq!(driver.until(Duration::from_secs(10), |_| false).await, Some(End::User));
}

#[tokio::test]
async fn an_error_of_mosh_server_is_reported_with_its_first_line() {
    let home = Home::new("fehler");
    let running = server::start(Options { home: Some(home.0.clone()), ..with_password() }, server::key(1)).await.unwrap();
    // `echo` statt mosh-server: antwortet, aber ohne `MOSH CONNECT`.
    let mosh = Mosh { server: Some("echo".into()), ..Mosh::default() };
    let mut driver = Driver::new(connect(running.address, mosh));
    assert_eq!(driver.until(Duration::from_secs(30), |d| d.output.ends_with(PROMPT)).await, None);
    assert_eq!(driver.mosh, [MoshEvent::Fallback(MoshFallback::Server("new -s -c 256 -l LANG=C.UTF-8".into()))]);
}

#[tokio::test]
async fn over_mosh_the_terminal_survives_a_dropout() {
    let Some(bridge) = bridge() else { return };
    let running = server::start(Options { mosh: Some(bridge.clone()), ..with_password() }, server::key(1)).await.unwrap();
    let mut driver = Driver::new(connect(running.address, Mosh::default()));
    assert_eq!(driver.until(Duration::from_secs(30), |d| d.mosh.contains(&MoshEvent::Active) && d.phases.contains(&Phase::Connected)).await, None);

    driver.typed("echo mosh-$((40+2))");
    assert_eq!(driver.until(Duration::from_secs(10), |d| d.output.contains("mosh-42")).await, None, "{}", driver.output);
    driver.send(Command::Resize(132, 40));
    tokio::time::sleep(Duration::from_millis(300)).await;
    driver.typed("stty size");
    assert_eq!(driver.until(Duration::from_secs(10), |d| d.output.contains("40 132")).await, None);

    // Die SSH-Verbindung daneben gibt Kanäle für die Seitenleiste her.
    let (reply, answer) = tokio::sync::oneshot::channel();
    driver.send(Command::Open(reply));
    let opened = tokio::spawn(answer);
    assert_eq!(driver.until(Duration::from_secs(5), |_| opened.is_finished()).await, None);
    assert!(opened.await.unwrap().unwrap().is_some(), "kein Kanal neben Mosh");

    // Aussetzer: neun Sekunden kein Paket. Getipptes geht nicht verloren.
    bridge.paused.store(true, Ordering::Relaxed);
    driver.typed("echo nach-$((1+1))");
    assert_eq!(driver.until(Duration::from_secs(15), |d| d.mosh.iter().any(|e| matches!(e, MoshEvent::Silent(Some(n)) if *n >= 7))).await, None, "{:?}", driver.mosh);
    bridge.paused.store(false, Ordering::Relaxed);
    assert_eq!(driver.until(Duration::from_secs(15), |d| d.mosh.last() == Some(&MoshEvent::Silent(None)) && d.output.contains("nach-2")).await, None, "{:?}", driver.mosh);

    driver.send(Command::Close);
    assert_eq!(driver.until(Duration::from_secs(15), |_| false).await, Some(End::User));
}

#[tokio::test]
async fn exit_ends_the_mosh_session() {
    let Some(bridge) = bridge() else { return };
    let running = server::start(Options { mosh: Some(bridge), ..with_password() }, server::key(1)).await.unwrap();
    let mut driver = Driver::new(connect(running.address, Mosh::default()));
    assert_eq!(driver.until(Duration::from_secs(30), |d| d.mosh.contains(&MoshEvent::Active)).await, None);
    driver.typed("exit");
    assert_eq!(driver.until(Duration::from_secs(20), |_| false).await, Some(End::Remote { exit_status: None }));
}

#[tokio::test]
async fn without_udp_the_session_falls_back_to_ssh() {
    let Some(blocked) = bridge() else { return };
    // Die Weiterleitung lässt nichts durch: wie eine Firewall, die die Ports von mosh sperrt.
    blocked.paused.store(true, Ordering::Relaxed);
    let running = server::start(Options { mosh: Some(blocked), ..with_password() }, server::key(1)).await.unwrap();
    let mut driver = Driver::new(connect(running.address, Mosh::default()));
    assert_eq!(driver.until(Duration::from_secs(40), |d| d.output.ends_with(PROMPT)).await, None);
    assert_eq!(driver.mosh, [MoshEvent::Fallback(MoshFallback::Udp)]);
}

//! Port-Weiterleitungen und Befehle ohne Terminal gegen den eigenen Testserver.

use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{atomic::Ordering, Arc},
    time::Duration,
};

use glowport_net::{
    forward::{self, Counters, Rule, Tunnel},
    run_command, stats, Command, Connect, End, Event, Phase, Secret, Session, COMMAND_TIMED_OUT,
};
use glowport_testserver::{self as server, Options};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{sleep, timeout},
};

fn options() -> Options {
    Options { password: Some(("tester".into(), "richtig".into())), forwarding: true, ..Options::default() }
}

fn connect(address: SocketAddr, password: Option<&str>) -> Connect {
    Connect { host: address.ip().to_string(), port: address.port(), user: "tester".into(), password: password.map(|p| Secret::new(p.into())), ..Connect::default() }
}

/// Ein Ziel hinter dem Server: antwortet auf alles mit „echo:“ davor.
async fn echo() -> SocketAddr {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0u8; 1024];
                while let Ok(n) = stream.read(&mut buffer).await {
                    if n == 0 || stream.write_all(&[b"echo:", &buffer[..n]].concat()).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    address
}

/// Ein Port, der gerade frei ist.
async fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).await.unwrap().local_addr().unwrap().port()
}

/// Wartet auf das Ergebnis des Aufbaus und vertraut dabei jedem Server-Schlüssel. Rückfragen nach einem Passwort
/// beantwortet `password`; ohne Vorgabe gelten sie als Fehler des Tests.
async fn settle(session: &mut Session, password: Option<&str>) -> Result<Tunnel, End> {
    loop {
        match timeout(Duration::from_secs(10), session.events.recv()).await.expect("nichts geschah").expect("Aufbau verschwand ohne Ergebnis") {
            Event::HostKey { reply, .. } => drop(reply.send(true)),
            Event::Secret { reply, .. } => drop(reply.send(Some(Secret::new(password.expect("unerwartete Rückfrage").into())))),
            Event::Forward(tunnel) => return Ok(tunnel),
            Event::End(end) => return Err(end),
            _ => {}
        }
    }
}

async fn local(address: SocketAddr, rule: Rule, counters: &Arc<Counters>) -> (Tunnel, u16) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut session = forward::open(connect(address, Some("richtig")), rule, Some(listener), Arc::clone(counters));
    (settle(&mut session, None).await.expect("Weiterleitung kam nicht zustande"), port)
}

async fn exchange(stream: &mut TcpStream, text: &[u8]) -> Vec<u8> {
    stream.write_all(text).await.unwrap();
    let mut reply = vec![0u8; text.len() + 5];
    timeout(Duration::from_secs(5), stream.read_exact(&mut reply)).await.expect("keine Antwort").unwrap();
    reply
}

/// Wartet, bis eine Bedingung zutrifft; Zähler und Aufräumen laufen in eigenen Aufgaben.
async fn eventually(what: &str, check: impl Fn() -> bool) {
    for _ in 0..100 {
        if check() {
            return;
        }
        sleep(Duration::from_millis(30)).await;
    }
    panic!("nicht eingetreten: {what}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_local_port_leads_through_the_server_to_its_target() {
    let running = server::start(options(), server::key(1)).await.unwrap();
    let target = echo().await;
    let counters = Arc::new(Counters::default());
    let (tunnel, port) = local(running.address, Rule::Local { host: "127.0.0.1".into(), port: target.port() }, &counters).await;

    let mut first = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    assert_eq!(exchange(&mut first, b"hallo").await, b"echo:hallo");
    let mut second = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    assert_eq!(exchange(&mut second, b"zwei").await, b"echo:zwei");
    assert_eq!((counters.open.load(Ordering::Relaxed), counters.total.load(Ordering::Relaxed)), (2, 2));
    assert_eq!((counters.sent.load(Ordering::Relaxed), counters.received.load(Ordering::Relaxed)), (9, 19));

    drop(first);
    drop(second);
    eventually("beide Verbindungen sind zu", || counters.open.load(Ordering::Relaxed) == 0).await;

    // Ausschalten gibt den Port wieder frei.
    drop(tunnel);
    eventually("der Port ist wieder frei", || std::net::TcpListener::bind(("127.0.0.1", port)).is_ok()).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_dynamic_port_speaks_socks() {
    let running = server::start(options(), server::key(1)).await.unwrap();
    let target = echo().await;
    let counters = Arc::new(Counters::default());
    let (_tunnel, port) = local(running.address, Rule::Dynamic, &counters).await;

    // SOCKS 5 mit einer Adresse als Name.
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut chosen = [0u8; 2];
    stream.read_exact(&mut chosen).await.unwrap();
    assert_eq!(chosen, [5, 0]);
    let mut request = vec![5, 1, 0, 3, 9];
    request.extend_from_slice(b"localhost");
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut answer = [0u8; 10];
    stream.read_exact(&mut answer).await.unwrap();
    assert_eq!(answer[..2], [5, 0], "verbunden");
    assert_eq!(exchange(&mut stream, b"socks").await, b"echo:socks");

    // SOCKS 4 mit einer Adresse als Zahl.
    let mut old = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    old.write_all(&[&[4u8, 1][..], &target.port().to_be_bytes(), &[127, 0, 0, 1, 0]].concat()).await.unwrap();
    let mut answer = [0u8; 8];
    old.read_exact(&mut answer).await.unwrap();
    assert_eq!(answer[..2], [0, 0x5A]);
    assert_eq!(exchange(&mut old, b"vier").await, b"echo:vier");

    // Ein Ziel, das es nicht gibt: Die Absage kommt in der Sprache von SOCKS, die Verbindung zum Server bleibt.
    let dead = free_port().await;
    let mut refused = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    refused.write_all(&[5, 1, 0]).await.unwrap();
    refused.read_exact(&mut chosen).await.unwrap();
    refused.write_all(&[&[5u8, 1, 0, 1, 127, 0, 0, 1][..], &dead.to_be_bytes()].concat()).await.unwrap();
    let mut answer = [0u8; 10];
    refused.read_exact(&mut answer).await.unwrap();
    assert_eq!(answer[..2], [5, 5], "abgelehnt");

    let mut again = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    again.write_all(&[&[4u8, 1][..], &target.port().to_be_bytes(), &[127, 0, 0, 1, 0]].concat()).await.unwrap();
    again.read_exact(&mut [0u8; 8]).await.unwrap();
    assert_eq!(exchange(&mut again, b"noch da").await, b"echo:noch da");
    assert_eq!(counters.total.load(Ordering::Relaxed), 4);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_remote_port_leads_back_to_this_machine() {
    let running = server::start(options(), server::key(1)).await.unwrap();
    let target = echo().await;
    let at_server = free_port().await;
    let counters = Arc::new(Counters::default());
    let rule = Rule::Remote { bind: "127.0.0.1".into(), bind_port: at_server, host: "127.0.0.1".into(), port: target.port() };
    let mut session = forward::open(connect(running.address, Some("richtig")), rule.clone(), None, Arc::clone(&counters));
    let tunnel = settle(&mut session, None).await.expect("Weiterleitung kam nicht zustande");

    // Der Testserver lauscht jetzt selbst; was dort ankommt, landet beim Ziel auf dieser Seite.
    let mut stream = TcpStream::connect(("127.0.0.1", at_server)).await.unwrap();
    assert_eq!(exchange(&mut stream, b"von draussen").await, b"echo:von draussen");
    assert_eq!((counters.total.load(Ordering::Relaxed), counters.sent.load(Ordering::Relaxed), counters.received.load(Ordering::Relaxed)), (1, 12, 17));

    // Ausschalten nimmt dem Server den Port wieder.
    drop(stream);
    drop(tunnel);
    eventually("der Server lauscht nicht mehr", || std::net::TcpListener::bind(("127.0.0.1", at_server)).is_ok()).await;

    // Ein Server, der das nicht erlaubt, lehnt ab; die Regel kommt nicht zustande.
    let strict = server::start(Options { forwarding: false, ..options() }, server::key(2)).await.unwrap();
    let mut session = forward::open(connect(strict.address, Some("richtig")), rule, None, Arc::new(Counters::default()));
    assert_eq!(settle(&mut session, None).await.err(), Some(End::Refused(format!("127.0.0.1:{at_server}"))));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_lost_connection_ends_the_tunnel() {
    let running = server::start(options(), server::key(1)).await.unwrap();
    let counters = Arc::new(Counters::default());
    // Dieses Ziel bringt den Testserver dazu, die Verbindung zu kappen.
    let (mut tunnel, port) = local(running.address, Rule::Local { host: "disconnect.test".into(), port: 1 }, &counters).await;
    let _ = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let end = timeout(Duration::from_secs(10), tunnel.closed()).await.expect("der Abriss blieb unbemerkt");
    assert!(matches!(end, End::ConnectionLost(_)), "{end:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn setting_up_asks_like_a_session_and_can_be_cancelled() {
    let running = server::start(options(), server::key(1)).await.unwrap();
    let target = echo().await;
    let rule = Rule::Local { host: "127.0.0.1".into(), port: target.port() };

    // Ohne hinterlegtes Passwort kommt die Rückfrage; mit der Antwort steht die Weiterleitung.
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut session = forward::open(connect(running.address, None), rule.clone(), Some(listener), Arc::new(Counters::default()));
    let _tunnel = settle(&mut session, Some("richtig")).await.unwrap();
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    assert_eq!(exchange(&mut stream, b"ok").await, b"echo:ok");

    // Abbrechen, während die Rückfrage offen ist: Es endet wie vom Nutzer beendet, und der Port ist wieder frei.
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut session = forward::open(connect(running.address, None), rule.clone(), Some(listener), Arc::new(Counters::default()));
    let mut phases = Vec::new();
    let reply = loop {
        match timeout(Duration::from_secs(10), session.events.recv()).await.unwrap().unwrap() {
            Event::HostKey { reply, .. } => drop(reply.send(true)),
            Event::Phase(phase) => phases.push(phase),
            Event::Secret { reply, .. } => break reply,
            _ => {}
        }
    };
    assert_eq!(phases, [Phase::Connecting, Phase::Authenticating]);
    session.commands.send(Command::Close).unwrap();
    let end = loop {
        if let Event::End(end) = timeout(Duration::from_secs(10), session.events.recv()).await.unwrap().unwrap() {
            break end;
        }
    };
    assert_eq!(end, End::User);
    drop(reply);
    eventually("der Port ist wieder frei", || std::net::TcpListener::bind(("127.0.0.1", port)).is_ok()).await;

    // Ein falsches Passwort lässt sich wiederholen; Ablehnen des Schlüssels endet ohne Weiterleitung.
    let mut session = forward::open(connect(running.address, None), rule, Some(TcpListener::bind(("127.0.0.1", 0)).await.unwrap()), Arc::new(Counters::default()));
    let end = loop {
        match timeout(Duration::from_secs(10), session.events.recv()).await.unwrap().unwrap() {
            Event::HostKey { reply, .. } => drop(reply.send(false)),
            Event::End(end) => break end,
            _ => {}
        }
    };
    assert_eq!(end, End::HostKeyRejected);
}

/// Legt ein Heimatverzeichnis für den Testserver an; mit ihm führt er Befehle wirklich aus.
struct Home(PathBuf);
impl Home {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("glowport-run-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn commands_report_output_errors_and_status() {
    if std::process::Command::new("sh").arg("-c").arg("true").output().is_err() {
        eprintln!("ohne sh im Pfad übersprungen");
        return;
    }
    let home = Home::new("befehle");
    let running = server::start(Options { home: Some(home.0.clone()), ..options() }, server::key(1)).await.unwrap();
    let ready = connect(running.address, Some("richtig"));
    let minute = Duration::from_secs(60);
    let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).replace("\r\n", "\n");

    let fine = run_command(&ready, "echo eins; echo zwei", minute, 1024, |_, _, _| true).await.unwrap();
    assert_eq!((text(&fine.stdout).as_str(), fine.exit_status, fine.truncated), ("eins\nzwei\n", Some(0), false));

    // Die Fehlerausgabe gehört zum Ergebnis, der Fehlercode auch.
    let failed = run_command(&ready, "echo vorher; echo kaputt >&2; exit 3", minute, 1024, |_, _, _| true).await.unwrap();
    assert_eq!(failed.exit_status, Some(3));
    assert!(text(&failed.stdout).contains("vorher") && text(&failed.stdout).contains("kaputt"), "{}", text(&failed.stdout));

    // Mehr als erlaubt wird abgeschnitten und so gemeldet.
    let long = run_command(&ready, "printf '%0100d' 7", minute, 40, |_, _, _| true).await.unwrap();
    assert_eq!((long.stdout.len(), long.truncated, long.exit_status), (40, true, Some(0)));

    // Ein Befehl, der zu lange läuft, endet mit einer eigenen Meldung.
    let slow = run_command(&ready, "sleep 3", Duration::from_millis(400), 1024, |_, _, _| true).await;
    assert_eq!(slow.unwrap_err(), End::ConnectionLost(COMMAND_TIMED_OUT.into()));

    // Ohne Rückfragen: fehlendes Passwort und unbekannter Server scheitern sofort.
    assert_eq!(run_command(&connect(running.address, None), "true", minute, 1024, |_, _, _| true).await.unwrap_err(), End::AuthFailed);
    assert_eq!(run_command(&ready, "true", minute, 1024, |_, _, _| false).await.unwrap_err(), End::HostKeyRejected);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_measuring_command_runs_in_a_plain_shell() {
    if std::process::Command::new("sh").arg("-c").arg("true").output().is_err() {
        eprintln!("ohne sh im Pfad übersprungen");
        return;
    }
    // Auf diesem Rechner gibt es kein /proc; geprüft wird, dass der Befehl als Ganzes läuft und seine Abschnitte nennt.
    let home = Home::new("messung");
    let running = server::start(Options { home: Some(home.0.clone()), ..options() }, server::key(1)).await.unwrap();
    let output = run_command(&connect(running.address, Some("richtig")), stats::COMMAND, Duration::from_secs(30), 256 * 1024, |_, _, _| true).await.unwrap();
    let text = String::from_utf8_lossy(&output.stdout);
    for section in ["@cpu", "@cores", "@mem", "@load", "@uptime", "@net", "@disk", "@kernel", "@host", "@os"] {
        assert!(text.lines().any(|line| line.trim() == section), "Abschnitt {section} fehlt in:\n{text}");
    }
    assert!(!text.contains("No such file"), "Fehlermeldungen gehören nicht in die Ausgabe:\n{text}");
    if std::path::Path::new("/proc/stat").exists() {
        assert!(stats::parse(&text).is_some());
    }
}

/// Kein Test, sondern Messwerte: wie schnell Daten durch eine lokale Weiterleitung gehen und was eine neue Verbindung
/// kostet, alles auf diesem Rechner gegen den eigenen Testserver; daneben dieselbe Menge ohne Tunnel. Aufruf:
/// `cargo test --release -p glowport-net --test forward measures_tunnel -- --ignored --nocapture`
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn measures_tunnel_throughput() {
    use std::time::Instant;
    const SIZE: usize = 512 * 1024 * 1024;
    const CONNECTIONS: u32 = 300;

    // Ein Ziel, das alles schluckt und am Ende sagt, wie viel es war.
    let sink = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let sink_port = sink.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = sink.accept().await {
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 256 * 1024];
                let mut total = 0u64;
                while let Ok(n) = stream.read(&mut buffer).await {
                    if n == 0 {
                        break;
                    }
                    total += n as u64;
                }
                let _ = stream.write_all(&total.to_be_bytes()).await;
            });
        }
    });
    let pour = |port: u16| async move {
        let started = Instant::now();
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let chunk = vec![7u8; 256 * 1024];
        for _ in 0..SIZE / chunk.len() {
            stream.write_all(&chunk).await.unwrap();
        }
        stream.shutdown().await.unwrap();
        let mut arrived = [0u8; 8];
        stream.read_exact(&mut arrived).await.unwrap();
        assert_eq!(u64::from_be_bytes(arrived), SIZE as u64);
        started.elapsed().as_secs_f64()
    };

    let running = server::start(options(), server::key(1)).await.unwrap();
    let counters = Arc::new(Counters::default());
    let (_tunnel, port) = local(running.address, Rule::Local { host: "127.0.0.1".into(), port: sink_port }, &counters).await;
    let direct = pour(sink_port).await;
    let tunnelled = pour(port).await;
    let megabytes = (SIZE / 1024 / 1024) as f64;
    println!("512 MB ohne Tunnel:  {direct:.2} s = {:.0} MB/s", megabytes / direct);
    println!("512 MB durch Tunnel: {tunnelled:.2} s = {:.0} MB/s", megabytes / tunnelled);

    let target = echo().await;
    let (_second, echo_port) = local(running.address, Rule::Local { host: "127.0.0.1".into(), port: target.port() }, &counters).await;
    let started = Instant::now();
    for _ in 0..CONNECTIONS {
        let mut stream = TcpStream::connect(("127.0.0.1", echo_port)).await.unwrap();
        assert_eq!(exchange(&mut stream, b"ping").await, b"echo:ping");
    }
    let each = started.elapsed().as_secs_f64() * 1000.0 / f64::from(CONNECTIONS);
    println!("{CONNECTIONS} Verbindungen nacheinander durch den Tunnel, je eine Anfrage: {each:.2} ms je Verbindung");
}

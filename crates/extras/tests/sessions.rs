//! The three kinds of terminals as whole sessions: a real shell on this machine, Telnet against a
//! counterpart in the test, and the serial port as far as it can be tested without a device.

use std::time::Duration;

use glowport_extras::{local, serial, telnet};
use glowport_net::{Command, End, Event, Phase, Session};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

const PATIENCE: Duration = Duration::from_secs(20);

const IAC: u8 = 255;
const DO: u8 = 253;
const WILL: u8 = 251;
const SB: u8 = 250;
const SE: u8 = 240;
const ECHO: u8 = 1;
const SGA: u8 = 3;
const TTYPE: u8 = 24;
const NAWS: u8 = 31;
const NEW_ENVIRON: u8 = 39;

/// What a session emits until its end.
#[derive(Debug, Default)]
struct Seen {
    phases: Vec<Phase>,
    output: Vec<u8>,
    end: Option<End>,
}

impl Seen {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.output).into_owned()
    }
}

/// Reads events until `done` is satisfied or the session ends.
async fn watch(session: &mut Session, seen: &mut Seen, done: impl Fn(&Seen) -> bool) {
    while !done(seen) && seen.end.is_none() {
        match timeout(PATIENCE, session.events.recv()).await.expect("the session no longer reports") {
            Some(Event::Phase(phase)) => seen.phases.push(phase),
            Some(Event::Output(bytes)) => seen.output.extend(bytes),
            Some(Event::End(end)) => seen.end = Some(end),
            Some(_) => {}
            None => panic!("the session ended without a reason"),
        }
    }
}

fn input(session: &Session, text: &str) {
    session.commands.send(Command::Input(text.as_bytes().to_vec())).unwrap();
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread")]
async fn a_local_shell_runs_and_reports_how_it_ended() {
    let shells = local::shells();
    let names: Vec<&str> = shells.iter().map(|shell| shell.id.as_str()).collect();
    assert!(names.contains(&"cmd") && names.contains(&"powershell"), "present on every Windows, found: {names:?}");
    assert!(local::shell("does-not-exist").is_none() && local::shell("C:\\Windows\\System32\\calc.exe").is_none(), "only what was found is started");

    let mut session = local::open(local::shell("cmd").unwrap(), (100, 30));
    let mut seen = Seen::default();
    watch(&mut session, &mut seen, |seen| seen.phases.contains(&Phase::Connected)).await;
    assert_eq!(seen.phases, [Phase::Connecting, Phase::Connected]);
    // Windows first asks where the cursor is. Here the test answers, as the terminal otherwise does.
    watch(&mut session, &mut seen, |seen| seen.text().contains("\x1b[6n")).await;
    input(&session, "\x1b[1;1R");

    // The answer contains what only the shell fills in; the echo of the input alone would not contain it.
    input(&session, "echo glowport-%OS%-ok\r");
    watch(&mut session, &mut seen, |seen| seen.text().contains("glowport-Windows_NT-ok")).await;
    assert!(seen.end.is_none(), "the shell keeps running: {}", seen.text());

    // The shell starts in the home directory.
    input(&session, "cd\r");
    let home = std::env::var("USERPROFILE").unwrap();
    watch(&mut session, &mut seen, |seen| seen.text().matches(home.as_str()).count() >= 2).await;

    // Resize and ask for an additional channel: the first works silently, the second does not exist here.
    session.commands.send(Command::Resize(140, 50)).unwrap();
    let (reply, opened) = tokio::sync::oneshot::channel();
    session.commands.send(Command::Open(reply)).unwrap();
    assert!(opened.await.unwrap().is_none());

    input(&session, "exit 7\r");
    watch(&mut session, &mut seen, |_| false).await;
    assert_eq!(seen.end, Some(End::Remote { exit_status: Some(7) }));
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread")]
async fn closing_a_local_terminal_ends_its_shell() {
    let mut session = local::open(local::shell("powershell").unwrap(), (80, 24));
    let mut seen = Seen::default();
    watch(&mut session, &mut seen, |seen| seen.phases.contains(&Phase::Connected)).await;
    // Here nobody answers the question about the cursor: after a short timeout the core does, and the shell
    // comes anyway. PowerShell's prompt ends in “> ”.
    watch(&mut session, &mut seen, |seen| seen.text().contains("> ")).await;
    session.commands.send(Command::Close).unwrap();
    watch(&mut session, &mut seen, |_| false).await;
    assert_eq!(seen.end, Some(End::User));
}

/// Reads from the client until `wanted` appeared as a sequence of bytes.
async fn expect(stream: &mut TcpStream, got: &mut Vec<u8>, wanted: &[u8]) {
    let mut buffer = [0u8; 512];
    while !got.windows(wanted.len()).any(|window| window == wanted) {
        let n = timeout(PATIENCE, stream.read(&mut buffer)).await.expect("the client is silent").unwrap();
        assert!(n > 0, "the client closed, seen: {got:?}");
        got.extend(&buffer[..n]);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn telnet_negotiates_names_the_user_and_passes_the_terminal_through() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut got = Vec::new();
        // A Telnet server like on a switch: it provides the echo and wants to know terminal type, size and user.
        stream.write_all(&[IAC, WILL, ECHO, IAC, WILL, SGA, IAC, DO, TTYPE, IAC, DO, NAWS, IAC, DO, NEW_ENVIRON]).await.unwrap();
        expect(&mut stream, &mut got, &[IAC, DO, ECHO, IAC, DO, SGA, IAC, WILL, TTYPE, IAC, WILL, NAWS, IAC, SB, NAWS, 0, 132, 0, 43, IAC, SE, IAC, WILL, NEW_ENVIRON]).await;
        stream.write_all(&[IAC, SB, TTYPE, 1, IAC, SE, IAC, SB, NEW_ENVIRON, 1, IAC, SE]).await.unwrap();
        expect(&mut stream, &mut got, &[&[IAC, SB, TTYPE, 0][..], b"vt220", &[IAC, SE]].concat()).await;
        expect(&mut stream, &mut got, &[&[IAC, SB, NEW_ENVIRON, 0, 0][..], b"USER", &[1], b"admin", &[IAC, SE]].concat()).await;
        // Text with a byte 255 in it and a CR NUL.
        stream.write_all(&[b'P', b'a', b's', b's', b'w', b'o', b'r', b'd', b':', b' ', IAC, IAC, b'\r', 0]).await.unwrap();
        got.clear();
        expect(&mut stream, &mut got, b"geheim\r\n").await;
        // The new window size arrives as a subnegotiation.
        expect(&mut stream, &mut got, &[IAC, SB, NAWS, 0, 90, 0, 20, IAC, SE]).await;
        stream.write_all(b"\r\nswitch>").await.unwrap();
        got
    });

    let mut session = telnet::open(telnet::Telnet { host: "127.0.0.1".into(), port, user: Some("admin".into()), term: "vt220".into(), size: (132, 43), ..telnet::Telnet::default() });
    let mut seen = Seen::default();
    watch(&mut session, &mut seen, |seen| seen.output.ends_with(&[IAC, b'\r'])).await;
    assert_eq!(seen.phases, [Phase::Connecting, Phase::Connected]);
    assert_eq!(seen.output, [&b"Password: "[..], &[IAC, b'\r']].concat(), "without protocol commands and without the NUL");

    input(&session, "geheim\r");
    session.commands.send(Command::Resize(90, 20)).unwrap();
    let got = server.await.unwrap();
    assert!(!got.windows(2).any(|pair| pair == [b'\r', 0]), "Enter is CR LF");

    // The server closes: the session ends, what it wrote last has arrived.
    watch(&mut session, &mut seen, |_| false).await;
    assert!(seen.text().ends_with("\r\nswitch>"));
    assert_eq!(seen.end, Some(End::Remote { exit_status: None }));
}

#[tokio::test(flavor = "multi_thread")]
async fn telnet_to_a_plain_service_builds_the_line_here() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        // A service that does not speak Telnet: it greets and waits for a line.
        stream.write_all(b"220 mail.test ESMTP\r\n").await.unwrap();
        let mut got = Vec::new();
        expect(&mut stream, &mut got, b"\r\n").await;
        stream.write_all(b"250 Hallo\r\n").await.unwrap();
        // Holds the connection until the client closes.
        let mut rest = Vec::new();
        let _ = stream.read_to_end(&mut rest).await;
        got
    });

    let mut session = telnet::open(telnet::Telnet { host: "127.0.0.1".into(), port, ..telnet::Telnet::default() });
    let mut seen = Seen::default();
    watch(&mut session, &mut seen, |seen| seen.text().contains("ESMTP\r\n")).await;
    // Mistyped and corrected: shown at once, only the finished line is sent.
    input(&session, "HELO glowporr");
    input(&session, "\x7ft\r");
    watch(&mut session, &mut seen, |seen| seen.text().contains("250 Hallo")).await;
    assert_eq!(seen.text(), "220 mail.test ESMTP\r\nHELO glowporr\x08 \x08t\r\n250 Hallo\r\n");

    session.commands.send(Command::Close).unwrap();
    watch(&mut session, &mut seen, |_| false).await;
    assert_eq!(seen.end, Some(End::User));
    assert_eq!(server.await.unwrap(), b"HELO glowport\r\n", "a service without Telnet sees no protocol byte");
}

#[tokio::test(flavor = "multi_thread")]
async fn telnet_reports_why_it_could_not_connect() {
    // A port that was listened on a moment ago and now nobody is.
    let port = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port();
    let mut session = telnet::open(telnet::Telnet { host: "127.0.0.1".into(), port, timeout: Duration::from_secs(5), ..telnet::Telnet::default() });
    let mut seen = Seen::default();
    watch(&mut session, &mut seen, |_| false).await;
    assert!(matches!(seen.end, Some(End::ConnectFailed(_))), "{:?}", seen.end);
    assert_eq!(seen.phases, [Phase::Connecting]);

    // Whoever closes while connecting does not wait for the timeout. 203.0.113.0/24 is reserved for examples and never answers.
    let mut session = telnet::open(telnet::Telnet { host: "203.0.113.1".into(), timeout: Duration::from_secs(60), ..telnet::Telnet::default() });
    session.commands.send(Command::Close).unwrap();
    let mut seen = Seen::default();
    watch(&mut session, &mut seen, |_| false).await;
    assert_eq!(seen.end, Some(End::User));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_serial_port_that_is_not_there_fails_to_open() {
    // Listing must never fail, even without a single port.
    let ports = serial::ports();
    assert!(ports.iter().all(|port| !port.name.is_empty()));
    let missing = if cfg!(windows) { "COM254" } else { "/dev/ttyGLOWPORT-missing" };
    assert!(!ports.iter().any(|port| port.name == missing));

    let mut session = serial::open(missing.into(), serial::Line::default());
    let mut seen = Seen::default();
    watch(&mut session, &mut seen, |_| false).await;
    assert!(matches!(seen.end, Some(End::ConnectFailed(_))), "{:?}", seen.end);
    assert_eq!(seen.phases, [Phase::Connecting]);

    // A frame that does not exist is already refused when opening.
    let mut session = serial::open(missing.into(), serial::Line { data_bits: 9, ..serial::Line::default() });
    let mut seen = Seen::default();
    watch(&mut session, &mut seen, |_| false).await;
    assert!(matches!(seen.end, Some(End::ConnectFailed(message)) if message.contains("data bits")));
}

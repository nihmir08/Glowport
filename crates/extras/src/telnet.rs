//! Telnet: a terminal over an unencrypted TCP connection, for devices that cannot do SSH.
//!
//! The protocol (RFC 854 and following) mixes control commands into the data stream: a byte 255 (`IAC`) starts
//! a command. Both sides negotiate options with them. [`Codec`] knows those a terminal needs:
//! echo by the server, characters instead of lines, terminal type, window size, user name, 8 bit.
//!
//! If the server does not announce its own echo (a simple service behind a port, not a Telnet server), the
//! classic mode applies: the line is composed here, shown here and sent with Enter.

use std::time::Duration;

use glowport_net::{Command, End, Event, Phase, Session};
use socket2::{SockRef, TcpKeepalive};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::mpsc,
    time::timeout,
};

use crate::channels;

const IAC: u8 = 255;
const DONT: u8 = 254;
const DO: u8 = 253;
const WONT: u8 = 252;
const WILL: u8 = 251;
const SB: u8 = 250;
const SE: u8 = 240;
/// “Interrupt Process”: what Ctrl+C means while the line is composed here.
const IP: u8 = 244;

const BINARY: u8 = 0;
const ECHO: u8 = 1;
const SUPPRESS_GO_AHEAD: u8 = 3;
const TERMINAL_TYPE: u8 = 24;
const WINDOW_SIZE: u8 = 31;
const NEW_ENVIRON: u8 = 39;

/// In a subnegotiation: “IS” starts the answer, “SEND” the question.
const IS: u8 = 0;
const SEND: u8 = 1;
/// In NEW-ENVIRON: name of a variable and its value.
const VAR: u8 = 0;
const VALUE: u8 = 1;

/// A subnegotiation collects no more than this; whatever a server sends beyond it is discarded.
const MAX_SUBNEGOTIATION: usize = 512;
/// Longest line composed here in line mode.
const MAX_LINE: usize = 4096;

pub const DEFAULT_PORT: u16 = 23;

/// State of an option on one side. `Asked`: proposed from here, the answer is pending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Opt {
    Off,
    Asked,
    On,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Data,
    /// After a CR: a NUL after it belongs to the protocol and not to the text.
    AfterCr,
    Iac,
    /// After WILL, WONT, DO or DONT: the option follows.
    Verb(u8),
    Sub,
    SubIac,
}

/// What becomes of the user's input.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Typed {
    /// Goes to the server.
    pub wire: Vec<u8>,
    /// Appears in the terminal at once, because the server provides no echo.
    pub echo: Vec<u8>,
}

/// Translates between the line's data stream and what the terminal sees and the user types.
/// Knows no connection and can therefore be tested on its own.
pub struct Codec {
    state: State,
    sub: Vec<u8>,
    /// Options this side operates (WILL), by number.
    ours: [Opt; 256],
    /// Options the server operates (DO from here).
    theirs: [Opt; 256],
    term: String,
    user: Option<String>,
    size: (u16, u16),
    /// The line currently being composed in line mode.
    line: Vec<u8>,
}

fn fit(n: u32) -> u16 {
    u16::try_from(n.clamp(1, 1000)).unwrap_or(80)
}

impl Codec {
    pub fn new(term: &str, user: Option<&str>, (columns, rows): (u32, u32)) -> Self {
        // Only what can safely be written into a subnegotiation.
        let clean = |text: &str| text.bytes().filter(|b| b.is_ascii_graphic()).take(64).map(char::from).collect::<String>();
        Self {
            state: State::Data,
            sub: Vec::new(),
            ours: [Opt::Off; 256],
            theirs: [Opt::Off; 256],
            term: clean(term),
            user: user.map(clean).filter(|user| !user.is_empty()),
            size: (fit(columns), fit(rows)),
            line: Vec::new(),
        }
    }

    /// Options this side operates at the server's request.
    fn offers(&self, option: u8) -> bool {
        matches!(option, BINARY | SUPPRESS_GO_AHEAD | TERMINAL_TYPE | WINDOW_SIZE) || (option == NEW_ENVIRON && self.user.is_some())
    }

    /// Options the server may operate.
    fn accepts(option: u8) -> bool {
        matches!(option, BINARY | ECHO | SUPPRESS_GO_AHEAD)
    }

    /// The server provides the echo: characters go out one by one, what comes back is shown.
    pub fn remote_echo(&self) -> bool {
        self.theirs[usize::from(ECHO)] == Opt::On
    }

    /// What this side proposes on its own. Only meant for the Telnet port: another service (SMTP, HTTP)
    /// would take the bytes for input.
    pub fn greeting(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        for option in [WINDOW_SIZE, TERMINAL_TYPE, NEW_ENVIRON, SUPPRESS_GO_AHEAD] {
            if self.offers(option) {
                self.ours[usize::from(option)] = Opt::Asked;
                out.extend([IAC, WILL, option]);
            }
        }
        for option in [ECHO, SUPPRESS_GO_AHEAD] {
            self.theirs[usize::from(option)] = Opt::Asked;
            out.extend([IAC, DO, option]);
        }
        out
    }

    fn window(&self) -> Vec<u8> {
        let mut out = vec![IAC, SB, WINDOW_SIZE];
        for byte in [self.size.0.to_be_bytes(), self.size.1.to_be_bytes()].concat() {
            // In a subnegotiation, too, 255 is doubled.
            out.extend(std::iter::repeat_n(byte, if byte == IAC { 2 } else { 1 }));
        }
        out.extend([IAC, SE]);
        out
    }

    /// New size of the terminal; empty as long as the window size is not negotiated.
    pub fn resize(&mut self, columns: u32, rows: u32) -> Vec<u8> {
        self.size = (fit(columns), fit(rows));
        if self.ours[usize::from(WINDOW_SIZE)] == Opt::On { self.window() } else { Vec::new() }
    }

    fn negotiate(&mut self, verb: u8, option: u8, reply: &mut Vec<u8>) {
        let index = usize::from(option);
        match verb {
            // The server asks this side to operate an option.
            DO => match self.ours[index] {
                Opt::On => {}
                state if self.offers(option) => {
                    self.ours[index] = Opt::On;
                    if state == Opt::Off {
                        reply.extend([IAC, WILL, option]);
                    }
                    if option == WINDOW_SIZE {
                        reply.extend(self.window());
                    }
                }
                _ => reply.extend([IAC, WONT, option]),
            },
            DONT => {
                let was = std::mem::replace(&mut self.ours[index], Opt::Off);
                if was == Opt::On {
                    reply.extend([IAC, WONT, option]);
                }
            }
            // The server announces that it operates an option.
            WILL => match self.theirs[index] {
                Opt::On => {}
                state if Self::accepts(option) => {
                    self.theirs[index] = Opt::On;
                    if state == Opt::Off {
                        reply.extend([IAC, DO, option]);
                    }
                    // From now on the server provides the echo: whatever was already typed here goes out at once.
                    if option == ECHO && !self.line.is_empty() {
                        reply.extend(Self::escaped(&std::mem::take(&mut self.line)));
                    }
                }
                _ => reply.extend([IAC, DONT, option]),
            },
            WONT => {
                let was = std::mem::replace(&mut self.theirs[index], Opt::Off);
                if was == Opt::On {
                    reply.extend([IAC, DONT, option]);
                }
            }
            _ => {}
        }
    }

    fn subnegotiation(&self, reply: &mut Vec<u8>) {
        match self.sub.as_slice() {
            [TERMINAL_TYPE, SEND, ..] if self.ours[usize::from(TERMINAL_TYPE)] == Opt::On => {
                reply.extend([IAC, SB, TERMINAL_TYPE, IS]);
                reply.extend(self.term.bytes());
                reply.extend([IAC, SE]);
            }
            [NEW_ENVIRON, SEND, ..] if self.ours[usize::from(NEW_ENVIRON)] == Opt::On => {
                reply.extend([IAC, SB, NEW_ENVIRON, IS]);
                if let Some(user) = &self.user {
                    reply.push(VAR);
                    reply.extend(b"USER");
                    reply.push(VALUE);
                    reply.extend(user.bytes());
                }
                reply.extend([IAC, SE]);
            }
            _ => {}
        }
    }

    /// Processes bytes from the server: `out` gets the text for the terminal, `reply` the protocol's answers.
    pub fn receive(&mut self, bytes: &[u8], out: &mut Vec<u8>, reply: &mut Vec<u8>) {
        let binary = self.theirs[usize::from(BINARY)] == Opt::On;
        for &byte in bytes {
            self.state = match (self.state, byte) {
                (State::AfterCr, 0) => State::Data,
                (State::Data | State::AfterCr, IAC) => State::Iac,
                (State::Data | State::AfterCr, _) => {
                    out.push(byte);
                    if byte == b'\r' && !binary { State::AfterCr } else { State::Data }
                }
                (State::Iac, IAC) => {
                    out.push(IAC);
                    State::Data
                }
                (State::Iac, WILL | WONT | DO | DONT) => State::Verb(byte),
                (State::Iac, SB) => {
                    self.sub.clear();
                    State::Sub
                }
                // NOP, “Go Ahead”, “Are You There” and the other commands without arguments: nothing to do.
                (State::Iac, _) => State::Data,
                (State::Verb(verb), option) => {
                    self.negotiate(verb, option, reply);
                    State::Data
                }
                (State::Sub, IAC) => State::SubIac,
                (State::Sub, _) => {
                    if self.sub.len() < MAX_SUBNEGOTIATION {
                        self.sub.push(byte);
                    }
                    State::Sub
                }
                (State::SubIac, IAC) => {
                    if self.sub.len() < MAX_SUBNEGOTIATION {
                        self.sub.push(IAC);
                    }
                    State::Sub
                }
                (State::SubIac, SE) => {
                    self.subnegotiation(reply);
                    self.sub.clear();
                    State::Data
                }
                // Another command in the middle of a subnegotiation: it counts as aborted.
                (State::SubIac, _) => State::Data,
            };
        }
    }

    /// Text for the line: 255 is doubled.
    fn escaped(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(bytes.len());
        for &byte in bytes {
            out.extend(std::iter::repeat_n(byte, if byte == IAC { 2 } else { 1 }));
        }
        out
    }

    /// Processes what the user types.
    ///
    /// If the server provides the echo, every character goes out at once; Enter becomes the protocol's
    /// line ending (CR LF). Otherwise the line is composed here: characters appear in the terminal, Backspace deletes,
    /// Ctrl+U discards, and only Enter sends the line.
    pub fn typed(&mut self, bytes: &[u8]) -> Typed {
        let mut typed = Typed::default();
        let raw = self.ours[usize::from(BINARY)] == Opt::On;
        if self.remote_echo() {
            for &byte in bytes {
                match byte {
                    b'\r' if !raw => typed.wire.extend(b"\r\n"),
                    IAC => typed.wire.extend([IAC, IAC]),
                    _ => typed.wire.push(byte),
                }
            }
            return typed;
        }
        let mut rest = bytes;
        while let Some((&byte, tail)) = rest.split_first() {
            rest = tail;
            match byte {
                b'\r' => {
                    typed.wire.extend(Self::escaped(&std::mem::take(&mut self.line)));
                    typed.wire.extend(b"\r\n");
                    typed.echo.extend(b"\r\n");
                }
                // Backspace: a whole character goes, even if it consists of several bytes in UTF-8.
                0x7f | 0x08 => {
                    if !self.line.is_empty() {
                        while self.line.pop().is_some_and(|b| b & 0xC0 == 0x80) {}
                        typed.echo.extend(b"\x08 \x08");
                    }
                }
                // Ctrl+U discards the line.
                0x15 => {
                    let shown = String::from_utf8_lossy(&self.line).chars().count();
                    self.line.clear();
                    typed.echo.extend(b"\x08 \x08".repeat(shown));
                }
                // Ctrl+C: the line is void, the server learns about the interruption.
                0x03 => {
                    self.line.clear();
                    typed.wire.extend([IAC, IP]);
                    typed.echo.extend(b"^C\r\n");
                }
                // Arrow keys and other key sequences edit nothing here; they go out together with the line before them.
                0x1b => {
                    typed.wire.extend(Self::escaped(&std::mem::take(&mut self.line)));
                    typed.wire.push(byte);
                    typed.wire.extend(Self::escaped(rest));
                    break;
                }
                // Other control characters (Tab, Ctrl+D) go out at once, together with what is already typed.
                0..0x20 => {
                    typed.wire.extend(Self::escaped(&std::mem::take(&mut self.line)));
                    typed.wire.push(byte);
                }
                _ => {
                    if self.line.len() < MAX_LINE {
                        self.line.push(byte);
                        typed.echo.push(byte);
                    }
                }
            }
        }
        typed
    }
}

pub struct Telnet {
    pub host: String,
    pub port: u16,
    /// Given to the server when it asks. Many use it to sign in without asking for the name.
    pub user: Option<String>,
    /// Terminal type the server sees as `TERM`.
    pub term: String,
    /// How long to wait for the connection to be established.
    pub timeout: Duration,
    /// Columns and rows of the terminal when connecting.
    pub size: (u32, u32),
}

impl Default for Telnet {
    fn default() -> Self {
        Self { host: String::new(), port: DEFAULT_PORT, user: None, term: "xterm-256color".into(), timeout: Duration::from_secs(15), size: (80, 24) }
    }
}

/// Opens a Telnet session. Must be called inside a tokio runtime.
pub fn open(telnet: Telnet) -> Session {
    let (session, events, mut commands) = channels();
    tokio::spawn(async move {
        let end = run(telnet, &events, &mut commands).await.unwrap_or_else(|end| end);
        let _ = events.send(Event::End(end)).await;
    });
    session
}

async fn emit(events: &mpsc::Sender<Event>, event: Event) -> Result<(), End> {
    events.send(event).await.map_err(|_| End::User)
}

fn lost(error: std::io::Error) -> End {
    End::ConnectionLost(error.to_string())
}

async fn run(telnet: Telnet, events: &mpsc::Sender<Event>, commands: &mut mpsc::UnboundedReceiver<Command>) -> Result<End, End> {
    emit(events, Event::Phase(Phase::Connecting)).await?;
    let mut size = telnet.size;
    // Until the connection is up, only “close” counts among the commands; the last reported size is remembered.
    let connecting = timeout(telnet.timeout, TcpStream::connect((telnet.host.as_str(), telnet.port)));
    tokio::pin!(connecting);
    let stream = loop {
        tokio::select! {
            result = &mut connecting => break result.map_err(|_| End::ConnectFailed("timed out".into()))?.map_err(|e| End::ConnectFailed(e.to_string()))?,
            command = commands.recv() => match command {
                Some(Command::Close) | None => return Err(End::User),
                Some(Command::Resize(columns, rows)) => size = (columns, rows),
                Some(Command::Open(reply)) => drop(reply.send(None)),
                Some(Command::Relink) => {}
                Some(Command::Input(_) | Command::Pause(_)) => {}
            },
        }
    };
    let _ = stream.set_nodelay(true);
    // Telnet has no keepalive. The operating system's notices a dead line without sending the device anything.
    let _ = SockRef::from(&stream).set_tcp_keepalive(&TcpKeepalive::new().with_time(Duration::from_secs(60)).with_interval(Duration::from_secs(15)));
    let (mut reader, mut writer) = stream.into_split();

    let mut codec = Codec::new(&telnet.term, telnet.user.as_deref(), size);
    if telnet.port == DEFAULT_PORT {
        writer.write_all(&codec.greeting()).await.map_err(lost)?;
    }
    emit(events, Event::Phase(Phase::Connected)).await?;

    let mut buffer = vec![0u8; 16 * 1024];
    let mut paused = false;
    loop {
        tokio::select! {
            read = reader.read(&mut buffer), if !paused => match read.map_err(lost)? {
                0 => return Ok(End::Remote { exit_status: None }),
                n => {
                    let (mut out, mut reply) = (Vec::with_capacity(n), Vec::new());
                    codec.receive(&buffer[..n], &mut out, &mut reply);
                    if !reply.is_empty() {
                        writer.write_all(&reply).await.map_err(lost)?;
                    }
                    if !out.is_empty() {
                        emit(events, Event::Output(out)).await?;
                    }
                }
            },
            command = commands.recv() => match command {
                Some(Command::Input(bytes)) => {
                    let typed = codec.typed(&bytes);
                    if !typed.wire.is_empty() {
                        writer.write_all(&typed.wire).await.map_err(lost)?;
                    }
                    if !typed.echo.is_empty() {
                        emit(events, Event::Output(typed.echo)).await?;
                    }
                }
                Some(Command::Resize(columns, rows)) => {
                    let update = codec.resize(columns, rows);
                    if !update.is_empty() {
                        writer.write_all(&update).await.map_err(lost)?;
                    }
                }
                Some(Command::Pause(pause)) => paused = pause,
                Some(Command::Open(reply)) => drop(reply.send(None)),
                Some(Command::Relink) => {}
                Some(Command::Close) | None => {
                    let _ = writer.shutdown().await;
                    return Ok(End::User);
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receive(codec: &mut Codec, bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let (mut out, mut reply) = (Vec::new(), Vec::new());
        codec.receive(bytes, &mut out, &mut reply);
        (out, reply)
    }

    #[test]
    fn options_are_negotiated_once_and_refused_when_unknown() {
        let mut codec = Codec::new("xterm-256color", Some("admin"), (120, 40));
        // The server wants to provide echo and character mode and asks for terminal type and window size.
        let (out, reply) = receive(&mut codec, &[IAC, WILL, ECHO, IAC, WILL, SUPPRESS_GO_AHEAD, IAC, DO, TERMINAL_TYPE, IAC, DO, WINDOW_SIZE]);
        assert!(out.is_empty());
        assert_eq!(reply, [&[IAC, DO, ECHO, IAC, DO, SUPPRESS_GO_AHEAD, IAC, WILL, TERMINAL_TYPE, IAC, WILL, WINDOW_SIZE][..], &[IAC, SB, WINDOW_SIZE, 0, 120, 0, 40, IAC, SE]].concat());
        assert!(codec.remote_echo());
        // The same announcement again: no answer, otherwise a loop would result.
        assert!(receive(&mut codec, &[IAC, WILL, ECHO, IAC, DO, TERMINAL_TYPE]).1.is_empty());
        // What this side does not know it refuses: 32 is the terminal speed, 34 the protocol's line mode.
        assert_eq!(receive(&mut codec, &[IAC, DO, 32, IAC, WILL, 34]).1, [IAC, WONT, 32, IAC, DONT, 34]);
        // If the server withdraws its echo, that is confirmed.
        assert_eq!(receive(&mut codec, &[IAC, WONT, ECHO]).1, [IAC, DONT, ECHO]);
        assert!(!codec.remote_echo());
        assert!(receive(&mut codec, &[IAC, WONT, ECHO, IAC, DONT, 99]).1.is_empty(), "what is already off needs no answer");
    }

    #[test]
    fn terminal_type_user_and_size_are_answered() {
        let mut codec = Codec::new("vt100", Some("admin"), (80, 24));
        receive(&mut codec, &[IAC, DO, TERMINAL_TYPE, IAC, DO, NEW_ENVIRON, IAC, DO, WINDOW_SIZE]);
        assert_eq!(receive(&mut codec, &[IAC, SB, TERMINAL_TYPE, SEND, IAC, SE]).1, [&[IAC, SB, TERMINAL_TYPE, IS][..], b"vt100", &[IAC, SE]].concat());
        assert_eq!(receive(&mut codec, &[IAC, SB, NEW_ENVIRON, SEND, VAR, b'U', b'S', b'E', b'R', IAC, SE]).1, [&[IAC, SB, NEW_ENVIRON, IS, VAR][..], b"USER", &[VALUE], b"admin", &[IAC, SE]].concat());
        // 255 columns: the byte is doubled in the subnegotiation.
        assert_eq!(codec.resize(255, 50), [IAC, SB, WINDOW_SIZE, 0, IAC, IAC, 0, 50, IAC, SE]);

        // Without a user this side does not even offer the environment.
        let mut nameless = Codec::new("vt100", None, (80, 24));
        assert_eq!(receive(&mut nameless, &[IAC, DO, NEW_ENVIRON]).1, [IAC, WONT, NEW_ENVIRON]);
        assert!(nameless.resize(100, 30).is_empty(), "the window size is not negotiated");
        // A question about something not negotiated stays unanswered.
        assert!(receive(&mut nameless, &[IAC, SB, TERMINAL_TYPE, SEND, IAC, SE]).1.is_empty());
    }

    #[test]
    fn what_this_side_proposes_needs_no_second_answer() {
        let mut codec = Codec::new("xterm", Some("admin"), (80, 24));
        assert_eq!(
            codec.greeting(),
            [IAC, WILL, WINDOW_SIZE, IAC, WILL, TERMINAL_TYPE, IAC, WILL, NEW_ENVIRON, IAC, WILL, SUPPRESS_GO_AHEAD, IAC, DO, ECHO, IAC, DO, SUPPRESS_GO_AHEAD]
        );
        // The server agrees: only the window size follows, no second promise.
        let (_, reply) = receive(&mut codec, &[IAC, DO, WINDOW_SIZE, IAC, DO, TERMINAL_TYPE, IAC, WILL, ECHO, IAC, WILL, SUPPRESS_GO_AHEAD]);
        assert_eq!(reply, [IAC, SB, WINDOW_SIZE, 0, 80, 0, 24, IAC, SE]);
        assert!(codec.remote_echo());
        // The server refuses something proposed: accepted without an answer.
        assert!(receive(&mut codec, &[IAC, DONT, NEW_ENVIRON]).1.is_empty());
        assert!(receive(&mut codec, &[IAC, SB, NEW_ENVIRON, SEND, IAC, SE]).1.is_empty());
    }

    #[test]
    fn data_is_separated_from_commands_even_across_packets() {
        let mut codec = Codec::new("xterm", None, (80, 24));
        // Double 255 is a data byte; CR NUL is a CR; CR LF stays.
        assert_eq!(receive(&mut codec, &[b'a', IAC, IAC, b'b', b'\r', 0, b'c', b'\r', b'\n']).0, [b'a', IAC, b'b', b'\r', b'c', b'\r', b'\n']);
        // A command spread over three packets.
        assert!(receive(&mut codec, &[b'x', IAC]).1.is_empty());
        assert!(receive(&mut codec, &[WILL]).1.is_empty());
        assert_eq!(receive(&mut codec, &[ECHO, b'y']), (vec![b'y'], vec![IAC, DO, ECHO]));
        // CR at the end of one packet, NUL at the start of the next.
        assert_eq!(receive(&mut codec, b"zeile\r").0, b"zeile\r");
        assert_eq!(receive(&mut codec, &[0, b'!']).0, b"!");
        // NOP and “Go Ahead” disappear; an overlong subnegotiation breaks nothing.
        assert_eq!(receive(&mut codec, &[b'1', IAC, 241, b'2', IAC, 249, b'3']).0, b"123");
        let mut long = vec![IAC, SB, 200];
        long.extend(std::iter::repeat_n(b'x', 5000));
        long.extend([IAC, SE, b'!']);
        assert_eq!(receive(&mut codec, &long).0, b"!");
        // In 8-bit mode a NUL after CR belongs to the text.
        receive(&mut codec, &[IAC, WILL, BINARY]);
        assert_eq!(receive(&mut codec, &[b'\r', 0]).0, [b'\r', 0]);
    }

    #[test]
    fn typing_goes_out_at_once_when_the_server_echoes() {
        let mut codec = Codec::new("xterm", None, (80, 24));
        receive(&mut codec, &[IAC, WILL, ECHO]);
        assert_eq!(codec.typed(b"ls\r"), Typed { wire: b"ls\r\n".to_vec(), echo: Vec::new() });
        assert_eq!(codec.typed(&[0x03, 0x7f, 0x1b, b'[', b'A', IAC]).wire, [0x03, 0x7f, 0x1b, b'[', b'A', IAC, IAC]);
        // In 8-bit mode Enter stays as it is.
        receive(&mut codec, &[IAC, DO, BINARY]);
        assert_eq!(codec.typed(b"\r").wire, b"\r");
    }

    #[test]
    fn without_remote_echo_the_line_is_built_here() {
        let mut codec = Codec::new("xterm", None, (80, 24));
        // Characters appear at once but only go out with Enter.
        assert_eq!(codec.typed(b"HELO x"), Typed { wire: Vec::new(), echo: b"HELO x".to_vec() });
        assert_eq!(codec.typed(&[0x7f]), Typed { wire: Vec::new(), echo: b"\x08 \x08".to_vec() });
        assert_eq!(codec.typed("ä\r".as_bytes()), Typed { wire: "HELO ä\r\n".as_bytes().to_vec(), echo: "ä\r\n".as_bytes().to_vec() });
        // Backspace takes a whole character, even one of two bytes; on an empty line it does nothing.
        codec.typed("aö".as_bytes());
        assert_eq!(codec.typed(&[0x7f, 0x7f, 0x7f]).echo, b"\x08 \x08\x08 \x08");
        assert_eq!(codec.typed(b"\r").wire, b"\r\n");
        // Ctrl+U discards, Ctrl+C reports the interruption to the server.
        codec.typed(b"gone");
        assert_eq!(codec.typed(&[0x15]).echo, b"\x08 \x08\x08 \x08\x08 \x08\x08 \x08");
        codec.typed(b"gone too");
        assert_eq!(codec.typed(&[0x03]), Typed { wire: vec![IAC, IP], echo: b"^C\r\n".to_vec() });
        assert_eq!(codec.typed(b"\r").wire, b"\r\n", "the discarded line does not go out with it");
        // A Tab and an arrow key take along what is already there.
        codec.typed(b"sh");
        assert_eq!(codec.typed(b"\t").wire, b"sh\t");
        codec.typed(b"x");
        assert_eq!(codec.typed(b"\x1b[A").wire, b"x\x1b[A");
        // If the server announces its echo in the middle of a line, what was typed goes out at once.
        codec.typed(b"admin");
        assert_eq!(receive(&mut codec, &[IAC, WILL, ECHO]).1, [&[IAC, DO, ECHO][..], b"admin"].concat());
        assert_eq!(codec.typed(b"\r").wire, b"\r\n");
    }
}

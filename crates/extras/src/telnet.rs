//! Telnet: ein Terminal über eine unverschlüsselte TCP-Verbindung, für Geräte, die kein SSH können.
//!
//! Das Protokoll (RFC 854 und folgende) mischt Steuerbefehle in den Datenstrom: Ein Byte 255 (`IAC`) leitet
//! einen Befehl ein. Beide Seiten handeln damit Optionen aus. [`Codec`] kennt die, die ein Terminal braucht:
//! Echo durch den Server, Zeichen statt Zeilen, Terminal-Typ, Fenstergröße, Benutzername, 8 Bit.
//!
//! Meldet der Server kein eigenes Echo an (ein einfacher Dienst hinter einem Port, kein Telnet-Server), gilt die
//! klassische Betriebsart: Die Zeile entsteht hier, wird hier angezeigt und geht mit der Eingabetaste ab.

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
/// „Interrupt Process“: was Strg+C bedeutet, solange die Zeile hier entsteht.
const IP: u8 = 244;

const BINARY: u8 = 0;
const ECHO: u8 = 1;
const SUPPRESS_GO_AHEAD: u8 = 3;
const TERMINAL_TYPE: u8 = 24;
const WINDOW_SIZE: u8 = 31;
const NEW_ENVIRON: u8 = 39;

/// In einer Unterverhandlung: „IS“ leitet die Antwort ein, „SEND“ die Frage.
const IS: u8 = 0;
const SEND: u8 = 1;
/// In NEW-ENVIRON: Name einer Variablen und ihr Wert.
const VAR: u8 = 0;
const VALUE: u8 = 1;

/// Mehr sammelt eine Unterverhandlung nicht; was ein Server darüber hinaus schickt, wird verworfen.
const MAX_SUBNEGOTIATION: usize = 512;
/// Längste Zeile, die im Zeilenbetrieb hier entsteht.
const MAX_LINE: usize = 4096;

pub const DEFAULT_PORT: u16 = 23;

/// Stand einer Option auf einer Seite. `Asked`: von hier vorgeschlagen, die Antwort steht aus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Opt {
    Off,
    Asked,
    On,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Data,
    /// Nach einem CR: Ein NUL dahinter gehört zum Protokoll und nicht zum Text.
    AfterCr,
    Iac,
    /// Nach WILL, WONT, DO oder DONT: Es folgt die Option.
    Verb(u8),
    Sub,
    SubIac,
}

/// Was aus einer Eingabe des Nutzers wird.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Typed {
    /// Geht an den Server.
    pub wire: Vec<u8>,
    /// Erscheint sofort im Terminal, weil der Server kein Echo liefert.
    pub echo: Vec<u8>,
}

/// Übersetzt zwischen dem Datenstrom der Leitung und dem, was das Terminal sieht und der Nutzer tippt.
/// Kennt keine Verbindung und lässt sich deshalb für sich prüfen.
pub struct Codec {
    state: State,
    sub: Vec<u8>,
    /// Optionen, die diese Seite betreibt (WILL), nach Nummer.
    ours: [Opt; 256],
    /// Optionen, die der Server betreibt (DO von hier).
    theirs: [Opt; 256],
    term: String,
    user: Option<String>,
    size: (u16, u16),
    /// Die Zeile, die im Zeilenbetrieb gerade entsteht.
    line: Vec<u8>,
}

fn fit(n: u32) -> u16 {
    u16::try_from(n.clamp(1, 1000)).unwrap_or(80)
}

impl Codec {
    pub fn new(term: &str, user: Option<&str>, (columns, rows): (u32, u32)) -> Self {
        // Nur was sich gefahrlos in eine Unterverhandlung schreiben lässt.
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

    /// Optionen, die diese Seite auf Wunsch des Servers betreibt.
    fn offers(&self, option: u8) -> bool {
        matches!(option, BINARY | SUPPRESS_GO_AHEAD | TERMINAL_TYPE | WINDOW_SIZE) || (option == NEW_ENVIRON && self.user.is_some())
    }

    /// Optionen, die der Server betreiben darf.
    fn accepts(option: u8) -> bool {
        matches!(option, BINARY | ECHO | SUPPRESS_GO_AHEAD)
    }

    /// Der Server liefert das Echo: Zeichen gehen einzeln ab, angezeigt wird, was zurückkommt.
    pub fn remote_echo(&self) -> bool {
        self.theirs[usize::from(ECHO)] == Opt::On
    }

    /// Was diese Seite von sich aus vorschlägt. Nur für den Telnet-Port gedacht: Ein anderer Dienst (SMTP, HTTP)
    /// hielte die Bytes für Eingabe.
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
            // Auch in einer Unterverhandlung steht 255 doppelt.
            out.extend(std::iter::repeat_n(byte, if byte == IAC { 2 } else { 1 }));
        }
        out.extend([IAC, SE]);
        out
    }

    /// Neue Größe des Terminals; leer, solange die Fenstergröße nicht ausgehandelt ist.
    pub fn resize(&mut self, columns: u32, rows: u32) -> Vec<u8> {
        self.size = (fit(columns), fit(rows));
        if self.ours[usize::from(WINDOW_SIZE)] == Opt::On { self.window() } else { Vec::new() }
    }

    fn negotiate(&mut self, verb: u8, option: u8, reply: &mut Vec<u8>) {
        let index = usize::from(option);
        match verb {
            // Der Server bittet diese Seite, eine Option zu betreiben.
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
            // Der Server kündigt an, eine Option zu betreiben.
            WILL => match self.theirs[index] {
                Opt::On => {}
                state if Self::accepts(option) => {
                    self.theirs[index] = Opt::On;
                    if state == Opt::Off {
                        reply.extend([IAC, DO, option]);
                    }
                    // Ab jetzt liefert der Server das Echo: Was hier schon getippt wurde, geht sofort ab.
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

    /// Verarbeitet Bytes vom Server: `out` bekommt den Text für das Terminal, `reply` die Antworten des Protokolls.
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
                // NOP, „Go Ahead“, „Are You There“ und die übrigen Befehle ohne Angabe: nichts zu tun.
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
                // Ein anderer Befehl mitten in der Unterverhandlung: Sie gilt als abgebrochen.
                (State::SubIac, _) => State::Data,
            };
        }
    }

    /// Text für die Leitung: 255 steht doppelt.
    fn escaped(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(bytes.len());
        for &byte in bytes {
            out.extend(std::iter::repeat_n(byte, if byte == IAC { 2 } else { 1 }));
        }
        out
    }

    /// Verarbeitet, was der Nutzer tippt.
    ///
    /// Liefert der Server das Echo, geht jedes Zeichen sofort ab; die Eingabetaste wird zum Zeilenende des
    /// Protokolls (CR LF). Sonst entsteht die Zeile hier: Zeichen erscheinen im Terminal, die Rücktaste löscht,
    /// Strg+U verwirft, und erst die Eingabetaste schickt die Zeile ab.
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
                // Rücktaste: ein ganzes Zeichen weg, auch wenn es in UTF-8 aus mehreren Bytes besteht.
                0x7f | 0x08 => {
                    if !self.line.is_empty() {
                        while self.line.pop().is_some_and(|b| b & 0xC0 == 0x80) {}
                        typed.echo.extend(b"\x08 \x08");
                    }
                }
                // Strg+U verwirft die Zeile.
                0x15 => {
                    let shown = String::from_utf8_lossy(&self.line).chars().count();
                    self.line.clear();
                    typed.echo.extend(b"\x08 \x08".repeat(shown));
                }
                // Strg+C: Die Zeile ist hinfällig, der Server erfährt vom Abbruch.
                0x03 => {
                    self.line.clear();
                    typed.wire.extend([IAC, IP]);
                    typed.echo.extend(b"^C\r\n");
                }
                // Pfeiltasten und andere Tastenfolgen bearbeiten hier nichts; sie gehen samt der Zeile davor ab.
                0x1b => {
                    typed.wire.extend(Self::escaped(&std::mem::take(&mut self.line)));
                    typed.wire.push(byte);
                    typed.wire.extend(Self::escaped(rest));
                    break;
                }
                // Andere Steuerzeichen (Tab, Strg+D) gehen sofort ab, mit dem, was schon getippt ist.
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
    /// Wird dem Server genannt, wenn er danach fragt. Viele melden damit ohne Nachfrage nach dem Namen an.
    pub user: Option<String>,
    /// Terminal-Typ, den der Server als `TERM` sieht.
    pub term: String,
    /// Wie lange auf das Zustandekommen der Verbindung gewartet wird.
    pub timeout: Duration,
    /// Spalten und Zeilen des Terminals beim Verbinden.
    pub size: (u32, u32),
}

impl Default for Telnet {
    fn default() -> Self {
        Self { host: String::new(), port: DEFAULT_PORT, user: None, term: "xterm-256color".into(), timeout: Duration::from_secs(15), size: (80, 24) }
    }
}

/// Öffnet eine Telnet-Sitzung. Muss in einem tokio-Runtime aufgerufen werden.
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
    // Bis die Verbindung steht, zählt von den Befehlen nur „Schließen“; die letzte gemeldete Größe wird gemerkt.
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
    // Telnet kennt kein Lebenszeichen. Das des Betriebssystems bemerkt eine tote Leitung, ohne dem Gerät etwas zu schicken.
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
        // Der Server will Echo und Zeichenbetrieb liefern und fragt nach Terminal-Typ und Fenstergröße.
        let (out, reply) = receive(&mut codec, &[IAC, WILL, ECHO, IAC, WILL, SUPPRESS_GO_AHEAD, IAC, DO, TERMINAL_TYPE, IAC, DO, WINDOW_SIZE]);
        assert!(out.is_empty());
        assert_eq!(reply, [&[IAC, DO, ECHO, IAC, DO, SUPPRESS_GO_AHEAD, IAC, WILL, TERMINAL_TYPE, IAC, WILL, WINDOW_SIZE][..], &[IAC, SB, WINDOW_SIZE, 0, 120, 0, 40, IAC, SE]].concat());
        assert!(codec.remote_echo());
        // Dieselbe Ankündigung noch einmal: keine Antwort, sonst entstünde eine Schleife.
        assert!(receive(&mut codec, &[IAC, WILL, ECHO, IAC, DO, TERMINAL_TYPE]).1.is_empty());
        // Was diese Seite nicht kennt, lehnt sie ab: 32 ist die Geschwindigkeit des Terminals, 34 der Zeilenbetrieb des Protokolls.
        assert_eq!(receive(&mut codec, &[IAC, DO, 32, IAC, WILL, 34]).1, [IAC, WONT, 32, IAC, DONT, 34]);
        // Nimmt der Server sein Echo zurück, wird das bestätigt.
        assert_eq!(receive(&mut codec, &[IAC, WONT, ECHO]).1, [IAC, DONT, ECHO]);
        assert!(!codec.remote_echo());
        assert!(receive(&mut codec, &[IAC, WONT, ECHO, IAC, DONT, 99]).1.is_empty(), "was schon aus ist, braucht keine Antwort");
    }

    #[test]
    fn terminal_type_user_and_size_are_answered() {
        let mut codec = Codec::new("vt100", Some("admin"), (80, 24));
        receive(&mut codec, &[IAC, DO, TERMINAL_TYPE, IAC, DO, NEW_ENVIRON, IAC, DO, WINDOW_SIZE]);
        assert_eq!(receive(&mut codec, &[IAC, SB, TERMINAL_TYPE, SEND, IAC, SE]).1, [&[IAC, SB, TERMINAL_TYPE, IS][..], b"vt100", &[IAC, SE]].concat());
        assert_eq!(receive(&mut codec, &[IAC, SB, NEW_ENVIRON, SEND, VAR, b'U', b'S', b'E', b'R', IAC, SE]).1, [&[IAC, SB, NEW_ENVIRON, IS, VAR][..], b"USER", &[VALUE], b"admin", &[IAC, SE]].concat());
        // 255 Spalten: Das Byte steht in der Unterverhandlung doppelt.
        assert_eq!(codec.resize(255, 50), [IAC, SB, WINDOW_SIZE, 0, IAC, IAC, 0, 50, IAC, SE]);

        // Ohne Benutzer bietet diese Seite die Umgebung gar nicht erst an.
        let mut nameless = Codec::new("vt100", None, (80, 24));
        assert_eq!(receive(&mut nameless, &[IAC, DO, NEW_ENVIRON]).1, [IAC, WONT, NEW_ENVIRON]);
        assert!(nameless.resize(100, 30).is_empty(), "die Fenstergröße ist nicht ausgehandelt");
        // Eine Frage nach etwas, das nicht ausgehandelt ist, bleibt ohne Antwort.
        assert!(receive(&mut nameless, &[IAC, SB, TERMINAL_TYPE, SEND, IAC, SE]).1.is_empty());
    }

    #[test]
    fn what_this_side_proposes_needs_no_second_answer() {
        let mut codec = Codec::new("xterm", Some("admin"), (80, 24));
        assert_eq!(
            codec.greeting(),
            [IAC, WILL, WINDOW_SIZE, IAC, WILL, TERMINAL_TYPE, IAC, WILL, NEW_ENVIRON, IAC, WILL, SUPPRESS_GO_AHEAD, IAC, DO, ECHO, IAC, DO, SUPPRESS_GO_AHEAD]
        );
        // Der Server stimmt zu: Nur die Fenstergröße folgt, keine zweite Zusage.
        let (_, reply) = receive(&mut codec, &[IAC, DO, WINDOW_SIZE, IAC, DO, TERMINAL_TYPE, IAC, WILL, ECHO, IAC, WILL, SUPPRESS_GO_AHEAD]);
        assert_eq!(reply, [IAC, SB, WINDOW_SIZE, 0, 80, 0, 24, IAC, SE]);
        assert!(codec.remote_echo());
        // Der Server lehnt etwas Vorgeschlagenes ab: hingenommen, ohne Antwort.
        assert!(receive(&mut codec, &[IAC, DONT, NEW_ENVIRON]).1.is_empty());
        assert!(receive(&mut codec, &[IAC, SB, NEW_ENVIRON, SEND, IAC, SE]).1.is_empty());
    }

    #[test]
    fn data_is_separated_from_commands_even_across_packets() {
        let mut codec = Codec::new("xterm", None, (80, 24));
        // Doppeltes 255 ist ein Datenbyte; CR NUL ist ein CR; CR LF bleibt.
        assert_eq!(receive(&mut codec, &[b'a', IAC, IAC, b'b', b'\r', 0, b'c', b'\r', b'\n']).0, [b'a', IAC, b'b', b'\r', b'c', b'\r', b'\n']);
        // Ein Befehl, auf drei Pakete verteilt.
        assert!(receive(&mut codec, &[b'x', IAC]).1.is_empty());
        assert!(receive(&mut codec, &[WILL]).1.is_empty());
        assert_eq!(receive(&mut codec, &[ECHO, b'y']), (vec![b'y'], vec![IAC, DO, ECHO]));
        // CR am Ende eines Pakets, NUL am Anfang des nächsten.
        assert_eq!(receive(&mut codec, b"zeile\r").0, b"zeile\r");
        assert_eq!(receive(&mut codec, &[0, b'!']).0, b"!");
        // NOP und „Go Ahead“ verschwinden; eine überlange Unterverhandlung sprengt nichts.
        assert_eq!(receive(&mut codec, &[b'1', IAC, 241, b'2', IAC, 249, b'3']).0, b"123");
        let mut long = vec![IAC, SB, 200];
        long.extend(std::iter::repeat_n(b'x', 5000));
        long.extend([IAC, SE, b'!']);
        assert_eq!(receive(&mut codec, &long).0, b"!");
        // Im 8-Bit-Betrieb gehört ein NUL nach CR zum Text.
        receive(&mut codec, &[IAC, WILL, BINARY]);
        assert_eq!(receive(&mut codec, &[b'\r', 0]).0, [b'\r', 0]);
    }

    #[test]
    fn typing_goes_out_at_once_when_the_server_echoes() {
        let mut codec = Codec::new("xterm", None, (80, 24));
        receive(&mut codec, &[IAC, WILL, ECHO]);
        assert_eq!(codec.typed(b"ls\r"), Typed { wire: b"ls\r\n".to_vec(), echo: Vec::new() });
        assert_eq!(codec.typed(&[0x03, 0x7f, 0x1b, b'[', b'A', IAC]).wire, [0x03, 0x7f, 0x1b, b'[', b'A', IAC, IAC]);
        // Im 8-Bit-Betrieb bleibt die Eingabetaste, wie sie ist.
        receive(&mut codec, &[IAC, DO, BINARY]);
        assert_eq!(codec.typed(b"\r").wire, b"\r");
    }

    #[test]
    fn without_remote_echo_the_line_is_built_here() {
        let mut codec = Codec::new("xterm", None, (80, 24));
        // Zeichen erscheinen sofort, gehen aber erst mit der Eingabetaste ab.
        assert_eq!(codec.typed(b"HELO x"), Typed { wire: Vec::new(), echo: b"HELO x".to_vec() });
        assert_eq!(codec.typed(&[0x7f]), Typed { wire: Vec::new(), echo: b"\x08 \x08".to_vec() });
        assert_eq!(codec.typed("ä\r".as_bytes()), Typed { wire: "HELO ä\r\n".as_bytes().to_vec(), echo: "ä\r\n".as_bytes().to_vec() });
        // Die Rücktaste nimmt ein ganzes Zeichen, auch eines aus zwei Bytes; auf leerer Zeile tut sie nichts.
        codec.typed("aö".as_bytes());
        assert_eq!(codec.typed(&[0x7f, 0x7f, 0x7f]).echo, b"\x08 \x08\x08 \x08");
        assert_eq!(codec.typed(b"\r").wire, b"\r\n");
        // Strg+U verwirft, Strg+C meldet dem Server den Abbruch.
        codec.typed(b"weg");
        assert_eq!(codec.typed(&[0x15]).echo, b"\x08 \x08\x08 \x08\x08 \x08");
        codec.typed(b"auch weg");
        assert_eq!(codec.typed(&[0x03]), Typed { wire: vec![IAC, IP], echo: b"^C\r\n".to_vec() });
        assert_eq!(codec.typed(b"\r").wire, b"\r\n", "die verworfene Zeile geht nicht mit ab");
        // Ein Tab und eine Pfeiltaste nehmen mit, was schon dasteht.
        codec.typed(b"sh");
        assert_eq!(codec.typed(b"\t").wire, b"sh\t");
        codec.typed(b"x");
        assert_eq!(codec.typed(b"\x1b[A").wire, b"x\x1b[A");
        // Kündigt der Server mitten in der Zeile sein Echo an, geht das Getippte sofort ab.
        codec.typed(b"admin");
        assert_eq!(receive(&mut codec, &[IAC, WILL, ECHO]).1, [&[IAC, DO, ECHO][..], b"admin"].concat());
        assert_eq!(codec.typed(b"\r").wire, b"\r\n");
    }
}

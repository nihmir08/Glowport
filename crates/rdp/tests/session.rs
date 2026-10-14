//! The session against a simulated RDP server (`ironrdp-server`): certificate, sign-in, picture, input,
//! resizing, disconnecting. The server is built after the protocol, not a Windows; what only a real Windows
//! shows is not covered by this test.

use std::{
    net::SocketAddr,
    num::{NonZeroU16, NonZeroUsize},
    sync::{Arc, Mutex},
    time::Duration,
};

use glowport_rdp::{open, Button, Command, Connect, End, Event, Fingerprint, Session};
use ironrdp_server::{
    tokio_rustls::{rustls, TlsAcceptor},
    BitmapUpdate, CredentialDecision, CredentialValidationError, CredentialValidator, Credentials, DesktopSize, DisplayUpdate, KeyboardEvent, MouseEvent, PixelFormat, RdpServer, RdpServerDisplay,
    RdpServerDisplayUpdates, RdpServerInputHandler,
};
use tokio::sync::mpsc;

const USER: &str = "tester";
/// Only applies to the simulated server in this test.
const PASSWORD: &str = "richtig";
/// Color of the whole picture and that of the rectangle the server paints after the key “A” (red, green, blue).
const BACKGROUND: [u8; 3] = [0xc0, 0x80, 0x40];
const PAINTED: [u8; 3] = [0x10, 0xf0, 0x20];
const PATCH: (u16, u16, u16, u16) = (64, 64, 128, 64);

#[derive(Default)]
struct World {
    /// Every sign-in the server saw: user, domain, and whether the password was right.
    logins: Vec<(String, Option<String>, bool)>,
    inputs: Vec<String>,
    size: (u16, u16),
    updates: Option<mpsc::UnboundedSender<DisplayUpdate>>,
}

type Shared = Arc<Mutex<World>>;

fn bitmap(x: u16, y: u16, width: u16, height: u16, [r, g, b]: [u8; 3]) -> DisplayUpdate {
    let data: Vec<u8> = std::iter::repeat_n([b, g, r, 0xff], usize::from(width) * usize::from(height)).flatten().collect();
    DisplayUpdate::Bitmap(BitmapUpdate {
        x,
        y,
        width: NonZeroU16::new(width).unwrap(),
        height: NonZeroU16::new(height).unwrap(),
        format: PixelFormat::BgrX32,
        data: data.into(),
        stride: NonZeroUsize::new(usize::from(width) * 4).unwrap(),
    })
}

struct Checker(Shared);

#[async_trait::async_trait]
impl CredentialValidator for Checker {
    async fn validate(&self, credentials: &Credentials) -> Result<CredentialDecision, CredentialValidationError> {
        let right = credentials.username == USER && credentials.password == PASSWORD;
        self.0.lock().unwrap().logins.push((credentials.username.clone(), credentials.domain.clone(), right));
        Ok(if right { CredentialDecision::Accept } else { CredentialDecision::Reject })
    }
}

struct Input(Shared);

impl RdpServerInputHandler for Input {
    fn keyboard(&mut self, event: KeyboardEvent) {
        let mut world = self.0.lock().unwrap();
        // On the key “A” the server paints a rectangle, the way a program draws something in response to input.
        if matches!(event, KeyboardEvent::Pressed { code: 0x1e, extended: false }) {
            if let Some(updates) = &world.updates {
                let _ = updates.send(bitmap(PATCH.0, PATCH.1, PATCH.2, PATCH.3, PAINTED));
            }
        }
        world.inputs.push(format!("{event:?}"));
    }

    fn mouse(&mut self, event: MouseEvent) {
        self.0.lock().unwrap().inputs.push(format!("{event:?}"));
    }
}

struct Display(Shared);
struct Updates(mpsc::UnboundedReceiver<DisplayUpdate>);

#[async_trait::async_trait]
impl RdpServerDisplayUpdates for Updates {
    async fn next_update(&mut self) -> anyhow::Result<Option<DisplayUpdate>> {
        Ok(self.0.recv().await)
    }
}

#[async_trait::async_trait]
impl RdpServerDisplay for Display {
    async fn size(&mut self) -> DesktopSize {
        let (width, height) = self.0.lock().unwrap().size;
        DesktopSize { width, height }
    }

    async fn updates(&mut self) -> anyhow::Result<Box<dyn RdpServerDisplayUpdates>> {
        let (sender, receiver) = mpsc::unbounded_channel();
        let mut world = self.0.lock().unwrap();
        let (width, height) = world.size;
        let _ = sender.send(bitmap(0, 0, width, height, BACKGROUND));
        world.updates = Some(sender);
        Ok(Box::new(Updates(receiver)))
    }

    fn request_layout(&mut self, layout: ironrdp_displaycontrol::pdu::DisplayControlMonitorLayout) {
        let Some((width, height)) = layout.monitors().first().map(|monitor| monitor.dimensions()) else { return };
        let mut world = self.0.lock().unwrap();
        world.size = (width as u16, height as u16);
        world.inputs.push(format!("Layout {width}x{height}"));
        if let Some(updates) = &world.updates {
            let _ = updates.send(DisplayUpdate::Resize(DesktopSize { width: width as u16, height: height as u16 }));
            let _ = updates.send(bitmap(0, 0, width as u16, height as u16, BACKGROUND));
        }
    }
}

struct Running {
    address: SocketAddr,
    fingerprint: Fingerprint,
    world: Shared,
}

/// Starts the server on a thread of its own; `nla` requires sign-in via CredSSP like a Windows.
fn serve(nla: bool) -> Running {
    let certified = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
    let der = certified.cert.der().clone();
    let fingerprint: Fingerprint = <sha2::Sha256 as sha2::Digest>::digest(&der).into();
    let key = rustls::pki_types::PrivateKeyDer::try_from(certified.signing_key.serialize_der()).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider())).with_safe_default_protocol_versions().unwrap().with_no_client_auth().with_single_cert(vec![der], key).unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let public_key = certified.signing_key.public_key_raw().to_vec();

    // A free port: occupy briefly, remember the number, release again.
    let address = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let world: Shared = Arc::new(Mutex::new(World { size: (640, 480), ..World::default() }));
    let shared = world.clone();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        tokio::task::LocalSet::new().block_on(&runtime, async move {
            let builder = RdpServer::builder().with_addr(address);
            let builder = if nla { builder.with_hybrid(acceptor, public_key) } else { builder.with_tls(acceptor) };
            let mut server = builder.with_input_handler(Input(shared.clone())).with_display_handler(Display(shared.clone())).with_credential_validator(Some(Arc::new(Checker(shared)))).build();
            server.set_credentials(Some(Credentials { username: USER.into(), password: PASSWORD.into(), domain: None }));
            let _ = server.run().await;
        });
    });
    // Until the server listens.
    for _ in 0..100 {
        if std::net::TcpStream::connect(address).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Running { address, fingerprint, world }
}

fn connect(running: &Running, user: &str, password: &str, pin: Option<Fingerprint>) -> Connect {
    Connect { host: "127.0.0.1".into(), port: running.address.port(), user: user.into(), password: password.into(), width: 640, height: 480, scale: 100, keyboard_layout: 0x407, pin }
}

async fn next(session: &mut Session) -> Event {
    tokio::time::timeout(Duration::from_secs(20), session.events.recv()).await.expect("the session does not report").expect("the session ended without an end")
}

/// Reads until an event matches; phases, pointers and other regions pass by.
async fn until<T>(session: &mut Session, mut pick: impl FnMut(Event) -> Option<T>) -> T {
    loop {
        let event = next(session).await;
        if let Event::End(end) = &event {
            let end = end.clone();
            return pick(event).unwrap_or_else(|| panic!("the session ended: {end:?}"));
        }
        if let Some(found) = pick(event) {
            return found;
        }
    }
}

async fn end(session: &mut Session) -> End {
    until(session, |event| if let Event::End(end) = event { Some(end) } else { None }).await
}

/// The pixel at one spot of a region, with some tolerance: the server may compress lossily.
fn near(pixels: &[u8], width: u16, x: u16, y: u16, [r, g, b]: [u8; 3]) -> bool {
    let at = (usize::from(y) * usize::from(width) + usize::from(x)) * 4;
    let close = |a: u8, b: u8| a.abs_diff(b) <= 12;
    close(pixels[at], r) && close(pixels[at + 1], g) && close(pixels[at + 2], b)
}

/// Keeps a picture from the reported regions, the way the window does.
struct Canvas {
    width: u16,
    height: u16,
    pixels: Vec<u8>,
}

impl Canvas {
    fn new(width: u16, height: u16) -> Canvas {
        Canvas { width, height, pixels: vec![0; usize::from(width) * usize::from(height) * 4] }
    }

    fn apply(&mut self, x: u16, y: u16, width: u16, height: u16, pixels: &[u8]) {
        assert_eq!(pixels.len(), usize::from(width) * usize::from(height) * 4, "a region brings exactly its pixels");
        assert!(x + width <= self.width && y + height <= self.height, "a region lies within the picture");
        for row in 0..usize::from(height) {
            let to = ((usize::from(y) + row) * usize::from(self.width) + usize::from(x)) * 4;
            self.pixels[to..to + usize::from(width) * 4].copy_from_slice(&pixels[row * usize::from(width) * 4..][..usize::from(width) * 4]);
        }
    }

    fn shows(&self, x: u16, y: u16, colour: [u8; 3]) -> bool {
        near(&self.pixels, self.width, x, y, colour)
    }

    /// Takes regions until the picture shows the color at that spot.
    async fn wait(&mut self, session: &mut Session, x: u16, y: u16, colour: [u8; 3]) {
        while !self.shows(x, y, colour) {
            match next(session).await {
                Event::Region { x, y, width, height, pixels } => self.apply(x, y, width, height, &pixels),
                Event::End(end) => panic!("the session ended: {end:?}"),
                _ => {}
            }
        }
    }
}

async fn ready(session: &mut Session) -> Canvas {
    let (width, height) = until(session, |event| if let Event::Ready { width, height } = event { Some((width, height)) } else { None }).await;
    Canvas::new(width, height)
}

#[tokio::test]
async fn an_unknown_certificate_is_asked_about_before_any_password_leaves() {
    for nla in [false, true] {
        let running = serve(nla);
        // Refused: the session ends, and the server saw no sign-in.
        let mut session = open(connect(&running, USER, PASSWORD, None));
        let (fingerprint, reply) = until(&mut session, |event| if let Event::Certificate { fingerprint, reply } = event { Some((fingerprint, reply)) } else { None }).await;
        assert_eq!(fingerprint, running.fingerprint, "the fingerprint shown is that of the certificate the server has");
        reply.send(false).unwrap();
        assert_eq!(end(&mut session).await, End::User);
        // Over NLA the simulated server does not show sign-ins; the flow up to here is the same.
        assert!(running.world.lock().unwrap().logins.is_empty(), "nla={nla}: without confirmation no sign-in goes to the server");

        // Confirmed: it continues up to the picture.
        let mut session = open(connect(&running, USER, PASSWORD, None));
        let reply = until(&mut session, |event| if let Event::Certificate { reply, .. } = event { Some(reply) } else { None }).await;
        reply.send(true).unwrap();
        let mut canvas = ready(&mut session).await;
        assert_eq!((canvas.width, canvas.height), (640, 480));
        canvas.wait(&mut session, 320, 240, BACKGROUND).await;
        session.commands.send(Command::Close).unwrap();
        assert_eq!(end(&mut session).await, End::User);
    }
}

#[tokio::test]
async fn a_confirmed_certificate_is_not_asked_about_and_a_different_one_stops_the_session() {
    // Without NLA, because only then does the simulated server show which sign-ins reached it.
    let running = serve(false);
    let mut session = open(connect(&running, USER, PASSWORD, Some(running.fingerprint)));
    let mut asked = false;
    until(&mut session, |event| match event {
        Event::Certificate { .. } => {
            asked = true;
            None
        }
        Event::Ready { .. } => Some(()),
        _ => None,
    })
    .await;
    assert!(!asked, "with a stored fingerprint there is no prompt");
    session.commands.send(Command::Close).unwrap();
    assert_eq!(end(&mut session).await, End::User);
    let before = running.world.lock().unwrap().logins.len();
    assert_eq!(before, 1, "the server saw the sign-in from just now");

    let mut other = running.fingerprint;
    other[0] ^= 0xff;
    let mut session = open(connect(&running, USER, PASSWORD, Some(other)));
    assert_eq!(end(&mut session).await, End::CertificateChanged(running.fingerprint));
    assert_eq!(running.world.lock().unwrap().logins.len(), before, "no sign-in goes to a server with a different certificate");
}

#[tokio::test]
async fn a_wrong_password_is_refused() {
    let running = serve(true);
    let mut session = open(connect(&running, USER, "falsch", Some(running.fingerprint)));
    assert_eq!(end(&mut session).await, End::AuthFailed, "over NLA the server already rejects the sign-in");

    // Without NLA the server only checks the password after setup and then disconnects.
    let running = serve(false);
    let mut session = open(connect(&running, USER, "falsch", Some(running.fingerprint)));
    let end = end(&mut session).await;
    assert!(matches!(end, End::AuthFailed | End::ConnectFailed(_) | End::Server(_) | End::ConnectionLost(_)), "{end:?}");
    let logins = running.world.lock().unwrap().logins.clone();
    assert!(logins.iter().all(|login| !login.2), "{logins:?}");
}

#[tokio::test]
async fn the_picture_arrives_and_follows_what_the_server_paints() {
    let running = serve(true);
    let mut session = open(connect(&running, "FIRMA\\tester", PASSWORD, Some(running.fingerprint)));
    let mut canvas = ready(&mut session).await;
    canvas.wait(&mut session, 0, 0, BACKGROUND).await;
    canvas.wait(&mut session, 639, 479, BACKGROUND).await;
    assert!(canvas.shows(PATCH.0 + 5, PATCH.1 + 5, BACKGROUND));

    // Input arrives, and what the server paints in response comes back as a region.
    session.commands.send(Command::Move { x: 100, y: 200 }).unwrap();
    session.commands.send(Command::Button { button: Button::Left, down: true, x: 100, y: 200 }).unwrap();
    session.commands.send(Command::Button { button: Button::Left, down: false, x: 100, y: 200 }).unwrap();
    session.commands.send(Command::Wheel { delta: -120, horizontal: false, x: 100, y: 200 }).unwrap();
    session.commands.send(Command::Unicode { unit: 'ä' as u16, down: true }).unwrap();
    session.commands.send(Command::Key { code: 0x1d, extended: true, down: true }).unwrap();
    session.commands.send(Command::Key { code: 0x1e, extended: false, down: true }).unwrap();
    session.commands.send(Command::Key { code: 0x1e, extended: false, down: false }).unwrap();
    canvas.wait(&mut session, PATCH.0 + 5, PATCH.1 + 5, PAINTED).await;
    assert!(canvas.shows(PATCH.0 + PATCH.2 - 5, PATCH.1 + PATCH.3 - 5, PAINTED));
    assert!(canvas.shows(PATCH.0 - 8, PATCH.1 - 8, BACKGROUND) && canvas.shows(PATCH.0 + PATCH.2 + 8, PATCH.1 + PATCH.3 + 8, BACKGROUND), "outside the rectangle the picture stays");
    {
        let world = running.world.lock().unwrap();
        let seen = world.inputs.join(" | ");
        for expected in ["Move { x: 100, y: 200 }", "LeftPressed", "LeftReleased", "VerticalScroll { value: -120 }", "UnicodePressed(228)", "Pressed { code: 29, extended: true }", "Pressed { code: 30, extended: false }", "Released { code: 30, extended: false }"] {
            assert!(seen.contains(expected), "{expected} missing in: {seen}");
        }
    }

    session.commands.send(Command::Close).unwrap();
    assert_eq!(end(&mut session).await, End::User);
}

#[tokio::test]
async fn a_new_size_gives_a_new_picture_without_a_new_login() {
    let running = serve(true);
    let mut session = open(connect(&running, USER, PASSWORD, Some(running.fingerprint)));
    let mut canvas = ready(&mut session).await;
    canvas.wait(&mut session, 320, 240, BACKGROUND).await;
    let logins = running.world.lock().unwrap().logins.len();

    session.commands.send(Command::Resize { width: 1024, height: 768, scale: 100 }).unwrap();
    let (width, height) = until(&mut session, |event| if let Event::Resized { width, height } = event { Some((width, height)) } else { None }).await;
    assert_eq!((width, height), (1024, 768));
    let mut canvas = Canvas::new(width, height);
    canvas.wait(&mut session, 1000, 700, BACKGROUND).await;
    assert_eq!(running.world.lock().unwrap().logins.len(), logins, "the size changes without a new sign-in");

    session.commands.send(Command::Close).unwrap();
    assert_eq!(end(&mut session).await, End::User);
}

#[tokio::test]
async fn a_server_that_is_not_there_fails_to_connect() {
    let address = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let mut session = open(Connect { host: "127.0.0.1".into(), port: address.port(), user: USER.into(), password: PASSWORD.into(), width: 800, height: 600, scale: 100, keyboard_layout: 0, pin: None });
    assert!(matches!(end(&mut session).await, End::ConnectFailed(_)));
}

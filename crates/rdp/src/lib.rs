//! RDP sessions: sign in to a Windows machine (or xrdp), receive its picture, send input.
//!
//! As with the terminals, the caller gets a [`Session`]: a stream of [`Event`]s and a channel for
//! [`Command`]s. Instead of bytes for a terminal, picture regions arrive here: the core keeps the whole picture and reports
//! only what changed ([`Event::Region`]).
//!
//! **Certificate:** every session runs over TLS. If the system does not trust the certificate and no fingerprint
//! is stored ([`Connect::pin`]), the session asks ([`Event::Certificate`]); if one is stored and the
//! certificate differs, it ends with [`End::CertificateChanged`]. Only then does the password go to the server.
//!
//! Every session runs on a thread of its own: unpacking the pictures is computing work that should not get
//! in the way of other connections.

mod tls;

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use ironrdp_connector::{
    connection_activation::ConnectionActivationState, ClientConnector, ConnectionResult, ConnectorError, ConnectorErrorKind, ConnectorResult, Credentials, DesktopSize, ServerName,
};
use ironrdp_core::WriteBuf;
use ironrdp_displaycontrol::{client::DisplayControlClient, pdu::MonitorLayoutEntry};
use ironrdp_graphics::image_processing::PixelFormat;
use ironrdp_pdu::{
    geometry::InclusiveRectangle,
    input::{
        fast_path::{FastPathInputEvent, KeyboardFlags, SynchronizeFlags},
        mouse::PointerFlags,
        MousePdu,
    },
    rdp::{
        capability_sets::{client_codecs_capabilities, MajorPlatformType},
        client_info::{CompressionType, PerformanceFlags, TimezoneInfo},
    },
};
use ironrdp_session::{fast_path, image::DecodedImage, ActiveStage, ActiveStageBuilder, ActiveStageOutput, GracefulDisconnectReason};
use ironrdp_tokio::{connect_begin, connect_finalize, mark_as_upgraded, single_sequence_step_read, FramedWrite, LocalTokioFramed, NetworkClient};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadHalf},
    net::TcpStream,
    sync::{mpsc, oneshot},
    time::timeout,
};

pub use tls::Fingerprint;

pub const DEFAULT_PORT: u16 = 3389;

/// For setting up the line and for every step of the sign-in.
const STEP_TIMEOUT: Duration = Duration::from_secs(20);
/// This many events may wait for the receiver. If the channel is full, the session stops reading from the
/// server; the server then slows down by itself.
const EVENT_QUEUE: usize = 64;

/// Where to and as whom.
#[derive(Clone)]
pub struct Connect {
    pub host: String,
    pub port: u16,
    /// `user`, `DOMAIN\user` or `user@domain`.
    pub user: String,
    pub password: String,
    /// Desired picture size; the server may name a different one ([`Event::Ready`]).
    pub width: u16,
    pub height: u16,
    /// Display scaling in percent (100 to 500), so text fits on the remote machine.
    pub scale: u32,
    /// This machine's keyboard layout as Windows numbers it (e.g. `0x407` for German); 0 leaves it to
    /// the server.
    pub keyboard_layout: u32,
    /// The fingerprint the user confirmed for this server.
    pub pin: Option<Fingerprint>,
}

impl std::fmt::Debug for Connect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Without the password.
        write!(f, "Connect({}@{}:{})", self.user, self.host, self.port)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Connecting,
    Securing,
    Authenticating,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pointer {
    /// The ordinary arrow.
    Default,
    Hidden,
    /// A pointer of the remote machine's own; `pixels` are `width * height` pixels in RGBA.
    Bitmap { width: u16, height: u16, hot_x: u16, hot_y: u16, pixels: Vec<u8> },
    /// The server moved the pointer.
    Position { x: u16, y: u16 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum End {
    /// Disconnected by the user or a prompt was cancelled.
    User,
    /// The server ended the session (signed out, pushed out by another sign-in …).
    Server(String),
    ConnectFailed(String),
    /// The certificate is not the one the user confirmed.
    CertificateChanged(Fingerprint),
    AuthFailed,
    ConnectionLost(String),
}

#[derive(Debug)]
pub enum Event {
    Phase(Phase),
    /// The system does not trust the certificate, and none is stored. `true` continues connecting; the caller
    /// then remembers the fingerprint for [`Connect::pin`].
    Certificate { fingerprint: Fingerprint, reply: oneshot::Sender<bool> },
    /// Signed in. The picture has this size and is black at first.
    Ready { width: u16, height: u16 },
    /// This region of the picture changed; `pixels` are `width * height` pixels in RGBA, row by row.
    Region { x: u16, y: u16, width: u16, height: u16, pixels: Vec<u8> },
    /// The picture has a new size and is black again.
    Resized { width: u16, height: u16 },
    Pointer(Pointer),
    End(End),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Button {
    Left,
    Right,
    Middle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// A key by its position on the keyboard (scancode, set 1); which character results is decided by
    /// the remote machine's layout.
    Key { code: u8, extended: bool, down: bool },
    /// A character without a key (UTF-16), e.g. from an input method.
    Unicode { unit: u16, down: bool },
    Move { x: u16, y: u16 },
    Button { button: Button, down: bool, x: u16, y: u16 },
    /// Mouse wheel; one notch is 120, up and right positive.
    Wheel { delta: i16, horizontal: bool, x: u16, y: u16 },
    /// State of the lock keys when the session gets the focus.
    Locks { caps: bool, num: bool, scroll: bool },
    /// Request for a new picture size. If the server cannot do it, the old one stays.
    Resize { width: u16, height: u16, scale: u32 },
    Close,
}

pub struct Session {
    pub commands: mpsc::UnboundedSender<Command>,
    pub events: mpsc::Receiver<Event>,
}

/// Splits `DOMAIN\user` into its parts. `user@domain` stays whole: that is how Windows signs in with it.
pub fn split_user(user: &str) -> (String, Option<String>) {
    match user.split_once('\\') {
        Some((domain, name)) if !domain.is_empty() && !name.is_empty() => (name.to_string(), Some(domain.to_string())),
        _ => (user.to_string(), None),
    }
}

/// The size a server accepts: 200 to 8192 pixels, the width even.
pub fn fit_size(width: u16, height: u16) -> (u16, u16) {
    let (width, height) = MonitorLayoutEntry::adjust_display_size(u32::from(width), u32::from(height));
    (width as u16, height as u16)
}

trait Wire: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> Wire for T {}
type Boxed = Box<dyn Wire>;

/// Connects directly to the server.
pub fn open(connect: Connect) -> Session {
    start(connect, |connect, events| async move {
        let _ = events.send(Event::Phase(Phase::Connecting)).await;
        let stream = match timeout(STEP_TIMEOUT, TcpStream::connect((connect.host.as_str(), connect.port))).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => return Err(End::ConnectFailed(error.to_string())),
            Err(_) => return Err(End::ConnectFailed("timed out".into())),
        };
        let _ = stream.set_nodelay(true);
        let local = stream.local_addr().unwrap_or(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)));
        Ok((Box::new(stream) as Boxed, local))
    })
}

/// Runs the session over a line that already stands, e.g. a tunnel through a jump host.
pub fn open_on<S>(connect: Connect, stream: S) -> Session
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    start(connect, |_, _| async move { Ok((Box::new(stream) as Boxed, SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))) })
}

fn start<W, F>(connect: Connect, wire: W) -> Session
where
    W: FnOnce(Connect, mpsc::Sender<Event>) -> F + Send + 'static,
    F: std::future::Future<Output = Result<(Boxed, SocketAddr), End>>,
{
    let (event_tx, events) = mpsc::channel(EVENT_QUEUE);
    let (commands, mut command_rx) = mpsc::unbounded_channel();
    let failed = event_tx.clone();
    let work = move || {
        let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(runtime) => runtime,
            Err(error) => {
                let _ = event_tx.blocking_send(Event::End(End::ConnectFailed(error.to_string())));
                return;
            }
        };
        runtime.block_on(async move {
            let end = match run(connect, wire, &event_tx, &mut command_rx).await {
                Ok(end) | Err(end) => end,
            };
            let _ = event_tx.send(Event::End(end)).await;
        });
    };
    if let Err(error) = std::thread::Builder::new().name("rdp".into()).spawn(work) {
        let _ = failed.try_send(Event::End(End::ConnectFailed(error.to_string())));
    }
    Session { commands, events }
}

/// The sign-in via NLA could ask a logon server on the network for Kerberos. Glowport signs in with NTLM
/// and asks nobody.
struct NoNetwork;

impl NetworkClient for NoNetwork {
    async fn send(&mut self, _: &ironrdp_connector::sspi::generator::NetworkRequest) -> ConnectorResult<Vec<u8>> {
        Err(ConnectorError::new("Kerberos", ConnectorErrorKind::General))
    }
}

fn settings(connect: &Connect) -> ironrdp_connector::Config {
    let (username, domain) = split_user(&connect.user);
    let (width, height) = fit_size(connect.width, connect.height);
    ironrdp_connector::Config {
        credentials: Credentials::UsernamePassword { username, password: connect.password.clone() },
        domain,
        enable_tls: true,
        enable_credssp: true,
        keyboard_type: ironrdp_pdu::gcc::KeyboardType::IbmEnhanced,
        keyboard_subtype: 0,
        keyboard_layout: connect.keyboard_layout,
        keyboard_functional_keys_count: 12,
        ime_file_name: String::new(),
        dig_product_id: String::new(),
        desktop_size: DesktopSize { width, height },
        desktop_scale_factor: if (100..=500).contains(&connect.scale) { connect.scale } else { 0 },
        bitmap: Some(ironrdp_connector::BitmapConfig { color_depth: 32, lossy_compression: true, codecs: client_codecs_capabilities(&[]).unwrap_or_default() }),
        client_build: 0,
        client_name: "Glowport".into(),
        client_dir: "C:\\Windows\\System32\\mstscax.dll".into(),
        platform: MajorPlatformType::WINDOWS,
        hardware_id: None,
        license_cache: None,
        enable_server_pointer: true,
        // With sign-in over TLS alone (xrdp, Windows without NLA) the server signs in right away with these details.
        autologon: true,
        enable_audio_playback: false,
        request_data: None,
        // The window draws the pointer itself; the core does not draw it into the picture.
        pointer_software_rendering: false,
        multitransport_flags: None,
        compression_type: Some(CompressionType::K64),
        performance_flags: PerformanceFlags::default(),
        timezone_info: TimezoneInfo::default(),
        alternate_shell: String::new(),
        work_dir: String::new(),
    }
}

/// Reads from a sign-in error what caused it.
fn refused(error: ConnectorError) -> End {
    match error.kind() {
        ConnectorErrorKind::Credssp(_) | ConnectorErrorKind::AccessDenied => End::AuthFailed,
        _ => {
            let text = error.to_string();
            let source = std::error::Error::source(&error).map(|source| format!(": {source}")).unwrap_or_default();
            End::ConnectFailed(format!("{text}{source}"))
        }
    }
}

async fn step<T>(work: impl std::future::Future<Output = ConnectorResult<T>>) -> Result<T, End> {
    match timeout(STEP_TIMEOUT, work).await {
        Ok(result) => result.map_err(refused),
        Err(_) => Err(End::ConnectFailed("timed out".into())),
    }
}

async fn run<W, F>(connect: Connect, wire: W, events: &mpsc::Sender<Event>, commands: &mut mpsc::UnboundedReceiver<Command>) -> Result<End, End>
where
    W: FnOnce(Connect, mpsc::Sender<Event>) -> F,
    F: std::future::Future<Output = Result<(Boxed, SocketAddr), End>>,
{
    let (stream, local) = tokio::select! {
        result = wire(connect.clone(), events.clone()) => result?,
        () = closed(commands) => return Ok(End::User),
    };
    let (result, framed) = tokio::select! {
        result = establish(&connect, stream, local, events) => result?,
        () = closed(commands) => return Ok(End::User),
    };
    Ok(session(result, framed, events, commands).await)
}

/// Waits until the user closes; everything else that comes before the sign-in is dropped.
async fn closed(commands: &mut mpsc::UnboundedReceiver<Command>) {
    while !matches!(commands.recv().await, Some(Command::Close) | None) {}
}

async fn establish(connect: &Connect, stream: Boxed, local: SocketAddr, events: &mpsc::Sender<Event>) -> Result<(ConnectionResult, LocalTokioFramed<Boxed>), End> {
    let _ = events.send(Event::Phase(Phase::Securing)).await;
    let drdynvc = ironrdp_dvc::DrdynvcClient::new().with_dynamic_channel(DisplayControlClient::new(|_| Ok(Vec::new())));
    let mut connector = ClientConnector::new(settings(connect), local).with_static_channel(drdynvc);
    let mut framed = LocalTokioFramed::new(stream);
    let should_upgrade = step(connect_begin(&mut framed, &mut connector)).await?;
    let (stream, leftover) = framed.into_inner();

    let seen: tls::Seen = Arc::new(Mutex::new(None));
    let config = tls::config(seen.clone()).map_err(|error| End::ConnectFailed(error.to_string()))?;
    let name = rustls::pki_types::ServerName::try_from(connect.host.clone()).map_err(|_| End::ConnectFailed("the address is not a valid name".into()))?;
    let mut stream = match timeout(STEP_TIMEOUT, tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, stream)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => return Err(End::ConnectFailed(format!("tls: {error}"))),
        Err(_) => return Err(End::ConnectFailed("timed out".into())),
    };
    stream.flush().await.map_err(|error| End::ConnectionLost(error.to_string()))?;

    // First the certificate, then the password.
    let (fingerprint, recognised) = seen.lock().unwrap_or_else(|p| p.into_inner()).ok_or_else(|| End::ConnectFailed("the server showed no certificate".into()))?;
    match connect.pin {
        Some(pin) if pin != fingerprint => return Err(End::CertificateChanged(fingerprint)),
        Some(_) => {}
        None if recognised => {}
        None => {
            let (reply, answer) = oneshot::channel();
            if events.send(Event::Certificate { fingerprint, reply }).await.is_err() || !answer.await.unwrap_or(false) {
                return Err(End::User);
            }
        }
    }
    let public_key = stream.get_ref().1.peer_certificates().and_then(|chain| chain.first()).and_then(|certificate| tls::public_key(certificate)).ok_or_else(|| End::ConnectFailed("the certificate has no usable key".into()))?;

    let _ = events.send(Event::Phase(Phase::Authenticating)).await;
    let upgraded = mark_as_upgraded(should_upgrade, &mut connector);
    let mut framed = LocalTokioFramed::new_with_leftover(Box::new(stream) as Boxed, leftover);
    let result = step(connect_finalize(upgraded, connector, &mut framed, &mut NoNetwork, ServerName::new(connect.host.clone()), public_key, None)).await?;
    Ok((result, framed))
}

/// The pixels of a region, row by row; `None` if it lies completely outside the picture.
fn region(image: &DecodedImage, rect: &InclusiveRectangle) -> Option<Event> {
    cut(image.data(), image.stride(), image.width(), image.height(), rect)
}

/// Cuts a region out of an RGBA picture whose rows are `stride` bytes long.
fn cut(data: &[u8], stride: usize, width: u16, height: u16, rect: &InclusiveRectangle) -> Option<Event> {
    if width == 0 || height == 0 || rect.left >= width || rect.top >= height || rect.right < rect.left || rect.bottom < rect.top {
        return None;
    }
    let (right, bottom) = (rect.right.min(width - 1), rect.bottom.min(height - 1));
    let (columns, rows) = (usize::from(right - rect.left) + 1, usize::from(bottom - rect.top) + 1);
    let mut pixels = Vec::with_capacity(columns * rows * 4);
    for row in 0..rows {
        let from = (usize::from(rect.top) + row) * stride + usize::from(rect.left) * 4;
        pixels.extend_from_slice(data.get(from..from + columns * 4)?);
    }
    Some(Event::Region { x: rect.left, y: rect.top, width: columns as u16, height: rows as u16, pixels })
}

fn mouse(flags: PointerFlags, units: i16, x: u16, y: u16) -> FastPathInputEvent {
    FastPathInputEvent::MouseEvent(MousePdu { flags, number_of_wheel_rotation_units: units, x_position: x, y_position: y })
}

/// What goes over the line from a command. `Resize` and `Close` are not input.
fn input(command: &Command) -> Option<FastPathInputEvent> {
    Some(match *command {
        Command::Key { code, extended, down } => {
            let mut flags = if down { KeyboardFlags::empty() } else { KeyboardFlags::RELEASE };
            if extended {
                flags |= KeyboardFlags::EXTENDED;
            }
            FastPathInputEvent::KeyboardEvent(flags, code)
        }
        Command::Unicode { unit, down } => FastPathInputEvent::UnicodeKeyboardEvent(if down { KeyboardFlags::empty() } else { KeyboardFlags::RELEASE }, unit),
        Command::Move { x, y } => mouse(PointerFlags::MOVE, 0, x, y),
        Command::Button { button, down, x, y } => {
            let which = match button {
                Button::Left => PointerFlags::LEFT_BUTTON,
                Button::Right => PointerFlags::RIGHT_BUTTON,
                Button::Middle => PointerFlags::MIDDLE_BUTTON_OR_WHEEL,
            };
            mouse(if down { which | PointerFlags::DOWN } else { which }, 0, x, y)
        }
        Command::Wheel { delta, horizontal, x, y } => mouse(if horizontal { PointerFlags::HORIZONTAL_WHEEL } else { PointerFlags::VERTICAL_WHEEL }, delta, x, y),
        Command::Locks { caps, num, scroll } => {
            let mut flags = SynchronizeFlags::empty();
            flags.set(SynchronizeFlags::CAPS_LOCK, caps);
            flags.set(SynchronizeFlags::NUM_LOCK, num);
            flags.set(SynchronizeFlags::SCROLL_LOCK, scroll);
            FastPathInputEvent::SyncEvent(flags)
        }
        Command::Resize { .. } | Command::Close => return None,
    })
}

async fn session(result: ConnectionResult, framed: LocalTokioFramed<Boxed>, events: &mpsc::Sender<Event>, commands: &mut mpsc::UnboundedReceiver<Command>) -> End {
    let (stream, leftover) = framed.into_inner();
    let (read_half, write_half) = tokio::io::split(stream);
    let mut reader: LocalTokioFramed<ReadHalf<Boxed>> = LocalTokioFramed::new_with_leftover(read_half, leftover);
    let mut writer = LocalTokioFramed::new(write_half);

    let lost = |error: &dyn std::fmt::Display| End::ConnectionLost(error.to_string());
    let mut image = DecodedImage::new(PixelFormat::RgbA32, result.desktop_size.width, result.desktop_size.height);
    let activation_factory = result.activation_factory;
    let mut stage: ActiveStage = ActiveStageBuilder {
        static_channels: result.static_channels,
        user_channel_id: result.user_channel_id,
        io_channel_id: result.io_channel_id,
        message_channel_id: result.message_channel_id,
        share_id: result.share_id,
        compression_type: result.compression_type,
        enable_server_pointer: result.enable_server_pointer,
        pointer_software_rendering: result.pointer_software_rendering,
    }
    .build();
    if events.send(Event::Ready { width: image.width(), height: image.height() }).await.is_err() {
        return End::User;
    }

    // After the user asks to disconnect, the server still answers; if that does not happen, it is over after a short time.
    let mut closing: Option<tokio::time::Instant> = None;
    loop {
        let outputs = tokio::select! {
            frame = reader.read_pdu() => match frame {
                Ok((action, payload)) => match stage.process(&mut image, action, &payload) {
                    Ok(outputs) => outputs,
                    Err(error) => return lost(&error),
                },
                Err(_) if closing.is_some() => return End::User,
                Err(error) => return lost(&error),
            },
            () = async { tokio::time::sleep_until(closing.unwrap_or_else(tokio::time::Instant::now)).await }, if closing.is_some() => return End::User,
            command = commands.recv(), if closing.is_none() => match command {
                Some(Command::Close) | None => {
                    closing = Some(tokio::time::Instant::now() + Duration::from_secs(2));
                    match stage.graceful_shutdown() {
                        Ok(outputs) => outputs,
                        Err(_) => return End::User,
                    }
                }
                Some(Command::Resize { width, height, scale }) => {
                    let (width, height) = fit_size(width, height);
                    let scale = (100..=500).contains(&scale).then_some(scale);
                    match stage.encode_resize(u32::from(width), u32::from(height), scale, None) {
                        Some(Ok(frame)) => vec![ActiveStageOutput::ResponseFrame(frame)],
                        Some(Err(error)) => return lost(&error),
                        // The server cannot change the size while running; the picture stays as it is.
                        None => Vec::new(),
                    }
                }
                Some(command) => match input(&command) {
                    Some(event) => match stage.process_fastpath_input(&mut image, &[event]) {
                        Ok(outputs) => outputs,
                        Err(error) => return lost(&error),
                    },
                    None => Vec::new(),
                },
            },
        };

        for output in outputs {
            let event = match output {
                ActiveStageOutput::ResponseFrame(frame) => {
                    if let Err(error) = writer.write_all(&frame).await {
                        return if closing.is_some() { End::User } else { lost(&error) };
                    }
                    None
                }
                ActiveStageOutput::GraphicsUpdate(rect) => region(&image, &rect),
                ActiveStageOutput::PointerDefault => Some(Event::Pointer(Pointer::Default)),
                ActiveStageOutput::PointerHidden => Some(Event::Pointer(Pointer::Hidden)),
                ActiveStageOutput::PointerPosition { x, y } => Some(Event::Pointer(Pointer::Position { x, y })),
                ActiveStageOutput::PointerBitmap(pointer) => {
                    Some(Event::Pointer(Pointer::Bitmap { width: pointer.width, height: pointer.height, hot_x: pointer.hotspot_x, hot_y: pointer.hotspot_y, pixels: pointer.bitmap_data.clone() }))
                }
                ActiveStageOutput::DeactivateAll => {
                    // The server reconfigures the session, e.g. after a resize: the settings
                    // are negotiated once more, after which there is a new, empty picture.
                    let mut activation = activation_factory.create();
                    let mut buffer = WriteBuf::new();
                    loop {
                        let written = match single_sequence_step_read(&mut reader, &mut activation, &mut buffer).await {
                            Ok(written) => written,
                            Err(error) => return lost(&error),
                        };
                        if written.size().is_some() {
                            if let Err(error) = writer.write_all(buffer.filled()).await {
                                return lost(&error);
                            }
                        }
                        if let ConnectionActivationState::Finalized { desktop_size, share_id, enable_server_pointer, pointer_software_rendering } = activation.connection_activation_state() {
                            image = DecodedImage::new(PixelFormat::RgbA32, desktop_size.width, desktop_size.height);
                            stage.set_fastpath_processor(
                                fast_path::ProcessorBuilder {
                                    io_channel_id: activation.io_channel_id(),
                                    user_channel_id: activation.user_channel_id(),
                                    share_id,
                                    enable_server_pointer,
                                    pointer_software_rendering,
                                    bulk_decompressor: None,
                                }
                                .build(),
                            );
                            stage.set_share_id(share_id);
                            stage.set_enable_server_pointer(enable_server_pointer);
                            break;
                        }
                    }
                    Some(Event::Resized { width: image.width(), height: image.height() })
                }
                ActiveStageOutput::Terminate(reason) => {
                    return match reason {
                        GracefulDisconnectReason::UserInitiated => End::User,
                        _ if closing.is_some() => End::User,
                        GracefulDisconnectReason::ServerInitiated => End::Server(String::new()),
                        GracefulDisconnectReason::Other(text) => End::Server(text),
                    };
                }
                // The faster path over UDP and measuring the line are not built; the server manages without.
                _ => None,
            };
            if let Some(event) = event {
                if events.send(event).await.is_err() {
                    return End::User;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_domain_in_front_of_the_user_is_split_off() {
        assert_eq!(split_user("alex"), ("alex".into(), None));
        assert_eq!(split_user("FIRMA\\alex"), ("alex".into(), Some("FIRMA".into())));
        assert_eq!(split_user("alex@firma.local"), ("alex@firma.local".into(), None));
        assert_eq!(split_user(".\\alex"), ("alex".into(), Some(".".into())));
        for odd in ["\\alex", "FIRMA\\", "\\"] {
            assert_eq!(split_user(odd), (odd.into(), None), "{odd}");
        }
    }

    #[test]
    fn sizes_are_fitted_to_what_a_server_takes() {
        assert_eq!(fit_size(1280, 720), (1280, 720));
        assert_eq!(fit_size(1281, 721), (1280, 721));
        assert_eq!(fit_size(10, 10), (200, 200));
        assert_eq!(fit_size(u16::MAX, u16::MAX), (8192, 8192));
    }

    #[test]
    fn commands_become_what_goes_over_the_wire() {
        assert_eq!(input(&Command::Key { code: 0x1e, extended: false, down: true }), Some(FastPathInputEvent::KeyboardEvent(KeyboardFlags::empty(), 0x1e)));
        assert_eq!(input(&Command::Key { code: 0x1d, extended: true, down: false }), Some(FastPathInputEvent::KeyboardEvent(KeyboardFlags::RELEASE | KeyboardFlags::EXTENDED, 0x1d)));
        assert_eq!(input(&Command::Button { button: Button::Right, down: true, x: 3, y: 4 }), Some(mouse(PointerFlags::RIGHT_BUTTON | PointerFlags::DOWN, 0, 3, 4)));
        assert_eq!(input(&Command::Button { button: Button::Left, down: false, x: 3, y: 4 }), Some(mouse(PointerFlags::LEFT_BUTTON, 0, 3, 4)));
        assert_eq!(input(&Command::Wheel { delta: -120, horizontal: false, x: 1, y: 2 }), Some(mouse(PointerFlags::VERTICAL_WHEEL, -120, 1, 2)));
        assert_eq!(input(&Command::Locks { caps: true, num: false, scroll: false }), Some(FastPathInputEvent::SyncEvent(SynchronizeFlags::CAPS_LOCK)));
        assert_eq!(input(&Command::Close), None);
        assert_eq!(input(&Command::Resize { width: 800, height: 600, scale: 100 }), None);
    }

    #[test]
    fn a_region_is_cut_out_of_the_picture_row_by_row() {
        // Every pixel carries its position: red the column, green the row. The rows are longer than the picture is wide.
        let (width, height, stride) = (4u16, 3u16, 20usize);
        let mut data = vec![0u8; stride * usize::from(height)];
        for y in 0..height {
            for x in 0..width {
                data[usize::from(y) * stride + usize::from(x) * 4..][..4].copy_from_slice(&[x as u8, y as u8, 0, 0xff]);
            }
        }
        let Some(Event::Region { x, y, width: w, height: h, pixels }) = cut(&data, stride, width, height, &InclusiveRectangle { left: 1, top: 1, right: 2, bottom: 2 }) else { panic!("kein Bereich") };
        assert_eq!((x, y, w, h), (1, 1, 2, 2));
        assert_eq!(pixels.chunks(4).map(|p| (p[0], p[1])).collect::<Vec<_>>(), [(1, 1), (2, 1), (1, 2), (2, 2)]);
        // If a region sticks out of the picture, it is clipped; if it lies completely outside, there is none.
        let Some(Event::Region { width: w, height: h, .. }) = cut(&data, stride, width, height, &InclusiveRectangle { left: 3, top: 2, right: 90, bottom: 90 }) else { panic!("kein Bereich") };
        assert_eq!((w, h), (1, 1));
        assert!(cut(&data, stride, width, height, &InclusiveRectangle { left: 4, top: 0, right: 9, bottom: 0 }).is_none());
        assert!(cut(&data[..10], stride, width, height, &InclusiveRectangle { left: 0, top: 0, right: 3, bottom: 2 }).is_none());
    }
}

//! The file manager against a simulated FTP server (`libunftp` on a folder on this machine): plain and
//! over FTPS with a self-signed certificate. What only third-party servers show (old listing formats in practice,
//! implicit FTPS, servers without `MLSD`) is not covered by this test.

use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use glowport_ftp::{Connect, Fingerprint, Refusal, Remote, Security};
use glowport_net::files::{FileError, Kind};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use unftp_core::auth::{AuthenticationError, Authenticator, Credentials, Principal};

const USER: &str = "tester";
/// Only applies to the simulated server in this test.
const PASSWORD: &str = "richtig";

/// Every sign-in the server saw: user, and whether the password was right.
type Logins = Arc<Mutex<Vec<(String, bool)>>>;

#[derive(Debug)]
struct Door(Logins);

#[async_trait::async_trait]
impl Authenticator for Door {
    async fn authenticate(&self, username: &str, credentials: &Credentials) -> Result<Principal, AuthenticationError> {
        let right = username == USER && credentials.password.as_deref() == Some(PASSWORD);
        self.0.lock().unwrap().push((username.to_string(), right));
        if right {
            Ok(Principal { username: username.to_string() })
        } else {
            Err(AuthenticationError::BadPassword)
        }
    }
}

struct Running {
    port: u16,
    root: PathBuf,
    fingerprint: Option<Fingerprint>,
    logins: Logins,
}

impl Running {
    fn connect(&self, security: Security, password: &str, pin: Option<Fingerprint>) -> Connect {
        Connect { host: "127.0.0.1".into(), port: self.port, user: USER.into(), password: password.into(), security, pin }
    }
}

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// Starts the server on a fresh folder with a few files; `tls` gives it a self-signed certificate.
async fn serve(tls: bool) -> Running {
    let base = std::env::temp_dir().join(format!("glowport-ftp-{}-{}", std::process::id(), COUNTER.fetch_add(1, Ordering::Relaxed)));
    let _ = std::fs::remove_dir_all(&base);
    let root = base.join("root");
    std::fs::create_dir_all(root.join("web/images")).unwrap();
    std::fs::write(root.join("readme.txt"), "Hello from the test server\n").unwrap();
    std::fs::write(root.join("with spaces and ä.txt"), "äöü").unwrap();
    std::fs::write(root.join("web/index.html"), "<h1>Seite</h1>").unwrap();
    std::fs::write(root.join("web/images/logo.bin"), (0..=255u8).cycle().take(300_000).collect::<Vec<_>>()).unwrap();

    // A free port: occupy briefly, remember the number, release again.
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let logins: Logins = Arc::default();
    let storage = root.clone();
    let mut builder = libunftp::ServerBuilder::with_authenticator(Box::new(move || unftp_sbe_fs::Filesystem::new(storage.clone()).unwrap()), Arc::new(Door(logins.clone()))).greeting("Glowport test server").passive_ports(50_000..=50_400);
    let mut fingerprint = None;
    if tls {
        let certified = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        fingerprint = Some(Sha256::digest(certified.cert.der()).into());
        let (cert, key) = (base.join("cert.pem"), base.join("key.pem"));
        std::fs::write(&cert, certified.cert.pem()).unwrap();
        std::fs::write(&key, certified.signing_key.serialize_pem()).unwrap();
        builder = builder.ftps(cert, key);
    }
    let server = builder.build().unwrap();
    tokio::spawn(server.listen(format!("127.0.0.1:{port}")));
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Running { port, root, fingerprint, logins }
}

fn names(entries: &[glowport_net::files::Entry]) -> Vec<&str> {
    let mut names: Vec<&str> = entries.iter().map(|entry| entry.name.as_str()).collect();
    names.sort_unstable();
    names
}

/// Everything the file manager needs, once through; the same for the plain connection and for FTPS.
async fn everything(remote: &Remote, running: &Running) {
    let home = remote.home().await.unwrap();
    assert_eq!(home, "/");

    // Reading folders, also with spaces and non-ASCII characters in the name.
    let listed = remote.list("/").await.unwrap();
    assert_eq!(names(&listed), ["readme.txt", "web", "with spaces and ä.txt"]);
    let readme = listed.iter().find(|entry| entry.name == "readme.txt").unwrap();
    assert_eq!((readme.kind, readme.size), (Kind::File, 27));
    assert!(readme.modified > 1_700_000_000, "the modification time comes along: {}", readme.modified);
    assert_eq!(listed.iter().find(|entry| entry.name == "web").unwrap().kind, Kind::Dir);
    assert_eq!(names(&remote.list("/web").await.unwrap()), ["images", "index.html"]);
    assert!(matches!(remote.list("/does-not-exist").await, Err(FileError::NoSuchFile | FileError::NotADirectory)));

    // Einzelnes ansehen.
    let stat = remote.stat("/web/index.html", true).await.unwrap();
    assert_eq!((stat.name.as_str(), stat.kind, stat.size), ("index.html", Kind::File, 14));
    assert_eq!(remote.stat("/web", true).await.unwrap().kind, Kind::Dir);
    assert_eq!(remote.stat("/", true).await.unwrap().kind, Kind::Dir);
    assert_eq!(remote.stat("/web/missing.txt", true).await, Err(FileError::NoSuchFile));

    // Reading, whole and with a limit; the connection continues afterwards.
    assert_eq!(remote.read("/readme.txt", 1024).await.unwrap(), (b"Hello from the test server\n".to_vec(), false));
    assert_eq!(remote.read("/with spaces and ä.txt", 1024).await.unwrap().0, "äöü".as_bytes());
    let (start, longer) = remote.read("/web/images/logo.bin", 1000).await.unwrap();
    assert!(longer && start.len() == 1000 && start[255] == 255 && start[256] == 0);
    assert_eq!(remote.read("/readme.txt", 5).await.unwrap(), (b"Hello".to_vec(), true));
    assert_eq!(remote.read("/missing.txt", 10).await, Err(FileError::NoSuchFile));

    // Writing, creating folders, renaming without overwriting.
    remote.mkdir("/new").await.unwrap();
    remote.write("/new/note.txt", b"first version").await.unwrap();
    assert_eq!(std::fs::read(running.root.join("new/note.txt")).unwrap(), b"first version");
    remote.write("/new/note.txt", b"second").await.unwrap();
    assert_eq!(remote.read("/new/note.txt", 100).await.unwrap().0, b"second");
    remote.rename("/new/note.txt", "/new/renamed.txt").await.unwrap();
    assert_eq!(names(&remote.list("/new").await.unwrap()), ["renamed.txt"]);
    assert_eq!(remote.rename("/readme.txt", "/new/renamed.txt").await, Err(FileError::Exists), "renaming never overwrites");
    assert!(running.root.join("readme.txt").exists());

    // Transfers run on their own connections; the one for commands stays usable meanwhile.
    let mut reader = remote.reader("/web/images/logo.bin", 0).await.unwrap();
    let mut first = vec![0u8; 1000];
    reader.read_exact(&mut first).await.unwrap();
    assert_eq!(names(&remote.list("/web/images").await.unwrap()), ["logo.bin"], "browsing continues during a transfer");
    let mut rest = Vec::new();
    reader.read_to_end(&mut rest).await.unwrap();
    assert_eq!(first.len() + rest.len(), 300_000);
    assert!(rest.iter().enumerate().all(|(i, byte)| *byte == ((i + 1000) % 256) as u8));

    // Resuming: downloading from a position, uploading from what is already there.
    let mut tail = Vec::new();
    remote.reader("/web/images/logo.bin", 299_990).await.unwrap().read_to_end(&mut tail).await.unwrap();
    assert_eq!(tail, (0..10).map(|i| ((299_990 + i) % 256) as u8).collect::<Vec<_>>());

    let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let mut writer = remote.writer("/new/big.bin", 0).await.unwrap();
    writer.write_all(&payload[..120_000]).await.unwrap();
    writer.shutdown().await.unwrap();
    assert_eq!(remote.stat("/new/big.bin", true).await.unwrap().size, 120_000);
    let mut writer = remote.writer("/new/big.bin", 120_000).await.unwrap();
    writer.write_all(&payload[120_000..]).await.unwrap();
    writer.shutdown().await.unwrap();
    assert_eq!(std::fs::read(running.root.join("new/big.bin")).unwrap(), payload, "a resumed upload yields exactly the file");
    assert!(remote.reader("/missing.bin", 0).await.is_err());

    // Setting the modification time if the server can.
    if remote.abilities().set_time {
        remote.touch("/new/big.bin", 1_582_934_400).await.unwrap();
        assert_eq!(remote.stat("/new/big.bin", true).await.unwrap().modified, 1_582_934_400);
    } else {
        assert_eq!(remote.touch("/new/big.bin", 1_582_934_400).await, Err(FileError::Unsupported));
    }

    // Deleting: a file, then a folder with its content.
    remote.remove("/new/renamed.txt").await.unwrap();
    assert!(!running.root.join("new/renamed.txt").exists());
    remote.mkdir("/new/deep").await.unwrap();
    remote.write("/new/deep/a.txt", b"a").await.unwrap();
    remote.remove("/new").await.unwrap();
    assert!(!running.root.join("new").exists());
    assert_eq!(remote.remove("/new").await, Err(FileError::NoSuchFile));
    assert!(running.root.join("web/index.html").exists(), "the rest stays");

    remote.ping().await.unwrap();
}

#[tokio::test]
async fn an_open_connection_does_everything_the_file_manager_needs() {
    let running = serve(false).await;
    let remote = Remote::connect(&running.connect(Security::None, PASSWORD, None)).await.unwrap();
    assert!(remote.certificate().is_none() && !remote.abilities().offers_tls);
    everything(&remote, &running).await;
    remote.close().await;
}

#[tokio::test]
async fn ftps_does_the_same_and_transfers_are_encrypted_too() {
    let running = serve(true).await;
    let remote = Remote::connect(&running.connect(Security::Explicit, PASSWORD, running.fingerprint)).await.unwrap();
    assert_eq!(remote.certificate(), running.fingerprint);
    everything(&remote, &running).await;
    remote.close().await;
}

#[tokio::test]
async fn an_unknown_certificate_stops_before_the_login() {
    let running = serve(true).await;
    let shown = match Remote::connect(&running.connect(Security::Explicit, PASSWORD, None)).await {
        Err(Refusal::Certificate(fingerprint)) => fingerprint,
        other => panic!("{:?}", other.err()),
    };
    assert_eq!(Some(shown), running.fingerprint, "the fingerprint shown is that of the certificate the server has");
    assert!(running.logins.lock().unwrap().is_empty(), "without confirmation no sign-in goes to the server");

    // A certificate other than the confirmed one: no sign-in in that case either.
    let mut other = shown;
    other[0] ^= 0xff;
    assert_eq!(Remote::connect(&running.connect(Security::Explicit, PASSWORD, Some(other))).await.err(), Some(Refusal::CertificateChanged(shown)));
    assert!(running.logins.lock().unwrap().is_empty());

    // Confirmed: it works.
    let remote = Remote::connect(&running.connect(Security::Explicit, PASSWORD, Some(shown))).await.unwrap();
    assert_eq!(*running.logins.lock().unwrap(), [(USER.to_string(), true)]);
    remote.close().await;
}

#[tokio::test]
async fn wrong_passwords_and_missing_tls_are_told_apart() {
    let running = serve(true).await;
    assert_eq!(Remote::connect(&running.connect(Security::Explicit, "falsch", running.fingerprint)).await.err(), Some(Refusal::AuthFailed));
    assert_eq!(Remote::connect(&running.connect(Security::None, "falsch", None)).await.err(), Some(Refusal::AuthFailed));
    // Connected in the clear, the server shows that it could do TLS.
    let remote = Remote::connect(&running.connect(Security::None, PASSWORD, None)).await.unwrap();
    assert!(remote.abilities().offers_tls);
    remote.close().await;

    // A server without TLS refuses the switch before a password is sent.
    let plain = serve(false).await;
    assert!(matches!(Remote::connect(&plain.connect(Security::Explicit, PASSWORD, None)).await.err(), Some(Refusal::NoTls(_))));
    assert!(plain.logins.lock().unwrap().is_empty());

    // And a server that does not exist.
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let nowhere = Connect { host: "127.0.0.1".into(), port, user: USER.into(), password: PASSWORD.into(), security: Security::None, pin: None };
    assert!(matches!(Remote::connect(&nowhere).await.err(), Some(Refusal::Offline(_))));
}

#[tokio::test]
async fn a_connection_the_server_closed_is_opened_again() {
    let running = serve(false).await;
    let storage = running.root.clone();
    // A second server on the same folder that closes connections after one second of quiet.
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let server = libunftp::ServerBuilder::with_authenticator(Box::new(move || unftp_sbe_fs::Filesystem::new(storage.clone()).unwrap()), Arc::new(Door(running.logins.clone()))).idle_session_timeout(1).passive_ports(50_401..=50_500).build().unwrap();
    tokio::spawn(server.listen(format!("127.0.0.1:{port}")));
    tokio::time::sleep(Duration::from_millis(300)).await;
    let remote = Remote::connect(&Connect { host: "127.0.0.1".into(), port, user: USER.into(), password: PASSWORD.into(), security: Security::None, pin: None }).await.unwrap();
    assert_eq!(names(&remote.list("/").await.unwrap()).len(), 3);
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert_eq!(names(&remote.list("/web").await.unwrap()), ["images", "index.html"], "after the pause the connection signs in again on its own");
    assert_eq!(running.logins.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn a_transfer_waits_when_the_server_allows_no_further_connection() {
    use std::sync::atomic::AtomicU32;
    let running = serve(false).await;
    // In front of the server there is a door that turns away the second and third connection, like a server that only
    // allows a few per address. The data channels bypass it and go straight to the server.
    let door = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = door.local_addr().unwrap().port();
    let (target, seen) = (running.port, Arc::new(AtomicU32::new(0)));
    let counted = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = door.accept().await {
            let number = counted.fetch_add(1, Ordering::SeqCst) + 1;
            tokio::spawn(async move {
                if number == 2 || number == 3 {
                    let _ = socket.write_all(b"421 Too many connections (1) from this IP\r\n").await;
                    return;
                }
                if let Ok(mut server) = tokio::net::TcpStream::connect(("127.0.0.1", target)).await {
                    let _ = tokio::io::copy_bidirectional(&mut socket, &mut server).await;
                }
            });
        }
    });
    let remote = Remote::connect(&Connect { host: "127.0.0.1".into(), port, user: USER.into(), password: PASSWORD.into(), security: Security::None, pin: None }).await.unwrap();
    assert_eq!(seen.load(Ordering::SeqCst), 1);
    let started = std::time::Instant::now();
    let mut text = String::new();
    remote.reader("/readme.txt", 0).await.unwrap().read_to_string(&mut text).await.unwrap();
    assert_eq!(text, "Hello from the test server\n");
    assert_eq!(seen.load(Ordering::SeqCst), 4, "rejected twice, in on the third attempt");
    assert!(started.elapsed() >= Duration::from_secs(3), "the attempts are spaced out: {:?}", started.elapsed());
    // The command connection noticed nothing of this.
    assert_eq!(names(&remote.list("/web").await.unwrap()), ["images", "index.html"]);
}

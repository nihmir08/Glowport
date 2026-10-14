//! Der Dateimanager gegen einen nachgebauten FTP-Server (`libunftp` auf einem Ordner dieses Rechners): offen und
//! über FTPS mit selbst erstelltem Zertifikat. Was nur fremde Server zeigen (alte Listenformate im Betrieb, FTPS
//! von Anfang an, Server ohne `MLSD`), prüft dieser Test nicht.

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
/// Gilt nur für den nachgebauten Server in diesem Test.
const PASSWORD: &str = "richtig";

/// Jede Anmeldung, die der Server zu sehen bekam: Benutzer, und ob das Passwort stimmte.
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

/// Startet den Server auf einem frischen Ordner mit ein paar Dateien; `tls` gibt ihm ein selbst erstelltes Zertifikat.
async fn serve(tls: bool) -> Running {
    let base = std::env::temp_dir().join(format!("glowport-ftp-{}-{}", std::process::id(), COUNTER.fetch_add(1, Ordering::Relaxed)));
    let _ = std::fs::remove_dir_all(&base);
    let root = base.join("root");
    std::fs::create_dir_all(root.join("web/bilder")).unwrap();
    std::fs::write(root.join("liesmich.txt"), "Hallo vom Testserver\n").unwrap();
    std::fs::write(root.join("mit leerzeichen und ä.txt"), "äöü").unwrap();
    std::fs::write(root.join("web/index.html"), "<h1>Seite</h1>").unwrap();
    std::fs::write(root.join("web/bilder/logo.bin"), (0..=255u8).cycle().take(300_000).collect::<Vec<_>>()).unwrap();

    // Ein freier Port: kurz belegen, Nummer merken, wieder freigeben.
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let logins: Logins = Arc::default();
    let storage = root.clone();
    let mut builder = libunftp::ServerBuilder::with_authenticator(Box::new(move || unftp_sbe_fs::Filesystem::new(storage.clone()).unwrap()), Arc::new(Door(logins.clone()))).greeting("Testserver von Glowport").passive_ports(50_000..=50_400);
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

/// Alles, was der Dateimanager braucht, einmal durch; gleich für die offene Verbindung und für FTPS.
async fn everything(remote: &Remote, running: &Running) {
    let home = remote.home().await.unwrap();
    assert_eq!(home, "/");

    // Ordner lesen, auch mit Leerzeichen und Umlauten im Namen.
    let listed = remote.list("/").await.unwrap();
    assert_eq!(names(&listed), ["liesmich.txt", "mit leerzeichen und ä.txt", "web"]);
    let readme = listed.iter().find(|entry| entry.name == "liesmich.txt").unwrap();
    assert_eq!((readme.kind, readme.size), (Kind::File, 21));
    assert!(readme.modified > 1_700_000_000, "die Änderungszeit kommt mit: {}", readme.modified);
    assert_eq!(listed.iter().find(|entry| entry.name == "web").unwrap().kind, Kind::Dir);
    assert_eq!(names(&remote.list("/web").await.unwrap()), ["bilder", "index.html"]);
    assert!(matches!(remote.list("/gibt-es-nicht").await, Err(FileError::NoSuchFile | FileError::NotADirectory)));

    // Einzelnes ansehen.
    let stat = remote.stat("/web/index.html", true).await.unwrap();
    assert_eq!((stat.name.as_str(), stat.kind, stat.size), ("index.html", Kind::File, 14));
    assert_eq!(remote.stat("/web", true).await.unwrap().kind, Kind::Dir);
    assert_eq!(remote.stat("/", true).await.unwrap().kind, Kind::Dir);
    assert_eq!(remote.stat("/web/fehlt.txt", true).await, Err(FileError::NoSuchFile));

    // Lesen, ganz und mit Grenze; danach geht die Verbindung weiter.
    assert_eq!(remote.read("/liesmich.txt", 1024).await.unwrap(), (b"Hallo vom Testserver\n".to_vec(), false));
    assert_eq!(remote.read("/mit leerzeichen und ä.txt", 1024).await.unwrap().0, "äöü".as_bytes());
    let (start, longer) = remote.read("/web/bilder/logo.bin", 1000).await.unwrap();
    assert!(longer && start.len() == 1000 && start[255] == 255 && start[256] == 0);
    assert_eq!(remote.read("/liesmich.txt", 5).await.unwrap(), (b"Hallo".to_vec(), true));
    assert_eq!(remote.read("/fehlt.txt", 10).await, Err(FileError::NoSuchFile));

    // Schreiben, Ordner anlegen, umbenennen ohne zu überschreiben.
    remote.mkdir("/neu").await.unwrap();
    remote.write("/neu/notiz.txt", b"erste Fassung").await.unwrap();
    assert_eq!(std::fs::read(running.root.join("neu/notiz.txt")).unwrap(), b"erste Fassung");
    remote.write("/neu/notiz.txt", b"zweite").await.unwrap();
    assert_eq!(remote.read("/neu/notiz.txt", 100).await.unwrap().0, b"zweite");
    remote.rename("/neu/notiz.txt", "/neu/umbenannt.txt").await.unwrap();
    assert_eq!(names(&remote.list("/neu").await.unwrap()), ["umbenannt.txt"]);
    assert_eq!(remote.rename("/liesmich.txt", "/neu/umbenannt.txt").await, Err(FileError::Exists), "umbenennen überschreibt nie");
    assert!(running.root.join("liesmich.txt").exists());

    // Übertragungen laufen auf eigenen Verbindungen; die für Befehle bleibt dabei benutzbar.
    let mut reader = remote.reader("/web/bilder/logo.bin", 0).await.unwrap();
    let mut first = vec![0u8; 1000];
    reader.read_exact(&mut first).await.unwrap();
    assert_eq!(names(&remote.list("/web/bilder").await.unwrap()), ["logo.bin"], "während einer Übertragung lässt sich weiter blättern");
    let mut rest = Vec::new();
    reader.read_to_end(&mut rest).await.unwrap();
    assert_eq!(first.len() + rest.len(), 300_000);
    assert!(rest.iter().enumerate().all(|(i, byte)| *byte == ((i + 1000) % 256) as u8));

    // Fortsetzen: herunter ab einer Stelle, hinauf ab dem, was schon liegt.
    let mut tail = Vec::new();
    remote.reader("/web/bilder/logo.bin", 299_990).await.unwrap().read_to_end(&mut tail).await.unwrap();
    assert_eq!(tail, (0..10).map(|i| ((299_990 + i) % 256) as u8).collect::<Vec<_>>());

    let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let mut writer = remote.writer("/neu/gross.bin", 0).await.unwrap();
    writer.write_all(&payload[..120_000]).await.unwrap();
    writer.shutdown().await.unwrap();
    assert_eq!(remote.stat("/neu/gross.bin", true).await.unwrap().size, 120_000);
    let mut writer = remote.writer("/neu/gross.bin", 120_000).await.unwrap();
    writer.write_all(&payload[120_000..]).await.unwrap();
    writer.shutdown().await.unwrap();
    assert_eq!(std::fs::read(running.root.join("neu/gross.bin")).unwrap(), payload, "ein fortgesetzter Upload ergibt genau die Datei");
    assert!(remote.reader("/fehlt.bin", 0).await.is_err());

    // Änderungszeit setzen, wenn der Server es kann.
    if remote.abilities().set_time {
        remote.touch("/neu/gross.bin", 1_582_934_400).await.unwrap();
        assert_eq!(remote.stat("/neu/gross.bin", true).await.unwrap().modified, 1_582_934_400);
    } else {
        assert_eq!(remote.touch("/neu/gross.bin", 1_582_934_400).await, Err(FileError::Unsupported));
    }

    // Löschen: eine Datei, dann einen Ordner samt Inhalt.
    remote.remove("/neu/umbenannt.txt").await.unwrap();
    assert!(!running.root.join("neu/umbenannt.txt").exists());
    remote.mkdir("/neu/tief").await.unwrap();
    remote.write("/neu/tief/a.txt", b"a").await.unwrap();
    remote.remove("/neu").await.unwrap();
    assert!(!running.root.join("neu").exists());
    assert_eq!(remote.remove("/neu").await, Err(FileError::NoSuchFile));
    assert!(running.root.join("web/index.html").exists(), "anderes bleibt");

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
    assert_eq!(Some(shown), running.fingerprint, "gezeigt wird der Fingerabdruck des Zertifikats, das der Server hat");
    assert!(running.logins.lock().unwrap().is_empty(), "ohne Bestätigung geht keine Anmeldung an den Server");

    // Ein anderes als das bestätigte Zertifikat: auch dann keine Anmeldung.
    let mut other = shown;
    other[0] ^= 0xff;
    assert_eq!(Remote::connect(&running.connect(Security::Explicit, PASSWORD, Some(other))).await.err(), Some(Refusal::CertificateChanged(shown)));
    assert!(running.logins.lock().unwrap().is_empty());

    // Bestätigt: Es geht.
    let remote = Remote::connect(&running.connect(Security::Explicit, PASSWORD, Some(shown))).await.unwrap();
    assert_eq!(*running.logins.lock().unwrap(), [(USER.to_string(), true)]);
    remote.close().await;
}

#[tokio::test]
async fn wrong_passwords_and_missing_tls_are_told_apart() {
    let running = serve(true).await;
    assert_eq!(Remote::connect(&running.connect(Security::Explicit, "falsch", running.fingerprint)).await.err(), Some(Refusal::AuthFailed));
    assert_eq!(Remote::connect(&running.connect(Security::None, "falsch", None)).await.err(), Some(Refusal::AuthFailed));
    // Offen verbunden zeigt der Server, dass er TLS könnte.
    let remote = Remote::connect(&running.connect(Security::None, PASSWORD, None)).await.unwrap();
    assert!(remote.abilities().offers_tls);
    remote.close().await;

    // Ein Server ohne TLS lehnt die Umstellung ab, bevor ein Passwort gesendet ist.
    let plain = serve(false).await;
    assert!(matches!(Remote::connect(&plain.connect(Security::Explicit, PASSWORD, None)).await.err(), Some(Refusal::NoTls(_))));
    assert!(plain.logins.lock().unwrap().is_empty());

    // Und ein Server, den es nicht gibt.
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let nowhere = Connect { host: "127.0.0.1".into(), port, user: USER.into(), password: PASSWORD.into(), security: Security::None, pin: None };
    assert!(matches!(Remote::connect(&nowhere).await.err(), Some(Refusal::Offline(_))));
}

#[tokio::test]
async fn a_connection_the_server_closed_is_opened_again() {
    let running = serve(false).await;
    let storage = running.root.clone();
    // Ein zweiter Server auf demselben Ordner, der Verbindungen nach einer Sekunde Ruhe schließt.
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let server = libunftp::ServerBuilder::with_authenticator(Box::new(move || unftp_sbe_fs::Filesystem::new(storage.clone()).unwrap()), Arc::new(Door(running.logins.clone()))).idle_session_timeout(1).passive_ports(50_401..=50_500).build().unwrap();
    tokio::spawn(server.listen(format!("127.0.0.1:{port}")));
    tokio::time::sleep(Duration::from_millis(300)).await;
    let remote = Remote::connect(&Connect { host: "127.0.0.1".into(), port, user: USER.into(), password: PASSWORD.into(), security: Security::None, pin: None }).await.unwrap();
    assert_eq!(names(&remote.list("/").await.unwrap()).len(), 3);
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert_eq!(names(&remote.list("/web").await.unwrap()), ["bilder", "index.html"], "nach der Pause meldet sich die Verbindung von selbst neu an");
    assert_eq!(running.logins.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn a_transfer_waits_when_the_server_allows_no_further_connection() {
    use std::sync::atomic::AtomicU32;
    let running = serve(false).await;
    // Vor dem Server steht eine Tür, die die zweite und dritte Verbindung abweist, wie ein Server, der je Adresse
    // nur wenige zulässt. Die Datenkanäle gehen an ihr vorbei direkt zum Server.
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
    remote.reader("/liesmich.txt", 0).await.unwrap().read_to_string(&mut text).await.unwrap();
    assert_eq!(text, "Hallo vom Testserver\n");
    assert_eq!(seen.load(Ordering::SeqCst), 4, "zweimal abgewiesen, beim dritten Versuch hinein");
    assert!(started.elapsed() >= Duration::from_secs(3), "zwischen den Versuchen wird gewartet: {:?}", started.elapsed());
    // Die Verbindung für Befehle hat davon nichts gemerkt.
    assert_eq!(names(&remote.list("/web").await.unwrap()), ["bilder", "index.html"]);
}

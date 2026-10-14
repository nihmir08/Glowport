//! An FTP server for the tests: `libunftp` on a folder of this machine, plain or with a self-signed
//! certificate (explicit FTPS). Sign-in with [`USER`] and [`PASSWORD`].

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use sha2::{Digest, Sha256};
use unftp_core::auth::{AuthenticationError, Authenticator, Credentials, Principal};

pub const USER: &str = "tester";
pub const PASSWORD: &str = "richtig";

/// Every sign-in the server saw: user, and whether the password was right.
pub type Logins = Arc<Mutex<Vec<(String, bool)>>>;

#[derive(Debug)]
struct Door(Logins);

#[async_trait::async_trait]
impl Authenticator for Door {
    async fn authenticate(&self, username: &str, credentials: &Credentials) -> Result<Principal, AuthenticationError> {
        let right = username == USER && credentials.password.as_deref() == Some(PASSWORD);
        self.0.lock().unwrap_or_else(|p| p.into_inner()).push((username.to_string(), right));
        if right {
            Ok(Principal { username: username.to_string() })
        } else {
            Err(AuthenticationError::BadPassword)
        }
    }
}

pub struct Running {
    pub address: SocketAddr,
    /// SHA-256 over the certificate, if the server offers TLS.
    pub fingerprint: Option<[u8; 32]>,
    pub logins: Logins,
}

/// Fills an empty folder with a small web space.
pub fn sample(root: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(root.join("htdocs/img"))?;
    std::fs::create_dir_all(root.join("logs"))?;
    std::fs::write(root.join("htdocs/index.html"), "<!doctype html>\n<title>Test server</title>\n<h1>It works</h1>\n")?;
    std::fs::write(root.join("htdocs/with spaces and ä.txt"), "äöü")?;
    std::fs::write(root.join("htdocs/img/logo.bin"), (0..=255u8).cycle().take(300_000).collect::<Vec<_>>())?;
    std::fs::write(root.join("logs/access.log"), "GET / 200\n")?;
    std::fs::write(root.join("readme.txt"), "Hello from the FTP test server\n")
}

/// Starts the server on `root`. With `tls` it gets a self-signed certificate; it puts its files into
/// `scratch`. `ports` are the ports for the data channels.
pub async fn start(root: PathBuf, tls: Option<&Path>, ports: std::ops::RangeInclusive<u16>) -> std::io::Result<Running> {
    let failed = |error: &dyn std::fmt::Display| std::io::Error::other(error.to_string());
    std::fs::create_dir_all(&root)?;
    // A free port: occupy briefly, remember the number, release again.
    let address = std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?;
    let logins: Logins = Arc::default();
    let storage = root.clone();
    let open = move || unftp_sbe_fs::Filesystem::new(storage.clone()).expect("the FTP server's folder is readable");
    let mut builder = libunftp::ServerBuilder::with_authenticator(Box::new(open), Arc::new(Door(logins.clone()))).greeting("Glowport test server").passive_ports(ports);
    let mut fingerprint = None;
    if let Some(scratch) = tls {
        let certified = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).map_err(|e| failed(&e))?;
        fingerprint = Some(Sha256::digest(certified.cert.der()).into());
        std::fs::create_dir_all(scratch)?;
        let (cert, key) = (scratch.join("ftp-cert.pem"), scratch.join("ftp-key.pem"));
        std::fs::write(&cert, certified.cert.pem())?;
        std::fs::write(&key, certified.signing_key.serialize_pem())?;
        builder = builder.ftps(cert, key);
    }
    let server = builder.build().map_err(|e| failed(&e))?;
    tokio::spawn(server.listen(address.to_string()));
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(address).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Ok(Running { address, fingerprint, logins })
}

/// This is how browsers and servers show a certificate's fingerprint: `5F:1A:…`.
pub fn fingerprint_text(fingerprint: &[u8; 32]) -> String {
    fingerprint.iter().map(|byte| format!("{byte:02X}")).collect::<Vec<_>>().join(":")
}

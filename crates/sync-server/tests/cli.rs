//! `glowport-sync` as a built program: the commands as they are typed on the server, and starting
//! with and without its own TLS.

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::Duration,
};

/// Clears away a folder as soon as the test ends.
struct Temp(PathBuf);

impl Temp {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("glowport-cli-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn program(data: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_glowport-sync"));
    // Whatever happens to be set on this machine should not steer the test.
    for name in ["LISTEN", "DATA", "TRUST_PROXY", "TLS_CERT", "TLS_KEY", "MAX_RECORD_KIB", "MAX_RECORDS", "MAX_VAULTS"] {
        command.env_remove(format!("GLOWPORT_SYNC_{name}"));
    }
    command.arg("--data").arg(data);
    command
}

/// A command: whether it succeeded, what it printed, what it reported as an error.
fn run(data: &Path, args: &[&str]) -> (bool, String, String) {
    let output = program(data).args(args).output().unwrap();
    (output.status.success(), String::from_utf8_lossy(&output.stdout).into_owned(), String::from_utf8_lossy(&output.stderr).into_owned())
}

/// A running server. Ends with the test, even if the test fails.
struct Running {
    child: Child,
    port: u16,
    /// What the server printed up to the message “listening on”.
    banner: String,
    /// What it prints afterwards: its log.
    log: Arc<Mutex<Vec<String>>>,
}

impl Running {
    /// Waits until a line with this text is in the log.
    fn logged(&self, text: &str) -> String {
        for _ in 0..100 {
            if let Some(line) = self.log.lock().unwrap().iter().find(|line| line.contains(text)) {
                return line.clone();
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("not in the log: {text}\n{}", self.log.lock().unwrap().join("\n"));
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

fn start(data: &Path, extra: &[&str]) -> Running {
    let port = free_port();
    let mut child = program(data).args(["serve", "--listen", &format!("127.0.0.1:{port}")]).args(extra).stdout(Stdio::piped()).spawn().unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let mut banner = String::new();
    for line in &mut lines {
        let line = line.unwrap();
        banner.push_str(&line);
        banner.push('\n');
        if line.contains("listening on") {
            break;
        }
    }
    assert!(banner.contains("listening on"), "the server did not start: {banner}");
    let log: Arc<Mutex<Vec<String>>> = Arc::default();
    let sink = log.clone();
    std::thread::spawn(move || lines.map_while(Result::ok).for_each(|line| sink.lock().unwrap().push(line)));
    Running { child, port, banner, log }
}

fn request() -> &'static [u8] {
    b"GET /v1/info HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
}

/// A request without TLS; returns the status line.
fn plain(port: u16, method: &str, path: &str, body: &str) -> String {
    let mut stream = connect(port);
    write!(stream, "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len()).unwrap();
    let mut answer = String::new();
    let _ = stream.read_to_string(&mut answer);
    answer.lines().next().unwrap_or_default().to_string()
}

fn connect(port: u16) -> TcpStream {
    let stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    stream
}

#[test]
fn commands_as_typed_on_the_server() {
    let data = Temp::new("commands");
    let dir = &data.0;

    // A command does not create a data store: in the wrong folder it says so instead of inventing an empty server.
    let (ok, out, err) = run(dir, &["invite"]);
    assert!(!ok && out.is_empty() && err.contains("No server data") && !dir.join("sync.db").exists(), "{err}");
    drop(start(dir, &[]));

    assert_eq!(run(dir, &["accounts"]), (true, "No account yet.\n".into(), String::new()));
    let (ok, out, _) = run(dir, &["invite"]);
    let code = out.lines().next().and_then(|line| line.strip_prefix("Invitation code: ")).expect("invitation code in the output").to_string();
    assert!(ok && code.len() >= 8 && out.contains("Valid once, until 20"), "{out}");
    assert!(run(dir, &["invites"]).1.starts_with(&code));
    // When typing it in, lower case is allowed.
    assert_eq!(run(dir, &["revoke", &code.to_lowercase()]), (true, "Invitation code revoked.\n".into(), String::new()));
    assert_eq!(run(dir, &["invites"]).1, "No open invitation codes.\n");
    let (ok, _, err) = run(dir, &["revoke", &code]);
    assert!(!ok && err.contains("There is no open invitation code"), "{err}");

    for command in ["disable", "enable", "delete", "admin", "noadmin"] {
        let (ok, out, err) = run(dir, &[command, "nobody"]);
        assert!(!ok && out.is_empty() && err.contains("There is no account “nobody”"), "{command}: {err}");
    }

    // The backup is a complete database and overwrites nothing.
    let copy = dir.join("backup.db");
    assert!(run(dir, &["backup", copy.to_str().unwrap()]).0);
    assert!(std::fs::read(&copy).unwrap().starts_with(b"SQLite format 3"));
    assert!(!run(dir, &["backup", copy.to_str().unwrap()]).0);

    // Mistyped: an explanation instead of a start.
    for args in [&["nonsense"][..], &["invite", "too much"], &["--unknown"], &["--help"]] {
        let (ok, _, err) = run(dir, args);
        assert!(!ok && err.contains("Usage:"), "{args:?}: {err}");
    }
    let (ok, _, err) = run(dir, &["--tls-cert", "cert.pem"]);
    assert!(!ok && err.contains("--tls-cert and --tls-key"), "{err}");
    let (ok, _, err) = run(dir, &["--listen", "nowhere"]);
    assert!(!ok && err.contains("not an address"), "{err}");
    let (ok, _, err) = run(dir, &["--trust-proxy-from", "10.0.0.10, nginx"]);
    assert!(!ok && err.contains("“nginx” is not an address"), "{err}");
    let output = program(dir).env("GLOWPORT_SYNC_TRUST_PROXY", "anyone").output().unwrap();
    assert!(!output.status.success() && String::from_utf8_lossy(&output.stderr).contains("GLOWPORT_SYNC_TRUST_PROXY"));
    let output = program(dir).env("GLOWPORT_SYNC_MAX_RECORDS", "many").output().unwrap();
    assert!(!output.status.success() && String::from_utf8_lossy(&output.stderr).contains("is not a number greater than zero"));
}

#[test]
fn serves_while_commands_run_beside_it() {
    let data = Temp::new("running");
    let server = start(&data.0, &[]);
    assert!(server.banner.contains("Setup code for the first account"), "{}", server.banner);

    let mut stream = connect(server.port);
    stream.write_all(request()).unwrap();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).unwrap();
    assert!(answer.starts_with("HTTP/1.1 200") && answer.contains("\"fresh\":true"), "{answer}");

    // The same database while the server is running.
    let (ok, out, err) = run(&data.0, &["invite"]);
    assert!(ok && out.starts_with("Invitation code: "), "{out}{err}");
    assert!(run(&data.0, &["backup", data.0.join("while-running.db").to_str().unwrap()]).0);

    // The log: what changes something or fails, with time, status, kind and account; reading stays silent.
    assert!(plain(server.port, "POST", "/v1/prelogin", r#"{"username":"anna"}"#).contains("200"));
    let line = server.logged("POST /v1/prelogin");
    assert!(line.starts_with("20") && line.ends_with(" 200 POST /v1/prelogin -"), "{line}");
    assert!(plain(server.port, "GET", "/v1/account", "").contains("401"));
    assert!(server.logged("GET /v1/account").ends_with(" 401 GET /v1/account -"));
    // What does not exist appears without the requested path; IDs in addresses appear as patterns.
    assert!(plain(server.port, "GET", "/secret/abc123", "").contains("404"));
    assert!(server.logged(" 404 ").ends_with(" 404 GET ? -"));
    assert!(plain(server.port, "DELETE", "/v1/devices/0123456789abcdef0123456789abcdef", "").contains("401"));
    assert!(server.logged("DELETE").ends_with(" 401 DELETE /v1/devices/{device} -"));
    let log = server.log.lock().unwrap().join("\n");
    assert!(!log.contains("/v1/info") && !log.contains("abc123") && !log.contains("0123456789abcdef"), "{log}");
}

#[test]
fn serves_with_its_own_certificate() {
    let data = Temp::new("tls");
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let (cert, key) = (data.0.join("cert.pem"), data.0.join("key.pem"));
    std::fs::write(&cert, certified.cert.pem()).unwrap();
    std::fs::write(&key, certified.signing_key.serialize_pem()).unwrap();
    let server = start(&data.0, &["--tls-cert", cert.to_str().unwrap(), "--tls-key", key.to_str().unwrap()]);
    assert!(server.banner.contains("(TLS)"), "{}", server.banner);

    let mut roots = rustls::RootCertStore::empty();
    roots.add(certified.cert.der().clone()).unwrap();
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider())).with_safe_default_protocol_versions().unwrap().with_root_certificates(roots).with_no_client_auth();
    let session = rustls::ClientConnection::new(Arc::new(config), "localhost".try_into().unwrap()).unwrap();
    let mut stream = rustls::StreamOwned::new(session, connect(server.port));
    stream.write_all(request()).unwrap();
    let mut answer = Vec::new();
    // The end of the connection may come without a goodbye; whatever is there until then counts.
    let _ = stream.read_to_end(&mut answer);
    let answer = String::from_utf8_lossy(&answer);
    assert!(answer.starts_with("HTTP/1.1 200") && answer.contains("\"fresh\":true"), "{answer}");

    // Without TLS this port does not answer with content.
    let mut plain = connect(server.port);
    plain.write_all(request()).unwrap();
    let mut answer = Vec::new();
    let _ = plain.read_to_end(&mut answer);
    assert!(!String::from_utf8_lossy(&answer).contains("fresh"));

    // A key that is none: the server does not start and says which files are the reason.
    std::fs::write(&key, "not a key").unwrap();
    let (ok, _, err) = run(&data.0, &["serve", "--listen", &format!("127.0.0.1:{}", free_port()), "--tls-cert", cert.to_str().unwrap(), "--tls-key", key.to_str().unwrap()]);
    assert!(!ok && err.contains("certificate") && err.contains("key.pem"), "{err}");
}

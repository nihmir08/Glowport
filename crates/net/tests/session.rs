//! Sessions against the own test server: the whole way from connecting to the end.

use std::{collections::VecDeque, path::PathBuf, time::Duration};

use glowport_net::{execute, keys, open, Command, Connect, End, Event, HostKey, Login, Phase, Proxy, Secret, SecretKind, Session, Station};
use glowport_testserver::{self as server, Options, PROMPT};
use russh::keys::PublicKey;
use tokio::time::timeout;

/// Throwaway key only for these tests, generated with `ssh-keygen -t ed25519 -N test-passphrase`.
const ENCRYPTED_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABDBw/Y9R+
vWsWSGFygsP/TdAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIDys3AvfCy6SxfZO
iMxTF6NyOkeHlispFMFFCUbiwNWyAAAAoFmnO8hrvGlKyxV/9XGGZarOMAYSiG3NbGlZzu
4xZpUa0wa0p/TWhTCHkPPzsFGEYfiQFrszc0obkJsLNKziX3mbrQuHNP5/6JSGt2ICAU4l
ikPpXAZ7KzkcS5wqq6nFXrkaD8wUObpskLTRmj2dg2omhdiytg9BRbVDlW2kr2/HaYdykM
O3jk4sUQfHo9MAev8H7tnr1dp1qmdnGEgq8zc=
-----END OPENSSH PRIVATE KEY-----
";
const ENCRYPTED_KEY_PUBLIC: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDys3AvfCy6SxfZOiMxTF6NyOkeHlispFMFFCUbiwNWy glowport-testschluessel";
const PASSPHRASE: &str = "test-passphrase";

/// Plays the part of the interface: answers prompts as instructed and remembers what happened.
struct Driver {
    session: Session,
    accept_host_key: bool,
    /// Answers to password and passphrase prompts, in order. `None` cancels.
    answers: VecDeque<Option<&'static str>>,
    output: String,
    phases: Vec<Phase>,
    host_key: Option<HostKey>,
    /// Addresses of all servers that showed their key, in this order.
    host_keys: Vec<(String, u16, String)>,
    /// These servers' keys are refused.
    distrust: Vec<u16>,
    /// For which hop the last question was asked.
    stations: Vec<Station>,
    asked: Vec<(SecretKind, u32)>,
    notices: Vec<&'static str>,
    accepted_password: Option<Secret>,
    banner: Option<String>,
    os: Option<String>,
}

impl Driver {
    fn new(connect: Connect) -> Self {
        Self {
            session: open(connect),
            accept_host_key: true,
            answers: VecDeque::new(),
            output: String::new(),
            phases: Vec::new(),
            host_key: None,
            host_keys: Vec::new(),
            distrust: Vec::new(),
            stations: Vec::new(),
            asked: Vec::new(),
            notices: Vec::new(),
            accepted_password: None,
            banner: None,
            os: None,
        }
    }

    /// Processes events until `done` holds (then `None`) or the session ends (then its end).
    async fn until(&mut self, done: impl Fn(&Driver) -> bool) -> Option<End> {
        loop {
            if done(self) {
                return None;
            }
            let event = timeout(Duration::from_secs(10), self.session.events.recv()).await.expect("nichts geschah").expect("Sitzung verschwand ohne Ende");
            match event {
                Event::Phase(phase) => self.phases.push(phase),
                Event::Banner(text) => self.banner = Some(text),
                Event::HostKey { host, port, key, reply } => {
                    self.host_keys.push((host, port, key.fingerprint.clone()));
                    self.host_key = Some(key);
                    let _ = reply.send(self.accept_host_key && !self.distrust.contains(&port));
                }
                Event::Secret { station, kind, attempt, reply } => {
                    self.stations.push(station);
                    self.asked.push((kind, attempt));
                    let answer = self.answers.pop_front().expect("unerwartete Rückfrage");
                    let _ = reply.send(answer.map(|text| Secret::new(text.into())));
                }
                Event::Interactive { reply, .. } => drop(reply.send(None)),
                Event::PasswordAccepted { password, .. } => self.accepted_password = Some(password),
                Event::Notice { code, .. } => self.notices.push(code),
                Event::Os(os) => self.os = Some(os),
                Event::Files(_) | Event::Forward(_) | Event::Mosh(_) => {}
                Event::Output(bytes) => self.output.push_str(&String::from_utf8_lossy(&bytes)),
                Event::End(end) => return Some(end),
            }
        }
    }

    async fn end(&mut self) -> End {
        self.until(|_| false).await.expect("Ende erwartet")
    }

    /// Waits until the shell is ready.
    async fn prompt(&mut self) {
        let seen = self.output.len();
        assert_eq!(self.until(|d| d.output[seen..].ends_with(PROMPT)).await, None, "Sitzung endete vor der Eingabeaufforderung");
    }

    fn send(&self, command: Command) {
        self.session.commands.send(command).expect("Sitzung nimmt keine Befehle mehr an");
    }

    fn typed(&self, line: &str) {
        self.send(Command::Input(format!("{line}\r").into_bytes()));
    }
}

fn with_password() -> Options {
    Options { password: Some(("tester".into(), "richtig".into())), ..Options::default() }
}

fn connect(address: std::net::SocketAddr, password: Option<&str>) -> Connect {
    Connect {
        host: address.ip().to_string(),
        port: address.port(),
        user: "tester".into(),
        password: password.map(|p| Secret::new(p.into())),
        ..Connect::default()
    }
}

/// Writes a key file into the temp folder; deleted when leaving.
struct KeyFile(PathBuf);
impl KeyFile {
    fn new(name: &str, contents: &str) -> Self {
        let path = std::env::temp_dir().join(format!("glowport-net-{}-{name}", std::process::id()));
        std::fs::write(&path, contents).unwrap();
        Self(path)
    }
}
impl Drop for KeyFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn password_login_gives_a_working_shell() {
    let running = server::start(with_password(), server::key(1)).await.unwrap();
    let mut driver = Driver::new(connect(running.address, Some("richtig")));
    driver.prompt().await;
    assert_eq!(driver.phases, [Phase::Connecting, Phase::Authenticating, Phase::Connected]);
    assert!(driver.output.contains("Willkommen beim Testserver"));
    assert!(driver.asked.is_empty(), "mit gespeichertem Passwort gibt es keine Rückfrage");

    let key = driver.host_key.clone().unwrap();
    assert_eq!(key.algorithm, "ssh-ed25519");
    assert!(key.fingerprint.starts_with("SHA256:") && key.openssh.starts_with("ssh-ed25519 "));

    // The size when connecting arrives, and so does a later change.
    driver.typed("size");
    driver.prompt().await;
    assert!(driver.output.contains("80x24"), "{}", driver.output);
    driver.send(Command::Resize(120, 40));
    driver.typed("size");
    driver.prompt().await;
    assert!(driver.output.contains("120x40"), "{}", driver.output);

    driver.typed("exit");
    assert_eq!(driver.end().await, End::Remote { exit_status: Some(0) });
}

#[tokio::test(flavor = "multi_thread")]
async fn same_server_shows_the_same_host_key_and_another_a_different_one() {
    let first = server::start(with_password(), server::key(1)).await.unwrap();
    let second = server::start(with_password(), server::key(2)).await.unwrap();
    let mut fingerprints = Vec::new();
    for address in [first.address, first.address, second.address] {
        let mut driver = Driver::new(connect(address, Some("richtig")));
        driver.prompt().await;
        fingerprints.push(driver.host_key.clone().unwrap().fingerprint);
        driver.send(Command::Close);
        assert_eq!(driver.end().await, End::User);
    }
    assert_eq!(fingerprints[0], fingerprints[1]);
    assert_ne!(fingerprints[0], fingerprints[2]);
}

#[tokio::test(flavor = "multi_thread")]
async fn rejected_host_key_stops_before_any_password_is_sent() {
    let running = server::start(with_password(), server::key(1)).await.unwrap();
    let mut driver = Driver::new(connect(running.address, Some("richtig")));
    driver.accept_host_key = false;
    assert_eq!(driver.end().await, End::HostKeyRejected);
    assert_eq!(driver.phases, [Phase::Connecting], "die Anmeldung darf gar nicht erst beginnen");
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_saved_password_leads_to_prompts() {
    let running = server::start(with_password(), server::key(1)).await.unwrap();
    let mut driver = Driver::new(connect(running.address, Some("veraltet")));
    driver.answers = [Some("vertippt"), Some("richtig")].into();
    driver.prompt().await;
    assert_eq!(driver.notices, ["saved_password_rejected"]);
    assert_eq!(driver.asked, [(SecretKind::Password, 1), (SecretKind::Password, 2)]);
    assert_eq!(driver.accepted_password.as_ref().map(|p| p.as_str()), Some("richtig"), "das funktionierende Passwort wird zum Speichern gemeldet");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_server_that_only_takes_keys_says_so_when_there_is_none() {
    // Without password sign-in, like a server with `PasswordAuthentication no`.
    let running = server::start(Options { authorized_keys: vec![server::key(7).public_key().clone()], ..Options::default() }, server::key(1)).await.unwrap();
    let mut driver = Driver::new(connect(running.address, None));
    assert_eq!(driver.end().await, End::AuthFailed);
    assert_eq!(driver.notices, ["key_required"]);
    assert!(driver.asked.is_empty(), "es gibt nichts zu fragen");

    // With a key the server does not know, the reason is a different one.
    let key = keys::generate(keys::Kind::Ed25519, 256).unwrap();
    let mut driver = Driver::new(Connect { key: Some(key.private.clone()), ..connect(running.address, None) });
    assert_eq!(driver.end().await, End::AuthFailed);
    assert_eq!(driver.notices, ["key_rejected"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn too_many_wrong_passwords_fail_and_cancel_ends_quietly() {
    let running = server::start(with_password(), server::key(1)).await.unwrap();

    let mut driver = Driver::new(connect(running.address, None));
    driver.answers = [Some("eins"), Some("zwei"), Some("drei")].into();
    assert_eq!(driver.end().await, End::AuthFailed);
    assert_eq!(driver.asked.len(), 3);
    assert!(driver.accepted_password.is_none());

    let mut driver = Driver::new(connect(running.address, None));
    driver.answers = [None].into();
    assert_eq!(driver.end().await, End::User, "Abbrechen der Rückfrage ist kein Fehler");
}

#[tokio::test(flavor = "multi_thread")]
async fn key_file_logs_in_and_asks_for_its_passphrase() {
    let public = PublicKey::from_openssh(ENCRYPTED_KEY_PUBLIC).unwrap();
    let running = server::start(Options { authorized_keys: vec![public], ..with_password() }, server::key(1)).await.unwrap();
    let file = KeyFile::new("verschluesselt", ENCRYPTED_KEY);
    let with_key = |password| Connect { key_file: Some(file.0.clone()), ..connect(running.address, password) };

    // Wrong passphrase, then the right one: sign-in via the key, without password.
    let mut driver = Driver::new(with_key(None));
    driver.answers = [Some("falsch"), Some(PASSPHRASE)].into();
    driver.prompt().await;
    let file_name = file.0.display().to_string();
    assert_eq!(driver.asked, [(SecretKind::Passphrase { file: file_name.clone() }, 1), (SecretKind::Passphrase { file: file_name }, 2)]);
    assert!(driver.accepted_password.is_none());

    // Three wrong passphrases: the key drops out, the saved password rescues the sign-in.
    let mut driver = Driver::new(with_key(Some("richtig")));
    driver.answers = [Some("a"), Some("b"), Some("c")].into();
    driver.prompt().await;
    assert_eq!(driver.notices, ["key_unreadable"]);

    // Cancelling the passphrase cancels connecting.
    let mut driver = Driver::new(with_key(Some("richtig")));
    driver.answers = [None].into();
    assert_eq!(driver.end().await, End::User);
}

#[tokio::test(flavor = "multi_thread")]
async fn unusable_or_unauthorised_key_falls_back_to_the_password() {
    let running = server::start(Options { authorized_keys: vec![server::key(9).public_key().clone()], ..with_password() }, server::key(1)).await.unwrap();

    let garbage = KeyFile::new("kaputt", "das ist kein Schlüssel");
    let mut driver = Driver::new(Connect { key_file: Some(garbage.0.clone()), ..connect(running.address, Some("richtig")) });
    driver.prompt().await;
    assert_eq!(driver.notices, ["key_unreadable"]);

    // A valid key the server does not know.
    let stranger = KeyFile::new("fremd", ENCRYPTED_KEY);
    let mut driver = Driver::new(Connect { key_file: Some(stranger.0.clone()), ..connect(running.address, Some("richtig")) });
    driver.answers = [Some(PASSPHRASE)].into();
    driver.prompt().await;
    assert_eq!(driver.notices, ["key_rejected"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn key_from_the_vault_logs_in_without_any_question() {
    let known = keys::generate(keys::Kind::Ed25519, 256).unwrap();
    let running = server::start(Options { authorized_keys: vec![PublicKey::from_openssh(&known.public).unwrap()], ..with_password() }, server::key(1)).await.unwrap();

    let mut driver = Driver::new(Connect { key: Some(known.private.clone()), ..connect(running.address, None) });
    driver.prompt().await;
    assert!(driver.asked.is_empty() && driver.notices.is_empty(), "weder Passphrase noch Passwort: {:?}", driver.notices);

    // A key the server does not know: a notice, then the saved password rescues the sign-in.
    let stranger = keys::generate(keys::Kind::Ecdsa, 256).unwrap();
    let mut driver = Driver::new(Connect { key: Some(stranger.private), ..connect(running.address, Some("richtig")) });
    driver.prompt().await;
    assert_eq!(driver.notices, ["key_rejected"]);

    // The key from the vault comes before the key file; if it fits, the file is not even read.
    let unused = KeyFile::new("unbenutzt", ENCRYPTED_KEY);
    let mut driver = Driver::new(Connect { key: Some(known.private), key_file: Some(unused.0.clone()), ..connect(running.address, None) });
    driver.prompt().await;
    assert!(driver.asked.is_empty(), "die Passphrase der Datei wird nicht gebraucht");

    let mut driver = Driver::new(Connect { key: Some(Secret::new("kaputt".into())), ..connect(running.address, Some("richtig")) });
    driver.prompt().await;
    assert_eq!(driver.notices, ["key_unreadable"]);
}

/// Home directory for the test server that disappears with the test.
struct Home(PathBuf);
impl Home {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("glowport-home-{}-{name}", std::process::id()));
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
async fn public_key_is_installed_over_ssh_and_logs_in_afterwards() {
    if std::process::Command::new("sh").arg("-c").arg("true").output().is_err() {
        eprintln!("ohne sh im Pfad übersprungen");
        return;
    }
    let home = Home::new("install");
    let running = server::start(Options { home: Some(home.0.clone()), ..with_password() }, server::key(1)).await.unwrap();
    let key = keys::generate(keys::Kind::Ed25519, 256).unwrap();
    let command = keys::install_command(&key.public, "arbeit").unwrap();

    // The server does not know the key yet.
    let mut driver = Driver::new(Connect { key: Some(key.private.clone()), ..connect(running.address, Some("richtig")) });
    driver.prompt().await;
    assert_eq!(driver.notices, ["key_rejected"]);

    // Without a stored password a prompt would be needed: that fails at once instead of waiting.
    assert_eq!(execute(&connect(running.address, None), &command, |_, _, _| true).await.unwrap_err(), End::AuthFailed);
    // Nothing is sent to a server whose key is not known.
    assert_eq!(execute(&connect(running.address, Some("richtig")), &command, |_, _, _| false).await.unwrap_err(), End::HostKeyRejected);
    assert!(!home.0.join(".ssh").exists());

    let first = execute(&connect(running.address, Some("richtig")), &command, |host, port, shown| host == "127.0.0.1" && port == running.address.port() && shown.algorithm == "ssh-ed25519").await.unwrap();
    assert_eq!((keys::install_outcome(&first.stdout), first.exit_status), (Some(keys::Installed::Added), Some(0)));
    let second = execute(&connect(running.address, Some("richtig")), &command, |_, _, _| true).await.unwrap();
    assert_eq!(keys::install_outcome(&second.stdout), Some(keys::Installed::Present));

    // Now the key alone gets in.
    let mut driver = Driver::new(Connect { key: Some(key.private), ..connect(running.address, None) });
    driver.prompt().await;
    assert!(driver.asked.is_empty() && driver.notices.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn jump_servers_are_chained_each_with_its_own_login() {
    let hop = |password: &str| Options { password: Some(("tester".into(), password.into())), forwarding: true, ..Options::default() };
    let first = server::start(hop("eins"), server::key(1)).await.unwrap();
    let second = server::start(hop("zwei"), server::key(2)).await.unwrap();
    let target = server::start(with_password(), server::key(3)).await.unwrap();
    let via = |address, password, tag: &str, jump: Option<Connect>| Connect { tag: Some(tag.into()), jump: jump.map(Box::new), ..connect(address, password) };

    // Two hops: each shows its key, each signs in with its own password, the shell runs on the destination.
    let chain = via(target.address, Some("richtig"), "ziel", Some(via(second.address, Some("zwei"), "b", Some(via(first.address, Some("eins"), "a", None)))));
    let mut driver = Driver::new(chain);
    driver.prompt().await;
    assert_eq!(driver.host_keys.iter().map(|(_, port, _)| *port).collect::<Vec<_>>(), [first.address.port(), second.address.port(), target.address.port()]);
    assert_eq!(driver.host_keys[2].2, server::key(3).public_key().fingerprint(Default::default()).to_string(), "der Schlüssel des Ziels, nicht der einer Station");
    assert!(driver.asked.is_empty());
    driver.typed("exit");
    assert_eq!(driver.end().await, End::Remote { exit_status: Some(0) });

    // If a hop lacks its password, exactly that hop is asked.
    let mut driver = Driver::new(via(target.address, Some("richtig"), "ziel", Some(via(first.address, None, "a", None))));
    driver.answers = [Some("eins")].into();
    driver.prompt().await;
    assert_eq!(driver.stations, [Station { label: format!("tester@127.0.0.1:{}", first.address.port()), tag: Some("a".into()) }]);

    // If a hop's key is not trusted, the connection does not come about; the destination is never asked.
    let mut driver = Driver::new(via(target.address, Some("richtig"), "ziel", Some(via(first.address, Some("eins"), "a", None))));
    driver.distrust = vec![first.address.port()];
    assert_eq!(driver.end().await, End::HostKeyRejected);
    assert_eq!(driver.host_keys.len(), 1);

    // A hop that does not forward, or a destination that cannot be reached from it.
    let closed = server::start(with_password(), server::key(4)).await.unwrap();
    let mut driver = Driver::new(via(target.address, Some("richtig"), "ziel", Some(via(closed.address, Some("richtig"), "zu", None))));
    assert!(matches!(driver.end().await, End::ConnectFailed(_)));
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let nowhere = listener.local_addr().unwrap();
    drop(listener);
    let mut driver = Driver::new(via(nowhere, Some("richtig"), "ziel", Some(via(first.address, Some("eins"), "a", None))));
    assert!(matches!(driver.end().await, End::ConnectFailed(_)));
}

#[tokio::test(flavor = "multi_thread")]
async fn start_command_and_environment_reach_the_shell() {
    let running = server::start(with_password(), server::key(1)).await.unwrap();
    let env = vec![("LANG".to_string(), "de_DE.UTF-8".to_string()), ("STUFE".to_string(), "test".to_string())];
    let mut driver = Driver::new(Connect { startcmd: Some("  env  ".into()), env, ..connect(running.address, Some("richtig")) });
    // The greeting ends with the prompt, after which Glowport types the startup command.
    assert_eq!(driver.until(|d| d.output.contains("STUFE=test") && d.output.ends_with(PROMPT)).await, None);
    assert!(driver.output.contains("LANG=de_DE.UTF-8"), "{}", driver.output);
}

/// An agent of its own for tests on a pipe of its own, so the machine's agent stays untouched.
#[cfg(windows)]
async fn start_agent(name: &str, keys: &[russh::keys::PrivateKey]) -> glowport_net::Agents {
    use russh::keys::agent::{client::AgentClient, server::serve};
    use tokio::net::windows::named_pipe::ServerOptions;

    let path = format!(r"\\.\pipe\glowport-test-{}-{name}", std::process::id());
    let first = ServerOptions::new().first_pipe_instance(true).create(&path).unwrap();
    // Every connection gets its own instance of the pipe; the next is ready before the current one is handed over.
    let connections = futures::stream::unfold((first, path.clone()), |(waiting, path)| async move {
        waiting.connect().await.ok()?;
        let next = ServerOptions::new().create(&path).ok()?;
        Some((Ok::<_, std::io::Error>(waiting), (next, path)))
    });
    tokio::spawn(serve(Box::pin(connections), ()));
    let mut client = AgentClient::connect_named_pipe(&path).await.unwrap();
    for key in keys {
        client.add_identity(key, &[]).await.unwrap();
    }
    glowport_net::Agents { openssh: Some(path), pageant: false }
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread")]
async fn agent_keys_log_in_and_the_agent_can_be_forwarded() {
    let (known, other) = (server::key(7), server::key(8));
    let agents = start_agent("anmelden", &[other.clone(), known.clone()]).await;
    let running = server::start(Options { authorized_keys: vec![known.public_key().clone()], ..with_password() }, server::key(1)).await.unwrap();

    // What the agent offers can be listed without a key leaving it.
    let listed = glowport_net::agent::list(&agents).await;
    assert_eq!(listed.iter().map(|a| (a.kind, a.running, a.keys.len())).collect::<Vec<_>>(), [(glowport_net::agent::Kind::OpenSsh, true, 2), (glowport_net::agent::Kind::Pageant, false, 0)]);
    assert!(listed[0].keys.iter().any(|k| k.label == "Ed25519" && k.fingerprint == known.public_key().fingerprint(Default::default()).to_string()));

    // The server only knows the agent's second key: the first is refused, the second gets in.
    let mut driver = Driver::new(Connect { agent: Some(agents.clone()), ..connect(running.address, None) });
    driver.prompt().await;
    assert!(driver.asked.is_empty(), "keine Rückfrage, der Agent unterschreibt");
    // Without forwarding the server sees no agent.
    driver.typed("agent");
    driver.prompt().await;
    assert!(driver.output.contains("kein Agent"), "{}", driver.output);

    // With forwarding the server can query the agent.
    let mut driver = Driver::new(Connect { agent: Some(agents.clone()), agent_forward: true, ..connect(running.address, None) });
    driver.prompt().await;
    driver.typed("agent");
    driver.prompt().await;
    assert!(driver.output.contains(&known.public_key().fingerprint(Default::default()).to_string()), "{}", driver.output);

    // There is no forwarding without an agent, even if it is switched on.
    let mut driver = Driver::new(Connect { agent_forward: true, ..connect(running.address, Some("richtig")) });
    driver.prompt().await;
    driver.typed("agent");
    driver.prompt().await;
    assert!(driver.output.contains("kein Agent"));

    // If no agent runs, it quietly continues with the other ways.
    let nowhere = glowport_net::Agents { openssh: Some(format!(r"\\.\pipe\glowport-test-{}-fehlt", std::process::id())), pageant: false };
    assert!(glowport_net::agent::list(&nowhere).await.iter().all(|a| !a.running));
    let mut driver = Driver::new(Connect { agent: Some(nowhere), ..connect(running.address, Some("richtig")) });
    driver.prompt().await;
    assert!(driver.notices.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn old_devices_need_the_legacy_setting() {
    let old = server::start(Options { legacy_only: true, ..with_password() }, server::key(1)).await.unwrap();
    let mut driver = Driver::new(connect(old.address, Some("richtig")));
    assert!(matches!(driver.end().await, End::ConnectFailed(_)), "ohne die Einstellung gibt es kein gemeinsames Verfahren");

    let mut driver = Driver::new(Connect { legacy: true, term: "vt100".into(), ..connect(old.address, Some("richtig")) });
    driver.prompt().await;
    driver.typed("term");
    driver.prompt().await;
    assert!(driver.output.contains("vt100"), "{}", driver.output);

    // The setting does no harm with a current server.
    let modern = server::start(with_password(), server::key(2)).await.unwrap();
    let mut driver = Driver::new(Connect { legacy: true, keepalive: Duration::ZERO, ..connect(modern.address, Some("richtig")) });
    driver.prompt().await;
    driver.typed("term");
    driver.prompt().await;
    assert!(driver.output.contains("xterm-256color"));
}

/// Tiny proxy for tests: accepts a connection, reads the destination by the rules of `kind` and passes through.
/// With `-auth` at the end it requires the sign-in `tester` / `geheim`.
async fn start_proxy(kind: &'static str) -> (std::net::SocketAddr, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = std::sync::Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            let log = std::sync::Arc::clone(&log);
            tokio::spawn(async move {
                let target = if kind.starts_with("http") {
                    let mut head = Vec::new();
                    while !head.ends_with(b"\r\n\r\n") {
                        head.push(client.read_u8().await.ok()?);
                    }
                    let head = String::from_utf8_lossy(&head).to_string();
                    let line = head.lines().next()?.to_string();
                    let target = line.strip_prefix("CONNECT ")?.split(' ').next()?.to_string();
                    if kind == "http-auth" && !head.contains("Proxy-Authorization: Basic dGVzdGVyOmdlaGVpbQ==\r\n") {
                        client.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n").await.ok()?;
                        return None;
                    }
                    if target.starts_with("verboten") {
                        client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await.ok()?;
                        return None;
                    }
                    client.write_all(b"HTTP/1.1 200 Connection established\r\nVia: test\r\n\r\n").await.ok()?;
                    target
                } else {
                    let mut greeting = [0u8; 2];
                    client.read_exact(&mut greeting).await.ok()?;
                    let mut methods = vec![0u8; usize::from(greeting[1])];
                    client.read_exact(&mut methods).await.ok()?;
                    if kind == "socks5-auth" {
                        if !methods.contains(&2) {
                            client.write_all(&[5, 0xFF]).await.ok()?;
                            return None;
                        }
                        client.write_all(&[5, 2]).await.ok()?;
                        let version = client.read_u8().await.ok()?;
                        let mut user = vec![0u8; usize::from(client.read_u8().await.ok()?)];
                        client.read_exact(&mut user).await.ok()?;
                        let mut password = vec![0u8; usize::from(client.read_u8().await.ok()?)];
                        client.read_exact(&mut password).await.ok()?;
                        let fine = version == 1 && user == b"tester" && password == b"geheim";
                        client.write_all(&[1, u8::from(!fine)]).await.ok()?;
                        if !fine {
                            return None;
                        }
                    } else {
                        client.write_all(&[5, 0]).await.ok()?;
                    }
                    let mut head = [0u8; 5];
                    client.read_exact(&mut head).await.ok()?;
                    let mut name = vec![0u8; usize::from(head[4])];
                    client.read_exact(&mut name).await.ok()?;
                    let port = client.read_u16().await.ok()?;
                    client.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).await.ok()?;
                    format!("{}:{port}", String::from_utf8_lossy(&name))
                };
                log.lock().unwrap().push(target.clone());
                let mut server = tokio::net::TcpStream::connect(target.replace("localhost", "127.0.0.1")).await.ok()?;
                tokio::io::copy_bidirectional(&mut client, &mut server).await.ok()?;
                Some(())
            });
        }
    });
    (address, seen)
}

#[tokio::test(flavor = "multi_thread")]
async fn connections_go_through_http_and_socks_proxies() {
    let running = server::start(with_password(), server::key(1)).await.unwrap();
    for kind in ["http", "socks5"] {
        let (proxy, seen) = start_proxy(kind).await;
        let proxy = if kind == "http" { Proxy::Http { host: "127.0.0.1".into(), port: proxy.port(), login: None } } else { Proxy::Socks5 { host: "127.0.0.1".into(), port: proxy.port(), login: None } };
        // The name goes to the proxy unresolved.
        let mut driver = Driver::new(Connect { host: "localhost".into(), proxy: Some(proxy), ..connect(running.address, Some("richtig")) });
        driver.prompt().await;
        assert_eq!(*seen.lock().unwrap(), [format!("localhost:{}", running.address.port())], "{kind}");
        driver.typed("exit");
        assert_eq!(driver.end().await, End::Remote { exit_status: Some(0) });
    }

    // If the proxy refuses or does not exist, the connection does not come about.
    let (proxy, _) = start_proxy("http").await;
    let mut driver = Driver::new(Connect { host: "verboten.test".into(), proxy: Some(Proxy::Http { host: "127.0.0.1".into(), port: proxy.port(), login: None }), ..connect(running.address, Some("richtig")) });
    let End::ConnectFailed(reason) = driver.end().await else { panic!("Ablehnung erwartet") };
    assert!(reason.contains("403"), "{reason}");
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let gone = listener.local_addr().unwrap().port();
    drop(listener);
    let mut driver = Driver::new(Connect { proxy: Some(Proxy::Socks5 { host: "127.0.0.1".into(), port: gone, login: None }), ..connect(running.address, Some("richtig")) });
    assert!(matches!(driver.end().await, End::ConnectFailed(_)));

    // Proxies that require authentication: in with the right details, not without or with wrong ones.
    let login = |password: &str| Some(Login { user: "tester".into(), password: Secret::new(password.into()) });
    for kind in ["http-auth", "socks5-auth"] {
        let (address, _) = start_proxy(kind).await;
        let proxy = |login: Option<Login>| if kind == "http-auth" { Proxy::Http { host: "127.0.0.1".into(), port: address.port(), login } } else { Proxy::Socks5 { host: "127.0.0.1".into(), port: address.port(), login } };
        let mut driver = Driver::new(Connect { proxy: Some(proxy(login("geheim"))), ..connect(running.address, Some("richtig")) });
        driver.prompt().await;
        for wrong in [login("falsch"), None] {
            let mut driver = Driver::new(Connect { proxy: Some(proxy(wrong)), ..connect(running.address, Some("richtig")) });
            assert!(matches!(driver.end().await, End::ConnectFailed(_)), "{kind}");
        }
    }
    assert!(!format!("{:?}", login("geheim")).contains("geheim"), "das Passwort steht nicht in Protokollen");
}

/// Issues a user certificate the way a certificate authority would with `ssh-keygen -s`.
fn certificate(ca: &russh::keys::PrivateKey, subject: &keys::Material, principal: &str, valid: std::ops::Range<u64>) -> String {
    use russh::keys::ssh_key::certificate::{Builder, CertType};
    let subject = PublicKey::from_openssh(&subject.public).unwrap();
    let mut builder = Builder::new_with_random_nonce(&mut rand::rng(), subject.key_data().clone(), valid.start, valid.end).unwrap();
    builder.cert_type(CertType::User).unwrap().key_id("test-zertifikat").unwrap().valid_principal(principal).unwrap();
    builder.sign(ca).unwrap().to_openssh().unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn certificates_log_in_where_only_the_authority_is_trusted() {
    let ca = server::key(20);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let running = server::start(Options { user_ca: Some(ca.public_key().clone()), ..with_password() }, server::key(1)).await.unwrap();
    let key = keys::generate(keys::Kind::Ed25519, 256).unwrap();
    let with = |certificate: &str, password| Connect { key: Some(key.private.clone()), certificate: Some(certificate.into()), ..connect(running.address, password) };

    // The server does not know the key, only the authority that certified it.
    let good = certificate(&ca, &key, "tester", now - 60..now + 3600);
    let info = keys::inspect_certificate(&format!("{good} kommentar"), &key.public).unwrap();
    assert_eq!((info.key_id.as_str(), info.principals.as_slice(), info.valid_before), ("test-zertifikat", ["tester".to_string()].as_slice(), Some(now + 3600)));
    assert_eq!(info.authority, ca.public_key().fingerprint(Default::default()).to_string());
    assert_eq!(info.text.split(' ').count(), 2, "ohne Kommentar abgelegt");
    let mut driver = Driver::new(with(&info.text, None));
    driver.prompt().await;
    assert!(driver.asked.is_empty() && driver.notices.is_empty());

    // Expired, for another user or from a foreign authority: refused, the password rescues the sign-in.
    let stranger = server::key(21);
    for bad in [certificate(&ca, &key, "tester", now - 7200..now - 3600), certificate(&ca, &key, "root", now - 60..now + 3600), certificate(&stranger, &key, "tester", now - 60..now + 3600)] {
        let mut driver = Driver::new(with(&bad, Some("richtig")));
        driver.prompt().await;
        assert_eq!(driver.notices, ["certificate_rejected", "key_rejected"]);
    }

    // A certificate for a different key is not even stored.
    let other = keys::generate(keys::Kind::Ed25519, 256).unwrap();
    assert_eq!(keys::inspect_certificate(&good, &other.public).unwrap_err(), keys::KeyError::CertificateMismatch);
    assert_eq!(keys::inspect_certificate("kein Zertifikat", &key.public).unwrap_err(), keys::KeyError::CertificateUnreadable);
}

#[tokio::test(flavor = "multi_thread")]
async fn servers_certified_by_a_trusted_authority_need_no_question() {
    use russh::keys::ssh_key::certificate::{Builder, CertType};
    let (ca, host_key) = (server::key(30), server::key(1));
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let issue = |signer: &russh::keys::PrivateKey, name: &str, valid: std::ops::Range<u64>| {
        let mut builder = Builder::new_with_random_nonce(&mut rand::rng(), host_key.public_key().key_data().clone(), valid.start, valid.end).unwrap();
        builder.cert_type(CertType::Host).unwrap().key_id("test-server").unwrap().valid_principal(name).unwrap();
        builder.sign(signer).unwrap()
    };
    let trusted = vec![ca.public_key().to_openssh().unwrap()];
    assert_eq!(keys::inspect_public(&format!("{} unsere-ca", trusted[0])).unwrap().fingerprint, ca.public_key().fingerprint(Default::default()).to_string());

    // Valid certificate from the trusted authority for this address: no prompt about the key.
    let good = server::start(Options { host_certificate: Some(issue(&ca, "127.0.0.1", now - 60..now + 3600)), ..with_password() }, host_key.clone()).await.unwrap();
    let mut driver = Driver::new(Connect { authorities: trusted.clone(), ..connect(good.address, Some("richtig")) });
    driver.prompt().await;
    assert!(driver.host_keys.is_empty(), "das Zertifikat hat genügt");

    // Whoever trusts no authority is shown the bare key as always.
    let mut driver = Driver::new(connect(good.address, Some("richtig")));
    driver.prompt().await;
    assert_eq!(driver.host_keys.len(), 1);

    // Issued for another name, expired or from a foreign authority: the certificate does not count, the user is asked.
    let stranger = server::key(31);
    for bad in [issue(&ca, "anderswo.test", now - 60..now + 3600), issue(&ca, "127.0.0.1", now - 7200..now - 3600), issue(&stranger, "127.0.0.1", now - 60..now + 3600)] {
        let running = server::start(Options { host_certificate: Some(bad), ..with_password() }, host_key.clone()).await.unwrap();
        let mut driver = Driver::new(Connect { authorities: trusted.clone(), ..connect(running.address, Some("richtig")) });
        driver.prompt().await;
        assert_eq!(driver.host_keys.len(), 1);
        assert_eq!(driver.host_keys[0].2, host_key.public_key().fingerprint(Default::default()).to_string());

        let mut driver = Driver::new(Connect { authorities: trusted.clone(), ..connect(running.address, Some("richtig")) });
        driver.accept_host_key = false;
        assert_eq!(driver.end().await, End::HostKeyRejected);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn unreachable_server_fails_to_connect() {
    // A port someone was listening on a moment ago and now nobody is.
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let mut driver = Driver::new(connect(address, Some("richtig")));
    assert!(matches!(driver.end().await, End::ConnectFailed(_)));
    assert_eq!(driver.phases, [Phase::Connecting]);
}

#[tokio::test(flavor = "multi_thread")]
async fn dropped_connection_is_reported_as_lost() {
    let running = server::start(with_password(), server::key(1)).await.unwrap();
    let mut driver = Driver::new(connect(running.address, Some("richtig")));
    driver.prompt().await;
    driver.typed("drop");
    assert!(matches!(driver.end().await, End::ConnectionLost(_)));
}

#[tokio::test(flavor = "multi_thread")]
async fn closing_works_at_any_time() {
    let running = server::start(with_password(), server::key(1)).await.unwrap();

    // While a prompt is open.
    let mut driver = Driver::new(connect(running.address, None));
    assert_eq!(driver.until(|d| d.phases.contains(&Phase::Authenticating)).await, None);
    driver.send(Command::Close);
    driver.answers = [Some("richtig")].into();
    assert_eq!(driver.end().await, End::User);

    // In the middle of the session.
    let mut driver = Driver::new(connect(running.address, Some("richtig")));
    driver.prompt().await;
    driver.send(Command::Close);
    assert_eq!(driver.end().await, End::User);
}

#[tokio::test(flavor = "multi_thread")]
async fn pausing_holds_output_back_until_resumed() {
    let running = server::start(with_password(), server::key(1)).await.unwrap();
    let mut driver = Driver::new(connect(running.address, Some("richtig")));
    driver.prompt().await;

    driver.send(Command::Pause(true));
    driver.typed("size");
    let waited = timeout(Duration::from_millis(400), driver.until(|d| d.output.contains("80x24"))).await;
    assert!(waited.is_err(), "angehalten darf nichts ankommen");

    driver.send(Command::Pause(false));
    assert_eq!(driver.until(|d| d.output.contains("80x24")).await, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn banner_and_operating_system_are_reported() {
    let options = Options { banner: Some("Zutritt nur für Befugte\u{7}\n".into()), exec_output: Some("Linux\nID=ubuntu\nID_LIKE=debian\n".into()), ..with_password() };
    let running = server::start(options, server::key(1)).await.unwrap();
    let mut driver = Driver::new(Connect { detect_os: true, ..connect(running.address, Some("richtig")) });
    assert_eq!(driver.until(|d| d.os.is_some()).await, None);
    assert_eq!(driver.os.as_deref(), Some("Ub"));
    assert_eq!(driver.banner.as_deref(), Some("Zutritt nur für Befugte\n"), "Steuerzeichen werden entfernt");

    // A server that refuses the query does not disturb the session.
    let plain = server::start(with_password(), server::key(1)).await.unwrap();
    let mut driver = Driver::new(Connect { detect_os: true, ..connect(plain.address, Some("richtig")) });
    driver.prompt().await;
    driver.typed("size");
    driver.prompt().await;
    assert_eq!(driver.os, None);
}

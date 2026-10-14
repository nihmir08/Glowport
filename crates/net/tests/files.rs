//! Files over SFTP against the own test server.

use std::{
    path::PathBuf,
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};

use glowport_net::files::{self, Change, FileError, Kind, Remote};
use glowport_net::{open, Command, Connect, End, Event, Phase, Secret};
use glowport_testserver::{self as server, sftp::HOME, Options, Running};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::oneshot,
    time::timeout,
};

static SEQ: AtomicU32 = AtomicU32::new(0);

/// An empty folder serving as the server's file system. It disappears with the test.
struct Root(PathBuf);

impl Root {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("glowport-sftp-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed)));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("folder for the test");
        Root(path)
    }

    /// Path on this machine for a path in the server's file system.
    fn local(&self, path: &str) -> PathBuf {
        path.split('/').filter(|part| !part.is_empty()).fold(self.0.clone(), |at, part| at.join(part))
    }

    fn put(&self, path: &str, content: &[u8]) {
        let local = self.local(path);
        std::fs::create_dir_all(local.parent().expect("folder above")).expect("create folder");
        std::fs::write(local, content).expect("write file");
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn serve(root: &Root, options: Options) -> Running {
    let options = Options { password: Some(("tester".into(), "richtig".into())), files: Some(root.0.clone()), ..options };
    server::start(options, server::key(1)).await.expect("Testserver")
}

fn target(running: &Running) -> Connect {
    Connect { host: "127.0.0.1".into(), port: running.address.port(), user: "tester".into(), password: Some(Secret::new("richtig".into())), detect_os: false, ..Connect::default() }
}

async fn remote(running: &Running) -> Remote {
    Remote::connect(&target(running), |_, _, _| true).await.expect("SFTP connection")
}

#[tokio::test]
async fn lists_a_folder_with_kinds_sizes_and_owner_names() {
    let root = Root::new();
    root.put("/etc/passwd", b"root:x:0:0:root:/root:/bin/bash\ntester:x:1000:1000::/home/tester:/bin/sh\n");
    root.put("/etc/group", b"root:x:0:\nstaff:x:1000:tester\n");
    root.put("/srv/data/notes.txt", b"hallo");
    std::fs::create_dir_all(root.local("/srv/data/sub")).unwrap();
    let running = serve(&root, Options::default()).await;
    let remote = remote(&running).await;

    assert_eq!(remote.home().await.unwrap(), HOME);
    assert_eq!(remote.resolve("/srv/./data/sub/..").await.unwrap(), "/srv/data");

    let mut entries = remote.list("/srv/data").await.unwrap();
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    assert_eq!(entries.iter().map(|e| (e.name.as_str(), e.kind)).collect::<Vec<_>>(), [("notes.txt", Kind::File), ("sub", Kind::Dir)]);
    let notes = &entries[0];
    assert_eq!((notes.size, notes.mode, notes.owner.as_str(), notes.group.as_str()), (5, 0o644, "tester", "staff"));
    assert!(notes.modified > 1_600_000_000, "modification time missing: {}", notes.modified);
    assert_eq!(entries[1].mode, 0o755);

    assert_eq!(remote.list("/does/not/exist").await, Err(FileError::NoSuchFile));
}

#[tokio::test]
async fn creates_renames_and_removes_even_full_folders() {
    let root = Root::new();
    let running = serve(&root, Options::default()).await;
    let remote = remote(&running).await;

    remote.mkdir("/srv").await.unwrap();
    remote.mkdir("/srv/old").await.unwrap();
    remote.write("/srv/old/a.txt", b"one").await.unwrap();
    remote.mkdir("/srv/old/deep").await.unwrap();
    remote.write("/srv/old/deep/b.txt", b"two").await.unwrap();

    remote.rename("/srv/old", "/srv/new").await.unwrap();
    assert!(!root.local("/srv/old").exists());
    assert_eq!(std::fs::read(root.local("/srv/new/deep/b.txt")).unwrap(), b"two");
    // Renaming overwrites nothing.
    remote.write("/srv/x.txt", b"x").await.unwrap();
    assert!(matches!(remote.rename("/srv/x.txt", "/srv/new").await, Err(FileError::Failure(_))));

    remote.remove("/srv/x.txt").await.unwrap();
    remote.remove("/srv/new").await.unwrap();
    assert!(!root.local("/srv/new").exists());
    assert_eq!(remote.remove("/srv/new").await, Err(FileError::NoSuchFile));
}

#[tokio::test]
async fn changes_mode_and_owner_also_for_everything_inside() {
    let root = Root::new();
    root.put("/etc/passwd", b"tester:x:1000:1000::/home/tester:/bin/sh\nwww-data:x:33:33::/var/www:/usr/sbin/nologin\n");
    root.put("/etc/group", b"tester:x:1000:\nwww-data:x:33:\n");
    root.put("/srv/app/index.html", b"<html>");
    root.put("/srv/app/css/site.css", b"body{}");
    let running = serve(&root, Options::default()).await;
    let files = running.files.clone().unwrap();
    let remote = remote(&running).await;

    remote.change("/srv/app/index.html", &Change { mode: Some(0o600), ..Change::default() }, false).await.unwrap();
    assert_eq!(files.mode("/srv/app/index.html"), Some(0o600));
    assert_eq!(files.mode("/srv/app/css/site.css"), None, "without “also inside” the rest stays untouched");

    remote.change("/srv/app", &Change { mode: Some(0o750), owner: Some("www-data".into()), group: None }, true).await.unwrap();
    assert_eq!(files.mode("/srv/app/css/site.css"), Some(0o750));
    let entry = remote.stat("/srv/app/css/site.css", true).await.unwrap();
    assert_eq!((entry.owner.as_str(), entry.group.as_str(), entry.uid, entry.gid), ("www-data", "tester", 33, 1000));

    let unknown = remote.change("/srv/app", &Change { owner: Some("nobody-who-exists".into()), ..Change::default() }, false).await;
    assert!(matches!(unknown, Err(FileError::Failure(_))), "{unknown:?}");
}

#[tokio::test]
async fn reads_with_a_limit_and_writes_back() {
    let root = Root::new();
    root.put("/etc/hosts", b"127.0.0.1 localhost\n");
    let running = serve(&root, Options::default()).await;
    let remote = remote(&running).await;

    assert_eq!(remote.read("/etc/hosts", 1024).await.unwrap(), (b"127.0.0.1 localhost\n".to_vec(), false));
    assert_eq!(remote.read("/etc/hosts", 9).await.unwrap(), (b"127.0.0.1".to_vec(), true));

    remote.write("/etc/hosts", b"short\n").await.unwrap();
    assert_eq!(std::fs::read(root.local("/etc/hosts")).unwrap(), b"short\n", "the old, longer content must be gone");
}

#[tokio::test]
async fn continues_a_file_from_an_offset_in_both_directions() {
    let root = Root::new();
    let content: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    root.put("/srv/gross.bin", &content);
    let running = serve(&root, Options::default()).await;
    let remote = remote(&running).await;

    // Downloading from the middle.
    let mut rest = Vec::new();
    remote.reader("/srv/gross.bin", 120_000).await.unwrap().read_to_end(&mut rest).await.unwrap();
    assert_eq!(rest, &content[120_000..]);

    // Uploading: first a piece, then the rest from there.
    let mut first = remote.writer("/srv/kopie.bin", 0).await.unwrap();
    first.write_all(&content[..70_000]).await.unwrap();
    first.shutdown().await.unwrap();
    drop(first);
    assert_eq!(remote.stat("/srv/kopie.bin", true).await.unwrap().size, 70_000);
    let mut second = remote.writer("/srv/kopie.bin", 70_000).await.unwrap();
    second.write_all(&content[70_000..]).await.unwrap();
    second.shutdown().await.unwrap();
    drop(second);
    assert_eq!(std::fs::read(root.local("/srv/kopie.bin")).unwrap(), content);

    remote.touch("/srv/kopie.bin", 1_700_000_000).await.unwrap();
    assert_eq!(remote.stat("/srv/kopie.bin", true).await.unwrap().modified, 1_700_000_000);
}

#[tokio::test]
async fn reports_folders_that_must_not_be_changed() {
    let root = Root::new();
    root.put("/etc/fstab", b"# empty\n");
    let running = serve(&root, Options { files_read_only: vec!["/etc".into()], ..Options::default() }).await;
    let remote = remote(&running).await;

    assert_eq!(remote.write("/etc/fstab", b"kaputt").await, Err(FileError::PermissionDenied));
    assert_eq!(remote.mkdir("/etc/new").await, Err(FileError::PermissionDenied));
    assert_eq!(remote.remove("/etc/fstab").await, Err(FileError::PermissionDenied));
    assert_eq!(remote.change("/etc/fstab", &Change { mode: Some(0o777), ..Change::default() }, false).await, Err(FileError::PermissionDenied));
    assert_eq!(std::fs::read(root.local("/etc/fstab")).unwrap(), b"# empty\n");
    assert_eq!(FileError::PermissionDenied.code(), "permission_denied");
}

#[tokio::test]
async fn refuses_to_connect_when_stored_credentials_do_not_suffice() {
    let root = Root::new();
    let running = serve(&root, Options::default()).await;
    let wrong = Connect { password: Some(Secret::new("falsch".into())), ..target(&running) };
    assert!(matches!(Remote::connect(&wrong, |_, _, _| true).await, Err(End::AuthFailed)));
    assert!(matches!(Remote::connect(&target(&running), |_, _, _| false).await, Err(End::HostKeyRejected)));
}

#[tokio::test]
async fn connects_for_files_alone_and_asks_like_a_terminal_would() {
    let root = Root::new();
    root.put("/srv/da.txt", b"here");
    let running = serve(&root, Options::default()).await;
    // No password stored: first comes the server's key, then the question for the password.
    let mut session = files::open(Connect { password: None, ..target(&running) });
    let mut asked = Vec::new();
    let remote = loop {
        match timeout(Duration::from_secs(10), session.events.recv()).await.expect("nichts geschah") {
            Some(Event::HostKey { reply, .. }) => {
                asked.push("key");
                reply.send(true).unwrap();
            }
            Some(Event::Secret { attempt, reply, .. }) => {
                asked.push(if attempt == 1 { "password" } else { "again" });
                reply.send(Some(Secret::new(if attempt == 1 { "falsch" } else { "richtig" }.into()))).unwrap();
            }
            Some(Event::Files(found)) => break found,
            Some(Event::End(end)) => panic!("endete: {end:?}"),
            Some(_) => {}
            None => panic!("stream ended without a result"),
        }
    };
    assert_eq!(asked, ["key", "password", "again"]);
    assert_eq!(remote.read("/srv/da.txt", 100).await.unwrap().0, b"here");

    // If the user cancels the prompt, it ends as ended by the user; likewise if they close in between.
    let mut session = files::open(Connect { password: None, ..target(&running) });
    let end = loop {
        match timeout(Duration::from_secs(10), session.events.recv()).await.expect("nothing happened").expect("stream ended without an end") {
            Event::HostKey { reply, .. } => reply.send(true).unwrap(),
            Event::Secret { reply, .. } => reply.send(None).unwrap(),
            Event::End(end) => break end,
            _ => {}
        }
    };
    assert_eq!(end, End::User);
    let mut session = files::open(Connect { password: None, ..target(&running) });
    let end = loop {
        match timeout(Duration::from_secs(10), session.events.recv()).await.expect("nothing happened").expect("stream ended without an end") {
            // The question stays unanswered; instead it is closed.
            Event::HostKey { reply, .. } => {
                session.commands.send(Command::Close).unwrap();
                std::mem::forget(reply);
            }
            Event::End(end) => break end,
            _ => {}
        }
    };
    assert_eq!(end, End::User);
}

#[tokio::test]
async fn says_so_when_the_server_has_no_sftp() {
    let running = server::start(Options { password: Some(("tester".into(), "richtig".into())), ..Options::default() }, server::key(1)).await.unwrap();
    assert!(matches!(Remote::connect(&target(&running), |_, _, _| true).await, Err(End::ConnectFailed(reason)) if reason == "sftp: not_supported"));
}

#[tokio::test]
async fn opens_sftp_and_runs_commands_on_the_connection_of_a_terminal() {
    let root = Root::new();
    root.put("/srv/da.txt", b"here");
    let running = serve(&root, Options { exec_output: Some("antwort\n".into()), ..Options::default() }).await;
    let mut session = open(target(&running));

    // Before the shell there is no additional channel.
    let (reply, early) = oneshot::channel();
    session.commands.send(Command::Open(reply)).unwrap();

    loop {
        match timeout(Duration::from_secs(10), session.events.recv()).await.expect("nothing happened").expect("session ended") {
            Event::HostKey { reply, .. } => drop(reply.send(true)),
            Event::Phase(Phase::Connected) => break,
            Event::End(end) => panic!("session ended: {end:?}"),
            _ => {}
        }
    }
    assert!(early.await.unwrap().is_none());

    let (reply, opened) = oneshot::channel();
    session.commands.send(Command::Open(reply)).unwrap();
    let remote = Remote::on(opened.await.unwrap().expect("additional channel")).await.unwrap();
    assert_eq!(remote.read("/srv/da.txt", 100).await.unwrap().0, b"here");

    let (reply, opened) = oneshot::channel();
    session.commands.send(Command::Open(reply)).unwrap();
    let output = files::run(opened.await.unwrap().unwrap(), "irgendwas").await.unwrap();
    assert_eq!(output.stdout, b"antwort\n");

    // The terminal keeps running next to it.
    session.commands.send(Command::Input(b"exit\r".to_vec())).unwrap();
    loop {
        if let Event::End(end) = timeout(Duration::from_secs(10), session.events.recv()).await.expect("nothing happened").expect("session disappeared") {
            break assert!(matches!(end, End::Remote { .. }), "{end:?}");
        }
    }
}

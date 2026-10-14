//! Starts the test server as a program of its own, for the end-to-end test of the executable.
//!
//! Listens on a free port of 127.0.0.1 and names the address in the first line of output. The second
//! line names the simulated Proxmox server running alongside: `pve <address> <fingerprint of its certificate>`.
//! Sign-in: user `tester`, password `right`. The first argument optionally names a home directory:
//! whoever owns a key from `.ssh/authorized_keys` inside it gets in without a password, and commands run
//! via `sh` with this folder as `$HOME` (needs `sh` on the path, on Windows e.g. from Git). The second argument
//! optionally names the file with a certificate authority's private key (without passphrase): its
//! user certificates are valid, and the server shows clients that ask for it a certificate from it for `127.0.0.1`.
//! The third and fourth lines name two FTP servers (`ftp <address>`, `ftps <address> <fingerprint>`; sign-in as
//! above) on a folder with a small web space or on the one `GLOWPORT_TEST_FTP` names.
//! If the environment variable `GLOWPORT_TEST_FILES` names a folder, the server shows it over SFTP as its file system;
//! nothing may be changed under `/etc` there.
//! If `GLOWPORT_TEST_MOSH` names a WSL distribution with mosh, the server starts `mosh-server` there and forwards UDP
//! via `127.0.0.1`; the fifth line then reads `mosh <address in WSL>`, otherwise `mosh -`. The line
//! `mosh pause` on input pauses the forwarder (dropout), `mosh resume` lets it continue.

use glowport_testserver::{host_certificate, key, start, Options};
use russh::keys::PrivateKey;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let ca = std::env::args().nth(2).and_then(|path| std::fs::read_to_string(path).ok()).and_then(|text| PrivateKey::from_openssh(text).ok());
    let options = Options {
        password: Some(("tester".into(), "right".into())),
        banner: Some("Glowport test server\n".into()),
        exec_output: Some("Linux\nID=ubuntu\nID_LIKE=debian\n".into()),
        home: std::env::args_os().nth(1).map(Into::into),
        user_ca: ca.as_ref().map(|ca| ca.public_key().clone()),
        host_certificate: ca.as_ref().and_then(|ca| host_certificate(ca, &key(1), "127.0.0.1")),
        forwarding: true,
        files: std::env::var_os("GLOWPORT_TEST_FILES").map(Into::into),
        files_read_only: vec!["/etc".into()],
        // For the sidebar: a Linux with Docker and systemd, which the test machine does not have.
        admin: Some(Default::default()),
        ..Options::default()
    };
    let bridge = std::env::var("GLOWPORT_TEST_MOSH").ok().and_then(|distro| glowport_testserver::mosh::Bridge::find(&distro));
    let options = Options { mosh: bridge.clone(), ..options };
    let running = start(options, key(1)).await?;
    println!("{}", running.address);
    // As with Proxmox, the list of machines still names the old state for a while after switching.
    let pve = glowport_testserver::pve::start_lagging(std::time::Duration::from_secs(8)).await?;
    println!("pve {} {}", pve.address, glowport_testserver::pve::fingerprint_text(&pve.fingerprint));
    // Two FTP servers on the same folder: one plain, one over FTPS with a self-signed certificate.
    let scratch = std::env::temp_dir().join(format!("glowport-testserver-{}", std::process::id()));
    let root = match std::env::var_os("GLOWPORT_TEST_FTP") {
        Some(root) => std::path::PathBuf::from(root),
        None => {
            let root = scratch.join("ftp");
            glowport_testserver::ftp::sample(&root)?;
            root
        }
    };
    let ftp = glowport_testserver::ftp::start(root.clone(), None, 50_600..=50_799).await?;
    println!("ftp {}", ftp.address);
    let ftps = glowport_testserver::ftp::start(root, Some(&scratch), 50_800..=50_999).await?;
    println!("ftps {} {}", ftps.address, ftps.fingerprint.as_ref().map(glowport_testserver::ftp::fingerprint_text).unwrap_or_default());
    println!("mosh {}", bridge.as_ref().map_or("-".to_string(), |bridge| bridge.address().to_string()));
    if let Some(bridge) = bridge {
        let paused = bridge.paused.clone();
        std::thread::spawn(move || {
            for line in std::io::stdin().lines().map_while(Result::ok) {
                match line.trim() {
                    "mosh pause" => paused.store(true, std::sync::atomic::Ordering::Relaxed),
                    "mosh resume" => paused.store(false, std::sync::atomic::Ordering::Relaxed),
                    _ => {}
                }
            }
        });
    }
    std::future::pending::<()>().await;
    Ok(())
}

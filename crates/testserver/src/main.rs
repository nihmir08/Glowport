//! Startet den Testserver als eigenes Programm, für die Ende-zu-Ende-Prüfung der Programmdatei.
//!
//! Lauscht auf einem freien Port von 127.0.0.1 und nennt die Adresse in der ersten Zeile der Ausgabe. Die zweite
//! Zeile nennt den nachgebauten Proxmox-Server, der mitläuft: `pve <Adresse> <Fingerabdruck seines Zertifikats>`.
//! Anmeldung: Benutzer `tester`, Passwort `richtig`. Das erste Argument nennt wahlweise ein Heimatverzeichnis:
//! Wer einen Schlüssel aus `.ssh/authorized_keys` darin besitzt, kommt ohne Passwort hinein, und Befehle laufen
//! über `sh` mit diesem Ordner als `$HOME` (braucht `sh` im Pfad, unter Windows etwa von Git). Das zweite Argument
//! nennt wahlweise die Datei mit dem privaten Schlüssel einer Zertifizierungsstelle (ohne Passphrase): Ihre
//! Benutzer-Zertifikate gelten, und der Server zeigt Clients, die danach fragen, ein Zertifikat von ihr für `127.0.0.1`.
//! Die dritte und vierte Zeile nennen zwei FTP-Server (`ftp <Adresse>`, `ftps <Adresse> <Fingerabdruck>`; Anmeldung wie
//! oben) auf einem Ordner mit einem kleinen Webspace oder auf dem, den `GLOWPORT_TEST_FTP` nennt.
//! Nennt die Umgebungsvariable `GLOWPORT_TEST_FILES` einen Ordner, zeigt der Server ihn über SFTP als sein Dateisystem;
//! unter `/etc` darf dabei nichts geändert werden.
//! Nennt `GLOWPORT_TEST_MOSH` eine WSL-Distribution mit mosh, startet der Server `mosh-server` dort und reicht UDP
//! über `127.0.0.1` weiter; die fünfte Zeile lautet dann `mosh <Adresse im WSL>`, sonst `mosh -`. Die Zeile
//! `mosh pause` auf der Eingabe hält die Weiterleitung an (Aussetzer), `mosh resume` lässt sie weiterlaufen.

use glowport_testserver::{host_certificate, key, start, Options};
use russh::keys::PrivateKey;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let ca = std::env::args().nth(2).and_then(|path| std::fs::read_to_string(path).ok()).and_then(|text| PrivateKey::from_openssh(text).ok());
    let options = Options {
        password: Some(("tester".into(), "richtig".into())),
        banner: Some("Testserver von Glowport\n".into()),
        exec_output: Some("Linux\nID=ubuntu\nID_LIKE=debian\n".into()),
        home: std::env::args_os().nth(1).map(Into::into),
        user_ca: ca.as_ref().map(|ca| ca.public_key().clone()),
        host_certificate: ca.as_ref().and_then(|ca| host_certificate(ca, &key(1), "127.0.0.1")),
        forwarding: true,
        files: std::env::var_os("GLOWPORT_TEST_FILES").map(Into::into),
        files_read_only: vec!["/etc".into()],
        // Für die Seitenleiste: ein Linux mit Docker und systemd, das es auf dem Rechner des Tests nicht gibt.
        admin: Some(Default::default()),
        ..Options::default()
    };
    let bridge = std::env::var("GLOWPORT_TEST_MOSH").ok().and_then(|distro| glowport_testserver::mosh::Bridge::find(&distro));
    let options = Options { mosh: bridge.clone(), ..options };
    let running = start(options, key(1)).await?;
    println!("{}", running.address);
    // Wie bei Proxmox nennt die Liste der Maschinen nach einem Schalten noch eine Weile den alten Zustand.
    let pve = glowport_testserver::pve::start_lagging(std::time::Duration::from_secs(8)).await?;
    println!("pve {} {}", pve.address, glowport_testserver::pve::fingerprint_text(&pve.fingerprint));
    // Zwei FTP-Server auf demselben Ordner: einer offen, einer über FTPS mit selbst erstelltem Zertifikat.
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

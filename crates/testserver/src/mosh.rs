//! Mosh für die Tests: `mosh-server` läuft im WSL dieses Rechners, und eine kleine Weiterleitung für UDP auf
//! `127.0.0.1` reicht die Pakete hin und her. Nötig, weil WSL (im Modus NAT) UDP nicht über `127.0.0.1` durchreicht,
//! der Client aber dorthin schickt, wohin seine SSH-Verbindung ging. Die Weiterleitung lässt sich anhalten: So
//! entsteht ein Aussetzer der Leitung, ohne am Netz dieses Rechners etwas zu ändern.

use std::{
    net::{Ipv4Addr, SocketAddr},
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use tokio::{net::UdpSocket, time::timeout};

/// Wie lange eine Weiterleitung ohne Verkehr bestehen bleibt.
const IDLE: Duration = Duration::from_secs(300);

#[derive(Clone)]
pub struct Bridge {
    distro: String,
    address: Ipv4Addr,
    /// Gesetzt: Die Weiterleitung verwirft alle Pakete (Aussetzer).
    pub paused: Arc<AtomicBool>,
}

impl Bridge {
    /// Findet `mosh-server` im WSL `distro` und dessen Adresse. `None`, wenn es kein WSL oder kein mosh gibt.
    pub fn find(distro: &str) -> Option<Self> {
        let output = Command::new("wsl").args(["-d", distro, "--", "sh", "-c", "command -v mosh-server >/dev/null && hostname -I"]).output().ok()?;
        if !output.status.success() {
            return None;
        }
        let address = String::from_utf8_lossy(&output.stdout).split_whitespace().find_map(|word| word.parse::<Ipv4Addr>().ok())?;
        Some(Self { distro: distro.into(), address, paused: Arc::default() })
    }

    /// Adresse des WSL, in dem `mosh-server` läuft.
    pub fn address(&self) -> Ipv4Addr {
        self.address
    }

    /// Ist das ein Aufruf von `mosh-server`, den diese Brücke übernimmt?
    pub fn takes(command: &str) -> bool {
        command.trim_start().starts_with("mosh-server ")
    }

    /// Führt `mosh-server` im WSL aus und richtet für seinen Port die Weiterleitung ein. Liefert Ausgabe,
    /// Fehlerausgabe und Rückgabewert wie ein gewöhnlicher Befehl.
    pub async fn run(&self, command: &str) -> (Vec<u8>, Vec<u8>, u32) {
        let (distro, command_line) = (self.distro.clone(), command.to_string());
        let ran = tokio::task::spawn_blocking(move || Command::new("wsl").args(["-d", &distro, "--", "sh", "-c", &command_line]).output()).await;
        let Ok(Ok(done)) = ran else {
            return (Vec::new(), b"wsl not available\n".to_vec(), 127);
        };
        let port = String::from_utf8_lossy(&done.stdout).lines().find_map(|line| line.strip_prefix("MOSH CONNECT ").and_then(|rest| rest.split(' ').next()).and_then(|port| port.parse::<u16>().ok()));
        if let Some(port) = port {
            if let Err(error) = self.relay(port).await {
                return (Vec::new(), format!("relay: {error}\n").into_bytes(), 1);
            }
        }
        (done.stdout, done.stderr, done.status.code().unwrap_or(1) as u32)
    }

    /// Reicht UDP von `127.0.0.1:port` an den Server im WSL weiter und zurück an den, der zuletzt geschickt hat.
    async fn relay(&self, port: u16) -> std::io::Result<()> {
        let outside = Arc::new(UdpSocket::bind(("127.0.0.1", port)).await?);
        let inside = Arc::new(UdpSocket::bind(("0.0.0.0", 0)).await?);
        inside.connect((self.address, port)).await?;
        let paused = Arc::clone(&self.paused);
        tokio::spawn(async move {
            let mut client: Option<SocketAddr> = None;
            let (mut up, mut down) = (vec![0u8; 65_536], vec![0u8; 65_536]);
            loop {
                tokio::select! {
                    received = timeout(IDLE, outside.recv_from(&mut up)) => match received {
                        Ok(Ok((n, from))) => {
                            client = Some(from);
                            if !paused.load(Ordering::Relaxed) {
                                let _ = inside.send(&up[..n]).await;
                            }
                        }
                        _ => break,
                    },
                    received = inside.recv(&mut down) => match received {
                        Ok(n) => {
                            if let (Some(to), false) = (client, paused.load(Ordering::Relaxed)) {
                                let _ = outside.send_to(&down[..n], to).await;
                            }
                        }
                        // Windows meldet ein Paket an einen geschlossenen Port beim nächsten Lesen als Fehler.
                        Err(_) => continue,
                    },
                }
            }
        });
        Ok(())
    }
}

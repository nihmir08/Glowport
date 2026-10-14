//! Mosh for the tests: `mosh-server` runs in this machine's WSL, and a small UDP forwarder on
//! `127.0.0.1` passes the packets back and forth. Needed because WSL (in NAT mode) does not pass UDP through `127.0.0.1`,
//! while the client sends where its SSH connection went. The forwarder can be paused: that
//! creates a line dropout without changing anything about this machine's network.

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

/// How long a forwarding stays without traffic.
const IDLE: Duration = Duration::from_secs(300);

#[derive(Clone)]
pub struct Bridge {
    distro: String,
    address: Ipv4Addr,
    /// Set: the forwarder drops all packets (dropout).
    pub paused: Arc<AtomicBool>,
}

impl Bridge {
    /// Finds `mosh-server` in the WSL `distro` and its address. `None` if there is no WSL or no mosh.
    pub fn find(distro: &str) -> Option<Self> {
        let output = Command::new("wsl").args(["-d", distro, "--", "sh", "-c", "command -v mosh-server >/dev/null && hostname -I"]).output().ok()?;
        if !output.status.success() {
            return None;
        }
        let address = String::from_utf8_lossy(&output.stdout).split_whitespace().find_map(|word| word.parse::<Ipv4Addr>().ok())?;
        Some(Self { distro: distro.into(), address, paused: Arc::default() })
    }

    /// Address of the WSL in which `mosh-server` runs.
    pub fn address(&self) -> Ipv4Addr {
        self.address
    }

    /// Is this a call of `mosh-server` that this bridge takes over?
    pub fn takes(command: &str) -> bool {
        command.trim_start().starts_with("mosh-server ")
    }

    /// Runs `mosh-server` in WSL and sets up the forwarding for its port. Returns output,
    /// error output and exit value like an ordinary command.
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

    /// Forwards UDP from `127.0.0.1:port` to the server in WSL and back to whoever sent last.
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
                        // Windows reports a packet to a closed port as an error on the next read.
                        Err(_) => continue,
                    },
                }
            }
        });
        Ok(())
    }
}

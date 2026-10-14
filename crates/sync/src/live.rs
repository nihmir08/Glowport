//! Syncing in the background: it runs as soon as something is changed here, as soon as the server nudges over the
//! WebSocket, and otherwise at longer intervals.

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use futures_util::{SinkExt, StreamExt};
use glowport_core::vault::VaultError;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    sync::Notify,
    task::JoinHandle,
    time::timeout,
};
use tokio_tungstenite::tungstenite::Message;

use crate::{api::Api, Door, Engine, Report, SyncError};

/// Collection time after a local change: whoever changes several things in quick succession sends one package.
const DEBOUNCE: Duration = Duration::from_millis(300);
/// Interval of rounds without a nudge: with a standing WebSocket only as a safety net, without it as a replacement.
const IDLE_LIVE: Duration = Duration::from_secs(300);
const IDLE_BLIND: Duration = Duration::from_secs(60);
/// Waiting times before the WebSocket's next connection attempt, in seconds.
const BACKOFF: [u64; 5] = [1, 2, 5, 10, 30];
/// The server reports at least once a minute. If it stays silent longer, the connection counts as dead.
const SILENCE: Duration = Duration::from_secs(150);
const CONNECT: Duration = Duration::from_secs(10);

/// What sync is doing right now; for the status bar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Syncing,
    Synced(Report),
    Offline,
    /// The vault is locked; syncing resumes after unlocking.
    Locked,
    /// The server no longer knows this device (signed out) or the account is disabled.
    SignedOut(String),
    Failed(String),
}

/// What a round's result means for the status bar.
pub fn status_of(result: Result<Report, SyncError>) -> Status {
    match result {
        Ok(report) => Status::Synced(report),
        Err(SyncError::Offline(_)) => Status::Offline,
        Err(SyncError::Vault(VaultError::Locked)) => Status::Locked,
        Err(SyncError::Refused { code, .. }) if code == "unauthorized" || code == "account_disabled" => Status::SignedOut(code),
        Err(error) => Status::Failed(error.code().to_string()),
    }
}

/// The running sync of a connected vault. Ends when it is dropped.
pub struct Runner {
    kick: Arc<Notify>,
    tasks: Vec<JoinHandle<()>>,
}

impl Runner {
    /// Starts syncing. `on_status` learns about every change; after `Synced` with `changed` the
    /// interface reads again.
    pub fn start<D: Door>(engine: Arc<Engine<D>>, on_status: impl Fn(Status) + Send + Sync + 'static) -> Self {
        let kick = Arc::new(Notify::new());
        let live = Arc::new(AtomicBool::new(false));
        let api = engine.api.clone();

        let rounds = tokio::spawn({
            let (kick, live) = (kick.clone(), live.clone());
            async move {
                loop {
                    on_status(Status::Syncing);
                    on_status(status_of(engine.sync().await));
                    let idle = if live.load(Ordering::Relaxed) { IDLE_LIVE } else { IDLE_BLIND };
                    if timeout(idle, kick.notified()).await.is_ok() {
                        tokio::time::sleep(DEBOUNCE).await;
                    }
                }
            }
        });

        let listener = tokio::spawn({
            let (kick, live) = (kick.clone(), live.clone());
            async move {
                let mut attempt = 0;
                loop {
                    let connected = listen(&api, &kick, &live).await;
                    live.store(false, Ordering::Relaxed);
                    // If the connection was up once, the wait starts short again.
                    if connected {
                        attempt = 0;
                    }
                    tokio::time::sleep(Duration::from_secs(BACKOFF[attempt.min(BACKOFF.len() - 1)])).await;
                    attempt += 1;
                }
            }
        });
        Self { kick, tasks: vec![rounds, listener] }
    }

    /// Something was changed here or the vault was unlocked: sync soon.
    pub fn kick(&self) {
        self.kick.notify_one();
    }
}

impl Drop for Runner {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Holds a WebSocket connection to the server while it stands. Returns whether it came about.
async fn listen(api: &Api, kick: &Notify, live: &AtomicBool) -> bool {
    let Some(token) = api.token() else { return false };
    let (host, port, secure, url) = api.live();
    let Ok(Ok(tcp)) = timeout(CONNECT, TcpStream::connect((host.as_str(), port))).await else { return false };
    let _ = tcp.set_nodelay(true);
    if !secure {
        return converse(tcp, &url, token, kick, live).await;
    }
    let Ok(name) = rustls::pki_types::ServerName::try_from(host) else { return false };
    let Ok(Ok(stream)) = timeout(CONNECT, tokio_rustls::TlsConnector::from(api.tls()).connect(name, tcp)).await else { return false };
    converse(stream, &url, token, kick, live).await
}

/// Identifies itself with the device token and triggers a round on every message from the server. What
/// changed is not in the message; the round fetches it over the ordinary requests.
async fn converse<S: AsyncRead + AsyncWrite + Unpin>(stream: S, url: &str, token: &str, kick: &Notify, live: &AtomicBool) -> bool {
    let Ok(Ok((mut socket, _))) = timeout(CONNECT, tokio_tungstenite::client_async(url, stream)).await else { return false };
    if socket.send(Message::Text(token.into())).await.is_err() {
        return false;
    }
    match timeout(CONNECT, socket.next()).await {
        Ok(Some(Ok(Message::Text(text)))) if text.as_str() == "ok" => {}
        _ => return false,
    }
    live.store(true, Ordering::Relaxed);
    // Check after every connect: something may have been missed in the meantime.
    kick.notify_one();
    loop {
        match timeout(SILENCE, socket.next()).await {
            Ok(Some(Ok(Message::Text(_)))) => kick.notify_one(),
            Ok(Some(Ok(Message::Close(_)))) | Ok(Some(Err(_))) | Ok(None) | Err(_) => return true,
            Ok(Some(Ok(_))) => {}
        }
    }
}

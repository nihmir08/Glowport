//! Der Abgleich im Hintergrund: Er läuft, sobald hier etwas geändert wird, sobald der Server über den
//! WebSocket anstößt, und sonst in größeren Abständen.

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

/// Sammelzeit nach einer lokalen Änderung: Wer mehrere Dinge kurz hintereinander ändert, schickt ein Paket.
const DEBOUNCE: Duration = Duration::from_millis(300);
/// Abstand der Runden ohne Anstoß: mit stehendem WebSocket nur zur Sicherheit, ohne ihn als Ersatz.
const IDLE_LIVE: Duration = Duration::from_secs(300);
const IDLE_BLIND: Duration = Duration::from_secs(60);
/// Wartezeiten vor dem nächsten Verbindungsversuch des WebSockets, in Sekunden.
const BACKOFF: [u64; 5] = [1, 2, 5, 10, 30];
/// Der Server meldet sich mindestens einmal in der Minute. Bleibt er länger still, gilt die Verbindung als tot.
const SILENCE: Duration = Duration::from_secs(150);
const CONNECT: Duration = Duration::from_secs(10);

/// Was der Abgleich gerade tut; für die Statusleiste.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Syncing,
    Synced(Report),
    Offline,
    /// Der Tresor ist gesperrt; abgeglichen wird wieder nach dem Entsperren.
    Locked,
    /// Der Server kennt dieses Gerät nicht mehr (abgemeldet) oder das Konto ist gesperrt.
    SignedOut(String),
    Failed(String),
}

/// Was das Ergebnis einer Runde für die Statusleiste heißt.
pub fn status_of(result: Result<Report, SyncError>) -> Status {
    match result {
        Ok(report) => Status::Synced(report),
        Err(SyncError::Offline(_)) => Status::Offline,
        Err(SyncError::Vault(VaultError::Locked)) => Status::Locked,
        Err(SyncError::Refused { code, .. }) if code == "unauthorized" || code == "account_disabled" => Status::SignedOut(code),
        Err(error) => Status::Failed(error.code().to_string()),
    }
}

/// Der laufende Abgleich eines verbundenen Tresors. Endet, wenn er fallen gelassen wird.
pub struct Runner {
    kick: Arc<Notify>,
    tasks: Vec<JoinHandle<()>>,
}

impl Runner {
    /// Startet den Abgleich. `on_status` erfährt jeden Wechsel; nach `Synced` mit `changed` liest die
    /// Oberfläche neu.
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
                    // Stand die Verbindung schon einmal, beginnt das Warten wieder kurz.
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

    /// Hier wurde etwas geändert oder der Tresor wurde entsperrt: bald abgleichen.
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

/// Hält eine WebSocket-Verbindung zum Server, solange sie steht. Liefert, ob sie zustande kam.
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

/// Weist sich mit dem Geräte-Token aus und stößt bei jeder Nachricht des Servers eine Runde an. Was sich
/// geändert hat, steht nicht in der Nachricht; das holt die Runde über die gewöhnlichen Anfragen.
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
    // Nach jedem Verbinden nachsehen: In der Zwischenzeit kann etwas verpasst worden sein.
    kick.notify_one();
    loop {
        match timeout(SILENCE, socket.next()).await {
            Ok(Some(Ok(Message::Text(_)))) => kick.notify_one(),
            Ok(Some(Ok(Message::Close(_)))) | Ok(Some(Err(_))) | Ok(None) | Err(_) => return true,
            Ok(Some(Ok(_))) => {}
        }
    }
}

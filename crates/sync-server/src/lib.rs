//! Sync-Server von Glowport (`docs/sync.md`). Dieses Crate ist die Bibliothek hinter dem Programm
//! `glowport-sync`: [`store`] entscheidet, hier steht nur die Schnittstelle nach außen.

pub mod store;

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        ConnectInfo, DefaultBodyLimit, Path, Query, State,
    },
    http::{header::AUTHORIZATION, Extensions, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use glowport_core::crypto::unhex;
use glowport_sync_proto::{ApiError, Bytes, CreateVault, Event, Login, PasswordChange, Prelogin, Push, Register, RenameDevice, RosterUpdate, Rotate};
use serde::Deserialize;
use store::{Caller, Fail, Id, Store};
use tokio::sync::broadcast;

/// Größtes Paket: ein Schlüsseltausch mit allen Datensätzen eines vollen Tresors.
const MAX_BODY: usize = 64 * 1024 * 1024;

/// Wem eine Nachricht über den WebSocket gilt.
#[derive(Debug, Clone)]
struct Notice {
    accounts: Vec<Id>,
    event: Event,
}

pub struct App {
    pub store: Store,
    hub: broadcast::Sender<Notice>,
    /// Hinter einem vorgeschalteten Webserver steht die Adresse des Absenders in `X-Forwarded-For`. Wessen
    /// Angabe gilt: niemandes (`None`), die jeder Verbindung (leere Liste; nur richtig, wenn allein der
    /// Webserver den Server erreicht, etwa über `127.0.0.1`) oder nur die von diesen Adressen.
    proxies: Option<Vec<std::net::IpAddr>>,
    /// Ob Anfragen ins Protokoll geschrieben werden (im Betrieb ja, in Tests nein).
    log: std::sync::atomic::AtomicBool,
}

impl App {
    pub fn new(store: Store, trust_proxy: bool) -> Arc<Self> {
        Self::with_proxies(store, trust_proxy.then(Vec::new))
    }

    /// Wie [`App::new`], mit der Angabe, wessen `X-Forwarded-For` gilt (siehe das Feld `proxies`).
    pub fn with_proxies(store: Store, proxies: Option<Vec<std::net::IpAddr>>) -> Arc<Self> {
        Arc::new(Self { store, hub: broadcast::channel(256).0, proxies, log: false.into() })
    }

    /// Schreibt ab jetzt ins Protokoll (Standardausgabe), was etwas ändert oder scheitert: Zeit, Ergebnis, Art
    /// der Anfrage, Konto. Nie Inhalte, Token oder Anmeldeschlüssel, und keine Adressen der Absender.
    pub fn log_requests(&self) {
        self.log.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    fn tell(&self, accounts: Vec<Id>, event: Event) {
        // Hört gerade niemand zu, ist das kein Fehler: Jedes Gerät holt nach dem Verbinden ohnehin.
        let _ = self.hub.send(Notice { accounts, event });
    }
}

type Shared = State<Arc<App>>;
type Reply<T> = Result<Json<T>, Fail>;

impl IntoResponse for Fail {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        // Was intern schiefging, geht den Anfragenden nichts an.
        let message = if matches!(self, Fail::Internal(_)) { "Interner Fehler".to_string() } else { self.to_string() };
        (status, Json(ApiError { code: self.code().into(), message })).into_response()
    }
}

/// Führt eine Entscheidung des Speichers abseits der Netz-Threads aus.
async fn run<T: Send + 'static>(app: &Arc<App>, work: impl FnOnce(&App) -> Result<T, Fail> + Send + 'static) -> Result<T, Fail> {
    let app = app.clone();
    tokio::task::spawn_blocking(move || work(&app)).await.map_err(|e| Fail::Internal(e.to_string()))?
}

fn token(headers: &HeaderMap) -> Result<Vec<u8>, Fail> {
    let value = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")).ok_or(Fail::Unauthorized)?;
    STANDARD.decode(value.trim()).map_err(|_| Fail::Unauthorized)
}

async fn caller(app: &Arc<App>, headers: &HeaderMap) -> Result<Caller, Fail> {
    let token = token(headers)?;
    run(app, move |app| app.store.authenticate(&token)).await
}

/// Adresse des Absenders für die Bremse gegen Rateversuche.
fn address(app: &App, headers: &HeaderMap, extensions: &Extensions) -> String {
    let peer = extensions.get::<ConnectInfo<SocketAddr>>().map(|info| info.0.ip().to_canonical());
    let trusted = app.proxies.as_ref().is_some_and(|list| list.is_empty() || peer.is_some_and(|peer| list.contains(&peer)));
    // Der letzte Eintrag ist der, den der Webserver selbst angehängt hat; davor steht, was der Absender behauptet.
    let forwarded = trusted.then(|| headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()).and_then(|v| v.rsplit(',').next()).map(|v| v.trim().to_string())).flatten();
    forwarded.filter(|v| !v.is_empty()).or_else(|| peer.map(|ip| ip.to_string())).unwrap_or_else(|| "unbekannt".into())
}

/// Ein Tag als `2026-10-10` (UTC), aus Millisekunden seit 1970.
pub fn day(ms: i64) -> String {
    // Bürgerlicher Kalender aus der Zahl der Tage, ohne eine Bibliothek nur dafür.
    let z = ms.div_euclid(86_400_000) + 719_468;
    let (era, doe) = (z.div_euclid(146_097), z.rem_euclid(146_097));
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let (day, month) = (doy - (153 * mp + 2) / 5 + 1, if mp < 10 { mp + 3 } else { mp - 9 });
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

/// Ein Zeitpunkt als `2026-10-10 14:03:27` (UTC).
fn moment(ms: i64) -> String {
    let seconds = ms.rem_euclid(86_400_000) / 1000;
    format!("{} {:02}:{:02}:{:02}", day(ms), seconds / 3600, seconds / 60 % 60, seconds % 60)
}

/// Das Protokoll: eine Zeile für alles, was etwas ändert oder scheitert. Gelesen wird ständig, das bleibt still.
/// Statt der Adresse der Anfrage steht ihr Muster da, also keine Kennungen und keine Codes.
async fn log(State(app): Shared, request: axum::extract::Request, next: axum::middleware::Next) -> Response {
    if !app.log.load(std::sync::atomic::Ordering::Relaxed) {
        return next.run(request).await;
    }
    let method = request.method().clone();
    let route = request.extensions().get::<axum::extract::MatchedPath>().map_or_else(|| "?".to_string(), |path| path.as_str().to_string());
    // Vorher nachsehen: Die Anfrage kann genau dieses Gerät abmelden.
    let who = match token(request.headers()) {
        Ok(token) => run(&app, move |app| Ok(app.store.username_of(&token))).await.ok().flatten(),
        Err(_) => None,
    };
    let response = next.run(request).await;
    let status = response.status().as_u16();
    if method != axum::http::Method::GET || status >= 400 {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as i64);
        println!("{} {status} {method} {route} {}", moment(now), who.as_deref().unwrap_or("-"));
    }
    response
}

fn id(text: &str) -> Result<Id, Fail> {
    unhex(text).ok_or(Fail::NotFound)
}

async fn info(State(app): Shared) -> Reply<glowport_sync_proto::Info> {
    Ok(Json(run(&app, |app| app.store.info()).await?))
}

async fn prelogin(State(app): Shared, Json(request): Json<Prelogin>) -> Reply<glowport_sync_proto::PreloginReply> {
    Ok(Json(run(&app, move |app| app.store.prelogin(&request.username)).await?))
}

async fn register(State(app): Shared, headers: HeaderMap, extensions: Extensions, Json(request): Json<Register>) -> Reply<glowport_sync_proto::LoginReply> {
    let from = address(&app, &headers, &extensions);
    Ok(Json(run(&app, move |app| app.store.register(&request, &from)).await?))
}

async fn login(State(app): Shared, headers: HeaderMap, extensions: Extensions, Json(request): Json<Login>) -> Reply<glowport_sync_proto::LoginReply> {
    let from = address(&app, &headers, &extensions);
    Ok(Json(run(&app, move |app| app.store.login(&request, &from)).await?))
}

async fn overview(State(app): Shared, headers: HeaderMap) -> Reply<glowport_sync_proto::Overview> {
    let caller = caller(&app, &headers).await?;
    Ok(Json(run(&app, move |app| app.store.overview(&caller)).await?))
}

async fn change_password(State(app): Shared, headers: HeaderMap, extensions: Extensions, Json(request): Json<PasswordChange>) -> Reply<()> {
    let caller = caller(&app, &headers).await?;
    let from = address(&app, &headers, &extensions);
    let account = caller.account;
    run(&app, move |app| app.store.change_password(&caller, &request, &from)).await?;
    app.tell(vec![account], Event::Account);
    Ok(Json(()))
}

async fn devices(State(app): Shared, headers: HeaderMap) -> Reply<Vec<glowport_sync_proto::Device>> {
    let caller = caller(&app, &headers).await?;
    Ok(Json(run(&app, move |app| app.store.devices(&caller)).await?))
}

async fn remove_device(State(app): Shared, headers: HeaderMap, Path(device): Path<String>) -> Reply<()> {
    let (caller, device) = (caller(&app, &headers).await?, id(&device)?);
    let account = caller.account;
    run(&app, move |app| app.store.remove_device(&caller, &device)).await?;
    app.tell(vec![account], Event::Account);
    Ok(Json(()))
}

async fn rename_device(State(app): Shared, headers: HeaderMap, Path(device): Path<String>, Json(request): Json<RenameDevice>) -> Reply<()> {
    let (caller, device) = (caller(&app, &headers).await?, id(&device)?);
    Ok(Json(run(&app, move |app| app.store.rename_device(&caller, &device, &request.name)).await?))
}

async fn public_keys(State(app): Shared, headers: HeaderMap, Path(username): Path<String>) -> Reply<glowport_sync_proto::PublicKeys> {
    caller(&app, &headers).await?;
    Ok(Json(run(&app, move |app| app.store.public_keys(&username)).await?))
}

async fn create_vault(State(app): Shared, headers: HeaderMap, Json(request): Json<CreateVault>) -> Reply<()> {
    let caller = caller(&app, &headers).await?;
    let account = caller.account;
    run(&app, move |app| app.store.create_vault(&caller, &request)).await?;
    app.tell(vec![account], Event::Account);
    Ok(Json(()))
}

#[derive(Deserialize)]
struct After {
    #[serde(default)]
    after: u64,
}

async fn pull(State(app): Shared, headers: HeaderMap, Path(vault): Path<String>, Query(query): Query<After>) -> Reply<glowport_sync_proto::Pull> {
    let (caller, vault) = (caller(&app, &headers).await?, id(&vault)?);
    Ok(Json(run(&app, move |app| app.store.pull(&caller, &vault, query.after)).await?))
}

async fn push(State(app): Shared, headers: HeaderMap, Path(vault): Path<String>, Json(request): Json<Push>) -> Reply<glowport_sync_proto::PushReply> {
    let (caller, vault) = (caller(&app, &headers).await?, id(&vault)?);
    let (reply, members) = run(&app, move |app| {
        let reply = app.store.push(&caller, &vault, &request)?;
        Ok((reply, app.store.members(&vault)?))
    })
    .await?;
    if reply.accepted {
        app.tell(members, Event::Vault { id: Bytes(vault.to_vec()), seq: reply.seq });
    }
    Ok(Json(reply))
}

/// Eine Änderung an Mitgliedschaften: Alle Betroffenen sehen nach, was sich an ihrem Konto geändert hat.
async fn membership(app: Arc<App>, headers: HeaderMap, vault: String, work: impl FnOnce(&Store, &Caller, &Id) -> Result<Vec<Id>, Fail> + Send + 'static) -> Reply<()> {
    let (caller, vault) = (caller(&app, &headers).await?, id(&vault)?);
    let mut accounts = run(&app, move |app| {
        let mut accounts = work(&app.store, &caller, &vault)?;
        accounts.push(caller.account);
        Ok(accounts)
    })
    .await?;
    accounts.sort();
    accounts.dedup();
    app.tell(accounts, Event::Account);
    Ok(Json(()))
}

async fn update_roster(State(app): Shared, headers: HeaderMap, Path(vault): Path<String>, Json(request): Json<RosterUpdate>) -> Reply<()> {
    membership(app, headers, vault, move |store, caller, vault| store.update_roster(caller, vault, &request)).await
}

async fn rotate(State(app): Shared, headers: HeaderMap, Path(vault): Path<String>, Json(request): Json<Rotate>) -> Reply<()> {
    membership(app, headers, vault, move |store, caller, vault| store.rotate(caller, vault, &request)).await
}

async fn accept(State(app): Shared, headers: HeaderMap, Path(vault): Path<String>) -> Reply<()> {
    membership(app, headers, vault, |store, caller, vault| store.accept(caller, vault)).await
}

async fn leave(State(app): Shared, headers: HeaderMap, Path(vault): Path<String>) -> Reply<()> {
    membership(app, headers, vault, |store, caller, vault| store.leave(caller, vault)).await
}

async fn delete_vault(State(app): Shared, headers: HeaderMap, Path(vault): Path<String>) -> Reply<()> {
    membership(app, headers, vault, |store, caller, vault| store.delete_vault(caller, vault)).await
}

async fn invites(State(app): Shared, headers: HeaderMap) -> Reply<Vec<glowport_sync_proto::Invite>> {
    let caller = caller(&app, &headers).await?;
    Ok(Json(run(&app, move |app| app.store.invites(&caller)).await?))
}

async fn create_invite(State(app): Shared, headers: HeaderMap) -> Reply<glowport_sync_proto::Invite> {
    let caller = caller(&app, &headers).await?;
    Ok(Json(run(&app, move |app| app.store.create_invite(&caller)).await?))
}

async fn revoke_invite(State(app): Shared, headers: HeaderMap, Path(code): Path<String>) -> Reply<()> {
    let caller = caller(&app, &headers).await?;
    Ok(Json(run(&app, move |app| app.store.revoke_invite(&caller, &code)).await?))
}

async fn accounts(State(app): Shared, headers: HeaderMap) -> Reply<Vec<glowport_sync_proto::AdminAccount>> {
    let caller = caller(&app, &headers).await?;
    Ok(Json(run(&app, move |app| app.store.accounts(&caller)).await?))
}

async fn set_disabled(app: Arc<App>, headers: HeaderMap, account: String, disabled: bool) -> Reply<()> {
    let (caller, account) = (caller(&app, &headers).await?, id(&account)?);
    run(&app, move |app| app.store.set_disabled(&caller, &account, disabled)).await?;
    app.tell(vec![account], Event::Account);
    Ok(Json(()))
}

async fn disable_account(State(app): Shared, headers: HeaderMap, Path(account): Path<String>) -> Reply<()> {
    set_disabled(app, headers, account, true).await
}

async fn enable_account(State(app): Shared, headers: HeaderMap, Path(account): Path<String>) -> Reply<()> {
    set_disabled(app, headers, account, false).await
}

async fn delete_account(State(app): Shared, headers: HeaderMap, Path(account): Path<String>) -> Reply<()> {
    let (caller, account) = (caller(&app, &headers).await?, id(&account)?);
    let mut accounts = run(&app, move |app| app.store.delete_account(&caller, &account)).await?;
    accounts.push(account);
    app.tell(accounts, Event::Account);
    Ok(Json(()))
}

/// WebSocket: Die erste Nachricht ist das Geräte-Token (so steht es in keiner Adresse und keinem Protokoll),
/// danach kommen nur noch Anstöße vom Server.
async fn live(State(app): Shared, upgrade: WebSocketUpgrade) -> Response {
    upgrade.on_upgrade(move |socket| async move {
        let _ = listen(app, socket).await;
    })
}

async fn listen(app: Arc<App>, mut socket: WebSocket) -> Result<(), ()> {
    let first = tokio::time::timeout(Duration::from_secs(10), socket.recv()).await.map_err(drop)?;
    let Some(Ok(Message::Text(text))) = first else { return Err(()) };
    let token = STANDARD.decode(text.trim()).map_err(drop)?;
    let check = token.clone();
    let caller = run(&app, move |app| app.store.authenticate(&check)).await.map_err(drop)?;
    let mut events = app.hub.subscribe();
    socket.send(Message::Text("ok".into())).await.map_err(drop)?;
    // Ein abgemeldetes Gerät oder ein gesperrtes Konto soll nicht ewig weiter zuhören.
    let mut recheck = tokio::time::interval(Duration::from_secs(60));
    recheck.tick().await;
    loop {
        tokio::select! {
            notice = events.recv() => match notice {
                Ok(notice) if notice.accounts.contains(&caller.account) => {
                    let text = serde_json::to_string(&notice.event).map_err(drop)?;
                    socket.send(Message::Text(text.into())).await.map_err(drop)?;
                }
                Ok(_) => {}
                // Zu langsam gelesen und etwas verpasst: Das Gerät soll alles nachsehen.
                Err(broadcast::error::RecvError::Lagged(_)) => socket.send(Message::Text("{\"event\":\"account\"}".into())).await.map_err(drop)?,
                Err(broadcast::error::RecvError::Closed) => return Ok(()),
            },
            message = socket.recv() => match message {
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => return Ok(()),
                Some(Ok(_)) => {}
            },
            _ = recheck.tick() => {
                let check = token.clone();
                run(&app, move |app| app.store.authenticate(&check)).await.map_err(drop)?;
                socket.send(Message::Ping(Vec::new().into())).await.map_err(drop)?;
            }
        }
    }
}

pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/v1/info", get(info))
        .route("/v1/prelogin", post(prelogin))
        .route("/v1/register", post(register))
        .route("/v1/login", post(login))
        .route("/v1/account", get(overview))
        .route("/v1/account/password", post(change_password))
        .route("/v1/devices", get(devices))
        .route("/v1/devices/{device}", delete(remove_device).post(rename_device))
        .route("/v1/keys/{username}", get(public_keys))
        .route("/v1/vaults", post(create_vault))
        .route("/v1/vaults/{vault}", delete(delete_vault))
        .route("/v1/vaults/{vault}/records", get(pull).post(push))
        .route("/v1/vaults/{vault}/roster", post(update_roster))
        .route("/v1/vaults/{vault}/rotate", post(rotate))
        .route("/v1/vaults/{vault}/accept", post(accept))
        .route("/v1/vaults/{vault}/leave", post(leave))
        .route("/v1/admin/invites", get(invites).post(create_invite))
        .route("/v1/admin/invites/{code}", delete(revoke_invite))
        .route("/v1/admin/accounts", get(accounts))
        .route("/v1/admin/accounts/{account}", delete(delete_account))
        .route("/v1/admin/accounts/{account}/disable", post(disable_account))
        .route("/v1/admin/accounts/{account}/enable", post(enable_account))
        .route("/v1/live", get(live))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .layer(axum::middleware::from_fn_with_state(app.clone(), log))
        .with_state(app)
}

/// Bedient Anfragen mit eigenem TLS, bis `stop` endet: für den Betrieb ohne vorgeschalteten Webserver.
/// Zertifikat und Schlüssel sind PEM-Dateien. Ändern sie sich (eine Verlängerung), gelten die neuen binnen
/// einer Stunde, ohne Neustart; lassen sie sich dann nicht lesen, bleibt es beim bisherigen Zertifikat.
pub async fn serve_tls(
    app: Arc<App>,
    listener: std::net::TcpListener,
    cert: std::path::PathBuf,
    key: std::path::PathBuf,
    stop: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    use axum_server::tls_rustls::RustlsConfig;

    // Schon gesetzt heißt: von uns, an anderer Stelle im selben Prozess.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config = RustlsConfig::from_pem_file(&cert, &key).await?;
    let handle = axum_server::Handle::new();
    let stopper = handle.clone();
    tokio::spawn(async move {
        stop.await;
        // Offene WebSockets enden nicht von selbst; nach der Frist wird geschlossen.
        stopper.graceful_shutdown(Some(Duration::from_secs(5)));
    });
    let renew = tokio::spawn({
        let config = config.clone();
        async move {
            let stamp = |path: &std::path::Path| std::fs::metadata(path).and_then(|meta| meta.modified()).ok();
            let mut seen = (stamp(&cert), stamp(&key));
            let mut hourly = tokio::time::interval(Duration::from_secs(60 * 60));
            hourly.tick().await;
            loop {
                hourly.tick().await;
                let now = (stamp(&cert), stamp(&key));
                if now != seen && config.reload_from_pem_file(&cert, &key).await.is_ok() {
                    seen = now;
                }
            }
        }
    });
    listener.set_nonblocking(true)?;
    let result = axum_server::from_tcp_rustls(listener, config).handle(handle).serve(router(app).into_make_service_with_connect_info::<SocketAddr>()).await;
    renew.abort();
    result
}

/// Bedient Anfragen, bis `stop` endet.
pub async fn serve(app: Arc<App>, listener: tokio::net::TcpListener, stop: impl std::future::Future<Output = ()> + Send + 'static) -> std::io::Result<()> {
    axum::serve(listener, router(app).into_make_service_with_connect_info::<SocketAddr>()).with_graceful_shutdown(stop).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sender_is_only_believed_through_a_trusted_proxy() {
        let app = |proxies| App::with_proxies(Store::in_memory().unwrap(), proxies);
        let from = |peer: &str, forwarded: Option<&str>| {
            let mut headers = HeaderMap::new();
            if let Some(value) = forwarded {
                headers.insert("x-forwarded-for", value.parse().unwrap());
            }
            let mut extensions = Extensions::new();
            extensions.insert(ConnectInfo(SocketAddr::new(peer.parse().unwrap(), 40_000)));
            (headers, extensions)
        };
        let seen = |app: &App, peer: &str, forwarded: Option<&str>| {
            let (headers, extensions) = from(peer, forwarded);
            address(app, &headers, &extensions)
        };

        // Ohne Vorschaltung zählt allein, wer verbunden ist; was er über sich behauptet, nicht.
        let direct = app(None);
        assert_eq!(seen(&direct, "203.0.113.7", Some("198.51.100.1")), "203.0.113.7");
        // Jeder Verbindung glauben: der letzte Eintrag, den der Webserver angehängt hat.
        let any = app(Some(vec![]));
        assert_eq!(seen(&any, "127.0.0.1", Some("198.51.100.1")), "198.51.100.1");
        assert_eq!(seen(&any, "127.0.0.1", Some("10.9.9.9, 198.51.100.1")), "198.51.100.1");
        assert_eq!(seen(&any, "127.0.0.1", None), "127.0.0.1");
        // Nur dem Webserver glauben: Wer den Server direkt erreicht, kann sich keine Adresse geben.
        let only = app(Some(vec!["10.0.0.10".parse().unwrap()]));
        assert_eq!(seen(&only, "10.0.0.10", Some("198.51.100.1")), "198.51.100.1");
        assert_eq!(seen(&only, "10.0.0.66", Some("198.51.100.1")), "10.0.0.66");
        // Dieselbe Adresse des Webservers, über einen Anschluss für IPv6 gesehen.
        assert_eq!(seen(&only, "::ffff:10.0.0.10", Some("198.51.100.1")), "198.51.100.1");
        assert_eq!(address(&only, &HeaderMap::new(), &Extensions::new()), "unbekannt");
    }

    #[test]
    fn dates_follow_the_calendar() {
        assert_eq!(day(0), "1970-01-01");
        assert_eq!(day(1_709_164_800_000), "2024-02-29");
        assert_eq!(day(1_709_251_199_999), "2024-02-29");
        assert_eq!(day(1_709_251_200_000), "2024-03-01");
        assert_eq!(day(1_800_000_000_000), "2027-01-15");
        assert_eq!(day(4_102_444_800_000), "2100-01-01");
        assert_eq!(moment(1_800_000_000_000), "2027-01-15 08:00:00");
        assert_eq!(moment(1_709_251_199_999), "2024-02-29 23:59:59");
    }
}

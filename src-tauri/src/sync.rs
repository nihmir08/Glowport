//! Bridge between interface and syncing (`glowport-sync`, `docs/sync.md`).
//!
//! Syncing only reaches into the vault through [`Gate`]: briefly in, out again, never during a request
//! to the server. It runs as long as the vault is open and linked to a server ([`ensure`]); on
//! locking it ends. What it changes in the vault the bridge reports to the interface like any other change.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
    time::{SystemTime, UNIX_EPOCH},
};

use glowport_core::{
    crypto::unhex,
    directory::VaultMarks,
    roster::{safety_code, Role},
    vault::{Vault, VaultError},
};
use glowport_sync::{connect, engine::MIN_KDF, login_new, probe, register, status_of, Candidate, Door, Engine, Invitation, Known, Notice, Report, Runner, Status as RunStatus, SyncError};
use glowport_sync_proto::{AdminAccount, Invite};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};
use zeroize::Zeroizing;

use crate::app::{check_password, emit_snapshot_quiet, AppState, CmdError, CmdResult, Status};

type Id = [u8; 16];

/// Syncing's access to the program's vault.
pub struct Gate(AppHandle);

impl Door for Gate {
    fn enter<T>(&self, work: impl FnOnce(&mut Vault) -> Result<T, SyncError>) -> Result<T, SyncError> {
        let outcome = self.0.state::<AppState>().session().background(work);
        match outcome {
            None => Err(VaultError::Locked.into()),
            Some((result, changed)) => {
                if changed {
                    emit_snapshot_quiet(&self.0);
                }
                result
            }
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum Phase {
    #[default]
    Synced,
    Syncing,
    Offline,
    SignedOut,
    Error,
}

impl Phase {
    fn name(self) -> &'static str {
        match self {
            Phase::Synced => "synced",
            Phase::Syncing => "syncing",
            Phase::Offline => "offline",
            Phase::SignedOut => "signedOut",
            Phase::Error => "error",
        }
    }
}

#[derive(Default)]
struct Inner {
    engine: Option<Arc<Engine<Gate>>>,
    runner: Option<Runner>,
    phase: Phase,
    error: Option<String>,
    /// What the last successful round produced.
    report: Report,
    synced_at: Option<i64>,
    /// Accounts looked up last: “Invite” means exactly the account whose safety code was shown.
    candidates: HashMap<String, Candidate>,
}

/// This program's running sync. There is at most one.
#[derive(Default)]
pub struct SyncHost(Mutex<Inner>);

fn lock(app: &AppHandle) -> MutexGuard<'_, Inner> {
    app.state::<SyncHost>().inner().0.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as i64)
}

/// Reasons the interface knows and translates. Everything else it shows as an unexpected answer.
const CODES: [&str; 35] = [
    "offline",
    "protocol",
    "address_invalid",
    "client_too_old",
    "certificate",
    "server_too_old",
    "not_linked",
    "already_linked",
    "other_account",
    "busy",
    "bad_request",
    "unauthorized",
    "code_invalid",
    "username_taken",
    "account_exists",
    "account_disabled",
    "too_many_attempts",
    "not_found",
    "read_only",
    "not_owner",
    "not_admin",
    "own_account",
    "owner_cannot_leave",
    "roster_invalid",
    "needs_rotation",
    "member_unknown",
    "vault_frozen",
    "vault_full",
    "vault_exists",
    "vault_changed",
    "too_many_vaults",
    "record_too_large",
    "record_invalid",
    "personal_vault",
    "internal",
];

impl From<SyncError> for CmdError {
    fn from(error: SyncError) -> Self {
        match error {
            SyncError::Vault(error) => error.into(),
            SyncError::Invalid("already_member") => CmdError::new("already_member", error.to_string()),
            SyncError::Invalid(_) => CmdError::new("sync_invalid", error.to_string()),
            error => CmdError::new(CODES.iter().find(|code| **code == error.code()).copied().unwrap_or("protocol"), error.to_string()),
        }
    }
}

fn id(text: &str) -> CmdResult<Id> {
    unhex(text).ok_or_else(|| CmdError::new("not_found", "Unbekannte Kennung"))
}

/// State of syncing as the interface shows it (`SyncState` in `types.ts`).
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StateView {
    linked: bool,
    server: String,
    username: String,
    admin: bool,
    phase: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    pending: usize,
    synced_at: Option<i64>,
    code: String,
    invitations: Vec<Invitation>,
    notices: usize,
    password_changed: bool,
}

fn view(app: &AppHandle) -> StateView {
    let (link, phase, error, report, synced_at) = {
        let inner = lock(app);
        (inner.engine.as_ref().map(|engine| engine.link().clone()), inner.phase, inner.error.clone(), inner.report.clone(), inner.synced_at)
    };
    let Some(link) = link else { return StateView { phase: Phase::Synced.name(), ..StateView::default() } };
    // What is waiting and what notices there are is stored in the vault and is right even without a connection.
    let (pending, notices, code) = app
        .state::<AppState>()
        .session()
        .directory_quiet()
        .map(|directory| {
            let vault = directory.vault();
            let pending = vault.vaults().unwrap_or_default().iter().map(|info| vault.pending(&info.id).map_or(0, |list| list.len())).sum();
            let code = vault.public_keys().map(|(ed25519, x25519)| safety_code(&ed25519, &x25519)).unwrap_or_default();
            (pending, vault.notices().map_or(0, |list| list.len()), code)
        })
        .unwrap_or_default();
    StateView {
        linked: true,
        server: link.server,
        username: link.username,
        // After a round, what the server just said applies; before that, the saved sign-in.
        admin: if synced_at.is_some() { report.admin } else { link.admin },
        phase: phase.name(),
        error,
        pending,
        synced_at,
        code,
        invitations: report.invitations,
        notices,
        password_changed: report.password_changed,
    }
}

/// Fills in what only syncing knows across the vaults and reports the state to the interface.
fn publish(app: &AppHandle) {
    let marks = {
        let inner = lock(app);
        let report = &inner.report;
        VaultMarks { rolled_back: report.rolled_back.iter().cloned().collect(), orphaned: report.orphaned.iter().cloned().collect(), invited: report.invited.iter().cloned().collect() }
    };
    let changed = app.state::<AppState>().session().directory_quiet().is_some_and(|directory| directory.mark_vaults(marks));
    if changed {
        emit_snapshot_quiet(app);
    }
    let _ = app.emit("sync-state", view(app));
}

fn on_status(app: &AppHandle, status: RunStatus) {
    {
        let mut inner = lock(app);
        match status {
            RunStatus::Syncing => inner.phase = Phase::Syncing,
            RunStatus::Synced(report) => {
                inner.phase = Phase::Synced;
                inner.error = None;
                inner.synced_at = Some(now_ms());
                inner.report = report;
            }
            RunStatus::Offline => inner.phase = Phase::Offline,
            // Locked, nothing runs; the state from before stays until it is unlocked again.
            RunStatus::Locked => return,
            RunStatus::SignedOut(code) => {
                inner.phase = Phase::SignedOut;
                inner.error = Some(code);
            }
            RunStatus::Failed(code) => {
                inner.phase = Phase::Error;
                inner.error = Some(code);
            }
        }
    }
    publish(app);
}

/// Starts background syncing. Only to be called from within a task of the runtime (a command with
/// `async` or [`poke`]): the `Runner` creates its own tasks there.
fn start(app: &AppHandle, engine: Engine<Gate>) {
    let engine = Arc::new(engine);
    let handle = app.clone();
    let runner = Runner::start(engine.clone(), move |status| on_status(&handle, status));
    let mut inner = lock(app);
    // Two attempts at the same time: the first one counts, this one ends with its `Runner`.
    if inner.engine.is_none() {
        *inner = Inner { engine: Some(engine), runner: Some(runner), phase: Phase::Syncing, ..Inner::default() };
    }
}

/// Makes sure syncing runs exactly when the vault is open and linked to a server.
pub fn ensure(app: &AppHandle) {
    if !app.state::<AppState>().session().is_open() {
        *lock(app) = Inner::default();
        return;
    }
    if lock(app).engine.is_some() {
        return;
    }
    // Reading the sign-in reaches into the vault; the lock of our own is free during that.
    if let Ok(Some(engine)) = Engine::open(Arc::new(Gate(app.clone()))) {
        start(app, engine);
    }
}

/// The vault was opened, locked or changed. Called while the program's state is locked,
/// so it does everything further in a task of its own: start or stop syncing, otherwise nudge it.
pub fn poke(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        ensure(&app);
        if let Some(runner) = &lock(&app).runner {
            runner.kick();
        }
    });
}

fn engine(app: &AppHandle) -> CmdResult<Arc<Engine<Gate>>> {
    ensure(app);
    lock(app).engine.clone().ok_or_else(|| CmdError::new("not_linked", "Syncing is not set up"))
}

/// A round right away, so the interface sees the result of a change immediately.
async fn round(app: &AppHandle, engine: &Engine<Gate>) -> StateView {
    on_status(app, status_of(engine.sync().await));
    view(app)
}

// `async`: the command can start background syncing, and that needs the tasks' runtime.
// An ordinary command would run on the window thread, where there is none.
#[tauri::command]
pub async fn sync_state(app: AppHandle) -> StateView {
    ensure(&app);
    view(&app)
}

#[derive(Serialize)]
pub struct ServerView {
    server: String,
    fresh: bool,
}

#[tauri::command]
pub async fn sync_probe(server: String) -> CmdResult<ServerView> {
    let (server, info) = probe(&server).await?;
    Ok(ServerView { server, fresh: info.fresh })
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    server: String,
    code: String,
    username: String,
    password: String,
    #[serde(default)]
    device: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    server: String,
    username: String,
    password: String,
    #[serde(default)]
    device: String,
    /// Only on a device with a vault of its own that does not belong to the account: `keep` takes over its entries,
    /// `discard` throws them away.
    #[serde(default)]
    local: Option<String>,
}

fn device_name(given: &str) -> String {
    let given = given.trim();
    if given.is_empty() {
        std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")).unwrap_or_else(|_| "Glowport".into())
    } else {
        given.chars().take(60).collect()
    }
}

#[tauri::command]
pub async fn sync_register(app: AppHandle, request: RegisterRequest) -> CmdResult<StateView> {
    let password = Zeroizing::new(request.password);
    let engine = register(&Arc::new(Gate(app.clone())), &request.server, &request.code, request.username.trim(), &password, &device_name(&request.device)).await?;
    start(&app, engine);
    Ok(view(&app))
}

#[tauri::command]
pub async fn sync_connect(app: AppHandle, state: State<'_, AppState>, request: LoginRequest) -> CmdResult<StateView> {
    let password = Zeroizing::new(request.password);
    let (username, device) = (request.username.trim().to_string(), device_name(&request.device));
    match request.local.as_deref() {
        // This device's vault already belongs to the account (after a backup or signing out).
        None => {
            let engine = connect(&Arc::new(Gate(app.clone())), &request.server, &username, &password, &device, MIN_KDF).await?;
            start(&app, engine);
        }
        // It belongs to no account or another one: the account's vault is created next to it and takes its place.
        Some(choice) => {
            let staged = state.session().path().with_extension("db.konto");
            let _ = std::fs::remove_file(&staged);
            drop(login_new(&staged, &request.server, &username, &password, &device, MIN_KDF).await?);
            let stamp = chrono::Local::now().format("%Y-%m-%d-%H%M%S").to_string();
            let replaced = state.session().replace_with_account(&staged, &password, choice == "keep", &stamp);
            if let Err(error) = replaced {
                let _ = std::fs::remove_file(&staged);
                return Err(error);
            }
            ensure(&app);
        }
    }
    Ok(view(&app))
}

/// First start without a vault: this device's vault is created from an existing account.
#[tauri::command]
pub async fn sync_login(app: AppHandle, state: State<'_, AppState>, request: LoginRequest) -> CmdResult<Status> {
    let password = Zeroizing::new(request.password);
    let path = state.session().path().to_path_buf();
    let vault = login_new(&path, &request.server, request.username.trim(), &password, &device_name(&request.device), MIN_KDF).await?;
    let status = state.session().adopt_opened(vault)?;
    ensure(&app);
    Ok(status)
}

#[tauri::command]
pub async fn sync_now(app: AppHandle) -> CmdResult<StateView> {
    let engine = engine(&app)?;
    Ok(round(&app, &engine).await)
}

#[tauri::command]
pub async fn sync_unlink(app: AppHandle) -> CmdResult<StateView> {
    let engine = engine(&app)?;
    engine.unlink().await?;
    *lock(&app) = Inner::default();
    publish(&app);
    Ok(view(&app))
}

/// The server has an older state than this device: what is newer here goes up again.
#[tauri::command]
pub async fn sync_resync(app: AppHandle, vault: String) -> CmdResult<StateView> {
    let engine = engine(&app)?;
    engine.resync(&id(&vault)?).await?;
    Ok(round(&app, &engine).await)
}

/// Change the master password. With syncing, the new wrapping goes to the server first (`docs/sync.md`).
#[tauri::command]
pub async fn vault_change_password(app: AppHandle, state: State<'_, AppState>, old: String, new: String, logout_others: Option<bool>) -> CmdResult<()> {
    let (old, new) = (Zeroizing::new(old), Zeroizing::new(new));
    check_password(&new)?;
    ensure(&app);
    let linked = lock(&app).engine.clone();
    match linked {
        Some(engine) => {
            let kdf = state.session().kdf();
            Ok(engine.change_password(&old, &new, kdf, logout_others.unwrap_or(false)).await?)
        }
        None => state.session().change_password(&old, &new),
    }
}

/// Signs this device out and deletes the vault on this PC (`Session::wipe`); then Glowport restarts, so
/// all sessions, port rules and transfers end. If the vault is open and linked to a server, the
/// device is signed out there first; if the server cannot be reached, the command ends with its error unless
/// `force` is set. Locked, signing out does not work (the access is stored encrypted in the vault): the
/// device stays in the device list until another one signs it out.
#[tauri::command]
pub async fn vault_wipe(app: AppHandle, force: bool) -> CmdResult<()> {
    ensure(&app);
    let linked = lock(&app).engine.clone();
    if let Some(engine) = linked {
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(15), engine.sign_out()).await;
        match outcome {
            Ok(Ok(())) => {}
            _ if force => {}
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => return Err(SyncError::Offline("no answer".into()).into()),
        }
    }
    *lock(&app) = Inner::default();
    crate::proxmox::forget_all(&app);
    // What was in the queue belongs to hosts of the deleted vault.
    let queue = &app.state::<crate::transfers::Queue>().0;
    queue.control(None, "cancel");
    queue.clear();
    queue.shutdown();
    crate::windows::forget_open_tabs(&app);
    // If something was left behind, Glowport does not restart: the interface shows what.
    app.state::<AppState>().session().wipe()?;
    app.restart()
}

#[tauri::command]
pub async fn sync_devices(app: AppHandle) -> CmdResult<Vec<glowport_sync::DeviceInfo>> {
    Ok(engine(&app)?.devices().await?)
}

#[tauri::command]
pub async fn sync_device_rename(app: AppHandle, id: String, name: String) -> CmdResult<Vec<glowport_sync::DeviceInfo>> {
    let engine = engine(&app)?;
    let name = name.trim();
    if name.is_empty() {
        return Err(CmdError::invalid("name_required"));
    }
    engine.rename_device(&self::id(&id)?, &device_name(name)).await?;
    Ok(engine.devices().await?)
}

#[tauri::command]
pub async fn sync_device_remove(app: AppHandle, id: String) -> CmdResult<Vec<glowport_sync::DeviceInfo>> {
    let engine = engine(&app)?;
    engine.remove_device(&self::id(&id)?).await?;
    Ok(engine.devices().await?)
}

/// A notice from syncing with the names the interface shows (`SyncNotice` in `types.ts`).
#[derive(Debug, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NoticeView {
    id: i64,
    at: i64,
    kind: &'static str,
    vault_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    record_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mine: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    count: Option<usize>,
}

#[tauri::command]
pub fn sync_notices(state: State<'_, AppState>) -> CmdResult<Vec<NoticeView>> {
    let mut session = state.session();
    let directory = session.directory()?;
    let mut out = Vec::new();
    // The newest first.
    for stored in directory.vault().notices()?.into_iter().rev() {
        let Ok(notice) = serde_json::from_slice::<Notice>(&stored.data) else { continue };
        let base = |kind, vault: &str| NoticeView { id: stored.id, at: stored.at, kind, vault_name: directory.vault_name(vault), ..NoticeView::default() };
        out.push(match &notice {
            Notice::Clash { vault, record, path, mine } => NoticeView { record_name: directory.record_name(record), path: Some(path.clone()), mine: Some(*mine), ..base("clash", vault) },
            Notice::Restored { vault, record } => NoticeView { record_name: directory.record_name(record), ..base("restored", vault) },
            Notice::Discarded { vault, count } => NoticeView { count: Some(*count), ..base("discarded", vault) },
            Notice::VaultRemoved { vault } => base("vault_removed", vault),
            Notice::Rejected { vault, count } => NoticeView { count: Some(*count), ..base("rejected", vault) },
        });
    }
    Ok(out)
}

#[tauri::command]
pub fn sync_notices_clear(app: AppHandle, state: State<'_, AppState>) -> CmdResult<()> {
    state.session().directory()?.vault_mut().clear_notices(i64::MAX)?;
    let _ = app.emit("sync-state", view(&app));
    Ok(())
}

// ── Shared vaults ────────────────────────────────────────────────────────────────────────────────────────

#[tauri::command]
pub async fn shared_create(app: AppHandle, name: String) -> CmdResult<String> {
    let engine = engine(&app)?;
    let vault = engine.create_vault(&name).await?;
    round(&app, &engine).await;
    Ok(glowport_core::crypto::hex(&vault))
}

/// The name is stored as a record in the vault and goes to the others with the next sync.
#[tauri::command]
pub fn shared_rename(state: State<'_, AppState>, vault: String, name: String) -> CmdResult<()> {
    let mut session = state.session();
    session.directory()?.rename_vault(&vault, &name)?;
    session.changed(None).map(drop)
}

#[derive(Serialize)]
pub struct CandidateView {
    account: String,
    username: String,
    code: String,
    known: Known,
}

#[tauri::command]
pub async fn shared_lookup(app: AppHandle, username: String) -> CmdResult<CandidateView> {
    let candidate = engine(&app)?.lookup(&username.trim().to_lowercase()).await?;
    let view = CandidateView { account: candidate.account.clone(), username: candidate.username.clone(), code: candidate.code.clone(), known: candidate.known };
    lock(&app).candidates.insert(candidate.account.clone(), candidate);
    Ok(view)
}

#[tauri::command]
pub async fn shared_invite(app: AppHandle, vault: String, account: String, role: Role) -> CmdResult<()> {
    let engine = engine(&app)?;
    // Exactly the account is invited whose keys' safety code was just shown.
    let candidate = lock(&app).candidates.get(&account).cloned().ok_or_else(|| CmdError::new("not_found", "Account not looked up"))?;
    engine.invite(&id(&vault)?, &candidate, role).await?;
    round(&app, &engine).await;
    Ok(())
}

#[tauri::command]
pub async fn shared_set_role(app: AppHandle, vault: String, account: String, role: Role) -> CmdResult<()> {
    let engine = engine(&app)?;
    engine.set_role(&id(&vault)?, &id(&account)?, role).await?;
    round(&app, &engine).await;
    Ok(())
}

#[tauri::command]
pub async fn shared_remove(app: AppHandle, vault: String, account: String) -> CmdResult<()> {
    let engine = engine(&app)?;
    engine.remove_member(&id(&vault)?, &id(&account)?).await?;
    round(&app, &engine).await;
    Ok(())
}

#[tauri::command]
pub async fn shared_transfer(app: AppHandle, vault: String, account: String) -> CmdResult<()> {
    let engine = engine(&app)?;
    engine.transfer(&id(&vault)?, &id(&account)?).await?;
    round(&app, &engine).await;
    Ok(())
}

#[tauri::command]
pub async fn shared_leave(app: AppHandle, vault: String) -> CmdResult<()> {
    let engine = engine(&app)?;
    engine.leave(&id(&vault)?).await?;
    round(&app, &engine).await;
    Ok(())
}

#[tauri::command]
pub async fn shared_delete(app: AppHandle, vault: String) -> CmdResult<()> {
    let engine = engine(&app)?;
    engine.delete_vault(&id(&vault)?).await?;
    round(&app, &engine).await;
    Ok(())
}

#[tauri::command]
pub async fn invitation_accept(app: AppHandle, vault: String) -> CmdResult<()> {
    let engine = engine(&app)?;
    engine.accept(&id(&vault)?).await?;
    round(&app, &engine).await;
    Ok(())
}

#[tauri::command]
pub async fn invitation_decline(app: AppHandle, vault: String) -> CmdResult<StateView> {
    let engine = engine(&app)?;
    engine.leave(&id(&vault)?).await?;
    Ok(round(&app, &engine).await)
}

// ── Server administration ───────────────────────────────────────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteView {
    code: String,
    created_at: i64,
    expires_at: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountView {
    id: String,
    username: String,
    admin: bool,
    disabled: bool,
    created_at: i64,
    seen_at: i64,
    devices: u32,
    bytes: u64,
}

fn invites(list: Vec<Invite>) -> Vec<InviteView> {
    list.into_iter().map(|invite| InviteView { code: invite.code, created_at: invite.created_at, expires_at: invite.expires_at }).collect()
}

fn accounts(list: Vec<AdminAccount>) -> Vec<AccountView> {
    list.into_iter()
        .map(|a| AccountView { id: glowport_core::crypto::hex(&a.id.0), username: a.username, admin: a.admin, disabled: a.disabled, created_at: a.created_at, seen_at: a.seen_at, devices: a.devices, bytes: a.bytes })
        .collect()
}

#[tauri::command]
pub async fn admin_invites(app: AppHandle) -> CmdResult<Vec<InviteView>> {
    Ok(invites(engine(&app)?.invites().await?))
}

#[tauri::command]
pub async fn admin_invite_create(app: AppHandle) -> CmdResult<Vec<InviteView>> {
    let engine = engine(&app)?;
    engine.create_invite().await?;
    Ok(invites(engine.invites().await?))
}

#[tauri::command]
pub async fn admin_invite_revoke(app: AppHandle, code: String) -> CmdResult<Vec<InviteView>> {
    let engine = engine(&app)?;
    engine.revoke_invite(&code).await?;
    Ok(invites(engine.invites().await?))
}

#[tauri::command]
pub async fn admin_accounts(app: AppHandle) -> CmdResult<Vec<AccountView>> {
    Ok(accounts(engine(&app)?.accounts().await?))
}

#[tauri::command]
pub async fn admin_account_disable(app: AppHandle, id: String, disabled: bool) -> CmdResult<Vec<AccountView>> {
    let engine = engine(&app)?;
    engine.set_disabled(&self::id(&id)?, disabled).await?;
    Ok(accounts(engine.accounts().await?))
}

#[tauri::command]
pub async fn admin_account_delete(app: AppHandle, id: String) -> CmdResult<Vec<AccountView>> {
    let engine = engine(&app)?;
    engine.delete_account(&self::id(&id)?).await?;
    Ok(accounts(engine.accounts().await?))
}

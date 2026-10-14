//! Bridge between interface and core for vault, hosts and groups.
//!
//! Only the state “no vault / locked / open” and the auto-lock live here. All rules are in `glowport-core`.
//! The flows are methods of `Session` so they can be tested without a program window; the commands only pass through.

use std::{
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
    time::{Duration, Instant},
};

use glowport_core::{
    crypto::KdfParams,
    directory::{DirError, Directory, GroupInput, HostInput, Invalid, Snapshot, WorkspaceInput},
    vault::{Vault, VaultError},
};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_dialog::DialogExt;
use zeroize::Zeroizing;

use crate::keystore::{KeyStore, ProtectedFile};

const MIN_PASSWORD_CHARS: usize = 8;
/// As long as no sync is set up, nobody needs old tombstones.
const TOMBSTONE_MAX_AGE_MS: i64 = 90 * 24 * 60 * 60 * 1000;

// There is exactly one of this state in the whole program; its size does not matter.
#[allow(clippy::large_enum_variant)]
enum Phase {
    Missing,
    Locked(Vault),
    Open(Directory),
    /// The file could not be opened (damaged or from a newer version).
    Broken(CmdError),
}

pub struct Session {
    path: PathBuf,
    phase: Phase,
    kdf: KdfParams,
    /// If switched on, holds the key for unlocking at startup without the master password.
    keystore: Box<dyn KeyStore>,
    /// Not yet tried to open without the master password at startup.
    start_pending: bool,
    last_activity: Instant,
    auto_lock: Option<Duration>,
    /// Called when the vault's state or content changed, so all windows follow.
    notify: Option<Box<dyn Fn() + Send>>,
}

pub struct AppState(Mutex<Session>);

/// Error as the interface gets it: a fixed code to translate, plus the text for logs.
#[derive(Debug, Clone, Serialize)]
pub struct CmdError {
    code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<Invalid>,
    message: String,
}

impl CmdError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self { code, reason: None, message: message.into() }
    }

    pub(crate) fn code(&self) -> &'static str {
        self.code
    }

    /// Rejected input with the reason as text, for checks outside the core.
    pub(crate) fn invalid(reason: &'static str) -> Self {
        Self::new(reason, format!("Eingabe abgelehnt: {reason}"))
    }
}

impl From<VaultError> for CmdError {
    fn from(error: VaultError) -> Self {
        let code = match &error {
            VaultError::Locked => "locked",
            VaultError::WrongPassword => "wrong_password",
            VaultError::AlreadyExists => "exists",
            VaultError::NotFound => "not_found",
            VaultError::Corrupt(_) => "corrupt",
            VaultError::UnsupportedFormat(_) => "unsupported",
            VaultError::ReadOnly => "read_only",
            VaultError::NotOwner => "not_owner",
            VaultError::NotMember => "not_member",
            VaultError::Roster(_) => "roster_invalid",
            VaultError::Kdf | VaultError::StaleDeviceKey | VaultError::Personal | VaultError::Pending | VaultError::Db(_) | VaultError::Io(_) => "internal",
        };
        Self::new(code, error.to_string())
    }
}

impl From<DirError> for CmdError {
    fn from(error: DirError) -> Self {
        match error {
            DirError::Vault(e) => e.into(),
            DirError::NotFound => Self::new("not_found", error.to_string()),
            DirError::Invalid(reason) => Self { code: "invalid", reason: Some(reason), message: error.to_string() },
        }
    }
}

pub(crate) type CmdResult<T> = Result<T, CmdError>;

#[derive(Serialize)]
pub struct Status {
    /// `missing`, `locked`, `open` or `broken`.
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Snapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<CmdError>,
    /// Whether the vault is opened at startup without the master password.
    #[serde(rename = "startUnlock")]
    start_unlock: bool,
}

/// Answer to a change: the new state and, if something was created, its ID.
#[derive(Serialize)]
pub struct Changed {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    data: Snapshot,
}

/// What [`Session::wipe`] deletes besides the vault: SQLite's rollback journal, the intermediate files of
/// restoring and converting, and the backups created when signing in with an account. Up to version 1.0.1
/// these files had German names (`db.alt`, `db.neu`, `glowport-vor-konto-…`); they go too.
fn wipe_targets(path: &Path) -> Vec<PathBuf> {
    let mut targets = vec![path.to_path_buf(), Vault::migration_copy(path)];
    targets.extend(["db.old", "db.new", "db.alt", "db.neu"].map(|extension| path.with_extension(extension)));
    let mut journal = path.as_os_str().to_os_string();
    journal.push("-journal");
    targets.push(journal.into());
    if let Some(entries) = path.parent().and_then(|dir| std::fs::read_dir(dir).ok()) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if (name.starts_with("glowport-before-account-") || name.starts_with("glowport-vor-konto-")) && name.ends_with(".gpvault") {
                targets.push(entry.path());
            }
        }
    }
    targets
}

pub(crate) fn check_password(password: &str) -> CmdResult<()> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(CmdError::new("weak_password", "The master password is too short"));
    }
    Ok(())
}

impl Session {
    fn new(path: PathBuf, kdf: KdfParams, keystore: Box<dyn KeyStore>) -> Self {
        let phase = Self::probe(&path);
        Self { path, phase, kdf, keystore, start_pending: true, last_activity: Instant::now(), auto_lock: None, notify: None }
    }

    fn notify(&self) {
        if let Some(notify) = &self.notify {
            notify();
        }
    }

    /// State for program start. On the first call, the vault is opened without the master password if that is switched on.
    /// That happens here and not when creating the session, so reading the stored key (file, DPAPI) does not hold up
    /// building the window. The command for it runs with `async`, i.e. off the window thread.
    fn initial_status(&mut self) -> Status {
        if std::mem::take(&mut self.start_pending) {
            self.start_unlock();
        }
        self.status()
    }

    /// Opens the vault at startup with the stored key, if the user switched that on.
    /// If the key does not fit (another vault, another Windows sign-in), it is discarded and the
    /// master password is requested.
    fn start_unlock(&mut self) {
        let Phase::Locked(vault) = &mut self.phase else { return };
        let Some(key) = vault.device_id().ok().and_then(|context| self.keystore.load(&context)) else { return };
        if vault.unlock_with_key(&key).is_err() {
            let _ = self.keystore.clear();
            return;
        }
        if let Phase::Locked(vault) = std::mem::replace(&mut self.phase, Phase::Missing) {
            self.phase = Self::opened(vault);
        }
        // As after unlocking by hand: the windows follow, and syncing starts.
        self.notify();
    }

    /// Reads a freshly unlocked vault.
    fn opened(mut vault: Vault) -> Phase {
        let _ = vault.purge_tombstones(TOMBSTONE_MAX_AGE_MS);
        match Directory::load(vault) {
            Ok(directory) => Phase::Open(directory),
            Err(e) => Phase::Broken(e.into()),
        }
    }

    /// Switches unlocking at startup without the master password on or off.
    fn set_start_unlock(&mut self, enabled: bool) -> CmdResult<Status> {
        let internal = |e: std::io::Error| CmdError::new("internal", e.to_string());
        if enabled {
            let vault = self.directory()?.vault();
            let (context, key) = (vault.device_id()?, vault.device_key()?);
            self.keystore.store(&context, &key).map_err(internal)?;
        } else {
            self.keystore.clear().map_err(internal)?;
        }
        Ok(self.status())
    }

    /// Determines the state from the file: missing, can be opened (locked) or unusable.
    fn probe(path: &Path) -> Phase {
        if !Vault::exists(path) {
            return Phase::Missing;
        }
        match Vault::open(path) {
            Ok(vault) => Phase::Locked(vault),
            Err(e) => Phase::Broken(e.into()),
        }
    }

    fn status(&self) -> Status {
        let (state, data, error) = match &self.phase {
            Phase::Missing => ("missing", None, None),
            Phase::Locked(_) => ("locked", None, None),
            Phase::Open(directory) => ("open", Some(directory.snapshot()), None),
            Phase::Broken(error) => ("broken", None, Some(error.clone())),
        };
        Status { state, data, error, start_unlock: self.keystore.is_set() }
    }

    /// Access to the entries. Counts as input for the auto-lock.
    pub(crate) fn directory(&mut self) -> CmdResult<&mut Directory> {
        self.last_activity = Instant::now();
        match &mut self.phase {
            Phase::Open(directory) => Ok(directory),
            _ => Err(VaultError::Locked.into()),
        }
    }

    pub(crate) fn create(&mut self, password: &str) -> CmdResult<Status> {
        check_password(password)?;
        if !matches!(self.phase, Phase::Missing) {
            return Err(VaultError::AlreadyExists.into());
        }
        let vault = Vault::create(&self.path, password, self.kdf)?;
        self.phase = Phase::Open(Directory::load(vault)?);
        self.last_activity = Instant::now();
        self.notify();
        Ok(self.status())
    }

    fn unlock(&mut self, password: &str) -> CmdResult<Status> {
        // Take the vault out briefly, because opening moves it into another state.
        let mut vault = match std::mem::replace(&mut self.phase, Phase::Missing) {
            Phase::Locked(vault) => vault,
            other => {
                self.phase = other;
                return Ok(self.status());
            }
        };
        if let Err(e) = vault.unlock(password) {
            self.phase = Phase::Locked(vault);
            return Err(e.into());
        }
        self.phase = Self::opened(vault);
        if let Phase::Broken(error) = &self.phase {
            return Err(error.clone());
        }
        self.last_activity = Instant::now();
        self.notify();
        Ok(self.status())
    }

    fn lock(&mut self) {
        match std::mem::replace(&mut self.phase, Phase::Missing) {
            Phase::Open(directory) => {
                let mut vault = directory.into_vault();
                vault.lock();
                self.phase = Phase::Locked(vault);
                self.notify();
            }
            other => self.phase = other,
        }
    }

    /// Deletes this PC's vault with everything that belongs to it: copies from converting, restoring and signing in,
    /// the stored key for starting without the master password. Works open, locked and unusable; afterwards the vault is missing.
    /// Settings, background image, recordings and logs stay.
    pub(crate) fn wipe(&mut self) -> CmdResult<()> {
        // The file is closed before it disappears.
        self.phase = Phase::Missing;
        let mut failed = Vec::new();
        if let Err(error) = self.keystore.clear() {
            failed.push(error.to_string());
        }
        for path in wipe_targets(&self.path) {
            match std::fs::remove_file(&path) {
                Err(error) if error.kind() != std::io::ErrorKind::NotFound => failed.push(format!("{}: {error}", path.display())),
                _ => {}
            }
        }
        self.phase = Self::probe(&self.path);
        self.notify();
        match failed.is_empty() {
            true => Ok(()),
            false => Err(CmdError::new("wipe_failed", failed.join("; "))),
        }
    }

    /// Makes a backup this PC's vault. Only works while there is none here yet: an existing
    /// vault is never overwritten. Afterwards the vault is locked and asks for the backup's master password.
    pub(crate) fn restore(&mut self, backup: &Path) -> CmdResult<Status> {
        if !matches!(self.phase, Phase::Missing) {
            return Err(VaultError::AlreadyExists.into());
        }
        // Check first, then put it in place: a file that is not a vault never ends up there.
        let staged = self.path.with_extension("db.new");
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| CmdError::new("internal", e.to_string()))?;
        }
        std::fs::copy(backup, &staged).map_err(|e| CmdError::new("restore_invalid", e.to_string()))?;
        // A backup from an older version is converted when opened; the copy before that is the backup itself here.
        let opened = Vault::open(&staged).is_ok();
        let _ = std::fs::remove_file(Vault::migration_copy(&staged));
        if !opened {
            let _ = std::fs::remove_file(&staged);
            return Err(CmdError::new("restore_invalid", "Not a Glowport backup"));
        }
        std::fs::rename(&staged, &self.path).map_err(|e| CmdError::new("internal", e.to_string()))?;
        self.phase = Self::probe(&self.path);
        self.notify();
        Ok(self.status())
    }

    pub(crate) fn change_password(&mut self, old: &str, new: &str) -> CmdResult<()> {
        check_password(new)?;
        let kdf = self.kdf;
        Ok(self.directory()?.vault_mut().change_password(old, new, kdf)?)
    }

    fn auto_lock_due(&self) -> bool {
        matches!(self.phase, Phase::Open(_)) && self.auto_lock.is_some_and(|limit| self.last_activity.elapsed() >= limit)
    }

    pub(crate) fn is_open(&self) -> bool {
        matches!(self.phase, Phase::Open(_))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn kdf(&self) -> KdfParams {
        self.kdf
    }

    /// For syncing: work on the open vault that does not count as input for the auto-lock. If the
    /// vault changed in the process, the directory reads it again. `None`: the vault is not open.
    pub(crate) fn background<T>(&mut self, work: impl FnOnce(&mut Vault) -> T) -> Option<(T, bool)> {
        let Phase::Open(directory) = &mut self.phase else { return None };
        let before = directory.vault().writes();
        let result = work(directory.vault_mut());
        let changed = directory.vault().writes() != before;
        if changed {
            // If reading fails, the interface shows the old state; the vault itself is untouched.
            let _ = directory.refresh();
        }
        Some((result, changed))
    }

    /// The directory, without the access counting as input for the auto-lock.
    pub(crate) fn directory_quiet(&mut self) -> Option<&mut Directory> {
        match &mut self.phase {
            Phase::Open(directory) => Some(directory),
            _ => None,
        }
    }

    /// First start, “Sign in with an account”: the vault was just created from an account and is already open.
    pub(crate) fn adopt_opened(&mut self, vault: Vault) -> CmdResult<Status> {
        if !matches!(self.phase, Phase::Missing) {
            return Err(VaultError::AlreadyExists.into());
        }
        self.phase = Self::opened(vault);
        self.last_activity = Instant::now();
        self.notify();
        Ok(self.status())
    }

    /// Replaces this device's vault with an account's (`staged`: the file freshly created for it).
    /// A backup of the previous one is created next to it first. With `keep` its entries go into the account.
    /// Afterwards the account's master password applies, and starting without the master password is off. Returns the
    /// backup's path.
    pub(crate) fn replace_with_account(&mut self, staged: &Path, password: &str, keep: bool, stamp: &str) -> CmdResult<PathBuf> {
        let internal = |e: std::io::Error| CmdError::new("internal", e.to_string());
        let old = match std::mem::replace(&mut self.phase, Phase::Missing) {
            Phase::Open(directory) => directory.into_vault(),
            other => {
                self.phase = other;
                return Err(VaultError::Locked.into());
            }
        };
        let backup = self.path.with_file_name(format!("glowport-before-account-{stamp}.gpvault"));
        let prepared = (|| -> CmdResult<()> {
            old.backup(&backup)?;
            let mut new = Vault::open(staged)?;
            new.unlock(password)?;
            if keep {
                new.adopt_from(&old)?;
            }
            Ok(())
        })();
        if let Err(error) = prepared {
            self.phase = Self::opened(old);
            return Err(error);
        }
        // Both files are closed before they swap places.
        drop(old);
        let parked = self.path.with_extension("db.old");
        let _ = std::fs::remove_file(&parked);
        std::fs::rename(&self.path, &parked).map_err(internal)?;
        if let Err(error) = std::fs::rename(staged, &self.path) {
            let _ = std::fs::rename(&parked, &self.path);
            self.phase = Self::probe(&self.path);
            return Err(internal(error));
        }
        let _ = std::fs::remove_file(&parked);
        // The stored key belonged to the old vault.
        let _ = self.keystore.clear();
        let mut vault = Vault::open(&self.path)?;
        vault.unlock(password)?;
        self.phase = Self::opened(vault);
        self.last_activity = Instant::now();
        self.notify();
        Ok(backup)
    }

    pub(crate) fn changed(&mut self, id: Option<String>) -> CmdResult<Changed> {
        let data = self.directory()?.snapshot();
        self.notify();
        Ok(Changed { id, data })
    }
}

impl AppState {
    pub fn new(path: PathBuf) -> Self {
        let keystore = ProtectedFile::new(path.with_file_name("start-unlock.bin"));
        Self(Mutex::new(Session::new(path, KdfParams::DEFAULT, Box::new(keystore))))
    }

    /// Reports changes to the vault. The windows then fetch the new state; that keeps all of them the same.
    pub fn watch(&self, notify: impl Fn() + Send + 'static) {
        self.session().notify = Some(Box::new(notify));
    }

    /// A crash in another command should not block the program permanently.
    pub(crate) fn session(&self) -> MutexGuard<'_, Session> {
        self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Sends the interface the current state when the vault changed without its doing
/// (host key saved, operating system detected, password taken over after signing in).
pub(crate) fn emit_snapshot(app: &AppHandle) {
    if let Ok(directory) = app.state::<AppState>().session().directory() {
        // As a JSON value, because an event must be able to copy its payload.
        if let Ok(snapshot) = serde_json::to_value(directory.snapshot()) {
            let _ = app.emit("vault-changed", snapshot);
        }
    }
}

/// Like [`emit_snapshot`], for changes by sync: they do not count as input for the auto-lock.
pub(crate) fn emit_snapshot_quiet(app: &AppHandle) {
    let snapshot = app.state::<AppState>().session().directory_quiet().map(|directory| serde_json::to_value(directory.snapshot()));
    if let Some(Ok(snapshot)) = snapshot {
        let _ = app.emit("vault-changed", snapshot);
    }
}

/// Locks the vault when nothing was typed for longer than set, and tells the interface.
pub fn spawn_auto_lock(app: AppHandle) {
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(5));
        let state = app.state::<AppState>();
        let mut session = state.session();
        if session.auto_lock_due() {
            session.lock();
            drop(session);
            crate::proxmox::forget_all(&app);
            let _ = app.emit("vault-locked", ());
        }
    });
}

#[tauri::command(async)]
pub fn vault_status(state: State<'_, AppState>) -> Status {
    state.session().initial_status()
}

#[tauri::command(async)]
pub fn vault_create(state: State<'_, AppState>, password: String) -> CmdResult<Status> {
    state.session().create(&Zeroizing::new(password))
}

#[tauri::command(async)]
pub fn vault_unlock(state: State<'_, AppState>, password: String) -> CmdResult<Status> {
    state.session().unlock(&Zeroizing::new(password))
}

#[tauri::command]
pub fn vault_lock(app: AppHandle, state: State<'_, AppState>) -> Status {
    let mut session = state.session();
    session.lock();
    crate::proxmox::forget_all(&app);
    session.status()
}

/// Asks for the location and writes a backup. `None` if the dialog was cancelled.
#[tauri::command(async)]
pub fn vault_backup(app: AppHandle, state: State<'_, AppState>, file_name: String) -> CmdResult<Option<String>> {
    // The dialog blocks; meanwhile the state stays free for other commands and the auto-lock.
    let Some(chosen) = app.dialog().file().set_file_name(file_name).add_filter("Glowport", &["gpvault"]).blocking_save_file() else {
        return Ok(None);
    };
    let path = chosen.into_path().map_err(|e| CmdError::new("internal", e.to_string()))?;
    state.session().directory()?.vault().backup(&path)?;
    Ok(Some(path.display().to_string()))
}

/// Lets the user choose a backup and restores it. `None` if the dialog was cancelled.
#[tauri::command(async)]
pub fn vault_restore(app: AppHandle, state: State<'_, AppState>) -> CmdResult<Option<Status>> {
    let Some(chosen) = app.dialog().file().add_filter("Glowport", &["gpvault", "db"]).blocking_pick_file() else {
        return Ok(None);
    };
    let path = chosen.into_path().map_err(|e| CmdError::new("internal", e.to_string()))?;
    state.session().restore(&path).map(Some)
}

#[tauri::command(async)]
pub fn vault_set_start_unlock(state: State<'_, AppState>, enabled: bool) -> CmdResult<Status> {
    state.session().set_start_unlock(enabled)
}

#[tauri::command]
pub fn vault_set_auto_lock(state: State<'_, AppState>, minutes: u32) {
    let mut session = state.session();
    session.auto_lock = (minutes > 0).then(|| Duration::from_secs(u64::from(minutes) * 60));
    session.last_activity = Instant::now();
}

/// The interface reports input so the auto-lock does not strike in the middle of work.
#[tauri::command]
pub fn vault_touch(state: State<'_, AppState>) {
    state.session().last_activity = Instant::now();
}

/// `vault`: only when creating, the vault the entry goes into. Without it, its group's vault,
/// otherwise the personal one.
#[tauri::command]
pub fn host_save(app: AppHandle, state: State<'_, AppState>, host: HostInput, vault: Option<String>) -> CmdResult<Changed> {
    let mut session = state.session();
    let id = session.directory()?.in_vault(vault.as_deref(), |directory| directory.save_host(host))?;
    crate::files::forget_ftp(&app, &id);
    session.changed(Some(id))
}

/// Moves a host into another vault. `carry`: identity and key come along as copies.
#[tauri::command]
pub fn host_move(state: State<'_, AppState>, id: String, vault: String, carry: bool) -> CmdResult<Changed> {
    let mut session = state.session();
    let id = session.directory()?.move_host(&id, &vault, carry)?;
    session.changed(Some(id))
}

#[tauri::command]
pub fn host_duplicate(state: State<'_, AppState>, id: String, name: String) -> CmdResult<Changed> {
    let mut session = state.session();
    let id = session.directory()?.duplicate_host(&id, &name)?;
    session.changed(Some(id))
}

#[tauri::command]
pub fn host_delete(app: AppHandle, state: State<'_, AppState>, id: String) -> CmdResult<Changed> {
    let mut session = state.session();
    session.directory()?.delete_host(&id)?;
    crate::files::forget_ftp(&app, &id);
    session.changed(None)
}

#[tauri::command]
pub fn group_save(state: State<'_, AppState>, group: GroupInput, vault: Option<String>) -> CmdResult<Changed> {
    let mut session = state.session();
    let id = session.directory()?.in_vault(vault.as_deref(), |directory| directory.save_group(group))?;
    session.changed(Some(id))
}

#[tauri::command]
pub fn group_delete(state: State<'_, AppState>, id: String, with_contents: bool) -> CmdResult<Changed> {
    let mut session = state.session();
    session.directory()?.delete_group(&id, with_contents)?;
    session.changed(None)
}

/// Lets the user choose a key file. `None` if the dialog was cancelled.
#[tauri::command(async)]
pub fn pick_key_file(app: AppHandle) -> Option<String> {
    app.dialog().file().blocking_pick_file().and_then(|chosen| chosen.into_path().ok()).map(|path| path.display().to_string())
}

#[tauri::command]
pub fn workspace_save(state: State<'_, AppState>, workspace: WorkspaceInput) -> CmdResult<Changed> {
    let mut session = state.session();
    let id = session.directory()?.save_workspace(workspace)?;
    session.changed(Some(id))
}

#[tauri::command]
pub fn workspace_delete(state: State<'_, AppState>, id: String) -> CmdResult<Changed> {
    let mut session = state.session();
    session.directory()?.delete_workspace(&id)?;
    session.changed(None)
}

#[tauri::command]
pub fn known_host_delete(state: State<'_, AppState>, id: String) -> CmdResult<Changed> {
    let mut session = state.session();
    session.directory()?.delete_known_host(&id)?;
    session.changed(None)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::keystore::MemoryStore;
    use glowport_core::crypto::{random_key, Key};
    use serde_json::{json, Value};
    use std::sync::Arc;

    const FAST: KdfParams = KdfParams { memory_kib: 64, passes: 1, lanes: 1 };

    pub(crate) struct Temp(PathBuf);
    impl Temp {
        pub(crate) fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!("glowport-app-{}-{name}.db", std::process::id()));
            let _ = std::fs::remove_file(&path);
            Self(path)
        }
        fn session(&self) -> Session {
            Session::new(self.0.clone(), FAST, Box::new(MemoryStore::default()))
        }
        /// State as the commands see it, with fast key derivation and without storage on disk.
        pub(crate) fn state(&self) -> AppState {
            AppState(Mutex::new(self.session()))
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn as_json<T: Serialize>(value: &T) -> Value {
        serde_json::to_value(value).unwrap()
    }

    #[test]
    fn restores_a_backup_only_where_no_vault_exists() {
        let source = Temp::new("restore-quelle");
        let backup = Temp::new("restore-sicherung");
        let mut session = source.session();
        session.create("right-and-long").unwrap();
        session.directory().unwrap().save_host(serde_json::from_value(json!({ "name": "web", "address": "10.0.0.1" })).unwrap()).unwrap();
        session.directory().unwrap().vault().backup(&backup.0).unwrap();
        // An existing vault is never overwritten.
        assert_eq!(session.restore(&backup.0).err().unwrap().code(), "exists");

        let target = Temp::new("restore-ziel");
        let mut fresh = target.session();
        // What is not a backup never ends up in the vault's place.
        let junk = Temp::new("restore-unsinn");
        std::fs::write(&junk.0, b"not a vault").unwrap();
        assert_eq!(fresh.restore(&junk.0).err().unwrap().code(), "restore_invalid");
        assert!(!target.0.exists());
        assert_eq!(fresh.status().state, "missing");

        // The backup becomes the vault: locked, and it opens with its own master password.
        assert_eq!(fresh.restore(&backup.0).unwrap().state, "locked");
        assert_eq!(fresh.unlock("wrong-and-long").err().unwrap().code(), "wrong_password");
        let opened = fresh.unlock("right-and-long").unwrap();
        assert_eq!(opened.data.unwrap().hosts[0].name, "web");
        let _ = std::fs::remove_file(target.0.with_extension("db.new"));
    }

    fn code<T>(result: CmdResult<T>) -> &'static str {
        result.err().map_or("no error", |e| e.code)
    }

    #[test]
    fn vault_walks_through_its_states() {
        let temp = Temp::new("states");
        let mut session = temp.session();
        assert_eq!(as_json(&session.status()), json!({ "state": "missing", "startUnlock": false }));
        assert_eq!(code(session.create("kurz")), "weak_password");
        assert_eq!(code(session.directory().map(drop)), "locked");

        let created = as_json(&session.create("long enough").unwrap());
        // A new vault is empty except for itself: the personal vault in which everything else lives.
        let personal = json!({ "id": created["data"]["vaults"][0]["id"], "kind": "personal", "name": "", "role": "owner", "members": [], "rolledBack": false, "orphaned": false });
        assert!(created["data"]["seq"].as_u64().is_some_and(|seq| seq > 0), "every state carries its sequence number");
        let empty = json!({ "seq": created["data"]["seq"], "groups": [], "hosts": [], "damaged": 0, "knownHosts": [], "keys": [], "identities": [], "authorities": [], "workspaces": [], "forwards": [], "snippets": [], "proxmox": [], "vaults": [personal], "homes": {} });
        assert_eq!(created, json!({ "state": "open", "data": empty, "startUnlock": false }));
        assert_eq!(code(session.create("long enough")), "exists");

        session.lock();
        assert_eq!(as_json(&session.status()), json!({ "state": "locked", "startUnlock": false }));
        assert_eq!(code(session.unlock("wrong")), "wrong_password");
        assert_eq!(as_json(&session.status())["state"], "locked", "after a wrong password the vault stays locked");
        assert_eq!(as_json(&session.unlock("long enough").unwrap())["state"], "open");
        assert_eq!(as_json(&session.unlock("whatever").unwrap())["state"], "open", "an open vault stays open");

        // A new program start finds the file and asks for the password.
        drop(session);
        let mut session = temp.session();
        assert_eq!(as_json(&session.status())["state"], "locked");
        assert_eq!(code(session.change_password("long enough", "new password")), "locked");
        session.unlock("long enough").unwrap();
        assert_eq!(code(session.change_password("wrong", "new password")), "wrong_password");
        assert_eq!(code(session.change_password("long enough", "short")), "weak_password");
        session.change_password("long enough", "new password").unwrap();
        session.lock();
        assert_eq!(code(session.unlock("long enough")), "wrong_password");
        session.unlock("new password").unwrap();
    }

    /// Exactly the shapes the interface sends and expects (see src/lib/types.ts).
    #[test]
    fn messages_match_what_the_interface_sends_and_expects() {
        let temp = Temp::new("shapes");
        let mut session = temp.session();
        session.create("long enough").unwrap();

        let group: GroupInput = serde_json::from_value(json!({ "name": "Production", "parent": null, "color": "#FF5D6C", "defs": { "user": "deploy", "port": 2200 } })).unwrap();
        let group_id = session.directory().unwrap().save_group(group).unwrap();
        let host: HostInput = serde_json::from_value(json!({
            "name": "web-01", "address": "10.0.10.11", "group": group_id, "color": null, "os": "Ub",
            "own": { "startcmd": "cd /srv", "reconnect": "auto", "jump": "" }, "password": "geheim"
        }))
        .unwrap();
        let host_id = session.directory().unwrap().save_host(host).unwrap();

        let changed = as_json(&session.changed(Some(host_id.clone())).unwrap());
        assert_eq!(changed["id"], host_id);
        assert_eq!(
            changed["data"]["hosts"][0],
            json!({
                "id": host_id, "name": "web-01", "address": "10.0.10.11", "group": group_id, "protocol": "ssh", "color": null, "os": "Ub",
                "own": { "jump": "", "startcmd": "cd /srv", "reconnect": "auto" }, "hasPassword": true, "hasProxyPassword": false
            })
        );
        assert_eq!(changed["data"]["groups"][0], json!({ "id": group_id, "name": "Production", "parent": null, "color": "#FF5D6C", "defs": { "user": "deploy", "port": 2200 }, "hasProxyPassword": false }));
        assert!(!changed.to_string().contains("geheim"), "the password must not leave the core");

        // A workspace as the interface builds it from a tab, and the message to the other windows.
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = calls.clone();
        session.notify = Some(Box::new(move || {
            counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }));
        let layout = json!({ "dir": "row", "ratio": 0.5, "a": { "pane": { "kind": "host", "id": host_id } }, "b": { "pane": { "kind": "host", "id": host_id } } });
        let workspace: WorkspaceInput = serde_json::from_value(json!({ "name": "Deploy round", "multi": true, "layout": layout })).unwrap();
        let workspace_id = session.directory().unwrap().save_workspace(workspace).unwrap();
        let changed = as_json(&session.changed(Some(workspace_id.clone())).unwrap());
        assert_eq!(changed["data"]["workspaces"], json!([{ "id": workspace_id, "name": "Deploy round", "multi": true, "layout": layout }]));
        session.lock();
        session.unlock("long enough").unwrap();
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 3, "change, lock and unlock report to the windows");

        let rejected: HostInput = serde_json::from_value(json!({ "name": "", "address": "x", "group": null, "color": null, "os": null, "own": {} })).unwrap();
        let error: CmdError = session.directory().unwrap().save_host(rejected).unwrap_err().into();
        assert_eq!(as_json(&error)["code"], "invalid");
        assert_eq!(as_json(&error)["reason"], "name_required");
        assert_eq!(as_json(&CmdError::from(VaultError::WrongPassword)), json!({ "code": "wrong_password", "message": "Wrong master password" }));
    }

    /// Storage that outlasts several program starts, like the real file.
    struct Shared(Arc<MemoryStore>);
    impl KeyStore for Shared {
        fn load(&self, context: &[u8]) -> Option<Key> {
            self.0.load(context)
        }
        fn store(&self, context: &[u8], key: &Key) -> std::io::Result<()> {
            self.0.store(context, key)
        }
        fn clear(&self) -> std::io::Result<()> {
            self.0.clear()
        }
        fn is_set(&self) -> bool {
            self.0.is_set()
        }
    }

    #[test]
    fn start_unlock_opens_at_launch_but_locking_still_needs_the_password() {
        let temp = Temp::new("startunlock");
        let store = Arc::new(MemoryStore::default());
        let launch = || Session::new(temp.0.clone(), FAST, Box::new(Shared(store.clone())));

        let mut session = launch();
        assert_eq!(code(session.set_start_unlock(true)), "locked", "without an open vault there is nothing to store");
        session.create("long enough").unwrap();
        assert_eq!(as_json(&session.set_start_unlock(true).unwrap())["startUnlock"], true);
        drop(session);

        // Next start: open without a password.
        let mut session = launch();
        assert_eq!(as_json(&session.initial_status())["state"], "open");
        // Locked stays locked: after that only the master password helps.
        session.lock();
        assert_eq!(as_json(&session.status())["state"], "locked");
        assert_eq!(code(session.unlock("wrong")), "wrong_password");
        session.unlock("long enough").unwrap();
        // A new master password leaves the stored key valid.
        session.change_password("long enough", "new password").unwrap();
        drop(session);
        assert_eq!(as_json(&launch().initial_status())["state"], "open");

        // Switching off removes the key; the next start asks for the password again.
        let mut session = launch();
        session.initial_status();
        assert_eq!(as_json(&session.set_start_unlock(false).unwrap())["startUnlock"], false);
        drop(session);
        assert_eq!(as_json(&launch().initial_status()), json!({ "state": "locked", "startUnlock": false }));
    }

    #[test]
    fn wipe_removes_the_vault_and_its_copies_but_keeps_the_rest() {
        let dir = std::env::temp_dir().join(format!("glowport-app-{}-wipe", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.db");
        let store = Arc::new(MemoryStore::default());
        let mut session = Session::new(path.clone(), FAST, Box::new(Shared(store.clone())));
        session.create("long enough").unwrap();
        session.set_start_unlock(true).unwrap();
        let copies = [dir.join("vault.db.format1"), dir.join("vault.db.old"), dir.join("vault.db.alt"), dir.join("glowport-before-account-20261014-1200.gpvault"), dir.join("glowport-vor-konto-20261013-0900.gpvault")];
        let kept = [dir.join("settings.json"), dir.join("glowport-before-account.txt"), dir.join("own.gpvault")];
        for file in copies.iter().chain(&kept) {
            std::fs::write(file, b"x").unwrap();
        }

        // Locked, i.e. without the master password: exactly then it must work.
        session.lock();
        session.wipe().unwrap();
        assert_eq!(as_json(&session.status()), json!({ "state": "missing", "startUnlock": false }));
        assert!(!path.exists());
        for file in &copies {
            assert!(!file.exists(), "{} is still there", file.display());
        }
        for file in &kept {
            assert!(file.exists(), "{} missing", file.display());
        }
        // After that it continues as at the first start.
        session.create("a new one").unwrap();
        drop(session);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stale_device_key_is_discarded() {
        let temp = Temp::new("stalekey");
        let store = Arc::new(MemoryStore::default());
        let mut session = Session::new(temp.0.clone(), FAST, Box::new(Shared(store.clone())));
        session.create("long enough").unwrap();
        session.set_start_unlock(true).unwrap();
        let context = session.directory().unwrap().vault().device_id().unwrap();
        drop(session);

        // Someone stores a key that does not belong to this vault.
        store.store(&context, &random_key()).unwrap();
        let mut session = Session::new(temp.0.clone(), FAST, Box::new(Shared(store.clone())));
        assert_eq!(as_json(&session.initial_status()), json!({ "state": "locked", "startUnlock": false }));
    }

    #[test]
    fn broken_file_is_reported_not_overwritten() {
        let temp = Temp::new("broken");
        std::fs::write(&temp.0, b"this is not a vault file, just some text").unwrap();
        let mut session = temp.session();
        let status = as_json(&session.status());
        assert_eq!((status["state"].as_str(), status["error"]["code"].as_str()), (Some("broken"), Some("corrupt")));
        assert_eq!(code(session.create("long enough")), "exists");
        assert_eq!(as_json(&session.unlock("long enough").unwrap())["state"], "broken");
        assert_eq!(std::fs::read(&temp.0).unwrap(), b"this is not a vault file, just some text");
    }

    #[test]
    fn auto_lock_fires_only_when_open_and_idle() {
        let temp = Temp::new("autolock");
        let mut session = temp.session();
        session.create("long enough").unwrap();
        assert!(!session.auto_lock_due(), "never without the setting");
        session.auto_lock = Some(Duration::from_millis(30));
        assert!(!session.auto_lock_due(), "just used");
        std::thread::sleep(Duration::from_millis(40));
        assert!(session.auto_lock_due());
        session.directory().unwrap();
        assert!(!session.auto_lock_due(), "every use resets the clock");
        std::thread::sleep(Duration::from_millis(40));
        session.lock();
        assert!(!session.auto_lock_due(), "locked, there is nothing to lock");
    }
}

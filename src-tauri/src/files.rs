//! Dateien: auf diesem PC, auf einem gespeicherten Host und am Server eines laufenden Terminals.
//!
//! Die Oberfläche nennt einen Ort ([`Place`]) und einen Pfad; zusammengesetzt und zerlegt werden Pfade nur hier.
//! Zu Servern hält die Brücke je Ort eine SFTP-Verbindung offen: für ein Terminal einen zusätzlichen Kanal auf
//! dessen Verbindung, für einen Host eine eigene, die sich ohne Rückfragen anmelden können muss.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::UNIX_EPOCH,
};

use glowport_core::directory::Verdict;
use glowport_core::model::FtpSecurity;
use glowport_net::{
    files::{Change, Entry, FileError, Kind},
    End,
};
use serde::{Deserialize, Serialize};
use tauri::{ipc::Response, AppHandle, Manager};
use tauri_plugin_dialog::DialogExt;
use tokio::sync::Mutex;

use crate::{
    app::{AppState, CmdError, CmdResult},
    sessions::{self, connect_chain},
    store::Store as Remote,
};

/// Bis zu dieser Größe öffnet der Editor eine Datei ganz; darüber zeigt er nur den Anfang und lässt nichts ändern.
const MAX_TEXT: u64 = 2 * 1024 * 1024;
const MAX_IMAGE: u64 = 32 * 1024 * 1024;
const IMAGES: &[(&str, &str)] = &[("png", "image/png"), ("jpg", "image/jpeg"), ("jpeg", "image/jpeg"), ("gif", "image/gif"), ("webp", "image/webp"), ("svg", "image/svg+xml"), ("ico", "image/x-icon"), ("bmp", "image/bmp")];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Place {
    Local,
    Host { id: String },
    Session { id: u64 },
    /// Ein FTP-Server aus der Schnellverbindung, den der Tresor nicht kennt. Ein leerer Benutzer meldet anonym an.
    Ftp { host: String, port: u16, user: String, security: FtpSecurity },
}

/// Offene SFTP-Verbindungen je Ort.
#[derive(Default)]
pub struct Files {
    remotes: Mutex<HashMap<Place, Arc<Remote>>>,
    /// Benutzernummer, unter der an einem Ort gearbeitet wird, soweit bekannt (Besitzer des Heimatverzeichnisses).
    users: Mutex<HashMap<Place, u32>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryView {
    name: String,
    path: String,
    kind: &'static str,
    size: u64,
    /// Millisekunden seit 1970.
    modified: u64,
    mode: Option<u32>,
    owner: String,
    group: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    /// Bei einer Verknüpfung: Führt sie zu einem Ordner?
    #[serde(skip_serializing_if = "Option::is_none")]
    links_to_dir: Option<bool>,
    hidden: bool,
}

#[derive(Serialize)]
pub struct Crumb {
    /// Leer für die Wurzel dieses PCs; die Oberfläche nennt sie selbst.
    name: String,
    path: String,
}

#[derive(Serialize)]
pub struct Listing {
    path: String,
    crumbs: Vec<Crumb>,
    parent: Option<String>,
    entries: Vec<EntryView>,
    writable: bool,
    /// Nur bei FTP: was dieser Server über das hinaus kann, was jeder kann.
    #[serde(skip_serializing_if = "Option::is_none")]
    ftp: Option<FtpView>,
}

#[derive(Serialize)]
pub struct FtpView {
    chmod: bool,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Content {
    /// `editable` ist falsch, wenn Speichern die Datei beschädigen würde: nur der Anfang geladen oder kein UTF-8.
    Text { text: String, truncated: bool, editable: bool },
    /// Die Bytes holt die Oberfläche mit `fs_read_bytes`.
    Image { mime: &'static str },
    Binary,
}

#[derive(Deserialize)]
pub struct ChmodRequest {
    paths: Vec<String>,
    mode: Option<u32>,
    owner: Option<String>,
    group: Option<String>,
    recursive: bool,
}

impl From<FileError> for CmdError {
    fn from(error: FileError) -> Self {
        CmdError::new(error.code(), error.message())
    }
}

fn io_error(error: std::io::Error) -> CmdError {
    FileError::from(error).into()
}

/// Ein Name für einen neuen Ordner oder zum Umbenennen: ein einzelnes Stück Pfad.
fn check_name(name: &str) -> CmdResult<&str> {
    let name = name.trim();
    if name.is_empty() || name == "." || name == ".." || name.len() > 255 || name.contains(['/', '\\', '\0']) {
        return Err(CmdError::invalid("name_required"));
    }
    Ok(name)
}

// ---------- Server ----------

fn remote_join(dir: &str, name: &str) -> String {
    if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

fn remote_parent(path: &str) -> Option<String> {
    let trimmed = path.trim_end_matches('/');
    let (dir, _) = trimmed.rsplit_once('/')?;
    Some(if dir.is_empty() { "/".into() } else { dir.into() })
}

fn connect_error(end: End) -> CmdError {
    match end {
        End::AuthFailed => CmdError::new("files_auth", "Die gespeicherten Zugangsdaten reichen nicht"),
        End::HostKeyRejected => CmdError::new("files_host_key", "Der Schlüssel des Servers ist nicht bestätigt"),
        End::ConnectFailed(reason) if reason.starts_with("sftp:") => CmdError::new("no_sftp", reason),
        End::ConnectFailed(reason) | End::ConnectionLost(reason) => CmdError::new("connect_failed", reason),
        other => CmdError::new("connect_failed", format!("{other:?}")),
    }
}

/// Die SFTP-Verbindung zu einem Ort; beim ersten Zugriff wird sie aufgebaut.
pub(crate) async fn remote(app: &AppHandle, place: &Place) -> CmdResult<Arc<Remote>> {
    let files = app.state::<Files>();
    if let Some(found) = files.remotes.lock().await.get(place) {
        return Ok(found.clone());
    }
    let made = match place {
        Place::Local => return Err(CmdError::new("not_supported", "Dieser PC braucht kein SFTP")),
        Place::Session { id } => {
            let opened = sessions::extra_channel(app, *id).await.ok_or_else(|| CmdError::new("not_connected", "Die Sitzung ist nicht verbunden"))?;
            Remote::Sftp(glowport_net::files::Remote::on(opened).await.map_err(|error| if error == FileError::Unsupported { CmdError::new("no_sftp", "Der Server bietet kein SFTP an") } else { error.into() })?)
        }
        Place::Ftp { .. } => crate::ftp::silent(app, &crate::ftp::Who::of(app, place).ok_or_else(|| CmdError::invalid("protocol_invalid"))?).await?,
        Place::Host { id } if app.state::<AppState>().session().directory()?.is_ftp(id) => crate::ftp::silent(app, &crate::ftp::Who::Host(id.clone())).await?,
        Place::Host { id } => {
            let state = app.state::<AppState>();
            let connect = connect_chain(state.session().directory()?, id)?;
            // Das gilt für jeden Server auf dem Weg, auch für die Sprung-Server.
            let trusted = |host: &str, port: u16, shown: &glowport_net::HostKey| state.session().directory().is_ok_and(|d| d.judge_host_key(host, port, &shown.openssh) == Verdict::Trusted);
            Remote::Sftp(glowport_net::files::Remote::connect(&connect, trusted).await.map_err(connect_error)?)
        }
    };
    let made = Arc::new(made);
    files.remotes.lock().await.insert(place.clone(), made.clone());
    Ok(made)
}

/// Übernimmt eine fertig aufgebaute Verbindung für einen Ort; eine frühere wird damit ersetzt.
pub(crate) async fn adopt(app: &AppHandle, place: Place, remote: Remote) {
    let files = app.state::<Files>();
    files.users.lock().await.remove(&place);
    files.remotes.lock().await.insert(place, Arc::new(remote));
}

/// Vergisst die FTP-Verbindung zu einem Host, dessen Einstellungen sich geändert haben oder den es nicht mehr
/// gibt: Der nächste Zugriff verbindet neu, mit dem, was jetzt gilt. Eine SFTP-Verbindung bleibt, wie bisher.
pub(crate) fn forget_ftp(app: &AppHandle, host: &str) {
    let (app, place) = (app.clone(), Place::Host { id: host.to_string() });
    tauri::async_runtime::spawn(async move {
        let files = app.state::<Files>();
        let mut remotes = files.remotes.lock().await;
        if remotes.get(&place).is_some_and(|remote| remote.ftp_chmod().is_some()) {
            remotes.remove(&place);
            files.users.lock().await.remove(&place);
        }
    });
}

/// Vergisst die Verbindung zu einem Ort, etwa wenn sie abgerissen ist oder die Sitzung endet.
pub(crate) async fn forget(app: &AppHandle, place: &Place) {
    let files = app.state::<Files>();
    files.remotes.lock().await.remove(place);
    files.users.lock().await.remove(place);
}

/// Führt etwas auf der SFTP-Verbindung eines Orts aus. Ist sie abgerissen, wird sie vergessen, damit der nächste
/// Zugriff neu verbindet.
async fn with_remote<T, F>(app: &AppHandle, place: &Place, work: impl FnOnce(Arc<Remote>) -> F) -> CmdResult<T>
where
    F: std::future::Future<Output = Result<T, FileError>>,
{
    let result = work(remote(app, place).await?).await;
    if matches!(result, Err(FileError::Lost(_))) {
        forget(app, place).await;
    }
    result.map_err(Into::into)
}

/// `~` am Anfang steht für das Heimatverzeichnis; alles andere bringt der Server in seine eigene Form.
async fn remote_path(remote: &Remote, path: &str) -> Result<String, FileError> {
    let path = path.trim();
    let wanted = match path.strip_prefix('~') {
        Some(rest) if rest.is_empty() || rest.starts_with('/') => format!("{}{rest}", remote.home().await?),
        _ if path.is_empty() => remote.home().await?,
        _ => path.to_string(),
    };
    remote.resolve(&wanted).await
}

fn remote_view(dir: &str, entry: Entry, links_to_dir: Option<bool>) -> EntryView {
    EntryView {
        path: remote_join(dir, &entry.name),
        hidden: entry.name.starts_with('.'),
        name: entry.name,
        kind: match entry.kind {
            Kind::Dir => "dir",
            Kind::File => "file",
            Kind::Link => "link",
        },
        size: if entry.kind == Kind::Dir { 0 } else { entry.size },
        modified: entry.modified * 1000,
        mode: Some(entry.mode),
        owner: entry.owner,
        group: entry.group,
        target: entry.target,
        links_to_dir,
    }
}

async fn remote_list(app: &AppHandle, place: &Place, path: &str) -> CmdResult<Listing> {
    let me = my_user(app, place).await;
    with_remote(app, place, |remote| async move {
        let path = remote_path(&remote, path).await?;
        let own = remote.stat(&path, true).await?;
        if own.kind != Kind::Dir {
            return Err(FileError::NotADirectory);
        }
        let mut entries = Vec::new();
        for entry in remote.list(&path).await? {
            let links_to_dir = match entry.kind {
                Kind::Link => Some(remote.stat(&remote_join(&path, &entry.name), true).await.is_ok_and(|target| target.kind == Kind::Dir)),
                _ => None,
            };
            entries.push(remote_view(&path, entry, links_to_dir));
        }
        let mut crumbs = vec![Crumb { name: "/".into(), path: "/".into() }];
        let mut at = String::new();
        for part in path.split('/').filter(|part| !part.is_empty()) {
            at = format!("{at}/{part}");
            crumbs.push(Crumb { name: part.into(), path: at.clone() });
        }
        // Ob hier geschrieben werden darf, weiß erst der Versuch. Gesperrt wird nur, was sicher nicht geht:
        // fremder Ordner, in den weder Gruppe noch andere schreiben dürfen.
        let writable = match me {
            Some(0) | None => true,
            Some(uid) if uid == own.uid => own.mode & 0o200 != 0,
            Some(_) => own.mode & 0o022 != 0,
        };
        let ftp = remote.ftp_chmod().map(|chmod| FtpView { chmod });
        Ok(Listing { parent: remote_parent(&path).filter(|_| path != "/"), path, crumbs, entries, writable, ftp })
    })
    .await
}

/// Benutzernummer an einem Ort: der Besitzer des Heimatverzeichnisses. Einmal ermittelt, dann gemerkt.
async fn my_user(app: &AppHandle, place: &Place) -> Option<u32> {
    let files = app.state::<Files>();
    if let Some(uid) = files.users.lock().await.get(place) {
        return Some(*uid);
    }
    let remote = remote(app, place).await.ok()?;
    let home = remote.home().await.ok()?;
    let uid = remote.stat(&home, true).await.ok()?.uid;
    files.users.lock().await.insert(place.clone(), uid);
    Some(uid)
}

// ---------- Dieser PC ----------

fn text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Laufwerke dieses Rechners als Wurzeln.
#[cfg(windows)]
fn roots() -> Vec<PathBuf> {
    // SAFETY: Der Aufruf nimmt keine Zeiger und liefert nur eine Bitmaske der vorhandenen Laufwerke.
    let mask = unsafe { windows_sys::Win32::Storage::FileSystem::GetLogicalDrives() };
    (0..26u8).filter(|bit| mask & (1 << bit) != 0).map(|bit| PathBuf::from(format!("{}:\\", (b'A' + bit) as char))).collect()
}

#[cfg(not(windows))]
fn roots() -> Vec<PathBuf> {
    vec![PathBuf::from("/")]
}

#[cfg(windows)]
fn hidden(name: &str, meta: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const HIDDEN: u32 = 0x2;
    name.starts_with('.') || meta.file_attributes() & HIDDEN != 0
}

#[cfg(not(windows))]
fn hidden(name: &str, _meta: &std::fs::Metadata) -> bool {
    name.starts_with('.')
}

fn millis(time: std::io::Result<std::time::SystemTime>) -> u64 {
    time.ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map_or(0, |d| d.as_millis() as u64)
}

fn local_view(path: &Path, name: String, meta: &std::fs::Metadata, link: bool) -> EntryView {
    EntryView {
        path: text(path),
        hidden: hidden(&name, meta),
        name,
        kind: if link { "link" } else if meta.is_dir() { "dir" } else { "file" },
        size: if meta.is_dir() { 0 } else { meta.len() },
        modified: millis(meta.modified()),
        mode: None,
        owner: String::new(),
        group: String::new(),
        target: None,
        links_to_dir: link.then(|| std::fs::metadata(path).is_ok_and(|target| target.is_dir())),
    }
}

fn local_list(path: &str) -> CmdResult<Listing> {
    // Die leere Angabe ist die Wurzel über den Laufwerken.
    if path.trim().is_empty() && cfg!(windows) {
        let entries = roots()
            .into_iter()
            .map(|root| EntryView { name: text(&root).trim_end_matches('\\').to_string(), path: text(&root), kind: "dir", size: 0, modified: 0, mode: None, owner: String::new(), group: String::new(), target: None, links_to_dir: None, hidden: false })
            .collect();
        return Ok(Listing { path: String::new(), crumbs: vec![Crumb { name: String::new(), path: String::new() }], parent: None, entries, writable: false, ftp: None });
    }
    let dir = std::fs::canonicalize(if path.trim().is_empty() { "/" } else { path.trim() }).map_err(io_error)?;
    // Windows liefert die lange Form `\\?\C:\…`; angezeigt wird die gewohnte.
    let dir = PathBuf::from(text(&dir).trim_start_matches(r"\\?\"));
    let meta = std::fs::metadata(&dir).map_err(io_error)?;
    if !meta.is_dir() {
        return Err(CmdError::new("not_a_directory", "Das ist kein Ordner"));
    }
    let mut entries = Vec::new();
    for item in std::fs::read_dir(&dir).map_err(io_error)? {
        let Ok(item) = item else { continue };
        // Was sich nicht lesen lässt (gesperrte Systemdateien), wird ausgelassen statt den ganzen Ordner zu verweigern.
        let Ok(meta) = item.metadata() else { continue };
        entries.push(local_view(&item.path(), item.file_name().to_string_lossy().into_owned(), &meta, meta.file_type().is_symlink()));
    }
    let mut crumbs = vec![Crumb { name: String::new(), path: String::new() }];
    let mut at = PathBuf::new();
    for part in dir.components() {
        at.push(part);
        let name = text(Path::new(part.as_os_str()));
        // Der Trenner nach dem Laufwerk ist ein eigenes Stück; es gehört zum Laufwerk davor.
        if name == "\\" || name == "/" {
            match crumbs.last_mut() {
                Some(drive) if !drive.path.is_empty() => drive.path = text(&at),
                _ => crumbs.push(Crumb { name, path: text(&at) }),
            }
            continue;
        }
        crumbs.push(Crumb { name: name.trim_end_matches('\\').to_string(), path: text(&at) });
    }
    let parent = dir.parent().map(text).or_else(|| cfg!(windows).then(String::new));
    Ok(Listing { path: text(&dir), crumbs, parent, entries, writable: !meta.permissions().readonly(), ftp: None })
}

/// Verschiebt Dateien und Ordner in den Papierkorb.
#[cfg(windows)]
fn local_remove(paths: &[String]) -> CmdResult<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::Shell::{SHFileOperationW, FOF_ALLOWUNDO, FOF_NOCONFIRMATION, FOF_NOERRORUI, FOF_SILENT, FO_DELETE, SHFILEOPSTRUCTW};
    // Die Liste der Pfade: jeder mit einer Null beendet, das Ganze mit einer weiteren.
    let mut from: Vec<u16> = Vec::new();
    for path in paths {
        if !Path::new(path).is_absolute() || !Path::new(path).exists() {
            return Err(FileError::NoSuchFile.into());
        }
        from.extend(std::ffi::OsStr::new(path).encode_wide());
        from.push(0);
    }
    from.push(0);
    // SAFETY: Eine mit Nullen gefüllte Struktur ist für diesen Typ gültig (Zahlen und leere Zeiger).
    let mut operation: SHFILEOPSTRUCTW = unsafe { std::mem::zeroed() };
    operation.wFunc = FO_DELETE;
    operation.pFrom = from.as_ptr();
    operation.fFlags = (FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT) as u16;
    // SAFETY: `from` ist doppelt mit Null beendet und lebt bis nach dem Aufruf; die übrigen Felder sind leer.
    let code = unsafe { SHFileOperationW(&mut operation) };
    if code != 0 || operation.fAnyOperationsAborted != 0 {
        return Err(CmdError::new("file_failure", format!("Windows meldet {code:#x}")));
    }
    Ok(())
}

#[cfg(not(windows))]
fn local_remove(paths: &[String]) -> CmdResult<()> {
    for path in paths {
        let meta = std::fs::symlink_metadata(path).map_err(io_error)?;
        if meta.is_dir() { std::fs::remove_dir_all(path) } else { std::fs::remove_file(path) }.map_err(io_error)?;
    }
    Ok(())
}

// ---------- Befehle ----------

fn image_type(path: &str) -> Option<&'static str> {
    let extension = path.rsplit_once('.')?.1.to_ascii_lowercase();
    IMAGES.iter().find(|(known, _)| *known == extension).map(|(_, mime)| *mime)
}

/// Macht aus den ersten Bytes einer Datei, was der Editor zeigen kann.
fn as_content(bytes: Vec<u8>, truncated: bool) -> Content {
    if bytes.contains(&0) {
        return Content::Binary;
    }
    match String::from_utf8(bytes) {
        Ok(text) => Content::Text { text, truncated, editable: !truncated },
        // Am abgeschnittenen Ende kann ein Zeichen zerteilt sein; das allein macht die Datei nicht unlesbar.
        Err(broken) => Content::Text { text: String::from_utf8_lossy(broken.as_bytes()).into_owned(), truncated, editable: false },
    }
}

/// Der Ordner, in dem man an einem Ort beginnt.
#[tauri::command]
pub async fn fs_home(app: AppHandle, place: Place) -> CmdResult<String> {
    match place {
        Place::Local => app.path().home_dir().map(|dir| text(&dir)).map_err(|e| CmdError::new("internal", e.to_string())),
        place => with_remote(&app, &place, |remote| async move { remote.home().await }).await,
    }
}

#[tauri::command]
pub async fn fs_list(app: AppHandle, place: Place, path: String) -> CmdResult<Listing> {
    match place {
        Place::Local => tauri::async_runtime::spawn_blocking(move || local_list(&path)).await.map_err(|e| CmdError::new("internal", e.to_string()))?,
        place => remote_list(&app, &place, &path).await,
    }
}

#[tauri::command]
pub async fn fs_mkdir(app: AppHandle, place: Place, dir: String, name: String) -> CmdResult<()> {
    let name = check_name(&name)?.to_string();
    match place {
        Place::Local => {
            let target = Path::new(&dir).join(&name);
            if target.exists() {
                return Err(CmdError::new("file_exists", name));
            }
            std::fs::create_dir(target).map_err(io_error)
        }
        place => {
            with_remote(&app, &place, |remote| async move {
                let target = remote_join(&dir, &name);
                if remote.stat(&target, false).await.is_ok() {
                    return Err(FileError::Exists);
                }
                remote.mkdir(&target).await
            })
            .await
        }
    }
}

#[tauri::command]
pub async fn fs_rename(app: AppHandle, place: Place, path: String, name: String) -> CmdResult<()> {
    let name = check_name(&name)?.to_string();
    match place {
        Place::Local => {
            let from = PathBuf::from(&path);
            let target = from.parent().ok_or_else(|| CmdError::invalid("name_required"))?.join(&name);
            // Nur Groß- und Kleinschreibung zu ändern ist unter Windows dieselbe Datei und erlaubt.
            if target.exists() && !text(&target).eq_ignore_ascii_case(&path) {
                return Err(CmdError::new("file_exists", name));
            }
            std::fs::rename(from, target).map_err(io_error)
        }
        place => {
            with_remote(&app, &place, |remote| async move {
                let target = remote_join(&remote_parent(&path).ok_or(FileError::NoSuchFile)?, &name);
                // Der Server sagt bei einem vorhandenen Namen nur „fehlgeschlagen“; deshalb vorher nachsehen.
                if remote.stat(&target, false).await.is_ok() {
                    return Err(FileError::Exists);
                }
                remote.rename(&path, &target).await
            })
            .await
        }
    }
}

/// Löscht Dateien und Ordner samt Inhalt. Auf diesem PC landen sie im Papierkorb, am Server sind sie weg.
#[tauri::command]
pub async fn fs_remove(app: AppHandle, place: Place, paths: Vec<String>) -> CmdResult<()> {
    match place {
        Place::Local => tauri::async_runtime::spawn_blocking(move || local_remove(&paths)).await.map_err(|e| CmdError::new("internal", e.to_string()))?,
        place => {
            with_remote(&app, &place, |remote| async move {
                for path in &paths {
                    // Die Wurzel und das Heimatverzeichnis löscht niemand aus Versehen mit.
                    if path.trim_end_matches('/').is_empty() {
                        return Err(FileError::PermissionDenied);
                    }
                    remote.remove(path).await?;
                }
                Ok(())
            })
            .await
        }
    }
}

#[tauri::command]
pub async fn fs_chmod(app: AppHandle, place: Place, request: ChmodRequest) -> CmdResult<()> {
    if place == Place::Local {
        return Err(CmdError::new("not_supported", "Rechte gibt es nur am Server"));
    }
    let change = Change { mode: request.mode, owner: request.owner.filter(|o| !o.trim().is_empty()), group: request.group.filter(|g| !g.trim().is_empty()) };
    with_remote(&app, &place, |remote| async move {
        for path in &request.paths {
            remote.change(path, &change, request.recursive).await?;
        }
        Ok(())
    })
    .await
}

/// Liest eine Datei zum Ansehen oder Bearbeiten.
#[tauri::command]
pub async fn fs_read(app: AppHandle, place: Place, path: String) -> CmdResult<Content> {
    if let Some(mime) = image_type(&path) {
        return Ok(Content::Image { mime });
    }
    let (bytes, truncated) = read_bytes(&app, place, path, MAX_TEXT).await?;
    Ok(as_content(bytes, truncated))
}

async fn read_bytes(app: &AppHandle, place: Place, path: String, limit: u64) -> CmdResult<(Vec<u8>, bool)> {
    match place {
        Place::Local => tauri::async_runtime::spawn_blocking(move || {
            use std::io::Read;
            let file = std::fs::File::open(&path).map_err(io_error)?;
            if file.metadata().map_err(io_error)?.is_dir() {
                return Err(CmdError::new("is_a_directory", "Das ist ein Ordner"));
            }
            let mut bytes = Vec::new();
            file.take(limit + 1).read_to_end(&mut bytes).map_err(io_error)?;
            let longer = bytes.len() as u64 > limit;
            bytes.truncate(limit as usize);
            Ok((bytes, longer))
        })
        .await
        .map_err(|e| CmdError::new("internal", e.to_string()))?,
        place => with_remote(app, &place, |remote| async move { remote.read(&path, limit).await }).await,
    }
}

/// Die rohen Bytes einer Datei, für Bilder in der Vorschau.
#[tauri::command]
pub async fn fs_read_bytes(app: AppHandle, place: Place, path: String) -> CmdResult<Response> {
    let (bytes, longer) = read_bytes(&app, place, path, MAX_IMAGE).await?;
    if longer {
        return Err(CmdError::new("file_too_large", "Die Datei ist zu groß"));
    }
    Ok(Response::new(bytes))
}

/// Schreibt den Text des Editors zurück an seinen Ort.
#[tauri::command]
pub async fn fs_write(app: AppHandle, place: Place, path: String, text: String) -> CmdResult<()> {
    match place {
        Place::Local => std::fs::write(path, text).map_err(io_error),
        place => with_remote(&app, &place, |remote| async move { remote.write(&path, text.as_bytes()).await }).await,
    }
}

// ---------- Dateidialoge ----------
// Diese Befehle laufen nicht im Thread des Fensters (`async`): Ein Dialog, der dort auf seine Antwort wartet,
// hielte das ganze Fenster an.

/// Der Ordner, in dem Downloads landen, wenn in den Einstellungen keiner gewählt ist.
#[tauri::command]
pub fn fs_downloads(app: AppHandle) -> CmdResult<String> {
    app.path().download_dir().map(|dir| text(&dir)).map_err(|e| CmdError::new("internal", e.to_string()))
}

/// Lässt den Nutzer Dateien dieses PCs zum Hochladen wählen; `None`, wenn abgebrochen.
#[tauri::command(async)]
pub fn pick_uploads(app: AppHandle) -> Option<Vec<String>> {
    let chosen = app.dialog().file().blocking_pick_files()?;
    Some(chosen.into_iter().filter_map(|file| file.into_path().ok()).map(|path| text(&path)).collect())
}

/// Lässt den Nutzer ein Programm wählen, etwa den Editor für Dateien vom Server.
#[tauri::command(async)]
pub fn pick_program(app: AppHandle) -> Option<String> {
    let dialog = app.dialog().file();
    let dialog = if cfg!(windows) { dialog.add_filter("Programme", &["exe", "cmd", "bat"]) } else { dialog };
    dialog.blocking_pick_file().and_then(|file| file.into_path().ok()).map(|path| text(&path))
}

#[tauri::command(async)]
pub fn pick_folder(app: AppHandle) -> Option<String> {
    app.dialog().file().blocking_pick_folder().and_then(|folder| folder.into_path().ok()).map(|path| text(&path))
}

// ---------- Suche am Server ----------

/// Mehr Treffer zeigt die Suche nicht; wer so viele hat, sucht genauer.
const MAX_HITS: usize = 300;
/// So viele Einträge sieht die Suche ohne `find` höchstens durch.
const MAX_WALKED: usize = 5000;

#[derive(Serialize, Clone)]
pub struct Hit {
    path: String,
    name: String,
    dir: String,
    kind: &'static str,
    size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
}

/// Ein Wort für die Shell: in einfachen Anführungszeichen, die enthaltenen entschärft.
fn quoted(word: &str) -> String {
    format!("'{}'", word.replace('\'', r"'\''"))
}

/// Der Befehl, der am Server sucht: nach Namen mit `find`, im Inhalt mit `grep`. Beide nehmen das Suchwort wörtlich.
fn search_command(dir: &str, query: &str, content: bool) -> String {
    if content {
        return format!("command -v grep >/dev/null 2>&1 || exit 127; grep -rIin -m 3 -F -e {} -- {} 2>/dev/null | head -n {MAX_HITS}", quoted(query), quoted(dir));
    }
    // In einem Namensmuster hätten diese Zeichen eine Bedeutung.
    let literal: String = query.chars().flat_map(|c| if matches!(c, '*' | '?' | '[' | ']' | '\\') { vec!['\\', c] } else { vec![c] }).collect();
    // Ob es `find` gibt, verrät die Pipeline sonst nicht: Ihr Ergebnis wäre das von `head`.
    format!("command -v find >/dev/null 2>&1 || exit 127; find {} -iname {} 2>/dev/null | head -n {MAX_HITS}", quoted(dir), quoted(&format!("*{literal}*")))
}

/// Zerlegt eine Trefferzeile von `grep -n`: Pfad, Zeilennummer, Zeile.
fn content_hit(line: &str) -> Option<Hit> {
    let (path, rest) = line.split_once(':')?;
    let (number, found) = rest.split_once(':')?;
    let shown: String = found.trim().chars().take(200).collect();
    Some(Hit { name: path.rsplit('/').next()?.to_string(), dir: remote_parent(path)?, path: path.to_string(), kind: "file", size: 0, line: Some(number.parse().ok()?), text: Some(shown) })
}

/// Führt einen Befehl am Server eines Orts aus: auf der Verbindung der Sitzung oder der eigenen des Hosts.
pub(crate) async fn run_at(app: &AppHandle, place: &Place, command: &str) -> CmdResult<glowport_net::Output> {
    match place {
        Place::Local => Err(CmdError::new("not_supported", "Befehle laufen nur am Server")),
        Place::Session { id } => {
            let opened = sessions::extra_channel(app, *id).await.ok_or_else(|| CmdError::new("not_connected", "Die Sitzung ist nicht verbunden"))?;
            glowport_net::files::run(opened, command).await.map_err(Into::into)
        }
        place => with_remote(app, place, |remote| async move { remote.run(command).await }).await,
    }
}

/// Sucht unterhalb eines Ordners nach Namen oder im Inhalt und meldet jeden Treffer über `hits`.
#[tauri::command]
pub async fn fs_search(app: AppHandle, place: Place, dir: String, query: String, content: bool, hits: tauri::ipc::Channel<Hit>) -> CmdResult<()> {
    let query = query.trim().to_string();
    if query.is_empty() || place == Place::Local {
        return Ok(());
    }
    let output = run_at(&app, &place, &search_command(&dir, &query, content)).await;
    let lines = output.as_ref().map(|output| String::from_utf8_lossy(&output.stdout).into_owned()).unwrap_or_default();
    // Ohne Shell oder ohne `find` (exit 127) geht es für Namen auch über SFTP, nur langsamer.
    let unusable = !output.as_ref().is_ok_and(|output| !lines.is_empty() || output.exit_status == Some(0));
    if unusable && !content {
        return with_remote(&app, &place, |remote| async move {
            let needle = query.to_lowercase();
            let mut folders = vec![dir];
            let (mut walked, mut found) = (0, 0);
            while let Some(folder) = folders.pop() {
                let Ok(entries) = remote.list(&folder).await else { continue };
                for entry in entries {
                    walked += 1;
                    let path = remote_join(&folder, &entry.name);
                    if entry.name.to_lowercase().contains(&needle) {
                        found += 1;
                        let _ = hits.send(Hit { path: path.clone(), name: entry.name.clone(), dir: folder.clone(), kind: if entry.kind == Kind::Dir { "dir" } else { "file" }, size: entry.size, line: None, text: None });
                    }
                    if entry.kind == Kind::Dir {
                        folders.push(path);
                    }
                    if walked >= MAX_WALKED || found >= MAX_HITS {
                        return Ok(());
                    }
                }
            }
            Ok(())
        })
        .await;
    }
    if unusable {
        return output.map(|_| ()).and(Err(CmdError::new("search_unavailable", "Am Server fehlt grep")));
    }
    if content {
        for hit in lines.lines().filter_map(content_hit) {
            let _ = hits.send(hit);
        }
        return Ok(());
    }
    with_remote(&app, &place, |remote| async move {
        for path in lines.lines().filter(|line| line.starts_with('/') && *line != dir) {
            // Art und Größe kennt `find` in dieser Form nicht; SFTP sagt sie.
            let (kind, size) = remote.stat(path, false).await.map_or(("file", 0), |entry| (if entry.kind == Kind::Dir { "dir" } else { "file" }, entry.size));
            let _ = hits.send(Hit { name: path.rsplit('/').next().unwrap_or_default().to_string(), dir: remote_parent(path).unwrap_or_else(|| "/".into()), path: path.to_string(), kind, size, line: None, text: None });
        }
        Ok(())
    })
    .await
}

// ---------- Ordner des Terminals ----------

/// Fragt den Server, in welchem Ordner die Shell einer Sitzung steht. Der Befehl läuft auf einem eigenen Kanal
/// derselben Verbindung und sucht unter den Prozessen dieser Verbindung den mit einem Terminal.
/// Das geht nur, wo es `/proc` gibt (Linux); sonst kommt `None`.
const CWD_PROBE: &str = r#"a=$PPID; n=0
while [ $n -lt 3 ] && [ -n "$a" ] && [ "$a" != 1 ]; do
  for p in $(pgrep -P "$a" 2>/dev/null || ps -o pid= --ppid "$a" 2>/dev/null); do
    t=$(readlink "/proc/$p/fd/0" 2>/dev/null)
    case "$t" in /dev/pts/*) c=$(readlink "/proc/$p/cwd" 2>/dev/null) && [ -n "$c" ] && { echo "$c"; exit 0; };; esac
  done
  a=$(sed 's/.*) //' "/proc/$a/stat" 2>/dev/null | cut -d' ' -f2); n=$((n+1))
done"#;

#[tauri::command]
pub async fn session_cwd(app: AppHandle, id: u64) -> Option<String> {
    let output = run_at(&app, &Place::Session { id }, &format!("sh -c {}", quoted(CWD_PROBE))).await.ok()?;
    let found = String::from_utf8_lossy(&output.stdout).lines().next()?.trim().to_string();
    found.starts_with('/').then_some(found)
}

/// Endet eine Sitzung, wird ihre SFTP-Verbindung nicht mehr gebraucht.
pub(crate) fn session_ended(app: &AppHandle, id: u64) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move { forget(&app, &Place::Session { id }).await });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_and_splits_server_paths() {
        assert_eq!(remote_join("/", "etc"), "/etc");
        assert_eq!(remote_join("/var/www", "app"), "/var/www/app");
        assert_eq!(remote_parent("/var/www/app"), Some("/var/www".into()));
        assert_eq!(remote_parent("/etc"), Some("/".into()));
        assert_eq!(remote_parent("/etc/"), Some("/".into()));
    }

    #[test]
    fn builds_search_commands_that_take_the_query_literally() {
        assert_eq!(search_command("/var/www", "conf", false), "command -v find >/dev/null 2>&1 || exit 127; find '/var/www' -iname '*conf*' 2>/dev/null | head -n 300");
        // Zeichen mit Bedeutung in Mustern und Anführungszeichen richten nichts an.
        assert_eq!(search_command("/srv/it's", "a*b'c", false), r#"command -v find >/dev/null 2>&1 || exit 127; find '/srv/it'\''s' -iname '*a\*b'\''c*' 2>/dev/null | head -n 300"#);
        assert_eq!(search_command("/etc", "$(reboot)", true), "command -v grep >/dev/null 2>&1 || exit 127; grep -rIin -m 3 -F -e '$(reboot)' -- '/etc' 2>/dev/null | head -n 300");
    }

    #[test]
    fn reads_hits_from_grep_output() {
        let hit = content_hit("/var/www/app/config.yaml:3:  port: 3000").unwrap();
        assert_eq!((hit.path.as_str(), hit.name.as_str(), hit.dir.as_str(), hit.line, hit.text.as_deref()), ("/var/www/app/config.yaml", "config.yaml", "/var/www/app", Some(3), Some("port: 3000")));
        assert!(content_hit("Binary file matches").is_none());
        assert!(content_hit("/etc/hosts:keine-zahl:text").is_none());
    }

    #[test]
    fn accepts_only_single_names() {
        assert_eq!(check_name("  notizen.txt ").ok(), Some("notizen.txt"));
        for bad in ["", "  ", ".", "..", "a/b", "a\\b", "x\0"] {
            assert!(check_name(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn tells_text_from_binary_and_protects_what_saving_would_break() {
        assert!(matches!(as_content(b"hallo\n".to_vec(), false), Content::Text { editable: true, truncated: false, .. }));
        assert!(matches!(as_content(b"anfang".to_vec(), true), Content::Text { editable: false, truncated: true, .. }));
        assert!(matches!(as_content(vec![b'a', 0, b'b'], false), Content::Binary));
        // Latin-1 statt UTF-8: lesbar, aber Speichern würde die Umlaute zerstören.
        assert!(matches!(as_content(vec![b'M', 0xFC, b'l', b'l'], false), Content::Text { editable: false, .. }));
        assert_eq!(image_type("/var/www/Logo.PNG"), Some("image/png"));
        assert_eq!(image_type("/etc/hosts"), None);
    }

    #[test]
    fn lists_a_local_folder_with_its_way_from_the_root() {
        let dir = std::env::temp_dir().join(format!("glowport-files-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("unter")).unwrap();
        std::fs::write(dir.join("a.txt"), b"abc").unwrap();
        std::fs::write(dir.join(".versteckt"), b"").unwrap();

        let listing = local_list(&text(&dir)).unwrap();
        let mut names: Vec<_> = listing.entries.iter().map(|e| (e.name.as_str(), e.kind, e.size, e.hidden)).collect();
        names.sort();
        assert_eq!(names, [(".versteckt", "file", 0, true), ("a.txt", "file", 3, false), ("unter", "dir", 0, false)]);
        assert!(listing.writable);
        assert_eq!(listing.crumbs.first().map(|c| c.path.as_str()), Some(""));
        assert_eq!(listing.crumbs.last().map(|c| c.path.as_str()), Some(listing.path.as_str()));
        // Jedes Stück des Wegs lässt sich selbst wieder öffnen.
        for crumb in &listing.crumbs {
            assert!(local_list(&crumb.path).is_ok(), "{:?}", crumb.path);
        }
        assert_eq!(local_list(&text(&dir.join("a.txt"))).err().map(|e| e.code()), Some("not_a_directory"));
        assert_eq!(local_list(&text(&dir.join("fehlt"))).err().map(|e| e.code()), Some("no_such_file"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

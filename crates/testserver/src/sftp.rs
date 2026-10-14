//! SFTP des Testservers: ein Ordner dieses Rechners als Dateisystem des „Servers“.
//!
//! Rechte und Besitzer führt der Server selbst in einer Tabelle, weil Windows sie nicht kennt; so lässt sich
//! auch dort prüfen, was der Client mit `chmod` und `chown` anrichtet.

use std::{
    collections::HashMap,
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, UNIX_EPOCH},
};

use russh_sftp::protocol::{Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode, Version};

/// Heimatverzeichnis des Benutzers im Dateisystem des Servers.
pub const HOME: &str = "/home/tester";
const UID: u32 = 1000;
const GID: u32 = 1000;
/// So viele Einträge gibt der Server je Antwort auf `readdir` heraus.
const BATCH: usize = 64;

/// Rechte, Benutzer und Gruppe je Pfad.
type Modes = HashMap<String, (u32, u32, u32)>;

/// Das Dateisystem des Servers; alle Verbindungen sehen dasselbe.
#[derive(Clone)]
pub struct Files {
    root: PathBuf,
    /// Pfade (wie der Client sie nennt), unter denen nichts geändert werden darf.
    read_only: Vec<String>,
    /// Pause vor jedem Lesen und Schreiben, damit Tests einen Transfer mittendrin erwischen.
    delay: Option<Duration>,
    /// Rechte, Benutzer und Gruppe je Pfad, soweit sie von der Vorgabe abweichen.
    modes: Arc<Mutex<Modes>>,
}

impl Files {
    pub fn new(root: PathBuf, read_only: Vec<String>, delay: Option<Duration>) -> Self {
        let _ = fs::create_dir_all(root.join(&HOME[1..]));
        Files { root, read_only, delay, modes: Arc::default() }
    }

    pub fn session(&self) -> SftpSession {
        SftpSession { files: self.clone(), handles: HashMap::new(), next: 0 }
    }

    /// Rechte eines Pfads, wie der Server sie führt (für Tests).
    pub fn mode(&self, path: &str) -> Option<u32> {
        self.modes.lock().ok()?.get(&clean(path)).map(|entry| entry.0)
    }
}

/// Bringt einen Pfad des Clients in die Form `/a/b`: absolut, ohne `.` und `..`.
fn clean(path: &str) -> String {
    let absolute = if path.starts_with('/') { path.to_string() } else { format!("{HOME}/{path}") };
    let mut parts: Vec<&str> = Vec::new();
    for part in absolute.split('/') {
        match part {
            "" | "." => {}
            ".." => drop(parts.pop()),
            name => parts.push(name),
        }
    }
    format!("/{}", parts.join("/"))
}

enum Open {
    File(fs::File),
    /// Was von einem Ordner noch nicht ausgegeben ist.
    Dir(Vec<File>),
}

pub struct SftpSession {
    files: Files,
    handles: HashMap<String, Open>,
    next: u32,
}

fn status(id: u32) -> Status {
    Status { id, status_code: StatusCode::Ok, error_message: "Ok".into(), language_tag: "en-US".into() }
}

fn failure(error: std::io::Error) -> StatusCode {
    match error.kind() {
        std::io::ErrorKind::NotFound => StatusCode::NoSuchFile,
        std::io::ErrorKind::PermissionDenied => StatusCode::PermissionDenied,
        _ => StatusCode::Failure,
    }
}

impl SftpSession {
    fn local(&self, path: &str) -> PathBuf {
        let cleaned = clean(path);
        cleaned.split('/').filter(|part| !part.is_empty()).fold(self.files.root.clone(), |at, part| at.join(part))
    }

    fn writable(&self, path: &str) -> Result<(), StatusCode> {
        let cleaned = clean(path);
        let locked = self.files.read_only.iter().any(|prefix| cleaned == *prefix || cleaned.starts_with(&format!("{prefix}/")));
        if locked { Err(StatusCode::PermissionDenied) } else { Ok(()) }
    }

    fn attrs(&self, path: &str, local: &Path, follow: bool) -> Result<FileAttributes, StatusCode> {
        let meta = if follow { fs::metadata(local) } else { fs::symlink_metadata(local) }.map_err(failure)?;
        let kind = if meta.is_dir() { 0o040000 } else if meta.file_type().is_symlink() { 0o120000 } else { 0o100000 };
        let fallback = (if meta.is_dir() { 0o755 } else { 0o644 }, UID, GID);
        let (mode, uid, gid) = self.files.modes.lock().ok().and_then(|modes| modes.get(&clean(path)).copied()).unwrap_or(fallback);
        let seconds = |time: std::io::Result<std::time::SystemTime>| time.ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs() as u32);
        Ok(FileAttributes { size: Some(meta.len()), uid: Some(uid), user: None, gid: Some(gid), group: None, permissions: Some(kind | mode), atime: seconds(meta.accessed()), mtime: seconds(meta.modified()) })
    }

    fn apply(&self, path: &str, local: &Path, attrs: &FileAttributes) -> Result<(), StatusCode> {
        self.writable(path)?;
        let current = self.attrs(path, local, true)?;
        if let Some(size) = attrs.size {
            fs::OpenOptions::new().write(true).open(local).and_then(|file| file.set_len(size)).map_err(failure)?;
        }
        if let Some(mtime) = attrs.mtime {
            let file = fs::OpenOptions::new().write(true).open(local).map_err(failure)?;
            file.set_modified(UNIX_EPOCH + Duration::from_secs(u64::from(mtime))).map_err(failure)?;
        }
        let entry = (attrs.permissions.map_or(current.permissions.unwrap_or(0) & 0o7777, |p| p & 0o7777), attrs.uid.or(current.uid).unwrap_or(UID), attrs.gid.or(current.gid).unwrap_or(GID));
        self.files.modes.lock().map_err(|_| StatusCode::Failure)?.insert(clean(path), entry);
        Ok(())
    }

    fn handle(&mut self, id: u32, open: Open) -> Handle {
        self.next += 1;
        let handle = format!("h{}", self.next);
        self.handles.insert(handle.clone(), open);
        Handle { id, handle }
    }

    async fn pause(&self) {
        if let Some(delay) = self.files.delay {
            tokio::time::sleep(delay).await;
        }
    }
}

impl russh_sftp::server::Handler for SftpSession {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn init(&mut self, _version: u32, _extensions: HashMap<String, String>) -> Result<Version, Self::Error> {
        Ok(Version::new())
    }

    async fn open(&mut self, id: u32, filename: String, pflags: OpenFlags, _attrs: FileAttributes) -> Result<Handle, Self::Error> {
        if pflags.intersects(OpenFlags::WRITE | OpenFlags::APPEND | OpenFlags::CREATE | OpenFlags::TRUNCATE) {
            self.writable(&filename)?;
        }
        let local = self.local(&filename);
        if local.is_dir() {
            return Err(StatusCode::Failure);
        }
        let file = fs::OpenOptions::from(pflags).open(local).map_err(failure)?;
        Ok(self.handle(id, Open::File(file)))
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        self.handles.remove(&handle);
        Ok(status(id))
    }

    async fn read(&mut self, id: u32, handle: String, offset: u64, len: u32) -> Result<Data, Self::Error> {
        self.pause().await;
        let Some(Open::File(file)) = self.handles.get_mut(&handle) else { return Err(StatusCode::Failure) };
        file.seek(SeekFrom::Start(offset)).map_err(failure)?;
        let mut data = vec![0; len.min(256 * 1024) as usize];
        let count = file.read(&mut data).map_err(failure)?;
        if count == 0 {
            return Err(StatusCode::Eof);
        }
        data.truncate(count);
        Ok(Data { id, data })
    }

    async fn write(&mut self, id: u32, handle: String, offset: u64, data: Vec<u8>) -> Result<Status, Self::Error> {
        self.pause().await;
        let Some(Open::File(file)) = self.handles.get_mut(&handle) else { return Err(StatusCode::Failure) };
        file.seek(SeekFrom::Start(offset)).map_err(failure)?;
        file.write_all(&data).map_err(failure)?;
        Ok(status(id))
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        Ok(Attrs { id, attrs: self.attrs(&path, &self.local(&path), false)? })
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        Ok(Attrs { id, attrs: self.attrs(&path, &self.local(&path), true)? })
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        let Some(Open::File(file)) = self.handles.get(&handle) else { return Err(StatusCode::Failure) };
        let meta = file.metadata().map_err(failure)?;
        Ok(Attrs { id, attrs: FileAttributes { size: Some(meta.len()), uid: Some(UID), user: None, gid: Some(GID), group: None, permissions: Some(0o100644), atime: None, mtime: None } })
    }

    async fn setstat(&mut self, id: u32, path: String, attrs: FileAttributes) -> Result<Status, Self::Error> {
        self.apply(&path, &self.local(&path), &attrs)?;
        Ok(status(id))
    }

    async fn fsetstat(&mut self, id: u32, _handle: String, _attrs: FileAttributes) -> Result<Status, Self::Error> {
        Ok(status(id))
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        let local = self.local(&path);
        let mut entries = Vec::new();
        for entry in fs::read_dir(&local).map_err(failure)? {
            let entry = entry.map_err(failure)?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let inner = format!("{}/{name}", clean(&path));
            entries.push(File::new(name, self.attrs(&inner, &entry.path(), false)?));
        }
        Ok(self.handle(id, Open::Dir(entries)))
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        let Some(Open::Dir(left)) = self.handles.get_mut(&handle) else { return Err(StatusCode::Failure) };
        if left.is_empty() {
            return Err(StatusCode::Eof);
        }
        let rest = left.split_off(left.len().min(BATCH));
        let files = std::mem::replace(left, rest);
        Ok(Name { id, files })
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        self.writable(&filename)?;
        fs::remove_file(self.local(&filename)).map_err(failure)?;
        Ok(status(id))
    }

    async fn mkdir(&mut self, id: u32, path: String, _attrs: FileAttributes) -> Result<Status, Self::Error> {
        self.writable(&path)?;
        fs::create_dir(self.local(&path)).map_err(failure)?;
        Ok(status(id))
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        self.writable(&path)?;
        fs::remove_dir(self.local(&path)).map_err(failure)?;
        Ok(status(id))
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        Ok(Name { id, files: vec![File::dummy(clean(&path))] })
    }

    async fn rename(&mut self, id: u32, oldpath: String, newpath: String) -> Result<Status, Self::Error> {
        self.writable(&oldpath)?;
        self.writable(&newpath)?;
        let target = self.local(&newpath);
        // Wie bei SFTP üblich: Umbenennen überschreibt nichts.
        if target.exists() {
            return Err(StatusCode::Failure);
        }
        fs::rename(self.local(&oldpath), target).map_err(failure)?;
        if let Ok(mut modes) = self.files.modes.lock() {
            if let Some(entry) = modes.remove(&clean(&oldpath)) {
                modes.insert(clean(&newpath), entry);
            }
        }
        Ok(status(id))
    }
}

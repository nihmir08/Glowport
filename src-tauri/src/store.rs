//! Dateien auf einem Server, über SFTP oder FTP. Der Dateimanager und die Übertragungen sprechen mit dieser einen
//! Form; was FTP nicht kann (Befehle ausführen, Besitzer ändern), meldet es als „nicht unterstützt“.

use std::{
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
};

use glowport_net::{
    files::{Change, Entry, FileError, Kind},
    Output,
};
use tokio::io::{AsyncRead, AsyncWrite};

// Je verbundenem Ort gibt es eine davon; die größere Form eigens auszulagern lohnt nicht.
#[allow(clippy::large_enum_variant)]
pub enum Store {
    Sftp(glowport_net::files::Remote),
    Ftp {
        remote: glowport_ftp::Remote,
        /// Ob der Server Rechte ändern kann, weiß erst der Versuch. Nach einem „kann ich nicht“ fehlt der Menüpunkt.
        chmod: AtomicBool,
    },
}

impl Store {
    pub fn ftp(remote: glowport_ftp::Remote) -> Store {
        Store::Ftp { remote, chmod: AtomicBool::new(true) }
    }

    /// Bei FTP: ob der Server (soweit bekannt) Rechte ändern kann. `None` bei SFTP.
    pub fn ftp_chmod(&self) -> Option<bool> {
        match self {
            Store::Sftp(_) => None,
            Store::Ftp { chmod, .. } => Some(chmod.load(Ordering::Relaxed)),
        }
    }

    /// Führt einen Befehl aus. FTP kennt keine Befehle.
    pub async fn run(&self, command: &str) -> Result<Output, FileError> {
        match self {
            Store::Sftp(remote) => remote.run(command).await,
            Store::Ftp { .. } => Err(FileError::Unsupported),
        }
    }

    pub async fn home(&self) -> Result<String, FileError> {
        match self {
            Store::Sftp(remote) => remote.home().await,
            Store::Ftp { remote, .. } => remote.home().await,
        }
    }

    /// Bringt einen Pfad in die Form des Servers. SFTP fragt ihn; für FTP wird er hier bereinigt.
    pub async fn resolve(&self, path: &str) -> Result<String, FileError> {
        match self {
            Store::Sftp(remote) => remote.resolve(path).await,
            Store::Ftp { remote, .. } => Ok(tidy(&remote.home().await?, path)),
        }
    }

    pub async fn list(&self, path: &str) -> Result<Vec<Entry>, FileError> {
        match self {
            Store::Sftp(remote) => remote.list(path).await,
            Store::Ftp { remote, .. } => remote.list(path).await,
        }
    }

    pub async fn stat(&self, path: &str, follow: bool) -> Result<Entry, FileError> {
        match self {
            Store::Sftp(remote) => remote.stat(path, follow).await,
            Store::Ftp { remote, .. } => remote.stat(path, follow).await,
        }
    }

    pub async fn mkdir(&self, path: &str) -> Result<(), FileError> {
        match self {
            Store::Sftp(remote) => remote.mkdir(path).await,
            Store::Ftp { remote, .. } => remote.mkdir(path).await,
        }
    }

    pub async fn rename(&self, from: &str, to: &str) -> Result<(), FileError> {
        match self {
            Store::Sftp(remote) => remote.rename(from, to).await,
            Store::Ftp { remote, .. } => remote.rename(from, to).await,
        }
    }

    pub fn remove<'a>(&'a self, path: &'a str) -> Pin<Box<dyn Future<Output = Result<(), FileError>> + Send + 'a>> {
        match self {
            Store::Sftp(remote) => remote.remove(path),
            Store::Ftp { remote, .. } => remote.remove(path),
        }
    }

    /// Ändert Rechte und Besitz. FTP kann höchstens die Rechte, und auch die nur, wenn der Server es anbietet.
    pub fn change<'a>(&'a self, path: &'a str, change: &'a Change, recursive: bool) -> Pin<Box<dyn Future<Output = Result<(), FileError>> + Send + 'a>> {
        Box::pin(async move {
            match self {
                Store::Sftp(remote) => remote.change(path, change, recursive).await,
                Store::Ftp { remote, chmod } => {
                    if change.owner.is_some() || change.group.is_some() {
                        return Err(FileError::Unsupported);
                    }
                    let Some(mode) = change.mode else { return Ok(()) };
                    let entry = remote.stat(path, false).await?;
                    // Wie bei SFTP bleiben Ordner betretbar, wenn die Rechte für ihren Inhalt gelten sollen.
                    let own = if entry.kind == Kind::Dir && recursive { mode | (mode & 0o444) >> 2 } else { mode };
                    if let Err(error) = remote.chmod(path, own).await {
                        if error == FileError::Unsupported {
                            chmod.store(false, Ordering::Relaxed);
                        }
                        return Err(error);
                    }
                    if entry.kind == Kind::Dir && recursive {
                        for child in remote.list(path).await? {
                            if child.kind != Kind::Link {
                                self.change(&format!("{}/{}", path.trim_end_matches('/'), child.name), change, true).await?;
                            }
                        }
                    }
                    Ok(())
                }
            }
        })
    }

    pub async fn read(&self, path: &str, limit: u64) -> Result<(Vec<u8>, bool), FileError> {
        match self {
            Store::Sftp(remote) => remote.read(path, limit).await,
            Store::Ftp { remote, .. } => remote.read(path, limit).await,
        }
    }

    pub async fn write(&self, path: &str, data: &[u8]) -> Result<(), FileError> {
        match self {
            Store::Sftp(remote) => remote.write(path, data).await,
            Store::Ftp { remote, .. } => remote.write(path, data).await,
        }
    }

    pub async fn reader(&self, path: &str, offset: u64) -> Result<Box<dyn AsyncRead + Unpin + Send>, FileError> {
        Ok(match self {
            Store::Sftp(remote) => Box::new(remote.reader(path, offset).await?),
            Store::Ftp { remote, .. } => Box::new(remote.reader(path, offset).await?),
        })
    }

    /// Bei FTP ist die Datei erst nach `shutdown` fertig: Erst dann bestätigt der Server sie.
    pub async fn writer(&self, path: &str, offset: u64) -> Result<Box<dyn AsyncWrite + Unpin + Send>, FileError> {
        Ok(match self {
            Store::Sftp(remote) => Box::new(remote.writer(path, offset).await?),
            Store::Ftp { remote, .. } => Box::new(remote.writer(path, offset).await?),
        })
    }

    pub async fn touch(&self, path: &str, modified: u64) -> Result<(), FileError> {
        match self {
            Store::Sftp(remote) => remote.touch(path, modified).await,
            Store::Ftp { remote, .. } => remote.touch(path, modified).await,
        }
    }
}

/// Ein Pfad ohne doppelte Striche, `.` und `..`; ein Pfad ohne Strich am Anfang gilt ab `home`.
fn tidy(home: &str, path: &str) -> String {
    let whole = if path.starts_with('/') { path.to_string() } else { format!("{}/{path}", home.trim_end_matches('/')) };
    let mut parts: Vec<&str> = Vec::new();
    for part in whole.split('/') {
        match part {
            "" | "." => {}
            ".." => drop(parts.pop()),
            part => parts.push(part),
        }
    }
    format!("/{}", parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::tidy;

    #[test]
    fn ftp_paths_are_tidied_without_asking_the_server() {
        assert_eq!(tidy("/", "/htdocs//img/"), "/htdocs/img");
        assert_eq!(tidy("/", "/htdocs/./img/../css"), "/htdocs/css");
        assert_eq!(tidy("/home/web", "logs"), "/home/web/logs");
        assert_eq!(tidy("/", ""), "/");
        assert_eq!(tidy("/", "/../.."), "/");
    }
}

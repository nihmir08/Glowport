//! Files on a server, over SFTP or FTP. The file manager and the transfers talk to this one
//! form; what FTP cannot do (run commands, change owner) it reports as “not supported”.

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

// There is one of these per connected location; moving the larger form out separately is not worth it.
#[allow(clippy::large_enum_variant)]
pub enum Store {
    Sftp(glowport_net::files::Remote),
    Ftp {
        remote: glowport_ftp::Remote,
        /// Whether the server can change permissions only the attempt tells. After a “cannot do” the menu item is missing.
        chmod: AtomicBool,
    },
}

impl Store {
    pub fn ftp(remote: glowport_ftp::Remote) -> Store {
        Store::Ftp { remote, chmod: AtomicBool::new(true) }
    }

    /// For FTP: whether the server (as far as known) can change permissions. `None` for SFTP.
    pub fn ftp_chmod(&self) -> Option<bool> {
        match self {
            Store::Sftp(_) => None,
            Store::Ftp { chmod, .. } => Some(chmod.load(Ordering::Relaxed)),
        }
    }

    /// Runs a command. FTP knows no commands.
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

    /// Brings a path into the server's form. SFTP asks it; for FTP it is cleaned up here.
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

    /// Changes permissions and ownership. FTP can at most do the permissions, and only if the server offers it.
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
                    // As with SFTP, folders stay enterable when the permissions are meant for their content.
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

    /// With FTP the file is only finished after `shutdown`: only then does the server confirm it.
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

/// A path without double slashes, `.` and `..`; a path without a leading slash counts from `home`.
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

//! Syncing with the sync server: the program's side (`docs/sync.md`).
//!
//! - [`api`]: the requests to the server, one function per route.
//! - [`engine`]: what happens with the vault: set up, sign in, fetch, send, merge, share.
//! - [`live`]: runs in the background, listens for the server's nudges and syncs.
//!
//! The vault belongs to the program, not to this crate. That is why every access goes through a [`Door`]: briefly
//! in, read or write, out again. Nobody ever waits on the network while the door is open.

pub mod api;
pub mod engine;
pub mod live;

use std::sync::Mutex;

use glowport_core::vault::{Vault, VaultError};
use serde::{Deserialize, Serialize};

pub use engine::{connect, login_new, probe, register, Candidate, DeviceInfo, Engine, Invitation, Known, Notice, Report};
pub use live::{status_of, Runner, Status};

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("Keine Verbindung zum Sync-Server ({0})")]
    Offline(String),
    /// The server is there, but its certificate is not valid: expired, for another name, or issued by
    /// nobody this machine trusts.
    #[error("Das Zertifikat des Sync-Servers wird nicht anerkannt ({0})")]
    Certificate(String),
    /// The server answered and refused. `code` is its reason, e.g. `unauthorized` or `code_invalid`.
    #[error("Der Sync-Server lehnt ab ({code})")]
    Refused { status: u16, code: String },
    #[error("Unerwartete Antwort des Sync-Servers ({0})")]
    Protocol(&'static str),
    #[error("Die Adresse des Sync-Servers ist ungültig")]
    Address,
    #[error("Dieser Server verlangt eine neuere Version von Glowport")]
    TooOld,
    #[error("Dieser Server ist zu alt für diese Version von Glowport")]
    ServerTooOld,
    #[error("Der Abgleich ist nicht eingerichtet")]
    NotLinked,
    #[error("Der Abgleich ist schon eingerichtet")]
    AlreadyLinked,
    /// This device's vault belongs to a different account than the one signed in to.
    #[error("Dieser Tresor gehört zu einem anderen Konto")]
    OtherAccount,
    #[error("Das geht hier nicht ({0})")]
    Invalid(&'static str),
    /// The vault was changed by others again and again during a key rotation.
    #[error("Der Tresor wird gerade von anderen geändert; bitte noch einmal versuchen")]
    Busy,
    #[error(transparent)]
    Vault(#[from] VaultError),
}

impl SyncError {
    /// Short reason for the interface.
    pub fn code(&self) -> &str {
        match self {
            SyncError::Offline(_) => "offline",
            SyncError::Certificate(_) => "certificate",
            SyncError::Refused { code, .. } => code,
            SyncError::Protocol(_) => "protocol",
            SyncError::Address => "address_invalid",
            SyncError::TooOld => "client_too_old",
            SyncError::ServerTooOld => "server_too_old",
            SyncError::NotLinked => "not_linked",
            SyncError::AlreadyLinked => "already_linked",
            SyncError::OtherAccount => "other_account",
            SyncError::Invalid(_) => "invalid",
            SyncError::Busy => "busy",
            SyncError::Vault(VaultError::Locked) => "locked",
            SyncError::Vault(VaultError::WrongPassword) => "wrong_password",
            SyncError::Vault(VaultError::ReadOnly) => "read_only",
            SyncError::Vault(VaultError::NotOwner) => "not_owner",
            SyncError::Vault(_) => "vault",
        }
    }

    pub(crate) fn refused(&self, code: &str) -> bool {
        matches!(self, SyncError::Refused { code: c, .. } if c == code)
    }
}

/// Access to the program's vault.
pub trait Door: Send + Sync + 'static {
    /// Runs `work` on the vault. If it is locked, the first access inside already fails with `Locked`.
    fn enter<T>(&self, work: impl FnOnce(&mut Vault) -> Result<T, SyncError>) -> Result<T, SyncError>;
}

impl Door for Mutex<Vault> {
    fn enter<T>(&self, work: impl FnOnce(&mut Vault) -> Result<T, SyncError>) -> Result<T, SyncError> {
        work(&mut self.lock().unwrap_or_else(|poisoned| poisoned.into_inner()))
    }
}

/// This device's sign-in at the server. Stored in the vault file, encrypted with the account key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Link {
    pub server: String,
    /// ID of the account (hex).
    pub account: String,
    pub username: String,
    /// ID of this device (hex).
    pub device: String,
    /// Device token (Base64). Identifies the device on every request.
    pub token: String,
    pub admin: bool,
}

impl std::fmt::Debug for Link {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Link").field("server", &self.server).field("username", &self.username).field("device", &self.device).finish_non_exhaustive()
    }
}

impl Link {
    pub fn load(vault: &Vault) -> Result<Option<Self>, SyncError> {
        match vault.link()? {
            Some(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|_| SyncError::Protocol("gespeicherte Anmeldung")),
            None => Ok(None),
        }
    }

    pub fn save(&self, vault: &mut Vault) -> Result<(), SyncError> {
        let bytes = serde_json::to_vec(self).map_err(|_| SyncError::Protocol("Anmeldung"))?;
        Ok(vault.set_link(Some(&bytes))?)
    }
}

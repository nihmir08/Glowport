//! Abgleich mit dem Sync-Server: die Seite des Programms (`docs/sync.md`).
//!
//! - [`api`]: die Anfragen an den Server, eine Funktion je Weg.
//! - [`engine`]: was mit dem Tresor geschieht: einrichten, anmelden, holen, schicken, zusammenführen, teilen.
//! - [`live`]: läuft im Hintergrund, hört auf Anstöße des Servers und gleicht ab.
//!
//! Der Tresor gehört dem Programm, nicht diesem Crate. Deshalb geht jeder Zugriff durch eine [`Door`]: kurz
//! hinein, lesen oder schreiben, wieder heraus. Über das Netz wird nie gewartet, während die Tür offen steht.

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
    /// Der Server ist da, aber sein Zertifikat gilt nicht: abgelaufen, für einen anderen Namen, oder von
    /// niemandem ausgestellt, dem dieser Rechner traut.
    #[error("Das Zertifikat des Sync-Servers wird nicht anerkannt ({0})")]
    Certificate(String),
    /// Der Server hat geantwortet und abgelehnt. `code` ist sein Grund, etwa `unauthorized` oder `code_invalid`.
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
    /// Der Tresor dieses Geräts gehört zu einem anderen Konto als dem, an dem angemeldet wurde.
    #[error("Dieser Tresor gehört zu einem anderen Konto")]
    OtherAccount,
    #[error("Das geht hier nicht ({0})")]
    Invalid(&'static str),
    /// Der Tresor wurde während eines Schlüsseltauschs immer wieder von anderen geändert.
    #[error("Der Tresor wird gerade von anderen geändert; bitte noch einmal versuchen")]
    Busy,
    #[error(transparent)]
    Vault(#[from] VaultError),
}

impl SyncError {
    /// Kurzer Grund für die Oberfläche.
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

/// Zugang zum Tresor des Programms.
pub trait Door: Send + Sync + 'static {
    /// Führt `work` am Tresor aus. Ist er gesperrt, scheitert schon der erste Zugriff darin mit `Locked`.
    fn enter<T>(&self, work: impl FnOnce(&mut Vault) -> Result<T, SyncError>) -> Result<T, SyncError>;
}

impl Door for Mutex<Vault> {
    fn enter<T>(&self, work: impl FnOnce(&mut Vault) -> Result<T, SyncError>) -> Result<T, SyncError> {
        work(&mut self.lock().unwrap_or_else(|poisoned| poisoned.into_inner()))
    }
}

/// Die Anmeldung dieses Geräts am Server. Liegt mit dem Kontoschlüssel verschlüsselt in der Tresor-Datei.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Link {
    pub server: String,
    /// Kennung des Kontos (Hex).
    pub account: String,
    pub username: String,
    /// Kennung dieses Geräts (Hex).
    pub device: String,
    /// Geräte-Token (Base64). Weist das Gerät bei jeder Anfrage aus.
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

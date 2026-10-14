//! Nachrichten zwischen Glowport und dem Sync-Server (`docs/sync.md`). JSON über HTTPS unter `/v1/…`.
//!
//! Alles Binäre reist als Base64. Der Server deutet davon nur, was er zum Prüfen braucht: Kennungen,
//! öffentliche Schlüssel, Signaturen. Schlüsseltexte reicht er durch.

use base64::{engine::general_purpose::STANDARD, Engine};
use glowport_core::{
    crypto::KdfParams,
    roster::Role,
    vault::{Account, Envelope},
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Fassung dieses Protokolls. Der Server nennt seine und die älteste, die er noch bedient.
pub const PROTOCOL: u32 = 1;

/// Binäres Feld; im JSON ein Base64-Text.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Bytes(pub Vec<u8>);

impl Bytes {
    pub fn array<const N: usize>(&self) -> Option<[u8; N]> {
        self.0.as_slice().try_into().ok()
    }
}

impl std::fmt::Debug for Bytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Bytes({})", self.0.len())
    }
}

impl<T: AsRef<[u8]>> From<T> for Bytes {
    fn from(bytes: T) -> Self {
        Self(bytes.as_ref().to_vec())
    }
}

impl Serialize for Bytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        STANDARD.decode(text).map(Self).map_err(serde::de::Error::custom)
    }
}

/// Fehlerantwort des Servers. `code` ist für das Programm, `message` für das Protokoll des Betreibers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Info {
    pub name: String,
    pub protocol: u32,
    pub min_protocol: u32,
    /// Es gibt noch kein Konto: Das erste braucht den Einrichtungscode statt einer Einladung.
    pub fresh: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Kdf {
    pub memory_kib: u32,
    pub passes: u32,
    pub lanes: u32,
}

impl From<KdfParams> for Kdf {
    fn from(k: KdfParams) -> Self {
        Self { memory_kib: k.memory_kib, passes: k.passes, lanes: k.lanes }
    }
}

impl From<Kdf> for KdfParams {
    fn from(k: Kdf) -> Self {
        Self { memory_kib: k.memory_kib, passes: k.passes, lanes: k.lanes }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prelogin {
    pub username: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreloginReply {
    pub salt: Bytes,
    pub kdf: Kdf,
}

/// Was der Server je Konto aufbewahrt, damit sich ein weiteres Gerät mit dem Master-Passwort anmelden kann.
/// Jedes Stück ist öffentlich oder schon verschlüsselt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireAccount {
    pub salt: Bytes,
    pub kdf: Kdf,
    pub account_nonce: Bytes,
    pub account_wrapped: Bytes,
    pub ed25519_public: Bytes,
    pub ed25519_nonce: Bytes,
    pub ed25519_wrapped: Bytes,
    pub x25519_public: Bytes,
    pub x25519_nonce: Bytes,
    pub x25519_wrapped: Bytes,
    pub personal: Bytes,
    pub personal_nonce: Bytes,
    pub personal_wrapped: Bytes,
}

impl From<&Account> for WireAccount {
    fn from(a: &Account) -> Self {
        Self {
            salt: a.salt.into(),
            kdf: a.kdf.into(),
            account_nonce: (&a.account_nonce).into(),
            account_wrapped: (&a.account_wrapped).into(),
            ed25519_public: a.ed25519_public.into(),
            ed25519_nonce: (&a.ed25519_nonce).into(),
            ed25519_wrapped: (&a.ed25519_wrapped).into(),
            x25519_public: a.x25519_public.into(),
            x25519_nonce: (&a.x25519_nonce).into(),
            x25519_wrapped: (&a.x25519_wrapped).into(),
            personal: a.personal.into(),
            personal_nonce: (&a.personal_nonce).into(),
            personal_wrapped: (&a.personal_wrapped).into(),
        }
    }
}

impl WireAccount {
    /// Zurück in die Form des Kerns, sofern jedes Stück die richtige Länge hat.
    pub fn account(&self) -> Option<Account> {
        Some(Account {
            salt: self.salt.array()?,
            kdf: self.kdf.into(),
            account_nonce: self.account_nonce.0.clone(),
            account_wrapped: self.account_wrapped.0.clone(),
            ed25519_public: self.ed25519_public.array()?,
            ed25519_nonce: self.ed25519_nonce.0.clone(),
            ed25519_wrapped: self.ed25519_wrapped.0.clone(),
            x25519_public: self.x25519_public.array()?,
            x25519_nonce: self.x25519_nonce.0.clone(),
            x25519_wrapped: self.x25519_wrapped.0.clone(),
            personal: self.personal.array()?,
            personal_nonce: self.personal_nonce.0.clone(),
            personal_wrapped: self.personal_wrapped.0.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Register {
    /// Einladungscode, beim allerersten Konto der Einrichtungscode des Servers.
    pub code: String,
    pub username: String,
    pub auth_key: Bytes,
    pub account: WireAccount,
    /// Name des Geräts, mit dem Kontoschlüssel verschlüsselt.
    pub device_name: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Login {
    pub username: String,
    pub auth_key: Bytes,
    pub device_name: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub account_id: Bytes,
    pub username: String,
    pub device_id: Bytes,
    /// Weist das Gerät bei jeder weiteren Anfrage aus (`Authorization: Bearer <Base64>`).
    pub token: Bytes,
    pub admin: bool,
    pub account: WireAccount,
}

/// Antwort auf Anmelden und Konto anlegen. `needs` ist für einen späteren zweiten Faktor vorgesehen: Steht
/// dort etwas, gibt es noch keine Sitzung, und ein Programm, das den Schritt nicht kennt, braucht ein Update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginReply {
    #[serde(default)]
    pub needs: Option<String>,
    #[serde(default)]
    pub session: Option<Session>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireRecord {
    pub id: Bytes,
    pub revision: u64,
    pub deleted: bool,
    pub modified_at: i64,
    pub author: Bytes,
    pub nonce: Bytes,
    pub ciphertext: Bytes,
    pub signature: Bytes,
    /// Nur beim Schicken: die Revision, auf der diese Änderung aufsetzt (0 = der Server kennt den Datensatz
    /// nicht). Der Server nimmt nur an, was auf seinem Stand aufsetzt.
    #[serde(default)]
    pub base: u64,
}

impl From<&Envelope> for WireRecord {
    fn from(e: &Envelope) -> Self {
        Self { id: e.id.into(), revision: e.revision, deleted: e.deleted, modified_at: e.modified_at, author: e.author.into(), nonce: e.nonce.into(), ciphertext: (&e.ciphertext).into(), signature: e.signature.into(), base: 0 }
    }
}

impl WireRecord {
    /// Ein Datensatz auf dem Weg zum Server, mit der Revision, auf der er aufsetzt.
    pub fn outgoing(envelope: &Envelope, base: u64) -> Self {
        Self { base, ..Self::from(envelope) }
    }

    pub fn envelope(&self) -> Option<Envelope> {
        Some(Envelope {
            id: self.id.array()?,
            revision: self.revision,
            deleted: self.deleted,
            modified_at: self.modified_at,
            author: self.author.array()?,
            nonce: self.nonce.array()?,
            ciphertext: self.ciphertext.0.clone(),
            signature: self.signature.array()?,
        })
    }
}

/// Ein Tresor aus Sicht eines Kontos.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultEntry {
    pub id: Bytes,
    pub shared: bool,
    pub epoch: u64,
    /// Nummer der letzten angenommenen Änderung.
    pub seq: u64,
    pub role: Role,
    /// Eingeladen, aber noch nicht angenommen.
    pub invited: bool,
    /// Signierte Mitgliederliste und der für dieses Konto verpackte Schlüssel (nur geteilte Tresore).
    pub roster: Option<Bytes>,
    pub sealed_key: Option<Bytes>,
    /// Wer beim Server gerade Mitglied ist. Nennt die Liste jemanden, der hier fehlt, ist er gegangen oder
    /// hat die Einladung abgelehnt; der Besitzer tauscht dann den Schlüssel.
    #[serde(default)]
    pub members: Vec<MemberState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberState {
    pub account: Bytes,
    pub invited: bool,
}

/// Neuer Name eines Geräts, mit dem Kontoschlüssel verschlüsselt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenameDevice {
    pub name: Bytes,
}

/// Alles, was ein Gerät nach dem Anmelden und nach „an deinem Konto hat sich etwas geändert“ wissen muss.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Overview {
    pub account_id: Bytes,
    pub username: String,
    pub admin: bool,
    pub account: WireAccount,
    pub vaults: Vec<VaultEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pull {
    pub seq: u64,
    pub epoch: u64,
    /// Der ganze Stand statt nur der Änderungen: Das Gerät war länger weg, als der Server Grabsteine aufhebt.
    pub full: bool,
    pub records: Vec<WireRecord>,
    /// Prüfsumme über den ganzen Stand des Tresors beim Server (`glowport_core::vault::state_digest`).
    #[serde(default)]
    pub digest: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Push {
    pub epoch: u64,
    pub records: Vec<WireRecord>,
}

/// Angenommen wird ein Paket ganz oder gar nicht. Abgelehnt nennt die Antwort, was der Server stattdessen hat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushReply {
    pub accepted: bool,
    pub seq: u64,
    pub epoch: u64,
    pub conflicts: Vec<WireRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateVault {
    pub id: Bytes,
    pub roster: Bytes,
    pub sealed_key: Bytes,
}

/// Der Schlüssel eines Tresors, verpackt für das Mitglied mit diesem Signaturschlüssel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedKey {
    pub member: Bytes,
    pub sealed: Bytes,
}

/// Neue Mitgliederliste beim selben Schlüsselstand, mit dem Schlüssel für jedes neue Mitglied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterUpdate {
    pub roster: Bytes,
    pub keys: Vec<SealedKey>,
}

/// Schlüsseltausch als ein Paket. Gilt nur, wenn seit `expected_seq` niemand geschrieben hat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rotate {
    pub expected_seq: u64,
    pub roster: Bytes,
    pub keys: Vec<SealedKey>,
    pub records: Vec<WireRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeys {
    pub account_id: Bytes,
    pub username: String,
    pub ed25519: Bytes,
    pub x25519: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    pub id: Bytes,
    pub name: Bytes,
    pub created_at: i64,
    pub seen_at: i64,
    pub current: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordChange {
    /// Der bisherige Anmeldeschlüssel: Ein gestohlenes Geräte-Token allein ändert kein Passwort.
    pub auth_key: Bytes,
    pub new_auth_key: Bytes,
    pub salt: Bytes,
    pub kdf: Kdf,
    pub account_nonce: Bytes,
    pub account_wrapped: Bytes,
    pub logout_others: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invite {
    pub code: String,
    pub created_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminAccount {
    pub id: Bytes,
    pub username: String,
    pub admin: bool,
    pub disabled: bool,
    pub created_at: i64,
    pub seen_at: i64,
    pub devices: u32,
    /// Größe aller Schlüsseltexte in Tresoren, die diesem Konto gehören.
    pub bytes: u64,
}

/// Nachricht über den WebSocket `/v1/live`: nur der Anstoß, geholt wird über die gewöhnlichen Anfragen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "lowercase")]
pub enum Event {
    Vault { id: Bytes, seq: u64 },
    Account,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_travel_as_base64_and_keep_their_length() {
        let bytes = Bytes(vec![0, 255, 16, 32]);
        assert_eq!(STANDARD.encode(&bytes.0), "AP8QIA==");
        assert_eq!(bytes.array::<4>(), Some([0, 255, 16, 32]));
        assert_eq!(bytes.array::<3>(), None);
        assert_eq!(format!("{bytes:?}"), "Bytes(4)", "kein Inhalt in Protokollen");
    }
}

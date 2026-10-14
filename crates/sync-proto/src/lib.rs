//! Messages between Glowport and the sync server (`docs/sync.md`). JSON over HTTPS under `/v1/…`.
//!
//! Everything binary travels as Base64. Of it the server only interprets what it needs for checking: IDs,
//! public keys, signatures. It passes ciphertexts through.

use base64::{engine::general_purpose::STANDARD, Engine};
use glowport_core::{
    crypto::KdfParams,
    roster::Role,
    vault::{Account, Envelope},
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Version of this protocol. The server names its own and the oldest it still serves.
pub const PROTOCOL: u32 = 1;

/// Binary field; a Base64 text in JSON.
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

/// Error response of the server. `code` is for the program, `message` for the operator's log.
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
    /// There is no account yet: the first one needs the setup code instead of an invitation.
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

/// What the server keeps per account so another device can sign in with the master password.
/// Every piece is public or already encrypted.
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
    /// Back into the core's form, provided every piece has the right length.
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
    /// Invitation code; for the very first account the server's setup code.
    pub code: String,
    pub username: String,
    pub auth_key: Bytes,
    pub account: WireAccount,
    /// Name of the device, encrypted with the account key.
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
    /// Identifies the device on every further request (`Authorization: Bearer <Base64>`).
    pub token: Bytes,
    pub admin: bool,
    pub account: WireAccount,
}

/// Response to signing in and creating an account. `needs` is intended for a later second factor: if something
/// is there, there is no session yet, and a program that does not know the step needs an update.
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
    /// Only when sending: the revision this change builds on (0 = the server does not know the record).
    /// The server only accepts what builds on its state.
    #[serde(default)]
    pub base: u64,
}

impl From<&Envelope> for WireRecord {
    fn from(e: &Envelope) -> Self {
        Self { id: e.id.into(), revision: e.revision, deleted: e.deleted, modified_at: e.modified_at, author: e.author.into(), nonce: e.nonce.into(), ciphertext: (&e.ciphertext).into(), signature: e.signature.into(), base: 0 }
    }
}

impl WireRecord {
    /// A record on its way to the server, with the revision it builds on.
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

/// A vault as an account sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultEntry {
    pub id: Bytes,
    pub shared: bool,
    pub epoch: u64,
    /// Number of the last accepted change.
    pub seq: u64,
    pub role: Role,
    /// Invited, but not accepted yet.
    pub invited: bool,
    /// Signed member list and the key wrapped for this account (shared vaults only).
    pub roster: Option<Bytes>,
    pub sealed_key: Option<Bytes>,
    /// Who is currently a member at the server. If the list names someone who is missing here, they left or
    /// declined the invitation; the owner then rotates the key.
    #[serde(default)]
    pub members: Vec<MemberState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberState {
    pub account: Bytes,
    pub invited: bool,
}

/// New name of a device, encrypted with the account key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenameDevice {
    pub name: Bytes,
}

/// Everything a device must know after signing in and after “something changed on your account”.
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
    /// The whole state instead of only the changes: the device was away longer than the server keeps tombstones.
    pub full: bool,
    pub records: Vec<WireRecord>,
    /// Checksum over the vault's whole state at the server (`glowport_core::vault::state_digest`).
    #[serde(default)]
    pub digest: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Push {
    pub epoch: u64,
    pub records: Vec<WireRecord>,
}

/// A package is accepted completely or not at all. If refused, the answer names what the server has instead.
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

/// A vault's key, wrapped for the member with this signing key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedKey {
    pub member: Bytes,
    pub sealed: Bytes,
}

/// New member list at the same key generation, with the key for every new member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterUpdate {
    pub roster: Bytes,
    pub keys: Vec<SealedKey>,
}

/// Key rotation as one package. Only valid if nobody has written since `expected_seq`.
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
    /// The previous sign-in key: a stolen device token alone changes no password.
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
    /// Size of all ciphertexts in vaults this account owns.
    pub bytes: u64,
}

/// Message over the WebSocket `/v1/live`: only the nudge, fetching happens over the ordinary requests.
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

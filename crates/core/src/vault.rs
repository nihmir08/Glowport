//! Encrypted storage: an SQLite file with individually encrypted and signed records.
//!
//! The vault knows no hosts or groups, only bytes. What they contain is defined by `model`.
//! Format and reasoning: `docs/vault.md`; several vaults, sharing and sync: `docs/sync.md`.

use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rusqlite::{params, types::ValueRef, Connection, ErrorCode, OptionalExtension};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{
    crypto::{self, KdfParams, Key, KEY_LEN, NONCE_LEN, SALT_LEN},
    merge::{Merge, Outcome},
    roster::{self, Member, Role, Roster, RosterError},
    share,
};

/// Version 2: several vaults per file and everything for syncing. Records, key chain
/// and test vectors are the same as in version 1; a version 1 file is converted when opened.
pub const FORMAT_VERSION: u32 = 2;

/// ID of a vault or record: 16 random bytes.
pub type Id = [u8; 16];

const INFO_KEK: &[u8] = b"glowport/kek/v1";
const INFO_AUTH: &[u8] = b"glowport/auth/v1";
const AAD_ACCOUNT: &str = "glowport/account/v1";
const AAD_ED25519: &str = "glowport/ed25519/v1";
const AAD_X25519: &str = "glowport/x25519/v1";
const AAD_VAULT: &str = "glowport/vault/v1";
const AAD_RECORD: &str = "glowport/record/v1";
const AAD_LINK: &str = "glowport/link/v1";
const AAD_ROSTER: &str = "glowport/roster-at-rest/v1";
const AAD_OWN: &str = "glowport/own/v1";
const AAD_CONTACT: &str = "glowport/contact/v1";
const AAD_NOTICE: &str = "glowport/notice/v1";

/// This many notices from syncing are kept; older ones drop out.
const MAX_NOTICES: i64 = 200;

const SCHEMA_1: &str = "
CREATE TABLE meta (key TEXT PRIMARY KEY, value BLOB NOT NULL) WITHOUT ROWID;
CREATE TABLE vaults (id BLOB PRIMARY KEY, nonce BLOB NOT NULL, wrapped_key BLOB NOT NULL) WITHOUT ROWID;
CREATE TABLE records (
    id BLOB PRIMARY KEY,
    vault_id BLOB NOT NULL REFERENCES vaults(id),
    revision INTEGER NOT NULL,
    deleted INTEGER NOT NULL,
    modified_at INTEGER NOT NULL,
    author BLOB NOT NULL,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    signature BLOB NOT NULL,
    dirty INTEGER NOT NULL DEFAULT 1
) WITHOUT ROWID;
";

/// The step from version 1 to 2. A new file is created from `SCHEMA_1` and this step, so that a
/// converted and a new file never look different.
///
/// - `vaults.kind`: 0 personal, 1 shared. `epoch`: key generation. `cursor`: up to which server number
///   everything has been fetched. `roster`: signed member list of a shared vault.
/// - `records.synced`: the revision the server last confirmed or delivered (0 = the server does not know it).
/// - `base`: the last synced state of every record whose change has not reached the server yet.
/// - `contacts`: public keys of other accounts seen once. `notices`: notices from syncing.
///
/// Member lists, contacts and notices contain names; they are therefore stored in the file encrypted
/// with the account key (`sealed`: nonce, followed by the ciphertext).
const SCHEMA_2: &str = "
ALTER TABLE vaults ADD COLUMN kind INTEGER NOT NULL DEFAULT 0;
ALTER TABLE vaults ADD COLUMN epoch INTEGER NOT NULL DEFAULT 1;
ALTER TABLE vaults ADD COLUMN cursor INTEGER NOT NULL DEFAULT 0;
ALTER TABLE vaults ADD COLUMN roster BLOB;
ALTER TABLE records ADD COLUMN synced INTEGER NOT NULL DEFAULT 0;
CREATE TABLE base (
    id BLOB PRIMARY KEY,
    revision INTEGER NOT NULL,
    deleted INTEGER NOT NULL,
    modified_at INTEGER NOT NULL,
    author BLOB NOT NULL,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    signature BLOB NOT NULL
) WITHOUT ROWID;
CREATE TABLE contacts (account BLOB PRIMARY KEY, sealed BLOB NOT NULL) WITHOUT ROWID;
CREATE TABLE notices (id INTEGER PRIMARY KEY, at INTEGER NOT NULL, sealed BLOB NOT NULL);
";

const ROW: &str = "id, vault_id, revision, deleted, modified_at, author, nonce, ciphertext, signature";

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("The vault is locked")]
    Locked,
    #[error("Wrong master password")]
    WrongPassword,
    #[error("A vault already exists")]
    AlreadyExists,
    #[error("Record not found")]
    NotFound,
    #[error("The vault file is damaged or was modified ({0})")]
    Corrupt(&'static str),
    #[error("Vault format {0} is not supported by this version")]
    UnsupportedFormat(u32),
    #[error("Key derivation failed")]
    Kdf,
    /// The key stored on this device does not fit this vault (any more).
    #[error("The stored device key does not match this vault")]
    StaleDeviceKey,
    #[error("The personal vault cannot be removed")]
    Personal,
    #[error("You only have read access to this vault")]
    ReadOnly,
    #[error("Only the vault's owner may do that")]
    NotOwner,
    #[error("You are not a member of this vault")]
    NotMember,
    /// A key rotation needs a vault without waiting changes.
    #[error("Changes in this vault are still waiting to be synced")]
    Pending,
    #[error(transparent)]
    Roster(#[from] RosterError),
    #[error(transparent)]
    Db(#[from] rusqlite::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

type Result<T> = std::result::Result<T, VaultError>;

/// Decrypted record. The content is overwritten when dropped.
#[derive(Debug)]
pub struct Record {
    pub id: Id,
    pub vault: Id,
    pub revision: u64,
    pub modified_at: i64,
    pub data: Zeroizing<Vec<u8>>,
}

/// Result of reading: what could be opened and what not. A damaged record does not lock out the rest.
#[derive(Debug, Default)]
pub struct Listing {
    pub records: Vec<Record>,
    pub damaged: Vec<Vec<u8>>,
}

/// A record as stored in the file and sent to the server: encrypted and signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub id: Id,
    pub revision: u64,
    pub deleted: bool,
    pub modified_at: i64,
    pub author: [u8; 32],
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
    pub signature: [u8; 64],
}

impl Envelope {
    /// Does the envelope carry its author's signature for this vault? That can be checked without a key
    /// of the vault, so also by the server.
    pub fn signed(&self, vault: &Id) -> bool {
        let aad = record_aad(vault, &self.id, self.revision, self.deleted);
        let message = [aad.as_slice(), &self.nonce, &self.ciphertext].concat();
        VerifyingKey::from_bytes(&self.author).is_ok_and(|key| key.verify_strict(&message, &Signature::from_bytes(&self.signature)).is_ok())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Personal,
    Shared,
}

#[derive(Debug, Clone)]
pub struct VaultInfo {
    pub id: Id,
    pub kind: Kind,
    pub epoch: u64,
    /// Up to which server number everything has been fetched.
    pub cursor: u64,
    /// Own role; always owner in the personal vault.
    pub role: Role,
    pub roster: Option<Roster>,
}

/// Everything a new device needs from the server to open this vault with the master password.
/// Every piece is already encrypted or public.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub salt: [u8; SALT_LEN],
    pub kdf: KdfParams,
    pub account_nonce: Vec<u8>,
    pub account_wrapped: Vec<u8>,
    pub ed25519_public: [u8; 32],
    pub ed25519_nonce: Vec<u8>,
    pub ed25519_wrapped: Vec<u8>,
    pub x25519_public: [u8; 32],
    pub x25519_nonce: Vec<u8>,
    pub x25519_wrapped: Vec<u8>,
    pub personal: Id,
    pub personal_nonce: Vec<u8>,
    pub personal_wrapped: Vec<u8>,
}

/// The public keys under which another account was last seen.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Contact {
    pub name: String,
    pub ed25519: String,
    pub x25519: String,
    pub seen_at: i64,
}

/// A notice from syncing as stored in the file: sequence number, time, content.
#[derive(Debug)]
pub struct StoredNotice {
    pub id: i64,
    pub at: i64,
    pub data: Zeroizing<Vec<u8>>,
}

/// What happened when taking over records from the server.
#[derive(Debug, Default)]
pub struct Applied {
    /// Taken over as delivered.
    pub taken: Vec<Id>,
    /// Merged with a waiting own change.
    pub merged: Vec<(Id, Merge)>,
    /// Rejected: wrong signature, author without write permission, cannot be decrypted or older than known.
    pub rejected: Vec<Id>,
}

/// A prepared key rotation: everything that goes to the server as one package. Locally nothing changes until
/// [`Vault::commit_rotation`], i.e. after the server accepted it.
pub struct Rotation {
    pub vault: Id,
    pub epoch: u64,
    pub roster: Vec<u8>,
    /// Per member (signing key) the new vault key wrapped for them.
    pub keys: Vec<([u8; 32], Vec<u8>)>,
    pub records: Vec<Envelope>,
    key: Key,
    parsed: Roster,
}

struct VaultKeys {
    key: Key,
    kind: Kind,
    epoch: u64,
    roster: Option<Roster>,
}

impl VaultKeys {
    /// May the holder of `author` write records here? In the personal vault only oneself.
    fn allows(&self, author: &[u8; 32], me: &[u8; 32]) -> bool {
        match &self.roster {
            Some(roster) => roster.may_write(author),
            None => author == me,
        }
    }

    fn role(&self, me: &[u8; 32]) -> Option<Role> {
        match &self.roster {
            Some(roster) => roster.role(me),
            None => Some(Role::Owner),
        }
    }
}

struct Unlocked {
    /// Stays in memory while the vault is open: all other keys follow from it anyway.
    /// It is needed for unlocking at startup without the master password (`device_key`).
    account_key: Key,
    signing: SigningKey,
    public: [u8; 32],
    /// Receives the keys of shared vaults.
    exchange: StaticSecret,
    personal: Id,
    vaults: BTreeMap<Id, VaultKeys>,
}

pub struct Vault {
    conn: Connection,
    path: PathBuf,
    unlocked: Option<Unlocked>,
    /// Counts changes to records and vaults (see [`Vault::writes`]).
    writes: Cell<u64>,
}

struct Row {
    id: Vec<u8>,
    vault_id: Vec<u8>,
    revision: i64,
    deleted: bool,
    modified_at: i64,
    author: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    signature: Vec<u8>,
}

impl Row {
    fn read(row: &rusqlite::Row) -> rusqlite::Result<Self> {
        Ok(Self {
            id: blob(row, 0)?,
            vault_id: blob(row, 1)?,
            revision: integer(row, 2)?,
            deleted: integer(row, 3)? != 0,
            modified_at: integer(row, 4)?,
            author: blob(row, 5)?,
            nonce: blob(row, 6)?,
            ciphertext: blob(row, 7)?,
            signature: blob(row, 8)?,
        })
    }

    /// As an envelope, provided every piece has the right length.
    fn envelope(&self) -> Option<Envelope> {
        Some(Envelope {
            id: self.id.as_slice().try_into().ok()?,
            revision: u64::try_from(self.revision).ok()?,
            deleted: self.deleted,
            modified_at: self.modified_at,
            author: self.author.as_slice().try_into().ok()?,
            nonce: self.nonce.as_slice().try_into().ok()?,
            ciphertext: self.ciphertext.clone(),
            signature: self.signature.as_slice().try_into().ok()?,
        })
    }
}

/// State of a record in the file, as writing needs it.
struct State {
    vault: Id,
    revision: u64,
    deleted: bool,
    dirty: bool,
    synced: u64,
}

pub(crate) fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as i64)
}

fn array<const N: usize>(bytes: &[u8], what: &'static str) -> Result<[u8; N]> {
    bytes.try_into().map_err(|_| VaultError::Corrupt(what))
}

/// Reads a column as bytes, whatever type SQLite gives it. A file altered from outside can turn a
/// blob into text; that should show up as “damaged” and not abort the whole read.
fn blob(row: &rusqlite::Row, index: usize) -> rusqlite::Result<Vec<u8>> {
    Ok(match row.get_ref(index)? {
        ValueRef::Blob(bytes) | ValueRef::Text(bytes) => bytes.to_vec(),
        _ => Vec::new(),
    })
}

fn integer(row: &rusqlite::Row, index: usize) -> rusqlite::Result<i64> {
    Ok(match row.get_ref(index)? {
        ValueRef::Integer(n) => n,
        _ => -1,
    })
}

/// Not an SQLite file or a foreign structure: for the user both are “damaged”. Other errors
/// (locked file, missing permissions) stay what they are.
fn as_corrupt(error: VaultError) -> VaultError {
    match &error {
        VaultError::Db(rusqlite::Error::SqliteFailure(failure, message))
            if matches!(failure.code, ErrorCode::NotADatabase | ErrorCode::DatabaseCorrupt)
                || message.as_deref().is_some_and(|m| m.contains("no such table")) =>
        {
            VaultError::Corrupt("not a vault file")
        }
        _ => error,
    }
}

fn meta_set(conn: &Connection, key: &str, value: &[u8]) -> Result<()> {
    conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)", params![key, value])?;
    Ok(())
}

fn record_aad(vault_id: &[u8], id: &[u8], revision: u64, deleted: bool) -> Vec<u8> {
    crypto::aad(AAD_RECORD, &[vault_id, id, &revision.to_le_bytes(), &[deleted as u8]])
}

fn account_aad(salt: &[u8], kdf: KdfParams) -> Vec<u8> {
    crypto::aad(AAD_ACCOUNT, &[&FORMAT_1.to_le_bytes(), salt, &kdf.to_bytes()])
}

/// The wrapped account key stays bound to the version that defined the key chain.
/// Otherwise no master password would open the file after it was converted.
const FORMAT_1: u32 = 1;

/// The account key wrapped under a master password: what changes on a password change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wrapping {
    pub salt: [u8; SALT_LEN],
    pub kdf: KdfParams,
    pub account_nonce: Vec<u8>,
    pub account_wrapped: Vec<u8>,
}

/// From the password: the key that unlocks the account key, and the one for signing in to the sync server.
/// Nothing can be decrypted with the second one.
fn password_keys(password: &str, salt: &[u8; SALT_LEN], kdf: KdfParams) -> Result<(Key, Key)> {
    let master = crypto::derive_master_key(password.as_bytes(), salt, kdf).map_err(|_| VaultError::Kdf)?;
    Ok((crypto::derive_subkey(&master, INFO_KEK), crypto::derive_subkey(&master, INFO_AUTH)))
}

/// Wraps the account key under a password. Also returns this password's sign-in key.
fn wrap_account(password: &str, kdf: KdfParams, account_key: &Key) -> Result<(Wrapping, Key)> {
    let salt: [u8; SALT_LEN] = crypto::random();
    let (kek, auth) = password_keys(password, &salt, kdf)?;
    let sealed = crypto::seal(&kek, &account_aad(&salt, kdf), account_key.as_ref());
    Ok((Wrapping { salt, kdf, account_nonce: sealed.nonce.to_vec(), account_wrapped: sealed.ciphertext }, auth))
}

/// Writes a wrapping: as the current one (`prefix` empty) or as a pending one (`next_`).
fn write_wrapping(conn: &Connection, wrapping: &Wrapping, prefix: &str) -> Result<()> {
    meta_set(conn, &format!("{prefix}salt"), &wrapping.salt)?;
    meta_set(conn, &format!("{prefix}kdf"), &wrapping.kdf.to_bytes())?;
    meta_set(conn, &format!("{prefix}account_nonce"), &wrapping.account_nonce)?;
    meta_set(conn, &format!("{prefix}account_wrapped"), &wrapping.account_wrapped)
}

fn clear_staged(conn: &Connection) -> Result<()> {
    conn.execute("DELETE FROM meta WHERE key IN ('next_salt', 'next_kdf', 'next_account_nonce', 'next_account_wrapped')", [])?;
    Ok(())
}

/// The key a device identifies itself with at the sync server. Nothing can be decrypted with it.
pub fn auth_key(password: &str, salt: &[u8; SALT_LEN], kdf: KdfParams) -> Result<Key> {
    Ok(password_keys(password, salt, kdf)?.1)
}

/// Checksum over a vault's state: ID and revision of every live record, ordered by
/// ID. The server computes it over what it has, a device over what it believes the server's state to be.
/// If they do not match, the device missed something or the server lost something; numbers alone
/// do not reliably show that, e.g. after restoring the server from a backup.
pub fn state_digest(entries: impl IntoIterator<Item = (Id, u64)>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for (id, revision) in entries {
        hasher.update(id);
        hasher.update(revision.to_le_bytes());
    }
    hasher.finalize().into()
}

/// A small piece under the account key: nonce, followed by the ciphertext.
fn seal_small(key: &Key, label: &str, context: &[u8], data: &[u8]) -> Vec<u8> {
    let sealed = crypto::seal(key, &crypto::aad(label, &[context]), data);
    [sealed.nonce.as_slice(), &sealed.ciphertext].concat()
}

fn open_small(key: &Key, label: &str, context: &[u8], stored: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if stored.len() < NONCE_LEN {
        return None;
    }
    let (nonce, ciphertext) = stored.split_at(NONCE_LEN);
    crypto::open(key, nonce, &crypto::aad(label, &[context]), ciphertext).ok()
}

/// Checks an envelope's signature and author and decrypts it.
fn unseal(vault_id: &Id, vault: &VaultKeys, me: &[u8; 32], envelope: &Envelope) -> Option<Zeroizing<Vec<u8>>> {
    if !vault.allows(&envelope.author, me) || !envelope.signed(vault_id) {
        return None;
    }
    let aad = record_aad(vault_id, &envelope.id, envelope.revision, envelope.deleted);
    crypto::open(&vault.key, &envelope.nonce, &aad, &envelope.ciphertext).ok()
}

/// Encrypts and signs a record as oneself.
fn seal(keys: &Unlocked, vault_id: &Id, key: &Key, id: Id, revision: u64, deleted: bool, plaintext: &[u8]) -> Envelope {
    let aad = record_aad(vault_id, &id, revision, deleted);
    let sealed = crypto::seal(key, &aad, plaintext);
    let signature = keys.signing.sign(&[aad.as_slice(), &sealed.nonce, &sealed.ciphertext].concat());
    Envelope { id, revision, deleted, modified_at: now_ms(), author: keys.public, nonce: sealed.nonce, ciphertext: sealed.ciphertext, signature: signature.to_bytes() }
}

impl Vault {
    pub fn exists(path: &Path) -> bool {
        path.is_file()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn is_unlocked(&self) -> bool {
        self.unlocked.is_some()
    }

    /// Rises with every change to records, vaults or member lists. Whoever keeps the content in memory
    /// (the directory) reads again when the number has changed, e.g. after a sync.
    pub fn writes(&self) -> u64 {
        self.writes.get()
    }

    fn touch(&self) {
        self.writes.set(self.writes.get() + 1);
    }

    fn connect(path: &Path) -> Result<Connection> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA synchronous = FULL;")?;
        Ok(conn)
    }

    /// Creates a new vault and leaves it open. If creating fails, no half-written file is left behind.
    pub fn create(path: &Path, password: &str, kdf: KdfParams) -> Result<Self> {
        if path.exists() {
            return Err(VaultError::AlreadyExists);
        }
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let conn = Self::connect(path)?;
        match Self::initialise(&conn, password, kdf) {
            Ok(unlocked) => Ok(Self { conn, path: path.into(), unlocked: Some(unlocked), writes: Cell::new(0) }),
            Err(e) => {
                drop(conn);
                let _ = std::fs::remove_file(path);
                Err(e)
            }
        }
    }

    fn initialise(conn: &Connection, password: &str, kdf: KdfParams) -> Result<Unlocked> {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(SCHEMA_1)?;
        tx.execute_batch(SCHEMA_2)?;
        meta_set(&tx, "format_version", &FORMAT_VERSION.to_le_bytes())?;
        meta_set(&tx, "device_id", &crypto::random::<16>())?;

        let account_key = crypto::random_key();
        write_wrapping(&tx, &wrap_account(password, kdf, &account_key)?.0, "")?;

        let seed = Zeroizing::new(crypto::random::<KEY_LEN>());
        let signing = SigningKey::from_bytes(&seed);
        let public = signing.verifying_key().to_bytes();
        let sealed = crypto::seal(&account_key, &crypto::aad(AAD_ED25519, &[&public]), seed.as_ref());
        meta_set(&tx, "ed25519_public", &public)?;
        meta_set(&tx, "ed25519_nonce", &sealed.nonce)?;
        meta_set(&tx, "ed25519_wrapped", &sealed.ciphertext)?;

        let secret = Zeroizing::new(crypto::random::<KEY_LEN>());
        let exchange = StaticSecret::from(*secret);
        let exchange_public = PublicKey::from(&exchange).to_bytes();
        let sealed = crypto::seal(&account_key, &crypto::aad(AAD_X25519, &[&exchange_public]), secret.as_ref());
        meta_set(&tx, "x25519_public", &exchange_public)?;
        meta_set(&tx, "x25519_nonce", &sealed.nonce)?;
        meta_set(&tx, "x25519_wrapped", &sealed.ciphertext)?;

        let vault_id: Id = crypto::random();
        let vault_key = crypto::random_key();
        let sealed = crypto::seal(&account_key, &crypto::aad(AAD_VAULT, &[&vault_id]), vault_key.as_ref());
        tx.execute(
            "INSERT INTO vaults (id, nonce, wrapped_key) VALUES (?1, ?2, ?3)",
            params![vault_id.as_slice(), sealed.nonce.as_slice(), sealed.ciphertext],
        )?;
        meta_set(&tx, "default_vault", &vault_id)?;
        tx.commit()?;

        let vaults = BTreeMap::from([(vault_id, VaultKeys { key: vault_key, kind: Kind::Personal, epoch: 1, roster: None })]);
        Ok(Unlocked { account_key, signing, public, exchange, personal: vault_id, vaults })
    }

    /// Where [`Vault::open`] puts the copy of a version 1 file before converting it.
    pub fn migration_copy(path: &Path) -> PathBuf {
        let mut name = path.file_name().unwrap_or_default().to_os_string();
        name.push(".format1");
        path.with_file_name(name)
    }

    /// Opens the file without unlocking it. A version 1 file is converted on the way; beforehand
    /// a copy is created next to it (see [`Vault::migration_copy`]).
    pub fn open(path: &Path) -> Result<Self> {
        let vault = Self { conn: Self::connect(path).map_err(as_corrupt)?, path: path.into(), unlocked: None, writes: Cell::new(0) };
        let version = vault.meta("format_version").map_err(as_corrupt)?;
        match u32::from_le_bytes(array(&version, "Formatversion")?) {
            FORMAT_VERSION => Ok(vault),
            FORMAT_1 => {
                vault.migrate_from_1()?;
                Ok(vault)
            }
            other => Err(VaultError::UnsupportedFormat(other)),
        }
    }

    fn migrate_from_1(&self) -> Result<()> {
        self.copy_to(&Self::migration_copy(&self.path))?;
        let tx = self.conn.unchecked_transaction()?;
        tx.execute_batch(SCHEMA_2)?;
        meta_set(&tx, "format_version", &FORMAT_VERSION.to_le_bytes())?;
        Ok(tx.commit()?)
    }

    fn meta(&self, key: &'static str) -> Result<Vec<u8>> {
        self.meta_opt(key)?.ok_or(VaultError::Corrupt(key))
    }

    fn meta_opt(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |row| blob(row, 0)).optional()?)
    }

    fn wrapping(&self, prefix: &str) -> Result<Option<Wrapping>> {
        let piece = |name: &str| self.meta_opt(&format!("{prefix}{name}"));
        let (Some(salt), Some(kdf), Some(account_nonce), Some(account_wrapped)) = (piece("salt")?, piece("kdf")?, piece("account_nonce")?, piece("account_wrapped")?) else { return Ok(None) };
        Ok(<[u8; SALT_LEN]>::try_from(salt.as_slice()).ok().zip(KdfParams::from_bytes(&kdf)).map(|(salt, kdf)| Wrapping { salt, kdf, account_nonce, account_wrapped }))
    }

    /// Unwraps the account key from a wrapping. Fails on the password or on altered header data;
    /// the two cannot be told apart.
    fn try_wrapping(password: &str, wrapping: &Wrapping) -> Result<(Key, Key)> {
        let (kek, auth) = password_keys(password, &wrapping.salt, wrapping.kdf)?;
        let account = crypto::open(&kek, &wrapping.account_nonce, &account_aad(&wrapping.salt, wrapping.kdf), &wrapping.account_wrapped).map_err(|_| VaultError::WrongPassword)?;
        Ok((Zeroizing::new(array(&account, "account key")?), auth))
    }

    /// Derives the keys from the password and unwraps the account key; also returns the
    /// sign-in key for the sync server.
    ///
    /// If the master password was changed on another device, its wrapping is stored next to it as pending
    /// (`stage_wrapping`). It comes from the server and is unverified; it therefore only applies once a password
    /// opens it and the key inside really is this account's. Until then the previous password opens.
    fn open_account(&self, password: &str) -> Result<(Key, Key)> {
        let current = self.wrapping("")?.ok_or(VaultError::Corrupt("account key"))?;
        match Self::try_wrapping(password, &current) {
            Err(VaultError::WrongPassword) => {}
            other => return other,
        }
        let Some(staged) = self.wrapping("next_")? else { return Err(VaultError::WrongPassword) };
        let (account_key, auth) = Self::try_wrapping(password, &staged)?;
        let public = self.meta("ed25519_public")?;
        self.open_private(&account_key, AAD_ED25519, "ed25519", &public).map_err(|_| VaultError::WrongPassword)?;
        let tx = self.conn.unchecked_transaction()?;
        write_wrapping(&tx, &staged, "")?;
        clear_staged(&tx)?;
        tx.commit()?;
        Ok((account_key, auth))
    }

    /// Unwraps a private key and returns its 32 bytes.
    fn open_private(&self, account_key: &Key, label: &str, name: &'static str, public: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
        let (nonce, wrapped) = match name {
            "ed25519" => (self.meta("ed25519_nonce")?, self.meta("ed25519_wrapped")?),
            _ => (self.meta("x25519_nonce")?, self.meta("x25519_wrapped")?),
        };
        let secret = crypto::open(account_key, &nonce, &crypto::aad(label, &[public]), &wrapped).map_err(|_| VaultError::Corrupt(name))?;
        Ok(Zeroizing::new(array(&secret, name)?))
    }

    pub fn unlock(&mut self, password: &str) -> Result<()> {
        let (account_key, _) = self.open_account(password)?;
        self.unlock_with(account_key)
    }

    /// ID of this vault file on this device. Not a secret; binds the device key to exactly this vault.
    pub fn device_id(&self) -> Result<Vec<u8>> {
        self.meta("device_id")
    }

    /// The account key of the open vault. Whoever has it opens the vault without the master password;
    /// it may only leave the core to be stored under the operating system's protection.
    pub fn device_key(&self) -> Result<Key> {
        Ok(self.keys()?.account_key.clone())
    }

    /// Unlocks with a key stored earlier via `device_key` instead of with the master password.
    pub fn unlock_with_key(&mut self, account_key: &Key) -> Result<()> {
        self.unlock_with(account_key.clone()).map_err(|e| match e {
            // With the wrong key, unwrapping the private keys already fails.
            VaultError::Corrupt(_) => VaultError::StaleDeviceKey,
            other => other,
        })
    }

    fn unlock_with(&mut self, account_key: Key) -> Result<()> {
        let public: [u8; 32] = array(&self.meta("ed25519_public")?, "ed25519")?;
        let signing = SigningKey::from_bytes(&*self.open_private(&account_key, AAD_ED25519, "ed25519", &public)?);
        if signing.verifying_key().to_bytes() != public {
            return Err(VaultError::Corrupt("ed25519"));
        }

        let exchange_public: [u8; 32] = array(&self.meta("x25519_public")?, "x25519")?;
        let exchange = StaticSecret::from(*self.open_private(&account_key, AAD_X25519, "x25519", &exchange_public)?);
        if PublicKey::from(&exchange).to_bytes() != exchange_public {
            return Err(VaultError::Corrupt("x25519"));
        }

        let personal: Id = array(&self.meta("default_vault")?, "vault ID")?;
        let mut vaults = BTreeMap::new();
        let mut statement = self.conn.prepare("SELECT id, nonce, wrapped_key, kind, epoch, roster FROM vaults")?;
        let rows = statement.query_map([], |row| Ok((blob(row, 0)?, blob(row, 1)?, blob(row, 2)?, integer(row, 3)?, integer(row, 4)?, blob(row, 5)?)))?;
        for row in rows {
            let (id, nonce, wrapped, kind, epoch, roster_blob) = row?;
            // A shared vault that cannot be opened does not lock out the rest: it is then missing,
            // and its records count as damaged.
            let Ok(id) = Id::try_from(id.as_slice()) else { continue };
            let Some(key) = crypto::open(&account_key, &nonce, &crypto::aad(AAD_VAULT, &[&id]), &wrapped).ok().and_then(|k| <[u8; KEY_LEN]>::try_from(k.as_slice()).ok()).map(Zeroizing::new) else { continue };
            let entry = match (id == personal, kind) {
                (true, 0) => VaultKeys { key, kind: Kind::Personal, epoch: 1, roster: None },
                (false, 1) => match open_small(&account_key, AAD_ROSTER, &id, &roster_blob).and_then(|blob| roster::verify(&blob, &id, None).ok()) {
                    Some(roster) if roster.role(&public).is_some() => VaultKeys { key, kind: Kind::Shared, epoch: epoch.max(1) as u64, roster: Some(roster) },
                    _ => continue,
                },
                _ => continue,
            };
            vaults.insert(id, entry);
        }
        drop(statement);
        if !vaults.contains_key(&personal) {
            return Err(VaultError::Corrupt("vault key"));
        }

        self.unlocked = Some(Unlocked { account_key, signing, public, exchange, personal, vaults });
        Ok(())
    }

    /// Discards all keys. The types overwrite their memory themselves when dropped.
    pub fn lock(&mut self) {
        self.unlocked = None;
    }

    fn keys(&self) -> Result<&Unlocked> {
        self.unlocked.as_ref().ok_or(VaultError::Locked)
    }

    fn vault_keys(&self, vault: &Id) -> Result<(&Unlocked, &VaultKeys)> {
        let keys = self.keys()?;
        Ok((keys, keys.vaults.get(vault).ok_or(VaultError::NotFound)?))
    }

    /// Like `vault_keys`, but requires write permission.
    fn writable(&self, vault: &Id) -> Result<(&Unlocked, &VaultKeys)> {
        let (keys, vault) = self.vault_keys(vault)?;
        match vault.role(&keys.public) {
            Some(role) if role.may_write() => Ok((keys, vault)),
            Some(_) => Err(VaultError::ReadOnly),
            None => Err(VaultError::NotMember),
        }
    }

    /// New password: only the account key is wrapped anew, the records stay untouched.
    pub fn change_password(&mut self, old: &str, new: &str, kdf: KdfParams) -> Result<()> {
        let (wrapping, _, _) = self.rewrap(old, new, kdf)?;
        self.install_wrapping(&wrapping)
    }

    /// Wraps the account key under a new password without writing anything. Also returns the
    /// previous and the new sign-in key. With sync, the wrapping first goes to the server and is
    /// then taken over with [`Vault::install_wrapping`]; so it never happens that only this device knows the new password.
    pub fn rewrap(&self, old: &str, new: &str, kdf: KdfParams) -> Result<(Wrapping, Key, Key)> {
        let (account_key, old_auth) = self.open_account(old)?;
        let (wrapping, new_auth) = wrap_account(new, kdf, &account_key)?;
        Ok((wrapping, old_auth, new_auth))
    }

    /// Makes a wrapping created with [`Vault::rewrap`] the current one.
    pub fn install_wrapping(&mut self, wrapping: &Wrapping) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        write_wrapping(&tx, wrapping, "")?;
        clear_staged(&tx)?;
        Ok(tx.commit()?)
    }

    /// The current wrapping, for comparison with the server's.
    pub fn current_wrapping(&self) -> Result<Wrapping> {
        self.wrapping("")?.ok_or(VaultError::Corrupt("account key"))
    }

    /// Stores as pending the wrapping the server delivers after a password change on another device.
    /// It only replaces the current one once it unlocks (see `open_account`): a server
    /// that sends nonsense here locks nobody out.
    pub fn stage_wrapping(&mut self, wrapping: &Wrapping) -> Result<()> {
        write_wrapping(&self.conn, wrapping, "next_")
    }

    /// Runs several changes as one: either all or none.
    pub fn batch<T>(&mut self, work: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        self.begin()?;
        match work(self) {
            Ok(value) => {
                self.end(true)?;
                Ok(value)
            }
            Err(e) => {
                let _ = self.end(false);
                Err(e)
            }
        }
    }

    /// Starts a batch change. Every `begin` must be followed by exactly one `end`.
    pub fn begin(&mut self) -> Result<()> {
        Ok(self.conn.execute_batch("BEGIN IMMEDIATE")?)
    }

    /// Finishes a batch change: commit or discard everything.
    pub fn end(&mut self, commit: bool) -> Result<()> {
        Ok(self.conn.execute_batch(if commit { "COMMIT" } else { "ROLLBACK" })?)
    }

    /// Runs `work` completely or not at all, also inside a batch change.
    fn atomic<T>(&self, work: impl FnOnce() -> Result<T>) -> Result<T> {
        self.conn.execute_batch("SAVEPOINT step")?;
        match work() {
            Ok(value) => {
                self.conn.execute_batch("RELEASE step")?;
                Ok(value)
            }
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK TO step; RELEASE step");
                Err(e)
            }
        }
    }

    /// Writes an envelope in place of its record.
    fn store(&self, vault: &Id, envelope: &Envelope, dirty: bool, synced: u64) -> Result<()> {
        self.touch();
        self.conn.execute(
            "INSERT OR REPLACE INTO records (id, vault_id, revision, deleted, modified_at, author, nonce, ciphertext, signature, dirty, synced)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                envelope.id.as_slice(),
                vault.as_slice(),
                envelope.revision as i64,
                envelope.deleted,
                envelope.modified_at,
                envelope.author.as_slice(),
                envelope.nonce.as_slice(),
                envelope.ciphertext,
                envelope.signature.as_slice(),
                dirty,
                synced as i64
            ],
        )?;
        Ok(())
    }

    fn store_base(&self, envelope: &Envelope) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO base (id, revision, deleted, modified_at, author, nonce, ciphertext, signature) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                envelope.id.as_slice(),
                envelope.revision as i64,
                envelope.deleted,
                envelope.modified_at,
                envelope.author.as_slice(),
                envelope.nonce.as_slice(),
                envelope.ciphertext,
                envelope.signature.as_slice()
            ],
        )?;
        Ok(())
    }

    fn drop_base(&self, id: &Id) -> Result<()> {
        self.conn.execute("DELETE FROM base WHERE id = ?1", [id.as_slice()])?;
        Ok(())
    }

    fn state(&self, id: &Id) -> Result<Option<State>> {
        let found = self
            .conn
            .query_row("SELECT vault_id, revision, deleted, dirty, synced FROM records WHERE id = ?1", [id.as_slice()], |row| {
                Ok((blob(row, 0)?, integer(row, 1)?, integer(row, 2)? != 0, integer(row, 3)? != 0, integer(row, 4)?))
            })
            .optional()?;
        let Some((vault, revision, deleted, dirty, synced)) = found else { return Ok(None) };
        Ok(Some(State { vault: array(&vault, "vault ID")?, revision: revision.max(0) as u64, deleted, dirty, synced: synced.max(0) as u64 }))
    }

    fn envelope(&self, id: &Id) -> Result<Option<Envelope>> {
        let row = self.conn.query_row(&format!("SELECT {ROW} FROM records WHERE id = ?1"), [id.as_slice()], Row::read).optional()?;
        Ok(row.and_then(|row| row.envelope()))
    }

    fn base(&self, id: &Id) -> Result<Option<Envelope>> {
        let row = self
            .conn
            .query_row("SELECT id, x'', revision, deleted, modified_at, author, nonce, ciphertext, signature FROM base WHERE id = ?1", [id.as_slice()], Row::read)
            .optional()?;
        Ok(row.and_then(|row| row.envelope()))
    }

    /// Changes or deletes a live record.
    ///
    /// If the server already knows it, its state before the first waiting change is kept as the base,
    /// and further changes do not raise the revision again: the server only accepts exactly
    /// “one above what it has” (`docs/sync.md`, “Syncing”).
    fn change(&mut self, id: &Id, deleted: bool, plaintext: &[u8]) -> Result<()> {
        let state = self.state(id)?.filter(|s| !s.deleted).ok_or(VaultError::NotFound)?;
        let (keys, vault) = self.writable(&state.vault)?;
        let waiting = state.dirty && state.synced > 0;
        let revision = if waiting { state.revision } else { state.revision + 1 };
        let envelope = seal(keys, &state.vault, &vault.key, *id, revision, deleted, plaintext);
        self.atomic(|| {
            if !state.dirty && state.synced > 0 {
                let current = self.envelope(id)?.ok_or(VaultError::Corrupt("record"))?;
                self.store_base(&current)?;
            }
            self.store(&state.vault, &envelope, true, state.synced)
        })
    }

    /// Creates a record in the personal vault (`id` = None) or replaces an existing one, whichever
    /// vault it lives in. Returns the ID.
    pub fn put(&mut self, id: Option<Id>, plaintext: &[u8]) -> Result<Id> {
        match id {
            Some(id) => {
                self.keys()?;
                self.change(&id, false, plaintext)?;
                Ok(id)
            }
            None => self.put_in(&self.personal()?, plaintext),
        }
    }

    /// Creates a new record in a specific vault.
    pub fn put_in(&mut self, vault: &Id, plaintext: &[u8]) -> Result<Id> {
        let (keys, vault_keys) = self.writable(vault)?;
        let id: Id = crypto::random();
        self.store(vault, &seal(keys, vault, &vault_keys.key, id, 1, false, plaintext), true, 0)?;
        Ok(id)
    }

    /// Deletes by leaving a tombstone. That way the deletion also reaches other devices.
    pub fn delete(&mut self, id: &Id) -> Result<()> {
        self.keys()?;
        self.change(id, true, &[])
    }

    fn check(keys: &Unlocked, row: &Row) -> Option<Zeroizing<Vec<u8>>> {
        let vault_id = Id::try_from(row.vault_id.as_slice()).ok()?;
        unseal(&vault_id, keys.vaults.get(&vault_id)?, &keys.public, &row.envelope()?)
    }

    /// Reads and checks all records of all vaults. Tombstones are checked too, so that deletion
    /// cannot be forged.
    pub fn list(&self) -> Result<Listing> {
        let keys = self.keys()?;
        let mut statement = self.conn.prepare(&format!("SELECT {ROW} FROM records ORDER BY id"))?;
        let rows = statement.query_map([], Row::read)?;

        let mut listing = Listing::default();
        for row in rows {
            let row = row?;
            match Self::check(keys, &row) {
                Some(_) if row.deleted => {}
                Some(data) => listing.records.push(Record {
                    id: row.id.as_slice().try_into().expect("length checked in check"),
                    vault: row.vault_id.as_slice().try_into().expect("length checked in check"),
                    revision: row.revision as u64,
                    modified_at: row.modified_at,
                    data,
                }),
                None => listing.damaged.push(row.id),
            }
        }
        Ok(listing)
    }

    /// Removes tombstones older than `max_age_ms`. With sync set up, those the server does
    /// not know about yet stay: otherwise the deleted entry would come back from there.
    pub fn purge_tombstones(&mut self, max_age_ms: i64) -> Result<usize> {
        let linked = self.meta_opt("link")?.is_some();
        Ok(self.conn.execute("DELETE FROM records WHERE deleted = 1 AND modified_at < ?1 AND (dirty = 0 OR ?2 = 0)", params![now_ms() - max_age_ms, linked])?)
    }

    fn copy_to(&self, dest: &Path) -> Result<()> {
        if dest.exists() {
            std::fs::remove_file(dest)?;
        }
        self.conn.execute("VACUUM INTO ?1", [dest.to_string_lossy()])?;
        Ok(())
    }

    /// Writes a consistent copy. It is encrypted the same way and needs the same master password.
    /// The sign-in to the sync server does not go along: whoever restores a backup signs in again and
    /// syncs from scratch.
    pub fn backup(&self, dest: &Path) -> Result<()> {
        self.copy_to(dest)?;
        let copy = Connection::open(dest)?;
        copy.execute_batch("DELETE FROM meta WHERE key = 'link'; UPDATE vaults SET cursor = 0;")?;
        Ok(())
    }

    // ── Account ──────────────────────────────────────────────────────────────────────────────────────────

    /// The own public keys: signing (Ed25519) and receiving shared vault keys (X25519).
    pub fn public_keys(&self) -> Result<([u8; 32], [u8; 32])> {
        let keys = self.keys()?;
        Ok((keys.public, PublicKey::from(&keys.exchange).to_bytes()))
    }

    /// Checks the master password and returns the key for signing in to the sync server.
    pub fn auth_key(&self, password: &str) -> Result<Key> {
        Ok(self.open_account(password)?.1)
    }

    /// What the server keeps so another device can sign in with the master password.
    pub fn account(&self) -> Result<Account> {
        let personal: Id = array(&self.meta("default_vault")?, "vault ID")?;
        let (personal_nonce, personal_wrapped) = self
            .conn
            .query_row("SELECT nonce, wrapped_key FROM vaults WHERE id = ?1", [personal.as_slice()], |row| Ok((blob(row, 0)?, blob(row, 1)?)))
            .optional()?
            .ok_or(VaultError::Corrupt("vault key"))?;
        Ok(Account {
            salt: array(&self.meta("salt")?, "Salz")?,
            kdf: KdfParams::from_bytes(&self.meta("kdf")?).ok_or(VaultError::Corrupt("key derivation cost"))?,
            account_nonce: self.meta("account_nonce")?,
            account_wrapped: self.meta("account_wrapped")?,
            ed25519_public: array(&self.meta("ed25519_public")?, "ed25519")?,
            ed25519_nonce: self.meta("ed25519_nonce")?,
            ed25519_wrapped: self.meta("ed25519_wrapped")?,
            x25519_public: array(&self.meta("x25519_public")?, "x25519")?,
            x25519_nonce: self.meta("x25519_nonce")?,
            x25519_wrapped: self.meta("x25519_wrapped")?,
            personal,
            personal_nonce,
            personal_wrapped,
        })
    }

    /// Creates the vault file of an existing account on a new device and opens it. If the
    /// master password does not match what the server delivered, no file is created.
    pub fn create_from_account(path: &Path, password: &str, account: &Account) -> Result<Self> {
        if path.exists() {
            return Err(VaultError::AlreadyExists);
        }
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut vault = Self { conn: Self::connect(path)?, path: path.into(), unlocked: None, writes: Cell::new(0) };
        match vault.adopt(account).and_then(|()| vault.unlock(password)) {
            Ok(()) => Ok(vault),
            Err(e) => {
                drop(vault);
                let _ = std::fs::remove_file(path);
                Err(e)
            }
        }
    }

    fn adopt(&self, account: &Account) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute_batch(SCHEMA_1)?;
        tx.execute_batch(SCHEMA_2)?;
        meta_set(&tx, "format_version", &FORMAT_VERSION.to_le_bytes())?;
        meta_set(&tx, "device_id", &crypto::random::<16>())?;
        meta_set(&tx, "salt", &account.salt)?;
        meta_set(&tx, "kdf", &account.kdf.to_bytes())?;
        meta_set(&tx, "account_nonce", &account.account_nonce)?;
        meta_set(&tx, "account_wrapped", &account.account_wrapped)?;
        meta_set(&tx, "ed25519_public", &account.ed25519_public)?;
        meta_set(&tx, "ed25519_nonce", &account.ed25519_nonce)?;
        meta_set(&tx, "ed25519_wrapped", &account.ed25519_wrapped)?;
        meta_set(&tx, "x25519_public", &account.x25519_public)?;
        meta_set(&tx, "x25519_nonce", &account.x25519_nonce)?;
        meta_set(&tx, "x25519_wrapped", &account.x25519_wrapped)?;
        tx.execute("INSERT INTO vaults (id, nonce, wrapped_key) VALUES (?1, ?2, ?3)", params![account.personal.as_slice(), account.personal_nonce, account.personal_wrapped])?;
        meta_set(&tx, "default_vault", &account.personal)?;
        Ok(tx.commit()?)
    }

    /// The sign-in to the sync server (address, account, device token …), as `glowport-sync` stores it.
    /// Encrypted with the account key and bound to this file.
    pub fn link(&self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let keys = self.keys()?;
        let Some(stored) = self.meta_opt("link")? else { return Ok(None) };
        open_small(&keys.account_key, AAD_LINK, &self.device_id()?, &stored).map(Some).ok_or(VaultError::Corrupt("sign-in to the sync server"))
    }

    pub fn set_link(&mut self, link: Option<&[u8]>) -> Result<()> {
        let keys = self.keys()?;
        match link {
            Some(link) => meta_set(&self.conn, "link", &seal_small(&keys.account_key, AAD_LINK, &self.device_id()?, link)),
            None => {
                self.conn.execute("DELETE FROM meta WHERE key = 'link'", [])?;
                Ok(())
            }
        }
    }

    /// Encrypts something small so that only this account's devices can read it, e.g. the name of a
    /// device that the server keeps.
    pub fn seal_own(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(seal_small(&self.keys()?.account_key, AAD_OWN, &[], data))
    }

    pub fn open_own(&self, sealed: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>> {
        Ok(open_small(&self.keys()?.account_key, AAD_OWN, &[], sealed))
    }

    /// Takes the records of another open vault into the personal vault: re-encrypted and
    /// self-signed, under the same IDs so references between them hold. Meant for a device
    /// that already had data and connects to an existing account. Returns the number taken over.
    pub fn adopt_from(&mut self, other: &Vault) -> Result<usize> {
        let (keys, personal) = (self.keys()?, self.personal()?);
        let vault = &keys.vaults[&personal];
        let listing = other.list()?;
        self.atomic(|| {
            let mut adopted = 0;
            for record in &listing.records {
                if self.state(&record.id)?.is_none() {
                    self.store(&personal, &seal(keys, &personal, &vault.key, record.id, 1, false, &record.data), true, 0)?;
                    adopted += 1;
                }
            }
            Ok(adopted)
        })
    }

    // ── Contacts and notices ─────────────────────────────────────────────────────────────────────────────

    /// The public keys under which another account was last seen.
    pub fn contact(&self, account: &Id) -> Result<Option<Contact>> {
        let keys = self.keys()?;
        let stored = self.conn.query_row("SELECT sealed FROM contacts WHERE account = ?1", [account.as_slice()], |row| blob(row, 0)).optional()?;
        Ok(stored.and_then(|stored| open_small(&keys.account_key, AAD_CONTACT, account, &stored)).and_then(|plain| serde_json::from_slice(&plain).ok()))
    }

    /// Remembers an account's keys. If they change later, the program can warn.
    pub fn remember_contact(&mut self, account: &Id, contact: &Contact) -> Result<()> {
        let keys = self.keys()?;
        let plain = serde_json::to_vec(contact).map_err(|_| VaultError::Corrupt("Kontakt"))?;
        self.conn.execute("INSERT OR REPLACE INTO contacts (account, sealed) VALUES (?1, ?2)", params![account.as_slice(), seal_small(&keys.account_key, AAD_CONTACT, account, &plain)])?;
        Ok(())
    }

    /// Records a notice from syncing (content decided by `glowport-sync`). Older ones than the last 200 drop out.
    pub fn add_notice(&mut self, data: &[u8]) -> Result<()> {
        let keys = self.keys()?;
        self.conn.execute("INSERT INTO notices (at, sealed) VALUES (?1, ?2)", params![now_ms(), seal_small(&keys.account_key, AAD_NOTICE, &[], data)])?;
        self.conn.execute("DELETE FROM notices WHERE id <= (SELECT max(id) FROM notices) - ?1", [MAX_NOTICES])?;
        Ok(())
    }

    /// All notices, oldest first.
    pub fn notices(&self) -> Result<Vec<StoredNotice>> {
        let keys = self.keys()?;
        let mut statement = self.conn.prepare("SELECT id, at, sealed FROM notices ORDER BY id")?;
        let rows = statement.query_map([], |row| Ok((integer(row, 0)?, integer(row, 1)?, blob(row, 2)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (id, at, sealed) = row?;
            out.extend(open_small(&keys.account_key, AAD_NOTICE, &[], &sealed).map(|data| StoredNotice { id, at, data }));
        }
        Ok(out)
    }

    /// Removes the notices up to and including this number.
    pub fn clear_notices(&mut self, up_to: i64) -> Result<()> {
        self.keys()?;
        self.conn.execute("DELETE FROM notices WHERE id <= ?1", [up_to])?;
        Ok(())
    }

    // ── Vaults ───────────────────────────────────────────────────────────────────────────────────────────

    pub fn personal(&self) -> Result<Id> {
        Ok(self.keys()?.personal)
    }

    /// All open vaults, the personal one first.
    pub fn vaults(&self) -> Result<Vec<VaultInfo>> {
        let keys = self.keys()?;
        let mut out = Vec::with_capacity(keys.vaults.len());
        for (id, vault) in &keys.vaults {
            out.push(VaultInfo { id: *id, kind: vault.kind, epoch: vault.epoch, cursor: self.cursor(id)?, role: vault.role(&keys.public).unwrap_or(Role::Read), roster: vault.roster.clone() });
        }
        out.sort_by_key(|v| v.kind == Kind::Shared);
        Ok(out)
    }

    /// Which vault a record lives in (a deleted one too).
    pub fn vault_of(&self, id: &Id) -> Result<Id> {
        Ok(self.state(id)?.ok_or(VaultError::NotFound)?.vault)
    }

    fn store_vault(&self, keys: &Unlocked, id: &Id, vault: &VaultKeys, roster: Option<&[u8]>) -> Result<()> {
        self.touch();
        let sealed = crypto::seal(&keys.account_key, &crypto::aad(AAD_VAULT, &[id]), vault.key.as_ref());
        self.conn.execute(
            "INSERT INTO vaults (id, nonce, wrapped_key, kind, epoch, roster) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(id) DO UPDATE SET nonce = excluded.nonce, wrapped_key = excluded.wrapped_key, epoch = excluded.epoch, roster = excluded.roster",
            params![id.as_slice(), sealed.nonce.as_slice(), sealed.ciphertext, (vault.kind == Kind::Shared) as i64, vault.epoch as i64, roster.map(|blob| seal_small(&keys.account_key, AAD_ROSTER, id, blob))],
        )?;
        Ok(())
    }

    fn insert_vault(&mut self, id: Id, vault: VaultKeys) {
        self.unlocked.as_mut().expect("only called with an open vault").vaults.insert(id, vault);
    }

    /// Creates a shared vault; oneself is owner and at first the only member.
    /// `account` and `name` are those of the own account on the server.
    pub fn create_shared(&mut self, account: &Id, name: &str) -> Result<Id> {
        let keys = self.keys()?;
        let id: Id = crypto::random();
        let me = Member { account: crypto::hex(account), name: name.to_string(), ed25519: crypto::hex(&keys.public), x25519: crypto::hex(&PublicKey::from(&keys.exchange).to_bytes()), role: Role::Owner };
        let roster = Roster { vault: crypto::hex(&id), epoch: 1, version: 1, members: vec![me], handovers: Vec::new() };
        let blob = roster::sign(&roster, None, &keys.signing)?;
        let entry = VaultKeys { key: crypto::random_key(), kind: Kind::Shared, epoch: 1, roster: Some(roster) };
        self.store_vault(keys, &id, &entry, Some(&blob))?;
        self.insert_vault(id, entry);
        Ok(id)
    }

    /// Takes in a shared vault one was invited to: member list and the key wrapped
    /// for oneself, both from the server.
    pub fn join_shared(&mut self, id: &Id, sealed_key: &[u8], roster: &[u8]) -> Result<()> {
        let keys = self.keys()?;
        if keys.vaults.contains_key(id) {
            return Err(VaultError::AlreadyExists);
        }
        let parsed = roster::verify(roster, id, None)?;
        if parsed.role(&keys.public).is_none() {
            return Err(VaultError::NotMember);
        }
        let key = share::open(sealed_key, id, parsed.epoch, &keys.exchange).map_err(|_| VaultError::Corrupt("vault key"))?;
        let entry = VaultKeys { key, kind: Kind::Shared, epoch: parsed.epoch, roster: Some(parsed) };
        self.store_vault(keys, id, &entry, Some(roster))?;
        self.insert_vault(*id, entry);
        Ok(())
    }

    /// The signed member list as it goes to the server.
    pub fn roster_blob(&self, vault: &Id) -> Result<Vec<u8>> {
        let (keys, _) = self.vault_keys(vault)?;
        let stored = self.conn.query_row("SELECT roster FROM vaults WHERE id = ?1", [vault.as_slice()], |row| blob(row, 0))?;
        Ok(open_small(&keys.account_key, AAD_ROSTER, vault, &stored).ok_or(VaultError::Corrupt("member list"))?.to_vec())
    }

    /// As owner, signs a new member list without taking it over yet.
    pub fn sign_roster(&self, vault: &Id, roster: &Roster) -> Result<Vec<u8>> {
        let (keys, current) = self.vault_keys(vault)?;
        let previous = current.roster.as_ref().ok_or(VaultError::NotOwner)?;
        if previous.role(&keys.public) != Some(Role::Owner) {
            return Err(VaultError::NotOwner);
        }
        Ok(roster::sign(roster, Some(previous), &keys.signing)?)
    }

    /// As owner, creates the list with which ownership passes to a member (their signing key).
    /// Oneself keeps write permission. It is taken over like any other with [`Vault::set_roster`].
    pub fn transfer_roster(&self, vault: &Id, to: &[u8; 32]) -> Result<Vec<u8>> {
        let (keys, current) = self.vault_keys(vault)?;
        let previous = current.roster.as_ref().ok_or(VaultError::NotOwner)?;
        if previous.role(&keys.public) != Some(Role::Owner) {
            return Err(VaultError::NotOwner);
        }
        let mut roster = previous.clone();
        roster.version += 1;
        roster::hand_over(&mut roster, to, &keys.signing)?;
        Ok(roster::sign(&roster, Some(previous), &keys.signing)?)
    }

    /// Takes over a new member list at the same key generation: new members, more permissions, transfer
    /// of ownership. Whoever would lose permissions on the way would need a key rotation ([`Vault::apply_rotation`]).
    pub fn set_roster(&mut self, vault: &Id, blob: &[u8]) -> Result<()> {
        let (keys, current) = self.vault_keys(vault)?;
        let previous = current.roster.as_ref().ok_or(VaultError::NotFound)?;
        let roster = roster::verify(blob, vault, Some(previous))?;
        if roster.epoch != current.epoch || roster::reduces(previous, &roster) {
            return Err(RosterError::NeedsRotation.into());
        }
        if roster.role(&keys.public).is_none() {
            return Err(VaultError::NotMember);
        }
        self.touch();
        self.conn.execute("UPDATE vaults SET roster = ?2 WHERE id = ?1", params![vault.as_slice(), seal_small(&keys.account_key, AAD_ROSTER, vault, blob)])?;
        let entry = self.unlocked.as_mut().and_then(|u| u.vaults.get_mut(vault)).expect("found above");
        entry.roster = Some(roster);
        Ok(())
    }

    /// Wraps a vault's key for a member (their public X25519 key).
    pub fn seal_key_for(&self, vault: &Id, recipient: &[u8; 32]) -> Result<Vec<u8>> {
        let (_, current) = self.vault_keys(vault)?;
        share::seal(&current.key, vault, current.epoch, recipient).map_err(|_| VaultError::Corrupt("public key"))
    }

    /// Removes a shared vault with all its records from this device.
    pub fn remove_vault(&mut self, vault: &Id) -> Result<()> {
        let keys = self.keys()?;
        if *vault == keys.personal {
            return Err(VaultError::Personal);
        }
        self.touch();
        self.atomic(|| {
            self.conn.execute("DELETE FROM base WHERE id IN (SELECT id FROM records WHERE vault_id = ?1)", [vault.as_slice()])?;
            self.conn.execute("DELETE FROM records WHERE vault_id = ?1", [vault.as_slice()])?;
            self.conn.execute("DELETE FROM vaults WHERE id = ?1", [vault.as_slice()])?;
            Ok(())
        })?;
        self.unlocked.as_mut().expect("checked above").vaults.remove(vault);
        Ok(())
    }

    // ── Sync ─────────────────────────────────────────────────────────────────────────────────────────────

    /// Up to which server number everything has been fetched.
    pub fn cursor(&self, vault: &Id) -> Result<u64> {
        let cursor = self.conn.query_row("SELECT cursor FROM vaults WHERE id = ?1", [vault.as_slice()], |row| integer(row, 0)).optional()?;
        Ok(cursor.ok_or(VaultError::NotFound)?.max(0) as u64)
    }

    pub fn set_cursor(&mut self, vault: &Id, cursor: u64) -> Result<()> {
        self.conn.execute("UPDATE vaults SET cursor = ?2 WHERE id = ?1", params![vault.as_slice(), cursor as i64])?;
        Ok(())
    }

    fn rows(&self, vault: &Id, only_dirty: bool) -> Result<Vec<(Envelope, bool)>> {
        let mut statement = self.conn.prepare(&format!("SELECT {ROW}, dirty FROM records WHERE vault_id = ?1 AND (dirty = 1 OR ?2 = 0) ORDER BY id"))?;
        let rows = statement.query_map(params![vault.as_slice(), only_dirty], |row| Ok((Row::read(row)?, integer(row, 9)? != 0)))?;
        let mut out = Vec::new();
        for row in rows {
            let (row, dirty) = row?;
            out.extend(row.envelope().map(|e| (e, dirty)));
        }
        Ok(out)
    }

    /// The records of a vault whose change the server does not have yet, as they go out.
    pub fn pending(&self, vault: &Id) -> Result<Vec<Envelope>> {
        self.vault_keys(vault)?;
        Ok(self.rows(vault, true)?.into_iter().map(|(envelope, _)| envelope).collect())
    }

    /// Like [`Vault::pending`], plus per record the revision the change builds on: the state
    /// the server last confirmed or delivered (0 = it does not know it). The server only accepts what builds on
    /// its state.
    pub fn outgoing(&self, vault: &Id) -> Result<Vec<(Envelope, u64)>> {
        let mut out = Vec::new();
        for envelope in self.pending(vault)? {
            let base = self.state(&envelope.id)?.map_or(0, |state| state.synced);
            out.push((envelope, base));
        }
        Ok(out)
    }

    /// What this device believes the server's state to be: per record the server knows, ID, revision
    /// and deletion mark. Where an own change is waiting, the state before it counts.
    fn believed(&self, vault: &Id) -> Result<Vec<(Id, u64, bool)>> {
        self.vault_keys(vault)?;
        let mut statement = self.conn.prepare(
            "SELECT r.id, CASE WHEN r.dirty = 0 THEN r.revision ELSE b.revision END, CASE WHEN r.dirty = 0 THEN r.deleted ELSE b.deleted END
             FROM records r LEFT JOIN base b ON b.id = r.id
             WHERE r.vault_id = ?1 AND r.synced > 0 AND (r.dirty = 0 OR b.id IS NOT NULL) ORDER BY r.id",
        )?;
        let rows = statement.query_map([vault.as_slice()], |row| Ok((blob(row, 0)?, integer(row, 1)?, integer(row, 2)? != 0)))?;
        let mut out = Vec::new();
        for row in rows {
            let (id, revision, deleted) = row?;
            out.extend(Id::try_from(id.as_slice()).ok().map(|id| (id, revision.max(0) as u64, deleted)));
        }
        Ok(out)
    }

    /// The checksum over what this device believes the server's state to be (see [`state_digest`]).
    pub fn believed_digest(&self, vault: &Id) -> Result<[u8; 32]> {
        Ok(state_digest(self.believed(vault)?.into_iter().filter(|(_, _, deleted)| !deleted).map(|(id, revision, _)| (id, revision))))
    }

    /// How many records this device knows as synced that are missing from the server's full state
    /// (`rows`) or older there. More than zero means: the server has lost something.
    pub fn ahead_of(&self, vault: &Id, rows: &[Envelope]) -> Result<usize> {
        let server: BTreeMap<Id, u64> = rows.iter().map(|row| (row.id, row.revision)).collect();
        Ok(self
            .believed(vault)?
            .into_iter()
            .filter(|(id, revision, deleted)| match server.get(id) {
                Some(theirs) => revision > theirs,
                // A tombstone the server no longer keeps has merely expired there.
                None => !deleted,
            })
            .count())
    }

    /// Opens what belongs to an invitation without taking in the vault: checks the member list, unwraps
    /// the key wrapped for oneself and decrypts the delivered records. That way
    /// the vault's name can be shown before anyone accepts.
    pub fn peek_invitation(&self, vault: &Id, sealed_key: &[u8], roster: &[u8], rows: &[Envelope]) -> Result<(Roster, Vec<Zeroizing<Vec<u8>>>)> {
        let keys = self.keys()?;
        let parsed = roster::verify(roster, vault, None)?;
        if parsed.role(&keys.public).is_none() {
            return Err(VaultError::NotMember);
        }
        let key = share::open(sealed_key, vault, parsed.epoch, &keys.exchange).map_err(|_| VaultError::Corrupt("vault key"))?;
        let entry = VaultKeys { key, kind: Kind::Shared, epoch: parsed.epoch, roster: Some(parsed.clone()) };
        let plain = rows.iter().filter(|row| !row.deleted).filter_map(|row| unseal(vault, &entry, &keys.public, row)).collect();
        Ok((parsed, plain))
    }

    /// The server has an older state than this device, e.g. after restoring from a backup
    /// (`rows`: everything it has for this vault). Whatever is newer here builds on its state and goes
    /// out again one revision higher, so every other device also accepts it as new; whatever it does not
    /// know at all counts as new; whatever is newer there is taken over as usual. Whoever may only read only takes over.
    pub fn rebase_onto(&mut self, vault: &Id, rows: &[Envelope]) -> Result<Applied> {
        let (keys, vault_keys) = self.vault_keys(vault)?;
        let may_write = vault_keys.role(&keys.public).is_some_and(Role::may_write);
        let mut applied = Applied::default();
        let server: BTreeMap<Id, &Envelope> = rows.iter().filter(|row| unseal(vault, vault_keys, &keys.public, row).is_some()).map(|row| (row.id, row)).collect();
        applied.rejected = rows.iter().filter(|row| !server.contains_key(&row.id)).map(|row| row.id).collect();
        self.atomic(|| {
            for (local, dirty) in self.rows(vault, false)? {
                match server.get(&local.id) {
                    None if may_write => {
                        self.drop_base(&local.id)?;
                        self.conn.execute("UPDATE records SET dirty = 1, synced = 0 WHERE id = ?1", [local.id.as_slice()])?;
                    }
                    Some(remote) if may_write && (remote.revision < local.revision || (remote.revision == local.revision && remote.nonce != local.nonce && !dirty)) => {
                        let Some(mine) = unseal(vault, vault_keys, &keys.public, &local) else { continue };
                        self.store_base(remote)?;
                        self.store(vault, &seal(keys, vault, &vault_keys.key, local.id, local.revision + 1, local.deleted, &mine), true, remote.revision)?;
                    }
                    _ => {}
                }
            }
            for remote in server.values() {
                if self.state(&remote.id)?.is_none_or(|state| remote.revision > state.revision || state.dirty) {
                    self.integrate(keys, vault, vault_keys, vault_keys, remote, false, &mut applied)?;
                }
            }
            Ok(())
        })?;
        self.touch();
        Ok(applied)
    }

    /// The server accepted `sent`. Whatever was not changed further since counts as synced; whatever
    /// was, keeps waiting, now with the accepted state as its base.
    pub fn acknowledge(&mut self, vault: &Id, sent: &[Envelope]) -> Result<()> {
        let (keys, vault_keys) = self.vault_keys(vault)?;
        self.atomic(|| {
            for sent in sent {
                let Some(current) = self.envelope(&sent.id)? else { continue };
                if current.nonce == sent.nonce && current.revision == sent.revision {
                    self.drop_base(&sent.id)?;
                    self.conn.execute("UPDATE records SET dirty = 0, synced = ?2 WHERE id = ?1", params![sent.id.as_slice(), sent.revision as i64])?;
                } else if let Some(mine) = unseal(vault, vault_keys, &keys.public, &current) {
                    self.store_base(sent)?;
                    self.store(vault, &seal(keys, vault, &vault_keys.key, sent.id, sent.revision + 1, current.deleted, &mine), true, sent.revision)?;
                }
            }
            Ok(())
        })
    }

    /// Discards a vault's waiting changes, e.g. when one may no longer write there: the
    /// last synced state applies again; never synced entries disappear. Returns the number.
    pub fn discard_pending(&mut self, vault: &Id) -> Result<usize> {
        let pending = self.pending(vault)?;
        self.touch();
        self.atomic(|| {
            for envelope in &pending {
                match self.base(&envelope.id)? {
                    Some(base) => {
                        self.store(vault, &base, false, base.revision)?;
                        self.drop_base(&envelope.id)?;
                    }
                    None => drop(self.conn.execute("DELETE FROM records WHERE id = ?1", [envelope.id.as_slice()])?),
                }
            }
            Ok(())
        })?;
        Ok(pending.len())
    }

    /// Instead of the changes, the server delivered a vault's whole state (`keep`: the IDs
    /// in it), because this device was away longer than it keeps tombstones. Whatever counted as synced here and
    /// is missing there has been deleted meanwhile; waiting changes to it count as new. Returns the number removed.
    pub fn retain_synced(&mut self, vault: &Id, keep: &BTreeSet<Id>) -> Result<usize> {
        self.vault_keys(vault)?;
        let rows = self.rows(vault, false)?;
        self.touch();
        self.atomic(|| {
            let mut removed = 0;
            for (envelope, dirty) in rows.iter().filter(|(envelope, _)| !keep.contains(&envelope.id)) {
                if *dirty {
                    self.drop_base(&envelope.id)?;
                    self.conn.execute("UPDATE records SET synced = 0 WHERE id = ?1", [envelope.id.as_slice()])?;
                } else {
                    self.conn.execute("DELETE FROM records WHERE id = ?1", [envelope.id.as_slice()])?;
                    removed += 1;
                }
            }
            Ok(removed)
        })
    }

    /// Takes over a record from the server. `old` are the keys under which this device's versions
    /// are stored, `new` those under which the delivered one is stored and everything will be stored; except for a key rotation
    /// (`rotation`) both are the same.
    #[allow(clippy::too_many_arguments)]
    fn integrate(&self, keys: &Unlocked, vault: &Id, old: &VaultKeys, new: &VaultKeys, remote: &Envelope, rotation: bool, applied: &mut Applied) -> Result<()> {
        let id = remote.id;
        let Some(theirs) = unseal(vault, new, &keys.public, remote) else {
            applied.rejected.push(id);
            return Ok(());
        };
        let take = |applied: &mut Applied| -> Result<()> {
            self.drop_base(&id)?;
            self.store(vault, remote, false, remote.revision)?;
            applied.taken.push(id);
            Ok(())
        };
        let Some(state) = self.state(&id)? else { return take(applied) };
        if state.vault != *vault {
            applied.rejected.push(id);
            return Ok(());
        }
        let Some(current) = self.envelope(&id)? else { return take(applied) };

        if !state.dirty {
            // Nothing is waiting here: whatever is newer applies. During a key rotation the same revision comes newly encrypted.
            if remote.revision > state.revision || (rotation && remote.revision == state.revision) {
                return take(applied);
            }
            // The same revision again is fine, an older one or a different equal one is not.
            if remote.revision < state.revision || current.nonce != remote.nonce {
                applied.rejected.push(id);
            }
            return Ok(());
        }

        // An own change is waiting.
        let base = self.base(&id)?;
        if base.as_ref().is_some_and(|b| remote.revision < b.revision) {
            applied.rejected.push(id);
            return Ok(());
        }
        let Some(mine) = unseal(vault, old, &keys.public, &current) else { return take(applied) };
        let reseal = |revision: u64, deleted: bool, plaintext: &[u8]| -> Result<()> {
            self.store_base(remote)?;
            self.store(vault, &seal(keys, vault, &new.key, id, revision, deleted, plaintext), true, remote.revision)
        };
        if base.as_ref().is_some_and(|b| remote.revision == b.revision) {
            // The server has nothing new. During a key rotation, base and own version move to the new key.
            if rotation {
                reseal(remote.revision + 1, current.deleted, &mine)?;
            }
            return Ok(());
        }

        let base_plain = base.as_ref().filter(|b| !b.deleted).and_then(|b| unseal(vault, old, &keys.public, b));
        let merge = crate::merge::merge(
            base_plain.as_ref().map(|b| b.as_slice()),
            (!current.deleted).then_some(mine.as_slice()),
            (!remote.deleted).then_some(theirs.as_slice()),
            current.modified_at > remote.modified_at,
        );
        match &merge.outcome {
            Outcome::Theirs => {
                self.drop_base(&id)?;
                self.store(vault, remote, false, remote.revision)?;
            }
            Outcome::Merged(bytes) => reseal(remote.revision + 1, false, bytes)?,
            Outcome::Deleted => reseal(remote.revision + 1, true, &[])?,
        }
        applied.merged.push((id, merge));
        Ok(())
    }

    /// Takes records from the server into a vault. Each one is checked (signature, author's write permission,
    /// key); where an own change is waiting, they are merged (`docs/sync.md`).
    pub fn apply_remote(&mut self, vault: &Id, rows: &[Envelope]) -> Result<Applied> {
        let (keys, vault_keys) = self.vault_keys(vault)?;
        let mut applied = Applied::default();
        self.atomic(|| {
            for remote in rows {
                self.integrate(keys, vault, vault_keys, vault_keys, remote, false, &mut applied)?;
            }
            Ok(())
        })?;
        Ok(applied)
    }

    /// As owner, prepares the key rotation: new key, all records encrypted with it and
    /// self-signed (revisions unchanged), the new member list, the key for every member.
    pub fn prepare_rotation(&self, vault: &Id, roster: &Roster) -> Result<Rotation> {
        let (keys, current) = self.vault_keys(vault)?;
        let previous = current.roster.as_ref().ok_or(VaultError::NotOwner)?;
        if previous.role(&keys.public) != Some(Role::Owner) {
            return Err(VaultError::NotOwner);
        }
        if roster.epoch != current.epoch + 1 {
            return Err(RosterError::Stale.into());
        }
        // The re-encrypted records carry the own signature; they only count if one may still write.
        if !roster.may_write(&keys.public) {
            return Err(VaultError::ReadOnly);
        }
        if !self.pending(vault)?.is_empty() {
            return Err(VaultError::Pending);
        }
        let blob = roster::sign(roster, Some(previous), &keys.signing)?;
        let key = crypto::random_key();
        let mut sealed_keys = Vec::with_capacity(roster.members.len());
        for member in &roster.members {
            let (signing, exchange) = member.signing_key().zip(member.exchange_key()).ok_or(RosterError::Malformed)?;
            sealed_keys.push((signing, share::seal(&key, vault, roster.epoch, &exchange).map_err(|_| RosterError::Malformed)?));
        }
        let mut records = Vec::new();
        for (envelope, _) in self.rows(vault, false)? {
            // Whatever could not be opened before cannot be rescued over.
            let Some(plain) = unseal(vault, current, &keys.public, &envelope) else { continue };
            let mut fresh = seal(keys, vault, &key, envelope.id, envelope.revision, envelope.deleted, &plain);
            fresh.modified_at = envelope.modified_at;
            records.push(fresh);
        }
        Ok(Rotation { vault: *vault, epoch: roster.epoch, roster: blob, keys: sealed_keys, records, key, parsed: roster.clone() })
    }

    /// The server accepted the prepared key rotation: switch over here too now.
    pub fn commit_rotation(&mut self, rotation: Rotation) -> Result<Applied> {
        let entry = VaultKeys { key: rotation.key, kind: Kind::Shared, epoch: rotation.epoch, roster: Some(rotation.parsed) };
        self.switch_keys(&rotation.vault, entry, &rotation.roster, &rotation.records)
    }

    /// Takes over an owner's key rotation: the new member list, the key wrapped for oneself
    /// and all records of the vault. If one is no longer a member, it fails with `NotMember`;
    /// then only [`Vault::remove_vault`] remains.
    pub fn apply_rotation(&mut self, vault: &Id, sealed_key: &[u8], roster: &[u8], rows: &[Envelope]) -> Result<Applied> {
        let (keys, current) = self.vault_keys(vault)?;
        let parsed = roster::verify(roster, vault, Some(current.roster.as_ref().ok_or(VaultError::NotFound)?))?;
        if parsed.epoch <= current.epoch {
            return Err(RosterError::Stale.into());
        }
        if parsed.role(&keys.public).is_none() {
            return Err(VaultError::NotMember);
        }
        let key = share::open(sealed_key, vault, parsed.epoch, &keys.exchange).map_err(|_| VaultError::Corrupt("vault key"))?;
        let entry = VaultKeys { key, kind: Kind::Shared, epoch: parsed.epoch, roster: Some(parsed) };
        self.switch_keys(vault, entry, roster, rows)
    }

    fn switch_keys(&mut self, vault: &Id, entry: VaultKeys, roster: &[u8], rows: &[Envelope]) -> Result<Applied> {
        let (keys, old) = self.vault_keys(vault)?;
        let mut applied = Applied::default();
        self.atomic(|| {
            for remote in rows {
                self.integrate(keys, vault, old, &entry, remote, true, &mut applied)?;
            }
            // Whatever still lies under the old key now did not come along (validly): own waiting changes
            // move over and count as new, everything else no longer exists on the server.
            for (envelope, dirty) in self.rows(vault, false)? {
                if unseal(vault, &entry, &keys.public, &envelope).is_some() {
                    continue;
                }
                self.drop_base(&envelope.id)?;
                match unseal(vault, old, &keys.public, &envelope).filter(|_| dirty) {
                    Some(mine) => self.store(vault, &seal(keys, vault, &entry.key, envelope.id, envelope.revision, envelope.deleted, &mine), true, 0)?,
                    None => drop(self.conn.execute("DELETE FROM records WHERE id = ?1", [envelope.id.as_slice()])?),
                }
            }
            self.store_vault(keys, vault, &entry, Some(roster))
        })?;
        self.insert_vault(*vault, entry);
        Ok(applied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    const FAST: KdfParams = KdfParams { memory_kib: 64, passes: 1, lanes: 1 };

    /// A file of its own per test; cleaned up when leaving.
    struct Temp(PathBuf);
    impl Temp {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!("glowport-vault-{}-{name}.db", std::process::id()));
            let _ = std::fs::remove_file(&path);
            Self(path)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn texts(vault: &Vault) -> Vec<String> {
        let mut out: Vec<String> = vault.list().unwrap().records.iter().map(|r| String::from_utf8(r.data.to_vec()).unwrap()).collect();
        out.sort();
        out
    }

    /// Alters the file from outside, as an attacker with write access could.
    fn tamper(path: &Path, sql: &str) {
        let conn = Connection::open(path).unwrap();
        assert!(conn.execute(sql, []).unwrap() > 0, "the tampering hit nothing: {sql}");
    }

    #[test]
    fn create_lock_unlock_round_trips() {
        let temp = Temp::new("roundtrip");
        let mut vault = Vault::create(&temp.0, "right", FAST).unwrap();
        vault.put(None, b"one").unwrap();
        vault.put(None, b"two").unwrap();
        vault.lock();
        assert!(matches!(vault.list(), Err(VaultError::Locked)));
        drop(vault);

        let mut vault = Vault::open(&temp.0).unwrap();
        assert!(!vault.is_unlocked());
        vault.unlock("right").unwrap();
        assert_eq!(texts(&vault), ["one", "two"]);
    }

    #[test]
    fn wrong_password_is_rejected_and_changes_nothing() {
        let temp = Temp::new("wrongpw");
        let mut vault = Vault::create(&temp.0, "right", FAST).unwrap();
        vault.put(None, b"one").unwrap();
        drop(vault);
        let before = std::fs::read(&temp.0).unwrap();

        let mut vault = Vault::open(&temp.0).unwrap();
        assert!(matches!(vault.unlock("wrong"), Err(VaultError::WrongPassword)));
        assert!(matches!(vault.unlock(""), Err(VaultError::WrongPassword)));
        assert!(!vault.is_unlocked());
        drop(vault);
        assert_eq!(std::fs::read(&temp.0).unwrap(), before);
    }

    #[test]
    fn locked_vault_refuses_everything() {
        let temp = Temp::new("locked");
        let mut vault = Vault::create(&temp.0, "right", FAST).unwrap();
        let id = vault.put(None, b"one").unwrap();
        vault.lock();
        assert!(matches!(vault.put(None, b"x"), Err(VaultError::Locked)));
        assert!(matches!(vault.put(Some(id), b"x"), Err(VaultError::Locked)));
        assert!(matches!(vault.delete(&id), Err(VaultError::Locked)));
        assert!(matches!(vault.list(), Err(VaultError::Locked)));
    }

    #[test]
    fn update_raises_revision_and_delete_leaves_tombstone() {
        let temp = Temp::new("revisions");
        let mut vault = Vault::create(&temp.0, "right", FAST).unwrap();
        let id = vault.put(None, b"old").unwrap();
        assert_eq!(vault.put(Some(id), b"new").unwrap(), id);
        let listing = vault.list().unwrap();
        assert_eq!((listing.records.len(), listing.records[0].revision, listing.records[0].data.as_slice()), (1, 2, b"new".as_slice()));

        vault.delete(&id).unwrap();
        assert!(vault.list().unwrap().records.is_empty());
        assert!(matches!(vault.put(Some(id), b"again"), Err(VaultError::NotFound)));
        assert!(matches!(vault.delete(&id), Err(VaultError::NotFound)));
        assert!(matches!(vault.put(Some([9; 16]), b"fremd"), Err(VaultError::NotFound)));

        let (revision, deleted): (i64, bool) =
            vault.conn.query_row("SELECT revision, deleted FROM records", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!((revision, deleted), (3, true), "tombstone with a higher revision");
        assert_eq!(vault.purge_tombstones(60_000).unwrap(), 0, "a fresh tombstone stays");
        assert_eq!(vault.purge_tombstones(-1).unwrap(), 1);
    }

    #[test]
    fn every_tampering_is_detected() {
        let cases = [
            ("ciphertext", "UPDATE records SET ciphertext = substr(ciphertext, 1, 2) || x'00' || substr(ciphertext, 4)"),
            ("Nonce", "UPDATE records SET nonce = x'000000000000000000000000000000000000000000000000'"),
            ("signature", "UPDATE records SET signature = substr(signature, 1, 10) || x'00' || substr(signature, 12)"),
            ("Revision", "UPDATE records SET revision = revision + 1"),
            ("deletion mark set", "UPDATE records SET deleted = 1"),
            ("Autor", "UPDATE records SET author = x'0000000000000000000000000000000000000000000000000000000000000000'"),
            ("vault ID", "UPDATE records SET vault_id = (SELECT id FROM records LIMIT 1)"),
            ("ID", "UPDATE records SET id = x'01010101010101010101010101010101'"),
        ];
        for (what, sql) in cases {
            let temp = Temp::new(&format!("tamper-{}", what.replace(' ', "-")));
            let mut vault = Vault::create(&temp.0, "right", FAST).unwrap();
            vault.put(None, b"exactly one record with some content").unwrap();
            // The vault ID points to `vaults` via a foreign key; this case needs a second entry there.
            if what == "vault ID" {
                tamper(&temp.0, "INSERT INTO vaults (id, nonce, wrapped_key) SELECT id, nonce, ciphertext FROM records");
            }
            tamper(&temp.0, sql);
            let listing = vault.list().unwrap();
            assert!(listing.records.is_empty(), "{what}: modified record was accepted");
            assert_eq!(listing.damaged.len(), 1, "{what}: modification not reported");
        }
    }

    #[test]
    fn swapped_and_resurrected_records_are_detected() {
        let temp = Temp::new("swap");
        let mut vault = Vault::create(&temp.0, "right", FAST).unwrap();
        let a = vault.put(None, b"Host A").unwrap();
        let b = vault.put(None, b"Host B").unwrap();
        let conn = Connection::open(&temp.0).unwrap();

        // Put A's content in the place of B (nonce and signature included).
        conn.execute(
            "UPDATE records SET (nonce, ciphertext, signature) = (SELECT nonce, ciphertext, signature FROM records WHERE id = ?1) WHERE id = ?2",
            params![a.as_slice(), b.as_slice()],
        )
        .unwrap();
        let listing = vault.list().unwrap();
        assert_eq!(listing.records.len(), 1);
        assert_eq!(listing.damaged, [b.to_vec()]);

        // Make a tombstone “alive” again.
        vault.delete(&a).unwrap();
        conn.execute("UPDATE records SET deleted = 0 WHERE id = ?1", [a.as_slice()]).unwrap();
        let listing = vault.list().unwrap();
        assert!(listing.records.is_empty());
        assert_eq!(listing.damaged.len(), 2);
    }

    #[test]
    fn header_tampering_prevents_unlock() {
        for sql in [
            "UPDATE meta SET value = x'00000000000000000000000000000000' WHERE key = 'salt'",
            "UPDATE meta SET value = x'400000000100000002000000' WHERE key = 'kdf'",
            "UPDATE meta SET value = substr(value, 1, 5) || x'00' || substr(value, 7) WHERE key = 'account_wrapped'",
        ] {
            let temp = Temp::new("header");
            drop(Vault::create(&temp.0, "right", FAST).unwrap());
            tamper(&temp.0, sql);
            assert!(matches!(Vault::open(&temp.0).unwrap().unlock("right"), Err(VaultError::WrongPassword)), "{sql}");
        }
        // A swapped public key shows up when unwrapping the private one.
        let temp = Temp::new("header-key");
        drop(Vault::create(&temp.0, "right", FAST).unwrap());
        tamper(&temp.0, "UPDATE meta SET value = x'0000000000000000000000000000000000000000000000000000000000000000' WHERE key = 'ed25519_public'");
        assert!(matches!(Vault::open(&temp.0).unwrap().unlock("right"), Err(VaultError::Corrupt("ed25519"))));
    }

    #[test]
    fn change_password_keeps_records() {
        let temp = Temp::new("changepw");
        let mut vault = Vault::create(&temp.0, "old", FAST).unwrap();
        vault.put(None, b"stays").unwrap();
        assert!(matches!(vault.change_password("wrong", "new", FAST), Err(VaultError::WrongPassword)));
        vault.change_password("old", "new", FAST).unwrap();
        assert_eq!(texts(&vault), ["stays"], "an open vault stays usable");
        drop(vault);

        let mut vault = Vault::open(&temp.0).unwrap();
        assert!(matches!(vault.unlock("old"), Err(VaultError::WrongPassword)));
        vault.unlock("new").unwrap();
        assert_eq!(texts(&vault), ["stays"]);
    }

    #[test]
    fn failed_batch_leaves_nothing_behind() {
        let temp = Temp::new("batch");
        let mut vault = Vault::create(&temp.0, "right", FAST).unwrap();
        vault.put(None, b"before").unwrap();
        let result = vault.batch(|v| {
            v.put(None, b"half")?;
            v.put(Some([9; 16]), b"does not exist")
        });
        assert!(matches!(result, Err(VaultError::NotFound)));
        assert_eq!(texts(&vault), ["before"]);

        vault.batch(|v| v.put(None, b"whole").map(drop)).unwrap();
        assert_eq!(texts(&vault), ["before", "whole"]);
    }

    #[test]
    fn backup_is_a_working_copy() {
        let temp = Temp::new("backup-src");
        let copy = Temp::new("backup-dst");
        let mut vault = Vault::create(&temp.0, "right", FAST).unwrap();
        vault.put(None, b"gesichert").unwrap();
        vault.backup(&copy.0).unwrap();
        vault.put(None, b"after").unwrap();
        vault.backup(&copy.0).unwrap();

        let mut restored = Vault::open(&copy.0).unwrap();
        assert!(matches!(restored.unlock("wrong"), Err(VaultError::WrongPassword)));
        restored.unlock("right").unwrap();
        assert_eq!(texts(&restored), ["after", "gesichert"]);
    }

    #[test]
    fn create_and_open_reject_bad_files() {
        let temp = Temp::new("badfiles");
        drop(Vault::create(&temp.0, "right", FAST).unwrap());
        assert!(matches!(Vault::create(&temp.0, "right", FAST), Err(VaultError::AlreadyExists)));

        tamper(&temp.0, "UPDATE meta SET value = x'03000000' WHERE key = 'format_version'");
        assert!(matches!(Vault::open(&temp.0), Err(VaultError::UnsupportedFormat(3))));

        std::fs::write(&temp.0, b"this is not a database, just text in a file").unwrap();
        assert!(matches!(Vault::open(&temp.0), Err(VaultError::Corrupt(_))));
    }

    #[test]
    fn stored_file_reveals_no_plaintext() {
        let temp = Temp::new("leak");
        let mut vault = Vault::create(&temp.0, "right", FAST).unwrap();
        vault.put(None, br#"{"t":"host","name":"geheimer-server","password":"hunter2-sehr-geheim"}"#).unwrap();
        drop(vault);
        let bytes = std::fs::read(&temp.0).unwrap();
        for needle in [b"geheimer-server".as_slice(), b"hunter2", b"\"host\"", b"right"] {
            assert!(!bytes.windows(needle.len()).any(|w| w == needle), "plaintext found in the file");
        }
    }

    #[test]
    fn device_key_unlocks_without_password_and_survives_a_password_change() {
        let temp = Temp::new("devicekey");
        let mut vault = Vault::create(&temp.0, "old", FAST).unwrap();
        vault.put(None, b"da").unwrap();
        let key = vault.device_key().unwrap();
        vault.change_password("old", "new", FAST).unwrap();
        vault.lock();
        assert!(matches!(vault.device_key(), Err(VaultError::Locked)));
        drop(vault);

        let mut vault = Vault::open(&temp.0).unwrap();
        assert!(matches!(vault.unlock_with_key(&crypto::random_key()), Err(VaultError::StaleDeviceKey)));
        assert!(!vault.is_unlocked());
        vault.unlock_with_key(&key).unwrap();
        assert_eq!(texts(&vault), ["da"]);
        assert_eq!(vault.device_id().unwrap().len(), 16);

        // Another vault does not accept the key.
        let other = Temp::new("devicekey-other");
        let mut other_vault = Vault::create(&other.0, "x", FAST).unwrap();
        other_vault.lock();
        assert!(matches!(other_vault.unlock_with_key(&key), Err(VaultError::StaleDeviceKey)));
    }

    /// Measures unlocking with the default values. Run: `cargo test -p glowport-core --release -- --ignored --nocapture`.
    #[test]
    #[ignore = "measurement, not a test"]
    fn measure_default_unlock() {
        let temp = Temp::new("measure");
        drop(Vault::create(&temp.0, "right", KdfParams::DEFAULT).unwrap());
        let mut vault = Vault::open(&temp.0).unwrap();
        let start = Instant::now();
        vault.unlock("right").unwrap();
        println!("Unlocking with {:?}: {} ms", KdfParams::DEFAULT, start.elapsed().as_millis());
    }

    // ── Format 2: several vaults, syncing, sharing ───────────────────────────────────────────────────────

    use serde_json::{json, Value};

    /// A file really written by version 0.8.0 (format version 1): group “Kunden”, host “web-01”
    /// in revision 2 and a deleted snippet. Master password “fixture-passwort”.
    #[test]
    fn a_file_of_format_1_is_migrated_and_keeps_everything() {
        let temp = Temp::new("format1");
        std::fs::copy(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/format1.db"), &temp.0).unwrap();
        let copy = Temp(Vault::migration_copy(&temp.0));

        let mut vault = Vault::open(&temp.0).unwrap();
        assert!(matches!(vault.unlock("wrong"), Err(VaultError::WrongPassword)));
        vault.unlock("fixture-passwort").unwrap();
        let listing = vault.list().unwrap();
        assert!(listing.damaged.is_empty());
        let mut names: Vec<(String, u64)> =
            listing.records.iter().map(|r| (serde_json::from_slice::<Value>(&r.data).unwrap()["name"].as_str().unwrap().to_string(), r.revision)).collect();
        names.sort();
        assert_eq!(names, [("Kunden".to_string(), 1), ("web-01".to_string(), 2)]);
        assert!(listing.records.iter().all(|r| r.vault == vault.personal().unwrap()));
        let tombstones: i64 = vault.conn.query_row("SELECT count(*) FROM records WHERE deleted = 1", [], |r| r.get(0)).unwrap();
        assert_eq!(tombstones, 1, "the tombstone is still there");
        assert_eq!(vault.pending(&vault.personal().unwrap()).unwrap().len(), 3, "everything waits for a first sync");

        // Keep working and reopen: the file is now version 2 and is not converted again.
        vault.put(None, b"new").unwrap();
        drop(vault);
        std::fs::remove_file(&copy.0).unwrap();
        let mut vault = Vault::open(&temp.0).unwrap();
        assert!(!copy.0.exists());
        vault.unlock("fixture-passwort").unwrap();
        assert_eq!(vault.list().unwrap().records.len(), 3);
    }

    #[test]
    fn the_copy_before_migration_is_the_untouched_file() {
        let temp = Temp::new("format1-copy");
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/format1.db");
        std::fs::copy(&fixture, &temp.0).unwrap();
        let copy = Temp(Vault::migration_copy(&temp.0));
        drop(Vault::open(&temp.0).unwrap());
        let version = |path: &Path| -> Vec<u8> { Connection::open(path).unwrap().query_row("SELECT value FROM meta WHERE key = 'format_version'", [], |r| r.get(0)).unwrap() };
        assert_eq!((version(&copy.0), version(&temp.0)), (vec![1, 0, 0, 0], vec![2, 0, 0, 0]));
    }

    fn account(seed: u8) -> Id {
        [seed; 16]
    }

    fn member(vault: &Vault, seed: u8, role: Role) -> Member {
        let (ed25519, x25519) = vault.public_keys().unwrap();
        Member { account: crypto::hex(&account(seed)), name: format!("account{seed}"), ed25519: crypto::hex(&ed25519), x25519: crypto::hex(&x25519), role }
    }

    /// Plays the server: whatever waits at `from` arrives at `to` and counts as accepted at `from`.
    fn deliver(from: &mut Vault, to: &mut Vault, vault: &Id) -> Applied {
        let sent = from.pending(vault).unwrap();
        let applied = to.apply_remote(vault, &sent).unwrap();
        from.acknowledge(vault, &sent).unwrap();
        applied
    }

    fn values(vault: &Vault, of: &Id) -> Vec<Value> {
        let mut out: Vec<Value> = vault.list().unwrap().records.iter().filter(|r| r.vault == *of).map(|r| serde_json::from_slice(&r.data).unwrap()).collect();
        out.sort_by_key(|v| v.to_string());
        out
    }

    fn put_json(vault: &mut Vault, id: Option<Id>, value: Value) -> Id {
        vault.put(id, &serde_json::to_vec(&value).unwrap()).unwrap()
    }

    /// Two devices of the same account: the second one is created from what the server keeps.
    fn two_devices(name: &str) -> (Temp, Temp, Vault, Vault, Id) {
        let (ta, tb) = (Temp::new(&format!("{name}-a")), Temp::new(&format!("{name}-b")));
        let a = Vault::create(&ta.0, "right", FAST).unwrap();
        let b = Vault::create_from_account(&tb.0, "right", &a.account().unwrap()).unwrap();
        let personal = a.personal().unwrap();
        (ta, tb, a, b, personal)
    }

    #[test]
    fn a_second_device_opens_with_the_master_password_only() {
        let (_ta, tb, mut a, mut b, personal) = two_devices("zweites");
        assert_eq!(b.personal().unwrap(), personal);
        assert_eq!(a.public_keys().unwrap(), b.public_keys().unwrap());
        assert_ne!(a.device_id().unwrap(), b.device_id().unwrap(), "every file is a device of its own");
        put_json(&mut a, None, json!({"name": "web"}));
        assert_eq!(deliver(&mut a, &mut b, &personal).taken.len(), 1);
        assert_eq!(values(&b, &personal), [json!({"name": "web"})]);
        assert!(b.pending(&personal).unwrap().is_empty(), "fetched records do not wait");

        let other = Temp::new("second-wrong");
        assert!(matches!(Vault::create_from_account(&other.0, "wrong", &a.account().unwrap()), Err(VaultError::WrongPassword)));
        assert!(!other.0.exists(), "no remains of a failed sign-in");
        assert!(matches!(Vault::create_from_account(&tb.0, "right", &a.account().unwrap()), Err(VaultError::AlreadyExists)));

        // The sign-in key follows from the password and opens nothing.
        let auth = a.auth_key("right").unwrap();
        let blob = a.account().unwrap();
        assert_eq!(auth.as_ref(), auth_key("right", &blob.salt, blob.kdf).unwrap().as_ref());
        assert!(matches!(a.auth_key("wrong"), Err(VaultError::WrongPassword)));
        assert!(matches!(a.unlock_with_key(&auth), Err(VaultError::StaleDeviceKey)));
    }

    #[test]
    fn a_waiting_change_raises_the_revision_only_once() {
        let (_ta, _tb, mut a, mut b, personal) = two_devices("revision");
        let id = put_json(&mut a, None, json!({"name": "one"}));
        put_json(&mut a, Some(id), json!({"name": "two"}));
        assert_eq!(a.pending(&personal).unwrap()[0].revision, 2, "what the server does not know counts up freely");
        deliver(&mut a, &mut b, &personal);
        assert!(a.pending(&personal).unwrap().is_empty());

        put_json(&mut a, Some(id), json!({"name": "three"}));
        put_json(&mut a, Some(id), json!({"name": "four"}));
        let pending = a.pending(&personal).unwrap();
        assert_eq!((pending.len(), pending[0].revision), (1, 3), "exactly one above the server");
        assert_eq!(a.base(&id).unwrap().unwrap().revision, 2, "the synced state is kept");

        // While the package is on its way, changes continue: the confirmation only applies to what was sent.
        let sent = a.pending(&personal).unwrap();
        put_json(&mut a, Some(id), json!({"name": "five"}));
        b.apply_remote(&personal, &sent).unwrap();
        a.acknowledge(&personal, &sent).unwrap();
        let pending = a.pending(&personal).unwrap();
        assert_eq!((pending.len(), pending[0].revision), (1, 4));
        assert_eq!(values(&b, &personal), [json!({"name": "four"})]);
        deliver(&mut a, &mut b, &personal);
        assert_eq!(values(&b, &personal), [json!({"name": "five"})]);
        assert!(a.base(&id).unwrap().is_none() && a.pending(&personal).unwrap().is_empty());

        // Deleting takes the same path.
        a.delete(&id).unwrap();
        deliver(&mut a, &mut b, &personal);
        assert!(values(&b, &personal).is_empty());
    }

    #[test]
    fn concurrent_changes_are_merged_field_by_field() {
        let (_ta, _tb, mut a, mut b, personal) = two_devices("merge");
        let id = put_json(&mut a, None, json!({"name": "web", "own": {"port": 22}}));
        deliver(&mut a, &mut b, &personal);

        // A changes the port and reaches the server first; B meanwhile changes the name.
        put_json(&mut a, Some(id), json!({"name": "web", "own": {"port": 2222}}));
        put_json(&mut b, Some(id), json!({"name": "web-01", "own": {"port": 22}}));
        let from_a = a.pending(&personal).unwrap();
        a.acknowledge(&personal, &from_a).unwrap();
        let applied = b.apply_remote(&personal, &from_a).unwrap();
        assert_eq!((applied.merged.len(), applied.taken.len(), applied.rejected.len()), (1, 0, 0));
        assert!(applied.merged[0].1.clashes.is_empty());
        let merged = json!({"name": "web-01", "own": {"port": 2222}});
        assert_eq!(values(&b, &personal), std::slice::from_ref(&merged));
        assert_eq!(b.pending(&personal).unwrap()[0].revision, 3, "the result is one above the server");

        assert_eq!(deliver(&mut b, &mut a, &personal).taken, [id]);
        assert_eq!(values(&a, &personal), [merged]);

        // The old package once more: rejected, and it changes nothing.
        let applied = b.apply_remote(&personal, &from_a).unwrap();
        assert_eq!((applied.taken.len(), applied.merged.len(), applied.rejected.len()), (0, 0, 1), "older than our own state");
    }

    #[test]
    fn a_change_wins_over_a_delete_on_the_other_device() {
        let (_ta, _tb, mut a, mut b, personal) = two_devices("loeschen");
        let id = put_json(&mut a, None, json!({"name": "web"}));
        deliver(&mut a, &mut b, &personal);

        a.delete(&id).unwrap();
        put_json(&mut b, Some(id), json!({"name": "web-01"}));
        let applied = deliver(&mut a, &mut b, &personal);
        assert!(applied.merged[0].1.restored);
        assert_eq!(values(&b, &personal), [json!({"name": "web-01"})]);
        deliver(&mut b, &mut a, &personal);
        assert_eq!(values(&a, &personal), [json!({"name": "web-01"})], "the entry is back");

        // The other way round: the server already has the change, here it was deleted.
        put_json(&mut a, Some(id), json!({"name": "web-02"}));
        b.delete(&id).unwrap();
        assert!(deliver(&mut a, &mut b, &personal).merged[0].1.restored);
        assert_eq!(values(&b, &personal), [json!({"name": "web-02"})]);
        assert!(b.pending(&personal).unwrap().is_empty(), "our own deletion is discarded");
    }

    #[test]
    fn forged_and_stale_records_from_the_server_are_refused() {
        let (_ta, _tb, mut a, mut b, personal) = two_devices("faelschen");
        let id = put_json(&mut a, None, json!({"name": "one"}));
        let first = a.pending(&personal).unwrap();
        deliver(&mut a, &mut b, &personal);
        put_json(&mut a, Some(id), json!({"name": "two"}));
        let second = a.pending(&personal).unwrap();
        deliver(&mut a, &mut b, &personal);

        let refused = |b: &mut Vault, envelope: Envelope, what: &str| {
            let applied = b.apply_remote(&personal, &[envelope]).unwrap();
            assert_eq!((applied.rejected.len(), applied.taken.len(), applied.merged.len()), (1, 0, 0), "{what}");
            assert_eq!(values(b, &personal), [json!({"name": "two"})], "{what}");
        };
        refused(&mut b, first[0].clone(), "alter Stand");
        let mut changed = second[0].clone();
        changed.ciphertext[3] ^= 1;
        refused(&mut b, changed, "modified content");
        let mut changed = second[0].clone();
        changed.revision = 9;
        refused(&mut b, changed, "Revision hochgesetzt");
        let mut changed = second[0].clone();
        changed.deleted = true;
        refused(&mut b, changed, "passed off as deleted");
        let mut changed = second[0].clone();
        changed.id = [3; 16];
        refused(&mut b, changed, "under another ID");

        // A foreign account has nothing to write in the personal vault, not even with the right key.
        let other = Temp::new("faelschen-fremd");
        let stranger = Vault::create(&other.0, "x", FAST).unwrap();
        let (keys, vault_keys) = b.vault_keys(&personal).unwrap();
        let forged = seal(stranger.keys().unwrap(), &personal, &vault_keys.key, [4; 16], 1, false, b"{}");
        let _ = keys;
        refused(&mut b, forged, "fremder Autor");
    }

    /// A owns a shared vault, B may write, C may only read.
    struct Team {
        _temps: [Temp; 3],
        a: Vault,
        b: Vault,
        c: Vault,
        shared: Id,
    }

    fn team(name: &str) -> Team {
        let temps = [Temp::new(&format!("{name}-a")), Temp::new(&format!("{name}-b")), Temp::new(&format!("{name}-c"))];
        let mut a = Vault::create(&temps[0].0, "a", FAST).unwrap();
        let mut b = Vault::create(&temps[1].0, "b", FAST).unwrap();
        let mut c = Vault::create(&temps[2].0, "c", FAST).unwrap();
        let shared = a.create_shared(&account(1), "account1").unwrap();
        let mut roster = a.vaults().unwrap()[1].roster.clone().unwrap();
        roster.version = 2;
        roster.members.extend([member(&b, 2, Role::Write), member(&c, 3, Role::Read)]);
        let blob = a.sign_roster(&shared, &roster).unwrap();
        a.set_roster(&shared, &blob).unwrap();
        for vault in [&mut b, &mut c] {
            let sealed = a.seal_key_for(&shared, &vault.public_keys().unwrap().1).unwrap();
            vault.join_shared(&shared, &sealed, &blob).unwrap();
        }
        Team { _temps: temps, a, b, c, shared }
    }

    #[test]
    fn a_shared_vault_reaches_its_members_and_enforces_roles() {
        let Team { _temps, mut a, mut b, mut c, shared } = team("share");
        let infos = b.vaults().unwrap();
        assert_eq!((infos.len(), infos[0].kind, infos[1].kind, infos[1].role), (2, Kind::Personal, Kind::Shared, Role::Write));
        assert_eq!(c.vaults().unwrap()[1].role, Role::Read);

        let host = a.put_in(&shared, br#"{"name":"team-host"}"#).unwrap();
        a.put(None, br#"{"name":"privat"}"#).unwrap();
        let sent = a.pending(&shared).unwrap();
        assert_eq!(sent.len(), 1, "the personal vault stays at home");
        assert_eq!(b.apply_remote(&shared, &sent).unwrap().taken.len(), 1);
        assert_eq!(c.apply_remote(&shared, &sent).unwrap().taken.len(), 1);
        a.acknowledge(&shared, &sent).unwrap();
        assert_eq!(values(&c, &shared), [json!({"name": "team-host"})]);
        assert_eq!(b.vault_of(&host).unwrap(), shared);

        // B may write, and everyone accepts it.
        b.put(Some(host), br#"{"name":"team-host","own":{"port":2222}}"#).unwrap();
        let sent = b.pending(&shared).unwrap();
        assert_eq!(a.apply_remote(&shared, &sent).unwrap().taken.len(), 1);
        assert_eq!(c.apply_remote(&shared, &sent).unwrap().taken.len(), 1);
        b.acknowledge(&shared, &sent).unwrap();

        // C may not: its own program refuses, and whatever C signs anyway nobody accepts.
        assert!(matches!(c.put(Some(host), b"{}"), Err(VaultError::ReadOnly)));
        assert!(matches!(c.put_in(&shared, b"{}"), Err(VaultError::ReadOnly)));
        assert!(matches!(c.delete(&host), Err(VaultError::ReadOnly)));
        let (keys, vault_keys) = c.vault_keys(&shared).unwrap();
        let smuggled = seal(keys, &shared, &vault_keys.key, host, 3, false, br#"{"name":"von C"}"#);
        for vault in [&mut a, &mut b] {
            assert_eq!(vault.apply_remote(&shared, std::slice::from_ref(&smuggled)).unwrap().rejected, [host]);
            assert_eq!(values(vault, &shared)[0]["own"]["port"], 2222);
        }

        // After locking and unlocking everything is back.
        b.lock();
        b.unlock("b").unwrap();
        assert_eq!(b.vaults().unwrap().len(), 2);
        assert_eq!(values(&b, &shared).len(), 1);

        // The server cannot put anyone in, and only a key rotation takes permissions away.
        let mut forged = b.vaults().unwrap()[1].roster.clone().unwrap();
        forged.version = 3;
        forged.members[2].role = Role::Write;
        assert!(matches!(c.sign_roster(&shared, &forged), Err(VaultError::NotOwner)));
        let mut reduced = forged.clone();
        reduced.members[2].role = Role::Read;
        reduced.members[1].role = Role::Read;
        let blob = a.sign_roster(&shared, &reduced).unwrap();
        assert!(matches!(b.set_roster(&shared, &blob), Err(VaultError::Roster(RosterError::NeedsRotation))));
        assert!(matches!(a.remove_vault(&a.personal().unwrap()), Err(VaultError::Personal)));
    }

    #[test]
    fn removing_a_member_rotates_the_key() {
        let Team { _temps, mut a, mut b, mut c, shared } = team("tausch");
        let kept = a.put_in(&shared, br#"{"name":"stays"}"#).unwrap();
        let edited = a.put_in(&shared, br#"{"name":"old","own":{"port":22}}"#).unwrap();
        let gone = a.put_in(&shared, br#"{"name":"gone"}"#).unwrap();
        let sent = a.pending(&shared).unwrap();
        b.apply_remote(&shared, &sent).unwrap();
        c.apply_remote(&shared, &sent).unwrap();
        a.acknowledge(&shared, &sent).unwrap();
        a.delete(&gone).unwrap();
        let sent = a.pending(&shared).unwrap();
        b.apply_remote(&shared, &sent).unwrap();
        a.acknowledge(&shared, &sent).unwrap();

        // B holds a change and a new entry offline while A removes the member C.
        b.put(Some(edited), br#"{"name":"new","own":{"port":22}}"#).unwrap();
        b.put_in(&shared, br#"{"name":"from B"}"#).unwrap();

        let mut roster = a.vaults().unwrap()[1].roster.clone().unwrap();
        roster.members.retain(|m| m.name != "account3");
        roster.version += 1;
        assert!(matches!(a.prepare_rotation(&shared, &roster), Err(VaultError::Roster(RosterError::Stale))), "without a new key epoch");
        roster.epoch += 1;
        a.put(Some(kept), br#"{"name":"stays!"}"#).unwrap();
        assert!(matches!(a.prepare_rotation(&shared, &roster), Err(VaultError::Pending)));
        let sent = a.pending(&shared).unwrap();
        a.acknowledge(&shared, &sent).unwrap();
        assert!(matches!(b.prepare_rotation(&shared, &roster), Err(VaultError::NotOwner)));

        let rotation = a.prepare_rotation(&shared, &roster).unwrap();
        assert_eq!((rotation.epoch, rotation.keys.len(), rotation.records.len()), (2, 2, 3), "the tombstone moves too");
        let (blob, records) = (rotation.roster.clone(), rotation.records.clone());
        let key_for = |vault: &Vault| rotation.keys.iter().find(|(key, _)| *key == vault.public_keys().unwrap().0).map(|(_, sealed)| sealed.clone());
        let (for_b, for_c) = (key_for(&b).unwrap(), key_for(&c));
        assert!(for_c.is_none(), "there is no key for the removed member");
        a.commit_rotation(rotation).unwrap();
        assert_eq!(a.vaults().unwrap()[1].epoch, 2);
        assert_eq!(values(&a, &shared), [json!({"name": "old", "own": {"port": 22}}), json!({"name": "stays!"})]);
        assert!(a.pending(&shared).unwrap().is_empty());

        // C is out: the new list does not name C, the new key is not for C, the new records stay closed.
        assert!(matches!(c.apply_rotation(&shared, &for_b, &blob, &records), Err(VaultError::NotMember)));
        assert_eq!(c.apply_remote(&shared, &records).unwrap().rejected.len(), 3);
        c.remove_vault(&shared).unwrap();
        assert!(c.vaults().unwrap().len() == 1 && c.list().unwrap().records.is_empty());

        // B moves over and keeps what was waiting there.
        let applied = b.apply_rotation(&shared, &for_b, &blob, &records).unwrap();
        assert!(applied.rejected.is_empty());
        assert_eq!(values(&b, &shared), [json!({"name": "from B"}), json!({"name": "new", "own": {"port": 22}}), json!({"name": "stays!"})]);
        let pending = b.pending(&shared).unwrap();
        assert_eq!(pending.len(), 2);
        assert_eq!(a.apply_remote(&shared, &pending).unwrap().taken.len(), 2, "under the new key, readable for A");
        b.acknowledge(&shared, &pending).unwrap();
        assert_eq!(values(&a, &shared), values(&b, &shared));

        // Everything survives locking, and the old state cannot be slipped in again.
        b.lock();
        b.unlock("b").unwrap();
        assert_eq!(values(&b, &shared).len(), 3);
        assert!(matches!(b.apply_rotation(&shared, &for_b, &blob, &records), Err(VaultError::Roster(RosterError::Stale))));
    }

    #[test]
    fn discarding_waiting_changes_returns_to_the_synced_state() {
        let (_ta, _tb, mut a, mut b, personal) = two_devices("discard");
        let id = put_json(&mut a, None, json!({"name": "synced"}));
        deliver(&mut a, &mut b, &personal);
        put_json(&mut a, Some(id), json!({"name": "changed"}));
        put_json(&mut a, None, json!({"name": "new"}));
        assert_eq!(a.discard_pending(&personal).unwrap(), 2);
        assert_eq!(values(&a, &personal), [json!({"name": "synced"})]);
        assert!(a.pending(&personal).unwrap().is_empty());
    }

    #[test]
    fn the_link_to_the_server_stays_on_this_device() {
        let temp = Temp::new("link");
        let copy = Temp::new("link-copy");
        let mut vault = Vault::create(&temp.0, "right", FAST).unwrap();
        let personal = vault.personal().unwrap();
        assert!(vault.link().unwrap().is_none());
        vault.set_link(Some(b"https://sync.example|token")).unwrap();
        vault.set_cursor(&personal, 42).unwrap();
        let id = vault.put(None, b"x").unwrap();
        vault.delete(&id).unwrap();
        assert_eq!(vault.purge_tombstones(-1).unwrap(), 0, "the server does not know about the deletion yet");
        let sent = vault.pending(&personal).unwrap();
        vault.acknowledge(&personal, &sent).unwrap();
        vault.backup(&copy.0).unwrap();
        assert_eq!(vault.purge_tombstones(-1).unwrap(), 1);

        vault.lock();
        assert!(matches!(vault.link(), Err(VaultError::Locked)));
        vault.unlock("right").unwrap();
        assert_eq!(vault.link().unwrap().unwrap().as_slice(), b"https://sync.example|token");
        assert_eq!(vault.cursor(&personal).unwrap(), 42);
        let bytes = std::fs::read(&temp.0).unwrap();
        assert!(!bytes.windows(12).any(|w| w == b"sync.example"), "the address is not in the file as plaintext");

        // The backup does not know the server and syncs from scratch.
        let mut restored = Vault::open(&copy.0).unwrap();
        restored.unlock("right").unwrap();
        assert!(restored.link().unwrap().is_none());
        assert_eq!(restored.cursor(&personal).unwrap(), 0);
        vault.set_link(None).unwrap();
        assert!(vault.link().unwrap().is_none());
    }

    #[test]
    fn a_password_changed_elsewhere_takes_over_once_it_opens() {
        let (_ta, _tb, mut a, mut b, _) = two_devices("password");
        assert!(matches!(a.rewrap("wrong", "new", FAST), Err(VaultError::WrongPassword)));
        let (wrapping, old_auth, new_auth) = a.rewrap("right", "new", FAST).unwrap();
        assert_eq!(old_auth.as_ref(), a.auth_key("right").unwrap().as_ref(), "before adopting, the old one still applies");
        a.install_wrapping(&wrapping).unwrap();
        assert_eq!(new_auth.as_ref(), a.auth_key("new").unwrap().as_ref());
        assert_ne!(old_auth.as_ref(), new_auth.as_ref());

        // The second device gets the new wrapping from the server and stores it as pending: the old password keeps opening.
        b.stage_wrapping(&wrapping).unwrap();
        b.lock();
        b.unlock("right").unwrap();
        assert_ne!(b.current_wrapping().unwrap(), wrapping);
        b.lock();
        assert!(matches!(b.unlock("wrong"), Err(VaultError::WrongPassword)));
        // With the new password it becomes the current one, and the old one no longer opens.
        b.unlock("new").unwrap();
        assert_eq!(b.current_wrapping().unwrap(), wrapping);
        b.lock();
        assert!(matches!(b.unlock("right"), Err(VaultError::WrongPassword)));
        b.unlock("new").unwrap();

        // Nonsense from the server locks nobody out, not even the real wrapping of a foreign account.
        let mut garbage = wrapping.clone();
        garbage.account_wrapped[0] ^= 1;
        b.stage_wrapping(&garbage).unwrap();
        b.lock();
        b.unlock("new").unwrap();
        let other = Temp::new("password-foreign");
        let stranger = Vault::create(&other.0, "fremd", FAST).unwrap();
        b.stage_wrapping(&stranger.current_wrapping().unwrap()).unwrap();
        b.lock();
        assert!(matches!(b.unlock("fremd"), Err(VaultError::WrongPassword)));
        b.unlock("new").unwrap();
        assert_eq!(b.current_wrapping().unwrap(), wrapping);
    }

    #[test]
    fn names_of_other_people_are_not_readable_in_the_file() {
        let Team { _temps, a, mut b, c: _, shared } = team("names");
        assert_eq!(b.roster_blob(&shared).unwrap(), a.roster_blob(&shared).unwrap(), "the same list as it goes to the server");

        let contact = Contact { name: "account1".into(), ed25519: "aa".repeat(32), x25519: "bb".repeat(32), seen_at: 5 };
        assert!(b.contact(&account(1)).unwrap().is_none());
        b.remember_contact(&account(1), &contact).unwrap();
        b.remember_contact(&account(1), &Contact { seen_at: 9, ..contact.clone() }).unwrap();
        assert_eq!(b.contact(&account(1)).unwrap().unwrap().seen_at, 9);
        assert!(b.contact(&account(2)).unwrap().is_none());

        for text in ["notice one about account1", "notice two", "notice three"] {
            b.add_notice(text.as_bytes()).unwrap();
        }
        let notices = b.notices().unwrap();
        assert_eq!(notices.iter().map(|notice| String::from_utf8(notice.data.to_vec()).unwrap()).collect::<Vec<_>>(), ["notice one about account1", "notice two", "notice three"]);
        b.clear_notices(notices[1].id).unwrap();
        assert_eq!(b.notices().unwrap().len(), 1);

        let bytes = std::fs::read(b.path()).unwrap();
        for needle in [b"account1".as_slice(), b"account3", b"Notice"] {
            assert!(!bytes.windows(needle.len()).any(|w| w == needle), "plaintext found in the file");
        }
        b.lock();
        assert!(matches!(b.contact(&account(1)), Err(VaultError::Locked)));
        assert!(matches!(b.notices(), Err(VaultError::Locked)));
        b.unlock("b").unwrap();
        assert_eq!(b.contact(&account(1)).unwrap().unwrap().name, "account1");
    }

    #[test]
    fn old_notices_fall_out() {
        let temp = Temp::new("notices");
        let mut vault = Vault::create(&temp.0, "right", FAST).unwrap();
        for i in 0..(MAX_NOTICES + 5) {
            vault.add_notice(format!("{i}").as_bytes()).unwrap();
        }
        let notices = vault.notices().unwrap();
        assert_eq!((notices.len() as i64, notices[0].data.as_slice()), (MAX_NOTICES, b"5".as_slice()));
    }

    #[test]
    fn devices_of_one_account_share_small_secrets() {
        let (_ta, _tb, a, b, _) = two_devices("eigen");
        let sealed = a.seal_own("Emirs PC".as_bytes()).unwrap();
        assert_eq!(b.open_own(&sealed).unwrap().unwrap().as_slice(), "Emirs PC".as_bytes());
        let other = Temp::new("eigen-fremd");
        let stranger = Vault::create(&other.0, "x", FAST).unwrap();
        assert!(stranger.open_own(&sealed).unwrap().is_none());
        assert!(b.open_own(b"too short").unwrap().is_none());
    }

    #[test]
    fn a_full_state_from_the_server_removes_what_is_gone_there() {
        let (_ta, _tb, mut a, mut b, personal) = two_devices("whole");
        let kept = put_json(&mut a, None, json!({"name": "stays"}));
        let gone = put_json(&mut a, None, json!({"name": "deleted there"}));
        let edited = put_json(&mut a, None, json!({"name": "deleted there, changed here"}));
        deliver(&mut a, &mut b, &personal);
        put_json(&mut b, Some(edited), json!({"name": "changed here"}));
        let fresh = put_json(&mut b, None, json!({"name": "new here"}));

        assert_eq!(b.retain_synced(&personal, &BTreeSet::from([kept])).unwrap(), 1);
        assert_eq!(values(&b, &personal), [json!({"name": "changed here"}), json!({"name": "new here"}), json!({"name": "stays"})]);
        assert!(b.state(&gone).unwrap().is_none());
        // The own change now counts as new and goes out with its revision.
        let pending = b.pending(&personal).unwrap();
        assert_eq!(pending.iter().map(|e| e.id).collect::<BTreeSet<_>>(), BTreeSet::from([edited, fresh]));
        assert!(b.base(&edited).unwrap().is_none());
    }

    #[test]
    fn a_device_with_own_data_can_bring_it_into_an_account() {
        let (_ta, _tb, mut a, _b, personal) = two_devices("uebernehmen");
        let existing = put_json(&mut a, None, json!({"name": "in the account"}));
        let local = Temp::new("adopt-local");
        let mut old = Vault::create(&local.0, "other password", FAST).unwrap();
        let group = put_json(&mut old, None, json!({"t": "group", "name": "Group"}));
        let host = put_json(&mut old, None, json!({"t": "host", "name": "local", "group": crypto::hex(&group)}));
        let deleted = put_json(&mut old, None, json!({"name": "was deleted"}));
        old.delete(&deleted).unwrap();

        assert_eq!(a.adopt_from(&old).unwrap(), 2);
        assert_eq!(a.adopt_from(&old).unwrap(), 0, "a second time brings nothing twice");
        assert_eq!(values(&a, &personal).len(), 3);
        // The same IDs: the host's reference to its group holds.
        assert_eq!(a.vault_of(&host).unwrap(), personal);
        assert_eq!(a.vault_of(&group).unwrap(), personal);
        assert!(a.state(&deleted).unwrap().is_none());
        assert_eq!(a.pending(&personal).unwrap().len(), 3);
        let _ = existing;
    }

    #[test]
    fn a_server_with_an_older_state_gets_the_newer_one_back() {
        let (_ta, _tb, mut a, mut b, personal) = two_devices("zurueck");
        let old = put_json(&mut a, None, json!({"name": "old"}));
        let stays = put_json(&mut a, None, json!({"name": "unchanged"}));
        // The state the server's backup records.
        let backup = a.pending(&personal).unwrap();
        deliver(&mut a, &mut b, &personal);
        // Then work continued: a change, a new entry, a deleted one. Both devices have everything.
        put_json(&mut a, Some(old), json!({"name": "new"}));
        let fresh = put_json(&mut a, None, json!({"name": "after the backup"}));
        a.delete(&stays).unwrap();
        deliver(&mut a, &mut b, &personal);
        assert!(a.pending(&personal).unwrap().is_empty());
        let writes = a.writes();

        // The server is back from the backup. Its state alone changes nothing here ...
        assert_eq!(a.apply_remote(&personal, &backup).unwrap().rejected.len(), 2);
        // ... only explicitly uploading the own state does.
        let applied = a.rebase_onto(&personal, &backup).unwrap();
        assert!(applied.rejected.is_empty() && applied.taken.is_empty());
        assert!(a.writes() > writes);
        assert_eq!(values(&a, &personal), [json!({"name": "after the backup"}), json!({"name": "new"})], "nothing changes about the content");
        let outgoing = a.outgoing(&personal).unwrap();
        let of = |id: &Id| outgoing.iter().find(|(e, _)| e.id == *id).map(|(e, base)| (e.revision, *base, e.deleted)).unwrap();
        assert_eq!(of(&old), (3, 1, false), "builds on the server's state and lies above everything any device ever saw");
        assert_eq!(of(&stays), (3, 1, true), "the deletion goes out again too");
        assert_eq!(of(&fresh), (1, 0, false), "what the server does not know counts as new");

        // The other device accepts everything as new and then has the same state.
        let applied = deliver(&mut a, &mut b, &personal);
        assert_eq!((applied.taken.len(), applied.rejected.len()), (2, 0), "it already has the new entry exactly like this");
        assert_eq!(values(&b, &personal), values(&a, &personal));

        // Whatever is newer on the server by now (a third device was faster) is taken over on the way.
        put_json(&mut b, Some(old), json!({"name": "even newer"}));
        let newer = b.pending(&personal).unwrap();
        let applied = a.rebase_onto(&personal, &newer).unwrap();
        assert_eq!(applied.taken, [old]);
        assert_eq!(values(&a, &personal)[1], json!({"name": "even newer"}));
    }

    #[test]
    fn an_invitation_can_be_looked_at_before_joining() {
        let Team { _temps, mut a, b, c: _, shared } = team("einladung");
        a.put_in(&shared, br#"{"t":"vault-info","name":"Team Server"}"#).unwrap();
        let gone = a.put_in(&shared, b"gone").unwrap();
        a.delete(&gone).unwrap();
        let rows = a.pending(&shared).unwrap();
        let (roster, sealed) = (a.roster_blob(&shared).unwrap(), |v: &Vault| a.seal_key_for(&shared, &v.public_keys().unwrap().1).unwrap());

        let other = Temp::new("invitation-new");
        let mut invited = Vault::create(&other.0, "x", FAST).unwrap();
        assert!(matches!(invited.peek_invitation(&shared, &sealed(&invited), &roster, &rows), Err(VaultError::NotMember)), "the list does not name this account");
        let mut next = a.vaults().unwrap()[1].roster.clone().unwrap();
        next.version += 1;
        next.members.push(member(&invited, 4, Role::Read));
        let roster = a.sign_roster(&shared, &next).unwrap();
        let (seen, plain) = invited.peek_invitation(&shared, &sealed(&invited), &roster, &rows).unwrap();
        assert_eq!(seen.owner().unwrap().name, "account1");
        assert_eq!(plain.iter().map(|p| p.to_vec()).collect::<Vec<_>>(), [br#"{"t":"vault-info","name":"Team Server"}"#.to_vec()]);
        assert_eq!(invited.vaults().unwrap().len(), 1, "only looked at, not taken in");
        assert!(matches!(invited.peek_invitation(&shared, &sealed(&b), &roster, &rows), Err(VaultError::Corrupt(_))), "someone else's key");
        invited.join_shared(&shared, &sealed(&invited), &roster).unwrap();
    }

    #[test]
    fn a_vault_survives_a_change_of_owner() {
        let Team { _temps, mut a, mut b, mut c, shared } = team("besitz");
        let key_of = |vault: &Vault| vault.public_keys().unwrap().0;
        assert!(matches!(b.transfer_roster(&shared, &key_of(&c)), Err(VaultError::NotOwner)));
        let blob = a.transfer_roster(&shared, &key_of(&b)).unwrap();
        for vault in [&mut a, &mut b, &mut c] {
            vault.set_roster(&shared, &blob).unwrap();
        }
        let role = |vault: &Vault| vault.vaults().unwrap()[1].role;
        assert_eq!((role(&a), role(&b), role(&c)), (Role::Write, Role::Owner, Role::Read));

        // The transfer list carries the former owner's signature and still counts after locking.
        for (vault, password) in [(&mut a, "a"), (&mut b, "b")] {
            vault.lock();
            vault.unlock(password).unwrap();
            assert_eq!(vault.vaults().unwrap().len(), 2);
        }

        // The new owner carries on: invite, rotate keys. The former owner can no longer do that.
        let mut roster = b.vaults().unwrap()[1].roster.clone().unwrap();
        roster.version += 1;
        assert!(matches!(a.sign_roster(&shared, &roster), Err(VaultError::NotOwner)));
        roster.members.retain(|m| m.name != "account3");
        roster.epoch += 1;
        let rotation = b.prepare_rotation(&shared, &roster).unwrap();
        let (blob, records) = (rotation.roster.clone(), rotation.records.clone());
        let for_a = rotation.keys.iter().find(|(key, _)| *key == key_of(&a)).unwrap().1.clone();
        b.commit_rotation(rotation).unwrap();
        a.apply_rotation(&shared, &for_a, &blob, &records).unwrap();
        assert_eq!(a.vaults().unwrap()[1].epoch, 2);

        // A device that joins later can verify the list although it never saw the transfer.
        let other = Temp::new("ownership-new");
        let mut late = Vault::create(&other.0, "x", FAST).unwrap();
        let mut next = b.vaults().unwrap()[1].roster.clone().unwrap();
        next.version += 1;
        next.members.push(member(&late, 4, Role::Read));
        let blob = b.sign_roster(&shared, &next).unwrap();
        late.join_shared(&shared, &b.seal_key_for(&shared, &late.public_keys().unwrap().1).unwrap(), &blob).unwrap();
        a.set_roster(&shared, &blob).unwrap();
    }
}

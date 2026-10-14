//! Verschlüsselte Ablage: eine SQLite-Datei mit einzeln verschlüsselten und signierten Datensätzen.
//!
//! Der Tresor kennt keine Hosts oder Gruppen, nur Bytes. Was darin steht, legt `model` fest.
//! Format und Begründungen: `docs/tresor.md`; mehrere Tresore, Teilen und Abgleich: `docs/sync.md`.

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

/// Fassung 2 (Meilenstein 9): mehrere Tresore je Datei und alles für den Abgleich. Datensätze, Schlüsselkette
/// und Prüfwerte sind dieselben wie in Fassung 1; eine Datei der Fassung 1 wird beim Öffnen umgestellt.
pub const FORMAT_VERSION: u32 = 2;

/// Kennung eines Tresors oder Datensatzes: 16 zufällige Byte.
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

/// So viele Hinweise aus dem Abgleich bleiben stehen; ältere fallen heraus.
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

/// Der Schritt von Fassung 1 zu 2. Eine neue Datei entsteht aus `SCHEMA_1` und diesem Schritt, damit eine
/// umgestellte und eine neue Datei nie verschieden aussehen.
///
/// - `vaults.kind`: 0 persönlich, 1 geteilt. `epoch`: Schlüsselstand. `cursor`: bis zu welcher Nummer des
///   Servers alles geholt ist. `roster`: signierte Mitgliederliste eines geteilten Tresors.
/// - `records.synced`: die Revision, die der Server zuletzt bestätigt oder geliefert hat (0 = kennt er nicht).
/// - `base`: der zuletzt abgeglichene Stand jedes Datensatzes, dessen Änderung noch nicht beim Server ist.
/// - `contacts`: einmal gesehene öffentliche Schlüssel anderer Konten. `notices`: Hinweise aus dem Abgleich.
///
/// Mitgliederlisten, Kontakte und Hinweise nennen Namen; sie liegen deshalb mit dem Kontoschlüssel
/// verschlüsselt in der Datei (`sealed`: Nonce, dahinter der Schlüsseltext).
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
    #[error("Der Tresor ist gesperrt")]
    Locked,
    #[error("Falsches Master-Passwort")]
    WrongPassword,
    #[error("Es gibt bereits einen Tresor")]
    AlreadyExists,
    #[error("Datensatz nicht gefunden")]
    NotFound,
    #[error("Die Tresor-Datei ist beschädigt oder wurde verändert ({0})")]
    Corrupt(&'static str),
    #[error("Tresor-Format {0} wird von dieser Version nicht unterstützt")]
    UnsupportedFormat(u32),
    #[error("Schlüsselableitung fehlgeschlagen")]
    Kdf,
    /// Der auf diesem Gerät hinterlegte Schlüssel passt nicht (mehr) zu diesem Tresor.
    #[error("Der hinterlegte Geräteschlüssel passt nicht zu diesem Tresor")]
    StaleDeviceKey,
    #[error("Der persönliche Tresor lässt sich nicht entfernen")]
    Personal,
    #[error("In diesem Tresor darfst du nur lesen")]
    ReadOnly,
    #[error("Das darf nur der Besitzer des Tresors")]
    NotOwner,
    #[error("Du bist kein Mitglied dieses Tresors")]
    NotMember,
    /// Ein Schlüsseltausch braucht einen Tresor ohne wartende Änderungen.
    #[error("In diesem Tresor warten noch Änderungen auf den Abgleich")]
    Pending,
    #[error(transparent)]
    Roster(#[from] RosterError),
    #[error(transparent)]
    Db(#[from] rusqlite::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

type Result<T> = std::result::Result<T, VaultError>;

/// Entschlüsselter Datensatz. Der Inhalt wird beim Freigeben überschrieben.
#[derive(Debug)]
pub struct Record {
    pub id: Id,
    pub vault: Id,
    pub revision: u64,
    pub modified_at: i64,
    pub data: Zeroizing<Vec<u8>>,
}

/// Ergebnis des Lesens: was sich öffnen ließ und was nicht. Ein beschädigter Datensatz sperrt nicht den Rest aus.
#[derive(Debug, Default)]
pub struct Listing {
    pub records: Vec<Record>,
    pub damaged: Vec<Vec<u8>>,
}

/// Ein Datensatz so, wie er in der Datei liegt und zum Server geht: verschlüsselt und signiert.
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
    /// Trägt der Umschlag die Signatur seines Autors für diesen Tresor? Das lässt sich ohne einen Schlüssel
    /// des Tresors prüfen, also auch vom Server.
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
    /// Bis zu welcher Nummer des Servers alles geholt ist.
    pub cursor: u64,
    /// Die eigene Rolle; im persönlichen Tresor immer Besitzer.
    pub role: Role,
    pub roster: Option<Roster>,
}

/// Alles, was ein neues Gerät vom Server braucht, um diesen Tresor mit dem Master-Passwort zu öffnen.
/// Jedes Stück ist schon verschlüsselt oder öffentlich.
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

/// Die öffentlichen Schlüssel, unter denen ein anderes Konto zuletzt gesehen wurde.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Contact {
    pub name: String,
    pub ed25519: String,
    pub x25519: String,
    pub seen_at: i64,
}

/// Ein Hinweis aus dem Abgleich, wie er in der Datei liegt: laufende Nummer, Zeitpunkt, Inhalt.
#[derive(Debug)]
pub struct StoredNotice {
    pub id: i64,
    pub at: i64,
    pub data: Zeroizing<Vec<u8>>,
}

/// Was beim Übernehmen von Datensätzen des Servers geschah.
#[derive(Debug, Default)]
pub struct Applied {
    /// Übernommen, wie geliefert.
    pub taken: Vec<Id>,
    /// Mit einer wartenden eigenen Änderung zusammengeführt.
    pub merged: Vec<(Id, Merge)>,
    /// Abgelehnt: falsche Signatur, Autor ohne Schreibrecht, nicht zu entschlüsseln oder älter als bekannt.
    pub rejected: Vec<Id>,
}

/// Ein vorbereiteter Schlüsseltausch: alles, was als ein Paket zum Server geht. Lokal ändert sich erst mit
/// [`Vault::commit_rotation`] etwas, also nachdem der Server angenommen hat.
pub struct Rotation {
    pub vault: Id,
    pub epoch: u64,
    pub roster: Vec<u8>,
    /// Je Mitglied (Signaturschlüssel) der für es verpackte neue Tresor-Schlüssel.
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
    /// Darf der Inhaber von `author` hier Datensätze schreiben? Im persönlichen Tresor nur man selbst.
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
    /// Bleibt im Speicher, solange der Tresor offen ist: Aus ihm folgen ohnehin alle anderen Schlüssel.
    /// Gebraucht wird er für das Entsperren beim Start ohne Master-Passwort (`device_key`).
    account_key: Key,
    signing: SigningKey,
    public: [u8; 32],
    /// Empfängt die Schlüssel geteilter Tresore.
    exchange: StaticSecret,
    personal: Id,
    vaults: BTreeMap<Id, VaultKeys>,
}

pub struct Vault {
    conn: Connection,
    path: PathBuf,
    unlocked: Option<Unlocked>,
    /// Zählt, was sich an Datensätzen und Tresoren ändert (siehe [`Vault::writes`]).
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

    /// Als Umschlag, sofern jedes Stück die richtige Länge hat.
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

/// Stand eines Datensatzes in der Datei, wie ihn das Schreiben braucht.
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

/// Liest eine Spalte als Bytes, egal welchen Typ SQLite ihr gibt. Eine von außen veränderte Datei kann aus einem
/// Blob einen Text machen; das soll als „beschädigt“ auffallen und nicht das ganze Lesen abbrechen.
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

/// Keine SQLite-Datei oder ein fremder Aufbau: für den Nutzer ist beides „beschädigt“. Andere Fehler
/// (gesperrte Datei, fehlende Rechte) bleiben, was sie sind.
fn as_corrupt(error: VaultError) -> VaultError {
    match &error {
        VaultError::Db(rusqlite::Error::SqliteFailure(failure, message))
            if matches!(failure.code, ErrorCode::NotADatabase | ErrorCode::DatabaseCorrupt)
                || message.as_deref().is_some_and(|m| m.contains("no such table")) =>
        {
            VaultError::Corrupt("keine Tresor-Datei")
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

/// Der verpackte Kontoschlüssel bleibt an die Fassung gebunden, mit der die Schlüsselkette festgelegt wurde.
/// Sonst öffnete nach der Umstellung der Datei kein Master-Passwort mehr.
const FORMAT_1: u32 = 1;

/// Der Kontoschlüssel, verpackt unter einem Master-Passwort: das, was sich bei einer Passwortänderung ändert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wrapping {
    pub salt: [u8; SALT_LEN],
    pub kdf: KdfParams,
    pub account_nonce: Vec<u8>,
    pub account_wrapped: Vec<u8>,
}

/// Aus dem Passwort: der Schlüssel, der den Kontoschlüssel entsperrt, und der für die Anmeldung am Sync-Server.
/// Aus dem zweiten lässt sich nichts entschlüsseln.
fn password_keys(password: &str, salt: &[u8; SALT_LEN], kdf: KdfParams) -> Result<(Key, Key)> {
    let master = crypto::derive_master_key(password.as_bytes(), salt, kdf).map_err(|_| VaultError::Kdf)?;
    Ok((crypto::derive_subkey(&master, INFO_KEK), crypto::derive_subkey(&master, INFO_AUTH)))
}

/// Verpackt den Kontoschlüssel unter einem Passwort. Liefert dazu den Anmeldeschlüssel dieses Passworts.
fn wrap_account(password: &str, kdf: KdfParams, account_key: &Key) -> Result<(Wrapping, Key)> {
    let salt: [u8; SALT_LEN] = crypto::random();
    let (kek, auth) = password_keys(password, &salt, kdf)?;
    let sealed = crypto::seal(&kek, &account_aad(&salt, kdf), account_key.as_ref());
    Ok((Wrapping { salt, kdf, account_nonce: sealed.nonce.to_vec(), account_wrapped: sealed.ciphertext }, auth))
}

/// Schreibt eine Verpackung: als die geltende (`prefix` leer) oder als vorgemerkte (`next_`).
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

/// Der Schlüssel, mit dem sich ein Gerät am Sync-Server ausweist. Aus ihm lässt sich nichts entschlüsseln.
pub fn auth_key(password: &str, salt: &[u8; SALT_LEN], kdf: KdfParams) -> Result<Key> {
    Ok(password_keys(password, salt, kdf)?.1)
}

/// Prüfsumme über den Stand eines Tresors: Kennung und Revision jedes lebenden Datensatzes, nach Kennung
/// geordnet. Der Server rechnet sie über das, was er hat, ein Gerät über das, was es für dessen Stand hält.
/// Stimmen beide nicht überein, hat das Gerät etwas verpasst oder der Server etwas verloren; Nummern allein
/// zeigen das nicht sicher, etwa nach dem Zurückholen des Servers aus einer Sicherung.
pub fn state_digest(entries: impl IntoIterator<Item = (Id, u64)>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for (id, revision) in entries {
        hasher.update(id);
        hasher.update(revision.to_le_bytes());
    }
    hasher.finalize().into()
}

/// Ein kleines Stück unter dem Kontoschlüssel: Nonce, dahinter der Schlüsseltext.
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

/// Prüft Signatur und Autor eines Umschlags und entschlüsselt ihn.
fn unseal(vault_id: &Id, vault: &VaultKeys, me: &[u8; 32], envelope: &Envelope) -> Option<Zeroizing<Vec<u8>>> {
    if !vault.allows(&envelope.author, me) || !envelope.signed(vault_id) {
        return None;
    }
    let aad = record_aad(vault_id, &envelope.id, envelope.revision, envelope.deleted);
    crypto::open(&vault.key, &envelope.nonce, &aad, &envelope.ciphertext).ok()
}

/// Verschlüsselt und signiert einen Datensatz als man selbst.
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

    /// Steigt mit jeder Änderung an Datensätzen, Tresoren oder Mitgliederlisten. Wer den Inhalt im Speicher
    /// hält (das Verzeichnis), liest neu ein, wenn sich die Zahl geändert hat, etwa nach einem Abgleich.
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

    /// Legt einen neuen Tresor an und lässt ihn offen. Scheitert das Anlegen, bleibt keine halbe Datei zurück.
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

    /// Wohin [`Vault::open`] die Kopie einer Datei der Fassung 1 legt, bevor es sie umstellt.
    pub fn migration_copy(path: &Path) -> PathBuf {
        let mut name = path.file_name().unwrap_or_default().to_os_string();
        name.push(".format1");
        path.with_file_name(name)
    }

    /// Öffnet die Datei, ohne sie zu entsperren. Eine Datei der Fassung 1 wird dabei umgestellt; vorher
    /// entsteht daneben eine Kopie (siehe [`Vault::migration_copy`]).
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

    /// Entpackt den Kontoschlüssel aus einer Verpackung. Scheitert am Passwort oder an veränderten Kopfdaten;
    /// beides lässt sich nicht unterscheiden.
    fn try_wrapping(password: &str, wrapping: &Wrapping) -> Result<(Key, Key)> {
        let (kek, auth) = password_keys(password, &wrapping.salt, wrapping.kdf)?;
        let account = crypto::open(&kek, &wrapping.account_nonce, &account_aad(&wrapping.salt, wrapping.kdf), &wrapping.account_wrapped).map_err(|_| VaultError::WrongPassword)?;
        Ok((Zeroizing::new(array(&account, "Kontoschlüssel")?), auth))
    }

    /// Leitet aus dem Passwort die Schlüssel ab und entpackt den Kontoschlüssel; liefert dazu den
    /// Anmeldeschlüssel für den Sync-Server.
    ///
    /// Wurde das Master-Passwort auf einem anderen Gerät geändert, liegt dessen Verpackung vorgemerkt daneben
    /// (`stage_wrapping`). Sie kommt vom Server und ist ungeprüft; deshalb gilt sie erst, wenn ein Passwort sie
    /// öffnet und der Schlüssel darin wirklich der dieses Kontos ist. Bis dahin öffnet das bisherige Passwort.
    fn open_account(&self, password: &str) -> Result<(Key, Key)> {
        let current = self.wrapping("")?.ok_or(VaultError::Corrupt("Kontoschlüssel"))?;
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

    /// Entpackt einen privaten Schlüssel und liefert seine 32 Byte.
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

    /// Kennung dieser Tresor-Datei auf diesem Gerät. Kein Geheimnis; bindet den Geräteschlüssel an genau diesen Tresor.
    pub fn device_id(&self) -> Result<Vec<u8>> {
        self.meta("device_id")
    }

    /// Der Kontoschlüssel des offenen Tresors. Wer ihn hat, öffnet den Tresor ohne Master-Passwort;
    /// er darf den Kern nur verlassen, um vom Betriebssystem geschützt abgelegt zu werden.
    pub fn device_key(&self) -> Result<Key> {
        Ok(self.keys()?.account_key.clone())
    }

    /// Entsperrt mit einem zuvor über `device_key` hinterlegten Schlüssel statt mit dem Master-Passwort.
    pub fn unlock_with_key(&mut self, account_key: &Key) -> Result<()> {
        self.unlock_with(account_key.clone()).map_err(|e| match e {
            // Mit dem falschen Schlüssel scheitert schon das Entpacken der privaten Schlüssel.
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

        let personal: Id = array(&self.meta("default_vault")?, "Tresor-Kennung")?;
        let mut vaults = BTreeMap::new();
        let mut statement = self.conn.prepare("SELECT id, nonce, wrapped_key, kind, epoch, roster FROM vaults")?;
        let rows = statement.query_map([], |row| Ok((blob(row, 0)?, blob(row, 1)?, blob(row, 2)?, integer(row, 3)?, integer(row, 4)?, blob(row, 5)?)))?;
        for row in rows {
            let (id, nonce, wrapped, kind, epoch, roster_blob) = row?;
            // Ein geteilter Tresor, der sich nicht öffnen lässt, sperrt nicht den Rest aus: Er fehlt dann,
            // und seine Datensätze zählen als beschädigt.
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
            return Err(VaultError::Corrupt("Tresor-Schlüssel"));
        }

        self.unlocked = Some(Unlocked { account_key, signing, public, exchange, personal, vaults });
        Ok(())
    }

    /// Verwirft alle Schlüssel. Die Typen überschreiben ihren Speicher beim Freigeben selbst.
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

    /// Wie `vault_keys`, verlangt aber das Recht zu schreiben.
    fn writable(&self, vault: &Id) -> Result<(&Unlocked, &VaultKeys)> {
        let (keys, vault) = self.vault_keys(vault)?;
        match vault.role(&keys.public) {
            Some(role) if role.may_write() => Ok((keys, vault)),
            Some(_) => Err(VaultError::ReadOnly),
            None => Err(VaultError::NotMember),
        }
    }

    /// Neues Passwort: Nur der Kontoschlüssel wird neu verpackt, die Datensätze bleiben unangetastet.
    pub fn change_password(&mut self, old: &str, new: &str, kdf: KdfParams) -> Result<()> {
        let (wrapping, _, _) = self.rewrap(old, new, kdf)?;
        self.install_wrapping(&wrapping)
    }

    /// Verpackt den Kontoschlüssel unter einem neuen Passwort, ohne etwas zu schreiben. Liefert dazu den
    /// bisherigen und den neuen Anmeldeschlüssel. Mit Abgleich geht die Verpackung erst zum Server und wird
    /// danach mit [`Vault::install_wrapping`] übernommen; so kennt nie nur dieses Gerät das neue Passwort.
    pub fn rewrap(&self, old: &str, new: &str, kdf: KdfParams) -> Result<(Wrapping, Key, Key)> {
        let (account_key, old_auth) = self.open_account(old)?;
        let (wrapping, new_auth) = wrap_account(new, kdf, &account_key)?;
        Ok((wrapping, old_auth, new_auth))
    }

    /// Macht eine mit [`Vault::rewrap`] erzeugte Verpackung zur geltenden.
    pub fn install_wrapping(&mut self, wrapping: &Wrapping) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        write_wrapping(&tx, wrapping, "")?;
        clear_staged(&tx)?;
        Ok(tx.commit()?)
    }

    /// Die geltende Verpackung, zum Vergleich mit der des Servers.
    pub fn current_wrapping(&self) -> Result<Wrapping> {
        self.wrapping("")?.ok_or(VaultError::Corrupt("Kontoschlüssel"))
    }

    /// Merkt die Verpackung vor, die der Server nach einer Passwortänderung auf einem anderen Gerät liefert.
    /// Sie ersetzt die geltende erst, wenn sich mit ihr entsperren lässt (siehe `open_account`): Ein Server,
    /// der hier Unsinn schickt, sperrt niemanden aus.
    pub fn stage_wrapping(&mut self, wrapping: &Wrapping) -> Result<()> {
        write_wrapping(&self.conn, wrapping, "next_")
    }

    /// Führt mehrere Änderungen als eine aus: entweder alle oder keine.
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

    /// Beginnt eine Sammeländerung. Jedem `begin` muss genau ein `end` folgen.
    pub fn begin(&mut self) -> Result<()> {
        Ok(self.conn.execute_batch("BEGIN IMMEDIATE")?)
    }

    /// Schließt eine Sammeländerung ab: übernehmen oder alles verwerfen.
    pub fn end(&mut self, commit: bool) -> Result<()> {
        Ok(self.conn.execute_batch(if commit { "COMMIT" } else { "ROLLBACK" })?)
    }

    /// Führt `work` ganz oder gar nicht aus, auch innerhalb einer Sammeländerung.
    fn atomic<T>(&self, work: impl FnOnce() -> Result<T>) -> Result<T> {
        self.conn.execute_batch("SAVEPOINT schritt")?;
        match work() {
            Ok(value) => {
                self.conn.execute_batch("RELEASE schritt")?;
                Ok(value)
            }
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK TO schritt; RELEASE schritt");
                Err(e)
            }
        }
    }

    /// Schreibt einen Umschlag an die Stelle seines Datensatzes.
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
        Ok(Some(State { vault: array(&vault, "Tresor-Kennung")?, revision: revision.max(0) as u64, deleted, dirty, synced: synced.max(0) as u64 }))
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

    /// Ändert oder löscht einen lebenden Datensatz.
    ///
    /// Kennt der Server ihn schon, wird sein Stand vor der ersten wartenden Änderung als Ausgangsstand
    /// aufgehoben, und weitere Änderungen erhöhen die Revision nicht noch einmal: Der Server nimmt nur genau
    /// „eins über dem, was er hat“ an (`docs/sync.md`, „Abgleich“).
    fn change(&mut self, id: &Id, deleted: bool, plaintext: &[u8]) -> Result<()> {
        let state = self.state(id)?.filter(|s| !s.deleted).ok_or(VaultError::NotFound)?;
        let (keys, vault) = self.writable(&state.vault)?;
        let waiting = state.dirty && state.synced > 0;
        let revision = if waiting { state.revision } else { state.revision + 1 };
        let envelope = seal(keys, &state.vault, &vault.key, *id, revision, deleted, plaintext);
        self.atomic(|| {
            if !state.dirty && state.synced > 0 {
                let current = self.envelope(id)?.ok_or(VaultError::Corrupt("Datensatz"))?;
                self.store_base(&current)?;
            }
            self.store(&state.vault, &envelope, true, state.synced)
        })
    }

    /// Legt einen Datensatz im persönlichen Tresor an (`id` = None) oder ersetzt einen bestehenden, in welchem
    /// Tresor er auch liegt. Liefert die Kennung.
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

    /// Legt einen neuen Datensatz in einem bestimmten Tresor an.
    pub fn put_in(&mut self, vault: &Id, plaintext: &[u8]) -> Result<Id> {
        let (keys, vault_keys) = self.writable(vault)?;
        let id: Id = crypto::random();
        self.store(vault, &seal(keys, vault, &vault_keys.key, id, 1, false, plaintext), true, 0)?;
        Ok(id)
    }

    /// Löscht, indem ein Grabstein hinterlassen wird. So kommt das Löschen auch auf anderen Geräten an.
    pub fn delete(&mut self, id: &Id) -> Result<()> {
        self.keys()?;
        self.change(id, true, &[])
    }

    fn check(keys: &Unlocked, row: &Row) -> Option<Zeroizing<Vec<u8>>> {
        let vault_id = Id::try_from(row.vault_id.as_slice()).ok()?;
        unseal(&vault_id, keys.vaults.get(&vault_id)?, &keys.public, &row.envelope()?)
    }

    /// Liest und prüft alle Datensätze aller Tresore. Grabsteine werden mitgeprüft, damit sich das Löschen
    /// nicht fälschen lässt.
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
                    id: row.id.as_slice().try_into().expect("Länge in check geprüft"),
                    vault: row.vault_id.as_slice().try_into().expect("Länge in check geprüft"),
                    revision: row.revision as u64,
                    modified_at: row.modified_at,
                    data,
                }),
                None => listing.damaged.push(row.id),
            }
        }
        Ok(listing)
    }

    /// Entfernt Grabsteine, die älter sind als `max_age_ms`. Mit eingerichtetem Abgleich bleiben die, von
    /// denen der Server noch nichts weiß: Sonst käme das Gelöschte von dort zurück.
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

    /// Schreibt eine folgerichtige Kopie. Sie ist genauso verschlüsselt und braucht dasselbe Master-Passwort.
    /// Die Anmeldung am Sync-Server geht nicht mit: Wer eine Sicherung einspielt, meldet sich neu an und
    /// gleicht von vorn ab.
    pub fn backup(&self, dest: &Path) -> Result<()> {
        self.copy_to(dest)?;
        let copy = Connection::open(dest)?;
        copy.execute_batch("DELETE FROM meta WHERE key = 'link'; UPDATE vaults SET cursor = 0;")?;
        Ok(())
    }

    // ── Konto ────────────────────────────────────────────────────────────────────────────────────────────

    /// Die eigenen öffentlichen Schlüssel: Signatur (Ed25519) und Empfang geteilter Tresor-Schlüssel (X25519).
    pub fn public_keys(&self) -> Result<([u8; 32], [u8; 32])> {
        let keys = self.keys()?;
        Ok((keys.public, PublicKey::from(&keys.exchange).to_bytes()))
    }

    /// Prüft das Master-Passwort und liefert den Schlüssel für die Anmeldung am Sync-Server.
    pub fn auth_key(&self, password: &str) -> Result<Key> {
        Ok(self.open_account(password)?.1)
    }

    /// Was der Server aufbewahrt, damit sich ein weiteres Gerät mit dem Master-Passwort anmelden kann.
    pub fn account(&self) -> Result<Account> {
        let personal: Id = array(&self.meta("default_vault")?, "Tresor-Kennung")?;
        let (personal_nonce, personal_wrapped) = self
            .conn
            .query_row("SELECT nonce, wrapped_key FROM vaults WHERE id = ?1", [personal.as_slice()], |row| Ok((blob(row, 0)?, blob(row, 1)?)))
            .optional()?
            .ok_or(VaultError::Corrupt("Tresor-Schlüssel"))?;
        Ok(Account {
            salt: array(&self.meta("salt")?, "Salz")?,
            kdf: KdfParams::from_bytes(&self.meta("kdf")?).ok_or(VaultError::Corrupt("Aufwand der Schlüsselableitung"))?,
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

    /// Legt auf einem neuen Gerät die Tresor-Datei eines bestehenden Kontos an und öffnet sie. Passt das
    /// Master-Passwort nicht zu dem, was der Server geliefert hat, entsteht keine Datei.
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

    /// Die Anmeldung am Sync-Server (Adresse, Konto, Geräte-Token …), wie sie `glowport-sync` ablegt.
    /// Verschlüsselt mit dem Kontoschlüssel und an diese Datei gebunden.
    pub fn link(&self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let keys = self.keys()?;
        let Some(stored) = self.meta_opt("link")? else { return Ok(None) };
        open_small(&keys.account_key, AAD_LINK, &self.device_id()?, &stored).map(Some).ok_or(VaultError::Corrupt("Anmeldung am Sync-Server"))
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

    /// Verschlüsselt etwas Kleines so, dass es nur die Geräte dieses Kontos lesen, etwa den Namen eines
    /// Geräts, den der Server aufbewahrt.
    pub fn seal_own(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(seal_small(&self.keys()?.account_key, AAD_OWN, &[], data))
    }

    pub fn open_own(&self, sealed: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>> {
        Ok(open_small(&self.keys()?.account_key, AAD_OWN, &[], sealed))
    }

    /// Übernimmt die Datensätze eines anderen offenen Tresors in den persönlichen Tresor: neu verschlüsselt und
    /// selbst signiert, unter denselben Kennungen, damit Verweise untereinander halten. Gedacht für ein Gerät,
    /// das schon Daten hatte und sich mit einem bestehenden Konto verbindet. Liefert die Zahl der übernommenen.
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

    // ── Kontakte und Hinweise ────────────────────────────────────────────────────────────────────────────

    /// Die öffentlichen Schlüssel, unter denen ein anderes Konto zuletzt gesehen wurde.
    pub fn contact(&self, account: &Id) -> Result<Option<Contact>> {
        let keys = self.keys()?;
        let stored = self.conn.query_row("SELECT sealed FROM contacts WHERE account = ?1", [account.as_slice()], |row| blob(row, 0)).optional()?;
        Ok(stored.and_then(|stored| open_small(&keys.account_key, AAD_CONTACT, account, &stored)).and_then(|plain| serde_json::from_slice(&plain).ok()))
    }

    /// Merkt sich die Schlüssel eines Kontos. Ändern sie sich später, kann das Programm warnen.
    pub fn remember_contact(&mut self, account: &Id, contact: &Contact) -> Result<()> {
        let keys = self.keys()?;
        let plain = serde_json::to_vec(contact).map_err(|_| VaultError::Corrupt("Kontakt"))?;
        self.conn.execute("INSERT OR REPLACE INTO contacts (account, sealed) VALUES (?1, ?2)", params![account.as_slice(), seal_small(&keys.account_key, AAD_CONTACT, account, &plain)])?;
        Ok(())
    }

    /// Hält einen Hinweis aus dem Abgleich fest (Inhalt bestimmt `glowport-sync`). Ältere als die letzten 200 fallen heraus.
    pub fn add_notice(&mut self, data: &[u8]) -> Result<()> {
        let keys = self.keys()?;
        self.conn.execute("INSERT INTO notices (at, sealed) VALUES (?1, ?2)", params![now_ms(), seal_small(&keys.account_key, AAD_NOTICE, &[], data)])?;
        self.conn.execute("DELETE FROM notices WHERE id <= (SELECT max(id) FROM notices) - ?1", [MAX_NOTICES])?;
        Ok(())
    }

    /// Alle Hinweise, älteste zuerst.
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

    /// Entfernt die Hinweise bis einschließlich dieser Nummer.
    pub fn clear_notices(&mut self, up_to: i64) -> Result<()> {
        self.keys()?;
        self.conn.execute("DELETE FROM notices WHERE id <= ?1", [up_to])?;
        Ok(())
    }

    // ── Tresore ──────────────────────────────────────────────────────────────────────────────────────────

    pub fn personal(&self) -> Result<Id> {
        Ok(self.keys()?.personal)
    }

    /// Alle offenen Tresore, der persönliche zuerst.
    pub fn vaults(&self) -> Result<Vec<VaultInfo>> {
        let keys = self.keys()?;
        let mut out = Vec::with_capacity(keys.vaults.len());
        for (id, vault) in &keys.vaults {
            out.push(VaultInfo { id: *id, kind: vault.kind, epoch: vault.epoch, cursor: self.cursor(id)?, role: vault.role(&keys.public).unwrap_or(Role::Read), roster: vault.roster.clone() });
        }
        out.sort_by_key(|v| v.kind == Kind::Shared);
        Ok(out)
    }

    /// In welchem Tresor ein Datensatz liegt (auch ein gelöschter).
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
        self.unlocked.as_mut().expect("nur bei offenem Tresor aufgerufen").vaults.insert(id, vault);
    }

    /// Legt einen geteilten Tresor an; man selbst ist Besitzer und zunächst einziges Mitglied.
    /// `account` und `name` sind die des eigenen Kontos auf dem Server.
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

    /// Nimmt einen geteilten Tresor auf, zu dem man eingeladen wurde: Mitgliederliste und der für einen
    /// selbst verpackte Schlüssel, beides vom Server.
    pub fn join_shared(&mut self, id: &Id, sealed_key: &[u8], roster: &[u8]) -> Result<()> {
        let keys = self.keys()?;
        if keys.vaults.contains_key(id) {
            return Err(VaultError::AlreadyExists);
        }
        let parsed = roster::verify(roster, id, None)?;
        if parsed.role(&keys.public).is_none() {
            return Err(VaultError::NotMember);
        }
        let key = share::open(sealed_key, id, parsed.epoch, &keys.exchange).map_err(|_| VaultError::Corrupt("Tresor-Schlüssel"))?;
        let entry = VaultKeys { key, kind: Kind::Shared, epoch: parsed.epoch, roster: Some(parsed) };
        self.store_vault(keys, id, &entry, Some(roster))?;
        self.insert_vault(*id, entry);
        Ok(())
    }

    /// Die signierte Mitgliederliste, wie sie zum Server geht.
    pub fn roster_blob(&self, vault: &Id) -> Result<Vec<u8>> {
        let (keys, _) = self.vault_keys(vault)?;
        let stored = self.conn.query_row("SELECT roster FROM vaults WHERE id = ?1", [vault.as_slice()], |row| blob(row, 0))?;
        Ok(open_small(&keys.account_key, AAD_ROSTER, vault, &stored).ok_or(VaultError::Corrupt("Mitgliederliste"))?.to_vec())
    }

    /// Signiert als Besitzer eine neue Mitgliederliste, ohne sie schon zu übernehmen.
    pub fn sign_roster(&self, vault: &Id, roster: &Roster) -> Result<Vec<u8>> {
        let (keys, current) = self.vault_keys(vault)?;
        let previous = current.roster.as_ref().ok_or(VaultError::NotOwner)?;
        if previous.role(&keys.public) != Some(Role::Owner) {
            return Err(VaultError::NotOwner);
        }
        Ok(roster::sign(roster, Some(previous), &keys.signing)?)
    }

    /// Erzeugt als Besitzer die Liste, mit der der Besitz an ein Mitglied (dessen Signaturschlüssel) übergeht.
    /// Man selbst behält das Schreibrecht. Übernommen wird sie wie jede andere mit [`Vault::set_roster`].
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

    /// Übernimmt eine neue Mitgliederliste beim selben Schlüsselstand: neue Mitglieder, mehr Rechte, Übergabe
    /// des Besitzes. Wer dabei Rechte verlöre, bräuchte einen Schlüsseltausch ([`Vault::apply_rotation`]).
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
        let entry = self.unlocked.as_mut().and_then(|u| u.vaults.get_mut(vault)).expect("oben gefunden");
        entry.roster = Some(roster);
        Ok(())
    }

    /// Verpackt den Schlüssel eines Tresors für ein Mitglied (dessen öffentlicher X25519-Schlüssel).
    pub fn seal_key_for(&self, vault: &Id, recipient: &[u8; 32]) -> Result<Vec<u8>> {
        let (_, current) = self.vault_keys(vault)?;
        share::seal(&current.key, vault, current.epoch, recipient).map_err(|_| VaultError::Corrupt("öffentlicher Schlüssel"))
    }

    /// Entfernt einen geteilten Tresor samt allen Datensätzen von diesem Gerät.
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
        self.unlocked.as_mut().expect("oben geprüft").vaults.remove(vault);
        Ok(())
    }

    // ── Abgleich ─────────────────────────────────────────────────────────────────────────────────────────

    /// Bis zu welcher Nummer des Servers alles geholt ist.
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

    /// Die Datensätze eines Tresors, deren Änderung der Server noch nicht hat, so wie sie hinausgehen.
    pub fn pending(&self, vault: &Id) -> Result<Vec<Envelope>> {
        self.vault_keys(vault)?;
        Ok(self.rows(vault, true)?.into_iter().map(|(envelope, _)| envelope).collect())
    }

    /// Wie [`Vault::pending`], dazu je Datensatz die Revision, auf der die Änderung aufsetzt: der Stand, den
    /// der Server zuletzt bestätigt oder geliefert hat (0 = kennt er nicht). Der Server nimmt nur an, was auf
    /// seinem Stand aufsetzt.
    pub fn outgoing(&self, vault: &Id) -> Result<Vec<(Envelope, u64)>> {
        let mut out = Vec::new();
        for envelope in self.pending(vault)? {
            let base = self.state(&envelope.id)?.map_or(0, |state| state.synced);
            out.push((envelope, base));
        }
        Ok(out)
    }

    /// Was dieses Gerät für den Stand des Servers hält: je Datensatz, den der Server kennt, Kennung, Revision
    /// und Löschmarke. Wo eine eigene Änderung wartet, zählt der Stand davor.
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

    /// Die Prüfsumme über das, was dieses Gerät für den Stand des Servers hält (siehe [`state_digest`]).
    pub fn believed_digest(&self, vault: &Id) -> Result<[u8; 32]> {
        Ok(state_digest(self.believed(vault)?.into_iter().filter(|(_, _, deleted)| !deleted).map(|(id, revision, _)| (id, revision))))
    }

    /// Wie viele Datensätze dieses Gerät als abgeglichen kennt, die im vollständigen Stand des Servers
    /// (`rows`) fehlen oder dort älter sind. Mehr als null heißt: Der Server hat etwas verloren.
    pub fn ahead_of(&self, vault: &Id, rows: &[Envelope]) -> Result<usize> {
        let server: BTreeMap<Id, u64> = rows.iter().map(|row| (row.id, row.revision)).collect();
        Ok(self
            .believed(vault)?
            .into_iter()
            .filter(|(id, revision, deleted)| match server.get(id) {
                Some(theirs) => revision > theirs,
                // Ein Grabstein, den der Server nicht mehr führt, ist dort nur abgelaufen.
                None => !deleted,
            })
            .count())
    }

    /// Öffnet, was zu einer Einladung gehört, ohne den Tresor aufzunehmen: prüft die Mitgliederliste, entpackt
    /// den für einen selbst verpackten Schlüssel und entschlüsselt die gelieferten Datensätze. So lässt sich
    /// der Name des Tresors zeigen, bevor jemand annimmt.
    pub fn peek_invitation(&self, vault: &Id, sealed_key: &[u8], roster: &[u8], rows: &[Envelope]) -> Result<(Roster, Vec<Zeroizing<Vec<u8>>>)> {
        let keys = self.keys()?;
        let parsed = roster::verify(roster, vault, None)?;
        if parsed.role(&keys.public).is_none() {
            return Err(VaultError::NotMember);
        }
        let key = share::open(sealed_key, vault, parsed.epoch, &keys.exchange).map_err(|_| VaultError::Corrupt("Tresor-Schlüssel"))?;
        let entry = VaultKeys { key, kind: Kind::Shared, epoch: parsed.epoch, roster: Some(parsed.clone()) };
        let plain = rows.iter().filter(|row| !row.deleted).filter_map(|row| unseal(vault, &entry, &keys.public, row)).collect();
        Ok((parsed, plain))
    }

    /// Der Server hat einen älteren Stand als dieses Gerät, etwa nach dem Zurückholen aus einer Sicherung
    /// (`rows`: alles, was er zu diesem Tresor hat). Was hier neuer ist, setzt auf seinem Stand auf und geht
    /// eine Revision höher wieder hinaus, damit es auch jedes andere Gerät als neu annimmt; was er gar nicht
    /// kennt, gilt als neu; was bei ihm neuer ist, wird wie gewohnt übernommen. Wer nur lesen darf, übernimmt nur.
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

    /// Der Server hat `sent` angenommen. Was seitdem nicht weiter geändert wurde, gilt als abgeglichen; was
    /// doch, wartet weiter, jetzt auf dem angenommenen Stand als Ausgang.
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

    /// Verwirft wartende Änderungen eines Tresors, etwa wenn man dort nicht mehr schreiben darf: Es gilt
    /// wieder der zuletzt abgeglichene Stand; nie Abgeglichenes verschwindet. Liefert die Zahl.
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

    /// Der Server hat statt der Änderungen den ganzen Stand eines Tresors geliefert (`keep`: die Kennungen
    /// darin), weil dieses Gerät länger weg war, als er Grabsteine aufhebt. Was hier als abgeglichen galt und
    /// dort fehlt, ist inzwischen gelöscht; wartende Änderungen daran gelten als neu. Liefert die Zahl der entfernten.
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

    /// Übernimmt einen Datensatz vom Server. `old` sind die Schlüssel, unter denen die Fassungen dieses Geräts
    /// liegen, `new` die, unter denen der gelieferte liegt und künftig alles liegt; außer beim Schlüsseltausch
    /// (`rotation`) sind beide dieselben.
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
            // Hier wartet nichts: Es gilt, was neuer ist. Beim Schlüsseltausch kommt dieselbe Revision neu verschlüsselt.
            if remote.revision > state.revision || (rotation && remote.revision == state.revision) {
                return take(applied);
            }
            // Dieselbe Revision noch einmal ist in Ordnung, eine ältere oder eine andere gleiche nicht.
            if remote.revision < state.revision || current.nonce != remote.nonce {
                applied.rejected.push(id);
            }
            return Ok(());
        }

        // Eine eigene Änderung wartet.
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
            // Der Server hat nichts Neues. Beim Schlüsseltausch ziehen Ausgangsstand und eigene Fassung auf den neuen Schlüssel um.
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

    /// Übernimmt Datensätze vom Server in einen Tresor. Jeder wird geprüft (Signatur, Schreibrecht des Autors,
    /// Schlüssel); wo eine eigene Änderung wartet, wird zusammengeführt (`docs/sync.md`).
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

    /// Bereitet als Besitzer den Schlüsseltausch vor: neuer Schlüssel, alle Datensätze damit verschlüsselt und
    /// selbst signiert (Revisionen unverändert), die neue Mitgliederliste, der Schlüssel für jedes Mitglied.
    pub fn prepare_rotation(&self, vault: &Id, roster: &Roster) -> Result<Rotation> {
        let (keys, current) = self.vault_keys(vault)?;
        let previous = current.roster.as_ref().ok_or(VaultError::NotOwner)?;
        if previous.role(&keys.public) != Some(Role::Owner) {
            return Err(VaultError::NotOwner);
        }
        if roster.epoch != current.epoch + 1 {
            return Err(RosterError::Stale.into());
        }
        // Die neu verschlüsselten Datensätze tragen die eigene Signatur; sie gelten nur, wenn man weiter schreiben darf.
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
            // Was sich schon vorher nicht öffnen ließ, lässt sich nicht hinüberretten.
            let Some(plain) = unseal(vault, current, &keys.public, &envelope) else { continue };
            let mut fresh = seal(keys, vault, &key, envelope.id, envelope.revision, envelope.deleted, &plain);
            fresh.modified_at = envelope.modified_at;
            records.push(fresh);
        }
        Ok(Rotation { vault: *vault, epoch: roster.epoch, roster: blob, keys: sealed_keys, records, key, parsed: roster.clone() })
    }

    /// Der Server hat den vorbereiteten Schlüsseltausch angenommen: jetzt auch hier umstellen.
    pub fn commit_rotation(&mut self, rotation: Rotation) -> Result<Applied> {
        let entry = VaultKeys { key: rotation.key, kind: Kind::Shared, epoch: rotation.epoch, roster: Some(rotation.parsed) };
        self.switch_keys(&rotation.vault, entry, &rotation.roster, &rotation.records)
    }

    /// Übernimmt den Schlüsseltausch eines Besitzers: die neue Mitgliederliste, den für einen selbst verpackten
    /// Schlüssel und alle Datensätze des Tresors. Ist man nicht mehr Mitglied, scheitert es mit `NotMember`;
    /// dann bleibt nur [`Vault::remove_vault`].
    pub fn apply_rotation(&mut self, vault: &Id, sealed_key: &[u8], roster: &[u8], rows: &[Envelope]) -> Result<Applied> {
        let (keys, current) = self.vault_keys(vault)?;
        let parsed = roster::verify(roster, vault, Some(current.roster.as_ref().ok_or(VaultError::NotFound)?))?;
        if parsed.epoch <= current.epoch {
            return Err(RosterError::Stale.into());
        }
        if parsed.role(&keys.public).is_none() {
            return Err(VaultError::NotMember);
        }
        let key = share::open(sealed_key, vault, parsed.epoch, &keys.exchange).map_err(|_| VaultError::Corrupt("Tresor-Schlüssel"))?;
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
            // Was jetzt noch unter dem alten Schlüssel liegt, kam nicht (gültig) mit: Eigene wartende Änderungen
            // ziehen um und gelten als neu, alles andere gibt es beim Server nicht mehr.
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

    /// Eigene Datei je Test; beim Verlassen wird aufgeräumt.
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

    /// Verändert die Datei von außen, so wie es ein Angreifer mit Schreibzugriff könnte.
    fn tamper(path: &Path, sql: &str) {
        let conn = Connection::open(path).unwrap();
        assert!(conn.execute(sql, []).unwrap() > 0, "Manipulation hat nichts getroffen: {sql}");
    }

    #[test]
    fn create_lock_unlock_round_trips() {
        let temp = Temp::new("roundtrip");
        let mut vault = Vault::create(&temp.0, "richtig", FAST).unwrap();
        vault.put(None, b"eins").unwrap();
        vault.put(None, b"zwei").unwrap();
        vault.lock();
        assert!(matches!(vault.list(), Err(VaultError::Locked)));
        drop(vault);

        let mut vault = Vault::open(&temp.0).unwrap();
        assert!(!vault.is_unlocked());
        vault.unlock("richtig").unwrap();
        assert_eq!(texts(&vault), ["eins", "zwei"]);
    }

    #[test]
    fn wrong_password_is_rejected_and_changes_nothing() {
        let temp = Temp::new("wrongpw");
        let mut vault = Vault::create(&temp.0, "richtig", FAST).unwrap();
        vault.put(None, b"eins").unwrap();
        drop(vault);
        let before = std::fs::read(&temp.0).unwrap();

        let mut vault = Vault::open(&temp.0).unwrap();
        assert!(matches!(vault.unlock("falsch"), Err(VaultError::WrongPassword)));
        assert!(matches!(vault.unlock(""), Err(VaultError::WrongPassword)));
        assert!(!vault.is_unlocked());
        drop(vault);
        assert_eq!(std::fs::read(&temp.0).unwrap(), before);
    }

    #[test]
    fn locked_vault_refuses_everything() {
        let temp = Temp::new("locked");
        let mut vault = Vault::create(&temp.0, "richtig", FAST).unwrap();
        let id = vault.put(None, b"eins").unwrap();
        vault.lock();
        assert!(matches!(vault.put(None, b"x"), Err(VaultError::Locked)));
        assert!(matches!(vault.put(Some(id), b"x"), Err(VaultError::Locked)));
        assert!(matches!(vault.delete(&id), Err(VaultError::Locked)));
        assert!(matches!(vault.list(), Err(VaultError::Locked)));
    }

    #[test]
    fn update_raises_revision_and_delete_leaves_tombstone() {
        let temp = Temp::new("revisions");
        let mut vault = Vault::create(&temp.0, "richtig", FAST).unwrap();
        let id = vault.put(None, b"alt").unwrap();
        assert_eq!(vault.put(Some(id), b"neu").unwrap(), id);
        let listing = vault.list().unwrap();
        assert_eq!((listing.records.len(), listing.records[0].revision, listing.records[0].data.as_slice()), (1, 2, b"neu".as_slice()));

        vault.delete(&id).unwrap();
        assert!(vault.list().unwrap().records.is_empty());
        assert!(matches!(vault.put(Some(id), b"wieder"), Err(VaultError::NotFound)));
        assert!(matches!(vault.delete(&id), Err(VaultError::NotFound)));
        assert!(matches!(vault.put(Some([9; 16]), b"fremd"), Err(VaultError::NotFound)));

        let (revision, deleted): (i64, bool) =
            vault.conn.query_row("SELECT revision, deleted FROM records", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!((revision, deleted), (3, true), "Grabstein mit höherer Revision");
        assert_eq!(vault.purge_tombstones(60_000).unwrap(), 0, "frischer Grabstein bleibt");
        assert_eq!(vault.purge_tombstones(-1).unwrap(), 1);
    }

    #[test]
    fn every_tampering_is_detected() {
        let cases = [
            ("Schlüsseltext", "UPDATE records SET ciphertext = substr(ciphertext, 1, 2) || x'00' || substr(ciphertext, 4)"),
            ("Nonce", "UPDATE records SET nonce = x'000000000000000000000000000000000000000000000000'"),
            ("Signatur", "UPDATE records SET signature = substr(signature, 1, 10) || x'00' || substr(signature, 12)"),
            ("Revision", "UPDATE records SET revision = revision + 1"),
            ("Löschmarke gesetzt", "UPDATE records SET deleted = 1"),
            ("Autor", "UPDATE records SET author = x'0000000000000000000000000000000000000000000000000000000000000000'"),
            ("Tresor-Kennung", "UPDATE records SET vault_id = (SELECT id FROM records LIMIT 1)"),
            ("Kennung", "UPDATE records SET id = x'01010101010101010101010101010101'"),
        ];
        for (what, sql) in cases {
            let temp = Temp::new(&format!("tamper-{}", what.replace(' ', "-")));
            let mut vault = Vault::create(&temp.0, "richtig", FAST).unwrap();
            vault.put(None, b"genau ein Datensatz mit etwas Inhalt").unwrap();
            // Die Tresor-Kennung zeigt per Fremdschlüssel auf `vaults`; für diesen Fall braucht es dort einen zweiten Eintrag.
            if what == "Tresor-Kennung" {
                tamper(&temp.0, "INSERT INTO vaults (id, nonce, wrapped_key) SELECT id, nonce, ciphertext FROM records");
            }
            tamper(&temp.0, sql);
            let listing = vault.list().unwrap();
            assert!(listing.records.is_empty(), "{what}: veränderter Datensatz wurde angenommen");
            assert_eq!(listing.damaged.len(), 1, "{what}: Veränderung nicht gemeldet");
        }
    }

    #[test]
    fn swapped_and_resurrected_records_are_detected() {
        let temp = Temp::new("swap");
        let mut vault = Vault::create(&temp.0, "richtig", FAST).unwrap();
        let a = vault.put(None, b"Host A").unwrap();
        let b = vault.put(None, b"Host B").unwrap();
        let conn = Connection::open(&temp.0).unwrap();

        // Inhalt von A an die Stelle von B setzen (samt Nonce und Signatur).
        conn.execute(
            "UPDATE records SET (nonce, ciphertext, signature) = (SELECT nonce, ciphertext, signature FROM records WHERE id = ?1) WHERE id = ?2",
            params![a.as_slice(), b.as_slice()],
        )
        .unwrap();
        let listing = vault.list().unwrap();
        assert_eq!(listing.records.len(), 1);
        assert_eq!(listing.damaged, [b.to_vec()]);

        // Einen Grabstein wieder „lebendig“ machen.
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
            drop(Vault::create(&temp.0, "richtig", FAST).unwrap());
            tamper(&temp.0, sql);
            assert!(matches!(Vault::open(&temp.0).unwrap().unlock("richtig"), Err(VaultError::WrongPassword)), "{sql}");
        }
        // Ein ausgetauschter öffentlicher Schlüssel fällt beim Entpacken des privaten auf.
        let temp = Temp::new("header-key");
        drop(Vault::create(&temp.0, "richtig", FAST).unwrap());
        tamper(&temp.0, "UPDATE meta SET value = x'0000000000000000000000000000000000000000000000000000000000000000' WHERE key = 'ed25519_public'");
        assert!(matches!(Vault::open(&temp.0).unwrap().unlock("richtig"), Err(VaultError::Corrupt("ed25519"))));
    }

    #[test]
    fn change_password_keeps_records() {
        let temp = Temp::new("changepw");
        let mut vault = Vault::create(&temp.0, "alt", FAST).unwrap();
        vault.put(None, b"bleibt").unwrap();
        assert!(matches!(vault.change_password("falsch", "neu", FAST), Err(VaultError::WrongPassword)));
        vault.change_password("alt", "neu", FAST).unwrap();
        assert_eq!(texts(&vault), ["bleibt"], "offener Tresor bleibt benutzbar");
        drop(vault);

        let mut vault = Vault::open(&temp.0).unwrap();
        assert!(matches!(vault.unlock("alt"), Err(VaultError::WrongPassword)));
        vault.unlock("neu").unwrap();
        assert_eq!(texts(&vault), ["bleibt"]);
    }

    #[test]
    fn failed_batch_leaves_nothing_behind() {
        let temp = Temp::new("batch");
        let mut vault = Vault::create(&temp.0, "richtig", FAST).unwrap();
        vault.put(None, b"vorher").unwrap();
        let result = vault.batch(|v| {
            v.put(None, b"halb")?;
            v.put(Some([9; 16]), b"gibt es nicht")
        });
        assert!(matches!(result, Err(VaultError::NotFound)));
        assert_eq!(texts(&vault), ["vorher"]);

        vault.batch(|v| v.put(None, b"ganz").map(drop)).unwrap();
        assert_eq!(texts(&vault), ["ganz", "vorher"]);
    }

    #[test]
    fn backup_is_a_working_copy() {
        let temp = Temp::new("backup-src");
        let copy = Temp::new("backup-dst");
        let mut vault = Vault::create(&temp.0, "richtig", FAST).unwrap();
        vault.put(None, b"gesichert").unwrap();
        vault.backup(&copy.0).unwrap();
        vault.put(None, b"danach").unwrap();
        vault.backup(&copy.0).unwrap();

        let mut restored = Vault::open(&copy.0).unwrap();
        assert!(matches!(restored.unlock("falsch"), Err(VaultError::WrongPassword)));
        restored.unlock("richtig").unwrap();
        assert_eq!(texts(&restored), ["danach", "gesichert"]);
    }

    #[test]
    fn create_and_open_reject_bad_files() {
        let temp = Temp::new("badfiles");
        drop(Vault::create(&temp.0, "richtig", FAST).unwrap());
        assert!(matches!(Vault::create(&temp.0, "richtig", FAST), Err(VaultError::AlreadyExists)));

        tamper(&temp.0, "UPDATE meta SET value = x'03000000' WHERE key = 'format_version'");
        assert!(matches!(Vault::open(&temp.0), Err(VaultError::UnsupportedFormat(3))));

        std::fs::write(&temp.0, b"das ist keine Datenbank, sondern nur Text in einer Datei").unwrap();
        assert!(matches!(Vault::open(&temp.0), Err(VaultError::Corrupt(_))));
    }

    #[test]
    fn stored_file_reveals_no_plaintext() {
        let temp = Temp::new("leak");
        let mut vault = Vault::create(&temp.0, "richtig", FAST).unwrap();
        vault.put(None, br#"{"t":"host","name":"geheimer-server","password":"hunter2-sehr-geheim"}"#).unwrap();
        drop(vault);
        let bytes = std::fs::read(&temp.0).unwrap();
        for needle in [b"geheimer-server".as_slice(), b"hunter2", b"\"host\"", b"richtig"] {
            assert!(!bytes.windows(needle.len()).any(|w| w == needle), "Klartext in der Datei gefunden");
        }
    }

    #[test]
    fn device_key_unlocks_without_password_and_survives_a_password_change() {
        let temp = Temp::new("devicekey");
        let mut vault = Vault::create(&temp.0, "alt", FAST).unwrap();
        vault.put(None, b"da").unwrap();
        let key = vault.device_key().unwrap();
        vault.change_password("alt", "neu", FAST).unwrap();
        vault.lock();
        assert!(matches!(vault.device_key(), Err(VaultError::Locked)));
        drop(vault);

        let mut vault = Vault::open(&temp.0).unwrap();
        assert!(matches!(vault.unlock_with_key(&crypto::random_key()), Err(VaultError::StaleDeviceKey)));
        assert!(!vault.is_unlocked());
        vault.unlock_with_key(&key).unwrap();
        assert_eq!(texts(&vault), ["da"]);
        assert_eq!(vault.device_id().unwrap().len(), 16);

        // Ein anderer Tresor nimmt den Schlüssel nicht an.
        let other = Temp::new("devicekey-other");
        let mut other_vault = Vault::create(&other.0, "x", FAST).unwrap();
        other_vault.lock();
        assert!(matches!(other_vault.unlock_with_key(&key), Err(VaultError::StaleDeviceKey)));
    }

    /// Misst das Entsperren mit den Vorgabewerten. Aufruf: `cargo test -p glowport-core --release -- --ignored --nocapture`.
    #[test]
    #[ignore = "Messung, kein Test"]
    fn measure_default_unlock() {
        let temp = Temp::new("measure");
        drop(Vault::create(&temp.0, "richtig", KdfParams::DEFAULT).unwrap());
        let mut vault = Vault::open(&temp.0).unwrap();
        let start = Instant::now();
        vault.unlock("richtig").unwrap();
        println!("Entsperren mit {:?}: {} ms", KdfParams::DEFAULT, start.elapsed().as_millis());
    }

    // ── Fassung 2: mehrere Tresore, Abgleich, Teilen ─────────────────────────────────────────────────────

    use serde_json::{json, Value};

    /// Eine Datei, die die Version 0.8.0 (Fassung 1) wirklich geschrieben hat: Gruppe „Kunden“, Host „web-01“
    /// in Revision 2 und ein gelöschtes Snippet. Master-Passwort „fixture-passwort“.
    #[test]
    fn a_file_of_format_1_is_migrated_and_keeps_everything() {
        let temp = Temp::new("format1");
        std::fs::copy(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/format1.db"), &temp.0).unwrap();
        let copy = Temp(Vault::migration_copy(&temp.0));

        let mut vault = Vault::open(&temp.0).unwrap();
        assert!(matches!(vault.unlock("falsch"), Err(VaultError::WrongPassword)));
        vault.unlock("fixture-passwort").unwrap();
        let listing = vault.list().unwrap();
        assert!(listing.damaged.is_empty());
        let mut names: Vec<(String, u64)> =
            listing.records.iter().map(|r| (serde_json::from_slice::<Value>(&r.data).unwrap()["name"].as_str().unwrap().to_string(), r.revision)).collect();
        names.sort();
        assert_eq!(names, [("Kunden".to_string(), 1), ("web-01".to_string(), 2)]);
        assert!(listing.records.iter().all(|r| r.vault == vault.personal().unwrap()));
        let tombstones: i64 = vault.conn.query_row("SELECT count(*) FROM records WHERE deleted = 1", [], |r| r.get(0)).unwrap();
        assert_eq!(tombstones, 1, "der Grabstein ist noch da");
        assert_eq!(vault.pending(&vault.personal().unwrap()).unwrap().len(), 3, "alles wartet auf einen ersten Abgleich");

        // Weiterarbeiten und neu öffnen: Die Datei ist jetzt Fassung 2 und wird nicht noch einmal umgestellt.
        vault.put(None, b"neu").unwrap();
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
        Member { account: crypto::hex(&account(seed)), name: format!("konto{seed}"), ed25519: crypto::hex(&ed25519), x25519: crypto::hex(&x25519), role }
    }

    /// Spielt den Server: Was bei `from` wartet, kommt bei `to` an und gilt bei `from` als angenommen.
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

    /// Zwei Geräte desselben Kontos: Das zweite entsteht aus dem, was der Server aufbewahrt.
    fn two_devices(name: &str) -> (Temp, Temp, Vault, Vault, Id) {
        let (ta, tb) = (Temp::new(&format!("{name}-a")), Temp::new(&format!("{name}-b")));
        let a = Vault::create(&ta.0, "richtig", FAST).unwrap();
        let b = Vault::create_from_account(&tb.0, "richtig", &a.account().unwrap()).unwrap();
        let personal = a.personal().unwrap();
        (ta, tb, a, b, personal)
    }

    #[test]
    fn a_second_device_opens_with_the_master_password_only() {
        let (_ta, tb, mut a, mut b, personal) = two_devices("zweites");
        assert_eq!(b.personal().unwrap(), personal);
        assert_eq!(a.public_keys().unwrap(), b.public_keys().unwrap());
        assert_ne!(a.device_id().unwrap(), b.device_id().unwrap(), "jede Datei ist ein eigenes Gerät");
        put_json(&mut a, None, json!({"name": "web"}));
        assert_eq!(deliver(&mut a, &mut b, &personal).taken.len(), 1);
        assert_eq!(values(&b, &personal), [json!({"name": "web"})]);
        assert!(b.pending(&personal).unwrap().is_empty(), "Geholtes wartet nicht");

        let other = Temp::new("zweites-falsch");
        assert!(matches!(Vault::create_from_account(&other.0, "falsch", &a.account().unwrap()), Err(VaultError::WrongPassword)));
        assert!(!other.0.exists(), "kein Rest einer gescheiterten Anmeldung");
        assert!(matches!(Vault::create_from_account(&tb.0, "richtig", &a.account().unwrap()), Err(VaultError::AlreadyExists)));

        // Der Anmeldeschlüssel folgt aus dem Passwort und öffnet nichts.
        let auth = a.auth_key("richtig").unwrap();
        let blob = a.account().unwrap();
        assert_eq!(auth.as_ref(), auth_key("richtig", &blob.salt, blob.kdf).unwrap().as_ref());
        assert!(matches!(a.auth_key("falsch"), Err(VaultError::WrongPassword)));
        assert!(matches!(a.unlock_with_key(&auth), Err(VaultError::StaleDeviceKey)));
    }

    #[test]
    fn a_waiting_change_raises_the_revision_only_once() {
        let (_ta, _tb, mut a, mut b, personal) = two_devices("revision");
        let id = put_json(&mut a, None, json!({"name": "eins"}));
        put_json(&mut a, Some(id), json!({"name": "zwei"}));
        assert_eq!(a.pending(&personal).unwrap()[0].revision, 2, "was der Server nicht kennt, zählt frei hoch");
        deliver(&mut a, &mut b, &personal);
        assert!(a.pending(&personal).unwrap().is_empty());

        put_json(&mut a, Some(id), json!({"name": "drei"}));
        put_json(&mut a, Some(id), json!({"name": "vier"}));
        let pending = a.pending(&personal).unwrap();
        assert_eq!((pending.len(), pending[0].revision), (1, 3), "genau eins über dem Server");
        assert_eq!(a.base(&id).unwrap().unwrap().revision, 2, "der abgeglichene Stand ist aufgehoben");

        // Während das Paket unterwegs ist, wird weiter geändert: Die Bestätigung gilt nur dem Geschickten.
        let sent = a.pending(&personal).unwrap();
        put_json(&mut a, Some(id), json!({"name": "fünf"}));
        b.apply_remote(&personal, &sent).unwrap();
        a.acknowledge(&personal, &sent).unwrap();
        let pending = a.pending(&personal).unwrap();
        assert_eq!((pending.len(), pending[0].revision), (1, 4));
        assert_eq!(values(&b, &personal), [json!({"name": "vier"})]);
        deliver(&mut a, &mut b, &personal);
        assert_eq!(values(&b, &personal), [json!({"name": "fünf"})]);
        assert!(a.base(&id).unwrap().is_none() && a.pending(&personal).unwrap().is_empty());

        // Löschen geht denselben Weg.
        a.delete(&id).unwrap();
        deliver(&mut a, &mut b, &personal);
        assert!(values(&b, &personal).is_empty());
    }

    #[test]
    fn concurrent_changes_are_merged_field_by_field() {
        let (_ta, _tb, mut a, mut b, personal) = two_devices("merge");
        let id = put_json(&mut a, None, json!({"name": "web", "own": {"port": 22}}));
        deliver(&mut a, &mut b, &personal);

        // A ändert den Port und ist zuerst beim Server; B ändert inzwischen den Namen.
        put_json(&mut a, Some(id), json!({"name": "web", "own": {"port": 2222}}));
        put_json(&mut b, Some(id), json!({"name": "web-01", "own": {"port": 22}}));
        let from_a = a.pending(&personal).unwrap();
        a.acknowledge(&personal, &from_a).unwrap();
        let applied = b.apply_remote(&personal, &from_a).unwrap();
        assert_eq!((applied.merged.len(), applied.taken.len(), applied.rejected.len()), (1, 0, 0));
        assert!(applied.merged[0].1.clashes.is_empty());
        let merged = json!({"name": "web-01", "own": {"port": 2222}});
        assert_eq!(values(&b, &personal), std::slice::from_ref(&merged));
        assert_eq!(b.pending(&personal).unwrap()[0].revision, 3, "das Ergebnis liegt eins über dem Server");

        assert_eq!(deliver(&mut b, &mut a, &personal).taken, [id]);
        assert_eq!(values(&a, &personal), [merged]);

        // Das alte Paket noch einmal: abgelehnt, und es ändert nichts.
        let applied = b.apply_remote(&personal, &from_a).unwrap();
        assert_eq!((applied.taken.len(), applied.merged.len(), applied.rejected.len()), (0, 0, 1), "älter als der eigene Stand");
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
        assert_eq!(values(&a, &personal), [json!({"name": "web-01"})], "der Eintrag ist zurück");

        // Umgekehrt: Der Server hat die Änderung schon, hier wurde gelöscht.
        put_json(&mut a, Some(id), json!({"name": "web-02"}));
        b.delete(&id).unwrap();
        assert!(deliver(&mut a, &mut b, &personal).merged[0].1.restored);
        assert_eq!(values(&b, &personal), [json!({"name": "web-02"})]);
        assert!(b.pending(&personal).unwrap().is_empty(), "das eigene Löschen ist verworfen");
    }

    #[test]
    fn forged_and_stale_records_from_the_server_are_refused() {
        let (_ta, _tb, mut a, mut b, personal) = two_devices("faelschen");
        let id = put_json(&mut a, None, json!({"name": "eins"}));
        let first = a.pending(&personal).unwrap();
        deliver(&mut a, &mut b, &personal);
        put_json(&mut a, Some(id), json!({"name": "zwei"}));
        let second = a.pending(&personal).unwrap();
        deliver(&mut a, &mut b, &personal);

        let refused = |b: &mut Vault, envelope: Envelope, what: &str| {
            let applied = b.apply_remote(&personal, &[envelope]).unwrap();
            assert_eq!((applied.rejected.len(), applied.taken.len(), applied.merged.len()), (1, 0, 0), "{what}");
            assert_eq!(values(b, &personal), [json!({"name": "zwei"})], "{what}");
        };
        refused(&mut b, first[0].clone(), "alter Stand");
        let mut changed = second[0].clone();
        changed.ciphertext[3] ^= 1;
        refused(&mut b, changed, "veränderter Inhalt");
        let mut changed = second[0].clone();
        changed.revision = 9;
        refused(&mut b, changed, "Revision hochgesetzt");
        let mut changed = second[0].clone();
        changed.deleted = true;
        refused(&mut b, changed, "als gelöscht ausgegeben");
        let mut changed = second[0].clone();
        changed.id = [3; 16];
        refused(&mut b, changed, "unter anderer Kennung");

        // Ein fremdes Konto hat im persönlichen Tresor nichts zu schreiben, auch nicht mit dem richtigen Schlüssel.
        let other = Temp::new("faelschen-fremd");
        let stranger = Vault::create(&other.0, "x", FAST).unwrap();
        let (keys, vault_keys) = b.vault_keys(&personal).unwrap();
        let forged = seal(stranger.keys().unwrap(), &personal, &vault_keys.key, [4; 16], 1, false, b"{}");
        let _ = keys;
        refused(&mut b, forged, "fremder Autor");
    }

    /// A besitzt einen geteilten Tresor, B darf schreiben, C nur lesen.
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
        let shared = a.create_shared(&account(1), "konto1").unwrap();
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
        let Team { _temps, mut a, mut b, mut c, shared } = team("teilen");
        let infos = b.vaults().unwrap();
        assert_eq!((infos.len(), infos[0].kind, infos[1].kind, infos[1].role), (2, Kind::Personal, Kind::Shared, Role::Write));
        assert_eq!(c.vaults().unwrap()[1].role, Role::Read);

        let host = a.put_in(&shared, br#"{"name":"team-host"}"#).unwrap();
        a.put(None, br#"{"name":"privat"}"#).unwrap();
        let sent = a.pending(&shared).unwrap();
        assert_eq!(sent.len(), 1, "der persönliche Tresor bleibt zu Hause");
        assert_eq!(b.apply_remote(&shared, &sent).unwrap().taken.len(), 1);
        assert_eq!(c.apply_remote(&shared, &sent).unwrap().taken.len(), 1);
        a.acknowledge(&shared, &sent).unwrap();
        assert_eq!(values(&c, &shared), [json!({"name": "team-host"})]);
        assert_eq!(b.vault_of(&host).unwrap(), shared);

        // B darf schreiben, und alle nehmen es an.
        b.put(Some(host), br#"{"name":"team-host","own":{"port":2222}}"#).unwrap();
        let sent = b.pending(&shared).unwrap();
        assert_eq!(a.apply_remote(&shared, &sent).unwrap().taken.len(), 1);
        assert_eq!(c.apply_remote(&shared, &sent).unwrap().taken.len(), 1);
        b.acknowledge(&shared, &sent).unwrap();

        // C darf nicht: Das eigene Programm lehnt ab, und was C trotzdem signiert, nimmt niemand an.
        assert!(matches!(c.put(Some(host), b"{}"), Err(VaultError::ReadOnly)));
        assert!(matches!(c.put_in(&shared, b"{}"), Err(VaultError::ReadOnly)));
        assert!(matches!(c.delete(&host), Err(VaultError::ReadOnly)));
        let (keys, vault_keys) = c.vault_keys(&shared).unwrap();
        let smuggled = seal(keys, &shared, &vault_keys.key, host, 3, false, br#"{"name":"von C"}"#);
        for vault in [&mut a, &mut b] {
            assert_eq!(vault.apply_remote(&shared, std::slice::from_ref(&smuggled)).unwrap().rejected, [host]);
            assert_eq!(values(vault, &shared)[0]["own"]["port"], 2222);
        }

        // Nach dem Sperren und Entsperren ist alles wieder da.
        b.lock();
        b.unlock("b").unwrap();
        assert_eq!(b.vaults().unwrap().len(), 2);
        assert_eq!(values(&b, &shared).len(), 1);

        // Der Server kann niemanden hineinsetzen, und Rechte entzieht nur ein Schlüsseltausch.
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
        let kept = a.put_in(&shared, br#"{"name":"bleibt"}"#).unwrap();
        let edited = a.put_in(&shared, br#"{"name":"alt","own":{"port":22}}"#).unwrap();
        let gone = a.put_in(&shared, br#"{"name":"weg"}"#).unwrap();
        let sent = a.pending(&shared).unwrap();
        b.apply_remote(&shared, &sent).unwrap();
        c.apply_remote(&shared, &sent).unwrap();
        a.acknowledge(&shared, &sent).unwrap();
        a.delete(&gone).unwrap();
        let sent = a.pending(&shared).unwrap();
        b.apply_remote(&shared, &sent).unwrap();
        a.acknowledge(&shared, &sent).unwrap();

        // B hält offline eine Änderung und einen neuen Eintrag, während A das Mitglied C entfernt.
        b.put(Some(edited), br#"{"name":"neu","own":{"port":22}}"#).unwrap();
        b.put_in(&shared, br#"{"name":"von B"}"#).unwrap();

        let mut roster = a.vaults().unwrap()[1].roster.clone().unwrap();
        roster.members.retain(|m| m.name != "konto3");
        roster.version += 1;
        assert!(matches!(a.prepare_rotation(&shared, &roster), Err(VaultError::Roster(RosterError::Stale))), "ohne neuen Schlüsselstand");
        roster.epoch += 1;
        a.put(Some(kept), br#"{"name":"bleibt!"}"#).unwrap();
        assert!(matches!(a.prepare_rotation(&shared, &roster), Err(VaultError::Pending)));
        let sent = a.pending(&shared).unwrap();
        a.acknowledge(&shared, &sent).unwrap();
        assert!(matches!(b.prepare_rotation(&shared, &roster), Err(VaultError::NotOwner)));

        let rotation = a.prepare_rotation(&shared, &roster).unwrap();
        assert_eq!((rotation.epoch, rotation.keys.len(), rotation.records.len()), (2, 2, 3), "auch der Grabstein zieht um");
        let (blob, records) = (rotation.roster.clone(), rotation.records.clone());
        let key_for = |vault: &Vault| rotation.keys.iter().find(|(key, _)| *key == vault.public_keys().unwrap().0).map(|(_, sealed)| sealed.clone());
        let (for_b, for_c) = (key_for(&b).unwrap(), key_for(&c));
        assert!(for_c.is_none(), "für das entfernte Mitglied gibt es keinen Schlüssel");
        a.commit_rotation(rotation).unwrap();
        assert_eq!(a.vaults().unwrap()[1].epoch, 2);
        assert_eq!(values(&a, &shared), [json!({"name": "alt", "own": {"port": 22}}), json!({"name": "bleibt!"})]);
        assert!(a.pending(&shared).unwrap().is_empty());

        // C ist draußen: Die neue Liste nennt C nicht, der neue Schlüssel ist nicht für C, die neuen Datensätze bleiben zu.
        assert!(matches!(c.apply_rotation(&shared, &for_b, &blob, &records), Err(VaultError::NotMember)));
        assert_eq!(c.apply_remote(&shared, &records).unwrap().rejected.len(), 3);
        c.remove_vault(&shared).unwrap();
        assert!(c.vaults().unwrap().len() == 1 && c.list().unwrap().records.is_empty());

        // B zieht um und behält, was bei ihm wartete.
        let applied = b.apply_rotation(&shared, &for_b, &blob, &records).unwrap();
        assert!(applied.rejected.is_empty());
        assert_eq!(values(&b, &shared), [json!({"name": "bleibt!"}), json!({"name": "neu", "own": {"port": 22}}), json!({"name": "von B"})]);
        let pending = b.pending(&shared).unwrap();
        assert_eq!(pending.len(), 2);
        assert_eq!(a.apply_remote(&shared, &pending).unwrap().taken.len(), 2, "unter dem neuen Schlüssel, für A lesbar");
        b.acknowledge(&shared, &pending).unwrap();
        assert_eq!(values(&a, &shared), values(&b, &shared));

        // Alles übersteht das Sperren, und der alte Stand lässt sich nicht noch einmal unterschieben.
        b.lock();
        b.unlock("b").unwrap();
        assert_eq!(values(&b, &shared).len(), 3);
        assert!(matches!(b.apply_rotation(&shared, &for_b, &blob, &records), Err(VaultError::Roster(RosterError::Stale))));
    }

    #[test]
    fn discarding_waiting_changes_returns_to_the_synced_state() {
        let (_ta, _tb, mut a, mut b, personal) = two_devices("verwerfen");
        let id = put_json(&mut a, None, json!({"name": "abgeglichen"}));
        deliver(&mut a, &mut b, &personal);
        put_json(&mut a, Some(id), json!({"name": "geändert"}));
        put_json(&mut a, None, json!({"name": "neu"}));
        assert_eq!(a.discard_pending(&personal).unwrap(), 2);
        assert_eq!(values(&a, &personal), [json!({"name": "abgeglichen"})]);
        assert!(a.pending(&personal).unwrap().is_empty());
    }

    #[test]
    fn the_link_to_the_server_stays_on_this_device() {
        let temp = Temp::new("link");
        let copy = Temp::new("link-copy");
        let mut vault = Vault::create(&temp.0, "richtig", FAST).unwrap();
        let personal = vault.personal().unwrap();
        assert!(vault.link().unwrap().is_none());
        vault.set_link(Some(b"https://sync.example|token")).unwrap();
        vault.set_cursor(&personal, 42).unwrap();
        let id = vault.put(None, b"x").unwrap();
        vault.delete(&id).unwrap();
        assert_eq!(vault.purge_tombstones(-1).unwrap(), 0, "der Server weiß noch nichts vom Löschen");
        let sent = vault.pending(&personal).unwrap();
        vault.acknowledge(&personal, &sent).unwrap();
        vault.backup(&copy.0).unwrap();
        assert_eq!(vault.purge_tombstones(-1).unwrap(), 1);

        vault.lock();
        assert!(matches!(vault.link(), Err(VaultError::Locked)));
        vault.unlock("richtig").unwrap();
        assert_eq!(vault.link().unwrap().unwrap().as_slice(), b"https://sync.example|token");
        assert_eq!(vault.cursor(&personal).unwrap(), 42);
        let bytes = std::fs::read(&temp.0).unwrap();
        assert!(!bytes.windows(12).any(|w| w == b"sync.example"), "die Adresse steht nicht im Klartext in der Datei");

        // Die Sicherung kennt den Server nicht und gleicht von vorn ab.
        let mut restored = Vault::open(&copy.0).unwrap();
        restored.unlock("richtig").unwrap();
        assert!(restored.link().unwrap().is_none());
        assert_eq!(restored.cursor(&personal).unwrap(), 0);
        vault.set_link(None).unwrap();
        assert!(vault.link().unwrap().is_none());
    }

    #[test]
    fn a_password_changed_elsewhere_takes_over_once_it_opens() {
        let (_ta, _tb, mut a, mut b, _) = two_devices("passwort");
        assert!(matches!(a.rewrap("falsch", "neu", FAST), Err(VaultError::WrongPassword)));
        let (wrapping, old_auth, new_auth) = a.rewrap("richtig", "neu", FAST).unwrap();
        assert_eq!(old_auth.as_ref(), a.auth_key("richtig").unwrap().as_ref(), "vor dem Übernehmen gilt noch das alte");
        a.install_wrapping(&wrapping).unwrap();
        assert_eq!(new_auth.as_ref(), a.auth_key("neu").unwrap().as_ref());
        assert_ne!(old_auth.as_ref(), new_auth.as_ref());

        // Das zweite Gerät bekommt die neue Verpackung vom Server und merkt sie vor: Das alte Passwort öffnet weiter.
        b.stage_wrapping(&wrapping).unwrap();
        b.lock();
        b.unlock("richtig").unwrap();
        assert_ne!(b.current_wrapping().unwrap(), wrapping);
        b.lock();
        assert!(matches!(b.unlock("falsch"), Err(VaultError::WrongPassword)));
        // Mit dem neuen Passwort wird sie zur geltenden, und das alte öffnet nicht mehr.
        b.unlock("neu").unwrap();
        assert_eq!(b.current_wrapping().unwrap(), wrapping);
        b.lock();
        assert!(matches!(b.unlock("richtig"), Err(VaultError::WrongPassword)));
        b.unlock("neu").unwrap();

        // Unsinn vom Server sperrt niemanden aus, auch nicht die echte Verpackung eines fremden Kontos.
        let mut garbage = wrapping.clone();
        garbage.account_wrapped[0] ^= 1;
        b.stage_wrapping(&garbage).unwrap();
        b.lock();
        b.unlock("neu").unwrap();
        let other = Temp::new("passwort-fremd");
        let stranger = Vault::create(&other.0, "fremd", FAST).unwrap();
        b.stage_wrapping(&stranger.current_wrapping().unwrap()).unwrap();
        b.lock();
        assert!(matches!(b.unlock("fremd"), Err(VaultError::WrongPassword)));
        b.unlock("neu").unwrap();
        assert_eq!(b.current_wrapping().unwrap(), wrapping);
    }

    #[test]
    fn names_of_other_people_are_not_readable_in_the_file() {
        let Team { _temps, a, mut b, c: _, shared } = team("namen");
        assert_eq!(b.roster_blob(&shared).unwrap(), a.roster_blob(&shared).unwrap(), "dieselbe Liste, wie sie zum Server geht");

        let contact = Contact { name: "konto1".into(), ed25519: "aa".repeat(32), x25519: "bb".repeat(32), seen_at: 5 };
        assert!(b.contact(&account(1)).unwrap().is_none());
        b.remember_contact(&account(1), &contact).unwrap();
        b.remember_contact(&account(1), &Contact { seen_at: 9, ..contact.clone() }).unwrap();
        assert_eq!(b.contact(&account(1)).unwrap().unwrap().seen_at, 9);
        assert!(b.contact(&account(2)).unwrap().is_none());

        for text in ["Hinweis eins zu konto1", "Hinweis zwei", "Hinweis drei"] {
            b.add_notice(text.as_bytes()).unwrap();
        }
        let notices = b.notices().unwrap();
        assert_eq!(notices.iter().map(|notice| String::from_utf8(notice.data.to_vec()).unwrap()).collect::<Vec<_>>(), ["Hinweis eins zu konto1", "Hinweis zwei", "Hinweis drei"]);
        b.clear_notices(notices[1].id).unwrap();
        assert_eq!(b.notices().unwrap().len(), 1);

        let bytes = std::fs::read(b.path()).unwrap();
        for needle in [b"konto1".as_slice(), b"konto3", b"Hinweis"] {
            assert!(!bytes.windows(needle.len()).any(|w| w == needle), "Klartext in der Datei gefunden");
        }
        b.lock();
        assert!(matches!(b.contact(&account(1)), Err(VaultError::Locked)));
        assert!(matches!(b.notices(), Err(VaultError::Locked)));
        b.unlock("b").unwrap();
        assert_eq!(b.contact(&account(1)).unwrap().unwrap().name, "konto1");
    }

    #[test]
    fn old_notices_fall_out() {
        let temp = Temp::new("hinweise");
        let mut vault = Vault::create(&temp.0, "richtig", FAST).unwrap();
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
        assert!(b.open_own(b"zu kurz").unwrap().is_none());
    }

    #[test]
    fn a_full_state_from_the_server_removes_what_is_gone_there() {
        let (_ta, _tb, mut a, mut b, personal) = two_devices("ganz");
        let kept = put_json(&mut a, None, json!({"name": "bleibt"}));
        let gone = put_json(&mut a, None, json!({"name": "dort gelöscht"}));
        let edited = put_json(&mut a, None, json!({"name": "dort gelöscht, hier geändert"}));
        deliver(&mut a, &mut b, &personal);
        put_json(&mut b, Some(edited), json!({"name": "hier geändert"}));
        let fresh = put_json(&mut b, None, json!({"name": "hier neu"}));

        assert_eq!(b.retain_synced(&personal, &BTreeSet::from([kept])).unwrap(), 1);
        assert_eq!(values(&b, &personal), [json!({"name": "bleibt"}), json!({"name": "hier geändert"}), json!({"name": "hier neu"})]);
        assert!(b.state(&gone).unwrap().is_none());
        // Die eigene Änderung gilt jetzt als neu und geht mit ihrer Revision hinaus.
        let pending = b.pending(&personal).unwrap();
        assert_eq!(pending.iter().map(|e| e.id).collect::<BTreeSet<_>>(), BTreeSet::from([edited, fresh]));
        assert!(b.base(&edited).unwrap().is_none());
    }

    #[test]
    fn a_device_with_own_data_can_bring_it_into_an_account() {
        let (_ta, _tb, mut a, _b, personal) = two_devices("uebernehmen");
        let existing = put_json(&mut a, None, json!({"name": "im Konto"}));
        let local = Temp::new("uebernehmen-lokal");
        let mut old = Vault::create(&local.0, "anderes passwort", FAST).unwrap();
        let group = put_json(&mut old, None, json!({"t": "group", "name": "Gruppe"}));
        let host = put_json(&mut old, None, json!({"t": "host", "name": "lokal", "group": crypto::hex(&group)}));
        let deleted = put_json(&mut old, None, json!({"name": "war gelöscht"}));
        old.delete(&deleted).unwrap();

        assert_eq!(a.adopt_from(&old).unwrap(), 2);
        assert_eq!(a.adopt_from(&old).unwrap(), 0, "ein zweites Mal bringt nichts doppelt");
        assert_eq!(values(&a, &personal).len(), 3);
        // Dieselben Kennungen: Der Verweis des Hosts auf seine Gruppe hält.
        assert_eq!(a.vault_of(&host).unwrap(), personal);
        assert_eq!(a.vault_of(&group).unwrap(), personal);
        assert!(a.state(&deleted).unwrap().is_none());
        assert_eq!(a.pending(&personal).unwrap().len(), 3);
        let _ = existing;
    }

    #[test]
    fn a_server_with_an_older_state_gets_the_newer_one_back() {
        let (_ta, _tb, mut a, mut b, personal) = two_devices("zurueck");
        let old = put_json(&mut a, None, json!({"name": "alt"}));
        let stays = put_json(&mut a, None, json!({"name": "unverändert"}));
        // Der Stand, den die Sicherung des Servers festhält.
        let backup = a.pending(&personal).unwrap();
        deliver(&mut a, &mut b, &personal);
        // Danach ging es weiter: eine Änderung, ein neuer Eintrag, ein gelöschter. Beide Geräte haben alles.
        put_json(&mut a, Some(old), json!({"name": "neu"}));
        let fresh = put_json(&mut a, None, json!({"name": "nach der Sicherung"}));
        a.delete(&stays).unwrap();
        deliver(&mut a, &mut b, &personal);
        assert!(a.pending(&personal).unwrap().is_empty());
        let writes = a.writes();

        // Der Server ist aus der Sicherung zurück. Sein Stand allein ändert hier nichts ...
        assert_eq!(a.apply_remote(&personal, &backup).unwrap().rejected.len(), 2);
        // ... erst das ausdrückliche Hochladen des eigenen Stands.
        let applied = a.rebase_onto(&personal, &backup).unwrap();
        assert!(applied.rejected.is_empty() && applied.taken.is_empty());
        assert!(a.writes() > writes);
        assert_eq!(values(&a, &personal), [json!({"name": "nach der Sicherung"}), json!({"name": "neu"})], "am Inhalt ändert sich nichts");
        let outgoing = a.outgoing(&personal).unwrap();
        let of = |id: &Id| outgoing.iter().find(|(e, _)| e.id == *id).map(|(e, base)| (e.revision, *base, e.deleted)).unwrap();
        assert_eq!(of(&old), (3, 1, false), "setzt auf dem Stand des Servers auf und liegt über allem, was je ein Gerät sah");
        assert_eq!(of(&stays), (3, 1, true), "auch das Löschen geht wieder hinaus");
        assert_eq!(of(&fresh), (1, 0, false), "was der Server nicht kennt, gilt als neu");

        // Das andere Gerät nimmt alles als neu an und hat danach denselben Stand.
        let applied = deliver(&mut a, &mut b, &personal);
        assert_eq!((applied.taken.len(), applied.rejected.len()), (2, 0), "den neuen Eintrag hat es schon genau so");
        assert_eq!(values(&b, &personal), values(&a, &personal));

        // Was beim Server inzwischen neuer ist (ein drittes Gerät war schneller), wird dabei übernommen.
        put_json(&mut b, Some(old), json!({"name": "noch neuer"}));
        let newer = b.pending(&personal).unwrap();
        let applied = a.rebase_onto(&personal, &newer).unwrap();
        assert_eq!(applied.taken, [old]);
        assert_eq!(values(&a, &personal)[1], json!({"name": "noch neuer"}));
    }

    #[test]
    fn an_invitation_can_be_looked_at_before_joining() {
        let Team { _temps, mut a, b, c: _, shared } = team("einladung");
        a.put_in(&shared, br#"{"t":"vault-info","name":"Team Server"}"#).unwrap();
        let gone = a.put_in(&shared, b"weg").unwrap();
        a.delete(&gone).unwrap();
        let rows = a.pending(&shared).unwrap();
        let (roster, sealed) = (a.roster_blob(&shared).unwrap(), |v: &Vault| a.seal_key_for(&shared, &v.public_keys().unwrap().1).unwrap());

        let other = Temp::new("einladung-neu");
        let mut invited = Vault::create(&other.0, "x", FAST).unwrap();
        assert!(matches!(invited.peek_invitation(&shared, &sealed(&invited), &roster, &rows), Err(VaultError::NotMember)), "die Liste nennt dieses Konto nicht");
        let mut next = a.vaults().unwrap()[1].roster.clone().unwrap();
        next.version += 1;
        next.members.push(member(&invited, 4, Role::Read));
        let roster = a.sign_roster(&shared, &next).unwrap();
        let (seen, plain) = invited.peek_invitation(&shared, &sealed(&invited), &roster, &rows).unwrap();
        assert_eq!(seen.owner().unwrap().name, "konto1");
        assert_eq!(plain.iter().map(|p| p.to_vec()).collect::<Vec<_>>(), [br#"{"t":"vault-info","name":"Team Server"}"#.to_vec()]);
        assert_eq!(invited.vaults().unwrap().len(), 1, "nur angesehen, nicht aufgenommen");
        assert!(matches!(invited.peek_invitation(&shared, &sealed(&b), &roster, &rows), Err(VaultError::Corrupt(_))), "der Schlüssel eines anderen");
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

        // Die Liste der Übergabe trägt die Signatur der früheren Besitzerin und gilt trotzdem nach dem Sperren.
        for (vault, password) in [(&mut a, "a"), (&mut b, "b")] {
            vault.lock();
            vault.unlock(password).unwrap();
            assert_eq!(vault.vaults().unwrap().len(), 2);
        }

        // Der neue Besitzer führt weiter: einladen, Schlüssel tauschen. Die frühere Besitzerin kann das nicht mehr.
        let mut roster = b.vaults().unwrap()[1].roster.clone().unwrap();
        roster.version += 1;
        assert!(matches!(a.sign_roster(&shared, &roster), Err(VaultError::NotOwner)));
        roster.members.retain(|m| m.name != "konto3");
        roster.epoch += 1;
        let rotation = b.prepare_rotation(&shared, &roster).unwrap();
        let (blob, records) = (rotation.roster.clone(), rotation.records.clone());
        let for_a = rotation.keys.iter().find(|(key, _)| *key == key_of(&a)).unwrap().1.clone();
        b.commit_rotation(rotation).unwrap();
        a.apply_rotation(&shared, &for_a, &blob, &records).unwrap();
        assert_eq!(a.vaults().unwrap()[1].epoch, 2);

        // Ein Gerät, das neu dazukommt, kann die Liste prüfen, obwohl es die Übergabe nie gesehen hat.
        let other = Temp::new("besitz-neu");
        let mut late = Vault::create(&other.0, "x", FAST).unwrap();
        let mut next = b.vaults().unwrap()[1].roster.clone().unwrap();
        next.version += 1;
        next.members.push(member(&late, 4, Role::Read));
        let blob = b.sign_roster(&shared, &next).unwrap();
        late.join_shared(&shared, &b.seal_key_for(&shared, &late.public_keys().unwrap().1).unwrap(), &blob).unwrap();
        a.set_roster(&shared, &blob).unwrap();
    }
}

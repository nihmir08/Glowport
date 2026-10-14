//! Everything the server knows and decides, without network: accounts, devices, vaults, records, permissions.
//! Rules: `docs/sync.md`. The server decrypts nothing; it checks signatures, roles and revisions.

use std::{
    collections::{BTreeSet, HashMap, VecDeque},
    path::Path,
    sync::{Mutex, MutexGuard},
    time::{SystemTime, UNIX_EPOCH},
};

use glowport_core::{
    crypto::{hex, unhex, KdfParams},
    roster::{self, Role, Roster},
    vault::{state_digest, Envelope},
};
use glowport_sync_proto::{
    AdminAccount, Bytes, CreateVault, Device, Info, Invite, Login, LoginReply, MemberState, Overview, PasswordChange, PreloginReply, PublicKeys, Pull, Push, PushReply, Register, RosterUpdate, Rotate,
    SealedKey, Session, VaultEntry, WireAccount, WireRecord, PROTOCOL,
};
use rand_core::{OsRng, RngCore};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub type Id = [u8; 16];

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value BLOB NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS accounts (
    id BLOB PRIMARY KEY, username TEXT NOT NULL UNIQUE, auth_salt BLOB NOT NULL, auth_hash BLOB NOT NULL,
    admin INTEGER NOT NULL, disabled INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, seen_at INTEGER NOT NULL,
    salt BLOB NOT NULL, kdf BLOB NOT NULL, account_nonce BLOB NOT NULL, account_wrapped BLOB NOT NULL,
    ed25519 BLOB NOT NULL UNIQUE, ed25519_nonce BLOB NOT NULL, ed25519_wrapped BLOB NOT NULL,
    x25519 BLOB NOT NULL, x25519_nonce BLOB NOT NULL, x25519_wrapped BLOB NOT NULL,
    personal BLOB NOT NULL, personal_nonce BLOB NOT NULL, personal_wrapped BLOB NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS devices (
    id BLOB PRIMARY KEY, account BLOB NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, token_hash BLOB NOT NULL UNIQUE,
    name BLOB NOT NULL, created_at INTEGER NOT NULL, seen_at INTEGER NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS invites (code TEXT PRIMARY KEY, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS vaults (
    id BLOB PRIMARY KEY, shared INTEGER NOT NULL, epoch INTEGER NOT NULL DEFAULT 1, seq INTEGER NOT NULL DEFAULT 0,
    floor INTEGER NOT NULL DEFAULT 0, frozen INTEGER NOT NULL DEFAULT 0, roster BLOB
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS members (
    vault BLOB NOT NULL REFERENCES vaults(id) ON DELETE CASCADE, account BLOB NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    role TEXT NOT NULL, invited INTEGER NOT NULL DEFAULT 0, sealed_key BLOB, PRIMARY KEY (vault, account)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS records (
    vault BLOB NOT NULL REFERENCES vaults(id) ON DELETE CASCADE, id BLOB NOT NULL, revision INTEGER NOT NULL, deleted INTEGER NOT NULL,
    modified_at INTEGER NOT NULL, author BLOB NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, signature BLOB NOT NULL,
    seq INTEGER NOT NULL, stored_at INTEGER NOT NULL, PRIMARY KEY (vault, id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS records_seq ON records (vault, seq);
";

const RECORD: &str = "id, revision, deleted, modified_at, author, nonce, ciphertext, signature";
const ACCOUNT: &str = "salt, kdf, account_nonce, account_wrapped, ed25519, ed25519_nonce, ed25519_wrapped, x25519, x25519_nonce, x25519_wrapped, personal, personal_nonce, personal_wrapped";

/// Characters of the codes: none that can be confused when typing (no 0, O, 1, I).
const CODE_ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const INVITE_DAYS: i64 = 7;
const WINDOW_MS: i64 = 15 * 60 * 1000;
const DAY_MS: i64 = 24 * 60 * 60 * 1000;

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub record_bytes: usize,
    pub records_per_vault: usize,
    pub vaults_per_account: usize,
    /// Failed attempts per account and per sender address in fifteen minutes.
    pub failures_per_account: usize,
    pub failures_per_address: usize,
    pub tombstone_days: i64,
}

impl Default for Limits {
    fn default() -> Self {
        Self { record_bytes: 256 * 1024, records_per_vault: 20_000, vaults_per_account: 50, failures_per_account: 5, failures_per_address: 30, tombstone_days: 180 }
    }
}

/// Why the server refuses a request. `code` goes to the program.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Fail {
    #[error("Anfrage unvollständig oder unlesbar ({0})")]
    Bad(&'static str),
    #[error("Nicht angemeldet")]
    Unauthorized,
    #[error("Nicht erlaubt ({0})")]
    Forbidden(&'static str),
    #[error("Nicht gefunden")]
    NotFound,
    #[error("Widerspruch zum Stand des Servers ({0})")]
    Conflict(&'static str),
    #[error("Zu viele Versuche")]
    TooMany,
    #[error("Grenze erreicht ({0})")]
    Limit(&'static str),
    #[error("Interner Fehler: {0}")]
    Internal(String),
}

impl Fail {
    pub fn code(&self) -> &'static str {
        match self {
            Fail::Bad(_) => "bad_request",
            Fail::Unauthorized => "unauthorized",
            Fail::Forbidden(code) | Fail::Conflict(code) | Fail::Limit(code) => code,
            Fail::NotFound => "not_found",
            Fail::TooMany => "too_many_attempts",
            Fail::Internal(_) => "internal",
        }
    }

    pub fn status(&self) -> u16 {
        match self {
            Fail::Bad(_) => 400,
            Fail::Unauthorized => 401,
            Fail::Forbidden(_) => 403,
            Fail::NotFound => 404,
            Fail::Conflict(_) => 409,
            Fail::Limit(_) => 413,
            Fail::TooMany => 429,
            Fail::Internal(_) => 500,
        }
    }
}

impl From<rusqlite::Error> for Fail {
    fn from(error: rusqlite::Error) -> Self {
        Fail::Internal(error.to_string())
    }
}

type Result<T> = std::result::Result<T, Fail>;

/// Who makes a request, after the device token was checked.
#[derive(Debug, Clone)]
pub struct Caller {
    pub account: Id,
    pub device: Id,
    pub admin: bool,
    pub username: String,
    pub ed25519: [u8; 32],
}

pub struct Store {
    conn: Mutex<Connection>,
    failures: Mutex<HashMap<String, VecDeque<i64>>>,
    pub limits: Limits,
    clock: Box<dyn Fn() -> i64 + Send + Sync>,
}

fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn sha(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u32).to_le_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn same(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// A code like `K7QF-2MXA-9RTD`: 60 bits of randomness.
fn new_code() -> String {
    let bytes: [u8; 12] = random();
    let mut code = String::with_capacity(14);
    for (i, byte) in bytes.iter().enumerate() {
        if i > 0 && i % 4 == 0 {
            code.push('-');
        }
        code.push(CODE_ALPHABET[(byte & 31) as usize] as char);
    }
    code
}

fn clean_code(code: &str) -> String {
    code.trim().to_ascii_uppercase()
}

fn valid_username(name: &str) -> Result<&str> {
    let ok = (3..=32).contains(&name.len()) && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.'));
    if ok {
        Ok(name)
    } else {
        Err(Fail::Bad("username"))
    }
}

fn id_of(bytes: &Bytes, what: &'static str) -> Result<Id> {
    bytes.array().ok_or(Fail::Bad(what))
}

fn role_text(role: Role) -> &'static str {
    match role {
        Role::Owner => "owner",
        Role::Write => "write",
        Role::Read => "read",
    }
}

fn role_of(text: &str) -> Role {
    match text {
        "owner" => Role::Owner,
        "write" => Role::Write,
        _ => Role::Read,
    }
}

fn wire_record(row: &rusqlite::Row) -> rusqlite::Result<WireRecord> {
    Ok(WireRecord {
        id: Bytes(row.get(0)?),
        revision: row.get::<_, i64>(1)? as u64,
        deleted: row.get(2)?,
        modified_at: row.get(3)?,
        author: Bytes(row.get(4)?),
        nonce: Bytes(row.get(5)?),
        ciphertext: Bytes(row.get(6)?),
        signature: Bytes(row.get(7)?),
        base: 0,
    })
}

fn wire_account(row: &rusqlite::Row) -> rusqlite::Result<WireAccount> {
    wire_account_at(row, 0)
}

/// State of a vault and the requester's role in it.
struct Seat {
    shared: bool,
    epoch: u64,
    seq: u64,
    floor: u64,
    frozen: bool,
    roster: Option<Vec<u8>>,
    role: Role,
    invited: bool,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        Self::with(Connection::open(path)?)
    }

    pub fn in_memory() -> Result<Self> {
        Self::with(Connection::open_in_memory()?)
    }

    fn with(conn: Connection) -> Result<Self> {
        // The administration commands open the same file next to the running server: wait briefly instead of failing.
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;")?;
        conn.execute_batch(SCHEMA)?;
        if conn.query_row("SELECT 1 FROM settings WHERE key = 'secret'", [], |_| Ok(())).optional()?.is_none() {
            conn.execute("INSERT INTO settings (key, value) VALUES ('secret', ?1)", [random::<32>().as_slice()])?;
        }
        Ok(Self {
            conn: Mutex::new(conn),
            failures: Mutex::new(HashMap::new()),
            limits: Limits::default(),
            clock: Box::new(|| SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as i64)),
        })
    }

    /// For tests: a clock that can be set.
    pub fn set_clock(&mut self, clock: impl Fn() -> i64 + Send + Sync + 'static) {
        self.clock = Box::new(clock);
    }

    fn now(&self) -> i64 {
        (self.clock)()
    }

    fn db(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn is_fresh(conn: &Connection) -> Result<bool> {
        Ok(conn.query_row("SELECT count(*) FROM accounts", [], |row| row.get::<_, i64>(0))? == 0)
    }

    pub fn info(&self) -> Result<Info> {
        Ok(Info { name: "glowport-sync".into(), protocol: PROTOCOL, min_protocol: PROTOCOL, fresh: Self::is_fresh(&self.db())? })
    }

    /// As long as there is no account: a new setup code for the first one, which becomes the administrator. The server
    /// prints it at startup; only its verifier is kept.
    pub fn setup_code(&self) -> Result<Option<String>> {
        let conn = self.db();
        if !Self::is_fresh(&conn)? {
            return Ok(None);
        }
        let code = new_code();
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('setup', ?1)", [sha(&[code.as_bytes()]).as_slice()])?;
        Ok(Some(code))
    }

    // ── Bremse ───────────────────────────────────────────────────────────────────────────────────────────

    fn throttled(&self, key: &str, limit: usize) -> bool {
        let now = self.now();
        let mut failures = self.failures.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(times) = failures.get_mut(key) else { return false };
        while times.front().is_some_and(|at| now - at > WINDOW_MS) {
            times.pop_front();
        }
        times.len() >= limit
    }

    fn check_throttle(&self, username: Option<&str>, address: &str) -> Result<()> {
        let blocked = self.throttled(&format!("a:{address}"), self.limits.failures_per_address) || username.is_some_and(|name| self.throttled(&format!("u:{name}"), self.limits.failures_per_account));
        if blocked {
            Err(Fail::TooMany)
        } else {
            Ok(())
        }
    }

    fn note_failure(&self, username: Option<&str>, address: &str) {
        let now = self.now();
        let mut failures = self.failures.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        failures.retain(|_, times| times.back().is_some_and(|at| now - at <= WINDOW_MS));
        failures.entry(format!("a:{address}")).or_default().push_back(now);
        if let Some(name) = username {
            failures.entry(format!("u:{name}")).or_default().push_back(now);
        }
    }

    // ── Account and devices ──────────────────────────────────────────────────────────────────────────────

    /// Salt and cost for the key derivation. For unknown names fixed made-up values, so that it cannot
    /// be read from here which accounts exist.
    pub fn prelogin(&self, username: &str) -> Result<PreloginReply> {
        let conn = self.db();
        let found = conn.query_row("SELECT salt, kdf FROM accounts WHERE username = ?1", [username], |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))).optional()?;
        Ok(match found {
            Some((salt, kdf)) => PreloginReply { salt: Bytes(salt), kdf: KdfParams::from_bytes(&kdf).unwrap_or(KdfParams::DEFAULT).into() },
            None => {
                let secret: Vec<u8> = conn.query_row("SELECT value FROM settings WHERE key = 'secret'", [], |row| row.get(0))?;
                PreloginReply { salt: Bytes(sha(&[&secret, username.as_bytes()])[..16].to_vec()), kdf: KdfParams::DEFAULT.into() }
            }
        })
    }

    fn new_device(&self, conn: &Connection, account: &Id, name: &Bytes) -> Result<(Id, [u8; 32])> {
        if name.0.len() > 512 {
            return Err(Fail::Bad("device_name"));
        }
        let (id, token): (Id, [u8; 32]) = (random(), random());
        conn.execute(
            "INSERT INTO devices (id, account, token_hash, name, created_at, seen_at) VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
            params![id.as_slice(), account.as_slice(), sha(&[&token]).as_slice(), name.0, self.now()],
        )?;
        Ok((id, token))
    }

    pub fn register(&self, request: &Register, address: &str) -> Result<LoginReply> {
        let username = valid_username(&request.username)?;
        let account = request.account.account().ok_or(Fail::Bad("account"))?;
        if request.auth_key.0.len() != 32 {
            return Err(Fail::Bad("auth_key"));
        }
        self.check_throttle(None, address)?;
        let conn = self.db();
        let tx = conn.unchecked_transaction()?;
        let fresh = Self::is_fresh(&tx)?;
        let code = clean_code(&request.code);
        let code_ok = if fresh {
            let setup: Option<Vec<u8>> = tx.query_row("SELECT value FROM settings WHERE key = 'setup'", [], |row| row.get(0)).optional()?;
            setup.is_some_and(|hash| same(&hash, &sha(&[code.as_bytes()])))
        } else {
            tx.query_row("SELECT 1 FROM invites WHERE code = ?1 AND expires_at > ?2", params![code, self.now()], |_| Ok(())).optional()?.is_some()
        };
        if !code_ok {
            drop(tx);
            drop(conn);
            self.note_failure(None, address);
            return Err(Fail::Forbidden("code_invalid"));
        }
        if tx.query_row("SELECT 1 FROM accounts WHERE username = ?1", [username], |_| Ok(())).optional()?.is_some() {
            return Err(Fail::Conflict("username_taken"));
        }
        if tx.query_row("SELECT 1 FROM accounts WHERE ed25519 = ?1 OR personal = ?2", params![account.ed25519_public.as_slice(), account.personal.as_slice()], |_| Ok(())).optional()?.is_some() {
            return Err(Fail::Conflict("account_exists"));
        }
        let (id, auth_salt): (Id, [u8; 16]) = (random(), random());
        let now = self.now();
        let a = &request.account;
        tx.execute(
            &format!("INSERT INTO accounts (id, username, auth_salt, auth_hash, admin, created_at, seen_at, {ACCOUNT}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)"),
            params![
                id.as_slice(),
                username,
                auth_salt.as_slice(),
                sha(&[&auth_salt, &request.auth_key.0]).as_slice(),
                fresh,
                now,
                a.salt.0,
                account.kdf.to_bytes().as_slice(),
                a.account_nonce.0,
                a.account_wrapped.0,
                a.ed25519_public.0,
                a.ed25519_nonce.0,
                a.ed25519_wrapped.0,
                a.x25519_public.0,
                a.x25519_nonce.0,
                a.x25519_wrapped.0,
                a.personal.0,
                a.personal_nonce.0,
                a.personal_wrapped.0
            ],
        )?;
        tx.execute("INSERT INTO vaults (id, shared) VALUES (?1, 0)", [account.personal.as_slice()])?;
        tx.execute("INSERT INTO members (vault, account, role) VALUES (?1, ?2, 'owner')", params![account.personal.as_slice(), id.as_slice()])?;
        if fresh {
            tx.execute("DELETE FROM settings WHERE key = 'setup'", [])?;
        } else {
            tx.execute("DELETE FROM invites WHERE code = ?1", [&code])?;
        }
        let (device, token) = self.new_device(&tx, &id, &request.device_name)?;
        tx.commit()?;
        Ok(LoginReply { needs: None, session: Some(Session { account_id: id.into(), username: username.into(), device_id: device.into(), token: token.into(), admin: fresh, account: request.account.clone() }) })
    }

    pub fn login(&self, request: &Login, address: &str) -> Result<LoginReply> {
        let username = request.username.as_str();
        self.check_throttle(Some(username), address)?;
        let conn = self.db();
        let found = conn
            .query_row(&format!("SELECT id, auth_salt, auth_hash, admin, disabled, {ACCOUNT} FROM accounts WHERE username = ?1"), [username], |row| {
                let account = wire_account_at(row, 5)?;
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, Vec<u8>>(2)?, row.get::<_, bool>(3)?, row.get::<_, bool>(4)?, account))
            })
            .optional()?;
        // Even for unknown names the computation and comparison run, so the response time reveals nothing.
        let (id, salt, hash, admin, disabled, account) = match found {
            Some(found) => (Some(found.0), found.1, found.2, found.3, found.4, Some(found.5)),
            None => (None, vec![0; 16], vec![0; 32], false, false, None),
        };
        let matches = same(&hash, &sha(&[&salt, &request.auth_key.0]));
        let (Some(id), Some(account), true) = (id, account, matches) else {
            drop(conn);
            self.note_failure(Some(username), address);
            return Err(Fail::Unauthorized);
        };
        if disabled {
            return Err(Fail::Forbidden("account_disabled"));
        }
        let id: Id = id.as_slice().try_into().map_err(|_| Fail::Internal("Kontokennung".into()))?;
        let (device, token) = self.new_device(&conn, &id, &request.device_name)?;
        conn.execute("UPDATE accounts SET seen_at = ?2 WHERE id = ?1", params![id.as_slice(), self.now()])?;
        Ok(LoginReply { needs: None, session: Some(Session { account_id: id.into(), username: username.into(), device_id: device.into(), token: token.into(), admin, account }) })
    }

    /// Checks a device token. A disabled account gets no further.
    pub fn authenticate(&self, token: &[u8]) -> Result<Caller> {
        let conn = self.db();
        let found = conn
            .query_row(
                "SELECT d.id, a.id, a.admin, a.disabled, a.username, a.ed25519, d.seen_at FROM devices d JOIN accounts a ON a.id = d.account WHERE d.token_hash = ?1",
                [sha(&[token]).as_slice()],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, bool>(2)?, row.get::<_, bool>(3)?, row.get::<_, String>(4)?, row.get::<_, Vec<u8>>(5)?, row.get::<_, i64>(6)?)),
            )
            .optional()?;
        let Some((device, account, admin, disabled, username, ed25519, seen_at)) = found else { return Err(Fail::Unauthorized) };
        if disabled {
            return Err(Fail::Forbidden("account_disabled"));
        }
        let now = self.now();
        if now - seen_at > 60_000 {
            conn.execute("UPDATE devices SET seen_at = ?2 WHERE id = ?1", params![device, now])?;
            conn.execute("UPDATE accounts SET seen_at = ?2 WHERE id = ?1", params![account, now])?;
        }
        let internal = || Fail::Internal("Kennung".into());
        Ok(Caller { account: account.as_slice().try_into().map_err(|_| internal())?, device: device.as_slice().try_into().map_err(|_| internal())?, admin, username, ed25519: ed25519.as_slice().try_into().map_err(|_| internal())? })
    }

    pub fn overview(&self, caller: &Caller) -> Result<Overview> {
        let conn = self.db();
        let account = conn.query_row(&format!("SELECT {ACCOUNT} FROM accounts WHERE id = ?1"), [caller.account.as_slice()], wire_account)?;
        let mut statement = conn.prepare("SELECT v.id, v.shared, v.epoch, v.seq, m.role, m.invited, v.roster, m.sealed_key FROM members m JOIN vaults v ON v.id = m.vault WHERE m.account = ?1 ORDER BY v.shared, v.id")?;
        let vaults = statement
            .query_map([caller.account.as_slice()], |row| {
                Ok(VaultEntry {
                    id: Bytes(row.get(0)?),
                    shared: row.get(1)?,
                    epoch: row.get::<_, i64>(2)? as u64,
                    seq: row.get::<_, i64>(3)? as u64,
                    role: role_of(&row.get::<_, String>(4)?),
                    invited: row.get(5)?,
                    roster: row.get::<_, Option<Vec<u8>>>(6)?.map(Bytes),
                    sealed_key: row.get::<_, Option<Vec<u8>>>(7)?.map(Bytes),
                    members: Vec::new(),
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut vaults = vaults;
        let mut members = conn.prepare("SELECT account, invited FROM members WHERE vault = ?1 ORDER BY account")?;
        for vault in vaults.iter_mut().filter(|vault| vault.shared) {
            vault.members = members.query_map([&vault.id.0], |row| Ok(MemberState { account: Bytes(row.get(0)?), invited: row.get(1)? }))?.collect::<rusqlite::Result<Vec<_>>>()?;
        }
        Ok(Overview { account_id: caller.account.into(), username: caller.username.clone(), admin: caller.admin, account, vaults })
    }

    pub fn devices(&self, caller: &Caller) -> Result<Vec<Device>> {
        let conn = self.db();
        let mut statement = conn.prepare("SELECT id, name, created_at, seen_at FROM devices WHERE account = ?1 ORDER BY created_at, id")?;
        let devices = statement
            .query_map([caller.account.as_slice()], |row| {
                let id: Vec<u8> = row.get(0)?;
                Ok(Device { current: id == caller.device, id: Bytes(id), name: Bytes(row.get(1)?), created_at: row.get(2)?, seen_at: row.get(3)? })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(devices)
    }

    /// Gives a device of the own account a name (encrypted; the server does not read it).
    pub fn rename_device(&self, caller: &Caller, device: &Id, name: &Bytes) -> Result<()> {
        if name.0.len() > 512 {
            return Err(Fail::Bad("device_name"));
        }
        match self.db().execute("UPDATE devices SET name = ?3 WHERE id = ?1 AND account = ?2", params![device.as_slice(), caller.account.as_slice(), name.0])? {
            0 => Err(Fail::NotFound),
            _ => Ok(()),
        }
    }

    /// Signs out a device of the own account: its token is no longer valid.
    pub fn remove_device(&self, caller: &Caller, device: &Id) -> Result<()> {
        match self.db().execute("DELETE FROM devices WHERE id = ?1 AND account = ?2", params![device.as_slice(), caller.account.as_slice()])? {
            0 => Err(Fail::NotFound),
            _ => Ok(()),
        }
    }

    pub fn change_password(&self, caller: &Caller, request: &PasswordChange, address: &str) -> Result<()> {
        if request.new_auth_key.0.len() != 32 || request.salt.0.len() != 16 {
            return Err(Fail::Bad("password"));
        }
        self.check_throttle(Some(&caller.username), address)?;
        let conn = self.db();
        let (salt, hash): (Vec<u8>, Vec<u8>) = conn.query_row("SELECT auth_salt, auth_hash FROM accounts WHERE id = ?1", [caller.account.as_slice()], |row| Ok((row.get(0)?, row.get(1)?)))?;
        if !same(&hash, &sha(&[&salt, &request.auth_key.0])) {
            drop(conn);
            self.note_failure(Some(&caller.username), address);
            return Err(Fail::Unauthorized);
        }
        let auth_salt: [u8; 16] = random();
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "UPDATE accounts SET auth_salt = ?2, auth_hash = ?3, salt = ?4, kdf = ?5, account_nonce = ?6, account_wrapped = ?7 WHERE id = ?1",
            params![
                caller.account.as_slice(),
                auth_salt.as_slice(),
                sha(&[&auth_salt, &request.new_auth_key.0]).as_slice(),
                request.salt.0,
                KdfParams::from(request.kdf).to_bytes().as_slice(),
                request.account_nonce.0,
                request.account_wrapped.0
            ],
        )?;
        if request.logout_others {
            tx.execute("DELETE FROM devices WHERE account = ?1 AND id <> ?2", params![caller.account.as_slice(), caller.device.as_slice()])?;
        }
        Ok(tx.commit()?)
    }

    /// Public keys of an account, for inviting.
    pub fn public_keys(&self, username: &str) -> Result<PublicKeys> {
        self.db()
            .query_row("SELECT id, username, ed25519, x25519 FROM accounts WHERE username = ?1 AND disabled = 0", [username], |row| {
                Ok(PublicKeys { account_id: Bytes(row.get(0)?), username: row.get(1)?, ed25519: Bytes(row.get(2)?), x25519: Bytes(row.get(3)?) })
            })
            .optional()?
            .ok_or(Fail::NotFound)
    }

    // ── Tresore ──────────────────────────────────────────────────────────────────────────────────────────

    fn seat(conn: &Connection, caller: &Caller, vault: &Id) -> Result<Seat> {
        conn.query_row(
            "SELECT v.shared, v.epoch, v.seq, v.floor, v.frozen, v.roster, m.role, m.invited FROM members m JOIN vaults v ON v.id = m.vault WHERE m.vault = ?1 AND m.account = ?2",
            params![vault.as_slice(), caller.account.as_slice()],
            |row| {
                Ok(Seat {
                    shared: row.get(0)?,
                    epoch: row.get::<_, i64>(1)? as u64,
                    seq: row.get::<_, i64>(2)? as u64,
                    floor: row.get::<_, i64>(3)? as u64,
                    frozen: row.get(4)?,
                    roster: row.get(5)?,
                    role: role_of(&row.get::<_, String>(6)?),
                    invited: row.get(7)?,
                })
            },
        )
        .optional()?
        // Whoever is not a member does not even learn whether the vault exists.
        .ok_or(Fail::NotFound)
    }

    /// The accounts that are notified about a change to this vault.
    pub fn members(&self, vault: &Id) -> Result<Vec<Id>> {
        let conn = self.db();
        let mut statement = conn.prepare("SELECT account FROM members WHERE vault = ?1")?;
        let accounts = statement.query_map([vault.as_slice()], |row| row.get::<_, Vec<u8>>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(accounts.iter().filter_map(|a| a.as_slice().try_into().ok()).collect())
    }

    /// The members of a list must be accounts on this server, with exactly the keys it names.
    fn accounts_of(conn: &Connection, roster: &Roster) -> Result<Vec<(Id, Role, [u8; 32])>> {
        let mut out = Vec::with_capacity(roster.members.len());
        for member in &roster.members {
            let (id, signing, exchange) = unhex::<16>(&member.account).zip(member.signing_key()).zip(member.exchange_key()).map(|((a, b), c)| (a, b, c)).ok_or(Fail::Bad("roster"))?;
            let known = conn.query_row("SELECT 1 FROM accounts WHERE id = ?1 AND ed25519 = ?2 AND x25519 = ?3", params![id.as_slice(), signing.as_slice(), exchange.as_slice()], |_| Ok(())).optional()?;
            if known.is_none() {
                return Err(Fail::Forbidden("member_unknown"));
            }
            out.push((id, member.role, signing));
        }
        Ok(out)
    }

    fn key_for<'a>(keys: &'a [SealedKey], member: &[u8; 32]) -> Option<&'a [u8]> {
        keys.iter().find(|key| key.member.0 == member).map(|key| key.sealed.0.as_slice())
    }

    /// Creates a shared vault. The requester is owner and only member.
    pub fn create_vault(&self, caller: &Caller, request: &CreateVault) -> Result<()> {
        let id = id_of(&request.id, "vault")?;
        let roster = roster::verify(&request.roster.0, &id, None).map_err(|_| Fail::Forbidden("roster_invalid"))?;
        let owner = roster.owner().ok_or(Fail::Bad("roster"))?;
        if roster.members.len() != 1 || roster.epoch != 1 || !roster.handovers.is_empty() || owner.signing_key() != Some(caller.ed25519) || owner.account != hex(&caller.account) {
            return Err(Fail::Forbidden("roster_invalid"));
        }
        let conn = self.db();
        let tx = conn.unchecked_transaction()?;
        Self::accounts_of(&tx, &roster)?;
        let owned: i64 = tx.query_row("SELECT count(*) FROM members WHERE account = ?1", [caller.account.as_slice()], |row| row.get(0))?;
        if owned as usize >= self.limits.vaults_per_account {
            return Err(Fail::Limit("too_many_vaults"));
        }
        if tx.query_row("SELECT 1 FROM vaults WHERE id = ?1", [id.as_slice()], |_| Ok(())).optional()?.is_some() {
            return Err(Fail::Conflict("vault_exists"));
        }
        tx.execute("INSERT INTO vaults (id, shared, roster) VALUES (?1, 1, ?2)", params![id.as_slice(), request.roster.0])?;
        tx.execute("INSERT INTO members (vault, account, role, sealed_key) VALUES (?1, ?2, 'owner', ?3)", params![id.as_slice(), caller.account.as_slice(), request.sealed_key.0])?;
        Ok(tx.commit()?)
    }

    pub fn pull(&self, caller: &Caller, vault: &Id, after: u64) -> Result<Pull> {
        let conn = self.db();
        // Even someone only invited may read: they already have the key anyway, and this way they see before
        // accepting what awaits them.
        let seat = Self::seat(&conn, caller, vault)?;
        let full = after < seat.floor;
        let mut statement = conn.prepare(&format!("SELECT {RECORD} FROM records WHERE vault = ?1 AND seq > ?2 ORDER BY seq, id"))?;
        let records = statement.query_map(params![vault.as_slice(), if full { 0 } else { after as i64 }], wire_record)?.collect::<rusqlite::Result<Vec<_>>>()?;
        let mut statement = conn.prepare("SELECT id, revision FROM records WHERE vault = ?1 AND deleted = 0 ORDER BY id")?;
        let state = statement.query_map([vault.as_slice()], |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
        let digest = state_digest(state.iter().filter_map(|(id, revision)| Some((Id::try_from(id.as_slice()).ok()?, *revision as u64))));
        Ok(Pull { seq: seat.seq, epoch: seat.epoch, full, records, digest: digest.into() })
    }

    /// Checks what can be checked without a key: size, author and signature.
    fn checked(&self, caller: &Caller, vault: &Id, records: &[WireRecord]) -> Result<Vec<Envelope>> {
        let mut seen = BTreeSet::new();
        let mut out = Vec::with_capacity(records.len());
        for record in records {
            let envelope = record.envelope().ok_or(Fail::Bad("record"))?;
            if envelope.ciphertext.len() > self.limits.record_bytes {
                return Err(Fail::Limit("record_too_large"));
            }
            if envelope.author != caller.ed25519 || envelope.revision == 0 || !envelope.signed(vault) || !seen.insert(envelope.id) {
                return Err(Fail::Forbidden("record_invalid"));
            }
            out.push(envelope);
        }
        Ok(out)
    }

    fn insert(&self, conn: &Connection, vault: &Id, envelope: &Envelope, seq: u64) -> Result<()> {
        conn.execute(
            &format!("INSERT OR REPLACE INTO records (vault, {RECORD}, seq, stored_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"),
            params![
                vault.as_slice(),
                envelope.id.as_slice(),
                envelope.revision as i64,
                envelope.deleted,
                envelope.modified_at,
                envelope.author.as_slice(),
                envelope.nonce.as_slice(),
                envelope.ciphertext,
                envelope.signature.as_slice(),
                seq as i64,
                self.now()
            ],
        )?;
        Ok(())
    }

    /// Accepts a package completely or not at all (`docs/sync.md`, “Sending”).
    pub fn push(&self, caller: &Caller, vault: &Id, request: &Push) -> Result<PushReply> {
        let envelopes = self.checked(caller, vault, &request.records)?;
        let conn = self.db();
        let tx = conn.unchecked_transaction()?;
        let seat = Self::seat(&tx, caller, vault)?;
        if seat.invited || !seat.role.may_write() {
            return Err(Fail::Forbidden("read_only"));
        }
        if seat.frozen {
            return Err(Fail::Forbidden("vault_frozen"));
        }
        if request.epoch != seat.epoch {
            return Ok(PushReply { accepted: false, seq: seat.seq, epoch: seat.epoch, conflicts: Vec::new() });
        }
        let mut conflicts = Vec::new();
        let mut added = 0usize;
        for (envelope, sent) in envelopes.iter().zip(&request.records) {
            let current = tx.query_row(&format!("SELECT {RECORD} FROM records WHERE vault = ?1 AND id = ?2"), params![vault.as_slice(), envelope.id.as_slice()], wire_record).optional()?;
            match current {
                // A record the server does not know is accepted with any revision.
                None => added += 1,
                // Otherwise only what builds on its state and lies above it. Usually that is exactly one
                // above; it becomes more when a device uploads its state after the server was restored.
                Some(current) if sent.base == current.revision && envelope.revision > current.revision => {}
                Some(current) => conflicts.push(current),
            }
        }
        if !conflicts.is_empty() {
            return Ok(PushReply { accepted: false, seq: seat.seq, epoch: seat.epoch, conflicts });
        }
        let count: i64 = tx.query_row("SELECT count(*) FROM records WHERE vault = ?1", [vault.as_slice()], |row| row.get(0))?;
        if count as usize + added > self.limits.records_per_vault {
            return Err(Fail::Limit("vault_full"));
        }
        let seq = seat.seq + 1;
        for envelope in &envelopes {
            self.insert(&tx, vault, envelope, seq)?;
        }
        tx.execute("UPDATE vaults SET seq = ?2 WHERE id = ?1", params![vault.as_slice(), seq as i64])?;
        tx.commit()?;
        Ok(PushReply { accepted: true, seq, epoch: seat.epoch, conflicts: Vec::new() })
    }

    /// The current member list, and the new one checked against it: signed by the previous owner and newer.
    fn next_roster(seat: &Seat, vault: &Id, blob: &[u8]) -> Result<(Roster, Roster)> {
        if !seat.shared {
            return Err(Fail::Forbidden("personal_vault"));
        }
        if seat.frozen {
            return Err(Fail::Forbidden("vault_frozen"));
        }
        let current = seat.roster.as_deref().and_then(|blob| roster::verify(blob, vault, None).ok()).ok_or_else(|| Fail::Internal("Mitgliederliste".into()))?;
        let next = roster::verify(blob, vault, Some(&current)).map_err(|_| Fail::Forbidden("roster_invalid"))?;
        Ok((current, next))
    }

    /// Writes the memberships as the list names them. Whoever is new counts as invited until they accept.
    fn write_members(conn: &Connection, vault: &Id, roster: &Roster, keys: &[SealedKey], replace_keys: bool) -> Result<()> {
        let accounts = Self::accounts_of(conn, roster)?;
        let listed: Vec<Vec<u8>> = accounts.iter().map(|(id, _, _)| id.to_vec()).collect();
        for (account, role, signing) in &accounts {
            let exists = conn.query_row("SELECT 1 FROM members WHERE vault = ?1 AND account = ?2", params![vault.as_slice(), account.as_slice()], |_| Ok(())).optional()?.is_some();
            let key = Self::key_for(keys, signing);
            match (exists, key) {
                (true, Some(key)) if replace_keys => drop(conn.execute("UPDATE members SET role = ?3, sealed_key = ?4 WHERE vault = ?1 AND account = ?2", params![vault.as_slice(), account.as_slice(), role_text(*role), key])?),
                (true, None) if replace_keys => return Err(Fail::Bad("keys")),
                (true, _) => drop(conn.execute("UPDATE members SET role = ?3 WHERE vault = ?1 AND account = ?2", params![vault.as_slice(), account.as_slice(), role_text(*role)])?),
                (false, Some(key)) => drop(conn.execute("INSERT INTO members (vault, account, role, invited, sealed_key) VALUES (?1, ?2, ?3, 1, ?4)", params![vault.as_slice(), account.as_slice(), role_text(*role), key])?),
                (false, None) => return Err(Fail::Bad("keys")),
            }
        }
        let mut statement = conn.prepare("SELECT account FROM members WHERE vault = ?1")?;
        let present = statement.query_map([vault.as_slice()], |row| row.get::<_, Vec<u8>>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
        for account in present.iter().filter(|account| !listed.contains(account)) {
            conn.execute("DELETE FROM members WHERE vault = ?1 AND account = ?2", params![vault.as_slice(), account])?;
        }
        Ok(())
    }

    /// New member list at the same key generation: invite, extend permissions, transfer ownership.
    /// Returns the accounts that are notified.
    pub fn update_roster(&self, caller: &Caller, vault: &Id, request: &RosterUpdate) -> Result<Vec<Id>> {
        let conn = self.db();
        let tx = conn.unchecked_transaction()?;
        let seat = Self::seat(&tx, caller, vault)?;
        let (current, next) = Self::next_roster(&seat, vault, &request.roster.0)?;
        if next.epoch != seat.epoch || roster::reduces(&current, &next) {
            return Err(Fail::Forbidden("needs_rotation"));
        }
        Self::write_members(&tx, vault, &next, &request.keys, false)?;
        tx.execute("UPDATE vaults SET roster = ?2 WHERE id = ?1", params![vault.as_slice(), request.roster.0])?;
        tx.commit()?;
        drop(conn);
        self.members(vault)
    }

    /// Key rotation: new list, new key for every member and all records as one package.
    /// Returns the accounts that are notified, the removed ones included.
    pub fn rotate(&self, caller: &Caller, vault: &Id, request: &Rotate) -> Result<Vec<Id>> {
        let envelopes = self.checked(caller, vault, &request.records)?;
        let mut notify = self.members(vault)?;
        let conn = self.db();
        let tx = conn.unchecked_transaction()?;
        let seat = Self::seat(&tx, caller, vault)?;
        let (_, next) = Self::next_roster(&seat, vault, &request.roster.0)?;
        if next.epoch != seat.epoch + 1 || !next.may_write(&caller.ed25519) {
            return Err(Fail::Forbidden("roster_invalid"));
        }
        if request.expected_seq != seat.seq {
            return Err(Fail::Conflict("vault_changed"));
        }
        if envelopes.len() > self.limits.records_per_vault {
            return Err(Fail::Limit("vault_full"));
        }
        Self::write_members(&tx, vault, &next, &request.keys, true)?;
        let seq = seat.seq + 1;
        tx.execute("DELETE FROM records WHERE vault = ?1", [vault.as_slice()])?;
        for envelope in &envelopes {
            self.insert(&tx, vault, envelope, seq)?;
        }
        tx.execute("UPDATE vaults SET seq = ?2, epoch = ?3, roster = ?4 WHERE id = ?1", params![vault.as_slice(), seq as i64, next.epoch as i64, request.roster.0])?;
        tx.commit()?;
        drop(conn);
        for account in self.members(vault)? {
            if !notify.contains(&account) {
                notify.push(account);
            }
        }
        Ok(notify)
    }

    /// Accepts an invitation.
    pub fn accept(&self, caller: &Caller, vault: &Id) -> Result<Vec<Id>> {
        let changed = self.db().execute("UPDATE members SET invited = 0 WHERE vault = ?1 AND account = ?2 AND invited = 1", params![vault.as_slice(), caller.account.as_slice()])?;
        if changed == 0 {
            return Err(Fail::NotFound);
        }
        self.members(vault)
    }

    /// Declines an invitation or leaves a vault. The owner cannot leave.
    pub fn leave(&self, caller: &Caller, vault: &Id) -> Result<Vec<Id>> {
        {
            let conn = self.db();
            let seat = Self::seat(&conn, caller, vault)?;
            if seat.role == Role::Owner {
                return Err(Fail::Forbidden("owner_cannot_leave"));
            }
            conn.execute("DELETE FROM members WHERE vault = ?1 AND account = ?2", params![vault.as_slice(), caller.account.as_slice()])?;
        }
        self.members(vault)
    }

    /// Deletes a shared vault for everyone. Owner only.
    pub fn delete_vault(&self, caller: &Caller, vault: &Id) -> Result<Vec<Id>> {
        let notify = self.members(vault)?;
        let conn = self.db();
        let seat = Self::seat(&conn, caller, vault)?;
        if !seat.shared || seat.role != Role::Owner {
            return Err(Fail::Forbidden("not_owner"));
        }
        conn.execute("DELETE FROM vaults WHERE id = ?1", [vault.as_slice()])?;
        Ok(notify)
    }

    // ── Verwaltung ───────────────────────────────────────────────────────────────────────────────────────

    /// Whoever sits at the server's command line administers it: the same actions as in Glowport, without
    /// an account. Meant for the case that no administrator can get in any more.
    pub fn operator() -> Caller {
        Caller { account: [0; 16], device: [0; 16], admin: true, username: String::new(), ed25519: [0; 32] }
    }

    /// Who a device token belongs to, for the log. Checks nothing and changes nothing.
    pub fn username_of(&self, token: &[u8]) -> Option<String> {
        self.db().query_row("SELECT a.username FROM devices d JOIN accounts a ON a.id = d.account WHERE d.token_hash = ?1", [sha(&[token]).as_slice()], |row| row.get(0)).optional().ok().flatten()
    }

    /// ID of an account for its user name.
    pub fn account_id(&self, username: &str) -> Result<Id> {
        let id: Option<Vec<u8>> = self.db().query_row("SELECT id FROM accounts WHERE username = ?1", [username], |row| row.get(0)).optional()?;
        id.and_then(|id| Id::try_from(id.as_slice()).ok()).ok_or(Fail::NotFound)
    }

    fn admin(caller: &Caller) -> Result<()> {
        if caller.admin {
            Ok(())
        } else {
            Err(Fail::Forbidden("not_admin"))
        }
    }

    pub fn create_invite(&self, caller: &Caller) -> Result<Invite> {
        Self::admin(caller)?;
        let now = self.now();
        let invite = Invite { code: new_code(), created_at: now, expires_at: now + INVITE_DAYS * DAY_MS };
        self.db().execute("INSERT INTO invites (code, created_at, expires_at) VALUES (?1, ?2, ?3)", params![invite.code, invite.created_at, invite.expires_at])?;
        Ok(invite)
    }

    pub fn invites(&self, caller: &Caller) -> Result<Vec<Invite>> {
        Self::admin(caller)?;
        let conn = self.db();
        conn.execute("DELETE FROM invites WHERE expires_at <= ?1", [self.now()])?;
        let mut statement = conn.prepare("SELECT code, created_at, expires_at FROM invites ORDER BY created_at, code")?;
        let invites = statement.query_map([], |row| Ok(Invite { code: row.get(0)?, created_at: row.get(1)?, expires_at: row.get(2)? }))?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(invites)
    }

    pub fn revoke_invite(&self, caller: &Caller, code: &str) -> Result<()> {
        Self::admin(caller)?;
        match self.db().execute("DELETE FROM invites WHERE code = ?1", [clean_code(code)])? {
            0 => Err(Fail::NotFound),
            _ => Ok(()),
        }
    }

    pub fn accounts(&self, caller: &Caller) -> Result<Vec<AdminAccount>> {
        Self::admin(caller)?;
        let conn = self.db();
        let mut statement = conn.prepare(
            "SELECT a.id, a.username, a.admin, a.disabled, a.created_at, a.seen_at,
                    (SELECT count(*) FROM devices d WHERE d.account = a.id),
                    (SELECT coalesce(sum(length(r.ciphertext)), 0) FROM records r JOIN members m ON m.vault = r.vault WHERE m.account = a.id AND m.role = 'owner')
             FROM accounts a ORDER BY a.username",
        )?;
        let accounts = statement
            .query_map([], |row| {
                Ok(AdminAccount { id: Bytes(row.get(0)?), username: row.get(1)?, admin: row.get(2)?, disabled: row.get(3)?, created_at: row.get(4)?, seen_at: row.get(5)?, devices: row.get(6)?, bytes: row.get::<_, i64>(7)? as u64 })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(accounts)
    }

    /// Disables an account or enables it again. Disabled means: no sign-in, no sync; the data stays.
    pub fn set_disabled(&self, caller: &Caller, account: &Id, disabled: bool) -> Result<()> {
        Self::admin(caller)?;
        if *account == caller.account {
            return Err(Fail::Forbidden("own_account"));
        }
        match self.db().execute("UPDATE accounts SET disabled = ?2 WHERE id = ?1", params![account.as_slice(), disabled])? {
            0 => Err(Fail::NotFound),
            _ => Ok(()),
        }
    }

    /// Makes an account an administrator or takes the right away. That only works on the server's command line
    /// ([`Store::operator`]): whoever sits there can do everything anyway, and this way a server gets an
    /// administrator again if the previous one no longer knows their master password.
    pub fn set_admin(&self, caller: &Caller, account: &Id, admin: bool) -> Result<()> {
        if !caller.admin || caller.account != Self::operator().account {
            return Err(Fail::Forbidden("not_admin"));
        }
        match self.db().execute("UPDATE accounts SET admin = ?2 WHERE id = ?1", params![account.as_slice(), admin])? {
            0 => Err(Fail::NotFound),
            _ => Ok(()),
        }
    }

    /// Deletes an account with its devices and personal vault. Shared vaults it owns stay readable for
    /// the other members but accept nothing any more. Returns the accounts that are notified.
    pub fn delete_account(&self, caller: &Caller, account: &Id) -> Result<Vec<Id>> {
        Self::admin(caller)?;
        if *account == caller.account {
            return Err(Fail::Forbidden("own_account"));
        }
        let conn = self.db();
        let tx = conn.unchecked_transaction()?;
        let personal: Vec<u8> = tx.query_row("SELECT personal FROM accounts WHERE id = ?1", [account.as_slice()], |row| row.get(0)).optional()?.ok_or(Fail::NotFound)?;
        let mut notify = Vec::new();
        {
            let mut statement = tx.prepare("SELECT DISTINCT o.account FROM members m JOIN members o ON o.vault = m.vault WHERE m.account = ?1 AND o.account <> ?1")?;
            for other in statement.query_map([account.as_slice()], |row| row.get::<_, Vec<u8>>(0))? {
                notify.extend(Id::try_from(other?.as_slice()).ok());
            }
        }
        tx.execute("UPDATE vaults SET frozen = 1 WHERE shared = 1 AND id IN (SELECT vault FROM members WHERE account = ?1 AND role = 'owner')", [account.as_slice()])?;
        tx.execute("DELETE FROM vaults WHERE id = ?1", [personal])?;
        tx.execute("DELETE FROM accounts WHERE id = ?1", [account.as_slice()])?;
        tx.commit()?;
        Ok(notify)
    }

    // ── Pflege ───────────────────────────────────────────────────────────────────────────────────────────

    /// Removes tombstones older than the retention period and records per vault from which number on
    /// the history is still complete. Returns the number removed.
    pub fn purge(&self) -> Result<usize> {
        let cutoff = self.now() - self.limits.tombstone_days * DAY_MS;
        let conn = self.db();
        let tx = conn.unchecked_transaction()?;
        tx.execute("UPDATE vaults SET floor = max(floor, coalesce((SELECT max(seq) FROM records r WHERE r.vault = vaults.id AND r.deleted = 1 AND r.stored_at < ?1), 0))", [cutoff])?;
        let removed = tx.execute("DELETE FROM records WHERE deleted = 1 AND stored_at < ?1", [cutoff])?;
        tx.commit()?;
        Ok(removed)
    }

    /// Writes a consistent copy of the database while running.
    pub fn backup(&self, dest: &Path) -> Result<()> {
        if dest.exists() {
            return Err(Fail::Conflict("file_exists"));
        }
        self.db().execute("VACUUM INTO ?1", [dest.to_string_lossy()])?;
        Ok(())
    }
}

fn wire_account_at(row: &rusqlite::Row, offset: usize) -> rusqlite::Result<WireAccount> {
    let kdf: Vec<u8> = row.get(offset + 1)?;
    Ok(WireAccount {
        salt: Bytes(row.get(offset)?),
        kdf: KdfParams::from_bytes(&kdf).unwrap_or(KdfParams::DEFAULT).into(),
        account_nonce: Bytes(row.get(offset + 2)?),
        account_wrapped: Bytes(row.get(offset + 3)?),
        ed25519_public: Bytes(row.get(offset + 4)?),
        ed25519_nonce: Bytes(row.get(offset + 5)?),
        ed25519_wrapped: Bytes(row.get(offset + 6)?),
        x25519_public: Bytes(row.get(offset + 7)?),
        x25519_nonce: Bytes(row.get(offset + 8)?),
        x25519_wrapped: Bytes(row.get(offset + 9)?),
        personal: Bytes(row.get(offset + 10)?),
        personal_nonce: Bytes(row.get(offset + 11)?),
        personal_wrapped: Bytes(row.get(offset + 12)?),
    })
}

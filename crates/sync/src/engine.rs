//! What happens with the vault when syncing (`docs/sync.md`): set up, sign in, fetch, send,
//! merge, share vaults, rotate keys.
//!
//! Every function alternates between short reaches into the vault ([`Door::enter`]) and requests to the server.
//! Nothing that can be checked is believed from the server: records, member lists and keys
//! are checked by the core (`glowport_core::vault`) before any of it counts.

use std::{
    collections::BTreeSet,
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use glowport_core::{
    crypto::{hex, unhex, KdfParams},
    merge::Side,
    roster::{safety_code, Member, Role, Roster},
    vault::{self, Applied, Contact, Envelope, Kind, Vault, VaultError, VaultInfo, Wrapping},
};
use glowport_sync_proto::{AdminAccount, Bytes, CreateVault, Info, Invite, Login, Overview, PasswordChange, Push, Register, RosterUpdate, Rotate, SealedKey, Session, VaultEntry, WireRecord, PROTOCOL};
use serde::{Deserialize, Serialize};

use crate::{
    api::{encode_token, Api},
    Door, Link, SyncError,
};

type Id = [u8; 16];
type Result<T> = std::result::Result<T, SyncError>;

/// This many times a package is merged and sent again after a refusal before the round ends.
const ROUNDS: usize = 5;

/// Lowest key derivation cost a server may prescribe at sign-in. A malicious
/// server could otherwise name tiny values and cheaply guess the master password from the sign-in key.
/// (Glowport's default is far above; the numbers here are the usual minimum for Argon2id.)
pub const MIN_KDF: KdfParams = KdfParams { memory_kib: 19 * 1024, passes: 2, lanes: 1 };

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as i64)
}

fn envelopes(records: &[WireRecord]) -> Result<Vec<Envelope>> {
    records.iter().map(|record| record.envelope().ok_or(SyncError::Protocol("Datensatz"))).collect()
}

/// A notice from syncing, as stored in the vault and shown in the settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Notice {
    /// Two sides changed the same field. `mine`: the own value applies.
    Clash { vault: String, record: String, path: String, mine: bool },
    /// One side had deleted, the other changed: the entry stayed.
    Restored { vault: String, record: String },
    /// Own changes were discarded because one may not write in this vault (any more).
    Discarded { vault: String, count: usize },
    /// One is no longer a member; the copy of the vault on this device has been removed.
    VaultRemoved { vault: String },
    /// The server delivered records that fail the check. None of them was taken over.
    Rejected { vault: String, count: usize },
}

fn note(vault: &mut Vault, notice: &Notice) -> Result<()> {
    Ok(vault.add_notice(&serde_json::to_vec(notice).map_err(|_| SyncError::Protocol("Hinweis"))?)?)
}

/// Records what was noticed while taking over. Returns the number of notices.
fn note_applied(vault: &mut Vault, id: &Id, applied: &Applied) -> Result<usize> {
    let mut count = 0;
    for (record, merge) in &applied.merged {
        for clash in &merge.clashes {
            note(vault, &Notice::Clash { vault: hex(id), record: hex(record), path: clash.path.clone(), mine: clash.winner == Side::Mine })?;
            count += 1;
        }
        if merge.restored {
            note(vault, &Notice::Restored { vault: hex(id), record: hex(record) })?;
            count += 1;
        }
    }
    if !applied.rejected.is_empty() {
        note(vault, &Notice::Rejected { vault: hex(id), count: applied.rejected.len() })?;
        count += 1;
    }
    Ok(count)
}

/// An invitation to a shared vault that has not been accepted yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Invitation {
    pub vault: String,
    /// Name of the vault, if it could already be read.
    pub name: Option<String>,
    pub owner: String,
    pub role: Role,
    /// The owner's safety code: six words from the hash of their keys.
    pub code: String,
    pub known: Known,
}

/// Whether an account's keys match those this device saw from it before.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Known {
    New,
    Same,
    /// Different keys than before: either the account started over, or someone slips in false ones.
    Changed,
}

/// An account that can be invited.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Candidate {
    pub account: String,
    pub username: String,
    pub ed25519: String,
    pub x25519: String,
    /// The account's safety code: six words from the hash of its keys.
    pub code: String,
    pub known: Known,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceInfo {
    pub id: String,
    /// Empty if the device has no name yet or it could not be read.
    pub name: String,
    pub created_at: i64,
    pub seen_at: i64,
    pub current: bool,
}

/// Result of a round.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Report {
    /// Records, vaults or roles changed: the interface reads again.
    pub changed: bool,
    /// Changes that have not reached the server yet.
    pub pending: usize,
    pub invitations: Vec<Invitation>,
    /// Vaults for which the server has an older state than this device. They rest until someone
    /// triggers [`Engine::resync`].
    pub rolled_back: Vec<String>,
    /// Own shared vaults the server no longer knows. The copy here stays.
    pub orphaned: Vec<String>,
    /// New notices from this round.
    pub notices: usize,
    /// The master password was changed on another device; here the new one applies from the first unlock with it.
    pub password_changed: bool,
    /// Vault and account of those who are invited and have not accepted yet.
    pub invited: Vec<(String, String)>,
    /// Whether this account administers the server, as of this round.
    pub admin: bool,
}

fn contact_of(member: &Member) -> Contact {
    Contact { name: member.name.clone(), ed25519: member.ed25519.clone(), x25519: member.x25519.clone(), seen_at: now_ms() }
}

fn known(vault: &Vault, account: &Id, ed25519: &str, x25519: &str) -> Result<Known> {
    Ok(match vault.contact(account)? {
        None => Known::New,
        Some(contact) if contact.ed25519 == ed25519 && contact.x25519 == x25519 => Known::Same,
        Some(_) => Known::Changed,
    })
}

fn code_of(ed25519: &str, x25519: &str) -> Option<String> {
    Some(safety_code(&unhex(ed25519)?, &unhex(x25519)?))
}

/// A shared vault's name is stored inside it, encrypted, as a record of kind `vault-info`.
fn vault_name<T: AsRef<[u8]>>(plain: &[T]) -> Option<String> {
    plain.iter().filter_map(|bytes| serde_json::from_slice::<serde_json::Value>(bytes.as_ref()).ok()).find(|value| value["t"] == "vault-info").and_then(|value| value["name"].as_str().map(str::to_string))
}

fn wrapping_of(overview: &Overview) -> Option<Wrapping> {
    let account = &overview.account;
    Some(Wrapping { salt: account.salt.array()?, kdf: account.kdf.into(), account_nonce: account.account_nonce.0.clone(), account_wrapped: account.account_wrapped.0.clone() })
}

/// Runs work on the vault that computes (key derivation) without holding up the network threads.
async fn heavy<D: Door, T: Send + 'static>(door: &Arc<D>, work: impl FnOnce(&mut Vault) -> Result<T> + Send + 'static) -> Result<T> {
    let door = door.clone();
    tokio::task::spawn_blocking(move || door.enter(work)).await.map_err(|_| SyncError::Protocol("abgebrochen"))?
}

/// Asks a server whether it is a Glowport one and fits this version. Returns the address in
/// fixed form and its information (including whether it is still waiting for its first account).
pub async fn probe(server: &str) -> Result<(String, Info)> {
    let api = Api::new(server)?;
    let info = check(&api).await?;
    Ok((api.server(), info))
}

async fn check(api: &Api) -> Result<Info> {
    let info = api.info().await?;
    if info.name != "glowport-sync" {
        return Err(SyncError::Protocol("kein Glowport-Server"));
    }
    if info.min_protocol > PROTOCOL {
        return Err(SyncError::TooOld);
    }
    if info.protocol < PROTOCOL {
        return Err(SyncError::ServerTooOld);
    }
    Ok(info)
}

fn link_from(api: &Api, session: &Session) -> Result<Link> {
    let (account, device) = session.account_id.array::<16>().zip(session.device_id.array::<16>()).ok_or(SyncError::Protocol("Sitzung"))?;
    Ok(Link { server: api.server(), account: hex(&account), username: session.username.clone(), device: hex(&device), token: encode_token(&session.token.0), admin: session.admin })
}

/// Signs in with user name and master password. The password does not leave the device: only the
/// sign-in key derived from it goes to the server.
async fn sign_in(api: &Api, username: &str, password: &str, min_kdf: KdfParams) -> Result<Session> {
    let pre = api.prelogin(username).await?;
    let salt = pre.salt.array().ok_or(SyncError::Protocol("Salz"))?;
    let kdf: KdfParams = pre.kdf.into();
    if kdf.memory_kib < min_kdf.memory_kib || kdf.passes < min_kdf.passes || kdf.lanes < min_kdf.lanes {
        return Err(SyncError::Protocol("zu schwache Schlüsselableitung"));
    }
    let secret = password.to_string();
    let auth = tokio::task::spawn_blocking(move || vault::auth_key(&secret, &salt, kdf)).await.map_err(|_| SyncError::Protocol("abgebrochen"))??;
    let reply = api.login(&Login { username: username.into(), auth_key: auth.as_ref().into(), device_name: Bytes::default() }).await?;
    if reply.needs.is_some() {
        return Err(SyncError::TooOld);
    }
    reply.session.ok_or(SyncError::Protocol("Sitzung"))
}

/// Signs out a device just signed in if something fails afterwards. If that does not work, a nameless
/// device stays at the server, which can be signed out in the device list.
async fn undo_sign_in(api: &Api, link: &Link) {
    if let Some(device) = unhex(&link.device) {
        let _ = api.with_token(&link.token).remove_device(&device).await;
    }
}

/// Turns this device's vault into an account on a server (“Set up sync”). `code` is an
/// invitation code; for the very first account the server's setup code.
pub async fn register<D: Door>(door: &Arc<D>, server: &str, code: &str, username: &str, password: &str, device_name: &str) -> Result<Engine<D>> {
    let api = Api::new(server)?;
    check(&api).await?;
    let (code, username, password, device_name) = (code.to_string(), username.to_string(), password.to_string(), device_name.to_string());
    let request = heavy(door, move |vault| {
        if vault.link()?.is_some() {
            return Err(SyncError::AlreadyLinked);
        }
        let auth_key = vault.auth_key(&password)?;
        Ok(Register { code, username, auth_key: auth_key.as_ref().into(), account: (&vault.account()?).into(), device_name: vault.seal_own(device_name.as_bytes())?.into() })
    })
    .await?;
    let session = api.register(&request).await?.session.ok_or(SyncError::Protocol("Sitzung"))?;
    let link = link_from(&api, &session)?;
    door.enter(|vault| link.save(vault))?;
    Engine::with(door.clone(), link)
}

/// Reconnects a vault that already belongs to an account to the server: after restoring a
/// backup or after the device was signed out. If the vault belongs to another account, it fails
/// with [`SyncError::OtherAccount`]; then the way leads through [`login_new`] and `Vault::adopt_from`.
pub async fn connect<D: Door>(door: &Arc<D>, server: &str, username: &str, password: &str, device_name: &str, min_kdf: KdfParams) -> Result<Engine<D>> {
    let api = Api::new(server)?;
    check(&api).await?;
    if door.enter(|vault| Ok(vault.link()?.is_some()))? {
        return Err(SyncError::AlreadyLinked);
    }
    let session = sign_in(&api, username, password, min_kdf).await?;
    let link = link_from(&api, &session)?;
    let account = session.account.account().ok_or(SyncError::Protocol("Konto"))?;
    let adopted = door.enter(|vault| {
        if vault.public_keys()?.0 != account.ed25519_public || vault.personal()? != account.personal {
            return Err(SyncError::OtherAccount);
        }
        // The password just used is the server's. If its wrapping differs from the local one, it applies
        // from the next unlock with it.
        let theirs = Wrapping { salt: account.salt, kdf: account.kdf, account_nonce: account.account_nonce.clone(), account_wrapped: account.account_wrapped.clone() };
        if vault.current_wrapping()? != theirs {
            vault.stage_wrapping(&theirs)?;
        }
        // What this device knew about the server's state no longer applies: fetch from scratch.
        for info in vault.vaults()? {
            vault.set_cursor(&info.id, 0)?;
        }
        link.save(vault)?;
        Ok(vault.seal_own(device_name.as_bytes())?)
    });
    let sealed = match adopted {
        Ok(sealed) => sealed,
        Err(error) => {
            undo_sign_in(&api, &link).await;
            return Err(error);
        }
    };
    let engine = Engine::with(door.clone(), link)?;
    let _ = engine.api.rename_device(&engine.device, sealed).await;
    Ok(engine)
}

/// Creates the vault of an existing account on a device without a vault (“Sign in with an account”). The vault is
/// then open and connected to the server, but still empty: the first round fetches the content.
pub async fn login_new(path: &Path, server: &str, username: &str, password: &str, device_name: &str, min_kdf: KdfParams) -> Result<Vault> {
    if Vault::exists(path) {
        return Err(VaultError::AlreadyExists.into());
    }
    let api = Api::new(server)?;
    check(&api).await?;
    let session = sign_in(&api, username, password, min_kdf).await?;
    let link = link_from(&api, &session)?;
    let account = session.account.account().ok_or(SyncError::Protocol("Konto"));
    let (target, secret, saved) = (path.to_path_buf(), password.to_string(), link.clone());
    let created = match account {
        Ok(account) => tokio::task::spawn_blocking(move || {
            let mut vault = Vault::create_from_account(&target, &secret, &account)?;
            saved.save(&mut vault)?;
            Ok::<_, SyncError>(vault)
        })
        .await
        .map_err(|_| SyncError::Protocol("abgebrochen"))
        .and_then(|result| result),
        Err(error) => Err(error),
    };
    let vault = match created {
        Ok(vault) => vault,
        Err(error) => {
            undo_sign_in(&api, &link).await;
            let _ = std::fs::remove_file(path);
            return Err(error);
        }
    };
    if let Some(device) = unhex(&link.device) {
        let _ = api.with_token(&link.token).rename_device(&device, vault.seal_own(device_name.as_bytes())?).await;
    }
    Ok(vault)
}

/// Syncing a connected vault.
pub struct Engine<D: Door> {
    door: Arc<D>,
    pub(crate) api: Api,
    link: Link,
    account: Id,
    device: Id,
}

impl<D: Door> Engine<D> {
    /// Reads the sign-in from the open vault. `None`: sync is not set up.
    pub fn open(door: Arc<D>) -> Result<Option<Self>> {
        match door.enter(|vault| Link::load(vault))? {
            Some(link) => Self::with(door, link).map(Some),
            None => Ok(None),
        }
    }

    fn with(door: Arc<D>, link: Link) -> Result<Self> {
        let api = Api::new(&link.server)?.with_token(&link.token);
        let (account, device) = unhex(&link.account).zip(unhex(&link.device)).ok_or(SyncError::Protocol("gespeicherte Anmeldung"))?;
        Ok(Self { door, api, link, account, device })
    }

    pub fn link(&self) -> &Link {
        &self.link
    }

    fn info(&self, vault: &Id) -> Result<VaultInfo> {
        self.door.enter(|v| v.vaults()?.into_iter().find(|info| info.id == *vault).ok_or(SyncError::Vault(VaultError::NotFound)))
    }

    // ── One round ────────────────────────────────────────────────────────────────────────────────────────

    /// Syncs everything: account, vaults, memberships, records in both directions.
    pub async fn sync(&self) -> Result<Report> {
        let overview = self.api.overview().await?;
        let mut report = Report { admin: overview.admin, ..Report::default() };
        let (local, writes) = self.door.enter(|vault| {
            if overview.account.ed25519_public.0 != vault.public_keys()?.0 {
                return Err(SyncError::OtherAccount);
            }
            // Whoever administers the server can change there; the stored sign-in follows.
            if let Some(mut link) = Link::load(vault)?.filter(|link| link.admin != overview.admin) {
                link.admin = overview.admin;
                link.save(vault)?;
            }
            // The master password was changed on another device: the new wrapping is stored as pending.
            let theirs = wrapping_of(&overview).ok_or(SyncError::Protocol("Konto"))?;
            if vault.current_wrapping()? != theirs {
                vault.stage_wrapping(&theirs)?;
                report.password_changed = true;
            }
            Ok((vault.vaults()?, vault.writes()))
        })?;

        for entry in &overview.vaults {
            let id: Id = entry.id.array().ok_or(SyncError::Protocol("Tresor"))?;
            report.invited.extend(entry.members.iter().filter(|member| member.invited).filter_map(|member| Some((hex(&id), hex(&member.account.array::<16>()?)))));
            match local.iter().find(|info| info.id == id) {
                Some(info) if !entry.shared => {
                    if info.kind != Kind::Personal {
                        return Err(SyncError::Protocol("Tresor"));
                    }
                    self.sync_vault(&id, &mut report).await?;
                }
                Some(info) => self.sync_shared(&id, info, entry, &mut report).await?,
                None if !entry.shared => return Err(SyncError::OtherAccount),
                None if entry.invited => report.invitations.extend(self.invitation(&id, entry).await?),
                // Accepted on another own device: here the vault is simply added.
                None => {
                    if self.join(&id, entry)? {
                        self.sync_vault(&id, &mut report).await?;
                    }
                }
            }
        }

        // Shared vaults the server no longer keeps for this account.
        let listed: BTreeSet<Id> = overview.vaults.iter().filter_map(|entry| entry.id.array()).collect();
        for info in local.iter().filter(|info| info.kind == Kind::Shared && !listed.contains(&info.id)) {
            if info.role == Role::Owner {
                report.orphaned.push(hex(&info.id));
            } else {
                self.door.enter(|vault| {
                    vault.remove_vault(&info.id)?;
                    note(vault, &Notice::VaultRemoved { vault: hex(&info.id) })
                })?;
                report.notices += 1;
            }
        }

        self.door.enter(|vault| {
            report.changed = vault.writes() != writes;
            for info in vault.vaults()? {
                report.pending += vault.pending(&info.id)?.len();
            }
            Ok(())
        })?;
        Ok(report)
    }

    /// A shared vault that already exists here: take over key rotation and new member list,
    /// then sync the records.
    async fn sync_shared(&self, id: &Id, info: &VaultInfo, entry: &VaultEntry, report: &mut Report) -> Result<()> {
        let (Some(roster), Some(sealed_key)) = (&entry.roster, &entry.sealed_key) else { return Err(SyncError::Protocol("Tresor")) };
        if entry.epoch > info.epoch {
            // The owner rotated the key: everything comes newly encrypted.
            let pull = self.api.pull(id, 0).await?;
            let rows = envelopes(&pull.records)?;
            let outcome = self.door.enter(|vault| match vault.apply_rotation(id, &sealed_key.0, &roster.0, &rows) {
                Ok(applied) => {
                    vault.set_cursor(id, pull.seq)?;
                    Ok(Some(note_applied(vault, id, &applied)?))
                }
                // The new list no longer names this account.
                Err(VaultError::NotMember) => {
                    vault.remove_vault(id)?;
                    note(vault, &Notice::VaultRemoved { vault: hex(id) })?;
                    Ok(None)
                }
                Err(error) => Err(error.into()),
            })?;
            match outcome {
                Some(notices) => report.notices += notices,
                None => {
                    report.notices += 1;
                    return Ok(());
                }
            }
        } else {
            // New members, more permissions, transfer of ownership: the list is newer, the key the same.
            self.door.enter(|vault| {
                if vault.roster_blob(id)? != roster.0 {
                    match vault.set_roster(id, &roster.0) {
                        // A list that fails the check changes nothing.
                        Ok(()) | Err(VaultError::Roster(_)) | Err(VaultError::NotMember) => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                Ok(())
            })?;
        }
        self.sync_vault(id, report).await?;

        // Whoever left or declined an invitation is still on the list but no longer a member
        // at the server. The owner takes them out and rotates the key.
        let info = self.info(id)?;
        if let (Role::Owner, Some(roster)) = (info.role, &info.roster) {
            let present: BTreeSet<String> = entry.members.iter().filter_map(|member| member.account.array::<16>()).map(|account| hex(&account)).collect();
            let departed: Vec<String> = roster.members.iter().filter(|member| !present.contains(&member.account)).map(|member| member.account.clone()).collect();
            if !departed.is_empty() && !entry.members.is_empty() {
                self.rotate(id, |roster| roster.members.retain(|member| !departed.contains(&member.account))).await?;
            }
        }
        Ok(())
    }

    /// Fetches what is new in a vault and sends what is waiting here.
    async fn sync_vault(&self, id: &Id, report: &mut Report) -> Result<()> {
        let mut reconciled = false;
        for _ in 0..ROUNDS {
            let (cursor, info) = self.door.enter(|vault| Ok((vault.cursor(id)?, vault.vaults()?.into_iter().find(|info| info.id == *id).ok_or(VaultError::NotFound)?)))?;
            let pull = self.api.pull(id, cursor).await?;
            if pull.epoch != info.epoch {
                // In the middle of a key rotation: the next round starts again at the overview.
                return Ok(());
            }
            let rows = envelopes(&pull.records)?;
            let may_write = info.role.may_write();
            // A smaller number than the last one seen: the server knows less than this device.
            let mut consistent = pull.seq >= cursor || reconciled;
            let outgoing = self.door.enter(|vault| {
                if consistent {
                    let applied = vault.apply_remote(id, &rows)?;
                    if pull.full {
                        vault.retain_synced(id, &rows.iter().map(|row| row.id).collect())?;
                    }
                    vault.set_cursor(id, pull.seq)?;
                    report.notices += note_applied(vault, id, &applied)?;
                    // Does what this device believes the server's state to be now match its checksum?
                    consistent = reconciled || pull.digest.0.is_empty() || vault.believed_digest(id)?.as_slice() == pull.digest.0;
                }
                if !consistent {
                    return Ok(Vec::new());
                }
                if may_write {
                    return Ok(vault.outgoing(id)?);
                }
                // Whoever may only read keeps no waiting changes (e.g. from the time before being downgraded).
                let discarded = vault.discard_pending(id)?;
                if discarded > 0 {
                    note(vault, &Notice::Discarded { vault: hex(id), count: discarded })?;
                    report.notices += 1;
                }
                Ok(Vec::new())
            })?;
            if !consistent {
                // Missed something or the server lost something: compare the whole state.
                if !self.reconcile(id, report).await? {
                    return Ok(());
                }
                reconciled = true;
                continue;
            }
            if outgoing.is_empty() {
                return Ok(());
            }

            let sent: Vec<Envelope> = outgoing.iter().map(|(envelope, _)| envelope.clone()).collect();
            let request = Push { epoch: info.epoch, records: outgoing.iter().map(|(envelope, base)| WireRecord::outgoing(envelope, *base)).collect() };
            match self.api.push(id, &request).await {
                Ok(reply) if reply.accepted => {
                    return self.door.enter(|vault| {
                        vault.acknowledge(id, &sent)?;
                        // Only if nothing else happened between fetching and sending is everything known with it.
                        if reply.seq == pull.seq + 1 {
                            vault.set_cursor(id, reply.seq)?;
                        }
                        Ok(())
                    });
                }
                // Refused because of a different key generation: the next round catches up on the rotation.
                Ok(reply) if reply.conflicts.is_empty() => return Ok(()),
                // Another device was faster: merge and once more.
                Ok(reply) => {
                    let theirs = envelopes(&reply.conflicts)?;
                    self.door.enter(|vault| {
                        let applied = vault.apply_remote(id, &theirs)?;
                        report.notices += note_applied(vault, id, &applied)?;
                        Ok(())
                    })?;
                }
                Err(error) if error.refused("read_only") => {
                    return self.door.enter(|vault| {
                        let count = vault.discard_pending(id)?;
                        note(vault, &Notice::Discarded { vault: hex(id), count })?;
                        report.notices += 1;
                        Ok(())
                    });
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Compares a vault's whole state with the server's. If the server only has newer things, they are
    /// taken over (`true`). If it lacks something that counts as synced here, it has an older state: then
    /// nothing changes, the vault is reported and rests until someone triggers [`Engine::resync`] (`false`).
    async fn reconcile(&self, id: &Id, report: &mut Report) -> Result<bool> {
        let full = self.api.pull(id, 0).await?;
        let rows = envelopes(&full.records)?;
        self.door.enter(|vault| {
            if vault.ahead_of(id, &rows)? > 0 {
                report.rolled_back.push(hex(id));
                return Ok(false);
            }
            let applied = vault.apply_remote(id, &rows)?;
            vault.set_cursor(id, full.seq)?;
            report.notices += note_applied(vault, id, &applied)?;
            Ok(true)
        })
    }

    /// Looks at an invitation: who invites, in which role, what the vault is called.
    async fn invitation(&self, id: &Id, entry: &VaultEntry) -> Result<Option<Invitation>> {
        let (Some(roster), Some(sealed_key)) = (&entry.roster, &entry.sealed_key) else { return Ok(None) };
        let rows = envelopes(&self.api.pull(id, 0).await?.records)?;
        self.door.enter(|vault| {
            // An invitation that fails the check is not shown.
            let Ok((roster, plain)) = vault.peek_invitation(id, &sealed_key.0, &roster.0, &rows) else { return Ok(None) };
            let Some(owner) = roster.owner() else { return Ok(None) };
            let (Some(account), Some(code)) = (unhex::<16>(&owner.account), code_of(&owner.ed25519, &owner.x25519)) else { return Ok(None) };
            Ok(Some(Invitation {
                vault: hex(id),
                name: vault_name(&plain),
                owner: owner.name.clone(),
                role: roster.role(&vault.public_keys()?.0).unwrap_or(Role::Read),
                code,
                known: known(vault, &account, &owner.ed25519, &owner.x25519)?,
            }))
        })
    }

    /// Takes a shared vault onto this device and remembers its owner's keys.
    /// Returns `false` if list or key fail the check.
    fn join(&self, id: &Id, entry: &VaultEntry) -> Result<bool> {
        let (Some(roster), Some(sealed_key)) = (&entry.roster, &entry.sealed_key) else { return Ok(false) };
        self.door.enter(|vault| {
            match vault.join_shared(id, &sealed_key.0, &roster.0) {
                Ok(()) => {}
                Err(VaultError::Roster(_) | VaultError::NotMember | VaultError::Corrupt(_)) => return Ok(false),
                Err(error) => return Err(error.into()),
            }
            let roster = vault.vaults()?.into_iter().find(|info| info.id == *id).and_then(|info| info.roster);
            if let Some((owner, account)) = roster.as_ref().and_then(Roster::owner).and_then(|owner| Some((owner, unhex::<16>(&owner.account)?))) {
                vault.remember_contact(&account, &contact_of(owner))?;
            }
            Ok(true)
        })
    }

    /// The server has an older state than this device (see [`Report::rolled_back`]), e.g. because it was
    /// restored from a backup: whatever is newer here goes up again.
    pub async fn resync(&self, vault: &Id) -> Result<Report> {
        let pull = self.api.pull(vault, 0).await?;
        let rows = envelopes(&pull.records)?;
        let mut report = Report::default();
        self.door.enter(|v| {
            let applied = v.rebase_onto(vault, &rows)?;
            v.set_cursor(vault, pull.seq)?;
            report.notices += note_applied(v, vault, &applied)?;
            Ok(())
        })?;
        self.sync_vault(vault, &mut report).await?;
        report.changed = true;
        Ok(report)
    }

    // ── Account and devices ──────────────────────────────────────────────────────────────────────────────

    /// Changes the master password: first at the server, then here. So it never happens that only this device knows the new one.
    pub async fn change_password(&self, old: &str, new: &str, kdf: KdfParams, logout_others: bool) -> Result<()> {
        let (old, new) = (old.to_string(), new.to_string());
        let (wrapping, old_auth, new_auth) = heavy(&self.door, move |vault| Ok(vault.rewrap(&old, &new, kdf)?)).await?;
        let request = PasswordChange {
            auth_key: old_auth.as_ref().into(),
            new_auth_key: new_auth.as_ref().into(),
            salt: wrapping.salt.into(),
            kdf: wrapping.kdf.into(),
            account_nonce: (&wrapping.account_nonce).into(),
            account_wrapped: (&wrapping.account_wrapped).into(),
            logout_others,
        };
        self.api.change_password(&request).await?;
        self.door.enter(|vault| Ok(vault.install_wrapping(&wrapping)?))
    }

    pub async fn devices(&self) -> Result<Vec<DeviceInfo>> {
        let devices = self.api.devices().await?;
        self.door.enter(|vault| {
            let mut out = Vec::with_capacity(devices.len());
            for device in &devices {
                let name = vault.open_own(&device.name.0)?.and_then(|name| String::from_utf8(name.to_vec()).ok()).unwrap_or_default();
                out.push(DeviceInfo { id: hex(&device.id.0), name, created_at: device.created_at, seen_at: device.seen_at, current: device.current });
            }
            Ok(out)
        })
    }

    pub async fn rename_device(&self, device: &Id, name: &str) -> Result<()> {
        let sealed = self.door.enter(|vault| Ok(vault.seal_own(name.as_bytes())?))?;
        self.api.rename_device(device, sealed).await
    }

    /// Signs out a device of the account. What it already has stays readable there for anyone who knows the master password.
    pub async fn remove_device(&self, device: &Id) -> Result<()> {
        self.api.remove_device(device).await
    }

    /// Signs this device out at the server and leaves the vault untouched; before deleting this PC's data.
    /// Unlike [`Engine::unlink`] it reports when the server could not be reached. If the server no longer
    /// knows the device, it is already signed out.
    pub async fn sign_out(&self) -> Result<()> {
        match self.api.remove_device(&self.device).await {
            Err(SyncError::Refused { status: 401 | 403 | 404, .. }) => Ok(()),
            other => other,
        }
    }

    /// Disconnects this device from the server. The vault stays as it is, the shared ones too.
    pub async fn unlink(&self) -> Result<()> {
        // If signing out fails (no network), the device stays in the list and can be signed out there.
        let _ = self.api.remove_device(&self.device).await;
        self.door.enter(|vault| {
            for info in vault.vaults()? {
                vault.set_cursor(&info.id, 0)?;
            }
            Ok(vault.set_link(None)?)
        })
    }

    // ── Geteilte Tresore ─────────────────────────────────────────────────────────────────────────────────

    /// Creates a shared vault; oneself is owner.
    pub async fn create_vault(&self, name: &str) -> Result<Id> {
        let name = name.trim();
        if name.is_empty() || name.chars().count() > 80 {
            return Err(SyncError::Invalid("name"));
        }
        let (id, request) = self.door.enter(|vault| {
            let id = vault.create_shared(&self.account, &self.link.username)?;
            vault.put_in(&id, &serde_json::to_vec(&serde_json::json!({ "t": "vault-info", "v": 1, "name": name })).map_err(|_| SyncError::Protocol("Name"))?)?;
            let sealed_key = vault.seal_key_for(&id, &vault.public_keys()?.1)?;
            Ok((id, CreateVault { id: id.into(), roster: vault.roster_blob(&id)?.into(), sealed_key: sealed_key.into() }))
        })?;
        if let Err(error) = self.api.create_vault(&request).await {
            self.door.enter(|vault| Ok(vault.remove_vault(&id)?))?;
            return Err(error);
        }
        self.sync_vault(&id, &mut Report::default()).await?;
        Ok(id)
    }

    /// Looks up an account to invite and says whether its keys match those seen before.
    pub async fn lookup(&self, username: &str) -> Result<Candidate> {
        let keys = self.api.keys(username.trim()).await?;
        let (account, ed25519, x25519) = keys.account_id.array::<16>().zip(keys.ed25519.array::<32>()).zip(keys.x25519.array::<32>()).map(|((a, b), c)| (a, hex(&b), hex(&c))).ok_or(SyncError::Protocol("Schlüssel"))?;
        let code = code_of(&ed25519, &x25519).ok_or(SyncError::Protocol("Schlüssel"))?;
        let known = self.door.enter(|vault| known(vault, &account, &ed25519, &x25519))?;
        Ok(Candidate { account: hex(&account), username: keys.username, ed25519, x25519, code, known })
    }

    /// Invites an account into an own vault. Owner only.
    pub async fn invite(&self, vault: &Id, candidate: &Candidate, role: Role) -> Result<()> {
        if role == Role::Owner {
            return Err(SyncError::Invalid("role"));
        }
        let (account, exchange) = unhex::<16>(&candidate.account).zip(unhex::<32>(&candidate.x25519)).ok_or(SyncError::Invalid("candidate"))?;
        let member = Member { account: candidate.account.clone(), name: candidate.username.clone(), ed25519: candidate.ed25519.clone(), x25519: candidate.x25519.clone(), role };
        let signing: [u8; 32] = member.signing_key().ok_or(SyncError::Invalid("candidate"))?;
        let (blob, sealed) = self.door.enter(|v| {
            let mut roster = v.vaults()?.into_iter().find(|info| info.id == *vault).and_then(|info| info.roster).ok_or(VaultError::NotFound)?;
            if roster.members.iter().any(|m| m.account == member.account) {
                return Err(SyncError::Invalid("already_member"));
            }
            roster.version += 1;
            roster.members.push(member.clone());
            Ok((v.sign_roster(vault, &roster)?, v.seal_key_for(vault, &exchange)?))
        })?;
        self.api.roster(vault, &RosterUpdate { roster: (&blob).into(), keys: vec![SealedKey { member: signing.into(), sealed: sealed.into() }] }).await?;
        self.door.enter(|v| {
            v.set_roster(vault, &blob)?;
            Ok(v.remember_contact(&account, &contact_of(&member))?)
        })
    }

    /// Changes a member's role. More permissions apply at once; fewer rotate the key.
    pub async fn set_role(&self, vault: &Id, account: &Id, role: Role) -> Result<()> {
        let account = hex(account);
        let roster = self.info(vault)?.roster.ok_or(VaultError::NotOwner)?;
        let current = roster.members.iter().find(|member| member.account == account).ok_or(SyncError::Invalid("member"))?.role;
        if role == Role::Owner || current == Role::Owner {
            return Err(SyncError::Invalid("role"));
        }
        if current == role {
            return Ok(());
        }
        let change = move |roster: &mut Roster| roster.members.iter_mut().filter(|member| member.account == account).for_each(|member| member.role = role);
        if role.may_write() {
            self.update_roster(vault, change).await
        } else {
            self.rotate(vault, change).await
        }
    }

    /// Removes a member and rotates the key. That does not take back what the member has already seen.
    pub async fn remove_member(&self, vault: &Id, account: &Id) -> Result<()> {
        let account = hex(account);
        let roster = self.info(vault)?.roster.ok_or(VaultError::NotOwner)?;
        match roster.members.iter().find(|member| member.account == account) {
            None => return Err(SyncError::Invalid("member")),
            Some(member) if member.role == Role::Owner => return Err(SyncError::Invalid("role")),
            Some(_) => {}
        }
        self.rotate(vault, move |roster| roster.members.retain(|member| member.account != account)).await
    }

    /// Transfers ownership to a member; oneself keeps write permission.
    pub async fn transfer(&self, vault: &Id, account: &Id) -> Result<()> {
        let account = hex(account);
        let roster = self.info(vault)?.roster.ok_or(VaultError::NotOwner)?;
        let to = roster.members.iter().find(|member| member.account == account && member.role != Role::Owner).and_then(Member::signing_key).ok_or(SyncError::Invalid("member"))?;
        let blob = self.door.enter(|v| Ok(v.transfer_roster(vault, &to)?))?;
        self.api.roster(vault, &RosterUpdate { roster: (&blob).into(), keys: Vec::new() }).await?;
        self.door.enter(|v| Ok(v.set_roster(vault, &blob)?))
    }

    /// New member list at the same key generation.
    async fn update_roster(&self, vault: &Id, change: impl FnOnce(&mut Roster)) -> Result<()> {
        let blob = self.door.enter(|v| {
            let mut roster = v.vaults()?.into_iter().find(|info| info.id == *vault).and_then(|info| info.roster).ok_or(VaultError::NotFound)?;
            change(&mut roster);
            roster.version += 1;
            Ok(v.sign_roster(vault, &roster)?)
        })?;
        self.api.roster(vault, &RosterUpdate { roster: (&blob).into(), keys: Vec::new() }).await?;
        self.door.enter(|v| Ok(v.set_roster(vault, &blob)?))
    }

    /// Key rotation: new list, new key, all records re-encrypted, as one package. The
    /// server only accepts it if nobody has written in the meantime; otherwise start again.
    async fn rotate(&self, vault: &Id, change: impl Fn(&mut Roster)) -> Result<()> {
        for _ in 0..ROUNDS {
            // Sync first: the rotation needs a vault without waiting changes and the server's state.
            self.sync_vault(vault, &mut Report::default()).await?;
            let prepared = self.door.enter(|v| {
                let mut roster = v.vaults()?.into_iter().find(|info| info.id == *vault).and_then(|info| info.roster).ok_or(VaultError::NotFound)?;
                change(&mut roster);
                roster.version += 1;
                roster.epoch += 1;
                match v.prepare_rotation(vault, &roster) {
                    Ok(rotation) => Ok(Some((rotation, v.cursor(vault)?))),
                    // Something was changed here between sync and preparation: one more round.
                    Err(VaultError::Pending) => Ok(None),
                    Err(error) => Err(error.into()),
                }
            })?;
            let Some((rotation, seq)) = prepared else { continue };
            let request = Rotate {
                expected_seq: seq,
                roster: (&rotation.roster).into(),
                keys: rotation.keys.iter().map(|(member, sealed)| SealedKey { member: member.into(), sealed: sealed.into() }).collect(),
                records: rotation.records.iter().map(WireRecord::from).collect(),
            };
            match self.api.rotate(vault, &request).await {
                Ok(()) => {
                    return self.door.enter(|v| {
                        v.commit_rotation(rotation)?;
                        Ok(v.set_cursor(vault, seq + 1)?)
                    });
                }
                Err(error) if error.refused("vault_changed") => {}
                Err(error) => return Err(error),
            }
        }
        Err(SyncError::Busy)
    }

    /// Accepts an invitation.
    pub async fn accept(&self, vault: &Id) -> Result<()> {
        let overview = self.api.overview().await?;
        let entry = overview.vaults.iter().find(|entry| entry.id.0 == vault).ok_or(SyncError::Invalid("invitation"))?;
        self.api.accept(vault).await?;
        if self.join(vault, entry)? {
            self.sync_vault(vault, &mut Report::default()).await?;
        }
        Ok(())
    }

    /// Declines an invitation or leaves a vault. The owner cannot leave.
    pub async fn leave(&self, vault: &Id) -> Result<()> {
        self.api.leave(vault).await?;
        self.forget(vault)
    }

    /// Deletes an own shared vault for everyone.
    pub async fn delete_vault(&self, vault: &Id) -> Result<()> {
        self.api.delete_vault(vault).await?;
        self.forget(vault)
    }

    fn forget(&self, vault: &Id) -> Result<()> {
        self.door.enter(|v| match v.remove_vault(vault) {
            Ok(()) | Err(VaultError::NotFound) => Ok(()),
            Err(error) => Err(error.into()),
        })
    }

    // ── Server administration (administrators only) ─────────────────────────────────────────────────────

    pub async fn invites(&self) -> Result<Vec<Invite>> {
        self.api.invites().await
    }

    pub async fn create_invite(&self) -> Result<Invite> {
        self.api.create_invite().await
    }

    pub async fn revoke_invite(&self, code: &str) -> Result<()> {
        self.api.revoke_invite(code).await
    }

    pub async fn accounts(&self) -> Result<Vec<AdminAccount>> {
        self.api.accounts().await
    }

    pub async fn set_disabled(&self, account: &Id, disabled: bool) -> Result<()> {
        self.api.set_disabled(account, disabled).await
    }

    pub async fn delete_account(&self, account: &Id) -> Result<()> {
        self.api.delete_account(account).await
    }
}

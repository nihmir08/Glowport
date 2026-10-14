//! Was beim Abgleich mit dem Tresor geschieht (`docs/sync.md`): einrichten, anmelden, holen, schicken,
//! zusammenführen, Tresore teilen, Schlüssel tauschen.
//!
//! Jede Funktion wechselt zwischen kurzen Griffen in den Tresor ([`Door::enter`]) und Anfragen an den Server.
//! Dem Server wird dabei nichts geglaubt, was sich prüfen lässt: Datensätze, Mitgliederlisten und Schlüssel
//! prüft der Kern (`glowport_core::vault`), bevor etwas davon gilt.

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

/// So oft wird ein Paket nach einer Ablehnung zusammengeführt und neu geschickt, bevor die Runde endet.
const ROUNDS: usize = 5;

/// Geringster Aufwand der Schlüsselableitung, den ein Server beim Anmelden vorgeben darf. Ein böswilliger
/// Server könnte sonst winzige Werte nennen und das Master-Passwort aus dem Anmeldeschlüssel billig erraten.
/// (Die Vorgabe von Glowport liegt weit darüber; die Zahlen hier sind die übliche Untergrenze für Argon2id.)
pub const MIN_KDF: KdfParams = KdfParams { memory_kib: 19 * 1024, passes: 2, lanes: 1 };

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as i64)
}

fn envelopes(records: &[WireRecord]) -> Result<Vec<Envelope>> {
    records.iter().map(|record| record.envelope().ok_or(SyncError::Protocol("Datensatz"))).collect()
}

/// Ein Hinweis aus dem Abgleich, wie er im Tresor liegt und in den Einstellungen erscheint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Notice {
    /// Zwei Seiten haben dasselbe Feld geändert. `mine`: Der eigene Wert gilt.
    Clash { vault: String, record: String, path: String, mine: bool },
    /// Eine Seite hatte gelöscht, die andere geändert: Der Eintrag ist geblieben.
    Restored { vault: String, record: String },
    /// Eigene Änderungen wurden verworfen, weil man in diesem Tresor nicht (mehr) schreiben darf.
    Discarded { vault: String, count: usize },
    /// Man ist kein Mitglied mehr; die Kopie des Tresors auf diesem Gerät ist entfernt.
    VaultRemoved { vault: String },
    /// Der Server hat Datensätze geliefert, die die Prüfung nicht bestehen. Nichts davon wurde übernommen.
    Rejected { vault: String, count: usize },
}

fn note(vault: &mut Vault, notice: &Notice) -> Result<()> {
    Ok(vault.add_notice(&serde_json::to_vec(notice).map_err(|_| SyncError::Protocol("Hinweis"))?)?)
}

/// Hält fest, was beim Übernehmen auffiel. Liefert die Zahl der Hinweise.
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

/// Eine Einladung in einen geteilten Tresor, die noch niemand angenommen hat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Invitation {
    pub vault: String,
    /// Name des Tresors, sofern er sich schon lesen ließ.
    pub name: Option<String>,
    pub owner: String,
    pub role: Role,
    /// Sicherheitscode des Besitzers: sechs Wörter aus dem Prüfwert seiner Schlüssel.
    pub code: String,
    pub known: Known,
}

/// Ob die Schlüssel eines Kontos zu denen passen, die dieses Gerät früher von ihm gesehen hat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Known {
    New,
    Same,
    /// Andere Schlüssel als früher: Entweder hat das Konto neu angefangen, oder jemand schiebt falsche unter.
    Changed,
}

/// Ein Konto, das sich einladen lässt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Candidate {
    pub account: String,
    pub username: String,
    pub ed25519: String,
    pub x25519: String,
    /// Sicherheitscode des Kontos: sechs Wörter aus dem Prüfwert seiner Schlüssel.
    pub code: String,
    pub known: Known,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceInfo {
    pub id: String,
    /// Leer, wenn das Gerät noch keinen Namen hat oder er sich nicht lesen ließ.
    pub name: String,
    pub created_at: i64,
    pub seen_at: i64,
    pub current: bool,
}

/// Ergebnis einer Runde.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Report {
    /// Datensätze, Tresore oder Rollen haben sich geändert: Die Oberfläche liest neu.
    pub changed: bool,
    /// Änderungen, die noch nicht beim Server sind.
    pub pending: usize,
    pub invitations: Vec<Invitation>,
    /// Tresore, bei denen der Server einen älteren Stand hat als dieses Gerät. Sie ruhen, bis jemand
    /// [`Engine::resync`] auslöst.
    pub rolled_back: Vec<String>,
    /// Eigene geteilte Tresore, die der Server nicht mehr kennt. Die Kopie hier bleibt.
    pub orphaned: Vec<String>,
    /// Neue Hinweise aus dieser Runde.
    pub notices: usize,
    /// Das Master-Passwort wurde auf einem anderen Gerät geändert; hier gilt das neue ab dem ersten Entsperren damit.
    pub password_changed: bool,
    /// Tresor und Konto derer, die eingeladen sind und noch nicht angenommen haben.
    pub invited: Vec<(String, String)>,
    /// Ob dieses Konto den Server verwaltet, nach dem Stand dieser Runde.
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

/// Der Name eines geteilten Tresors steht verschlüsselt darin, als Datensatz der Art `vault-info`.
fn vault_name<T: AsRef<[u8]>>(plain: &[T]) -> Option<String> {
    plain.iter().filter_map(|bytes| serde_json::from_slice::<serde_json::Value>(bytes.as_ref()).ok()).find(|value| value["t"] == "vault-info").and_then(|value| value["name"].as_str().map(str::to_string))
}

fn wrapping_of(overview: &Overview) -> Option<Wrapping> {
    let account = &overview.account;
    Some(Wrapping { salt: account.salt.array()?, kdf: account.kdf.into(), account_nonce: account.account_nonce.0.clone(), account_wrapped: account.account_wrapped.0.clone() })
}

/// Führt Arbeit am Tresor aus, die rechnet (Schlüsselableitung), ohne die Netz-Threads aufzuhalten.
async fn heavy<D: Door, T: Send + 'static>(door: &Arc<D>, work: impl FnOnce(&mut Vault) -> Result<T> + Send + 'static) -> Result<T> {
    let door = door.clone();
    tokio::task::spawn_blocking(move || door.enter(work)).await.map_err(|_| SyncError::Protocol("abgebrochen"))?
}

/// Fragt einen Server, ob er einer von Glowport ist und zu dieser Version passt. Liefert die Adresse in
/// fester Form und seine Auskunft (darin: ob er noch auf sein erstes Konto wartet).
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

/// Meldet sich mit Benutzername und Master-Passwort an. Das Passwort verlässt das Gerät nicht: Zum Server
/// geht nur der daraus abgeleitete Anmeldeschlüssel.
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

/// Meldet ein eben angemeldetes Gerät wieder ab, wenn danach etwas scheitert. Gelingt das nicht, bleibt beim
/// Server ein namenloses Gerät stehen, das sich in der Geräteliste abmelden lässt.
async fn undo_sign_in(api: &Api, link: &Link) {
    if let Some(device) = unhex(&link.device) {
        let _ = api.with_token(&link.token).remove_device(&device).await;
    }
}

/// Macht den Tresor dieses Geräts zum Konto auf einem Server („Sync einrichten“). `code` ist ein
/// Einladungscode, beim allerersten Konto der Einrichtungscode des Servers.
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

/// Verbindet einen Tresor, der schon zu einem Konto gehört, wieder mit dem Server: nach dem Einspielen einer
/// Sicherung oder nachdem das Gerät abgemeldet wurde. Gehört der Tresor zu einem anderen Konto, scheitert es
/// mit [`SyncError::OtherAccount`]; dann führt der Weg über [`login_new`] und `Vault::adopt_from`.
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
        // Das eben benutzte Passwort ist das des Servers. Weicht seine Verpackung von der hiesigen ab, gilt sie
        // ab dem nächsten Entsperren damit.
        let theirs = Wrapping { salt: account.salt, kdf: account.kdf, account_nonce: account.account_nonce.clone(), account_wrapped: account.account_wrapped.clone() };
        if vault.current_wrapping()? != theirs {
            vault.stage_wrapping(&theirs)?;
        }
        // Was dieses Gerät vom Stand des Servers wusste, gilt nicht mehr: von vorn holen.
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

/// Legt auf einem Gerät ohne Tresor den eines bestehenden Kontos an („Mit Konto anmelden“). Der Tresor ist
/// danach offen und mit dem Server verbunden, aber noch leer: Den Inhalt holt die erste Runde.
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

/// Der Abgleich eines verbundenen Tresors.
pub struct Engine<D: Door> {
    door: Arc<D>,
    pub(crate) api: Api,
    link: Link,
    account: Id,
    device: Id,
}

impl<D: Door> Engine<D> {
    /// Liest die Anmeldung aus dem offenen Tresor. `None`: Der Abgleich ist nicht eingerichtet.
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

    // ── Eine Runde ───────────────────────────────────────────────────────────────────────────────────────

    /// Gleicht alles ab: Konto, Tresore, Mitgliedschaften, Datensätze in beide Richtungen.
    pub async fn sync(&self) -> Result<Report> {
        let overview = self.api.overview().await?;
        let mut report = Report { admin: overview.admin, ..Report::default() };
        let (local, writes) = self.door.enter(|vault| {
            if overview.account.ed25519_public.0 != vault.public_keys()?.0 {
                return Err(SyncError::OtherAccount);
            }
            // Wer den Server verwaltet, kann sich dort ändern; die gespeicherte Anmeldung zieht nach.
            if let Some(mut link) = Link::load(vault)?.filter(|link| link.admin != overview.admin) {
                link.admin = overview.admin;
                link.save(vault)?;
            }
            // Auf einem anderen Gerät wurde das Master-Passwort geändert: Die neue Verpackung wird vorgemerkt.
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
                // Auf einem anderen eigenen Gerät angenommen: Hier kommt der Tresor einfach dazu.
                None => {
                    if self.join(&id, entry)? {
                        self.sync_vault(&id, &mut report).await?;
                    }
                }
            }
        }

        // Geteilte Tresore, die der Server für dieses Konto nicht mehr führt.
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

    /// Ein geteilter Tresor, den es hier schon gibt: Schlüsseltausch und neue Mitgliederliste übernehmen,
    /// dann die Datensätze abgleichen.
    async fn sync_shared(&self, id: &Id, info: &VaultInfo, entry: &VaultEntry, report: &mut Report) -> Result<()> {
        let (Some(roster), Some(sealed_key)) = (&entry.roster, &entry.sealed_key) else { return Err(SyncError::Protocol("Tresor")) };
        if entry.epoch > info.epoch {
            // Der Besitzer hat den Schlüssel getauscht: Alles kommt neu verschlüsselt.
            let pull = self.api.pull(id, 0).await?;
            let rows = envelopes(&pull.records)?;
            let outcome = self.door.enter(|vault| match vault.apply_rotation(id, &sealed_key.0, &roster.0, &rows) {
                Ok(applied) => {
                    vault.set_cursor(id, pull.seq)?;
                    Ok(Some(note_applied(vault, id, &applied)?))
                }
                // Die neue Liste nennt dieses Konto nicht mehr.
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
            // Neue Mitglieder, mehr Rechte, Übergabe des Besitzes: Die Liste ist neuer, der Schlüssel derselbe.
            self.door.enter(|vault| {
                if vault.roster_blob(id)? != roster.0 {
                    match vault.set_roster(id, &roster.0) {
                        // Eine Liste, die die Prüfung nicht besteht, ändert nichts.
                        Ok(()) | Err(VaultError::Roster(_)) | Err(VaultError::NotMember) => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                Ok(())
            })?;
        }
        self.sync_vault(id, report).await?;

        // Wer gegangen ist oder eine Einladung abgelehnt hat, steht noch in der Liste, ist beim Server aber
        // kein Mitglied mehr. Der Besitzer nimmt ihn heraus und tauscht den Schlüssel.
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

    /// Holt, was es in einem Tresor Neues gibt, und schickt, was hier wartet.
    async fn sync_vault(&self, id: &Id, report: &mut Report) -> Result<()> {
        let mut reconciled = false;
        for _ in 0..ROUNDS {
            let (cursor, info) = self.door.enter(|vault| Ok((vault.cursor(id)?, vault.vaults()?.into_iter().find(|info| info.id == *id).ok_or(VaultError::NotFound)?)))?;
            let pull = self.api.pull(id, cursor).await?;
            if pull.epoch != info.epoch {
                // Mitten in einem Schlüsseltausch: Die nächste Runde beginnt wieder bei der Übersicht.
                return Ok(());
            }
            let rows = envelopes(&pull.records)?;
            let may_write = info.role.may_write();
            // Eine kleinere Nummer als die zuletzt gesehene: Der Server weiß weniger als dieses Gerät.
            let mut consistent = pull.seq >= cursor || reconciled;
            let outgoing = self.door.enter(|vault| {
                if consistent {
                    let applied = vault.apply_remote(id, &rows)?;
                    if pull.full {
                        vault.retain_synced(id, &rows.iter().map(|row| row.id).collect())?;
                    }
                    vault.set_cursor(id, pull.seq)?;
                    report.notices += note_applied(vault, id, &applied)?;
                    // Stimmt jetzt, was dieses Gerät für den Stand des Servers hält, mit dessen Prüfsumme überein?
                    consistent = reconciled || pull.digest.0.is_empty() || vault.believed_digest(id)?.as_slice() == pull.digest.0;
                }
                if !consistent {
                    return Ok(Vec::new());
                }
                if may_write {
                    return Ok(vault.outgoing(id)?);
                }
                // Wer nur lesen darf, behält keine wartenden Änderungen (etwa aus der Zeit vor dem Herabstufen).
                let discarded = vault.discard_pending(id)?;
                if discarded > 0 {
                    note(vault, &Notice::Discarded { vault: hex(id), count: discarded })?;
                    report.notices += 1;
                }
                Ok(Vec::new())
            })?;
            if !consistent {
                // Etwas verpasst oder der Server hat etwas verloren: den ganzen Stand vergleichen.
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
                        // Nur wenn zwischen Holen und Schicken sonst nichts geschah, ist damit alles bekannt.
                        if reply.seq == pull.seq + 1 {
                            vault.set_cursor(id, reply.seq)?;
                        }
                        Ok(())
                    });
                }
                // Abgelehnt wegen eines anderen Schlüsselstands: Die nächste Runde holt den Tausch nach.
                Ok(reply) if reply.conflicts.is_empty() => return Ok(()),
                // Ein anderes Gerät war schneller: zusammenführen und noch einmal.
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

    /// Vergleicht den ganzen Stand eines Tresors mit dem des Servers. Hat der Server nur Neueres, wird es
    /// übernommen (`true`). Fehlt ihm etwas, das hier als abgeglichen gilt, hat er einen älteren Stand: Dann
    /// ändert sich nichts, der Tresor wird gemeldet und ruht, bis jemand [`Engine::resync`] auslöst (`false`).
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

    /// Sieht sich eine Einladung an: Wer lädt ein, in welcher Rolle, wie heißt der Tresor.
    async fn invitation(&self, id: &Id, entry: &VaultEntry) -> Result<Option<Invitation>> {
        let (Some(roster), Some(sealed_key)) = (&entry.roster, &entry.sealed_key) else { return Ok(None) };
        let rows = envelopes(&self.api.pull(id, 0).await?.records)?;
        self.door.enter(|vault| {
            // Eine Einladung, die die Prüfung nicht besteht, wird nicht gezeigt.
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

    /// Nimmt einen geteilten Tresor auf dieses Gerät und merkt sich die Schlüssel seines Besitzers.
    /// Liefert `false`, wenn Liste oder Schlüssel die Prüfung nicht bestehen.
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

    /// Der Server hat einen älteren Stand als dieses Gerät (siehe [`Report::rolled_back`]), etwa weil er aus
    /// einer Sicherung zurückgeholt wurde: Was hier neuer ist, geht wieder hinauf.
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

    // ── Konto und Geräte ─────────────────────────────────────────────────────────────────────────────────

    /// Ändert das Master-Passwort: erst beim Server, dann hier. So kennt nie nur dieses Gerät das neue.
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

    /// Meldet ein Gerät des Kontos ab. Was es schon hat, bleibt dort lesbar, solange jemand das Master-Passwort kennt.
    pub async fn remove_device(&self, device: &Id) -> Result<()> {
        self.api.remove_device(device).await
    }

    /// Meldet dieses Gerät beim Server ab und lässt den Tresor unberührt; vor dem Löschen der Daten dieses PCs.
    /// Anders als [`Engine::unlink`] meldet es, wenn der Server nicht erreichbar war. Kennt der Server das Gerät
    /// nicht mehr, ist es schon abgemeldet.
    pub async fn sign_out(&self) -> Result<()> {
        match self.api.remove_device(&self.device).await {
            Err(SyncError::Refused { status: 401 | 403 | 404, .. }) => Ok(()),
            other => other,
        }
    }

    /// Trennt dieses Gerät vom Server. Der Tresor bleibt, wie er ist, auch die geteilten.
    pub async fn unlink(&self) -> Result<()> {
        // Gelingt das Abmelden nicht (kein Netz), bleibt das Gerät in der Liste stehen und lässt sich dort abmelden.
        let _ = self.api.remove_device(&self.device).await;
        self.door.enter(|vault| {
            for info in vault.vaults()? {
                vault.set_cursor(&info.id, 0)?;
            }
            Ok(vault.set_link(None)?)
        })
    }

    // ── Geteilte Tresore ─────────────────────────────────────────────────────────────────────────────────

    /// Legt einen geteilten Tresor an; man selbst ist Besitzer.
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

    /// Sucht ein Konto zum Einladen und sagt, ob seine Schlüssel zu früher gesehenen passen.
    pub async fn lookup(&self, username: &str) -> Result<Candidate> {
        let keys = self.api.keys(username.trim()).await?;
        let (account, ed25519, x25519) = keys.account_id.array::<16>().zip(keys.ed25519.array::<32>()).zip(keys.x25519.array::<32>()).map(|((a, b), c)| (a, hex(&b), hex(&c))).ok_or(SyncError::Protocol("Schlüssel"))?;
        let code = code_of(&ed25519, &x25519).ok_or(SyncError::Protocol("Schlüssel"))?;
        let known = self.door.enter(|vault| known(vault, &account, &ed25519, &x25519))?;
        Ok(Candidate { account: hex(&account), username: keys.username, ed25519, x25519, code, known })
    }

    /// Lädt ein Konto in einen eigenen Tresor ein. Nur der Besitzer.
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

    /// Ändert die Rolle eines Mitglieds. Mehr Rechte gelten sofort; weniger tauscht den Schlüssel.
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

    /// Entfernt ein Mitglied und tauscht den Schlüssel. Was das Mitglied schon gesehen hat, holt das nicht zurück.
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

    /// Übergibt den Besitz an ein Mitglied; man selbst behält das Schreibrecht.
    pub async fn transfer(&self, vault: &Id, account: &Id) -> Result<()> {
        let account = hex(account);
        let roster = self.info(vault)?.roster.ok_or(VaultError::NotOwner)?;
        let to = roster.members.iter().find(|member| member.account == account && member.role != Role::Owner).and_then(Member::signing_key).ok_or(SyncError::Invalid("member"))?;
        let blob = self.door.enter(|v| Ok(v.transfer_roster(vault, &to)?))?;
        self.api.roster(vault, &RosterUpdate { roster: (&blob).into(), keys: Vec::new() }).await?;
        self.door.enter(|v| Ok(v.set_roster(vault, &blob)?))
    }

    /// Neue Mitgliederliste beim selben Schlüsselstand.
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

    /// Schlüsseltausch: neue Liste, neuer Schlüssel, alle Datensätze neu verschlüsselt, als ein Paket. Der
    /// Server nimmt es nur an, wenn inzwischen niemand geschrieben hat; sonst von vorn.
    async fn rotate(&self, vault: &Id, change: impl Fn(&mut Roster)) -> Result<()> {
        for _ in 0..ROUNDS {
            // Erst abgleichen: Der Tausch braucht einen Tresor ohne wartende Änderungen und den Stand des Servers.
            self.sync_vault(vault, &mut Report::default()).await?;
            let prepared = self.door.enter(|v| {
                let mut roster = v.vaults()?.into_iter().find(|info| info.id == *vault).and_then(|info| info.roster).ok_or(VaultError::NotFound)?;
                change(&mut roster);
                roster.version += 1;
                roster.epoch += 1;
                match v.prepare_rotation(vault, &roster) {
                    Ok(rotation) => Ok(Some((rotation, v.cursor(vault)?))),
                    // Zwischen Abgleich und Vorbereitung wurde hier etwas geändert: noch eine Runde.
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

    /// Nimmt eine Einladung an.
    pub async fn accept(&self, vault: &Id) -> Result<()> {
        let overview = self.api.overview().await?;
        let entry = overview.vaults.iter().find(|entry| entry.id.0 == vault).ok_or(SyncError::Invalid("invitation"))?;
        self.api.accept(vault).await?;
        if self.join(vault, entry)? {
            self.sync_vault(vault, &mut Report::default()).await?;
        }
        Ok(())
    }

    /// Lehnt eine Einladung ab oder verlässt einen Tresor. Der Besitzer kann nicht gehen.
    pub async fn leave(&self, vault: &Id) -> Result<()> {
        self.api.leave(vault).await?;
        self.forget(vault)
    }

    /// Löscht einen eigenen geteilten Tresor für alle.
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

    // ── Verwaltung des Servers (nur für den Verwalter) ───────────────────────────────────────────────────

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

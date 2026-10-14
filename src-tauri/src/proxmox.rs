//! Proxmox (`docs/verwaltung.md`): Verbindungen prüfen und speichern, Maschinen auflisten und schalten, Hosts aus
//! ihnen anlegen und aktuell halten.
//!
//! Der Zugriff auf die Schnittstelle kommt aus `glowport_proxmox`, die Datensätze aus `glowport_core`. Hier treffen
//! sich beide: Das Geheimnis eines Tokens geht aus dem Tresor nur an den Server seiner Verbindung, und nur über ein
//! Zertifikat, das anerkannt oder vom Nutzer bestätigt ist. Das Nachlesen der Übersicht zählt nicht als Eingabe für
//! die Auto-Sperre.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use glowport_core::{
    directory::{GuestHost, GuestSeen, ProxmoxAccess, ProxmoxInput},
    vault::VaultError,
};
use glowport_proxmox::{fingerprint_text, look, normalize, parse_fingerprint, Client, Facts, Guest, Kind, Power, PveError};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

use crate::app::{emit_snapshot_quiet, AppState, Changed, CmdError, CmdResult};

/// So lange gilt, was über eine Maschine gelesen wurde (Einstellungen, Adresse), bevor neu gefragt wird.
const FACTS_AGE: Duration = Duration::from_secs(60);
/// So viele Maschinen werden zugleich gefragt.
const PARALLEL: usize = 6;
/// So lange gilt nach dem Schalten, was die Maschine selbst über ihren Zustand gesagt hat, vor dem, was die Liste
/// aller Maschinen nennt. Proxmox erneuert diese Liste nur alle paar Sekunden.
const SETTLED_AGE: Duration = Duration::from_secs(30);

/// Was zuletzt über eine Maschine gelesen wurde.
struct Known {
    at: Instant,
    status: &'static str,
    facts: Facts,
}

/// Der Zugang zu einem Proxmox-Server, solange sich an seiner Verbindung nichts ändert.
struct Link {
    access: ProxmoxAccess,
    client: Client,
    facts: Mutex<HashMap<u32, Known>>,
    /// Je eben geschalteter Maschine: ihr Zustand danach und wann.
    settled: Mutex<HashMap<u32, (Instant, &'static str)>>,
}

impl Link {
    fn settled(&self) -> MutexGuard<'_, HashMap<u32, (Instant, &'static str)>> {
        self.settled.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Setzt bei eben geschalteten Maschinen den Zustand ein, den sie selbst genannt haben, solange die Liste
    /// noch den alten führt. Hat die Liste aufgeholt, ist die Sache erledigt.
    fn settle(&self, guests: &mut [Guest]) {
        let mut settled = self.settled();
        settled.retain(|_, (at, _)| at.elapsed() < SETTLED_AGE);
        for guest in guests {
            match settled.get(&guest.vmid) {
                Some((_, status)) if *status != guest.status => {
                    guest.status = status;
                    if guest.status != "running" {
                        (guest.cpu, guest.uptime) = (None, None);
                        guest.memory = guest.memory.map(|(_, total)| (0, total));
                    }
                }
                Some(_) => drop(settled.remove(&guest.vmid)),
                None => {}
            }
        }
    }

    fn known(&self) -> MutexGuard<'_, HashMap<u32, Known>> {
        self.facts.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Die offenen Zugänge, je Verbindung einer.
#[derive(Default)]
pub struct Links(Mutex<HashMap<String, Arc<Link>>>);

fn failed(error: PveError) -> CmdError {
    let message = match &error {
        PveError::Failed(said) => said.clone(),
        PveError::Offline(why) => why.clone(),
        other => other.to_string(),
    };
    CmdError::new(error.code(), message)
}

fn locked() -> CmdError {
    VaultError::Locked.into()
}

/// Der Zugang zu einer Verbindung. `quiet`: Der Zugriff auf den Tresor zählt nicht als Eingabe (Nachlesen).
fn link(app: &AppHandle, id: &str, quiet: bool) -> CmdResult<Arc<Link>> {
    let access = {
        let state = app.state::<AppState>();
        let mut session = state.session();
        let directory = if quiet { session.directory_quiet().ok_or_else(locked)? } else { session.directory()? };
        directory.proxmox_access(id)?
    };
    let links = app.state::<Links>();
    let mut links = links.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(link) = links.get(id).filter(|link| link.access == access) {
        return Ok(link.clone());
    }
    let pin = match &access.fingerprint {
        Some(text) => Some(parse_fingerprint(text).ok_or_else(|| failed(PveError::Certificate))?),
        None => None,
    };
    let client = Client::new(&access.address, &access.token_id, access.secret.expose(), pin).map_err(failed)?;
    let link = Arc::new(Link { access, client, facts: Mutex::default(), settled: Mutex::default() });
    links.insert(id.to_string(), link.clone());
    Ok(link)
}

/// Der Tresor wird gesperrt: Die offenen Zugänge tragen das Geheimnis ihres Tokens und verschwinden mit.
pub(crate) fn forget_all(app: &AppHandle) {
    app.state::<Links>().0.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clear();
}

fn forget(app: &AppHandle, id: &str) {
    app.state::<Links>().0.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).remove(id);
}

/// Was über die Maschinen zu wissen ist, um sich mit ihnen zu verbinden. Gefragt wird nur, wessen Stand alt ist
/// oder wer seinen Zustand gewechselt hat; eine laufende Maschine ohne Adresse jedes Mal, bis sie eine nennt.
async fn facts_of(link: &Arc<Link>, guests: &[Guest]) -> HashMap<u32, Facts> {
    let mut found = HashMap::new();
    let mut tasks = tokio::task::JoinSet::new();
    let gate = Arc::new(tokio::sync::Semaphore::new(PARALLEL));
    {
        let known = link.known();
        for guest in guests {
            let fresh = |k: &&Known| k.status == guest.status && k.at.elapsed() < FACTS_AGE && !(guest.status == "running" && k.facts.address.is_none());
            match known.get(&guest.vmid).filter(fresh) {
                Some(k) => drop(found.insert(guest.vmid, k.facts.clone())),
                None => {
                    let (link, guest, gate) = (link.clone(), guest.clone(), gate.clone());
                    tasks.spawn(async move {
                        let _turn = gate.acquire().await;
                        (guest.vmid, guest.status, link.client.facts(&guest).await)
                    });
                }
            }
        }
    }
    while let Some(done) = tasks.join_next().await {
        // Gibt Proxmox die Einstellungen einer Maschine nicht her, bleibt offen, wie sie zu erreichen ist; beim
        // nächsten Nachlesen wird wieder gefragt.
        if let Ok((vmid, status, Ok(facts))) = done {
            link.known().insert(vmid, Known { at: Instant::now(), status, facts: facts.clone() });
            found.insert(vmid, facts);
        }
    }
    found
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Usage {
    used: u64,
    total: u64,
}

fn usage(memory: Option<(u64, u64)>) -> Option<Usage> {
    memory.map(|(used, total)| Usage { used, total })
}

#[derive(Debug, Serialize, PartialEq)]
pub struct NodeView {
    node: String,
    online: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    cpu: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cores: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    memory: Option<Usage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    uptime: Option<u64>,
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GuestView {
    node: String,
    vmid: u32,
    kind: &'static str,
    name: String,
    status: &'static str,
    template: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    cpu: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cores: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    memory: Option<Usage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    uptime: Option<u64>,
    tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<String>,
    /// Kennung und Name des Schlüssels im Tresor, den Cloud-Init für diese Maschine hinterlegt hat.
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    os: Option<&'static str>,
    /// Kennung des Hosts, der zu dieser Maschine gehört.
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<String>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Overview {
    version: String,
    nodes: Vec<NodeView>,
    guests: Vec<GuestView>,
}

/// Knoten und Maschinen einer Verbindung. Dabei ziehen verknüpfte Hosts nach, wenn sich in Proxmox ihr Name oder
/// ihre Adresse geändert hat; dann bekommen alle Fenster den neuen Stand, und der Abgleich läuft an. `fresh`: Der
/// Nutzer will neu lesen; dann wird jede Maschine gefragt, auch wenn ihr Stand noch nicht alt ist.
#[tauri::command]
pub async fn proxmox_overview(app: AppHandle, id: String, fresh: Option<bool>) -> CmdResult<Overview> {
    let link = link(&app, &id, true)?;
    if fresh == Some(true) {
        link.known().clear();
    }
    let (version, mut guests) = tokio::try_join!(link.client.version(), link.client.guests()).map_err(failed)?;
    link.settle(&mut guests);
    // Ohne das Recht, die Knoten zu sehen, bleiben ihre Namen aus der Liste der Maschinen.
    let mut nodes: Vec<NodeView> = link.client.nodes().await.unwrap_or_default().into_iter().map(|n| NodeView { node: n.node, online: n.online, cpu: n.cpu, cores: n.cores, memory: usage(n.memory), uptime: n.uptime }).collect();
    for guest in &guests {
        if !nodes.iter().any(|n| n.node == guest.node) {
            nodes.push(NodeView { node: guest.node.clone(), online: true, cpu: None, cores: None, memory: None, uptime: None });
        }
    }
    let facts = facts_of(&link, &guests).await;
    let address = |guest: &Guest| facts.get(&guest.vmid).and_then(|f| f.address.as_ref());

    let (overview, changed) = {
        let state = app.state::<AppState>();
        let mut session = state.session();
        let directory = session.directory_quiet().ok_or_else(locked)?;
        let seen: Vec<GuestSeen> = guests.iter().map(|g| GuestSeen { node: g.node.clone(), vmid: g.vmid, name: g.name.clone(), address: address(g).map(|(address, _)| address.clone()) }).collect();
        let changed = directory.follow_proxmox(&id, &seen)?;
        let guests = guests
            .iter()
            .map(|g| {
                let known = facts.get(&g.vmid);
                let key = known.and_then(|f| f.keys.iter().find_map(|fingerprint| directory.key_by_fingerprint(fingerprint)));
                GuestView {
                    node: g.node.clone(),
                    vmid: g.vmid,
                    kind: g.kind.name(),
                    name: g.name.clone(),
                    status: g.status,
                    template: g.template,
                    cpu: g.cpu,
                    cores: g.cores,
                    memory: usage(g.memory),
                    uptime: g.uptime,
                    tags: g.tags.clone(),
                    address: address(g).map(|(address, _)| address.clone()),
                    source: address(g).map(|(_, source)| source.name()),
                    user: known.and_then(|f| f.user.clone()),
                    key: key.map(|(id, _)| id.to_string()),
                    key_name: key.map(|(_, name)| name.to_string()),
                    os: known.and_then(|f| f.os),
                    host: directory.proxmox_host(&id, g.vmid).map(str::to_string),
                }
            })
            .collect();
        (Overview { version, nodes, guests }, changed)
    };
    if changed {
        emit_snapshot_quiet(&app);
        crate::sync::poke(&app);
    }
    Ok(overview)
}

/// Was eine Prüfung der Angaben ergab (`ProxmoxProbe` in `types.ts`).
#[derive(Debug, Serialize, PartialEq)]
pub struct Probe {
    /// Leer, solange der Fingerabdruck eines selbst erstellten Zertifikats nicht bestätigt ist: Bis dahin ist der
    /// Token nicht hinausgegangen.
    version: String,
    trusted: bool,
    fingerprint: String,
    missing: Vec<&'static str>,
    /// Der Server zeigt ein anderes Zertifikat als das, dessen Fingerabdruck mitkam.
    changed: bool,
}

/// Prüft Adresse, Zertifikat und Token, ohne etwas zu speichern. In zwei Schritten: Erst wird nur die Verbindung
/// aufgebaut und das Zertifikat angesehen. Ist es anerkannt, oder nennt die Eingabe genau seinen Fingerabdruck (der
/// Nutzer hat ihn bestätigt), geht der Token hinaus und liest Version und Rechte.
#[tauri::command]
pub async fn proxmox_probe(app: AppHandle, input: ProxmoxInput) -> CmdResult<Probe> {
    let address = normalize(&input.address).map_err(failed)?;
    let seen = look(&address).await.map_err(failed)?;
    let confirmed = input.fingerprint.as_deref().and_then(parse_fingerprint);
    let waiting = |changed| Probe { version: String::new(), trusted: false, fingerprint: fingerprint_text(&seen.fingerprint), missing: Vec::new(), changed };
    let pin = match (seen.trusted, confirmed) {
        (true, _) => None,
        (false, Some(confirmed)) if confirmed == seen.fingerprint => Some(confirmed),
        (false, other) => return Ok(waiting(other.is_some())),
    };
    // Ohne neues Geheimnis gilt das gespeicherte der Verbindung, die gerade bearbeitet wird.
    let secret = match (input.secret.filter(|secret| !secret.expose().trim().is_empty()), &input.id) {
        (Some(secret), _) => secret,
        (None, Some(id)) => app.state::<AppState>().session().directory()?.proxmox_access(id)?.secret,
        (None, None) => return Err(failed(PveError::Token)),
    };
    let client = Client::new(&address, &input.token_id, secret.expose(), pin).map_err(failed)?;
    let version = client.version().await.map_err(failed)?;
    // Lässt sich nicht lesen, was der Token darf, wird nichts bemängelt; es zeigt sich dann beim Benutzen.
    let missing = client.missing().await.unwrap_or_default().into_iter().map(|missing| missing.name()).collect();
    Ok(Probe { version, trusted: seen.trusted, missing, ..waiting(false) })
}

#[tauri::command]
pub fn proxmox_save(app: AppHandle, mut input: ProxmoxInput) -> CmdResult<Changed> {
    input.address = normalize(&input.address).map_err(failed)?;
    let state = app.state::<AppState>();
    let mut session = state.session();
    let id = session.directory()?.save_proxmox(input)?;
    forget(&app, &id);
    session.changed(Some(id))
}

/// Entfernt die Verbindung. Die Hosts bleiben und verlieren nur ihre Verknüpfung.
#[tauri::command]
pub fn proxmox_delete(app: AppHandle, id: String) -> CmdResult<Changed> {
    let state = app.state::<AppState>();
    let mut session = state.session();
    session.directory()?.delete_proxmox(&id)?;
    forget(&app, &id);
    session.changed(None)
}

/// Eine Maschine, wie die Oberfläche sie benennt.
#[derive(Debug, Deserialize)]
pub struct GuestRef {
    node: String,
    vmid: u32,
    kind: String,
}

/// Starten, herunterfahren, hart stoppen, neu starten. Kehrt zurück, wenn Proxmox den Auftrag ausgeführt hat.
#[tauri::command]
pub async fn proxmox_action(app: AppHandle, id: String, guest: GuestRef, action: String) -> CmdResult<()> {
    let invalid = || CmdError::new("proxmox_failed", "Ungültige Angabe");
    let kind = match guest.kind.as_str() {
        "qemu" => Kind::Qemu,
        "lxc" => Kind::Lxc,
        _ => return Err(invalid()),
    };
    let action = match action.as_str() {
        "start" => Power::Start,
        "shutdown" => Power::Shutdown,
        "stop" => Power::Stop,
        "reboot" => Power::Reboot,
        _ => return Err(invalid()),
    };
    let link = link(&app, &id, false)?;
    let outcome = link.client.power(&guest.node, kind, guest.vmid, action).await;
    // Nach dem Schalten stimmt nicht mehr, was über die Maschine gelesen wurde.
    link.known().remove(&guest.vmid);
    if outcome.is_ok() {
        // Die Liste aller Maschinen nennt jetzt noch den alten Zustand; die Oberfläche soll gleich den neuen
        // zeigen. Also die Maschine selbst fragen. Antwortet sie nicht, gilt, was der Auftrag bewirkt hat.
        let expected = if matches!(action, Power::Start | Power::Reboot) { "running" } else { "stopped" };
        let status = link.client.status(&guest.node, kind, guest.vmid).await.unwrap_or(expected);
        link.settled().insert(guest.vmid, (Instant::now(), status));
    }
    outcome.map_err(failed)
}

/// Legt aus den gewählten Maschinen Hosts an und verknüpft sie. Was über sie eingetragen wird (Adresse, Benutzer,
/// Schlüssel, Betriebssystem), liest der Kern selbst aus Proxmox; die Oberfläche nennt nur, welche.
#[tauri::command]
pub async fn proxmox_import(app: AppHandle, id: String, picks: Vec<GuestRef>, group: Option<String>) -> CmdResult<Changed> {
    let link = link(&app, &id, false)?;
    let wanted: Vec<Guest> = link.client.guests().await.map_err(failed)?.into_iter().filter(|g| picks.iter().any(|pick| pick.vmid == g.vmid && pick.node == g.node && pick.kind == g.kind.name())).collect();
    let facts = facts_of(&link, &wanted).await;
    let state = app.state::<AppState>();
    let mut session = state.session();
    let directory = session.directory()?;
    let hosts = wanted
        .into_iter()
        .map(|g| {
            let known = facts.get(&g.vmid).cloned().unwrap_or_default();
            let key = known.keys.iter().find_map(|fingerprint| directory.key_by_fingerprint(fingerprint)).map(|(id, _)| id.to_string());
            GuestHost { kind: g.kind.name().into(), node: g.node, vmid: g.vmid, name: g.name, address: known.address.map(|(address, _)| address), user: known.user, key, os: known.os.map(str::to_string) }
        })
        .collect();
    directory.add_proxmox_hosts(&id, hosts, group.as_deref())?;
    session.changed(None)
}

/// Nimmt ein Host an seinem Port Verbindungen an? Ein einzelner Versuch, für „Starten und verbinden“: Eine eben
/// gestartete Maschine braucht eine Weile, bis ihr SSH-Server läuft. Über einen Sprung-Server oder Proxy lässt sich
/// von hier aus nicht fragen; dann gilt der Host als erreichbar, und das Verbinden selbst zeigt, ob es stimmt.
#[tauri::command]
pub async fn proxmox_reachable(app: AppHandle, host: String) -> CmdResult<bool> {
    let target = {
        let state = app.state::<AppState>();
        let mut session = state.session();
        let directory = session.directory()?;
        let info = if directory.is_ssh(&host) { Some(directory.connect_info(&host)?) } else { None };
        info.filter(|info| info.jump.is_none() && info.proxy.is_none()).map(|info| (info.address.clone(), info.port))
    };
    let Some(target) = target else { return Ok(true) };
    Ok(matches!(tokio::time::timeout(Duration::from_secs(3), tokio::net::TcpStream::connect(target)).await, Ok(Ok(_))))
}

/// Löst die Verknüpfung eines Hosts mit seiner Maschine. Der Host bleibt, wie er ist.
#[tauri::command]
pub fn proxmox_unlink(app: AppHandle, host: String) -> CmdResult<Changed> {
    let state = app.state::<AppState>();
    let mut session = state.session();
    session.directory()?.unlink_proxmox(&host)?;
    session.changed(None)
}

//! Proxmox (`docs/management.md`): check and save connections, list and switch machines, create hosts from
//! them and keep them up to date.
//!
//! Access to the API comes from `glowport_proxmox`, the records from `glowport_core`. This is where
//! both meet: a token's secret only goes from the vault to the server of its connection, and only over a
//! certificate that is trusted or confirmed by the user. Refreshing the overview does not count as input for
//! the auto-lock.

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

/// This long what was read about a machine (settings, address) applies before it is asked again.
const FACTS_AGE: Duration = Duration::from_secs(60);
/// This many machines are asked at the same time.
const PARALLEL: usize = 6;
/// For this long after switching, what the machine itself said about its state applies before what the list
/// of all machines names. Proxmox only refreshes that list every few seconds.
const SETTLED_AGE: Duration = Duration::from_secs(30);

/// What was last read about a machine.
struct Known {
    at: Instant,
    status: &'static str,
    facts: Facts,
}

/// Access to a Proxmox server, as long as nothing changes about its connection.
struct Link {
    access: ProxmoxAccess,
    client: Client,
    facts: Mutex<HashMap<u32, Known>>,
    /// Per machine just switched: its state afterwards and when.
    settled: Mutex<HashMap<u32, (Instant, &'static str)>>,
}

impl Link {
    fn settled(&self) -> MutexGuard<'_, HashMap<u32, (Instant, &'static str)>> {
        self.settled.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// For machines just switched, fills in the state they named themselves while the list
    /// still carries the old one. Once the list has caught up, the matter is settled.
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

/// The open accesses, one per connection.
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

/// Access to a connection. `quiet`: the access to the vault does not count as input (refreshing).
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

/// The vault is being locked: the open accesses carry their token's secret and disappear with it.
pub(crate) fn forget_all(app: &AppHandle) {
    app.state::<Links>().0.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clear();
}

fn forget(app: &AppHandle, id: &str) {
    app.state::<Links>().0.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).remove(id);
}

/// What there is to know about the machines in order to connect to them. Only those whose state is old
/// or that changed their state are asked; a running machine without an address every time until it names one.
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
        // If Proxmox does not hand out a machine's settings, how to reach it stays open; it is asked again
        // on the next refresh.
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
    /// ID and name of the key in the vault that Cloud-Init stored for this machine.
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    os: Option<&'static str>,
    /// ID of the host that belongs to this machine.
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<String>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Overview {
    version: String,
    nodes: Vec<NodeView>,
    guests: Vec<GuestView>,
}

/// Nodes and machines of a connection. Linked hosts follow along when their name or
/// address changed in Proxmox; then all windows get the new state, and syncing starts. `fresh`: the
/// user wants to reload; then every machine is asked, even if its state is not old yet.
#[tauri::command]
pub async fn proxmox_overview(app: AppHandle, id: String, fresh: Option<bool>) -> CmdResult<Overview> {
    let link = link(&app, &id, true)?;
    if fresh == Some(true) {
        link.known().clear();
    }
    let (version, mut guests) = tokio::try_join!(link.client.version(), link.client.guests()).map_err(failed)?;
    link.settle(&mut guests);
    // Without the permission to see the nodes, their names come from the list of machines.
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

/// What checking the details resulted in (`ProxmoxProbe` in `types.ts`).
#[derive(Debug, Serialize, PartialEq)]
pub struct Probe {
    /// Empty as long as the fingerprint of a self-signed certificate is not confirmed: until then the
    /// token has not gone out.
    version: String,
    trusted: bool,
    fingerprint: String,
    missing: Vec<&'static str>,
    /// The server shows a different certificate than the one whose fingerprint came along.
    changed: bool,
}

/// Checks address, certificate and token without saving anything. In two steps: first only the connection
/// is established and the certificate looked at. If it is trusted, or the input names exactly its fingerprint (the
/// user confirmed it), the token goes out and reads version and permissions.
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
    // Without a new secret, the saved one of the connection currently being edited applies.
    let secret = match (input.secret.filter(|secret| !secret.expose().trim().is_empty()), &input.id) {
        (Some(secret), _) => secret,
        (None, Some(id)) => app.state::<AppState>().session().directory()?.proxmox_access(id)?.secret,
        (None, None) => return Err(failed(PveError::Token)),
    };
    let client = Client::new(&address, &input.token_id, secret.expose(), pin).map_err(failed)?;
    let version = client.version().await.map_err(failed)?;
    // If what the token may do cannot be read, nothing is criticised; it then shows when using it.
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

/// Removes the connection. The hosts stay and only lose their link.
#[tauri::command]
pub fn proxmox_delete(app: AppHandle, id: String) -> CmdResult<Changed> {
    let state = app.state::<AppState>();
    let mut session = state.session();
    session.directory()?.delete_proxmox(&id)?;
    forget(&app, &id);
    session.changed(None)
}

/// A machine as the interface names it.
#[derive(Debug, Deserialize)]
pub struct GuestRef {
    node: String,
    vmid: u32,
    kind: String,
}

/// Start, shut down, hard stop, restart. Returns when Proxmox has carried out the task.
#[tauri::command]
pub async fn proxmox_action(app: AppHandle, id: String, guest: GuestRef, action: String) -> CmdResult<()> {
    let invalid = || CmdError::new("proxmox_failed", "Invalid value");
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
    // After switching, what was read about the machine is no longer right.
    link.known().remove(&guest.vmid);
    if outcome.is_ok() {
        // The list of all machines still names the old state now; the interface should show the new one
        // right away. So ask the machine itself. If it does not answer, what the task brought about applies.
        let expected = if matches!(action, Power::Start | Power::Reboot) { "running" } else { "stopped" };
        let status = link.client.status(&guest.node, kind, guest.vmid).await.unwrap_or(expected);
        link.settled().insert(guest.vmid, (Instant::now(), status));
    }
    outcome.map_err(failed)
}

/// Creates hosts from the chosen machines and links them. What is entered about them (address, user,
/// key, operating system) the core reads from Proxmox itself; the interface only names which ones.
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

/// Does a host accept connections on its port? A single attempt, for “Start and connect”: a machine just
/// started needs a while until its SSH server runs. Through a jump host or proxy it cannot be asked
/// from here; then the host counts as reachable, and connecting itself shows whether that is true.
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

/// Unlinks a host from its machine. The host stays as it is.
#[tauri::command]
pub fn proxmox_unlink(app: AppHandle, host: String) -> CmdResult<Changed> {
    let state = app.state::<AppState>();
    let mut session = state.session();
    session.directory()?.unlink_proxmox(&host)?;
    session.changed(None)
}

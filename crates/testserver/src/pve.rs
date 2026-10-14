//! Ein nachgebauter Proxmox-Server: über TLS mit einem selbst erstellten Zertifikat, wie Proxmox es mitbringt. Die
//! Wege und Antworten sind nach der Dokumentation der Schnittstelle gebaut, nicht an einem echten Server
//! aufgezeichnet.
//!
//! Es gibt zwei Tokens: [`TOKEN`] darf alles, `leser@pve!test` nur sehen; beide mit [`SECRET`]. Unter `/test/…`
//! (ohne Anmeldung, nur für Prüfungen) lässt sich der Stand verstellen, so als hätte jemand in Proxmox den Namen
//! oder die Adresse einer Maschine geändert oder ihr Zertifikat erneuert.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    Json, Router,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const TOKEN: &str = "glowport@pve!test";
pub const SECRET: &str = "0c6f2c1e-58a1-4c0e-9d3b-7a1f0e2b4c55";

#[derive(Default)]
pub struct World {
    /// Jeder Kopf `Authorization`, den der Server zu sehen bekam.
    pub tokens: Vec<String>,
    /// Zustand je Maschine, soweit er sich geändert hat.
    pub status: HashMap<u32, &'static str>,
    /// Wie oft nach einem Auftrag gefragt wurde.
    pub polls: HashMap<String, u32>,
    /// Name und feste Adresse der VM 101, soweit sie verstellt wurden.
    pub renamed: Option<String>,
    pub readdressed: Option<String>,
    /// Wie oft die Einstellungen einer Maschine gelesen wurden.
    pub configs: u32,
    /// So lange nennt die Liste aller Maschinen nach einem Schalten noch den alten Zustand. Proxmox führt sie aus
    /// einem Stand, den es nur alle paar Sekunden erneuert; `status/current` einer Maschine stimmt sofort.
    pub lag: Duration,
    /// Je geschalteter Maschine: ihr Zustand davor und wann geschaltet wurde.
    pub switched: HashMap<u32, (&'static str, Instant)>,
    /// Wie oft die Liste einen Zustand nannte, der schon nicht mehr stimmte.
    pub stale: u32,
}

/// Der Zustand, in dem eine Maschine anfängt.
fn initial(vmid: u32) -> &'static str {
    if matches!(vmid, 130 | 9000) {
        "stopped"
    } else {
        "running"
    }
}

impl World {
    /// Der wirkliche Zustand einer Maschine.
    fn truth(&self, vmid: u32) -> &'static str {
        self.status.get(&vmid).copied().unwrap_or(initial(vmid))
    }

    /// Der Zustand, den die Liste aller Maschinen nennt.
    fn listed(&mut self, vmid: u32) -> &'static str {
        match self.switched.get(&vmid) {
            Some((before, at)) if at.elapsed() < self.lag && *before != self.truth(vmid) => {
                self.stale += 1;
                before
            }
            _ => self.truth(vmid),
        }
    }
}

pub type Shared = Arc<Mutex<World>>;

async fn handle(State(world): State<Shared>, method: Method, uri: Uri, headers: HeaderMap) -> (StatusCode, Json<Value>) {
    let mut world = world.lock().unwrap();
    let ok = |data: Value| (StatusCode::OK, Json(json!({ "data": data })));
    // Für Prüfungen: `/test/rename/<name>`, `/test/address/<adresse>` und `/test/reset` verstellen die VM 101;
    // `/test/seen` nennt, wie viele Tokens der Server zu sehen bekam und wie oft Einstellungen gelesen wurden.
    if let Some(rest) = uri.path().strip_prefix("/test/") {
        match rest.split('/').collect::<Vec<_>>().as_slice() {
            ["seen"] => return ok(json!({ "tokens": world.tokens.len(), "configs": world.configs, "stale": world.stale })),
            ["rename", name] => world.renamed = Some(name.to_string()),
            ["address", address] => world.readdressed = Some(address.to_string()),
            ["reset"] => (world.renamed, world.readdressed) = (None, None),
            _ => return (StatusCode::NOT_FOUND, Json(Value::Null)),
        }
        world.status.clear();
        world.switched.clear();
        return ok(Value::Null);
    }
    let auth = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
    if !auth.is_empty() {
        world.tokens.push(auth.clone());
    }
    let reader = auth == format!("PVEAPIToken=leser@pve!test={SECRET}");
    if auth != format!("PVEAPIToken={TOKEN}={SECRET}") && !reader {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "data": null })));
    }
    let path = uri.path().trim_start_matches("/api2/json/").to_string();
    let parts: Vec<&str> = path.split('/').collect();
    let shop = world.renamed.clone().unwrap_or_else(|| "shop-01".into());
    let shop_address = world.readdressed.clone().unwrap_or_else(|| "10.0.10.11".into());
    if matches!(parts.as_slice(), ["nodes", _, _, _, "config"]) {
        world.configs += 1;
    }
    match (method.as_str(), parts.as_slice()) {
        ("GET", ["version"]) => ok(json!({ "version": "9.0.11", "release": "9.0", "repoid": "abc" })),
        ("GET", ["nodes"]) => ok(json!([{ "node": "pve", "status": "online", "cpu": 0.21, "maxcpu": 32, "mem": 76235669504u64, "maxmem": 137438953472u64, "uptime": 5184000 }, { "node": "alt", "status": "offline" }])),
        ("GET", ["cluster", "resources"]) => {
            let listed: HashMap<u32, &'static str> = [101, 111, 112, 120, 130].into_iter().map(|vmid| (vmid, world.listed(vmid))).collect();
            let state = |vmid: u32| listed[&vmid];
            ok(json!([
            { "type": "lxc", "vmid": 111, "node": "pve", "name": "pihole", "status": state(111), "template": 0, "cpu": 0.01, "maxcpu": 1, "mem": 214748364, "maxmem": 536870912, "uptime": 2592000, "tags": "netz" },
            { "type": "qemu", "vmid": "101", "node": "pve", "name": shop, "status": state(101), "template": 0, "cpu": 0.18, "maxcpu": 4, "mem": 3113851289u64, "maxmem": 8589934592u64, "uptime": 1209600, "tags": "prod;web" },
            { "type": "qemu", "vmid": 120, "node": "pve", "name": "monitoring", "status": state(120), "cpu": 0.09, "maxcpu": 2, "mem": 1, "maxmem": 4294967296u64, "uptime": 600000 },
            { "type": "qemu", "vmid": 130, "node": "pve", "name": "spielwiese", "status": state(130), "cpu": 0, "maxcpu": 2, "mem": 0, "maxmem": 4294967296u64, "uptime": 0, "tags": " " },
            { "type": "qemu", "vmid": 9000, "node": "pve", "name": "debian-13-vorlage", "status": "stopped", "template": 1, "maxcpu": 2, "maxmem": 2147483648u64 },
            { "type": "lxc", "vmid": 112, "node": "pve", "name": "gitea", "status": state(112), "maxcpu": 2, "mem": 5, "maxmem": 2147483648u64, "uptime": 86400 },
            { "type": "storage", "node": "pve", "storage": "local" },
            ]))
        }
        // Die Maschine selbst gefragt: Das stimmt sofort.
        ("GET", ["nodes", "pve", "qemu" | "lxc", vmid, "status", "current"]) => {
            let vmid: u32 = vmid.parse().unwrap_or_default();
            ok(json!({ "vmid": vmid, "status": world.truth(vmid), "qmpstatus": world.truth(vmid) }))
        }
        ("GET", ["nodes", "pve", "qemu", "101", "config"]) => ok(json!({ "ipconfig0": format!("ip={shop_address}/24,gw=10.0.10.1"), "ciuser": "deploy", "ostype": "l26", "agent": "1", "name": shop,
            "sshkeys": "ssh-ed25519%20AAAAC3NzaC1lZDI1NTE5AAAAIOgQqXeoYfd9GJUg5ajXbvrpe%2B0M0f5PTO0MRd4ZpqK7%20deploy%40laptop%0A" })),
        ("GET", ["nodes", "pve", "qemu", "120", "config"]) => ok(json!({ "ipconfig0": "ip=dhcp", "ostype": "l26", "agent": "enabled=1" })),
        ("GET", ["nodes", "pve", "qemu", "120", "agent", "network-get-interfaces"]) => ok(json!({ "result": [
            { "name": "lo", "ip-addresses": [{ "ip-address": "127.0.0.1", "ip-address-type": "ipv4", "prefix": 8 }] },
            { "name": "docker0", "ip-addresses": [{ "ip-address": "172.17.0.1", "ip-address-type": "ipv4", "prefix": 16 }] },
            { "name": "ens18", "ip-addresses": [{ "ip-address": "fe80::be24:11ff:fe00:1", "ip-address-type": "ipv6", "prefix": 64 }, { "ip-address": "10.0.10.90", "ip-address-type": "ipv4", "prefix": 24 }] },
        ] })),
        ("GET", ["nodes", "pve", "qemu", "130", "config"]) => ok(json!({ "ostype": "l26", "name": "spielwiese" })),
        ("GET", ["nodes", "pve", "qemu", "9000", "config"]) => ok(json!({ "ostype": "l26", "name": "debian-13-vorlage", "template": 1 })),
        // Der Gastagent läuft nicht: So antwortet Proxmox dann.
        ("GET", ["nodes", "pve", "qemu", _, "agent", _]) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "data": null, "message": "QEMU guest agent is not running\n" }))),
        ("GET", ["nodes", "pve", "lxc", "111", "config"]) => ok(json!({ "net0": "name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:00:01,ip=10.0.0.53/24,gw=10.0.0.1,type=veth", "ostype": "debian", "hostname": "pihole" })),
        ("GET", ["nodes", "pve", "lxc", "112", "config"]) => ok(json!({ "net0": "name=eth0,bridge=vmbr0,ip=dhcp,type=veth", "ostype": "alpine" })),
        ("GET", ["nodes", "pve", "lxc", "112", "interfaces"]) => ok(json!([{ "name": "lo", "inet": "127.0.0.1/8", "inet6": "::1/128" }, { "name": "eth0", "hwaddr": "bc:24:11:00:00:02", "inet": "10.0.10.74/24", "inet6": "fe80::1/64" }])),
        ("GET", ["access", "permissions"]) if reader => ok(json!({ "/": { "VM.Audit": 1, "Sys.Audit": 1 } })),
        ("GET", ["access", "permissions"]) => ok(json!({ "/vms": { "VM.Audit": 1, "VM.PowerMgmt": 1 }, "/vms/120": { "VM.GuestAgent.Audit": 1 } })),
        ("POST", ["nodes", "pve", _, _, "status", _]) if reader => (StatusCode::FORBIDDEN, Json(json!({ "data": null, "message": "Permission check failed (/vms/101, VM.PowerMgmt)\n" }))),
        ("POST", ["nodes", "pve", kind, vmid, "status", action]) => {
            let vmid: u32 = vmid.parse().unwrap_or_default();
            if vmid != 9000 {
                let before = world.truth(vmid);
                world.switched.insert(vmid, (before, Instant::now()));
                world.status.insert(vmid, if matches!(*action, "start" | "reboot") { "running" } else { "stopped" });
            }
            ok(json!(format!("UPID:pve:0000{vmid:04X}:00000001:6703A1B2:{kind}{action}:{vmid}:{TOKEN}:")))
        }
        ("GET", ["nodes", "pve", "tasks", upid, "status"]) => {
            let asked = world.polls.entry(upid.to_string()).or_insert(0);
            *asked += 1;
            // Der erste Blick sieht den Auftrag noch laufen.
            match (*asked, upid.contains(":9000:")) {
                (1, _) => ok(json!({ "status": "running", "upid": upid })),
                (_, true) => ok(json!({ "status": "stopped", "exitstatus": "unable to start VM 9000 - VM is a template" })),
                _ => ok(json!({ "status": "stopped", "exitstatus": "OK" })),
            }
        }
        _ => (StatusCode::NOT_IMPLEMENTED, Json(json!({ "data": null, "message": format!("Method '{method} /{path}' not implemented") }))),
    }
}

/// Ein laufender nachgebauter Proxmox-Server.
pub struct Running {
    /// `https://localhost:<port>`
    pub address: String,
    /// SHA-256 über sein Zertifikat.
    pub fingerprint: [u8; 32],
    pub world: Shared,
}

/// Startet den nachgebauten Server an einem freien Port, mit einem frisch erstellten Zertifikat. Seine Liste der
/// Maschinen stimmt sofort; mit [`start_lagging`] hinkt sie nach einem Schalten hinterher wie bei Proxmox.
pub async fn start() -> std::io::Result<Running> {
    start_lagging(Duration::ZERO).await
}

pub async fn start_lagging(lag: Duration) -> std::io::Result<Running> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).map_err(std::io::Error::other)?;
    let fingerprint: [u8; 32] = Sha256::digest(certified.cert.der().as_ref()).into();
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem(certified.cert.pem().into_bytes(), certified.signing_key.serialize_pem().into_bytes()).await?;
    let world = Shared::default();
    world.lock().unwrap().lag = lag;
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    let app = Router::new().fallback(handle).with_state(world.clone());
    tokio::spawn(async move {
        let _ = axum_server::from_tcp_rustls(listener, tls).serve(app.into_make_service_with_connect_info::<SocketAddr>()).await;
    });
    Ok(Running { address: format!("https://localhost:{port}"), fingerprint, world })
}

/// So zeigt Proxmox einen Fingerabdruck: `5F:1A:…`.
pub fn fingerprint_text(fingerprint: &[u8; 32]) -> String {
    fingerprint.iter().map(|byte| format!("{byte:02X}")).collect::<Vec<_>>().join(":")
}

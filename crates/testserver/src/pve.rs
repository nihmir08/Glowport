//! A simulated Proxmox server: over TLS with a self-signed certificate, as Proxmox ships it. The
//! routes and answers are built after the API documentation, not recorded on a real
//! server.
//!
//! There are two tokens: [`TOKEN`] may do everything, `leser@pve!test` may only look; both with [`SECRET`]. Under `/test/…`
//! (without sign-in, only for tests) the state can be changed, as if someone had changed a machine's name
//! or address in Proxmox or renewed its certificate.

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
    /// Every `Authorization` header the server saw.
    pub tokens: Vec<String>,
    /// State per machine, as far as it changed.
    pub status: HashMap<u32, &'static str>,
    /// How often a task was asked about.
    pub polls: HashMap<String, u32>,
    /// Name and fixed address of VM 101, as far as they were changed.
    pub renamed: Option<String>,
    pub readdressed: Option<String>,
    /// How often a machine's settings were read.
    pub configs: u32,
    /// For this long the list of all machines still names the old state after switching. Proxmox keeps it from
    /// a state it only refreshes every few seconds; a machine's `status/current` is right at once.
    pub lag: Duration,
    /// Per switched machine: its state before and when it was switched.
    pub switched: HashMap<u32, (&'static str, Instant)>,
    /// How often the list named a state that was no longer right.
    pub stale: u32,
}

/// The state a machine starts in.
fn initial(vmid: u32) -> &'static str {
    if matches!(vmid, 130 | 9000) {
        "stopped"
    } else {
        "running"
    }
}

impl World {
    /// A machine's real state.
    fn truth(&self, vmid: u32) -> &'static str {
        self.status.get(&vmid).copied().unwrap_or(initial(vmid))
    }

    /// The state the list of all machines names.
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
    // For tests: `/test/rename/<name>`, `/test/address/<address>` and `/test/reset` change VM 101;
    // `/test/seen` says how many tokens the server saw and how often settings were read.
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
        // The machine asked itself: that is right at once.
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
        // The guest agent is not running: this is how Proxmox answers then.
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
            // The first look still sees the task running.
            match (*asked, upid.contains(":9000:")) {
                (1, _) => ok(json!({ "status": "running", "upid": upid })),
                (_, true) => ok(json!({ "status": "stopped", "exitstatus": "unable to start VM 9000 - VM is a template" })),
                _ => ok(json!({ "status": "stopped", "exitstatus": "OK" })),
            }
        }
        _ => (StatusCode::NOT_IMPLEMENTED, Json(json!({ "data": null, "message": format!("Method '{method} /{path}' not implemented") }))),
    }
}

/// A running simulated Proxmox server.
pub struct Running {
    /// `https://localhost:<port>`
    pub address: String,
    /// SHA-256 over its certificate.
    pub fingerprint: [u8; 32],
    pub world: Shared,
}

/// Starts the simulated server on a free port with a freshly created certificate. Its list of
/// machines is right at once; with [`start_lagging`] it lags behind after switching, as with Proxmox.
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

/// This is how Proxmox shows a fingerprint: `5F:1A:…`.
pub fn fingerprint_text(fingerprint: &[u8; 32]) -> String {
    fingerprint.iter().map(|byte| format!("{byte:02X}")).collect::<Vec<_>>().join(":")
}

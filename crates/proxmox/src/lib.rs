//! Access to the Proxmox VE API (`docs/management.md`): list nodes and machines, switch machines,
//! find out under which address they can be reached.
//!
//! This crate knows neither vault nor interface. It signs in with an API token. **The token's secret
//! never goes to a server whose certificate is neither trusted nor confirmed by the user:** [`look`]
//! only establishes the connection and names the fingerprint; only a [`Client`] with a trusted certificate or
//! a stored fingerprint sends the token along.

pub mod guest;
mod tls;

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use serde_json::Value;

pub use guest::{Facts, Interface, Source};
pub use tls::{fingerprint_text, parse_fingerprint, Fingerprint};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PveError {
    #[error("Die Adresse ist keine der Form https://pve.example.de:8006")]
    Address,
    #[error("Der Proxmox-Server ist nicht erreichbar ({0})")]
    Offline(String),
    /// The certificate is not trusted, or it differs from the confirmed one.
    #[error("Das Zertifikat des Proxmox-Servers wird nicht anerkannt")]
    Certificate,
    #[error("Der Token ist unvollständig oder wird abgelehnt")]
    Token,
    /// The token lacks a permission.
    #[error("Dem Token fehlt das Recht dafür")]
    Forbidden,
    #[error("Proxmox meldet: {0}")]
    Failed(String),
    #[error("Unerwartete Antwort von Proxmox ({0})")]
    Protocol(&'static str),
}

impl PveError {
    /// Short reason for the interface.
    pub fn code(&self) -> &'static str {
        match self {
            PveError::Address => "proxmox_address",
            PveError::Offline(_) => "proxmox_offline",
            PveError::Certificate => "proxmox_certificate",
            PveError::Token => "proxmox_token",
            PveError::Forbidden => "proxmox_forbidden",
            PveError::Failed(_) | PveError::Protocol(_) => "proxmox_failed",
        }
    }
}

type Result<T> = std::result::Result<T, PveError>;

/// Brings a typed address into shape: `https://host[:port]`, nothing else.
pub fn normalize(address: &str) -> Result<String> {
    let text = address.trim().trim_end_matches('/');
    let rest = text.strip_prefix("https://").ok_or(PveError::Address)?;
    let host_ok = !rest.is_empty() && rest.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'));
    if host_ok {
        Ok(text.to_string())
    } else {
        Err(PveError::Address)
    }
}

/// What a look at the server without signing in reveals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Look {
    pub fingerprint: Fingerprint,
    /// The certificate is trusted on its own (e.g. from Let's Encrypt).
    pub trusted: bool,
}

fn http(config: rustls::ClientConfig) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .tls_backend_preconfigured(config)
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .user_agent(concat!("Glowport/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| PveError::Offline(e.to_string()))
}

fn transport(error: reqwest::Error, seen: &tls::Seen) -> PveError {
    // If the verifier rejected the certificate, that is the reason, whatever the layers above call it.
    if seen.lock().unwrap_or_else(|p| p.into_inner()).is_some_and(|look| !look.1) {
        PveError::Certificate
    } else {
        PveError::Offline(error.without_url().to_string())
    }
}

/// Only establishes the connection and looks at the certificate. No token goes along.
pub async fn look(address: &str) -> Result<Look> {
    let base = normalize(address)?;
    let seen = tls::Seen::default();
    let client = http(tls::config(tls::Mode::Observe, seen.clone())?)?;
    // The answer itself does not matter (Proxmox refuses without sign-in); what was seen while connecting counts.
    let outcome = client.get(format!("{base}/api2/json/version")).send().await;
    let looked = *seen.lock().unwrap_or_else(|p| p.into_inner());
    match (looked, outcome) {
        (Some((fingerprint, trusted)), _) => Ok(Look { fingerprint, trusted }),
        (None, Err(error)) => Err(PveError::Offline(error.without_url().to_string())),
        (None, Ok(_)) => Err(PveError::Protocol("Zertifikat")),
    }
}

/// Kind of a machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A VM.
    Qemu,
    /// A container.
    Lxc,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Qemu => "qemu",
            Kind::Lxc => "lxc",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Power {
    Start,
    /// Asks the system to shut down properly.
    Shutdown,
    /// Switches off at once.
    Stop,
    Reboot,
}

impl Power {
    fn name(self) -> &'static str {
        match self {
            Power::Start => "start",
            Power::Shutdown => "shutdown",
            Power::Stop => "stop",
            Power::Reboot => "reboot",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Node {
    pub node: String,
    pub online: bool,
    /// 0 to 1.
    pub cpu: Option<f64>,
    pub cores: Option<u32>,
    /// Memory in bytes: used and total.
    pub memory: Option<(u64, u64)>,
    pub uptime: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Guest {
    pub node: String,
    pub vmid: u32,
    pub kind: Kind,
    pub name: String,
    /// `running`, `stopped`, `paused`; everything else is `unknown`.
    pub status: &'static str,
    pub template: bool,
    pub cpu: Option<f64>,
    pub cores: Option<u32>,
    pub memory: Option<(u64, u64)>,
    pub uptime: Option<u64>,
    pub tags: Vec<String>,
}

/// What the token lacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Missing {
    /// Maschinen sehen (`VM.Audit`).
    Audit,
    /// Switch on and off (`VM.PowerMgmt`).
    Power,
    /// Query the guest agent (`VM.GuestAgent.Audit`, before Proxmox 9 `VM.Monitor`).
    Agent,
}

impl Missing {
    pub fn name(self) -> &'static str {
        match self {
            Missing::Audit => "audit",
            Missing::Power => "power",
            Missing::Agent => "agent",
        }
    }
}

/// The node's name goes into a request's address: only what belongs there.
fn node_fits(node: &str) -> Result<()> {
    if node.is_empty() || !node.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(PveError::Protocol("Knoten"));
    }
    Ok(())
}

/// Numbers come from Proxmox sometimes as a number, sometimes as text.
fn number(value: &Value, key: &str) -> Option<f64> {
    match value.get(key)? {
        Value::Number(n) => n.as_f64(),
        Value::String(text) => text.parse().ok(),
        Value::Bool(flag) => Some(f64::from(u8::from(*flag))),
        _ => None,
    }
}

fn text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn usage(value: &Value) -> Option<(u64, u64)> {
    let total = number(value, "maxmem")? as u64;
    (total > 0).then(|| (number(value, "mem").unwrap_or(0.0) as u64, total))
}

/// Access to a Proxmox server with a token.
pub struct Client {
    base: String,
    http: reqwest::Client,
    auth: String,
    seen: tls::Seen,
}

impl Client {
    /// `pin`: the confirmed fingerprint of a self-signed certificate. Then exactly this certificate applies
    /// and no other; without it the certificate must be trusted.
    pub fn new(address: &str, token_id: &str, secret: &str, pin: Option<Fingerprint>) -> Result<Self> {
        let base = normalize(address)?;
        let (token_id, secret) = (token_id.trim(), secret.trim());
        // `user@realm!name`; nothing in the secret that could break a request header.
        let shaped = token_id.split_once('@').is_some_and(|(user, rest)| !user.is_empty() && rest.split_once('!').is_some_and(|(realm, name)| !realm.is_empty() && !name.is_empty()));
        let clean = |text: &str| !text.is_empty() && text.chars().all(|c| c.is_ascii_graphic());
        if !shaped || !clean(token_id) || !clean(secret) {
            return Err(PveError::Token);
        }
        let seen = tls::Seen::default();
        let mode = pin.map_or(tls::Mode::System, tls::Mode::Pinned);
        Ok(Self { base, http: http(tls::config(mode, seen.clone())?)?, auth: format!("PVEAPIToken={token_id}={secret}"), seen })
    }

    async fn call(&self, method: reqwest::Method, path: &str) -> Result<Value> {
        let request = self.http.request(method, format!("{}/api2/json/{path}", self.base)).header(reqwest::header::AUTHORIZATION, &self.auth);
        let response = request.send().await.map_err(|e| transport(e, &self.seen))?;
        let status = response.status();
        let reason = status.canonical_reason().unwrap_or_default().to_string();
        let body = response.bytes().await.map_err(|e| transport(e, &self.seen))?;
        let json: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        match status.as_u16() {
            200 => json.get("data").cloned().ok_or(PveError::Protocol("Antwort")),
            401 => Err(PveError::Token),
            403 => Err(PveError::Forbidden),
            code => {
                // Proxmox names the reason in the `message` field, in `errors` or only in the status line.
                let said = text(&json, "message").map(str::trim).filter(|m| !m.is_empty()).map(str::to_string).or_else(|| json.get("errors").filter(|e| !e.is_null()).map(Value::to_string));
                Err(PveError::Failed(said.unwrap_or(format!("{code} {reason}"))))
            }
        }
    }

    async fn get(&self, path: &str) -> Result<Value> {
        self.call(reqwest::Method::GET, path).await
    }

    pub async fn version(&self) -> Result<String> {
        Ok(text(&self.get("version").await?, "version").ok_or(PveError::Protocol("Version"))?.to_string())
    }

    pub async fn nodes(&self) -> Result<Vec<Node>> {
        let data = self.get("nodes").await?;
        let mut nodes: Vec<Node> = data
            .as_array()
            .ok_or(PveError::Protocol("Knoten"))?
            .iter()
            .filter_map(|n| Some(Node { node: text(n, "node")?.to_string(), online: text(n, "status") == Some("online"), cpu: number(n, "cpu"), cores: number(n, "maxcpu").map(|c| c as u32), memory: usage(n), uptime: number(n, "uptime").map(|u| u as u64) }))
            .collect();
        nodes.sort_by(|a, b| a.node.cmp(&b.node));
        Ok(nodes)
    }

    /// All VMs and containers, by node and number.
    pub async fn guests(&self) -> Result<Vec<Guest>> {
        let data = self.get("cluster/resources?type=vm").await?;
        let mut guests: Vec<Guest> = data
            .as_array()
            .ok_or(PveError::Protocol("Maschinen"))?
            .iter()
            .filter_map(|g| {
                let kind = match text(g, "type")? {
                    "qemu" => Kind::Qemu,
                    "lxc" => Kind::Lxc,
                    _ => return None,
                };
                let vmid = number(g, "vmid")? as u32;
                let status = match text(g, "status").unwrap_or_default() {
                    "running" => "running",
                    "stopped" => "stopped",
                    "paused" | "suspended" => "paused",
                    _ => "unknown",
                };
                Some(Guest {
                    node: text(g, "node")?.to_string(),
                    vmid,
                    kind,
                    name: text(g, "name").map_or_else(|| vmid.to_string(), str::to_string),
                    status,
                    template: number(g, "template").is_some_and(|t| t != 0.0),
                    cpu: number(g, "cpu").filter(|_| status == "running"),
                    cores: number(g, "maxcpu").map(|c| c as u32),
                    memory: usage(g),
                    // Only what runs has an uptime, whatever Proxmox still names for a switched-off machine.
                    uptime: number(g, "uptime").map(|u| u as u64).filter(|u| *u > 0 && status == "running"),
                    tags: text(g, "tags").unwrap_or_default().split([';', ',', ' ']).filter(|tag| !tag.is_empty()).map(str::to_string).collect(),
                })
            })
            .collect();
        guests.sort_by(|a, b| (&a.node, a.vmid).cmp(&(&b.node, b.vmid)));
        Ok(guests)
    }

    /// What there is to know about a machine to connect to it. If it runs and has no fixed address,
    /// it is asked itself (guest agent or container). If it does not answer, the address simply stays open.
    pub async fn facts(&self, guest: &Guest) -> Result<Facts> {
        let (vm, at) = (guest.kind == Kind::Qemu, format!("nodes/{}/{}/{}", guest.node, guest.kind.name(), guest.vmid));
        let config = self.get(&format!("{at}/config")).await?;
        let settled = guest::facts(vm, &guest.name, &config, &[], None);
        if settled.address.is_some() || guest.status != "running" {
            return Ok(settled);
        }
        let interfaces: Vec<Interface> = if vm {
            let reply = self.get(&format!("{at}/agent/network-get-interfaces")).await.unwrap_or(Value::Null);
            let list = reply.get("result").and_then(Value::as_array).cloned().unwrap_or_default();
            list.iter().filter_map(|i| Some((text(i, "name")?.to_string(), i.get("ip-addresses")?.as_array()?.iter().filter_map(|a| text(a, "ip-address").map(str::to_string)).collect()))).collect()
        } else {
            let reply = self.get(&format!("{at}/interfaces")).await.unwrap_or(Value::Null);
            let list = reply.as_array().cloned().unwrap_or_default();
            list.iter().filter_map(|i| Some((text(i, "name")?.to_string(), [text(i, "inet"), text(i, "inet6")].into_iter().flatten().map(str::to_string).collect()))).collect()
        };
        Ok(guest::facts(vm, &guest.name, &config, &interfaces, None))
    }

    /// What the token lacks to do everything Glowport offers.
    pub async fn missing(&self) -> Result<Vec<Missing>> {
        let data = self.get("access/permissions").await?;
        let has = |right: &str| data.as_object().is_some_and(|paths| paths.values().any(|rights| number(rights, right).is_some_and(|granted| granted != 0.0)));
        let checks = [(Missing::Audit, has("VM.Audit")), (Missing::Power, has("VM.PowerMgmt")), (Missing::Agent, has("VM.GuestAgent.Audit") || has("VM.Monitor"))];
        Ok(checks.into_iter().filter(|(_, granted)| !granted).map(|(missing, _)| missing).collect())
    }

    /// A machine's state, asked of the machine itself: `running`, `stopped`, `paused`, otherwise `unknown`. Proxmox
    /// keeps the list of all machines ([`Client::guests`]) from a state it only refreshes every few seconds;
    /// right after switching it still names the old state. This answer does not.
    pub async fn status(&self, node: &str, kind: Kind, vmid: u32) -> Result<&'static str> {
        node_fits(node)?;
        let state = self.get(&format!("nodes/{node}/{}/{vmid}/status/current", kind.name())).await?;
        Ok(match (text(&state, "status").unwrap_or_default(), text(&state, "qmpstatus")) {
            ("running", Some("paused")) | ("paused" | "suspended", _) => "paused",
            ("running", _) => "running",
            ("stopped", _) => "stopped",
            _ => "unknown",
        })
    }

    /// Switches a machine and waits until Proxmox has carried out the task.
    pub async fn power(&self, node: &str, kind: Kind, vmid: u32, action: Power) -> Result<()> {
        node_fits(node)?;
        let started = self.call(reqwest::Method::POST, &format!("nodes/{node}/{}/{vmid}/status/{}", kind.name(), action.name())).await?;
        let task = started.as_str().filter(|upid| upid.starts_with("UPID:") && upid.chars().all(|c| c.is_ascii_graphic() && c != '/')).ok_or(PveError::Protocol("Auftrag"))?.to_string();
        // A proper shutdown may take a while; Proxmox itself gives a VM three minutes for it.
        for _ in 0..400 {
            let state = self.get(&format!("nodes/{node}/tasks/{task}/status")).await?;
            if text(&state, "status") == Some("stopped") {
                return match text(&state, "exitstatus") {
                    Some("OK") => Ok(()),
                    other => Err(PveError::Failed(other.unwrap_or("unbekannt").to_string())),
                };
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        Err(PveError::Failed("Der Auftrag läuft noch".into()))
    }

    /// Whether this connection's certificate is trusted on its own. `None` before the first request.
    pub fn seen(&self) -> Option<Look> {
        self.seen.lock().unwrap_or_else(|p| p.into_inner()).map(|(fingerprint, trusted)| Look { fingerprint, trusted })
    }
}

/// For [`tls`]: shared place for what was seen while connecting.
pub(crate) type Shared<T> = Arc<Mutex<T>>;

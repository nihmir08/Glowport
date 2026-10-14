//! Hosts, groups, keys and identities of an open vault: read, check, change.
//!
//! Every change is checked first, then written to the vault as a whole and read back afterwards.
//! The state in memory therefore always matches what is in the file.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Map;

use crate::{
    model::{
        self, double_option, Arrangement, Auth, Authority, Effective, Fields, Forward, ForwardKind, Ftp, FtpSecurity, Group, Host, Identity, Key, KeyCertificate, KeyKind, KeyOrigin, KnownHost, MacroStep, Payload, Proxmox, ProxmoxLink, ProxySpec, Reconnect, Secret,
        Serial, Snippet, SnippetKind, VaultLabel, Workspace,
    },
    roster::{self, Role},
    vault::{now_ms, Id, Kind, Vault, VaultError},
};

/// Reason an input is rejected. The interface translates it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Invalid {
    NameRequired,
    NameTooLong,
    AddressRequired,
    AddressInvalid,
    UserInvalid,
    PortInvalid,
    ColorInvalid,
    GroupMissing,
    GroupCycle,
    JumpMissing,
    JumpSelf,
    UserRequired,
    KeyMissing,
    IdentityMissing,
    EnvInvalid,
    ProxyInvalid,
    KeepaliveInvalid,
    TimeoutInvalid,
    TermInvalid,
    CharsetInvalid,
    PatternInvalid,
    SchemeInvalid,
    MoshPredictInvalid,
    MoshPortInvalid,
    MoshServerInvalid,
    WorkspaceEmpty,
    WorkspaceTooLarge,
    HostMissing,
    DestRequired,
    CommandRequired,
    MacroEmpty,
    SnippetTooLarge,
    HotkeyInvalid,
    HotkeyTaken,
    ProtocolInvalid,
    /// The host is a jump host for others or carries port rules; that only works with SSH.
    ProtocolInUse,
    SerialRequired,
    SerialInvalid,
    BaudInvalid,
    /// A host reached via SSH is needed.
    HostNotSsh,
    /// An entry lives in the same vault as its group, and a shared vault only refers within itself.
    OtherVault,
    /// The token ID does not have the form `user@realm!name`, or the secret contains something that does not belong there.
    TokenInvalid,
    /// A new Proxmox connection needs its token's secret.
    SecretRequired,
    FingerprintInvalid,
    /// The kind of machine is neither VM nor container.
    GuestInvalid,
}

#[derive(Debug, thiserror::Error)]
pub enum DirError {
    #[error(transparent)]
    Vault(#[from] VaultError),
    #[error("Eingabe abgelehnt: {0:?}")]
    Invalid(Invalid),
    #[error("Eintrag nicht gefunden")]
    NotFound,
}

type Result<T> = std::result::Result<T, DirError>;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostInput {
    #[serde(default)]
    pub id: Option<String>,
    pub name: String,
    pub address: String,
    /// If the field is missing, the protocol stays as it is; a new host gets SSH.
    #[serde(default)]
    pub protocol: Option<String>,
    /// Serial line settings. If missing, they stay as they are.
    #[serde(default)]
    pub serial: Option<Serial>,
    /// FTP settings. If missing, they stay as they are.
    #[serde(default)]
    pub ftp: Option<Ftp>,
    #[serde(default)]
    pub group: Option<String>,
    #[serde(default)]
    pub color: Option<String>,
    #[serde(default)]
    pub os: Option<String>,
    #[serde(default)]
    pub own: Fields,
    /// If the field is missing, the password stays as it is; `null` removes it.
    #[serde(default, deserialize_with = "double_option")]
    pub password: Option<Option<Secret>>,
    /// Password for the host's proxy, with the same rules.
    #[serde(default, deserialize_with = "double_option")]
    pub proxy_password: Option<Option<Secret>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupInput {
    #[serde(default)]
    pub id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub parent: Option<String>,
    #[serde(default)]
    pub color: Option<String>,
    #[serde(default)]
    pub defs: Fields,
    /// Password for the group's proxy: missing = unchanged, `null` = remove.
    #[serde(default, deserialize_with = "double_option")]
    pub proxy_password: Option<Option<Secret>>,
}

/// A key already generated or read, ready to be stored. Generating and reading is the job of `keys`.
#[derive(Debug)]
pub struct NewKey {
    pub name: String,
    pub kind: KeyKind,
    pub bits: u32,
    pub fingerprint: String,
    /// Public key in OpenSSH format; a comment after it is discarded.
    pub public: String,
    /// Private key in OpenSSH format, unencrypted.
    pub private: Secret,
    pub origin: KeyOrigin,
}

/// A certificate authority for servers, ready to be stored. The caller reads and checks the key.
#[derive(Debug)]
pub struct NewAuthority {
    pub name: String,
    pub pattern: String,
    pub label: String,
    pub fingerprint: String,
    pub public: String,
}

/// A workspace as the interface sends it. Without an ID a new one is created.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceInput {
    #[serde(default)]
    pub id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub multi: bool,
    pub layout: Arrangement,
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceView {
    pub id: String,
    pub name: String,
    pub multi: bool,
    pub layout: Arrangement,
}

/// A port rule as the interface sends it. Without an ID a new one is created.
/// Ports arrive as a wide number so an impossible value ends as a rejection and not as a parse error.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForwardInput {
    #[serde(default)]
    pub id: Option<String>,
    pub name: String,
    pub kind: ForwardKind,
    pub host: String,
    #[serde(default)]
    pub bind_address: String,
    pub bind_port: u32,
    #[serde(default)]
    pub dest_host: String,
    #[serde(default)]
    pub dest_port: u32,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ForwardView {
    pub id: String,
    pub name: String,
    pub kind: ForwardKind,
    pub host: String,
    pub bind_address: String,
    pub bind_port: u16,
    pub dest_host: String,
    pub dest_port: u16,
}

/// A snippet or macro as the interface sends it. Without an ID a new one is created.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnippetInput {
    #[serde(default)]
    pub id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub package: String,
    pub kind: SnippetKind,
    #[serde(default)]
    pub command: String,
    #[serde(default)]
    pub steps: Vec<MacroStep>,
    #[serde(default)]
    pub hotkey: Option<String>,
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SnippetView {
    pub id: String,
    pub name: String,
    pub package: String,
    pub kind: SnippetKind,
    pub command: String,
    pub steps: Vec<MacroStep>,
    pub hotkey: Option<String>,
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AuthorityView {
    pub id: String,
    pub name: String,
    pub pattern: String,
    /// Kind of key, for display.
    pub kind: String,
    pub fingerprint: String,
    pub added_at: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityInput {
    #[serde(default)]
    pub id: Option<String>,
    pub name: String,
    pub user: String,
    #[serde(default)]
    pub key: Option<String>,
    /// If the field is missing, the password stays as it is; `null` removes it.
    #[serde(default, deserialize_with = "double_option")]
    pub password: Option<Option<Secret>>,
}

/// Key as the interface sees it: without the private part.
#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KeyView {
    pub id: String,
    pub name: String,
    pub kind: KeyKind,
    pub bits: u32,
    pub fingerprint: String,
    /// Line for `authorized_keys`, with the name as comment.
    pub public_key: String,
    pub origin: KeyOrigin,
    pub added_at: i64,
    pub certificate: Option<KeyCertificate>,
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct IdentityView {
    pub id: String,
    pub name: String,
    pub user: String,
    pub key: Option<String>,
    pub has_password: bool,
}

/// Host as the interface sees it: without password, only a hint whether one is set.
#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HostView {
    pub id: String,
    pub name: String,
    pub address: String,
    pub group: Option<String>,
    pub protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial: Option<Serial>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ftp: Option<Ftp>,
    pub color: Option<String>,
    pub os: Option<String>,
    pub own: Fields,
    pub has_password: bool,
    pub has_proxy_password: bool,
    /// The Proxmox machine the host belongs to; only while its connection exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxmox: Option<LinkView>,
}

/// The link between a host and its machine, as the interface sees it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LinkView {
    pub connection: String,
    pub node: String,
    pub vmid: u32,
    pub kind: String,
}

/// A Proxmox connection as the interface sends it. Without an ID a new one is created.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxmoxInput {
    #[serde(default)]
    pub id: Option<String>,
    pub name: String,
    pub address: String,
    pub token_id: String,
    /// If the secret is missing, it stays as it is.
    #[serde(default)]
    pub secret: Option<Secret>,
    /// The confirmed fingerprint of a self-signed certificate. If missing, the certificate must be trusted.
    #[serde(default)]
    pub fingerprint: Option<String>,
    /// ID of the identity for this connection's machines. Missing or empty means none.
    #[serde(default)]
    pub identity: Option<String>,
}

/// A Proxmox connection as the interface sees it: without the token's secret.
#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProxmoxView {
    pub id: String,
    pub name: String,
    pub address: String,
    pub token_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// The identity for this connection's machines; only while it exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
}

/// What a connection without a saved host signs in with.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Login {
    /// The identity's user; `None` if only a key was named.
    pub user: Option<String>,
    pub password: Option<Secret>,
    /// Private key from the vault in OpenSSH format.
    pub key: Option<Secret>,
    /// User certificate for `key`, if one is stored.
    pub certificate: Option<String>,
}

/// What is needed to talk to a Proxmox server. Leaves the core only towards that server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxmoxAccess {
    pub address: String,
    pub token_id: String,
    pub secret: Secret,
    pub fingerprint: Option<String>,
}

/// A machine that is to become a host, with what Proxmox knows about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestHost {
    pub node: String,
    pub vmid: u32,
    /// `qemu` or `lxc`.
    pub kind: String,
    pub name: String,
    /// If Proxmox knows none, the host gets the machine's name for now; the address follows as soon as there is one.
    pub address: Option<String>,
    pub user: Option<String>,
    /// ID of a key in the vault.
    pub key: Option<String>,
    /// Short name of the operating system.
    pub os: Option<String>,
}

/// A machine as Proxmox currently names it; for updating the linked hosts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestSeen {
    pub node: String,
    pub vmid: u32,
    pub name: String,
    /// `None`: Proxmox currently knows none (machine off and without a fixed address). The host's stays.
    pub address: Option<String>,
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GroupView {
    pub id: String,
    pub name: String,
    pub parent: Option<String>,
    pub color: Option<String>,
    pub defs: Fields,
    pub has_proxy_password: bool,
}

/// Sequence number of the states this program hands out. A state created later always has the higher one,
/// across locking, unlocking and switching vaults.
static SNAPSHOTS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The number of a state. It does not count when comparing two states: equal is what shows the same.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(transparent)]
pub struct Stamp(pub u64);

impl PartialEq for Stamp {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    /// Responses and events do not always reach the interface in the order they were created.
    /// This number lets it recognise a state older than the one shown, and ignore it.
    pub seq: Stamp,
    pub groups: Vec<GroupView>,
    pub hosts: Vec<HostView>,
    /// Number of records that could not be opened or read.
    pub damaged: usize,
    pub known_hosts: Vec<KnownHostView>,
    pub keys: Vec<KeyView>,
    pub identities: Vec<IdentityView>,
    pub authorities: Vec<AuthorityView>,
    pub workspaces: Vec<WorkspaceView>,
    pub forwards: Vec<ForwardView>,
    pub snippets: Vec<SnippetView>,
    /// Proxmox connections.
    pub proxmox: Vec<ProxmoxView>,
    /// All vaults of this device, the personal one first.
    pub vaults: Vec<VaultView>,
    /// For every entry in a shared vault: that vault's ID. Everything else is in the personal one.
    pub homes: BTreeMap<String, String>,
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VaultView {
    pub id: String,
    /// `personal` or `shared`.
    pub kind: &'static str,
    /// Empty for the personal one.
    pub name: String,
    /// Own role.
    pub role: Role,
    pub members: Vec<MemberView>,
    pub rolled_back: bool,
    pub orphaned: bool,
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MemberView {
    pub account: String,
    pub name: String,
    pub role: Role,
    pub me: bool,
    /// Invited, but has not accepted yet.
    pub invited: bool,
    /// Safety code: six words from the hash of the keys.
    pub code: String,
}

/// What only sync knows about the vaults, and the interface shows anyway.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct VaultMarks {
    /// Vaults for which the server has an older state than this device.
    pub rolled_back: BTreeSet<String>,
    /// Own vaults the server no longer knows.
    pub orphaned: BTreeSet<String>,
    /// Vault and account of those who are invited and have not accepted yet.
    pub invited: BTreeSet<(String, String)>,
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KnownHostView {
    pub id: String,
    pub host: String,
    pub port: u16,
    pub algorithm: String,
    pub fingerprint: String,
    /// Time of trust in milliseconds since 1970.
    pub added_at: i64,
}

/// Verdict on the key a server shows when connecting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Exactly this key is stored for this address.
    Trusted,
    /// Nothing is stored for this address yet.
    Unknown,
    /// A different key is stored for this address. That can be a reinstalled server
    /// or someone who has put themselves in between. `known` are the fingerprints so far.
    Changed { known: Vec<String> },
}

/// What is needed to connect to a host, after inheritance.
#[derive(Debug)]
pub struct ConnectInfo {
    pub name: String,
    pub address: String,
    pub port: u16,
    pub user: String,
    /// The host's password, otherwise the identity's.
    pub password: Option<Secret>,
    /// Private key from the vault in OpenSSH format.
    pub key: Option<Secret>,
    /// User certificate for `key`, if one is stored.
    pub certificate: Option<String>,
    pub key_file: Option<String>,
    /// Public keys of the certificate authorities that apply to this host's address.
    pub authorities: Vec<String>,
    /// ID of the host the connection goes through. It has its own connection details.
    pub jump: Option<String>,
    pub startcmd: Option<String>,
    pub env: Vec<(String, String)>,
    pub agent: bool,
    pub agent_forward: bool,
    pub proxy: Option<ProxySpec>,
    /// Password for the proxy, from wherever the proxy is defined.
    pub proxy_password: Option<Secret>,
    /// Seconds; 0 = no keepalives.
    pub keepalive: u16,
    pub timeout: u16,
    pub term: String,
    pub charset: String,
    pub legacy: bool,
    /// Set if the terminal should run over Mosh.
    pub mosh: Option<MoshInfo>,
}

/// A host's Mosh settings after inheritance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MoshInfo {
    /// One of [`model::MOSH_PREDICT`].
    pub predict: String,
    pub port: Option<String>,
    pub server: Option<String>,
}

/// What is needed to connect to a host over Telnet. It does not inherit port and user: a group's defaults
/// mean SSH.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelnetInfo {
    pub name: String,
    pub address: String,
    pub port: u16,
    /// Given to the device when it asks for it. There is no password for Telnet.
    pub user: Option<String>,
    pub timeout: u16,
    pub term: String,
    pub charset: String,
}

/// What is needed to open a serial line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerialInfo {
    pub name: String,
    /// Name of the port: `COM3`, `/dev/ttyUSB0`.
    pub port: String,
    pub line: Serial,
    pub charset: String,
}

/// How a host is reached. For SSH, [`Directory::connect_info`] provides the details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    Ssh,
    Telnet(TelnetInfo),
    Serial(SerialInfo),
    /// No terminal: files over FTP, see [`Directory::ftp_info`].
    Ftp,
}

/// What it takes to connect to an FTP host. Contains the password and therefore stays in the core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FtpInfo {
    pub name: String,
    pub address: String,
    pub port: u16,
    /// Empty for anonymous sign-in.
    pub user: String,
    pub password: Option<Secret>,
    pub security: FtpSecurity,
    pub dir: Option<String>,
    pub plain_ok: bool,
    /// The fingerprint of the certificate confirmed for this address (`5F:1A:…`).
    pub pin: Option<String>,
    /// A typed password could be saved on the host: it signs in with its own user, not
    /// via an identity and not anonymously.
    pub saves_password: bool,
}

pub struct Directory {
    vault: Vault,
    groups: BTreeMap<String, Group>,
    hosts: BTreeMap<String, Host>,
    damaged: usize,
    /// Known hosts with their time of trust.
    known: BTreeMap<String, (KnownHost, i64)>,
    keys: BTreeMap<String, Key>,
    identities: BTreeMap<String, Identity>,
    /// Certificate authorities for servers with the time they were added.
    authorities: BTreeMap<String, (Authority, i64)>,
    workspaces: BTreeMap<String, Workspace>,
    forwards: BTreeMap<String, Forward>,
    snippets: BTreeMap<String, Snippet>,
    /// Proxmox connections.
    proxmox: BTreeMap<String, Proxmox>,
    /// Is [`Directory::batch`] running? Then `put` remembers what was written itself, and `reload` waits until the end.
    bulk: bool,
    /// Which shared vault a record lives in. Whatever is missing here is in the personal one.
    homes: BTreeMap<String, String>,
    /// Name of every shared vault together with the ID of the record that carries it.
    names: BTreeMap<String, (String, VaultLabel)>,
    /// Where a new record goes if it is not to be its group's vault or the personal one.
    target: Option<Id>,
    marks: VaultMarks,
}

/// Largest command and largest macro that can be saved.
const MAX_COMMAND: usize = 16 * 1024;
const MAX_MACRO_STEPS: usize = 2000;
const MAX_MACRO_KEYS: usize = 64 * 1024;
/// Longest pause of a macro that is saved (ten minutes).
const MAX_MACRO_WAIT: u32 = 600_000;

fn hex(id: &Id) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_id(text: &str) -> Result<Id> {
    let mut id = [0u8; 16];
    if text.len() != 32 || !text.is_ascii() {
        return Err(DirError::NotFound);
    }
    for (i, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).map_err(|_| DirError::NotFound)?;
    }
    Ok(id)
}

/// Algorithm and key without the comment after them.
fn key_body(openssh: &str) -> String {
    openssh.split_whitespace().take(2).collect::<Vec<_>>().join(" ")
}

fn forward_view(id: &str, rule: &Forward) -> ForwardView {
    ForwardView { id: id.to_string(), name: rule.name.clone(), kind: rule.kind, host: rule.host.clone(), bind_address: rule.bind_address.clone(), bind_port: rule.bind_port, dest_host: rule.dest_host.clone(), dest_port: rule.dest_port }
}

/// What a record refers to: first the group it lives in (for a group, the parent group), then
/// everything else (jump host, identity, key, the host of a port rule).
fn references(payload: &Payload) -> (Option<&str>, Vec<&str>) {
    fn of_fields(fields: &Fields) -> Vec<&str> {
        [&fields.jump, &fields.identity, &fields.key].into_iter().filter_map(|id| id.as_deref()).filter(|id| !id.is_empty()).collect()
    }
    match payload {
        Payload::Host(host) => (host.group.as_deref(), of_fields(&host.own)),
        Payload::Group(group) => (group.parent.as_deref(), of_fields(&group.defs)),
        Payload::Identity(identity) => (None, identity.key.as_deref().filter(|key| !key.is_empty()).into_iter().collect()),
        Payload::Forward(rule) => (None, vec![rule.host.as_str()]),
        _ => (None, Vec::new()),
    }
}

fn invalid<T>(reason: Invalid) -> Result<T> {
    Err(DirError::Invalid(reason))
}

fn clean_name(name: &str) -> Result<String> {
    let name = name.trim();
    match name.chars().count() {
        0 => invalid(Invalid::NameRequired),
        n if n > 80 => invalid(Invalid::NameTooLong),
        _ => Ok(name.to_string()),
    }
}

/// Addresses and users later end up in command lines and logs: no whitespace or control characters
/// and no leading `-` that could be read as an option.
fn is_safe_token(text: &str, max: usize) -> bool {
    !text.is_empty() && text.chars().count() <= max && !text.starts_with('-') && !text.chars().any(|c| c.is_whitespace() || c.is_control())
}

fn clean_color(color: Option<String>) -> Result<Option<String>> {
    match color.as_deref().map(str::trim) {
        None | Some("") => Ok(None),
        Some(c) if c.len() == 7 && c.starts_with('#') && c[1..].chars().all(|d| d.is_ascii_hexdigit()) => Ok(Some(c.to_uppercase())),
        Some(_) => invalid(Invalid::ColorInvalid),
    }
}

impl Directory {
    /// Reads an open vault.
    pub fn load(vault: Vault) -> Result<Self> {
        let mut directory = Self { vault, groups: BTreeMap::new(), hosts: BTreeMap::new(), damaged: 0, known: BTreeMap::new(), keys: BTreeMap::new(), identities: BTreeMap::new(), authorities: BTreeMap::new(), workspaces: BTreeMap::new(), forwards: BTreeMap::new(), snippets: BTreeMap::new(), proxmox: BTreeMap::new(), bulk: false, homes: BTreeMap::new(), names: BTreeMap::new(), target: None, marks: VaultMarks::default() };
        directory.reload()?;
        Ok(directory)
    }

    pub fn vault(&self) -> &Vault {
        &self.vault
    }

    pub fn vault_mut(&mut self) -> &mut Vault {
        &mut self.vault
    }

    /// Hands the vault back, e.g. for locking. The decrypted entries are discarded.
    pub fn into_vault(self) -> Vault {
        self.vault
    }

    fn reload(&mut self) -> Result<()> {
        if self.bulk {
            return Ok(());
        }
        let listing = self.vault.list()?;
        self.groups.clear();
        self.hosts.clear();
        self.known.clear();
        self.keys.clear();
        self.identities.clear();
        self.authorities.clear();
        self.workspaces.clear();
        self.forwards.clear();
        self.snippets.clear();
        self.proxmox.clear();
        self.damaged = listing.damaged.len();
        self.homes.clear();
        self.names.clear();
        let personal = self.vault.personal()?;
        for record in listing.records {
            if record.vault != personal {
                self.homes.insert(hex(&record.id), hex(&record.vault));
            }
            match serde_json::from_slice::<Payload>(&record.data) {
                Ok(Payload::VaultInfo(label)) => drop(self.names.insert(hex(&record.vault), (hex(&record.id), label))),
                Ok(Payload::Host(host)) => drop(self.hosts.insert(hex(&record.id), host)),
                Ok(Payload::Group(group)) => drop(self.groups.insert(hex(&record.id), group)),
                Ok(Payload::KnownHost(known)) => drop(self.known.insert(hex(&record.id), (known, record.modified_at))),
                Ok(Payload::Key(key)) => drop(self.keys.insert(hex(&record.id), key)),
                Ok(Payload::Identity(identity)) => drop(self.identities.insert(hex(&record.id), identity)),
                Ok(Payload::Authority(authority)) => drop(self.authorities.insert(hex(&record.id), (authority, record.modified_at))),
                Ok(Payload::Workspace(workspace)) => drop(self.workspaces.insert(hex(&record.id), workspace)),
                Ok(Payload::Forward(forward)) => drop(self.forwards.insert(hex(&record.id), forward)),
                Ok(Payload::Snippet(snippet)) => drop(self.snippets.insert(hex(&record.id), snippet)),
                // Proxmox connections only count from the personal vault. Whatever someone puts into a shared one
                // stays there and does not count: otherwise another member would decide where Glowport connects to.
                Ok(Payload::Proxmox(connection)) if record.vault == personal => drop(self.proxmox.insert(hex(&record.id), connection)),
                Ok(Payload::Proxmox(_)) | Ok(Payload::Unknown) => {}
                Err(_) => self.damaged += 1,
            }
        }
        Ok(())
    }

    pub fn snapshot(&self) -> Snapshot {
        let mut groups: Vec<GroupView> = self
            .groups
            .iter()
            .map(|(id, g)| GroupView { id: id.clone(), name: g.name.clone(), parent: self.shown_parent(id, g).map(str::to_string), color: g.color.clone(), defs: g.defs.clone(), has_proxy_password: g.proxy_password.is_some() })
            .collect();
        let mut hosts: Vec<HostView> = self
            .hosts
            .iter()
            .map(|(id, h)| HostView {
                id: id.clone(),
                name: h.name.clone(),
                address: h.address.clone(),
                group: h.group.clone().filter(|group| self.groups.contains_key(group)),
                protocol: h.protocol.clone(),
                serial: h.serial,
                ftp: h.ftp.clone(),
                color: h.color.clone(),
                os: h.os.clone(),
                own: h.own.clone(),
                has_password: h.password.is_some(),
                has_proxy_password: h.proxy_password.is_some(),
                proxmox: self.link_of(id, h).map(|link| LinkView { connection: link.connection.clone(), node: link.node.clone(), vmid: link.vmid, kind: link.kind.clone() }),
            })
            .collect();
        groups.sort_by_cached_key(|g| (g.name.to_lowercase(), g.id.clone()));
        hosts.sort_by_cached_key(|h| (h.name.to_lowercase(), h.id.clone()));
        let mut known_hosts: Vec<KnownHostView> = self
            .known
            .iter()
            .map(|(id, (k, added_at))| KnownHostView { id: id.clone(), host: k.host.clone(), port: k.port, algorithm: k.algorithm.clone(), fingerprint: k.fingerprint.clone(), added_at: *added_at })
            .collect();
        known_hosts.sort_by_cached_key(|k| (k.host.clone(), k.port, k.id.clone()));
        let mut keys: Vec<KeyView> = self
            .keys
            .iter()
            .map(|(id, k)| KeyView {
                id: id.clone(),
                name: k.name.clone(),
                kind: k.kind,
                bits: k.bits,
                fingerprint: k.fingerprint.clone(),
                public_key: format!("{} {}", k.public, k.name),
                origin: k.origin,
                added_at: k.added_at,
                certificate: k.certificate.clone(),
            })
            .collect();
        keys.sort_by_cached_key(|k| (k.name.to_lowercase(), k.id.clone()));
        let mut identities: Vec<IdentityView> = self
            .identities
            .iter()
            .map(|(id, i)| IdentityView { id: id.clone(), name: i.name.clone(), user: i.user.clone(), key: i.key.clone(), has_password: i.password.is_some() })
            .collect();
        identities.sort_by_cached_key(|i| (i.name.to_lowercase(), i.id.clone()));
        let mut authorities: Vec<AuthorityView> = self
            .authorities
            .iter()
            .map(|(id, (a, added_at))| AuthorityView { id: id.clone(), name: a.name.clone(), pattern: a.pattern.clone(), kind: a.label.clone(), fingerprint: a.fingerprint.clone(), added_at: *added_at })
            .collect();
        authorities.sort_by_cached_key(|a| (a.name.to_lowercase(), a.id.clone()));
        let mut workspaces: Vec<WorkspaceView> = self.workspaces.iter().map(|(id, w)| WorkspaceView { id: id.clone(), name: w.name.clone(), multi: w.multi, layout: w.layout.clone() }).collect();
        workspaces.sort_by_cached_key(|w| (w.name.to_lowercase(), w.id.clone()));
        let mut forwards: Vec<ForwardView> = self.forwards.iter().map(|(id, f)| forward_view(id, f)).collect();
        forwards.sort_by_cached_key(|f| (f.name.to_lowercase(), f.id.clone()));
        let mut snippets: Vec<SnippetView> = self
            .snippets
            .iter()
            .map(|(id, s)| SnippetView { id: id.clone(), name: s.name.clone(), package: s.package.clone(), kind: s.kind, command: s.command.clone(), steps: s.steps.clone(), hotkey: s.hotkey.clone().filter(|hotkey| self.owns_hotkey(id, hotkey)) })
            .collect();
        snippets.sort_by_cached_key(|s| (s.name.to_lowercase(), s.id.clone()));
        let mut proxmox: Vec<ProxmoxView> = self
            .proxmox
            .iter()
            .map(|(id, p)| ProxmoxView { id: id.clone(), name: p.name.clone(), address: p.address.clone(), token_id: p.token_id.clone(), fingerprint: p.fingerprint.clone(), identity: p.identity.clone().filter(|identity| self.identities.contains_key(identity)) })
            .collect();
        proxmox.sort_by_cached_key(|p| (p.name.to_lowercase(), p.id.clone()));
        let seq = Stamp(SNAPSHOTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1);
        Snapshot { seq, groups, hosts, damaged: self.damaged, known_hosts, keys, identities, authorities, workspaces, forwards, snippets, proxmox, vaults: self.vault_views(), homes: self.homes.clone() }
    }

    fn vault_views(&self) -> Vec<VaultView> {
        let me = self.vault.public_keys().ok().map(|keys| keys.0);
        let view = |info: crate::vault::VaultInfo| {
            let id = hex(&info.id);
            let member = |m: &roster::Member| MemberView {
                account: m.account.clone(),
                name: m.name.clone(),
                role: m.role,
                me: m.signing_key().is_some() && m.signing_key() == me,
                invited: self.marks.invited.contains(&(id.clone(), m.account.clone())),
                code: m.signing_key().zip(m.exchange_key()).map(|(ed25519, x25519)| roster::safety_code(&ed25519, &x25519)).unwrap_or_default(),
            };
            VaultView {
                kind: if info.kind == Kind::Personal { "personal" } else { "shared" },
                name: self.names.get(&id).map(|(_, label)| label.name.clone()).unwrap_or_default(),
                role: info.role,
                members: info.roster.as_ref().map(|roster| roster.members.iter().map(member).collect()).unwrap_or_default(),
                rolled_back: self.marks.rolled_back.contains(&id),
                orphaned: self.marks.orphaned.contains(&id),
                id,
            }
        };
        self.vault.vaults().unwrap_or_default().into_iter().map(view).collect()
    }

    /// Reads the vault again after sync changed it.
    pub fn refresh(&mut self) -> Result<()> {
        self.reload()
    }

    /// Records what sync knows about the vaults. Returns whether this changes anything in the view.
    pub fn mark_vaults(&mut self, marks: VaultMarks) -> bool {
        let changed = self.marks != marks;
        self.marks = marks;
        changed
    }

    /// The vault an entry lives in.
    fn home(&self, id: &str, personal: Id) -> Id {
        self.homes.get(id).and_then(|vault| crate::crypto::unhex(vault)).unwrap_or(personal)
    }

    /// Own role in the vault an entry lives in.
    pub fn role_of(&self, id: &str) -> Role {
        let Ok(personal) = self.vault.personal() else { return Role::Read };
        let home = self.home(id, personal);
        self.vault.vaults().ok().and_then(|vaults| vaults.into_iter().find(|info| info.id == home)).map_or(Role::Read, |info| info.role)
    }

    /// Name of a vault for display; empty for the personal one.
    pub fn vault_name(&self, vault: &str) -> String {
        self.names.get(vault).map(|(_, label)| label.name.clone()).unwrap_or_default()
    }

    /// Name of an entry for display, e.g. in a notice from sync.
    pub fn record_name(&self, id: &str) -> Option<String> {
        None.or_else(|| self.hosts.get(id).map(|h| h.name.clone()))
            .or_else(|| self.groups.get(id).map(|g| g.name.clone()))
            .or_else(|| self.keys.get(id).map(|k| k.name.clone()))
            .or_else(|| self.identities.get(id).map(|i| i.name.clone()))
            .or_else(|| self.snippets.get(id).map(|s| s.name.clone()))
            .or_else(|| self.forwards.get(id).map(|f| f.name.clone()))
            .or_else(|| self.workspaces.get(id).map(|w| w.name.clone()))
            .or_else(|| self.proxmox.get(id).map(|p| p.name.clone()))
    }

    /// Runs `work` so that newly created entries land in this vault. Without one, the vault of the group
    /// the entry goes into applies, otherwise the personal one.
    pub fn in_vault<T>(&mut self, vault: Option<&str>, work: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        let target = match vault {
            Some(vault) => {
                let id = parse_id(vault)?;
                if !self.vault.vaults()?.iter().any(|info| info.id == id) {
                    return Err(DirError::NotFound);
                }
                Some(id)
            }
            None => None,
        };
        let previous = std::mem::replace(&mut self.target, target);
        let outcome = work(self);
        self.target = previous;
        outcome
    }

    /// Gives an own shared vault a name. It is stored as a record inside the vault itself.
    pub fn rename_vault(&mut self, vault: &str, name: &str) -> Result<()> {
        let name = clean_name(name)?;
        let id = parse_id(vault)?;
        let info = self.vault.vaults()?.into_iter().find(|info| info.id == id).ok_or(DirError::NotFound)?;
        if info.kind != Kind::Shared || info.role != Role::Owner {
            return Err(VaultError::NotOwner.into());
        }
        let existing = self.names.get(vault).cloned();
        let label = VaultLabel { v: existing.as_ref().map_or(1, |(_, label)| label.v), name, extra: existing.as_ref().map(|(_, label)| label.extra.clone()).unwrap_or_default() };
        self.in_vault(Some(vault), |dir| dir.put(existing.as_ref().map(|(id, _)| id.as_str()), &Payload::VaultInfo(label)))?;
        self.reload()
    }

    /// The group under which a group appears and from which it inherits.
    ///
    /// Two devices can cause together during sync what neither may do alone (`docs/sync.md`,
    /// “Rules across several records”): a group whose parent was deleted, or groups in a cycle.
    /// Both are defused here, not rewritten: without a parent the group sits at the top
    /// level, and a cycle is broken on every device at the same group, the one with the smallest ID.
    fn shown_parent<'a>(&'a self, id: &str, group: &'a Group) -> Option<&'a str> {
        let parent_of = |group: &'a Group| group.parent.as_deref().filter(|parent| self.groups.contains_key(*parent));
        let parent = parent_of(group)?;
        let (mut current, mut smallest) = (parent, id);
        for _ in 0..self.groups.len() {
            if current == id {
                return (smallest != id).then_some(parent);
            }
            smallest = smallest.min(current);
            match self.groups.get(current).and_then(parent_of) {
                Some(next) => current = next,
                None => break,
            }
        }
        Some(parent)
    }

    /// A hotkey belongs to one snippet. If two carry it after a sync, it applies to the one with the
    /// smaller ID.
    fn owns_hotkey(&self, id: &str, hotkey: &str) -> bool {
        !self.snippets.iter().any(|(other, snippet)| other.as_str() < id && snippet.hotkey.as_deref() == Some(hotkey))
    }

    /// Groups from the root down to `group`.
    fn chain(&self, group: Option<&str>) -> Vec<(&str, &Group)> {
        let mut chain = Vec::new();
        let mut current = group;
        while let Some((id, group)) = current.and_then(|id| self.groups.get_key_value(id)) {
            chain.push((id.as_str(), group));
            current = self.shown_parent(id, group);
        }
        chain.reverse();
        chain
    }

    pub fn effective(&self, host_id: &str, default_reconnect: Reconnect) -> Result<Effective> {
        let host = self.hosts.get(host_id).ok_or(DirError::NotFound)?;
        Ok(model::resolve(host, &self.chain(host.group.as_deref()), default_reconnect))
    }

    /// A host's sign-in after inheritance. A reference to a deleted key does not count.
    fn auth<'a>(&'a self, host: &'a Host) -> Auth<'a> {
        let chain = self.chain(host.group.as_deref());
        let mut levels: Vec<&Fields> = chain.iter().map(|(_, group)| &group.defs).collect();
        levels.push(&host.own);
        let mut auth = model::resolve_auth(&levels, |id| self.identities.get(id));
        auth.key = auth.key.filter(|id| self.keys.contains_key(*id));
        auth
    }

    /// A host's connection details after inheritance. Contains password and key and therefore stays in the core.
    pub fn connect_info(&self, host_id: &str) -> Result<ConnectInfo> {
        let host = self.hosts.get(host_id).ok_or(DirError::NotFound)?;
        if host.protocol != model::PROTOCOL_SSH {
            return invalid(Invalid::HostNotSsh);
        }
        let effective = model::resolve(host, &self.chain(host.group.as_deref()), Reconnect::Notice);
        let auth = self.auth(host);
        let identity = auth.identity.and_then(|id| self.identities.get(id));
        let key = auth.key.and_then(|id| self.keys.get(id));
        // The password belongs to the proxy that applies: on the host if it sets one itself, otherwise on the group it comes from.
        let proxy_password = match &effective.proxy.source {
            model::Source::Host => host.proxy_password.clone(),
            model::Source::Group(id) => self.groups.get(id).and_then(|group| group.proxy_password.clone()),
            model::Source::Default => None,
        };
        Ok(ConnectInfo {
            name: host.name.clone(),
            address: host.address.clone(),
            port: effective.port.value,
            user: auth.user.unwrap_or(model::DEFAULT_USER).to_string(),
            password: host.password.clone().or_else(|| identity.and_then(|i| i.password.clone())),
            key: key.map(|key| key.private.clone()),
            certificate: key.and_then(|key| key.certificate.as_ref()).map(|certificate| certificate.text.clone()),
            key_file: auth.key_file.map(str::to_string),
            authorities: self.authorities.values().filter(|(authority, _)| model::pattern_matches(&authority.pattern, &host.address)).map(|(authority, _)| authority.public.clone()).collect(),
            jump: effective.jump.value.filter(|id| id != host_id && self.hosts.contains_key(id)),
            startcmd: effective.startcmd.value,
            env: effective.env.value.as_deref().and_then(model::parse_env).unwrap_or_default(),
            agent: effective.agent.value,
            agent_forward: effective.agent_forward.value,
            proxy: effective.proxy.value.as_deref().and_then(model::parse_proxy),
            proxy_password,
            keepalive: effective.keepalive.value,
            timeout: effective.timeout.value,
            term: effective.term.value,
            charset: effective.charset.value,
            legacy: effective.legacy.value,
            mosh: effective.mosh.value.then_some(MoshInfo { predict: effective.mosh_predict.value, port: effective.mosh_port.value, server: effective.mosh_server.value }),
        })
    }

    /// How a host is reached, for Telnet and serial lines including everything needed to connect.
    /// A protocol this version does not know is rejected.
    pub fn endpoint(&self, host_id: &str) -> Result<Endpoint> {
        let host = self.hosts.get(host_id).ok_or(DirError::NotFound)?;
        let effective = || model::resolve(host, &self.chain(host.group.as_deref()), Reconnect::Notice);
        match host.protocol.as_str() {
            model::PROTOCOL_SSH => Ok(Endpoint::Ssh),
            model::PROTOCOL_TELNET => {
                let effective = effective();
                Ok(Endpoint::Telnet(TelnetInfo {
                    name: host.name.clone(),
                    address: host.address.clone(),
                    port: host.own.port.unwrap_or(model::DEFAULT_TELNET_PORT),
                    user: host.own.user.clone(),
                    timeout: effective.timeout.value,
                    term: effective.term.value,
                    charset: effective.charset.value,
                }))
            }
            model::PROTOCOL_SERIAL => {
                let line = host.serial.ok_or(DirError::Invalid(Invalid::SerialRequired))?;
                Ok(Endpoint::Serial(SerialInfo { name: host.name.clone(), port: host.address.clone(), line, charset: effective().charset.value }))
            }
            model::PROTOCOL_FTP => Ok(Endpoint::Ftp),
            _ => invalid(Invalid::ProtocolInvalid),
        }
    }

    /// A host's name, whatever its protocol.
    pub fn host_name(&self, host_id: &str) -> Option<String> {
        self.hosts.get(host_id).map(|host| host.name.clone())
    }

    /// Does FTP lead to this host?
    pub fn is_ftp(&self, host_id: &str) -> bool {
        self.hosts.get(host_id).is_some_and(|host| host.protocol == model::PROTOCOL_FTP)
    }

    /// Connection details of an FTP host. User and password come from the identity if one is chosen,
    /// otherwise from the host itself; groups set nothing for FTP.
    pub fn ftp_info(&self, host_id: &str) -> Result<FtpInfo> {
        let host = self.hosts.get(host_id).ok_or(DirError::NotFound)?;
        if host.protocol != model::PROTOCOL_FTP {
            return invalid(Invalid::ProtocolInvalid);
        }
        let ftp = host.ftp.clone().unwrap_or(Ftp { security: FtpSecurity::Explicit, anonymous: false, dir: None, plain_ok: false });
        let port = host.own.port.unwrap_or(ftp.default_port());
        let identity = host.own.identity.as_deref().filter(|id| !id.is_empty()).and_then(|id| self.identities.get(id));
        let saves_password = !ftp.anonymous && identity.is_none();
        let (user, password) = match (ftp.anonymous, identity) {
            (true, _) => (String::new(), None),
            (false, Some(identity)) => (identity.user.clone(), identity.password.clone()),
            (false, None) => (host.own.user.clone().unwrap_or_default(), host.password.clone()),
        };
        Ok(FtpInfo { name: host.name.clone(), address: host.address.clone(), port, user, password, security: ftp.security, dir: ftp.dir, plain_ok: ftp.plain_ok, pin: self.certificate_pin(&host.address, port), saves_password })
    }

    /// The fingerprint of the certificate the user confirmed for an address.
    pub fn certificate_pin(&self, host: &str, port: u16) -> Option<String> {
        self.known_for(host, port).find(|(_, entry)| entry.algorithm == model::ALGORITHM_TLS).map(|(_, entry)| entry.fingerprint.clone())
    }

    /// Remembers a server's certificate. It is listed with the known hosts; whatever was there for the address is replaced.
    pub fn trust_certificate(&mut self, host: &str, port: u16, fingerprint: &str) -> Result<()> {
        if !is_safe_token(host, 255) || port == 0 {
            return invalid(Invalid::AddressInvalid);
        }
        let old: Vec<String> = self.known_for(host, port).map(|(id, _)| id.clone()).collect();
        let entry = KnownHost { v: 1, host: host.to_lowercase(), port, algorithm: model::ALGORITHM_TLS.to_string(), fingerprint: fingerprint.to_string(), key: fingerprint.to_string(), extra: Map::new() };
        self.atomically(|dir| {
            for id in &old {
                dir.vault.delete(&parse_id(id)?)?;
            }
            dir.put(None, &Payload::KnownHost(entry)).map(drop)
        })
    }

    /// Changes on an FTP host what the question before an unencrypted connection resulted in: switching it off
    /// (`plain_ok`) or moving the host to FTPS (`secure`). The port does not follow: it applies to both.
    pub fn set_ftp_choice(&mut self, id: &str, plain_ok: bool, secure: bool) -> Result<()> {
        let mut host = self.hosts.get(id).ok_or(DirError::NotFound)?.clone();
        let Some(ftp) = host.ftp.as_mut().filter(|_| host.protocol == model::PROTOCOL_FTP) else { return invalid(Invalid::ProtocolInvalid) };
        if secure {
            ftp.security = FtpSecurity::Explicit;
            ftp.plain_ok = false;
        } else {
            ftp.plain_ok = plain_ok && ftp.security == FtpSecurity::None;
        }
        self.put(Some(id), &Payload::Host(host))?;
        self.reload()
    }

    /// Does SSH lead to this host? Only then is it suitable as a jump host, for port rules, files and commands.
    pub fn is_ssh(&self, host_id: &str) -> bool {
        self.hosts.get(host_id).is_some_and(|host| host.protocol == model::PROTOCOL_SSH)
    }

    fn known_for(&self, host: &str, port: u16) -> impl Iterator<Item = (&String, &KnownHost)> {
        let host = host.to_lowercase();
        self.known.iter().filter(move |(_, (k, _))| k.host == host && k.port == port).map(|(id, (k, _))| (id, k))
    }

    /// Judges the key a server shows. The key itself is compared, not the fingerprint.
    pub fn judge_host_key(&self, host: &str, port: u16, key_openssh: &str) -> Verdict {
        let key = key_body(key_openssh);
        let mut known = Vec::new();
        for (_, entry) in self.known_for(host, port) {
            if entry.key == key {
                return Verdict::Trusted;
            }
            known.push(entry.fingerprint.clone());
        }
        if known.is_empty() {
            Verdict::Unknown
        } else {
            Verdict::Changed { known }
        }
    }

    /// Trusts a key for an address. Whatever was stored there so far is replaced.
    pub fn trust_host_key(&mut self, host: &str, port: u16, algorithm: &str, fingerprint: &str, key_openssh: &str) -> Result<()> {
        let old: Vec<String> = self.known_for(host, port).map(|(id, _)| id.clone()).collect();
        let entry = KnownHost { v: 1, host: host.to_lowercase(), port, algorithm: algorithm.to_string(), fingerprint: fingerprint.to_string(), key: key_body(key_openssh), extra: Map::new() };
        self.atomically(|dir| {
            for id in &old {
                dir.vault.delete(&parse_id(id)?)?;
            }
            dir.put(None, &Payload::KnownHost(entry)).map(drop)
        })
    }

    pub fn delete_known_host(&mut self, id: &str) -> Result<()> {
        if !self.known.contains_key(id) {
            return Err(DirError::NotFound);
        }
        self.vault.delete(&parse_id(id)?)?;
        self.reload()
    }

    /// Records the operating system detected while connecting. Returns whether anything changed.
    pub fn set_host_os(&mut self, id: &str, os: &str) -> Result<bool> {
        let mut host = self.hosts.get(id).ok_or(DirError::NotFound)?.clone();
        if host.os.as_deref() == Some(os) {
            return Ok(false);
        }
        host.os = Some(os.to_string());
        self.put(Some(id), &Payload::Host(host))?;
        self.reload()?;
        Ok(true)
    }

    /// Trusts a certificate authority for the addresses its pattern matches.
    pub fn add_authority(&mut self, authority: NewAuthority) -> Result<String> {
        let pattern = authority.pattern.trim().to_string();
        let allowed = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '*' | '?' | ',' | ':' | ' ');
        if pattern.is_empty() || pattern.len() > 255 || !pattern.chars().all(allowed) {
            return invalid(Invalid::PatternInvalid);
        }
        let record = Authority { v: 1, name: clean_name(&authority.name)?, pattern, label: authority.label, fingerprint: authority.fingerprint, public: key_body(&authority.public), extra: Map::new() };
        let id = self.put(None, &Payload::Authority(record))?;
        self.reload()?;
        Ok(id)
    }

    pub fn delete_authority(&mut self, id: &str) -> Result<()> {
        if !self.authorities.contains_key(id) {
            return Err(DirError::NotFound);
        }
        self.vault.delete(&parse_id(id)?)?;
        self.reload()
    }

    /// Creates or replaces a workspace. Panes whose host does not exist are dropped.
    pub fn save_workspace(&mut self, input: WorkspaceInput) -> Result<String> {
        let name = clean_name(&input.name)?;
        let old = match &input.id {
            Some(id) => Some(self.workspaces.get(id).ok_or(DirError::NotFound)?.clone()),
            None => None,
        };
        if input.layout.panes() > model::MAX_PANES {
            return invalid(Invalid::WorkspaceTooLarge);
        }
        let Some(layout) = input.layout.retain(&|host| self.hosts.contains_key(host)) else {
            return invalid(Invalid::WorkspaceEmpty);
        };
        let multi = input.multi && layout.panes() > 1;
        let record = Workspace { v: old.as_ref().map_or(1, |w| w.v), name, multi, layout, extra: old.map(|w| w.extra).unwrap_or_default() };
        let id = self.put(input.id.as_deref(), &Payload::Workspace(record))?;
        self.reload()?;
        Ok(id)
    }

    pub fn delete_workspace(&mut self, id: &str) -> Result<()> {
        if !self.workspaces.contains_key(id) {
            return Err(DirError::NotFound);
        }
        self.vault.delete(&parse_id(id)?)?;
        self.reload()
    }

    /// A port rule as stored in the vault; for switching it on.
    pub fn forward(&self, id: &str) -> Result<ForwardView> {
        self.forwards.get(id).map(|f| forward_view(id, f)).ok_or(DirError::NotFound)
    }

    /// Creates or replaces a port rule.
    pub fn save_forward(&mut self, input: ForwardInput) -> Result<String> {
        let name = clean_name(&input.name)?;
        let old = match &input.id {
            Some(id) => Some(self.forwards.get(id).ok_or(DirError::NotFound)?.clone()),
            None => None,
        };
        if !self.hosts.contains_key(&input.host) {
            return invalid(Invalid::HostMissing);
        }
        if !self.is_ssh(&input.host) {
            return invalid(Invalid::HostNotSsh);
        }
        let port = |n: u32| u16::try_from(n).ok().filter(|p| *p != 0).ok_or(DirError::Invalid(Invalid::PortInvalid));
        let address = |text: &str| if is_safe_token(text, 255) && !text.contains(['/', '@']) { Ok(text.to_string()) } else { invalid(Invalid::AddressInvalid) };
        let bind_address = match input.bind_address.trim() {
            "" => "127.0.0.1".to_string(),
            text => address(text)?,
        };
        let bind_port = port(input.bind_port)?;
        let (dest_host, dest_port) = match input.kind {
            ForwardKind::Dynamic => (String::new(), 0),
            _ if input.dest_host.trim().is_empty() => return invalid(Invalid::DestRequired),
            _ => (address(input.dest_host.trim())?, port(input.dest_port)?),
        };
        let record = Forward { v: old.as_ref().map_or(1, |f| f.v), name, kind: input.kind, host: input.host, bind_address, bind_port, dest_host, dest_port, extra: old.map(|f| f.extra).unwrap_or_default() };
        let id = self.put(input.id.as_deref(), &Payload::Forward(record))?;
        self.reload()?;
        Ok(id)
    }

    pub fn delete_forward(&mut self, id: &str) -> Result<()> {
        if !self.forwards.contains_key(id) {
            return Err(DirError::NotFound);
        }
        self.vault.delete(&parse_id(id)?)?;
        self.reload()
    }

    /// Creates or replaces a snippet or macro. A hotkey belongs to at most one.
    pub fn save_snippet(&mut self, input: SnippetInput) -> Result<String> {
        let name = clean_name(&input.name)?;
        let old = match &input.id {
            Some(id) => Some(self.snippets.get(id).ok_or(DirError::NotFound)?.clone()),
            None => None,
        };
        let package = input.package.trim();
        if package.chars().count() > 60 {
            return invalid(Invalid::NameTooLong);
        }
        let (command, steps) = match input.kind {
            SnippetKind::Command => {
                // Uniform line endings; when run, every line is sent with Enter.
                let command = input.command.replace("\r\n", "\n").trim().to_string();
                if command.is_empty() {
                    return invalid(Invalid::CommandRequired);
                }
                if command.len() > MAX_COMMAND {
                    return invalid(Invalid::SnippetTooLarge);
                }
                (command, Vec::new())
            }
            SnippetKind::Macro => {
                let steps: Vec<MacroStep> = input.steps.into_iter().filter(|step| !step.keys.is_empty()).map(|step| MacroStep { wait: step.wait.min(MAX_MACRO_WAIT), keys: step.keys }).collect();
                if steps.is_empty() {
                    return invalid(Invalid::MacroEmpty);
                }
                if steps.len() > MAX_MACRO_STEPS || steps.iter().map(|step| step.keys.len()).sum::<usize>() > MAX_MACRO_KEYS {
                    return invalid(Invalid::SnippetTooLarge);
                }
                (String::new(), steps)
            }
        };
        let hotkey = input.hotkey.filter(|hotkey| !hotkey.is_empty());
        if let Some(hotkey) = &hotkey {
            if !model::valid_hotkey(hotkey) {
                return invalid(Invalid::HotkeyInvalid);
            }
            if self.snippets.iter().any(|(id, other)| Some(id) != input.id.as_ref() && other.hotkey.as_ref() == Some(hotkey)) {
                return invalid(Invalid::HotkeyTaken);
            }
        }
        let record = Snippet { v: old.as_ref().map_or(1, |s| s.v), name, package: package.to_string(), kind: input.kind, command, steps, hotkey, extra: old.map(|s| s.extra).unwrap_or_default() };
        let id = self.put(input.id.as_deref(), &Payload::Snippet(record))?;
        self.reload()?;
        Ok(id)
    }

    pub fn delete_snippet(&mut self, id: &str) -> Result<()> {
        if !self.snippets.contains_key(id) {
            return Err(DirError::NotFound);
        }
        self.vault.delete(&parse_id(id)?)?;
        self.reload()
    }

    /// Switches a host to a key from the vault. Returns whether anything changed.
    pub fn set_host_key(&mut self, id: &str, key: &str) -> Result<bool> {
        let mut host = self.hosts.get(id).ok_or(DirError::NotFound)?.clone();
        if !self.keys.contains_key(key) {
            return invalid(Invalid::KeyMissing);
        }
        if host.own.key.as_deref() == Some(key) {
            return Ok(false);
        }
        host.own.key = Some(key.to_string());
        self.put(Some(id), &Payload::Host(host))?;
        self.reload()?;
        Ok(true)
    }

    /// Saves a password that was typed while connecting and worked.
    pub fn set_host_password(&mut self, id: &str, password: Secret) -> Result<()> {
        let mut host = self.hosts.get(id).ok_or(DirError::NotFound)?.clone();
        host.password = Some(password);
        self.put(Some(id), &Payload::Host(host))?;
        self.reload()
    }

    /// Checks and cleans inheritable values. `owner` is the host carrying them (for “do not jump to itself”).
    fn clean_fields(&self, fields: Fields, owner: Option<&str>) -> Result<Fields> {
        let user = fields.user.map(|u| u.trim().to_string()).filter(|u| !u.is_empty());
        if user.as_deref().is_some_and(|u| !is_safe_token(u, 64)) {
            return invalid(Invalid::UserInvalid);
        }
        if fields.port == Some(0) {
            return invalid(Invalid::PortInvalid);
        }
        match fields.jump.as_deref() {
            None | Some("") => {}
            Some(id) if Some(id) == owner => return invalid(Invalid::JumpSelf),
            Some(id) if !self.hosts.contains_key(id) => return invalid(Invalid::JumpMissing),
            Some(id) if !self.is_ssh(id) => return invalid(Invalid::HostNotSsh),
            Some(_) => {}
        }
        if fields.identity.as_deref().is_some_and(|id| !id.is_empty() && !self.identities.contains_key(id)) {
            return invalid(Invalid::IdentityMissing);
        }
        if fields.key.as_deref().is_some_and(|id| !id.is_empty() && !self.keys.contains_key(id)) {
            return invalid(Invalid::KeyMissing);
        }
        let startcmd = fields.startcmd.map(|c| c.trim().to_string()).filter(|c| !c.is_empty());
        let key_file = fields.key_file.map(|p| p.trim().to_string()).filter(|p| !p.is_empty() && !p.chars().any(char::is_control));
        let env = fields.env.map(|e| e.trim().to_string()).filter(|e| !e.is_empty());
        if env.as_deref().is_some_and(|e| model::parse_env(e).is_none()) {
            return invalid(Invalid::EnvInvalid);
        }
        // For the proxy, empty means “explicitly none” and therefore stays.
        let proxy = fields.proxy.map(|p| p.trim().to_string());
        if proxy.as_deref().is_some_and(|p| !p.is_empty() && model::parse_proxy(p).is_none()) {
            return invalid(Invalid::ProxyInvalid);
        }
        if fields.keepalive.is_some_and(|seconds| seconds > 3600) {
            return invalid(Invalid::KeepaliveInvalid);
        }
        if fields.timeout.is_some_and(|seconds| !(1..=300).contains(&seconds)) {
            return invalid(Invalid::TimeoutInvalid);
        }
        let term = fields.term.map(|t| t.trim().to_string()).filter(|t| !t.is_empty());
        if term.as_deref().is_some_and(|t| t.len() > 32 || !t.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+'))) {
            return invalid(Invalid::TermInvalid);
        }
        let charset = fields.charset.map(|c| c.trim().to_ascii_lowercase()).filter(|c| !c.is_empty());
        if charset.as_deref().is_some_and(|c| !model::CHARSETS.contains(&c)) {
            return invalid(Invalid::CharsetInvalid);
        }
        // Only the interface knows which schemes exist; here the form of the ID counts.
        let scheme = fields.scheme.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        if scheme.as_deref().is_some_and(|s| s.len() > 64 || !s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')) {
            return invalid(Invalid::SchemeInvalid);
        }
        let mosh_predict = fields.mosh_predict.map(|p| p.trim().to_string()).filter(|p| !p.is_empty());
        if mosh_predict.as_deref().is_some_and(|p| !model::MOSH_PREDICT.contains(&p)) {
            return invalid(Invalid::MoshPredictInvalid);
        }
        let mosh_port = fields.mosh_port.map(|p| p.trim().to_string()).filter(|p| !p.is_empty());
        if mosh_port.as_deref().is_some_and(|p| !model::valid_mosh_port(p)) {
            return invalid(Invalid::MoshPortInvalid);
        }
        let mosh_server = fields.mosh_server.map(|p| p.trim().to_string()).filter(|p| !p.is_empty());
        if mosh_server.as_deref().is_some_and(|p| !model::valid_mosh_server(p)) {
            return invalid(Invalid::MoshServerInvalid);
        }
        Ok(Fields {
            user,
            port: fields.port,
            jump: fields.jump,
            startcmd,
            reconnect: fields.reconnect,
            key_file,
            identity: fields.identity,
            key: fields.key,
            env,
            agent: fields.agent,
            agent_forward: fields.agent_forward,
            proxy,
            keepalive: fields.keepalive,
            timeout: fields.timeout,
            term,
            charset,
            legacy: fields.legacy,
            scheme,
            mosh: fields.mosh,
            mosh_predict,
            mosh_port,
            mosh_server,
        })
    }

    fn put(&mut self, id: Option<&str>, payload: &Payload) -> Result<String> {
        let personal = self.vault.personal()?;
        let (parent, others) = references(payload);
        // An existing entry stays where it is. A new one goes into the chosen vault, otherwise into
        // its group's, otherwise into the personal one.
        let home = match id {
            Some(id) => self.home(id, personal),
            None => self.target.unwrap_or_else(|| parent.map_or(personal, |parent| self.home(parent, personal))),
        };
        // An entry lives in the same vault as its group. And whatever lives in a shared vault only refers
        // to entries of the same vault: the other members would not have them otherwise.
        let elsewhere = |id: &&str| self.known(id) && self.home(id, personal) != home;
        if parent.as_ref().is_some_and(elsewhere) || (home != personal && others.iter().any(elsewhere)) {
            return invalid(Invalid::OtherVault);
        }
        let bytes = zeroize::Zeroizing::new(serde_json::to_vec(payload).expect("Datensätze lassen sich immer als JSON schreiben"));
        let id = match id {
            Some(id) => hex(&self.vault.put(Some(parse_id(id)?), &bytes)?),
            None => hex(&self.vault.put_in(&home, &bytes)?),
        };
        if home != personal {
            self.homes.insert(id.clone(), hex(&home));
        }
        if self.bulk {
            self.remember(&id, payload);
        }
        Ok(id)
    }

    /// Is there an entry with this ID that can be referred to?
    fn known(&self, id: &str) -> bool {
        self.hosts.contains_key(id) || self.groups.contains_key(id) || self.keys.contains_key(id) || self.identities.contains_key(id)
    }

    /// Adds a record just written to the state in memory without reading the whole vault again.
    fn remember(&mut self, id: &str, payload: &Payload) {
        let id = id.to_string();
        match payload.clone() {
            Payload::Host(host) => drop(self.hosts.insert(id, host)),
            Payload::Group(group) => drop(self.groups.insert(id, group)),
            Payload::KnownHost(known) => drop(self.known.insert(id, (known, now_ms()))),
            Payload::Key(key) => drop(self.keys.insert(id, key)),
            Payload::Identity(identity) => drop(self.identities.insert(id, identity)),
            Payload::Authority(authority) => drop(self.authorities.insert(id, (authority, now_ms()))),
            Payload::Workspace(workspace) => drop(self.workspaces.insert(id, workspace)),
            Payload::Forward(forward) => drop(self.forwards.insert(id, forward)),
            Payload::Snippet(snippet) => drop(self.snippets.insert(id, snippet)),
            Payload::Proxmox(connection) => drop(self.proxmox.insert(id, connection)),
            Payload::VaultInfo(_) | Payload::Unknown => {}
        }
    }

    /// Runs many changes as one: if `work` fails, the vault stays as it was. Meanwhile it is not
    /// read again after every write, only at the end; so an import of hundreds of entries stays quick.
    /// Allowed inside is everything that creates or replaces (`save_…`, `add_…`), nothing that deletes.
    pub fn batch<T>(&mut self, work: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        self.vault.begin()?;
        self.bulk = true;
        let outcome = work(self);
        self.bulk = false;
        let ended = self.vault.end(outcome.is_ok());
        self.reload()?;
        let value = outcome?;
        ended?;
        Ok(value)
    }

    /// Adds a server key to those already valid for an address, e.g. from an import.
    /// Unlike [`Directory::trust_host_key`] this replaces nothing. Returns whether it was new.
    pub fn add_known_host(&mut self, host: &str, port: u16, algorithm: &str, fingerprint: &str, key_openssh: &str) -> Result<bool> {
        let key = key_body(key_openssh);
        if !is_safe_token(host, 255) || port == 0 || key.split(' ').count() != 2 {
            return invalid(Invalid::AddressInvalid);
        }
        if self.known_for(host, port).any(|(_, entry)| entry.key == key) {
            return Ok(false);
        }
        let entry = KnownHost { v: 1, host: host.to_lowercase(), port, algorithm: algorithm.to_string(), fingerprint: fingerprint.to_string(), key, extra: Map::new() };
        self.put(None, &Payload::KnownHost(entry))?;
        self.reload()?;
        Ok(true)
    }

    /// The known hosts with their key, for exporting. The interface's view only carries the fingerprint.
    pub fn known_hosts(&self) -> Vec<KnownHost> {
        self.known.values().map(|(entry, _)| entry.clone()).collect()
    }

    /// An identity's user. The export writes it where the identity was set.
    pub fn identity_user(&self, id: &str) -> Option<String> {
        self.identities.get(id).map(|i| i.user.clone())
    }

    /// A host's link, if its connection exists. A sync can delete a connection
    /// while another device links a host to it; the link then points nowhere and does not count.
    /// Nor does it count on a host in a shared vault: Glowport creates none there.
    fn link_of<'a>(&self, id: &str, host: &'a Host) -> Option<&'a ProxmoxLink> {
        host.proxmox.as_ref().filter(|link| !self.homes.contains_key(id) && self.proxmox.contains_key(&link.connection))
    }

    /// Creates or changes a Proxmox connection. It always lives in the personal vault. Whether the address
    /// answers and the token is valid is checked by the caller; here the form counts.
    pub fn save_proxmox(&mut self, input: ProxmoxInput) -> Result<String> {
        let existing = match &input.id {
            Some(id) => Some(self.proxmox.get(id).ok_or(DirError::NotFound)?.clone()),
            None => None,
        };
        let name = clean_name(&input.name)?;
        // `https://host[:port]` and nothing else: that is where the token's secret goes.
        let address = input.address.trim().trim_end_matches('/').to_string();
        let host = address.strip_prefix("https://").unwrap_or_default();
        if host.is_empty() || address.len() > 255 || !host.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']')) {
            return invalid(Invalid::AddressInvalid);
        }
        // ID and secret later go into a request header: visible ASCII characters only.
        let plain = |text: &str| !text.is_empty() && text.len() <= 255 && text.chars().all(|c| c.is_ascii_graphic());
        let token_id = input.token_id.trim().to_string();
        let shaped = token_id.split_once('@').is_some_and(|(user, rest)| !user.is_empty() && rest.split_once('!').is_some_and(|(realm, token)| !realm.is_empty() && !token.is_empty()));
        if !shaped || !plain(&token_id) {
            return invalid(Invalid::TokenInvalid);
        }
        let secret = match input.secret.map(|secret| Secret::new(secret.expose().trim().to_string())).filter(|secret| !secret.expose().is_empty()) {
            Some(secret) if plain(secret.expose()) => secret,
            Some(_) => return invalid(Invalid::TokenInvalid),
            None => existing.as_ref().map(|p| p.secret.clone()).ok_or(DirError::Invalid(Invalid::SecretRequired))?,
        };
        let fingerprint = match input.fingerprint.as_deref().map(str::trim).filter(|text| !text.is_empty()) {
            Some(text) => {
                // As Proxmox shows it: 32 pairs, upper case, with colons.
                let digits = text.chars().filter(|c| !matches!(c, ':' | ' ')).collect::<String>().to_ascii_uppercase();
                if digits.len() != 64 || !digits.chars().all(|c| c.is_ascii_hexdigit()) {
                    return invalid(Invalid::FingerprintInvalid);
                }
                Some(digits.as_bytes().chunks(2).map(|pair| String::from_utf8_lossy(pair).into_owned()).collect::<Vec<_>>().join(":"))
            }
            None => None,
        };
        let identity = input.identity.filter(|id| !id.is_empty());
        if identity.as_deref().is_some_and(|id| !self.identities.contains_key(id)) {
            return invalid(Invalid::IdentityMissing);
        }
        let record = Proxmox { v: existing.as_ref().map_or(1, |p| p.v), name, address, token_id, secret, fingerprint, identity, extra: existing.map(|p| p.extra).unwrap_or_default() };
        let previous = self.target.take();
        let saved = self.put(input.id.as_deref(), &Payload::Proxmox(record));
        self.target = previous;
        let id = saved?;
        self.reload()?;
        Ok(id)
    }

    /// Removes a Proxmox connection. Its hosts stay and only lose the link.
    pub fn delete_proxmox(&mut self, id: &str) -> Result<()> {
        if !self.proxmox.contains_key(id) {
            return Err(DirError::NotFound);
        }
        self.atomically(|dir| {
            let linked: Vec<(String, Host)> = dir.hosts.iter().filter(|(_, h)| h.proxmox.as_ref().is_some_and(|link| link.connection == id)).map(|(i, h)| (i.clone(), h.clone())).collect();
            for (host_id, mut host) in linked {
                // Where one may only read, the link stays; without its connection it does not count.
                if dir.role_of(&host_id).may_write() {
                    host.proxmox = None;
                    dir.put(Some(&host_id), &Payload::Host(host))?;
                }
            }
            Ok(dir.vault.delete(&parse_id(id)?)?)
        })
    }

    /// Address and token of a connection, to talk to its server.
    pub fn proxmox_access(&self, id: &str) -> Result<ProxmoxAccess> {
        let p = self.proxmox.get(id).ok_or(DirError::NotFound)?;
        Ok(ProxmoxAccess { address: p.address.clone(), token_id: p.token_id.clone(), secret: p.secret.clone(), fingerprint: p.fingerprint.clone() })
    }

    /// The host belonging to a machine. If there are several (two devices created the same machine),
    /// the one with the smallest ID, the same on every device.
    pub fn proxmox_host(&self, connection: &str, vmid: u32) -> Option<&str> {
        self.hosts.iter().find(|(id, h)| self.link_of(id, h).is_some_and(|link| link.connection == connection && link.vmid == vmid)).map(|(id, _)| id.as_str())
    }

    /// What a connection without a saved host signs in with: an identity (user, its key,
    /// its password) or a single key from the vault. A named key takes precedence over the
    /// identity's.
    pub fn login(&self, identity: Option<&str>, key: Option<&str>) -> Result<Login> {
        let identity = match identity.filter(|id| !id.is_empty()) {
            Some(id) => Some(self.identities.get(id).ok_or(DirError::Invalid(Invalid::IdentityMissing))?),
            None => None,
        };
        let key = match key.filter(|id| !id.is_empty()).or(identity.and_then(|i| i.key.as_deref())) {
            Some(id) => Some(self.keys.get(id).ok_or(DirError::Invalid(Invalid::KeyMissing))?),
            None => None,
        };
        Ok(Login {
            user: identity.map(|i| i.user.clone()),
            password: identity.and_then(|i| i.password.clone()),
            key: key.map(|key| key.private.clone()),
            certificate: key.and_then(|key| key.certificate.as_ref()).map(|certificate| certificate.text.clone()),
        })
    }

    /// The key in the vault with this fingerprint (`SHA256:…`): ID and name.
    pub fn key_by_fingerprint(&self, fingerprint: &str) -> Option<(&str, &str)> {
        self.keys.iter().find(|(_, key)| key.fingerprint == fingerprint).map(|(id, key)| (id.as_str(), key.name.as_str()))
    }

    /// Creates hosts from machines of a connection and links them, all or none. The hosts live in the
    /// personal vault, like the connection; a group from a shared vault is therefore rejected.
    /// Machines that already have a host stay as they are. Returns the IDs of the new hosts.
    pub fn add_proxmox_hosts(&mut self, connection: &str, guests: Vec<GuestHost>, group: Option<&str>) -> Result<Vec<String>> {
        if !self.proxmox.contains_key(connection) {
            return Err(DirError::NotFound);
        }
        let personal = self.vault.personal()?;
        match group {
            Some(group) if !self.groups.contains_key(group) => return invalid(Invalid::GroupMissing),
            Some(group) if self.home(group, personal) != personal => return invalid(Invalid::OtherVault),
            _ => {}
        }
        let identity = self.proxmox.get(connection).and_then(|p| p.identity.clone()).filter(|id| self.identities.contains_key(id));
        let previous = self.target.take();
        let outcome = self.batch(|dir| {
            let mut made = Vec::new();
            for guest in guests {
                if dir.proxmox_host(connection, guest.vmid).is_some() {
                    continue;
                }
                if !model::GUEST_KINDS.contains(&guest.kind.as_str()) || !is_safe_token(&guest.node, 64) {
                    return invalid(Invalid::GuestInvalid);
                }
                let address = guest.address.clone().unwrap_or_else(|| guest.name.clone());
                // If Cloud-Init names a key from the vault, Cloud-Init applies. Otherwise the connection's identity
                // applies as a whole, and without one only the user Proxmox names.
                let own = match (guest.key.filter(|key| dir.keys.contains_key(key)), &identity) {
                    (Some(key), _) => Fields { user: guest.user, key: Some(key), ..Fields::default() },
                    (None, Some(identity)) => Fields { identity: Some(identity.clone()), ..Fields::default() },
                    (None, None) => Fields { user: guest.user, ..Fields::default() },
                };
                let input = HostInput { id: None, name: guest.name, address, protocol: None, serial: None, ftp: None, group: group.map(str::to_string), color: None, os: guest.os, own, password: None, proxy_password: None };
                let id = dir.save_host(input)?;
                let mut host = dir.hosts.get(&id).ok_or(DirError::NotFound)?.clone();
                host.proxmox = Some(ProxmoxLink { connection: connection.to_string(), node: guest.node, vmid: guest.vmid, kind: guest.kind, name: Some(host.name.clone()), address: Some(host.address.clone()), extra: Map::new() });
                dir.put(Some(&id), &Payload::Host(host))?;
                made.push(id);
            }
            Ok(made)
        });
        self.target = previous;
        outcome
    }

    /// Unlinks a host from its machine. The host stays as it is.
    pub fn unlink_proxmox(&mut self, host_id: &str) -> Result<()> {
        let mut host = self.hosts.get(host_id).ok_or(DirError::NotFound)?.clone();
        if host.proxmox.take().is_some() {
            self.put(Some(host_id), &Payload::Host(host))?;
            self.reload()?;
        }
        Ok(())
    }

    /// Updates a connection's hosts: if a machine's name or address changed in Proxmox,
    /// its host gets the new value, but only if it still carries the one Glowport last
    /// gave it. What the user changed on the host stays. A machine that moved to another node
    /// is recognised by its number. Only what really changes is written; returns
    /// whether that was the case.
    pub fn follow_proxmox(&mut self, connection: &str, seen: &[GuestSeen]) -> Result<bool> {
        let mut changes: Vec<(String, Host)> = Vec::new();
        for (id, host) in &self.hosts {
            let Some(link) = self.link_of(id, host).filter(|link| link.connection == connection) else { continue };
            let Some(guest) = seen.iter().find(|guest| guest.vmid == link.vmid) else { continue };
            let mut next = host.clone();
            let mut new_link = link.clone();
            if is_safe_token(&guest.node, 64) {
                new_link.node = guest.node.clone();
            }
            if let (true, Ok(name)) = (link.name.as_deref() == Some(host.name.as_str()), clean_name(&guest.name)) {
                (next.name, new_link.name) = (name.clone(), Some(name));
            }
            if let (true, Some(address)) = (link.address.as_deref() == Some(host.address.as_str()), guest.address.as_deref().filter(|address| is_safe_token(address, 255))) {
                (next.address, new_link.address) = (address.to_string(), Some(address.to_string()));
            }
            next.proxmox = Some(new_link);
            if next != *host && self.role_of(id).may_write() {
                changes.push((id.clone(), next));
            }
        }
        if changes.is_empty() {
            return Ok(false);
        }
        self.atomically(|dir| {
            for (id, host) in changes {
                dir.put(Some(&id), &Payload::Host(host))?;
            }
            Ok(())
        })?;
        Ok(true)
    }

    pub fn save_host(&mut self, input: HostInput) -> Result<String> {
        let existing = match &input.id {
            Some(id) => Some(self.hosts.get(id).ok_or(DirError::NotFound)?.clone()),
            None => None,
        };
        let name = clean_name(&input.name)?;
        let address = input.address.trim().to_string();
        if address.is_empty() {
            return invalid(Invalid::AddressRequired);
        }
        if !is_safe_token(&address, 255) {
            return invalid(Invalid::AddressInvalid);
        }
        if input.group.as_deref().is_some_and(|g| !self.groups.contains_key(g)) {
            return invalid(Invalid::GroupMissing);
        }
        // Without a value the protocol stays, even one only a newer version knows.
        let protocol = match input.protocol {
            Some(protocol) if model::PROTOCOLS.contains(&protocol.as_str()) => protocol,
            Some(_) => return invalid(Invalid::ProtocolInvalid),
            None => existing.as_ref().map_or_else(|| model::PROTOCOL_SSH.into(), |h| h.protocol.clone()),
        };
        let ssh = protocol == model::PROTOCOL_SSH;
        // Whoever is a jump host for others or carries port rules must stay on SSH.
        if let (false, Some(id)) = (ssh, input.id.as_deref()) {
            let jumped = self.hosts.iter().any(|(other, h)| other != id && h.own.jump.as_deref() == Some(id)) || self.groups.values().any(|g| g.defs.jump.as_deref() == Some(id));
            if jumped || self.forwards.values().any(|rule| rule.host == id) {
                return invalid(Invalid::ProtocolInUse);
            }
        }
        let serial = if protocol == model::PROTOCOL_SERIAL {
            let line = input.serial.or(existing.as_ref().and_then(|h| h.serial)).ok_or(DirError::Invalid(Invalid::SerialRequired))?;
            if !line.baud_valid() {
                return invalid(Invalid::BaudInvalid);
            }
            if !line.frame_valid() {
                return invalid(Invalid::SerialInvalid);
            }
            Some(line)
        } else {
            None
        };
        let ftp = if protocol == model::PROTOCOL_FTP {
            let mut ftp = input.ftp.or(existing.as_ref().and_then(|h| h.ftp.clone())).unwrap_or(Ftp { security: FtpSecurity::Explicit, anonymous: false, dir: None, plain_ok: false });
            ftp.dir = ftp.dir.map(|dir| dir.trim().to_string()).filter(|dir| !dir.is_empty());
            if ftp.dir.as_deref().is_some_and(|dir| dir.len() > 1024 || dir.chars().any(char::is_control)) {
                return invalid(Invalid::AddressInvalid);
            }
            // Switching off the question only applies to an unencrypted connection.
            ftp.plain_ok = ftp.plain_ok && ftp.security == FtpSecurity::None;
            Some(ftp)
        } else {
            None
        };
        let own = self.clean_fields(input.own, input.id.as_deref())?;
        // What does not belong to the protocol is not saved: it would never apply and still sit in the vault.
        let own = match protocol.as_str() {
            model::PROTOCOL_TELNET => Fields { user: own.user, port: own.port, reconnect: own.reconnect, timeout: own.timeout, term: own.term, charset: own.charset, scheme: own.scheme, ..Fields::default() },
            model::PROTOCOL_SERIAL => Fields { reconnect: own.reconnect, charset: own.charset, scheme: own.scheme, ..Fields::default() },
            // With anonymous sign-in there is neither user nor identity; with an identity no user of its own.
            model::PROTOCOL_FTP => {
                let anonymous = ftp.as_ref().is_some_and(|ftp| ftp.anonymous);
                let identity = own.identity.filter(|id| !anonymous && !id.is_empty());
                Fields { user: own.user.filter(|_| !anonymous && identity.is_none()), port: own.port, identity, ..Fields::default() }
            }
            _ => own,
        };
        // Passwords exist for SSH and FTP. Over Telnet they would travel in plain text, and a serial line knows none.
        // (Unencrypted FTP also sends them in plain text; the interface warns about that, and the user chose it.)
        let keeps_password = ssh || (protocol == model::PROTOCOL_FTP && own.user.is_some());
        let password = match input.password {
            None => existing.as_ref().and_then(|h| h.password.clone()),
            Some(new) => new.filter(|p| !p.expose().is_empty()),
        }
        .filter(|_| keeps_password);
        // Without a proxy of its own there is no password for it either.
        let proxy_password = match input.proxy_password {
            None => existing.as_ref().and_then(|h| h.proxy_password.clone()),
            Some(new) => new.filter(|p| !p.expose().is_empty()),
        }
        .filter(|_| own.proxy.as_deref().is_some_and(|p| !p.is_empty()));
        let host = Host {
            v: existing.as_ref().map_or(1, |h| h.v),
            name,
            address,
            group: input.group,
            protocol,
            serial,
            ftp,
            color: clean_color(input.color)?,
            os: input.os.map(|o| o.trim().to_string()).filter(|o| !o.is_empty() && o.len() <= 16),
            own,
            password,
            proxy_password,
            // The Proxmox link stays. A name or address now set by hand
            // differs from what the link records and is therefore no longer updated.
            proxmox: existing.as_ref().and_then(|h| h.proxmox.clone()),
            extra: existing.map(|h| h.extra).unwrap_or_else(Map::new),
        };
        let id = self.put(input.id.as_deref(), &Payload::Host(host))?;
        self.reload()?;
        Ok(id)
    }

    pub fn duplicate_host(&mut self, id: &str, name: &str) -> Result<String> {
        let mut copy = self.hosts.get(id).ok_or(DirError::NotFound)?.clone();
        copy.name = clean_name(name)?;
        // The original belongs to a Proxmox machine, not the copy.
        copy.proxmox = None;
        // The copy lives in the same vault as the original.
        let home = hex(&self.home(id, self.vault.personal()?));
        let id = self.in_vault(Some(&home), |dir| dir.put(None, &Payload::Host(copy)))?;
        self.reload()?;
        Ok(id)
    }

    /// Moves a host into another vault. It is created anew there (without a group) and disappears here.
    ///
    /// A shared vault only refers within itself. If an identity or key from another vault is attached
    /// to the host, `carry` brings them along as copies, otherwise the reference is dropped; a jump host from
    /// elsewhere is always dropped. Port rules, workspaces and jump references of others follow the host
    /// as far as they may refer there. Returns the new ID.
    pub fn move_host(&mut self, id: &str, vault: &str, carry: bool) -> Result<String> {
        let target = parse_id(vault)?;
        let personal = self.vault.personal()?;
        let info = self.vault.vaults()?.into_iter().find(|info| info.id == target).ok_or(DirError::NotFound)?;
        let host = self.hosts.get(id).ok_or(DirError::NotFound)?.clone();
        if self.home(id, personal) == target {
            return Ok(id.to_string());
        }
        if !info.role.may_write() || !self.role_of(id).may_write() {
            return Err(VaultError::ReadOnly.into());
        }
        let mut moved = String::new();
        self.atomically(|dir| {
            let previous = dir.target.replace(target);
            let outcome = dir.move_into(id, host, target, personal, carry);
            dir.target = previous;
            moved = outcome?;
            Ok(())
        })?;
        Ok(moved)
    }

    /// May an entry in the target vault refer to `id`? The personal one may refer to anything.
    fn reachable(&self, id: &str, target: Id, personal: Id) -> bool {
        id.is_empty() || target == personal || self.home(id, personal) == target
    }

    fn move_into(&mut self, old: &str, mut host: Host, target: Id, personal: Id, carry: bool) -> Result<String> {
        host.group = None;
        // Proxmox connections live in the personal vault; the other members would not have them.
        if target != personal {
            host.proxmox = None;
        }
        if host.own.jump.as_deref().is_some_and(|jump| !self.reachable(jump, target, personal)) {
            host.own.jump = None;
        }
        if let Some(identity_id) = host.own.identity.clone().filter(|identity| !self.reachable(identity, target, personal)) {
            host.own.identity = match (carry, self.identities.get(&identity_id).cloned()) {
                (true, Some(mut identity)) => {
                    if let Some(key_id) = identity.key.clone().filter(|key| !self.reachable(key, target, personal)) {
                        identity.key = match self.keys.get(&key_id).cloned() {
                            Some(key) => Some(self.put(None, &Payload::Key(key))?),
                            None => None,
                        };
                    }
                    Some(self.put(None, &Payload::Identity(identity))?)
                }
                _ => None,
            };
        }
        if let Some(key_id) = host.own.key.clone().filter(|key| !self.reachable(key, target, personal)) {
            host.own.key = match (carry, self.keys.get(&key_id).cloned()) {
                (true, Some(key)) => Some(self.put(None, &Payload::Key(key))?),
                _ => None,
            };
        }
        let new = self.put(None, &Payload::Host(host))?;

        // Whoever referred to the host follows it, as far as it may refer there.
        let follows = |dir: &Self, id: &str| {
            let home = dir.home(id, personal);
            home == personal || home == target
        };
        let rules: Vec<(String, Forward)> = self.forwards.iter().filter(|(_, rule)| rule.host == old).map(|(id, rule)| (id.clone(), rule.clone())).collect();
        for (id, mut rule) in rules {
            if follows(self, &id) {
                rule.host = new.clone();
                self.put(Some(&id), &Payload::Forward(rule))?;
            } else {
                self.vault.delete(&parse_id(&id)?)?;
            }
        }
        let workspaces: Vec<(String, Workspace)> = self.workspaces.iter().filter(|(_, w)| w.layout.hosts().contains(&old)).map(|(id, w)| (id.clone(), w.clone())).collect();
        for (id, mut workspace) in workspaces {
            // IDs are 32 hex characters and appear in the structure only as IDs.
            let layout = serde_json::to_string(&workspace.layout).expect("Aufbau lässt sich immer schreiben").replace(old, &new);
            workspace.layout = serde_json::from_str(&layout).expect("derselbe Aufbau mit anderer Kennung");
            self.put(Some(&id), &Payload::Workspace(workspace))?;
        }
        let jump_to = |fields: &Fields| fields.jump.as_deref() == Some(old);
        let hosts: Vec<(String, Host)> = self.hosts.iter().filter(|(id, h)| id.as_str() != old && jump_to(&h.own)).map(|(id, h)| (id.clone(), h.clone())).collect();
        for (id, mut other) in hosts {
            other.own.jump = follows(self, &id).then(|| new.clone());
            self.put(Some(&id), &Payload::Host(other))?;
        }
        let groups: Vec<(String, Group)> = self.groups.iter().filter(|(_, g)| jump_to(&g.defs)).map(|(id, g)| (id.clone(), g.clone())).collect();
        for (id, mut group) in groups {
            group.defs.jump = follows(self, &id).then(|| new.clone());
            self.put(Some(&id), &Payload::Group(group))?;
        }
        self.vault.delete(&parse_id(old)?)?;
        Ok(new)
    }

    /// Removes hosts and drops references to them as jump hosts. Workspaces lose their panes;
    /// one without panes disappears. Port rules run through exactly one host and disappear with it.
    /// Runs inside a batch change.
    fn remove_hosts(&mut self, ids: &[String]) -> Result<()> {
        let rules: Vec<String> = self.forwards.iter().filter(|(_, rule)| ids.contains(&rule.host)).map(|(id, _)| id.clone()).collect();
        for id in rules {
            self.vault.delete(&parse_id(&id)?)?;
        }
        let touched: Vec<(String, Workspace)> = self.workspaces.iter().filter(|(_, w)| w.layout.hosts().iter().any(|h| ids.iter().any(|id| id == h))).map(|(i, w)| (i.clone(), w.clone())).collect();
        for (id, mut workspace) in touched {
            match workspace.layout.retain(&|host| !ids.iter().any(|id| id == host)) {
                Some(layout) => {
                    workspace.multi &= layout.panes() > 1;
                    workspace.layout = layout;
                    self.put(Some(&id), &Payload::Workspace(workspace))?;
                }
                None => self.vault.delete(&parse_id(&id)?)?,
            }
        }
        let points_at = |fields: &Fields| fields.jump.as_ref().is_some_and(|j| ids.contains(j));
        let hosts: Vec<(String, Host)> = self.hosts.iter().filter(|(id, h)| !ids.contains(*id) && points_at(&h.own)).map(|(i, h)| (i.clone(), h.clone())).collect();
        let groups: Vec<(String, Group)> = self.groups.iter().filter(|(_, g)| points_at(&g.defs)).map(|(i, g)| (i.clone(), g.clone())).collect();
        for (id, mut host) in hosts {
            host.own.jump = None;
            self.put(Some(&id), &Payload::Host(host))?;
        }
        for (id, mut group) in groups {
            group.defs.jump = None;
            self.put(Some(&id), &Payload::Group(group))?;
        }
        for id in ids {
            self.vault.delete(&parse_id(id)?)?;
        }
        Ok(())
    }

    /// Runs several writes as one and reads again afterwards in any case.
    fn atomically(&mut self, work: impl FnOnce(&mut Self) -> Result<()>) -> Result<()> {
        self.vault.begin()?;
        let outcome = work(self);
        let ended = self.vault.end(outcome.is_ok());
        self.reload()?;
        outcome?;
        Ok(ended?)
    }

    pub fn delete_host(&mut self, id: &str) -> Result<()> {
        if !self.hosts.contains_key(id) {
            return Err(DirError::NotFound);
        }
        self.atomically(|dir| dir.remove_hosts(&[id.to_string()]))
    }

    fn descendants(&self, group: &str) -> Vec<String> {
        let mut found = vec![group.to_string()];
        let mut index = 0;
        while index < found.len() {
            let parent = found[index].clone();
            let children: Vec<String> =
                self.groups.iter().filter(|(id, g)| g.parent.as_deref() == Some(parent.as_str()) && !found.contains(*id)).map(|(id, _)| id.clone()).collect();
            found.extend(children);
            index += 1;
        }
        found
    }

    pub fn save_group(&mut self, input: GroupInput) -> Result<String> {
        let existing = match &input.id {
            Some(id) => Some(self.groups.get(id).ok_or(DirError::NotFound)?.clone()),
            None => None,
        };
        let name = clean_name(&input.name)?;
        if let Some(parent) = input.parent.as_deref() {
            if !self.groups.contains_key(parent) {
                return invalid(Invalid::GroupMissing);
            }
            // A group must not move into itself or into one of its subgroups.
            if input.id.as_deref().is_some_and(|id| self.descendants(id).iter().any(|d| d == parent)) {
                return invalid(Invalid::GroupCycle);
            }
        }
        let defs = self.clean_fields(input.defs, None)?;
        let proxy_password = match input.proxy_password {
            None => existing.as_ref().and_then(|g| g.proxy_password.clone()),
            Some(new) => new.filter(|p| !p.expose().is_empty()),
        }
        .filter(|_| defs.proxy.as_deref().is_some_and(|p| !p.is_empty()));
        let group = Group {
            v: existing.as_ref().map_or(1, |g| g.v),
            name,
            parent: input.parent,
            color: clean_color(input.color)?,
            defs,
            proxy_password,
            extra: existing.map(|g| g.extra).unwrap_or_else(Map::new),
        };
        let id = self.put(input.id.as_deref(), &Payload::Group(group))?;
        self.reload()?;
        Ok(id)
    }

    /// Rewrites all hosts and groups whose inheritable values `change` alters. Runs inside a batch change.
    fn rewrite_fields(&mut self, change: impl Fn(&mut Fields) -> bool) -> Result<()> {
        let hosts: Vec<(String, Host)> = self.hosts.iter().map(|(id, h)| (id.clone(), h.clone())).filter_map(|(id, mut h)| change(&mut h.own).then_some((id, h))).collect();
        let groups: Vec<(String, Group)> = self.groups.iter().map(|(id, g)| (id.clone(), g.clone())).filter_map(|(id, mut g)| change(&mut g.defs).then_some((id, g))).collect();
        for (id, host) in hosts {
            self.put(Some(&id), &Payload::Host(host))?;
        }
        for (id, group) in groups {
            self.put(Some(&id), &Payload::Group(group))?;
        }
        Ok(())
    }

    /// Stores a finished key and returns its ID.
    pub fn add_key(&mut self, key: NewKey) -> Result<String> {
        let record = Key {
            v: 1,
            name: clean_name(&key.name)?,
            kind: key.kind,
            bits: key.bits,
            fingerprint: key.fingerprint,
            public: key_body(&key.public),
            private: key.private,
            origin: key.origin,
            added_at: now_ms(),
            certificate: None,
            extra: Map::new(),
        };
        let id = self.put(None, &Payload::Key(record))?;
        self.reload()?;
        Ok(id)
    }

    pub fn rename_key(&mut self, id: &str, name: &str) -> Result<()> {
        let mut key = self.keys.get(id).ok_or(DirError::NotFound)?.clone();
        key.name = clean_name(name)?;
        self.put(Some(id), &Payload::Key(key))?;
        self.reload()
    }

    /// Attaches a user certificate to the key or removes it. The caller checks that it belongs to the key.
    pub fn set_key_certificate(&mut self, id: &str, certificate: Option<KeyCertificate>) -> Result<()> {
        let mut key = self.keys.get(id).ok_or(DirError::NotFound)?.clone();
        key.certificate = certificate;
        self.put(Some(id), &Payload::Key(key))?;
        self.reload()
    }

    /// Public key as a line for `authorized_keys`, with the name as comment.
    pub fn key_public(&self, id: &str) -> Result<String> {
        let key = self.keys.get(id).ok_or(DirError::NotFound)?;
        Ok(format!("{} {}", key.public, key.name))
    }

    /// Name and private key in OpenSSH format. Leaves the core only when the user explicitly exports.
    pub fn key_private(&self, id: &str) -> Result<(String, Secret)> {
        let key = self.keys.get(id).ok_or(DirError::NotFound)?;
        Ok((key.name.clone(), key.private.clone()))
    }

    /// Deletes a key and drops the references from hosts, groups and identities.
    pub fn delete_key(&mut self, id: &str) -> Result<()> {
        if !self.keys.contains_key(id) {
            return Err(DirError::NotFound);
        }
        let id = id.to_string();
        self.atomically(|dir| {
            dir.rewrite_fields(|fields| fields.key.as_deref() == Some(id.as_str()) && fields.key.take().is_some())?;
            let identities: Vec<(String, Identity)> = dir.identities.iter().filter(|(_, i)| i.key.as_deref() == Some(id.as_str())).map(|(i, identity)| (i.clone(), identity.clone())).collect();
            for (identity_id, mut identity) in identities {
                identity.key = None;
                dir.put(Some(&identity_id), &Payload::Identity(identity))?;
            }
            Ok(dir.vault.delete(&parse_id(&id)?)?)
        })
    }

    pub fn save_identity(&mut self, input: IdentityInput) -> Result<String> {
        let existing = match &input.id {
            Some(id) => Some(self.identities.get(id).ok_or(DirError::NotFound)?.clone()),
            None => None,
        };
        let name = clean_name(&input.name)?;
        let user = input.user.trim().to_string();
        if user.is_empty() {
            return invalid(Invalid::UserRequired);
        }
        if !is_safe_token(&user, 64) {
            return invalid(Invalid::UserInvalid);
        }
        let key = input.key.filter(|id| !id.is_empty());
        if key.as_deref().is_some_and(|id| !self.keys.contains_key(id)) {
            return invalid(Invalid::KeyMissing);
        }
        let password = match input.password {
            None => existing.as_ref().and_then(|i| i.password.clone()),
            Some(new) => new.filter(|p| !p.expose().is_empty()),
        };
        let identity = Identity { v: existing.as_ref().map_or(1, |i| i.v), name, user, key, password, extra: existing.map(|i| i.extra).unwrap_or_else(Map::new) };
        let id = self.put(input.id.as_deref(), &Payload::Identity(identity))?;
        self.reload()?;
        Ok(id)
    }

    /// Deletes an identity and drops the references from hosts and groups.
    pub fn delete_identity(&mut self, id: &str) -> Result<()> {
        if !self.identities.contains_key(id) {
            return Err(DirError::NotFound);
        }
        let id = id.to_string();
        self.atomically(|dir| {
            dir.rewrite_fields(|fields| fields.identity.as_deref() == Some(id.as_str()) && fields.identity.take().is_some())?;
            // A Proxmox connection can also set it for its machines.
            let connections: Vec<(String, Proxmox)> = dir.proxmox.iter().filter(|(_, p)| p.identity.as_deref() == Some(id.as_str())).map(|(i, p)| (i.clone(), p.clone())).collect();
            for (connection, mut record) in connections {
                record.identity = None;
                dir.put(Some(&connection), &Payload::Proxmox(record))?;
            }
            Ok(dir.vault.delete(&parse_id(&id)?)?)
        })
    }

    /// Deletes a group. With `with_contents` together with everything inside, otherwise the content moves up a level.
    pub fn delete_group(&mut self, id: &str, with_contents: bool) -> Result<()> {
        let parent = self.groups.get(id).ok_or(DirError::NotFound)?.parent.clone();
        let id = id.to_string();
        self.atomically(|dir| {
            if with_contents {
                let groups = dir.descendants(&id);
                let hosts: Vec<String> = dir.hosts.iter().filter(|(_, h)| h.group.as_ref().is_some_and(|g| groups.contains(g))).map(|(i, _)| i.clone()).collect();
                dir.remove_hosts(&hosts)?;
                for group in &groups {
                    dir.vault.delete(&parse_id(group)?)?;
                }
                return Ok(());
            }
            let hosts: Vec<(String, Host)> = dir.hosts.iter().filter(|(_, h)| h.group.as_deref() == Some(id.as_str())).map(|(i, h)| (i.clone(), h.clone())).collect();
            let groups: Vec<(String, Group)> = dir.groups.iter().filter(|(_, g)| g.parent.as_deref() == Some(id.as_str())).map(|(i, g)| (i.clone(), g.clone())).collect();
            for (host_id, mut host) in hosts {
                host.group = parent.clone();
                dir.put(Some(&host_id), &Payload::Host(host))?;
            }
            for (group_id, mut group) in groups {
                group.parent = parent.clone();
                dir.put(Some(&group_id), &Payload::Group(group))?;
            }
            Ok(dir.vault.delete(&parse_id(&id)?)?)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto::KdfParams, model::Source};
    use std::path::PathBuf;

    const FAST: KdfParams = KdfParams { memory_kib: 64, passes: 1, lanes: 1 };

    struct Temp(PathBuf);
    impl Temp {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!("glowport-dir-{}-{name}.db", std::process::id()));
            let _ = std::fs::remove_file(&path);
            Self(path)
        }
        fn directory(&self) -> Directory {
            Directory::load(Vault::create(&self.0, "richtig", FAST).unwrap()).unwrap()
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn host(name: &str, group: Option<&str>) -> HostInput {
        HostInput { id: None, name: name.into(), address: "10.0.0.1".into(), protocol: None, serial: None, ftp: None, group: group.map(Into::into), color: None, os: None, own: Fields::default(), password: None, proxy_password: None }
    }

    fn group(name: &str, parent: Option<&str>) -> GroupInput {
        GroupInput { id: None, name: name.into(), parent: parent.map(Into::into), color: None, defs: Fields::default(), proxy_password: None }
    }

    fn reason<T: std::fmt::Debug>(result: Result<T>) -> Invalid {
        match result {
            Err(DirError::Invalid(reason)) => reason,
            other => panic!("Ablehnung erwartet, bekommen: {other:?}"),
        }
    }

    /// Writes into the vault past the directory, the way a sync brings in records from other devices.
    fn raw(dir: &mut Directory, id: Option<&str>, value: serde_json::Value) -> String {
        let id = dir.vault.put(id.map(|id| parse_id(id).unwrap()), &serde_json::to_vec(&value).unwrap()).unwrap();
        dir.reload().unwrap();
        hex(&id)
    }

    #[test]
    fn a_later_snapshot_carries_the_higher_number() {
        let temp = Temp::new("stamp");
        let dir = temp.directory();
        let (first, second) = (dir.snapshot(), dir.snapshot());
        assert!(first.seq.0 > 0 && second.seq.0 > first.seq.0);
        // The number says which state is the newer one, not whether two states show the same.
        assert_eq!(first, second);
        // Another vault in the same program keeps counting too: after locking and unlocking the same sequence applies.
        let other = Temp::new("stamp-other");
        assert!(other.directory().snapshot().seq.0 > second.seq.0);
    }

    #[test]
    fn contradictions_from_a_sync_are_defused_when_reading() {
        let temp = Temp::new("defuse");
        let mut dir = temp.directory();
        let a = dir.save_group(GroupInput { defs: Fields { user: Some("von-a".into()), ..Fields::default() }, ..group("A", None) }).unwrap();
        let b = dir.save_group(group("B", Some(&a))).unwrap();
        let c = dir.save_group(group("C", Some(&b))).unwrap();
        let web = dir.save_host(host("web", Some(&c))).unwrap();
        assert_eq!(reason(dir.save_group(GroupInput { id: Some(a.clone()), ..group("A", Some(&c)) })), Invalid::GroupCycle, "ein Gerät allein darf das nicht");

        // Another device put A under C while here B was under A: A → C → B → A.
        raw(&mut dir, Some(&a), serde_json::json!({"t": "group", "v": 1, "name": "A", "parent": c, "defs": {"user": "von-a"}}));
        let snapshot = dir.snapshot();
        let parent = |id: &str| snapshot.groups.iter().find(|g| g.id == id).unwrap().parent.clone();
        let smallest = [&a, &b, &c].into_iter().min().unwrap();
        let roots: Vec<&String> = [&a, &b, &c].into_iter().filter(|id| parent(id).is_none()).collect();
        assert_eq!(roots, [smallest], "genau eine Gruppe öffnet den Kreis, überall dieselbe");
        // Inheritance ends there and does not go round in circles.
        assert!(dir.chain(Some(&c)).len() <= 3);
        assert!(dir.effective(&web, Reconnect::Auto).is_ok());

        // A group's parent and a host's group were deleted on another device.
        let orphan = raw(&mut dir, None, serde_json::json!({"t": "group", "v": 1, "name": "Waise", "parent": "00".repeat(16)}));
        let lost = raw(&mut dir, None, serde_json::json!({"t": "host", "v": 1, "name": "verloren", "address": "10.0.0.9", "group": "00".repeat(16)}));
        let snapshot = dir.snapshot();
        assert_eq!(snapshot.groups.iter().find(|g| g.id == orphan).unwrap().parent, None);
        assert_eq!(snapshot.hosts.iter().find(|h| h.id == lost).unwrap().group, None);
        assert!(dir.connect_info(&lost).is_ok());

        // Two devices assigned the same hotkey: it applies to the snippet with the smaller ID.
        let snippet = |name: &str| serde_json::json!({"t": "snippet", "v": 1, "name": name, "kind": "command", "command": "uptime", "hotkey": "Alt+1"});
        let (one, two) = (raw(&mut dir, None, snippet("eins")), raw(&mut dir, None, snippet("zwei")));
        let snapshot = dir.snapshot();
        let hotkey = |id: &str| snapshot.snippets.iter().find(|s| s.id == id).unwrap().hotkey.clone();
        let (first, second) = if one < two { (&one, &two) } else { (&two, &one) };
        assert_eq!((hotkey(first), hotkey(second)), (Some("Alt+1".to_string()), None));
    }

    #[test]
    fn hosts_and_groups_persist_and_inherit() {
        let temp = Temp::new("inherit");
        let mut dir = temp.directory();
        let prod = dir.save_group(GroupInput { defs: Fields { user: Some("deploy".into()), ..Fields::default() }, ..group("Produktiv", None) }).unwrap();
        let web = dir.save_group(GroupInput { defs: Fields { port: Some(2200), ..Fields::default() }, ..group("Web", Some(&prod)) }).unwrap();
        let id = dir.save_host(host("web-01", Some(&web))).unwrap();

        let effective = dir.effective(&id, Reconnect::Auto).unwrap();
        assert_eq!(dir.connect_info(&id).unwrap().user, "deploy");
        assert_eq!((effective.port.value, effective.port.source), (2200, Source::Group(web.clone())));

        // After locking and opening again everything is back.
        let mut vault = dir.into_vault();
        vault.lock();
        vault.unlock("richtig").unwrap();
        let dir = Directory::load(vault).unwrap();
        let snapshot = dir.snapshot();
        assert_eq!(snapshot.groups.iter().map(|g| g.name.as_str()).collect::<Vec<_>>(), ["Produktiv", "Web"]);
        assert_eq!((snapshot.hosts[0].name.as_str(), snapshot.hosts[0].group.as_deref(), snapshot.damaged), ("web-01", Some(web.as_str()), 0));
    }

    #[test]
    fn input_is_validated() {
        let temp = Temp::new("validate");
        let mut dir = temp.directory();
        assert_eq!(reason(dir.save_host(host("  ", None))), Invalid::NameRequired);
        assert_eq!(reason(dir.save_host(host(&"x".repeat(81), None))), Invalid::NameTooLong);
        assert_eq!(reason(dir.save_host(HostInput { address: " ".into(), ..host("a", None) })), Invalid::AddressRequired);
        for bad in ["-oProxyCommand=x", "10.0.0.1 extra", "a\u{7}b"] {
            assert_eq!(reason(dir.save_host(HostInput { address: bad.into(), ..host("a", None) })), Invalid::AddressInvalid, "{bad}");
        }
        let own = |user: &str| Fields { user: Some(user.into()), ..Fields::default() };
        assert_eq!(reason(dir.save_host(HostInput { own: own("-root"), ..host("a", None) })), Invalid::UserInvalid);
        assert_eq!(reason(dir.save_host(HostInput { own: own("ro ot"), ..host("a", None) })), Invalid::UserInvalid);
        assert_eq!(reason(dir.save_host(HostInput { own: Fields { port: Some(0), ..Fields::default() }, ..host("a", None) })), Invalid::PortInvalid);
        assert_eq!(reason(dir.save_host(HostInput { color: Some("rot".into()), ..host("a", None) })), Invalid::ColorInvalid);
        assert_eq!(reason(dir.save_host(host("a", Some("00000000000000000000000000000000")))), Invalid::GroupMissing);
        assert_eq!(reason(dir.save_host(HostInput { own: Fields { jump: Some("ffffffffffffffffffffffffffffffff".into()), ..Fields::default() }, ..host("a", None) })), Invalid::JumpMissing);
        assert!(dir.snapshot().hosts.is_empty(), "abgelehnte Eingaben dürfen nichts hinterlassen");

        // Whitespace is removed, empty values count as “not set”.
        let id = dir.save_host(HostInput { address: " example.org ".into(), color: Some("#ff2e63".into()), own: own("  "), ..host("  web  ", None) }).unwrap();
        let snapshot = dir.snapshot();
        let saved = &snapshot.hosts[0];
        assert_eq!((saved.name.as_str(), saved.address.as_str(), saved.color.as_deref(), &saved.own.user), ("web", "example.org", Some("#FF2E63"), &None));
        assert_eq!(reason(dir.save_host(HostInput { id: Some(id.clone()), own: Fields { jump: Some(id), ..Fields::default() }, ..host("web", None) })), Invalid::JumpSelf);
    }

    #[test]
    fn password_is_kept_cleared_or_replaced_and_never_shown() {
        let temp = Temp::new("password");
        let mut dir = temp.directory();
        let secret = |s: &str| Some(Some(Secret::new(s.into())));
        let id = dir.save_host(HostInput { password: secret("hunter2"), ..host("a", None) }).unwrap();
        assert!(dir.snapshot().hosts[0].has_password);
        assert!(!serde_json::to_string(&dir.snapshot()).unwrap().contains("hunter2"));

        let edit = |password| HostInput { id: Some(id.clone()), password, ..host("b", None) };
        dir.save_host(edit(None)).unwrap();
        assert_eq!(dir.hosts[&id].password.as_ref().map(Secret::expose), Some("hunter2"), "fehlendes Feld ändert nichts");
        dir.save_host(edit(secret("neu"))).unwrap();
        assert_eq!(dir.hosts[&id].password.as_ref().map(Secret::expose), Some("neu"));
        dir.save_host(edit(Some(None))).unwrap();
        assert!(!dir.snapshot().hosts[0].has_password);

        // This is how it comes from the interface: missing, null or text.
        let parse = |json: &str| serde_json::from_str::<HostInput>(json).unwrap().password;
        assert_eq!(parse(r#"{"name":"a","address":"b"}"#), None);
        assert_eq!(parse(r#"{"name":"a","address":"b","password":null}"#), Some(None));
        assert_eq!(parse(r#"{"name":"a","address":"b","password":"x"}"#).unwrap().unwrap().expose(), "x");
    }

    #[test]
    fn groups_cannot_form_a_cycle() {
        let temp = Temp::new("cycle");
        let mut dir = temp.directory();
        let a = dir.save_group(group("A", None)).unwrap();
        let b = dir.save_group(group("B", Some(&a))).unwrap();
        let c = dir.save_group(group("C", Some(&b))).unwrap();
        let moved = |id: &str, parent: &str| GroupInput { id: Some(id.into()), ..group("X", Some(parent)) };
        assert_eq!(reason(dir.save_group(moved(&a, &a))), Invalid::GroupCycle);
        assert_eq!(reason(dir.save_group(moved(&a, &c))), Invalid::GroupCycle);
        assert_eq!(reason(dir.save_group(group("D", Some("00000000000000000000000000000000")))), Invalid::GroupMissing);
        dir.save_group(moved(&c, &a)).unwrap();
        assert_eq!(dir.groups[&c].parent.as_deref(), Some(a.as_str()));
    }

    #[test]
    fn deleting_a_group_dissolves_or_removes_contents() {
        let temp = Temp::new("delgroup");
        let mut dir = temp.directory();
        let top = dir.save_group(group("Top", None)).unwrap();
        let mid = dir.save_group(group("Mitte", Some(&top))).unwrap();
        let low = dir.save_group(group("Unten", Some(&mid))).unwrap();
        let in_mid = dir.save_host(host("in-mitte", Some(&mid))).unwrap();
        let in_low = dir.save_host(host("in-unten", Some(&low))).unwrap();
        let outside = dir.save_host(HostInput { own: Fields { jump: Some(in_low.clone()), ..Fields::default() }, ..host("draussen", None) }).unwrap();

        // Dissolve: the content moves up one level.
        dir.delete_group(&mid, false).unwrap();
        assert!(!dir.groups.contains_key(&mid));
        assert_eq!(dir.groups[&low].parent.as_deref(), Some(top.as_str()));
        assert_eq!(dir.hosts[&in_mid].group.as_deref(), Some(top.as_str()));

        // Delete with content: subgroups and hosts disappear, references to them are dropped.
        dir.delete_group(&top, true).unwrap();
        assert!(dir.groups.is_empty());
        assert_eq!(dir.hosts.keys().collect::<Vec<_>>(), [&outside]);
        assert_eq!(dir.hosts[&outside].own.jump, None);
        assert!(matches!(dir.delete_group(&top, true), Err(DirError::NotFound)));
        let _ = in_mid;
    }

    #[test]
    fn deleting_and_duplicating_hosts() {
        let temp = Temp::new("delhost");
        let mut dir = temp.directory();
        let bastion = dir.save_host(HostInput { password: Some(Some(Secret::new("pw".into()))), ..host("bastion", None) }).unwrap();
        let grp = dir.save_group(GroupInput { defs: Fields { jump: Some(bastion.clone()), ..Fields::default() }, ..group("G", None) }).unwrap();

        let copy = dir.duplicate_host(&bastion, "bastion (Kopie)").unwrap();
        assert_ne!(copy, bastion);
        assert_eq!((dir.hosts[&copy].name.as_str(), dir.hosts[&copy].password.is_some()), ("bastion (Kopie)", true));

        dir.delete_host(&bastion).unwrap();
        assert_eq!(dir.groups[&grp].defs.jump, None, "Verweis der Gruppe gelöst");
        assert!(matches!(dir.delete_host(&bastion), Err(DirError::NotFound)));
        assert!(matches!(dir.delete_host("kein-hex"), Err(DirError::NotFound)));
        assert_eq!(dir.snapshot().hosts.len(), 1);
    }

    #[test]
    fn host_keys_are_trusted_recognised_and_replaced() {
        let temp = Temp::new("knownhosts");
        let mut dir = temp.directory();
        let (key_a, key_b) = ("ssh-ed25519 AAAAschluesselA", "ssh-ed25519 AAAAschluesselB");
        assert_eq!(dir.judge_host_key("Server.Example", 22, key_a), Verdict::Unknown);

        dir.trust_host_key("Server.Example", 22, "ssh-ed25519", "SHA256:aaa", &format!("{key_a} kommentar")).unwrap();
        assert_eq!(dir.judge_host_key("server.example", 22, key_a), Verdict::Trusted, "Groß- und Kleinschreibung der Adresse zählt nicht");
        assert_eq!(dir.judge_host_key("server.example", 22, &format!("{key_a} anderer-kommentar")), Verdict::Trusted);
        assert_eq!(dir.judge_host_key("server.example", 2222, key_a), Verdict::Unknown, "ein anderer Port ist ein anderer Dienst");
        assert_eq!(dir.judge_host_key("server.example", 22, key_b), Verdict::Changed { known: vec!["SHA256:aaa".into()] });

        // If the user trusts the new key, it replaces the old one.
        dir.trust_host_key("server.example", 22, "ssh-ed25519", "SHA256:bbb", key_b).unwrap();
        assert_eq!(dir.judge_host_key("server.example", 22, key_b), Verdict::Trusted);
        assert_eq!(dir.judge_host_key("server.example", 22, key_a), Verdict::Changed { known: vec!["SHA256:bbb".into()] });
        let snapshot = dir.snapshot();
        assert_eq!(snapshot.known_hosts.len(), 1);
        assert_eq!((snapshot.known_hosts[0].host.as_str(), snapshot.known_hosts[0].fingerprint.as_str()), ("server.example", "SHA256:bbb"));
        assert!(snapshot.known_hosts[0].added_at > 0);

        // Survives locking and unlocking; deleting makes the server unknown again.
        let mut vault = dir.into_vault();
        vault.lock();
        vault.unlock("richtig").unwrap();
        let mut dir = Directory::load(vault).unwrap();
        assert_eq!(dir.judge_host_key("server.example", 22, key_b), Verdict::Trusted);
        let id = dir.snapshot().known_hosts[0].id.clone();
        dir.delete_known_host(&id).unwrap();
        assert_eq!(dir.judge_host_key("server.example", 22, key_b), Verdict::Unknown);
        assert!(matches!(dir.delete_known_host(&id), Err(DirError::NotFound)));
    }

    #[test]
    fn mosh_settings_are_checked_and_inherited() {
        let temp = Temp::new("mosh");
        let mut dir = temp.directory();
        let fine = |fields: Fields| HostInput { own: fields, ..host("x", None) };
        for bad in ["0", "70000", "60010:60001", "60001-60010", "abc", "1:2:3"] {
            assert_eq!(reason(dir.save_host(fine(Fields { mosh_port: Some(bad.into()), ..Fields::default() }))), Invalid::MoshPortInvalid, "{bad}");
        }
        for bad in ["mosh server", "mosh-server;id", "$(id)", "`id`", "a|b", "x>y"] {
            assert_eq!(reason(dir.save_host(fine(Fields { mosh_server: Some(bad.into()), ..Fields::default() }))), Invalid::MoshServerInvalid, "{bad}");
        }
        assert_eq!(reason(dir.save_host(fine(Fields { mosh_predict: Some("manchmal".into()), ..Fields::default() }))), Invalid::MoshPredictInvalid);

        // A group switches Mosh on; one host takes it over, another switches it off.
        let defs = Fields { mosh: Some(true), mosh_port: Some(" 60001:60010 ".into()), mosh_server: Some("~/.local/bin/mosh-server".into()), ..Fields::default() };
        let roaming = dir.save_group(GroupInput { defs, ..group("Unterwegs", None) }).unwrap();
        let laptop = dir.save_host(HostInput { own: Fields { mosh_predict: Some("always".into()), ..Fields::default() }, ..host("laptop", Some(&roaming)) }).unwrap();
        let plain = dir.save_host(HostInput { own: Fields { mosh: Some(false), ..Fields::default() }, ..host("plain", Some(&roaming)) }).unwrap();
        let info = dir.connect_info(&laptop).unwrap();
        assert_eq!(info.mosh, Some(MoshInfo { predict: "always".into(), port: Some("60001:60010".into()), server: Some("~/.local/bin/mosh-server".into()) }));
        assert_eq!(dir.connect_info(&plain).unwrap().mosh, None);
        let lone = dir.save_host(host("allein", None)).unwrap();
        assert_eq!(dir.connect_info(&lone).unwrap().mosh, None, "ohne Vorgabe kein Mosh");
    }

    #[test]
    fn connect_info_follows_inheritance_and_connecting_can_update_the_host() {
        let temp = Temp::new("connectinfo");
        let mut dir = temp.directory();
        let defs = Fields { user: Some("deploy".into()), port: Some(2200), key_file: Some("  C:\\Keys\\deploy  ".into()), ..Fields::default() };
        let group_id = dir.save_group(GroupInput { defs, ..group("Produktiv", None) }).unwrap();
        let id = dir.save_host(HostInput { address: "10.0.10.11".into(), ..host("web-01", Some(&group_id)) }).unwrap();

        let info = dir.connect_info(&id).unwrap();
        assert_eq!((info.name.as_str(), info.address.as_str(), info.port, info.user.as_str()), ("web-01", "10.0.10.11", 2200, "deploy"));
        assert_eq!((info.jump.as_deref(), info.startcmd.as_deref(), info.env.len()), (None, None, 0));
        assert_eq!((info.agent, info.agent_forward), (false, false), "ohne Vorgabe kein Agent");
        assert_eq!((info.proxy.is_none(), info.keepalive, info.timeout, info.term.as_str(), info.charset.as_str(), info.legacy), (true, 30, 15, "xterm-256color", "utf-8", false));

        // Fine-tuning and proxy: checked when saving, inherited like everything else, can be switched off on the host.
        let fine = |fields: Fields| HostInput { own: fields, ..host("x", None) };
        assert_eq!(reason(dir.save_host(fine(Fields { proxy: Some("ich:pw@proxy".into()), ..Fields::default() }))), Invalid::ProxyInvalid);
        assert_eq!(reason(dir.save_host(fine(Fields { keepalive: Some(4000), ..Fields::default() }))), Invalid::KeepaliveInvalid);
        assert_eq!(reason(dir.save_host(fine(Fields { timeout: Some(0), ..Fields::default() }))), Invalid::TimeoutInvalid);
        assert_eq!(reason(dir.save_host(fine(Fields { term: Some("xterm; rm".into()), ..Fields::default() }))), Invalid::TermInvalid);
        assert_eq!(reason(dir.save_host(fine(Fields { charset: Some("klingonisch".into()), ..Fields::default() }))), Invalid::CharsetInvalid);
        let old_gear = Fields { proxy: Some(" socks5://127.0.0.1:9050 ".into()), keepalive: Some(0), timeout: Some(60), term: Some("vt100".into()), charset: Some("ISO-8859-1".into()), legacy: Some(true), ..Fields::default() };
        let switches = dir.save_group(GroupInput { defs: old_gear, ..group("Switches", None) }).unwrap();
        let switch = dir.save_host(HostInput { own: Fields { proxy: Some(String::new()), ..Fields::default() }, ..host("sw-01", Some(&switches)) }).unwrap();
        let other = dir.save_host(host("sw-02", Some(&switches))).unwrap();
        let info = dir.connect_info(&other).unwrap();
        assert_eq!(info.proxy, Some(ProxySpec { kind: model::ProxyKind::Socks5, host: "127.0.0.1".into(), port: 9050, user: None }));
        assert_eq!((info.keepalive, info.timeout, info.term.as_str(), info.charset.as_str(), info.legacy), (0, 60, "vt100", "iso-8859-1", true));
        assert!(dir.connect_info(&switch).unwrap().proxy.is_none(), "„ausdrücklich keiner“ am Host");

        // Proxy with sign-in: the user is in the address, the password is stored as a secret where the proxy is defined.
        let secret = |text: &str| Some(Some(Secret::new(text.into())));
        let with_login = Fields { proxy: Some("http://ich@proxy.firma.test:3128".into()), ..Fields::default() };
        dir.save_group(GroupInput { id: Some(switches.clone()), defs: with_login.clone(), proxy_password: secret("gruppen-pw"), ..group("Switches", None) }).unwrap();
        let info = dir.connect_info(&other).unwrap();
        assert_eq!((info.proxy.as_ref().and_then(|p| p.user.as_deref()), info.proxy_password.as_ref().map(Secret::expose)), (Some("ich"), Some("gruppen-pw")));
        assert!(dir.connect_info(&switch).unwrap().proxy_password.is_none(), "ohne Proxy auch kein Passwort");
        let own_proxy = Fields { proxy: Some("socks5://anders@10.0.0.9".into()), ..Fields::default() };
        dir.save_host(HostInput { id: Some(other.clone()), own: own_proxy.clone(), proxy_password: secret("host-pw"), ..host("sw-02", Some(&switches)) }).unwrap();
        assert_eq!(dir.connect_info(&other).unwrap().proxy_password.as_ref().map(Secret::expose), Some("host-pw"), "der eigene Proxy bringt sein eigenes Passwort mit");
        let snapshot = dir.snapshot();
        assert!(snapshot.groups.iter().any(|g| g.has_proxy_password) && snapshot.hosts.iter().find(|h| h.id == other).unwrap().has_proxy_password);
        assert!(!serde_json::to_string(&snapshot).unwrap().contains("-pw"), "kein Passwort verlässt den Kern");
        // Without the field it stays, `null` removes it, and without a proxy of its own it is dropped.
        dir.save_host(HostInput { id: Some(other.clone()), own: own_proxy.clone(), ..host("sw-02", Some(&switches)) }).unwrap();
        assert!(dir.snapshot().hosts.iter().find(|h| h.id == other).unwrap().has_proxy_password);
        dir.save_host(HostInput { id: Some(other.clone()), own: own_proxy, proxy_password: Some(None), ..host("sw-02", Some(&switches)) }).unwrap();
        assert!(!dir.snapshot().hosts.iter().find(|h| h.id == other).unwrap().has_proxy_password);
        dir.save_group(GroupInput { id: Some(switches.clone()), defs: Fields::default(), ..group("Switches", None) }).unwrap();
        assert!(!dir.snapshot().groups.iter().any(|g| g.has_proxy_password));
        dir.delete_group(&switches, true).unwrap();

        // Jump host, startup command and environment come from group and host; the jump host has its own details.
        let bastion = dir.save_host(HostInput { address: "203.0.113.10".into(), own: Fields { jump: Some(String::new()), user: Some("sprung".into()), ..Fields::default() }, ..host("bastion", Some(&group_id)) }).unwrap();
        let defs = Fields { user: Some("deploy".into()), port: Some(2200), jump: Some(bastion.clone()), env: Some(" STUFE=prod ".into()), agent: Some(true), agent_forward: Some(true), ..Fields::default() };
        dir.save_group(GroupInput { id: Some(group_id.clone()), defs, ..group("Produktiv", None) }).unwrap();
        dir.save_host(HostInput { id: Some(id.clone()), address: "10.0.10.11".into(), own: Fields { startcmd: Some("cd /srv".into()), agent_forward: Some(false), ..Fields::default() }, ..host("web-01", Some(&group_id)) }).unwrap();
        let info = dir.connect_info(&id).unwrap();
        assert_eq!((info.agent, info.agent_forward), (true, false), "Agent von der Gruppe, Weiterreichen am Host abgeschaltet");
        assert_eq!((info.jump.as_deref(), info.startcmd.as_deref()), (Some(bastion.as_str()), Some("cd /srv")));
        assert_eq!(info.env, [("STUFE".to_string(), "prod".to_string())]);
        let hop = dir.connect_info(&bastion).unwrap();
        assert_eq!((hop.user.as_str(), hop.jump.as_deref()), ("sprung", None), "„ausdrücklich keiner“ am Sprung-Server selbst");
        assert_eq!(reason(dir.save_host(HostInput { own: Fields { env: Some("kaputt".into()), ..Fields::default() }, ..host("x", None) })), Invalid::EnvInvalid);
        dir.save_group(GroupInput { id: Some(group_id.clone()), defs: Fields { user: Some("deploy".into()), port: Some(2200), key_file: Some("  C:\\Keys\\deploy  ".into()), ..Fields::default() }, ..group("Produktiv", None) }).unwrap();
        let info = dir.connect_info(&id).unwrap();
        assert_eq!(info.key_file.as_deref(), Some("C:\\Keys\\deploy"), "Leerraum um den Pfad wird entfernt");
        assert!(info.password.is_none());
        assert!(matches!(dir.connect_info("00000000000000000000000000000000"), Err(DirError::NotFound)));

        dir.set_host_password(&id, Secret::new("neu-eingegeben".into())).unwrap();
        assert_eq!(dir.connect_info(&id).unwrap().password.as_ref().map(Secret::expose), Some("neu-eingegeben"));
        assert!(dir.set_host_os(&id, "Ub").unwrap());
        assert!(!dir.set_host_os(&id, "Ub").unwrap(), "gleiches System ist keine Änderung");
        let snapshot = dir.snapshot();
        let saved = snapshot.hosts.iter().find(|h| h.id == id).unwrap();
        assert_eq!((saved.os.as_deref(), saved.has_password), (Some("Ub"), true));
    }

    fn key(name: &str) -> NewKey {
        NewKey {
            name: name.into(),
            kind: KeyKind::Ed25519,
            bits: 256,
            fingerprint: format!("SHA256:{name}"),
            public: format!("ssh-ed25519 AAAA{name} kommentar aus der datei"),
            private: Secret::new(format!("-----BEGIN OPENSSH PRIVATE KEY-----{name}")),
            origin: KeyOrigin::Generated,
        }
    }

    fn identity(name: &str, user: &str, key: Option<&str>) -> IdentityInput {
        IdentityInput { id: None, name: name.into(), user: user.into(), key: key.map(Into::into), password: None }
    }

    #[test]
    fn keys_are_stored_without_showing_the_private_part() {
        let temp = Temp::new("keys");
        let mut dir = temp.directory();
        assert_eq!(reason(dir.add_key(key("  "))), Invalid::NameRequired);
        let id = dir.add_key(key("arbeit")).unwrap();
        dir.add_key(key("Alt")).unwrap();

        let snapshot = dir.snapshot();
        assert_eq!(snapshot.keys.iter().map(|k| k.name.as_str()).collect::<Vec<_>>(), ["Alt", "arbeit"]);
        let view = &snapshot.keys[1];
        assert_eq!((view.id.as_str(), view.kind, view.bits, view.origin), (id.as_str(), KeyKind::Ed25519, 256, KeyOrigin::Generated));
        assert_eq!(view.public_key, "ssh-ed25519 AAAAarbeit arbeit", "der Kommentar ist der Name, nicht der aus der Datei");
        assert!(view.added_at > 0);
        assert!(!serde_json::to_string(&snapshot).unwrap().contains("PRIVATE"), "der private Teil verlässt den Kern nicht");

        dir.rename_key(&id, " arbeit-2026 ").unwrap();
        assert_eq!(dir.key_public(&id).unwrap(), "ssh-ed25519 AAAAarbeit arbeit-2026");
        let (name, private) = dir.key_private(&id).unwrap();
        assert_eq!((name.as_str(), private.expose()), ("arbeit-2026", "-----BEGIN OPENSSH PRIVATE KEY-----arbeit"));
        assert!(matches!(dir.rename_key("00000000000000000000000000000000", "x"), Err(DirError::NotFound)));

        // After locking and opening again the key and its time are back.
        let added_at = dir.snapshot().keys[1].added_at;
        let mut vault = dir.into_vault();
        vault.lock();
        vault.unlock("richtig").unwrap();
        let dir = Directory::load(vault).unwrap();
        assert_eq!((dir.snapshot().keys[1].name.as_str(), dir.snapshot().keys[1].added_at), ("arbeit-2026", added_at));
    }

    #[test]
    fn identities_are_validated_and_keep_their_password() {
        let temp = Temp::new("identities");
        let mut dir = temp.directory();
        let key_id = dir.add_key(key("arbeit")).unwrap();
        assert_eq!(reason(dir.save_identity(identity("", "deploy", None))), Invalid::NameRequired);
        assert_eq!(reason(dir.save_identity(identity("Deploy", "  ", None))), Invalid::UserRequired);
        assert_eq!(reason(dir.save_identity(identity("Deploy", "-oProxyCommand=x", None))), Invalid::UserInvalid);
        assert_eq!(reason(dir.save_identity(identity("Deploy", "deploy", Some("00000000000000000000000000000000")))), Invalid::KeyMissing);

        let id = dir.save_identity(IdentityInput { password: Some(Some(Secret::new("geheim".into()))), ..identity("Deploy", " deploy ", Some(&key_id)) }).unwrap();
        let view = &dir.snapshot().identities[0];
        assert_eq!((view.name.as_str(), view.user.as_str(), view.key.as_deref(), view.has_password), ("Deploy", "deploy", Some(key_id.as_str()), true));
        assert!(!serde_json::to_string(&dir.snapshot()).unwrap().contains("geheim"));

        // Without the field the password stays, `null` removes it; an empty key means “none”.
        dir.save_identity(IdentityInput { id: Some(id.clone()), ..identity("Deploy", "deploy", Some("")) }).unwrap();
        let view = &dir.snapshot().identities[0];
        assert_eq!((view.key.as_deref(), view.has_password), (None, true));
        dir.save_identity(IdentityInput { id: Some(id.clone()), password: Some(None), ..identity("Deploy", "deploy", None) }).unwrap();
        assert!(!dir.snapshot().identities[0].has_password);
    }

    #[test]
    fn sign_in_follows_identities_and_keys() {
        let temp = Temp::new("auth");
        let mut dir = temp.directory();
        let work = dir.add_key(key("arbeit")).unwrap();
        let other = dir.add_key(key("anderer")).unwrap();
        let deploy = dir.save_identity(IdentityInput { password: Some(Some(Secret::new("id-passwort".into()))), ..identity("Deploy", "deploy", Some(&work)) }).unwrap();
        let missing = Some("00000000000000000000000000000000".to_string());
        assert_eq!(reason(dir.save_group(GroupInput { defs: Fields { identity: missing.clone(), ..Fields::default() }, ..group("G", None) })), Invalid::IdentityMissing);
        assert_eq!(reason(dir.save_host(HostInput { own: Fields { key: missing, ..Fields::default() }, ..host("h", None) })), Invalid::KeyMissing);

        let prod = dir.save_group(GroupInput { defs: Fields { identity: Some(deploy.clone()), ..Fields::default() }, ..group("Produktiv", None) }).unwrap();
        let plain = dir.save_host(host("web-01", Some(&prod))).unwrap();
        let info = dir.connect_info(&plain).unwrap();
        assert_eq!((info.user.as_str(), info.password.as_ref().map(Secret::expose)), ("deploy", Some("id-passwort")));
        assert_eq!(info.key.as_ref().map(Secret::expose), Some("-----BEGIN OPENSSH PRIVATE KEY-----arbeit"));

        // Values set individually on the host take precedence, including its own password.
        let own = Fields { user: Some("admin".into()), key: Some(other.clone()), ..Fields::default() };
        let special = dir.save_host(HostInput { own, password: Some(Some(Secret::new("host-passwort".into()))), ..host("db-01", Some(&prod)) }).unwrap();
        let info = dir.connect_info(&special).unwrap();
        assert_eq!((info.user.as_str(), info.password.as_ref().map(Secret::expose)), ("admin", Some("host-passwort")));
        assert_eq!(info.key.as_ref().map(Secret::expose), Some("-----BEGIN OPENSSH PRIVATE KEY-----anderer"));

        // “Explicitly no identity” on the host: default user, no key, no password.
        let bare = dir.save_host(HostInput { own: Fields { identity: Some(String::new()), ..Fields::default() }, ..host("alt", Some(&prod)) }).unwrap();
        let info = dir.connect_info(&bare).unwrap();
        assert_eq!((info.user.as_str(), info.password.is_none(), info.key.is_none()), (model::DEFAULT_USER, true, true));

        // A certificate on the key goes into the connection details and the display until it is removed.
        let certificate = KeyCertificate { text: "ssh-ed25519-cert-v01@openssh.com AAAAzert".into(), key_id: "deploy".into(), principals: vec!["deploy".into()], valid_after: 0, valid_before: None, authority: "SHA256:ca".into() };
        dir.set_key_certificate(&work, Some(certificate.clone())).unwrap();
        assert_eq!(dir.connect_info(&plain).unwrap().certificate.as_deref(), Some("ssh-ed25519-cert-v01@openssh.com AAAAzert"));
        assert_eq!(dir.snapshot().keys.iter().find(|k| k.id == work).unwrap().certificate, Some(certificate));
        assert!(dir.connect_info(&special).unwrap().certificate.is_none(), "der andere Schlüssel hat keines");
        dir.set_key_certificate(&work, None).unwrap();
        assert!(dir.connect_info(&plain).unwrap().certificate.is_none());
        assert!(matches!(dir.set_key_certificate("00000000000000000000000000000000", None), Err(DirError::NotFound)));

        // Deleting a key drops the references on the host and in the identity, everything else stays.
        dir.delete_key(&other).unwrap();
        assert!(dir.snapshot().hosts.iter().all(|h| h.own.key.is_none()));
        assert_eq!(dir.connect_info(&special).unwrap().key.as_ref().map(Secret::expose), Some("-----BEGIN OPENSSH PRIVATE KEY-----arbeit"), "jetzt gilt der Schlüssel der Identität");
        dir.delete_key(&work).unwrap();
        assert_eq!((dir.snapshot().keys.len(), dir.snapshot().identities[0].key.as_deref()), (0, None));
        assert!(dir.connect_info(&plain).unwrap().key.is_none());
        assert!(matches!(dir.delete_key(&work), Err(DirError::NotFound)));

        // After copying it to a host, the host can be switched to the key.
        let fresh = dir.add_key(key("frisch")).unwrap();
        assert!(dir.set_host_key(&plain, &fresh).unwrap());
        assert!(!dir.set_host_key(&plain, &fresh).unwrap(), "derselbe Schlüssel ist keine Änderung");
        assert_eq!(dir.connect_info(&plain).unwrap().key.as_ref().map(Secret::expose), Some("-----BEGIN OPENSSH PRIVATE KEY-----frisch"));
        assert_eq!(reason(dir.set_host_key(&plain, "00000000000000000000000000000000")), Invalid::KeyMissing);

        // Deleting an identity drops the references in group and host.
        dir.delete_identity(&deploy).unwrap();
        let snapshot = dir.snapshot();
        assert!(snapshot.identities.is_empty() && snapshot.groups[0].defs.identity.is_none());
        assert_eq!(snapshot.hosts.iter().find(|h| h.id == bare).unwrap().own.identity.as_deref(), Some(""), "„ausdrücklich keine“ bleibt stehen");
        assert_eq!(dir.connect_info(&plain).unwrap().user, model::DEFAULT_USER);
        assert_eq!(snapshot.hosts.len(), 3);
    }

    #[test]
    fn authorities_apply_to_the_hosts_their_pattern_names() {
        let temp = Temp::new("authorities");
        let mut dir = temp.directory();
        let ca = |name: &str, pattern: &str| NewAuthority { name: name.into(), pattern: pattern.into(), label: "Ed25519".into(), fingerprint: format!("SHA256:{name}"), public: format!("ssh-ed25519 AAAA{name} kommentar") };
        assert_eq!(reason(dir.add_authority(ca("", "*"))), Invalid::NameRequired);
        assert_eq!(reason(dir.add_authority(ca("Firma", "  "))), Invalid::PatternInvalid);
        assert_eq!(reason(dir.add_authority(ca("Firma", "$(rm)"))), Invalid::PatternInvalid);
        let company = dir.add_authority(ca("Firma", " *.firma.test, 10.0.* ")).unwrap();
        dir.add_authority(ca("Alles", "*")).unwrap();

        let view = &dir.snapshot().authorities[1];
        assert_eq!((view.name.as_str(), view.pattern.as_str(), view.kind.as_str(), view.fingerprint.as_str()), ("Firma", "*.firma.test, 10.0.*", "Ed25519", "SHA256:Firma"));
        assert!(view.added_at > 0);

        let inside = dir.save_host(HostInput { address: "web-01.firma.test".into(), ..host("web-01", None) }).unwrap();
        let outside = dir.save_host(HostInput { address: "203.0.113.5".into(), ..host("fremd", None) }).unwrap();
        let mut both = dir.connect_info(&inside).unwrap().authorities;
        both.sort();
        assert_eq!(both, ["ssh-ed25519 AAAAAlles", "ssh-ed25519 AAAAFirma"], "ohne Kommentar, beide passen");
        assert_eq!(dir.connect_info(&outside).unwrap().authorities, ["ssh-ed25519 AAAAAlles"]);

        dir.delete_authority(&company).unwrap();
        assert_eq!(dir.connect_info(&inside).unwrap().authorities.len(), 1);
        assert!(matches!(dir.delete_authority(&company), Err(DirError::NotFound)));
    }

    #[test]
    fn workspaces_keep_their_arrangement_and_follow_their_hosts() {
        use crate::model::{PaneTarget, Split};
        let temp = Temp::new("workspaces");
        let mut dir = temp.directory();
        let web = dir.save_host(host("web-01", None)).unwrap();
        let db = dir.save_host(host("db-01", None)).unwrap();
        let cache = dir.save_host(host("cache-01", None)).unwrap();
        let pane = |id: &str| Box::new(Arrangement::Pane { pane: PaneTarget::Host { id: id.into() } });
        let side = |ratio: f64, a: Box<Arrangement>, b: Box<Arrangement>| Arrangement::Split { dir: Split::Row, ratio, a, b };
        let stacked = Box::new(Arrangement::Split { dir: Split::Col, ratio: 0.5, a: pane(&db), b: pane(&cache) });
        let input = |name: &str, layout: Arrangement| WorkspaceInput { id: None, name: name.into(), multi: true, layout };

        assert_eq!(reason(dir.save_workspace(input("", *pane(&web)))), Invalid::NameRequired);
        assert_eq!(reason(dir.save_workspace(input("Leer", *pane("00000000000000000000000000000000")))), Invalid::WorkspaceEmpty);
        let id = dir.save_workspace(input("Deploy", side(7.0, pane(&web), stacked.clone()))).unwrap();
        let single = dir.save_workspace(input("Allein", side(0.5, pane(&db), pane("00000000000000000000000000000000")))).unwrap();

        let view = dir.snapshot().workspaces.into_iter().find(|w| w.id == id).unwrap();
        assert_eq!((view.name.as_str(), view.multi), ("Deploy", true));
        assert_eq!(view.layout, side(0.95, pane(&web), stacked), "das Verhältnis wird begrenzt, der Rest bleibt");
        let alone = dir.snapshot().workspaces.into_iter().find(|w| w.id == single).unwrap();
        assert_eq!((alone.layout.clone(), alone.multi), (*pane(&db), false), "unbekannte Hosts fallen weg, Multi-Exec braucht zwei Bereiche");

        // The same form the interface sends and reads.
        let json = serde_json::to_value(&alone.layout).unwrap();
        assert_eq!(json, serde_json::json!({ "pane": { "kind": "host", "id": db } }));
        assert!(serde_json::from_value::<Arrangement>(serde_json::json!({ "pane": { "kind": "direct", "user": "root", "host": "1.2.3.4", "port": 22 } })).is_err(), "eingetippte Adressen gehören nicht in den Tresor");

        dir.save_workspace(WorkspaceInput { id: Some(id.clone()), name: "Deploy-Runde".into(), multi: false, layout: side(0.4, pane(&web), pane(&db)) }).unwrap();
        assert_eq!(dir.snapshot().workspaces.iter().map(|w| w.name.as_str()).collect::<Vec<_>>(), ["Allein", "Deploy-Runde"]);

        dir.delete_host(&db).unwrap();
        let left = dir.snapshot().workspaces;
        assert_eq!(left.len(), 1, "der Arbeitsbereich ohne Hosts ist weg");
        assert_eq!(left[0].layout, *pane(&web));
        dir.delete_workspace(&id).unwrap();
        assert!(matches!(dir.delete_workspace(&id), Err(DirError::NotFound)));
    }

    #[test]
    fn port_rules_are_validated_and_leave_with_their_host() {
        let temp = Temp::new("forwards");
        let mut dir = temp.directory();
        let web = dir.save_host(host("web-01", None)).unwrap();
        let db = dir.save_host(host("db-01", None)).unwrap();
        let rule = |name: &str, kind: ForwardKind, host: &str, bind: u32, dest: &str, port: u32| ForwardInput { id: None, name: name.into(), kind, host: host.into(), bind_address: String::new(), bind_port: bind, dest_host: dest.into(), dest_port: port };

        assert_eq!(reason(dir.save_forward(rule("", ForwardKind::Local, &web, 3000, "127.0.0.1", 3000))), Invalid::NameRequired);
        assert_eq!(reason(dir.save_forward(rule("Grafana", ForwardKind::Local, "00000000000000000000000000000000", 3000, "127.0.0.1", 3000))), Invalid::HostMissing);
        assert_eq!(reason(dir.save_forward(rule("Grafana", ForwardKind::Local, &web, 0, "127.0.0.1", 3000))), Invalid::PortInvalid);
        assert_eq!(reason(dir.save_forward(rule("Grafana", ForwardKind::Local, &web, 70_000, "127.0.0.1", 3000))), Invalid::PortInvalid);
        assert_eq!(reason(dir.save_forward(rule("Grafana", ForwardKind::Local, &web, 3000, "  ", 3000))), Invalid::DestRequired);
        assert_eq!(reason(dir.save_forward(rule("Grafana", ForwardKind::Remote, &web, 3000, "zwei worte", 3000))), Invalid::AddressInvalid);
        assert_eq!(reason(dir.save_forward(rule("Grafana", ForwardKind::Local, &web, 3000, "127.0.0.1", 0))), Invalid::PortInvalid);
        assert_eq!(reason(dir.save_forward(ForwardInput { bind_address: "-o ProxyCommand".into(), ..rule("Grafana", ForwardKind::Local, &web, 3000, "127.0.0.1", 3000) })), Invalid::AddressInvalid);

        let grafana = dir.save_forward(rule(" Grafana ", ForwardKind::Local, &web, 3000, " 127.0.0.1 ", 3000)).unwrap();
        let socks = dir.save_forward(rule("SOCKS", ForwardKind::Dynamic, &db, 1080, "wird ignoriert", 99_999)).unwrap();
        dir.save_forward(ForwardInput { bind_address: "0.0.0.0".into(), ..rule("Webhook", ForwardKind::Remote, &db, 8080, "localhost", 5173) }).unwrap();

        let view = dir.forward(&grafana).unwrap();
        assert_eq!((view.name.as_str(), view.bind_address.as_str(), view.bind_port, view.dest_host.as_str(), view.dest_port), ("Grafana", "127.0.0.1", 3000, "127.0.0.1", 3000));
        let dynamic = dir.forward(&socks).unwrap();
        assert_eq!((dynamic.dest_host.as_str(), dynamic.dest_port), ("", 0), "ein SOCKS-Proxy hat kein festes Ziel");
        assert_eq!(dir.snapshot().forwards.iter().map(|f| (f.name.as_str(), f.bind_address.as_str())).collect::<Vec<_>>(), [("Grafana", "127.0.0.1"), ("SOCKS", "127.0.0.1"), ("Webhook", "0.0.0.0")]);
        // The same form the interface reads.
        assert_eq!(serde_json::to_value(&dynamic).unwrap(), serde_json::json!({ "id": socks, "name": "SOCKS", "kind": "dynamic", "host": db, "bindAddress": "127.0.0.1", "bindPort": 1080, "destHost": "", "destPort": 0 }));

        dir.save_forward(ForwardInput { id: Some(grafana.clone()), ..rule("Grafana neu", ForwardKind::Local, &web, 3001, "10.0.0.5", 80) }).unwrap();
        assert_eq!(dir.forward(&grafana).unwrap().dest_host, "10.0.0.5");

        dir.delete_host(&db).unwrap();
        assert_eq!(dir.snapshot().forwards.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(), ["Grafana neu"], "mit dem Host gehen seine Regeln");
        dir.delete_forward(&grafana).unwrap();
        assert!(matches!(dir.delete_forward(&grafana), Err(DirError::NotFound)));
        assert!(matches!(dir.forward(&grafana), Err(DirError::NotFound)));
    }

    #[test]
    fn snippets_and_macros_are_validated_and_share_no_hotkey() {
        let temp = Temp::new("snippets");
        let mut dir = temp.directory();
        let command = |name: &str, text: &str, hotkey: Option<&str>| SnippetInput { id: None, name: name.into(), package: " Alltag ".into(), kind: SnippetKind::Command, command: text.into(), steps: Vec::new(), hotkey: hotkey.map(Into::into) };
        let step = |wait: u32, keys: &str| MacroStep { wait, keys: keys.into() };
        let recorded = |name: &str, steps: Vec<MacroStep>| SnippetInput { id: None, name: name.into(), package: String::new(), kind: SnippetKind::Macro, command: "wird ignoriert".into(), steps, hotkey: None };

        assert_eq!(reason(dir.save_snippet(command("", "df -h", None))), Invalid::NameRequired);
        assert_eq!(reason(dir.save_snippet(command("Platz", "  \n ", None))), Invalid::CommandRequired);
        assert_eq!(reason(dir.save_snippet(command("Platz", &"x".repeat(MAX_COMMAND + 1), None))), Invalid::SnippetTooLarge);
        assert_eq!(reason(dir.save_snippet(command("Platz", "df -h", Some("Ctrl+C")))), Invalid::HotkeyInvalid);
        assert_eq!(reason(dir.save_snippet(recorded("Leer", vec![step(100, "")]))), Invalid::MacroEmpty);

        let space = dir.save_snippet(command("Plattenplatz", "df -h\r\ndu -sh *\n", Some("Alt+1"))).unwrap();
        assert_eq!(reason(dir.save_snippet(command("Container", "docker ps", Some("Alt+1")))), Invalid::HotkeyTaken);
        let containers = dir.save_snippet(command("Container", "docker ps", Some("Alt+2"))).unwrap();
        let tour = dir.save_snippet(recorded("Rundgang", vec![step(0, "cd /var\r"), step(4_000_000_000, "ls\r"), step(5, "")])).unwrap();

        let all = dir.snapshot().snippets;
        assert_eq!(all.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(), ["Container", "Plattenplatz", "Rundgang"]);
        let stored = all.iter().find(|s| s.id == space).unwrap();
        assert_eq!((stored.package.as_str(), stored.command.as_str(), stored.hotkey.as_deref()), ("Alltag", "df -h\ndu -sh *", Some("Alt+1")));
        let played = all.iter().find(|s| s.id == tour).unwrap();
        assert_eq!((played.command.as_str(), played.steps.len(), played.steps[1].wait), ("", 2, MAX_MACRO_WAIT), "leere Schritte fallen weg, endlose Pausen werden begrenzt");
        assert_eq!(serde_json::to_value(&played.steps[0]).unwrap(), serde_json::json!({ "wait": 0, "keys": "cd /var\r" }));
        assert!(!format!("{:?}", dir.snippets[&tour]).contains("cd /var"), "getippte Tasten erscheinen in keiner Ausgabe");

        // A snippet may keep its own hotkey when edited; it gets a free one without further ado.
        dir.save_snippet(SnippetInput { id: Some(space.clone()), ..command("Platz", "df -h", Some("Alt+1")) }).unwrap();
        assert_eq!(reason(dir.save_snippet(SnippetInput { id: Some(containers.clone()), ..command("Container", "docker ps", Some("Alt+1")) })), Invalid::HotkeyTaken);
        dir.save_snippet(SnippetInput { id: Some(containers.clone()), ..command("Container", "docker ps", Some("")) }).unwrap();
        assert_eq!(dir.snapshot().snippets.iter().find(|s| s.id == containers).unwrap().hotkey, None);

        dir.delete_snippet(&space).unwrap();
        assert!(matches!(dir.delete_snippet(&space), Err(DirError::NotFound)));
        dir.save_snippet(command("Container 2", "docker ps -a", Some("Alt+1"))).unwrap();
    }

    #[test]
    fn hotkeys_leave_the_shell_and_glowport_their_keys() {
        for good in ["Alt+1", "Alt+R", "Ctrl+Alt+R", "Ctrl+Shift+K", "Ctrl+1", "Ctrl+F5", "Alt+Shift+F12", "Ctrl+Alt+Shift+Z"] {
            assert!(model::valid_hotkey(good), "{good}");
        }
        for bad in ["", "R", "F5", "Shift+F5", "Ctrl+C", "Ctrl+Shift+C", "Ctrl+0", "Alt+F4", "Alt+Ctrl+R", "Alt+Alt+R", "Alt+r", "Alt+F13", "Alt+F01", "Alt+", "Win+R", "Alt+Enter"] {
            assert!(!model::valid_hotkey(bad), "{bad}");
        }
    }

    #[test]
    fn colour_schemes_are_inherited_values_with_a_safe_name() {
        let temp = Temp::new("schemes");
        let mut dir = temp.directory();
        let scheme = |name: &str| Fields { scheme: Some(name.into()), ..Fields::default() };
        assert_eq!(reason(dir.save_group(GroupInput { defs: scheme("Nord Light"), ..group("Labor", None) })), Invalid::SchemeInvalid);
        let lab = dir.save_group(GroupInput { defs: scheme(" nord "), ..group("Labor", None) }).unwrap();
        let nas = dir.save_host(HostInput { own: scheme("custom-mein-schema"), ..host("nas", Some(&lab)) }).unwrap();
        let snapshot = dir.snapshot();
        assert_eq!(snapshot.groups[0].defs.scheme.as_deref(), Some("nord"));
        assert_eq!(snapshot.hosts.iter().find(|h| h.id == nas).unwrap().own.scheme.as_deref(), Some("custom-mein-schema"));
    }

    #[test]
    fn unknown_fields_and_records_survive_an_edit() {
        let temp = Temp::new("unknown");
        let mut dir = temp.directory();
        let future = br#"{"t":"host","v":2,"name":"alt","address":"1.2.3.4","zukunft":"bleibt"}"#;
        let id = hex(&dir.vault_mut().put(None, future).unwrap());
        dir.vault_mut().put(None, r#"{"t":"zukunft","name":"kommt später"}"#.as_bytes()).unwrap();
        dir.vault_mut().put(None, b"kein json").unwrap();
        dir.reload().unwrap();
        assert_eq!((dir.snapshot().hosts.len(), dir.snapshot().damaged), (1, 1));

        dir.save_host(HostInput { id: Some(id.clone()), ..host("neu", None) }).unwrap();
        assert_eq!((dir.hosts[&id].v, dir.hosts[&id].extra["zukunft"].as_str()), (2, Some("bleibt")));
        assert_eq!(dir.vault().list().unwrap().records.len(), 3, "fremde Datensätze bleiben im Tresor");
    }

    #[test]
    fn batch_writes_all_or_nothing_and_known_hosts_add_up() {
        let temp = Temp::new("batch");
        let mut dir = temp.directory();
        // In the middle of the batch change every step sees what the previous ones wrote.
        let made = dir
            .batch(|dir| {
                let g = dir.save_group(group("Import", None))?;
                let jump = dir.save_host(HostInput { group: Some(g.clone()), ..host("bastion", None) })?;
                let web = dir.save_host(HostInput { group: Some(g.clone()), own: Fields { jump: Some(jump.clone()), ..Fields::default() }, ..host("web", None) })?;
                Ok((g, jump, web))
            })
            .unwrap();
        let snapshot = dir.snapshot();
        assert_eq!((snapshot.groups.len(), snapshot.hosts.len()), (1, 2));
        assert_eq!(snapshot.hosts.iter().find(|h| h.id == made.2).unwrap().own.jump.as_deref(), Some(made.1.as_str()));

        // If a step fails, what was written before is gone again too.
        let failed = dir.batch(|dir| {
            dir.save_host(host("bleibt-nicht", None))?;
            dir.save_host(HostInput { address: " ".into(), ..host("kaputt", None) })
        });
        assert_eq!(reason(failed), Invalid::AddressRequired);
        assert_eq!(dir.snapshot().hosts.len(), 2);
        assert!(dir.save_host(host("danach", None)).is_ok(), "nach einer Sammeländerung geht es normal weiter");

        // Several keys may apply to one address; the same one is not added a second time.
        assert!(dir.add_known_host("Web.Example.org", 22, "ssh-ed25519", "SHA256:a", "ssh-ed25519 AAAA kommentar").unwrap());
        assert!(dir.add_known_host("web.example.org", 22, "ssh-rsa", "SHA256:b", "ssh-rsa BBBB").unwrap());
        assert!(!dir.add_known_host("web.example.org", 22, "ssh-ed25519", "SHA256:a", "ssh-ed25519 AAAA").unwrap());
        assert_eq!(dir.known_hosts().len(), 2);
        assert_eq!(dir.judge_host_key("web.example.org", 22, "ssh-rsa BBBB"), Verdict::Trusted);
        assert_eq!(dir.judge_host_key("web.example.org", 22, "ssh-ed25519 AAAA"), Verdict::Trusted);
        assert_eq!(reason(dir.add_known_host("-böse", 22, "x", "y", "ssh-rsa BBBB")), Invalid::AddressInvalid);
    }

    #[test]
    fn ftp_hosts_follow_their_own_rules() {
        let temp = Temp::new("ftp");
        let mut dir = temp.directory();
        // A group sets nothing for FTP: neither user nor port.
        let net = dir.save_group(GroupInput { defs: Fields { user: Some("deploy".into()), port: Some(2222), ..Fields::default() }, ..group("Netz", None) }).unwrap();
        let ftp = |security| Ftp { security, anonymous: false, dir: None, plain_ok: false };
        let web = |own: Fields, settings: Option<Ftp>, password: Option<&str>| HostInput {
            protocol: Some("ftp".into()),
            address: "ftp.example.org".into(),
            ftp: settings,
            own,
            password: password.map(|p| Some(Secret::new(p.into()))),
            ..host("webspace", Some(&net))
        };

        // Without a value, FTPS on port 21 applies; user and password are on the host, everything for the terminal is dropped.
        let own = Fields { user: Some("web123".into()), term: Some("xterm".into()), charset: Some("utf-8".into()), startcmd: Some("ls".into()), ..Fields::default() };
        let id = dir.save_host(web(own, None, Some("geheim"))).unwrap();
        assert!(matches!(dir.endpoint(&id).unwrap(), Endpoint::Ftp));
        assert!(dir.is_ftp(&id) && !dir.is_ssh(&id));
        assert_eq!(reason(dir.connect_info(&id)), Invalid::HostNotSsh);
        let info = dir.ftp_info(&id).unwrap();
        assert_eq!((info.address.as_str(), info.port, info.user.as_str(), info.security, info.pin.as_deref()), ("ftp.example.org", 21, "web123", FtpSecurity::Explicit, None));
        assert_eq!(info.password.as_ref().map(Secret::expose), Some("geheim"));
        assert!(info.saves_password && !info.plain_ok);
        let view = serde_json::to_value(dir.snapshot().hosts.iter().find(|h| h.id == id).unwrap()).unwrap();
        assert_eq!(view["ftp"], serde_json::json!({ "security": "explicit", "anonymous": false }));
        assert_eq!(view["own"], serde_json::json!({ "user": "web123" }));
        assert_eq!(view["hasPassword"], true);

        // Implicit FTPS has its own port; a port of its own and a start folder stay.
        let settings = Ftp { dir: Some(" /htdocs ".into()), ..ftp(FtpSecurity::Implicit) };
        dir.save_host(HostInput { id: Some(id.clone()), ..web(Fields { user: Some("web123".into()), ..Fields::default() }, Some(settings), None) }).unwrap();
        let info = dir.ftp_info(&id).unwrap();
        assert_eq!((info.port, info.dir.as_deref()), (990, Some("/htdocs")));
        assert_eq!(info.password.as_ref().map(Secret::expose), Some("geheim"), "ohne Angabe bleibt das Passwort");
        dir.save_host(HostInput { id: Some(id.clone()), ..web(Fields { user: Some("web123".into()), port: Some(2121), ..Fields::default() }, None, None) }).unwrap();
        assert_eq!((dir.ftp_info(&id).unwrap().port, dir.ftp_info(&id).unwrap().security), (2121, FtpSecurity::Implicit), "ohne Angabe bleiben die Einstellungen");

        // With an identity, user and password come from it; the host then holds none.
        let identity = dir.save_identity(IdentityInput { password: Some(Some(Secret::new("aus-der-identitaet".into()))), ..identity("Hoster", "kunde7", None) }).unwrap();
        dir.save_host(HostInput { id: Some(id.clone()), ..web(Fields { user: Some("web123".into()), identity: Some(identity.clone()), ..Fields::default() }, None, None) }).unwrap();
        let info = dir.ftp_info(&id).unwrap();
        assert_eq!((info.user.as_str(), info.password.as_ref().map(Secret::expose), info.saves_password), ("kunde7", Some("aus-der-identitaet"), false));
        let view = serde_json::to_value(dir.snapshot().hosts.iter().find(|h| h.id == id).unwrap()).unwrap();
        assert_eq!((view["own"].clone(), view["hasPassword"].clone()), (serde_json::json!({ "identity": identity }), serde_json::json!(false)));

        // Anonymous: no user, no password, no identity.
        let anonymous = Ftp { anonymous: true, ..ftp(FtpSecurity::None) };
        dir.save_host(HostInput { id: Some(id.clone()), ..web(Fields { user: Some("web123".into()), identity: Some(identity), ..Fields::default() }, Some(anonymous), Some("egal")) }).unwrap();
        let info = dir.ftp_info(&id).unwrap();
        assert_eq!((info.user.as_str(), info.password.is_none(), info.saves_password, info.security), ("", true, false, FtpSecurity::None));

        // The question before the unencrypted connection can be switched off; with FTPS that lapses.
        dir.set_ftp_choice(&id, true, false).unwrap();
        assert!(dir.ftp_info(&id).unwrap().plain_ok);
        dir.set_ftp_choice(&id, false, true).unwrap();
        let info = dir.ftp_info(&id).unwrap();
        assert_eq!((info.security, info.plain_ok), (FtpSecurity::Explicit, false));
        dir.set_ftp_choice(&id, true, false).unwrap();
        assert!(!dir.ftp_info(&id).unwrap().plain_ok, "bei FTPS gibt es nichts abzubestellen");

        // A confirmed certificate is listed with the known hosts and applies to exactly this address and port.
        let port = dir.ftp_info(&id).unwrap().port;
        dir.trust_certificate("FTP.example.org", port, "5F:1A").unwrap();
        assert_eq!(dir.ftp_info(&id).unwrap().pin.as_deref(), Some("5F:1A"));
        assert_eq!(dir.certificate_pin("ftp.example.org", port + 1), None);
        dir.trust_certificate("ftp.example.org", port, "AA:BB").unwrap();
        assert_eq!(dir.ftp_info(&id).unwrap().pin.as_deref(), Some("AA:BB"), "ein neues ersetzt das alte");
        let known = dir.snapshot().known_hosts;
        assert_eq!(known.iter().filter(|k| k.algorithm == "tls").map(|k| (k.host.as_str(), k.fingerprint.as_str())).collect::<Vec<_>>(), [("ftp.example.org", "AA:BB")]);

        // An FTP host is not suitable as a jump host and carries no port rules; with another protocol its settings disappear.
        assert_eq!(reason(dir.save_host(HostInput { own: Fields { jump: Some(id.clone()), ..Fields::default() }, ..host("hinten", None) })), Invalid::HostNotSsh);
        let plain = dir.save_host(host("ssh-host", None)).unwrap();
        assert_eq!(reason(dir.set_ftp_choice(&plain, true, false)), Invalid::ProtocolInvalid);
        dir.save_host(HostInput { id: Some(id.clone()), protocol: Some("ssh".into()), ..host("webspace", None) }).unwrap();
        assert!(dir.snapshot().hosts.iter().find(|h| h.id == id).unwrap().ftp.is_none());
        assert_eq!(reason(dir.ftp_info(&id)), Invalid::ProtocolInvalid);
    }

    #[test]
    fn telnet_and_serial_hosts_follow_their_own_rules() {
        use crate::model::{Flow, Parity};
        let temp = Temp::new("protocols");
        let mut dir = temp.directory();
        let line = Serial { baud: 115_200, data_bits: 8, parity: Parity::None, stop_bits: 1, flow: Flow::None };
        let defs = Fields { user: Some("deploy".into()), port: Some(2222), charset: Some("iso-8859-1".into()), timeout: Some(40), ..Fields::default() };
        let net = dir.save_group(GroupInput { defs, ..group("Netz", None) }).unwrap();

        // Telnet: the host does not inherit port and user, but timeout and charset it does.
        let own = Fields { startcmd: Some("enable".into()), ..Fields::default() };
        let switch = dir.save_host(HostInput { protocol: Some("telnet".into()), password: Some(Some(Secret::new("geheim".into()))), own, ..host("switch", Some(&net)) }).unwrap();
        let Endpoint::Telnet(info) = dir.endpoint(&switch).unwrap() else { panic!("Telnet erwartet") };
        assert_eq!((info.port, info.user.as_deref(), info.timeout, info.charset.as_str(), info.term.as_str()), (23, None, 40, "iso-8859-1", "xterm-256color"));
        let snapshot = dir.snapshot();
        let view = snapshot.hosts.iter().find(|h| h.id == switch).unwrap();
        assert_eq!(view.protocol, "telnet");
        assert!(!view.has_password, "für Telnet wird kein Passwort gespeichert");
        assert!(view.own.startcmd.is_none(), "was zum Protokoll nicht gehört, wird nicht gespeichert");
        assert_eq!(reason(dir.connect_info(&switch)), Invalid::HostNotSsh);

        // Without a value the protocol stays, e.g. when moving into another group.
        dir.save_host(HostInput { id: Some(switch.clone()), own: Fields { port: Some(2323), user: Some("admin".into()), ..Fields::default() }, ..host("switch", None) }).unwrap();
        let Endpoint::Telnet(info) = dir.endpoint(&switch).unwrap() else { panic!("Telnet erwartet") };
        assert_eq!((info.port, info.user.as_deref(), info.timeout), (2323, Some("admin"), 15));

        // Serial: the line belongs to it and must be possible.
        let serial = |line: Option<Serial>| HostInput { protocol: Some("serial".into()), serial: line, address: "COM3".into(), ..host("konsole", None) };
        assert_eq!(reason(dir.save_host(serial(None))), Invalid::SerialRequired);
        assert_eq!(reason(dir.save_host(serial(Some(Serial { baud: 10, ..line })))), Invalid::BaudInvalid);
        assert_eq!(reason(dir.save_host(serial(Some(Serial { data_bits: 9, ..line })))), Invalid::SerialInvalid);
        assert_eq!(reason(dir.save_host(serial(Some(Serial { stop_bits: 3, ..line })))), Invalid::SerialInvalid);
        let console = dir.save_host(serial(Some(line))).unwrap();
        let Endpoint::Serial(info) = dir.endpoint(&console).unwrap() else { panic!("seriell erwartet") };
        assert_eq!((info.port.as_str(), info.line, info.charset.as_str()), ("COM3", line, "utf-8"));
        dir.save_host(HostInput { id: Some(console.clone()), address: "/dev/ttyUSB0".into(), ..host("konsole", Some(&net)) }).unwrap();
        let Endpoint::Serial(info) = dir.endpoint(&console).unwrap() else { panic!("seriell erwartet") };
        assert_eq!((info.port.as_str(), info.line.baud, info.charset.as_str()), ("/dev/ttyUSB0", 115_200, "iso-8859-1"), "die Leitung bleibt, der Zeichensatz kommt von der Gruppe");
        assert_eq!(serde_json::to_value(dir.snapshot().hosts.iter().find(|h| h.id == console).unwrap()).unwrap()["serial"], serde_json::json!({ "baud": 115_200, "dataBits": 8, "parity": "none", "stopBits": 1, "flow": "none" }));

        // If the line becomes a Telnet host, its settings disappear.
        let moved = dir.save_host(serial(Some(line))).unwrap();
        dir.save_host(HostInput { id: Some(moved.clone()), protocol: Some("telnet".into()), address: "10.0.0.9".into(), ..host("konsole-2", None) }).unwrap();
        assert!(dir.snapshot().hosts.iter().find(|h| h.id == moved).unwrap().serial.is_none());

        assert_eq!(reason(dir.save_host(HostInput { protocol: Some("rdp".into()), ..host("x", None) })), Invalid::ProtocolInvalid);
        let plain = dir.save_host(host("web", None)).unwrap();
        assert!(matches!(dir.endpoint(&plain).unwrap(), Endpoint::Ssh));

        // Jumping and port rules only work over SSH.
        assert_eq!(reason(dir.save_host(HostInput { own: Fields { jump: Some(switch.clone()), ..Fields::default() }, ..host("hinten", None) })), Invalid::HostNotSsh);
        let rule = |host: &str| ForwardInput { id: None, name: "Web".into(), kind: ForwardKind::Local, host: host.into(), bind_address: String::new(), bind_port: 8080, dest_host: "127.0.0.1".into(), dest_port: 80 };
        assert_eq!(reason(dir.save_forward(rule(&switch))), Invalid::HostNotSsh);

        // Whoever is a jump host or carries port rules stays on SSH.
        let bastion = dir.save_host(host("bastion", None)).unwrap();
        let behind = dir.save_host(HostInput { own: Fields { jump: Some(bastion.clone()), ..Fields::default() }, ..host("dahinter", None) }).unwrap();
        let to_telnet = |id: &str| HostInput { id: Some(id.into()), protocol: Some("telnet".into()), ..host("bastion", None) };
        assert_eq!(reason(dir.save_host(to_telnet(&bastion))), Invalid::ProtocolInUse);
        dir.delete_host(&behind).unwrap();
        let forward = dir.save_forward(rule(&bastion)).unwrap();
        assert_eq!(reason(dir.save_host(to_telnet(&bastion))), Invalid::ProtocolInUse);
        dir.delete_forward(&forward).unwrap();
        dir.save_host(to_telnet(&bastion)).unwrap();
        assert!(matches!(dir.endpoint(&bastion).unwrap(), Endpoint::Telnet(_)));

        // After locking and opening, everything is there again.
        drop(dir);
        let mut vault = Vault::open(&temp.0).unwrap();
        vault.unlock("richtig").unwrap();
        let reopened = Directory::load(vault).unwrap();
        assert!(matches!(reopened.endpoint(&console).unwrap(), Endpoint::Serial(info) if info.line == line));
    }

    #[test]
    fn workspaces_take_local_terminals() {
        use crate::model::{PaneTarget, Split};
        let temp = Temp::new("workspaces-local");
        let mut dir = temp.directory();
        let web = dir.save_host(host("web-01", None)).unwrap();
        let local = |shell: &str| Box::new(Arrangement::Pane { pane: PaneTarget::Local { shell: shell.into() } });
        let server = Box::new(Arrangement::Pane { pane: PaneTarget::Host { id: web.clone() } });
        let side = |a: Box<Arrangement>, b: Box<Arrangement>| Arrangement::Split { dir: Split::Row, ratio: 0.5, a, b };
        let input = |layout: Arrangement| WorkspaceInput { id: None, name: "Werkbank".into(), multi: true, layout };

        let id = dir.save_workspace(input(side(server, local("wsl:Ubuntu")))).unwrap();
        let view = dir.snapshot().workspaces.into_iter().find(|w| w.id == id).unwrap();
        assert!(view.multi, "ein lokales Terminal zählt als Bereich");
        assert_eq!(serde_json::to_value(&view.layout).unwrap()["b"], serde_json::json!({ "pane": { "kind": "local", "shell": "wsl:Ubuntu" } }));

        // The host's pane disappears with it; the local terminal remains on its own.
        dir.delete_host(&web).unwrap();
        let left = dir.snapshot().workspaces;
        assert_eq!((left[0].layout.clone(), left[0].multi), (*local("wsl:Ubuntu"), false));

        assert_eq!(reason(dir.save_workspace(input(*local("")))), Invalid::WorkspaceEmpty);
        assert_eq!(reason(dir.save_workspace(input(*local("bö\u{7}se")))), Invalid::WorkspaceEmpty);
        dir.save_workspace(input(*local("pwsh"))).unwrap();
    }

    /// A directory with an own shared vault called “Team Infra”.
    fn with_shared(temp: &Temp) -> (Directory, String) {
        let mut dir = temp.directory();
        let shared = hex(&dir.vault.create_shared(&[1; 16], "ich").unwrap());
        dir.rename_vault(&shared, " Team Infra ").unwrap();
        (dir, shared)
    }

    #[test]
    fn entries_live_in_vaults_and_shared_vaults_only_point_into_themselves() {
        let temp = Temp::new("vaults");
        let (mut dir, shared) = with_shared(&temp);
        let snapshot = dir.snapshot();
        assert_eq!(snapshot.vaults.iter().map(|v| (v.kind, v.name.as_str(), v.role)).collect::<Vec<_>>(), [("personal", "", Role::Owner), ("shared", "Team Infra", Role::Owner)]);
        let me = &snapshot.vaults[1].members[0];
        assert!(me.me && !me.invited && me.code.split(" · ").count() == 6, "{me:?}");
        dir.rename_vault(&shared, "Team").unwrap();
        assert_eq!((dir.vault_name(&shared), dir.snapshot().homes.len()), ("Team".to_string(), 1), "umbenennen ersetzt den einen Datensatz mit dem Namen");
        assert!(matches!(dir.rename_vault(&snapshot.vaults[0].id, "x"), Err(DirError::Vault(VaultError::NotOwner))), "der persönliche Tresor hat keinen Namen");

        // Creating in the chosen vault. Without a choice, the group decides where an entry goes.
        let team_group = dir.in_vault(Some(&shared), |d| d.save_group(group("Team", None))).unwrap();
        let team_host = dir.save_host(host("pve-01", Some(&team_group))).unwrap();
        let own_group = dir.save_group(group("Privat", None)).unwrap();
        let own_host = dir.save_host(host("web", Some(&own_group))).unwrap();
        let homes = dir.snapshot().homes;
        assert_eq!((homes.get(&team_group), homes.get(&team_host), homes.get(&own_host), homes.get(&own_group)), (Some(&shared), Some(&shared), None, None));
        assert_eq!(dir.record_name(&team_host).as_deref(), Some("pve-01"));

        // An entry lives in the same vault as its group.
        assert_eq!(reason(dir.in_vault(Some(&shared), |d| d.save_host(host("falsch", Some(&own_group))))), Invalid::OtherVault);
        assert_eq!(reason(dir.save_host(HostInput { id: Some(own_host.clone()), ..host("web", Some(&team_group)) })), Invalid::OtherVault);
        assert_eq!(reason(dir.save_group(GroupInput { id: Some(own_group.clone()), ..group("Privat", Some(&team_group)) })), Invalid::OtherVault);

        // A shared vault only refers within itself; the personal one may refer to anything.
        let own_key = dir.add_key(key("mein")).unwrap();
        let team_key = dir.in_vault(Some(&shared), |d| d.add_key(key("team"))).unwrap();
        let with_key = |id: &str, name: &str, group: &str, key: &str| HostInput { id: Some(id.into()), own: Fields { key: Some(key.into()), ..Fields::default() }, ..host(name, Some(group)) };
        assert_eq!(reason(dir.save_host(with_key(&team_host, "pve-01", &team_group, &own_key))), Invalid::OtherVault);
        dir.save_host(with_key(&team_host, "pve-01", &team_group, &team_key)).unwrap();
        dir.save_host(with_key(&own_host, "web", &own_group, &team_key)).unwrap();

        // A copy stays in the original's vault.
        let copy = dir.duplicate_host(&team_host, "pve-02").unwrap();
        assert_eq!(dir.snapshot().homes.get(&copy), Some(&shared));
        assert_eq!(dir.role_of(&team_host), Role::Owner);
        assert!(matches!(dir.in_vault(Some(&"00".repeat(16)), |d| d.save_group(group("x", None))), Err(DirError::NotFound)));

        // After locking and unlocking everything is back in its place.
        let mut vault = dir.into_vault();
        vault.lock();
        vault.unlock("richtig").unwrap();
        let dir = Directory::load(vault).unwrap();
        let snapshot = dir.snapshot();
        assert_eq!((snapshot.vaults[1].name.as_str(), snapshot.homes.get(&team_host)), ("Team", Some(&shared)));
    }

    #[test]
    fn a_host_moves_into_a_shared_vault_with_what_belongs_to_it() {
        let temp = Temp::new("move");
        let (mut dir, shared) = with_shared(&temp);
        let personal = dir.snapshot().vaults[0].id.clone();
        let own_key = dir.add_key(key("mein")).unwrap();
        let deploy = dir.save_identity(identity("deploy", "deploy", Some(&own_key))).unwrap();
        let bastion = dir.save_host(host("bastion", None)).unwrap();
        let own_group = dir.save_group(group("Privat", None)).unwrap();
        let own = Fields { identity: Some(deploy.clone()), jump: Some(bastion.clone()), ..Fields::default() };
        let web = dir.save_host(HostInput { own, password: Some(Some(Secret::new("geheim".into()))), ..host("web", Some(&own_group)) }).unwrap();
        let behind = dir.save_host(HostInput { own: Fields { jump: Some(web.clone()), ..Fields::default() }, ..host("db", None) }).unwrap();
        let rule = dir.save_forward(ForwardInput { id: None, name: "pg".into(), kind: ForwardKind::Local, host: web.clone(), bind_address: String::new(), bind_port: 5432, dest_host: "127.0.0.1".into(), dest_port: 5432 }).unwrap();
        use crate::model::{PaneTarget, Split};
        let pane = |id: &str| Box::new(Arrangement::Pane { pane: PaneTarget::Host { id: id.into() } });
        let layout = Arrangement::Split { dir: Split::Row, ratio: 0.5, a: pane(&web), b: pane(&behind) };
        let workspace = dir.save_workspace(WorkspaceInput { id: None, name: "Runde".into(), multi: false, layout }).unwrap();

        assert!(matches!(dir.move_host(&web, &"00".repeat(16), true), Err(DirError::NotFound)));
        assert_eq!(dir.move_host(&web, &personal, true).unwrap(), web, "liegt schon dort");
        let moved = dir.move_host(&web, &shared, true).unwrap();
        assert_ne!(moved, web);
        let snapshot = dir.snapshot();
        assert!(!snapshot.hosts.iter().any(|h| h.id == web), "hier ist er weg");
        let host_view = snapshot.hosts.iter().find(|h| h.id == moved).unwrap();
        assert_eq!((snapshot.homes.get(&moved), host_view.group.as_deref(), host_view.has_password), (Some(&shared), None, true));
        // The jump host from elsewhere is dropped; identity and its key came along as copies.
        assert_eq!(host_view.own.jump, None);
        let carried = host_view.own.identity.clone().unwrap();
        assert_ne!(carried, deploy);
        let carried_identity = snapshot.identities.iter().find(|i| i.id == carried).unwrap();
        let carried_key = carried_identity.key.clone().unwrap();
        assert_eq!((snapshot.homes.get(&carried), snapshot.homes.get(&carried_key), carried_key != own_key), (Some(&shared), Some(&shared), true));
        assert!(snapshot.identities.iter().any(|i| i.id == deploy) && snapshot.keys.iter().any(|k| k.id == own_key), "die eigenen bleiben, wo sie waren");
        assert_eq!(dir.connect_info(&moved).unwrap().user, "deploy");
        // Port rule, workspace and the host behind them are personal and follow the host.
        assert_eq!(snapshot.forwards.iter().find(|f| f.id == rule).unwrap().host, moved);
        assert_eq!(snapshot.workspaces.iter().find(|w| w.id == workspace).unwrap().layout.hosts(), [moved.as_str(), behind.as_str()]);
        assert_eq!(snapshot.hosts.iter().find(|h| h.id == behind).unwrap().own.jump.as_deref(), Some(moved.as_str()));

        // Back into the personal vault: it may refer to the shared one, so the identity stays.
        let back = dir.move_host(&moved, &personal, false).unwrap();
        let snapshot = dir.snapshot();
        let host_view = snapshot.hosts.iter().find(|h| h.id == back).unwrap();
        assert_eq!((snapshot.homes.get(&back), host_view.own.identity.as_deref()), (None, Some(carried.as_str())));

        // Without carrying, the reference is dropped instead of copied.
        let plain = dir.save_host(HostInput { own: Fields { key: Some(own_key.clone()), ..Fields::default() }, ..host("ohne", None) }).unwrap();
        let moved = dir.move_host(&plain, &shared, false).unwrap();
        assert_eq!(dir.snapshot().hosts.iter().find(|h| h.id == moved).unwrap().own.key, None);
    }

    const FINGERPRINT: &str = "5F:1A:9C:42:D7:0B:E3:68:AA:14:7C:90:3D:E2:56:B1:08:F4:6D:2A:C9:71:35:EE:80:4B:1D:97:A6:53:CF:02";

    fn pve(name: &str) -> ProxmoxInput {
        ProxmoxInput { id: None, name: name.into(), address: "https://pve.example.de:8006/".into(), token_id: " glowport@pve!glowport ".into(), secret: Some(Secret::new("0c6f2c1e-58a1".into())), fingerprint: None, identity: None }
    }

    fn guest(vmid: u32, name: &str, address: Option<&str>) -> GuestHost {
        GuestHost { node: "pve".into(), vmid, kind: model::GUEST_QEMU.into(), name: name.into(), address: address.map(Into::into), user: None, key: None, os: None }
    }

    fn seen(vmid: u32, name: &str, address: Option<&str>) -> GuestSeen {
        GuestSeen { node: "pve".into(), vmid, name: name.into(), address: address.map(Into::into) }
    }

    #[test]
    fn proxmox_connections_are_validated_and_never_show_their_secret() {
        let temp = Temp::new("pve");
        let mut dir = temp.directory();
        let id = dir.save_proxmox(ProxmoxInput { fingerprint: Some(FINGERPRINT.to_lowercase().replace(':', "")), ..pve(" Dedi ") }).unwrap();
        let snapshot = dir.snapshot();
        assert_eq!(snapshot.proxmox, [ProxmoxView { id: id.clone(), name: "Dedi".into(), address: "https://pve.example.de:8006".into(), token_id: "glowport@pve!glowport".into(), fingerprint: Some(FINGERPRINT.into()), identity: None }]);
        assert!(!serde_json::to_string(&snapshot).unwrap().contains("0c6f2c1e"), "das Geheimnis geht nicht an die Oberfläche");
        assert_eq!(dir.proxmox_access(&id).unwrap().secret.expose(), "0c6f2c1e-58a1");
        assert_eq!(dir.record_name(&id).as_deref(), Some("Dedi"));

        // Without a new secret the old one stays; without a fingerprint the certificate must be valid on its own.
        dir.save_proxmox(ProxmoxInput { id: Some(id.clone()), secret: None, ..pve("Dedi 2") }).unwrap();
        let access = dir.proxmox_access(&id).unwrap();
        assert_eq!((access.secret.expose(), access.fingerprint, dir.snapshot().proxmox[0].name.as_str()), ("0c6f2c1e-58a1", None, "Dedi 2"));
        dir.save_proxmox(ProxmoxInput { id: Some(id.clone()), secret: Some(Secret::new(" neu ".into())), ..pve("Dedi") }).unwrap();
        assert_eq!(dir.proxmox_access(&id).unwrap().secret.expose(), "neu");

        assert_eq!(reason(dir.save_proxmox(pve(" "))), Invalid::NameRequired);
        for address in ["http://pve.example.de:8006", "pve.example.de:8006", "https://", "https://pve.example.de/pfad", "https://a b", "https://ich@pve"] {
            assert_eq!(reason(dir.save_proxmox(ProxmoxInput { address: address.into(), ..pve("x") })), Invalid::AddressInvalid, "{address}");
        }
        for token in ["glowport", "glowport@pve", "@pve!x", "a@!x", "a@pve!", "a b@pve!x", "ä@pve!x"] {
            assert_eq!(reason(dir.save_proxmox(ProxmoxInput { token_id: token.into(), ..pve("x") })), Invalid::TokenInvalid, "{token}");
        }
        assert_eq!(reason(dir.save_proxmox(ProxmoxInput { secret: None, ..pve("x") })), Invalid::SecretRequired);
        assert_eq!(reason(dir.save_proxmox(ProxmoxInput { secret: Some(Secret::new("  ".into())), ..pve("x") })), Invalid::SecretRequired);
        assert_eq!(reason(dir.save_proxmox(ProxmoxInput { secret: Some(Secret::new("zeile\r\nX-Kopf: 1".into())), ..pve("x") })), Invalid::TokenInvalid);
        for fingerprint in ["5F:1A", &FINGERPRINT[..94], &FINGERPRINT.replace("5F", "ZZ")] {
            assert_eq!(reason(dir.save_proxmox(ProxmoxInput { fingerprint: Some(fingerprint.into()), ..pve("x") })), Invalid::FingerprintInvalid, "{fingerprint}");
        }
        assert!(matches!(dir.save_proxmox(ProxmoxInput { id: Some("00".repeat(16)), ..pve("x") }), Err(DirError::NotFound)));
        assert_eq!(dir.snapshot().proxmox.len(), 1, "nichts Abgelehntes ist angekommen");
    }

    #[test]
    fn machines_become_linked_hosts_in_the_personal_vault() {
        let temp = Temp::new("pve-hosts");
        let (mut dir, shared) = with_shared(&temp);
        let connection = dir.save_proxmox(pve("Dedi")).unwrap();
        let deploy = dir.add_key(key("deploy")).unwrap();
        assert_eq!(dir.key_by_fingerprint("SHA256:deploy"), Some((deploy.as_str(), "deploy")));
        assert_eq!(dir.key_by_fingerprint("SHA256:fremd"), None);
        let own_group = dir.save_group(group("Proxmox", None)).unwrap();
        let team_group = dir.in_vault(Some(&shared), |dir| dir.save_group(group("Team", None))).unwrap();

        let web = GuestHost { user: Some("deploy".into()), key: Some(deploy.clone()), os: Some("Ub".into()), ..guest(101, "web-01", Some("10.0.10.11")) };
        let container = GuestHost { kind: model::GUEST_LXC.into(), user: Some("root".into()), key: Some("gibt-es-nicht".into()), ..guest(111, "pihole", Some("10.0.0.53")) };
        // Even if entries were currently being created in a shared vault: these hosts go into the personal one.
        let made = dir.in_vault(Some(&shared), |dir| dir.add_proxmox_hosts(&connection, vec![web.clone(), container, guest(130, "spielwiese", None)], Some(&own_group))).unwrap();
        assert_eq!(made.len(), 3);
        let snapshot = dir.snapshot();
        assert!(made.iter().all(|id| !snapshot.homes.contains_key(id)));
        let by = |name: &str| snapshot.hosts.iter().find(|h| h.name == name).unwrap();
        let link = |vmid: u32, kind: &str| Some(LinkView { connection: connection.clone(), node: "pve".into(), vmid, kind: kind.into() });
        assert_eq!((by("web-01").address.as_str(), by("web-01").group.as_deref(), by("web-01").os.as_deref(), by("web-01").own.user.as_deref(), by("web-01").own.key.as_deref()), ("10.0.10.11", Some(own_group.as_str()), Some("Ub"), Some("deploy"), Some(deploy.as_str())));
        assert_eq!((&by("web-01").proxmox, &by("pihole").proxmox), (&link(101, "qemu"), &link(111, "lxc")));
        assert_eq!(by("pihole").own.key, None, "ein Schlüssel, den es nicht gibt, wird nicht eingetragen");
        assert_eq!(by("spielwiese").address, "spielwiese", "ohne bekannte Adresse steht vorerst der Name da");
        assert_eq!(dir.proxmox_host(&connection, 111), Some(by("pihole").id.as_str()));
        assert_eq!(dir.proxmox_host(&connection, 999), None);

        // Whoever already has a host gets no second one. If one fails, none is created.
        assert_eq!(dir.add_proxmox_hosts(&connection, vec![web.clone(), guest(120, "monitoring", Some("10.0.10.90"))], None).unwrap().len(), 1);
        assert_eq!(reason(dir.add_proxmox_hosts(&connection, vec![guest(140, "neu", Some("10.0.0.9")), guest(141, "kaputt", Some("a b"))], None)), Invalid::AddressInvalid);
        assert_eq!(reason(dir.add_proxmox_hosts(&connection, vec![GuestHost { kind: "docker".into(), ..guest(142, "x", Some("10.0.0.8")) }], None)), Invalid::GuestInvalid);
        assert_eq!(reason(dir.add_proxmox_hosts(&connection, vec![guest(143, "x", Some("10.0.0.7"))], Some(&team_group))), Invalid::OtherVault);
        assert_eq!(reason(dir.add_proxmox_hosts(&connection, vec![guest(143, "x", Some("10.0.0.7"))], Some("gibt-es-nicht"))), Invalid::GroupMissing);
        assert!(matches!(dir.add_proxmox_hosts(&"00".repeat(16), vec![guest(143, "x", Some("10.0.0.7"))], None), Err(DirError::NotFound)));
        assert_eq!(dir.snapshot().hosts.len(), 4);

        // A host's copy belongs to no machine; neither does a host that moves into a shared vault.
        let web_id = by("web-01").id.clone();
        let copy = dir.duplicate_host(&web_id, "web-01 Kopie").unwrap();
        let moved = dir.move_host(&by("pihole").id, &shared, false).unwrap();
        let snapshot = dir.snapshot();
        let view = |id: &str| snapshot.hosts.iter().find(|h| h.id == id).unwrap();
        assert_eq!((&view(&copy).proxmox, &view(&moved).proxmox, &view(&web_id).proxmox), (&None, &None, &link(101, "qemu")));
        assert_eq!(dir.proxmox_host(&connection, 111), None);

        // Editing leaves the link in place, unlinking removes it and nothing else.
        dir.save_host(HostInput { id: Some(web_id.clone()), color: Some("#ff0000".into()), address: "10.0.10.11".into(), ..host("web-01", None) }).unwrap();
        assert_eq!(dir.snapshot().hosts.iter().find(|h| h.id == web_id).unwrap().proxmox, link(101, "qemu"));
        dir.unlink_proxmox(&web_id).unwrap();
        dir.unlink_proxmox(&web_id).unwrap();
        let snapshot = dir.snapshot();
        let unlinked = snapshot.hosts.iter().find(|h| h.id == web_id).unwrap();
        assert_eq!((&unlinked.proxmox, unlinked.color.as_deref(), unlinked.address.as_str()), (&None, Some("#FF0000"), "10.0.10.11"));

        // What another member puts into a shared vault does not count: neither a connection nor the
        // link of a host there.
        let foreign = serde_json::to_vec(&serde_json::json!({ "t": "proxmox", "name": "Fremd", "address": "https://boese.example", "tokenId": "a@pve!b", "secret": "x" })).unwrap();
        let linked = serde_json::to_vec(&serde_json::json!({ "t": "host", "name": "untergeschoben", "address": "10.9.9.9", "proxmox": { "connection": connection, "node": "pve", "vmid": 555, "kind": "qemu" } })).unwrap();
        let shared_id = parse_id(&shared).unwrap();
        dir.vault.put_in(&shared_id, &foreign).unwrap();
        dir.vault.put_in(&shared_id, &linked).unwrap();
        dir.refresh().unwrap();
        let snapshot = dir.snapshot();
        assert_eq!(snapshot.proxmox.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(), ["Dedi"]);
        assert_eq!((snapshot.hosts.iter().find(|h| h.name == "untergeschoben").unwrap().proxmox.clone(), dir.proxmox_host(&connection, 555)), (None, None));
        assert!(!dir.follow_proxmox(&connection, &[seen(555, "umbenannt", Some("10.6.6.6"))]).unwrap());

        // The links disappear with the connection, the hosts stay.
        let before = dir.snapshot().hosts.len();
        dir.delete_proxmox(&connection).unwrap();
        let snapshot = dir.snapshot();
        assert_eq!((snapshot.proxmox.len(), snapshot.hosts.len(), snapshot.hosts.iter().filter(|h| h.proxmox.is_some()).count()), (0, before, 0));
        assert!(dir.hosts.values().all(|h| h.proxmox.is_none()), "auch im Tresor steht keine mehr");
        assert_eq!(dir.damaged, 0);
        assert!(matches!(dir.delete_proxmox(&connection), Err(DirError::NotFound)));
    }

    #[test]
    fn a_connection_names_the_identity_for_its_machines() {
        let temp = Temp::new("pve-identity");
        let mut dir = temp.directory();
        let own = dir.add_key(key("mein")).unwrap();
        let cloud = dir.add_key(key("cloud")).unwrap();
        let admin = dir.save_identity(IdentityInput { password: Some(Some(Secret::new("hunter2".into()))), ..identity("Admin", "alex", Some(&own)) }).unwrap();
        assert_eq!(reason(dir.save_proxmox(ProxmoxInput { identity: Some("gibt-es-nicht".into()), ..pve("x") })), Invalid::IdentityMissing);
        let connection = dir.save_proxmox(ProxmoxInput { identity: Some(admin.clone()), ..pve("Dedi") }).unwrap();
        assert_eq!(dir.snapshot().proxmox[0].identity.as_deref(), Some(admin.as_str()));

        // Cloud-Init names a key from the vault: Cloud-Init applies. Otherwise the identity applies as a whole,
        // even before the user Proxmox assumes for the machine.
        let with_key = GuestHost { user: Some("deploy".into()), key: Some(cloud.clone()), ..guest(101, "shop", Some("10.0.10.11")) };
        let without = GuestHost { user: Some("root".into()), ..guest(111, "pihole", Some("10.0.0.53")) };
        let made = dir.add_proxmox_hosts(&connection, vec![with_key, without], None).unwrap();
        let snapshot = dir.snapshot();
        let own_of = |id: &str| snapshot.hosts.iter().find(|h| h.id == id).unwrap().own.clone();
        assert_eq!(own_of(&made[0]), Fields { user: Some("deploy".into()), key: Some(cloud.clone()), ..Fields::default() });
        assert_eq!(own_of(&made[1]), Fields { identity: Some(admin.clone()), ..Fields::default() });
        let info = dir.connect_info(&made[1]).unwrap();
        assert_eq!((info.user.as_str(), info.key.as_ref().map(|k| k.expose().contains("mein")), info.password.as_ref().map(Secret::expose)), ("alex", Some(true), Some("hunter2")));

        // Without a saved host: the identity, or just a key; a named key takes precedence.
        let login = dir.login(Some(&admin), None).unwrap();
        assert_eq!((login.user.as_deref(), login.key.as_ref().map(|k| k.expose().contains("mein")), login.password.as_ref().map(Secret::expose)), (Some("alex"), Some(true), Some("hunter2")));
        let login = dir.login(None, Some(&cloud)).unwrap();
        assert_eq!((login.user, login.key.as_ref().map(|k| k.expose().contains("cloud")), login.password), (None, Some(true), None));
        assert_eq!(dir.login(Some(&admin), Some(&cloud)).unwrap().key.map(|k| k.expose().contains("cloud")), Some(true));
        assert_eq!(dir.login(None, None).unwrap(), Login::default());
        assert_eq!((reason(dir.login(Some("fehlt"), None)), reason(dir.login(None, Some("fehlt")))), (Invalid::IdentityMissing, Invalid::KeyMissing));

        // Editing without an identity removes it; a deleted identity also disappears from the connection.
        dir.save_proxmox(ProxmoxInput { id: Some(connection.clone()), secret: None, ..pve("Dedi") }).unwrap();
        assert_eq!(dir.snapshot().proxmox[0].identity, None);
        dir.save_proxmox(ProxmoxInput { id: Some(connection.clone()), secret: None, identity: Some(admin.clone()), ..pve("Dedi") }).unwrap();
        dir.delete_identity(&admin).unwrap();
        assert_eq!((dir.snapshot().proxmox[0].identity.clone(), dir.proxmox.get(&connection).unwrap().identity.clone()), (None, None));
        // Without identity and key, the user Proxmox names remains.
        let plain = dir.add_proxmox_hosts(&connection, vec![GuestHost { user: Some("root".into()), ..guest(112, "gitea", Some("10.0.10.74")) }], None).unwrap();
        assert_eq!(dir.snapshot().hosts.iter().find(|h| h.id == plain[0]).unwrap().own, Fields { user: Some("root".into()), ..Fields::default() });
    }

    #[test]
    fn linked_hosts_follow_proxmox_until_changed_by_hand() {
        let temp = Temp::new("pve-follow");
        let mut dir = temp.directory();
        let connection = dir.save_proxmox(pve("Dedi")).unwrap();
        let other = dir.save_proxmox(pve("Zweiter")).unwrap();
        let made = dir.add_proxmox_hosts(&connection, vec![guest(101, "web-01", Some("10.0.10.11")), guest(102, "db-01", Some("10.0.20.21")), guest(130, "spielwiese", None)], None).unwrap();
        let (web, db, sandbox) = (made[0].clone(), made[1].clone(), made[2].clone());
        dir.add_proxmox_hosts(&other, vec![guest(101, "fremd", Some("192.168.1.1"))], None).unwrap();
        let shown = |dir: &Directory, id: &str| dir.hosts.get(id).map(|h| (h.name.clone(), h.address.clone())).unwrap();
        let writes = |dir: &Directory| dir.vault.writes();

        // Nothing changed: nothing is written, not even on the hundredth refresh.
        let same = [seen(101, "web-01", Some("10.0.10.11")), seen(102, "db-01", Some("10.0.20.21")), seen(130, "spielwiese", None)];
        let before = writes(&dir);
        assert!(!dir.follow_proxmox(&connection, &same).unwrap());
        assert_eq!(writes(&dir), before);

        // Name and address change in Proxmox: the hosts follow. The machine without an address gets one
        // as soon as Proxmox knows it. The other connection has a machine with the same number; it stays.
        let renamed = [seen(101, "web-prod", Some("10.0.10.12")), seen(102, "db-01", Some("10.0.20.21")), seen(130, "spielwiese", Some("10.0.10.77"))];
        assert!(dir.follow_proxmox(&connection, &renamed).unwrap());
        assert_eq!(shown(&dir, &web), ("web-prod".into(), "10.0.10.12".into()));
        assert_eq!(shown(&dir, &sandbox), ("spielwiese".into(), "10.0.10.77".into()));
        assert_eq!(dir.hosts.values().find(|h| h.name == "fremd").map(|h| h.address.as_str()), Some("192.168.1.1"));
        assert!(!dir.follow_proxmox(&connection, &renamed).unwrap(), "ein zweites Mal ändert nichts");

        // Changed by hand: the name stays, the address keeps following. And the other way round.
        dir.save_host(HostInput { id: Some(web.clone()), ..HostInput { address: "10.0.10.12".into(), ..host("Mein Webserver", None) } }).unwrap();
        dir.save_host(HostInput { id: Some(db.clone()), ..HostInput { address: "db.intern".into(), ..host("db-01", None) } }).unwrap();
        let later = [seen(101, "web-neu", Some("10.0.10.13")), seen(102, "db-neu", Some("10.0.20.99")), seen(130, "spielwiese", None)];
        assert!(dir.follow_proxmox(&connection, &later).unwrap());
        assert_eq!(shown(&dir, &web), ("Mein Webserver".into(), "10.0.10.13".into()));
        assert_eq!(shown(&dir, &db), ("db-neu".into(), "db.intern".into()));
        assert_eq!(shown(&dir, &sandbox).1, "10.0.10.77", "ohne Adresse in Proxmox bleibt die letzte bekannte");

        // Moved to another node: recognised by its number. Unusable data from Proxmox stays out.
        let moved = [GuestSeen { node: "pve2".into(), ..seen(101, " ", Some("a b")) }, seen(102, "db-neu", Some("10.0.20.99"))];
        assert!(dir.follow_proxmox(&connection, &moved).unwrap());
        assert_eq!(dir.snapshot().hosts.iter().find(|h| h.id == web).unwrap().proxmox.as_ref().map(|link| link.node.as_str()), Some("pve2"));
        assert_eq!(shown(&dir, &web), ("Mein Webserver".into(), "10.0.10.13".into()));

        // A machine that no longer exists in Proxmox: the host stays as it is, link included.
        assert!(!dir.follow_proxmox(&connection, &[]).unwrap());
        assert_eq!(dir.snapshot().hosts.iter().filter(|h| h.proxmox.is_some()).count(), 4);

        // A link whose connection is missing (deleted on another device) does not count.
        dir.vault.delete(&parse_id(&other).unwrap()).unwrap();
        dir.refresh().unwrap();
        let snapshot = dir.snapshot();
        assert_eq!(snapshot.hosts.iter().find(|h| h.name == "fremd").unwrap().proxmox, None);
        assert_eq!(dir.proxmox_host(&other, 101), None);
        assert!(!dir.follow_proxmox(&other, &[seen(101, "anders", Some("192.168.1.2"))]).unwrap());
    }
}

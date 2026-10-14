//! Content of the records: hosts, groups, known hosts, keys, identities and workspaces. Structure see `docs/vault.md`,
//! section “Records”.
//!
//! Rule for all kinds: unknown fields are kept (`extra`), so an older version of the program
//! throws away nothing a newer one saved.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use zeroize::Zeroize;

/// Secret that never ends up in logs and is overwritten when dropped.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: String) -> Self {
        Self(value)
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(…)")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Reconnect {
    Notice,
    Auto,
}

/// Inheritable values. `None` means: not set here, the value comes from further up.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Fields {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// ID of the jump host. Empty means “explicitly none” and overrides an inherited default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jump: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub startcmd: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconnect: Option<Reconnect>,
    /// Path of a key file on this machine, for keys that should not live in the vault.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_file: Option<String>,
    /// ID of an identity. Empty means “explicitly none”.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    /// ID of a key in the vault. Empty means “explicitly none”.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Environment variables for the shell in `SetEnv` notation: `NAME=value`, several separated by spaces,
    /// values with spaces in quotes. See [`parse_env`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<String>,
    /// Offer keys from an SSH agent on this machine for signing in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<bool>,
    /// Forward the agent to the server. Only has an effect together with `agent`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_forward: Option<bool>,
    /// Proxy as `http://address:port` or `socks5://address:port`, optionally with `user@` in front. Empty means
    /// “explicitly none”. The password for it is not here but stored as a secret on the host or group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
    /// Keepalive interval in seconds; 0 switches it off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive: Option<u16>,
    /// Seconds to wait for the connection to be established.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u16>,
    /// Terminal type the shell sees as `TERM`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub term: Option<String>,
    /// The server's character set, one of [`CHARSETS`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub charset: Option<String>,
    /// Also offer algorithms considered weak today, for old devices.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy: Option<bool>,
    /// ID of a terminal color scheme. Only the interface knows the schemes themselves.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    /// Run the terminal over Mosh; signing in still happens over SSH.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mosh: Option<bool>,
    /// Mosh's local echo, one of [`MOSH_PREDICT`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mosh_predict: Option<String>,
    /// UDP port or range for `mosh-server`, see [`valid_mosh_port`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mosh_port: Option<String>,
    /// Path to `mosh-server` on the server, see [`valid_mosh_server`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mosh_server: Option<String>,
}

/// Settings for Mosh's local echo; the first one is the default.
pub const MOSH_PREDICT: [&str; 3] = ["adaptive", "always", "never"];

/// UDP port or range for `mosh-server -p`: `60001` or `60001:60010`, ascending, without port 0.
pub fn valid_mosh_port(text: &str) -> bool {
    let port = |part: &str| part.len() <= 5 && part.chars().all(|c| c.is_ascii_digit()) && part.parse::<u16>().is_ok_and(|p| p > 0);
    match text.split_once(':') {
        None => port(text),
        Some((low, high)) => port(low) && port(high) && low.parse::<u16>().ok() <= high.parse::<u16>().ok(),
    }
}

/// Path to `mosh-server`. It goes unchanged into a command on the server: no spaces and nothing the
/// shell there would interpret (except `~` for the home directory).
pub fn valid_mosh_server(text: &str) -> bool {
    !text.is_empty() && text.chars().count() <= 200 && text.chars().all(|c| !c.is_whitespace() && !c.is_control() && !r#";&|`$<>()'"\*?!{}[]#="#.contains(c))
}

pub const DEFAULT_KEEPALIVE: u16 = 30;
pub const DEFAULT_TIMEOUT: u16 = 15;
pub const DEFAULT_TERM: &str = "xterm-256color";
pub const DEFAULT_CHARSET: &str = "utf-8";
/// Character sets to choose from. The first is the default and needs no conversion.
pub const CHARSETS: [&str; 12] = ["utf-8", "iso-8859-1", "iso-8859-15", "windows-1252", "windows-1250", "windows-1251", "koi8-r", "ibm866", "gbk", "big5", "shift_jis", "euc-kr"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyKind {
    Http,
    Socks5,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxySpec {
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
    /// User for signing in to the proxy.
    pub user: Option<String>,
}

/// Reads `http://address:port` or `socks5://address:port`, optionally with `user@` before the address. Without a port
/// 8080 or 1080 applies; IPv6 addresses are in square brackets. A password in the address (`user:password@…`)
/// is rejected: inheritable values travel to the interface, passwords do not.
pub fn parse_proxy(text: &str) -> Option<ProxySpec> {
    let (scheme, rest) = text.trim().split_once("://")?;
    let (kind, default_port) = match scheme.to_ascii_lowercase().as_str() {
        "http" => (ProxyKind::Http, 8080),
        "socks5" | "socks5h" | "socks" => (ProxyKind::Socks5, 1080),
        _ => return None,
    };
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    let (user, rest) = match rest.rsplit_once('@') {
        Some((user, rest)) => (Some(user), rest),
        None => (None, rest),
    };
    if user.is_some_and(|u| u.is_empty() || u.len() > 255 || u.chars().any(|c| c == ':' || c.is_whitespace() || c.is_control())) {
        return None;
    }
    let (host, port) = match rest.strip_prefix('[') {
        Some(bracketed) => {
            let (host, after) = bracketed.split_once(']')?;
            (host, after.strip_prefix(':'))
        }
        None => match rest.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (rest, None),
        },
    };
    let port = match port {
        Some(port) => port.parse().ok().filter(|p| *p != 0)?,
        None => default_port,
    };
    let safe = !host.is_empty() && !host.starts_with('-') && host.len() <= 255 && !host.chars().any(|c| c.is_whitespace() || c.is_control() || matches!(c, '@' | '/' | '[' | ']'));
    safe.then(|| ProxySpec { kind, host: host.to_string(), port, user: user.map(str::to_string) })
}

/// Splits environment variables in `SetEnv` notation. `None` if a part is not `NAME=value`,
/// a name has invalid characters or a quote stays open.
pub fn parse_env(text: &str) -> Option<Vec<(String, String)>> {
    let mut pairs = Vec::new();
    let mut rest = text.trim_start();
    while !rest.is_empty() {
        let (name, after) = rest.split_once('=')?;
        let valid = name.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_') && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !valid {
            return None;
        }
        let (value, tail) = match after.strip_prefix('"') {
            // After the closing quote there must be a space or the end.
            Some(quoted) => quoted.split_once('"').filter(|(_, tail)| tail.is_empty() || tail.starts_with(char::is_whitespace))?,
            None => after.split_once(char::is_whitespace).unwrap_or((after, "")),
        };
        if value.chars().any(char::is_control) {
            return None;
        }
        pairs.push((name.to_string(), value.to_string()));
        rest = tail.trim_start();
    }
    Some(pairs)
}

fn one() -> u32 {
    1
}

fn ssh() -> String {
    "ssh".into()
}

/// Protocols a host is reached with. If a host carries something else, a newer version of the program
/// saved it; it then stays, but cannot be connected to.
pub const PROTOCOL_SSH: &str = "ssh";
pub const PROTOCOL_TELNET: &str = "telnet";
pub const PROTOCOL_SERIAL: &str = "serial";
/// No terminal: an FTP host opens in the file manager.
pub const PROTOCOL_FTP: &str = "ftp";
pub const PROTOCOLS: [&str; 4] = [PROTOCOL_SSH, PROTOCOL_TELNET, PROTOCOL_SERIAL, PROTOCOL_FTP];

pub const DEFAULT_TELNET_PORT: u16 = 23;
pub const DEFAULT_FTP_PORT: u16 = 21;
/// Implicit FTPS has its own port.
pub const DEFAULT_FTPS_PORT: u16 = 990;
/// Under this algorithm a server's confirmed certificate is listed with the known hosts.
pub const ALGORITHM_TLS: &str = "tls";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FtpSecurity {
    /// The connection starts in the clear and switches to TLS before signing in.
    Explicit,
    /// TLS from the start.
    Implicit,
    /// Unencrypted: password and files are readable along the way.
    None,
}

/// An FTP host's settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ftp {
    pub security: FtpSecurity,
    /// Sign in without user and password.
    #[serde(default)]
    pub anonymous: bool,
    /// Folder the file manager starts in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dir: Option<String>,
    /// The question before an unencrypted connection is switched off for this host.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub plain_ok: bool,
}

impl Ftp {
    pub fn default_port(&self) -> u16 {
        if self.security == FtpSecurity::Implicit {
            DEFAULT_FTPS_PORT
        } else {
            DEFAULT_FTP_PORT
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Parity {
    None,
    Odd,
    Even,
}

/// Flow control of a serial line: none, XON/XOFF or RTS/CTS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Flow {
    None,
    Software,
    Hardware,
}

/// Settings of a serial line. The usual “9600 8N1” is 9600 baud, 8 data bits, no parity,
/// 1 stop bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Serial {
    pub baud: u32,
    pub data_bits: u8,
    pub parity: Parity,
    pub stop_bits: u8,
    pub flow: Flow,
}

pub const MIN_BAUD: u32 = 50;
pub const MAX_BAUD: u32 = 4_000_000;

impl Serial {
    pub fn baud_valid(&self) -> bool {
        (MIN_BAUD..=MAX_BAUD).contains(&self.baud)
    }

    /// Does such a frame exist? 5 to 8 data bits, 1 or 2 stop bits.
    pub fn frame_valid(&self) -> bool {
        (5..=8).contains(&self.data_bits) && (1..=2).contains(&self.stop_bits)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Group {
    #[serde(default = "one")]
    pub v: u32,
    pub name: String,
    #[serde(default)]
    pub parent: Option<String>,
    #[serde(default)]
    pub color: Option<String>,
    #[serde(default)]
    pub defs: Fields,
    /// Password for the proxy this group sets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_password: Option<Secret>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Host {
    #[serde(default = "one")]
    pub v: u32,
    pub name: String,
    /// Address of the server; for a serial line the name of the port (`COM3`, `/dev/ttyUSB0`).
    pub address: String,
    #[serde(default)]
    pub group: Option<String>,
    /// One of [`PROTOCOLS`].
    #[serde(default = "ssh")]
    pub protocol: String,
    /// Settings of the line; only for [`PROTOCOL_SERIAL`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<Serial>,
    /// FTP settings; only for [`PROTOCOL_FTP`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ftp: Option<Ftp>,
    #[serde(default)]
    pub color: Option<String>,
    /// Short name of the operating system for the icon. It is detected when connecting.
    #[serde(default)]
    pub os: Option<String>,
    /// What the host sets itself. Everything else comes from the group path.
    #[serde(default)]
    pub own: Fields,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<Secret>,
    /// Password for the proxy this host sets itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_password: Option<Secret>,
    /// The Proxmox machine this host belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxmox: Option<ProxmoxLink>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Kinds of Proxmox machines: a VM or a container.
pub const GUEST_QEMU: &str = "qemu";
pub const GUEST_LXC: &str = "lxc";
pub const GUEST_KINDS: [&str; 2] = [GUEST_QEMU, GUEST_LXC];

/// Which Proxmox machine a host belongs to (`docs/management.md`, “Creating hosts and keeping them up to date”).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxmoxLink {
    /// ID of the connection in the vault.
    pub connection: String,
    /// The node the machine was last on. It is recognised by its number.
    pub node: String,
    pub vmid: u32,
    /// One of [`GUEST_KINDS`].
    pub kind: String,
    /// Name and address Glowport last gave the host itself. Only while the host still carries them
    /// does it follow when they change in Proxmox; what the user changed on the host stays.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A connection to a Proxmox server via an API token. It lives in the personal vault.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Proxmox {
    #[serde(default = "one")]
    pub v: u32,
    pub name: String,
    /// `https://pve.example.de:8006`
    pub address: String,
    /// Token ID: `user@realm!name`.
    pub token_id: String,
    /// The token's secret.
    pub secret: Secret,
    /// The confirmed fingerprint (SHA-256) of a self-signed certificate, as Proxmox shows it
    /// (`5F:1A:…`). If missing, the server's certificate must be trusted on its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// ID of the identity Glowport uses to sign in to this connection's machines when Cloud-Init
    /// names no key from the vault for a machine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A server key the user has trusted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KnownHost {
    #[serde(default = "one")]
    pub v: u32,
    /// Address as used when connecting, in lower case.
    pub host: String,
    pub port: u16,
    pub algorithm: String,
    /// Fingerprint as in OpenSSH (`SHA256:…`), for display only.
    pub fingerprint: String,
    /// Public key in OpenSSH format without comment. The server is recognised by it.
    pub key: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyKind {
    Ed25519,
    Ecdsa,
    Rsa,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyOrigin {
    Generated,
    Imported,
}

/// User certificate for a key: a certificate authority confirms who it belongs to. Times in
/// seconds since 1970. None of it is secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyCertificate {
    /// The line in OpenSSH format without comment.
    pub text: String,
    /// Name the certificate authority gave the certificate.
    pub key_id: String,
    /// User names it applies to. Empty means: for everyone.
    pub principals: Vec<String>,
    pub valid_after: u64,
    /// Missing if it does not expire.
    #[serde(default)]
    pub valid_before: Option<u64>,
    /// Fingerprint of the certificate authority.
    pub authority: String,
}

/// A key pair. The private part carries no passphrase of its own; the vault's encryption protects it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Key {
    #[serde(default = "one")]
    pub v: u32,
    pub name: String,
    pub kind: KeyKind,
    /// Length in bits: Ed25519 256, ECDSA 256/384/521, RSA as generated.
    pub bits: u32,
    /// Fingerprint as in OpenSSH (`SHA256:…`), for display only.
    pub fingerprint: String,
    /// Public key in OpenSSH format without comment.
    pub public: String,
    /// Private key in OpenSSH format, unencrypted.
    pub private: Secret,
    pub origin: KeyOrigin,
    /// Time of generation or import in milliseconds since 1970.
    pub added_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<KeyCertificate>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// User together with key and/or password, referred to by hosts and groups.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    #[serde(default = "one")]
    pub v: u32,
    pub name: String,
    pub user: String,
    /// ID of a key in the vault.
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<Secret>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A certificate authority whose certificates apply to servers, like `@cert-authority` in `known_hosts`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Authority {
    #[serde(default = "one")]
    pub v: u32,
    pub name: String,
    /// Addresses it applies to. See [`pattern_matches`].
    pub pattern: String,
    /// Kind of key for display, e.g. “Ed25519”.
    pub label: String,
    pub fingerprint: String,
    /// Public key in OpenSSH format without comment.
    pub public: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Does an address match a pattern? `*` stands for any number of characters, `?` for exactly one; several patterns
/// are separated by commas. Case does not matter.
pub fn pattern_matches(pattern: &str, host: &str) -> bool {
    fn glob(pattern: &[char], text: &[char]) -> bool {
        match pattern.split_first() {
            None => text.is_empty(),
            Some(('*', rest)) => (0..=text.len()).any(|skip| glob(rest, &text[skip..])),
            Some((expected, rest)) => text.split_first().is_some_and(|(found, tail)| (*expected == '?' || expected == found) && glob(rest, tail)),
        }
    }
    let host: Vec<char> = host.to_lowercase().chars().collect();
    pattern.split(',').map(str::trim).filter(|part| !part.is_empty()).any(|part| glob(&part.to_lowercase().chars().collect::<Vec<_>>(), &host))
}

/// Direction in which an area is split: `Row` puts the parts side by side, `Col` on top of each other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Split {
    Row,
    Col,
}

/// What a workspace pane shows: a saved host or a local terminal. `shell` is
/// the ID of a shell on this machine (`pwsh`, `wsl:Ubuntu`); the vault does not know which ones exist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum PaneTarget {
    Host { id: String },
    Local { shell: String },
}

/// Longest shell ID a workspace accepts.
pub const MAX_SHELL_ID: usize = 80;

/// Layout of a workspace's panes: a tree whose nodes cut their area in two.
/// The interface uses the same form for open tabs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Arrangement {
    Split {
        dir: Split,
        /// Share of the first part, between 0 and 1.
        ratio: f64,
        a: Box<Arrangement>,
        b: Box<Arrangement>,
    },
    Pane {
        pane: PaneTarget,
    },
}

/// A workspace takes no more panes. Also protects against arbitrarily deep trees from foreign data.
pub const MAX_PANES: usize = 32;

impl Arrangement {
    /// IDs of the hosts in the order of their panes.
    pub fn hosts(&self) -> Vec<&str> {
        match self {
            Self::Pane { pane: PaneTarget::Host { id } } => vec![id.as_str()],
            Self::Pane { pane: PaneTarget::Local { .. } } => Vec::new(),
            Self::Split { a, b, .. } => [a.hosts(), b.hosts()].concat(),
        }
    }

    /// Number of panes, local terminals included.
    pub fn panes(&self) -> usize {
        match self {
            Self::Pane { .. } => 1,
            Self::Split { a, b, .. } => a.panes() + b.panes(),
        }
    }

    /// The same layout with only the hosts `keep` keeps; their neighbour takes over the freed area.
    /// Local terminals stay as long as their ID looks like one. `None` if no pane is left.
    /// The ratio is pulled into a usable range on the way.
    pub fn retain(&self, keep: &impl Fn(&str) -> bool) -> Option<Self> {
        match self {
            Self::Pane { pane: PaneTarget::Host { id } } => keep(id).then(|| self.clone()),
            Self::Pane { pane: PaneTarget::Local { shell } } => (!shell.is_empty() && shell.chars().count() <= MAX_SHELL_ID && !shell.chars().any(char::is_control)).then(|| self.clone()),
            Self::Split { dir, ratio, a, b } => match (a.retain(keep), b.retain(keep)) {
                (Some(a), Some(b)) => Some(Self::Split { dir: *dir, ratio: if ratio.is_finite() { ratio.clamp(0.05, 0.95) } else { 0.5 }, a: Box::new(a), b: Box::new(b) }),
                (one, other) => one.or(other),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Workspace {
    #[serde(default = "one")]
    pub v: u32,
    pub name: String,
    /// Switch on multi-exec when opening: input goes to all panes.
    #[serde(default)]
    pub multi: bool,
    pub layout: Arrangement,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Direction of a port rule. `Local`: a port on this machine leads through the server to a destination.
/// `Remote`: a port on the server leads back to a destination this machine reaches.
/// `Dynamic`: a SOCKS proxy on this machine that goes out to the network through the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ForwardKind {
    Local,
    Remote,
    Dynamic,
}

/// A saved port rule. Whether it is running is not stored in the vault.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Forward {
    #[serde(default = "one")]
    pub v: u32,
    pub name: String,
    pub kind: ForwardKind,
    /// ID of the host the rule runs through.
    pub host: String,
    /// Address to listen on: on this machine (local, dynamic) or on the server (remote).
    pub bind_address: String,
    pub bind_port: u16,
    /// Where the connections go, as seen from the other end. Empty for `Dynamic`.
    #[serde(default)]
    pub dest_host: String,
    #[serde(default)]
    pub dest_port: u16,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SnippetKind {
    /// A command, multi-line allowed, with variables like `{{name}}`.
    Command,
    /// Recorded keys that are typed again the same way.
    Macro,
}

/// One step of a macro: wait this long, then send these keys.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacroStep {
    /// Milliseconds since the previous step.
    pub wait: u32,
    pub keys: String,
}

// A macro contains everything that was typed, possibly a password: the keys appear in no output.
impl fmt::Debug for MacroStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MacroStep {{ wait: {}, keys: <{} characters> }}", self.wait, self.keys.chars().count())
    }
}

/// A saved command or a recorded macro.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Snippet {
    #[serde(default = "one")]
    pub v: u32,
    pub name: String,
    /// Name of the package it lives in; empty = none.
    #[serde(default)]
    pub package: String,
    pub kind: SnippetKind,
    #[serde(default)]
    pub command: String,
    #[serde(default)]
    pub steps: Vec<MacroStep>,
    /// Hotkey in fixed notation, e.g. “Ctrl+Alt+R”. See [`valid_hotkey`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hotkey: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Shortcuts Glowport or Windows use themselves. The interface keeps the same list (`snippets.ts`).
const RESERVED_HOTKEYS: [&str; 9] = ["Ctrl+Shift+W", "Ctrl+Shift+D", "Ctrl+Shift+E", "Ctrl+Shift+M", "Ctrl+Shift+F", "Ctrl+Shift+C", "Ctrl+Shift+V", "Ctrl+0", "Alt+F4"];

/// Whether a hotkey can be assigned to a snippet. The notation is fixed: first `Ctrl`, `Alt`, `Shift`
/// in this order, then a letter, a digit or F1 to F12. Allowed is whatever takes nothing away from the
/// shell: with Alt, with Ctrl+Shift, or Ctrl with a digit or function key.
pub fn valid_hotkey(hotkey: &str) -> bool {
    let mut parts: Vec<&str> = hotkey.split('+').collect();
    let Some(key) = parts.pop() else { return false };
    let letter = key.len() == 1 && key.chars().all(|c| c.is_ascii_uppercase());
    let digit = key.len() == 1 && key.chars().all(|c| c.is_ascii_digit());
    let function = key.strip_prefix('F').and_then(|n| n.parse::<u8>().ok()).is_some_and(|n| (1..=12).contains(&n) && key == format!("F{n}"));
    if !(letter || digit || function) {
        return false;
    }
    // Every modifier at most once and in the fixed order.
    let order = ["Ctrl", "Alt", "Shift"];
    let places: Option<Vec<usize>> = parts.iter().map(|part| order.iter().position(|known| known == part)).collect();
    let Some(places) = places else { return false };
    if !places.windows(2).all(|pair| pair[0] < pair[1]) {
        return false;
    }
    let (ctrl, alt, shift) = (parts.contains(&"Ctrl"), parts.contains(&"Alt"), parts.contains(&"Shift"));
    (alt || (ctrl && shift) || (ctrl && !letter)) && !RESERVED_HOTKEYS.contains(&hotkey)
}

/// The name of a shared vault. It is stored inside the vault itself so the server does not see it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VaultLabel {
    #[serde(default = "one")]
    pub v: u32,
    pub name: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Plaintext of a record. The kind is in the encrypted part.
// A record only lives between reading and sorting; that a host needs more space than the others does not matter.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "kebab-case")]
pub enum Payload {
    Host(Host),
    Group(Group),
    KnownHost(KnownHost),
    Key(Key),
    Identity(Identity),
    Authority(Authority),
    Workspace(Workspace),
    Forward(Forward),
    Snippet(Snippet),
    /// Name of a shared vault; lives in the vault it names.
    VaultInfo(VaultLabel),
    Proxmox(Proxmox),
    /// Kinds this version does not know. Such records stay untouched in the vault.
    #[serde(other)]
    Unknown,
}

/// Tells “field missing” (change nothing) from “field is null” (remove).
pub fn double_option<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::deserialize(deserializer).map(Some)
}

/// Where an effective value comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    Host,
    /// ID of the group.
    Group(String),
    /// Neither host nor groups set anything.
    Default,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved<T> {
    pub value: T,
    pub source: Source,
}

/// Effective values of a host after inheritance. User and key also depend on identities
/// and are therefore in [`Auth`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Effective {
    pub port: Resolved<u16>,
    pub jump: Resolved<Option<String>>,
    pub startcmd: Resolved<Option<String>>,
    pub reconnect: Resolved<Reconnect>,
    pub env: Resolved<Option<String>>,
    pub agent: Resolved<bool>,
    pub agent_forward: Resolved<bool>,
    pub proxy: Resolved<Option<String>>,
    pub keepalive: Resolved<u16>,
    pub timeout: Resolved<u16>,
    pub term: Resolved<String>,
    pub charset: Resolved<String>,
    pub legacy: Resolved<bool>,
    pub mosh: Resolved<bool>,
    pub mosh_predict: Resolved<String>,
    pub mosh_port: Resolved<Option<String>>,
    pub mosh_server: Resolved<Option<String>>,
}

/// What applies if nobody sets anything. The behaviour on disconnect comes from the settings.
pub const DEFAULT_USER: &str = "root";
pub const DEFAULT_PORT: u16 = 22;

/// Computes the effective values. `chain` are the groups from the root to the host's group,
/// each with its ID. Deeper groups override higher ones, the host overrides everything.
pub fn resolve(host: &Host, chain: &[(&str, &Group)], default_reconnect: Reconnect) -> Effective {
    fn pick<T: Clone>(own: &Option<T>, chain: &[(&str, &Group)], field: impl Fn(&Fields) -> &Option<T>, default: T) -> Resolved<T> {
        if let Some(value) = own {
            return Resolved { value: value.clone(), source: Source::Host };
        }
        for (id, group) in chain.iter().rev() {
            if let Some(value) = field(&group.defs) {
                return Resolved { value: value.clone(), source: Source::Group((*id).to_string()) };
            }
        }
        Resolved { value: default, source: Source::Default }
    }

    let own = &host.own;
    let jump = pick(&own.jump, chain, |f| &f.jump, String::new());
    let startcmd = pick(&own.startcmd, chain, |f| &f.startcmd, String::new());
    let env = pick(&own.env, chain, |f| &f.env, String::new());
    let proxy = pick(&own.proxy, chain, |f| &f.proxy, String::new());
    let mosh_port = pick(&own.mosh_port, chain, |f| &f.mosh_port, String::new());
    let mosh_server = pick(&own.mosh_server, chain, |f| &f.mosh_server, String::new());
    let some = |r: Resolved<String>| Resolved { value: (!r.value.is_empty()).then_some(r.value), source: r.source };
    Effective {
        port: pick(&own.port, chain, |f| &f.port, DEFAULT_PORT),
        jump: some(jump),
        startcmd: some(startcmd),
        reconnect: pick(&own.reconnect, chain, |f| &f.reconnect, default_reconnect),
        env: some(env),
        agent: pick(&own.agent, chain, |f| &f.agent, false),
        agent_forward: pick(&own.agent_forward, chain, |f| &f.agent_forward, false),
        proxy: some(proxy),
        keepalive: pick(&own.keepalive, chain, |f| &f.keepalive, DEFAULT_KEEPALIVE),
        timeout: pick(&own.timeout, chain, |f| &f.timeout, DEFAULT_TIMEOUT),
        term: pick(&own.term, chain, |f| &f.term, DEFAULT_TERM.to_string()),
        charset: pick(&own.charset, chain, |f| &f.charset, DEFAULT_CHARSET.to_string()),
        legacy: pick(&own.legacy, chain, |f| &f.legacy, false),
        mosh: pick(&own.mosh, chain, |f| &f.mosh, false),
        mosh_predict: pick(&own.mosh_predict, chain, |f| &f.mosh_predict, MOSH_PREDICT[0].to_string()),
        mosh_port: some(mosh_port),
        mosh_server: some(mosh_server),
    }
}

/// Sign-in after inheritance. Key and identity are IDs; the caller checks whether they still exist.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Auth<'a> {
    /// ID of the effective identity.
    pub identity: Option<&'a str>,
    /// Effective user; `None` means nobody sets one.
    pub user: Option<&'a str>,
    /// ID of the key in the vault.
    pub key: Option<&'a str>,
    pub key_file: Option<&'a str>,
}

/// Computes the sign-in. `levels` are the inheritable values from the topmost group to the host,
/// `identity` looks up an identity.
///
/// Whatever is closer to the host wins. On the same level a field set individually wins over the identity.
/// Counterpart in the interface: `authFor` in `src/lib/data.svelte.ts`.
pub fn resolve_auth<'a>(levels: &[&'a Fields], identity: impl Fn(&str) -> Option<&'a Identity>) -> Auth<'a> {
    fn deepest<'a, T: ?Sized>(levels: &[&'a Fields], field: impl Fn(&'a Fields) -> Option<&'a T>) -> Option<(usize, &'a T)> {
        levels.iter().enumerate().rev().find_map(|(i, fields)| field(fields).map(|value| (i, value)))
    }
    // The deepest level that sets an identity (including “none”) decides it.
    let chosen = deepest(levels, |f| f.identity.as_deref()).and_then(|(at, id)| identity(id).map(|found| (at, id, found)));
    // A value set individually only counts if it is not above the identity.
    let pick = |field: fn(&'a Fields) -> Option<&'a str>| deepest(levels, field).filter(|(i, _)| chosen.is_none_or(|(at, _, _)| *i >= at)).map(|(_, value)| value);
    let some = |text: &'a str| (!text.is_empty()).then_some(text);
    Auth {
        identity: chosen.map(|(_, id, _)| id),
        user: pick(|f| f.user.as_deref()).or(chosen.map(|(_, _, found)| found.user.as_str())),
        key: match pick(|f| f.key.as_deref()) {
            Some(own) => some(own),
            None => chosen.and_then(|(_, _, found)| found.key.as_deref()),
        },
        key_file: pick(|f| f.key_file.as_deref()).and_then(some),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group(defs: Fields) -> Group {
        Group { v: 1, name: "g".into(), parent: None, color: None, defs, proxy_password: None, extra: Map::new() }
    }

    fn host(own: Fields) -> Host {
        Host { v: 1, name: "h".into(), address: "a".into(), group: None, protocol: ssh(), serial: None, ftp: None, color: None, os: None, own, password: None, proxy_password: None, proxmox: None, extra: Map::new() }
    }

    #[test]
    fn deeper_groups_override_and_host_wins() {
        let top = group(Fields { user: Some("deploy".into()), port: Some(2222), jump: Some("bastion".into()), ..Fields::default() });
        let sub = group(Fields { port: Some(2200), startcmd: Some("cd /srv".into()), ..Fields::default() });
        let chain = [("top", &top), ("sub", &sub)];

        let plain = resolve(&host(Fields::default()), &chain, Reconnect::Auto);
        assert_eq!(resolve_auth(&[&top.defs, &sub.defs, &Fields::default()], |_| None).user, Some("deploy"));
        assert_eq!(plain.port, Resolved { value: 2200, source: Source::Group("sub".into()) });
        assert_eq!(plain.jump.value.as_deref(), Some("bastion"));
        assert_eq!(plain.startcmd.value.as_deref(), Some("cd /srv"));
        assert_eq!(plain.reconnect, Resolved { value: Reconnect::Auto, source: Source::Default });

        let own = Fields { user: Some("admin".into()), jump: Some(String::new()), reconnect: Some(Reconnect::Notice), ..Fields::default() };
        assert_eq!(resolve_auth(&[&top.defs, &sub.defs, &own], |_| None).user, Some("admin"));
        let overridden = resolve(&host(own), &chain, Reconnect::Auto);
        assert_eq!(overridden.jump, Resolved { value: None, source: Source::Host }, "empty explicitly means no jump host");
        assert_eq!(overridden.reconnect.value, Reconnect::Notice);
    }

    #[test]
    fn defaults_apply_without_groups() {
        let effective = resolve(&host(Fields::default()), &[], Reconnect::Notice);
        assert_eq!((effective.port.value, &effective.port.source), (DEFAULT_PORT, &Source::Default));
        assert_eq!(resolve_auth(&[&Fields::default()], |_| None), Auth::default());
        assert_eq!((effective.jump.value, effective.startcmd.value), (None, None));
    }

    #[test]
    fn unknown_fields_and_types_survive() {
        let json = r#"{"t":"host","v":3,"name":"web","address":"10.0.0.1","own":{"user":"x"},"password":"geheim","zukunft":{"a":1}}"#;
        let Payload::Host(host) = serde_json::from_str::<Payload>(json).unwrap() else { panic!("not a host") };
        assert_eq!(host.extra["zukunft"]["a"], 1);
        assert_eq!(host.protocol, "ssh");
        let back: Value = serde_json::to_value(Payload::Host(host)).unwrap();
        assert_eq!((back["t"].as_str(), back["v"].as_u64(), back["zukunft"]["a"].as_u64()), (Some("host"), Some(3), Some(1)));

        assert_eq!(serde_json::from_str::<Payload>(r#"{"t":"future","name":"later"}"#).unwrap(), Payload::Unknown);
    }

    #[test]
    fn environment_is_parsed_like_setenv() {
        let pairs = |text: &str| parse_env(text).map(|v| v.into_iter().map(|(n, v)| format!("{n}={v}")).collect::<Vec<_>>().join("|"));
        assert_eq!(pairs("LANG=de_DE.UTF-8  TZ=Europe/Berlin").as_deref(), Some("LANG=de_DE.UTF-8|TZ=Europe/Berlin"));
        assert_eq!(pairs(r#"GREETING="Hello World" _X=1 EMPTY="#).as_deref(), Some("GREETING=Hello World|_X=1|EMPTY="));
        assert_eq!(pairs("  ").as_deref(), Some(""));
        for broken in ["no-equals", "1A=x", "A B=x", r#"A="open"#, r#"A="closed"trailing"#, "A-B=x", "=x"] {
            assert_eq!(parse_env(broken), None, "{broken}");
        }
    }

    #[test]
    fn host_patterns_match_like_known_hosts() {
        assert!(pattern_matches("*", "irgendwo.test"));
        assert!(pattern_matches("*.company.test", "Web-01.Company.TEST"));
        assert!(!pattern_matches("*.company.test", "company.test"));
        assert!(pattern_matches("web-0?, 10.0.*", "web-01") && pattern_matches("web-0?, 10.0.*", "10.0.20.21"));
        assert!(!pattern_matches("web-0?", "web-012") && !pattern_matches("", "x") && !pattern_matches("10.0.*", "110.0.1.1"));
        assert!(pattern_matches("**a*", "bbab"));
    }

    #[test]
    fn proxies_are_parsed_and_logins_refused() {
        let proxy = |text: &str| parse_proxy(text).filter(|p| p.user.is_none()).map(|p| (p.kind, p.host, p.port));
        let with_user = parse_proxy("socks5://me@proxy.company.test:1081").unwrap();
        assert_eq!((with_user.user.as_deref(), with_user.host.as_str(), with_user.port), (Some("me"), "proxy.company.test", 1081));
        assert_eq!(parse_proxy("http://me@[::1]").unwrap().user.as_deref(), Some("me"));
        assert_eq!(proxy("socks5://127.0.0.1:9050"), Some((ProxyKind::Socks5, "127.0.0.1".into(), 9050)));
        assert_eq!(proxy(" HTTP://proxy.company.test/"), Some((ProxyKind::Http, "proxy.company.test".into(), 8080)));
        assert_eq!(proxy("socks5h://tor"), Some((ProxyKind::Socks5, "tor".into(), 1080)));
        assert_eq!(proxy("http://[::1]:3128"), Some((ProxyKind::Http, "::1".into(), 3128)));
        assert_eq!(proxy("socks5://[fe80::1]"), Some((ProxyKind::Socks5, "fe80::1".into(), 1080)));
        for broken in ["proxy:8080", "ftp://x:1", "http://", "http://x:0", "http://x:99999", "http://me:secret@x:1", "http://@x:1", "http://x/path", "socks5://-x", "http://a b:1"] {
            assert_eq!(parse_proxy(broken), None, "{broken}");
        }
    }

    #[test]
    fn identity_and_single_fields_follow_depth() {
        let deploy = Identity { v: 1, name: "Deploy".into(), user: "deploy".into(), key: Some("k1".into()), password: None, extra: Map::new() };
        let find = |id: &str| (id == "i1").then_some(&deploy);
        let with_identity = Fields { identity: Some("i1".into()), ..Fields::default() };
        let user_www = Fields { user: Some("www".into()), ..Fields::default() };
        let empty = Fields::default();

        // Identity above, single user deeper: the deeper value wins, the key stays from the identity.
        let auth = resolve_auth(&[&with_identity, &user_www, &empty], find);
        assert_eq!((auth.identity, auth.user, auth.key), (Some("i1"), Some("www"), Some("k1")));

        // Single user above, identity deeper: the identity overrules it.
        let auth = resolve_auth(&[&user_www, &with_identity, &empty], find);
        assert_eq!((auth.user, auth.key), (Some("deploy"), Some("k1")));

        // On the same level the field set individually wins.
        let both = Fields { identity: Some("i1".into()), user: Some("admin".into()), key: Some("k2".into()), ..Fields::default() };
        let auth = resolve_auth(&[&both], find);
        assert_eq!((auth.user, auth.key), (Some("admin"), Some("k2")));

        // “Explicitly none” on the host cancels the inherited identity, “explicitly none” the key.
        let none = Fields { identity: Some(String::new()), ..Fields::default() };
        assert_eq!(resolve_auth(&[&with_identity, &none], find), Auth::default());
        let no_key = Fields { key: Some(String::new()), ..Fields::default() };
        let auth = resolve_auth(&[&with_identity, &no_key], find);
        assert_eq!((auth.user, auth.key), (Some("deploy"), None));

        // A deleted identity no longer has an effect; the individual fields apply again.
        let gone = Fields { identity: Some("gone".into()), ..Fields::default() };
        let auth = resolve_auth(&[&user_www, &gone], find);
        assert_eq!((auth.identity, auth.user), (None, Some("www")));

        // Key file: empty counts as not set.
        let file = Fields { key_file: Some("C:/k".into()), ..Fields::default() };
        assert_eq!(resolve_auth(&[&file, &empty], find).key_file, Some("C:/k"));
    }

    #[test]
    fn keys_and_identities_keep_secrets_out_of_debug_output() {
        let json = r#"{"t":"key","name":"work","kind":"ed25519","bits":256,"fingerprint":"SHA256:x","public":"ssh-ed25519 AAAA","private":"-----BEGIN secret","origin":"generated","addedAt":5,"new":1}"#;
        let Payload::Key(key) = serde_json::from_str::<Payload>(json).unwrap() else { panic!("not a key") };
        assert_eq!((key.kind, key.origin, key.added_at, key.extra["new"].as_u64()), (KeyKind::Ed25519, KeyOrigin::Generated, 5, Some(1)));
        assert!(!format!("{key:?}").contains("secret"));

        let json = r#"{"t":"identity","name":"Deploy","user":"deploy","key":"k1","password":"hunter2"}"#;
        let Payload::Identity(identity) = serde_json::from_str::<Payload>(json).unwrap() else { panic!("not an identity") };
        assert_eq!(identity.key.as_deref(), Some("k1"));
        assert!(!format!("{identity:?}").contains("hunter2"));
    }

    #[test]
    fn proxmox_connections_and_links_keep_what_they_do_not_know() {
        let json = r#"{"t":"proxmox","name":"Dedi","address":"https://pve.example.de:8006","tokenId":"glowport@pve!glowport","secret":"0c6f2c1e","fingerprint":"5F:1A","new":1}"#;
        let Payload::Proxmox(connection) = serde_json::from_str::<Payload>(json).unwrap() else { panic!("not a connection") };
        assert_eq!((connection.token_id.as_str(), connection.fingerprint.as_deref(), connection.extra["new"].as_u64()), ("glowport@pve!glowport", Some("5F:1A"), Some(1)));
        assert!(!format!("{connection:?}").contains("0c6f2c1e"));
        let back: Value = serde_json::to_value(Payload::Proxmox(connection)).unwrap();
        assert_eq!((back["t"].as_str(), back["tokenId"].as_str(), back["new"].as_u64()), (Some("proxmox"), Some("glowport@pve!glowport"), Some(1)));

        // The link on the host: without it nothing is in the record, with it unknown data stays too.
        assert!(serde_json::to_value(Payload::Host(host(Fields::default()))).unwrap().get("proxmox").is_none());
        let json = r#"{"t":"host","name":"web","address":"10.0.0.1","proxmox":{"connection":"c1","node":"pve","vmid":101,"kind":"qemu","name":"web","later":true}}"#;
        let Payload::Host(linked) = serde_json::from_str::<Payload>(json).unwrap() else { panic!("not a host") };
        let link = linked.proxmox.clone().unwrap();
        assert_eq!((link.vmid, link.kind.as_str(), link.name.as_deref(), link.address), (101, GUEST_QEMU, Some("web"), None));
        assert_eq!(serde_json::to_value(Payload::Host(linked)).unwrap()["proxmox"]["later"], true);
    }

    #[test]
    fn secrets_stay_out_of_debug_output() {
        let mut host = host(Fields::default());
        host.password = Some(Secret::new("hunter2".into()));
        assert!(!format!("{host:?}").contains("hunter2"));
    }
}

//! Import from other programs. Every reader is a pure function: text or values in, [`Draft`] out.
//! Who finds and reads the files, who opens key files and who writes the draft into the vault
//! is in the bridge (`src-tauri/src/import.rs`).
//!
//! Rule for all readers: what they do not understand they leave out and say so (`skipped`, `notes`); a single
//! unreadable entry never brings down the whole import.

use std::collections::BTreeMap;

use glowport_core::model::{Flow, ForwardKind, Ftp, FtpSecurity, Parity, Secret, Serial};

pub mod csv;
pub mod glowport;
pub mod knownhosts;
pub mod mobaxterm;
pub mod nexusssh;
pub mod putty;
pub mod sshconfig;
pub mod text;
pub mod winscp;
pub mod wterminal;
pub mod xml;
pub mod xshell;

/// Programs and file formats that can be imported from. The names are the interface's IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Source {
    SshConfig,
    Putty,
    MobaXterm,
    WinScp,
    SecureCrt,
    MRemoteNg,
    Xshell,
    WTerminal,
    NexusSsh,
    FileZilla,
    KnownHosts,
    Csv,
    Glowport,
}

impl Source {
    pub const ALL: [Source; 13] = [
        Source::SshConfig,
        Source::Putty,
        Source::MobaXterm,
        Source::WinScp,
        Source::SecureCrt,
        Source::MRemoteNg,
        Source::Xshell,
        Source::WTerminal,
        Source::NexusSsh,
        Source::FileZilla,
        Source::KnownHosts,
        Source::Csv,
        Source::Glowport,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Source::SshConfig => "sshconfig",
            Source::Putty => "putty",
            Source::MobaXterm => "mobaxterm",
            Source::WinScp => "winscp",
            Source::SecureCrt => "securecrt",
            Source::MRemoteNg => "mremoteng",
            Source::Xshell => "xshell",
            Source::WTerminal => "wterminal",
            Source::NexusSsh => "nexusssh",
            Source::FileZilla => "filezilla",
            Source::KnownHosts => "knownhosts",
            Source::Csv => "csv",
            Source::Glowport => "glowport",
        }
    }

    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.id() == id)
    }
}

/// Why something could not be read. The interface has the texts for it (`err.import_…`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportError {
    /// The content is not what it should be.
    Unreadable(String),
    /// No known format.
    Unknown,
    /// Protected with a password.
    Protected,
}

pub type Result<T> = std::result::Result<T, ImportError>;

pub(crate) fn unreadable<T>(why: impl Into<String>) -> Result<T> {
    Err(ImportError::Unreadable(why.into()))
}

/// Note about a host. `code` is a key of the interface (`imp.note.…`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    pub code: &'static str,
    pub detail: Option<String>,
}

impl Note {
    pub fn new(code: &'static str) -> Self {
        Self { code, detail: None }
    }
    pub fn with(code: &'static str, detail: impl Into<String>) -> Self {
        Self { code, detail: Some(detail.into()) }
    }
}

/// Reference to a jump host: inherited, explicitly none, or a host of the same draft.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Jump {
    #[default]
    Unset,
    None,
    Host(usize),
}

/// Inheritable values as a source provides them. Whatever is missing stays unset in the vault.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Values {
    pub user: Option<String>,
    pub port: Option<u16>,
    pub jump: Jump,
    /// Key of the same draft.
    pub key: Option<usize>,
    pub agent: Option<bool>,
    pub agent_forward: Option<bool>,
    /// In the vault's notation: `http://…` or `socks5://…`.
    pub proxy: Option<String>,
    pub startcmd: Option<String>,
    pub env: Option<String>,
    pub keepalive: Option<u16>,
    pub timeout: Option<u16>,
    pub term: Option<String>,
    pub legacy: Option<bool>,
    pub scheme: Option<String>,
    pub charset: Option<String>,
    pub reconnect: Option<String>,
    /// Run the terminal over Mosh.
    pub mosh: Option<bool>,
    pub mosh_predict: Option<String>,
    pub mosh_port: Option<String>,
    pub mosh_server: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct DraftGroup {
    pub name: String,
    pub parent: Option<usize>,
    pub color: Option<String>,
    pub defs: Values,
}

/// How a host of the source is reached.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Protocol {
    #[default]
    Ssh,
    Telnet,
    Serial,
    Ftp,
}

impl Protocol {
    /// The ID under which the protocol is stored on the host in the vault.
    pub fn id(self) -> &'static str {
        match self {
            Self::Ssh => "ssh",
            Self::Telnet => "telnet",
            Self::Serial => "serial",
            Self::Ftp => "ftp",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct DraftHost {
    pub name: String,
    /// Address of the server; for a serial line the name of the port.
    pub address: String,
    pub protocol: Protocol,
    /// The line, for [`Protocol::Serial`].
    pub serial: Option<Serial>,
    /// Encryption and sign-in, for [`Protocol::Ftp`].
    pub ftp: Option<Ftp>,
    pub group: Option<usize>,
    pub color: Option<String>,
    pub os: Option<String>,
    pub own: Values,
    pub password: Option<Secret>,
    /// The source contains a password that cannot be read (encrypted, stored elsewhere).
    pub password_lost: bool,
    pub proxy_password: Option<Secret>,
    pub notes: Vec<Note>,
}

/// Where a key comes from: a file on this machine or the source itself.
#[derive(Debug, Clone, PartialEq)]
pub enum KeySource {
    File(String),
    Text(Secret),
}

#[derive(Debug, Clone, PartialEq)]
pub struct DraftKey {
    pub name: String,
    pub source: KeySource,
    pub passphrase: Option<Secret>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DraftForward {
    pub name: String,
    pub kind: ForwardKind,
    pub host: usize,
    pub bind_address: String,
    pub bind_port: u16,
    pub dest_host: String,
    pub dest_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DraftSnippet {
    pub name: String,
    pub package: String,
    pub command: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DraftKnownHost {
    pub host: String,
    pub port: u16,
    /// Name of the algorithm as the server names it (`ssh-ed25519`).
    pub algorithm: String,
    /// `SHA256:…` as in OpenSSH.
    pub fingerprint: String,
    /// Public key in OpenSSH format without comment.
    pub key: String,
}

/// An entry Glowport does not take over. `reason` is a key of the interface (`imp.skip.…`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    pub name: String,
    pub reason: &'static str,
}

/// What a source provides. References are positions in the lists of the same draft.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Draft {
    pub groups: Vec<DraftGroup>,
    pub hosts: Vec<DraftHost>,
    pub keys: Vec<DraftKey>,
    pub forwards: Vec<DraftForward>,
    pub snippets: Vec<DraftSnippet>,
    pub known_hosts: Vec<DraftKnownHost>,
    pub skipped: Vec<Skipped>,
}

impl Draft {
    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty() && self.snippets.is_empty() && self.known_hosts.is_empty() && self.skipped.is_empty()
    }

    pub(crate) fn skip(&mut self, name: impl Into<String>, reason: &'static str) {
        self.skipped.push(Skipped { name: name.into(), reason });
    }

    /// The group for a path like `["Customers", "Smith"]`; missing levels are created on the way. Empty names are dropped.
    pub(crate) fn group_at<S: AsRef<str>>(&mut self, path: &[S]) -> Option<usize> {
        let mut parent = None;
        for name in path.iter().map(|s| s.as_ref().trim()).filter(|s| !s.is_empty()) {
            let name: String = name.chars().take(80).collect();
            let found = self.groups.iter().position(|g| g.parent == parent && g.name == name);
            parent = Some(found.unwrap_or_else(|| {
                self.groups.push(DraftGroup { name, parent, ..DraftGroup::default() });
                self.groups.len() - 1
            }));
        }
        parent
    }

    /// The key for a file; the same file is only taken in once.
    pub(crate) fn key_file(&mut self, path: &str) -> Option<usize> {
        let path = path.trim();
        if path.is_empty() {
            return None;
        }
        let same = |k: &DraftKey| matches!(&k.source, KeySource::File(p) if p.eq_ignore_ascii_case(path));
        Some(self.keys.iter().position(same).unwrap_or_else(|| {
            let name = path.rsplit(['\\', '/']).next().unwrap_or(path).to_string();
            self.keys.push(DraftKey { name, source: KeySource::File(path.to_string()), passphrase: None });
            self.keys.len() - 1
        }))
    }

    /// A key whose text is in the source itself; the same text is only taken in once.
    pub(crate) fn key_text(&mut self, name: &str, text: &str, passphrase: Option<&str>) -> Option<usize> {
        if !text.contains("PRIVATE KEY") && !text.starts_with("PuTTY-User-Key-File") {
            return None;
        }
        let same = |k: &DraftKey| matches!(&k.source, KeySource::Text(t) if t.expose() == text);
        Some(self.keys.iter().position(same).unwrap_or_else(|| {
            self.keys.push(DraftKey {
                name: if name.trim().is_empty() { format!("key-{}", self.keys.len() + 1) } else { name.trim().to_string() },
                source: KeySource::Text(Secret::new(text.to_string())),
                passphrase: passphrase.filter(|p| !p.is_empty()).map(|p| Secret::new(p.to_string())),
            });
            self.keys.len() - 1
        }))
    }
}

/// Values of a registry key or an INI section: name → text. Numbers are decimal text.
pub type Entries = BTreeMap<String, String>;

/// A section with its name, e.g. a PuTTY session.
pub type Section = (String, Entries);

/// Reads a chosen file whose kind is known. For sources made of several files (Xshell, SecureCRT as a folder)
/// the bridge calls their readers itself.
pub fn read(source: Source, bytes: &[u8], home: &str) -> Result<Draft> {
    let text = text::decode(bytes);
    match source {
        Source::SshConfig => Ok(sshconfig::parse(&text, home, &|_| Vec::new())),
        Source::KnownHosts => Ok(knownhosts::parse(&text)),
        Source::Putty => Ok(putty::from_sections(&text::reg_sections(&text, putty::KEY))),
        Source::WinScp if text.trim_start().starts_with("Windows Registry Editor") || text.trim_start().starts_with("REGEDIT4") => Ok(winscp::from_sections(&text::reg_sections(&text, winscp::KEY), false)),
        Source::WinScp => Ok(winscp::from_ini(&text)),
        Source::MobaXterm => Ok(mobaxterm::parse(&text, home)),
        Source::Csv => csv::parse(&text),
        Source::Glowport => glowport::parse(&text),
        Source::NexusSsh => nexusssh::parse(&text, home),
        Source::WTerminal => wterminal::parse(&text, home),
        Source::MRemoteNg => xml::mremoteng(&text),
        Source::FileZilla => xml::filezilla(&text),
        Source::SecureCrt => xml::securecrt(&text),
        Source::Xshell => Ok(xshell::parse(&[("session".to_string(), text)])),
    }
}

/// Recognises from the content which program a file comes from.
pub fn detect(file_name: &str, bytes: &[u8]) -> Option<Source> {
    let text = text::decode(bytes);
    let head = text.trim_start_matches('\u{feff}').trim_start();
    let name = file_name.to_ascii_lowercase();
    if head.starts_with("Windows Registry Editor") || head.starts_with("REGEDIT4") {
        return if text.contains(winscp::KEY) { Some(Source::WinScp) } else if text.contains(putty::KEY) { Some(Source::Putty) } else { None };
    }
    if head.starts_with('<') {
        return [("<FileZilla3", Source::FileZilla), ("<VanDyke", Source::SecureCrt), ("Connections", Source::MRemoteNg)].into_iter().find(|(mark, _)| text.contains(mark)).map(|(_, s)| s);
    }
    if head.starts_with('{') || head.starts_with('[') && (name.ends_with(".json") || head[1..].trim_start().starts_with('{')) {
        let value = text::jsonc(&text)?;
        if value.get("glowport").is_some() {
            return Some(Source::Glowport);
        }
        if value.get("format").and_then(|f| f.as_str()) == Some("nexusssh-export") || name == "profiles.json" {
            return Some(Source::NexusSsh);
        }
        if value.get("profiles").is_some_and(|p| p.get("list").is_some() || p.is_array()) && (value.get("$schema").is_some() || value.get("defaultProfile").is_some() || value.get("actions").is_some()) {
            return Some(Source::WTerminal);
        }
        return value.get("profiles").map(|_| Source::NexusSsh);
    }
    if text.contains("[Bookmarks") && text.contains("SubRep=") {
        return Some(Source::MobaXterm);
    }
    if text.contains("[Sessions\\") {
        return Some(Source::WinScp);
    }
    if text.contains("[CONNECTION]") {
        return Some(Source::Xshell);
    }
    if knownhosts::looks_like(&text) {
        return Some(Source::KnownHosts);
    }
    if sshconfig::looks_like(&text) {
        return Some(Source::SshConfig);
    }
    csv::looks_like(&text).then_some(Source::Csv)
}

/// Port from a text; only 1 to 65535.
/// A host over Telnet. Of the values only user and port count; the usual port 23 is left out.
pub(crate) fn telnet_host(name: &str, address: &str, port: Option<u16>, user: Option<String>, group: Option<usize>) -> DraftHost {
    let mut host = DraftHost { name: host_name(name, address), address: address.to_string(), group, protocol: Protocol::Telnet, ..DraftHost::default() };
    host.own.port = port.filter(|p| *p != 0 && *p != 23);
    host.own.user = user.map(|u| u.trim().to_string()).filter(|u| !u.is_empty());
    host
}

/// An FTP host. Without a user or with `anonymous` it signs in anonymously. `sure` says whether the source really
/// names the encryption; otherwise the host gets a note to check it.
pub(crate) fn ftp_host(name: &str, address: &str, port: Option<u16>, user: Option<String>, security: FtpSecurity, sure: bool, group: Option<usize>) -> DraftHost {
    let user = user.map(|u| u.trim().to_string()).filter(|u| !u.is_empty());
    let anonymous = user.as_deref().is_none_or(|u| u.eq_ignore_ascii_case("anonymous"));
    let ftp = Ftp { security, anonymous, dir: None, plain_ok: false };
    let mut host = DraftHost { name: host_name(name, address), address: address.to_string(), group, protocol: Protocol::Ftp, ..DraftHost::default() };
    host.own.port = port.filter(|p| *p != 0 && *p != ftp.default_port());
    host.own.user = user.filter(|_| !anonymous);
    if !sure {
        host.notes.push(Note::new("ftp_security"));
    }
    host.ftp = Some(ftp);
    host
}

/// A serial line as a host: the address is the name of the port.
pub(crate) fn serial_host(name: &str, port: &str, line: Serial, group: Option<usize>) -> DraftHost {
    let port = port.trim().to_uppercase();
    DraftHost { name: host_name(name, &port), address: port, group, protocol: Protocol::Serial, serial: Some(line), ..DraftHost::default() }
}

/// Does the text look like a Windows serial port (`COM3`)?
pub(crate) fn usable_serial_port(text: &str) -> bool {
    let text = text.trim();
    text.len() > 3 && text.len() <= 6 && text.is_char_boundary(3) && text[..3].eq_ignore_ascii_case("com") && text[3..].chars().all(|c| c.is_ascii_digit())
}

/// A line from what the source names. Whatever is missing or cannot exist becomes the usual: 9600 8N1.
pub(crate) fn serial_line(baud: Option<u32>, data_bits: Option<u32>, parity: Parity, two_stop_bits: bool, flow: Flow) -> Serial {
    let line = Serial {
        baud: baud.unwrap_or(9600),
        data_bits: data_bits.and_then(|bits| u8::try_from(bits).ok()).filter(|bits| (5..=8).contains(bits)).unwrap_or(8),
        parity,
        stop_bits: if two_stop_bits { 2 } else { 1 },
        flow,
    };
    if line.baud_valid() { line } else { Serial { baud: 9600, ..line } }
}

pub(crate) fn port(text: &str) -> Option<u16> {
    text.trim().parse::<u16>().ok().filter(|p| *p != 0)
}

/// Is this an address the vault accepts? No spaces, no leading hyphen.
pub(crate) fn usable_address(text: &str) -> bool {
    !text.is_empty() && text.len() <= 255 && !text.starts_with('-') && !text.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// Name for a host: at most 80 characters, never empty.
pub(crate) fn host_name(name: &str, address: &str) -> String {
    let name = name.trim();
    (if name.is_empty() { address } else { name }).chars().take(80).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg(key: &str) -> String {
        format!("Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\{key}\\web]\r\n\"HostName\"=\"web.example.org\"\r\n")
    }

    #[test]
    fn recognises_files_by_their_content() {
        let utf16: Vec<u8> = [0xFF, 0xFE].into_iter().chain(reg(putty::KEY).encode_utf16().flat_map(u16::to_le_bytes)).collect();
        assert_eq!(detect("putty.reg", &utf16), Some(Source::Putty));
        assert_eq!(detect("winscp.reg", reg(winscp::KEY).as_bytes()), Some(Source::WinScp));
        assert_eq!(detect("x.reg", reg("Software\\Anderes").as_bytes()), None);
        assert_eq!(detect("MobaXterm.ini", b"[Bookmarks]\nSubRep=\nImgNum=42\n"), Some(Source::MobaXterm));
        assert_eq!(detect("WinSCP.ini", b"[Sessions\\web]\nHostName=web\n"), Some(Source::WinScp));
        assert_eq!(detect("a.xsh", b"[CONNECTION]\nHost=web\n"), Some(Source::Xshell));
        assert_eq!(detect("confCons.xml", b"<?xml version=\"1.0\"?><mrng:Connections xmlns:mrng=\"x\" ConfVersion=\"2.6\"/>"), Some(Source::MRemoteNg));
        assert_eq!(detect("sitemanager.xml", b"<FileZilla3><Servers/></FileZilla3>"), Some(Source::FileZilla));
        assert_eq!(detect("export.xml", b"<VanDyke version=\"3.0\"/>"), Some(Source::SecureCrt));
        assert_eq!(detect("export.json", b"{\"glowport\":1,\"hosts\":[]}"), Some(Source::Glowport));
        assert_eq!(detect("export.json", b"{\"format\":\"nexusssh-export\",\"profiles\":[]}"), Some(Source::NexusSsh));
        assert_eq!(detect("settings.json", b"{\n// Kommentar\n\"$schema\":\"https://aka.ms/terminal-profiles-schema\",\"profiles\":{\"list\":[]}}"), Some(Source::WTerminal));
        assert_eq!(detect("known_hosts", b"web.example.org ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG8xl5W2c2FrEsznplCeG1VfI9zSm9CciIj3drnCX2xq\n"), Some(Source::KnownHosts));
        assert_eq!(detect("config", b"Host web\n  HostName 10.0.0.1\n  User root\n"), Some(Source::SshConfig));
        assert_eq!(detect("hosts.csv", b"Label,Host,Port\nweb,10.0.0.1,22\n"), Some(Source::Csv));
        assert_eq!(detect("note.txt", b"just a few words\n"), None);
        assert_eq!(detect("empty", b""), None);
    }

    #[test]
    fn reads_a_chosen_file_of_each_kind() {
        let home = "C:\\Users\\ich";
        assert_eq!(read(Source::SshConfig, b"Host web\n  HostName 10.0.0.1\n", home).unwrap().hosts.len(), 1);
        assert_eq!(read(Source::Csv, b"name,address\nweb,10.0.0.1\n", home).unwrap().hosts.len(), 1);
        assert_eq!(read(Source::Csv, b"Groups,Label,Tags,Hostname/IP,Protocol,Port,Username,Password,SSH_KEY\nA,web,,10.0.0.1,ssh,22,root,,\n", home).unwrap().groups.len(), 1);
        assert_eq!(read(Source::WinScp, b"[Sessions\\web]\nHostName=web.example.org\n", home).unwrap().hosts.len(), 1);
        assert_eq!(read(Source::WinScp, reg(winscp::KEY).as_bytes(), home).unwrap().hosts.len(), 1);
        assert_eq!(read(Source::Putty, reg(putty::KEY).as_bytes(), home).unwrap().hosts.len(), 1);
        assert_eq!(read(Source::Xshell, b"[CONNECTION]\nHost=web\n", home).unwrap().hosts.len(), 1);
        assert!(matches!(read(Source::Glowport, b"{}", home), Err(ImportError::Unreadable(_))));
        assert!(Source::ALL.iter().all(|s| Source::from_id(s.id()) == Some(*s)));
    }
}

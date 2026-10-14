//! Import aus anderen Programmen. Jeder Leser ist eine reine Funktion: Text oder Werte hinein, [`Draft`] heraus.
//! Wer die Dateien findet und liest, wer Schlüsseldateien öffnet und wer den Entwurf in den Tresor schreibt,
//! steht in der Brücke (`src-tauri/src/import.rs`).
//!
//! Regel für alle Leser: Was sie nicht verstehen, lassen sie aus und sagen es (`skipped`, `notes`); ein einzelner
//! unlesbarer Eintrag bringt nie den ganzen Import zu Fall.

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

/// Programme und Dateiformate, aus denen importiert wird. Die Namen sind die Kennungen der Oberfläche.
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

/// Warum sich etwas nicht lesen ließ. Die Texte dazu hat die Oberfläche (`err.import_…`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportError {
    /// Der Inhalt ist nicht das, was er sein soll.
    Unreadable(String),
    /// Kein bekanntes Format.
    Unknown,
    /// Mit einem Passwort geschützt.
    Protected,
}

pub type Result<T> = std::result::Result<T, ImportError>;

pub(crate) fn unreadable<T>(why: impl Into<String>) -> Result<T> {
    Err(ImportError::Unreadable(why.into()))
}

/// Hinweis zu einem Host. `code` ist ein Schlüssel der Oberfläche (`imp.note.…`).
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

/// Verweis auf einen Sprung-Server: geerbt, ausdrücklich keiner, oder ein Host desselben Entwurfs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Jump {
    #[default]
    Unset,
    None,
    Host(usize),
}

/// Vererbbare Werte, wie sie eine Quelle hergibt. Was fehlt, bleibt im Tresor ungesetzt.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Values {
    pub user: Option<String>,
    pub port: Option<u16>,
    pub jump: Jump,
    /// Schlüssel desselben Entwurfs.
    pub key: Option<usize>,
    pub agent: Option<bool>,
    pub agent_forward: Option<bool>,
    /// In der Schreibweise des Tresors: `http://…` oder `socks5://…`.
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
    /// Das Terminal über Mosh führen.
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

/// Wie ein Host der Quelle angesprochen wird.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Protocol {
    #[default]
    Ssh,
    Telnet,
    Serial,
    Ftp,
}

impl Protocol {
    /// Die Kennung, unter der das Protokoll am Host im Tresor steht.
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
    /// Adresse des Servers; bei einer seriellen Leitung der Name des Ports.
    pub address: String,
    pub protocol: Protocol,
    /// Die Leitung, bei [`Protocol::Serial`].
    pub serial: Option<Serial>,
    /// Verschlüsselung und Anmeldung, bei [`Protocol::Ftp`].
    pub ftp: Option<Ftp>,
    pub group: Option<usize>,
    pub color: Option<String>,
    pub os: Option<String>,
    pub own: Values,
    pub password: Option<Secret>,
    /// In der Quelle steht ein Passwort, das sich nicht lesen lässt (verschlüsselt, an anderer Stelle abgelegt).
    pub password_lost: bool,
    pub proxy_password: Option<Secret>,
    pub notes: Vec<Note>,
}

/// Woher ein Schlüssel kommt: aus einer Datei auf diesem Rechner oder aus der Quelle selbst.
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
    /// Name des Verfahrens, wie ihn der Server nennt (`ssh-ed25519`).
    pub algorithm: String,
    /// `SHA256:…` wie bei OpenSSH.
    pub fingerprint: String,
    /// Öffentlicher Schlüssel im OpenSSH-Format ohne Kommentar.
    pub key: String,
}

/// Ein Eintrag, den Glowport nicht übernimmt. `reason` ist ein Schlüssel der Oberfläche (`imp.skip.…`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    pub name: String,
    pub reason: &'static str,
}

/// Was eine Quelle hergibt. Verweise sind Stellen in den Listen desselben Entwurfs.
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

    /// Die Gruppe für einen Weg wie `["Kunden", "Meier"]`; fehlende Stufen entstehen dabei. Leere Namen fallen weg.
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

    /// Der Schlüssel zu einer Datei; dieselbe Datei wird nur einmal aufgenommen.
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

    /// Ein Schlüssel, dessen Text in der Quelle selbst steht; derselbe Text wird nur einmal aufgenommen.
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

/// Werte eines Registry-Schlüssels oder eines INI-Abschnitts: Name → Text. Zahlen stehen als Dezimaltext.
pub type Entries = BTreeMap<String, String>;

/// Ein Abschnitt mit seinem Namen, etwa eine PuTTY-Sitzung.
pub type Section = (String, Entries);

/// Liest eine gewählte Datei, deren Art feststeht. Für Quellen aus mehreren Dateien (Xshell, SecureCRT als Ordner)
/// ruft die Brücke deren Leser selbst auf.
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

/// Erkennt am Inhalt, aus welchem Programm eine Datei stammt.
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

/// Port aus einem Text; nur 1 bis 65535.
/// Ein Host über Telnet. Von den Werten zählen nur Benutzer und Port; der übliche Port 23 bleibt weg.
pub(crate) fn telnet_host(name: &str, address: &str, port: Option<u16>, user: Option<String>, group: Option<usize>) -> DraftHost {
    let mut host = DraftHost { name: host_name(name, address), address: address.to_string(), group, protocol: Protocol::Telnet, ..DraftHost::default() };
    host.own.port = port.filter(|p| *p != 0 && *p != 23);
    host.own.user = user.map(|u| u.trim().to_string()).filter(|u| !u.is_empty());
    host
}

/// Ein FTP-Host. Ohne Benutzer oder mit `anonymous` meldet er sich anonym an. `sure` sagt, ob die Quelle die
/// Verschlüsselung wirklich nennt; sonst bekommt der Host einen Hinweis, sie zu prüfen.
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

/// Eine serielle Leitung als Host: Die Adresse ist der Name des Ports.
pub(crate) fn serial_host(name: &str, port: &str, line: Serial, group: Option<usize>) -> DraftHost {
    let port = port.trim().to_uppercase();
    DraftHost { name: host_name(name, &port), address: port, group, protocol: Protocol::Serial, serial: Some(line), ..DraftHost::default() }
}

/// Sieht der Text nach einem seriellen Port von Windows aus (`COM3`)?
pub(crate) fn usable_serial_port(text: &str) -> bool {
    let text = text.trim();
    text.len() > 3 && text.len() <= 6 && text.is_char_boundary(3) && text[..3].eq_ignore_ascii_case("com") && text[3..].chars().all(|c| c.is_ascii_digit())
}

/// Eine Leitung aus dem, was die Quelle nennt. Was fehlt oder was es nicht geben kann, wird zum Üblichen: 9600 8N1.
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

/// Ist das eine Adresse, die der Tresor annimmt? Keine Leerzeichen, kein Anfang mit Bindestrich.
pub(crate) fn usable_address(text: &str) -> bool {
    !text.is_empty() && text.len() <= 255 && !text.starts_with('-') && !text.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// Name für einen Host: höchstens 80 Zeichen, nie leer.
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
        assert_eq!(detect("notiz.txt", b"nur ein paar Worte\n"), None);
        assert_eq!(detect("leer", b""), None);
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

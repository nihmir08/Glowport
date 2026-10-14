//! Import und Export.
//!
//! Findet, was andere Programme auf diesem PC an Verbindungen gespeichert haben, lässt `glowport-import` es lesen,
//! zeigt der Oberfläche einen Entwurf und schreibt die Auswahl in den Tresor. Passwörter und private Schlüssel
//! einer Quelle bleiben hier: Die Oberfläche sieht nur, dass es sie gibt.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
};

use glowport_core::{
    directory::{DirError, Directory, ForwardInput, GroupInput, HostInput, NewKey, SnippetInput},
    model::{self, parse_env, parse_proxy, pattern_matches, Fields, ForwardKind, KeyKind, KeyOrigin, Reconnect, Secret, SnippetKind, CHARSETS},
};
use glowport_import::{self as reader, glowport as format, Draft, DraftHost, ImportError, Jump, KeySource, Protocol, Source, Values};
use glowport_net::keys::{self, KeyError, Kind, Material};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, State};
use tauri_plugin_dialog::DialogExt;

use crate::app::{AppState, Changed, CmdError, CmdResult};

/// Größer ist keine Datei, aus der sich Verbindungen lesen lassen; alles darüber ist etwas anderes.
const MAX_FILE: u64 = 16 * 1024 * 1024;
const MAX_KEY_FILE: u64 = 64 * 1024;
/// So viele Dateien nimmt ein Sitzungsordner (Xshell, SecureCRT) höchstens auf.
const MAX_SESSION_FILES: usize = 5000;

impl From<ImportError> for CmdError {
    fn from(error: ImportError) -> Self {
        match error {
            ImportError::Unreadable(why) => CmdError::new("import_unreadable", why),
            ImportError::Unknown => CmdError::new("import_unknown", "Format nicht erkannt"),
            ImportError::Protected => CmdError::new("import_protected", "Datei ist mit einem Passwort geschützt"),
        }
    }
}

fn unreadable(error: impl ToString) -> CmdError {
    CmdError::new("import_unreadable", error.to_string())
}

/// Was aus einem Schlüssel der Quelle geworden ist, nachdem seine Datei gelesen wurde.
enum KeyState {
    /// Lässt sich in den Tresor legen.
    Ready(Box<Material>),
    /// Braucht eine Passphrase; bleibt als Schlüsseldatei eingetragen.
    Encrypted { kind: Option<Kind>, bits: Option<u32> },
    Missing,
    Unreadable,
}

/// Ein gelesener Entwurf, bis er übernommen oder verworfen wird.
struct Entry {
    source: Source,
    origin: String,
    draft: Draft,
    keys: Vec<KeyState>,
}

#[derive(Default)]
struct Held {
    next: u64,
    entries: HashMap<u64, Entry>,
}

/// Die Entwürfe laufender Importe. Sie gehören dem Programm, nicht einem Fenster.
#[derive(Default)]
pub struct Imports(Mutex<Held>);

impl Imports {
    fn held(&self) -> std::sync::MutexGuard<'_, Held> {
        self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

// ---------- Wo die Quellen liegen ----------

fn env_dir(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).map(PathBuf::from).filter(|p| !p.as_os_str().is_empty())
}

fn home() -> String {
    env_dir("USERPROFILE").map(|p| p.display().to_string()).unwrap_or_default()
}

fn read_bytes(path: &Path, max: u64) -> CmdResult<Vec<u8>> {
    if fs::metadata(path).map_err(unreadable)?.len() > max {
        return Err(CmdError::new("import_too_large", "Die Datei ist zu groß"));
    }
    fs::read(path).map_err(unreadable)
}

/// Alle Dateien mit einer Endung unterhalb eines Ordners, jede mit ihrem Pfad darunter und ihrem Text.
fn session_files(root: &Path, extension: &str) -> Vec<(String, String)> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|e| e.eq_ignore_ascii_case(extension)) && found.len() < MAX_SESSION_FILES {
                if let (Ok(relative), Ok(bytes)) = (path.strip_prefix(root), read_bytes(&path, 1024 * 1024)) {
                    found.push((relative.display().to_string(), reader::text::decode(&bytes)));
                }
            }
        }
    }
    found.sort();
    found
}

#[cfg(windows)]
mod registry {
    use glowport_import::{Entries, Section};
    use winreg::{enums::HKEY_CURRENT_USER, types::FromRegValue, RegKey};

    /// Die Werte eines Schlüssels unter `HKEY_CURRENT_USER`: Texte und Zahlen, Zahlen als Dezimaltext.
    pub fn values(path: &str) -> Option<Entries> {
        let key = RegKey::predef(HKEY_CURRENT_USER).open_subkey(path).ok()?;
        Some(
            key.enum_values()
                .flatten()
                .filter_map(|(name, value)| {
                    let text = String::from_reg_value(&value).ok().or_else(|| u32::from_reg_value(&value).ok().map(|n| n.to_string()))?;
                    Some((name, text))
                })
                .collect(),
        )
    }

    /// Alle Schlüssel direkt unterhalb von `path`, jeder mit seinen Werten.
    pub fn sections(path: &str) -> Vec<Section> {
        let Ok(key) = RegKey::predef(HKEY_CURRENT_USER).open_subkey(path) else { return Vec::new() };
        key.enum_keys().flatten().filter_map(|name| Some((name.clone(), values(&format!("{path}\\{name}"))?))).collect()
    }
}

#[cfg(not(windows))]
mod registry {
    use glowport_import::{Entries, Section};
    pub fn values(_: &str) -> Option<Entries> {
        None
    }
    pub fn sections(_: &str) -> Vec<Section> {
        Vec::new()
    }
}

/// Löst `Include` einer OpenSSH-Konfiguration auf: Pfade gelten ab dem Ordner der Datei, `*` und `?` im Dateinamen
/// stehen für mehrere Dateien.
fn includes(base: &Path, home: &str, pattern: &str) -> Vec<String> {
    let expanded = reader::text::expand_home(pattern, home);
    let path = if Path::new(&expanded).is_absolute() { PathBuf::from(expanded) } else { base.join(expanded) };
    let (Some(dir), Some(name)) = (path.parent(), path.file_name().map(|n| n.to_string_lossy().into_owned())) else { return Vec::new() };
    let mut files: Vec<PathBuf> = if name.contains(['*', '?']) {
        fs::read_dir(dir).into_iter().flatten().flatten().map(|e| e.path()).filter(|p| p.is_file() && p.file_name().is_some_and(|n| pattern_matches(&name, &n.to_string_lossy()))).collect()
    } else {
        vec![path.clone()]
    };
    files.sort();
    files.iter().filter_map(|file| read_bytes(file, 1024 * 1024).ok()).map(|bytes| reader::text::decode(&bytes)).collect()
}

fn ssh_config(path: &Path) -> CmdResult<Draft> {
    let home = home();
    let base = path.parent().unwrap_or(Path::new(".")).to_path_buf();
    let text = reader::text::decode(&read_bytes(path, MAX_FILE)?);
    Ok(reader::sshconfig::parse(&text, &home, &|pattern| includes(&base, &home, pattern)))
}

/// Wo eine Quelle auf diesem PC liegt, wenn es sie gibt. Leerer Pfad: in der Registry.
fn location(source: Source) -> Option<PathBuf> {
    let home = env_dir("USERPROFILE")?;
    let roaming = env_dir("APPDATA");
    let local = env_dir("LOCALAPPDATA");
    let file = |path: Option<PathBuf>| path.filter(|p| p.is_file());
    let dir = |path: Option<PathBuf>| path.filter(|p| p.is_dir());
    match source {
        Source::SshConfig => file(Some(home.join(".ssh").join("config"))),
        Source::KnownHosts => file(Some(home.join(".ssh").join("known_hosts"))),
        Source::Putty => (!registry::sections(reader::putty::KEY).is_empty()).then(PathBuf::new),
        Source::WinScp => {
            if registry::sections(reader::winscp::KEY).is_empty() {
                file(roaming.map(|r| r.join("WinSCP.ini")))
            } else {
                Some(PathBuf::new())
            }
        }
        Source::MobaXterm => file(roaming.map(|r| r.join("MobaXterm").join("MobaXterm.ini"))).or_else(|| file(Some(home.join("Documents").join("MobaXterm").join("MobaXterm.ini")))),
        Source::MRemoteNg => file(roaming.map(|r| r.join("mRemoteNG").join("confCons.xml"))),
        Source::FileZilla => file(roaming.map(|r| r.join("FileZilla").join("sitemanager.xml"))),
        Source::SecureCrt => dir(roaming.map(|r| r.join("VanDyke").join("Config").join("Sessions"))),
        Source::Xshell => {
            // Der Ordner trägt die Version im Namen: `Documents\NetSarang Computer\8\Xshell\Sessions`.
            let base = home.join("Documents").join("NetSarang Computer");
            let mut versions: Vec<PathBuf> = fs::read_dir(base).into_iter().flatten().flatten().map(|e| e.path().join("Xshell").join("Sessions")).filter(|p| p.is_dir()).collect();
            versions.sort();
            versions.pop()
        }
        Source::WTerminal => {
            let packages = local?.join("Packages");
            ["Microsoft.WindowsTerminal_8wekyb3d8bbwe", "Microsoft.WindowsTerminalPreview_8wekyb3d8bbwe"].iter().find_map(|package| file(Some(packages.join(package).join("LocalState").join("settings.json"))))
        }
        Source::NexusSsh => file(local.map(|l| l.join("NexusSSH").join("profiles.json"))),
        Source::Csv | Source::Glowport => None,
    }
}

/// Liest eine Quelle von ihrem Ort auf diesem PC.
fn load(source: Source) -> CmdResult<(String, Draft)> {
    let place = location(source).ok_or_else(|| CmdError::new("not_found", "Quelle nicht gefunden"))?;
    let origin = place.display().to_string();
    let home = home();
    let draft = match source {
        Source::SshConfig => ssh_config(&place)?,
        Source::Putty => {
            let mut draft = reader::putty::from_sections(&registry::sections(reader::putty::KEY));
            // Dazu die Server-Schlüssel, die PuTTY sich gemerkt hat.
            if let Some(keys) = registry::values(reader::putty::HOST_KEYS) {
                let known = reader::putty::host_keys(&keys);
                draft.known_hosts = known.known_hosts;
                draft.skipped.extend(known.skipped);
            }
            draft
        }
        Source::WinScp if origin.is_empty() => {
            let protected = registry::values(reader::winscp::SECURITY).and_then(|v| v.get("UseMasterPassword").cloned()).is_some_and(|v| v == "1");
            reader::winscp::from_sections(&registry::sections(reader::winscp::KEY), protected)
        }
        Source::SecureCrt => reader::xml::securecrt_files(&session_files(&place, "ini")),
        Source::Xshell => reader::xshell::parse(&session_files(&place, "xsh")),
        _ => reader::read(source, &read_bytes(&place, MAX_FILE)?, &home)?,
    };
    Ok((origin, draft))
}

/// Liest eine Datei, die der Nutzer gewählt oder ins Fenster gezogen hat. Ohne `source` entscheidet der Inhalt.
fn load_file(path: &Path, source: Option<Source>) -> CmdResult<(Source, Draft)> {
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let bytes = read_bytes(path, MAX_FILE)?;
    let detected = reader::detect(&name, &bytes);
    // Der Inhalt entscheidet, wenn er eindeutig ist; die gewählte Kachel nur, wo er nichts verrät.
    let source = match (source, detected) {
        (_, Some(found)) => found,
        (Some(chosen), None) => chosen,
        (None, None) => return Err(ImportError::Unknown.into()),
    };
    let draft = if source == Source::SshConfig { ssh_config(path)? } else { reader::read(source, &bytes, &home())? };
    Ok((source, draft))
}

// ---------- Schlüssel der Quelle ----------

/// Liest die Schlüssel eines Entwurfs. Pfade ohne Laufwerk gelten ab `base` (bei einer Tabelle der Ordner der Datei;
/// freie Termius-Exporter legen die Schlüssel daneben in `ssh_keys`).
fn resolve_keys(draft: &mut Draft, base: Option<&Path>) -> Vec<KeyState> {
    let mut states = Vec::with_capacity(draft.keys.len());
    for key in &mut draft.keys {
        let text = match &key.source {
            KeySource::Text(text) => Some(text.expose().to_string()),
            KeySource::File(path) => {
                let direct = PathBuf::from(path);
                let candidates: Vec<PathBuf> = match base.filter(|_| !direct.is_absolute()) {
                    Some(base) => vec![base.join(&direct), base.join("ssh_keys").join(&direct), base.join("ssh_keys").join(format!("{path}.pem")), base.join("keys").join(&direct)],
                    None => vec![direct],
                };
                let Some(found) = candidates.into_iter().find(|p| p.is_file()) else {
                    states.push(KeyState::Missing);
                    continue;
                };
                let text = fs::metadata(&found).ok().filter(|m| m.len() <= MAX_KEY_FILE).and_then(|_| fs::read(&found).ok()).and_then(|bytes| String::from_utf8(bytes).ok());
                // Von hier an gilt der Ort, an dem die Datei wirklich liegt.
                key.source = KeySource::File(found.display().to_string());
                text
            }
        };
        let passphrase = key.passphrase.as_ref().map(|p| p.expose().to_string());
        states.push(match text.as_deref().map(|text| (keys::import(text, passphrase.as_deref()), text)) {
            None => KeyState::Unreadable,
            Some((Ok(material), _)) => KeyState::Ready(Box::new(material)),
            Some((Err(KeyError::PassphraseRequired | KeyError::WrongPassphrase), text)) => {
                let info = keys::inspect(text, None).ok();
                KeyState::Encrypted { kind: info.as_ref().and_then(|i| i.kind), bits: info.as_ref().and_then(|i| i.bits) }
            }
            Some((Err(_), _)) => KeyState::Unreadable,
        });
    }
    states
}

fn core_kind(kind: Kind) -> KeyKind {
    match kind {
        Kind::Ed25519 => KeyKind::Ed25519,
        Kind::Ecdsa => KeyKind::Ecdsa,
        Kind::Rsa => KeyKind::Rsa,
    }
}

// ---------- Was die Oberfläche sieht ----------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Found {
    source: &'static str,
    #[serde(rename = "where")]
    place: String,
    count: Option<usize>,
}

#[derive(Serialize)]
struct NoteView {
    code: &'static str,
    detail: Option<String>,
}

#[derive(Serialize)]
struct GroupView {
    #[serde(rename = "ref")]
    reference: String,
    name: String,
    parent: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HostView {
    #[serde(rename = "ref")]
    reference: String,
    name: String,
    address: String,
    /// `ssh`, `telnet`, `serial` oder `ftp`.
    protocol: &'static str,
    group: Option<String>,
    user: Option<String>,
    port: Option<u16>,
    os: Option<String>,
    auth: &'static str,
    has_password: bool,
    key: Option<String>,
    jump: Option<String>,
    notes: Vec<NoteView>,
    existing: Option<String>,
}

#[derive(Serialize)]
struct KeyView {
    #[serde(rename = "ref")]
    reference: String,
    name: String,
    path: Option<String>,
    kind: Option<KeyKind>,
    bits: Option<u32>,
    fingerprint: Option<String>,
    state: &'static str,
    existing: Option<String>,
    uses: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ForwardView {
    #[serde(rename = "ref")]
    reference: String,
    name: String,
    kind: ForwardKind,
    host: String,
    bind_address: String,
    bind_port: u16,
    dest_host: String,
    dest_port: u16,
}

#[derive(Serialize)]
struct SnippetView {
    #[serde(rename = "ref")]
    reference: String,
    name: String,
    package: String,
    command: String,
    existing: bool,
}

#[derive(Serialize)]
struct KnownView {
    #[serde(rename = "ref")]
    reference: String,
    host: String,
    port: u16,
    algorithm: String,
    fingerprint: String,
    existing: bool,
}

#[derive(Serialize)]
struct SkippedView {
    name: String,
    reason: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DraftView {
    token: u64,
    source: &'static str,
    origin: String,
    groups: Vec<GroupView>,
    hosts: Vec<HostView>,
    keys: Vec<KeyView>,
    forwards: Vec<ForwardView>,
    snippets: Vec<SnippetView>,
    known_hosts: Vec<KnownView>,
    skipped: Vec<SkippedView>,
}

/// Der Host im Tresor, der dasselbe Ziel hat: gleiche Adresse, gleicher Port, und kein anderer Benutzer.
fn twin(directory: &Directory, host: &DraftHost) -> Option<String> {
    let snapshot = directory.snapshot();
    snapshot
        .hosts
        .into_iter()
        .find(|known| {
            let same_user = match (&known.own.user, &host.own.user) {
                (Some(a), Some(b)) => a == b,
                _ => true,
            };
            // Der übliche Port hängt am Protokoll; eine serielle Leitung hat keinen.
            let usual = match host.protocol {
                Protocol::Telnet => 23,
                Protocol::Ftp => host.ftp.as_ref().map_or(model::DEFAULT_FTP_PORT, |ftp| ftp.default_port()),
                _ => 22,
            };
            let same_port = host.protocol == Protocol::Serial || known.own.port.unwrap_or(usual) == host.own.port.unwrap_or(usual);
            known.protocol == host.protocol.id() && known.address.eq_ignore_ascii_case(&host.address) && same_port && same_user
        })
        .map(|known| known.id)
}

fn view(token: u64, entry: &Entry, directory: &Directory) -> DraftView {
    let draft = &entry.draft;
    let snapshot = directory.snapshot();
    let known = directory.known_hosts();
    let key_ref = |at: usize| format!("k{at}");
    let hosts = draft
        .hosts
        .iter()
        .enumerate()
        .map(|(at, host)| {
            let mut notes: Vec<NoteView> = host.notes.iter().map(|n| NoteView { code: n.code, detail: n.detail.clone() }).collect();
            if host.password_lost {
                notes.push(NoteView { code: "password_unreadable", detail: None });
            }
            let has_password = host.password.is_some() || host.password_lost;
            HostView {
                reference: format!("h{at}"),
                name: host.name.clone(),
                address: host.address.clone(),
                protocol: host.protocol.id(),
                group: host.group.map(|g| format!("g{g}")),
                user: host.own.user.clone(),
                port: host.own.port,
                os: host.os.clone(),
                auth: if host.own.key.is_some() { "key" } else if has_password { "password" } else if host.own.agent == Some(true) { "agent" } else { "none" },
                has_password,
                key: host.own.key.map(key_ref),
                jump: match host.own.jump {
                    Jump::Host(at) => Some(format!("h{at}")),
                    _ => None,
                },
                notes,
                existing: twin(directory, host),
            }
        })
        .collect();
    let keys = draft
        .keys
        .iter()
        .zip(&entry.keys)
        .enumerate()
        .map(|(at, (key, state))| {
            let (kind, bits, fingerprint, label) = match state {
                KeyState::Ready(material) => (Some(material.kind), Some(material.bits), Some(material.fingerprint.clone()), "ready"),
                KeyState::Encrypted { kind, bits } => (*kind, *bits, None, "encrypted"),
                KeyState::Missing => (None, None, None, "missing"),
                KeyState::Unreadable => (None, None, None, "unreadable"),
            };
            KeyView {
                reference: key_ref(at),
                name: key.name.clone(),
                path: match &key.source {
                    KeySource::File(path) => Some(path.clone()),
                    KeySource::Text(_) => None,
                },
                kind: kind.map(core_kind),
                bits,
                existing: fingerprint.as_ref().and_then(|f| snapshot.keys.iter().find(|k| &k.fingerprint == f).map(|k| k.id.clone())),
                fingerprint,
                state: label,
                uses: draft.hosts.iter().filter(|h| h.own.key == Some(at)).count() + draft.groups.iter().filter(|g| g.defs.key == Some(at)).count(),
            }
        })
        .collect();
    DraftView {
        token,
        source: entry.source.id(),
        origin: entry.origin.clone(),
        groups: draft.groups.iter().enumerate().map(|(at, g)| GroupView { reference: format!("g{at}"), name: g.name.clone(), parent: g.parent.map(|p| format!("g{p}")) }).collect(),
        hosts,
        keys,
        forwards: draft
            .forwards
            .iter()
            .enumerate()
            .map(|(at, f)| ForwardView { reference: format!("f{at}"), name: f.name.clone(), kind: f.kind, host: format!("h{}", f.host), bind_address: f.bind_address.clone(), bind_port: f.bind_port, dest_host: f.dest_host.clone(), dest_port: f.dest_port })
            .collect(),
        snippets: draft
            .snippets
            .iter()
            .enumerate()
            .map(|(at, s)| SnippetView { reference: format!("s{at}"), name: s.name.clone(), package: s.package.clone(), command: s.command.clone(), existing: snapshot.snippets.iter().any(|known| known.command.trim() == s.command.trim()) })
            .collect(),
        known_hosts: draft
            .known_hosts
            .iter()
            .enumerate()
            .map(|(at, k)| KnownView { reference: format!("n{at}"), host: k.host.clone(), port: k.port, algorithm: k.algorithm.clone(), fingerprint: k.fingerprint.clone(), existing: known.iter().any(|have| have.host == k.host && have.port == k.port && have.key == k.key) })
            .collect(),
        skipped: draft.skipped.iter().map(|s| SkippedView { name: s.name.clone(), reason: s.reason }).collect(),
    }
}

// ---------- Übernehmen ----------

#[derive(Deserialize)]
#[serde(untagged)]
pub enum Into {
    Existing { id: String },
    New { name: String },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Options {
    hosts: Vec<String>,
    keys: Vec<String>,
    forwards: Vec<String>,
    snippets: Vec<String>,
    known_hosts: Vec<String>,
    into: Option<Into>,
    /// `skip`, `update` oder `add`.
    existing: String,
    keys_to_vault: bool,
    passwords: bool,
}

#[derive(Default, Serialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    hosts: usize,
    groups: usize,
    keys: usize,
    forwards: usize,
    snippets: usize,
    known_hosts: usize,
    updated: usize,
    skipped: usize,
    key_files: usize,
    failed: Vec<Failed>,
}

#[derive(Serialize, Debug, PartialEq)]
pub struct Failed {
    name: String,
    reason: String,
}

/// Wohin der Schlüssel eines Hosts zeigt, nachdem die Schlüssel verarbeitet sind.
enum KeyTarget {
    Vault(String),
    File(String),
}

/// Stellen aus Verweisen wie `h3`, soweit sie den richtigen Buchstaben tragen.
fn picked(references: &[String], letter: char) -> Vec<usize> {
    references.iter().filter_map(|r| r.strip_prefix(letter)?.parse().ok()).collect()
}

/// Grund einer Ablehnung als Text, wie ihn die Oberfläche für `err.invalid.…` kennt.
fn reason_of(error: &DirError) -> Option<String> {
    match error {
        DirError::Invalid(reason) => serde_json::to_value(reason).ok().and_then(|v| v.as_str().map(str::to_string)),
        _ => None,
    }
}

/// Vererbbare Werte der Quelle in der Form des Tresors. Was der Tresor ablehnen würde, bleibt weg, statt den
/// ganzen Host scheitern zu lassen.
fn fields(values: &Values, keys: &HashMap<usize, KeyTarget>) -> Fields {
    let token = |text: &String| !text.is_empty() && !text.starts_with('-') && !text.chars().any(|c| c.is_whitespace() || c.is_control());
    let mut out = Fields {
        user: values.user.clone().filter(token),
        port: values.port.filter(|p| *p != 0),
        agent: values.agent,
        agent_forward: values.agent_forward,
        proxy: values.proxy.clone().filter(|p| p.is_empty() || parse_proxy(p).is_some()),
        startcmd: values.startcmd.clone().filter(|c| !c.trim().is_empty() && c.len() <= 2000 && !c.chars().any(|ch| ch.is_control() && ch != '\t')),
        env: values.env.clone().filter(|e| parse_env(e).is_some()),
        keepalive: values.keepalive.filter(|k| *k <= 3600),
        timeout: values.timeout.filter(|t| (1..=300).contains(t)),
        term: values.term.clone().filter(|t| !t.is_empty() && t.len() <= 64 && t.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+'))),
        charset: values.charset.clone().filter(|c| CHARSETS.contains(&c.as_str())),
        legacy: values.legacy,
        scheme: values.scheme.clone(),
        reconnect: match values.reconnect.as_deref() {
            Some("auto") => Some(Reconnect::Auto),
            Some("notice") => Some(Reconnect::Notice),
            _ => None,
        },
        mosh: values.mosh,
        mosh_predict: values.mosh_predict.clone().filter(|p| model::MOSH_PREDICT.contains(&p.as_str())),
        mosh_port: values.mosh_port.clone().filter(|p| model::valid_mosh_port(p)),
        mosh_server: values.mosh_server.clone().filter(|p| model::valid_mosh_server(p)),
        ..Fields::default()
    };
    match values.key.and_then(|at| keys.get(&at)) {
        Some(KeyTarget::Vault(id)) => out.key = Some(id.clone()),
        Some(KeyTarget::File(path)) => out.key_file = Some(path.clone()),
        None => {}
    }
    if values.jump == Jump::None {
        out.jump = Some(String::new());
    }
    out
}

/// Legt neuere Werte über vorhandene: Was der Import nennt, gilt; alles andere bleibt, wie es war.
fn overlay(mut base: Fields, new: Fields) -> Fields {
    macro_rules! take {
        ($($field:ident),*) => { $( if new.$field.is_some() { base.$field = new.$field; } )* };
    }
    take!(user, port, jump, startcmd, reconnect, key_file, key, env, agent, agent_forward, proxy, keepalive, timeout, term, charset, legacy, scheme, mosh, mosh_predict, mosh_port, mosh_server);
    base
}

/// Die Gruppen eines Entwurfs auf dem Weg in den Tresor: Sie entstehen erst, wenn ein Host sie braucht.
struct Groups<'a> {
    draft: &'a Draft,
    /// Wohin kommt, was in der Quelle auf der obersten Ebene liegt.
    root: Option<String>,
    ids: HashMap<usize, Option<String>>,
    /// Neu angelegte Gruppen, deren Vorgaben noch ihren Sprung-Server brauchen.
    jumps: Vec<(String, usize)>,
    keys: &'a HashMap<usize, KeyTarget>,
}

impl Groups<'_> {
    /// Kennung der Gruppe im Tresor. Eine gleichnamige an derselben Stelle wird benutzt statt verdoppelt.
    fn id_for(&mut self, at: Option<usize>, dir: &mut Directory, report: &mut Report) -> Result<Option<String>, DirError> {
        let Some(at) = at.filter(|at| *at < self.draft.groups.len()) else { return Ok(self.root.clone()) };
        if let Some(known) = self.ids.get(&at) {
            return Ok(known.clone());
        }
        // Vorläufig eintragen: Zeigt eine Gruppe über Umwege auf sich selbst, endet die Suche hier.
        self.ids.insert(at, self.root.clone());
        let source = &self.draft.groups[at];
        let parent = self.id_for(source.parent, dir, report)?;
        let found = dir.snapshot().groups.into_iter().find(|g| g.parent == parent && g.name == source.name.trim()).map(|g| g.id);
        let id = match found {
            Some(id) => id,
            None => {
                let made = dir.save_group(GroupInput { id: None, name: source.name.clone(), parent: parent.clone(), color: source.color.clone(), defs: fields(&source.defs, self.keys), proxy_password: None });
                // Lehnt der Tresor die Vorgaben ab, entsteht die Gruppe ohne sie.
                let id = match made {
                    Err(DirError::Invalid(_)) => dir.save_group(GroupInput { id: None, name: source.name.clone(), parent, color: None, defs: Fields::default(), proxy_password: None })?,
                    other => other?,
                };
                report.groups += 1;
                if let Jump::Host(jump) = source.defs.jump {
                    self.jumps.push((id.clone(), jump));
                }
                id
            }
        };
        self.ids.insert(at, Some(id.clone()));
        Ok(Some(id))
    }
}

/// Schreibt die Auswahl in den Tresor, als eine Änderung: Geht dabei der Tresor selbst kaputt, bleibt nichts halb
/// zurück. Einzelne Einträge, die der Tresor ablehnt, stehen danach im Bericht, und der Rest kommt trotzdem an.
fn apply(directory: &mut Directory, entry: &Entry, options: &Options) -> CmdResult<Report> {
    let draft = &entry.draft;
    let chosen_hosts = picked(&options.hosts, 'h');
    let chosen_keys = picked(&options.keys, 'k');
    let chosen_forwards = picked(&options.forwards, 'f');
    let chosen_snippets = picked(&options.snippets, 's');
    let chosen_known = picked(&options.known_hosts, 'n');
    let twins: HashMap<usize, String> = chosen_hosts.iter().filter_map(|at| Some((*at, twin(directory, draft.hosts.get(*at)?)?))).collect();
    if let Some(Into::Existing { id }) = &options.into {
        if !directory.snapshot().groups.iter().any(|g| &g.id == id) {
            return Err(CmdError::new("not_found", "Zielgruppe nicht gefunden"));
        }
    }

    let outcome = directory.batch(|dir| {
        let mut report = Report::default();
        let fail = |report: &mut Report, name: &str, error: DirError| match reason_of(&error) {
            Some(reason) => {
                report.failed.push(Failed { name: name.to_string(), reason });
                Ok(())
            }
            None => Err(error),
        };

        // 1. Schlüssel: in den Tresor, wenn sie lesbar sind und es gewünscht ist; sonst bleibt der Pfad.
        let mut key_targets: HashMap<usize, KeyTarget> = HashMap::new();
        for at in chosen_keys.iter().copied().filter(|at| *at < draft.keys.len()) {
            let key = &draft.keys[at];
            let file = match &key.source {
                KeySource::File(path) => Some(path.clone()),
                KeySource::Text(_) => None,
            };
            match &entry.keys[at] {
                KeyState::Ready(material) => {
                    let known = dir.snapshot().keys.into_iter().find(|k| k.fingerprint == material.fingerprint).map(|k| k.id);
                    match (known, file) {
                        (Some(id), _) => drop(key_targets.insert(at, KeyTarget::Vault(id))),
                        // Ein Schlüssel, der nur in der Quelle steht, hat keine Datei, auf die sich verweisen ließe.
                        (None, file) if options.keys_to_vault || file.is_none() => {
                            let name = key.name.trim_end_matches(".ppk").trim_end_matches(".pem").to_string();
                            let added = dir.add_key(NewKey {
                                name: if name.trim().is_empty() { "import".into() } else { name.chars().take(80).collect() },
                                kind: core_kind(material.kind),
                                bits: material.bits,
                                fingerprint: material.fingerprint.clone(),
                                public: material.public.clone(),
                                private: Secret::new(material.private.to_string()),
                                origin: KeyOrigin::Imported,
                            });
                            match added {
                                Ok(id) => {
                                    report.keys += 1;
                                    key_targets.insert(at, KeyTarget::Vault(id));
                                }
                                Err(error) => fail(&mut report, &key.name, error)?,
                            }
                        }
                        (None, Some(path)) => {
                            report.key_files += 1;
                            key_targets.insert(at, KeyTarget::File(path));
                        }
                        (None, None) => {}
                    }
                }
                KeyState::Encrypted { .. } => match file {
                    Some(path) => {
                        report.key_files += 1;
                        key_targets.insert(at, KeyTarget::File(path));
                    }
                    None => report.failed.push(Failed { name: key.name.clone(), reason: "key_unreadable".into() }),
                },
                KeyState::Missing | KeyState::Unreadable => {}
            }
        }

        // 2. Gruppen: nur, soweit ein gewählter Host darin liegt. Gleichnamige an derselben Stelle werden benutzt.
        let mut root: Option<String> = None;
        let will_add = chosen_hosts.iter().any(|at| !twins.contains_key(at) || options.existing == "add");
        match &options.into {
            Some(Into::Existing { id }) => root = Some(id.clone()),
            Some(Into::New { name }) if will_add => {
                let found = dir.snapshot().groups.into_iter().find(|g| g.parent.is_none() && g.name == name.trim()).map(|g| g.id);
                root = Some(match found {
                    Some(id) => id,
                    None => {
                        report.groups += 1;
                        dir.save_group(GroupInput { id: None, name: name.clone(), parent: None, color: None, defs: Fields::default(), proxy_password: None })?
                    }
                });
            }
            _ => {}
        }
        let mut groups = Groups { draft, root, ids: HashMap::new(), jumps: Vec::new(), keys: &key_targets };

        // 3. Hosts, zuerst ohne Sprung-Server: Der darf im Entwurf weiter hinten stehen.
        let mut host_ids: HashMap<usize, String> = HashMap::new();
        let mut written: Vec<usize> = Vec::new();
        for at in chosen_hosts.iter().copied().filter(|at| *at < draft.hosts.len()) {
            let host = &draft.hosts[at];
            let own = fields(&host.own, &key_targets);
            let password = host.password.clone().filter(|_| options.passwords);
            let proxy_password = host.proxy_password.clone().filter(|_| options.passwords && own.proxy.is_some());
            let input = match (twins.get(&at), options.existing.as_str()) {
                (Some(id), "update") => {
                    let Some(known) = dir.snapshot().hosts.into_iter().find(|h| &h.id == id) else { continue };
                    HostInput { id: Some(known.id), name: known.name, address: known.address, protocol: None, serial: None, ftp: None, group: known.group, color: known.color, os: known.os, own: overlay(known.own, own), password: password.map(Some), proxy_password: proxy_password.map(Some) }
                }
                (Some(id), existing) if existing != "add" => {
                    // Ausgelassen; Sprünge und Port-Regeln anderer Einträge zeigen auf den vorhandenen Host.
                    host_ids.insert(at, id.clone());
                    report.skipped += 1;
                    continue;
                }
                _ => {
                    let group = groups.id_for(host.group, dir, &mut report)?;
                    HostInput { id: None, name: host.name.clone(), address: host.address.clone(), protocol: Some(host.protocol.id().to_string()), serial: host.serial, ftp: host.ftp.clone(), group, color: host.color.clone(), os: host.os.clone(), own, password: password.map(Some), proxy_password: proxy_password.map(Some) }
                }
            };
            let updating = input.id.is_some();
            // Lehnt der Tresor Feinheiten ab (eine Farbe, ein Zeichensatz), kommt der Host mit dem Nötigsten an.
            let plain = HostInput {
                id: input.id.clone(),
                name: input.name.clone(),
                address: input.address.clone(),
                protocol: input.protocol.clone(),
                serial: input.serial,
                ftp: input.ftp.clone(),
                group: input.group.clone(),
                color: None,
                os: None,
                own: Fields { user: input.own.user.clone(), port: input.own.port, key: input.own.key.clone(), key_file: input.own.key_file.clone(), ..Fields::default() },
                password: input.password.clone(),
                proxy_password: None,
            };
            let saved = match dir.save_host(input) {
                Err(DirError::Invalid(_)) if !updating => dir.save_host(plain),
                other => other,
            };
            match saved {
                Ok(id) => {
                    if updating {
                        report.updated += 1;
                    } else {
                        report.hosts += 1;
                    }
                    host_ids.insert(at, id);
                    written.push(at);
                }
                Err(error) => fail(&mut report, &host.name, error)?,
            }
        }

        // 4. Sprung-Server eintragen, jetzt wo jeder Host seine Kennung hat.
        for at in written {
            let (Jump::Host(jump), Some(id)) = (draft.hosts[at].own.jump, host_ids.get(&at)) else { continue };
            let Some(target) = host_ids.get(&jump).filter(|target| *target != id).cloned() else { continue };
            let Some(known) = dir.snapshot().hosts.into_iter().find(|h| &h.id == id) else { continue };
            let own = Fields { jump: Some(target), ..known.own };
            if let Err(error) = dir.save_host(HostInput { id: Some(known.id), name: known.name, address: known.address, protocol: None, serial: None, ftp: None, group: known.group, color: known.color, os: known.os, own, password: None, proxy_password: None }) {
                fail(&mut report, &draft.hosts[at].name, error)?;
            }
        }
        for (group, jump) in groups.jumps {
            let Some(target) = host_ids.get(&jump).cloned() else { continue };
            let Some(known) = dir.snapshot().groups.into_iter().find(|g| g.id == group) else { continue };
            let defs = Fields { jump: Some(target), ..known.defs };
            // Scheitert das (etwa weil der Host selbst in der Gruppe liegt und es einen Kreis gäbe), bleibt die Gruppe ohne Sprung.
            let _ = dir.save_group(GroupInput { id: Some(known.id), name: known.name, parent: known.parent, color: known.color, defs, proxy_password: None });
        }

        // 5. Port-Regeln, Snippets, bekannte Hosts.
        for at in chosen_forwards.iter().copied().filter(|at| *at < draft.forwards.len()) {
            let rule = &draft.forwards[at];
            let Some(host) = host_ids.get(&rule.host).cloned() else {
                report.failed.push(Failed { name: rule.name.clone(), reason: "host_missing".into() });
                continue;
            };
            let same = dir.snapshot().forwards.into_iter().any(|f| f.host == host && f.kind == rule.kind && f.bind_port == rule.bind_port && f.dest_host == rule.dest_host && f.dest_port == rule.dest_port);
            if same {
                report.skipped += 1;
                continue;
            }
            let input = ForwardInput { id: None, name: rule.name.clone(), kind: rule.kind, host, bind_address: rule.bind_address.clone(), bind_port: rule.bind_port.into(), dest_host: rule.dest_host.clone(), dest_port: rule.dest_port.into() };
            match dir.save_forward(input) {
                Ok(_) => report.forwards += 1,
                Err(error) => fail(&mut report, &rule.name, error)?,
            }
        }
        for at in chosen_snippets.iter().copied().filter(|at| *at < draft.snippets.len()) {
            let snippet = &draft.snippets[at];
            if dir.snapshot().snippets.iter().any(|s| s.name == snippet.name.trim() && s.command.trim() == snippet.command.trim()) {
                report.skipped += 1;
                continue;
            }
            let input = SnippetInput { id: None, name: snippet.name.clone(), package: snippet.package.clone(), kind: SnippetKind::Command, command: snippet.command.clone(), steps: Vec::new(), hotkey: None };
            match dir.save_snippet(input) {
                Ok(_) => report.snippets += 1,
                Err(error) => fail(&mut report, &snippet.name, error)?,
            }
        }
        for at in chosen_known.iter().copied().filter(|at| *at < draft.known_hosts.len()) {
            let known = &draft.known_hosts[at];
            match dir.add_known_host(&known.host, known.port, &known.algorithm, &known.fingerprint, &known.key) {
                Ok(true) => report.known_hosts += 1,
                Ok(false) => report.skipped += 1,
                Err(error) => fail(&mut report, &known.host, error)?,
            }
        }
        Ok(report)
    });
    Ok(outcome?)
}

// ---------- Export ----------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportRequest {
    /// `glowport`, `sshconfig` oder `csv`.
    format: String,
    group: Option<String>,
    snippets: bool,
    forwards: bool,
    known_hosts: bool,
}

/// Was exportiert wird, in der Form des eigenen Formats; die anderen Formate entstehen daraus.
fn collect(directory: &Directory, request: &ExportRequest, app_version: &str, now: i64) -> format::Export {
    let snapshot = directory.snapshot();
    // Mit einer Gruppe als Umfang zählen sie und alles darunter.
    let mut inside: Vec<String> = request.group.iter().cloned().collect();
    let mut index = 0;
    while index < inside.len() {
        let parent = inside[index].clone();
        let children: Vec<String> = snapshot.groups.iter().filter(|g| g.parent.as_deref() == Some(parent.as_str()) && !inside.contains(&g.id)).map(|g| g.id.clone()).collect();
        inside.extend(children);
        index += 1;
    }
    let in_scope = |group: &Option<String>| request.group.is_none() || group.as_ref().is_some_and(|g| inside.contains(g));
    // Identitäten und Schlüssel bleiben im Tresor. Der Benutzer einer Identität steht dafür als Benutzer da.
    let clean = |mut fields: Fields| {
        if fields.user.is_none() {
            fields.user = fields.identity.as_deref().filter(|id| !id.is_empty()).and_then(|id| directory.identity_user(id));
        }
        fields.identity = None;
        fields.key = None;
        fields
    };
    let hosts: Vec<format::Host> = snapshot
        .hosts
        .iter()
        .filter(|h| in_scope(&h.group))
        .map(|h| format::Host {
            id: h.id.clone(),
            name: h.name.clone(),
            address: h.address.clone(),
            protocol: Some(h.protocol.clone()).filter(|protocol| protocol != "ssh"),
            serial: h.serial,
            // Dass die Warnung vor der offenen Verbindung abbestellt ist, gilt für dieses Gerät und wandert nicht mit.
            ftp: h.ftp.clone().map(|ftp| model::Ftp { plain_ok: false, ..ftp }),
            group: h.group.clone(),
            color: h.color.clone(),
            os: h.os.clone(),
            own: clean(h.own.clone()),
        })
        .collect();
    let exported = |id: &str| hosts.iter().any(|h| h.id == id);
    format::Export {
        glowport: format::VERSION,
        app: app_version.to_string(),
        exported: now,
        groups: snapshot
            .groups
            .iter()
            .filter(|g| request.group.is_none() || inside.contains(&g.id))
            .map(|g| format::Group { id: g.id.clone(), name: g.name.clone(), parent: g.parent.clone().filter(|p| request.group.is_none() || inside.contains(p)), color: g.color.clone(), defs: clean(g.defs.clone()) })
            .collect(),
        forwards: snapshot
            .forwards
            .iter()
            .filter(|f| request.forwards && exported(&f.host))
            .map(|f| format::Forward { name: f.name.clone(), kind: f.kind, host: f.host.clone(), bind_address: f.bind_address.clone(), bind_port: f.bind_port, dest_host: f.dest_host.clone(), dest_port: f.dest_port })
            .collect(),
        snippets: snapshot
            .snippets
            .iter()
            .filter(|s| request.snippets && s.kind == SnippetKind::Command)
            .map(|s| format::Snippet { name: s.name.clone(), package: s.package.clone(), command: s.command.clone() })
            .collect(),
        known_hosts: if request.known_hosts {
            directory.known_hosts().into_iter().map(|k| format::KnownHost { host: k.host, port: k.port, algorithm: k.algorithm, fingerprint: k.fingerprint, key: k.key }).collect()
        } else {
            Vec::new()
        },
        hosts,
    }
}

/// Wirksame Werte eines Hosts: seine eigenen, sonst die der nächsten Gruppe, die etwas festlegt.
fn effective(export: &format::Export, host: &format::Host) -> Fields {
    let mut out = host.own.clone();
    let mut group = host.group.as_deref();
    let mut depth = 0;
    while let Some(found) = group.and_then(|id| export.groups.iter().find(|g| g.id == id)).filter(|_| depth < 32) {
        out = overlay(found.defs.clone(), out);
        group = found.parent.as_deref();
        depth += 1;
    }
    out
}

fn group_path(export: &format::Export, group: Option<&str>) -> Vec<String> {
    let mut path = Vec::new();
    let mut at = group;
    while let Some(found) = at.and_then(|id| export.groups.iter().find(|g| g.id == id)).filter(|_| path.len() < 32) {
        path.insert(0, found.name.clone());
        at = found.parent.as_deref();
    }
    path
}

/// Name eines Hosts für `Host` in der OpenSSH-Konfiguration: ohne Leerzeichen und Platzhalter, und einmalig.
fn alias(name: &str, taken: &mut Vec<String>) -> String {
    let base: String = name.trim().chars().map(|c| if c.is_whitespace() || matches!(c, '*' | '?' | '!' | '#' | '"' | ',') { '-' } else { c }).collect();
    let base = if base.is_empty() { "host".to_string() } else { base };
    let mut candidate = base.clone();
    let mut n = 2;
    while taken.iter().any(|t| t.eq_ignore_ascii_case(&candidate)) {
        candidate = format!("{base}-{n}");
        n += 1;
    }
    taken.push(candidate.clone());
    candidate
}

fn ssh_config_text(export: &format::Export) -> String {
    let mut taken = Vec::new();
    let aliases: HashMap<&str, String> = export.hosts.iter().map(|h| (h.id.as_str(), alias(&h.name, &mut taken))).collect();
    // Eine OpenSSH-Konfiguration kennt nur SSH: Telnet und serielle Leitungen bleiben weg.
    let mut hosts: Vec<&format::Host> = export.hosts.iter().filter(|h| h.protocol.is_none()).collect();
    hosts.sort_by_key(|h| (group_path(export, h.group.as_deref()), h.name.to_lowercase()));
    let mut out = String::from("# Geschrieben von Glowport. Passwörter und Schlüssel aus dem Tresor stehen nicht darin.\n");
    let mut last_group: Option<Vec<String>> = None;
    for host in hosts {
        let path = group_path(export, host.group.as_deref());
        if last_group.as_ref() != Some(&path) {
            if !path.is_empty() {
                out.push_str(&format!("\n# ---- {} ----\n", path.join(" / ")));
            }
            last_group = Some(path);
        }
        let own = effective(export, host);
        let bracket = |address: &str| if address.contains(':') { format!("[{address}]") } else { address.to_string() };
        out.push_str(&format!("\nHost {}\n    HostName {}\n", aliases[host.id.as_str()], host.address));
        let mut line = |key: &str, value: String| out.push_str(&format!("    {key} {value}\n"));
        if let Some(user) = own.user.filter(|u| !u.is_empty()) {
            line("User", user);
        }
        if let Some(port) = own.port.filter(|p| *p != 22) {
            line("Port", port.to_string());
        }
        if let Some(file) = own.key_file.filter(|f| !f.is_empty()) {
            line("IdentityFile", if file.contains(' ') { format!("\"{file}\"") } else { file });
        }
        match own.jump.as_deref() {
            Some("") => line("ProxyJump", "none".into()),
            Some(id) => {
                if let Some(jump) = aliases.get(id) {
                    line("ProxyJump", jump.clone());
                }
            }
            None => {}
        }
        if own.agent_forward == Some(true) && own.agent == Some(true) {
            line("ForwardAgent", "yes".into());
        }
        if let Some(seconds) = own.keepalive.filter(|k| *k > 0) {
            line("ServerAliveInterval", seconds.to_string());
        }
        if let Some(seconds) = own.timeout {
            line("ConnectTimeout", seconds.to_string());
        }
        if let Some(env) = own.env.filter(|e| !e.is_empty()) {
            line("SetEnv", env);
        }
        for rule in export.forwards.iter().filter(|f| f.host == host.id) {
            let listen = format!("{}:{}", bracket(&rule.bind_address), rule.bind_port);
            match rule.kind {
                ForwardKind::Local => line("LocalForward", format!("{listen} {}:{}", bracket(&rule.dest_host), rule.dest_port)),
                ForwardKind::Remote => line("RemoteForward", format!("{listen} {}:{}", bracket(&rule.dest_host), rule.dest_port)),
                ForwardKind::Dynamic => line("DynamicForward", listen),
            }
        }
    }
    out
}

fn csv_text(export: &format::Export) -> String {
    let cell = |text: &str| if text.contains([',', '"', '\n', ';']) { format!("\"{}\"", text.replace('"', "\"\"")) } else { text.to_string() };
    // Die Spalten, wie Termius sie für seinen Import beschreibt; so nimmt auch Termius die Datei an.
    let mut out = String::from("\u{feff}Groups,Label,Tags,Hostname/IP,Protocol,Port,Username,Password,SSH_KEY\r\n");
    for host in &export.hosts {
        let own = effective(export, host);
        // Port und Benutzer erbt nur ein SSH-Host. Bei einer seriellen Leitung steht in der Spalte des Ports die Baudrate.
        let (protocol, port, user) = match host.protocol.as_deref() {
            Some("serial") => ("serial", host.serial.map(|line| line.baud.to_string()).unwrap_or_default(), String::new()),
            Some("telnet") => ("telnet", host.own.port.unwrap_or(23).to_string(), host.own.user.clone().unwrap_or_default()),
            // `ftp` heißt in der Tabelle unverschlüsselt, `ftps` verschlüsselt; der Port sagt, auf welche Art.
            Some("ftp") => {
                let ftp = host.ftp.clone().unwrap_or(model::Ftp { security: model::FtpSecurity::Explicit, anonymous: false, dir: None, plain_ok: false });
                let kind = if ftp.security == model::FtpSecurity::None { "ftp" } else { "ftps" };
                (kind, host.own.port.unwrap_or(ftp.default_port()).to_string(), host.own.user.clone().unwrap_or_default())
            }
            _ => (if own.mosh == Some(true) { "mosh" } else { "ssh" }, own.port.unwrap_or(22).to_string(), own.user.unwrap_or_default()),
        };
        let row = [group_path(export, host.group.as_deref()).join("/"), host.name.clone(), String::new(), host.address.clone(), protocol.into(), port, user, String::new(), String::new()];
        out.push_str(&row.iter().map(|c| cell(c)).collect::<Vec<_>>().join(","));
        out.push_str("\r\n");
    }
    out
}

fn export_text(directory: &Directory, request: &ExportRequest, app_version: &str, now: i64) -> CmdResult<String> {
    let export = collect(directory, request, app_version, now);
    Ok(match request.format.as_str() {
        "sshconfig" => ssh_config_text(&export),
        "csv" => csv_text(&export),
        "glowport" => serde_json::to_string_pretty(&export).map_err(|e| CmdError::new("internal", e.to_string()))?,
        other => return Err(CmdError::new("internal", format!("unbekanntes Format {other}"))),
    })
}

// ---------- Befehle ----------

fn hold(imports: &Imports, state: &AppState, source: Source, origin: String, mut draft: Draft, base: Option<&Path>) -> CmdResult<DraftView> {
    if draft.is_empty() {
        return Err(CmdError::new("import_empty", "Nichts zu übernehmen"));
    }
    let keys = resolve_keys(&mut draft, base);
    let entry = Entry { source, origin, draft, keys };
    let mut session = state.session();
    let directory = session.directory()?;
    let mut held = imports.held();
    held.next += 1;
    let token = held.next;
    let shown = view(token, &entry, directory);
    // Ein Entwurf je Fenster reicht; ältere, die niemand mehr ansieht, fallen weg.
    if held.entries.len() >= 4 {
        let oldest = held.entries.keys().min().copied();
        if let Some(oldest) = oldest {
            held.entries.remove(&oldest);
        }
    }
    held.entries.insert(token, entry);
    Ok(shown)
}

/// Sieht nach, welche Programme auf diesem PC Verbindungen gespeichert haben, und zählt sie.
#[tauri::command(async)]
pub fn import_scan() -> Vec<Found> {
    Source::ALL
        .into_iter()
        .filter_map(|source| {
            let place = location(source)?;
            let count = load(source).ok().map(|(_, draft)| if source == Source::KnownHosts { draft.known_hosts.len() } else { draft.hosts.len() });
            // Ein Programm ohne eine einzige Verbindung, die sich übernehmen ließe, ist keine Quelle.
            (count != Some(0)).then(|| Found { source: source.id(), place: place.display().to_string(), count })
        })
        .collect()
}

#[tauri::command(async)]
pub fn import_read(imports: State<'_, Imports>, state: State<'_, AppState>, source: String) -> CmdResult<DraftView> {
    let source = Source::from_id(&source).ok_or_else(|| CmdError::from(ImportError::Unknown))?;
    let (origin, draft) = load(source)?;
    hold(&imports, &state, source, origin, draft, None)
}

fn read_path(imports: &Imports, state: &AppState, path: &Path, source: Option<Source>) -> CmdResult<DraftView> {
    let (source, draft) = load_file(path, source)?;
    hold(imports, state, source, path.display().to_string(), draft, path.parent())
}

/// Lässt den Nutzer eine Datei wählen und liest sie. `None`, wenn der Dialog abgebrochen wurde.
#[tauri::command(async)]
pub fn import_pick(app: AppHandle, imports: State<'_, Imports>, state: State<'_, AppState>, source: Option<String>) -> CmdResult<Option<DraftView>> {
    let source = source.as_deref().and_then(Source::from_id);
    let Some(path) = app.dialog().file().blocking_pick_file().and_then(|chosen| chosen.into_path().ok()) else { return Ok(None) };
    read_path(&imports, &state, &path, source).map(Some)
}

#[tauri::command(async)]
pub fn import_file(imports: State<'_, Imports>, state: State<'_, AppState>, path: String) -> CmdResult<DraftView> {
    read_path(&imports, &state, Path::new(&path), None)
}

#[derive(Serialize)]
pub struct Applied {
    report: Report,
    #[serde(flatten)]
    changed: Changed,
}

#[tauri::command(async)]
pub fn import_apply(imports: State<'_, Imports>, state: State<'_, AppState>, token: u64, options: Options) -> CmdResult<Applied> {
    let entry = imports.held().entries.remove(&token).ok_or_else(|| CmdError::new("not_found", "Entwurf nicht mehr vorhanden"))?;
    let mut session = state.session();
    let report = apply(session.directory()?, &entry, &options)?;
    Ok(Applied { report, changed: session.changed(None)? })
}

#[tauri::command]
pub fn import_discard(imports: State<'_, Imports>, token: u64) {
    imports.held().entries.remove(&token);
}

/// Fragt nach dem Speicherort und schreibt den Export. `None`, wenn der Dialog abgebrochen wurde.
#[tauri::command(async)]
pub fn export_data(app: AppHandle, state: State<'_, AppState>, request: ExportRequest, file_name: String) -> CmdResult<Option<String>> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as i64);
    // Erst der Inhalt, dann der Dialog: So steht fest, was geschrieben wird, bevor der Nutzer einen Ort wählt.
    let text = export_text(state.session().directory()?, &request, env!("CARGO_PKG_VERSION"), now)?;
    let Some(chosen) = app.dialog().file().set_file_name(file_name).blocking_save_file() else { return Ok(None) };
    let path = chosen.into_path().map_err(|e| CmdError::new("internal", e.to_string()))?;
    fs::write(&path, text).map_err(|e| CmdError::new("internal", e.to_string()))?;
    Ok(Some(path.display().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::tests::Temp;

    fn held_entry(source: Source, mut draft: Draft) -> Entry {
        let keys = resolve_keys(&mut draft, None);
        Entry { source, origin: String::new(), draft, keys }
    }

    fn options(entry: &Entry) -> Options {
        let all = |letter: char, n: usize| (0..n).map(|i| format!("{letter}{i}")).collect();
        Options {
            hosts: all('h', entry.draft.hosts.len()),
            keys: all('k', entry.draft.keys.len()),
            forwards: all('f', entry.draft.forwards.len()),
            snippets: all('s', entry.draft.snippets.len()),
            known_hosts: all('n', entry.draft.known_hosts.len()),
            into: None,
            existing: "skip".into(),
            keys_to_vault: true,
            passwords: true,
        }
    }

    /// Sieht nach, was auf diesem PC liegt, und nennt nur Zahlen: keine Namen, keine Adressen, keine Geheimnisse.
    /// `cargo test -p glowport scans_this_pc -- --ignored --nocapture`
    #[test]
    #[ignore = "liest die echten Quellen dieses PCs"]
    fn scans_this_pc() {
        for found in import_scan() {
            let source = Source::from_id(found.source).unwrap();
            let (origin, mut draft) = load(source).unwrap();
            let keys = resolve_keys(&mut draft, None);
            let state = |wanted: fn(&KeyState) -> bool| keys.iter().filter(|k| wanted(k)).count();
            println!(
                "{:<10} Ort: {:<9} gezählt {:?} | Hosts {} · Gruppen {} · Port-Regeln {} · Snippets {} · bekannte Hosts {} · ausgelassen {} | Passwörter gelesen {} · nicht lesbar {} | Schlüssel: bereit {} · Passphrase {} · fehlt {} · unlesbar {} | Sprünge {}",
                found.source,
                if origin.is_empty() { "Registry" } else { "Datei" },
                found.count,
                draft.hosts.len(),
                draft.groups.len(),
                draft.forwards.len(),
                draft.snippets.len(),
                draft.known_hosts.len(),
                draft.skipped.len(),
                draft.hosts.iter().filter(|h| h.password.is_some()).count(),
                draft.hosts.iter().filter(|h| h.password_lost).count(),
                state(|k| matches!(k, KeyState::Ready(_))),
                state(|k| matches!(k, KeyState::Encrypted { .. })),
                state(|k| matches!(k, KeyState::Missing)),
                state(|k| matches!(k, KeyState::Unreadable)),
                draft.hosts.iter().filter(|h| matches!(h.own.jump, Jump::Host(_))).count(),
            );
            let reasons: std::collections::BTreeMap<&str, usize> = draft.skipped.iter().fold(Default::default(), |mut map, s| {
                *map.entry(s.reason).or_default() += 1;
                map
            });
            if !reasons.is_empty() {
                println!("           ausgelassen nach Grund: {reasons:?}");
            }
        }
    }

    const CONFIG: &str = "Host bastion\n  HostName 203.0.113.10\n  User deploy\n  DynamicForward 1080\nHost web\n  HostName 10.20.0.11\n  User deploy\n  Port 2222\n  ProxyJump bastion\n  LocalForward 8080 127.0.0.1:80\n  SetEnv LANG=C\nHost db\n  HostName 10.20.1.5\n  ProxyJump bastion\n";

    #[test]
    fn imports_a_config_with_jumps_and_rules() {
        let temp = Temp::new("import-config");
        let state = temp.state();
        let mut session = state.session();
        session.create("richtig-lang").unwrap();
        let entry = held_entry(Source::SshConfig, reader::sshconfig::parse(CONFIG, "C:\\Users\\ich", &|_| Vec::new()));
        let mut choice = options(&entry);
        choice.into = Some(Into::New { name: "OpenSSH".into() });
        let report = apply(session.directory().unwrap(), &entry, &choice).unwrap();
        assert_eq!((report.hosts, report.groups, report.forwards, report.failed.len()), (3, 1, 2, 0));

        let snapshot = session.directory().unwrap().snapshot();
        let host = |name: &str| snapshot.hosts.iter().find(|h| h.name == name).unwrap();
        let group = &snapshot.groups[0];
        assert_eq!(group.name, "OpenSSH");
        assert_eq!(host("web").group.as_deref(), Some(group.id.as_str()));
        assert_eq!((host("web").own.user.as_deref(), host("web").own.port, host("web").own.env.as_deref()), (Some("deploy"), Some(2222), Some("LANG=C")));
        assert_eq!(host("web").own.jump.as_deref(), Some(host("bastion").id.as_str()));
        assert_eq!(host("db").own.jump.as_deref(), Some(host("bastion").id.as_str()));
        assert_eq!(host("bastion").own.jump, None);
        assert!(snapshot.forwards.iter().any(|f| f.kind == ForwardKind::Dynamic && f.host == host("bastion").id && f.bind_port == 1080));
        assert!(snapshot.forwards.iter().any(|f| f.kind == ForwardKind::Local && f.host == host("web").id && f.dest_port == 80));

        // Zweiter Lauf: Alles ist schon da und wird ausgelassen, auch die Regeln; nichts kommt doppelt.
        let again = held_entry(Source::SshConfig, reader::sshconfig::parse(CONFIG, "C:\\Users\\ich", &|_| Vec::new()));
        let shown = view(1, &again, session.directory().unwrap());
        assert!(shown.hosts.iter().all(|h| h.existing.is_some()));
        let report = apply(session.directory().unwrap(), &again, &choice).unwrap();
        assert_eq!((report.hosts, report.groups, report.forwards, report.skipped), (0, 0, 0, 5));
        assert_eq!(session.directory().unwrap().snapshot().hosts.len(), 3);

        // „Aktualisieren“ legt die Werte der Quelle über den vorhandenen Host und lässt den Rest stehen.
        let changed = "Host web\n  HostName 10.20.0.11\n  User deploy\n  Port 2222\n  ServerAliveInterval 45\n";
        let update = held_entry(Source::SshConfig, reader::sshconfig::parse(changed, "", &|_| Vec::new()));
        let mut choice = options(&update);
        choice.existing = "update".into();
        let report = apply(session.directory().unwrap(), &update, &choice).unwrap();
        assert_eq!((report.updated, report.hosts), (1, 0));
        let snapshot = session.directory().unwrap().snapshot();
        let web = snapshot.hosts.iter().find(|h| h.name == "web").unwrap();
        assert_eq!((web.own.keepalive, web.own.env.as_deref(), web.own.jump.is_some()), (Some(45), Some("LANG=C"), true));
    }

    #[test]
    fn imports_groups_passwords_keys_and_known_hosts() {
        let temp = Temp::new("import-mixed");
        let state = temp.state();
        let mut session = state.session();
        session.create("richtig-lang").unwrap();

        // Eine Tabelle mit Gruppen und Passwörtern; ein Schlüssel als Text in der Zelle.
        let key = keys::generate(Kind::Ed25519, 256).unwrap();
        let csv = format!("Groups,Label,Hostname/IP,Port,Username,Password,SSH_KEY\nKunden/Meier,web,web.meier.example,22,admin,geheim,\nKunden/Meier,db,db.meier.example,5022,admin,,\"{}\"\nKunden,böser,-oProxyCommand=x,22,root,,\n", key.private.to_string().replace('\n', "\\n"));
        let entry = held_entry(Source::Csv, reader::csv::parse(&csv).unwrap());
        assert!(matches!(entry.keys[0], KeyState::Ready(_)));
        let shown = view(7, &entry, session.directory().unwrap());
        assert_eq!((shown.hosts[0].auth, shown.hosts[1].auth, shown.keys[0].state, shown.keys[0].uses), ("password", "key", "ready", 1));
        assert!(!serde_json::to_string(&shown).unwrap().contains("geheim"), "die Vorschau trägt kein Passwort");
        assert!(!serde_json::to_string(&shown).unwrap().contains("PRIVATE KEY"), "und keinen privaten Schlüssel");

        let report = apply(session.directory().unwrap(), &entry, &options(&entry)).unwrap();
        assert_eq!((report.hosts, report.groups, report.keys, report.key_files), (2, 2, 1, 0));
        let directory = session.directory().unwrap();
        let snapshot = directory.snapshot();
        let web = snapshot.hosts.iter().find(|h| h.name == "web").unwrap();
        let db = snapshot.hosts.iter().find(|h| h.name == "db").unwrap();
        assert!(web.has_password && !db.has_password);
        assert_eq!(db.own.key.as_deref(), Some(snapshot.keys[0].id.as_str()));
        let meier = snapshot.groups.iter().find(|g| g.name == "Meier").unwrap();
        assert_eq!(snapshot.groups.iter().find(|g| Some(&g.id) == meier.parent.as_ref()).unwrap().name, "Kunden");
        assert_eq!(directory.connect_info(&web.id).unwrap().password.unwrap().expose(), "geheim");

        // Ohne „Passwörter übernehmen“ bleibt das Passwort zurück.
        let entry = held_entry(Source::Csv, reader::csv::parse("name,address,password\nnas,192.168.1.20,pw\n").unwrap());
        let mut choice = options(&entry);
        choice.passwords = false;
        apply(session.directory().unwrap(), &entry, &choice).unwrap();
        assert!(!session.directory().unwrap().snapshot().hosts.iter().find(|h| h.name == "nas").unwrap().has_password);

        // Bekannte Hosts: neu, schon vorhanden, und ein zweiter Schlüssel für dieselbe Adresse.
        let text = "web.meier.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG8xl5W2c2FrEsznplCeG1VfI9zSm9CciIj3drnCX2xq\n";
        let entry = held_entry(Source::KnownHosts, reader::knownhosts::parse(text));
        assert_eq!(apply(session.directory().unwrap(), &entry, &options(&entry)).unwrap().known_hosts, 1);
        let entry = held_entry(Source::KnownHosts, reader::knownhosts::parse(text));
        assert!(view(8, &entry, session.directory().unwrap()).known_hosts[0].existing);
        let report = apply(session.directory().unwrap(), &entry, &options(&entry)).unwrap();
        assert_eq!((report.known_hosts, report.skipped), (0, 1));
    }

    #[test]
    fn exports_and_reads_back() {
        let temp = Temp::new("import-export");
        let state = temp.state();
        let mut session = state.session();
        session.create("richtig-lang").unwrap();
        let entry = held_entry(Source::SshConfig, reader::sshconfig::parse(CONFIG, "", &|_| Vec::new()));
        let mut choice = options(&entry);
        choice.into = Some(Into::New { name: "Produktiv Web".into() });
        apply(session.directory().unwrap(), &entry, &choice).unwrap();
        let directory = session.directory().unwrap();
        let request = |format: &str| ExportRequest { format: format.into(), group: None, snippets: true, forwards: true, known_hosts: true };

        let json = export_text(directory, &request("glowport"), "0.7.0", 1).unwrap();
        assert!(!json.contains("password") && !json.contains("identity"));
        let back = format::parse(&json).unwrap();
        assert_eq!((back.hosts.len(), back.groups.len(), back.forwards.len()), (3, 1, 2));
        assert!(matches!(back.hosts.iter().find(|h| h.name == "web").unwrap().own.jump, Jump::Host(_)));

        // Als OpenSSH-Konfiguration geschrieben und wieder gelesen, kommt dasselbe heraus.
        let config = export_text(directory, &request("sshconfig"), "0.7.0", 1).unwrap();
        assert!(config.contains("# ---- Produktiv Web ----") && config.contains("ProxyJump bastion") && config.contains("LocalForward 127.0.0.1:8080 127.0.0.1:80"));
        let back = reader::sshconfig::parse(&config, "", &|_| Vec::new());
        let web = back.hosts.iter().find(|h| h.name == "web").unwrap();
        assert_eq!((web.address.as_str(), web.own.port, web.own.user.as_deref(), web.own.env.as_deref()), ("10.20.0.11", Some(2222), Some("deploy"), Some("LANG=C")));
        assert_eq!((back.hosts.len(), back.forwards.len()), (3, 2));

        let table = export_text(directory, &request("csv"), "0.7.0", 1).unwrap();
        let back = reader::csv::parse(&table).unwrap();
        assert_eq!((back.hosts.len(), back.groups[0].name.as_str()), (3, "Produktiv Web"));
        assert_eq!(back.hosts.iter().find(|h| h.name == "web").unwrap().own.port, Some(2222));

        // Ein Export aus Glowport lässt sich in einen leeren Tresor einlesen und ergibt denselben Aufbau.
        let other = Temp::new("import-export-ziel");
        let target_state = other.state();
        let mut target = target_state.session();
        target.create("richtig-lang").unwrap();
        let entry = held_entry(Source::Glowport, format::parse(&json).unwrap());
        let report = apply(target.directory().unwrap(), &entry, &options(&entry)).unwrap();
        assert_eq!((report.hosts, report.groups, report.forwards, report.failed.len()), (3, 1, 2, 0));
        let snapshot = target.directory().unwrap().snapshot();
        let web = snapshot.hosts.iter().find(|h| h.name == "web").unwrap();
        let bastion = snapshot.hosts.iter().find(|h| h.name == "bastion").unwrap();
        assert_eq!(web.own.jump.as_deref(), Some(bastion.id.as_str()));
    }

    #[test]
    fn ftp_hosts_survive_import_and_export() {
        let temp = Temp::new("import-ftp");
        let state = temp.state();
        let mut session = state.session();
        session.create("richtig-lang").unwrap();
        let table = "Groups,Label,Hostname/IP,Protocol,Port,Username,Password\nWeb,webspace,ftp.example.org,ftps,,web1,geheim\nWeb,scanner,10.0.0.60,ftp,2121,scan,\nWeb,spiegel,mirror.example.org,ftps,990,,\nWeb,web,ftp.example.org,ssh,,web1,\n";
        let entry = held_entry(Source::Csv, reader::csv::parse(table).unwrap());
        let report = apply(session.directory().unwrap(), &entry, &options(&entry)).unwrap();
        assert_eq!((report.hosts, report.groups, report.failed.len()), (4, 1, 0));

        let directory = session.directory().unwrap();
        let hosts = directory.snapshot().hosts;
        let by_name = |name: &str| hosts.iter().find(|h| h.name == name).unwrap();
        let ftp = |name: &str| by_name(name).ftp.clone().map(|ftp| (ftp.security, ftp.anonymous));
        assert_eq!((by_name("webspace").protocol.as_str(), ftp("webspace"), by_name("webspace").own.port, by_name("webspace").has_password), ("ftp", Some((model::FtpSecurity::Explicit, false)), None, true));
        assert_eq!((ftp("scanner"), by_name("scanner").own.port, by_name("scanner").own.user.as_deref()), (Some((model::FtpSecurity::None, false)), Some(2121), Some("scan")));
        assert_eq!((ftp("spiegel"), by_name("spiegel").own.port, by_name("spiegel").own.user.as_deref()), (Some((model::FtpSecurity::Implicit, true)), None, None));
        // Das Passwort kam mit und gilt beim Verbinden.
        let info = directory.ftp_info(&by_name("webspace").id).unwrap();
        assert_eq!((info.user.as_str(), info.password.as_ref().map(Secret::expose), info.port), ("web1", Some("geheim"), 21));

        // Noch einmal dieselbe Tabelle: Alles gilt als schon vorhanden. Der SSH-Host unter derselben Adresse ist ein anderer.
        let again = held_entry(Source::Csv, reader::csv::parse(table).unwrap());
        let twins: Vec<_> = again.draft.hosts.iter().map(|host| twin(directory, host)).collect();
        assert!(twins.iter().all(Option::is_some));
        assert_ne!(twins[0], twins[3], "gleiche Adresse und gleicher Benutzer, anderes Protokoll");
        // Derselbe Server auf einem anderen Port ist ein anderer Host.
        let other = reader::csv::parse("Label,Hostname/IP,Protocol,Port,Username\nwebspace-2,ftp.example.org,ftps,2121,web1\n").unwrap();
        assert!(twin(directory, &other.hosts[0]).is_none());

        let request = |format: &str| ExportRequest { format: format.into(), group: None, snippets: false, forwards: false, known_hosts: false };
        // Das eigene Format trägt die Verschlüsselung und liest sie wieder; die abbestellte Warnung wandert nicht mit.
        let scanner = by_name("scanner").id.clone();
        session.directory().unwrap().set_ftp_choice(&scanner, true, false).unwrap();
        let directory = session.directory().unwrap();
        let json = export_text(directory, &request("glowport"), "0.10.0", 1).unwrap();
        let back = format::parse(&json).unwrap();
        let read = |name: &str| back.hosts.iter().find(|h| h.name == name).unwrap();
        assert_eq!((read("webspace").protocol, read("web").protocol), (Protocol::Ftp, Protocol::Ssh));
        assert_eq!(read("scanner").ftp, Some(model::Ftp { security: model::FtpSecurity::None, anonymous: false, dir: None, plain_ok: false }));
        assert_eq!(read("spiegel").ftp.as_ref().map(|ftp| (ftp.security, ftp.anonymous)), Some((model::FtpSecurity::Implicit, true)));
        // Eine OpenSSH-Konfiguration kennt nur SSH.
        let config = export_text(directory, &request("sshconfig"), "0.10.0", 1).unwrap();
        assert!(config.contains("Host web") && !config.contains("webspace") && !config.contains("scanner"), "{config}");
        // Die Tabelle nennt `ftp` für unverschlüsselt und `ftps` sonst, mit dem Port, der gilt.
        let csv = export_text(directory, &request("csv"), "0.10.0", 1).unwrap();
        assert!(csv.contains("Web,webspace,,ftp.example.org,ftps,21,web1") && csv.contains("Web,scanner,,10.0.0.60,ftp,2121,scan") && csv.contains("Web,spiegel,,mirror.example.org,ftps,990,"), "{csv}");
        let back = reader::csv::parse(&csv).unwrap();
        let read = |name: &str| back.hosts.iter().find(|h| h.name == name).unwrap();
        assert_eq!((read("spiegel").ftp.as_ref().map(|ftp| ftp.security), read("scanner").ftp.as_ref().map(|ftp| ftp.security)), (Some(model::FtpSecurity::Implicit), Some(model::FtpSecurity::None)));
    }

    #[test]
    fn telnet_and_serial_hosts_survive_import_and_export() {
        let temp = Temp::new("import-protokolle");
        let state = temp.state();
        let mut session = state.session();
        session.create("richtig-lang").unwrap();
        let table = "Groups,Label,Hostname/IP,Protocol,Port,Username\nNetz,switch,192.168.1.250,telnet,,admin\nNetz,konsole,COM4,serial,115200,\nNetz,web,10.0.0.5,ssh,2222,deploy\n";
        let entry = held_entry(Source::Csv, reader::csv::parse(table).unwrap());
        let report = apply(session.directory().unwrap(), &entry, &options(&entry)).unwrap();
        assert_eq!((report.hosts, report.groups, report.failed.len()), (3, 1, 0));

        let directory = session.directory().unwrap();
        let hosts = directory.snapshot().hosts;
        let by_name = |name: &str| hosts.iter().find(|h| h.name == name).unwrap();
        assert_eq!((by_name("switch").protocol.as_str(), by_name("switch").own.user.as_deref(), by_name("switch").own.port), ("telnet", Some("admin"), None));
        let console = by_name("konsole");
        assert_eq!((console.protocol.as_str(), console.address.as_str(), console.serial.map(|line| (line.baud, line.data_bits, line.stop_bits))), ("serial", "COM4", Some((115_200, 8, 1))));
        assert_eq!(by_name("web").protocol, "ssh");

        // Noch einmal dieselbe Tabelle: Alles gilt als schon vorhanden. Ein SSH-Host unter der Adresse des Switches wäre es nicht.
        let again = held_entry(Source::Csv, reader::csv::parse(table).unwrap());
        assert!(again.draft.hosts.iter().all(|host| twin(directory, host).is_some()));
        let other = reader::csv::parse("Label,Hostname/IP,Protocol\nswitch-ssh,192.168.1.250,ssh\n").unwrap();
        assert!(twin(directory, &other.hosts[0]).is_none(), "gleiche Adresse, anderes Protokoll");

        let request = |format: &str| ExportRequest { format: format.into(), group: None, snippets: false, forwards: false, known_hosts: false };
        // Das eigene Format trägt Protokoll und Leitung und liest sie wieder.
        let json = export_text(directory, &request("glowport"), "0.8.0", 1).unwrap();
        let back = format::parse(&json).unwrap();
        let read = |name: &str| back.hosts.iter().find(|h| h.name == name).unwrap();
        assert_eq!((read("switch").protocol, read("konsole").protocol, read("web").protocol), (Protocol::Telnet, Protocol::Serial, Protocol::Ssh));
        assert_eq!(read("konsole").serial.map(|line| line.baud), Some(115_200));
        // Eine OpenSSH-Konfiguration kennt nur SSH.
        let config = export_text(directory, &request("sshconfig"), "0.8.0", 1).unwrap();
        assert!(config.contains("Host web") && !config.contains("switch") && !config.contains("COM4"), "{config}");
        // Die Tabelle nennt das Protokoll; bei der seriellen Leitung steht die Baudrate in der Spalte des Ports.
        let csv = export_text(directory, &request("csv"), "0.8.0", 1).unwrap();
        assert!(csv.contains("Netz,switch,,192.168.1.250,telnet,23,admin") && csv.contains("Netz,konsole,,COM4,serial,115200,") && csv.contains("Netz,web,,10.0.0.5,ssh,2222,deploy"), "{csv}");
        let back = reader::csv::parse(&csv).unwrap();
        assert_eq!(back.hosts.iter().map(|h| h.protocol).collect::<Vec<_>>().len(), 3);
        assert!(back.hosts.iter().any(|h| h.protocol == Protocol::Serial && h.serial.is_some_and(|line| line.baud == 115_200)));
    }
}

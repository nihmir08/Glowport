//! Inhalt der Datensätze: Hosts, Gruppen, bekannte Hosts, Schlüssel, Identitäten und Arbeitsbereiche. Aufbau siehe `docs/tresor.md`,
//! Abschnitt „Datensätze“.
//!
//! Regel für alle Arten: Unbekannte Felder bleiben erhalten (`extra`), damit eine ältere Programmversion
//! nichts wegwirft, was eine neuere gespeichert hat.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use zeroize::Zeroize;

/// Geheimnis, das nie in Protokollen landet und beim Freigeben überschrieben wird.
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

/// Vererbbare Werte. `None` heißt: hier nicht festgelegt, der Wert kommt von weiter oben.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Fields {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Kennung des Sprung-Servers. Leer bedeutet „ausdrücklich keiner“ und überschreibt eine geerbte Vorgabe.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jump: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub startcmd: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconnect: Option<Reconnect>,
    /// Pfad einer Schlüsseldatei auf diesem Rechner, für Schlüssel, die nicht im Tresor liegen sollen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_file: Option<String>,
    /// Kennung einer Identität. Leer bedeutet „ausdrücklich keine“.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    /// Kennung eines Schlüssels im Tresor. Leer bedeutet „ausdrücklich keiner“.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Umgebungsvariablen für die Shell in der Schreibweise von `SetEnv`: `NAME=wert`, mehrere durch Leerzeichen
    /// getrennt, Werte mit Leerzeichen in Anführungszeichen. Siehe [`parse_env`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<String>,
    /// Schlüssel aus einem SSH-Agenten dieses Rechners für die Anmeldung anbieten.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<bool>,
    /// Den Agenten an den Server weiterreichen. Wirkt nur zusammen mit `agent`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_forward: Option<bool>,
    /// Proxy als `http://adresse:port` oder `socks5://adresse:port`, wahlweise mit `benutzer@` davor. Leer bedeutet
    /// „ausdrücklich keiner“. Das Passwort dazu steht nicht hier, sondern als Geheimnis am Host oder an der Gruppe.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
    /// Abstand der Lebenszeichen in Sekunden; 0 schaltet sie ab.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive: Option<u16>,
    /// Sekunden, die auf das Zustandekommen der Verbindung gewartet wird.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u16>,
    /// Terminal-Typ, den die Shell als `TERM` sieht.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub term: Option<String>,
    /// Zeichensatz des Servers, einer aus [`CHARSETS`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub charset: Option<String>,
    /// Auch Verfahren anbieten, die heute als schwach gelten, für alte Geräte.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy: Option<bool>,
    /// Kennung eines Farbschemas für das Terminal. Die Schemata selbst kennt nur die Oberfläche.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    /// Das Terminal über Mosh führen; angemeldet wird weiter per SSH.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mosh: Option<bool>,
    /// Lokales Echo von Mosh, einer aus [`MOSH_PREDICT`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mosh_predict: Option<String>,
    /// UDP-Port oder Bereich für `mosh-server`, siehe [`valid_mosh_port`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mosh_port: Option<String>,
    /// Pfad zu `mosh-server` auf dem Server, siehe [`valid_mosh_server`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mosh_server: Option<String>,
}

/// Einstellungen des lokalen Echos von Mosh; die erste ist die Vorgabe.
pub const MOSH_PREDICT: [&str; 3] = ["adaptive", "always", "never"];

/// UDP-Port oder Bereich für `mosh-server -p`: `60001` oder `60001:60010`, aufsteigend, ohne Port 0.
pub fn valid_mosh_port(text: &str) -> bool {
    let port = |part: &str| part.len() <= 5 && part.chars().all(|c| c.is_ascii_digit()) && part.parse::<u16>().is_ok_and(|p| p > 0);
    match text.split_once(':') {
        None => port(text),
        Some((low, high)) => port(low) && port(high) && low.parse::<u16>().ok() <= high.parse::<u16>().ok(),
    }
}

/// Pfad zu `mosh-server`. Er kommt unverändert in einen Befehl auf dem Server: keine Leerzeichen und nichts, was die
/// Shell dort deuten würde (außer `~` für das Heimatverzeichnis).
pub fn valid_mosh_server(text: &str) -> bool {
    !text.is_empty() && text.chars().count() <= 200 && text.chars().all(|c| !c.is_whitespace() && !c.is_control() && !r#";&|`$<>()'"\*?!{}[]#="#.contains(c))
}

pub const DEFAULT_KEEPALIVE: u16 = 30;
pub const DEFAULT_TIMEOUT: u16 = 15;
pub const DEFAULT_TERM: &str = "xterm-256color";
pub const DEFAULT_CHARSET: &str = "utf-8";
/// Zeichensätze, die zur Wahl stehen. Der erste ist die Vorgabe und braucht keine Umwandlung.
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
    /// Benutzer für die Anmeldung am Proxy.
    pub user: Option<String>,
}

/// Liest `http://adresse:port` oder `socks5://adresse:port`, wahlweise mit `benutzer@` vor der Adresse. Ohne Port
/// gilt 8080 bzw. 1080; IPv6-Adressen stehen in eckigen Klammern. Ein Passwort in der Adresse (`benutzer:passwort@…`)
/// wird abgelehnt: Vererbbare Werte gehen bis zur Oberfläche, Passwörter nicht.
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

/// Zerlegt Umgebungsvariablen in der Schreibweise von `SetEnv`. `None`, wenn ein Teil kein `NAME=wert` ist,
/// ein Name ungültige Zeichen hat oder ein Anführungszeichen offen bleibt.
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
            // Nach dem schließenden Anführungszeichen muss ein Leerzeichen oder das Ende kommen.
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

/// Protokolle, mit denen ein Host angesprochen wird. Steht an einem Host etwas anderes, hat es eine neuere
/// Programmversion gespeichert; dann bleibt es stehen, verbinden lässt sich damit aber nicht.
pub const PROTOCOL_SSH: &str = "ssh";
pub const PROTOCOL_TELNET: &str = "telnet";
pub const PROTOCOL_SERIAL: &str = "serial";
/// Kein Terminal: Ein FTP-Host öffnet sich im Dateimanager.
pub const PROTOCOL_FTP: &str = "ftp";
pub const PROTOCOLS: [&str; 4] = [PROTOCOL_SSH, PROTOCOL_TELNET, PROTOCOL_SERIAL, PROTOCOL_FTP];

pub const DEFAULT_TELNET_PORT: u16 = 23;
pub const DEFAULT_FTP_PORT: u16 = 21;
/// FTPS von Anfang an hat seinen eigenen Port.
pub const DEFAULT_FTPS_PORT: u16 = 990;
/// Unter diesem Verfahren steht das bestätigte Zertifikat eines Servers bei den bekannten Hosts.
pub const ALGORITHM_TLS: &str = "tls";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FtpSecurity {
    /// Die Verbindung beginnt offen und schaltet vor der Anmeldung auf TLS um.
    Explicit,
    /// TLS von Anfang an.
    Implicit,
    /// Unverschlüsselt: Passwort und Dateien sind auf dem Weg lesbar.
    None,
}

/// Einstellungen eines FTP-Hosts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ftp {
    pub security: FtpSecurity,
    /// Ohne Benutzer und Passwort anmelden.
    #[serde(default)]
    pub anonymous: bool,
    /// Ordner, in dem der Dateimanager beginnt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dir: Option<String>,
    /// Die Rückfrage vor einer unverschlüsselten Verbindung ist für diesen Host abbestellt.
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

/// Flusskontrolle einer seriellen Leitung: keine, XON/XOFF oder RTS/CTS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Flow {
    None,
    Software,
    Hardware,
}

/// Einstellungen einer seriellen Leitung. Das übliche „9600 8N1“ sind 9600 Baud, 8 Datenbits, keine Parität,
/// 1 Stoppbit.
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

    /// Gibt es so einen Rahmen? 5 bis 8 Datenbits, 1 oder 2 Stoppbits.
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
    /// Passwort für den Proxy, den diese Gruppe vorgibt.
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
    /// Adresse des Servers; bei einer seriellen Leitung der Name des Ports (`COM3`, `/dev/ttyUSB0`).
    pub address: String,
    #[serde(default)]
    pub group: Option<String>,
    /// Eines aus [`PROTOCOLS`].
    #[serde(default = "ssh")]
    pub protocol: String,
    /// Einstellungen der Leitung; nur bei [`PROTOCOL_SERIAL`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<Serial>,
    /// Einstellungen für FTP; nur bei [`PROTOCOL_FTP`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ftp: Option<Ftp>,
    #[serde(default)]
    pub color: Option<String>,
    /// Kürzel des Betriebssystems für das Symbol. Ab Meilenstein 2 wird es beim Verbinden erkannt.
    #[serde(default)]
    pub os: Option<String>,
    /// Was der Host selbst festlegt. Alles andere kommt aus dem Gruppenpfad.
    #[serde(default)]
    pub own: Fields,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<Secret>,
    /// Passwort für den Proxy, den dieser Host selbst festlegt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_password: Option<Secret>,
    /// Die Maschine in Proxmox, zu der dieser Host gehört.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxmox: Option<ProxmoxLink>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Arten von Maschinen in Proxmox: eine VM oder ein Container.
pub const GUEST_QEMU: &str = "qemu";
pub const GUEST_LXC: &str = "lxc";
pub const GUEST_KINDS: [&str; 2] = [GUEST_QEMU, GUEST_LXC];

/// Zu welcher Maschine in Proxmox ein Host gehört (`docs/verwaltung.md`, „Hosts anlegen und aktuell halten“).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxmoxLink {
    /// Kennung der Verbindung im Tresor.
    pub connection: String,
    /// Der Knoten, auf dem die Maschine zuletzt lag. Wiedererkannt wird sie an ihrer Nummer.
    pub node: String,
    pub vmid: u32,
    /// Eines aus [`GUEST_KINDS`].
    pub kind: String,
    /// Name und Adresse, die Glowport dem Host zuletzt selbst gegeben hat. Nur solange der Host sie noch trägt,
    /// zieht er nach, wenn sie sich in Proxmox ändern; was der Nutzer am Host geändert hat, bleibt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Eine Verbindung zu einem Proxmox-Server über einen API-Token. Sie liegt im persönlichen Tresor.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Proxmox {
    #[serde(default = "one")]
    pub v: u32,
    pub name: String,
    /// `https://pve.example.de:8006`
    pub address: String,
    /// Kennung des Tokens: `benutzer@realm!name`.
    pub token_id: String,
    /// Geheimnis des Tokens.
    pub secret: Secret,
    /// Der bestätigte Fingerabdruck (SHA-256) eines selbst erstellten Zertifikats, wie Proxmox ihn zeigt
    /// (`5F:1A:…`). Fehlt er, muss das Zertifikat des Servers von sich aus anerkannt sein.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// Kennung der Identität, mit der sich Glowport an den Maschinen dieser Verbindung anmeldet, wenn Cloud-Init
    /// für eine Maschine keinen Schlüssel aus dem Tresor nennt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Ein Server-Schlüssel, dem der Nutzer vertraut hat.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KnownHost {
    #[serde(default = "one")]
    pub v: u32,
    /// Adresse, wie sie beim Verbinden benutzt wurde, in Kleinbuchstaben.
    pub host: String,
    pub port: u16,
    pub algorithm: String,
    /// Fingerabdruck wie bei OpenSSH (`SHA256:…`), nur zur Anzeige.
    pub fingerprint: String,
    /// Öffentlicher Schlüssel im OpenSSH-Format ohne Kommentar. An ihm wird der Server wiedererkannt.
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

/// Benutzer-Zertifikat zu einem Schlüssel: Eine Zertifizierungsstelle bestätigt, wem er gehört. Zeiten in
/// Sekunden seit 1970. Nichts davon ist geheim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyCertificate {
    /// Die Zeile im OpenSSH-Format ohne Kommentar.
    pub text: String,
    /// Name, den die Zertifizierungsstelle dem Zertifikat gegeben hat.
    pub key_id: String,
    /// Benutzernamen, für die es gilt. Leer heißt: für jeden.
    pub principals: Vec<String>,
    pub valid_after: u64,
    /// Fehlt, wenn es nicht abläuft.
    #[serde(default)]
    pub valid_before: Option<u64>,
    /// Fingerabdruck der Zertifizierungsstelle.
    pub authority: String,
}

/// Ein Schlüsselpaar. Der private Teil trägt keine eigene Passphrase; ihn schützt die Verschlüsselung des Tresors.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Key {
    #[serde(default = "one")]
    pub v: u32,
    pub name: String,
    pub kind: KeyKind,
    /// Länge in Bit: Ed25519 256, ECDSA 256/384/521, RSA wie erzeugt.
    pub bits: u32,
    /// Fingerabdruck wie bei OpenSSH (`SHA256:…`), nur zur Anzeige.
    pub fingerprint: String,
    /// Öffentlicher Schlüssel im OpenSSH-Format ohne Kommentar.
    pub public: String,
    /// Privater Schlüssel im OpenSSH-Format, unverschlüsselt.
    pub private: Secret,
    pub origin: KeyOrigin,
    /// Zeitpunkt des Erzeugens oder Importierens in Millisekunden seit 1970.
    pub added_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<KeyCertificate>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Benutzer samt Schlüssel und/oder Passwort, auf die Hosts und Gruppen verweisen.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    #[serde(default = "one")]
    pub v: u32,
    pub name: String,
    pub user: String,
    /// Kennung eines Schlüssels im Tresor.
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<Secret>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Eine Zertifizierungsstelle, deren Zertifikate für Server gelten, wie `@cert-authority` in `known_hosts`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Authority {
    #[serde(default = "one")]
    pub v: u32,
    pub name: String,
    /// Adressen, für die sie gilt. Siehe [`pattern_matches`].
    pub pattern: String,
    /// Art des Schlüssels zum Anzeigen, etwa „Ed25519“.
    pub label: String,
    pub fingerprint: String,
    /// Öffentlicher Schlüssel im OpenSSH-Format ohne Kommentar.
    pub public: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Passt eine Adresse auf ein Muster? `*` steht für beliebig viele Zeichen, `?` für genau eines; mehrere Muster
/// werden durch Komma getrennt. Groß- und Kleinschreibung zählt nicht.
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

/// Richtung, in der eine Fläche geteilt ist: `Row` legt die Teile nebeneinander, `Col` übereinander.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Split {
    Row,
    Col,
}

/// Was ein Bereich eines Arbeitsbereichs zeigt: einen gespeicherten Host oder ein lokales Terminal. `shell` ist
/// die Kennung einer Shell dieses Rechners (`pwsh`, `wsl:Ubuntu`); welche es gibt, weiß der Tresor nicht.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum PaneTarget {
    Host { id: String },
    Local { shell: String },
}

/// Längste Kennung einer Shell, die ein Arbeitsbereich aufnimmt.
pub const MAX_SHELL_ID: usize = 80;

/// Anordnung der Bereiche eines Arbeitsbereichs: ein Baum, dessen Knoten ihre Fläche in zwei Teile schneiden.
/// Dieselbe Form benutzt die Oberfläche für offene Tabs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Arrangement {
    Split {
        dir: Split,
        /// Anteil des ersten Teils, zwischen 0 und 1.
        ratio: f64,
        a: Box<Arrangement>,
        b: Box<Arrangement>,
    },
    Pane {
        pane: PaneTarget,
    },
}

/// Mehr Bereiche nimmt ein Arbeitsbereich nicht auf. Schützt auch vor beliebig tiefen Bäumen aus fremden Daten.
pub const MAX_PANES: usize = 32;

impl Arrangement {
    /// Kennungen der Hosts in der Reihenfolge ihrer Bereiche.
    pub fn hosts(&self) -> Vec<&str> {
        match self {
            Self::Pane { pane: PaneTarget::Host { id } } => vec![id.as_str()],
            Self::Pane { pane: PaneTarget::Local { .. } } => Vec::new(),
            Self::Split { a, b, .. } => [a.hosts(), b.hosts()].concat(),
        }
    }

    /// Anzahl der Bereiche, lokale Terminals eingeschlossen.
    pub fn panes(&self) -> usize {
        match self {
            Self::Pane { .. } => 1,
            Self::Split { a, b, .. } => a.panes() + b.panes(),
        }
    }

    /// Dieselbe Anordnung nur mit den Hosts, die `keep` behält; ihr Nachbar übernimmt die frei gewordene Fläche.
    /// Lokale Terminals bleiben, solange ihre Kennung nach einer aussieht. `None`, wenn kein Bereich übrig bleibt.
    /// Das Verhältnis wird dabei in einen brauchbaren Bereich geholt.
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
    /// Multi-Exec beim Öffnen einschalten: Eingaben gehen an alle Bereiche.
    #[serde(default)]
    pub multi: bool,
    pub layout: Arrangement,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Richtung einer Port-Regel. `Local`: Ein Port dieses Rechners führt über den Server zu einem Ziel.
/// `Remote`: Ein Port des Servers führt zurück zu einem Ziel, das dieser Rechner erreicht.
/// `Dynamic`: ein SOCKS-Proxy auf diesem Rechner, der über den Server ins Netz geht.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ForwardKind {
    Local,
    Remote,
    Dynamic,
}

/// Eine gespeicherte Port-Regel. Ob sie gerade läuft, steht nicht im Tresor.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Forward {
    #[serde(default = "one")]
    pub v: u32,
    pub name: String,
    pub kind: ForwardKind,
    /// Kennung des Hosts, über den die Regel läuft.
    pub host: String,
    /// Adresse, an der gelauscht wird: auf diesem Rechner (lokal, dynamisch) oder am Server (remote).
    pub bind_address: String,
    pub bind_port: u16,
    /// Wohin die Verbindungen gehen, vom anderen Ende aus gesehen. Bei `Dynamic` leer.
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
    /// Ein Befehl, auch mehrzeilig, mit Variablen wie `{{name}}`.
    Command,
    /// Aufgezeichnete Tasten, die so wieder getippt werden.
    Macro,
}

/// Ein Schritt eines Makros: so lange warten, dann diese Tasten schicken.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacroStep {
    /// Millisekunden seit dem vorigen Schritt.
    pub wait: u32,
    pub keys: String,
}

// Ein Makro enthält alles, was getippt wurde, womöglich ein Passwort: Die Tasten erscheinen in keiner Ausgabe.
impl fmt::Debug for MacroStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MacroStep {{ wait: {}, keys: <{} Zeichen> }}", self.wait, self.keys.chars().count())
    }
}

/// Ein gespeicherter Befehl oder ein aufgezeichnetes Makro.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Snippet {
    #[serde(default = "one")]
    pub v: u32,
    pub name: String,
    /// Name des Pakets, in dem es liegt; leer = keines.
    #[serde(default)]
    pub package: String,
    pub kind: SnippetKind,
    #[serde(default)]
    pub command: String,
    #[serde(default)]
    pub steps: Vec<MacroStep>,
    /// Tastenkürzel in fester Schreibweise, etwa „Ctrl+Alt+R“. Siehe [`valid_hotkey`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hotkey: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Kürzel, die Glowport oder Windows selbst benutzen. Dieselbe Liste führt die Oberfläche (`snippets.ts`).
const RESERVED_HOTKEYS: [&str; 9] = ["Ctrl+Shift+W", "Ctrl+Shift+D", "Ctrl+Shift+E", "Ctrl+Shift+M", "Ctrl+Shift+F", "Ctrl+Shift+C", "Ctrl+Shift+V", "Ctrl+0", "Alt+F4"];

/// Ob sich ein Tastenkürzel für ein Snippet vergeben lässt. Die Schreibweise ist fest: erst `Ctrl`, `Alt`, `Shift`
/// in dieser Reihenfolge, dann ein Buchstabe, eine Ziffer oder F1 bis F12. Erlaubt ist, was der Shell nichts
/// wegnimmt: mit Alt, mit Strg+Umschalt, oder Strg mit Ziffer oder Funktionstaste.
pub fn valid_hotkey(hotkey: &str) -> bool {
    let mut parts: Vec<&str> = hotkey.split('+').collect();
    let Some(key) = parts.pop() else { return false };
    let letter = key.len() == 1 && key.chars().all(|c| c.is_ascii_uppercase());
    let digit = key.len() == 1 && key.chars().all(|c| c.is_ascii_digit());
    let function = key.strip_prefix('F').and_then(|n| n.parse::<u8>().ok()).is_some_and(|n| (1..=12).contains(&n) && key == format!("F{n}"));
    if !(letter || digit || function) {
        return false;
    }
    // Jeder Zusatz höchstens einmal und in der festen Reihenfolge.
    let order = ["Ctrl", "Alt", "Shift"];
    let places: Option<Vec<usize>> = parts.iter().map(|part| order.iter().position(|known| known == part)).collect();
    let Some(places) = places else { return false };
    if !places.windows(2).all(|pair| pair[0] < pair[1]) {
        return false;
    }
    let (ctrl, alt, shift) = (parts.contains(&"Ctrl"), parts.contains(&"Alt"), parts.contains(&"Shift"));
    (alt || (ctrl && shift) || (ctrl && !letter)) && !RESERVED_HOTKEYS.contains(&hotkey)
}

/// Der Name eines geteilten Tresors. Er steht im Tresor selbst, damit der Server ihn nicht sieht.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VaultLabel {
    #[serde(default = "one")]
    pub v: u32,
    pub name: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Klartext eines Datensatzes. Die Art steht im verschlüsselten Teil.
// Ein Datensatz lebt nur zwischen Lesen und Einsortieren; dass ein Host mehr Platz braucht als die anderen, stört nicht.
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
    /// Name eines geteilten Tresors; liegt in dem Tresor, den er benennt.
    VaultInfo(VaultLabel),
    Proxmox(Proxmox),
    /// Arten, die diese Version nicht kennt. Solche Datensätze bleiben unangetastet im Tresor.
    #[serde(other)]
    Unknown,
}

/// Unterscheidet „Feld fehlt“ (nichts ändern) von „Feld ist null“ (entfernen).
pub fn double_option<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::deserialize(deserializer).map(Some)
}

/// Woher ein wirksamer Wert stammt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    Host,
    /// Kennung der Gruppe.
    Group(String),
    /// Weder Host noch Gruppen legen etwas fest.
    Default,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved<T> {
    pub value: T,
    pub source: Source,
}

/// Wirksame Werte eines Hosts nach der Vererbung. Benutzer und Schlüssel hängen zusätzlich an Identitäten
/// und stehen deshalb in [`Auth`].
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

/// Was gilt, wenn niemand etwas festlegt. Das Verhalten bei Abriss kommt aus den Einstellungen.
pub const DEFAULT_USER: &str = "root";
pub const DEFAULT_PORT: u16 = 22;

/// Berechnet die wirksamen Werte. `chain` sind die Gruppen von der Wurzel bis zur Gruppe des Hosts,
/// jeweils mit Kennung. Tiefere Gruppen überschreiben höhere, der Host überschreibt alles.
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

/// Anmeldung nach der Vererbung. Schlüssel und Identität sind Kennungen; ob es sie noch gibt, prüft der Aufrufer.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Auth<'a> {
    /// Kennung der wirksamen Identität.
    pub identity: Option<&'a str>,
    /// Wirksamer Benutzer; `None` heißt, niemand legt einen fest.
    pub user: Option<&'a str>,
    /// Kennung des Schlüssels im Tresor.
    pub key: Option<&'a str>,
    pub key_file: Option<&'a str>,
}

/// Berechnet die Anmeldung. `levels` sind die vererbbaren Werte von der obersten Gruppe bis zum Host,
/// `identity` schlägt eine Identität nach.
///
/// Was näher am Host steht, gewinnt. Auf derselben Ebene gewinnt das einzeln eingetragene Feld über die Identität.
/// Gegenstück in der Oberfläche: `authFor` in `src/lib/data.svelte.ts`.
pub fn resolve_auth<'a>(levels: &[&'a Fields], identity: impl Fn(&str) -> Option<&'a Identity>) -> Auth<'a> {
    fn deepest<'a, T: ?Sized>(levels: &[&'a Fields], field: impl Fn(&'a Fields) -> Option<&'a T>) -> Option<(usize, &'a T)> {
        levels.iter().enumerate().rev().find_map(|(i, fields)| field(fields).map(|value| (i, value)))
    }
    // Die tiefste Ebene, die eine Identität festlegt (auch „keine“), bestimmt sie.
    let chosen = deepest(levels, |f| f.identity.as_deref()).and_then(|(at, id)| identity(id).map(|found| (at, id, found)));
    // Ein einzeln eingetragener Wert zählt nur, wenn er nicht oberhalb der Identität steht.
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
        assert_eq!(overridden.jump, Resolved { value: None, source: Source::Host }, "leer heißt ausdrücklich kein Sprung-Server");
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
        let Payload::Host(host) = serde_json::from_str::<Payload>(json).unwrap() else { panic!("kein Host") };
        assert_eq!(host.extra["zukunft"]["a"], 1);
        assert_eq!(host.protocol, "ssh");
        let back: Value = serde_json::to_value(Payload::Host(host)).unwrap();
        assert_eq!((back["t"].as_str(), back["v"].as_u64(), back["zukunft"]["a"].as_u64()), (Some("host"), Some(3), Some(1)));

        assert_eq!(serde_json::from_str::<Payload>(r#"{"t":"zukunft","name":"später"}"#).unwrap(), Payload::Unknown);
    }

    #[test]
    fn environment_is_parsed_like_setenv() {
        let pairs = |text: &str| parse_env(text).map(|v| v.into_iter().map(|(n, v)| format!("{n}={v}")).collect::<Vec<_>>().join("|"));
        assert_eq!(pairs("LANG=de_DE.UTF-8  TZ=Europe/Berlin").as_deref(), Some("LANG=de_DE.UTF-8|TZ=Europe/Berlin"));
        assert_eq!(pairs(r#"GRUSS="Hallo Welt" _X=1 LEER="#).as_deref(), Some("GRUSS=Hallo Welt|_X=1|LEER="));
        assert_eq!(pairs("  ").as_deref(), Some(""));
        for broken in ["ohne-gleich", "1A=x", "A B=x", r#"A="offen"#, r#"A="zu"dran"#, "A-B=x", "=x"] {
            assert_eq!(parse_env(broken), None, "{broken}");
        }
    }

    #[test]
    fn host_patterns_match_like_known_hosts() {
        assert!(pattern_matches("*", "irgendwo.test"));
        assert!(pattern_matches("*.firma.test", "Web-01.Firma.TEST"));
        assert!(!pattern_matches("*.firma.test", "firma.test"));
        assert!(pattern_matches("web-0?, 10.0.*", "web-01") && pattern_matches("web-0?, 10.0.*", "10.0.20.21"));
        assert!(!pattern_matches("web-0?", "web-012") && !pattern_matches("", "x") && !pattern_matches("10.0.*", "110.0.1.1"));
        assert!(pattern_matches("**a*", "bbab"));
    }

    #[test]
    fn proxies_are_parsed_and_logins_refused() {
        let proxy = |text: &str| parse_proxy(text).filter(|p| p.user.is_none()).map(|p| (p.kind, p.host, p.port));
        let with_user = parse_proxy("socks5://ich@proxy.firma.test:1081").unwrap();
        assert_eq!((with_user.user.as_deref(), with_user.host.as_str(), with_user.port), (Some("ich"), "proxy.firma.test", 1081));
        assert_eq!(parse_proxy("http://ich@[::1]").unwrap().user.as_deref(), Some("ich"));
        assert_eq!(proxy("socks5://127.0.0.1:9050"), Some((ProxyKind::Socks5, "127.0.0.1".into(), 9050)));
        assert_eq!(proxy(" HTTP://proxy.firma.test/ "), Some((ProxyKind::Http, "proxy.firma.test".into(), 8080)));
        assert_eq!(proxy("socks5h://tor"), Some((ProxyKind::Socks5, "tor".into(), 1080)));
        assert_eq!(proxy("http://[::1]:3128"), Some((ProxyKind::Http, "::1".into(), 3128)));
        assert_eq!(proxy("socks5://[fe80::1]"), Some((ProxyKind::Socks5, "fe80::1".into(), 1080)));
        for broken in ["proxy:8080", "ftp://x:1", "http://", "http://x:0", "http://x:99999", "http://ich:geheim@x:1", "http://@x:1", "http://x/pfad", "socks5://-x", "http://a b:1"] {
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

        // Identität oben, einzelner Benutzer tiefer: Der tiefere Wert gewinnt, der Schlüssel bleibt aus der Identität.
        let auth = resolve_auth(&[&with_identity, &user_www, &empty], find);
        assert_eq!((auth.identity, auth.user, auth.key), (Some("i1"), Some("www"), Some("k1")));

        // Einzelner Benutzer oben, Identität tiefer: Die Identität überstimmt ihn.
        let auth = resolve_auth(&[&user_www, &with_identity, &empty], find);
        assert_eq!((auth.user, auth.key), (Some("deploy"), Some("k1")));

        // Auf derselben Ebene gewinnt das einzeln eingetragene Feld.
        let both = Fields { identity: Some("i1".into()), user: Some("admin".into()), key: Some("k2".into()), ..Fields::default() };
        let auth = resolve_auth(&[&both], find);
        assert_eq!((auth.user, auth.key), (Some("admin"), Some("k2")));

        // „Ausdrücklich keine“ am Host hebt die geerbte Identität auf, „ausdrücklich keiner“ den Schlüssel.
        let none = Fields { identity: Some(String::new()), ..Fields::default() };
        assert_eq!(resolve_auth(&[&with_identity, &none], find), Auth::default());
        let no_key = Fields { key: Some(String::new()), ..Fields::default() };
        let auth = resolve_auth(&[&with_identity, &no_key], find);
        assert_eq!((auth.user, auth.key), (Some("deploy"), None));

        // Eine gelöschte Identität wirkt nicht mehr; die einzelnen Felder gelten wieder.
        let gone = Fields { identity: Some("weg".into()), ..Fields::default() };
        let auth = resolve_auth(&[&user_www, &gone], find);
        assert_eq!((auth.identity, auth.user), (None, Some("www")));

        // Schlüsseldatei: leer zählt als nicht gesetzt.
        let file = Fields { key_file: Some("C:/k".into()), ..Fields::default() };
        assert_eq!(resolve_auth(&[&file, &empty], find).key_file, Some("C:/k"));
    }

    #[test]
    fn keys_and_identities_keep_secrets_out_of_debug_output() {
        let json = r#"{"t":"key","name":"arbeit","kind":"ed25519","bits":256,"fingerprint":"SHA256:x","public":"ssh-ed25519 AAAA","private":"-----BEGIN geheim","origin":"generated","addedAt":5,"neu":1}"#;
        let Payload::Key(key) = serde_json::from_str::<Payload>(json).unwrap() else { panic!("kein Schlüssel") };
        assert_eq!((key.kind, key.origin, key.added_at, key.extra["neu"].as_u64()), (KeyKind::Ed25519, KeyOrigin::Generated, 5, Some(1)));
        assert!(!format!("{key:?}").contains("geheim"));

        let json = r#"{"t":"identity","name":"Deploy","user":"deploy","key":"k1","password":"hunter2"}"#;
        let Payload::Identity(identity) = serde_json::from_str::<Payload>(json).unwrap() else { panic!("keine Identität") };
        assert_eq!(identity.key.as_deref(), Some("k1"));
        assert!(!format!("{identity:?}").contains("hunter2"));
    }

    #[test]
    fn proxmox_connections_and_links_keep_what_they_do_not_know() {
        let json = r#"{"t":"proxmox","name":"Dedi","address":"https://pve.example.de:8006","tokenId":"glowport@pve!glowport","secret":"0c6f2c1e","fingerprint":"5F:1A","neu":1}"#;
        let Payload::Proxmox(connection) = serde_json::from_str::<Payload>(json).unwrap() else { panic!("keine Verbindung") };
        assert_eq!((connection.token_id.as_str(), connection.fingerprint.as_deref(), connection.extra["neu"].as_u64()), ("glowport@pve!glowport", Some("5F:1A"), Some(1)));
        assert!(!format!("{connection:?}").contains("0c6f2c1e"));
        let back: Value = serde_json::to_value(Payload::Proxmox(connection)).unwrap();
        assert_eq!((back["t"].as_str(), back["tokenId"].as_str(), back["neu"].as_u64()), (Some("proxmox"), Some("glowport@pve!glowport"), Some(1)));

        // Die Verknüpfung am Host: ohne sie steht nichts im Datensatz, mit ihr bleibt auch Unbekanntes stehen.
        assert!(serde_json::to_value(Payload::Host(host(Fields::default()))).unwrap().get("proxmox").is_none());
        let json = r#"{"t":"host","name":"web","address":"10.0.0.1","proxmox":{"connection":"c1","node":"pve","vmid":101,"kind":"qemu","name":"web","spaeter":true}}"#;
        let Payload::Host(linked) = serde_json::from_str::<Payload>(json).unwrap() else { panic!("kein Host") };
        let link = linked.proxmox.clone().unwrap();
        assert_eq!((link.vmid, link.kind.as_str(), link.name.as_deref(), link.address), (101, GUEST_QEMU, Some("web"), None));
        assert_eq!(serde_json::to_value(Payload::Host(linked)).unwrap()["proxmox"]["spaeter"], true);
    }

    #[test]
    fn secrets_stay_out_of_debug_output() {
        let mut host = host(Fields::default());
        host.password = Some(Secret::new("hunter2".into()));
        assert!(!format!("{host:?}").contains("hunter2"));
    }
}

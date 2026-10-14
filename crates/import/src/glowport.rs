//! Das eigene Austauschformat: eine JSON-Datei mit Hosts, Gruppen samt ihren Vorgaben, Port-Regeln, Snippets und
//! bekannten Hosts. **Nie Geheimnisse:** keine Passwörter, keine privaten Schlüssel, keine Identitäten. Die
//! vollständige Kopie eines Tresors ist die verschlüsselte Sicherung.
//!
//! Geschrieben wird die Datei von der Brücke (sie kennt den Tresor), gelesen hier.

use std::collections::HashMap;

use glowport_core::model::{Fields, ForwardKind, Ftp, FtpSecurity, Reconnect, Serial};
use serde::{Deserialize, Serialize};

use crate::{host_name, unreadable, usable_address, Draft, DraftForward, DraftGroup, DraftHost, DraftKnownHost, DraftSnippet, ImportError, Jump, Protocol, Result, Values};

/// Wird erhöht, wenn eine ältere Version von Glowport die Datei nicht mehr richtig lesen könnte.
pub const VERSION: u32 = 1;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Export {
    /// Fassung des Formats; an diesem Feld erkennt Glowport die Datei.
    pub glowport: u32,
    /// Version des Programms, das die Datei geschrieben hat, nur zur Auskunft.
    #[serde(default)]
    pub app: String,
    /// Zeitpunkt in Millisekunden seit 1970.
    #[serde(default)]
    pub exported: i64,
    #[serde(default)]
    pub groups: Vec<Group>,
    #[serde(default)]
    pub hosts: Vec<Host>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forwards: Vec<Forward>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub snippets: Vec<Snippet>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub known_hosts: Vec<KnownHost>,
}

/// Eine Gruppe. `id` gilt nur innerhalb der Datei; `parent` und der `group` eines Hosts verweisen darauf.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Group {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    /// Vorgaben für alles in der Gruppe. `identity` und `key` stehen nie darin; der Benutzer einer Identität
    /// steht als `user`. `jump` ist die `id` eines Hosts derselben Datei.
    #[serde(default)]
    pub defs: Fields,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Host {
    pub id: String,
    pub name: String,
    pub address: String,
    /// Fehlt bei SSH.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// Die Leitung eines seriellen Hosts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<Serial>,
    /// Verschlüsselung und Anmeldung eines FTP-Hosts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ftp: Option<Ftp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    #[serde(default)]
    pub own: Fields,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Forward {
    pub name: String,
    pub kind: ForwardKind,
    /// `id` eines Hosts derselben Datei.
    pub host: String,
    #[serde(default)]
    pub bind_address: String,
    pub bind_port: u16,
    #[serde(default)]
    pub dest_host: String,
    #[serde(default)]
    pub dest_port: u16,
}

/// Ein gespeicherter Befehl. Makros fehlen mit Absicht: Sie enthalten, was getippt wurde, womöglich ein Passwort.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Snippet {
    pub name: String,
    #[serde(default)]
    pub package: String,
    pub command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KnownHost {
    pub host: String,
    pub port: u16,
    pub algorithm: String,
    pub fingerprint: String,
    /// Öffentlicher Schlüssel im OpenSSH-Format ohne Kommentar.
    pub key: String,
}

/// Überträgt vererbbare Werte in den Entwurf. Der Sprung-Server wird danach eingetragen, wenn alle Hosts da sind.
fn values(fields: &Fields, draft: &mut Draft) -> Values {
    Values {
        user: fields.user.clone().filter(|u| !u.is_empty()),
        port: fields.port.filter(|p| *p != 0),
        jump: Jump::Unset,
        key: fields.key_file.as_deref().and_then(|file| draft.key_file(file)),
        agent: fields.agent,
        agent_forward: fields.agent_forward,
        proxy: fields.proxy.clone(),
        startcmd: fields.startcmd.clone(),
        env: fields.env.clone(),
        keepalive: fields.keepalive,
        timeout: fields.timeout,
        term: fields.term.clone(),
        legacy: fields.legacy,
        scheme: fields.scheme.clone(),
        charset: fields.charset.clone(),
        reconnect: fields.reconnect.map(|r| if r == Reconnect::Auto { "auto" } else { "notice" }.to_string()),
        mosh: fields.mosh,
        mosh_predict: fields.mosh_predict.clone(),
        mosh_port: fields.mosh_port.clone(),
        mosh_server: fields.mosh_server.clone(),
    }
}

pub fn parse(text: &str) -> Result<Draft> {
    let file: Export = match serde_json::from_str(text.trim_start_matches('\u{feff}')) {
        Ok(file) => file,
        Err(e) => return unreadable(e.to_string()),
    };
    if file.glowport == 0 {
        return Err(ImportError::Unknown);
    }
    let mut draft = Draft::default();

    let group_at: HashMap<&str, usize> = file.groups.iter().enumerate().map(|(i, g)| (g.id.as_str(), i)).collect();
    for group in &file.groups {
        // Eine Gruppe, die sich über ihre Eltern selbst enthält, wandert nach oben, statt den Import zu sprengen.
        let mut parent = group.parent.as_deref().and_then(|p| group_at.get(p).copied());
        let mut seen = vec![group_at[group.id.as_str()]];
        let mut walk = parent;
        while let Some(at) = walk {
            if seen.contains(&at) {
                parent = None;
                break;
            }
            seen.push(at);
            walk = file.groups[at].parent.as_deref().and_then(|p| group_at.get(p).copied());
        }
        let defs = values(&group.defs, &mut draft);
        draft.groups.push(DraftGroup { name: group.name.chars().take(80).collect(), parent, color: group.color.clone(), defs });
    }

    let mut host_at: HashMap<&str, usize> = HashMap::new();
    for host in &file.hosts {
        if !usable_address(host.address.trim()) {
            draft.skip(host.name.clone(), "invalid");
            continue;
        }
        let protocol = match (host.protocol.as_deref(), host.serial) {
            (None | Some("ssh"), _) => Protocol::Ssh,
            (Some("telnet"), _) => Protocol::Telnet,
            (Some("serial"), Some(line)) if line.baud_valid() && line.frame_valid() => Protocol::Serial,
            (Some("ftp"), _) => Protocol::Ftp,
            // Ein Protokoll aus einer neueren Fassung, oder eine Leitung, die es nicht geben kann.
            _ => {
                draft.skip(host.name.clone(), "protocol_other");
                continue;
            }
        };
        let own = values(&host.own, &mut draft);
        host_at.insert(host.id.as_str(), draft.hosts.len());
        draft.hosts.push(DraftHost {
            name: host_name(&host.name, &host.address),
            address: host.address.trim().to_string(),
            protocol,
            serial: host.serial.filter(|_| protocol == Protocol::Serial),
            // Ohne Angabe gilt, was auch ein neuer FTP-Host bekommt: FTPS, nicht anonym.
            ftp: (protocol == Protocol::Ftp).then(|| host.ftp.clone().unwrap_or(Ftp { security: FtpSecurity::Explicit, anonymous: false, dir: None, plain_ok: false })),
            group: host.group.as_deref().and_then(|g| group_at.get(g).copied()),
            color: host.color.clone(),
            os: host.os.clone(),
            own,
            ..DraftHost::default()
        });
    }
    let jump = |fields: &Fields| match fields.jump.as_deref() {
        None => Jump::Unset,
        Some("") => Jump::None,
        Some(id) => host_at.get(id).copied().map(Jump::Host).unwrap_or(Jump::Unset),
    };
    for (at, group) in file.groups.iter().enumerate() {
        draft.groups[at].defs.jump = jump(&group.defs);
    }
    for host in &file.hosts {
        if let Some(at) = host_at.get(host.id.as_str()) {
            draft.hosts[*at].own.jump = jump(&host.own);
        }
    }

    for rule in &file.forwards {
        match host_at.get(rule.host.as_str()) {
            Some(host) if rule.bind_port != 0 => draft.forwards.push(DraftForward {
                name: rule.name.clone(),
                kind: rule.kind,
                host: *host,
                bind_address: if rule.bind_address.is_empty() { "127.0.0.1".into() } else { rule.bind_address.clone() },
                bind_port: rule.bind_port,
                dest_host: rule.dest_host.clone(),
                dest_port: rule.dest_port,
            }),
            _ => draft.skip(rule.name.clone(), "invalid"),
        }
    }
    draft.snippets = file.snippets.iter().filter(|s| !s.command.trim().is_empty()).map(|s| DraftSnippet { name: s.name.clone(), package: s.package.clone(), command: s.command.clone() }).collect();
    draft.known_hosts = file
        .known_hosts
        .iter()
        .filter(|k| usable_address(&k.host) && k.port != 0 && k.key.split(' ').count() == 2)
        .map(|k| DraftKnownHost { host: k.host.to_lowercase(), port: k.port, algorithm: k.algorithm.clone(), fingerprint: k.fingerprint.clone(), key: k.key.clone() })
        .collect();
    Ok(draft)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeySource;

    #[test]
    fn reads_back_what_it_writes() {
        let file = Export {
            glowport: VERSION,
            app: "0.7.0".into(),
            exported: 1_790_000_000_000,
            groups: vec![
                Group { id: "g1".into(), name: "Produktiv".into(), color: Some("#FF5D6C".into()), defs: Fields { user: Some("deploy".into()), jump: Some("h1".into()), ..Fields::default() }, ..Group::default() },
                Group { id: "g2".into(), name: "Web".into(), parent: Some("g1".into()), ..Group::default() },
            ],
            hosts: vec![
                Host { id: "h1".into(), name: "bastion".into(), address: "203.0.113.10".into(), group: Some("g1".into()), own: Fields { jump: Some(String::new()), key_file: Some("C:\\keys\\a".into()), ..Fields::default() }, ..Host::default() },
                Host { id: "h2".into(), name: "web-01".into(), address: "10.20.0.11".into(), group: Some("g2".into()), os: Some("debian".into()), own: Fields { port: Some(2222), reconnect: Some(Reconnect::Notice), ..Fields::default() }, ..Host::default() },
            ],
            forwards: vec![Forward { name: "Grafana".into(), kind: ForwardKind::Local, host: "h2".into(), bind_address: "127.0.0.1".into(), bind_port: 3000, dest_host: "127.0.0.1".into(), dest_port: 3000 }],
            snippets: vec![Snippet { name: "Platz".into(), package: "System".into(), command: "df -h".into() }],
            known_hosts: vec![KnownHost { host: "203.0.113.10".into(), port: 22, algorithm: "ssh-ed25519".into(), fingerprint: "SHA256:x".into(), key: "ssh-ed25519 AAAA".into() }],
        };
        let text = serde_json::to_string_pretty(&file).unwrap();
        assert!(!text.contains("password") && !text.contains("identity"));
        let draft = parse(&text).unwrap();
        assert_eq!(draft.groups.len(), 2);
        assert_eq!((draft.groups[0].defs.user.as_deref(), draft.groups[0].defs.jump, draft.groups[1].parent), (Some("deploy"), Jump::Host(0), Some(0)));
        let bastion = &draft.hosts[0];
        assert_eq!((bastion.own.jump, bastion.group), (Jump::None, Some(0)));
        assert_eq!(draft.keys[bastion.own.key.unwrap()].source, KeySource::File("C:\\keys\\a".into()));
        let web = &draft.hosts[1];
        assert_eq!((web.own.port, web.own.reconnect.as_deref(), web.os.as_deref(), web.own.jump), (Some(2222), Some("notice"), Some("debian"), Jump::Unset));
        assert_eq!((draft.forwards[0].host, draft.forwards[0].bind_port), (1, 3000));
        assert_eq!(draft.snippets[0].command, "df -h");
        assert_eq!(draft.known_hosts[0].key, "ssh-ed25519 AAAA");
    }

    #[test]
    fn survives_foreign_and_broken_files() {
        assert!(matches!(parse("{ kaputt"), Err(ImportError::Unreadable(_))));
        assert!(matches!(parse("{\"profiles\":[]}"), Err(ImportError::Unreadable(_))));
        // Gruppen im Kreis, ein Host mit unbrauchbarer Adresse, eine Regel ohne ihren Host, unbekannte Felder.
        let text = r#"{"glowport":1,"neu":true,"groups":[{"id":"a","name":"A","parent":"b"},{"id":"b","name":"B","parent":"a"}],
            "hosts":[{"id":"h","name":"ok","address":"10.0.0.1","group":"a","own":{"jump":"fehlt","zukunft":1}},{"id":"x","name":"schlecht","address":"-oProxyCommand=x"}],
            "forwards":[{"name":"verwaist","kind":"local","host":"weg","bindPort":80}]}"#;
        let draft = parse(text).unwrap();
        assert_eq!(draft.hosts.len(), 1);
        assert!(draft.groups.iter().any(|g| g.parent.is_none()));
        assert_eq!(draft.hosts[0].own.jump, Jump::Unset);
        assert_eq!(draft.skipped.iter().map(|s| s.reason).collect::<Vec<_>>(), ["invalid", "invalid"]);
    }
}

//! Programme, die ihre Verbindungen als XML ablegen: mRemoteNG (`confCons.xml`), FileZilla (`sitemanager.xml`) und
//! SecureCRT (XML-Export; dazu dessen Sitzungsdateien, die dieselben Namen benutzen).

use base64::Engine;
use glowport_core::model::{Flow, FtpSecurity, Parity, Secret};
use roxmltree::{Document, Node};

use crate::{ftp_host, host_name, port, serial_host, serial_line, telnet_host, unreadable, usable_address, usable_serial_port, Draft, DraftHost, Entries, ImportError, Protocol, Result};

fn document(text: &str) -> Result<Document<'_>> {
    Document::parse(text.trim_start_matches('\u{feff}')).or_else(|e| unreadable(e.to_string()))
}

fn attribute<'a>(node: Node<'a, '_>, name: &str) -> Option<&'a str> {
    node.attribute(name).map(str::trim).filter(|v| !v.is_empty())
}

/// mRemoteNG: verschachtelte `Node`-Elemente, Ordner mit `Type="Container"`. Passwörter sind dort immer
/// verschlüsselt und bleiben zurück.
pub fn mremoteng(text: &str) -> Result<Draft> {
    let doc = document(text)?;
    let root = doc.root_element();
    if root.tag_name().name() != "Connections" {
        return Err(ImportError::Unknown);
    }
    if root.attribute("FullFileEncryption").is_some_and(|v| v.eq_ignore_ascii_case("true")) {
        return Err(ImportError::Protected);
    }
    fn walk(node: Node, path: &mut Vec<String>, draft: &mut Draft) {
        for child in node.children().filter(|c| c.is_element() && c.tag_name().name() == "Node") {
            let name = attribute(child, "Name").unwrap_or_default().to_string();
            if child.attribute("Type").is_some_and(|t| t.eq_ignore_ascii_case("Container")) {
                path.push(name);
                walk(child, path, draft);
                path.pop();
                continue;
            }
            let protocol = attribute(child, "Protocol").unwrap_or("RDP").to_ascii_uppercase();
            let reason = match protocol.as_str() {
                "SSH2" | "SSH1" | "TELNET" => None,
                "RDP" => Some("protocol_rdp"),
                "VNC" => Some("protocol_vnc"),
                _ => Some("protocol_other"),
            };
            if let Some(reason) = reason {
                draft.skip(name, reason);
                continue;
            }
            let Some(address) = attribute(child, "Hostname").filter(|a| usable_address(a)) else {
                draft.skip(name, "no_address");
                continue;
            };
            if protocol == "TELNET" {
                let group = draft.group_at(path);
                draft.hosts.push(telnet_host(&name, address, attribute(child, "Port").and_then(port), attribute(child, "Username").map(str::to_string), group));
                continue;
            }
            let mut host = DraftHost { name: host_name(&name, address), address: address.to_string(), group: draft.group_at(path), ..DraftHost::default() };
            host.own.user = attribute(child, "Username").map(str::to_string);
            host.own.port = attribute(child, "Port").and_then(port).filter(|p| *p != 22);
            host.password_lost = attribute(child, "Password").is_some();
            draft.hosts.push(host);
        }
    }
    let mut draft = Draft::default();
    walk(root, &mut Vec::new(), &mut draft);
    Ok(draft)
}

fn child_text<'a>(node: Node<'a, '_>, name: &str) -> Option<&'a str> {
    node.children().find(|c| c.is_element() && c.tag_name().name() == name).and_then(|c| c.text()).map(str::trim).filter(|v| !v.is_empty())
}

/// FileZilla: `Server`-Einträge in verschachtelten `Folder`-Elementen. Übernommen wird, was SFTP oder FTP spricht.
pub fn filezilla(text: &str) -> Result<Draft> {
    let doc = document(text)?;
    let root = doc.root_element();
    if root.tag_name().name() != "FileZilla3" {
        return Err(ImportError::Unknown);
    }
    fn walk(node: Node, path: &mut Vec<String>, draft: &mut Draft) {
        for child in node.children().filter(Node::is_element) {
            match child.tag_name().name() {
                "Folder" => {
                    // Der Name eines Ordners steht als Text direkt im Element, vor seinen Kindern.
                    path.push(child.children().find(|c| c.is_text()).and_then(|c| c.text()).unwrap_or_default().trim().to_string());
                    walk(child, path, draft);
                    path.pop();
                }
                "Servers" => walk(child, path, draft),
                "Server" => {
                    let name = child_text(child, "Name").unwrap_or_default().to_string();
                    // 0 = FTP, 1 = SFTP, 3 und 4 = FTP über TLS, 6 = FTP ohne Verschlüsselung.
                    let kind = child_text(child, "Protocol").unwrap_or("0");
                    match kind {
                        "0" | "1" | "3" | "4" | "6" => {}
                        _ => {
                            draft.skip(name, "protocol_other");
                            continue;
                        }
                    }
                    let Some(address) = child_text(child, "Host").filter(|a| usable_address(a)) else {
                        draft.skip(name, "no_address");
                        continue;
                    };
                    let mut host = if kind == "1" {
                        let mut host = DraftHost { name: host_name(&name, address), address: address.to_string(), group: draft.group_at(path), ..DraftHost::default() };
                        host.own.user = child_text(child, "User").map(str::to_string);
                        host.own.port = child_text(child, "Port").and_then(port).filter(|p| *p != 22);
                        host.own.key = child_text(child, "Keyfile").and_then(|file| draft.key_file(file));
                        host
                    } else {
                        // „FTP“ (0) heißt bei FileZilla: verschlüsselt, wenn der Server es kann, sonst offen. Glowport
                        // verbindet dann nur verschlüsselt und sagt dazu, dass das zu prüfen ist.
                        let (security, sure) = match kind {
                            "3" => (FtpSecurity::Implicit, true),
                            "6" => (FtpSecurity::None, true),
                            "4" => (FtpSecurity::Explicit, true),
                            _ => (FtpSecurity::Explicit, false),
                        };
                        // Anmeldeart 0 ist die anonyme.
                        let user = child_text(child, "User").filter(|_| child_text(child, "Logontype") != Some("0")).map(str::to_string);
                        let group = draft.group_at(path);
                        ftp_host(&name, address, child_text(child, "Port").and_then(port), user, security, sure, group)
                    };
                    let keeps_password = host.protocol != Protocol::Ftp || host.own.user.is_some();
                    if let Some(pass) = child.children().find(|c| c.is_element() && c.tag_name().name() == "Pass").filter(|_| keeps_password) {
                        let value = pass.text().unwrap_or_default().trim();
                        let clear = match pass.attribute("encoding") {
                            Some("base64") => base64::engine::general_purpose::STANDARD.decode(value).ok().and_then(|b| String::from_utf8(b).ok()),
                            // `crypt`: mit dem Master-Passwort von FileZilla verschlüsselt.
                            Some(_) => None,
                            None => Some(value.to_string()),
                        };
                        match clear {
                            Some(password) if !password.is_empty() => host.password = Some(Secret::new(password)),
                            Some(_) => {}
                            None => host.password_lost = true,
                        }
                    }
                    draft.hosts.push(host);
                }
                _ => {}
            }
        }
    }
    let mut draft = Draft::default();
    walk(root, &mut Vec::new(), &mut draft);
    Ok(draft)
}

/// Eine SecureCRT-Sitzung aus ihren Werten: dieselben Namen stehen im XML-Export und in den Sitzungsdateien.
fn securecrt_session(name: &str, path: &[String], values: &Entries, draft: &mut Draft) {
    let value = |key: &str| values.get(key).map(|v| v.trim()).filter(|v| !v.is_empty());
    let protocol = value("Protocol Name").unwrap_or("SSH2");
    let upper = protocol.to_ascii_uppercase();
    if upper == "SERIAL" {
        let number = |key: &str| value(key).and_then(|text| text.parse::<u32>().ok());
        let Some(line) = value("Com Port").filter(|line| usable_serial_port(line)) else {
            draft.skip(name, "no_address");
            return;
        };
        let parity = match number("Parity") {
            Some(1) => Parity::Odd,
            Some(2) => Parity::Even,
            _ => Parity::None,
        };
        let flow = if number("RTS Flow Control").or(number("CTS Flow")) == Some(1) {
            Flow::Hardware
        } else if number("XON Flow") == Some(1) {
            Flow::Software
        } else {
            Flow::None
        };
        // SecureCRT zählt Stoppbits ab null: 0 ist eines, 2 sind zwei.
        let group = draft.group_at(path);
        draft.hosts.push(serial_host(name, line, serial_line(number("Baud Rate"), number("Data Bits"), parity, number("Stop Bits") == Some(2), flow), group));
        return;
    }
    let reason = match upper.as_str() {
        "SSH2" | "SSH1" | "TELNET" => None,
        // Telnet über TLS kann Glowport nicht.
        "TELNET/SSL" | "TELNET/TLS" => Some("protocol_other"),
        "RDP" => Some("protocol_rdp"),
        _ => Some("protocol_other"),
    };
    if let Some(reason) = reason {
        draft.skip(name, reason);
        return;
    }
    let Some(address) = value("Hostname").filter(|a| usable_address(a)) else {
        draft.skip(name, "no_address");
        return;
    };
    if upper == "TELNET" {
        let group = draft.group_at(path);
        draft.hosts.push(telnet_host(name, address, value("Port").and_then(port), value("Username").map(str::to_string), group));
        return;
    }
    let mut host = DraftHost { name: host_name(name, address), address: address.to_string(), group: draft.group_at(path), ..DraftHost::default() };
    host.own.user = value("Username").map(str::to_string);
    host.own.port = value(&format!("[{protocol}] Port")).and_then(port).filter(|p| *p != 22);
    // Hinter dem Pfad steht bei SecureCRT, wie der Schlüssel abgelegt ist (`::rawkey`).
    host.own.key = value("Identity Filename V2").map(|file| file.split("::").next().unwrap_or(file)).filter(|f| !f.is_empty()).and_then(|file| draft.key_file(file));
    host.password_lost = value("Password V2").is_some() || value("Password").is_some();
    draft.hosts.push(host);
}

/// SecureCRT, XML-Export (Tools → Export Settings): `key`-Elemente als Ordner und Sitzungen unter `Sessions`.
pub fn securecrt(text: &str) -> Result<Draft> {
    let doc = document(text)?;
    let root = doc.root_element();
    if root.tag_name().name() != "VanDyke" {
        return Err(ImportError::Unknown);
    }
    fn walk(node: Node, path: &mut Vec<String>, draft: &mut Draft) {
        for child in node.children().filter(|c| c.is_element() && c.tag_name().name() == "key") {
            let name = child.attribute("name").unwrap_or_default().to_string();
            let mut values = Entries::new();
            for value in child.children().filter(|c| c.is_element() && matches!(c.tag_name().name(), "string" | "dword")) {
                if let Some(key) = value.attribute("name") {
                    values.insert(key.to_string(), value.text().unwrap_or_default().to_string());
                }
            }
            if values.contains_key("Hostname") || values.contains_key("Protocol Name") {
                // „Default“ ist die Vorlage für neue Sitzungen.
                if name != "Default" || values.get("Hostname").is_some_and(|h| !h.trim().is_empty()) {
                    securecrt_session(&name, path, &values, draft);
                }
            } else {
                path.push(name);
                walk(child, path, draft);
                path.pop();
            }
        }
    }
    let mut draft = Draft::default();
    let sessions = root.children().find(|c| c.is_element() && c.attribute("name") == Some("Sessions")).unwrap_or(root);
    walk(sessions, &mut Vec::new(), &mut draft);
    Ok(draft)
}

/// SecureCRT, Ordner `Sessions` aus dem Konfigurationsordner: je Sitzung eine Datei mit Zeilen wie
/// `S:"Hostname"=web.example.org` und `D:"[SSH2] Port"=00000016`. `files`: Pfad unterhalb des Ordners und Inhalt.
pub fn securecrt_files(files: &[(String, String)]) -> Draft {
    let mut draft = Draft::default();
    for (path, text) in files {
        let mut parts: Vec<String> = path.split(['\\', '/']).map(str::to_string).collect();
        let Some(name) = parts.pop().and_then(|file| file.strip_suffix(".ini").map(str::to_string)) else { continue };
        if name.starts_with("__") || name == "Default" {
            continue;
        }
        let mut values = Entries::new();
        for line in text.lines() {
            let Some((kind, rest)) = line.trim().split_once(":\"") else { continue };
            let Some((key, value)) = rest.split_once("\"=") else { continue };
            let value = match kind {
                "D" => u32::from_str_radix(value.trim(), 16).map(|n| n.to_string()).unwrap_or_default(),
                "S" => value.to_string(),
                _ => continue,
            };
            values.insert(key.to_string(), value);
        }
        securecrt_session(&name, &parts, &values, &mut draft);
    }
    draft
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeySource;

    #[test]
    fn reads_mremoteng() {
        let text = r#"<?xml version="1.0" encoding="utf-8"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000" FullFileEncryption="false" Protected="abc" ConfVersion="2.6">
  <Node Name="Kunden" Type="Container" Expanded="true">
    <Node Name="Meier" Type="Container">
      <Node Name="web" Type="Connection" Hostname="web.meier.example" Protocol="SSH2" Port="2222" Username="admin" Password="QUJD" />
      <Node Name="dc" Type="Connection" Hostname="dc.meier.example" Protocol="RDP" Port="3389" />
    </Node>
    <Node Name="ohne" Type="Connection" Hostname="" Protocol="SSH2" />
  </Node>
  <Node Name="nas" Type="Connection" Hostname="192.168.1.20" Protocol="SSH2" Port="22" Username="" Password="" />
</mrng:Connections>"#;
        let draft = mremoteng(text).unwrap();
        assert_eq!(draft.hosts.len(), 2);
        let web = &draft.hosts[0];
        assert_eq!((web.name.as_str(), web.own.port, web.own.user.as_deref(), web.password_lost), ("web", Some(2222), Some("admin"), true));
        assert_eq!(draft.groups[web.group.unwrap()].name, "Meier");
        assert_eq!((draft.hosts[1].group, draft.hosts[1].password_lost), (None, false));
        assert_eq!(draft.skipped.iter().map(|s| s.reason).collect::<Vec<_>>(), ["protocol_rdp", "no_address"]);
        assert_eq!(mremoteng(&text.replace("FullFileEncryption=\"false\"", "FullFileEncryption=\"true\"")), Err(ImportError::Protected));
        assert_eq!(mremoteng("<Anderes/>"), Err(ImportError::Unknown));
        assert!(matches!(mremoteng("<kaputt"), Err(ImportError::Unreadable(_))));
    }

    #[test]
    fn reads_filezilla() {
        let text = r#"<?xml version="1.0" encoding="UTF-8"?>
<FileZilla3 version="3.67.0" platform="windows">
  <Servers>
    <Folder expanded="1">Kunden
      <Server><Host>sftp.kunde.example</Host><Port>2222</Port><Protocol>1</Protocol><Type>0</Type><User>web1</User><Pass encoding="base64">Z2VoZWlt</Pass><Logontype>1</Logontype><Name>Kunde SFTP</Name></Server>
      <Server><Host>ftp.kunde.example</Host><Port>21</Port><Protocol>0</Protocol><Name>Kunde FTP</Name></Server>
      <Server><Host>10.0.0.60</Host><Port>2121</Port><Protocol>6</Protocol><User>scan</User><Pass encoding="base64">Z2VoZWlt</Pass><Logontype>1</Logontype><Name>Scanner</Name></Server>
      <Server><Host>alt.example</Host><Port>990</Port><Protocol>3</Protocol><User>anonymous</User><Pass encoding="base64">Z2VoZWlt</Pass><Logontype>0</Logontype><Name>Alt</Name></Server>
      <Server><Host>neu.example</Host><Port>21</Port><Protocol>4</Protocol><User>web2</User><Logontype>2</Logontype><Name>Neu</Name></Server>
    </Folder>
    <Server><Host>nas.local</Host><Port>22</Port><Protocol>1</Protocol><User>admin</User><Pass encoding="crypt" pubkey="x" salt="y">zzz</Pass><Keyfile>C:\keys\nas.ppk</Keyfile><Name>NAS</Name></Server>
  </Servers>
</FileZilla3>"#;
        let draft = filezilla(text).unwrap();
        assert_eq!(draft.hosts.len(), 6);
        let customer = &draft.hosts[0];
        assert_eq!((customer.name.as_str(), customer.own.port, customer.own.user.as_deref()), ("Kunde SFTP", Some(2222), Some("web1")));
        assert_eq!(customer.password.as_ref().map(|p| p.expose()), Some("geheim"));
        assert_eq!(draft.groups[customer.group.unwrap()].name, "Kunden");
        let nas = &draft.hosts[5];
        assert!(nas.password.is_none() && nas.password_lost);
        assert_eq!(draft.keys[nas.own.key.unwrap()].source, KeySource::File("C:\\keys\\nas.ppk".into()));
        // FTP: „verschlüsselt, wenn möglich“ wird FTPS mit dem Hinweis, das zu prüfen; die anderen Arten sind eindeutig.
        let ftp: Vec<_> = draft.hosts[1..5].iter().map(|h| (h.name.as_str(), h.protocol, h.ftp.as_ref().map(|f| (f.security, f.anonymous)), h.own.port, h.own.user.as_deref(), h.notes.iter().map(|n| n.code).collect::<Vec<_>>())).collect();
        assert_eq!(
            ftp,
            [
                ("Kunde FTP", Protocol::Ftp, Some((FtpSecurity::Explicit, true)), None, None, vec!["ftp_security"]),
                ("Scanner", Protocol::Ftp, Some((FtpSecurity::None, false)), Some(2121), Some("scan"), vec![]),
                ("Alt", Protocol::Ftp, Some((FtpSecurity::Implicit, true)), None, None, vec![]),
                ("Neu", Protocol::Ftp, Some((FtpSecurity::Explicit, false)), None, Some("web2"), vec![]),
            ]
        );
        assert_eq!(draft.hosts[2].password.as_ref().map(|p| p.expose()), Some("geheim"));
        assert!(draft.hosts[3].password.is_none(), "ein anonymer Host hält kein Passwort");
        assert!(draft.skipped.is_empty());
    }

    #[test]
    fn reads_securecrt() {
        let text = r#"<?xml version="1.0" encoding="UTF-8"?>
<VanDyke version="3.0">
  <key name="Sessions">
    <key name="Default"><string name="Hostname"></string><string name="Protocol Name">SSH2</string></key>
    <key name="Rechenzentrum">
      <key name="core-01">
        <string name="Hostname">10.0.0.1</string>
        <dword name="[SSH2] Port">2200</dword>
        <string name="Username">netadmin</string>
        <string name="Protocol Name">SSH2</string>
        <string name="Identity Filename V2">C:\keys\core.pem::rawkey</string>
        <string name="Password V2">02:abcdef</string>
      </key>
      <key name="konsole"><string name="Hostname">10.0.0.2</string><string name="Protocol Name">Telnet</string></key>
    </key>
  </key>
</VanDyke>"#;
        let draft = securecrt(text).unwrap();
        assert_eq!(draft.hosts.len(), 2);
        assert_eq!((draft.hosts[1].name.as_str(), draft.hosts[1].protocol, draft.hosts[1].own.port), ("konsole", crate::Protocol::Telnet, None));
        let core = &draft.hosts[0];
        assert_eq!((core.name.as_str(), core.own.port, core.own.user.as_deref(), core.password_lost), ("core-01", Some(2200), Some("netadmin"), true));
        assert_eq!(draft.groups[core.group.unwrap()].name, "Rechenzentrum");
        assert_eq!(draft.keys[0].source, KeySource::File("C:\\keys\\core.pem".into()));
        assert!(draft.skipped.is_empty());

        let files = [
            ("Rechenzentrum\\core-02.ini".to_string(), "S:\"Hostname\"=10.0.0.3\r\nS:\"Username\"=netadmin\r\nD:\"[SSH2] Port\"=00000898\r\nS:\"Protocol Name\"=SSH2\r\n".to_string()),
            ("Default.ini".to_string(), "S:\"Hostname\"=\r\n".to_string()),
            ("__FolderData__.ini".to_string(), "S:\"Is Expanded\"=1\r\n".to_string()),
            // Eine serielle Sitzung: 115200 Baud, 7 Datenbits, gerade Parität, zwei Stoppbits, RTS/CTS.
            ("Labor\\konsole.ini".to_string(), "S:\"Protocol Name\"=Serial\r\nS:\"Com Port\"=COM4\r\nD:\"Baud Rate\"=0001c200\r\nD:\"Data Bits\"=00000007\r\nD:\"Parity\"=00000002\r\nD:\"Stop Bits\"=00000002\r\nD:\"RTS Flow Control\"=00000001\r\n".to_string()),
            ("Labor\\ohne-port.ini".to_string(), "S:\"Protocol Name\"=Serial\r\n".to_string()),
        ];
        let draft = securecrt_files(&files);
        assert_eq!(draft.hosts.len(), 2);
        assert_eq!((draft.hosts[0].name.as_str(), draft.hosts[0].own.port), ("core-02", Some(2200)));
        let console = &draft.hosts[1];
        let line = console.serial.unwrap();
        assert_eq!((console.address.as_str(), console.protocol, line.baud, line.data_bits, line.parity, line.stop_bits, line.flow), ("COM4", crate::Protocol::Serial, 115_200, 7, Parity::Even, 2, Flow::Hardware));
        assert_eq!(draft.groups[console.group.unwrap()].name, "Labor");
        assert_eq!(draft.skipped.iter().map(|s| (s.name.as_str(), s.reason)).collect::<Vec<_>>(), [("ohne-port", "no_address")]);
    }
}

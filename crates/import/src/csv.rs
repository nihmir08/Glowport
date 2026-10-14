//! CSV tables with a header line. Columns are read by name, in any order; that fits
//! the table Termius describes for its own import (`Groups,Label,Tags,Hostname/IP,Protocol,Port,
//! Username,Password,SSH_KEY`), the files of free Termius exporters and hand-written lists.

use glowport_core::model::{Flow, FtpSecurity, Parity, Secret};

use crate::text::user_host_port;
use crate::{ftp_host, host_name, port, serial_host, serial_line, telnet_host, unreadable, usable_address, usable_serial_port, Draft, DraftHost, ImportError, Result};

const NAME: &[&str] = &["label", "name", "title", "alias", "displayname", "sessionname", "bezeichnung"];
const ADDRESS: &[&str] = &["hostnameip", "hostname", "address", "adresse", "host", "ip", "ipaddress", "ipadresse", "server", "hostip", "fqdn"];
const USER: &[&str] = &["username", "user", "login", "account", "benutzer", "benutzername"];
const PASSWORD: &[&str] = &["password", "pass", "pwd", "password", "kennwort"];
const GROUP: &[&str] = &["groups", "group", "folder", "path", "category", "gruppe", "gruppen", "ordner"];
const KEY: &[&str] = &["sshkey", "key", "keyfile", "identityfile", "privatekey", "keypath", "schlüssel", "schluessel", "schlüsseldatei"];
const PROTOCOL: &[&str] = &["protocol", "type", "protokoll"];

/// Splits the text into rows and fields. Fields in quotes may contain separators and line breaks;
/// a double quote inside stands for one.
fn rows(text: &str, delimiter: char) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = text.trim_start_matches('\u{feff}').chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                chars.next();
                field.push('"');
            }
            '"' if quoted => quoted = false,
            '"' if field.is_empty() => quoted = true,
            c if c == delimiter && !quoted => row.push(std::mem::take(&mut field)),
            '\r' if !quoted => {}
            '\n' if !quoted => {
                row.push(std::mem::take(&mut field));
                if row.iter().any(|f| !f.trim().is_empty()) {
                    rows.push(std::mem::take(&mut row));
                } else {
                    row.clear();
                }
            }
            c => field.push(c),
        }
    }
    row.push(field);
    if row.iter().any(|f| !f.trim().is_empty()) {
        rows.push(row);
    }
    rows
}

fn delimiter(text: &str) -> char {
    let head = text.lines().next().unwrap_or("");
    [',', ';', '\t'].into_iter().max_by_key(|d| head.matches(*d).count()).unwrap_or(',')
}

/// Column name without case and without characters such as `_` or `/`.
fn plain(header: &str) -> String {
    header.chars().filter(|c| c.is_alphanumeric()).flat_map(char::to_lowercase).collect()
}

fn column(headers: &[String], names: &[&str]) -> Option<usize> {
    names.iter().find_map(|name| headers.iter().position(|h| h == name))
}

/// Does the text look like a table with a header line and a column for the address?
pub fn looks_like(text: &str) -> bool {
    let all = rows(text, delimiter(text));
    all.first().is_some_and(|head| head.len() > 1 && column(&head.iter().map(|h| plain(h)).collect::<Vec<_>>(), ADDRESS).is_some())
}

pub fn parse(text: &str) -> Result<Draft> {
    let mut all = rows(text, delimiter(text)).into_iter();
    let Some(head) = all.next() else { return unreadable("empty") };
    let headers: Vec<String> = head.iter().map(|h| plain(h)).collect();
    let address = column(&headers, ADDRESS).ok_or(ImportError::Unknown)?;
    // “host” can be the name or the address; it only counts as the name if another column carries the address.
    let name = column(&headers, NAME).or_else(|| headers.iter().position(|h| h == "host").filter(|at| *at != address));
    let (user, password, group, key, protocol, port_at) = (column(&headers, USER), column(&headers, PASSWORD), column(&headers, GROUP), column(&headers, KEY), column(&headers, PROTOCOL), column(&headers, &["port", "sshport"]));

    let mut draft = Draft::default();
    for row in all {
        let cell = |at: Option<usize>| at.and_then(|i| row.get(i)).map(|v| v.trim()).filter(|v| !v.is_empty());
        let label = cell(name).unwrap_or_default().to_string();
        let Some(target) = cell(Some(address)) else {
            if !label.is_empty() {
                draft.skip(label, "no_address");
            }
            continue;
        };
        let kind = cell(protocol).unwrap_or("ssh").to_ascii_lowercase();
        let path: Vec<&str> = cell(group).map(|g| g.split(['/', '\\', '>', '›']).collect()).unwrap_or_default();
        // A serial line: the address column holds the port, the port column the baud rate.
        if kind == "serial" {
            if usable_serial_port(target) {
                let group_at = draft.group_at(&path);
                let baud = cell(port_at).and_then(|text| text.parse().ok());
                draft.hosts.push(serial_host(&label, target, serial_line(baud, None, Parity::None, false, Flow::None), group_at));
            } else {
                draft.skip(if label.is_empty() { target } else { label.as_str() }, "invalid");
            }
            continue;
        }
        let reason = match kind.as_str() {
            "ssh" | "ssh2" | "sftp" | "scp" | "mosh" | "ssh1" | "telnet" | "ftp" | "ftps" | "ftpes" => None,
            "rdp" => Some("protocol_rdp"),
            "vnc" => Some("protocol_vnc"),
            _ => Some("protocol_other"),
        };
        if let Some(reason) = reason {
            draft.skip(if label.is_empty() { target } else { label.as_str() }, reason);
            continue;
        }
        // The address column may contain `user@address:port`.
        let (user_in_target, host_part, port_in_target) = user_host_port(target);
        if !usable_address(&host_part) {
            draft.skip(if label.is_empty() { target } else { label.as_str() }, "invalid");
            continue;
        }
        if kind == "telnet" {
            let group_at = draft.group_at(&path);
            draft.hosts.push(telnet_host(&label, &host_part, cell(port_at).and_then(port).or(port_in_target), cell(user).map(str::to_string).or(user_in_target), group_at));
            continue;
        }
        if kind.starts_with("ftp") {
            // `ftp` means unencrypted, `ftps` and `ftpes` encrypted; on port 990 implicit.
            let wanted = cell(port_at).and_then(port).or(port_in_target);
            let security = match (kind.as_str(), wanted) {
                ("ftp", _) => FtpSecurity::None,
                ("ftps", Some(990)) => FtpSecurity::Implicit,
                _ => FtpSecurity::Explicit,
            };
            let group_at = draft.group_at(&path);
            let mut host = ftp_host(&label, &host_part, wanted, cell(user).map(str::to_string).or(user_in_target), security, true, group_at);
            host.password = cell(password).filter(|_| host.own.user.is_some()).map(|p| Secret::new(p.to_string()));
            draft.hosts.push(host);
            continue;
        }
        let mut host = DraftHost { name: host_name(&label, &host_part), address: host_part, group: draft.group_at(&path), ..DraftHost::default() };
        host.own.user = cell(user).map(str::to_string).or(user_in_target);
        host.own.port = cell(port_at).and_then(port).or(port_in_target).filter(|p| *p != 22);
        host.password = cell(password).map(|p| Secret::new(p.to_string()));
        // `mosh` is an SSH host whose terminal runs over Mosh.
        host.own.mosh = (kind == "mosh").then_some(true);
        host.own.key = cell(key).and_then(|value| {
            // A key can be in the cell as text (line breaks also written as `\n`) or as a file.
            let text = value.replace("\\n", "\n");
            if text.contains("PRIVATE KEY") { draft.key_text(&host.name, &text, None) } else { draft.key_file(value) }
        });
        draft.hosts.push(host);
    }
    Ok(draft)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeySource;

    #[test]
    fn a_mosh_row_becomes_an_ssh_host_with_mosh() {
        let draft = parse("Groups,Label,Tags,Hostname/IP,Protocol,Port,Username,Password,SSH_KEY
,laptop,,10.0.0.7,mosh,22,me,,
,server,,10.0.0.8,ssh,22,me,,
").unwrap();
        let laptop = draft.hosts.iter().find(|h| h.name == "laptop").unwrap();
        assert_eq!((laptop.protocol, laptop.own.mosh), (crate::Protocol::Ssh, Some(true)));
        assert_eq!(draft.hosts.iter().find(|h| h.name == "server").unwrap().own.mosh, None);
    }

    #[test]
    fn reads_the_table_termius_describes() {
        let text = "\u{feff}Groups,Label,Tags,Hostname/IP,Protocol,Port,Username,Password,SSH_KEY\r\nProduktion/Web,app-01,\"a,b\",10.1.0.11,ssh,22,deploy,\"ge\"\"heim, wirklich\",\r\nProduktion/Web,app-02,,10.1.0.12,ssh,2200,deploy,,C:\\keys\\app.pem\r\nTest,switch,,10.9.0.1,telnet,23,admin,,\r\n,ohne-adresse,,,ssh,,,,\r\n\r\n";
        let draft = parse(text).unwrap();
        let groups: Vec<_> = draft.groups.iter().map(|g| (g.name.as_str(), g.parent)).collect();
        assert_eq!(groups, [("Produktion", None), ("Web", Some(0)), ("Test", None)]);
        let first = &draft.hosts[0];
        assert_eq!((first.name.as_str(), first.address.as_str(), first.own.port, first.own.user.as_deref(), first.group), ("app-01", "10.1.0.11", None, Some("deploy"), Some(1)));
        assert_eq!(first.password.as_ref().map(|p| p.expose()), Some("ge\"heim, wirklich"));
        let second = &draft.hosts[1];
        assert_eq!(second.own.port, Some(2200));
        assert_eq!(draft.keys[second.own.key.unwrap()].source, KeySource::File("C:\\keys\\app.pem".into()));
        // The row with Telnet arrives as a host with that protocol, in its group.
        let switch = draft.hosts.iter().find(|h| h.name == "switch").unwrap();
        assert_eq!((switch.protocol, switch.own.port, switch.group), (crate::Protocol::Telnet, None, Some(2)));
        assert_eq!(draft.skipped.iter().map(|s| (s.name.as_str(), s.reason)).collect::<Vec<_>>(), [("ohne-adresse", "no_address")]);

        // A serial line: the port in the address column, the baud rate in the port column.
        let lines = "Label,Hostname/IP,Protocol,Port\nkonsole,com4,serial,115200\nkaputt,10.0.0.1,serial,\ngeraet,COM7,serial,\n";
        let draft = parse(lines).unwrap();
        let found: Vec<_> = draft.hosts.iter().map(|h| (h.name.as_str(), h.address.as_str(), h.protocol, h.serial.map(|line| line.baud))).collect();
        assert_eq!(found, [("konsole", "COM4", crate::Protocol::Serial, Some(115_200)), ("geraet", "COM7", crate::Protocol::Serial, Some(9600))]);
        assert_eq!(draft.skipped.iter().map(|s| (s.name.as_str(), s.reason)).collect::<Vec<_>>(), [("kaputt", "invalid")]);
    }

    #[test]
    fn reads_other_tables() {
        // The file of a free Termius exporter: key as a name, comma as separator, everything in quotes.
        let exported = "Label,Host,Port,Username,Password,SSH_Key,OS\n\"web\",\"203.0.113.5\",\"22\",\"root\",\"pw\",\"arbeit\",\"ubuntu\"\n";
        let draft = parse(exported).unwrap();
        assert_eq!((draft.hosts[0].name.as_str(), draft.hosts[0].address.as_str()), ("web", "203.0.113.5"));
        assert_eq!(draft.keys[0].source, KeySource::File("arbeit".into()));

        // German spreadsheet programs separate with semicolons; the address may carry user and port.
        let german = "Name;Adresse;Gruppe\nnas;admin@192.168.1.20:2222;Zuhause\\Keller\n;pi.local;\n";
        let draft = parse(german).unwrap();
        assert_eq!((draft.hosts[0].own.user.as_deref(), draft.hosts[0].own.port, draft.hosts[0].address.as_str()), (Some("admin"), Some(2222), "192.168.1.20"));
        assert_eq!(draft.groups.len(), 2);
        assert_eq!(draft.hosts[1].name, "pi.local");

        // A key as text in the cell, over several lines.
        let inline = "name,host,key\nweb,10.0.0.1,\"-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\"\n";
        let draft = parse(inline).unwrap();
        assert!(matches!(&draft.keys[0].source, KeySource::Text(text) if text.expose().lines().count() == 3));

        assert!(looks_like(exported) && looks_like(german));
        assert!(!looks_like("irgendein text\nohne spalten\n"));
        assert_eq!(parse("a,b\n1,2\n"), Err(ImportError::Unknown));
    }

    #[test]
    fn reads_ftp_lines_with_their_encryption() {
        let text = "Label,Hostname/IP,Protocol,Port,Username,Password\nweb,ftp.example.org,ftp,,web1,geheim\nsicher,ftps.example.org,ftps,990,web2,\nauch,ftp2.example.org,ftpes,2121,,nutzlos\nmit-adresse,kunde@ftp3.example.org:2122,FTPS,,,\n";
        let draft = parse(text).unwrap();
        let found: Vec<_> = draft.hosts.iter().map(|h| (h.name.as_str(), h.address.as_str(), h.protocol, h.ftp.as_ref().map(|f| (f.security, f.anonymous)), h.own.port, h.own.user.as_deref(), h.password.as_ref().map(|p| p.expose()))).collect();
        assert_eq!(
            found,
            [
                // `ftp` is unencrypted; Glowport warns about that when connecting.
                ("web", "ftp.example.org", crate::Protocol::Ftp, Some((FtpSecurity::None, false)), None, Some("web1"), Some("geheim")),
                ("sicher", "ftps.example.org", crate::Protocol::Ftp, Some((FtpSecurity::Implicit, false)), None, Some("web2"), None),
                ("auch", "ftp2.example.org", crate::Protocol::Ftp, Some((FtpSecurity::Explicit, true)), Some(2121), None, None),
                ("mit-adresse", "ftp3.example.org", crate::Protocol::Ftp, Some((FtpSecurity::Explicit, false)), Some(2122), Some("kunde"), None),
            ]
        );
        assert!(draft.skipped.is_empty() && draft.hosts.iter().all(|h| h.notes.is_empty()));
    }
}

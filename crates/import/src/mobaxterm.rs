//! MobaXterm: `MobaXterm.ini` oder eine exportierte `.mxtsessions`. Sitzungen stehen in Abschnitten `[Bookmarks]`,
//! `[Bookmarks_1]`, …; jeder Abschnitt ist ein Ordner (`SubRep`), jede weitere Zeile eine Sitzung in der Form
//! `name=#symbol#art%feld%feld…#terminal…`. Passwörter stehen dort nicht (MobaXterm legt sie verschlüsselt woanders ab).

use crate::text::ini_sections;
use glowport_core::model::FtpSecurity;

use crate::{ftp_host, host_name, port, telnet_host, usable_address, Draft, DraftHost, Jump, Note, Values};

// Stellen der Felder einer SSH-Sitzung, gezählt ab der Art.
const HOST: usize = 1;
const PORT: usize = 2;
const USER: usize = 3;
const COMMAND: usize = 7;
const GATEWAY_HOST: usize = 8;
const GATEWAY_PORT: usize = 9;
const GATEWAY_USER: usize = 10;
const KEY: usize = 14;
const GATEWAY_KEY: usize = 15;

/// MobaXterm umschreibt Zeichen, die in seiner Zeile etwas bedeuten.
fn unescape(text: &str) -> String {
    text.replace("__PERCENT__", "%").replace("__DIEZE__", "#").replace("__PTVIRG__", ";").replace("__DBLQUO__", "\"").replace("__PIPE__", "|")
}

/// Setzt die Platzhalter für Ordner des Benutzers ein.
fn path(text: &str, home: &str) -> String {
    let home = home.trim_end_matches(['\\', '/']);
    unescape(text).replace("_ProfileDir_", home).replace("_MyDocuments_", &format!("{home}\\Documents")).replace("_DesktopDir_", &format!("{home}\\Desktop"))
}

pub fn parse(text: &str, home: &str) -> Draft {
    let mut draft = Draft::default();
    for (section, entries) in ini_sections(text) {
        if !section.starts_with("Bookmarks") {
            continue;
        }
        let folder = entries.get("SubRep").map(|f| unescape(f)).unwrap_or_default();
        let group = draft.group_at(&folder.split('\\').collect::<Vec<_>>());
        for (name, value) in entries.iter().filter(|(k, _)| *k != "SubRep" && *k != "ImgNum") {
            let name = unescape(name);
            let Some(fields) = value.split('#').nth(2).map(|part| part.split('%').collect::<Vec<_>>()) else { continue };
            let field = |i: usize| fields.get(i).map(|f| f.trim()).filter(|f| !f.is_empty());
            let reason = match fields[0] {
                // SSH und SFTP führen zum selben Server. Telnet führt Adresse und Port an denselben Stellen.
                "0" | "1" | "6" | "7" => None,
                "4" => Some("protocol_rdp"),
                "5" => Some("protocol_vnc"),
                "8" => Some("protocol_serial"),
                "2" | "3" | "12" | "13" => Some("protocol_other"),
                // Lokale Shell, WSL, Dateien, Browser: nichts, was zu einem Server führt.
                _ => continue,
            };
            if let Some(reason) = reason {
                draft.skip(name, reason);
                continue;
            }
            let Some(address) = field(HOST).map(unescape).filter(|a| usable_address(a)) else {
                draft.skip(name, "no_address");
                continue;
            };
            if fields[0] == "6" {
                // FTP: Adresse, Port und Benutzer stehen wie bei SFTP. Wo MobaXterm die Verschlüsselung führt, ist nicht
                // gesichert; der Host bekommt FTPS und den Hinweis, das zu prüfen.
                draft.hosts.push(ftp_host(&name, &address, field(PORT).and_then(port), field(USER).map(unescape), FtpSecurity::Explicit, false, group));
                continue;
            }
            if fields[0] == "1" {
                // Wo MobaXterm den Benutzer einer Telnet-Sitzung führt, ist nicht gesichert; er bleibt weg.
                draft.hosts.push(telnet_host(&name, &address, field(PORT).and_then(port), None, group));
                continue;
            }
            let mut host = DraftHost { name: host_name(&name, &address), address, group, ..DraftHost::default() };
            host.own.user = field(USER).map(unescape);
            host.own.port = field(PORT).and_then(port).filter(|p| *p != 22);
            if fields[0] == "7" {
                // Dieselbe Verbindung steht oft zweimal da, einmal als SSH und einmal als SFTP.
                if draft.hosts.iter().any(|h| h.address == host.address && h.own.user == host.own.user && h.own.port == host.own.port) {
                    continue;
                }
                draft.hosts.push(host);
                continue;
            }
            host.own.key = field(KEY).and_then(|file| draft.key_file(&path(file, home)));
            if let Some(command) = field(COMMAND).map(unescape) {
                host.notes.push(Note::with("startcmd", command.clone()));
                host.own.startcmd = Some(command);
            }
            // Mehrere Sprung-Server stehen durch `__PIPE__` getrennt, der erste ist der nächste an diesem PC.
            let part = |i: usize| fields.get(i).map(|f| f.split("__PIPE__").map(str::trim).collect::<Vec<_>>()).unwrap_or_default();
            let (gateways, ports, users, keys) = (part(GATEWAY_HOST), part(GATEWAY_PORT), part(GATEWAY_USER), part(GATEWAY_KEY));
            let mut previous: Option<usize> = None;
            for (i, gateway) in gateways.iter().enumerate().filter(|(_, g)| !g.is_empty()) {
                let address = unescape(gateway);
                if !usable_address(&address) {
                    host.notes.push(Note::with("jump_missing", address));
                    continue;
                }
                let user = users.get(i).filter(|u| !u.is_empty()).map(|u| unescape(u));
                let port = ports.get(i).and_then(|p| port(p)).filter(|p| *p != 22);
                let known = draft.hosts.iter().position(|h| h.address == address && h.own.port == port && (user.is_none() || h.own.user == user));
                let at = known.unwrap_or_else(|| {
                    let key = keys.get(i).filter(|k| !k.is_empty()).and_then(|file| draft.key_file(&path(file, home)));
                    let jump = previous.map(Jump::Host).unwrap_or_default();
                    draft.hosts.push(DraftHost { name: host_name(&address, &address), address, group, own: Values { user, port, key, jump, ..Values::default() }, ..DraftHost::default() });
                    draft.hosts.len() - 1
                });
                previous = Some(at);
            }
            if let Some(last) = previous {
                host.own.jump = Jump::Host(last);
            }
            draft.hosts.push(host);
        }
    }
    draft
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeySource;

    // Die erste Zeile hat die Form aus einer echten Datei (Beispiel aus dem Forum von Devolutions); die übrigen
    // sind nach derselben Form gebaut.
    const INI: &str = "[Bookmarks]\r\nSubRep=\r\nImgNum=42\r\nsesafrazu01=#109#0%sesafrazu01%22%azroot%%-1%-1%%%22%%0%0%Interactive shell%%%-1%0%0%0%%1080%%0%0%1#MobaFont%10%0%0%-1%15%236,236,236%30,30,30%180,180,192%0%-1%0%%xterm%-1%-1%_Std_Colors_0_%80%24%0%1%-1%<none>%%0%0%-1#0# #-1\r\nlokal=#84#10%%%%%0#MobaFont#0# #-1\r\n\r\n[Bookmarks_1]\r\nSubRep=Kunden\\Meier GmbH\r\nImgNum=41\r\nmeier-web=#109#0%web.meier.example%2222%admin%%-1%-1%sudo -i%gate.meier.example__PIPE__10.8.0.1%22__PIPE__2200%jump__PIPE__%0%0%Interactive shell%_ProfileDir_\\.ssh\\id_ed25519%_MyDocuments_\\gate.ppk__PIPE__%-1%0%0%0%%1080%%0%0%1#MobaFont#0# #-1\r\nmeier-web (SFTP)=#140#7%web.meier.example%2222%admin%-1%0#MobaFont#0# #-1\r\nmeier-dc=#91#4%dc01.meier.example%3389%MEIER\\admin%0%-1#MobaFont#0# #-1\r\nswitch=#98#1%10.8.0.250%23%%%2%%22%%%0#MobaFont#0# #-1\r\n100__PERCENT__ wichtig=#109#0%10.8.0.9%22%root%%-1%-1%%%22%%0%0%Interactive shell%%%-1%0%0%0%%1080#MobaFont#0# #-1\r\n";

    #[test]
    fn reads_sessions_folders_and_gateways() {
        let draft = parse(INI, "C:\\Users\\ich");
        let groups: Vec<_> = draft.groups.iter().map(|g| (g.name.as_str(), g.parent)).collect();
        assert_eq!(groups, [("Kunden", None), ("Meier GmbH", Some(0))]);

        let names: Vec<&str> = draft.hosts.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(names, ["sesafrazu01", "100% wichtig", "gate.meier.example", "10.8.0.1", "meier-web", "switch"]);
        assert_eq!(draft.hosts[5].protocol, crate::Protocol::Telnet);
        let first = &draft.hosts[0];
        assert_eq!((first.address.as_str(), first.own.user.as_deref(), first.own.port, first.group), ("sesafrazu01", Some("azroot"), None, None));
        assert_eq!(first.own.key, None);

        let web = &draft.hosts[4];
        assert_eq!((web.address.as_str(), web.own.user.as_deref(), web.own.port, web.group), ("web.meier.example", Some("admin"), Some(2222), Some(1)));
        assert_eq!(web.own.startcmd.as_deref(), Some("sudo -i"));
        assert_eq!(draft.keys[web.own.key.unwrap()].source, KeySource::File("C:\\Users\\ich\\.ssh\\id_ed25519".into()));
        // Kette: dieser PC → gate → 10.8.0.1 → Ziel.
        assert_eq!(web.own.jump, Jump::Host(3));
        let (gate, inner) = (&draft.hosts[2], &draft.hosts[3]);
        assert_eq!((gate.own.user.as_deref(), gate.own.port, gate.own.jump), (Some("jump"), None, Jump::Unset));
        assert_eq!(draft.keys[gate.own.key.unwrap()].source, KeySource::File("C:\\Users\\ich\\Documents\\gate.ppk".into()));
        assert_eq!((inner.own.user.as_deref(), inner.own.port, inner.own.jump, inner.own.key), (None, Some(2200), Jump::Host(2), None));

        let skipped: Vec<_> = draft.skipped.iter().map(|s| (s.name.as_str(), s.reason)).collect();
        assert_eq!(skipped, [("meier-dc", "protocol_rdp")]);
    }

    #[test]
    fn reads_ftp_sessions() {
        // Nach der Form einer FTP-Sitzung gebaut (Art 6: Adresse, Port, Benutzer wie bei SFTP), nicht aus einer echten Datei.
        let ini = "[Bookmarks]\r\nSubRep=Kunden\r\nImgNum=41\r\nwebspace=#130#6%ftp.example.com%2121%web1%-1%-1%0%0%%21%%%%%0%0%0#MobaFont%10%0%0%-1%15%236,236,236%30,30,30%180,180,192%0%-1%0%%xterm%-1%0%_Std_Colors_0_%80%24%0%0%-1%<none>%%0%0%-1%0%#0# #-1\r\noeffentlich=#130#6%mirror.example.com%21%%-1%-1%0%0%%21%%%%%0%0%0#MobaFont#0# #-1\r\n";
        let draft = parse(ini, "C:\\Users\\ich");
        let found: Vec<_> = draft.hosts.iter().map(|h| (h.name.as_str(), h.protocol, h.address.as_str(), h.own.port, h.own.user.as_deref(), h.ftp.as_ref().map(|f| (f.security, f.anonymous)), h.group)).collect();
        assert_eq!(
            found,
            [
                // Die Sitzungen eines Ordners kommen nach Namen geordnet.
                ("oeffentlich", crate::Protocol::Ftp, "mirror.example.com", None, None, Some((FtpSecurity::Explicit, true)), Some(0)),
                ("webspace", crate::Protocol::Ftp, "ftp.example.com", Some(2121), Some("web1"), Some((FtpSecurity::Explicit, false)), Some(0)),
            ]
        );
        // MobaXterm sagt nicht, ob verschlüsselt wird: Der Hinweis bittet, das zu prüfen.
        assert!(draft.hosts.iter().all(|h| h.notes.iter().map(|n| n.code).collect::<Vec<_>>() == ["ftp_security"]));
        assert!(draft.skipped.is_empty());
    }
}

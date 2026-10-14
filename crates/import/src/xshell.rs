//! Xshell: one `.xsh` file per session (an INI file, mostly in UTF-16), folders are folders on disk.
//! Passwords there are encrypted and stay behind; Xshell keeps keys in a manager of its own.

use crate::text::ini_sections;
use glowport_core::model::FtpSecurity;

use crate::{ftp_host, host_name, port, telnet_host, usable_address, Draft, DraftHost};

/// `files`: path of every file below the session folder and its content.
pub fn parse(files: &[(String, String)]) -> Draft {
    let mut draft = Draft::default();
    for (path, text) in files {
        let mut parts: Vec<&str> = path.split(['\\', '/']).collect();
        let file = parts.pop().unwrap_or_default();
        let name = file.strip_suffix(".xsh").or_else(|| file.strip_suffix(".XSH")).unwrap_or(file);
        let sections = ini_sections(text);
        let value = |section: &str, key: &str| sections.iter().find(|(name, _)| name.eq_ignore_ascii_case(section)).and_then(|(_, entries)| entries.get(key)).map(|v| v.trim()).filter(|v| !v.is_empty());
        let protocol = value("CONNECTION", "Protocol").unwrap_or("SSH").to_ascii_uppercase();
        let reason = match protocol.as_str() {
            "SSH" | "SFTP" | "TELNET" | "FTP" => None,
            // How Xshell stores the line (numbers instead of values) is not certain; better leave it out than guess.
            "SERIAL" => Some("protocol_serial"),
            _ => Some("protocol_other"),
        };
        if let Some(reason) = reason {
            draft.skip(name, reason);
            continue;
        }
        let Some(address) = value("CONNECTION", "Host").filter(|a| usable_address(a)) else {
            draft.skip(name, "no_address");
            continue;
        };
        if protocol == "TELNET" {
            let group = draft.group_at(&parts);
            draft.hosts.push(telnet_host(name, address, value("CONNECTION", "Port").and_then(port), value("CONNECTION:AUTHENTICATION", "UserName").map(str::to_string), group));
            continue;
        }
        if protocol == "FTP" {
            // Where Xshell keeps an FTP session's encryption is not certain: FTPS with the note to check it.
            let group = draft.group_at(&parts);
            let mut host = ftp_host(name, address, value("CONNECTION", "Port").and_then(port), value("CONNECTION:AUTHENTICATION", "UserName").map(str::to_string), FtpSecurity::Explicit, false, group);
            host.password_lost = host.own.user.is_some() && value("CONNECTION:AUTHENTICATION", "Password").is_some();
            draft.hosts.push(host);
            continue;
        }
        let mut host = DraftHost { name: host_name(name, address), address: address.to_string(), group: draft.group_at(&parts), ..DraftHost::default() };
        host.own.port = value("CONNECTION", "Port").and_then(port).filter(|p| *p != 22);
        host.own.user = value("CONNECTION:AUTHENTICATION", "UserName").map(str::to_string);
        host.password_lost = value("CONNECTION:AUTHENTICATION", "Password").is_some();
        draft.hosts.push(host);
    }
    draft
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_session_files() {
        let files = [
            ("Kunden\\web.xsh".to_string(), "[CONNECTION]\r\nHost=web.example.org\r\nPort=2222\r\nProtocol=SSH\r\n[CONNECTION:AUTHENTICATION]\r\nUserName=root\r\nPassword=abc==\r\n".to_string()),
            ("router.xsh".to_string(), "[CONNECTION]\r\nHost=10.0.0.1\r\nProtocol=TELNET\r\n".to_string()),
            ("leer.xsh".to_string(), "[CONNECTION]\r\nHost=\r\n".to_string()),
        ];
        let draft = parse(&files);
        assert_eq!(draft.hosts.len(), 2);
        let web = &draft.hosts[0];
        assert_eq!((draft.hosts[1].name.as_str(), draft.hosts[1].protocol, draft.hosts[1].own.port), ("router", crate::Protocol::Telnet, None));
        assert_eq!((web.name.as_str(), web.own.port, web.own.user.as_deref(), web.password_lost), ("web", Some(2222), Some("root"), true));
        assert_eq!(draft.groups[web.group.unwrap()].name, "Kunden");
        assert_eq!(draft.skipped.iter().map(|s| s.reason).collect::<Vec<_>>(), ["no_address"]);
    }

    #[test]
    fn reads_ftp_sessions() {
        let files = vec![("Kunden\\webspace.xsh".to_string(), "[CONNECTION]\r\nHost=ftp.example.org\r\nPort=2121\r\nProtocol=FTP\r\n[CONNECTION:AUTHENTICATION]\r\nUserName=web1\r\nPassword=abc==\r\n".to_string())];
        let draft = parse(&files);
        let host = &draft.hosts[0];
        assert_eq!((host.name.as_str(), host.protocol, host.own.port, host.own.user.as_deref()), ("webspace", crate::Protocol::Ftp, Some(2121), Some("web1")));
        assert_eq!(host.ftp.as_ref().map(|f| (f.security, f.anonymous)), Some((FtpSecurity::Explicit, false)));
        // In Xshell the password is encrypted and stays behind; the connection's encryption needs checking.
        assert!(host.password.is_none() && host.password_lost);
        assert_eq!(host.notes.iter().map(|n| n.code).collect::<Vec<_>>(), ["ftp_security"]);
    }
}

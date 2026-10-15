//! WinSCP: sessions from the registry or from `WinSCP.ini`. A session's name carries its folders (`Customers/web`)
//! and is escaped like an address (`%20`). Saved passwords are only obfuscated and can be read
//! as long as no master password is set in WinSCP.

use glowport_core::model::{FtpSecurity, Secret};

use crate::text::{ini_sections, percent_decode};
use crate::{ftp_host, host_name, usable_address, Draft, DraftHost, Entries, Jump, Note, Section, Values};

/// The sessions live below this key (in `HKEY_CURRENT_USER`).
pub const KEY: &str = "Software\\Martin Prikryl\\WinSCP 2\\Sessions";
/// This says whether a master password protects the saved passwords (`UseMasterPassword`).
pub const SECURITY: &str = "Software\\Martin Prikryl\\WinSCP 2\\Configuration\\Security";

const MAGIC: u8 = 0xA3;
const FLAG: u8 = 0xFF;

/// Makes an obfuscated password readable again. `key` is user and address one after the other; WinSCP uses it
/// to check that the password belongs to this session.
fn reveal(hex: &str, key: &str) -> Option<String> {
    let digits: Vec<u8> = hex.trim().chars().map(|c| c.to_digit(16).map(|d| d as u8)).collect::<Option<_>>()?;
    let mut bytes = digits.as_chunks::<2>().0.iter().map(|pair| !(((pair[0] << 4) | pair[1]) ^ MAGIC));
    let flag = bytes.next()?;
    // After the marker WinSCP names the version: 0 = length in one byte, 2 = in two (newer versions).
    let length = match (flag == FLAG).then(|| bytes.next()).flatten() {
        Some(2) => (bytes.next()? as usize) << 8 | bytes.next()? as usize,
        Some(_) => bytes.next()? as usize,
        None if flag == FLAG => return None,
        None => flag as usize,
    };
    let skip = bytes.next()? as usize;
    let clear: Vec<u8> = bytes.skip(skip).take(length).collect();
    if clear.len() != length {
        return None;
    }
    let text = String::from_utf8(clear).ok()?;
    if flag == FLAG {
        return text.strip_prefix(key).map(str::to_string);
    }
    Some(text)
}

fn text<'a>(entries: &'a Entries, name: &str) -> Option<&'a str> {
    entries.get(name).map(|v| v.trim()).filter(|v| !v.is_empty())
}

fn number(entries: &Entries, name: &str) -> Option<u32> {
    entries.get(name)?.trim().parse().ok()
}

/// From `WinSCP.ini`: sections `[Sessions\name]`, plus `[Configuration\Security]`.
pub fn from_ini(text: &str) -> Draft {
    let all = ini_sections(text);
    let protected = all.iter().any(|(name, entries)| name == "Configuration\\Security" && number(entries, "UseMasterPassword") == Some(1));
    let sessions: Vec<Section> = all.into_iter().filter_map(|(name, entries)| name.strip_prefix("Sessions\\").map(|n| (n.to_string(), entries))).collect();
    from_sections(&sessions, protected)
}

/// Turns the sessions into a draft. `protected`: a master password is set in WinSCP; then the
/// passwords are really encrypted and stay behind.
pub fn from_sections(sections: &[Section], protected: bool) -> Draft {
    let mut draft = Draft::default();
    for (raw_name, entries) in sections {
        let full = percent_decode(raw_name);
        let mut path: Vec<&str> = full.split('/').collect();
        let name = path.pop().unwrap_or_default().to_string();
        let Some(address) = text(entries, "HostName").map(percent_decode) else {
            if name != "Default Settings" && !entries.is_empty() {
                draft.skip(full.clone(), "no_address");
            }
            continue;
        };
        // 0 = SCP, 1 and 2 = SFTP (the default), 5 = FTP, 6 = WebDAV, 7 = S3.
        let kind = number(entries, "FSProtocol").unwrap_or(2);
        let reason = match kind {
            0..=2 | 5 => None,
            _ => Some("protocol_other"),
        };
        if let Some(reason) = reason {
            draft.skip(full.clone(), reason);
            continue;
        }
        if !usable_address(&address) {
            draft.skip(full.clone(), "invalid");
            continue;
        }
        let group = draft.group_at(&path);
        let user = text(entries, "UserName").map(percent_decode);
        if kind == 5 {
            // 0 = unencrypted, 1 = implicit TLS, 2 and 3 = explicit (SSL or TLS).
            let security = match number(entries, "Ftps").unwrap_or(0) {
                0 => FtpSecurity::None,
                1 => FtpSecurity::Implicit,
                _ => FtpSecurity::Explicit,
            };
            let mut host = ftp_host(&name, &address, number(entries, "PortNumber").and_then(|p| u16::try_from(p).ok()), user.clone(), security, true, group);
            if let Some(hidden) = text(entries, "Password").filter(|_| host.own.user.is_some()) {
                let key = format!("{}{}", user.as_deref().unwrap_or(""), address);
                match (protected, reveal(hidden, &key)) {
                    (false, Some(password)) if !password.is_empty() => host.password = Some(Secret::new(password)),
                    _ => host.password_lost = true,
                }
            }
            draft.hosts.push(host);
            continue;
        }
        let mut host = DraftHost { name: host_name(&name, &address), group, ..DraftHost::default() };
        host.own.port = number(entries, "PortNumber").and_then(|p| u16::try_from(p).ok()).filter(|p| *p != 0 && *p != 22);
        host.own.key = text(entries, "PublicKeyFile").and_then(|file| draft.key_file(&percent_decode(file)));
        if let Some(hidden) = text(entries, "Password") {
            let key = format!("{}{}", user.as_deref().unwrap_or(""), address);
            match (protected, reveal(hidden, &key)) {
                (false, Some(password)) if !password.is_empty() => host.password = Some(Secret::new(password)),
                _ => host.password_lost = true,
            }
        }
        if number(entries, "AgentFwd") == Some(1) {
            host.own.agent = Some(true);
            host.own.agent_forward = Some(true);
            host.notes.push(Note::new("agent_forward"));
        }
        // Tunnel: WinSCP connects through a second SSH server. In Glowport that is a jump host.
        if let (Some(1), Some(tunnel)) = (number(entries, "Tunnel"), text(entries, "TunnelHostName").map(percent_decode).filter(|t| usable_address(t))) {
            let tunnel_user = text(entries, "TunnelUserName").map(percent_decode);
            let tunnel_port = number(entries, "TunnelPortNumber").and_then(|p| u16::try_from(p).ok()).filter(|p| *p != 0 && *p != 22);
            let known = draft.hosts.iter().position(|h| h.address == tunnel && h.own.port == tunnel_port && (tunnel_user.is_none() || h.own.user == tunnel_user));
            let at = known.unwrap_or_else(|| {
                let key = text(entries, "TunnelPublicKeyFile").and_then(|file| draft.key_file(&percent_decode(file)));
                let mut jump = DraftHost { name: host_name(&tunnel, &tunnel), address: tunnel.clone(), group, own: Values { user: tunnel_user.clone(), port: tunnel_port, key, ..Values::default() }, ..DraftHost::default() };
                if let Some(hidden) = text(entries, "TunnelPassword") {
                    let key = format!("{}{}", tunnel_user.as_deref().unwrap_or(""), tunnel);
                    match (protected, reveal(hidden, &key)) {
                        (false, Some(password)) if !password.is_empty() => jump.password = Some(Secret::new(password)),
                        _ => jump.password_lost = true,
                    }
                }
                draft.hosts.push(jump);
                draft.hosts.len() - 1
            });
            host.own.jump = Jump::Host(at);
        }
        // 1 = SOCKS 4, 2 = SOCKS 5, 3 = HTTP.
        let proxy_host = text(entries, "ProxyHost").map(percent_decode).filter(|h| usable_address(h) && !h.contains(['@', '/']));
        match (number(entries, "ProxyMethod").unwrap_or(0), proxy_host) {
            (0, _) | (_, None) => {}
            (method @ (2 | 3), Some(proxy)) => {
                let scheme = if method == 2 { "socks5" } else { "http" };
                let port = number(entries, "ProxyPort").filter(|p| (1..=65535).contains(p)).unwrap_or(if method == 2 { 1080 } else { 8080 });
                let proxy_user = text(entries, "ProxyUsername").map(percent_decode).filter(|u| !u.contains([':', '@', ' '])).map(|u| format!("{u}@")).unwrap_or_default();
                host.own.proxy = Some(format!("{scheme}://{proxy_user}{proxy}:{port}"));
            }
            (_, Some(proxy)) => host.notes.push(Note::with("option_ignored", format!("Proxy {proxy}"))),
        }
        host.own.user = user;
        host.address = address;
        draft.hosts.push(host);
    }
    draft
}

#[cfg(test)]
mod tests {
    use super::*;
    use glowport_core::model::Ftp;
    use crate::KeySource;

    /// Obfuscates the way WinSCP does, so the test does not depend on a copied example.
    fn hide(password: &str, key: &str, padding: u8) -> String {
        let clear = format!("{key}{password}");
        let mut bytes = vec![FLAG, 0, clear.len() as u8, padding];
        bytes.extend(std::iter::repeat_n(0x41, padding as usize));
        bytes.extend(clear.bytes());
        bytes.extend([0x42, 0x43]);
        bytes.iter().map(|b| format!("{:02X}", !(b ^ MAGIC))).collect()
    }

    #[test]
    fn reveals_stored_passwords() {
        let hidden = hide("secret-äöü", "web123ssh.kunde-a.example", 7);
        assert_eq!(reveal(&hidden, "web123ssh.kunde-a.example").as_deref(), Some("secret-äöü"));
        assert_eq!(reveal(&hidden, "andererssh.kunde-a.example"), None, "belongs to another session");
        assert_eq!(reveal("not hex", "x"), None);
        assert_eq!(reveal("A3", "x"), None);
        // Old form without marker: the first number is the length right away.
        let old: String = [3u8, 0, b'a', b'b', b'c'].iter().map(|b| format!("{:02X}", !(b ^ MAGIC))).collect();
        assert_eq!(reveal(&old, "whatever").as_deref(), Some("abc"));
    }

    #[test]
    fn reads_sessions_from_ini_and_registry() {
        let password = hide("kennwort", "web123ssh.kunde-a.example", 3);
        let tunnel = hide("tunnel-pw", "jumpgate.example.org", 0);
        let ini = format!(
            "[Configuration\\Security]\nUseMasterPassword=0\n\n[Sessions\\Default%20Settings]\nHostName=\n\n[Sessions\\Webspace/Kunde%20A]\nHostName=ssh.kunde-a.example\nUserName=web123\nPassword={password}\nPublicKeyFile=C:%5CUsers%5Cme%5C.ssh%5Carbeit.ppk\n\n[Sessions\\Webspace/intern]\nHostName=10.0.0.5\nPortNumber=2222\nUserName=root\nTunnel=1\nTunnelHostName=gate.example.org\nTunnelUserName=jump\nTunnelPassword={tunnel}\nProxyMethod=2\nProxyHost=proxy.example\n\n[Sessions\\alter-ftp]\nHostName=ftp.example.org\nFSProtocol=5\n"
        );
        let draft = from_ini(&ini);
        let names: Vec<&str> = draft.hosts.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(names, ["Kunde A", "gate.example.org", "intern", "alter-ftp"]);
        assert_eq!(draft.groups.len(), 1);
        let a = &draft.hosts[0];
        assert_eq!((a.address.as_str(), a.own.user.as_deref(), a.group), ("ssh.kunde-a.example", Some("web123"), Some(0)));
        assert_eq!(a.password.as_ref().map(|p| p.expose()), Some("kennwort"));
        assert_eq!(draft.keys[a.own.key.unwrap()].source, KeySource::File("C:\\Users\\me\\.ssh\\arbeit.ppk".into()));
        let inner = &draft.hosts[2];
        assert_eq!((inner.own.port, inner.own.jump, inner.own.proxy.as_deref()), (Some(2222), Jump::Host(1), Some("socks5://proxy.example:1080")));
        assert_eq!(draft.hosts[1].password.as_ref().map(|p| p.expose()), Some("tunnel-pw"));
        // An FTP session without further details: unencrypted and without a user, i.e. anonymous.
        let old = &draft.hosts[3];
        assert_eq!((old.protocol, old.address.as_str(), old.own.port, old.own.user.as_deref()), (crate::Protocol::Ftp, "ftp.example.org", None, None));
        assert_eq!(old.ftp, Some(Ftp { security: FtpSecurity::None, anonymous: true, dir: None, plain_ok: false }));
        assert!(draft.skipped.is_empty());

        // With a master password the passwords are encrypted: they stay behind, and the host says so.
        let locked = from_ini(&ini.replace("UseMasterPassword=0", "UseMasterPassword=1"));
        assert!(locked.hosts[0].password.is_none() && locked.hosts[0].password_lost);
    }

    #[test]
    fn reads_ftp_sessions_with_their_encryption() {
        let password = hide("ftp-kennwort", "web1ftp.kunde.example", 2);
        let ini = format!(
            "[Sessions\\Kunde/Webspace]\nHostName=ftp.kunde.example\nFSProtocol=5\nFtps=3\nPortNumber=2121\nUserName=web1\nPassword={password}\n\n[Sessions\\alt]\nHostName=alt.example\nFSProtocol=5\nFtps=1\nPortNumber=990\nUserName=anonymous\nPassword={password}\n\n[Sessions\\offen]\nHostName=10.0.0.60\nFSProtocol=5\nPortNumber=21\nUserName=scan\n\n[Sessions\\wolke]\nHostName=s3.example\nFSProtocol=7\n"
        );
        let draft = from_ini(&ini);
        let found: Vec<_> = draft.hosts.iter().map(|h| (h.name.as_str(), h.protocol, h.ftp.as_ref().map(|f| (f.security, f.anonymous)), h.own.port, h.own.user.as_deref())).collect();
        assert_eq!(
            found,
            [
                ("Webspace", crate::Protocol::Ftp, Some((FtpSecurity::Explicit, false)), Some(2121), Some("web1")),
                // The usual port of implicit FTPS is not stored separately; “anonymous” is not a user.
                ("alt", crate::Protocol::Ftp, Some((FtpSecurity::Implicit, true)), None, None),
                ("offen", crate::Protocol::Ftp, Some((FtpSecurity::None, false)), None, Some("scan")),
            ]
        );
        assert_eq!(draft.hosts[0].password.as_ref().map(|p| p.expose()), Some("ftp-kennwort"));
        assert!(draft.hosts[1].password.is_none() && !draft.hosts[1].password_lost, "an anonymous host holds no password");
        assert!(draft.hosts.iter().all(|h| h.notes.is_empty()), "WinSCP names the encryption; there is nothing to check");
        assert_eq!(draft.groups.len(), 1);
        assert_eq!(draft.skipped.iter().map(|s| (s.name.as_str(), s.reason)).collect::<Vec<_>>(), [("wolke", "protocol_other")]);
    }
}

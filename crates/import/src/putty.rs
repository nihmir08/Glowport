//! PuTTY (and KiTTY, which uses the same names): sessions from the registry or from an export as `.reg`.
//! The bridge reads the registry and hands in every session as a section; `text::reg_sections` splits the export.

use glowport_core::model::{Flow, ForwardKind, Parity};

use crate::text::{percent_decode, user_host_port};
use crate::{host_name, port, serial_host, serial_line, telnet_host, usable_address, usable_serial_port, Draft, DraftForward, DraftHost, DraftKnownHost, Entries, Note, Section};

/// The sessions live below this key (in `HKEY_CURRENT_USER`).
pub const KEY: &str = "Software\\SimonTatham\\PuTTY\\Sessions";
/// This is where PuTTY remembers the servers' keys.
pub const HOST_KEYS: &str = "Software\\SimonTatham\\PuTTY\\SshHostKeys";

fn number(entries: &Entries, name: &str) -> Option<u32> {
    entries.get(name)?.parse().ok()
}

fn text<'a>(entries: &'a Entries, name: &str) -> Option<&'a str> {
    entries.get(name).map(|v| v.trim()).filter(|v| !v.is_empty())
}

/// `L8080=localhost:80`, `R9000=127.0.0.1:9000`, `D1080`, optionally preceded by `4` or `6`, and before the port optionally
/// an address to listen on.
fn forwards(list: &str, host: usize, name: &str, draft: &mut Draft) {
    for entry in list.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        let entry = entry.trim_start_matches(['4', '6']);
        let (kind, rest) = match entry.chars().next() {
            Some('L') => (ForwardKind::Local, &entry[1..]),
            Some('R') => (ForwardKind::Remote, &entry[1..]),
            Some('D') => (ForwardKind::Dynamic, &entry[1..]),
            _ => continue,
        };
        let (listen, dest) = rest.split_once('=').unwrap_or((rest, ""));
        let (bind_address, bind_port) = match listen.rsplit_once(':') {
            Some((address, number)) => (address.to_string(), port(number)),
            None => ("127.0.0.1".to_string(), port(listen)),
        };
        let Some(bind_port) = bind_port else { continue };
        let (dest_host, dest_port) = if kind == ForwardKind::Dynamic {
            (String::new(), 0)
        } else {
            match dest.rsplit_once(':').and_then(|(h, p)| Some((h.to_string(), port(p)?))) {
                Some(found) if !found.0.is_empty() => found,
                _ => continue,
            }
        };
        let label = if kind == ForwardKind::Dynamic { "SOCKS".to_string() } else { dest_port.to_string() };
        draft.forwards.push(DraftForward { name: format!("{name} · {label}"), kind, host, bind_address, bind_port, dest_host, dest_port });
    }
}

/// Turns the sessions into a draft. The name of every section is the session's name as it appears in the
/// registry (with `%20` for spaces).
pub fn from_sections(sections: &[Section]) -> Draft {
    let mut draft = Draft::default();
    for (raw_name, entries) in sections {
        let name = percent_decode(raw_name);
        let protocol = text(entries, "Protocol").unwrap_or("ssh").to_ascii_lowercase();
        // A serial session has no address but a port and its line. The port is in `SerialLine`;
        // older versions kept it in the address field.
        if protocol == "serial" {
            let Some(line) = text(entries, "SerialLine").or(text(entries, "HostName")).filter(|line| usable_serial_port(line)) else {
                draft.skip(name, "no_address");
                continue;
            };
            let parity = match number(entries, "SerialParity") {
                Some(1) => Parity::Odd,
                Some(2) => Parity::Even,
                _ => Parity::None,
            };
            let flow = match number(entries, "SerialFlowControl") {
                Some(1) => Flow::Software,
                Some(2) => Flow::Hardware,
                _ => Flow::None,
            };
            // PuTTY counts stop bits in halves: 2 is one, 4 is two.
            let settings = serial_line(number(entries, "SerialSpeed"), number(entries, "SerialDataBits"), parity, number(entries, "SerialStopHalfbits") == Some(4), flow);
            draft.hosts.push(serial_host(&name, line, settings, None));
            continue;
        }
        let Some(target) = text(entries, "HostName") else {
            // “Default Settings” is the template for new sessions and has no address.
            if name != "Default Settings" && !entries.is_empty() {
                draft.skip(name, "no_address");
            }
            continue;
        };
        if protocol != "ssh" && protocol != "telnet" {
            draft.skip(name, "protocol_other");
            continue;
        }
        // PuTTY allows `user@address` in the address field.
        let (user_in_target, address, _) = user_host_port(target);
        if !usable_address(&address) {
            draft.skip(name, "invalid");
            continue;
        }
        if protocol == "telnet" {
            let user = text(entries, "UserName").map(str::to_string).or(user_in_target);
            draft.hosts.push(telnet_host(&name, &address, number(entries, "PortNumber").and_then(|p| u16::try_from(p).ok()), user, None));
            continue;
        }
        let mut host = DraftHost { name: host_name(&name, &address), address, ..DraftHost::default() };
        host.own.user = text(entries, "UserName").map(str::to_string).or(user_in_target);
        host.own.port = number(entries, "PortNumber").and_then(|p| u16::try_from(p).ok()).filter(|p| *p != 0 && *p != 22);
        host.own.key = text(entries, "PublicKeyFile").and_then(|file| draft.key_file(file));
        if number(entries, "AgentFwd") == Some(1) {
            host.own.agent = Some(true);
            host.own.agent_forward = Some(true);
            host.notes.push(Note::new("agent_forward"));
        }
        // Seconds between keepalives; PuTTY also keeps minutes (`PingInterval`).
        let seconds = number(entries, "PingIntervalSecs").unwrap_or(0) + number(entries, "PingInterval").unwrap_or(0) * 60;
        host.own.keepalive = u16::try_from(seconds).ok().filter(|s| (1..=3600).contains(s));
        host.own.term = text(entries, "TerminalType").filter(|t| *t != "xterm" && t.len() <= 64 && t.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')).map(str::to_string);
        host.own.startcmd = text(entries, "RemoteCommand").map(str::to_string);
        // 0 = none, 1 = SOCKS 4, 2 = SOCKS 5, 3 = HTTP; Glowport does not know anything beyond that (Telnet, own program).
        let proxy_host = text(entries, "ProxyHost").filter(|h| usable_address(h) && !h.contains(['@', '/']));
        match (number(entries, "ProxyMethod").unwrap_or(0), proxy_host) {
            (0, _) | (_, None) => {}
            (method @ (2 | 3), Some(proxy)) => {
                let scheme = if method == 2 { "socks5" } else { "http" };
                let port = number(entries, "ProxyPort").filter(|p| (1..=65535).contains(p)).unwrap_or(if method == 2 { 1080 } else { 8080 });
                let user = text(entries, "ProxyUsername").filter(|u| !u.contains([':', '@', ' '])).map(|u| format!("{u}@")).unwrap_or_default();
                host.own.proxy = Some(format!("{scheme}://{user}{proxy}:{port}"));
                host.proxy_password = text(entries, "ProxyPassword").map(|p| glowport_core::model::Secret::new(p.to_string()));
            }
            (_, Some(proxy)) => host.notes.push(Note::with("option_ignored", format!("Proxy {proxy}"))),
        }
        let index = draft.hosts.len();
        let label = host.name.clone();
        draft.hosts.push(host);
        if let Some(list) = text(entries, "PortForwardings") {
            forwards(list, index, &label, &mut draft);
        }
    }
    draft
}

/// Appends the number from PuTTY's notation (`0x…`) as bytes, most significant first.
fn hex_bytes(text: &str) -> Option<Vec<u8>> {
    let digits = text.trim().strip_prefix("0x")?;
    let digits = if digits.len() % 2 == 1 { format!("0{digits}") } else { digits.to_string() };
    (0..digits.len()).step_by(2).map(|i| u8::from_str_radix(&digits[i..i + 2], 16).ok()).collect()
}

fn ssh_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend((bytes.len() as u32).to_be_bytes());
    out.extend(bytes);
}

/// A number in SSH notation: without leading zeros, with one in front if the top bit is set.
fn ssh_mpint(out: &mut Vec<u8>, bytes: &[u8]) {
    let trimmed: &[u8] = &bytes[bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len())..];
    let pad = trimmed.first().is_some_and(|b| b & 0x80 != 0);
    out.extend((trimmed.len() as u32 + pad as u32).to_be_bytes());
    if pad {
        out.push(0);
    }
    out.extend(trimmed);
}

fn left_pad(bytes: Vec<u8>, len: usize) -> Option<Vec<u8>> {
    (bytes.len() <= len).then(|| [vec![0; len - bytes.len()], bytes].concat())
}

/// The server keys PuTTY has remembered. Name of a value: `ssh-ed25519@22:address`; the value is the
/// key's numbers in PuTTY's own notation, from which the OpenSSH form is rebuilt here.
pub fn host_keys(entries: &Entries) -> Draft {
    let mut draft = Draft::default();
    for (name, value) in entries {
        let Some((kind, target)) = name.split_once('@') else { continue };
        let Some((port_text, host)) = target.split_once(':') else { continue };
        let (Some(port), true) = (port(port_text), usable_address(host)) else { continue };
        let parts: Vec<&str> = value.split(',').collect();
        let mut blob = Vec::new();
        let algorithm = match (kind, parts.as_slice()) {
            ("rsa2", [exponent, modulus]) => {
                let (Some(e), Some(n)) = (hex_bytes(exponent), hex_bytes(modulus)) else { continue };
                ssh_string(&mut blob, b"ssh-rsa");
                ssh_mpint(&mut blob, &e);
                ssh_mpint(&mut blob, &n);
                "ssh-rsa".to_string()
            }
            ("ssh-ed25519", [x, y]) => {
                // OpenSSH stores the point compressed: y with the lowest byte first, the sign of x in the top bit.
                let (Some(x), Some(y)) = (hex_bytes(x), hex_bytes(y).and_then(|y| left_pad(y, 32))) else { continue };
                let mut point: Vec<u8> = y.into_iter().rev().collect();
                point[31] |= (x.last().copied().unwrap_or(0) & 1) << 7;
                ssh_string(&mut blob, b"ssh-ed25519");
                ssh_string(&mut blob, &point);
                "ssh-ed25519".to_string()
            }
            (ecdsa, [curve, x, y]) if ecdsa.starts_with("ecdsa-sha2-") => {
                let size = match *curve {
                    "nistp256" => 32,
                    "nistp384" => 48,
                    "nistp521" => 66,
                    _ => continue,
                };
                let (Some(x), Some(y)) = (hex_bytes(x).and_then(|x| left_pad(x, size)), hex_bytes(y).and_then(|y| left_pad(y, size))) else { continue };
                let algorithm = format!("ecdsa-sha2-{curve}");
                ssh_string(&mut blob, algorithm.as_bytes());
                ssh_string(&mut blob, curve.as_bytes());
                ssh_string(&mut blob, &[vec![4], x, y].concat());
                algorithm
            }
            _ => {
                draft.skip(format!("{host}:{port}"), "key_type");
                continue;
            }
        };
        let (key, fingerprint) = crate::knownhosts::encode(&algorithm, &blob);
        draft.known_hosts.push(DraftKnownHost { host: host.to_lowercase(), port, algorithm, fingerprint, key });
    }
    draft
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::text::reg_sections;
    use crate::{Jump, KeySource, Protocol};

    const EXPORT: &str = r#"Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\Default%20Settings]
"HostName"=""
"Protocol"="ssh"

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\mail%20server]
"HostName"="root@mail.example.org"
"Protocol"="ssh"
"PortNumber"=dword:00000016
"PublicKeyFile"="C:\\Users\\ich\\.ssh\\arbeit.ppk"
"PortForwardings"="L8080=127.0.0.1:80,D1080,4R127.0.0.1:9000=intern:9000,kaputt"
"AgentFwd"=dword:00000001
"PingIntervalSecs"=dword:0000001e
"TerminalType"="xterm-256color"

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\gitlab]
"HostName"="git.example.org"
"UserName"="git"
"Protocol"="ssh"
"PortNumber"=dword:000008ae
"ProxyMethod"=dword:00000003
"ProxyHost"="proxy.firma.example"
"ProxyPort"=dword:00000c38
"ProxyUsername"="ich"
"ProxyPassword"="geheim"

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\router]
"HostName"="192.168.1.1"
"Protocol"="telnet"

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\COM3]
"HostName"="COM3"
"Protocol"="serial"
"#;

    #[test]
    fn reads_sessions() {
        let draft = from_sections(&reg_sections(EXPORT, KEY));
        assert_eq!(draft.hosts.len(), 4);
        let mail = &draft.hosts[0];
        assert_eq!((mail.name.as_str(), mail.address.as_str(), mail.own.user.as_deref(), mail.own.port), ("mail server", "mail.example.org", Some("root"), None));
        assert_eq!(draft.keys[mail.own.key.unwrap()].source, KeySource::File("C:\\Users\\ich\\.ssh\\arbeit.ppk".into()));
        assert_eq!((mail.own.agent_forward, mail.own.keepalive, mail.own.term.as_deref()), (Some(true), Some(30), Some("xterm-256color")));
        assert_eq!(mail.own.jump, Jump::Unset);

        let git = &draft.hosts[1];
        assert_eq!((git.own.user.as_deref(), git.own.port), (Some("git"), Some(2222)));
        assert_eq!(git.own.proxy.as_deref(), Some("http://ich@proxy.firma.example:3128"));
        assert_eq!(git.proxy_password.as_ref().map(|p| p.expose()), Some("geheim"));

        let rules: Vec<_> = draft.forwards.iter().map(|f| (f.kind, f.bind_address.as_str(), f.bind_port, f.dest_host.as_str(), f.dest_port)).collect();
        assert_eq!(rules, [(ForwardKind::Local, "127.0.0.1", 8080, "127.0.0.1", 80), (ForwardKind::Dynamic, "127.0.0.1", 1080, "", 0), (ForwardKind::Remote, "127.0.0.1", 9000, "intern", 9000)]);
        // Telnet and serial line arrive as hosts with their protocol.
        let others: Vec<_> = draft.hosts[2..].iter().map(|h| (h.name.as_str(), h.address.as_str(), h.protocol, h.own.port, h.serial.map(|line| (line.baud, line.data_bits, line.stop_bits)))).collect();
        assert_eq!(others, [("router", "192.168.1.1", Protocol::Telnet, None, None), ("COM3", "COM3", Protocol::Serial, None, Some((9600, 8, 1)))]);
        assert!(draft.skipped.is_empty(), "{:?}", draft.skipped);
    }

    #[test]
    fn rebuilds_host_keys() {
        // An Ed25519 key in PuTTY's notation and the same one as OpenSSH writes it.
        let x = "0x2b4f2a8d0c4d1e6f0a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f50617";
        let y = "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let entries: Entries = [("ssh-ed25519@2222:Web.Example.org".to_string(), format!("{x},{y}")), ("rsa2@22:alt.example".to_string(), "0x10001,0xc0ffee".to_string()), ("dss@22:uralt".to_string(), "0x1,0x2,0x3,0x4".to_string())].into();
        let draft = host_keys(&entries);
        assert_eq!(draft.known_hosts.len(), 2);
        let ed = draft.known_hosts.iter().find(|k| k.algorithm == "ssh-ed25519").unwrap();
        assert_eq!((ed.host.as_str(), ed.port), ("web.example.org", 2222));
        use base64::Engine;
        let blob = base64::engine::general_purpose::STANDARD.decode(ed.key.split(' ').nth(1).unwrap()).unwrap();
        assert_eq!(&blob[..15], b"\0\0\0\x0bssh-ed25519");
        let point = &blob[19..];
        assert_eq!(point.len(), 32);
        assert_eq!(point[0], 0x20, "y comes with the lowest byte first");
        assert_eq!(point[31], 0x01 | 0x80, "x is odd, so the top bit is set");
        assert!(ed.fingerprint.starts_with("SHA256:"));

        let rsa = draft.known_hosts.iter().find(|k| k.algorithm == "ssh-rsa").unwrap();
        let blob = base64::engine::general_purpose::STANDARD.decode(rsa.key.split(' ').nth(1).unwrap()).unwrap();
        // Exponent 0x010001, then the modulus with a zero in front, because its top bit is set.
        assert_eq!(&blob[11..], [0, 0, 0, 3, 1, 0, 1, 0, 0, 0, 4, 0, 0xc0, 0xff, 0xee]);
        assert_eq!(draft.skipped[0].reason, "key_type");
    }
}

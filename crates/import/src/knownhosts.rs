//! OpenSSH's `known_hosts`: the server keys the user already trusted there.

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine;
use sha2::{Digest, Sha256};

use crate::{port, usable_address, Draft, DraftKnownHost};

const KINDS: [&str; 6] = ["ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-dss"];

/// Key as a line without comment and its fingerprint, both as in OpenSSH.
pub(crate) fn encode(algorithm: &str, blob: &[u8]) -> (String, String) {
    (format!("{algorithm} {}", STANDARD.encode(blob)), format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(blob))))
}

/// Does the text look like `known_hosts`? Every line then names hosts, algorithm and a key.
pub fn looks_like(text: &str) -> bool {
    let mut lines = text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).peekable();
    lines.peek().is_some() && lines.take(20).all(|line| line.split_whitespace().any(|word| KINDS.contains(&word) || word.starts_with("sk-")))
}

/// Reads the file. Hashed names (`HashKnownHosts`) cannot be recovered and are only counted;
/// patterns for many hosts and certificate authorities are not taken over here.
pub fn parse(text: &str) -> Draft {
    let mut draft = Draft::default();
    let mut hashed = 0;
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let mut fields = line.split_whitespace();
        let Some(mut names) = fields.next() else { continue };
        if names.starts_with('@') {
            // `@cert-authority` and `@revoked` are not keys of individual servers.
            draft.skip(fields.next().unwrap_or(names), "pattern");
            continue;
        }
        if names.starts_with('|') {
            hashed += 1;
            continue;
        }
        let (Some(algorithm), Some(encoded)) = (fields.next(), fields.next()) else { continue };
        let Ok(blob) = STANDARD.decode(encoded) else {
            draft.skip(names, "invalid");
            continue;
        };
        // The key names its algorithm itself; if that does not match the line, the line is damaged.
        if blob.len() < 4 + algorithm.len() || &blob[4..4 + algorithm.len()] != algorithm.as_bytes() {
            draft.skip(names, "invalid");
            continue;
        }
        if algorithm == "ssh-dss" || algorithm.starts_with("sk-") {
            draft.skip(names, "key_type");
            continue;
        }
        let (key, fingerprint) = encode(algorithm, &blob);
        while !names.is_empty() {
            let (name, rest) = names.split_once(',').unwrap_or((names, ""));
            names = rest;
            let (host, port) = match name.strip_prefix('[').and_then(|n| n.split_once("]:")) {
                Some((host, number)) => (host, port(number)),
                None => (name, Some(22)),
            };
            let Some(port) = port else { continue };
            if host.contains(['*', '?', '!']) {
                draft.skip(name, "pattern");
            } else if usable_address(host) {
                let entry = DraftKnownHost { host: host.to_lowercase(), port, algorithm: algorithm.to_string(), fingerprint: fingerprint.clone(), key: key.clone() };
                if !draft.known_hosts.contains(&entry) {
                    draft.known_hosts.push(entry);
                }
            }
        }
    }
    if hashed > 0 {
        draft.skip(hashed.to_string(), "hashed");
    }
    draft
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real keys from a throwaway run of `ssh-keygen`; the fingerprint comes from `ssh-keygen -lf`.
    const ED: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIG8xl5W2c2FrEsznplCeG1VfI9zSm9CciIj3drnCX2xq";
    const ED_FINGERPRINT: &str = "SHA256:tD76U1hNhVuXZzAUSjsGP8WEJgAy+hQIg7VMbjQZ6wU";

    #[test]
    fn reads_names_ports_and_fingerprints() {
        let text = format!(
            "# comment\nweb.example.org,203.0.113.10 ssh-ed25519 {ED} me@pc\n[Git.Example.org]:2222 ssh-ed25519 {ED}\n|1|c2FsdA==|aGFzaA== ssh-ed25519 {ED}\n|1|YQ==|Yg== ssh-ed25519 {ED}\n*.intern.example ssh-ed25519 {ED}\n@cert-authority *.company.example ssh-ed25519 {ED}\nbroken ssh-ed25519 !!!\nwrong ssh-rsa {ED}\n"
        );
        let draft = parse(&text);
        let found: Vec<_> = draft.known_hosts.iter().map(|k| (k.host.as_str(), k.port, k.algorithm.as_str())).collect();
        assert_eq!(found, [("web.example.org", 22, "ssh-ed25519"), ("203.0.113.10", 22, "ssh-ed25519"), ("git.example.org", 2222, "ssh-ed25519")]);
        assert_eq!(draft.known_hosts[0].key, format!("ssh-ed25519 {ED}"));
        assert_eq!(draft.known_hosts[0].fingerprint, ED_FINGERPRINT);
        let skipped: Vec<_> = draft.skipped.iter().map(|s| (s.name.as_str(), s.reason)).collect();
        assert_eq!(skipped, [("*.intern.example", "pattern"), ("*.company.example", "pattern"), ("broken", "invalid"), ("wrong", "invalid"), ("2", "hashed")]);
        assert!(looks_like(&text));
        assert!(!looks_like("Host web\n  HostName 10.0.0.1\n"));
        assert!(!looks_like(""));
    }
}

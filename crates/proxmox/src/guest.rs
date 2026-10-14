//! What Glowport knows about a machine in order to connect to it: address, user, stored keys,
//! operating system. Combined from what Proxmox provides; pure functions without network.

use base64::{engine::general_purpose::STANDARD, engine::general_purpose::STANDARD_NO_PAD, Engine};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Where an address comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Fixed address from Cloud-Init (`ipconfig0`).
    CloudInit,
    /// Reported by the VM's guest agent.
    Agent,
    /// Fixed address from the container's settings (`net0`).
    Config,
    /// Reported by the running container.
    Guest,
}

impl Source {
    pub fn name(self) -> &'static str {
        match self {
            Source::CloudInit => "cloudinit",
            Source::Agent => "agent",
            Source::Config => "config",
            Source::Guest => "guest",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Facts {
    pub address: Option<(String, Source)>,
    pub user: Option<String>,
    /// Fingerprints of the public keys stored in Cloud-Init (`SHA256:…`, as OpenSSH shows them).
    pub keys: Vec<String>,
    /// Short name of the operating system as the interface knows them (`Ub`, `De`, …).
    pub os: Option<&'static str>,
}

/// One of the machine's interfaces with its addresses, as the guest agent or container reports them.
pub type Interface = (String, Vec<String>);

/// The fixed address from `ip=10.0.0.5/24,gw=10.0.0.1` (Cloud-Init) or `name=eth0,bridge=vmbr0,ip=10.0.0.5/24`
/// (container). `None` for `dhcp`, `manual`, `auto` or without a value. IPv4 counts before IPv6.
pub fn static_address(setting: &str) -> Option<String> {
    let value = |key: &str| setting.split(',').filter_map(|part| part.trim().split_once('=')).find(|(name, _)| *name == key).map(|(_, value)| value.split('/').next().unwrap_or(value).trim());
    [value("ip"), value("ip6")].into_iter().flatten().find(|address| address.parse::<std::net::IpAddr>().is_ok()).map(str::to_string)
}

/// The address under which the machine can be reached from outside: IPv4 before IPv6. Addresses that only apply
/// inside the machine (`127.…`, `::1`, `fe80:…`), and the bridges of Docker and others, do not count.
pub fn measured_address(interfaces: &[Interface]) -> Option<String> {
    let inner = |name: &str| name == "lo" || ["docker", "br-", "veth", "virbr", "cni", "flannel", "tailscale", "wg"].iter().any(|prefix| name.starts_with(prefix));
    let usable: Vec<std::net::IpAddr> = interfaces
        .iter()
        .filter(|(name, _)| !inner(name))
        .flat_map(|(_, addresses)| addresses.iter())
        .filter_map(|address| address.split('/').next()?.trim().parse::<std::net::IpAddr>().ok())
        .filter(|address| match address {
            std::net::IpAddr::V4(v4) => !v4.is_loopback() && !v4.is_link_local() && !v4.is_unspecified(),
            std::net::IpAddr::V6(v6) => !v6.is_loopback() && !v6.is_unspecified() && (v6.segments()[0] & 0xffc0) != 0xfe80,
        })
        .collect();
    usable.iter().find(|address| address.is_ipv4()).or(usable.first()).map(ToString::to_string)
}

/// Fingerprints of the keys from `sshkeys`. Proxmox delivers the text escaped like an address
/// (`%20`, `%0A`), one line per key.
pub fn key_fingerprints(encoded: &str) -> Vec<String> {
    let mut text = Vec::with_capacity(encoded.len());
    let bytes = encoded.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hex = (bytes[i] == b'%').then(|| encoded.get(i + 1..i + 3)).flatten().and_then(|pair| u8::from_str_radix(pair, 16).ok());
        match hex {
            Some(byte) => (text.push(byte), i += 3).1,
            None => (text.push(bytes[i]), i += 1).1,
        }
    }
    String::from_utf8_lossy(&text)
        .lines()
        .filter_map(|line| {
            // `ssh-ed25519 AAAA… comment`, options may come before it.
            let mut words = line.split_whitespace().skip_while(|word| !(word.starts_with("ssh-") || word.starts_with("ecdsa-") || word.starts_with("sk-")));
            let blob = STANDARD.decode(words.nth(1)?).ok()?;
            Some(format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(&blob))))
        })
        .collect()
}

/// The short name of the operating system from what Proxmox and the guest agent name. The machine's name helps when
/// Proxmox only knows “Linux” (`l26`).
pub fn os_code(ostype: Option<&str>, reported: Option<&str>, name: &str) -> Option<&'static str> {
    // The short names are in `src/lib/os.ts`. Whatever has none of its own there shows as “Linux”.
    const KNOWN: [(&str, &str); 13] = [
        ("ubuntu", "Ub"),
        ("debian", "De"),
        ("alpine", "Al"),
        ("arch", "Ar"),
        ("alma", "Alma"),
        ("red hat", "RH"),
        ("rhel", "RH"),
        ("suse", "SUSE"),
        ("kali", "Kali"),
        ("mint", "Mint"),
        ("freebsd", "BSD"),
        ("proxmox", "PVE"),
        ("windows", "Win"),
    ];
    let texts = [reported.unwrap_or_default().to_lowercase(), ostype.unwrap_or_default().to_lowercase(), name.to_lowercase()];
    let found = texts.iter().find_map(|text| KNOWN.iter().find(|(word, _)| text.contains(word)).map(|(_, code)| *code));
    found.or_else(|| match ostype.unwrap_or_default() {
        // This is how Proxmox names the Windows versions: wxp, w2k8, win10, win11 …
        os if os.starts_with('w') => Some("Win"),
        "l24" | "l26" => Some("Li"),
        _ => None,
    })
}

/// Combines what is known about a machine. `config` are its settings in Proxmox, `interfaces`
/// what it currently reports itself (empty if it is off or reports nothing), `reported` the name of the system
/// from the guest agent.
pub fn facts(vm: bool, name: &str, config: &Value, interfaces: &[Interface], reported: Option<&str>) -> Facts {
    let text = |key: &str| config.get(key).and_then(Value::as_str);
    // A fixed address applies before a measured one: it is right even when the machine is off.
    let fixed = (0..8).find_map(|n| text(&format!("{}{n}", if vm { "ipconfig" } else { "net" })).and_then(static_address));
    let address = match fixed {
        Some(address) => Some((address, if vm { Source::CloudInit } else { Source::Config })),
        None => measured_address(interfaces).map(|address| (address, if vm { Source::Agent } else { Source::Guest })),
    };
    Facts {
        address,
        // Proxmox containers sign in as root; for VMs Cloud-Init says so or nobody does.
        user: if vm { text("ciuser").filter(|user| !user.is_empty()).map(str::to_string) } else { Some("root".into()) },
        keys: text("sshkeys").map(key_fingerprints).unwrap_or_default(),
        os: os_code(text("ostype"), reported, name),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn fixed_addresses_come_from_the_settings() {
        assert_eq!(static_address("ip=10.0.10.11/24,gw=10.0.10.1").as_deref(), Some("10.0.10.11"));
        assert_eq!(static_address("name=eth0,bridge=vmbr0,hwaddr=BC:24:11:AA:BB:CC,ip=10.0.0.53/24,gw=10.0.0.1,type=veth").as_deref(), Some("10.0.0.53"));
        assert_eq!(static_address("ip=dhcp,ip6=2001:db8::5/64").as_deref(), Some("2001:db8::5"), "IPv4 per DHCP, IPv6 fest");
        assert_eq!(static_address("gw=10.0.0.1,ip6=2001:db8::5/64,ip=10.0.0.7/24").as_deref(), Some("10.0.0.7"), "IPv4 vor IPv6");
        for none in ["ip=dhcp", "ip=dhcp,ip6=auto", "name=eth0,bridge=vmbr0,ip=manual", "name=eth0,bridge=vmbr0", "", "ip=quatsch"] {
            assert_eq!(static_address(none), None, "{none}");
        }
    }

    #[test]
    fn measured_addresses_skip_what_only_counts_inside() {
        let interface = |name: &str, addresses: &[&str]| (name.to_string(), addresses.iter().map(|a| a.to_string()).collect::<Vec<_>>());
        let seen = [
            interface("lo", &["127.0.0.1", "::1"]),
            interface("docker0", &["172.17.0.1"]),
            interface("br-3f1a", &["172.18.0.1"]),
            interface("eth0", &["fe80::be24:11ff:feaa:bbcc", "2001:db8::10/64", "10.0.10.90/24"]),
            interface("eth1", &["192.168.50.4"]),
        ];
        assert_eq!(measured_address(&seen).as_deref(), Some("10.0.10.90"), "IPv4 vor IPv6, ohne Schleife und Docker");
        assert_eq!(measured_address(&[interface("eth0", &["fe80::1", "2001:db8::10/64"])]).as_deref(), Some("2001:db8::10"));
        assert_eq!(measured_address(&[interface("lo", &["127.0.0.1"]), interface("eth0", &["169.254.3.4", "fe80::1", "quatsch"])]), None);
        assert_eq!(measured_address(&[]), None);
    }

    #[test]
    fn stored_keys_are_known_by_their_fingerprint() {
        // A throwaway key generated for this; the fingerprint was read from `ssh-keygen -lf`.
        let line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOgQqXeoYfd9GJUg5ajXbvrpe+0M0f5PTO0MRd4ZpqK7 deploy@laptop";
        let own = "SHA256:HHT2sEZO+TuiQj394rcd79mgejTl0WQ0Gdawh2rVk/c".to_string();
        let encoded = format!("{}%0A%0Ano-pty%20{}%0Akein%20schluessel%0A", line.replace(' ', "%20"), line.replace(' ', "%20"));
        assert_eq!(key_fingerprints(&encoded), [own.clone(), own.clone()], "umschrieben, mit Leerzeile, mit Optionen davor");
        assert_eq!(key_fingerprints("ssh-ed25519%20kein-base64!%0A%ZZ"), Vec::<String>::new());
    }

    #[test]
    fn the_system_is_read_from_whatever_names_it() {
        assert_eq!(os_code(Some("l26"), Some("Ubuntu 24.04.1 LTS"), "web-01"), Some("Ub"));
        assert_eq!(os_code(Some("l26"), None, "debian-13-vorlage"), Some("De"), "der Name der Maschine hilft");
        assert_eq!(os_code(Some("alpine"), None, "gitea"), Some("Al"), "Container nennen ihr System selbst");
        assert_eq!(os_code(Some("l26"), None, "web-01"), Some("Li"));
        assert_eq!(os_code(Some("win11"), None, "büro"), Some("Win"));
        assert_eq!(os_code(Some("l26"), Some("Fedora Linux 42"), "kiste"), Some("Li"), "ohne eigenes Kürzel: Linux");
        assert_eq!(os_code(Some("other"), None, "kiste"), None);
        assert_eq!(os_code(None, None, ""), None);
    }

    #[test]
    fn a_fixed_address_beats_a_measured_one() {
        let eth = [("eth0".to_string(), vec!["10.0.10.99/24".to_string()])];
        let vm = json!({ "ipconfig0": "ip=10.0.10.11/24,gw=10.0.10.1", "ciuser": "deploy", "ostype": "l26", "sshkeys": "" });
        assert_eq!(facts(true, "web-01", &vm, &eth, Some("Ubuntu 24.04")), Facts { address: Some(("10.0.10.11".into(), Source::CloudInit)), user: Some("deploy".into()), keys: vec![], os: Some("Ub") });
        // DHCP: what the guest agent reports counts. Without Cloud-Init nobody names a user.
        assert_eq!(facts(true, "monitoring", &json!({ "ipconfig0": "ip=dhcp", "ostype": "l26" }), &eth, None), Facts { address: Some(("10.0.10.99".into(), Source::Agent)), user: None, keys: vec![], os: Some("Li") });
        assert_eq!(facts(true, "aus", &json!({ "ostype": "l26" }), &[], None).address, None, "aus und ohne feste Adresse");
        // Container: fixed address from net0, otherwise the reported one; user root.
        assert_eq!(facts(false, "pihole", &json!({ "net0": "name=eth0,bridge=vmbr0,ip=10.0.0.53/24", "ostype": "debian" }), &[], None), Facts { address: Some(("10.0.0.53".into(), Source::Config)), user: Some("root".into()), keys: vec![], os: Some("De") });
        assert_eq!(facts(false, "gitea", &json!({ "net0": "name=eth0,bridge=vmbr0,ip=dhcp", "ostype": "alpine" }), &eth, None).address, Some(("10.0.10.99".into(), Source::Guest)));
        // The second network card has the fixed address.
        assert_eq!(facts(false, "zwei", &json!({ "net0": "name=eth0,ip=dhcp", "net1": "name=eth1,ip=10.9.9.9/24" }), &[], None).address, Some(("10.9.9.9".into(), Source::Config)));
    }
}

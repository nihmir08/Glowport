//! Bestimmt das Betriebssystem eines Servers für das Symbol des Hosts.

use std::time::Duration;

use russh::{client::Handle, ChannelMsg};
use tokio::time::timeout;

use crate::Client;

/// Läuft in `sh`, damit die Abfrage auch dort gelingt, wo die Anmelde-Shell eine andere Schreibweise hat (csh auf
/// FreeBSD). Jede Zeile `GLOWPORT_MARK=…` meldet eine Datei, an der sich ein Aufsatz verrät, der sich sonst als sein
/// Unterbau ausgibt (Proxmox als Debian, OPNsense als FreeBSD). Unter Windows gibt es kein `sh`; dann antwortet `ver`.
const PROBE: &str = "sh -c 'uname -s 2>/dev/null; cat /etc/os-release 2>/dev/null; \
test -d /etc/pve && echo GLOWPORT_MARK=pve; test -d /etc/proxmox-backup && echo GLOWPORT_MARK=pbs; \
test -f /etc/rpi-issue && echo GLOWPORT_MARK=rpi; test -f /etc/synoinfo.conf && echo GLOWPORT_MARK=synology; \
test -f /etc/unraid-version && echo GLOWPORT_MARK=unraid; test -d /usr/local/opnsense && echo GLOWPORT_MARK=opnsense; \
grep -qi pfsense /etc/platform 2>/dev/null && echo GLOWPORT_MARK=pfsense; true' || ver";
const MAX_OUTPUT: usize = 8192;

/// Fragt den Server auf einem eigenen Kanal. Scheitert das, gibt es eben kein Ergebnis; die Sitzung stört es nicht.
pub(crate) async fn probe(handle: &Handle<Client>) -> Option<String> {
    let mut channel = handle.channel_open_session().await.ok()?;
    channel.exec(true, PROBE).await.ok()?;
    let mut output = Vec::new();
    let read = async {
        while let Some(message) = channel.wait().await {
            if let ChannelMsg::Data { data } = message {
                output.extend_from_slice(&data);
                if output.len() > MAX_OUTPUT {
                    break;
                }
            }
        }
    };
    timeout(Duration::from_secs(5), read).await.ok()?;
    classify(&String::from_utf8_lossy(&output))
}

/// Kennung eines Systems zu seiner `ID` aus `/etc/os-release`.
fn by_id(id: &str) -> Option<&'static str> {
    Some(match id {
        "ubuntu" => "Ub",
        "raspbian" => "Rp",
        "debian" => "De",
        "alpine" => "Al",
        "rhel" => "RH",
        "rocky" => "Rocky",
        "almalinux" => "Alma",
        "centos" => "CentOS",
        "fedora" => "Fedora",
        "ol" => "Oracle",
        "amzn" => "Amazon",
        "arch" | "archarm" => "Ar",
        "manjaro" | "manjaro-arm" => "Manjaro",
        "linuxmint" => "Mint",
        "pop" => "Pop",
        "kali" => "Kali",
        "opensuse" | "opensuse-leap" | "opensuse-tumbleweed" | "opensuse-microos" | "sles" | "sled" | "suse" => "SUSE",
        "nixos" => "NixOS",
        "gentoo" => "Gentoo",
        "void" => "Void",
        "openwrt" => "OpenWrt",
        _ => return None,
    })
}

/// Ordnet die Ausgabe von [`PROBE`] einer Kennung zu. Die Kennungen sind dieselben wie in `src/lib/os.ts`.
pub fn classify(output: &str) -> Option<String> {
    let marked = |name: &str| output.lines().any(|line| line.trim().strip_prefix("GLOWPORT_MARK=") == Some(name));
    // Aufsätze zuerst: Ihr Unterbau meldet sich zwar auch, gemeint ist aber das, was darauf läuft.
    for (mark, key) in [("pve", "PVE"), ("pbs", "PBS"), ("synology", "Synology"), ("unraid", "Unraid"), ("opnsense", "OPNsense"), ("pfsense", "pfSense")] {
        if marked(mark) {
            return Some(key.into());
        }
    }
    let field = |name: &str| output.lines().find_map(|line| line.strip_prefix(name)).map(|value| value.trim().trim_matches('"').to_lowercase());
    let own = field("ID=");
    // Raspberry Pi OS nennt sich in der 64-Bit-Fassung schlicht `debian`; die Datei `/etc/rpi-issue` verrät es.
    if own.as_deref() == Some("debian") && marked("rpi") {
        return Some("Rp".into());
    }
    // Die eigene Kennung zählt vor der Verwandtschaft; ein unbekannter Abkömmling bekommt das Zeichen seiner Familie.
    let relatives = field("ID_LIKE=").unwrap_or_default();
    if let Some(key) = own.iter().map(String::as_str).chain(relatives.split_whitespace()).find_map(by_id) {
        return Some(key.into());
    }
    match output.lines().next().map(str::trim).unwrap_or_default() {
        "FreeBSD" => Some("BSD".into()),
        "OpenBSD" => Some("OpenBSD".into()),
        "NetBSD" => Some("NetBSD".into()),
        "Darwin" => Some("macOS".into()),
        "Linux" => Some("Li".into()),
        // `ver` unter Windows: „Microsoft Windows [Version 10.0.…]“, davor eine Leerzeile.
        _ if output.lines().any(|line| line.trim_start().starts_with("Microsoft Windows")) => Some("Win".into()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::classify;

    #[test]
    fn known_systems_are_recognised() {
        let os = |text: &str| classify(text);
        assert_eq!(os("Linux\nNAME=\"Ubuntu\"\nID=ubuntu\nID_LIKE=debian\n").as_deref(), Some("Ub"));
        assert_eq!(os("Linux\nID=debian\n").as_deref(), Some("De"));
        assert_eq!(os("Linux\nID=raspbian\nID_LIKE=debian\n").as_deref(), Some("Rp"));
        assert_eq!(os("Linux\nID=debian\nGLOWPORT_MARK=rpi\n").as_deref(), Some("Rp"), "die 64-Bit-Fassung nennt sich debian");
        assert_eq!(os("Linux\nID=alpine\n").as_deref(), Some("Al"));
        assert_eq!(os("Linux\nID=arch\n").as_deref(), Some("Ar"));
        assert_eq!(os("Linux\nID=irgendwas\n").as_deref(), Some("Li"));
        assert_eq!(os(""), None);
        assert_eq!(os("'uname' is not recognized as an internal or external command"), None);
    }

    /// Jedes System bekommt sein eigenes Zeichen; früher teilten sich Verwandte eines.
    #[test]
    fn relatives_are_told_apart() {
        let os = |text: &str| classify(text);
        for (id, key) in [("rhel", "RH"), ("rocky", "Rocky"), ("almalinux", "Alma"), ("centos", "CentOS"), ("fedora", "Fedora"), ("ol", "Oracle"), ("amzn", "Amazon")] {
            assert_eq!(os(&format!("Linux\nID=\"{id}\"\nID_LIKE=\"rhel centos fedora\"\n")).as_deref(), Some(key), "{id}");
        }
        assert_eq!(os("Linux\nID=manjaro\nID_LIKE=arch\n").as_deref(), Some("Manjaro"));
        assert_eq!(os("Linux\nID=linuxmint\nID_LIKE=\"ubuntu debian\"\n").as_deref(), Some("Mint"));
        assert_eq!(os("Linux\nID=\"opensuse-leap\"\nID_LIKE=\"suse opensuse\"\n").as_deref(), Some("SUSE"));
        assert_eq!(os("Linux\nID=kali\nID_LIKE=debian\n").as_deref(), Some("Kali"));
        assert_eq!(os("Linux\nID=nixos\n").as_deref(), Some("NixOS"));
        assert_eq!(os("Linux\nID=\"openwrt\"\nID_LIKE=\"lede openwrt\"\n").as_deref(), Some("OpenWrt"));
        assert_eq!(os("Linux\nID=zorin\nID_LIKE=\"ubuntu debian\"\n").as_deref(), Some("Ub"), "ein unbekannter Abkömmling bekommt das Zeichen seiner Familie");
        assert_eq!(os("Linux\nID=eurolinux\nID_LIKE=\"rhel fedora centos\"\n").as_deref(), Some("RH"));
    }

    #[test]
    fn systems_built_on_another_show_as_themselves() {
        let os = |text: &str| classify(text);
        assert_eq!(os("Linux\nID=debian\nGLOWPORT_MARK=pve\n").as_deref(), Some("PVE"), "Proxmox ist Debian mit /etc/pve");
        assert_eq!(os("Linux\nID=debian\nGLOWPORT_MARK=pbs\n").as_deref(), Some("PBS"));
        assert_eq!(os("Linux\nGLOWPORT_MARK=synology\n").as_deref(), Some("Synology"));
        assert_eq!(os("Linux\nID=slackware\nGLOWPORT_MARK=unraid\n").as_deref(), Some("Unraid"));
        assert_eq!(os("FreeBSD\nGLOWPORT_MARK=opnsense\n").as_deref(), Some("OPNsense"));
        assert_eq!(os("FreeBSD\nGLOWPORT_MARK=pfsense\n").as_deref(), Some("pfSense"));
        assert_eq!(os("FreeBSD\n").as_deref(), Some("BSD"));
        assert_eq!(os("OpenBSD\n").as_deref(), Some("OpenBSD"));
        assert_eq!(os("NetBSD\n").as_deref(), Some("NetBSD"));
        assert_eq!(os("Darwin\n").as_deref(), Some("macOS"));
        assert_eq!(os("\r\nMicrosoft Windows [Version 10.0.26100.1742]\r\n").as_deref(), Some("Win"), "Antwort von ver");
        // Die Abfrage selbst muss in csh wie in sh gültig sein: ein einziges Argument in einfachen Anführungszeichen.
        assert!(super::PROBE.starts_with("sh -c '") && super::PROBE.ends_with("' || ver") && super::PROBE.matches('\'').count() == 2);
    }
}

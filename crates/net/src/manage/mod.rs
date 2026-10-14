//! Verwaltung eines Linux-Servers über Befehle auf der bestehenden Verbindung: Docker, systemd-Dienste, Prozesse
//! (`docs/verwaltung.md`).
//!
//! Dieses Modul baut Befehle und liest ihre Ausgabe; es führt selbst nichts aus. Jede Liste entsteht aus einem
//! einzigen Aufruf, dessen Ausgabe in Abschnitte zerfällt, die mit einer Zeile `@name` beginnen (wie bei
//! [`crate::stats`]). Alles läuft in `sh`, damit die Anmelde-Shell des Benutzers (fish, csh) keine Rolle spielt, und
//! mit `LC_ALL=C`, damit die Meldungen englisch und damit lesbar sind.
//!
//! Was vom Server kommt (Kennungen von Containern, Namen von Diensten, Prozessnummern), geht nie als Text in einen
//! Befehl: Es wird auf seine Form geprüft und als eigenes Argument übergeben (`"$1"`).

pub mod docker;
pub mod processes;
pub mod services;

use std::collections::HashMap;

/// Mit welchen Rechten ein Befehl läuft.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum As {
    /// Als der angemeldete Benutzer.
    User,
    /// Mit `sudo -n`: ohne Passwortabfrage, sonst gar nicht.
    Sudo,
}

impl As {
    /// Was vor dem Programm steht.
    fn prefix(self) -> &'static str {
        match self {
            As::User => "",
            As::Sudo => "sudo -n -- ",
        }
    }
}

/// Was nach einem Versuch gilt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Done,
    /// Dem angemeldeten Benutzer fehlen die Rechte: mit [`As::Sudo`] noch einmal.
    NeedsRoot,
    /// `sudo` will ein Passwort. Das gibt der Nutzer selbst im Terminal ein, siehe [`typed`].
    NeedsPassword,
    /// Es ging aus einem anderen Grund nicht; der Text ist die Meldung des Servers.
    Failed(String),
}

/// Meldungen, mit denen Programme fehlende Rechte anzeigen.
const DENIED: [&str; 8] = ["permission denied", "access denied", "operation not permitted", "authentication required", "authentication is required", "must be root", "are you root", "not permitted"];
/// Meldungen von `sudo -n`, wenn es ein Passwort bräuchte (klassisches sudo und sudo-rs).
const PASSWORD: [&str; 5] = ["a password is required", "password is required", "authentication is required", "a terminal is required", "no tty present"];

/// Deutet das Ende eines Befehls, den dieses Modul gebaut hat: `ok` ist sein Erfolg, `text` seine Ausgabe samt
/// Fehlermeldungen.
pub fn verdict(ok: bool, text: &str, how: As) -> Verdict {
    if ok {
        return Verdict::Done;
    }
    let lower = text.to_lowercase();
    match how {
        As::Sudo if lower.contains("sudo") && PASSWORD.iter().any(|sign| lower.contains(sign)) => Verdict::NeedsPassword,
        As::User if DENIED.iter().any(|sign| lower.contains(sign)) => Verdict::NeedsRoot,
        _ => Verdict::Failed(message(text)),
    }
}

/// Die Meldung des Servers in einer Länge, die sich zeigen lässt: die letzten Zeilen, ohne Leerzeilen.
fn message(text: &str) -> String {
    const LINES: usize = 6;
    const CHARS: usize = 600;
    let lines: Vec<&str> = text.lines().map(str::trim).filter(|line| !line.is_empty()).collect();
    let kept = lines[lines.len().saturating_sub(LINES)..].join("\n");
    match kept.char_indices().nth(CHARS) {
        Some((at, _)) => format!("{}…", &kept[..at]),
        None => kept,
    }
}

/// Was der Nutzer selbst im Terminal abschickt, wenn `sudo` ein Passwort will. `command` ist der Befehl ohne `sudo`,
/// so wie ihn ein Mensch tippen würde (siehe etwa [`docker::Action::typed`]).
pub fn typed(command: &str) -> String {
    format!("sudo {command}")
}

/// Ein Wort so, dass jede Shell es wörtlich nimmt.
pub(crate) fn quoted(word: &str) -> String {
    format!("'{}'", word.replace('\'', r"'\''"))
}

/// Ein Befehl mit genau einem Wert vom Server. Der Wert steht nicht im Text des Befehls, sondern kommt als
/// eigenes Argument dazu und heißt darin `"$1"`. Fehlermeldungen landen mit in der Ausgabe.
fn with_argument(script: &str, argument: &str) -> String {
    debug_assert!(!script.contains('\''), "das Skript steht selbst in einfachen Anführungszeichen");
    format!("sh -c 'exec 2>&1; export LC_ALL=C; {script}' sh {}", quoted(argument))
}

/// Zerlegt eine Ausgabe in ihre Abschnitte. Was vor dem ersten `@name` steht, zählt nicht.
fn sections(text: &str) -> HashMap<&str, Vec<&str>> {
    let mut out: HashMap<&str, Vec<&str>> = HashMap::new();
    let mut current = None;
    for line in text.lines() {
        match line.strip_prefix('@') {
            Some(name) if !name.is_empty() && name.bytes().all(|b| b.is_ascii_lowercase()) => {
                out.entry(name).or_default();
                current = Some(name);
            }
            _ => {
                if let Some(name) = current {
                    out.entry(name).or_default().push(line);
                }
            }
        }
    }
    out
}

/// Findet heraus, was ein Server hergibt. Läuft einmal je Sitzung.
///
/// `ps` zählt nur, wenn es die Spalten kennt, die [`processes`] braucht (procps; das `ps` von BusyBox nicht).
pub const PROBE: &str = concat!(
    "sh -c '",
    "exec 2>/dev/null; ",
    "echo @uid; id -u; ",
    "echo @docker; command -v docker; ",
    "echo @systemd; test -d /run/systemd/system && command -v systemctl; ",
    "echo @ps; ps -o pid=,etimes=,user:32= -p 1; ",
    "echo @sudo; sudo -n true && echo yes",
    "'"
);

/// Was es auf einem Server zu verwalten gibt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Abilities {
    /// Die Sitzung ist als `root` angemeldet.
    pub root: bool,
    pub docker: bool,
    pub services: bool,
    pub processes: bool,
    /// `sudo` geht ohne Passwort.
    pub sudo: bool,
}

/// Liest die Ausgabe von [`PROBE`].
pub fn abilities(text: &str) -> Abilities {
    let sections = sections(text);
    let filled = |name: &str| sections.get(name).is_some_and(|lines| lines.iter().any(|line| !line.trim().is_empty()));
    Abilities {
        root: sections.get("uid").and_then(|lines| lines.first()).is_some_and(|line| line.trim() == "0"),
        docker: filled("docker"),
        services: filled("systemd"),
        processes: filled("ps"),
        sudo: sections.get("sudo").is_some_and(|lines| lines.iter().any(|line| line.trim() == "yes")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_probe_tells_what_a_server_offers() {
        // Ubuntu im WSL als gewöhnlicher Benutzer: systemd und procps, kein Docker, sudo nur mit Passwort.
        let ubuntu = "@uid\n1000\n@docker\n@systemd\n/usr/bin/systemctl\n@ps\n      1       2 root\n@sudo\n";
        assert_eq!(abilities(ubuntu), Abilities { root: false, docker: false, services: true, processes: true, sudo: false });
        let root = "@uid\n0\n@docker\n/usr/bin/docker\n@systemd\n/usr/bin/systemctl\n@ps\n      1  864000 root\n@sudo\nyes\n";
        assert_eq!(abilities(root), Abilities { root: true, docker: true, services: true, processes: true, sudo: true });
        // Alpine im Container: kein systemd, das ps von BusyBox kennt die Spalten nicht.
        assert_eq!(abilities("@uid\n0\n@docker\n@systemd\n@ps\n@sudo\n"), Abilities { root: true, ..Abilities::default() });
        // Kein Linux, keine Shell, die antwortet.
        assert_eq!(abilities(""), Abilities::default());
        assert_eq!(abilities("irgendetwas\nganz anderes"), Abilities::default());
    }

    #[test]
    fn a_refusal_says_what_to_try_next() {
        assert_eq!(verdict(true, "permission denied", As::User), Verdict::Done, "gelungen ist gelungen");
        // Als Benutzer abgelehnt: mit sudo noch einmal.
        for text in [
            "permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock",
            "Failed to restart cron.service: Interactive authentication required.\nSee system logs and 'systemctl status cron.service' for details.",
            "Failed to stop ssh.service: Access denied",
            "sh: 1: kill: (1) - Operation not permitted",
        ] {
            assert_eq!(verdict(false, text, As::User), Verdict::NeedsRoot, "{text}");
        }
        // sudo will ein Passwort: klassisches sudo und sudo-rs.
        for text in ["sudo: a password is required", "sudo: interactive authentication is required", "sudo: a terminal is required to read the password; either use the -S option"] {
            assert_eq!(verdict(false, text, As::Sudo), Verdict::NeedsPassword, "{text}");
        }
        // Alles andere ist ein Fehler mit der Meldung des Servers, auch unter sudo.
        assert_eq!(verdict(false, "Error response from daemon: No such container: abc\n", As::User), Verdict::Failed("Error response from daemon: No such container: abc".into()));
        assert_eq!(verdict(false, "Failed to start nix.service: Unit nix.service not found.", As::Sudo), Verdict::Failed("Failed to start nix.service: Unit nix.service not found.".into()));
        assert_eq!(verdict(false, "alex is not in the sudoers file.", As::Sudo), Verdict::Failed("alex is not in the sudoers file.".into()));
        // Lange Ausgaben: die letzten Zeilen.
        let long = (1..=20).map(|n| format!("Zeile {n}\n\n")).collect::<String>();
        assert_eq!(verdict(false, &long, As::User), Verdict::Failed("Zeile 15\nZeile 16\nZeile 17\nZeile 18\nZeile 19\nZeile 20".into()));
        let Verdict::Failed(cut) = verdict(false, &"ä".repeat(2000), As::User) else { panic!() };
        assert_eq!(cut.chars().count(), 601);
    }

    #[test]
    fn values_from_the_server_never_become_part_of_a_command() {
        assert_eq!(quoted("cron.service"), "'cron.service'");
        assert_eq!(quoted("a'; rm -rf /; '"), r"'a'\''; rm -rf /; '\'''");
        assert_eq!(with_argument("systemctl restart \"$1\"", "cron.service"), "sh -c 'exec 2>&1; export LC_ALL=C; systemctl restart \"$1\"' sh 'cron.service'");
        assert_eq!(typed("systemctl restart cron.service"), "sudo systemctl restart cron.service");
        assert_eq!((As::User.prefix(), As::Sudo.prefix()), ("", "sudo -n -- "));
    }

    #[test]
    fn output_falls_into_sections() {
        let parts = sections("davor\n@eins\na\nb\n@leer\n@zwei\nc\n@Kein Abschnitt\n@\n");
        assert_eq!(parts.get("eins"), Some(&vec!["a", "b"]));
        assert_eq!(parts.get("leer"), Some(&vec![]));
        // Zeilen, die nur so aussehen, gehören zum Inhalt.
        assert_eq!(parts.get("zwei"), Some(&vec!["c", "@Kein Abschnitt", "@"]));
        assert_eq!(parts.len(), 3);
    }
}

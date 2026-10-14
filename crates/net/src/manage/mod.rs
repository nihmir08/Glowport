//! Managing a Linux server through commands on the existing connection: Docker, systemd services, processes
//! (`docs/management.md`).
//!
//! This module builds commands and reads their output; it runs nothing itself. Every list comes from a
//! single call whose output splits into sections that start with a line `@name` (as in
//! [`crate::stats`]). Everything runs in `sh`, so the user's login shell (fish, csh) does not matter, and
//! with `LC_ALL=C`, so the messages are in English and therefore readable.
//!
//! What comes from the server (container IDs, service names, process numbers) never goes into a
//! command as text: it is checked for its form and passed as an argument of its own (`"$1"`).

pub mod docker;
pub mod processes;
pub mod services;

use std::collections::HashMap;

/// With which permissions a command runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum As {
    /// As the signed-in user.
    User,
    /// With `sudo -n`: without a password prompt, otherwise not at all.
    Sudo,
}

impl As {
    /// What goes before the program.
    fn prefix(self) -> &'static str {
        match self {
            As::User => "",
            As::Sudo => "sudo -n -- ",
        }
    }
}

/// What applies after an attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Done,
    /// The signed-in user lacks permissions: once more with [`As::Sudo`].
    NeedsRoot,
    /// `sudo` wants a password. The user types it in the terminal themselves, see [`typed`].
    NeedsPassword,
    /// It failed for another reason; the text is the server's message.
    Failed(String),
}

/// Messages with which programs report missing permissions.
const DENIED: [&str; 8] = ["permission denied", "access denied", "operation not permitted", "authentication required", "authentication is required", "must be root", "are you root", "not permitted"];
/// Messages of `sudo -n` when it would need a password (classic sudo and sudo-rs).
const PASSWORD: [&str; 5] = ["a password is required", "password is required", "authentication is required", "a terminal is required", "no tty present"];

/// Interprets the end of a command this module built: `ok` is its success, `text` its output including
/// error messages.
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

/// The server's message at a length that can be shown: the last lines, without empty lines.
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

/// What the user sends in the terminal themselves when `sudo` wants a password. `command` is the command without `sudo`,
/// as a human would type it (see e.g. [`docker::Action::typed`]).
pub fn typed(command: &str) -> String {
    format!("sudo {command}")
}

/// A word in a form every shell takes literally.
pub(crate) fn quoted(word: &str) -> String {
    format!("'{}'", word.replace('\'', r"'\''"))
}

/// A command with exactly one value from the server. The value is not in the command's text but comes as
/// an argument of its own and is called `"$1"` there. Error messages end up in the output too.
fn with_argument(script: &str, argument: &str) -> String {
    debug_assert!(!script.contains('\''), "the script itself is in single quotes");
    format!("sh -c 'exec 2>&1; export LC_ALL=C; {script}' sh {}", quoted(argument))
}

/// Splits an output into its sections. Whatever comes before the first `@name` does not count.
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

/// Finds out what a server offers. Runs once per session.
///
/// `ps` only counts if it knows the columns [`processes`] needs (procps; BusyBox's `ps` does not).
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

/// What there is to manage on a server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Abilities {
    /// The session is signed in as `root`.
    pub root: bool,
    pub docker: bool,
    pub services: bool,
    pub processes: bool,
    /// `sudo` works without a password.
    pub sudo: bool,
}

/// Reads the output of [`PROBE`].
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
        // Ubuntu in WSL as an ordinary user: systemd and procps, no Docker, sudo only with a password.
        let ubuntu = "@uid\n1000\n@docker\n@systemd\n/usr/bin/systemctl\n@ps\n      1       2 root\n@sudo\n";
        assert_eq!(abilities(ubuntu), Abilities { root: false, docker: false, services: true, processes: true, sudo: false });
        let root = "@uid\n0\n@docker\n/usr/bin/docker\n@systemd\n/usr/bin/systemctl\n@ps\n      1  864000 root\n@sudo\nyes\n";
        assert_eq!(abilities(root), Abilities { root: true, docker: true, services: true, processes: true, sudo: true });
        // Alpine in a container: no systemd, BusyBox's ps does not know the columns.
        assert_eq!(abilities("@uid\n0\n@docker\n@systemd\n@ps\n@sudo\n"), Abilities { root: true, ..Abilities::default() });
        // No Linux, no shell that answers.
        assert_eq!(abilities(""), Abilities::default());
        assert_eq!(abilities("irgendetwas\nganz anderes"), Abilities::default());
    }

    #[test]
    fn a_refusal_says_what_to_try_next() {
        assert_eq!(verdict(true, "permission denied", As::User), Verdict::Done, "succeeded is succeeded");
        // Refused as the user: once more with sudo.
        for text in [
            "permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock",
            "Failed to restart cron.service: Interactive authentication required.\nSee system logs and 'systemctl status cron.service' for details.",
            "Failed to stop ssh.service: Access denied",
            "sh: 1: kill: (1) - Operation not permitted",
        ] {
            assert_eq!(verdict(false, text, As::User), Verdict::NeedsRoot, "{text}");
        }
        // sudo wants a password: classic sudo and sudo-rs.
        for text in ["sudo: a password is required", "sudo: interactive authentication is required", "sudo: a terminal is required to read the password; either use the -S option"] {
            assert_eq!(verdict(false, text, As::Sudo), Verdict::NeedsPassword, "{text}");
        }
        // Everything else is an error with the server's message, also under sudo.
        assert_eq!(verdict(false, "Error response from daemon: No such container: abc\n", As::User), Verdict::Failed("Error response from daemon: No such container: abc".into()));
        assert_eq!(verdict(false, "Failed to start nix.service: Unit nix.service not found.", As::Sudo), Verdict::Failed("Failed to start nix.service: Unit nix.service not found.".into()));
        assert_eq!(verdict(false, "alex is not in the sudoers file.", As::Sudo), Verdict::Failed("alex is not in the sudoers file.".into()));
        // Long output: the last lines.
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
        let parts = sections("before\n@one\na\nb\n@empty\n@two\nc\n@No section\n@\n");
        assert_eq!(parts.get("one"), Some(&vec!["a", "b"]));
        assert_eq!(parts.get("empty"), Some(&vec![]));
        // Lines that only look like it belong to the content.
        assert_eq!(parts.get("two"), Some(&vec!["c", "@No section", "@"]));
        assert_eq!(parts.len(), 3);
    }
}

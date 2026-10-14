//! Dienste von systemd: auflisten, starten, stoppen, neu starten, beim Start ein- und ausschalten.

use std::collections::BTreeMap;

use super::{quoted, sections, with_argument, As};

/// Der Befehl für die Liste. Lesen darf das jeder Benutzer.
pub const LIST: &str = concat!(
    "sh -c '",
    "exec 2>/dev/null; export LC_ALL=C; ",
    "echo @units; systemctl list-units --type=service --all --no-legend --no-pager --plain; ",
    "echo @files; systemctl list-unit-files --type=service --no-legend --no-pager",
    "'"
);

/// Mehr Dienste zeigt die Liste nicht.
const MAX_SERVICES: usize = 2000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Active {
    Active,
    Inactive,
    Failed,
    Activating,
    Deactivating,
    Other,
}

impl Active {
    fn read(text: &str) -> Self {
        match text {
            "active" | "reloading" | "refreshing" => Active::Active,
            "inactive" => Active::Inactive,
            "failed" => Active::Failed,
            "activating" => Active::Activating,
            "deactivating" => Active::Deactivating,
            _ => Active::Other,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Active::Active => "active",
            Active::Inactive => "inactive",
            Active::Failed => "failed",
            Active::Activating => "activating",
            Active::Deactivating => "deactivating",
            Active::Other => "other",
        }
    }

    /// Reihenfolge in der Liste: Fehlgeschlagenes zuerst, dann was läuft.
    fn rank(self) -> u8 {
        match self {
            Active::Failed => 0,
            Active::Activating | Active::Deactivating => 1,
            Active::Active => 2,
            _ => 3,
        }
    }
}

/// Ob ein Dienst beim Start des Servers mitläuft.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enabled {
    Enabled,
    Disabled,
    /// Lässt sich nicht einschalten: Er wird nur von anderen gestartet.
    Static,
    Masked,
    /// Etwas, das sich nicht umschalten lässt (erzeugt, flüchtig, Verweis) oder das systemd nicht nennt.
    Other,
}

impl Enabled {
    fn read(text: &str) -> Self {
        match text {
            "enabled" | "enabled-runtime" => Enabled::Enabled,
            "disabled" => Enabled::Disabled,
            "static" => Enabled::Static,
            "masked" | "masked-runtime" => Enabled::Masked,
            _ => Enabled::Other,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Enabled::Enabled => "enabled",
            Enabled::Disabled => "disabled",
            Enabled::Static => "static",
            Enabled::Masked => "masked",
            Enabled::Other => "other",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    /// Der volle Name, etwa `cron.service`.
    pub unit: String,
    pub description: String,
    pub active: Active,
    /// Der feinere Zustand von systemd, etwa `running`, `exited`, `dead`.
    pub sub: String,
    pub enabled: Enabled,
}

/// Liest die Ausgabe von [`LIST`]. `None`: Der Server gibt die Liste nicht her.
pub fn parse(text: &str) -> Option<Vec<Service>> {
    let parts = sections(text);
    let units = parts.get("units")?;
    let files: BTreeMap<&str, Enabled> = parts
        .get("files")
        .into_iter()
        .flatten()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            Some((words.next()?, Enabled::read(words.next()?)))
        })
        .collect();

    let mut services: BTreeMap<String, Service> = BTreeMap::new();
    for line in units {
        // Manche Fassungen stellen einem fehlgeschlagenen Dienst trotz `--plain` einen Punkt voran.
        let line = line.trim_start().trim_start_matches(['●', '*', '○', '×']).trim_start();
        let mut words = line.split_whitespace();
        let (Some(unit), Some(load), Some(active), Some(sub)) = (words.next(), words.next(), words.next(), words.next()) else { continue };
        // Was andere Dienste nur nennen, ohne dass es das gibt, lässt sich weder ansehen noch steuern.
        if !valid_unit(unit) || load == "not-found" {
            continue;
        }
        let description = words.collect::<Vec<_>>().join(" ");
        let enabled = if load == "masked" { Enabled::Masked } else { files.get(unit).copied().unwrap_or(Enabled::Other) };
        services.insert(unit.to_string(), Service { unit: unit.to_string(), description, active: Active::read(active), sub: sub.to_string(), enabled });
    }
    // Dienste, die es gibt, die systemd aber gerade nicht geladen hat. Vorlagen (`name@.service`) sind keine Dienste.
    for (unit, enabled) in &files {
        if valid_unit(unit) && !unit.contains("@.") && !services.contains_key(*unit) {
            services.insert(unit.to_string(), Service { unit: unit.to_string(), description: String::new(), active: Active::Inactive, sub: "dead".into(), enabled: *enabled });
        }
    }
    let mut list: Vec<Service> = services.into_values().take(MAX_SERVICES).collect();
    list.sort_by_cached_key(|service| (service.active.rank(), service.unit.to_lowercase()));
    Some(list)
}

/// Ein Name, wie systemd ihn für einen Dienst vergibt: Buchstaben, Ziffern und `:-_.\@`, am Ende `.service`.
pub fn valid_unit(unit: &str) -> bool {
    let Some(stem) = unit.strip_suffix(".service") else { return false };
    !stem.is_empty() && unit.len() <= 256 && !unit.starts_with('-') && unit.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b':' | b'-' | b'_' | b'.' | b'\\' | b'@'))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Start,
    Stop,
    Restart,
    Enable,
    Disable,
}

impl Action {
    fn verb(self) -> &'static str {
        match self {
            Action::Start => "start",
            Action::Stop => "stop",
            Action::Restart => "restart",
            Action::Enable => "enable",
            Action::Disable => "disable",
        }
    }

    /// Der Befehl für einen Dienst. `None`: Das ist kein Name eines Dienstes.
    pub fn command(self, unit: &str, how: As) -> Option<String> {
        valid_unit(unit).then(|| with_argument(&format!("{}systemctl {} \"$1\"", how.prefix(), self.verb()), unit))
    }

    /// Derselbe Befehl, wie ihn ein Mensch tippt (für [`super::typed`]).
    pub fn typed(self, unit: &str) -> Option<String> {
        valid_unit(unit).then(|| format!("systemctl {} {}", self.verb(), quoted(unit)))
    }
}

/// Zustand und letzte Meldungen eines Dienstes als Text. Endet bei einem Dienst, der nicht läuft, mit dem Wert 3;
/// das ist kein Fehler.
pub fn status_command(unit: &str, how: As) -> Option<String> {
    valid_unit(unit).then(|| with_argument(&format!("{}systemctl status --no-pager --full --lines=30 \"$1\"", how.prefix()), unit))
}

/// Was in einen neuen Tab getippt wird, damit dort das Journal des Dienstes mitläuft.
pub fn journal_line(unit: &str, sudo: bool) -> Option<String> {
    valid_unit(unit).then(|| format!("{}journalctl -n 100 -f -u {}", if sudo { "sudo " } else { "" }, quoted(unit)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Aufgezeichnet am Ubuntu 26.04 im WSL (systemd 259), gekürzt; dazu ein fehlgeschlagener Dienst und einer mit
    /// umschriebenem Bindestrich im Namen.
    const SAMPLE: &str = "\
@units
apparmor.service                            loaded    inactive dead    Load AppArmor profiles
chrony.service                              loaded    active   running chrony, an NTP client/server
connman.service                             not-found inactive dead    connman.service
console-getty.service                       masked    inactive dead    console-getty.service
console-setup.service                       loaded    active   exited  Set console font and keymap
cron.service                                loaded    active   running Regular background program processing daemon
● kaputt.service                            loaded    failed   failed  Etwas, das nicht startet
systemd-fsck@dev-disk-by\\x2duuid-12ab.service loaded  active   exited  File System Check on /dev/disk/by-uuid/12ab
user@1000.service                           loaded    activating start User Manager for UID 1000
@files
apparmor.service                             enabled         enabled
apport-forward@.service                      static          -
apt-news.service                             static          -
chrony.service                               enabled         enabled
console-getty.service                        masked          disabled
console-setup.service                        enabled         enabled
cron.service                                 enabled         enabled
kaputt.service                               disabled        enabled
rsync.service                                disabled        enabled
systemd-fsck@.service                        static          -
user@.service                                static          -
";

    #[test]
    fn units_and_their_files_become_one_list() {
        let list = parse(SAMPLE).unwrap();
        let brief: Vec<(&str, Active, &str, Enabled)> = list.iter().map(|s| (s.unit.as_str(), s.active, s.sub.as_str(), s.enabled)).collect();
        assert_eq!(
            brief,
            [
                // Fehlgeschlagenes zuerst, dann was gerade startet, dann was läuft, dann der Rest; jeweils nach Namen.
                ("kaputt.service", Active::Failed, "failed", Enabled::Disabled),
                ("user@1000.service", Active::Activating, "start", Enabled::Other),
                ("chrony.service", Active::Active, "running", Enabled::Enabled),
                ("console-setup.service", Active::Active, "exited", Enabled::Enabled),
                ("cron.service", Active::Active, "running", Enabled::Enabled),
                ("systemd-fsck@dev-disk-by\\x2duuid-12ab.service", Active::Active, "exited", Enabled::Other),
                ("apparmor.service", Active::Inactive, "dead", Enabled::Enabled),
                // Nur als Datei bekannt, nicht geladen.
                ("apt-news.service", Active::Inactive, "dead", Enabled::Static),
                ("console-getty.service", Active::Inactive, "dead", Enabled::Masked),
                ("rsync.service", Active::Inactive, "dead", Enabled::Disabled),
            ],
            "ohne den Dienst, den es nicht gibt, und ohne Vorlagen"
        );
        assert_eq!(list[2].description, "chrony, an NTP client/server");
        assert_eq!(list[0].description, "Etwas, das nicht startet", "der Punkt davor gehört nicht zum Namen");
    }

    #[test]
    fn a_server_without_the_list_says_so() {
        assert_eq!(parse(""), None);
        assert_eq!(parse("sh: 1: systemctl: not found"), None);
        assert_eq!(parse("@units\n@files\n"), Some(vec![]));
    }

    #[test]
    fn commands_take_only_what_looks_like_a_unit() {
        for good in ["cron.service", "user@1000.service", "systemd-fsck@dev-disk-by\\x2duuid-12ab.service", "a.b_c:d.service"] {
            assert!(valid_unit(good), "{good}");
        }
        for bad in ["", ".service", "cron", "cron.timer", "cron.service; reboot", "$(reboot).service", "a b.service", "-rf.service", "ä.service", "a'b.service", "a\"b.service", &format!("{}.service", "a".repeat(250))] {
            assert!(!valid_unit(bad), "{bad}");
            assert_eq!((Action::Stop.command(bad, As::User), Action::Stop.typed(bad), status_command(bad, As::User), journal_line(bad, false)), (None, None, None, None), "{bad}");
        }
        assert_eq!(Action::Restart.command("cron.service", As::User).unwrap(), "sh -c 'exec 2>&1; export LC_ALL=C; systemctl restart \"$1\"' sh 'cron.service'");
        assert_eq!(Action::Disable.command("cron.service", As::Sudo).unwrap(), "sh -c 'exec 2>&1; export LC_ALL=C; sudo -n -- systemctl disable \"$1\"' sh 'cron.service'");
        assert_eq!(Action::Enable.typed("user@1000.service").unwrap(), "systemctl enable 'user@1000.service'");
        assert_eq!(status_command("cron.service", As::Sudo).unwrap(), "sh -c 'exec 2>&1; export LC_ALL=C; sudo -n -- systemctl status --no-pager --full --lines=30 \"$1\"' sh 'cron.service'");
        assert_eq!(journal_line("cron.service", true).unwrap(), "sudo journalctl -n 100 -f -u 'cron.service'");
        assert_eq!(LIST.matches('\'').count(), 2);
    }
}

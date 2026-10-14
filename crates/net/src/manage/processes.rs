//! Prozesse: auflisten und beenden.
//!
//! Die Auslastung eines Prozesses ergibt sich erst aus zwei Messungen: `ps` nennt nur den Schnitt über seine ganze
//! Laufzeit. Deshalb liefert jede Messung die verbrauchte Rechenzeit in Ticks und die Uhr des Servers; das Rechnen
//! zwischen zwei Messungen überlässt dieses Modul dem Aufrufer (siehe [`cpu_between`]).

use std::collections::HashMap;

use super::{sections, with_argument, As};

/// Der Befehl für die Liste. Lesen darf das jeder Benutzer.
pub const LIST: &str = concat!(
    "sh -c '",
    "exec 2>/dev/null; export LC_ALL=C; ",
    "echo @clock; getconf CLK_TCK; cat /proc/uptime; ",
    "echo @mem; grep MemTotal: /proc/meminfo; ",
    "echo @ps; ps -eo pid=,ppid=,user:32=,rss=,etimes=,args=; ",
    "echo @stat; cat /proc/[0-9]*/stat",
    "'"
);

/// Mehr Prozesse liest die Liste nicht.
const MAX_PROCESSES: usize = 5000;
/// So viel vom Befehl eines Prozesses bleibt.
const MAX_COMMAND: usize = 400;

#[derive(Debug, Clone, PartialEq)]
pub struct Process {
    pub pid: u32,
    pub parent: u32,
    pub user: String,
    /// Kurzer Name: das Programm ohne Pfad und Argumente.
    pub name: String,
    /// Der ganze Befehl mit Argumenten.
    pub command: String,
    /// Arbeitsspeicher in Bytes.
    pub memory: u64,
    /// Sekunden, die er läuft.
    pub elapsed: u64,
    /// Verbrauchte Rechenzeit seit seinem Start, in Ticks (siehe [`Sample::ticks_per_second`]).
    pub ticks: u64,
    /// Ein Faden des Kerns, kein Programm.
    pub kernel: bool,
}

/// Eine Messung.
#[derive(Debug, Clone, PartialEq)]
pub struct Sample {
    pub ticks_per_second: u32,
    /// Sekunden seit dem Start des Servers: die Uhr für den Abstand zweier Messungen.
    pub uptime: f64,
    /// Arbeitsspeicher des Servers in Bytes.
    pub memory_total: u64,
    pub processes: Vec<Process>,
}

/// Liest die Ausgabe von [`LIST`]. `None`: Der Server gibt die Liste nicht her.
pub fn parse(text: &str) -> Option<Sample> {
    let parts = sections(text);
    let clock = parts.get("clock")?;
    let ticks_per_second = clock.first()?.trim().parse::<u32>().ok().filter(|ticks| *ticks > 0)?;
    let uptime = clock.get(1)?.split_whitespace().next()?.parse::<f64>().ok()?;
    let memory_total = parts.get("mem").and_then(|lines| lines.first()).and_then(|line| line.split_whitespace().nth(1)).and_then(|kb| kb.parse::<u64>().ok()).unwrap_or(0) * 1024;
    let ticks: HashMap<u32, u64> = parts.get("stat").into_iter().flatten().filter_map(|line| used(line)).collect();

    let mut processes = Vec::new();
    for line in parts.get("ps")?.iter().take(MAX_PROCESSES) {
        let mut rest = line.trim_start();
        let mut word = || {
            let end = rest.find(char::is_whitespace)?;
            let (word, tail) = rest.split_at(end);
            rest = tail.trim_start();
            Some(word)
        };
        let (Some(pid), Some(parent), Some(user), Some(rss), Some(elapsed)) = (word(), word(), word(), word(), word()) else { continue };
        let (Ok(pid), Ok(parent), Ok(rss), Ok(elapsed)) = (pid.parse::<u32>(), parent.parse::<u32>(), rss.parse::<u64>(), elapsed.parse::<u64>()) else { continue };
        let command = rest.trim_end();
        if command.is_empty() {
            continue;
        }
        // Fäden des Kerns stehen in eckigen Klammern und haben keinen eigenen Speicher.
        let kernel = command.starts_with('[') && command.ends_with(']') && rss == 0;
        processes.push(Process {
            pid,
            parent,
            user: user.to_string(),
            name: name_of(command),
            command: command.chars().take(MAX_COMMAND).collect(),
            memory: rss * 1024,
            elapsed,
            ticks: ticks.get(&pid).copied().unwrap_or(0),
            kernel,
        });
    }
    Some(Sample { ticks_per_second, uptime, memory_total, processes })
}

/// Aus einer Zeile von `/proc/<pid>/stat`: die Nummer und die verbrauchte Rechenzeit (im Programm und im Kern).
/// Der Name in Klammern kann selbst Klammern und Leerzeichen enthalten; gezählt wird deshalb ab der letzten.
fn used(line: &str) -> Option<(u32, u64)> {
    let pid = line.split_whitespace().next()?.parse().ok()?;
    let mut fields = line[line.rfind(')')? + 1..].split_whitespace();
    // Nach dem Namen: Zustand, dann zehn Felder bis `utime`, direkt dahinter `stime`.
    let user: u64 = fields.nth(11)?.parse().ok()?;
    let system: u64 = fields.next()?.parse().ok()?;
    Some((pid, user + system))
}

/// Der kurze Name eines Befehls: `/usr/sbin/nginx -g daemon off;` → `nginx`, `[kworker/0:1]` → `kworker/0:1`.
fn name_of(command: &str) -> String {
    if let Some(thread) = command.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')) {
        return thread.to_string();
    }
    let first = command.split_whitespace().next().unwrap_or(command);
    // Manche Dienste nennen sich selbst, etwa `sshd: alex [priv]` oder `nginx: worker process`.
    let first = first.trim_end_matches(':');
    first.rsplit('/').next().filter(|name| !name.is_empty()).unwrap_or(first).to_string()
}

/// Auslastung eines Prozesses zwischen zwei Messungen in Prozent eines Kerns (wie bei `top`: 200 heißt zwei Kerne
/// voll). `None`: Den Prozess gab es vorher nicht, oder zwischen den Messungen lag keine Zeit.
pub fn cpu_between(before: &Sample, after: &Sample, pid: u32) -> Option<f64> {
    let seconds = after.uptime - before.uptime;
    let old = before.processes.iter().find(|p| p.pid == pid)?;
    let new = after.processes.iter().find(|p| p.pid == pid)?;
    // Dieselbe Nummer, aber kürzere Laufzeit: Das ist ein neuer Prozess.
    if seconds <= 0.0 || new.elapsed < old.elapsed || new.ticks < old.ticks {
        return None;
    }
    Some((new.ticks - old.ticks) as f64 / f64::from(after.ticks_per_second) / seconds * 100.0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    /// Bittet den Prozess, sich zu beenden.
    Term,
    /// Beendet ihn sofort, ohne dass er aufräumen kann.
    Kill,
}

impl Signal {
    fn name(self) -> &'static str {
        match self {
            Signal::Term => "TERM",
            Signal::Kill => "KILL",
        }
    }

    /// Der Befehl für einen Prozess. `None`: Diese Nummer beendet Glowport nicht (0 und 1: alles oder das System).
    pub fn command(self, pid: u32, how: As) -> Option<String> {
        (pid > 1).then(|| with_argument(&format!("{}kill -{} \"$1\"", how.prefix(), self.name()), &pid.to_string()))
    }

    /// Derselbe Befehl, wie ihn ein Mensch tippt (für [`super::typed`]).
    pub fn typed(self, pid: u32) -> Option<String> {
        (pid > 1).then(|| format!("kill -{} {pid}", self.name()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Aufgezeichnet am Ubuntu 26.04 im WSL (procps), gekürzt; dazu ein Faden des Kerns und Befehle mit
    /// Leerzeichen und Doppelpunkt.
    const SAMPLE: &str = "\
@clock
100
1000.50 80.60
@mem
MemTotal:       16166952 kB
@ps
      1       0 root                             15272     900 /sbin/init
      2       0 root                                 0     900 [kthreadd]
     49       1 root                             16224     898 /usr/lib/systemd/systemd-journald
     72       1 systemd-resolve                  14168     897 /usr/lib/systemd/systemd-resolved
    109      95 root                              6284     897 (udev-worker)
    300       1 www-data                        204800     120 nginx: worker process
    301       1 alex                              9000      60 /usr/bin/python3 /opt/bot/main.py --name \"Mein Bot\"
 kaputt
    999       1 root
@stat
1 (systemd) S 0 1 1 0 -1 4194560 5535 77662 138 944 24 47 56 67 20 0 1 0 114 24903680 3597 18446744073709551615 1 1 0 0 0 0 671173123 4096 1260 0 0 0 17 3 0 0 0 0 0 0 0 0 0 0 0 0 0
2 (kthreadd) S 0 0 0 0 -1 2129984 0 0 0 0 0 3 0 0 20 0 1 0 0 0 0 18446744073709551615 0 0 0 0 0 0 0 2147483647 0 0 0 0 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0
109 ((udev-worker)) S 95 95 95 0 -1 4194624 137 0 0 0 0 0 0 0 20 0 1 0 185 34422784 1447 18446744073709551615 1 1 0 0 0 0 81923 4096 0 0 0 0 17 16 0 0 0 0 0 0 0 0 0 0 0 0 0
300 (nginx) R 1 300 300 0 -1 4194624 137 0 0 0 5000 1000 0 0 20 0 1 0 185 34422784 1447 18446744073709551615 1 1 0 0 0 0 81923 4096 0 0 0 0 17 16 0 0 0 0 0 0 0 0 0 0 0 0 0
301 (Mein Bot) S) x) S 1 301 301 0 -1 4194624 137 0 0 0 250 50 0 0 20 0 4 0 185 34422784 1447 18446744073709551615 1 1 0 0 0 0 81923 4096 0 0 0 0 17 16 0 0 0 0 0 0 0 0 0 0 0 0 0
unlesbar
";

    #[test]
    fn processes_come_with_memory_runtime_and_used_time() {
        let sample = parse(SAMPLE).unwrap();
        assert_eq!((sample.ticks_per_second, sample.uptime, sample.memory_total), (100, 1000.5, 16_166_952 * 1024));
        let brief: Vec<(u32, &str, &str, u64, u64, bool)> = sample.processes.iter().map(|p| (p.pid, p.user.as_str(), p.name.as_str(), p.ticks, p.elapsed, p.kernel)).collect();
        assert_eq!(
            brief,
            [
                (1, "root", "init", 71, 900, false),
                (2, "root", "kthreadd", 3, 900, true),
                (49, "root", "systemd-journald", 0, 898, false),
                (72, "systemd-resolve", "systemd-resolved", 0, 897, false),
                (109, "root", "(udev-worker)", 0, 897, false),
                (300, "www-data", "nginx", 6000, 120, false),
                // Der Name im Kern enthält Klammern und Leerzeichen; gezählt wird ab der letzten Klammer.
                (301, "alex", "python3", 300, 60, false),
            ],
            "unlesbare Zeilen fallen weg"
        );
        let bot = &sample.processes[6];
        assert_eq!((bot.parent, bot.memory, bot.command.as_str()), (1, 9000 * 1024, "/usr/bin/python3 /opt/bot/main.py --name \"Mein Bot\""));
    }

    #[test]
    fn load_is_what_happened_between_two_samples() {
        let before = parse(SAMPLE).unwrap();
        // Fünf Sekunden später: nginx hat 250 Ticks mehr verbraucht (2,5 Sekunden Rechenzeit), der Bot 1000 (zwei Kerne voll).
        let later = SAMPLE.replace("1000.50 80.60", "1005.50 80.60").replace("5000 1000 0 0 20", "5200 1050 0 0 20").replace("250 50 0 0 20 0 4", "1050 250 0 0 20 0 4").replace("     120 nginx", "     125 nginx").replace("      60 /usr/bin/python3", "      65 /usr/bin/python3");
        let after = parse(&later).unwrap();
        assert_eq!(cpu_between(&before, &after, 300), Some(50.0));
        assert_eq!(cpu_between(&before, &after, 301), Some(200.0));
        assert_eq!(cpu_between(&before, &after, 1), Some(0.0));
        assert_eq!(cpu_between(&before, &after, 4711), None, "den gab es nicht");
        assert_eq!(cpu_between(&before, &before, 300), None, "keine Zeit vergangen");
        // Dieselbe Nummer, neu vergeben: kürzere Laufzeit.
        let reused = parse(&later.replace("     125 nginx", "       2 nginx")).unwrap();
        assert_eq!(cpu_between(&before, &reused, 300), None);
    }

    #[test]
    fn a_server_without_the_list_says_so() {
        assert_eq!(parse(""), None);
        assert_eq!(parse("@clock\n@mem\n@ps\n@stat\n"), None);
        assert_eq!(parse("@clock\n0\n1.0 1.0\n@ps\n"), None, "ohne Takt lässt sich nichts rechnen");
        // BusyBox: Die Uhr gibt es, `ps` kennt die Spalten nicht.
        assert_eq!(parse("@clock\n100\n5.00 5.00\n@mem\n@ps\n@stat\n").map(|s| s.processes.len()), Some(0));
    }

    #[test]
    fn names_are_the_program_without_path_and_arguments() {
        for (command, name) in [("/usr/sbin/nginx -g daemon off;", "nginx"), ("[kworker/0:1-events]", "kworker/0:1-events"), ("sshd: alex [priv]", "sshd"), ("bash", "bash"), ("/", "/"), ("./run.sh --x", "run.sh")] {
            assert_eq!(name_of(command), name, "{command}");
        }
    }

    #[test]
    fn only_real_processes_can_be_ended() {
        assert_eq!(Signal::Term.command(4711, As::User).unwrap(), "sh -c 'exec 2>&1; export LC_ALL=C; kill -TERM \"$1\"' sh '4711'");
        assert_eq!(Signal::Kill.command(4711, As::Sudo).unwrap(), "sh -c 'exec 2>&1; export LC_ALL=C; sudo -n -- kill -KILL \"$1\"' sh '4711'");
        assert_eq!(Signal::Kill.typed(4711).unwrap(), "kill -KILL 4711");
        for pid in [0, 1] {
            assert_eq!((Signal::Term.command(pid, As::Sudo), Signal::Kill.typed(pid)), (None, None), "{pid}");
        }
        assert_eq!(LIST.matches('\'').count(), 2);
    }
}

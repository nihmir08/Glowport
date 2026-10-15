//! Docker: list, start, stop and restart containers; plus the commands for logs and shell in a tab.

use std::collections::HashMap;

use super::{sections, with_argument, As};

/// Columns of `docker ps`, separated by `|`: the character does not occur in ID, name and image.
const PS_FORMAT: &str = "{{.ID}}|{{.Names}}|{{.Image}}|{{.Ports}}";
/// State per container from `docker inspect`. The times are UTC in RFC 3339 format.
const INSPECT_FORMAT: &str = "{{.Id}}|{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}|{{.State.StartedAt}}|{{.State.FinishedAt}}|{{.State.ExitCode}}";
const STATS_FORMAT: &str = "{{.ID}}|{{.CPUPerc}}|{{.MemUsage}}";

/// The list shows no more containers than this.
const MAX_CONTAINERS: usize = 500;

/// The command for the list. If `docker ps` already fails, the message is in the `@error` section.
pub fn list_command(how: As) -> String {
    let docker = format!("{}docker", how.prefix());
    format!(
        concat!(
            "sh -c '",
            "export LC_ALL=C; ",
            "out=$({docker} ps -a --no-trunc --format \"{ps}\" 2>&1) || {{ echo @error; echo \"$out\"; exit 1; }}; ",
            "exec 2>/dev/null; ",
            "echo @now; date +%s; ",
            "echo @ps; echo \"$out\"; ",
            // Without containers, `inspect` without arguments would only give an error message.
            "echo @inspect; ids=$({docker} ps -aq --no-trunc); test -n \"$ids\" && {docker} inspect --format \"{inspect}\" $ids; ",
            "echo @stats; {docker} stats --no-stream --no-trunc --format \"{stats}\"",
            "'"
        ),
        docker = docker,
        ps = PS_FORMAT,
        inspect = INSPECT_FORMAT,
        stats = STATS_FORMAT,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Running,
    Paused,
    Restarting,
    Exited,
    Created,
    Dead,
    /// A state this version does not know, or none.
    Other,
}

impl State {
    fn read(text: &str) -> Self {
        match text {
            "running" => State::Running,
            "paused" => State::Paused,
            "restarting" => State::Restarting,
            "exited" => State::Exited,
            "created" => State::Created,
            "dead" => State::Dead,
            _ => State::Other,
        }
    }

    /// Short name for the interface.
    pub fn name(self) -> &'static str {
        match self {
            State::Running => "running",
            State::Paused => "paused",
            State::Restarting => "restarting",
            State::Exited => "exited",
            State::Created => "created",
            State::Dead => "dead",
            State::Other => "other",
        }
    }

    /// Order in the list: what runs is at the top.
    fn rank(self) -> u8 {
        match self {
            State::Running => 0,
            State::Restarting => 1,
            State::Paused => 2,
            _ => 3,
        }
    }
}

/// Result of a container's health check, if it has one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    Healthy,
    Unhealthy,
    Starting,
}

impl Health {
    pub fn name(self) -> &'static str {
        match self {
            Health::Healthy => "healthy",
            Health::Unhealthy => "unhealthy",
            Health::Starting => "starting",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Container {
    /// The full ID (64 characters); only it goes into commands.
    pub id: String,
    pub name: String,
    pub image: String,
    pub state: State,
    pub health: Option<Health>,
    /// Published ports, e.g. `8080->80/tcp`, once per pair.
    pub ports: Vec<String>,
    /// Seconds it has been running; for an exited one the seconds since it ended.
    pub since: Option<u64>,
    /// Exit code; only for an exited one.
    pub exit_code: Option<i32>,
    /// Load in percent of one core; only for running ones.
    pub cpu: Option<f32>,
    /// Memory in bytes: used and limit.
    pub memory: Option<(u64, u64)>,
}

/// What the list resulted in.
#[derive(Debug, Clone, PartialEq)]
pub enum Listing {
    Containers(Vec<Container>),
    /// Docker refused; the text is its message (see [`super::verdict`]).
    Refused(String),
}

/// Reads the output of [`list_command`].
pub fn parse(text: &str) -> Listing {
    let parts = sections(text);
    if let Some(error) = parts.get("error") {
        return Listing::Refused(error.join("\n"));
    }
    let now = parts.get("now").and_then(|lines| lines.first()).and_then(|line| line.trim().parse::<i64>().ok());
    let states: HashMap<&str, Vec<&str>> = rows(&parts, "inspect", 6);
    let stats: HashMap<&str, Vec<&str>> = rows(&parts, "stats", 3);

    let mut containers = Vec::new();
    for line in parts.get("ps").into_iter().flatten().take(MAX_CONTAINERS) {
        let fields: Vec<&str> = line.splitn(4, '|').collect();
        let [id, names, image, ports] = fields[..] else { continue };
        if !valid_id(id) {
            continue;
        }
        let state_row = states.get(id);
        let state = state_row.map_or(State::Other, |row| State::read(row[1]));
        let health = state_row.and_then(|row| match row[2] {
            "healthy" => Some(Health::Healthy),
            "unhealthy" => Some(Health::Unhealthy),
            "starting" => Some(Health::Starting),
            _ => None,
        });
        let running = matches!(state, State::Running | State::Paused | State::Restarting);
        // A running one counts from its start, an exited one from its end. The clock is the server's.
        let moment = state_row.and_then(|row| timestamp(row[if running { 3 } else { 4 }]));
        let since = now.zip(moment).map(|(now, moment)| (now - moment).max(0) as u64);
        let usage = stats.get(id).filter(|_| running);
        containers.push(Container {
            id: id.to_string(),
            // Several names (old-style links) appear one after another with commas; the first is its own.
            name: names.split(',').next().unwrap_or_default().trim().trim_start_matches('/').to_string(),
            image: image.to_string(),
            state,
            health,
            ports: published(ports),
            since,
            exit_code: state_row.filter(|_| !running && state != State::Created).and_then(|row| row[5].trim().parse().ok()),
            cpu: usage.and_then(|row| row[1].trim().trim_end_matches('%').parse().ok()),
            memory: usage.and_then(|row| row[2].split_once('/')).and_then(|(used, limit)| size(used).zip(size(limit))),
        });
    }
    containers.sort_by_cached_key(|container| (container.state.rank(), container.name.to_lowercase(), container.id.clone()));
    Listing::Containers(containers)
}

/// The lines of a section with exactly `columns` columns, keyed by their first column (the ID).
fn rows<'a>(parts: &HashMap<&'a str, Vec<&'a str>>, name: &str, columns: usize) -> HashMap<&'a str, Vec<&'a str>> {
    parts.get(name).into_iter().flatten().map(|line| line.split('|').collect::<Vec<_>>()).filter(|row| row.len() == columns).map(|row| (row[0], row)).collect()
}

/// `0.0.0.0:8080->80/tcp, :::8080->80/tcp, 443/tcp` becomes `8080->80/tcp`: only what is published, without the
/// address in front, once per pair.
fn published(ports: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for entry in ports.split(',').map(str::trim) {
        let Some((outside, inside)) = entry.split_once("->") else { continue };
        let port = outside.rsplit(':').next().unwrap_or(outside);
        let pair = format!("{port}->{inside}");
        if !out.contains(&pair) {
            out.push(pair);
        }
    }
    out
}

/// A size like `12.5MiB` or `1.2GB` in bytes.
fn size(text: &str) -> Option<u64> {
    let text = text.trim();
    let split = text.find(|c: char| !(c.is_ascii_digit() || c == '.'))?;
    let number: f64 = text[..split].parse().ok()?;
    let factor: f64 = match &text[split..] {
        "B" => 1.0,
        "kB" | "KB" => 1e3,
        "MB" => 1e6,
        "GB" => 1e9,
        "TB" => 1e12,
        "KiB" => 1024.0,
        "MiB" => 1024.0 * 1024.0,
        "GiB" => 1024.0 * 1024.0 * 1024.0,
        "TiB" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        _ => return None,
    };
    Some((number * factor).round() as u64)
}

/// Seconds since 1970 from a time like `2026-10-11T20:52:44.123456789Z` or with `+02:00` at the end. The year 1
/// means “never” in Docker.
fn timestamp(text: &str) -> Option<i64> {
    let text = text.trim();
    let (date, rest) = text.split_once('T')?;
    let mut date = date.split('-').map(|part| part.parse::<i64>().ok());
    let (year, month, day) = (date.next()??, date.next()??, date.next()??);
    if year < 1970 || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // The zone starts at the first character that does not belong to the time of day.
    let zone_at = rest.find(['Z', '+', '-'])?;
    let (clock, zone) = rest.split_at(zone_at);
    let mut clock = clock.split(':');
    let (hour, minute) = (clock.next()?.parse::<i64>().ok()?, clock.next()?.parse::<i64>().ok()?);
    let second = clock.next()?.split('.').next()?.parse::<i64>().ok()?;
    let offset = match zone {
        "Z" => 0,
        zone => {
            let (hours, minutes) = zone[1..].split_once(':')?;
            let seconds = hours.parse::<i64>().ok()? * 3600 + minutes.parse::<i64>().ok()? * 60;
            if zone.starts_with('-') {
                -seconds
            } else {
                seconds
            }
        }
    };
    // Days since 1970 by the civil calendar.
    let (y, m) = if month <= 2 { (year - 1, month + 9) } else { (year, month - 3) };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * m + 2) / 5 + day - 1;
    let days = era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468;
    Some(days * 86_400 + hour * 3600 + minute * 60 + second - offset)
}

/// An ID as Docker assigns it: 12 to 64 characters from `0-9a-f`.
pub fn valid_id(id: &str) -> bool {
    (12..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Start,
    Stop,
    Restart,
}

impl Action {
    fn verb(self) -> &'static str {
        match self {
            Action::Start => "start",
            Action::Stop => "stop",
            Action::Restart => "restart",
        }
    }

    /// The command for a container. `None`: that is not an ID.
    pub fn command(self, id: &str, how: As) -> Option<String> {
        valid_id(id).then(|| with_argument(&format!("{}docker {} \"$1\"", how.prefix(), self.verb()), id))
    }

    /// The same command as a human would type it (for [`super::typed`]).
    pub fn typed(self, id: &str) -> Option<String> {
        valid_id(id).then(|| format!("docker {} {}", self.verb(), short(id)))
    }
}

/// The short form of an ID, as Docker shows it.
fn short(id: &str) -> &str {
    &id[..id.len().min(12)]
}

/// What is typed into a new tab so the logs follow along there. `sudo`: the list only worked with sudo.
pub fn logs_line(id: &str, sudo: bool) -> Option<String> {
    valid_id(id).then(|| format!("{}docker logs --tail 200 -f {}", if sudo { "sudo " } else { "" }, short(id)))
}

/// What is typed into a new tab so a shell inside the container opens there: `bash` where it exists.
pub fn shell_line(id: &str, sudo: bool) -> Option<String> {
    valid_id(id).then(|| format!("{}docker exec -it {} sh -c 'command -v bash >/dev/null 2>&1 && exec bash || exec sh'", if sudo { "sudo " } else { "" }, short(id)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const WEB: &str = "4c01db0b339c4c01db0b339c4c01db0b339c4c01db0b339c4c01db0b339c4c01";
    const DB: &str = "aa11bb22cc33aa11bb22cc33aa11bb22cc33aa11bb22cc33aa11bb22cc33aa11";
    const OLD: &str = "0123456789ab0123456789ab0123456789ab0123456789ab0123456789ab0123";
    const NEW: &str = "ffeeddccbbaaffeeddccbbaaffeeddccbbaaffeeddccbbaaffeeddccbbaaffee";

    /// This is what the output of [`list_command`] looks like (assembled from Docker's documentation, not
    /// recorded on a server).
    fn sample() -> String {
        format!(
            "@now\n1791752000\n@ps\n\
             {WEB}|web|nginx:1.27|0.0.0.0:8080->80/tcp, :::8080->80/tcp, 0.0.0.0:8443->443/tcp, 9000/tcp\n\
             {DB}|db|postgres:17|5432/tcp\n\
             {OLD}|/alt,/web/alt|registry.example.com:5000/team/job@sha256:abc|\n\
             {NEW}|Neu|alpine|\n\
             kaputte zeile\n\
             zukurz|x|y|z\n\
             @inspect\n\
             {WEB}|running|healthy|2026-10-11T20:52:44.123456789Z|0001-01-01T00:00:00Z|0\n\
             {DB}|running||2026-10-11T22:53:20+02:00|0001-01-01T00:00:00Z|0\n\
             {OLD}|exited||2026-10-01T08:00:00Z|2026-10-11T20:53:20.5Z|137\n\
             {NEW}|created||0001-01-01T00:00:00Z|0001-01-01T00:00:00Z|0\n\
             @stats\n\
             {WEB}|0.07%|12.5MiB / 7.6GiB\n\
             {DB}|153.20%|1.2GB / 2GB\n\
             {OLD}|0.00%|0B / 0B\n"
        )
    }

    #[test]
    fn the_list_puts_together_what_three_commands_say() {
        let Listing::Containers(list) = parse(&sample()) else { panic!("abgelehnt") };
        assert_eq!(list.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(), ["db", "web", "alt", "Neu"], "running ones first, then by name");

        let web = &list[1];
        assert_eq!((web.id.as_str(), web.image.as_str(), web.state, web.health), (WEB, "nginx:1.27", State::Running, Some(Health::Healthy)));
        assert_eq!(web.ports, ["8080->80/tcp", "8443->443/tcp"], "without address, once per pair, only published ones");
        // 1791752000 is 2026-10-11 20:53:20 UTC: 36 seconds after the start.
        assert_eq!((web.since, web.exit_code, web.cpu, web.memory), (Some(36), None, Some(0.07), Some((13_107_200, 8_160_437_862))));

        let db = &list[0];
        assert_eq!((db.health, db.ports.len(), db.since, db.cpu, db.memory), (None, 0, Some(0), Some(153.2), Some((1_200_000_000, 2_000_000_000))), "time with zone, more than one core");

        let old = &list[2];
        assert_eq!((old.state, old.since, old.exit_code, old.cpu, old.memory), (State::Exited, Some(0), Some(137), None, None), "exited: since the end, no load");
        assert_eq!(old.image, "registry.example.com:5000/team/job@sha256:abc");

        let new = &list[3];
        assert_eq!((new.state, new.since, new.exit_code), (State::Created, None, None), "never started");
    }

    #[test]
    fn a_refusal_and_an_empty_host_are_told_apart() {
        let refused = "@error\npermission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock: Get \"http://%2Fvar%2Frun%2Fdocker.sock/v1.47/containers/json?all=1\": dial unix /var/run/docker.sock: connect: permission denied\n";
        let Listing::Refused(text) = parse(refused) else { panic!("not refused") };
        assert_eq!(super::super::verdict(false, &text, As::User), super::super::Verdict::NeedsRoot);
        assert_eq!(parse("@error\nsudo: a password is required\n"), Listing::Refused("sudo: a password is required".into()));
        // Docker runs but has no container.
        assert_eq!(parse("@now\n1791752000\n@ps\n\n@inspect\n@stats\n"), Listing::Containers(vec![]));
        assert_eq!(parse(""), Listing::Containers(vec![]));
        // Without the sections after it, what `ps` knows remains.
        let Listing::Containers(list) = parse(&format!("@ps\n{WEB}|web|nginx|\n")) else { panic!() };
        assert_eq!((list[0].state, list[0].since, list[0].cpu), (State::Other, None, None));
    }

    #[test]
    fn times_and_sizes_are_read_exactly() {
        assert_eq!(timestamp("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(timestamp("2026-10-11T20:52:44.123456789Z"), Some(1_791_751_964));
        assert_eq!(timestamp("2026-10-11T22:52:44+02:00"), Some(1_791_751_964));
        assert_eq!(timestamp("2026-10-11T15:22:44.5-05:30"), Some(1_791_751_964));
        assert_eq!(timestamp("2024-02-29T23:59:59Z"), Some(1_709_251_199));
        for never in ["0001-01-01T00:00:00Z", "", "gestern", "2026-13-01T00:00:00Z", "2026-10-11 20:52:44"] {
            assert_eq!(timestamp(never), None, "{never}");
        }
        assert_eq!((size("0B"), size("512B"), size("1.5kB"), size("12.5MiB"), size(" 7.6GiB ")), (Some(0), Some(512), Some(1500), Some(13_107_200), Some(8_160_437_862)));
        assert_eq!((size("lots"), size("12"), size("3 pieces")), (None, None, None));
    }

    #[test]
    fn commands_take_only_what_looks_like_an_id() {
        assert!(valid_id(WEB) && valid_id("4c01db0b339c"));
        for bad in ["", "web", "4c01db0b339", "4C01DB0B339C", "4c01db0b339c; rm -rf /", "$(reboot)aaaaaaaaaa", &"a".repeat(65)] {
            assert!(!valid_id(bad), "{bad}");
            assert_eq!((Action::Stop.command(bad, As::User), Action::Stop.typed(bad), logs_line(bad, false), shell_line(bad, false)), (None, None, None, None), "{bad}");
        }
        assert_eq!(Action::Restart.command(WEB, As::User).unwrap(), format!("sh -c 'exec 2>&1; export LC_ALL=C; docker restart \"$1\"' sh '{WEB}'"));
        assert_eq!(Action::Start.command(WEB, As::Sudo).unwrap(), format!("sh -c 'exec 2>&1; export LC_ALL=C; sudo -n -- docker start \"$1\"' sh '{WEB}'"));
        assert_eq!(Action::Stop.typed(WEB).unwrap(), "docker stop 4c01db0b339c");
        assert_eq!(logs_line(WEB, false).unwrap(), "docker logs --tail 200 -f 4c01db0b339c");
        assert_eq!(shell_line(WEB, true).unwrap(), "sudo docker exec -it 4c01db0b339c sh -c 'command -v bash >/dev/null 2>&1 && exec bash || exec sh'");
    }

    #[test]
    fn the_list_command_reports_a_refusal_in_its_own_section() {
        let plain = list_command(As::User);
        assert!(plain.starts_with("sh -c 'export LC_ALL=C; out=$(docker ps -a --no-trunc --format \"{{.ID}}|{{.Names}}|{{.Image}}|{{.Ports}}\" 2>&1) || { echo @error; echo \"$out\"; exit 1; }; "), "{plain}");
        assert!(plain.ends_with("echo @stats; docker stats --no-stream --no-trunc --format \"{{.ID}}|{{.CPUPerc}}|{{.MemUsage}}\"'"), "{plain}");
        // The script is in single quotes and contains none itself.
        assert_eq!(plain.matches('\'').count(), 2);
        let sudo = list_command(As::Sudo);
        assert_eq!(sudo.matches("sudo -n -- docker").count(), 4, "every Docker call with sudo");
        assert_eq!(sudo.matches('\'').count(), 2);
    }
}

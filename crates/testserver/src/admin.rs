//! A simulated Linux with Docker, systemd and procps: fixed answers to the commands Glowport uses to
//! manage a server (`glowport_net::manage`). This way the sidebar can be tested without any of them
//! running on the test machine.
//!
//! The signed-in user is never `root` here, but belongs to the `docker` group: they may control containers, not
//! services, and `sudo` wants a password. They may end their own processes, not others'.

use std::time::{Instant, SystemTime, UNIX_EPOCH};

struct Container {
    id: &'static str,
    name: &'static str,
    image: &'static str,
    ports: &'static str,
    running: bool,
    exit_code: i32,
    /// Since when it has been running or stopped.
    since: Instant,
}

struct Service {
    unit: &'static str,
    description: &'static str,
    active: &'static str,
    sub: &'static str,
    enabled: &'static str,
}

struct Process {
    pid: u32,
    parent: u32,
    user: &'static str,
    /// Memory in KiB.
    rss: u64,
    command: &'static str,
    /// CPU time used in ticks per second: 100 means one core fully used.
    load: f64,
}

pub struct Admin {
    started: Instant,
    containers: Vec<Container>,
    services: Vec<Service>,
    processes: Vec<Process>,
}

/// This is how long the simulated server has already been running when the test starts.
const BOOTED: u64 = 86_400;
/// The session's user.
const USER: &str = "e2e";

impl Default for Admin {
    fn default() -> Self {
        let now = Instant::now();
        let container = |id, name, image, ports, running, exit_code| Container { id, name, image, ports, running, exit_code, since: now };
        let service = |unit, description, active, sub, enabled| Service { unit, description, active, sub, enabled };
        let process = |pid, parent, user, rss, command, load| Process { pid, parent, user, rss, command, load };
        Self {
            started: now,
            containers: vec![
                container("1111111111111111111111111111111111111111111111111111111111111111", "e2e-web", "nginx:1.27", "0.0.0.0:8080->80/tcp, :::8080->80/tcp", true, 0),
                container("2222222222222222222222222222222222222222222222222222222222222222", "e2e-db", "postgres:17", "5432/tcp", true, 0),
                container("3333333333333333333333333333333333333333333333333333333333333333", "e2e-job", "alpine:3", "", false, 1),
            ],
            services: vec![
                service("e2e-backup.service", "Nightly backup", "failed", "failed", "static"),
                service("e2e-idle.service", "Something that is switched off", "inactive", "dead", "disabled"),
                service("e2e-web.service", "The web server of the test", "active", "running", "enabled"),
                service("ssh.service", "OpenBSD Secure Shell server", "active", "running", "enabled"),
            ],
            processes: vec![
                process(1, 0, "root", 9_000, "/sbin/init", 0.0),
                process(2, 0, "root", 0, "[kthreadd]", 0.0),
                process(300, 1, "root", 20_000, "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups", 1.0),
                process(4711, 300, USER, 30_000, "/usr/bin/python3 /opt/e2e/busy.py --workers 4", 50.0),
                process(4712, 300, USER, 5_000, "sleep 600", 0.0),
            ],
        }
    }
}

/// Seconds since 1970 as `2026-10-11T20:52:44Z`.
fn rfc3339(seconds: u64) -> String {
    let (days, rest) = ((seconds / 86_400) as i64, seconds % 86_400);
    let z = days + 719_468;
    let (era, doe) = (z.div_euclid(146_097), z.rem_euclid(146_097));
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let (day, month) = (doy - (153 * mp + 2) / 5 + 1, if mp < 10 { mp + 3 } else { mp - 9 });
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z", rest / 3600, rest / 60 % 60, rest % 60)
}

/// Reads verb and value from a command of the form `… program verb "$1"' sh 'value'`.
fn action<'a>(command: &'a str, program: &str) -> Option<(&'a str, &'a str)> {
    let after = command.split_once(&format!("{program} "))?.1;
    let verb = after.split(' ').next()?;
    // Switches can stand between verb and value, e.g. with `systemctl status`.
    let value = after.split_once("\"$1\"' sh '")?.1.strip_suffix('\'')?;
    Some((verb, value))
}

impl Admin {
    /// The answer to a command: output and exit value. `None`: this is not a management command.
    pub fn answer(&mut self, command: &str) -> Option<(String, u32)> {
        let sudo = command.contains("sudo -n -- ");
        let password = || Some(("sudo: a password is required\n".to_string(), 1));
        if command.contains("echo @sudo") {
            return Some((format!("@uid\n1000\n@docker\n/usr/bin/docker\n@systemd\n/usr/bin/systemctl\n@ps\n      1   {BOOTED} root\n@sudo\n"), 0));
        }
        if command.contains("docker ps -a --no-trunc") {
            return Some((self.containers(), 0));
        }
        if command.contains("systemctl list-units") {
            return Some((self.services(), 0));
        }
        if command.contains("/proc/[0-9]*/stat") {
            return Some((self.processes(), 0));
        }
        if let Some((verb, id)) = action(command, "docker") {
            let Some(container) = self.containers.iter_mut().find(|c| c.id == id) else { return Some((format!("Error response from daemon: No such container: {id}\n"), 1)) };
            (container.running, container.exit_code, container.since) = (verb != "stop", 0, Instant::now());
            return Some((format!("{id}\n"), 0));
        }
        if let Some((verb, unit)) = action(command, "systemctl") {
            if verb == "status" {
                let Some(service) = self.services.iter().find(|s| s.unit == unit) else { return Some((format!("Unit {unit} could not be found.\n"), 4)) };
                let text = format!("* {unit} - {}\n     Loaded: loaded (/usr/lib/systemd/system/{unit}; {})\n     Active: {} ({})\n\nOct 12 09:41:12 e2e systemd[1]: {} {unit}.\n", service.description, service.enabled, service.active, service.sub, if service.active == "active" { "Started" } else { "Stopped" });
                return Some((text, if service.active == "active" { 0 } else { 3 }));
            }
            // Only root controls services, and sudo wants a password here.
            return if sudo { password() } else { Some((format!("Failed to {verb} {unit}: Interactive authentication required.\nSee system logs and 'systemctl status {unit}' for details.\n"), 1)) };
        }
        if let Some((_, pid)) = action(command, "kill") {
            let pid: u32 = pid.parse().ok()?;
            return match self.processes.iter().position(|p| p.pid == pid) {
                None => Some(("sh: 1: kill: No such process\n".to_string(), 1)),
                Some(_) if sudo => password(),
                Some(at) if self.processes[at].user == USER => {
                    self.processes.remove(at);
                    Some((String::new(), 0))
                }
                Some(_) => Some((format!("sh: 1: kill: ({pid}) - Operation not permitted\n"), 1)),
            };
        }
        None
    }

    fn containers(&self) -> String {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |since| since.as_secs());
        let mut out = format!("@now\n{now}\n@ps\n");
        for c in &self.containers {
            out.push_str(&format!("{}|{}|{}|{}\n", c.id, c.name, c.image, c.ports));
        }
        out.push_str("@inspect\n");
        for c in &self.containers {
            // When the test starts, the containers have been running for an hour; what it triggers itself counts from then on.
            let ago = if c.since == self.started { 3600 } else { c.since.elapsed().as_secs() };
            let (moment, never) = (rfc3339(now.saturating_sub(ago)), "0001-01-01T00:00:00Z");
            let (state, started, finished) = if c.running { ("running", moment.as_str(), never) } else { ("exited", never, moment.as_str()) };
            out.push_str(&format!("{}|{state}||{started}|{finished}|{}\n", c.id, c.exit_code));
        }
        out.push_str("@stats\n");
        for c in self.containers.iter().filter(|c| c.running) {
            out.push_str(&format!("{}|2.50%|64MiB / 2GiB\n", c.id));
        }
        out
    }

    fn services(&self) -> String {
        let mut out = String::from("@units\n");
        for s in &self.services {
            out.push_str(&format!("{:<40} loaded    {:<8} {:<7} {}\n", s.unit, s.active, s.sub, s.description));
        }
        out.push_str("@files\n");
        for s in &self.services {
            out.push_str(&format!("{:<40} {:<15} enabled\n", s.unit, s.enabled));
        }
        out
    }

    fn processes(&self) -> String {
        let seconds = self.started.elapsed().as_secs_f64();
        let uptime = BOOTED as f64 + seconds;
        let mut out = format!("@clock\n100\n{uptime:.2} 1.00\n@mem\nMemTotal:        4194304 kB\n@ps\n");
        for p in &self.processes {
            out.push_str(&format!("{:>7} {:>7} {:<32} {:>6} {:>7} {}\n", p.pid, p.parent, p.user, p.rss, uptime as u64, p.command));
        }
        out.push_str("@stat\n");
        for p in &self.processes {
            // CPU time grows with the clock, so two measurements give a load.
            let ticks = (uptime * p.load) as u64;
            out.push_str(&format!("{} (prozess) S {} 1 1 0 -1 0 0 0 0 0 {ticks} 0 0 0 20 0 1 0 0 0 0 0\n", p.pid, p.parent));
        }
        out
    }
}

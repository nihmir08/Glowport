//! OpenSSH configuration (`~/.ssh/config`), read the way `ssh` itself does: for every name the first value applies
//! that a matching `Host` block names. Only names without wildcards become hosts; blocks like `Host *`
//! pass their defaults to everyone they match.

use glowport_core::model::{pattern_matches, ForwardKind};

use crate::text::{expand_home, user_host_port, words};
use crate::{host_name, port, usable_address, Draft, DraftForward, DraftHost, Jump, Note, Values};

/// `Include` is not followed any deeper; protects against files that include each other.
const MAX_DEPTH: usize = 8;

struct Block {
    patterns: Vec<String>,
    options: Vec<(String, String)>,
}

/// Does the text look like an OpenSSH configuration?
pub fn looks_like(text: &str) -> bool {
    let mut hosts = 0;
    let mut options = 0;
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let key = line.split(|c: char| c.is_whitespace() || c == '=').next().unwrap_or("").to_ascii_lowercase();
        match key.as_str() {
            "host" | "match" => hosts += 1,
            "hostname" | "user" | "port" | "identityfile" | "proxyjump" | "proxycommand" | "include" | "forwardagent" => options += 1,
            _ => {}
        }
    }
    hosts > 0 && options > 0
}

/// Splits a line into keyword and rest. Between them is whitespace or an `=`.
fn split_line(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let end = line.find(|c: char| c.is_whitespace() || c == '=').unwrap_or(line.len());
    let value = line[end..].trim_start().strip_prefix('=').unwrap_or(&line[end..]).trim();
    Some((line[..end].to_ascii_lowercase(), value.to_string()))
}

fn blocks(text: &str, include: &dyn Fn(&str) -> Vec<String>, depth: usize, out: &mut Vec<Block>) {
    // Whatever comes before the first `Host` applies to all.
    let mut current = Block { patterns: vec!["*".into()], options: Vec::new() };
    for (key, value) in text.lines().filter_map(split_line) {
        match key.as_str() {
            "host" => {
                out.push(std::mem::replace(&mut current, Block { patterns: words(&value), options: Vec::new() }));
            }
            // `Match` depends on conditions that only show when connecting; its content applies to nobody here.
            "match" => out.push(std::mem::replace(&mut current, Block { patterns: Vec::new(), options: Vec::new() })),
            "include" if depth < MAX_DEPTH => {
                out.push(std::mem::replace(&mut current, Block { patterns: Vec::new(), options: Vec::new() }));
                let scope = out.last().map(|b| b.patterns.clone()).unwrap_or_default();
                for pattern in words(&value) {
                    for file in include(&pattern) {
                        let from = out.len();
                        blocks(&file, include, depth + 1, out);
                        // A file included inside a block only applies to that block's hosts.
                        if scope != ["*"] {
                            for block in &mut out[from..] {
                                if block.patterns == ["*"] {
                                    block.patterns = scope.clone();
                                }
                            }
                        }
                    }
                }
                current.patterns = scope;
            }
            _ => current.options.push((key, value)),
        }
    }
    out.push(current);
}

fn matches(patterns: &[String], name: &str) -> bool {
    let mut hit = false;
    for pattern in patterns {
        match pattern.strip_prefix('!') {
            Some(negated) if pattern_matches(negated, name) => return false,
            Some(_) => {}
            None => hit |= pattern_matches(pattern, name),
        }
    }
    hit
}

/// All values that apply to a name, in the file's order.
fn options_for<'a>(blocks: &'a [Block], name: &str) -> Vec<(&'a str, &'a str)> {
    blocks.iter().filter(|b| matches(&b.patterns, name)).flat_map(|b| b.options.iter().map(|(k, v)| (k.as_str(), v.as_str()))).collect()
}

fn first<'a>(options: &[(&'a str, &'a str)], key: &str) -> Option<&'a str> {
    options.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
}

fn yes(value: &str) -> bool {
    matches!(value.to_ascii_lowercase().as_str(), "yes" | "true" | "on")
}

/// `[address:]port` or `address/port`, IPv6 in square brackets. Without an address the default applies.
fn endpoint(text: &str, default_host: &str) -> Option<(String, u16)> {
    let text = text.trim();
    if let Some(port) = port(text) {
        return Some((default_host.to_string(), port));
    }
    if let Some(rest) = text.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        return Some((host.to_string(), port(after.strip_prefix(':').or_else(|| after.strip_prefix('/'))?)?));
    }
    let (host, number) = text.rsplit_once(':').or_else(|| text.rsplit_once('/'))?;
    let host = if host == "*" || host.is_empty() { "0.0.0.0" } else { host };
    Some((host.to_string(), port(number)?))
}

/// Reads `ssh -W %h:%p jump` from a `ProxyCommand`: that is a jump host in the old notation.
fn jump_from_command(command: &str) -> Option<String> {
    let args = words(command);
    let program = args.first()?.rsplit(['/', '\\']).next()?.to_ascii_lowercase();
    if program != "ssh" && program != "ssh.exe" {
        return None;
    }
    let at = args.iter().position(|a| a == "-W")?;
    if !args.get(at + 1)?.contains("%h") {
        return None;
    }
    let mut target = None;
    let mut port = None;
    let mut user = None;
    let mut rest = args[1..].iter().enumerate().filter(|(i, _)| *i + 1 != at && *i + 1 != at + 1).map(|(_, a)| a.as_str());
    while let Some(arg) = rest.next() {
        match arg {
            "-p" => port = rest.next(),
            "-l" => user = rest.next(),
            "-q" | "-a" | "-x" | "-T" | "-A" => {}
            "-i" | "-o" | "-F" | "-J" => return None,
            other if other.starts_with('-') => return None,
            other if target.is_none() => target = Some(other),
            _ => return None,
        }
    }
    let target = target?;
    let target = match user {
        Some(user) if !target.contains('@') => format!("{user}@{target}"),
        _ => target.to_string(),
    };
    Some(match port {
        Some(port) => format!("{target}:{port}"),
        None => target,
    })
}

const WEAK: [&str; 8] = ["sha1", "-cbc", "3des", "ssh-rsa", "ssh-dss", "group1-", "group14-sha1", "arcfour"];

/// Reads a configuration. `home` replaces `~` in paths; `include` returns the content of the files an
/// `Include` points to (the pattern arrives as written in the file).
pub fn parse(text: &str, home: &str, include: &dyn Fn(&str) -> Vec<String>) -> Draft {
    let mut all = Vec::new();
    blocks(text, include, 0, &mut all);

    let mut names: Vec<&str> = Vec::new();
    for pattern in all.iter().flat_map(|b| &b.patterns) {
        if !pattern.contains(['*', '?', '!']) && !names.contains(&pattern.as_str()) {
            names.push(pattern);
        }
    }

    let mut draft = Draft::default();
    // First all hosts, then the jumps: a jump host may appear further down in the file.
    let mut jumps: Vec<(usize, String)> = Vec::new();
    for name in names {
        let options = options_for(&all, name);
        let address = first(&options, "hostname").map(|h| h.replace("%h", name).replace("%%", "%")).unwrap_or_else(|| name.to_string());
        if !usable_address(&address) {
            draft.skip(name, "invalid");
            continue;
        }
        let mut host = DraftHost { name: host_name(name, &address), address, ..DraftHost::default() };
        let own = &mut host.own;
        own.user = first(&options, "user").map(str::to_string).filter(|u| !u.is_empty());
        own.port = first(&options, "port").and_then(port).filter(|p| *p != 22);
        if let Some(file) = first(&options, "identityfile").filter(|f| !f.eq_ignore_ascii_case("none")) {
            own.key = draft.key_file(&expand_home(file.trim_matches('"'), home));
        }
        if first(&options, "forwardagent").is_some_and(yes) {
            own.agent = Some(true);
            own.agent_forward = Some(true);
            host.notes.push(Note::new("agent_forward"));
        }
        own.keepalive = first(&options, "serveraliveinterval").and_then(|v| v.parse::<u16>().ok()).filter(|v| *v <= 3600);
        own.timeout = first(&options, "connecttimeout").and_then(|v| v.parse::<u16>().ok()).filter(|v| (1..=300).contains(v));
        own.startcmd = first(&options, "remotecommand").filter(|c| !c.eq_ignore_ascii_case("none")).map(str::to_string);
        // `SetEnv` may appear several times; all lines count. The vault uses the same notation.
        let env: Vec<&str> = options.iter().filter(|(k, _)| *k == "setenv").map(|(_, v)| *v).collect();
        if !env.is_empty() {
            own.env = Some(env.join(" "));
        }
        let weak = ["kexalgorithms", "ciphers", "macs", "hostkeyalgorithms", "pubkeyacceptedalgorithms", "pubkeyacceptedkeytypes"];
        if options.iter().any(|(k, v)| weak.contains(k) && WEAK.iter().any(|w| v.to_ascii_lowercase().contains(w))) {
            own.legacy = Some(true);
            host.notes.push(Note::new("legacy"));
        }
        let index = draft.hosts.len();
        match (first(&options, "proxyjump"), first(&options, "proxycommand")) {
            (Some(jump), _) if jump.eq_ignore_ascii_case("none") => host.own.jump = Jump::None,
            (Some(jump), _) => jumps.push((index, jump.to_string())),
            (None, Some(command)) if command.eq_ignore_ascii_case("none") => {}
            (None, Some(command)) => match jump_from_command(command) {
                Some(jump) => jumps.push((index, jump)),
                None => host.notes.push(Note::with("proxy_command", command)),
            },
            (None, None) => {}
        }
        draft.hosts.push(host);

        for (key, value) in options.iter().filter(|(k, _)| matches!(*k, "localforward" | "remoteforward" | "dynamicforward")) {
            let parts = words(value);
            let rule = match (*key, parts.as_slice()) {
                ("dynamicforward", [listen]) => endpoint(listen, "127.0.0.1").map(|(a, p)| (ForwardKind::Dynamic, a, p, String::new(), 0)),
                ("localforward", [listen, dest]) => endpoint(listen, "127.0.0.1").zip(endpoint(dest, "")).map(|((a, p), (h, q))| (ForwardKind::Local, a, p, h, q)),
                ("remoteforward", [listen, dest]) => endpoint(listen, "127.0.0.1").zip(endpoint(dest, "")).map(|((a, p), (h, q))| (ForwardKind::Remote, a, p, h, q)),
                _ => None,
            };
            match rule {
                Some((kind, bind_address, bind_port, dest_host, dest_port)) if kind == ForwardKind::Dynamic || !dest_host.is_empty() => {
                    let label = if kind == ForwardKind::Dynamic { "SOCKS".to_string() } else { dest_port.to_string() };
                    draft.forwards.push(DraftForward { name: format!("{name} · {label}"), kind, host: index, bind_address, bind_port, dest_host, dest_port });
                }
                _ => draft.hosts[index].notes.push(Note::with("option_ignored", format!("{key} {value}"))),
            }
        }
    }

    for (index, chain) in jumps {
        // `ProxyJump a,b`: first a, from there b, from there the destination. So the destination jumps via b, b via a.
        let mut previous: Option<usize> = None;
        for hop in chain.split(',').map(str::trim).filter(|h| !h.is_empty()) {
            let (user, address, port) = user_host_port(hop);
            let known = draft.hosts.iter().position(|h| h.name == address || (h.address == address && h.own.port == port.filter(|p| *p != 22) && (user.is_none() || h.own.user == user)));
            let at = match known {
                Some(at) => at,
                None if usable_address(&address) => {
                    // A jump host only named here becomes a host of its own.
                    draft.hosts.push(DraftHost { name: host_name(&address, &address), address, own: Values { user, port: port.filter(|p| *p != 22), ..Values::default() }, ..DraftHost::default() });
                    let at = draft.hosts.len() - 1;
                    if let Some(before) = previous {
                        draft.hosts[at].own.jump = Jump::Host(before);
                    }
                    at
                }
                None => {
                    draft.hosts[index].notes.push(Note::with("jump_missing", hop));
                    continue;
                }
            };
            previous = Some(at);
        }
        if let Some(last) = previous.filter(|last| *last != index) {
            draft.hosts[index].own.jump = Jump::Host(last);
        }
    }
    draft
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeySource;

    const SAMPLE: &str = r#"
# Arbeit
Host bastion
    HostName 203.0.113.10
    User deploy
    IdentityFile ~/.ssh/id_ed25519
    DynamicForward 1080

Host web-01 web-02
    HostName %h.intern.example
    ProxyJump bastion
    LocalForward 8080 127.0.0.1:80

Host db
  HostName=10.20.1.5
  Port 5022
  User postgres
  ProxyJump deploy@gate.example.org:2222,bastion
  RemoteForward [::1]:9000 localhost:9000
  SetEnv LANG=C TERM_PROGRAM="mein ssh"

Host alt
    HostName 192.168.1.20
    KexAlgorithms +diffie-hellman-group1-sha1
    ProxyCommand ssh -q -W %h:%p bastion
    ForwardAgent yes

Host kunde
    HostName 172.16.4.2
    ProxyCommand nc -X connect -x proxy.example:3128 %h %p
    IdentityFile "C:\Users\ich\Documents\kunde key.pem"

Host frei
    ProxyJump none

Host *.intern.example !web-02
    User intern

Match host irgendwas
    User falsch

Host *
    User admin
    ServerAliveInterval 60
    ConnectTimeout 20
"#;

    fn host<'a>(draft: &'a Draft, name: &str) -> &'a DraftHost {
        draft.hosts.iter().find(|h| h.name == name).unwrap_or_else(|| panic!("{name} fehlt"))
    }

    #[test]
    fn resolves_hosts_like_ssh_does() {
        let draft = parse(SAMPLE, "C:\\Users\\ich", &|_| Vec::new());
        let names: Vec<&str> = draft.hosts.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(names, ["bastion", "web-01", "web-02", "db", "alt", "kunde", "frei", "gate.example.org"]);

        let bastion = host(&draft, "bastion");
        assert_eq!(bastion.address, "203.0.113.10");
        assert_eq!(bastion.own.user.as_deref(), Some("deploy"));
        assert_eq!(bastion.own.port, None);
        assert_eq!(bastion.own.keepalive, Some(60));
        assert_eq!(bastion.own.timeout, Some(20));
        assert_eq!(draft.keys[bastion.own.key.unwrap()].source, KeySource::File("C:\\Users\\ich\\.ssh\\id_ed25519".into()));

        // `%h` is replaced; the first matching value wins, so “admin” from `Host *` only where nothing comes before it.
        let web = host(&draft, "web-01");
        assert_eq!(web.address, "web-01.intern.example");
        assert_eq!(web.own.user.as_deref(), Some("admin"));
        assert_eq!(web.own.jump, Jump::Host(0));

        let db = host(&draft, "db");
        assert_eq!((db.address.as_str(), db.own.port, db.own.user.as_deref()), ("10.20.1.5", Some(5022), Some("postgres")));
        assert_eq!(db.own.env.as_deref(), Some("LANG=C TERM_PROGRAM=\"mein ssh\""));
        // Chain: destination via bastion, bastion stays as it is; the machine only named here becomes a host of its own.
        assert_eq!(db.own.jump, Jump::Host(0));
        let gate = host(&draft, "gate.example.org");
        assert_eq!((gate.own.user.as_deref(), gate.own.port), (Some("deploy"), Some(2222)));

        let old = host(&draft, "alt");
        assert_eq!(old.own.legacy, Some(true));
        assert_eq!(old.own.jump, Jump::Host(0), "ssh -W ist ein Sprung-Server");
        assert_eq!((old.own.agent, old.own.agent_forward), (Some(true), Some(true)));

        let customer = host(&draft, "kunde");
        assert!(customer.notes.iter().any(|n| n.code == "proxy_command" && n.detail.as_deref().unwrap().starts_with("nc ")));
        assert_eq!(draft.keys[customer.own.key.unwrap()].name, "kunde key.pem");
        assert_eq!(host(&draft, "frei").own.jump, Jump::None);
        assert_eq!(host(&draft, "frei").address, "frei");
    }

    #[test]
    fn reads_forwards() {
        let draft = parse(SAMPLE, "", &|_| Vec::new());
        let rules: Vec<_> = draft.forwards.iter().map(|f| (draft.hosts[f.host].name.as_str(), f.kind, f.bind_address.as_str(), f.bind_port, f.dest_host.as_str(), f.dest_port)).collect();
        assert_eq!(
            rules,
            [
                ("bastion", ForwardKind::Dynamic, "127.0.0.1", 1080, "", 0),
                ("web-01", ForwardKind::Local, "127.0.0.1", 8080, "127.0.0.1", 80),
                ("web-02", ForwardKind::Local, "127.0.0.1", 8080, "127.0.0.1", 80),
                ("db", ForwardKind::Remote, "::1", 9000, "localhost", 9000),
            ]
        );
    }

    #[test]
    fn follows_includes_and_patterns() {
        let main = "Include conf.d/*\nHost nach\n  HostName nach.example\nHost *\n  User alle\n";
        let included = "Host aus-datei\n  HostName 10.0.0.9\n  User eigen\n";
        let draft = parse(main, "", &|pattern| if pattern == "conf.d/*" { vec![included.to_string()] } else { Vec::new() });
        assert_eq!(draft.hosts.len(), 2);
        assert_eq!(host(&draft, "aus-datei").own.user.as_deref(), Some("eigen"));
        assert_eq!(host(&draft, "nach").own.user.as_deref(), Some("alle"));

        // A file that includes itself ends after a few levels.
        let looping = parse("Include selbst\nHost a\n", "", &|_| vec!["Include selbst\nHost b\n".to_string()]);
        assert!(looping.hosts.iter().any(|h| h.name == "a") && looping.hosts.iter().any(|h| h.name == "b"));

        assert!(looks_like(SAMPLE));
        assert!(!looks_like("name,address\nweb,10.0.0.1\n"));
        assert!(parse("Host *\n  User x\n", "", &|_| Vec::new()).hosts.is_empty());
    }
}

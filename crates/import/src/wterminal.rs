//! Windows Terminal: Profile aus `settings.json`, deren Befehl `ssh …` startet. Auch für sich brauchbar ist
//! [`command_line`], das eine `ssh`-Kommandozeile in einen Host übersetzt.

use glowport_core::model::ForwardKind;
use serde_json::Value;

use crate::text::{expand_home, jsonc, user_host_port, words};
use crate::{host_name, port, unreadable, usable_address, Draft, DraftForward, DraftHost, Jump, Note, Result, Values};

/// Schalter von `ssh`, denen ein Wert folgt.
const WITH_VALUE: &str = "BbcDEeFIiJLlmOoPpQRSWw";

/// Liest `ssh [schalter] [benutzer@]adresse [befehl]` und hängt den Host an den Entwurf. `None`, wenn die Zeile
/// kein `ssh` startet oder keine Adresse nennt.
pub fn command_line(line: &str, name: &str, home: &str, draft: &mut Draft) -> Option<usize> {
    let args = words(line);
    let program = args.first()?.rsplit(['/', '\\']).next()?.to_ascii_lowercase();
    if program != "ssh" && program != "ssh.exe" {
        return None;
    }
    let mut own = Values::default();
    let mut notes = Vec::new();
    let mut target: Option<String> = None;
    let mut jump: Option<String> = None;
    let mut rules: Vec<(ForwardKind, String)> = Vec::new();
    let mut command: Vec<&str> = Vec::new();
    let mut rest = args[1..].iter().map(String::as_str);
    while let Some(arg) = rest.next() {
        if target.is_some() {
            command.push(arg);
            continue;
        }
        let Some(switches) = arg.strip_prefix('-').filter(|s| !s.is_empty()) else {
            target = Some(arg.to_string());
            continue;
        };
        // Schalter ohne Wert dürfen zusammenstehen (`-AT`); der Wert eines Schalters klebt daran oder folgt.
        for (at, switch) in switches.char_indices() {
            if !WITH_VALUE.contains(switch) {
                if switch == 'A' {
                    own.agent = Some(true);
                    own.agent_forward = Some(true);
                    notes.push(Note::new("agent_forward"));
                }
                continue;
            }
            let glued = &switches[at + switch.len_utf8()..];
            let value = if glued.is_empty() { rest.next()? } else { glued };
            match switch {
                'p' => own.port = port(value).filter(|p| *p != 22),
                'l' => own.user = Some(value.to_string()),
                'i' => own.key = draft.key_file(&expand_home(value, home)),
                'J' => jump = Some(value.to_string()),
                'L' => rules.push((ForwardKind::Local, value.to_string())),
                'R' => rules.push((ForwardKind::Remote, value.to_string())),
                'D' => rules.push((ForwardKind::Dynamic, value.to_string())),
                _ => {}
            }
            break;
        }
    }
    let (user, address, port_in_target) = user_host_port(&target?);
    if !usable_address(&address) {
        return None;
    }
    own.user = own.user.or(user);
    own.port = own.port.or(port_in_target.filter(|p| *p != 22));
    if !command.is_empty() {
        own.startcmd = Some(command.join(" "));
    }
    if let Some(jump) = jump.as_deref().and_then(|j| j.split(',').next_back()) {
        let (jump_user, jump_address, jump_port) = user_host_port(jump);
        let known = draft.hosts.iter().position(|h| h.name == jump_address || h.address == jump_address);
        let at = known.or_else(|| {
            usable_address(&jump_address).then(|| {
                draft.hosts.push(DraftHost { name: host_name(&jump_address, &jump_address), address: jump_address.clone(), own: Values { user: jump_user, port: jump_port.filter(|p| *p != 22), ..Values::default() }, ..DraftHost::default() });
                draft.hosts.len() - 1
            })
        });
        own.jump = at.map(Jump::Host).unwrap_or_default();
    }
    let index = draft.hosts.len();
    let label = host_name(name, &address);
    draft.hosts.push(DraftHost { name: label.clone(), address, own, notes, ..DraftHost::default() });
    for (kind, spec) in rules {
        // `[adresse:]port[:ziel:zielport]`; für `-D` nur der vordere Teil.
        let parts: Vec<&str> = spec.split(':').collect();
        let rule = match (kind, parts.as_slice()) {
            (ForwardKind::Dynamic, [listen]) => port(listen).map(|p| ("127.0.0.1".to_string(), p, String::new(), 0)),
            (ForwardKind::Dynamic, [address, listen]) => port(listen).map(|p| (address.to_string(), p, String::new(), 0)),
            (_, [listen, dest, dest_port]) => port(listen).zip(port(dest_port)).map(|(p, q)| ("127.0.0.1".to_string(), p, dest.to_string(), q)),
            (_, [address, listen, dest, dest_port]) => port(listen).zip(port(dest_port)).map(|(p, q)| (address.to_string(), p, dest.to_string(), q)),
            _ => None,
        };
        if let Some((bind_address, bind_port, dest_host, dest_port)) = rule {
            let what = if kind == ForwardKind::Dynamic { "SOCKS".to_string() } else { dest_port.to_string() };
            draft.forwards.push(DraftForward { name: format!("{label} · {what}"), kind, host: index, bind_address, bind_port, dest_host, dest_port });
        }
    }
    Some(index)
}

pub fn parse(text: &str, home: &str) -> Result<Draft> {
    let Some(root) = jsonc(text) else { return unreadable("kein JSON") };
    let profiles = root.get("profiles").map(|p| p.get("list").unwrap_or(p)).and_then(Value::as_array);
    let mut draft = Draft::default();
    for profile in profiles.into_iter().flatten() {
        let (Some(line), name) = (profile.get("commandline").and_then(Value::as_str), profile.get("name").and_then(Value::as_str).unwrap_or_default()) else { continue };
        command_line(line, name, home, &mut draft);
    }
    Ok(draft)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeySource;

    #[test]
    fn reads_ssh_profiles() {
        let settings = r#"{
            "$schema": "https://aka.ms/terminal-profiles-schema",
            "defaultProfile": "{0caa0dad-35be-5f56-a8ff-afceeeaa6101}",
            "profiles": {
                "defaults": {},
                "list": [
                    { "name": "PowerShell", "commandline": "powershell.exe -NoLogo" },
                    { "name": "Webserver", "commandline": "ssh -p 2222 -i ~/.ssh/id_ed25519 -AT deploy@web.example.org", },
                    { "name": "DB", "commandline": "C:\\Windows\\System32\\OpenSSH\\ssh.exe -J jump@gate.example.org:2200 -L 15432:127.0.0.1:5432 -D1080 -l postgres db.intern tmux attach" },
                    { "name": "WSL", "source": "Windows.Terminal.Wsl" },
                ]
            }
        }"#;
        let draft = parse(settings, "C:\\Users\\ich").unwrap();
        let names: Vec<&str> = draft.hosts.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(names, ["Webserver", "gate.example.org", "DB"]);
        let web = &draft.hosts[0];
        assert_eq!((web.address.as_str(), web.own.user.as_deref(), web.own.port, web.own.agent_forward), ("web.example.org", Some("deploy"), Some(2222), Some(true)));
        assert_eq!(draft.keys[web.own.key.unwrap()].source, KeySource::File("C:\\Users\\ich\\.ssh\\id_ed25519".into()));
        let db = &draft.hosts[2];
        assert_eq!((db.own.user.as_deref(), db.own.jump, db.own.startcmd.as_deref()), (Some("postgres"), Jump::Host(1), Some("tmux attach")));
        assert_eq!((draft.hosts[1].own.user.as_deref(), draft.hosts[1].own.port), (Some("jump"), Some(2200)));
        let rules: Vec<_> = draft.forwards.iter().map(|f| (f.kind, f.bind_port, f.dest_host.as_str(), f.dest_port)).collect();
        assert_eq!(rules, [(ForwardKind::Local, 15432, "127.0.0.1", 5432), (ForwardKind::Dynamic, 1080, "", 0)]);
    }
}

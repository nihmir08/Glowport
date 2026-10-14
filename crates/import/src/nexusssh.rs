//! NexusSSH: the export file (`"format": "nexusssh-export"`) or `profiles.json` from its data folder.
//! Both name the same fields, one in `camelCase`, the other with underscores. Neither contains secrets.

use std::collections::HashMap;

use serde_json::Value;

use crate::text::{expand_home, jsonc};
use crate::{host_name, unreadable, usable_address, Draft, DraftHost, DraftSnippet, Jump, Note, Result};

fn field<'a>(profile: &'a Value, camel: &str, snake: &str) -> Option<&'a Value> {
    profile.get(camel).or_else(|| profile.get(snake)).filter(|v| !v.is_null())
}

pub fn parse(text: &str, home: &str) -> Result<Draft> {
    let Some(root) = jsonc(text) else { return unreadable("kein JSON") };
    let profiles = match &root {
        Value::Array(list) => list.as_slice(),
        Value::Object(_) => root.get("profiles").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]),
        _ => return unreadable("keine Profile"),
    };
    let mut draft = Draft::default();
    let mut by_id: HashMap<&str, usize> = HashMap::new();
    let mut jumps: Vec<(usize, &str)> = Vec::new();
    for profile in profiles {
        let text_of = |camel: &str, snake: &str| field(profile, camel, snake).and_then(Value::as_str).map(str::trim).filter(|v| !v.is_empty());
        let name = text_of("name", "name").unwrap_or_default();
        let Some(address) = text_of("host", "host").filter(|a| usable_address(a)) else {
            draft.skip(name, "no_address");
            continue;
        };
        let group = text_of("group", "group").map(|g| g.split(['/', '\\']).collect::<Vec<_>>()).unwrap_or_default();
        let mut host = DraftHost { name: host_name(name, address), address: address.to_string(), group: draft.group_at(&group), ..DraftHost::default() };
        host.own.user = text_of("user", "user").map(str::to_string);
        host.own.port = field(profile, "port", "port").and_then(Value::as_u64).and_then(|p| u16::try_from(p).ok()).filter(|p| *p != 0 && *p != 22);
        host.own.key = text_of("keyPath", "key_path").and_then(|file| draft.key_file(&expand_home(file, home)));
        // NexusSSH offers keys from the agent unless that is switched off.
        if field(profile, "useAgent", "use_agent").and_then(Value::as_bool).unwrap_or(true) {
            host.own.agent = Some(true);
        }
        if field(profile, "forwardAgent", "forward_agent").and_then(Value::as_bool) == Some(true) {
            host.own.agent = Some(true);
            host.own.agent_forward = Some(true);
            host.notes.push(Note::new("agent_forward"));
        }
        if let Some(id) = text_of("id", "id") {
            by_id.insert(id, draft.hosts.len());
        }
        if let Some(jump) = text_of("jump", "jump") {
            jumps.push((draft.hosts.len(), jump));
        }
        draft.hosts.push(host);
    }
    for (at, jump) in jumps {
        match by_id.get(jump) {
            Some(target) if *target != at => draft.hosts[at].own.jump = Jump::Host(*target),
            _ => draft.hosts[at].notes.push(Note::with("jump_missing", jump)),
        }
    }
    for snippet in root.get("snippets").and_then(Value::as_array).into_iter().flatten() {
        let (Some(name), Some(command)) = (snippet.get("name").and_then(Value::as_str), snippet.get("text").and_then(Value::as_str)) else { continue };
        if !command.trim().is_empty() {
            draft.snippets.push(DraftSnippet { name: name.trim().to_string(), package: "NexusSSH".into(), command: command.to_string() });
        }
    }
    Ok(draft)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeySource;

    #[test]
    fn reads_export_and_profile_store() {
        let export = r#"{
            // written by NexusSSH
            "format": "nexusssh-export", "version": 1,
            "profiles": [
                { "id": "a", "name": "bastion", "host": "203.0.113.10", "port": 22, "user": "deploy", "group": "Produktiv", "keyPath": "~/.ssh/id_ed25519", "useAgent": false },
                { "id": "b", "name": "web", "host": "10.0.0.5", "port": 2222, "user": "root", "group": "Produktiv", "jump": "a", "forwardAgent": true },
                { "id": "c", "name": "leer", "host": "" },
            ],
            "snippets": [ { "name": "Platz", "text": "df -h", "run": true } ]
        }"#;
        let draft = parse(export, "C:\\Users\\ich").unwrap();
        assert_eq!(draft.hosts.len(), 2);
        assert_eq!(draft.groups[0].name, "Produktiv");
        assert_eq!(draft.keys[draft.hosts[0].own.key.unwrap()].source, KeySource::File("C:\\Users\\ich\\.ssh\\id_ed25519".into()));
        assert_eq!((draft.hosts[0].own.agent, draft.hosts[0].own.port), (None, None));
        assert_eq!((draft.hosts[1].own.jump, draft.hosts[1].own.port, draft.hosts[1].own.agent_forward), (Jump::Host(0), Some(2222), Some(true)));
        assert_eq!(draft.snippets[0].command, "df -h");
        assert_eq!(draft.skipped[0].reason, "no_address");

        let store = r#"[{"id":"x","name":"nas","host":"192.168.1.20","port":22,"user":"admin","group":"","tags":[],"favorite":false,"key_path":null,"use_agent":true,"jump":"fehlt","forward_agent":false}]"#;
        let draft = parse(store, "").unwrap();
        assert_eq!((draft.hosts[0].name.as_str(), draft.hosts[0].own.agent, draft.hosts[0].own.jump), ("nas", Some(true), Jump::Unset));
        assert_eq!(draft.hosts[0].notes[0].code, "jump_missing");
        assert!(parse("kein json", "").is_err());
    }
}

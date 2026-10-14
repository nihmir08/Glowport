//! Gemeinsames Handwerk der Leser: Zeichensätze, Registry-Exporte, INI-Dateien, JSON mit Kommentaren, Kommandozeilen.

use crate::{Entries, Section};

/// Macht aus Bytes Text. Dateien anderer Programme kommen als UTF-8, als UTF-16 (Registry-Export, Xshell) oder in
/// der Codepage von Windows (alte INI-Dateien); im Zweifel gilt Windows-1252, das jedes Byte abbildet.
pub fn decode(bytes: &[u8]) -> String {
    if let Some((encoding, _)) = encoding_rs::Encoding::for_bom(bytes) {
        return encoding.decode_with_bom_removal(bytes).0.into_owned();
    }
    // UTF-16 ohne Kennung: Bei lateinischem Text ist jedes zweite Byte null.
    if bytes.len() >= 4 && bytes.len().is_multiple_of(2) && bytes.iter().skip(1).step_by(2).take(64).all(|b| *b == 0) {
        return encoding_rs::UTF_16LE.decode_without_bom_handling(bytes).0.into_owned();
    }
    match std::str::from_utf8(bytes) {
        Ok(text) => text.to_string(),
        Err(_) => encoding_rs::WINDOWS_1252.decode_without_bom_handling(bytes).0.into_owned(),
    }
}

/// Löst `%20` und Ähnliches auf; kaputte Folgen bleiben stehen. Die Bytes gelten als UTF-8.
pub fn percent_decode(text: &str) -> String {
    let raw = text.as_bytes();
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        let hex = |b: u8| (b as char).to_digit(16);
        match (raw[i], raw.get(i + 1).copied().and_then(hex), raw.get(i + 2).copied().and_then(hex)) {
            (b'%', Some(high), Some(low)) => {
                out.push((high * 16 + low) as u8);
                i += 3;
            }
            (byte, ..) => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8(out).unwrap_or_else(|e| encoding_rs::WINDOWS_1252.decode_without_bom_handling(e.as_bytes()).0.into_owned())
}

/// Die Abschnitte eines Registry-Exports (`.reg`) unterhalb von `key`, jeder mit dem Rest seines Pfads als Namen.
/// Zahlen (`dword:`) werden zu Dezimaltext; binäre Werte fallen weg.
pub fn reg_sections(text: &str, key: &str) -> Vec<Section> {
    let mark = format!("{}\\", key.to_ascii_lowercase());
    let mut sections: Vec<Section> = Vec::new();
    let mut inside = false;
    for line in text.lines().map(|l| l.trim_end_matches('\r')) {
        if let Some(path) = line.trim().strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            inside = false;
            if let Some(at) = path.to_ascii_lowercase().find(&mark) {
                sections.push((path[at + mark.len()..].to_string(), Entries::new()));
                inside = true;
            }
            continue;
        }
        if !inside {
            continue;
        }
        let Some(rest) = line.trim_start().strip_prefix('"') else { continue };
        // Der Name endet am ersten Anführungszeichen ohne Rückstrich davor.
        let Some(end) = closing_quote(rest) else { continue };
        let name = unescape_reg(&rest[..end]);
        let Some(value) = rest[end + 1..].trim_start().strip_prefix('=') else { continue };
        let value = value.trim();
        let parsed = if let Some(quoted) = value.strip_prefix('"') {
            closing_quote(quoted).map(|end| unescape_reg(&quoted[..end]))
        } else if let Some(hex) = value.strip_prefix("dword:") {
            u32::from_str_radix(hex.trim(), 16).ok().map(|n| n.to_string())
        } else {
            None
        };
        if let (Some(value), Some((_, entries))) = (parsed, sections.last_mut()) {
            entries.insert(name, value);
        }
    }
    sections
}

fn closing_quote(text: &str) -> Option<usize> {
    let mut escaped = false;
    text.char_indices().find_map(|(i, c)| match c {
        '\\' if !escaped => {
            escaped = true;
            None
        }
        '"' if !escaped => Some(i),
        _ => {
            escaped = false;
            None
        }
    })
}

fn unescape_reg(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        out.push(if c == '\\' { chars.next().unwrap_or('\\') } else { c });
    }
    out
}

/// Die Abschnitte einer INI-Datei. Zeilen vor dem ersten Abschnitt gehören zu einem Abschnitt ohne Namen.
/// Kommentare gibt es nur am Zeilenanfang (`;`): MobaXterm benutzt `#` und `;` mitten in seinen Werten.
pub fn ini_sections(text: &str) -> Vec<Section> {
    let mut sections: Vec<Section> = Vec::new();
    for line in text.trim_start_matches('\u{feff}').lines().map(|l| l.trim_end_matches('\r')) {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with(';') {
            continue;
        }
        if let Some(name) = trimmed.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            sections.push((name.to_string(), Entries::new()));
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            if sections.is_empty() {
                sections.push((String::new(), Entries::new()));
            }
            sections.last_mut().unwrap().1.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    sections
}

/// Liest JSON, das Kommentare und Kommas vor schließenden Klammern enthalten darf (Windows Terminal, NexusSSH).
pub fn jsonc(text: &str) -> Option<serde_json::Value> {
    let text = text.trim_start_matches('\u{feff}');
    if let Ok(value) = serde_json::from_str(text) {
        return Some(value);
    }
    let mut clean = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut in_string = false;
    while let Some(c) = chars.next() {
        if in_string {
            clean.push(c);
            match c {
                '\\' => clean.extend(chars.next()),
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match (c, chars.peek().copied()) {
            ('"', _) => {
                in_string = true;
                clean.push(c);
            }
            ('/', Some('/')) => {
                for next in chars.by_ref() {
                    if next == '\n' {
                        clean.push('\n');
                        break;
                    }
                }
            }
            ('/', Some('*')) => {
                chars.next();
                let mut star = false;
                for next in chars.by_ref() {
                    if star && next == '/' {
                        break;
                    }
                    star = next == '*';
                }
            }
            ('}' | ']', _) => {
                // Ein Komma vor der schließenden Klammer nimmt serde_json nicht hin.
                let kept = clean.trim_end().len();
                if clean[..kept].ends_with(',') {
                    clean.truncate(kept - 1);
                }
                clean.push(c);
            }
            _ => clean.push(c),
        }
    }
    serde_json::from_str(&clean).ok()
}

/// Zerlegt eine Zeile in Wörter wie eine Shell: Leerzeichen trennen, Anführungszeichen halten zusammen.
/// Rückstriche bleiben Zeichen, weil sie unter Windows in jedem Pfad stehen.
pub fn words(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut started = false;
    for c in line.chars() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => current.push(c),
            None if c == '"' || c == '\'' => {
                quote = Some(c);
                started = true;
            }
            None if c.is_whitespace() => {
                if started || !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            None => current.push(c),
        }
    }
    if started || !current.is_empty() {
        out.push(current);
    }
    out
}

/// Setzt den Benutzerordner für `~` am Anfang eines Pfads ein und richtet die Schrägstriche nach Windows aus.
pub fn expand_home(path: &str, home: &str) -> String {
    let path = path.trim();
    let rest = path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\")).or_else(|| path.strip_prefix("%d/")).or_else(|| path.strip_prefix("%USERPROFILE%\\")).or_else(|| path.strip_prefix("%USERPROFILE%/"));
    match rest {
        Some(rest) if !home.is_empty() => format!("{}\\{}", home.trim_end_matches(['\\', '/']), rest.replace('/', "\\")),
        _ => path.to_string(),
    }
}

/// `[benutzer@]adresse[:port]`, wie es in `ProxyJump`, in Kommandozeilen und in manchen Feldern steht.
/// IPv6-Adressen stehen dabei in eckigen Klammern, wenn ein Port folgt.
pub fn user_host_port(text: &str) -> (Option<String>, String, Option<u16>) {
    let text = text.trim();
    let text = text.strip_prefix("ssh://").unwrap_or(text);
    let (user, rest) = match text.rsplit_once('@') {
        Some((user, rest)) if !user.is_empty() => (Some(user.to_string()), rest),
        _ => (None, text),
    };
    if let Some(bracketed) = rest.strip_prefix('[') {
        if let Some((host, after)) = bracketed.split_once(']') {
            return (user, host.to_string(), after.strip_prefix(':').and_then(crate::port));
        }
    }
    match rest.rsplit_once(':') {
        // Mehr als ein Doppelpunkt ohne Klammern ist eine nackte IPv6-Adresse.
        Some((host, port)) if !host.contains(':') && crate::port(port).is_some() => (user, host.to_string(), crate::port(port)),
        _ => (user, rest.to_string(), None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_what_other_programs_write() {
        assert_eq!(decode("Größe".as_bytes()), "Größe");
        assert_eq!(decode(b"\xEF\xBB\xBFname"), "name");
        let utf16: Vec<u8> = [0xFF, 0xFE].into_iter().chain("Tür".encode_utf16().flat_map(u16::to_le_bytes)).collect();
        assert_eq!(decode(&utf16), "Tür");
        let bare: Vec<u8> = "Host=a".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(decode(&bare), "Host=a");
        assert_eq!(decode(b"Gr\xF6\xDFe"), "Größe");
    }

    #[test]
    fn reads_registry_exports() {
        let text = "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\mein%20server]\r\n\"HostName\"=\"web.example.org\"\r\n\"PortNumber\"=dword:00000016\r\n\"PublicKeyFile\"=\"C:\\\\Users\\\\ich\\\\a \\\"b\\\".ppk\"\r\n\"Bin\"=hex:00,01\r\n\r\n[HKEY_CURRENT_USER\\Software\\Anderes]\r\n\"HostName\"=\"nicht.gemeint\"\r\n";
        let sections = reg_sections(text, "Software\\SimonTatham\\PuTTY\\Sessions");
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].0, "mein%20server");
        assert_eq!(sections[0].1["HostName"], "web.example.org");
        assert_eq!(sections[0].1["PortNumber"], "22");
        assert_eq!(sections[0].1["PublicKeyFile"], "C:\\Users\\ich\\a \"b\".ppk");
        assert!(!sections[0].1.contains_key("Bin"));
        assert_eq!(percent_decode(&sections[0].0), "mein server");
        assert_eq!(percent_decode("B%C3%BCro%2Fweb 100%"), "Büro/web 100%");
    }

    #[test]
    fn reads_ini_and_tolerant_json() {
        let sections = ini_sections("; Kommentar\n[Bookmarks]\nSubRep=\na=#109#0%h;x#y\n[Leer]\n");
        assert_eq!(sections.len(), 2);
        assert_eq!(sections[0].1["a"], "#109#0%h;x#y");
        let value = jsonc("{\n // Kommentar\n \"a\": \"x // bleibt\", /* weg */ \"b\": [1, 2,],\n}").unwrap();
        assert_eq!(value["a"], "x // bleibt");
        assert_eq!(value["b"][1], 2);
        assert!(jsonc("kein json").is_none());
    }

    #[test]
    fn splits_words_and_targets() {
        assert_eq!(words("ssh -i \"C:\\Users\\ich\\a b.pem\" root@host  -p 22"), ["ssh", "-i", "C:\\Users\\ich\\a b.pem", "root@host", "-p", "22"]);
        assert_eq!(words("a '' b"), ["a", "", "b"]);
        assert_eq!(user_host_port("root@web:2222"), (Some("root".into()), "web".into(), Some(2222)));
        assert_eq!(user_host_port("web"), (None, "web".into(), None));
        assert_eq!(user_host_port("[2001:db8::1]:22"), (None, "2001:db8::1".into(), Some(22)));
        assert_eq!(user_host_port("2001:db8::1"), (None, "2001:db8::1".into(), None));
        assert_eq!(expand_home("~/.ssh/id_ed25519", "C:\\Users\\ich"), "C:\\Users\\ich\\.ssh\\id_ed25519");
        assert_eq!(expand_home("D:\\keys\\a.pem", "C:\\Users\\ich"), "D:\\keys\\a.pem");
    }
}

//! Settings without secret value (appearance, language, view) as a JSON file in the data folder.
//!
//! The interface decides the content and checks it when loading; this is only about safe reading and writing.

use std::{
    fs,
    io::{self, Write},
    path::Path,
};

use serde_json::Value;

const FILE: &str = "settings.json";
const TEMP: &str = "settings.json.neu";
const BROKEN: &str = "settings.json.defekt";

/// Reads the settings. `None` if there are none yet or the file was unreadable.
/// A broken file is put aside instead of overwritten, so nothing gets lost silently.
pub fn load(dir: &Path) -> io::Result<Option<Value>> {
    let path = dir.join(FILE);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    match serde_json::from_str(&text) {
        Ok(value) => Ok(Some(value)),
        Err(_) => {
            fs::rename(&path, dir.join(BROKEN))?;
            Ok(None)
        }
    }
}

/// German or English for a Windows language ID. The lower ten bits name the language; 7 is German
/// in every variant (Germany, Austria, Switzerland). Everything else gets English.
fn language_of(id: u32) -> &'static str {
    if id & 0x3ff == 0x07 {
        "de"
    } else {
        "en"
    }
}

/// The language for the very first start, as long as there are no settings: the one chosen in the installer
/// (`installer`, a language ID as text like “1033”), otherwise that of Windows' interface (`system`).
/// If both are unknown, English.
pub fn first_language(installer: Option<&str>, system: Option<u32>) -> &'static str {
    installer.and_then(|text| text.trim().parse().ok()).or(system).map_or("en", language_of)
}

/// The language chosen in the installer. It stores it for the signed-in user in the registry,
/// under the program's publisher and name.
#[cfg(windows)]
pub fn installer_language(publisher: &str, product: &str) -> Option<String> {
    use winreg::{enums::HKEY_CURRENT_USER, RegKey};
    RegKey::predef(HKEY_CURRENT_USER).open_subkey(format!("Software\\{publisher}\\{product}")).ok()?.get_value("Installer Language").ok()
}

#[cfg(not(windows))]
pub fn installer_language(_publisher: &str, _product: &str) -> Option<String> {
    None
}

/// The language Windows shows its interface in.
#[cfg(windows)]
pub fn system_language() -> Option<u32> {
    // SAFETY: The call takes nothing and returns a number.
    Some(u32::from(unsafe { windows_sys::Win32::Globalization::GetUserDefaultUILanguage() }))
}

#[cfg(not(windows))]
pub fn system_language() -> Option<u32> {
    let lang = std::env::var("LC_ALL").or_else(|_| std::env::var("LANG")).ok()?;
    Some(if lang.to_lowercase().starts_with("de") { 0x07 } else { 0x09 })
}

/// Writes atomically: first a neighbouring file, then rename. A crash midway leaves the old file intact.
pub fn save(dir: &Path, settings: &Value) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    let temp = dir.join(TEMP);
    let mut file = fs::File::create(&temp)?;
    file.write_all(serde_json::to_string_pretty(settings)?.as_bytes())?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temp, dir.join(FILE))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::path::PathBuf;

    /// An empty folder of its own per test, so parallel tests do not disturb each other.
    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("glowport-test-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn first_start_follows_the_installer_then_windows() {
        // 1031 German (Germany), 3079 Austria, 2055 Switzerland; 1033 and 2057 English; 1036 French.
        for german in [1031, 3079, 2055] {
            assert_eq!(language_of(german), "de");
        }
        for other in [1033, 2057, 1036, 0] {
            assert_eq!(language_of(other), "en");
        }
        // The choice in the installer comes first, even against the language of Windows.
        assert_eq!(first_language(Some("1033"), Some(1031)), "en");
        assert_eq!(first_language(Some(" 1031 "), Some(2057)), "de");
        // Without an installer (portable version) or with an unreadable entry, Windows counts.
        assert_eq!(first_language(None, Some(3079)), "de");
        assert_eq!(first_language(Some("kaputt"), Some(1031)), "de");
        assert_eq!(first_language(None, Some(2057)), "en");
        assert_eq!(first_language(None, None), "en");
    }

    /// Reads what is really stored on this PC and only prints the IDs.
    /// `cargo test -p glowport reads_the_languages_of_this_pc -- --ignored --nocapture`
    #[test]
    #[ignore = "liest Registry und Sprache dieses PCs"]
    fn reads_the_languages_of_this_pc() {
        let installer = installer_language("Glowport", "Glowport");
        let system = system_language();
        println!("Installer: {installer:?} · Windows: {system:?} · erster Start: {}", first_language(installer.as_deref(), system));
        assert!(system.is_some());
    }

    #[test]
    fn missing_file_is_none() {
        let dir = temp_dir("missing");
        assert_eq!(load(&dir).unwrap(), None);
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = temp_dir("roundtrip");
        let value = json!({ "mode": "light", "accent": "#FF2E63", "autoLockMinutes": 15 });
        save(&dir, &value).unwrap();
        assert_eq!(load(&dir).unwrap(), Some(value));
        assert!(!dir.join(TEMP).exists(), "Nachbardatei muss nach dem Speichern weg sein");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn save_replaces_existing() {
        let dir = temp_dir("replace");
        save(&dir, &json!({ "lang": "de" })).unwrap();
        save(&dir, &json!({ "lang": "en" })).unwrap();
        assert_eq!(load(&dir).unwrap(), Some(json!({ "lang": "en" })));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn broken_file_is_set_aside() {
        let dir = temp_dir("broken");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(FILE), "{ kaputt").unwrap();
        assert_eq!(load(&dir).unwrap(), None);
        assert!(!dir.join(FILE).exists());
        assert_eq!(fs::read_to_string(dir.join(BROKEN)).unwrap(), "{ kaputt");
        fs::remove_dir_all(&dir).unwrap();
    }
}

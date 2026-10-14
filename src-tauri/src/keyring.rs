//! Brücke für Schlüssel und Identitäten.
//!
//! Erzeugen, Lesen und Schreiben von Schlüsseln macht `glowport-net`, abgelegt wird im Kern. Der private Teil
//! verlässt dieses Modul nur beim ausdrücklichen Export in eine Datei, die der Nutzer wählt.

use glowport_core::{
    directory::{IdentityInput, NewAuthority, NewKey, Verdict},
    model::{KeyCertificate, KeyKind, KeyOrigin, Secret},
};
use glowport_net::{
    agent,
    keys::{self, Format, Installed, KeyError, Kind, Material},
    Agents, End,
};
use serde::{Deserialize, Serialize};
use tauri::{ipc::Channel, AppHandle, Manager, State};
use tauri_plugin_dialog::DialogExt;
use zeroize::Zeroizing;

use crate::{
    app::{emit_snapshot, AppState, Changed, CmdError, CmdResult},
    sessions::connect_chain,
};

/// Schlüsseldateien sind wenige Kilobyte groß; alles darüber ist etwas anderes.
const MAX_KEY_FILE: u64 = 64 * 1024;

impl From<KeyError> for CmdError {
    fn from(error: KeyError) -> Self {
        CmdError::invalid(match error {
            KeyError::Unreadable => "key_unreadable",
            KeyError::Unsupported => "key_unsupported",
            KeyError::PassphraseRequired => "passphrase_required",
            KeyError::WrongPassphrase => "wrong_passphrase",
            KeyError::InvalidSize => "key_size",
            KeyError::CertificateUnreadable => "certificate_unreadable",
            KeyError::CertificateMismatch => "certificate_mismatch",
            KeyError::CertificateWrongType => "certificate_wrong_type",
        })
    }
}

fn to_net(kind: KeyKind) -> Kind {
    match kind {
        KeyKind::Ed25519 => Kind::Ed25519,
        KeyKind::Ecdsa => Kind::Ecdsa,
        KeyKind::Rsa => Kind::Rsa,
    }
}

fn to_core(kind: Kind) -> KeyKind {
    match kind {
        Kind::Ed25519 => KeyKind::Ed25519,
        Kind::Ecdsa => KeyKind::Ecdsa,
        Kind::Rsa => KeyKind::Rsa,
    }
}

#[derive(Deserialize)]
pub struct Generate {
    name: String,
    kind: KeyKind,
    bits: u32,
}

#[derive(Deserialize)]
pub struct Import {
    name: String,
    text: String,
    #[serde(default)]
    passphrase: Option<String>,
}

/// Was in einer Schlüsseldatei steckt, für die Anzeige vor dem Importieren.
#[derive(Debug, Serialize, PartialEq)]
pub struct Info {
    kind: Option<KeyKind>,
    bits: Option<u32>,
    fingerprint: Option<String>,
    encrypted: bool,
    /// `openssh`, `pem` oder `ppk`.
    format: &'static str,
    comment: String,
}

#[derive(Serialize)]
pub struct PickedFile {
    path: String,
    text: String,
}

fn store(state: &AppState, name: String, material: Material, origin: KeyOrigin, vault: Option<&str>) -> CmdResult<Changed> {
    let key = NewKey {
        name,
        kind: to_core(material.kind),
        bits: material.bits,
        fingerprint: material.fingerprint,
        public: material.public,
        private: Secret::new(material.private.to_string()),
        origin,
    };
    let mut session = state.session();
    let id = session.directory()?.in_vault(vault, |directory| directory.add_key(key))?;
    session.changed(Some(id))
}

#[cfg(test)]
pub(crate) fn generate(state: &AppState, key: Generate) -> CmdResult<Changed> {
    generate_in(state, key, None)
}

/// `vault`: der Tresor, in den der Schlüssel kommt; ohne Angabe der persönliche.
fn generate_in(state: &AppState, key: Generate, vault: Option<&str>) -> CmdResult<Changed> {
    // Erst prüfen, ob der Tresor offen ist; das Rechnen selbst geschieht ohne die Sperre auf dem Zustand.
    state.session().directory()?;
    let material = keys::generate(to_net(key.kind), key.bits)?;
    store(state, key.name, material, KeyOrigin::Generated, vault)
}

pub(crate) fn inspect(text: &str, passphrase: Option<&str>) -> CmdResult<Info> {
    let info = keys::inspect(text, passphrase)?;
    let format = match info.format {
        Format::Openssh => "openssh",
        Format::Pem => "pem",
        Format::Ppk => "ppk",
    };
    Ok(Info { kind: info.kind.map(to_core), bits: info.bits, fingerprint: info.fingerprint, encrypted: info.encrypted, format, comment: info.comment })
}

#[cfg(test)]
pub(crate) fn import(state: &AppState, key: Import) -> CmdResult<Changed> {
    import_in(state, key, None)
}

fn import_in(state: &AppState, key: Import, vault: Option<&str>) -> CmdResult<Changed> {
    let text = Zeroizing::new(key.text);
    let passphrase = key.passphrase.map(Zeroizing::new);
    state.session().directory()?;
    let material = keys::import(&text, passphrase.as_ref().map(|p| p.as_str()))?;
    store(state, key.name, material, KeyOrigin::Imported, vault)
}

/// Dateiname für den Export: nur Zeichen, die überall erlaubt sind.
fn file_name(name: &str) -> String {
    let safe: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') { c } else { '_' }).collect();
    if safe.trim_matches('_').is_empty() {
        "id_glowport".into()
    } else {
        safe
    }
}

#[tauri::command(async)]
pub fn key_generate(state: State<'_, AppState>, key: Generate, vault: Option<String>) -> CmdResult<Changed> {
    generate_in(&state, key, vault.as_deref())
}

/// Lässt den Nutzer eine Schlüsseldatei wählen und liest sie. `None`, wenn der Dialog abgebrochen wurde.
#[tauri::command(async)]
pub fn key_pick_file(app: AppHandle) -> CmdResult<Option<PickedFile>> {
    let Some(path) = app.dialog().file().blocking_pick_file().and_then(|chosen| chosen.into_path().ok()) else {
        return Ok(None);
    };
    read_file(&path.display().to_string()).map(Some)
}

/// Liest eine Schlüsseldatei an einem bekannten Ort: vom Nutzer ins Fenster gezogen oder im Feld „Schlüsseldatei“ eingetragen.
pub(crate) fn read_file(path: &str) -> CmdResult<PickedFile> {
    let unreadable = || CmdError::from(KeyError::Unreadable);
    if std::fs::metadata(path).map_err(|_| unreadable())?.len() > MAX_KEY_FILE {
        return Err(unreadable());
    }
    let text = String::from_utf8(std::fs::read(path).map_err(|_| unreadable())?).map_err(|_| unreadable())?;
    Ok(PickedFile { path: path.to_string(), text })
}

#[tauri::command(async)]
pub fn key_read_file(path: String) -> CmdResult<PickedFile> {
    read_file(&path)
}

/// Übernimmt eine Schlüsseldatei in den Tresor und lässt den Host sich künftig damit anmelden. Aufgerufen, nachdem
/// die Anmeldung mit Datei und Passphrase geklappt hat. Liegt derselbe Schlüssel schon im Tresor, wird er benutzt
/// statt ein zweites Mal angelegt.
pub(crate) fn adopt_file(state: &AppState, path: &str, passphrase: &str, host: &str) -> CmdResult<()> {
    let file = read_file(path)?;
    let text = Zeroizing::new(file.text);
    let material = keys::import(&text, Some(passphrase))?;
    let name = std::path::Path::new(path).file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_else(|| "schluessel".into());
    let mut session = state.session();
    let directory = session.directory()?;
    let known = directory.snapshot().keys.into_iter().find(|key| key.fingerprint == material.fingerprint).map(|key| key.id);
    let id = match known {
        Some(id) => id,
        None => directory.add_key(NewKey {
            name,
            kind: to_core(material.kind),
            bits: material.bits,
            fingerprint: material.fingerprint,
            public: material.public,
            private: Secret::new(material.private.to_string()),
            origin: KeyOrigin::Imported,
        })?,
    };
    directory.set_host_key(host, &id)?;
    Ok(())
}

#[tauri::command(async)]
pub fn key_inspect(text: String, passphrase: Option<String>) -> CmdResult<Info> {
    let text = Zeroizing::new(text);
    let passphrase = passphrase.map(Zeroizing::new);
    inspect(&text, passphrase.as_ref().map(|p| p.as_str()))
}

#[tauri::command(async)]
pub fn key_import(state: State<'_, AppState>, key: Import, vault: Option<String>) -> CmdResult<Changed> {
    import_in(&state, key, vault.as_deref())
}

#[tauri::command]
pub fn key_rename(state: State<'_, AppState>, id: String, name: String) -> CmdResult<Changed> {
    let mut session = state.session();
    session.directory()?.rename_key(&id, &name)?;
    session.changed(Some(id))
}

#[tauri::command]
pub fn key_delete(state: State<'_, AppState>, id: String) -> CmdResult<Changed> {
    let mut session = state.session();
    session.directory()?.delete_key(&id)?;
    session.changed(None)
}

/// Hinterlegt ein Benutzer-Zertifikat am Schlüssel; ohne Text wird es entfernt. Angenommen wird nur eines,
/// das zu genau diesem Schlüssel gehört.
#[tauri::command]
pub fn key_set_certificate(state: State<'_, AppState>, id: String, text: Option<String>) -> CmdResult<Changed> {
    let mut session = state.session();
    let directory = session.directory()?;
    let certificate = match text.as_deref().map(str::trim).filter(|text| !text.is_empty()) {
        Some(text) => {
            let info = keys::inspect_certificate(text, &directory.key_public(&id)?)?;
            Some(KeyCertificate { text: info.text, key_id: info.key_id, principals: info.principals, valid_after: info.valid_after, valid_before: info.valid_before, authority: info.authority })
        }
        None => None,
    };
    directory.set_key_certificate(&id, certificate)?;
    session.changed(Some(id))
}

/// Schreibt den privaten Schlüssel in eine Datei, die der Nutzer wählt. `None`, wenn der Dialog abgebrochen wurde.
#[tauri::command(async)]
pub fn key_export(app: AppHandle, state: State<'_, AppState>, id: String, passphrase: Option<String>) -> CmdResult<Option<String>> {
    let passphrase = passphrase.map(Zeroizing::new);
    let (name, private) = {
        let mut session = state.session();
        let directory = session.directory()?;
        // Mit Leserecht lässt sich ein Schlüssel benutzen, aber nicht herausgeben (`docs/sync.md`, „Rollen“).
        if directory.role_of(&id) == glowport_core::roster::Role::Read {
            return Err(CmdError::new("read_only", "Mit Leserecht lässt sich der private Schlüssel nicht exportieren"));
        }
        directory.key_private(&id)?
    };
    let text = keys::export(private.expose(), &name, passphrase.as_ref().map(|p| p.as_str()))?;
    // Der Dialog blockiert; währenddessen bleibt der Zustand für andere Befehle frei.
    let Some(chosen) = app.dialog().file().set_file_name(file_name(&name)).blocking_save_file() else {
        return Ok(None);
    };
    let path = chosen.into_path().map_err(|e| CmdError::new("internal", e.to_string()))?;
    std::fs::write(&path, text.as_bytes()).map_err(|e| CmdError::new("internal", e.to_string()))?;
    Ok(Some(path.display().to_string()))
}

/// Ergebnis für einen Host beim Kopieren eines öffentlichen Schlüssels.
#[derive(Clone, Serialize)]
pub struct Deployed {
    host: String,
    /// `added`, `present` oder `failed`.
    outcome: &'static str,
    /// Grund des Scheiterns als Code, den die Oberfläche übersetzt.
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<&'static str>,
}

/// Trägt den Schlüssel auf einem Host ein. Angemeldet wird mit dem, was für den Host hinterlegt ist, ohne Rückfragen;
/// der Schlüssel des Servers muss schon bekannt sein.
async fn deploy_to(app: &AppHandle, host_id: &str, command: &str) -> Result<Installed, &'static str> {
    let state = app.state::<AppState>();
    let connect = connect_chain(state.session().directory().map_err(|_| "locked")?, host_id).map_err(|_| "not_found")?;
    // Das gilt für jeden Server auf dem Weg, auch für die Sprung-Server.
    let trusted = |host: &str, port: u16, shown: &glowport_net::HostKey| state.session().directory().is_ok_and(|d| d.judge_host_key(host, port, &shown.openssh) == Verdict::Trusted);
    match glowport_net::execute(&connect, command, trusted).await {
        Ok(output) => keys::install_outcome(&output.stdout).ok_or("unsupported"),
        Err(End::AuthFailed) => Err("auth_failed"),
        Err(End::HostKeyRejected) => Err("host_key"),
        Err(_) => Err("connect_failed"),
    }
}

/// Kopiert den öffentlichen Schlüssel nacheinander auf die Hosts und meldet jedes Ergebnis über `results`.
/// Mit `adopt` melden sich die Hosts, bei denen es geklappt hat, künftig mit diesem Schlüssel an.
#[tauri::command]
pub async fn key_deploy(app: AppHandle, id: String, hosts: Vec<String>, adopt: bool, results: Channel<Deployed>) -> CmdResult<()> {
    let public = app.state::<AppState>().session().directory()?.key_public(&id)?;
    let (body, comment) = public.rsplit_once(' ').unwrap_or((public.as_str(), ""));
    let command = keys::install_command(body, comment)?;
    let mut adopted = false;
    for host in hosts {
        let result = deploy_to(&app, &host, &command).await;
        if adopt && result.is_ok() {
            adopted |= app.state::<AppState>().session().directory().is_ok_and(|d| d.set_host_key(&host, &id).unwrap_or(false));
        }
        let (outcome, message) = match result {
            Ok(Installed::Added) => ("added", None),
            Ok(Installed::Present) => ("present", None),
            Err(reason) => ("failed", Some(reason)),
        };
        let _ = results.send(Deployed { host, outcome, message });
    }
    if adopted {
        emit_snapshot(&app);
    }
    Ok(())
}

#[derive(Serialize)]
pub struct AgentKeyView {
    comment: String,
    /// Art und Länge zum Anzeigen, etwa „Ed25519“.
    kind: String,
    fingerprint: String,
}

/// Ein SSH-Agent auf diesem Rechner und die Schlüssel, die er anbietet.
#[derive(Serialize)]
pub struct AgentView {
    /// `openssh` (Windows, 1Password, Bitwarden) oder `pageant`.
    kind: &'static str,
    running: bool,
    keys: Vec<AgentKeyView>,
}

#[tauri::command]
pub async fn agent_list() -> Vec<AgentView> {
    agent::list(&Agents::system())
        .await
        .into_iter()
        .map(|found| AgentView {
            kind: match found.kind {
                agent::Kind::OpenSsh => "openssh",
                agent::Kind::Pageant => "pageant",
            },
            running: found.running,
            keys: found.keys.into_iter().map(|k| AgentKeyView { comment: k.comment, kind: k.label, fingerprint: k.fingerprint }).collect(),
        })
        .collect()
}

/// Vertraut einer Zertifizierungsstelle für Server. `key` ist ihr öffentlicher Schlüssel als Zeile im OpenSSH-Format.
#[tauri::command]
pub fn authority_add(state: State<'_, AppState>, name: String, pattern: String, key: String) -> CmdResult<Changed> {
    let info = keys::inspect_public(&key)?;
    let mut session = state.session();
    let id = session.directory()?.add_authority(NewAuthority { name, pattern, label: info.label, fingerprint: info.fingerprint, public: info.public })?;
    session.changed(Some(id))
}

#[tauri::command]
pub fn authority_delete(state: State<'_, AppState>, id: String) -> CmdResult<Changed> {
    let mut session = state.session();
    session.directory()?.delete_authority(&id)?;
    session.changed(None)
}

#[tauri::command]
pub fn identity_save(state: State<'_, AppState>, identity: IdentityInput, vault: Option<String>) -> CmdResult<Changed> {
    let mut session = state.session();
    let id = session.directory()?.in_vault(vault.as_deref(), |directory| directory.save_identity(identity))?;
    session.changed(Some(id))
}

#[tauri::command]
pub fn identity_delete(state: State<'_, AppState>, id: String) -> CmdResult<Changed> {
    let mut session = state.session();
    session.directory()?.delete_identity(&id)?;
    session.changed(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::tests::Temp;
    use serde_json::{json, Value};

    const ENCRYPTED: &str = include_str!("../../crates/net/tests/keys/openssh_ed25519_enc");
    const FINGERPRINT: &str = "SHA256:+mcbLMkgoIlEAnnSBVbTyfVSZUNm5w/PZWj1l+QQtwg";

    fn code<T>(result: CmdResult<T>) -> &'static str {
        result.err().map_or("kein Fehler", |e| e.code())
    }

    fn data(changed: &Changed) -> Value {
        serde_json::to_value(changed).unwrap()["data"].clone()
    }

    #[test]
    fn a_key_file_is_adopted_once_and_the_host_signs_in_with_it() {
        let temp = Temp::new("adopt");
        let state = temp.state();
        state.session().create("lang genug").unwrap();
        let host = |name: &str| {
            let input = serde_json::from_value(json!({ "name": name, "address": "10.0.0.1", "group": null, "color": null, "os": null, "own": { "keyFile": "C:/schluessel" } })).unwrap();
            state.session().directory().unwrap().save_host(input).unwrap()
        };
        let (first, second) = (host("web-01"), host("web-02"));
        let file = concat!(env!("CARGO_MANIFEST_DIR"), "/../crates/net/tests/keys/openssh_ed25519_enc");

        assert_eq!(code(adopt_file(&state, file, "falsch", &first)), "wrong_passphrase");
        assert_eq!(code(adopt_file(&state, "Z:/gibt/es/nicht", "geheim", &first)), "key_unreadable");
        adopt_file(&state, file, "geheim", &first).unwrap();
        adopt_file(&state, file, "geheim", &second).unwrap();

        let snapshot = serde_json::to_value(state.session().directory().unwrap().snapshot()).unwrap();
        let keys = snapshot["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1, "derselbe Schlüssel wird nicht doppelt angelegt");
        assert_eq!((keys[0]["name"].as_str(), keys[0]["fingerprint"].as_str(), keys[0]["origin"].as_str()), (Some("openssh_ed25519_enc"), Some(FINGERPRINT), Some("imported")));
        for host in snapshot["hosts"].as_array().unwrap() {
            assert_eq!(host["own"]["key"], keys[0]["id"], "beide Hosts melden sich mit dem Schlüssel aus dem Tresor an");
        }
        assert!(!snapshot.to_string().contains("PRIVATE KEY"));
    }

    #[test]
    fn keys_are_generated_imported_and_reach_the_surface_without_their_private_part() {
        let temp = Temp::new("keyring");
        let state = temp.state();
        assert_eq!(code(generate(&state, Generate { name: "x".into(), kind: KeyKind::Ed25519, bits: 256 })), "locked");
        state.session().create("lang genug").unwrap();

        let made = generate(&state, Generate { name: "arbeit".into(), kind: KeyKind::Ed25519, bits: 256 }).unwrap();
        let keys = data(&made)["keys"].clone();
        assert_eq!((keys[0]["name"].as_str(), keys[0]["kind"].as_str(), keys[0]["bits"].as_u64(), keys[0]["origin"].as_str()), (Some("arbeit"), Some("ed25519"), Some(256), Some("generated")));
        assert!(keys[0]["publicKey"].as_str().unwrap().starts_with("ssh-ed25519 ") && keys[0]["publicKey"].as_str().unwrap().ends_with(" arbeit"));
        assert!(!serde_json::to_string(&made).unwrap().contains("PRIVATE"));
        assert_eq!(code(generate(&state, Generate { name: "x".into(), kind: KeyKind::Rsa, bits: 1024 })), "key_size");
        assert_eq!(code(generate(&state, Generate { name: " ".into(), kind: KeyKind::Ed25519, bits: 256 })), "invalid");

        // Importieren: erst ansehen, dann mit Passphrase übernehmen.
        let locked = inspect(ENCRYPTED, None).unwrap();
        assert_eq!(serde_json::to_value(&locked).unwrap(), json!({ "kind": "ed25519", "bits": 256, "fingerprint": FINGERPRINT, "encrypted": true, "format": "openssh", "comment": "" }));
        assert_eq!(code(inspect("Hallo", None)), "key_unreadable");
        let import_with = |passphrase: Option<&str>| import(&state, Import { name: "alt".into(), text: ENCRYPTED.into(), passphrase: passphrase.map(Into::into) });
        assert_eq!(code(import_with(None)), "passphrase_required");
        assert_eq!(code(import_with(Some("falsch"))), "wrong_passphrase");
        let imported = import_with(Some("geheim")).unwrap();
        let keys = data(&imported)["keys"].clone();
        assert_eq!((keys[0]["name"].as_str(), keys[0]["fingerprint"].as_str(), keys[0]["origin"].as_str()), (Some("alt"), Some(FINGERPRINT), Some("imported")));
        assert_eq!(keys.as_array().unwrap().len(), 2);

        // Im Tresor liegt der importierte Schlüssel ohne Passphrase, der Export kann eine neue setzen.
        let id = keys[0]["id"].as_str().unwrap().to_string();
        let (name, private) = state.session().directory().unwrap().key_private(&id).unwrap();
        assert!(!keys::inspect(private.expose(), None).unwrap().encrypted);
        let exported = keys::export(private.expose(), &name, Some("neu")).unwrap();
        assert_eq!(keys::import(&exported, Some("neu")).unwrap().fingerprint, FINGERPRINT);
    }

    #[test]
    fn export_file_names_are_harmless() {
        assert_eq!(file_name("arbeit-2026"), "arbeit-2026");
        assert_eq!(file_name("Mein Schlüssel / Büro"), "Mein_Schl_ssel___B_ro");
        assert_eq!(file_name("../.."), ".._..");
        assert_eq!(file_name("///"), "id_glowport");
    }
}

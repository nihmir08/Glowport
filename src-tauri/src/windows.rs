//! Fenster: das Hauptfenster, eigene Fenster für herausgezogene Tabs, und was sich das Programm über offene Tabs
//! merkt, um sie nach einem Abbruch wieder anzubieten. Dazu die Dateidialoge für Farbschemata und Hintergrundbild.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Mutex, MutexGuard,
    },
    thread,
    time::Duration,
};

use serde::Serialize;
use serde_json::{json, Value};
use tauri::{
    ipc::Response,
    window::{Color, Effect, EffectsBuilder},
    AppHandle, Emitter, Manager, State, WebviewUrl, WebviewWindow, WebviewWindowBuilder, Window,
};
use tauri_plugin_dialog::DialogExt;

use crate::{
    app::{CmdError, CmdResult},
    sessions,
};

pub const MAIN: &str = "main";
const TAB_PREFIX: &str = "tab-";
const RESTORE_FILE: &str = "open-tabs.json";
const RESTORE_TEMP: &str = "open-tabs.json.neu";
/// Hintergrund des Fensters, bis die Oberfläche geladen ist: dieselbe Farbe wie ihr dunkler Grund.
const BACKDROP: Color = Color(7, 7, 12, 255);
/// So lange darf die Oberfläche brauchen, bis sie sich fertig meldet. Danach zeigt sich das Fenster von selbst:
/// Ein Programm, dessen Oberfläche nicht lädt, soll nicht unsichtbar bleiben.
const REVEAL_AFTER: Duration = Duration::from_secs(3);
const MAX_TEXT_FILE: u64 = 2 * 1024 * 1024;
const MAX_IMAGE: u64 = 24 * 1024 * 1024;
const IMAGE_TYPES: [(&str, &str); 6] = [("png", "image/png"), ("jpg", "image/jpeg"), ("jpeg", "image/jpeg"), ("webp", "image/webp"), ("gif", "image/gif"), ("bmp", "image/bmp")];

#[derive(Default)]
pub struct Desk {
    next: AtomicU64,
    /// Tabs, die einem neuen Fenster mitgegeben wurden und auf dessen Abholung warten.
    payloads: Mutex<HashMap<String, Value>>,
    /// Offene Tabs je Fenster, so wie sie die Oberfläche zuletzt gemeldet hat.
    open: Mutex<BTreeMap<String, Vec<Value>>>,
    /// Die Tabs vom letzten Mal wurden in diesem Lauf schon angeboten.
    offered: AtomicBool,
    /// Durchscheinendes Fenster, mit dem dieser Lauf gestartet ist: „mica“, „acrylic“ oder leer.
    effect: Mutex<String>,
    /// Fenster, die schon zu sehen sind. Die übrigen warten darauf, dass ihre Oberfläche steht.
    revealed: Mutex<HashSet<String>>,
}

fn guard<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn io_error(error: impl ToString) -> CmdError {
    CmdError::new("io", error.to_string())
}

fn data_dir(app: &AppHandle) -> CmdResult<PathBuf> {
    crate::data_dir(app).map_err(io_error)
}

impl Desk {
    pub fn effect(&self) -> String {
        guard(&self.effect).clone()
    }
}

/// Der Fenster-Effekt aus den Einstellungen. Er gilt ab dem nächsten Start, weil ein Fenster nur beim Anlegen
/// durchscheinend werden kann.
fn wanted_effect(dir: &Path) -> Option<Effect> {
    let settings = crate::settings::load(dir).ok().flatten()?;
    match settings.get("windowEffect")?.as_str()? {
        "mica" => Some(Effect::Mica),
        "acrylic" => Some(Effect::Acrylic),
        _ => None,
    }
}

fn window_builder<'a>(app: &'a AppHandle, label: &str, effect: Option<Effect>) -> WebviewWindowBuilder<'a, tauri::Wry, AppHandle> {
    // Jedes Fenster entsteht unsichtbar und zeigt sich erst, wenn seine Oberfläche steht (siehe `build` und `reveal`).
    let mut builder = WebviewWindowBuilder::new(app, label, WebviewUrl::App("index.html".into())).title(crate::app_name(app)).decorations(false).shadow(true).visible(false);
    // Die portable Fassung hinterlässt nichts außerhalb ihres Ordners: Auch der Webview legt seine Daten dort ab.
    if let (true, Ok(dir)) = (crate::portable(), crate::data_dir(app)) {
        builder = builder.data_directory(dir.join("webview"));
    }
    match effect {
        // Durchscheinend geht nur ohne eigene Hintergrundfarbe; die Oberfläche malt dann selbst halb durchsichtig.
        Some(effect) => builder.transparent(true).effects(EffectsBuilder::new().effect(effect).build()),
        None => builder.background_color(BACKDROP),
    }
}

/// Verhüllt ein Fenster oder enthüllt es. Verhüllt gilt es für Windows als sichtbar, wird gezeichnet und
/// zusammengesetzt, aber nicht angezeigt. Liefert, ob das System mitgemacht hat.
#[cfg(windows)]
fn cloak(window: &WebviewWindow, hidden: bool) -> bool {
    use windows_sys::Win32::Graphics::Dwm::{DwmSetWindowAttribute, DWMWA_CLOAK};
    let Ok(hwnd) = window.hwnd() else { return false };
    let value = i32::from(hidden);
    // SAFETY: Der Griff gehört einem Fenster dieses Prozesses; übergeben wird ein BOOL samt seiner Größe.
    unsafe { DwmSetWindowAttribute(hwnd.0.cast(), DWMWA_CLOAK as u32, std::ptr::from_ref(&value).cast(), size_of::<i32>() as u32) == 0 }
}

/// Baut ein Fenster, das erst zu sehen ist, wenn seine Oberfläche steht.
///
/// Ein Fenster, das sofort erscheint, ist eine halbe Sekunde lang leer: Windows blendet die leere Fläche über das
/// ein, was dahinter liegt, dann zeichnet der Webview sein erstes, graues Bild, und erst danach kommt die
/// Oberfläche. Deshalb wird das Fenster unter Windows verhüllt geöffnet: Der Webview lädt und zeichnet wie in
/// einem sichtbaren Fenster, und `reveal` nimmt die Hülle ab, sobald alles fertig ist. Anderswo bleibt es bis
/// dahin versteckt.
fn build(builder: WebviewWindowBuilder<'_, tauri::Wry, AppHandle>) -> tauri::Result<WebviewWindow> {
    let window = builder.build()?;
    #[cfg(windows)]
    {
        // Lässt sich das Fenster nicht verhüllen, bleibt es versteckt, bis die Oberfläche sich meldet.
        if cloak(&window, true) {
            let _ = window.show();
        }
    }
    let waiting = window.clone();
    thread::spawn(move || {
        thread::sleep(REVEAL_AFTER);
        reveal(&waiting);
    });
    Ok(window)
}

/// Zeigt ein Fenster, das auf seine Oberfläche gewartet hat. Ein zweiter Aufruf tut nichts mehr: Er würde einem
/// anderen Programm die Tastatur nehmen.
fn reveal(window: &WebviewWindow) {
    if !guard(&window.app_handle().state::<Desk>().revealed).insert(window.label().to_string()) {
        return;
    }
    #[cfg(windows)]
    cloak(window, false);
    if !window.is_visible().unwrap_or(true) {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

/// Die Oberfläche eines Fensters steht: Ab jetzt ist es zu sehen.
#[tauri::command]
pub fn window_ready(window: WebviewWindow) {
    reveal(&window);
}

/// Legt das Hauptfenster an. Es steht nicht in `tauri.conf.json`, weil der Effekt aus den Einstellungen es prägt.
pub fn create_main(app: &AppHandle) -> tauri::Result<WebviewWindow> {
    let effect = crate::data_dir(app).ok().and_then(|dir| wanted_effect(&dir));
    *guard(&app.state::<Desk>().effect) = match effect {
        Some(Effect::Mica) => "mica".into(),
        Some(Effect::Acrylic) => "acrylic".into(),
        _ => String::new(),
    };
    build(window_builder(app, MAIN, effect).inner_size(1360.0, 860.0).min_inner_size(940.0, 600.0).center())
}

/// Das Fenster unter dem Mauszeiger, außer `except`.
fn window_at_cursor(app: &AppHandle, except: &str) -> Option<String> {
    let cursor = app.cursor_position().ok()?;
    app.webview_windows().into_iter().find_map(|(label, window)| {
        let (position, size) = (window.outer_position().ok()?, window.outer_size().ok()?);
        let inside = cursor.x >= f64::from(position.x) && cursor.y >= f64::from(position.y) && cursor.x < f64::from(position.x) + f64::from(size.width) && cursor.y < f64::from(position.y) + f64::from(size.height);
        (label != except && inside && window.is_visible().unwrap_or(false) && !window.is_minimized().unwrap_or(true)).then_some(label)
    })
}

/// Gibt einem anderen Fenster einen Tab samt seiner laufenden Sitzungen.
fn adopt(app: &AppHandle, target: &str, tab: Value, sessions: &[u64]) {
    sessions::hand_over(app, sessions, target);
    let _ = app.emit("adopt-tab", json!({ "window": target, "tab": tab }));
    if let Some(window) = app.get_webview_window(target) {
        let _ = window.set_focus();
    }
}

/// Verlegt einen Tab in ein anderes Fenster. `sessions` nennt seine laufenden Sitzungen; sie müssen vorher mit
/// `session_hold` angehalten sein. `to` bestimmt das Ziel: ein bestimmtes Fenster, sonst (mit `at_cursor`) das
/// Fenster unter dem Mauszeiger, sonst ein neues.
#[tauri::command]
pub async fn window_move(app: AppHandle, window: Window, tab: Value, sessions: Vec<u64>, to: Option<String>, at_cursor: bool) -> CmdResult<()> {
    let source = window.label().to_string();
    let target = to.filter(|label| app.get_webview_window(label).is_some()).or_else(|| if at_cursor { window_at_cursor(&app, &source) } else { None });
    if let Some(target) = target {
        adopt(&app, &target, tab, &sessions);
        return Ok(());
    }

    let desk = app.state::<Desk>();
    let label = format!("{TAB_PREFIX}{}", desk.next.fetch_add(1, Ordering::Relaxed) + 1);
    guard(&desk.payloads).insert(label.clone(), tab);
    sessions::hand_over(&app, &sessions, &label);
    let effect = match desk.effect().as_str() {
        "mica" => Some(Effect::Mica),
        "acrylic" => Some(Effect::Acrylic),
        _ => None,
    };
    let mut builder = window_builder(&app, &label, effect).inner_size(1040.0, 680.0).min_inner_size(640.0, 400.0).initialization_script("window.__GLOWPORT_DETACHED__ = true;");
    // Beim Herausziehen entsteht das Fenster dort, wo losgelassen wurde; sonst versetzt zum bisherigen.
    let scale = window.scale_factor().unwrap_or(1.0);
    let place = if at_cursor { app.cursor_position().ok().map(|c| (c.x / scale - 120.0, c.y / scale - 24.0)) } else { window.outer_position().ok().map(|p| (f64::from(p.x) / scale + 48.0, f64::from(p.y) / scale + 48.0)) };
    if let Some((x, y)) = place {
        builder = builder.position(x, y);
    }
    build(builder).map(drop).map_err(|e| {
        // Ohne Fenster bliebe der Tab unsichtbar: zurück an den Absender.
        guard(&desk.payloads).remove(&label);
        sessions::hand_over(&app, &sessions, &source);
        CmdError::new("window_failed", e.to_string())
    })
}

/// Der Tab, mit dem dieses Fenster geöffnet wurde. Liefert ihn nur einmal.
#[tauri::command]
pub fn window_payload(window: Window, desk: State<'_, Desk>) -> Option<Value> {
    guard(&desk.payloads).remove(window.label())
}

fn write_restore(dir: &Path, open: &BTreeMap<String, Vec<Value>>) -> io::Result<()> {
    let path = dir.join(RESTORE_FILE);
    if open.values().all(Vec::is_empty) {
        return match fs::remove_file(path) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        };
    }
    fs::create_dir_all(dir)?;
    let temp = dir.join(RESTORE_TEMP);
    let mut file = fs::File::create(&temp)?;
    file.write_all(serde_json::to_string(open)?.as_bytes())?;
    drop(file);
    fs::rename(temp, path)
}

/// Liest die Tabs vom letzten Mal, alle Fenster zusammen, das Hauptfenster zuerst. Eine unlesbare Datei zählt als leer.
fn read_restore(dir: &Path) -> Vec<Value> {
    let Ok(text) = fs::read_to_string(dir.join(RESTORE_FILE)) else { return Vec::new() };
    let Ok(mut open) = serde_json::from_str::<BTreeMap<String, Vec<Value>>>(&text) else { return Vec::new() };
    let mut tabs = open.remove(MAIN).unwrap_or_default();
    tabs.extend(open.into_values().flatten());
    tabs
}

/// Die Tabs, die beim letzten Mal offen waren, falls Glowport nicht ordentlich beendet wurde. Nur das Hauptfenster
/// bekommt sie, und nur einmal je Lauf.
#[tauri::command(async)]
pub fn restore_load(app: AppHandle, window: Window, desk: State<'_, Desk>) -> CmdResult<Option<Vec<Value>>> {
    if window.label() != MAIN || desk.offered.swap(true, Ordering::Relaxed) {
        return Ok(None);
    }
    let tabs = read_restore(&data_dir(&app)?);
    Ok((!tabs.is_empty()).then_some(tabs))
}

/// Merkt sich die offenen Tabs eines Fensters für den Fall eines Abbruchs.
#[tauri::command(async)]
pub fn restore_save(app: AppHandle, window: Window, desk: State<'_, Desk>, tabs: Vec<Value>) -> CmdResult<()> {
    let mut open = guard(&desk.open);
    open.insert(window.label().to_string(), tabs);
    write_restore(&data_dir(&app)?, &open).map_err(io_error)
}

/// Vergisst die offenen Tabs aller Fenster, damit nach dem Löschen des Tresors nichts mehr angeboten wird.
pub(crate) fn forget_open_tabs(app: &AppHandle) {
    let desk = app.state::<Desk>();
    let mut open = guard(&desk.open);
    open.clear();
    if let Ok(dir) = crate::data_dir(app) {
        let _ = write_restore(&dir, &open);
    }
}

/// Ein Fenster wurde geschlossen: Seine Sitzungen enden, seine Tabs gelten nicht mehr als offen. Mit dem
/// Hauptfenster endet das Programm ordentlich; dann gibt es beim nächsten Start nichts wiederherzustellen.
pub fn closed(app: &AppHandle, label: &str) {
    sessions::close_window(app, label);
    let desk = app.state::<Desk>();
    guard(&desk.payloads).remove(label);
    guard(&desk.revealed).remove(label);
    let mut open = guard(&desk.open);
    if label == MAIN {
        open.clear();
    } else {
        open.remove(label);
    }
    if let Ok(dir) = crate::data_dir(app) {
        let _ = write_restore(&dir, &open);
    }
    drop(open);
    if label == MAIN {
        // Laufende Transfers werden angehalten und zum Fortsetzen vorgemerkt.
        app.state::<crate::transfers::Queue>().0.shutdown();
        app.exit(0);
    }
}

#[derive(Serialize)]
pub struct TextFile {
    name: String,
    text: String,
}

/// Lässt den Nutzer eine Textdatei wählen und liest sie. `accept` nennt die Endungen wie `.json,.itermcolors`.
#[tauri::command(async)]
pub fn pick_text_file(app: AppHandle, accept: String) -> CmdResult<Option<TextFile>> {
    let extensions: Vec<&str> = accept.split(',').map(|e| e.trim().trim_start_matches('.')).filter(|e| !e.is_empty()).collect();
    let mut dialog = app.dialog().file();
    if !extensions.is_empty() {
        dialog = dialog.add_filter(accept.as_str(), &extensions);
    }
    let Some(path) = dialog.blocking_pick_file().and_then(|chosen| chosen.into_path().ok()) else { return Ok(None) };
    if fs::metadata(&path).map_err(io_error)?.len() > MAX_TEXT_FILE {
        return Err(CmdError::new("file_too_large", "Die Datei ist zu groß"));
    }
    let text = String::from_utf8_lossy(&fs::read(&path).map_err(io_error)?).into_owned();
    Ok(Some(TextFile { name: path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(), text }))
}

/// Dateien, die als Hintergrundbild abgelegt sind: `background-<Zahl>.<Endung>` im Datenordner.
fn is_background(name: &str) -> bool {
    name.strip_prefix("background-").and_then(|rest| rest.split_once('.')).is_some_and(|(stamp, extension)| !stamp.is_empty() && stamp.chars().all(|c| c.is_ascii_digit()) && IMAGE_TYPES.iter().any(|(known, _)| *known == extension))
}

/// Lässt den Nutzer ein Bild wählen und legt eine Kopie in den Datenordner. Liefert ihren Dateinamen; ein
/// früheres Bild wird dabei entfernt.
#[tauri::command(async)]
pub fn pick_background(app: AppHandle) -> CmdResult<Option<String>> {
    let extensions: Vec<&str> = IMAGE_TYPES.iter().map(|(extension, _)| *extension).collect();
    let Some(path) = app.dialog().file().add_filter("Bild", &extensions).blocking_pick_file().and_then(|chosen| chosen.into_path().ok()) else { return Ok(None) };
    let extension = path.extension().and_then(|e| e.to_str()).map(str::to_ascii_lowercase).filter(|e| extensions.contains(&e.as_str())).ok_or_else(|| CmdError::new("image_unsupported", "Kein unterstütztes Bildformat"))?;
    if fs::metadata(&path).map_err(io_error)?.len() > MAX_IMAGE {
        return Err(CmdError::new("file_too_large", "Das Bild ist zu groß"));
    }
    let dir = data_dir(&app)?;
    fs::create_dir_all(&dir).map_err(io_error)?;
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis());
    let name = format!("background-{stamp}.{extension}");
    fs::copy(&path, dir.join(&name)).map_err(io_error)?;
    for entry in fs::read_dir(&dir).map_err(io_error)?.filter_map(Result::ok) {
        let other = entry.file_name().to_string_lossy().into_owned();
        if other != name && is_background(&other) {
            let _ = fs::remove_file(entry.path());
        }
    }
    Ok(Some(name))
}

/// Der Inhalt des Hintergrundbilds als rohe Bytes. Die Oberfläche macht daraus eine Adresse für die Anzeige.
#[tauri::command(async)]
pub fn background_read(app: AppHandle, name: String) -> CmdResult<Response> {
    if !is_background(&name) {
        return Err(CmdError::new("not_found", "Kein Hintergrundbild"));
    }
    fs::read(data_dir(&app)?.join(&name)).map(Response::new).map_err(|e| CmdError::new("not_found", e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_tabs_are_remembered_per_window_and_forgotten_when_none_are_left() {
        let dir = std::env::temp_dir().join(format!("glowport-restore-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        assert!(read_restore(&dir).is_empty(), "ohne Datei gibt es nichts wiederherzustellen");

        let mut open = BTreeMap::new();
        open.insert("tab-2".to_string(), vec![json!({ "name": "eigenes Fenster" })]);
        open.insert(MAIN.to_string(), vec![json!({ "name": "erster" }), json!({ "name": "zweiter" })]);
        write_restore(&dir, &open).unwrap();
        let names: Vec<String> = read_restore(&dir).iter().map(|tab| tab["name"].as_str().unwrap().to_string()).collect();
        assert_eq!(names, ["erster", "zweiter", "eigenes Fenster"], "das Hauptfenster zuerst");
        assert!(!dir.join(RESTORE_TEMP).exists());

        open.insert(MAIN.to_string(), Vec::new());
        open.remove("tab-2");
        write_restore(&dir, &open).unwrap();
        assert!(!dir.join(RESTORE_FILE).exists(), "ohne offene Tabs verschwindet die Datei");
        write_restore(&dir, &open).unwrap();

        fs::write(dir.join(RESTORE_FILE), "kein json").unwrap();
        assert!(read_restore(&dir).is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn only_background_images_from_the_data_folder_are_served() {
        assert!(is_background("background-1791224894591.png") && is_background("background-1.jpeg"));
        for name in ["vault.db", "background-.png", "background-12.exe", "background-12.png/../vault.db", "..\\background-1.png", "background-1x.png"] {
            assert!(!is_background(name), "{name}");
        }
    }
}

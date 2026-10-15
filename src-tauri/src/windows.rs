//! Windows: the main window, windows of their own for tabs pulled out, and what the program remembers about open tabs
//! to offer them again after a crash. Plus the file dialogs for color schemes and background image.

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
const RESTORE_TEMP: &str = "open-tabs.json.new";
/// Background of the window until the interface has loaded: the same color as its dark base.
const BACKDROP: Color = Color(7, 7, 12, 255);
/// This long the interface may take until it reports ready. After that the window shows itself:
/// a program whose interface does not load should not stay invisible.
const REVEAL_AFTER: Duration = Duration::from_secs(3);
const MAX_TEXT_FILE: u64 = 2 * 1024 * 1024;
const MAX_IMAGE: u64 = 24 * 1024 * 1024;
const IMAGE_TYPES: [(&str, &str); 6] = [("png", "image/png"), ("jpg", "image/jpeg"), ("jpeg", "image/jpeg"), ("webp", "image/webp"), ("gif", "image/gif"), ("bmp", "image/bmp")];

#[derive(Default)]
pub struct Desk {
    next: AtomicU64,
    /// Tabs that were given to a new window and are waiting for it to pick them up.
    payloads: Mutex<HashMap<String, Value>>,
    /// Open tabs per window, as the interface last reported them.
    open: Mutex<BTreeMap<String, Vec<Value>>>,
    /// The tabs from last time were already offered in this run.
    offered: AtomicBool,
    /// Translucent window this run was started with: “mica”, “acrylic” or empty.
    effect: Mutex<String>,
    /// Windows that can already be seen. The others wait for their interface to be ready.
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

/// The window effect from the settings. It applies from the next start, because a window can only become
/// translucent when it is created.
fn wanted_effect(dir: &Path) -> Option<Effect> {
    let settings = crate::settings::load(dir).ok().flatten()?;
    match settings.get("windowEffect")?.as_str()? {
        "mica" => Some(Effect::Mica),
        "acrylic" => Some(Effect::Acrylic),
        _ => None,
    }
}

fn window_builder<'a>(app: &'a AppHandle, label: &str, effect: Option<Effect>) -> WebviewWindowBuilder<'a, tauri::Wry, AppHandle> {
    // Every window is created invisible and only shows itself when its interface is ready (see `build` and `reveal`).
    let mut builder = WebviewWindowBuilder::new(app, label, WebviewUrl::App("index.html".into())).title(crate::app_name(app)).decorations(false).shadow(true).visible(false);
    // The portable version leaves nothing outside its folder: the webview stores its data there too.
    if let (true, Ok(dir)) = (crate::portable(), crate::data_dir(app)) {
        builder = builder.data_directory(dir.join("webview"));
    }
    match effect {
        // Translucency only works without a background color of its own; the interface then paints half-transparent itself.
        Some(effect) => builder.transparent(true).effects(EffectsBuilder::new().effect(effect).build()),
        None => builder.background_color(BACKDROP),
    }
}

/// Cloaks or uncloaks a window. Cloaked, it counts as visible for Windows, is drawn and
/// composited, but not displayed. Returns whether the system went along.
#[cfg(windows)]
fn cloak(window: &WebviewWindow, hidden: bool) -> bool {
    use windows_sys::Win32::Graphics::Dwm::{DwmSetWindowAttribute, DWMWA_CLOAK};
    let Ok(hwnd) = window.hwnd() else { return false };
    let value = i32::from(hidden);
    // SAFETY: The handle belongs to a window of this process; a BOOL is passed together with its size.
    unsafe { DwmSetWindowAttribute(hwnd.0.cast(), DWMWA_CLOAK as u32, std::ptr::from_ref(&value).cast(), size_of::<i32>() as u32) == 0 }
}

/// Builds a window that can only be seen once its interface is ready.
///
/// A window that appears immediately is empty for half a second: Windows fades the empty area in over
/// what is behind it, then the webview draws its first grey frame, and only after that comes the
/// interface. So under Windows the window is opened cloaked: the webview loads and draws as in
/// a visible window, and `reveal` removes the cloak as soon as everything is ready. Elsewhere it stays
/// hidden until then.
fn build(builder: WebviewWindowBuilder<'_, tauri::Wry, AppHandle>) -> tauri::Result<WebviewWindow> {
    let window = builder.build()?;
    #[cfg(windows)]
    {
        // If the window cannot be cloaked, it stays hidden until the interface reports.
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

/// Shows a window that waited for its interface. A second call does nothing: it would take the keyboard away
/// from another program.
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

/// A window's interface is ready: from now on it can be seen.
#[tauri::command]
pub fn window_ready(window: WebviewWindow) {
    reveal(&window);
}

/// Creates the main window. It is not in `tauri.conf.json`, because the effect from the settings shapes it.
pub fn create_main(app: &AppHandle) -> tauri::Result<WebviewWindow> {
    let effect = crate::data_dir(app).ok().and_then(|dir| wanted_effect(&dir));
    *guard(&app.state::<Desk>().effect) = match effect {
        Some(Effect::Mica) => "mica".into(),
        Some(Effect::Acrylic) => "acrylic".into(),
        _ => String::new(),
    };
    build(window_builder(app, MAIN, effect).inner_size(1360.0, 860.0).min_inner_size(940.0, 600.0).center())
}

/// The window under the mouse pointer, except `except`.
fn window_at_cursor(app: &AppHandle, except: &str) -> Option<String> {
    let cursor = app.cursor_position().ok()?;
    app.webview_windows().into_iter().find_map(|(label, window)| {
        let (position, size) = (window.outer_position().ok()?, window.outer_size().ok()?);
        let inside = cursor.x >= f64::from(position.x) && cursor.y >= f64::from(position.y) && cursor.x < f64::from(position.x) + f64::from(size.width) && cursor.y < f64::from(position.y) + f64::from(size.height);
        (label != except && inside && window.is_visible().unwrap_or(false) && !window.is_minimized().unwrap_or(true)).then_some(label)
    })
}

/// Gives another window a tab together with its running sessions.
fn adopt(app: &AppHandle, target: &str, tab: Value, sessions: &[u64]) {
    sessions::hand_over(app, sessions, target);
    let _ = app.emit("adopt-tab", json!({ "window": target, "tab": tab }));
    if let Some(window) = app.get_webview_window(target) {
        let _ = window.set_focus();
    }
}

/// Moves a tab into another window. `sessions` names its running sessions; they must have been paused
/// with `session_hold` beforehand. `to` determines the destination: a specific window, otherwise (with `at_cursor`) the
/// window under the mouse pointer, otherwise a new one.
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
    // When pulled out, the window appears where it was dropped; otherwise offset from the previous one.
    let scale = window.scale_factor().unwrap_or(1.0);
    let place = if at_cursor { app.cursor_position().ok().map(|c| (c.x / scale - 120.0, c.y / scale - 24.0)) } else { window.outer_position().ok().map(|p| (f64::from(p.x) / scale + 48.0, f64::from(p.y) / scale + 48.0)) };
    if let Some((x, y)) = place {
        builder = builder.position(x, y);
    }
    build(builder).map(drop).map_err(|e| {
        // Without a window the tab would stay invisible: back to the sender.
        guard(&desk.payloads).remove(&label);
        sessions::hand_over(&app, &sessions, &source);
        CmdError::new("window_failed", e.to_string())
    })
}

/// The tab this window was opened with. Returns it only once.
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

/// Reads the tabs from last time, all windows together, the main window first. An unreadable file counts as empty.
fn read_restore(dir: &Path) -> Vec<Value> {
    let Ok(text) = fs::read_to_string(dir.join(RESTORE_FILE)) else { return Vec::new() };
    let Ok(mut open) = serde_json::from_str::<BTreeMap<String, Vec<Value>>>(&text) else { return Vec::new() };
    let mut tabs = open.remove(MAIN).unwrap_or_default();
    tabs.extend(open.into_values().flatten());
    tabs
}

/// The tabs that were open last time, in case Glowport was not quit properly. Only the main window
/// gets them, and only once per run.
#[tauri::command(async)]
pub fn restore_load(app: AppHandle, window: Window, desk: State<'_, Desk>) -> CmdResult<Option<Vec<Value>>> {
    if window.label() != MAIN || desk.offered.swap(true, Ordering::Relaxed) {
        return Ok(None);
    }
    let tabs = read_restore(&data_dir(&app)?);
    Ok((!tabs.is_empty()).then_some(tabs))
}

/// Remembers a window's open tabs in case of a crash.
#[tauri::command(async)]
pub fn restore_save(app: AppHandle, window: Window, desk: State<'_, Desk>, tabs: Vec<Value>) -> CmdResult<()> {
    let mut open = guard(&desk.open);
    open.insert(window.label().to_string(), tabs);
    write_restore(&data_dir(&app)?, &open).map_err(io_error)
}

/// Forgets the open tabs of all windows, so nothing is offered any more after the vault is deleted.
pub(crate) fn forget_open_tabs(app: &AppHandle) {
    let desk = app.state::<Desk>();
    let mut open = guard(&desk.open);
    open.clear();
    if let Ok(dir) = crate::data_dir(app) {
        let _ = write_restore(&dir, &open);
    }
}

/// A window was closed: its sessions end, its tabs no longer count as open. With the
/// main window the program ends properly; then there is nothing to restore on the next start.
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
        // Running transfers are paused and noted for resuming.
        app.state::<crate::transfers::Queue>().0.shutdown();
        app.exit(0);
    }
}

#[derive(Serialize)]
pub struct TextFile {
    name: String,
    text: String,
}

/// Lets the user choose a text file and reads it. `accept` names the extensions like `.json,.itermcolors`.
#[tauri::command(async)]
pub fn pick_text_file(app: AppHandle, accept: String) -> CmdResult<Option<TextFile>> {
    let extensions: Vec<&str> = accept.split(',').map(|e| e.trim().trim_start_matches('.')).filter(|e| !e.is_empty()).collect();
    let mut dialog = app.dialog().file();
    if !extensions.is_empty() {
        dialog = dialog.add_filter(accept.as_str(), &extensions);
    }
    let Some(path) = dialog.blocking_pick_file().and_then(|chosen| chosen.into_path().ok()) else { return Ok(None) };
    if fs::metadata(&path).map_err(io_error)?.len() > MAX_TEXT_FILE {
        return Err(CmdError::new("file_too_large", "The file is too large"));
    }
    let text = String::from_utf8_lossy(&fs::read(&path).map_err(io_error)?).into_owned();
    Ok(Some(TextFile { name: path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(), text }))
}

/// Files stored as background image: `background-<number>.<extension>` in the data folder.
fn is_background(name: &str) -> bool {
    name.strip_prefix("background-").and_then(|rest| rest.split_once('.')).is_some_and(|(stamp, extension)| !stamp.is_empty() && stamp.chars().all(|c| c.is_ascii_digit()) && IMAGE_TYPES.iter().any(|(known, _)| *known == extension))
}

/// Lets the user choose an image and puts a copy into the data folder. Returns its file name; an
/// earlier image is removed in the process.
#[tauri::command(async)]
pub fn pick_background(app: AppHandle) -> CmdResult<Option<String>> {
    let extensions: Vec<&str> = IMAGE_TYPES.iter().map(|(extension, _)| *extension).collect();
    let Some(path) = app.dialog().file().add_filter("Image", &extensions).blocking_pick_file().and_then(|chosen| chosen.into_path().ok()) else { return Ok(None) };
    let extension = path.extension().and_then(|e| e.to_str()).map(str::to_ascii_lowercase).filter(|e| extensions.contains(&e.as_str())).ok_or_else(|| CmdError::new("image_unsupported", "Not a supported image format"))?;
    if fs::metadata(&path).map_err(io_error)?.len() > MAX_IMAGE {
        return Err(CmdError::new("file_too_large", "The image is too large"));
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

/// The background image's content as raw bytes. The interface turns it into an address for display.
#[tauri::command(async)]
pub fn background_read(app: AppHandle, name: String) -> CmdResult<Response> {
    if !is_background(&name) {
        return Err(CmdError::new("not_found", "No background image"));
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
        assert!(read_restore(&dir).is_empty(), "without a file there is nothing to restore");

        let mut open = BTreeMap::new();
        open.insert("tab-2".to_string(), vec![json!({ "name": "eigenes Fenster" })]);
        open.insert(MAIN.to_string(), vec![json!({ "name": "erster" }), json!({ "name": "zweiter" })]);
        write_restore(&dir, &open).unwrap();
        let names: Vec<String> = read_restore(&dir).iter().map(|tab| tab["name"].as_str().unwrap().to_string()).collect();
        assert_eq!(names, ["erster", "zweiter", "eigenes Fenster"], "the main window first");
        assert!(!dir.join(RESTORE_TEMP).exists());

        open.insert(MAIN.to_string(), Vec::new());
        open.remove("tab-2");
        write_restore(&dir, &open).unwrap();
        assert!(!dir.join(RESTORE_FILE).exists(), "without open tabs the file disappears");
        write_restore(&dir, &open).unwrap();

        fs::write(dir.join(RESTORE_FILE), "not json").unwrap();
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

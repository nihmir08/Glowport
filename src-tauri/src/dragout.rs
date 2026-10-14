//! Dateien aus Glowport in den Explorer und in andere Programme ziehen.
//!
//! Windows will dafür Dateien, die es auf diesem Rechner gibt. Was auf diesem PC liegt, lässt sich deshalb sofort
//! ziehen. Was auf einem Server liegt, wird beim Verlassen des Fensters erst in einen Arbeitsordner geholt
//! (`drag_stage`, als gewöhnlicher Transfer) und danach gezogen (`drag_out`), solange die Maustaste gedrückt bleibt.

use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
};

use serde::Serialize;
use tauri::{AppHandle, State, Window};
use tokio::sync::oneshot;

use crate::{
    app::{CmdError, CmdResult},
    files::Place,
    transfers::{self, Queue},
};

/// Bildchen, das beim Ziehen am Mauszeiger hängt.
const BADGE: &[u8] = include_bytes!("../icons/32x32.png");

static NEXT: AtomicU64 = AtomicU64::new(0);

fn staging(app: &AppHandle) -> CmdResult<PathBuf> {
    crate::data_dir(app).map(|dir| dir.join("drag")).map_err(|e| CmdError::new("internal", e))
}

#[derive(Serialize)]
pub struct Staged {
    /// Die Transfers, die die Dateien holen.
    ids: Vec<u64>,
    /// Wo die Dateien danach auf diesem Rechner liegen.
    paths: Vec<String>,
}

/// Holt Dateien und Ordner eines Servers in einen Arbeitsordner, damit sie sich danach aus dem Fenster ziehen lassen.
#[tauri::command]
pub fn drag_stage(app: AppHandle, queue: State<'_, Queue>, place: Place, paths: Vec<String>) -> CmdResult<Staged> {
    if place == Place::Local || paths.is_empty() {
        return Err(CmdError::new("not_supported", "Bereitlegen gibt es nur für Dateien eines Servers"));
    }
    // Jeder Zug bekommt seinen eigenen Ordner, damit gleiche Namen aus verschiedenen Zügen sich nicht überschreiben.
    let dir = staging(&app)?.join(format!("{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed) + 1));
    std::fs::create_dir_all(&dir).map_err(|e| CmdError::new("internal", e.to_string()))?;
    let (ids, staged) = transfers::stage(&app, &queue, &place, paths, &dir);
    Ok(Staged { ids, paths: staged })
}

/// Ist die Maustaste gedrückt, mit der gezogen wird? Ohne sie würde Windows sofort dort ablegen, wo der Zeiger steht.
#[cfg(windows)]
fn button_down() -> bool {
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetAsyncKeyState, VK_LBUTTON, VK_RBUTTON};
    use windows_sys::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_SWAPBUTTON};
    // SAFETY: Beide Aufrufe lesen nur den Zustand des Systems und nehmen keine Zeiger.
    unsafe {
        // Bei vertauschten Maustasten ist die rechte die Haupttaste.
        let key = if GetSystemMetrics(SM_SWAPBUTTON) != 0 { VK_RBUTTON } else { VK_LBUTTON };
        GetAsyncKeyState(i32::from(key)) < 0
    }
}

#[cfg(not(windows))]
fn button_down() -> bool {
    true
}

/// Beginnt das Ziehen der genannten Dateien dieses Rechners aus dem Fenster heraus. Die Maustaste muss noch
/// gedrückt sein; sonst geschieht nichts. Liefert, ob die Dateien irgendwo abgelegt wurden.
#[tauri::command]
pub async fn drag_out(window: Window, paths: Vec<String>) -> CmdResult<bool> {
    let files: Vec<PathBuf> = paths.iter().map(PathBuf::from).collect();
    if files.is_empty() || files.iter().any(|file| !file.is_absolute() || !file.exists()) {
        return Err(CmdError::new("no_such_file", "Die Datei gibt es auf diesem Rechner nicht"));
    }
    let (done, outcome) = oneshot::channel::<Result<bool, String>>();
    let done = std::sync::Arc::new(Mutex::new(Some(done)));
    let report = move |result: Result<bool, String>| {
        if let Some(done) = done.lock().ok().and_then(|mut slot| slot.take()) {
            let _ = done.send(result);
        }
    };
    let source = window.clone();
    // Ziehen und Ablegen läuft bei Windows in dem Thread, dem das Fenster gehört.
    window
        .run_on_main_thread(move || {
            if !button_down() {
                return report(Ok(false));
            }
            let finished = report.clone();
            let started = drag::start_drag(&source, drag::DragItem::Files(files), drag::Image::Raw(BADGE.to_vec()), move |result, _| finished(Ok(matches!(result, drag::DragResult::Dropped))), drag::Options::default());
            if let Err(error) = started {
                report(Err(error.to_string()));
            }
        })
        .map_err(|e| CmdError::new("internal", e.to_string()))?;
    match outcome.await {
        Ok(Ok(dropped)) => Ok(dropped),
        Ok(Err(message)) => Err(CmdError::new("drag_failed", message)),
        Err(_) => Ok(false),
    }
}

/// Beim Start: Was vom letzten Mal im Arbeitsordner liegt, wird nicht mehr gebraucht.
pub fn clean(app: &AppHandle) {
    if let Ok(dir) = staging(app) {
        let _ = std::fs::remove_dir_all(dir);
    }
}

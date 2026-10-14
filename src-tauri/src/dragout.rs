//! Dragging files from Glowport into Explorer and other programs.
//!
//! Windows wants files that exist on this machine for that. What lies on this PC can therefore be dragged
//! at once. What lies on a server is first fetched into a working folder when leaving the window
//! (`drag_stage`, as an ordinary transfer) and then dragged (`drag_out`) while the mouse button stays pressed.

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

/// Little picture hanging at the mouse pointer while dragging.
const BADGE: &[u8] = include_bytes!("../icons/32x32.png");

static NEXT: AtomicU64 = AtomicU64::new(0);

fn staging(app: &AppHandle) -> CmdResult<PathBuf> {
    crate::data_dir(app).map(|dir| dir.join("drag")).map_err(|e| CmdError::new("internal", e))
}

#[derive(Serialize)]
pub struct Staged {
    /// The transfers that fetch the files.
    ids: Vec<u64>,
    /// Where the files lie on this machine afterwards.
    paths: Vec<String>,
}

/// Fetches a server's files and folders into a working folder so they can then be dragged out of the window.
#[tauri::command]
pub fn drag_stage(app: AppHandle, queue: State<'_, Queue>, place: Place, paths: Vec<String>) -> CmdResult<Staged> {
    if place == Place::Local || paths.is_empty() {
        return Err(CmdError::new("not_supported", "Bereitlegen gibt es nur für Dateien eines Servers"));
    }
    // Every drag gets its own folder, so equal names from different drags do not overwrite each other.
    let dir = staging(&app)?.join(format!("{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed) + 1));
    std::fs::create_dir_all(&dir).map_err(|e| CmdError::new("internal", e.to_string()))?;
    let (ids, staged) = transfers::stage(&app, &queue, &place, paths, &dir);
    Ok(Staged { ids, paths: staged })
}

/// Is the mouse button used for dragging pressed? Without it Windows would drop at once wherever the pointer is.
#[cfg(windows)]
fn button_down() -> bool {
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetAsyncKeyState, VK_LBUTTON, VK_RBUTTON};
    use windows_sys::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_SWAPBUTTON};
    // SAFETY: both calls only read the system's state and take no pointers.
    unsafe {
        // With swapped mouse buttons the right one is the primary button.
        let key = if GetSystemMetrics(SM_SWAPBUTTON) != 0 { VK_RBUTTON } else { VK_LBUTTON };
        GetAsyncKeyState(i32::from(key)) < 0
    }
}

#[cfg(not(windows))]
fn button_down() -> bool {
    true
}

/// Starts dragging the named files of this machine out of the window. The mouse button must still be
/// pressed; otherwise nothing happens. Returns whether the files were dropped somewhere.
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
    // On Windows, drag and drop runs on the thread that owns the window.
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

/// At startup: what is left in the working folder from last time is no longer needed.
pub fn clean(app: &AppHandle) {
    if let Ok(dir) = staging(app) {
        let _ = std::fs::remove_dir_all(dir);
    }
}

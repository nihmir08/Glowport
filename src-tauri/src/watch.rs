//! Dateien vom Server im eigenen Programm bearbeiten: Die Datei wird in einen Arbeitsordner geholt, dort geöffnet
//! und nach jedem Speichern wieder hochgeladen, bis der Nutzer das beendet.

use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex, MutexGuard,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};

use crate::{
    app::{CmdError, CmdResult},
    files::{self, Place},
    sessions,
};

/// Größer darf eine Datei nicht sein, um so bearbeitet zu werden.
const MAX_EDITED: u64 = 64 * 1024 * 1024;
const LOOK_EVERY: Duration = Duration::from_millis(900);

#[derive(Default)]
pub struct Watches {
    next: AtomicU64,
    open: Mutex<Vec<Watch>>,
}

struct Watch {
    view: Watched,
    local: PathBuf,
    stop: Arc<AtomicBool>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Watched {
    id: u64,
    name: String,
    /// „web-01:/etc/nginx/nginx.conf“
    origin: String,
    uploads: u32,
    /// Millisekunden seit 1970.
    uploaded_at: Option<u64>,
    /// Fehlercode, wenn das letzte Hochladen gescheitert ist.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'static str>,
}

impl Watches {
    fn open(&self) -> MutexGuard<'_, Vec<Watch>> {
        self.open.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn views(&self) -> Vec<Watched> {
        self.open().iter().map(|watch| watch.view.clone()).collect()
    }
}

fn publish(app: &AppHandle) {
    let _ = app.emit("watched", app.state::<Watches>().views());
}

/// Öffnet eine Datei mit einem Programm; ohne Angabe mit dem, das das System für sie vorsieht.
fn launch(program: Option<&str>, file: &PathBuf) -> std::io::Result<()> {
    let mut command = match program.map(str::trim).filter(|p| !p.is_empty()) {
        Some(program) => std::process::Command::new(program),
        // Der Explorer öffnet eine Datei mit ihrem Standardprogramm, ohne dass eine Shell den Pfad deutet.
        None if cfg!(windows) => std::process::Command::new("explorer.exe"),
        None if cfg!(target_os = "macos") => std::process::Command::new("open"),
        None => std::process::Command::new("xdg-open"),
    };
    command.arg(file).spawn().map(drop)
}

fn changed(file: &PathBuf) -> Option<SystemTime> {
    std::fs::metadata(file).and_then(|meta| meta.modified()).ok()
}

/// Holt eine Datei vom Server, öffnet sie im Programm des Nutzers und lädt sie nach jedem Speichern wieder hoch.
#[tauri::command]
pub async fn watch_open(app: AppHandle, place: Place, path: String, program: Option<String>) -> CmdResult<()> {
    if place == Place::Local {
        return launch(program.as_deref(), &PathBuf::from(&path)).map_err(|e| CmdError::new("open_failed", e.to_string()));
    }
    let remote = files::remote(&app, &place).await?;
    let (bytes, longer) = remote.read(&path, MAX_EDITED).await?;
    if longer {
        return Err(CmdError::new("file_too_large", "Die Datei ist zu groß"));
    }
    let name = path.rsplit('/').next().filter(|name| !name.is_empty() && !name.contains(['\\', ':'])).ok_or_else(|| CmdError::invalid("name_required"))?.to_string();
    let watches = app.state::<Watches>();
    let id = watches.next.fetch_add(1, Ordering::Relaxed) + 1;
    // Jede Datei bekommt ihren eigenen Ordner, damit gleiche Namen verschiedener Server sich nicht überschreiben.
    let dir = crate::data_dir(&app).map_err(|e| CmdError::new("internal", e))?.join("edit").join(id.to_string());
    std::fs::create_dir_all(&dir).and_then(|()| std::fs::write(dir.join(&name), bytes)).map_err(|e| CmdError::new("internal", e.to_string()))?;
    let local = dir.join(&name);
    launch(program.as_deref(), &local).map_err(|e| CmdError::new("open_failed", e.to_string()))?;

    let label = match &place {
        Place::Session { id } => sessions::origin(&app, *id).map(|(_, label)| label).unwrap_or_default(),
        Place::Host { id } => app.state::<crate::app::AppState>().session().directory().ok().and_then(|d| d.host_name(id)).unwrap_or_default(),
        Place::Ftp { host, .. } => host.clone(),
        Place::Local => String::new(),
    };
    let stop = Arc::new(AtomicBool::new(false));
    watches.open().push(Watch { view: Watched { id, name, origin: format!("{label}:{path}"), uploads: 0, uploaded_at: None, error: None }, local: local.clone(), stop: stop.clone() });
    publish(&app);

    let mut seen = changed(&local);
    tauri::async_runtime::spawn(async move {
        while !stop.load(Ordering::Relaxed) {
            tokio::time::sleep(LOOK_EVERY).await;
            let now = changed(&local);
            if now.is_none() || now == seen {
                continue;
            }
            seen = now;
            // Manche Programme schreiben in zwei Schritten; kurz warten, bis die Datei steht.
            tokio::time::sleep(Duration::from_millis(150)).await;
            let result = match std::fs::read(&local) {
                Ok(bytes) => match files::remote(&app, &place).await {
                    Ok(remote) => remote.write(&path, &bytes).await.map_err(|error| error.code()),
                    Err(error) => Err(error.code()),
                },
                Err(_) => continue,
            };
            if let Some(watch) = app.state::<Watches>().open().iter_mut().find(|watch| watch.view.id == id) {
                watch.view.error = result.err();
                if watch.view.error.is_none() {
                    watch.view.uploads += 1;
                    watch.view.uploaded_at = SystemTime::now().duration_since(UNIX_EPOCH).ok().map(|d| d.as_millis() as u64);
                }
            }
            if result.err() == Some("not_connected") {
                files::forget(&app, &place).await;
            }
            publish(&app);
        }
    });
    Ok(())
}

/// Beendet das Beobachten einer Datei und räumt ihre Arbeitskopie weg.
#[tauri::command]
pub fn watch_stop(app: AppHandle, watches: State<'_, Watches>, id: u64) {
    let gone: Vec<Watch> = {
        let mut open = watches.open();
        let (gone, kept) = std::mem::take(&mut *open).into_iter().partition(|watch| watch.view.id == id);
        *open = kept;
        gone
    };
    for watch in gone {
        watch.stop.store(true, Ordering::Relaxed);
        if let Some(dir) = watch.local.parent() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
    publish(&app);
}

#[tauri::command]
pub fn watch_list(watches: State<'_, Watches>) -> Vec<Watched> {
    watches.views()
}

/// Beim Start: Arbeitskopien vom letzten Mal sind verwaist und werden entfernt.
pub fn clean(app: &AppHandle) {
    if let Ok(dir) = crate::data_dir(app) {
        let _ = std::fs::remove_dir_all(dir.join("edit"));
    }
}

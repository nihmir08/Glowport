//! Updates: nachsehen, ob es eine neuere Version gibt, und sie nach Rückfrage laden, prüfen und installieren.
//!
//! Ob eine Fassung das kann, entscheidet sich beim Bauen: Nur wenn dabei eine Adresse und der öffentliche Schlüssel
//! für die Signatur mitgegeben wurden (`GLOWPORT_UPDATE_URL`, `GLOWPORT_UPDATE_PUBKEY`), sucht Glowport je nach
//! Updates. Ohne beides gibt es in der Oberfläche nichts dazu, und kein Aufruf geht ins Netz. Die portable Fassung
//! aktualisiert sich nie selbst: Sie hat keinen Installer, der sie ersetzen könnte.

use serde::Serialize;
use tauri::{ipc::Channel, AppHandle};
use tauri_plugin_updater::{Update, UpdaterExt};

use crate::app::{CmdError, CmdResult};

/// Wo die Beschreibung der neuesten Version liegt (`latest.json`), etwa bei den Veröffentlichungen auf GitHub.
const URL: Option<&str> = option_env!("GLOWPORT_UPDATE_URL");
/// Öffentlicher Schlüssel, gegen den jedes geladene Update geprüft wird, bevor es läuft.
const PUBKEY: Option<&str> = option_env!("GLOWPORT_UPDATE_PUBKEY");

pub fn enabled() -> bool {
    URL.is_some_and(|url| !url.is_empty()) && PUBKEY.is_some_and(|key| !key.is_empty()) && !crate::portable()
}

#[derive(Serialize)]
pub struct Info {
    version: String,
    notes: String,
    /// Tag der Veröffentlichung in Millisekunden seit 1970.
    date: Option<i64>,
}

#[derive(Clone, Serialize)]
pub struct Progress {
    done: u64,
    total: Option<u64>,
}

fn failed(error: impl ToString) -> CmdError {
    CmdError::new("update_failed", error.to_string())
}

async fn newest(app: &AppHandle) -> CmdResult<Option<Update>> {
    let (Some(url), Some(key), true) = (URL, PUBKEY, enabled()) else {
        return Err(CmdError::new("update_unavailable", "Diese Fassung sucht nicht nach Updates"));
    };
    let endpoint = url.parse().map_err(failed)?;
    let updater = app.updater_builder().endpoints(vec![endpoint]).map_err(failed)?.pubkey(key).build().map_err(failed)?;
    updater.check().await.map_err(failed)
}

/// Fragt nach einer neueren Version; `None`, wenn diese die neueste ist.
#[tauri::command]
pub async fn update_check(app: AppHandle) -> CmdResult<Option<Info>> {
    Ok(newest(&app).await?.map(|update| Info { version: update.version.clone(), notes: update.body.clone().unwrap_or_default(), date: update.date.map(|d| d.unix_timestamp() * 1000) }))
}

/// Lädt die neue Version, prüft ihre Signatur und startet den Installer. Der beendet Glowport und startet es danach
/// neu; bis dahin meldet `progress`, wie weit das Laden ist.
#[tauri::command]
pub async fn update_install(app: AppHandle, progress: Channel<Progress>) -> CmdResult<()> {
    let update = newest(&app).await?.ok_or_else(|| failed("keine neuere Version"))?;
    let mut done = 0u64;
    update
        .download_and_install(
            |chunk, total| {
                done += chunk as u64;
                let _ = progress.send(Progress { done, total });
            },
            || {},
        )
        .await
        .map_err(failed)?;
    app.restart()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stays_off_unless_built_for_it() {
        // Die Tests werden ohne Adresse und Schlüssel gebaut: Dann darf nichts eingeschaltet sein.
        assert_eq!(enabled(), option_env!("GLOWPORT_UPDATE_URL").is_some() && option_env!("GLOWPORT_UPDATE_PUBKEY").is_some() && !crate::portable());
    }
}

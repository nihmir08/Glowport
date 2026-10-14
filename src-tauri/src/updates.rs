//! Updates: check whether there is a newer version and, after asking, download, verify and install it.
//!
//! Whether a build can do that is decided at build time: only if an address and the public key
//! for the signature were given (`GLOWPORT_UPDATE_URL`, `GLOWPORT_UPDATE_PUBKEY`) does Glowport ever look for
//! updates. Without both there is nothing about it in the interface, and no call goes to the network. The portable version
//! never updates itself: it has no installer that could replace it.

use serde::Serialize;
use tauri::{ipc::Channel, AppHandle};
use tauri_plugin_updater::{Update, UpdaterExt};

use crate::app::{CmdError, CmdResult};

/// Where the description of the newest version is (`latest.json`), for example in the releases on GitHub.
const URL: Option<&str> = option_env!("GLOWPORT_UPDATE_URL");
/// Public key every downloaded update is checked against before it runs.
const PUBKEY: Option<&str> = option_env!("GLOWPORT_UPDATE_PUBKEY");

pub fn enabled() -> bool {
    URL.is_some_and(|url| !url.is_empty()) && PUBKEY.is_some_and(|key| !key.is_empty()) && !crate::portable()
}

#[derive(Serialize)]
pub struct Info {
    version: String,
    notes: String,
    /// Day of release in milliseconds since 1970.
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

/// Asks for a newer version; `None` if this one is the newest.
#[tauri::command]
pub async fn update_check(app: AppHandle) -> CmdResult<Option<Info>> {
    Ok(newest(&app).await?.map(|update| Info { version: update.version.clone(), notes: update.body.clone().unwrap_or_default(), date: update.date.map(|d| d.unix_timestamp() * 1000) }))
}

/// Downloads the new version, checks its signature and starts the installer. That quits Glowport and starts it again
/// afterwards; until then `progress` reports how far the download is.
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
        // The tests are built without address and key: then nothing may be switched on.
        assert_eq!(enabled(), option_env!("GLOWPORT_UPDATE_URL").is_some() && option_env!("GLOWPORT_UPDATE_PUBKEY").is_some() && !crate::portable());
    }
}

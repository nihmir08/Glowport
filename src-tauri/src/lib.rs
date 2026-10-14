//! Glowport – Tauri-Hülle.
//!
//! Hier liegen nur Fenster und die Brücke zur Oberfläche. Der Kern (Tresor, SSH, Dateien)
//! kommt ab Meilenstein 1 in eigenen Crates dazu, die ohne Tauri testbar sind.

mod app;
mod dragout;
mod files;
mod forwards;
mod ftp;
mod import;
mod keyring;
mod keystore;
mod manage;
mod proxmox;
mod recordings;
mod sessions;
mod settings;
mod snippets;
mod store;
mod sync;
mod transfers;
mod updates;
mod watch;
mod windows;

use std::path::PathBuf;

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, Window, WindowEvent};

/// Name des Programms: „Glowport“ oder, bei der Entwicklungsversion, „Glowport Dev“ (siehe `tauri.dev.conf.json`).
/// Er ist zugleich der Ordnername unter `%APPDATA%`. Dadurch hat jede Fassung ihren eigenen Tresor und beide
/// können nebeneinander laufen.
fn app_name(app: &AppHandle) -> String {
    app.config().product_name.clone().unwrap_or_else(|| "Glowport".into())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AppInfo {
    name: String,
    version: &'static str,
    data_dir: String,
    /// Durchscheinendes Fenster, mit dem das Programm gestartet ist: „mica“, „acrylic“ oder leer.
    effect: String,
    /// Liegen die Daten neben dem Programm (portable Fassung)?
    portable: bool,
    /// Kann diese Fassung nach Updates suchen?
    updates: bool,
    /// Name dieses Rechners, als Vorschlag für den Namen des Geräts beim Abgleich.
    device: String,
}

/// Portable Fassung: Neben dem Programm liegt eine Datei `portable`.
pub(crate) fn portable() -> bool {
    std::env::current_exe().ok().and_then(|exe| exe.parent().map(|dir| dir.join("portable").exists())).unwrap_or(false)
}

/// Portable Variante: Liegt neben dem Programm eine Datei `portable`, bleiben alle Daten im Ordner `data` daneben.
fn data_dir(app: &AppHandle) -> Result<PathBuf, String> {
    if let Some(dir) = std::env::current_exe().ok().and_then(|exe| exe.parent().map(PathBuf::from)) {
        if dir.join("portable").exists() {
            return Ok(dir.join("data"));
        }
    }
    app.path().config_dir().map(|dir| dir.join(app_name(app))).map_err(|e| e.to_string())
}

/// Seite des Projekts auf GitHub: Quellcode, Lizenzen, Veröffentlichungen.
const REPO: &str = "https://github.com/nihmir08/Glowport";

/// Öffnet die Seite des Projekts im Browser. Die Adresse steht fest; von der Oberfläche kommt nichts hinein.
#[tauri::command]
fn about_open() -> Result<(), String> {
    let opener = if cfg!(windows) { "explorer.exe" } else if cfg!(target_os = "macos") { "open" } else { "xdg-open" };
    std::process::Command::new(opener).arg(REPO).spawn().map(drop).map_err(|e| e.to_string())
}

#[tauri::command]
fn app_info(app: AppHandle) -> Result<AppInfo, String> {
    Ok(AppInfo { name: app_name(&app), version: env!("CARGO_PKG_VERSION"), data_dir: data_dir(&app)?.display().to_string(), effect: app.state::<windows::Desk>().effect(), portable: portable(), updates: updates::enabled(), device: std::env::var("COMPUTERNAME").unwrap_or_default() })
}

/// Liest die Einstellungen. Gibt es noch keine (erster Start), steht darin nur die Sprache: die im Installer
/// gewählte, sonst die von Windows. Die portable Fassung hat keinen Installer.
#[tauri::command]
fn settings_load(app: AppHandle) -> Result<Option<serde_json::Value>, String> {
    if let Some(saved) = settings::load(&data_dir(&app)?).map_err(|e| e.to_string())? {
        return Ok(Some(saved));
    }
    let publisher = app.config().bundle.publisher.clone().unwrap_or_else(|| "Glowport".into());
    let installer = if portable() { None } else { settings::installer_language(&publisher, &app_name(&app)) };
    Ok(Some(serde_json::json!({ "lang": settings::first_language(installer.as_deref(), settings::system_language()) })))
}

/// Speichert die Einstellungen und gibt sie den anderen Fenstern weiter. Unverändertes wird weder geschrieben noch
/// gemeldet; sonst schickten sich zwei Fenster denselben Stand endlos hin und her.
#[tauri::command]
fn settings_save(app: AppHandle, window: Window, settings: serde_json::Value) -> Result<(), String> {
    let dir = data_dir(&app)?;
    if settings::load(&dir).ok().flatten().as_ref() == Some(&settings) {
        return Ok(());
    }
    settings::save(&dir, &settings).map_err(|e| e.to_string())?;
    let _ = app.emit("settings-changed", serde_json::json!({ "window": window.label(), "settings": settings }));
    Ok(())
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            let dir = data_dir(app.handle())?;
            let state = app::AppState::new(dir.join("vault.db"));
            let handle = app.handle().clone();
            // Jede Änderung am Tresor geht an die anderen Fenster und stößt den Abgleich an.
            state.watch(move || {
                let _ = handle.emit("vault-sync", ());
                sync::poke(&handle);
            });
            app.manage(state);
            app.manage(sync::SyncHost::default());
            app.manage(sessions::Sessions::default());
            app.manage(ftp::Ftps::default());
            app.manage(files::Files::default());
            app.manage(watch::Watches::default());
            watch::clean(app.handle());
            dragout::clean(app.handle());
            app.manage(transfers::init(app.handle(), dir.join("transfers.json")));
            app.manage(windows::Desk::default());
            app.manage(forwards::Forwards::default());
            app.manage(snippets::Runs::default());
            app.manage(import::Imports::default());
            app.manage(proxmox::Links::default());
            forwards::watch(app.handle().clone());
            app::spawn_auto_lock(app.handle().clone());
            // Der Fenstertitel steht in der Taskleiste und im Fensterwechsler; dort soll die Fassung zu erkennen sein
            // („Glowport“ oder „Glowport Dev“). Das Fenster entsteht hier und nicht aus `tauri.conf.json`.
            windows::create_main(app.handle())?;
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::Destroyed = event {
                windows::closed(window.app_handle(), window.label());
            }
        })
        .invoke_handler(tauri::generate_handler![
            app_info,
            settings_load,
            settings_save,
            app::vault_status,
            app::vault_create,
            app::vault_unlock,
            app::vault_lock,
            sync::vault_change_password,
            sync::vault_wipe,
            app::vault_backup,
            app::vault_restore,
            app::vault_set_start_unlock,
            app::vault_set_auto_lock,
            app::vault_touch,
            app::host_save,
            app::host_move,
            app::host_duplicate,
            app::host_delete,
            app::group_save,
            app::group_delete,
            app::known_host_delete,
            app::workspace_save,
            app::workspace_delete,
            app::pick_key_file,
            keyring::key_generate,
            keyring::key_pick_file,
            keyring::key_read_file,
            keyring::key_inspect,
            keyring::key_import,
            keyring::key_rename,
            keyring::key_delete,
            keyring::key_export,
            keyring::key_set_certificate,
            keyring::key_deploy,
            keyring::identity_save,
            keyring::identity_delete,
            keyring::agent_list,
            keyring::authority_add,
            keyring::authority_delete,
            sessions::session_open,
            sessions::local_shells,
            sessions::serial_ports,
            sessions::fs_connect,
            ftp::ftp_connect,
            sessions::session_write,
            sessions::session_relink,
            sessions::session_resize,
            sessions::session_ack,
            sessions::session_answer,
            sessions::session_close,
            sessions::session_count,
            sessions::session_hold,
            sessions::session_attach,
            sessions::session_record,
            sessions::log_list,
            sessions::log_read,
            sessions::log_delete,
            sessions::log_rename,
            sessions::log_reveal,
            windows::window_move,
            windows::window_ready,
            windows::window_payload,
            windows::restore_load,
            windows::restore_save,
            windows::pick_text_file,
            windows::pick_background,
            windows::background_read,
            files::fs_home,
            files::fs_list,
            files::fs_mkdir,
            files::fs_rename,
            files::fs_remove,
            files::fs_chmod,
            files::fs_read,
            files::fs_read_bytes,
            files::fs_write,
            transfers::transfer_start,
            transfers::transfer_list,
            transfers::transfer_control,
            transfers::transfer_clear,
            transfers::fs_compare,
            transfers::sync_start,
            files::fs_downloads,
            files::pick_uploads,
            files::pick_program,
            files::pick_folder,
            files::fs_search,
            files::session_cwd,
            watch::watch_open,
            watch::watch_stop,
            watch::watch_list,
            dragout::drag_stage,
            dragout::drag_out,
            forwards::forward_save,
            forwards::forward_delete,
            forwards::forward_start,
            forwards::forward_stop,
            forwards::forward_list,
            snippets::snippet_save,
            snippets::snippet_delete,
            snippets::snippet_run,
            snippets::snippet_cancel,
            snippets::session_stats,
            manage::manage_probe,
            manage::docker_list,
            manage::docker_action,
            manage::docker_line,
            manage::service_list,
            manage::service_action,
            manage::service_status,
            manage::service_line,
            manage::process_list,
            manage::process_kill,
            proxmox::proxmox_probe,
            proxmox::proxmox_save,
            proxmox::proxmox_delete,
            proxmox::proxmox_overview,
            proxmox::proxmox_action,
            proxmox::proxmox_import,
            proxmox::proxmox_unlink,
            proxmox::proxmox_reachable,
            import::import_scan,
            import::import_read,
            import::import_pick,
            import::import_file,
            import::import_apply,
            import::import_discard,
            import::export_data,
            sync::sync_state,
            sync::sync_probe,
            sync::sync_register,
            sync::sync_connect,
            sync::sync_login,
            sync::sync_now,
            sync::sync_unlink,
            sync::sync_resync,
            sync::sync_devices,
            sync::sync_device_rename,
            sync::sync_device_remove,
            sync::sync_notices,
            sync::sync_notices_clear,
            sync::shared_create,
            sync::shared_rename,
            sync::shared_lookup,
            sync::shared_invite,
            sync::shared_set_role,
            sync::shared_remove,
            sync::shared_transfer,
            sync::shared_leave,
            sync::shared_delete,
            sync::invitation_accept,
            sync::invitation_decline,
            sync::admin_invites,
            sync::admin_invite_create,
            sync::admin_invite_revoke,
            sync::admin_accounts,
            sync::admin_account_disable,
            sync::admin_account_delete,
            about_open,
            updates::update_check,
            updates::update_install,
        ])
        .run(tauri::generate_context!())
        .expect("Glowport konnte nicht starten");
}

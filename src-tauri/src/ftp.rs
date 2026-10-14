//! FTP for the Files page: setting up the connection with its prompts.
//!
//! An FTP server has no terminal. `fs_connect` (saved host) and `ftp_connect` (quick connect) lead
//! here; the prompts run over the same events and answers as for a session (`session`,
//! `session_answer`), so the interface only knows one way. Order: first the warning about an
//! unencrypted connection, then the password, then (over TLS) the certificate. **The password only goes to
//! the server once all of that is answered.**

use std::{
    collections::HashMap,
    sync::{Mutex, MutexGuard},
};

use glowport_core::{
    directory::FtpInfo,
    model::{FtpSecurity, Secret},
};
use glowport_ftp::{Connect, Fingerprint, Refusal, Remote, Security};
use tauri::{AppHandle, Manager, Window};
use tokio::sync::oneshot;

use crate::{
    app::{emit_snapshot, AppState, CmdError, CmdResult},
    files::{self, Place},
    sessions::{self, Answer, SessionEvent},
    store::Store,
};

/// This many times a password is asked for before the setup gives up.
const MAX_ATTEMPTS: u32 = 3;

struct Task {
    window: String,
    handle: tauri::async_runtime::JoinHandle<()>,
}

/// Running connection setups and their open prompts, by number.
#[derive(Default)]
pub struct Ftps {
    tasks: Mutex<HashMap<u64, Task>>,
    asking: Mutex<HashMap<u64, oneshot::Sender<Answer>>>,
}

impl Ftps {
    fn tasks(&self) -> MutexGuard<'_, HashMap<u64, Task>> {
        self.tasks.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn asking(&self) -> MutexGuard<'_, HashMap<u64, oneshot::Sender<Answer>>> {
        self.asking.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Where to: a saved host or a server from quick connect that the vault does not know.
#[derive(Clone)]
pub(crate) enum Who {
    Host(String),
    Direct { host: String, port: u16, user: String, security: FtpSecurity },
}

impl Who {
    /// The place of an FTP connection; `None` for everything else.
    pub(crate) fn of(app: &AppHandle, place: &Place) -> Option<Who> {
        match place {
            Place::Host { id } if app.state::<AppState>().session().directory().is_ok_and(|directory| directory.is_ftp(id)) => Some(Who::Host(id.clone())),
            Place::Ftp { host, port, user, security } => Some(Who::Direct { host: host.clone(), port: *port, user: user.clone(), security: *security }),
            _ => None,
        }
    }

    fn place(&self) -> Place {
        match self {
            Who::Host(id) => Place::Host { id: id.clone() },
            Who::Direct { host, port, user, security } => Place::Ftp { host: host.clone(), port: *port, user: user.clone(), security: *security },
        }
    }

    /// What it takes to connect. A server from quick connect has no saved password; its
    /// confirmed certificate is listed with the known hosts like any other when the vault is open.
    fn info(&self, app: &AppHandle) -> CmdResult<FtpInfo> {
        match self {
            Who::Host(id) => Ok(app.state::<AppState>().session().directory()?.ftp_info(id)?),
            Who::Direct { host, port, user, security } => {
                sessions::check_address(host, *port)?;
                if !user.is_empty() && !sessions::safe_token(user, 64) {
                    return Err(CmdError::invalid("user_invalid"));
                }
                let pin = app.state::<AppState>().session().directory().ok().and_then(|directory| directory.certificate_pin(host, *port));
                Ok(FtpInfo { name: host.clone(), address: host.clone(), port: *port, user: user.clone(), password: None, security: *security, dir: None, plain_ok: false, pin, saves_password: false })
            }
        }
    }
}

/// This is how browsers and servers show a certificate's fingerprint: `5F:1A:…`.
fn fingerprint_text(fingerprint: &Fingerprint) -> String {
    fingerprint.iter().map(|byte| format!("{byte:02X}")).collect::<Vec<_>>().join(":")
}

fn parse_fingerprint(text: &str) -> Option<Fingerprint> {
    let hex: String = text.chars().filter(|c| *c != ':').collect();
    if hex.len() != 64 || !hex.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn security(security: FtpSecurity) -> Security {
    match security {
        FtpSecurity::Explicit => Security::Explicit,
        FtpSecurity::Implicit => Security::Implicit,
        FtpSecurity::None => Security::None,
    }
}

/// Connects quietly, without any prompt: only when there is nothing left to ask. Otherwise `files_auth`; the interface
/// then sets up the connection with prompts.
pub(crate) async fn silent(app: &AppHandle, who: &Who) -> CmdResult<Store> {
    let info = who.info(app)?;
    let ask = || CmdError::new("files_auth", "The connection needs a prompt");
    if (info.security == FtpSecurity::None && !info.plain_ok) || (info.password.is_none() && !info.user.is_empty()) {
        return Err(ask());
    }
    let connect = Connect {
        host: info.address,
        port: info.port,
        user: info.user,
        password: info.password.map(|password| password.expose().to_string()).unwrap_or_default(),
        security: security(info.security),
        pin: info.pin.as_deref().and_then(parse_fingerprint),
    };
    match Remote::connect(&connect).await {
        Ok(remote) => Ok(Store::ftp(remote)),
        Err(Refusal::Certificate(_) | Refusal::CertificateChanged(_) | Refusal::AuthFailed) => Err(ask()),
        Err(refusal @ Refusal::NoTls(_)) => Err(CmdError::new("files_auth", format!("{refusal:?}"))),
        Err(Refusal::Offline(reason) | Refusal::Failed(reason)) => Err(CmdError::new("connect_failed", reason)),
    }
}

/// Starts the setup and returns the number under which its events arrive.
pub(crate) fn connect(app: &AppHandle, window: String, who: Who) -> CmdResult<u64> {
    // If even the lookup fails (locked vault, not an FTP host, unusable address), there is no number.
    who.info(app)?;
    let number = sessions::number(app);
    let task = {
        let (app, window) = (app.clone(), window.clone());
        tauri::async_runtime::spawn(async move {
            let result = flow(&app, number, &window, &who).await;
            let ftps = app.state::<Ftps>();
            ftps.asking().remove(&number);
            ftps.tasks().remove(&number);
            let event = match result {
                Ok(()) => SessionEvent::Phase { phase: "connected" },
                Err((reason, message)) => SessionEvent::End { reason, message, exit_status: None },
            };
            sessions::emit_to(&app, window, number, event);
        })
    };
    app.state::<Ftps>().tasks().insert(number, Task { window, handle: task });
    Ok(number)
}

/// Sets up the connection to an FTP server from quick connect for the Files page. The prompts
/// arrive as `session` events, as with `fs_connect`.
#[tauri::command]
pub fn ftp_connect(app: AppHandle, window: Window, place: Place) -> CmdResult<u64> {
    match &place {
        Place::Ftp { .. } => connect(&app, window.label().to_string(), Who::of(&app, &place).ok_or_else(|| CmdError::invalid("protocol_invalid"))?),
        _ => Err(CmdError::invalid("protocol_invalid")),
    }
}

/// Asks a prompt and waits for the answer. `None` if the setup was given up in the meantime.
async fn ask(app: &AppHandle, number: u64, window: &str, event: SessionEvent) -> Option<Answer> {
    let (reply, answer) = oneshot::channel();
    app.state::<Ftps>().asking().insert(number, reply);
    sessions::emit_to(app, window.to_string(), number, event);
    answer.await.ok()
}

type Failure = (&'static str, Option<String>);

async fn flow(app: &AppHandle, number: u64, window: &str, who: &Who) -> Result<(), Failure> {
    let failed = |error: CmdError| ("connect_failed", Some(error.code().to_string()));
    let user_gave_up = || ("user", None);
    let host = match who {
        Who::Host(id) => Some(id.as_str()),
        Who::Direct { .. } => None,
    };
    sessions::emit_to(app, window.to_string(), number, SessionEvent::Phase { phase: "connecting" });
    let mut plain_accepted = false;
    // The typed password and whether it should go into the vault.
    let mut typed: Option<(String, bool)> = None;
    // The server refused the saved password.
    let mut stored_refused = false;
    // The certificate the user confirmed in this setup. It applies even if it could not be saved.
    let mut accepted: Option<Fingerprint> = None;
    let mut attempt = 0;
    loop {
        let info = who.info(app).map_err(failed)?;

        if info.security == FtpSecurity::None && !info.plain_ok && !plain_accepted {
            let offers_tls = glowport_ftp::offers_tls(&info.address, info.port).await;
            let event = SessionEvent::Plain { host: info.address.clone(), offers_tls, can_remember: host.is_some() };
            let Some(Answer::Plain { accept: true, remember, secure }) = ask(app, number, window, event).await else { return Err(user_gave_up()) };
            plain_accepted = true;
            match host {
                Some(id) if remember || secure => {
                    let saved = app.state::<AppState>().session().directory().map_err(drop).and_then(|directory| directory.set_ftp_choice(id, remember, secure).map_err(drop));
                    if saved.is_ok() {
                        emit_snapshot(app);
                    }
                    if secure {
                        // From here on the host counts as FTPS; if that could not be saved, the plain connection stays.
                        continue;
                    }
                }
                // A server from quick connect cannot be switched: the interface then opens it anew, as FTPS.
                None if secure => return Err(user_gave_up()),
                _ => {}
            }
        }

        let stored = info.password.as_ref().filter(|_| !stored_refused).map(|password| password.expose().to_string());
        let password = match typed.as_ref().map(|typed| typed.0.clone()).or(stored) {
            Some(password) => password,
            None if info.user.is_empty() => String::new(),
            None => {
                attempt += 1;
                let event = SessionEvent::Secret { kind: "password", attempt, file: None, can_save: info.saves_password, station: None };
                let Some(Answer::Secret { value: Some(value), save }) = ask(app, number, window, event).await else { return Err(user_gave_up()) };
                typed = Some((value.clone(), save));
                value
            }
        };

        let pin = accepted.or_else(|| info.pin.as_deref().and_then(parse_fingerprint));
        let connect = Connect { host: info.address.clone(), port: info.port, user: info.user.clone(), password, security: security(info.security), pin };
        sessions::emit_to(app, window.to_string(), number, SessionEvent::Phase { phase: "authenticating" });
        match Remote::connect(&connect).await {
            Ok(remote) => {
                if let (Some(id), Some((value, true))) = (host, typed.take().filter(|_| info.saves_password)) {
                    let saved = app.state::<AppState>().session().directory().map_err(drop).and_then(|directory| directory.set_host_password(id, Secret::new(value)).map_err(drop));
                    if saved.is_ok() {
                        emit_snapshot(app);
                    }
                }
                files::adopt(app, who.place(), Store::ftp(remote)).await;
                return Ok(());
            }
            Err(refusal @ (Refusal::Certificate(_) | Refusal::CertificateChanged(_))) => {
                let (fingerprint, changed) = match refusal {
                    Refusal::CertificateChanged(fingerprint) => (fingerprint, true),
                    Refusal::Certificate(fingerprint) => (fingerprint, false),
                    _ => unreachable!(),
                };
                // The same certificate once more: then asking further is of no use.
                if accepted == Some(fingerprint) {
                    return Err(("connect_failed", Some("certificate".into())));
                }
                let shown = fingerprint_text(&fingerprint);
                let event = SessionEvent::Certificate { host: info.address.clone(), port: info.port, fingerprint: shown.clone(), changed };
                let Some(Answer::Certificate { accept: true }) = ask(app, number, window, event).await else { return Err(("certificate_rejected", None)) };
                accepted = Some(fingerprint);
                // If it cannot be remembered (locked vault), the confirmation still applies to this connection.
                let saved = app.state::<AppState>().session().directory().map_err(drop).and_then(|directory| directory.trust_certificate(&info.address, info.port, &shown).map_err(drop));
                if saved.is_ok() {
                    emit_snapshot(app);
                }
            }
            Err(Refusal::AuthFailed) => {
                if info.user.is_empty() || attempt >= MAX_ATTEMPTS {
                    return Err(("auth_failed", None));
                }
                typed = None;
                stored_refused = true;
            }
            Err(Refusal::NoTls(message)) => return Err(("no_tls", Some(message))),
            Err(Refusal::Offline(message) | Refusal::Failed(message)) => return Err(("connect_failed", Some(message))),
        }
    }
}

/// Takes the answer to a prompt. If the number does not belong to an FTP setup, the answer is returned.
pub(crate) fn answer(app: &AppHandle, number: u64, answer: Answer) -> Option<Answer> {
    let ftps = app.state::<Ftps>();
    if let Some(reply) = ftps.asking().remove(&number) {
        let _ = reply.send(answer);
        return None;
    }
    if ftps.tasks().contains_key(&number) {
        return None;
    }
    Some(answer)
}

/// Gives up a setup. Returns whether the number belonged to one.
pub(crate) fn cancel(app: &AppHandle, number: u64) -> bool {
    let ftps = app.state::<Ftps>();
    let Some(task) = ftps.tasks().remove(&number) else { return false };
    ftps.asking().remove(&number);
    task.handle.abort();
    sessions::emit_to(app, task.window, number, SessionEvent::End { reason: "user", message: None, exit_status: None });
    true
}

/// Gives up all setups of a window that was closed.
pub(crate) fn close_window(app: &AppHandle, window: &str) {
    let ftps = app.state::<Ftps>();
    let gone: Vec<u64> = ftps.tasks().iter().filter(|(_, task)| task.window == window).map(|(number, _)| *number).collect();
    for number in gone {
        if let Some(task) = ftps.tasks().remove(&number) {
            ftps.asking().remove(&number);
            task.handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_are_shown_and_read_back() {
        let mut fingerprint = [0u8; 32];
        for (i, byte) in fingerprint.iter_mut().enumerate() {
            *byte = (i * 7 + 3) as u8;
        }
        let shown = fingerprint_text(&fingerprint);
        assert!(shown.starts_with("03:0A:11") && shown.len() == 95);
        assert_eq!(parse_fingerprint(&shown), Some(fingerprint));
        for bad in ["", "03:0A", &shown[..94], &shown.replace("03", "ZZ"), &"ä".repeat(32)] {
            assert_eq!(parse_fingerprint(bad), None, "{bad}");
        }
    }
}

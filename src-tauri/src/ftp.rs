//! FTP für die Seite „Dateien“: der Aufbau der Verbindung mit seinen Rückfragen.
//!
//! Ein FTP-Server hat kein Terminal. `fs_connect` (gespeicherter Host) und `ftp_connect` (Schnellverbindung) führen
//! hierher; die Rückfragen laufen über dieselben Ereignisse und Antworten wie bei einer Sitzung (`session`,
//! `session_answer`), damit die Oberfläche nur einen Weg kennt. Reihenfolge: erst die Warnung vor einer
//! unverschlüsselten Verbindung, dann das Passwort, dann (über TLS) das Zertifikat. **Das Passwort geht erst an
//! den Server, wenn all das beantwortet ist.**

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

/// So oft wird nach einem Passwort gefragt, bevor der Aufbau aufgibt.
const MAX_ATTEMPTS: u32 = 3;

struct Task {
    window: String,
    handle: tauri::async_runtime::JoinHandle<()>,
}

/// Laufende Verbindungsaufbauten und ihre offenen Rückfragen, je Nummer.
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

/// Wohin: ein gespeicherter Host oder ein Server aus der Schnellverbindung, den der Tresor nicht kennt.
#[derive(Clone)]
pub(crate) enum Who {
    Host(String),
    Direct { host: String, port: u16, user: String, security: FtpSecurity },
}

impl Who {
    /// Der Ort einer FTP-Verbindung; `None` für alles andere.
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

    /// Was es zum Verbinden braucht. Ein Server aus der Schnellverbindung hat kein gespeichertes Passwort; sein
    /// bestätigtes Zertifikat steht, wenn der Tresor offen ist, wie bei jedem anderen bei den bekannten Hosts.
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

/// So zeigen Browser und Server den Fingerabdruck eines Zertifikats: `5F:1A:…`.
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

/// Verbindet still, ohne jede Rückfrage: nur, wenn nichts mehr zu fragen ist. Sonst `files_auth`; die Oberfläche
/// baut die Verbindung dann mit Rückfragen auf.
pub(crate) async fn silent(app: &AppHandle, who: &Who) -> CmdResult<Store> {
    let info = who.info(app)?;
    let ask = || CmdError::new("files_auth", "Die Verbindung braucht eine Rückfrage");
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

/// Beginnt den Aufbau und liefert die Nummer, unter der seine Ereignisse kommen.
pub(crate) fn connect(app: &AppHandle, window: String, who: Who) -> CmdResult<u64> {
    // Scheitert schon das Nachschlagen (gesperrter Tresor, kein FTP-Host, unbrauchbare Adresse), gibt es keine Nummer.
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

/// Baut für die Seite „Dateien“ die Verbindung zu einem FTP-Server aus der Schnellverbindung auf. Die Rückfragen
/// kommen wie bei `fs_connect` als Ereignisse `session`.
#[tauri::command]
pub fn ftp_connect(app: AppHandle, window: Window, place: Place) -> CmdResult<u64> {
    match &place {
        Place::Ftp { .. } => connect(&app, window.label().to_string(), Who::of(&app, &place).ok_or_else(|| CmdError::invalid("protocol_invalid"))?),
        _ => Err(CmdError::invalid("protocol_invalid")),
    }
}

/// Stellt eine Rückfrage und wartet auf die Antwort. `None`, wenn der Aufbau inzwischen aufgegeben wurde.
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
    // Das eingetippte Passwort und ob es in den Tresor soll.
    let mut typed: Option<(String, bool)> = None;
    // Das gespeicherte Passwort hat der Server abgelehnt.
    let mut stored_refused = false;
    // Das Zertifikat, das der Nutzer in diesem Aufbau bestätigt hat. Es gilt auch, wenn es sich nicht speichern ließ.
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
                        // Ab hier gilt der Host als FTPS; ließ es sich nicht speichern, bleibt es bei der offenen Verbindung.
                        continue;
                    }
                }
                // Ein Server aus der Schnellverbindung lässt sich nicht umstellen: Die Oberfläche öffnet ihn dann neu, als FTPS.
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
                // Dasselbe Zertifikat noch einmal: Dann nützt weiteres Fragen nichts.
                if accepted == Some(fingerprint) {
                    return Err(("connect_failed", Some("certificate".into())));
                }
                let shown = fingerprint_text(&fingerprint);
                let event = SessionEvent::Certificate { host: info.address.clone(), port: info.port, fingerprint: shown.clone(), changed };
                let Some(Answer::Certificate { accept: true }) = ask(app, number, window, event).await else { return Err(("certificate_rejected", None)) };
                accepted = Some(fingerprint);
                // Lässt es sich nicht merken (gesperrter Tresor), gilt die Bestätigung für diese Verbindung trotzdem.
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

/// Nimmt die Antwort auf eine Rückfrage an. Gehört die Nummer nicht zu einem FTP-Aufbau, kommt die Antwort zurück.
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

/// Gibt einen Aufbau auf. Liefert, ob die Nummer zu einem gehörte.
pub(crate) fn cancel(app: &AppHandle, number: u64) -> bool {
    let ftps = app.state::<Ftps>();
    let Some(task) = ftps.tasks().remove(&number) else { return false };
    ftps.asking().remove(&number);
    task.handle.abort();
    sessions::emit_to(app, task.window, number, SessionEvent::End { reason: "user", message: None, exit_status: None });
    true
}

/// Gibt alle Aufbauten eines Fensters auf, das geschlossen wurde.
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

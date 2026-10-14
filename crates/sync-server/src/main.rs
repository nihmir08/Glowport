//! `glowport-sync`: Glowport's self-hosted sync server (`docs/sync.md`, `docs/sync-server.md`).

use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    process::ExitCode,
    time::Duration,
};

use glowport_sync_server::{day, serve, serve_tls, store::Store, App};

const USAGE: &str = "Aufruf:
  glowport-sync [serve]              Server starten
  glowport-sync backup <Datei>       Sicherung der Datenbank schreiben (auch im Betrieb)
  glowport-sync invite               Einladungscode erzeugen (einmal gültig, sieben Tage)
  glowport-sync invites              offene Einladungscodes auflisten
  glowport-sync revoke <Code>        offenen Einladungscode widerrufen
  glowport-sync accounts             Konten auflisten
  glowport-sync disable <Name>       Konto sperren (keine Anmeldung, kein Abgleich; die Daten bleiben)
  glowport-sync enable <Name>        Konto wieder freigeben
  glowport-sync delete <Name>        Konto samt Geräten und persönlichem Tresor löschen
  glowport-sync admin <Name>         Konto zum Verwalter machen
  glowport-sync noadmin <Name>       einem Konto die Verwaltung nehmen

Angaben (auch über die Umgebung):
  --listen <Adresse>     GLOWPORT_SYNC_LISTEN       Vorgabe 127.0.0.1:8787
  --data <Ordner>        GLOWPORT_SYNC_DATA         Vorgabe ./data
  --trust-proxy          GLOWPORT_SYNC_TRUST_PROXY=1  hinter einem Webserver auf demselben Rechner: Absender aus
                                                      X-Forwarded-For
  --trust-proxy-from <Adressen>  GLOWPORT_SYNC_TRUST_PROXY=<Adressen>
                                                      wie oben, aber nur Verbindungen von diesen Adressen wird
                                                      es geglaubt (der Webserver auf einem anderen Rechner)
  --tls-cert <Datei>     GLOWPORT_SYNC_TLS_CERT     Zertifikat (PEM), für den Betrieb ohne vorgeschalteten Webserver
  --tls-key <Datei>      GLOWPORT_SYNC_TLS_KEY      zugehöriger privater Schlüssel (PEM)

Grenzen (nur über die Umgebung):
  GLOWPORT_SYNC_MAX_RECORD_KIB   Größe eines Datensatzes in KiB, Vorgabe 256
  GLOWPORT_SYNC_MAX_RECORDS      Datensätze je Tresor, Vorgabe 20000
  GLOWPORT_SYNC_MAX_VAULTS       Tresore je Konto, Vorgabe 50

Die Befehle der Verwaltung wirken sofort, auch während der Server läuft. Ohne --data suchen sie den
Datenbestand in ./data und dann in /var/lib/glowport-sync.";

/// Where the service keeps its data when set up according to the guide.
const SERVICE_DATA: &str = "/var/lib/glowport-sync";

struct Options {
    words: Vec<String>,
    listen: String,
    /// `None`: nothing given, the default applies.
    data: Option<PathBuf>,
    /// Whose `X-Forwarded-For` counts: nobody's, everyone's (empty list) or only that of these addresses.
    proxies: Option<Vec<IpAddr>>,
    tls: Option<(PathBuf, PathBuf)>,
}

/// The addresses of the web servers whose sender statement is believed, separated by commas.
fn proxies(text: &str) -> Result<Vec<IpAddr>, String> {
    text.split(',').map(|part| part.trim().parse().map_err(|_| format!("„{}“ ist keine Adresse der Form 10.0.0.10", part.trim()))).collect()
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

fn options() -> Result<Options, String> {
    let mut listen = env("GLOWPORT_SYNC_LISTEN").unwrap_or_else(|| "127.0.0.1:8787".into());
    let mut data = env("GLOWPORT_SYNC_DATA").map(PathBuf::from);
    let mut trusted = match env("GLOWPORT_SYNC_TRUST_PROXY") {
        None => None,
        Some(v) if v == "0" || v.eq_ignore_ascii_case("false") => None,
        Some(v) if v == "1" || v.eq_ignore_ascii_case("true") => Some(Vec::new()),
        Some(v) => Some(proxies(&v).map_err(|e| format!("GLOWPORT_SYNC_TRUST_PROXY: {e}"))?),
    };
    let (mut cert, mut key) = (env("GLOWPORT_SYNC_TLS_CERT").map(PathBuf::from), env("GLOWPORT_SYNC_TLS_KEY").map(PathBuf::from));
    let mut words = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = |what: &str| args.next().ok_or(format!("{arg} braucht {what}"));
        match arg.as_str() {
            "--listen" => listen = value("eine Adresse")?,
            "--data" => data = Some(value("einen Ordner")?.into()),
            "--tls-cert" => cert = Some(value("eine Datei")?.into()),
            "--tls-key" => key = Some(value("eine Datei")?.into()),
            "--trust-proxy" => trusted = Some(Vec::new()),
            "--trust-proxy-from" => trusted = Some(proxies(&value("Adressen")?)?),
            "--help" | "-h" => return Err(USAGE.into()),
            flag if flag.starts_with('-') => return Err(format!("Unbekannte Angabe: {flag}\n\n{USAGE}")),
            _ => words.push(arg),
        }
    }
    let tls = match (cert, key) {
        (Some(cert), Some(key)) => Some((cert, key)),
        (None, None) => None,
        _ => return Err("Für TLS braucht es beides: --tls-cert und --tls-key".into()),
    };
    Ok(Options { words, listen, data, proxies: trusted, tls })
}

/// A limit from the environment: a number greater than zero, otherwise the default stays.
fn limit(name: &str, target: &mut usize, factor: usize) -> Result<(), String> {
    if let Some(text) = env(name) {
        let value: usize = text.parse().ok().filter(|value| *value > 0).ok_or(format!("{name}: „{text}“ ist keine Zahl größer null"))?;
        *target = value.saturating_mul(factor);
    }
    Ok(())
}

/// A size in the unit in which it reads best.
fn size(bytes: u64) -> String {
    match bytes {
        0..=1023 => format!("{bytes} B"),
        1024..=1_048_575 => format!("{:.1} KB", bytes as f64 / 1024.0).replace('.', ","),
        _ => format!("{:.1} MB", bytes as f64 / 1_048_576.0).replace('.', ","),
    }
}

/// The administration actions on the command line. They act directly on the database, even while the
/// server is running.
fn manage(store: &Store, words: &[String]) -> Result<(), String> {
    let operator = Store::operator();
    let fail = |e: glowport_sync_server::store::Fail| e.to_string();
    let account = |name: &String| store.account_id(name).map_err(|_| format!("Ein Konto „{name}“ gibt es nicht"));
    match words {
        [command, file] if command == "backup" => {
            store.backup(&PathBuf::from(file)).map_err(|_| format!("Die Sicherung ließ sich nicht schreiben. Gibt es {file} schon, oder fehlt das Schreibrecht im Ordner?"))?;
            println!("Sicherung geschrieben: {file}");
        }
        [command] if command == "invite" => {
            let invite = store.create_invite(&operator).map_err(fail)?;
            println!("Einladungscode: {}\nGilt einmal, bis {}.", invite.code, day(invite.expires_at));
        }
        [command] if command == "invites" => {
            let invites = store.invites(&operator).map_err(fail)?;
            if invites.is_empty() {
                println!("Keine offenen Einladungscodes.");
            }
            for invite in invites {
                println!("{}  gilt bis {}", invite.code, day(invite.expires_at));
            }
        }
        [command, code] if command == "revoke" => {
            store.revoke_invite(&operator, code).map_err(|_| format!("Einen offenen Einladungscode „{code}“ gibt es nicht"))?;
            println!("Einladungscode widerrufen.");
        }
        [command] if command == "accounts" => {
            let accounts = store.accounts(&operator).map_err(fail)?;
            if accounts.is_empty() {
                println!("Noch kein Konto.");
            }
            for a in accounts {
                let marks = [a.admin.then_some("Verwalter"), a.disabled.then_some("gesperrt")].into_iter().flatten().collect::<Vec<_>>().join(", ");
                let devices = if a.devices == 1 { "Gerät " } else { "Geräte" };
                println!("{:<32} {:>2} {devices}  {:>9}  zuletzt da {}  {marks}", a.username, a.devices, size(a.bytes), day(a.seen_at));
            }
        }
        [command, name] if command == "admin" || command == "noadmin" => {
            store.set_admin(&operator, &account(name)?, command == "admin").map_err(fail)?;
            println!("Konto „{name}“ ist jetzt {}. In Glowport zeigt es sich nach dem nächsten Abgleich.", if command == "admin" { "Verwalter" } else { "kein Verwalter mehr" });
        }
        [command, name] if command == "disable" || command == "enable" => {
            store.set_disabled(&operator, &account(name)?, command == "disable").map_err(fail)?;
            println!("Konto „{name}“ ist jetzt {}.", if command == "disable" { "gesperrt" } else { "freigegeben" });
        }
        [command, name] if command == "delete" => {
            store.delete_account(&operator, &account(name)?).map_err(fail)?;
            println!("Konto „{name}“ ist gelöscht.");
        }
        _ => return Err(USAGE.into()),
    }
    Ok(())
}

fn run() -> Result<(), String> {
    let options = options()?;
    let serving = matches!(options.words.as_slice(), [] | [_] if options.words.first().is_none_or(|word| word == "serve"));
    if !serving {
        // A command never creates a new data store: an invitation code from the wrong folder would be valid nowhere.
        let folders = match &options.data {
            Some(folder) => vec![folder.clone()],
            None => vec![PathBuf::from("data"), PathBuf::from(SERVICE_DATA)],
        };
        let Some(file) = folders.iter().map(|folder| folder.join("sync.db")).find(|file| file.is_file()) else {
            let searched = folders.iter().map(|folder| folder.display().to_string()).collect::<Vec<_>>().join(", ");
            return Err(format!("Kein Datenbestand eines Servers gefunden (gesucht in: {searched}). Mit --data den Ordner des Servers angeben."));
        };
        let store = Store::open(&file).map_err(|e| format!("{}: {e}", file.display()))?;
        return manage(&store, &options.words);
    }

    let data = options.data.unwrap_or_else(|| PathBuf::from("data"));
    std::fs::create_dir_all(&data).map_err(|e| format!("Datenordner {}: {e}", data.display()))?;
    let mut store = Store::open(&data.join("sync.db")).map_err(|e| format!("Datenordner {}: {e}", data.display()))?;
    limit("GLOWPORT_SYNC_MAX_RECORD_KIB", &mut store.limits.record_bytes, 1024)?;
    limit("GLOWPORT_SYNC_MAX_RECORDS", &mut store.limits.records_per_vault, 1)?;
    limit("GLOWPORT_SYNC_MAX_VAULTS", &mut store.limits.vaults_per_account, 1)?;
    let address: SocketAddr = options.listen.parse().map_err(|_| format!("{}: keine Adresse der Form 127.0.0.1:8787", options.listen))?;
    // Only the verifier is kept; every start therefore prints a new code, and only the latest is valid.
    if let Some(code) = store.setup_code().map_err(|e| e.to_string())? {
        println!("Noch kein Konto. Einrichtungscode für das erste Konto (es wird Verwalter): {code}");
    }
    let app = App::with_proxies(store, options.proxies);
    app.log_requests();
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().map_err(|e| e.to_string())?;
    runtime.block_on(async {
        // Einmal am Tag alte Grabsteine entfernen.
        let cleaner = app.clone();
        tokio::spawn(async move {
            let mut daily = tokio::time::interval(Duration::from_secs(24 * 60 * 60));
            loop {
                daily.tick().await;
                let app = cleaner.clone();
                let _ = tokio::task::spawn_blocking(move || app.store.purge()).await;
            }
        });
        // Ctrl+C on screen; as a service or in a container SIGTERM comes instead.
        let stop = async {
            #[cfg(unix)]
            {
                let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("Signal");
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            #[cfg(not(unix))]
            {
                let _ = tokio::signal::ctrl_c().await;
            }
        };

        match options.tls {
            // Behind a web server in front that handles TLS (or only for the own machine).
            None => {
                let listener = tokio::net::TcpListener::bind(address).await.map_err(|e| format!("{address}: {e}"))?;
                println!("glowport-sync hört auf {address}");
                serve(app, listener, stop).await.map_err(|e| e.to_string())
            }
            Some((cert, key)) => {
                let listener = std::net::TcpListener::bind(address).map_err(|e| format!("{address}: {e}"))?;
                println!("glowport-sync hört auf {address} (TLS)");
                let files = format!("Zertifikat {} / Schlüssel {}", cert.display(), key.display());
                serve_tls(app, listener, cert, key, stop).await.map_err(|e| format!("{files}: {e}"))
            }
        }
    })
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::size;

    #[test]
    fn sizes_read_well() {
        assert_eq!(size(0), "0 B");
        assert_eq!(size(1023), "1023 B");
        assert_eq!(size(1536), "1,5 KB");
        assert_eq!(size(5 * 1_048_576 + 104_858), "5,1 MB");
    }
}

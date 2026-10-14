//! `glowport-sync`: Glowport's self-hosted sync server (`docs/sync.md`, `docs/sync-server.md`).

use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    process::ExitCode,
    time::Duration,
};

use glowport_sync_server::{day, serve, serve_tls, store::Store, App};

const USAGE: &str = "Usage:
  glowport-sync [serve]              start the server
  glowport-sync backup <file>        write a backup of the database (also while running)
  glowport-sync invite               create an invitation code (valid once, for seven days)
  glowport-sync invites              list open invitation codes
  glowport-sync revoke <code>        revoke an open invitation code
  glowport-sync accounts             list accounts
  glowport-sync disable <name>       disable an account (no sign-in, no sync; the data stays)
  glowport-sync enable <name>        enable an account again
  glowport-sync delete <name>        delete an account with its devices and personal vault
  glowport-sync admin <name>         make an account an administrator
  glowport-sync noadmin <name>       take administration away from an account

Options (also through the environment):
  --listen <address>     GLOWPORT_SYNC_LISTEN       default 127.0.0.1:8787
  --data <folder>        GLOWPORT_SYNC_DATA         default ./data
  --trust-proxy          GLOWPORT_SYNC_TRUST_PROXY=1  behind a web server on the same machine: sender from
                                                      X-Forwarded-For
  --trust-proxy-from <addresses>  GLOWPORT_SYNC_TRUST_PROXY=<addresses>
                                                      as above, but only connections from these addresses
                                                      are believed (the web server on another machine)
  --tls-cert <file>      GLOWPORT_SYNC_TLS_CERT     certificate (PEM), for running without a web server in front
  --tls-key <file>       GLOWPORT_SYNC_TLS_KEY      matching private key (PEM)

Limits (only through the environment):
  GLOWPORT_SYNC_MAX_RECORD_KIB   size of a record in KiB, default 256
  GLOWPORT_SYNC_MAX_RECORDS      records per vault, default 20000
  GLOWPORT_SYNC_MAX_VAULTS       vaults per account, default 50

The administration commands take effect immediately, even while the server is running. Without --data
they look for the data in ./data and then in /var/lib/glowport-sync.";

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
    text.split(',').map(|part| part.trim().parse().map_err(|_| format!("“{}” is not an address of the form 10.0.0.10", part.trim()))).collect()
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
        let mut value = |what: &str| args.next().ok_or(format!("{arg} needs {what}"));
        match arg.as_str() {
            "--listen" => listen = value("an address")?,
            "--data" => data = Some(value("a folder")?.into()),
            "--tls-cert" => cert = Some(value("a file")?.into()),
            "--tls-key" => key = Some(value("a file")?.into()),
            "--trust-proxy" => trusted = Some(Vec::new()),
            "--trust-proxy-from" => trusted = Some(proxies(&value("addresses")?)?),
            "--help" | "-h" => return Err(USAGE.into()),
            flag if flag.starts_with('-') => return Err(format!("Unknown option: {flag}\n\n{USAGE}")),
            _ => words.push(arg),
        }
    }
    let tls = match (cert, key) {
        (Some(cert), Some(key)) => Some((cert, key)),
        (None, None) => None,
        _ => return Err("TLS needs both: --tls-cert and --tls-key".into()),
    };
    Ok(Options { words, listen, data, proxies: trusted, tls })
}

/// A limit from the environment: a number greater than zero, otherwise the default stays.
fn limit(name: &str, target: &mut usize, factor: usize) -> Result<(), String> {
    if let Some(text) = env(name) {
        let value: usize = text.parse().ok().filter(|value| *value > 0).ok_or(format!("{name}: “{text}” is not a number greater than zero"))?;
        *target = value.saturating_mul(factor);
    }
    Ok(())
}

/// A size in the unit in which it reads best.
fn size(bytes: u64) -> String {
    match bytes {
        0..=1023 => format!("{bytes} B"),
        1024..=1_048_575 => format!("{:.1} KB", bytes as f64 / 1024.0),
        _ => format!("{:.1} MB", bytes as f64 / 1_048_576.0),
    }
}

/// The administration actions on the command line. They act directly on the database, even while the
/// server is running.
fn manage(store: &Store, words: &[String]) -> Result<(), String> {
    let operator = Store::operator();
    let fail = |e: glowport_sync_server::store::Fail| e.to_string();
    let account = |name: &String| store.account_id(name).map_err(|_| format!("There is no account “{name}”"));
    match words {
        [command, file] if command == "backup" => {
            store.backup(&PathBuf::from(file)).map_err(|_| format!("The backup could not be written. Does {file} already exist, or is write permission missing in the folder?"))?;
            println!("Backup written: {file}");
        }
        [command] if command == "invite" => {
            let invite = store.create_invite(&operator).map_err(fail)?;
            println!("Invitation code: {}\nValid once, until {}.", invite.code, day(invite.expires_at));
        }
        [command] if command == "invites" => {
            let invites = store.invites(&operator).map_err(fail)?;
            if invites.is_empty() {
                println!("No open invitation codes.");
            }
            for invite in invites {
                println!("{}  valid until {}", invite.code, day(invite.expires_at));
            }
        }
        [command, code] if command == "revoke" => {
            store.revoke_invite(&operator, code).map_err(|_| format!("There is no open invitation code “{code}”"))?;
            println!("Invitation code revoked.");
        }
        [command] if command == "accounts" => {
            let accounts = store.accounts(&operator).map_err(fail)?;
            if accounts.is_empty() {
                println!("No account yet.");
            }
            for a in accounts {
                let marks = [a.admin.then_some("admin"), a.disabled.then_some("disabled")].into_iter().flatten().collect::<Vec<_>>().join(", ");
                let devices = if a.devices == 1 { "device " } else { "devices" };
                println!("{:<32} {:>2} {devices}  {:>9}  last seen {}  {marks}", a.username, a.devices, size(a.bytes), day(a.seen_at));
            }
        }
        [command, name] if command == "admin" || command == "noadmin" => {
            store.set_admin(&operator, &account(name)?, command == "admin").map_err(fail)?;
            println!("Account “{name}” is now {}. Glowport shows it after the next sync.", if command == "admin" { "an administrator" } else { "no longer an administrator" });
        }
        [command, name] if command == "disable" || command == "enable" => {
            store.set_disabled(&operator, &account(name)?, command == "disable").map_err(fail)?;
            println!("Account “{name}” is now {}.", if command == "disable" { "disabled" } else { "enabled" });
        }
        [command, name] if command == "delete" => {
            store.delete_account(&operator, &account(name)?).map_err(fail)?;
            println!("Account “{name}” is deleted.");
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
            return Err(format!("No server data found (searched in: {searched}). Name the server's folder with --data."));
        };
        let store = Store::open(&file).map_err(|e| format!("{}: {e}", file.display()))?;
        return manage(&store, &options.words);
    }

    let data = options.data.unwrap_or_else(|| PathBuf::from("data"));
    std::fs::create_dir_all(&data).map_err(|e| format!("Data folder {}: {e}", data.display()))?;
    let mut store = Store::open(&data.join("sync.db")).map_err(|e| format!("Data folder {}: {e}", data.display()))?;
    limit("GLOWPORT_SYNC_MAX_RECORD_KIB", &mut store.limits.record_bytes, 1024)?;
    limit("GLOWPORT_SYNC_MAX_RECORDS", &mut store.limits.records_per_vault, 1)?;
    limit("GLOWPORT_SYNC_MAX_VAULTS", &mut store.limits.vaults_per_account, 1)?;
    let address: SocketAddr = options.listen.parse().map_err(|_| format!("{}: not an address of the form 127.0.0.1:8787", options.listen))?;
    // Only the verifier is kept; every start therefore prints a new code, and only the latest is valid.
    if let Some(code) = store.setup_code().map_err(|e| e.to_string())? {
        println!("No account yet. Setup code for the first account (it becomes the administrator): {code}");
    }
    let app = App::with_proxies(store, options.proxies);
    app.log_requests();
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().map_err(|e| e.to_string())?;
    runtime.block_on(async {
        // Remove old tombstones once a day.
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
                println!("glowport-sync listening on {address}");
                serve(app, listener, stop).await.map_err(|e| e.to_string())
            }
            Some((cert, key)) => {
                let listener = std::net::TcpListener::bind(address).map_err(|e| format!("{address}: {e}"))?;
                println!("glowport-sync listening on {address} (TLS)");
                let files = format!("certificate {} / key {}", cert.display(), key.display());
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
        assert_eq!(size(1536), "1.5 KB");
        assert_eq!(size(5 * 1_048_576 + 104_858), "5.1 MB");
    }
}

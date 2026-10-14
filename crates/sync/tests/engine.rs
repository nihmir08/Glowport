//! Der Abgleich gegen einen echten Server im selben Prozess: über TCP, mit echten Tresor-Dateien, so wie
//! später zwischen dem Programm und `glowport-sync`.

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use glowport_core::{
    crypto::{self, KdfParams},
    roster::Role,
    vault::{Vault, VaultError},
};
use glowport_sync::{connect, engine::MIN_KDF, login_new, probe, register, Engine, Known, Link, Notice, Runner, Status, SyncError};
use glowport_sync_server::{
    serve, serve_tls,
    store::{Fail, Store},
    App,
};
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};

const FAST: KdfParams = KdfParams { memory_kib: 64, passes: 1, lanes: 1 };

type Id = [u8; 16];
type Door = Mutex<Vault>;

/// Räumt eine Datei weg, sobald nichts mehr darauf zeigt.
struct Temp(PathBuf);

impl Temp {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("glowport-engine-{}-{name}-{}", std::process::id(), crypto::hex(&crypto::random::<4>())));
        Self(path)
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Server {
    address: String,
    port: u16,
    app: Arc<App>,
    setup: Option<String>,
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl Server {
    async fn start(store: Store, port: u16) -> Self {
        let setup = store.setup_code().unwrap();
        let app = App::new(store, false);
        let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (stop, stopped) = oneshot::channel::<()>();
        let task = tokio::spawn({
            let app = app.clone();
            async move {
                let _ = serve(app, listener, async {
                    let _ = stopped.await;
                })
                .await;
            }
        });
        Self { address: format!("http://127.0.0.1:{port}"), port, app, setup, stop: Some(stop), task }
    }

    async fn new() -> Self {
        Self::start(Store::in_memory().unwrap(), 0).await
    }

    /// Derselbe Server mit eigenem TLS: Zertifikat und Schlüssel aus Dateien, ausgestellt auf `localhost`.
    /// Die Geräte dieses Prozesses trauen ab jetzt genau diesem Zertifikat.
    async fn tls(files: &Path) -> Self {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        std::fs::create_dir_all(files).unwrap();
        let (cert, key) = (files.join("cert.pem"), files.join("key.pem"));
        std::fs::write(&cert, certified.cert.pem()).unwrap();
        std::fs::write(&key, certified.signing_key.serialize_pem()).unwrap();
        glowport_sync::api::trust_only(certified.cert.der().to_vec());

        let store = Store::in_memory().unwrap();
        let setup = store.setup_code().unwrap();
        let app = App::new(store, false);
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let (stop, stopped) = oneshot::channel::<()>();
        let task = tokio::spawn({
            let app = app.clone();
            async move {
                serve_tls(app, listener, cert, key, async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
            }
        });
        Self { address: format!("https://localhost:{port}"), port, app, setup, stop: Some(stop), task }
    }

    fn setup(&self) -> &str {
        self.setup.as_deref().unwrap()
    }

    /// Hält den Server an: Er beendet seine Verbindungen, schließt die Datenbank und gibt den Port frei.
    async fn stop(mut self) -> u16 {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        // Offene WebSockets halten das geordnete Ende auf; dann wird abgebrochen.
        if tokio::time::timeout(Duration::from_secs(3), &mut self.task).await.is_err() {
            self.task.abort();
            let _ = (&mut self.task).await;
        }
        for _ in 0..150 {
            if Arc::strong_count(&self.app) == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        self.port
    }
}

/// Ein Gerät: eine Tresor-Datei, verbunden mit dem Server.
struct Device {
    door: Arc<Door>,
    engine: Arc<Engine<Door>>,
    _file: Temp,
}

fn password(name: &str) -> String {
    format!("pw-{name}")
}

impl Device {
    fn wrap(vault: Vault, file: Temp) -> Self {
        let door = Arc::new(Mutex::new(vault));
        let engine = Arc::new(Engine::open(door.clone()).unwrap().expect("mit dem Server verbunden"));
        Self { door, engine, _file: file }
    }

    /// Neues Konto aus einem neuen Tresor.
    async fn register(server: &Server, name: &str, code: &str) -> Self {
        let file = Temp::new(name);
        let door = Arc::new(Mutex::new(Vault::create(&file.0, &password(name), FAST).unwrap()));
        let engine = Arc::new(register(&door, &server.address, code, name, &password(name), &format!("PC von {name}")).await.unwrap());
        Self { door, engine, _file: file }
    }

    /// Weiteres Gerät eines Kontos: nur Benutzername und Master-Passwort.
    async fn login(server: &Server, name: &str, device: &str) -> Self {
        let file = Temp::new(name);
        let vault = login_new(&file.0, &server.address, name, &password(name), device, FAST).await.unwrap();
        Self::wrap(vault, file)
    }

    fn vault<T>(&self, work: impl FnOnce(&mut Vault) -> T) -> T {
        work(&mut self.door.lock().unwrap())
    }

    fn personal(&self) -> Id {
        self.vault(|v| v.personal().unwrap())
    }

    fn put(&self, id: Option<Id>, text: &str) -> Id {
        self.vault(|v| v.put(id, text.as_bytes()).unwrap())
    }

    fn put_in(&self, vault: &Id, text: &str) -> Id {
        self.vault(|v| v.put_in(vault, text.as_bytes()).unwrap())
    }

    /// Die Inhalte eines Tresors, ohne den Datensatz mit dessen Namen.
    fn texts(&self, vault: &Id) -> Vec<String> {
        let mut texts: Vec<String> = self.vault(|v| v.list().unwrap().records.iter().filter(|r| r.vault == *vault).map(|r| String::from_utf8(r.data.to_vec()).unwrap()).collect());
        texts.retain(|text| !text.contains("vault-info"));
        texts.sort();
        texts
    }

    fn notices(&self) -> Vec<Notice> {
        self.vault(|v| v.notices().unwrap().iter().map(|notice| serde_json::from_slice(&notice.data).unwrap()).collect())
    }

    fn role(&self, vault: &Id) -> Option<(Role, u64)> {
        self.vault(|v| v.vaults().unwrap().into_iter().find(|info| info.id == *vault).map(|info| (info.role, info.epoch)))
    }

    fn account(&self) -> Id {
        crypto::unhex(&self.engine.link().account).unwrap()
    }

    async fn invite_code(&self) -> String {
        self.engine.create_invite().await.unwrap().code
    }
}

fn refused<T>(result: Result<T, SyncError>, code: &str) {
    match result {
        Err(error) if error.code() == code => {}
        Err(error) => panic!("Ablehnung {code} erwartet, bekommen: {error:?}"),
        Ok(_) => panic!("Ablehnung {code} erwartet, aber es ging durch"),
    }
}

async fn eventually(what: &str, check: impl Fn() -> bool) {
    for _ in 0..200 {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("nicht eingetreten: {what}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_vault_becomes_an_account_and_a_second_device_follows() {
    let server = Server::new().await;
    let (address, info) = probe(&format!("{}/", server.address)).await.unwrap();
    assert_eq!((address.as_str(), info.fresh), (server.address.as_str(), true));
    assert!(matches!(probe("http://127.0.0.1:1").await, Err(SyncError::Offline(_))), "dort hört niemand");

    // Ein falscher Code legt kein Konto an und lässt den Tresor unverbunden.
    let file = Temp::new("anna");
    let door = Arc::new(Mutex::new(Vault::create(&file.0, &password("anna"), FAST).unwrap()));
    door.lock().unwrap().put(None, b"eins").unwrap();
    let host = door.lock().unwrap().put(None, br#"{"name":"web","own":{"port":22}}"#).unwrap();
    refused(register(&door, &server.address, "FALS-CHER-CODE", "anna", &password("anna"), "PC").await.map(drop), "code_invalid");
    refused(register(&door, &server.address, server.setup(), "anna", "falsches passwort", "PC").await.map(drop), "wrong_password");
    assert!(Engine::open(door.clone()).unwrap().is_none());

    let engine = register(&door, &server.address, server.setup(), "anna", &password("anna"), "PC").await.unwrap();
    assert!(engine.link().admin, "das erste Konto verwaltet den Server");
    refused(register(&door, &server.address, server.setup(), "anna", &password("anna"), "PC").await.map(drop), "already_linked");
    let one = Device { door, engine: Arc::new(engine), _file: file };
    let personal = one.personal();
    let report = one.engine.sync().await.unwrap();
    assert_eq!((report.pending, report.rolled_back.len(), report.notices), (0, 0, 0));
    assert!(!probe(&server.address).await.unwrap().1.fresh);

    // Das zweite Gerät braucht nur Benutzername und Master-Passwort.
    let missing = Temp::new("anna-falsch");
    refused(login_new(&missing.0, &server.address, "anna", "falsch", "Laptop", FAST).await.map(drop), "unauthorized");
    assert!(!missing.0.exists());
    assert!(matches!(login_new(&missing.0, &server.address, "anna", &password("anna"), "Laptop", MIN_KDF).await, Err(SyncError::Protocol(_))), "ein Server darf keine winzige Schlüsselableitung vorgeben");
    assert!(!missing.0.exists());
    let two = Device::login(&server, "anna", "Laptop").await;
    assert!(two.texts(&personal).is_empty());
    assert!(two.engine.sync().await.unwrap().changed);
    assert_eq!(two.texts(&personal), one.texts(&personal));
    assert!(!two.engine.sync().await.unwrap().changed, "eine Runde ohne Neues ändert nichts");

    // Verschiedene Felder desselben Eintrags: Beides bleibt, niemand bekommt einen Hinweis.
    one.put(Some(host), r#"{"name":"web-01","own":{"port":22}}"#);
    two.put(Some(host), r#"{"name":"web","own":{"port":2222}}"#);
    one.engine.sync().await.unwrap();
    assert_eq!(two.engine.sync().await.unwrap().notices, 0);
    one.engine.sync().await.unwrap();
    assert_eq!(one.texts(&personal), ["eins", r#"{"name":"web-01","own":{"port":2222}}"#]);
    assert_eq!(two.texts(&personal), one.texts(&personal));

    // Dasselbe Feld: Die neuere Änderung gilt, und das Gerät, das zusammenführt, hält es fest.
    one.put(Some(host), r#"{"name":"alt","own":{"port":2222}}"#);
    tokio::time::sleep(Duration::from_millis(5)).await;
    two.put(Some(host), r#"{"name":"neu","own":{"port":2222}}"#);
    one.engine.sync().await.unwrap();
    assert_eq!(two.engine.sync().await.unwrap().notices, 1);
    one.engine.sync().await.unwrap();
    assert_eq!(one.texts(&personal)[1], r#"{"name":"neu","own":{"port":2222}}"#);
    assert_eq!(two.notices(), [Notice::Clash { vault: crypto::hex(&personal), record: crypto::hex(&host), path: "name".into(), mine: true }]);

    // Löschen kommt an, und die Namen der Geräte kennt nur das Konto.
    one.vault(|v| v.delete(&host).unwrap());
    one.engine.sync().await.unwrap();
    two.engine.sync().await.unwrap();
    assert_eq!(two.texts(&personal), ["eins"]);
    let devices = one.engine.devices().await.unwrap();
    assert_eq!(devices.iter().map(|d| (d.name.as_str(), d.current)).collect::<Vec<_>>(), [("PC", true), ("Laptop", false)]);
}

#[tokio::test(flavor = "multi_thread")]
async fn changes_arrive_on_their_own() {
    let server = Server::new().await;
    let one = Device::register(&server, "anna", server.setup()).await;
    let two = Device::login(&server, "anna", "Laptop").await;
    let personal = one.personal();

    let seen: Arc<Mutex<Vec<Status>>> = Arc::default();
    let log = seen.clone();
    let first = Runner::start(one.engine.clone(), |_| {});
    let second = Runner::start(two.engine.clone(), move |status| log.lock().unwrap().push(status));
    let saw = |wanted: fn(&Status) -> bool| seen.lock().unwrap().iter().any(wanted);
    eventually("erste Runde", || saw(|s| matches!(s, Status::Synced(_)))).await;

    // Eine Änderung hier, ein Anstoß: Das andere Gerät hat sie, ohne dass dort jemand etwas tut.
    let id = one.put(None, "kommt von selbst");
    first.kick();
    eventually("Änderung auf dem zweiten Gerät", || two.texts(&personal) == ["kommt von selbst"]).await;
    assert!(saw(|s| matches!(s, Status::Synced(report) if report.changed)));
    two.vault(|v| v.delete(&id).unwrap());
    second.kick();
    eventually("Löschen auf dem ersten Gerät", || one.texts(&personal).is_empty()).await;

    // Gesperrt wird nicht abgeglichen; nach dem Entsperren geht es weiter.
    two.vault(|v| v.lock());
    seen.lock().unwrap().clear();
    one.put(None, "während der Sperre");
    first.kick();
    eventually("Meldung der Sperre", || saw(|s| *s == Status::Locked)).await;
    two.vault(|v| v.unlock(&password("anna")).unwrap());
    second.kick();
    eventually("Nachholen nach dem Entsperren", || two.texts(&personal) == ["während der Sperre"]).await;

    // Fällt der Server aus, meldet das Gerät „ohne Verbindung“ und behält, was wartet.
    drop(first);
    server.stop().await;
    seen.lock().unwrap().clear();
    two.put(None, "wartet");
    second.kick();
    eventually("Meldung ohne Verbindung", || saw(|s| *s == Status::Offline)).await;
    assert_eq!(two.vault(|v| v.pending(&personal).unwrap().len()), 1);
}

/// Der Weg zum Server auf dem Dedi: `https` für die Anfragen, `wss` für die Anstöße, das Zertifikat aus Dateien.
#[tokio::test(flavor = "multi_thread")]
async fn the_same_over_an_encrypted_connection() {
    let files = Temp::new("tls");
    let server = Server::tls(&files.0).await;
    let (address, info) = probe(&server.address).await.unwrap();
    assert_eq!((address.as_str(), info.fresh), (server.address.as_str(), true));
    // Dasselbe Zertifikat unter einem Namen, für den es nicht ausgestellt ist: abgelehnt, und zwar als das.
    match probe(&format!("https://127.0.0.1:{}", server.port)).await {
        Err(SyncError::Certificate(_)) => {}
        other => panic!("abgelehntes Zertifikat erwartet, bekommen: {other:?}"),
    }
    // Unverschlüsselt redet dieser Server nicht.
    assert!(probe(&format!("http://localhost:{}", server.port)).await.is_err());

    let one = Device::register(&server, "anna", server.setup()).await;
    let two = Device::login(&server, "anna", "Laptop").await;
    let personal = one.personal();
    let seen: Arc<Mutex<Vec<Status>>> = Arc::default();
    let log = seen.clone();
    let first = Runner::start(one.engine.clone(), |_| {});
    let _second = Runner::start(two.engine.clone(), move |status| log.lock().unwrap().push(status));
    eventually("erste Runde", || seen.lock().unwrap().iter().any(|s| matches!(s, Status::Synced(_)))).await;

    // Nur das erste Gerät wird angestoßen. Dass es beim zweiten binnen Sekunden ankommt, geht allein über den
    // WebSocket: Von sich aus fragt ein Gerät erst nach einer Minute wieder nach.
    one.put(None, "verschlüsselt unterwegs");
    first.kick();
    eventually("Änderung auf dem zweiten Gerät", || two.texts(&personal) == ["verschlüsselt unterwegs"]).await;

    // Ein geteilter Tresor samt Einladung geht denselben Weg.
    let bert = Device::register(&server, "bert", &one.invite_code().await).await;
    let shared = one.engine.create_vault("Team").await.unwrap();
    let candidate = one.engine.lookup("bert").await.unwrap();
    one.engine.invite(&shared, &candidate, Role::Read).await.unwrap();
    let invitations = bert.engine.sync().await.unwrap().invitations;
    assert_eq!(invitations.len(), 1);
    bert.engine.accept(&shared).await.unwrap();
    one.put_in(&shared, "für alle");
    one.engine.sync().await.unwrap();
    bert.engine.sync().await.unwrap();
    assert_eq!(bert.texts(&shared), ["für alle"]);
}

/// Wer an der Kommandozeile des Servers sitzt, verwaltet ihn ohne Konto, und kann einen neuen Verwalter ernennen.
#[tokio::test(flavor = "multi_thread")]
async fn the_operator_manages_without_an_account() {
    let server = Server::new().await;
    let anna = Device::register(&server, "anna", server.setup()).await;
    let (store, operator) = (&server.app.store, Store::operator());

    // Einladungscode von der Kommandozeile: gilt wie einer aus Glowport.
    let code = store.create_invite(&operator).unwrap().code;
    assert_eq!(store.invites(&operator).unwrap().len(), 1);
    let bert = Device::register(&server, "bert", &code).await;
    assert!(store.invites(&operator).unwrap().is_empty());
    let id = store.account_id("bert").unwrap();
    assert_eq!(id, bert.account());
    assert_eq!(store.account_id("niemand"), Err(Fail::NotFound));
    assert_eq!(store.accounts(&operator).unwrap().iter().map(|a| (a.username.as_str(), a.admin)).collect::<Vec<_>>(), [("anna", true), ("bert", false)]);

    // Verwalter ernennen: Das Gerät erfährt es mit dem nächsten Abgleich und behält es.
    refused(bert.engine.create_invite().await.map(drop), "not_admin");
    assert!(!bert.engine.sync().await.unwrap().admin);
    store.set_admin(&operator, &id, true).unwrap();
    assert!(bert.engine.sync().await.unwrap().admin);
    assert!(bert.vault(|v| Link::load(v).unwrap().unwrap().admin));
    bert.engine.create_invite().await.unwrap();
    // Aus Glowport heraus geht das nicht, auch nicht als Verwalter.
    let mut pretender = Store::operator();
    pretender.account = anna.account();
    assert_eq!(store.set_admin(&pretender, &id, false), Err(Fail::Forbidden("not_admin")));
    store.set_admin(&operator, &id, false).unwrap();
    assert!(!bert.engine.sync().await.unwrap().admin);
    assert!(!bert.vault(|v| Link::load(v).unwrap().unwrap().admin));
    refused(bert.engine.create_invite().await.map(drop), "not_admin");

    // Sperren und Löschen wirken sofort, auch auf den einzigen Verwalter.
    store.set_disabled(&operator, &anna.account(), true).unwrap();
    refused(anna.engine.sync().await.map(drop), "account_disabled");
    store.set_disabled(&operator, &anna.account(), false).unwrap();
    anna.engine.sync().await.unwrap();
    store.delete_account(&operator, &id).unwrap();
    refused(bert.engine.sync().await.map(drop), "unauthorized");
}

#[tokio::test(flavor = "multi_thread")]
async fn sharing_from_invitation_to_removal() {
    let server = Server::new().await;
    let anna = Device::register(&server, "anna", server.setup()).await;
    let bert = Device::register(&server, "bert", &anna.invite_code().await).await;
    let carl = Device::register(&server, "carl", &anna.invite_code().await).await;
    refused(bert.engine.create_invite().await.map(drop), "not_admin");

    // Anna legt einen Tresor an und lädt ein.
    refused(anna.engine.create_vault("  ").await.map(drop), "invalid");
    let shared = anna.engine.create_vault("Team").await.unwrap();
    refused(anna.engine.lookup("niemand").await.map(drop), "not_found");
    let candidate = anna.engine.lookup("bert").await.unwrap();
    assert_eq!((candidate.known, candidate.code.split(" · ").count()), (Known::New, 6));
    refused(anna.engine.invite(&shared, &candidate, Role::Owner).await, "invalid");
    anna.engine.invite(&shared, &candidate, Role::Write).await.unwrap();
    refused(anna.engine.invite(&shared, &candidate, Role::Read).await, "invalid");
    assert_eq!(anna.engine.lookup("bert").await.unwrap().known, Known::Same);
    anna.engine.invite(&shared, &anna.engine.lookup("carl").await.unwrap(), Role::Read).await.unwrap();
    anna.put_in(&shared, "team-host");
    anna.engine.sync().await.unwrap();

    // Bert sieht die Einladung mit Namen, Besitzerin und Rolle, bevor er annimmt.
    let report = bert.engine.sync().await.unwrap();
    assert_eq!(report.invitations.len(), 1);
    let invitation = &report.invitations[0];
    assert_eq!((invitation.name.as_deref(), invitation.owner.as_str(), invitation.role, invitation.known), (Some("Team"), "anna", Role::Write, Known::New));
    assert_eq!(invitation.code, bert.engine.lookup("anna").await.unwrap().code, "beide sehen denselben Sicherheitscode");
    assert!(bert.role(&shared).is_none(), "nur angesehen");
    refused(bert.engine.invite(&shared, &candidate, Role::Read).await, "vault");
    bert.engine.accept(&shared).await.unwrap();
    assert_eq!(bert.role(&shared), Some((Role::Write, 1)));
    assert_eq!(bert.texts(&shared), ["team-host"]);
    assert!(bert.engine.sync().await.unwrap().invitations.is_empty());
    // Solange Carl nicht angenommen hat, weiß Annas Gerät, dass er nur eingeladen ist.
    assert_eq!(anna.engine.sync().await.unwrap().invited, [(crypto::hex(&shared), crypto::hex(&carl.account()))]);
    carl.engine.accept(&shared).await.unwrap();
    assert!(anna.engine.sync().await.unwrap().invited.is_empty());
    assert_eq!(carl.texts(&shared), ["team-host"]);

    // Ein zweites Gerät von Bert bekommt den Tresor von selbst dazu.
    let bert2 = Device::login(&server, "bert", "Laptop").await;
    bert2.engine.sync().await.unwrap();
    assert_eq!((bert2.role(&shared), bert2.texts(&shared)), (Some((Role::Write, 1)), vec!["team-host".to_string()]));

    // Schreiben und lesen nach Rolle.
    bert.put_in(&shared, "von bert");
    bert.engine.sync().await.unwrap();
    anna.engine.sync().await.unwrap();
    carl.engine.sync().await.unwrap();
    assert_eq!(carl.texts(&shared), ["team-host", "von bert"]);
    assert!(matches!(carl.vault(|v| v.put_in(&shared, b"von carl")), Err(VaultError::ReadOnly)));
    refused(carl.engine.remove_member(&shared, &bert.account()).await, "not_owner");

    // Anna entfernt Carl, während bei Bert eine Änderung wartet.
    bert.put_in(&shared, "wartete bei bert");
    anna.engine.remove_member(&shared, &carl.account()).await.unwrap();
    assert_eq!(anna.role(&shared), Some((Role::Owner, 2)));
    let report = carl.engine.sync().await.unwrap();
    assert!(report.changed && carl.role(&shared).is_none());
    assert_eq!(carl.notices(), [Notice::VaultRemoved { vault: crypto::hex(&shared) }]);
    bert.engine.sync().await.unwrap();
    assert_eq!(bert.role(&shared), Some((Role::Write, 2)));
    anna.engine.sync().await.unwrap();
    assert_eq!(anna.texts(&shared), ["team-host", "von bert", "wartete bei bert"]);
    bert2.engine.sync().await.unwrap();
    assert_eq!((bert2.role(&shared), bert2.texts(&shared)), (Some((Role::Write, 2)), anna.texts(&shared)));

    // Weniger Rechte tauschen den Schlüssel, mehr Rechte nicht.
    bert.put_in(&shared, "kurz vor dem Herabstufen");
    anna.engine.set_role(&shared, &bert.account(), Role::Read).await.unwrap();
    let report = bert.engine.sync().await.unwrap();
    assert_eq!(bert.role(&shared), Some((Role::Read, 3)));
    assert_eq!((report.pending, bert.notices()), (0, vec![Notice::Discarded { vault: crypto::hex(&shared), count: 1 }]), "was nicht mehr hinaus darf, wird verworfen und gemeldet");
    anna.engine.set_role(&shared, &bert.account(), Role::Write).await.unwrap();
    bert.engine.sync().await.unwrap();
    assert_eq!(bert.role(&shared), Some((Role::Write, 3)));

    // Übergabe des Besitzes; danach geht Anna, und Berts Gerät tauscht von selbst den Schlüssel.
    anna.engine.transfer(&shared, &bert.account()).await.unwrap();
    bert.engine.sync().await.unwrap();
    assert_eq!((anna.role(&shared), bert.role(&shared)), (Some((Role::Write, 3)), Some((Role::Owner, 3))));
    refused(bert.engine.leave(&shared).await, "owner_cannot_leave");
    anna.engine.leave(&shared).await.unwrap();
    assert!(anna.role(&shared).is_none());
    bert.engine.sync().await.unwrap();
    assert_eq!(bert.role(&shared), Some((Role::Owner, 4)));
    assert_eq!(bert.vault(|v| v.vaults().unwrap()[1].roster.clone().unwrap().members.len()), 1);
    bert2.engine.sync().await.unwrap();
    assert_eq!(bert2.role(&shared), Some((Role::Owner, 4)));

    // Löschen für alle.
    bert.engine.delete_vault(&shared).await.unwrap();
    bert2.engine.sync().await.unwrap();
    assert!(bert.role(&shared).is_none());
    assert!(bert2.role(&shared).is_some(), "die Kopie des Besitzers bleibt, bis er sie selbst entfernt");
    assert_eq!(bert2.engine.sync().await.unwrap().orphaned, [crypto::hex(&shared)]);
}

#[tokio::test(flavor = "multi_thread")]
async fn password_devices_and_reconnecting() {
    let server = Server::new().await;
    let one = Device::register(&server, "anna", server.setup()).await;
    let two = Device::login(&server, "anna", "Laptop").await;
    let personal = one.personal();
    one.put(None, "eins");
    one.engine.sync().await.unwrap();

    // Passwort ändern: Der Server bekommt die neue Verpackung zuerst; das zweite Gerät merkt sie vor.
    refused(one.engine.change_password("falsch", "neues passwort", FAST, false).await, "wrong_password");
    one.engine.change_password(&password("anna"), "neues passwort", FAST, false).await.unwrap();
    assert!(two.engine.sync().await.unwrap().password_changed);
    two.vault(|v| {
        v.lock();
        v.unlock(&password("anna")).expect("das alte öffnet hier noch");
        v.lock();
        v.unlock("neues passwort").expect("das neue gilt ab jetzt");
        v.lock();
        assert!(matches!(v.unlock(&password("anna")), Err(VaultError::WrongPassword)));
        v.unlock("neues passwort").unwrap();
    });
    assert!(!two.engine.sync().await.unwrap().password_changed);

    // Geräte umbenennen und abmelden.
    let devices = one.engine.devices().await.unwrap();
    let other: Id = crypto::unhex(&devices.iter().find(|d| !d.current).unwrap().id).unwrap();
    one.engine.rename_device(&other, "Laptop im Büro").await.unwrap();
    assert_eq!(two.engine.devices().await.unwrap().iter().find(|d| d.current).unwrap().name, "Laptop im Büro");
    one.engine.remove_device(&other).await.unwrap();
    refused(two.engine.sync().await.map(drop), "unauthorized");

    // Das abgemeldete Gerät verbindet sich wieder: derselbe Tresor, eine neue Anmeldung.
    refused(connect(&two.door, &server.address, "anna", "neues passwort", "Laptop", FAST).await.map(drop), "already_linked");
    // Abmelden vor dem Löschen der Daten: Ein schon abgemeldetes Gerät gilt als abgemeldet.
    two.engine.sign_out().await.unwrap();
    two.engine.unlink().await.unwrap();
    assert!(Engine::open(two.door.clone()).unwrap().is_none());
    refused(connect(&two.door, &server.address, "anna", "falsch", "Laptop", FAST).await.map(drop), "unauthorized");
    let again = connect(&two.door, &server.address, "anna", "neues passwort", "Laptop wieder", FAST).await.unwrap();
    one.put(None, "zwei");
    one.engine.sync().await.unwrap();
    again.sync().await.unwrap();
    assert_eq!(two.texts(&personal), ["eins", "zwei"]);
    assert_eq!(one.engine.devices().await.unwrap().iter().map(|d| d.name.clone()).collect::<Vec<_>>(), ["PC von anna", "Laptop wieder"]);

    // Ein Tresor, der zu keinem Konto gehört, lässt sich so nicht verbinden, und es bleibt kein Gerät zurück.
    let foreign_file = Temp::new("fremd");
    let foreign = Arc::new(Mutex::new(Vault::create(&foreign_file.0, "lokal", FAST).unwrap()));
    foreign.lock().unwrap().put(None, b"lag schon auf diesem Geraet").unwrap();
    refused(connect(&foreign, &server.address, "anna", "neues passwort", "Dritter", FAST).await.map(drop), "other_account");
    assert!(Engine::open(foreign.clone()).unwrap().is_none());
    assert_eq!(one.engine.devices().await.unwrap().len(), 2);

    // Der Weg dafür: als neues Gerät anmelden und die vorhandenen Einträge in das Konto übernehmen.
    let third_file = Temp::new("anna-dritter");
    let mut vault = login_new(&third_file.0, &server.address, "anna", "neues passwort", "Dritter", FAST).await.unwrap();
    assert_eq!(vault.adopt_from(&foreign.lock().unwrap()).unwrap(), 1);
    let third = Device::wrap(vault, third_file);
    third.engine.sync().await.unwrap();
    one.engine.sync().await.unwrap();
    assert_eq!(one.texts(&personal), ["eins", "lag schon auf diesem Geraet", "zwei"]);
    assert_eq!(third.texts(&personal), one.texts(&personal));

    // Abmelden vor dem Löschen der Daten: Das Gerät verschwindet aus der Liste und kommt nicht mehr hinein.
    third.engine.sign_out().await.unwrap();
    refused(third.engine.sync().await.map(drop), "unauthorized");
    assert_eq!(one.engine.devices().await.unwrap().len(), 2);
}

/// Kopiert eine Sicherung des Servers an die Stelle seiner Datenbank.
fn restore(backup: &Path, data: &Path) {
    for leftover in ["sync.db", "sync.db-wal", "sync.db-shm"] {
        let _ = std::fs::remove_file(data.join(leftover));
    }
    std::fs::copy(backup, data.join("sync.db")).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_restored_server_gets_the_newer_state_back() {
    let data = Temp::new("server");
    std::fs::create_dir_all(&data.0).unwrap();
    let server = Server::start(Store::open(&data.0.join("sync.db")).unwrap(), 0).await;
    let one = Device::register(&server, "anna", server.setup()).await;
    let two = Device::login(&server, "anna", "Laptop").await;
    let personal = one.personal();
    let old = one.put(None, "alt");
    let gone = one.put(None, "wird geloescht");
    one.engine.sync().await.unwrap();
    two.engine.sync().await.unwrap();

    // Die Sicherung hält diesen Stand fest. Danach geht die Arbeit weiter, auf beiden Geräten.
    let backup = data.0.join("sicherung.db");
    server.app.store.backup(&backup).unwrap();
    one.put(Some(old), "neu");
    one.put(None, "nach der Sicherung");
    one.vault(|v| v.delete(&gone).unwrap());
    one.engine.sync().await.unwrap();
    two.engine.sync().await.unwrap();
    let expected = ["nach der Sicherung", "neu"];
    assert_eq!(two.texts(&personal), expected);

    // Der Server fällt aus und kommt aus der Sicherung zurück, unter derselben Adresse.
    let port = server.stop().await;
    restore(&backup, &data.0);
    let server = Server::start(Store::open(&data.0.join("sync.db")).unwrap(), port).await;
    assert!(server.setup.is_none(), "die Konten sind noch da");

    // Jedes Gerät merkt es, übernimmt nichts vom alten Stand und meldet den Tresor.
    for device in [&one, &two] {
        let mut report = device.engine.sync().await;
        if matches!(report, Err(SyncError::Offline(_))) {
            // Die alte Verbindung ist mit dem Server gestorben; die nächste Anfrage baut eine neue auf.
            report = device.engine.sync().await;
        }
        assert_eq!(report.unwrap().rolled_back, [crypto::hex(&personal)]);
        assert_eq!(device.texts(&personal), expected);
    }

    // Auf Wunsch lädt ein Gerät seinen Stand wieder hoch.
    one.engine.resync(&personal).await.unwrap();
    assert_eq!(one.texts(&personal), expected);
    let report = one.engine.sync().await.unwrap();
    assert_eq!((report.rolled_back.len(), report.pending), (0, 0));

    // Das andere findet danach von selbst wieder in den Gleichschritt, obwohl die Nummern des Servers
    // jetzt dieselben sind wie vor dem Ausfall.
    let report = two.engine.sync().await.unwrap();
    assert_eq!((report.rolled_back.len(), report.pending, report.notices), (0, 0, 0));
    assert_eq!(two.texts(&personal), expected);
    two.put(Some(old), "noch neuer");
    two.engine.sync().await.unwrap();
    one.engine.sync().await.unwrap();
    assert_eq!(one.texts(&personal), ["nach der Sicherung", "noch neuer"]);

    // Ein frisches Gerät bekommt vom Server genau diesen Stand, also hat er wirklich alles wieder.
    let three = Device::login(&server, "anna", "Dritter").await;
    three.engine.sync().await.unwrap();
    assert_eq!(three.texts(&personal), one.texts(&personal));
}

//! Der Zugriff gegen einen nachgebauten Proxmox-Server (`glowport_testserver::pve`): über TLS mit einem selbst
//! erstellten Zertifikat, wie Proxmox es mitbringt. Die Wege und Antworten sind nach der Dokumentation der
//! Schnittstelle gebaut, nicht an einem echten Server aufgezeichnet.

use glowport_proxmox::{fingerprint_text, look, Client, Kind, Missing, Power, PveError, Source};
use glowport_testserver::pve::{self, Shared, SECRET, TOKEN};

/// Startet den nachgebauten Server. Liefert seine Adresse, den Fingerabdruck seines Zertifikats und seinen Stand.
async fn start() -> (String, [u8; 32], Shared) {
    let running = pve::start().await.unwrap();
    (running.address, running.fingerprint, running.world)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_secret_only_travels_over_a_confirmed_certificate() {
    let (address, fingerprint, world) = start().await;

    // Ein Blick ohne Anmeldung: der Fingerabdruck, und dass diesem Zertifikat niemand von sich aus traut.
    let seen = look(&address).await.unwrap();
    assert_eq!((seen.fingerprint, seen.trusted), (fingerprint, false));
    assert_eq!(fingerprint_text(&seen.fingerprint).len(), 95);

    // Ohne bestätigten Fingerabdruck und mit einem falschen kommt keine Verbindung zustande.
    for pin in [None, Some([7u8; 32])] {
        let client = Client::new(&address, TOKEN, SECRET, pin).unwrap();
        assert_eq!(client.version().await, Err(PveError::Certificate));
        assert_eq!(client.seen().map(|look| (look.fingerprint, look.trusted)), Some((fingerprint, false)));
    }
    assert!(world.lock().unwrap().tokens.is_empty(), "bis hierher hat der Server kein Token gesehen");

    // Mit dem bestätigten Fingerabdruck gilt genau dieses Zertifikat.
    let client = Client::new(&address, TOKEN, SECRET, Some(fingerprint)).unwrap();
    assert_eq!(client.version().await.as_deref(), Ok("9.0.11"));
    assert_eq!(world.lock().unwrap().tokens, [format!("PVEAPIToken={TOKEN}={SECRET}")]);

    // Ein falsches Geheimnis, ein unvollständiges Token, eine Adresse, die keine ist, ein Server, den es nicht gibt.
    assert_eq!(Client::new(&address, TOKEN, "falsch", Some(fingerprint)).unwrap().version().await, Err(PveError::Token));
    for (token, secret) in [("glowport", SECRET), ("glowport@pve", SECRET), ("@pve!test", SECRET), (TOKEN, ""), (TOKEN, "mit leer"), (TOKEN, "zeile\r\nX-Kopf: 1")] {
        assert!(matches!(Client::new(&address, token, secret, None), Err(PveError::Token)), "{token} {secret:?}");
    }
    for bad in ["http://localhost:8006", "localhost:8006", "https://", "https://pve.example.de/pfad", "https://a b"] {
        assert!(matches!(Client::new(bad, TOKEN, SECRET, None), Err(PveError::Address)), "{bad}");
        assert_eq!(look(bad).await, Err(PveError::Address));
    }
    assert!(matches!(look("https://127.0.0.1:1").await, Err(PveError::Offline(_))));
    assert!(matches!(Client::new("https://127.0.0.1:1/", TOKEN, SECRET, None).unwrap().version().await, Err(PveError::Offline(_))));
}

#[tokio::test(flavor = "multi_thread")]
async fn machines_are_listed_located_and_switched() {
    let (address, fingerprint, world) = start().await;
    let client = Client::new(&address, TOKEN, SECRET, Some(fingerprint)).unwrap();

    let nodes = client.nodes().await.unwrap();
    assert_eq!(nodes.iter().map(|n| (n.node.as_str(), n.online, n.cores)).collect::<Vec<_>>(), [("alt", false, None), ("pve", true, Some(32))]);
    assert_eq!((nodes[1].cpu, nodes[1].memory, nodes[1].uptime), (Some(0.21), Some((76_235_669_504, 137_438_953_472)), Some(5_184_000)));

    // Nach Knoten und Nummer; was keine Maschine ist, fällt weg. Zahlen kommen auch als Text.
    let guests = client.guests().await.unwrap();
    assert_eq!(guests.iter().map(|g| (g.vmid, g.kind, g.name.as_str(), g.status, g.template)).collect::<Vec<_>>(), [
        (101, Kind::Qemu, "shop-01", "running", false),
        (111, Kind::Lxc, "pihole", "running", false),
        (112, Kind::Lxc, "gitea", "running", false),
        (120, Kind::Qemu, "monitoring", "running", false),
        (130, Kind::Qemu, "spielwiese", "stopped", false),
        (9000, Kind::Qemu, "debian-13-vorlage", "stopped", true),
    ]);
    let by = |vmid: u32| guests.iter().find(|g| g.vmid == vmid).unwrap();
    assert_eq!((by(101).tags.as_slice(), by(101).cpu, by(101).cores, by(101).uptime), (&["prod".to_string(), "web".to_string()][..], Some(0.18), Some(4), Some(1_209_600)));
    assert_eq!((by(130).tags.len(), by(130).cpu, by(130).uptime, by(130).memory), (0, None, None, Some((0, 4_294_967_296))), "aus: keine Last, keine Laufzeit");

    // Woher die Adresse kommt: Cloud-Init, Gastagent, Einstellungen des Containers, der Container selbst.
    let web = client.facts(by(101)).await.unwrap();
    assert_eq!((web.address, web.user.as_deref(), web.os), (Some(("10.0.10.11".into(), Source::CloudInit)), Some("deploy"), Some("Li")));
    assert_eq!(web.keys, ["SHA256:HHT2sEZO+TuiQj394rcd79mgejTl0WQ0Gdawh2rVk/c"], "der hinterlegte Schlüssel, wie OpenSSH ihn nennt");
    let monitoring = client.facts(by(120)).await.unwrap();
    assert_eq!((monitoring.address, monitoring.user), (Some(("10.0.10.90".into(), Source::Agent)), None));
    assert_eq!(client.facts(by(111)).await.unwrap().address, Some(("10.0.0.53".into(), Source::Config)));
    let gitea = client.facts(by(112)).await.unwrap();
    assert_eq!((gitea.address, gitea.user.as_deref(), gitea.os), (Some(("10.0.10.74".into(), Source::Guest)), Some("root"), Some("Al")));
    assert_eq!(client.facts(by(130)).await.unwrap().address, None, "aus und ohne feste Adresse");

    // Rechte: Dem vollen Token fehlt nichts, dem Leser das Schalten und der Gastagent.
    assert_eq!(client.missing().await.unwrap(), []);
    let reader = Client::new(&address, "leser@pve!test", SECRET, Some(fingerprint)).unwrap();
    assert_eq!(reader.missing().await.unwrap(), [Missing::Power, Missing::Agent]);
    assert_eq!(reader.power("pve", Kind::Qemu, 101, Power::Stop).await, Err(PveError::Forbidden));

    // Schalten wartet auf das Ende des Auftrags und meldet, wenn Proxmox ihn nicht ausführen konnte.
    client.power("pve", Kind::Qemu, 130, Power::Start).await.unwrap();
    client.power("pve", Kind::Qemu, 101, Power::Shutdown).await.unwrap();
    let after = client.guests().await.unwrap();
    assert_eq!(after.iter().filter(|g| [101, 130].contains(&g.vmid)).map(|g| g.status).collect::<Vec<_>>(), ["stopped", "running"]);
    assert_eq!(world.lock().unwrap().polls.values().copied().collect::<Vec<_>>(), [2, 2], "jeder Auftrag wurde abgewartet");
    assert_eq!(client.power("pve", Kind::Qemu, 9000, Power::Start).await, Err(PveError::Failed("unable to start VM 9000 - VM is a template".into())));
    assert_eq!(client.power("pve/../x", Kind::Qemu, 101, Power::Start).await, Err(PveError::Protocol("Knoten")));
    // Der Gastagent einer Maschine läuft nicht: Die Adresse bleibt offen, ein Fehler ist das nicht.
    let started = after.iter().find(|g| g.vmid == 130).unwrap();
    assert_eq!(client.facts(started).await.unwrap().address, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn right_after_switching_the_machine_itself_knows_its_state() {
    // Wie bei Proxmox: Die Liste aller Maschinen nennt nach dem Schalten noch eine Weile den alten Zustand.
    let running = pve::start_lagging(std::time::Duration::from_secs(30)).await.unwrap();
    let client = Client::new(&running.address, TOKEN, SECRET, Some(running.fingerprint)).unwrap();
    let listed = |guests: Vec<glowport_proxmox::Guest>, vmid: u32| guests.into_iter().find(|g| g.vmid == vmid).unwrap().status;

    assert_eq!(client.status("pve", Kind::Qemu, 130).await, Ok("stopped"));
    client.power("pve", Kind::Qemu, 130, Power::Start).await.unwrap();
    assert_eq!(listed(client.guests().await.unwrap(), 130), "stopped", "die Liste hinkt hinterher");
    assert_eq!(client.status("pve", Kind::Qemu, 130).await, Ok("running"));
    client.power("pve", Kind::Lxc, 111, Power::Stop).await.unwrap();
    assert_eq!((listed(client.guests().await.unwrap(), 111), client.status("pve", Kind::Lxc, 111).await), ("running", Ok("stopped")));
    assert_eq!(client.status("pve/../x", Kind::Qemu, 130).await, Err(PveError::Protocol("Knoten")));
    assert!(running.world.lock().unwrap().stale >= 2);
}

/// Die Prüfung gegen den Zertifikatsspeicher des Systems, an öffentlichen Adressen. Braucht das Internet und läuft
/// deshalb nur von Hand: `cargo test -p glowport-proxmox --test fake -- --ignored`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "braucht das Internet"]
async fn a_recognised_certificate_needs_no_fingerprint() {
    assert!(look("https://example.com").await.unwrap().trusted);
    assert!(!look("https://self-signed.badssl.com").await.unwrap().trusted);
    // Ohne Fingerabdruck entscheidet das System: Ein anerkanntes Zertifikat lässt die Anfrage durch (dort ist nur
    // kein Proxmox), ein selbst erstelltes nicht.
    let reached = Client::new("https://example.com", TOKEN, SECRET, None).unwrap().version().await;
    assert!(!matches!(reached, Err(PveError::Certificate | PveError::Offline(_))), "{reached:?}");
    assert_eq!(Client::new("https://self-signed.badssl.com", TOKEN, SECRET, None).unwrap().version().await, Err(PveError::Certificate));
}

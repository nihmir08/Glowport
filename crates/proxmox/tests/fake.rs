//! The access against a simulated Proxmox server (`glowport_testserver::pve`): over TLS with a self-signed
//! certificate, as Proxmox ships it. The routes and answers are built after the API documentation,
//! not recorded on a real server.

use glowport_proxmox::{fingerprint_text, look, Client, Kind, Missing, Power, PveError, Source};
use glowport_testserver::pve::{self, Shared, SECRET, TOKEN};

/// Starts the simulated server. Returns its address, its certificate's fingerprint and its state.
async fn start() -> (String, [u8; 32], Shared) {
    let running = pve::start().await.unwrap();
    (running.address, running.fingerprint, running.world)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_secret_only_travels_over_a_confirmed_certificate() {
    let (address, fingerprint, world) = start().await;

    // A look without signing in: the fingerprint, and that nobody trusts this certificate on their own.
    let seen = look(&address).await.unwrap();
    assert_eq!((seen.fingerprint, seen.trusted), (fingerprint, false));
    assert_eq!(fingerprint_text(&seen.fingerprint).len(), 95);

    // Without a confirmed fingerprint and with a wrong one no connection comes about.
    for pin in [None, Some([7u8; 32])] {
        let client = Client::new(&address, TOKEN, SECRET, pin).unwrap();
        assert_eq!(client.version().await, Err(PveError::Certificate));
        assert_eq!(client.seen().map(|look| (look.fingerprint, look.trusted)), Some((fingerprint, false)));
    }
    assert!(world.lock().unwrap().tokens.is_empty(), "the server has not seen a token up to here");

    // With the confirmed fingerprint exactly this certificate applies.
    let client = Client::new(&address, TOKEN, SECRET, Some(fingerprint)).unwrap();
    assert_eq!(client.version().await.as_deref(), Ok("9.0.11"));
    assert_eq!(world.lock().unwrap().tokens, [format!("PVEAPIToken={TOKEN}={SECRET}")]);

    // A wrong secret, an incomplete token, an address that is none, a server that does not exist.
    assert_eq!(Client::new(&address, TOKEN, "wrong", Some(fingerprint)).unwrap().version().await, Err(PveError::Token));
    for (token, secret) in [("glowport", SECRET), ("glowport@pve", SECRET), ("@pve!test", SECRET), (TOKEN, ""), (TOKEN, "with space"), (TOKEN, "line\r\nX-Header: 1")] {
        assert!(matches!(Client::new(&address, token, secret, None), Err(PveError::Token)), "{token} {secret:?}");
    }
    for bad in ["http://localhost:8006", "localhost:8006", "https://", "https://pve.example.com/path", "https://a b"] {
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
    assert_eq!(nodes.iter().map(|n| (n.node.as_str(), n.online, n.cores)).collect::<Vec<_>>(), [("old", false, None), ("pve", true, Some(32))]);
    assert_eq!((nodes[1].cpu, nodes[1].memory, nodes[1].uptime), (Some(0.21), Some((76_235_669_504, 137_438_953_472)), Some(5_184_000)));

    // By node and number; whatever is not a machine is dropped. Numbers also come as text.
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
    assert_eq!((by(130).tags.len(), by(130).cpu, by(130).uptime, by(130).memory), (0, None, None, Some((0, 4_294_967_296))), "off: no load, no uptime");

    // Where the address comes from: Cloud-Init, guest agent, container settings, the container itself.
    let web = client.facts(by(101)).await.unwrap();
    assert_eq!((web.address, web.user.as_deref(), web.os), (Some(("10.0.10.11".into(), Source::CloudInit)), Some("deploy"), Some("Li")));
    assert_eq!(web.keys, ["SHA256:HHT2sEZO+TuiQj394rcd79mgejTl0WQ0Gdawh2rVk/c"], "the stored key, as OpenSSH names it");
    let monitoring = client.facts(by(120)).await.unwrap();
    assert_eq!((monitoring.address, monitoring.user), (Some(("10.0.10.90".into(), Source::Agent)), None));
    assert_eq!(client.facts(by(111)).await.unwrap().address, Some(("10.0.0.53".into(), Source::Config)));
    let gitea = client.facts(by(112)).await.unwrap();
    assert_eq!((gitea.address, gitea.user.as_deref(), gitea.os), (Some(("10.0.10.74".into(), Source::Guest)), Some("root"), Some("Al")));
    assert_eq!(client.facts(by(130)).await.unwrap().address, None, "off and without a fixed address");

    // Permissions: the full token lacks nothing, the reader lacks switching and the guest agent.
    assert_eq!(client.missing().await.unwrap(), []);
    let reader = Client::new(&address, "leser@pve!test", SECRET, Some(fingerprint)).unwrap();
    assert_eq!(reader.missing().await.unwrap(), [Missing::Power, Missing::Agent]);
    assert_eq!(reader.power("pve", Kind::Qemu, 101, Power::Stop).await, Err(PveError::Forbidden));

    // Switching waits for the end of the task and reports when Proxmox could not carry it out.
    client.power("pve", Kind::Qemu, 130, Power::Start).await.unwrap();
    client.power("pve", Kind::Qemu, 101, Power::Shutdown).await.unwrap();
    let after = client.guests().await.unwrap();
    assert_eq!(after.iter().filter(|g| [101, 130].contains(&g.vmid)).map(|g| g.status).collect::<Vec<_>>(), ["stopped", "running"]);
    assert_eq!(world.lock().unwrap().polls.values().copied().collect::<Vec<_>>(), [2, 2], "every task was waited for");
    assert_eq!(client.power("pve", Kind::Qemu, 9000, Power::Start).await, Err(PveError::Failed("unable to start VM 9000 - VM is a template".into())));
    assert_eq!(client.power("pve/../x", Kind::Qemu, 101, Power::Start).await, Err(PveError::Protocol("Knoten")));
    // A machine's guest agent is not running: the address stays open, that is not an error.
    let started = after.iter().find(|g| g.vmid == 130).unwrap();
    assert_eq!(client.facts(started).await.unwrap().address, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn right_after_switching_the_machine_itself_knows_its_state() {
    // As with Proxmox: the list of all machines still names the old state for a while after switching.
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

/// Checking against the system's certificate store, at public addresses. Needs the internet and therefore
/// only runs by hand: `cargo test -p glowport-proxmox --test fake -- --ignored`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the internet"]
async fn a_recognised_certificate_needs_no_fingerprint() {
    assert!(look("https://example.com").await.unwrap().trusted);
    assert!(!look("https://self-signed.badssl.com").await.unwrap().trusted);
    // Without a fingerprint the system decides: a trusted certificate lets the request through (there is just
    // no Proxmox there), a self-signed one does not.
    let reached = Client::new("https://example.com", TOKEN, SECRET, None).unwrap().version().await;
    assert!(!matches!(reached, Err(PveError::Certificate | PveError::Offline(_))), "{reached:?}");
    assert_eq!(Client::new("https://self-signed.badssl.com", TOKEN, SECRET, None).unwrap().version().await, Err(PveError::Certificate));
}

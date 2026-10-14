//! Checking certificates against the system's store, at public addresses. Needs the internet
//! and therefore only runs by hand: `cargo test -p glowport-sync --test internet -- --ignored`.

use glowport_sync::{probe, SyncError};

#[tokio::test(flavor = "multi_thread")]
#[ignore = "braucht das Internet"]
async fn certificates_are_checked_against_the_system_store() {
    // A valid certificate: the connection stands, there is just no Glowport server there.
    match probe("https://example.com").await {
        Err(SyncError::Refused { .. } | SyncError::Protocol(_)) => {}
        other => panic!("eine Antwort erwartet, die kein Glowport-Server ist, bekommen: {other:?}"),
    }
    // Expired, self-signed, for another name: each refused as a certificate problem.
    for address in ["https://expired.badssl.com", "https://self-signed.badssl.com", "https://wrong.host.badssl.com", "https://untrusted-root.badssl.com"] {
        match probe(address).await {
            Err(SyncError::Certificate(_)) => {}
            other => panic!("{address}: abgelehntes Zertifikat erwartet, bekommen: {other:?}"),
        }
    }
}

/// How long it takes until an address without a sync server is reported as such.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "braucht das Internet"]
async fn wrong_addresses_are_reported_soon() {
    for address in ["gibt-es-nicht.example.com", "sync.example.invalid", "quatsch", "example.org", "example.com", "192.0.2.1", "example.com:444"] {
        let started = std::time::Instant::now();
        let outcome = probe(address).await;
        println!("{address:<32} {:>6} ms  {:?}", started.elapsed().as_millis(), outcome.map(|(server, _)| server).map_err(|e| e.code().to_string()));
    }
}

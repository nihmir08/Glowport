//! The server against real vaults: every “device” here is a vault file of the core, and everything goes through
//! the same paths as later over the network (router, JSON, device token).

use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicI64, Ordering},
        Arc,
    },
};

use axum::{
    body::Body,
    http::{Method, Request},
    Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use glowport_core::{
    crypto::{self, KdfParams},
    roster::{Member, Role},
    vault::{Envelope, Vault},
};
use glowport_sync_proto::*;
use glowport_sync_server::{router, store::Store, App};
use serde::{de::DeserializeOwned, Serialize};
use tower::ServiceExt;

const FAST: KdfParams = KdfParams { memory_kib: 64, passes: 1, lanes: 1 };
const MINUTE: i64 = 60_000;
const DAY: i64 = 24 * 60 * MINUTE;

struct Server {
    router: Router,
    app: Arc<App>,
    clock: Arc<AtomicI64>,
    setup: String,
}

/// Error response: status and code.
type Failure = (u16, String);

impl Server {
    fn new() -> Self {
        let clock = Arc::new(AtomicI64::new(1_800_000_000_000));
        let mut store = Store::in_memory().unwrap();
        let now = clock.clone();
        store.set_clock(move || now.load(Ordering::SeqCst));
        let setup = store.setup_code().unwrap().unwrap();
        let app = App::new(store, false);
        Self { router: router(app.clone()), app, clock, setup }
    }

    fn pass(&self, ms: i64) {
        self.clock.fetch_add(ms, Ordering::SeqCst);
    }

    async fn call<T: DeserializeOwned>(&self, method: Method, path: &str, token: Option<&Bytes>, body: Option<serde_json::Value>) -> Result<T, Failure> {
        let mut request = Request::builder().method(method).uri(path);
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {}", STANDARD.encode(&token.0)));
        }
        let request = match body {
            Some(body) => request.header("content-type", "application/json").body(Body::from(body.to_string())),
            None => request.body(Body::empty()),
        }
        .unwrap();
        let response = self.router.clone().oneshot(request).await.unwrap();
        let status = response.status().as_u16();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        if status == 200 {
            Ok(serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("{path}: {e}: {}", String::from_utf8_lossy(&bytes))))
        } else {
            Err((status, serde_json::from_slice::<ApiError>(&bytes).map(|e| e.code).unwrap_or_default()))
        }
    }

    async fn get<T: DeserializeOwned>(&self, path: &str, token: &Bytes) -> Result<T, Failure> {
        self.call(Method::GET, path, Some(token), None).await
    }

    async fn post<T: DeserializeOwned>(&self, path: &str, token: Option<&Bytes>, body: impl Serialize) -> Result<T, Failure> {
        self.call(Method::POST, path, token, Some(serde_json::to_value(body).unwrap())).await
    }

    async fn delete(&self, path: &str, token: &Bytes) -> Result<(), Failure> {
        self.call(Method::DELETE, path, Some(token), None).await
    }
}

fn fails<T: std::fmt::Debug>(result: Result<T, Failure>, status: u16, code: &str) {
    match result {
        Err((s, c)) => assert_eq!((s, c.as_str()), (status, code)),
        Ok(value) => panic!("Ablehnung {status} {code} erwartet, bekommen: {value:?}"),
    }
}

/// A device: a vault file and its sign-in at the server.
struct Device {
    vault: Vault,
    path: PathBuf,
    token: Bytes,
    account: [u8; 16],
    name: String,
}

impl Drop for Device {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn temp(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("glowport-sync-{}-{name}.db", std::process::id()));
    let _ = std::fs::remove_file(&path);
    path
}

impl Device {
    fn hex(&self, vault: &[u8; 16]) -> String {
        crypto::hex(vault)
    }

    fn personal(&self) -> [u8; 16] {
        self.vault.personal().unwrap()
    }

    fn member(&self, role: Role) -> Member {
        let (ed25519, x25519) = self.vault.public_keys().unwrap();
        Member { account: crypto::hex(&self.account), name: self.name.clone(), ed25519: crypto::hex(&ed25519), x25519: crypto::hex(&x25519), role }
    }

    /// Sends what is waiting. If the server refuses, it merges and sends again.
    async fn push(&mut self, server: &Server, vault: &[u8; 16]) -> Result<PushReply, Failure> {
        for _ in 0..3 {
            let outgoing = self.vault.outgoing(vault).unwrap();
            let sent: Vec<Envelope> = outgoing.iter().map(|(envelope, _)| envelope.clone()).collect();
            let epoch = self.vault.vaults().unwrap().iter().find(|v| v.id == *vault).unwrap().epoch;
            let body = Push { epoch, records: outgoing.iter().map(|(envelope, base)| WireRecord::outgoing(envelope, *base)).collect() };
            let reply: PushReply = server.post(&format!("/v1/vaults/{}/records", self.hex(vault)), Some(&self.token), body).await?;
            if reply.accepted {
                self.vault.acknowledge(vault, &sent).unwrap();
                return Ok(reply);
            }
            if reply.conflicts.is_empty() {
                return Ok(reply);
            }
            let theirs: Vec<Envelope> = reply.conflicts.iter().map(|r| r.envelope().unwrap()).collect();
            assert!(self.vault.apply_remote(vault, &theirs).unwrap().rejected.is_empty());
        }
        panic!("not accepted after three attempts");
    }

    async fn pull(&mut self, server: &Server, vault: &[u8; 16]) -> Result<Pull, Failure> {
        let after = self.vault.cursor(vault).unwrap();
        let pull: Pull = server.get(&format!("/v1/vaults/{}/records?after={after}", self.hex(vault)), &self.token).await?;
        let rows: Vec<Envelope> = pull.records.iter().map(|r| r.envelope().unwrap()).collect();
        assert!(self.vault.apply_remote(vault, &rows).unwrap().rejected.is_empty(), "the honest server delivers nothing wrong");
        self.vault.set_cursor(vault, pull.seq).unwrap();
        Ok(pull)
    }

    fn names(&self, vault: &[u8; 16]) -> Vec<String> {
        let mut names: Vec<String> = self.vault.list().unwrap().records.iter().filter(|r| r.vault == *vault).map(|r| String::from_utf8(r.data.to_vec()).unwrap()).collect();
        names.sort();
        names
    }
}

async fn register(server: &Server, name: &str, code: &str) -> Result<Device, Failure> {
    let path = temp(&format!("{name}-{}", crypto::hex(&crypto::random::<4>())));
    let vault = Vault::create(&path, name, FAST).unwrap();
    let request = Register { code: code.into(), username: name.into(), auth_key: vault.auth_key(name).unwrap().as_ref().into(), account: (&vault.account().unwrap()).into(), device_name: b"erstes".into() };
    let result: Result<LoginReply, Failure> = server.post("/v1/register", None, request).await;
    match result {
        Ok(reply) => {
            let session = reply.session.unwrap();
            Ok(Device { vault, path, token: session.token, account: session.account_id.array().unwrap(), name: name.into() })
        }
        Err(failure) => {
            drop(vault);
            let _ = std::fs::remove_file(&path);
            Err(failure)
        }
    }
}

/// Another device of the same account: only user name and master password (here equal to the name).
async fn login(server: &Server, name: &str, password: &str) -> Result<Device, Failure> {
    let salt: PreloginReply = server.post("/v1/prelogin", None, Prelogin { username: name.into() }).await?;
    let auth = glowport_core::vault::auth_key(password, &salt.salt.array().unwrap(), salt.kdf.into()).unwrap();
    let reply: LoginReply = server.post("/v1/login", None, Login { username: name.into(), auth_key: auth.as_ref().into(), device_name: b"zweites".into() }).await?;
    let session = reply.session.unwrap();
    let path = temp(&format!("{name}-{}", crypto::hex(&crypto::random::<4>())));
    let vault = Vault::create_from_account(&path, password, &session.account.account().unwrap()).unwrap();
    Ok(Device { vault, path, token: session.token, account: session.account_id.array().unwrap(), name: name.into() })
}

async fn invite(server: &Server, admin: &Device) -> String {
    server.post::<Invite>("/v1/admin/invites", Some(&admin.token), ()).await.unwrap().code
}

#[tokio::test]
async fn accounts_need_a_code_and_logins_are_throttled() {
    let server = Server::new();
    assert!(server.call::<Info>(Method::GET, "/v1/info", None, None).await.unwrap().fresh);
    fails(register(&server, "anna", "FALS-CHER-CODE").await.map(drop), 403, "code_invalid");
    let anna = register(&server, "anna", &server.setup).await.unwrap();
    assert!(!server.call::<Info>(Method::GET, "/v1/info", None, None).await.unwrap().fresh);
    fails(register(&server, "bert", &server.setup).await.map(drop), 403, "code_invalid");

    let code = invite(&server, &anna).await;
    fails(register(&server, "anna", &code).await.map(drop), 409, "username_taken");
    fails(register(&server, "Bert!", &code).await.map(drop), 400, "bad_request");
    let bert = register(&server, "bert", &code.to_lowercase()).await.unwrap();
    fails(register(&server, "carl", &code).await.map(drop), 403, "code_invalid");
    fails(server.post::<Invite>("/v1/admin/invites", Some(&bert.token), ()).await, 403, "not_admin");
    fails(server.get::<Overview>("/v1/account", &Bytes(vec![1; 32])).await, 401, "unauthorized");

    // An expired code is no longer valid.
    let code = invite(&server, &anna).await;
    server.pass(8 * DAY);
    fails(register(&server, "carl", &code).await.map(drop), 403, "code_invalid");
    assert!(server.get::<Vec<Invite>>("/v1/admin/invites", &anna.token).await.unwrap().is_empty());

    // Unbekannte Namen bekommen feste erfundene Werte.
    let unknown = |name: &str| server.post::<PreloginReply>("/v1/prelogin", None, Prelogin { username: name.into() });
    assert_eq!(unknown("niemand").await.unwrap(), unknown("niemand").await.unwrap());
    assert_ne!(unknown("niemand").await.unwrap().salt, unknown("keiner").await.unwrap().salt);

    // The second device opens with the master password; wrong attempts are slowed down.
    let second = login(&server, "bert", "bert").await.unwrap();
    assert_eq!(second.vault.public_keys().unwrap(), bert.vault.public_keys().unwrap());
    for _ in 0..5 {
        fails(login(&server, "bert", "falsch").await.map(drop), 401, "unauthorized");
    }
    fails(login(&server, "bert", "bert").await.map(drop), 429, "too_many_attempts");
    server.pass(16 * MINUTE);
    login(&server, "bert", "bert").await.unwrap();

    let overview: Overview = server.get("/v1/account", &second.token).await.unwrap();
    assert_eq!((overview.username.as_str(), overview.admin, overview.vaults.len(), overview.vaults[0].shared), ("bert", false, 1, false));
    assert_eq!(overview.vaults[0].id.0, bert.personal());
}

#[tokio::test]
async fn two_devices_of_one_account_converge() {
    let server = Server::new();
    let mut one = register(&server, "anna", &server.setup).await.unwrap();
    let personal = one.personal();
    one.vault.put(None, b"eins").unwrap();
    let host = one.vault.put(None, br#"{"name":"web","own":{"port":22}}"#).unwrap();
    assert_eq!(one.push(&server, &personal).await.unwrap().seq, 1);

    let mut two = login(&server, "anna", "anna").await.unwrap();
    assert_eq!(two.pull(&server, &personal).await.unwrap().records.len(), 2);
    assert_eq!(two.names(&personal), one.names(&personal));
    assert!(two.pull(&server, &personal).await.unwrap().records.is_empty(), "nothing new since the last number");

    // Both change the same host without knowing of each other: the second one at the server merges.
    two.vault.put(Some(host), br#"{"name":"web","own":{"port":2222}}"#).unwrap();
    one.vault.put(Some(host), br#"{"name":"web-01","own":{"port":22}}"#).unwrap();
    assert!(two.push(&server, &personal).await.unwrap().accepted);
    assert!(one.push(&server, &personal).await.unwrap().accepted);
    two.pull(&server, &personal).await.unwrap();
    one.pull(&server, &personal).await.unwrap();
    assert_eq!(one.names(&personal), ["eins", r#"{"name":"web-01","own":{"port":2222}}"#]);
    assert_eq!(two.names(&personal), one.names(&personal));
    assert!(one.vault.pending(&personal).unwrap().is_empty() && two.vault.pending(&personal).unwrap().is_empty());

    // Deleting arrives.
    one.vault.delete(&host).unwrap();
    one.push(&server, &personal).await.unwrap();
    two.pull(&server, &personal).await.unwrap();
    assert_eq!(two.names(&personal), ["eins"]);

    // All or nothing: a package with an outdated record does not get the new one in either.
    let stale = two.vault.pending(&personal).unwrap();
    assert!(stale.is_empty());
    let kept = one.vault.put(None, b"stays").unwrap();
    one.push(&server, &personal).await.unwrap();
    two.pull(&server, &personal).await.unwrap();
    one.vault.put(Some(kept), b"stays, newer").unwrap();
    one.push(&server, &personal).await.unwrap();
    two.vault.put(Some(kept), b"stays, outdated").unwrap();
    two.vault.put(None, b"new").unwrap();
    let body = Push { epoch: 1, records: two.vault.outgoing(&personal).unwrap().iter().map(|(envelope, base)| WireRecord::outgoing(envelope, *base)).collect() };
    let path = format!("/v1/vaults/{}/records", crypto::hex(&personal));
    let reply: PushReply = server.post(&path, Some(&two.token), &body).await.unwrap();
    assert_eq!((reply.accepted, reply.conflicts.len()), (false, 1));
    assert_eq!(server.get::<Pull>(&format!("{path}?after=0"), &two.token).await.unwrap().records.len(), 3, "one, the tombstone, stays");

    // What the server can check without a key, it checks: signature and author.
    let mut forged = body.clone();
    forged.records[0].revision += 5;
    fails(server.post::<PushReply>(&path, Some(&two.token), &forged).await, 403, "record_invalid");
    let stranger = register(&server, "bert", &invite(&server, &one).await).await.unwrap();
    fails(server.post::<PushReply>(&path, Some(&stranger.token), &body).await, 403, "record_invalid");
    fails(server.get::<Pull>(&format!("{path}?after=0"), &stranger.token).await, 404, "not_found");
}

#[tokio::test]
async fn sharing_roles_and_key_rotation() {
    let server = Server::new();
    let mut anna = register(&server, "anna", &server.setup).await.unwrap();
    let mut bert = register(&server, "bert", &invite(&server, &anna).await).await.unwrap();
    let mut carl = register(&server, "carl", &invite(&server, &anna).await).await.unwrap();

    // Anna creates a vault and invites Bert (write) and Carl (read).
    let shared = anna.vault.create_shared(&anna.account, "anna").unwrap();
    let path = format!("/v1/vaults/{}", crypto::hex(&shared));
    let create = CreateVault { id: shared.into(), roster: anna.vault.roster_blob(&shared).unwrap().into(), sealed_key: anna.vault.seal_key_for(&shared, &anna.vault.public_keys().unwrap().1).unwrap().into() };
    server.post::<()>("/v1/vaults", Some(&anna.token), &create).await.unwrap();
    fails(server.post::<()>("/v1/vaults", Some(&anna.token), &create).await, 409, "vault_exists");

    let keys: PublicKeys = server.get("/v1/keys/bert", &anna.token).await.unwrap();
    assert_eq!(keys.ed25519.0, bert.vault.public_keys().unwrap().0);
    fails(server.get::<PublicKeys>("/v1/keys/niemand", &anna.token).await, 404, "not_found");
    let mut roster = anna.vault.vaults().unwrap()[1].roster.clone().unwrap();
    roster.version = 2;
    roster.members.extend([bert.member(Role::Write), carl.member(Role::Read)]);
    let blob = anna.vault.sign_roster(&shared, &roster).unwrap();
    let sealed = |device: &Device| SealedKey { member: device.vault.public_keys().unwrap().0.into(), sealed: anna.vault.seal_key_for(&shared, &device.vault.public_keys().unwrap().1).unwrap().into() };
    let update = RosterUpdate { roster: blob.clone().into(), keys: vec![sealed(&bert), sealed(&carl)] };
    fails(server.post::<()>(&format!("{path}/roster"), Some(&anna.token), RosterUpdate { roster: blob.clone().into(), keys: vec![sealed(&bert)] }).await, 400, "bad_request");
    server.post::<()>(&format!("{path}/roster"), Some(&anna.token), &update).await.unwrap();
    anna.vault.set_roster(&shared, &blob).unwrap();

    // Invited means: list and key are ready, and the content can already be viewed.
    for device in [&mut bert, &mut carl] {
        let overview: Overview = server.get("/v1/account", &device.token).await.unwrap();
        let entry = overview.vaults.iter().find(|v| v.shared).unwrap();
        assert!(entry.invited);
        assert_eq!(entry.members.len(), 3);
        // Viewing already works, writing only after accepting.
        server.get::<Pull>(&format!("{path}/records?after=0"), &device.token).await.unwrap();
        fails(server.post::<PushReply>(&format!("{path}/records"), Some(&device.token), Push { epoch: 1, records: Vec::new() }).await, 403, "read_only");
        server.post::<()>(&format!("{path}/accept"), Some(&device.token), ()).await.unwrap();
        device.vault.join_shared(&shared, &entry.sealed_key.as_ref().unwrap().0, &entry.roster.as_ref().unwrap().0).unwrap();
    }

    anna.vault.put_in(&shared, b"team-host").unwrap();
    anna.push(&server, &shared).await.unwrap();
    bert.pull(&server, &shared).await.unwrap();
    carl.pull(&server, &shared).await.unwrap();
    assert_eq!(carl.names(&shared), ["team-host"]);
    bert.vault.put_in(&shared, b"from bert").unwrap();
    bert.push(&server, &shared).await.unwrap();
    anna.pull(&server, &shared).await.unwrap();
    assert_eq!(anna.names(&shared), ["from bert", "team-host"]);

    // Carl may only read: not even a record signed by Bert gets in through Carl's sign-in.
    bert.vault.put_in(&shared, b"waiting at bert").unwrap();
    let smuggled = Push { epoch: 1, records: bert.vault.pending(&shared).unwrap().iter().map(WireRecord::from).collect() };
    fails(server.post::<PushReply>(&format!("{path}/records"), Some(&carl.token), &smuggled).await, 403, "record_invalid");
    let own = Push { epoch: 1, records: Vec::new() };
    fails(server.post::<PushReply>(&format!("{path}/records"), Some(&carl.token), &own).await, 403, "read_only");

    // Only the owner changes the list, and only a key rotation takes permissions away.
    let mut reduced = roster.clone();
    reduced.version = 3;
    reduced.members.retain(|m| m.name != "carl");
    let blob = anna.vault.sign_roster(&shared, &reduced).unwrap();
    fails(server.post::<()>(&format!("{path}/roster"), Some(&anna.token), RosterUpdate { roster: blob.into(), keys: vec![] }).await, 403, "needs_rotation");
    fails(server.post::<()>(&format!("{path}/roster"), Some(&bert.token), &update).await, 403, "roster_invalid");

    // Anna removes Carl. Bert's waiting change survives the rotation.
    reduced.epoch = 2;
    let seq = anna.pull(&server, &shared).await.unwrap().seq;
    let rotation = anna.vault.prepare_rotation(&shared, &reduced).unwrap();
    let mut request = Rotate {
        expected_seq: seq + 7,
        roster: rotation.roster.clone().into(),
        keys: rotation.keys.iter().map(|(member, sealed)| SealedKey { member: member.into(), sealed: sealed.into() }).collect(),
        records: rotation.records.iter().map(WireRecord::from).collect(),
    };
    fails(server.post::<()>(&format!("{path}/rotate"), Some(&anna.token), &request).await, 409, "vault_changed");
    fails(server.post::<()>(&format!("{path}/rotate"), Some(&bert.token), &request).await, 403, "record_invalid");
    request.expected_seq = seq;
    server.post::<()>(&format!("{path}/rotate"), Some(&anna.token), &request).await.unwrap();
    anna.vault.commit_rotation(rotation).unwrap();

    fails(server.get::<Pull>(&format!("{path}/records?after=0"), &carl.token).await, 404, "not_found");
    assert!(server.get::<Overview>("/v1/account", &carl.token).await.unwrap().vaults.iter().all(|v| !v.shared));

    let reply = bert.push(&server, &shared).await.unwrap();
    assert_eq!((reply.accepted, reply.epoch), (false, 2), "with the old key epoch the server accepts nothing");
    let overview: Overview = server.get("/v1/account", &bert.token).await.unwrap();
    let entry = overview.vaults.iter().find(|v| v.shared).unwrap();
    assert_eq!(entry.epoch, 2);
    let pull: Pull = server.get(&format!("{path}/records?after={}", bert.vault.cursor(&shared).unwrap()), &bert.token).await.unwrap();
    let rows: Vec<Envelope> = pull.records.iter().map(|r| r.envelope().unwrap()).collect();
    assert_eq!(rows.len(), 2, "after the rotation everything comes anew");
    assert!(bert.vault.apply_rotation(&shared, &entry.sealed_key.as_ref().unwrap().0, &entry.roster.as_ref().unwrap().0, &rows).unwrap().rejected.is_empty());
    bert.vault.set_cursor(&shared, pull.seq).unwrap();
    assert!(bert.push(&server, &shared).await.unwrap().accepted);
    anna.pull(&server, &shared).await.unwrap();
    assert_eq!(anna.names(&shared), ["from bert", "team-host", "waiting at bert"]);
    assert_eq!(bert.names(&shared), anna.names(&shared));

    // Bert leaves on his own; Anna as owner cannot leave, but can delete.
    server.post::<()>(&format!("{path}/leave"), Some(&bert.token), ()).await.unwrap();
    fails(server.get::<Pull>(&format!("{path}/records?after=0"), &bert.token).await, 404, "not_found");
    fails(server.post::<()>(&format!("{path}/leave"), Some(&anna.token), ()).await, 403, "owner_cannot_leave");
    server.delete(&path, &anna.token).await.unwrap();
    assert_eq!(server.get::<Overview>("/v1/account", &anna.token).await.unwrap().vaults.len(), 1);
}

#[tokio::test]
async fn devices_password_and_administration() {
    let server = Server::new();
    let anna = register(&server, "anna", &server.setup).await.unwrap();
    let mut bert = register(&server, "bert", &invite(&server, &anna).await).await.unwrap();
    let second = login(&server, "bert", "bert").await.unwrap();

    // Devices: list, signing out another one.
    let devices: Vec<Device2> = server.get("/v1/devices", &bert.token).await.unwrap();
    assert_eq!((devices.len(), devices.iter().filter(|d| d.current).count()), (2, 1));
    let other = devices.iter().find(|d| !d.current).unwrap();
    server.delete(&format!("/v1/devices/{}", crypto::hex(&other.id.0)), &bert.token).await.unwrap();
    fails(server.get::<Overview>("/v1/account", &second.token).await, 401, "unauthorized");
    fails(server.delete(&format!("/v1/devices/{}", crypto::hex(&other.id.0)), &anna.token).await, 404, "not_found");

    // Changing the password: only with the previous sign-in key; afterwards the new one applies.
    let third = login(&server, "bert", "bert").await.unwrap();
    let old_auth = bert.vault.auth_key("bert").unwrap();
    bert.vault.change_password("bert", "neues passwort", FAST).unwrap();
    let account = bert.vault.account().unwrap();
    let change = |auth: &[u8]| PasswordChange {
        auth_key: auth.into(),
        new_auth_key: bert.vault.auth_key("neues passwort").unwrap().as_ref().into(),
        salt: account.salt.into(),
        kdf: account.kdf.into(),
        account_nonce: (&account.account_nonce).into(),
        account_wrapped: (&account.account_wrapped).into(),
        logout_others: true,
    };
    fails(server.post::<()>("/v1/account/password", Some(&bert.token), change(&[0; 32])).await, 401, "unauthorized");
    server.post::<()>("/v1/account/password", Some(&bert.token), change(old_auth.as_ref())).await.unwrap();
    fails(server.get::<Overview>("/v1/account", &third.token).await, 401, "unauthorized");
    fails(login(&server, "bert", "bert").await.map(drop), 401, "unauthorized");
    let fresh = login(&server, "bert", "neues passwort").await.unwrap();
    assert_eq!(fresh.vault.public_keys().unwrap(), bert.vault.public_keys().unwrap());

    // Administration: view, disable, enable, delete. None of it opens a vault.
    bert.vault.put(None, b"etwas").unwrap();
    let personal = bert.personal();
    bert.push(&server, &personal).await.unwrap();
    let accounts: Vec<AdminAccount> = server.get("/v1/admin/accounts", &anna.token).await.unwrap();
    let row = accounts.iter().find(|a| a.username == "bert").unwrap();
    assert_eq!((accounts.len(), row.admin, row.disabled, row.devices, row.bytes > 0), (2, false, false, 2, true));
    fails(server.get::<Vec<AdminAccount>>("/v1/admin/accounts", &bert.token).await, 403, "not_admin");
    let id = crypto::hex(&bert.account);
    fails(server.post::<()>(&format!("/v1/admin/accounts/{}/disable", crypto::hex(&anna.account)), Some(&anna.token), ()).await, 403, "own_account");
    server.post::<()>(&format!("/v1/admin/accounts/{id}/disable"), Some(&anna.token), ()).await.unwrap();
    fails(server.get::<Overview>("/v1/account", &bert.token).await, 403, "account_disabled");
    fails(login(&server, "bert", "neues passwort").await.map(drop), 403, "account_disabled");
    server.post::<()>(&format!("/v1/admin/accounts/{id}/enable"), Some(&anna.token), ()).await.unwrap();
    server.get::<Overview>("/v1/account", &bert.token).await.unwrap();
    server.delete(&format!("/v1/admin/accounts/{id}"), &anna.token).await.unwrap();
    fails(server.get::<Overview>("/v1/account", &bert.token).await, 401, "unauthorized");
    assert_eq!(server.get::<Vec<AdminAccount>>("/v1/admin/accounts", &anna.token).await.unwrap().len(), 1);
    // The name is free again.
    register(&server, "bert", &invite(&server, &anna).await).await.unwrap();
}

/// Readable name for the device in the log; in the test the own helper struct is already called `Device`.
type Device2 = glowport_sync_proto::Device;

#[tokio::test]
async fn old_tombstones_leave_and_late_devices_get_everything() {
    let server = Server::new();
    let mut one = register(&server, "anna", &server.setup).await.unwrap();
    let mut two = login(&server, "anna", "anna").await.unwrap();
    let personal = one.personal();
    let gone = one.vault.put(None, b"will be deleted").unwrap();
    one.vault.put(None, b"stays").unwrap();
    one.push(&server, &personal).await.unwrap();
    two.pull(&server, &personal).await.unwrap();
    one.vault.delete(&gone).unwrap();
    one.push(&server, &personal).await.unwrap();
    one.pull(&server, &personal).await.unwrap();

    server.pass(179 * DAY);
    assert_eq!(server.app.store.purge().unwrap(), 0);
    server.pass(2 * DAY);
    assert_eq!(server.app.store.purge().unwrap(), 1);

    // The second device missed the deletion: it gets the whole state instead of the changes.
    let after = two.vault.cursor(&personal).unwrap();
    let pull: Pull = server.get(&format!("/v1/vaults/{}/records?after={after}", crypto::hex(&personal)), &two.token).await.unwrap();
    assert_eq!((pull.full, pull.records.len()), (true, 1));
    // Whoever already had everything gets only what is new, as usual.
    assert!(!one.pull(&server, &personal).await.unwrap().full);
}

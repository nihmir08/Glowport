//! The requests to the sync server, one function per route. Knows no vault.

use std::{sync::Arc, time::Duration};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use glowport_core::crypto::hex;
use glowport_sync_proto::{
    AdminAccount, ApiError, CreateVault, Device, Info, Invite, Login, LoginReply, Overview, PasswordChange, Prelogin, PreloginReply, PublicKeys, Pull, Push, PushReply, Register, RenameDevice,
    RosterUpdate, Rotate,
};
use reqwest::{Method, Url};
use rustls_platform_verifier::BuilderVerifierExt;
use serde::{de::DeserializeOwned, Serialize};

use crate::SyncError;

type Id = [u8; 16];

#[derive(Clone)]
pub struct Api {
    base: Url,
    http: reqwest::Client,
    tls: Arc<rustls::ClientConfig>,
    token: Option<String>,
}

#[cfg(feature = "test-roots")]
static TEST_ROOT: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();

/// Only for tests (switch `test-roots`): from now on all connections of this process are checked against this one
/// certificate (DER) instead of the system's store.
#[cfg(feature = "test-roots")]
pub fn trust_only(root: Vec<u8>) {
    let _ = TEST_ROOT.set(root);
}

/// TLS with `ring`, checked against the system's certificate store. The same setup applies to the
/// requests and to the WebSocket.
fn tls_config() -> Result<rustls::ClientConfig, SyncError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider).with_safe_default_protocol_versions().map_err(|e| SyncError::Offline(e.to_string()))?;
    #[cfg(feature = "test-roots")]
    if let Some(root) = TEST_ROOT.get() {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(rustls::pki_types::CertificateDer::from(root.clone())).map_err(|e| SyncError::Offline(e.to_string()))?;
        return Ok(builder.with_root_certificates(roots).with_no_client_auth());
    }
    Ok(builder.with_platform_verifier().map_err(|e| SyncError::Offline(e.to_string()))?.with_no_client_auth())
}

/// Whether a rejected certificate is behind a connection error. The reason sits several layers deep
/// and partly wrapped in an I/O error.
fn certificate_refused(error: &(dyn std::error::Error + 'static)) -> Option<String> {
    let mut current = Some(error);
    while let Some(error) = current {
        if let Some(rustls::Error::InvalidCertificate(reason)) = error.downcast_ref::<rustls::Error>() {
            return Some(format!("{reason:?}"));
        }
        // An I/O error names its content's cause as its own; the content itself is the next layer.
        current = match error.downcast_ref::<std::io::Error>().and_then(|io| io.get_ref()) {
            Some(inner) => Some(inner as &(dyn std::error::Error + 'static)),
            None => error.source(),
        };
    }
    None
}

/// Brings a typed address into shape. Without a scheme `https://` applies; unencrypted only works to the
/// own machine (for tests and for a server behind a tunnel).
fn parse(server: &str) -> Result<Url, SyncError> {
    let text = server.trim();
    let text = if text.contains("://") { text.to_string() } else { format!("https://{text}") };
    let mut url = Url::parse(&text).map_err(|_| SyncError::Address)?;
    let local = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    let allowed = match url.scheme() {
        "https" => true,
        "http" => local,
        _ => false,
    };
    if !allowed || url.host_str().is_none() || url.query().is_some() || url.fragment().is_some() || !url.username().is_empty() {
        return Err(SyncError::Address);
    }
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    Ok(url)
}

impl Api {
    pub fn new(server: &str) -> Result<Self, SyncError> {
        let base = parse(server)?;
        let tls = tls_config()?;
        let http = reqwest::Client::builder()
            .tls_backend_preconfigured(tls.clone())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(120))
            .user_agent(concat!("Glowport/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| SyncError::Offline(e.to_string()))?;
        Ok(Self { base, http, tls: Arc::new(tls), token: None })
    }

    /// The address in its fixed form, as it is stored.
    pub fn server(&self) -> String {
        self.base.as_str().trim_end_matches('/').to_string()
    }

    /// The same connection, identified with a device token (Base64).
    pub fn with_token(&self, token: &str) -> Self {
        Self { token: Some(token.to_string()), ..self.clone() }
    }

    pub(crate) fn token(&self) -> Option<&str> {
        self.token.as_deref()
    }

    pub(crate) fn tls(&self) -> Arc<rustls::ClientConfig> {
        self.tls.clone()
    }

    fn url(&self, segments: &[&str]) -> Url {
        let mut url = self.base.clone();
        // The address ends in `/`; the empty last segment is dropped before the own ones are appended.
        url.path_segments_mut().expect("http and https always have a path").pop_if_empty().push("v1").extend(segments);
        url
    }

    /// Address of the WebSocket for nudges: host, port, whether encrypted, and the address itself.
    pub(crate) fn live(&self) -> (String, u16, bool, String) {
        let mut url = self.url(&["live"]);
        let secure = url.scheme() == "https";
        let _ = url.set_scheme(if secure { "wss" } else { "ws" });
        let host = url.host_str().unwrap_or_default().trim_matches(['[', ']']).to_string();
        (host, url.port_or_known_default().unwrap_or(if secure { 443 } else { 80 }), secure, url.to_string())
    }

    async fn call<B: Serialize + ?Sized, T: DeserializeOwned>(&self, method: Method, segments: &[&str], query: Option<(&str, u64)>, body: Option<&B>) -> Result<T, SyncError> {
        let mut url = self.url(segments);
        if let Some((name, value)) = query {
            url.query_pairs_mut().append_pair(name, &value.to_string());
        }
        let mut request = self.http.request(method, url);
        if let Some(token) = &self.token {
            request = request.header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"));
        }
        if let Some(body) = body {
            request = request.json(body);
        }
        // Without the address in the text: it would otherwise end up in messages and logs.
        let offline = |e: reqwest::Error| match certificate_refused(&e) {
            Some(reason) => SyncError::Certificate(reason),
            None => SyncError::Offline(e.without_url().to_string()),
        };
        let response = request.send().await.map_err(offline)?;
        let status = response.status().as_u16();
        let bytes = response.bytes().await.map_err(offline)?;
        if status == 200 {
            serde_json::from_slice(&bytes).map_err(|_| SyncError::Protocol("Antwort"))
        } else {
            let code = serde_json::from_slice::<ApiError>(&bytes).map(|e| e.code).unwrap_or_else(|_| "unknown".into());
            Err(SyncError::Refused { status, code })
        }
    }

    async fn get<T: DeserializeOwned>(&self, segments: &[&str]) -> Result<T, SyncError> {
        self.call::<(), T>(Method::GET, segments, None, None).await
    }

    async fn post<B: Serialize + ?Sized, T: DeserializeOwned>(&self, segments: &[&str], body: &B) -> Result<T, SyncError> {
        self.call(Method::POST, segments, None, Some(body)).await
    }

    async fn delete(&self, segments: &[&str]) -> Result<(), SyncError> {
        self.call::<(), ()>(Method::DELETE, segments, None, None).await
    }

    pub async fn info(&self) -> Result<Info, SyncError> {
        self.get(&["info"]).await
    }

    pub async fn prelogin(&self, username: &str) -> Result<PreloginReply, SyncError> {
        self.post(&["prelogin"], &Prelogin { username: username.into() }).await
    }

    pub async fn register(&self, request: &Register) -> Result<LoginReply, SyncError> {
        self.post(&["register"], request).await
    }

    pub async fn login(&self, request: &Login) -> Result<LoginReply, SyncError> {
        self.post(&["login"], request).await
    }

    pub async fn overview(&self) -> Result<Overview, SyncError> {
        self.get(&["account"]).await
    }

    pub async fn change_password(&self, request: &PasswordChange) -> Result<(), SyncError> {
        self.post(&["account", "password"], request).await
    }

    pub async fn devices(&self) -> Result<Vec<Device>, SyncError> {
        self.get(&["devices"]).await
    }

    pub async fn rename_device(&self, device: &Id, name: Vec<u8>) -> Result<(), SyncError> {
        self.post(&["devices", &hex(device)], &RenameDevice { name: name.into() }).await
    }

    pub async fn remove_device(&self, device: &Id) -> Result<(), SyncError> {
        self.delete(&["devices", &hex(device)]).await
    }

    pub async fn keys(&self, username: &str) -> Result<PublicKeys, SyncError> {
        self.get(&["keys", username]).await
    }

    pub async fn create_vault(&self, request: &CreateVault) -> Result<(), SyncError> {
        self.post(&["vaults"], request).await
    }

    pub async fn delete_vault(&self, vault: &Id) -> Result<(), SyncError> {
        self.delete(&["vaults", &hex(vault)]).await
    }

    pub async fn pull(&self, vault: &Id, after: u64) -> Result<Pull, SyncError> {
        self.call::<(), Pull>(Method::GET, &["vaults", &hex(vault), "records"], Some(("after", after)), None).await
    }

    pub async fn push(&self, vault: &Id, request: &Push) -> Result<PushReply, SyncError> {
        self.post(&["vaults", &hex(vault), "records"], request).await
    }

    pub async fn roster(&self, vault: &Id, request: &RosterUpdate) -> Result<(), SyncError> {
        self.post(&["vaults", &hex(vault), "roster"], request).await
    }

    pub async fn rotate(&self, vault: &Id, request: &Rotate) -> Result<(), SyncError> {
        self.post(&["vaults", &hex(vault), "rotate"], request).await
    }

    pub async fn accept(&self, vault: &Id) -> Result<(), SyncError> {
        self.post(&["vaults", &hex(vault), "accept"], &()).await
    }

    pub async fn leave(&self, vault: &Id) -> Result<(), SyncError> {
        self.post(&["vaults", &hex(vault), "leave"], &()).await
    }

    pub async fn invites(&self) -> Result<Vec<Invite>, SyncError> {
        self.get(&["admin", "invites"]).await
    }

    pub async fn create_invite(&self) -> Result<Invite, SyncError> {
        self.post(&["admin", "invites"], &()).await
    }

    pub async fn revoke_invite(&self, code: &str) -> Result<(), SyncError> {
        self.delete(&["admin", "invites", code]).await
    }

    pub async fn accounts(&self) -> Result<Vec<AdminAccount>, SyncError> {
        self.get(&["admin", "accounts"]).await
    }

    pub async fn set_disabled(&self, account: &Id, disabled: bool) -> Result<(), SyncError> {
        self.post(&["admin", "accounts", &hex(account), if disabled { "disable" } else { "enable" }], &()).await
    }

    pub async fn delete_account(&self, account: &Id) -> Result<(), SyncError> {
        self.delete(&["admin", "accounts", &hex(account)]).await
    }
}

/// A device token in the form in which it travels and is stored.
pub(crate) fn encode_token(token: &[u8]) -> String {
    STANDARD.encode(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_are_normalised_and_plain_http_stays_local() {
        let server = |text: &str| Api::new(text).map(|api| api.server());
        assert_eq!(server("sync.example.com").unwrap(), "https://sync.example.com");
        assert_eq!(server(" https://sync.example.com/ ").unwrap(), "https://sync.example.com");
        assert_eq!(server("https://example.com/glowport").unwrap(), "https://example.com/glowport");
        assert_eq!(server("http://127.0.0.1:8787").unwrap(), "http://127.0.0.1:8787");
        assert_eq!(server("http://localhost:8787/").unwrap(), "http://localhost:8787");
        for bad in ["http://sync.example.com", "ftp://example.com", "https://user@example.com", "https://example.com/?x=1", "", "https://"] {
            assert!(matches!(server(bad), Err(SyncError::Address)), "{bad}");
        }

        let api = Api::new("https://example.com/glowport").unwrap();
        assert_eq!(api.url(&["vaults", "ab", "records"]).as_str(), "https://example.com/glowport/v1/vaults/ab/records");
        assert_eq!(api.url(&["keys", "a/b c"]).as_str(), "https://example.com/glowport/v1/keys/a%2Fb%20c", "a name stays one piece of the path");
        assert_eq!(api.live(), ("example.com".into(), 443, true, "wss://example.com/glowport/v1/live".into()));
        assert_eq!(Api::new("http://127.0.0.1:8787").unwrap().live(), ("127.0.0.1".into(), 8787, false, "ws://127.0.0.1:8787/v1/live".into()));
    }
}

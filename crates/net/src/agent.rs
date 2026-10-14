//! SSH-Agenten auf diesem Rechner.
//!
//! Unter Windows gibt es zwei Stellen: die Pipe des OpenSSH-Agenten (dort stellen auch 1Password und Bitwarden
//! ihren Agenten bereit) und Pageant von PuTTY. Schlüssel aus einem Agenten bleiben dort; Glowport lässt ihn nur
//! unterschreiben.

use std::time::Duration;

use russh::keys::{
    agent::{
        client::{AgentClient, AgentStream},
        AgentIdentity,
    },
    HashAlg, PublicKey,
};
use tokio::time::timeout;

/// Pipe des OpenSSH-Agenten unter Windows.
pub const OPENSSH_PIPE: &str = r"\\.\pipe\openssh-ssh-agent";
/// Ein Agent, der nicht binnen dieser Zeit antwortet, gilt als nicht vorhanden.
const AGENT_TIMEOUT: Duration = Duration::from_secs(3);

pub(crate) type Stream = Box<dyn AgentStream + Send + Unpin>;
pub(crate) type Client = AgentClient<Stream>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    OpenSsh,
    Pageant,
}

/// Welche Agenten eine Verbindung benutzen darf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Agents {
    /// Pipe (Windows) oder Socket (sonst) des OpenSSH-Agenten. Tests setzen hier ihren eigenen.
    pub openssh: Option<String>,
    pub pageant: bool,
}

impl Agents {
    /// Die Stellen, an denen auf diesem Rechner üblicherweise ein Agent zu finden ist.
    pub fn system() -> Self {
        #[cfg(windows)]
        return Self { openssh: Some(OPENSSH_PIPE.into()), pageant: true };
        #[cfg(not(windows))]
        return Self { openssh: std::env::var("SSH_AUTH_SOCK").ok(), pageant: false };
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentKey {
    pub comment: String,
    /// Art und Länge zum Anzeigen, etwa „Ed25519“ oder „RSA 4096“.
    pub label: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentInfo {
    pub kind: Kind,
    pub running: bool,
    pub keys: Vec<AgentKey>,
}

async fn connect(kind: Kind, agents: &Agents) -> Option<Client> {
    match kind {
        Kind::OpenSsh => {
            let path = agents.openssh.as_deref()?;
            // Eine Pipe, die es nicht gibt, scheitert sofort; ist sie nur belegt, wartet der Aufruf, deshalb die Grenze.
            #[cfg(windows)]
            return timeout(AGENT_TIMEOUT, AgentClient::connect_named_pipe(path)).await.ok()?.ok().map(AgentClient::dynamic);
            #[cfg(not(windows))]
            return timeout(AGENT_TIMEOUT, AgentClient::connect_uds(path)).await.ok()?.ok().map(AgentClient::dynamic);
        }
        Kind::Pageant => {
            #[cfg(windows)]
            if agents.pageant {
                return timeout(AGENT_TIMEOUT, AgentClient::connect_pageant()).await.ok()?.ok().map(AgentClient::dynamic);
            }
            None
        }
    }
}

/// Was der Agent anbietet. `None`: Er antwortet nicht. Bei Pageant zeigt sich erst hier, ob es überhaupt läuft.
async fn identities(client: &mut Client) -> Option<Vec<AgentIdentity>> {
    timeout(AGENT_TIMEOUT, client.request_identities()).await.ok().and_then(Result::ok)
}

/// Verbindet sich mit einem Agenten und fragt ihn ab. `None`, wenn er nicht läuft oder nicht antwortet.
async fn ask(kind: Kind, agents: &Agents) -> Option<(Client, Vec<AgentIdentity>)> {
    let mut client = connect(kind, agents).await?;
    let offered = identities(&mut client).await?;
    Some((client, offered))
}

fn describe(identity: &AgentIdentity) -> AgentKey {
    match identity {
        AgentIdentity::PublicKey { key, comment } => {
            let label = crate::keys::label(key).unwrap_or_else(|| key.algorithm().to_string());
            AgentKey { comment: comment.clone(), label, fingerprint: key.fingerprint(HashAlg::Sha256).to_string() }
        }
        AgentIdentity::Certificate { certificate, comment } => {
            AgentKey { comment: comment.clone(), label: certificate.algorithm().to_string(), fingerprint: certificate.public_key().fingerprint(HashAlg::Sha256).to_string() }
        }
    }
}

/// Fragt alle Stellen ab und sagt, welche Agenten laufen und welche Schlüssel sie anbieten.
pub async fn list(agents: &Agents) -> Vec<AgentInfo> {
    let mut found = Vec::new();
    for kind in [Kind::OpenSsh, Kind::Pageant] {
        let info = match ask(kind, agents).await {
            Some((_, offered)) => AgentInfo { kind, running: true, keys: offered.iter().map(describe).collect() },
            None => AgentInfo { kind, running: false, keys: Vec::new() },
        };
        found.push(info);
    }
    found
}

/// Jeder laufende Agent samt den öffentlichen Schlüsseln, die er anbietet. Zertifikate folgen mit dem Rest von Meilenstein 3.
pub(crate) async fn offers(agents: &Agents) -> Vec<(Client, Vec<PublicKey>)> {
    let mut found = Vec::new();
    for kind in [Kind::OpenSsh, Kind::Pageant] {
        if let Some((client, offered)) = ask(kind, agents).await {
            let keys = offered
                .into_iter()
                .filter_map(|identity| match identity {
                    AgentIdentity::PublicKey { key, .. } => Some(key),
                    AgentIdentity::Certificate { .. } => None,
                })
                .collect();
            found.push((client, keys));
        }
    }
    found
}

/// Rohe Verbindung zum ersten laufenden Agenten, für das Weiterreichen an einen Server.
pub(crate) async fn stream(agents: &Agents) -> Option<Stream> {
    for kind in [Kind::OpenSsh, Kind::Pageant] {
        if let Some((client, _)) = ask(kind, agents).await {
            return Some(client.into_inner());
        }
    }
    None
}

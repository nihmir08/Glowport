//! SSH agents on this machine.
//!
//! On Windows there are two places: the OpenSSH agent's pipe (1Password and Bitwarden also provide
//! their agent there) and PuTTY's Pageant. Keys from an agent stay there; Glowport only lets it
//! sign.

use std::time::Duration;

use russh::keys::{
    agent::{
        client::{AgentClient, AgentStream},
        AgentIdentity,
    },
    HashAlg, PublicKey,
};
use tokio::time::timeout;

/// Pipe of the OpenSSH agent on Windows.
pub const OPENSSH_PIPE: &str = r"\\.\pipe\openssh-ssh-agent";
/// An agent that does not answer within this time counts as absent.
const AGENT_TIMEOUT: Duration = Duration::from_secs(3);

pub(crate) type Stream = Box<dyn AgentStream + Send + Unpin>;
pub(crate) type Client = AgentClient<Stream>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    OpenSsh,
    Pageant,
}

/// Which agents a connection may use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Agents {
    /// Pipe (Windows) or socket (elsewhere) of the OpenSSH agent. Tests set their own here.
    pub openssh: Option<String>,
    pub pageant: bool,
}

impl Agents {
    /// The places where an agent is usually found on this machine.
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
    /// Kind and length for display, e.g. “Ed25519” or “RSA 4096”.
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
            // A pipe that does not exist fails at once; if it is only busy, the call waits, hence the limit.
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

/// What the agent offers. `None`: it does not answer. With Pageant only this shows whether it runs at all.
async fn identities(client: &mut Client) -> Option<Vec<AgentIdentity>> {
    timeout(AGENT_TIMEOUT, client.request_identities()).await.ok().and_then(Result::ok)
}

/// Connects to an agent and queries it. `None` if it is not running or does not answer.
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

/// Queries all places and says which agents run and which keys they offer.
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

/// Every running agent together with the public keys it offers.
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

/// Raw connection to the first running agent, for forwarding it to a server.
pub(crate) async fn stream(agents: &Agents) -> Option<Stream> {
    for kind in [Kind::OpenSsh, Kind::Pageant] {
        if let Some((client, _)) = ask(kind, agents).await {
            return Some(client.into_inner());
        }
    }
    None
}

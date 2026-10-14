//! Checking a Proxmox server's certificate. Proxmox ships a self-signed certificate that no
//! computer trusts on its own; the user therefore confirms its fingerprint once, as with SSH's known
//! hosts. After that exactly this certificate applies and no other.

use std::sync::Arc;

use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::CryptoProvider,
    pki_types::{CertificateDer, ServerName, UnixTime},
    CertificateError, DigitallySignedStruct, SignatureScheme,
};
use sha2::{Digest, Sha256};

use crate::{PveError, Shared};

/// SHA-256 over the server's certificate.
pub type Fingerprint = [u8; 32];

/// What was seen while connecting: the fingerprint, and whether the certificate was valid.
pub(crate) type Seen = Shared<Option<(Fingerprint, bool)>>;

/// This is how Proxmox shows the fingerprint: `5F:1A:…`, 32 pairs.
pub fn fingerprint_text(fingerprint: &Fingerprint) -> String {
    fingerprint.iter().map(|byte| format!("{byte:02X}")).collect::<Vec<_>>().join(":")
}

/// Reads a fingerprint, with or without colons, in upper or lower case.
pub fn parse_fingerprint(text: &str) -> Option<Fingerprint> {
    let hex: String = text.chars().filter(|c| !matches!(c, ':' | ' ')).collect();
    if hex.len() != 64 || !hex.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

pub(crate) enum Mode {
    /// The system's certificate store decides.
    System,
    /// Exactly the certificate with this fingerprint applies, whatever the system thinks of it.
    Pinned(Fingerprint),
    /// Only look: every certificate passes. A secret never goes over such a connection.
    Observe,
}

struct Check {
    mode: Mode,
    system: rustls_platform_verifier::Verifier,
    provider: Arc<CryptoProvider>,
    seen: Seen,
}

impl std::fmt::Debug for Check {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Check")
    }
}

impl ServerCertVerifier for Check {
    fn verify_server_cert(&self, end_entity: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>], server_name: &ServerName<'_>, ocsp_response: &[u8], now: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        let fingerprint: Fingerprint = Sha256::digest(end_entity.as_ref()).into();
        let recognised = || self.system.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now).is_ok();
        let (valid, pass) = match self.mode {
            Mode::System => {
                let valid = recognised();
                (valid, valid)
            }
            Mode::Pinned(pin) => (pin == fingerprint, pin == fingerprint),
            Mode::Observe => (recognised(), true),
        };
        *self.seen.lock().unwrap_or_else(|p| p.into_inner()) = Some((fingerprint, valid));
        if pass {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure))
        }
    }

    // That the server really has the key to its certificate is checked in any case.
    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

pub(crate) fn config(mode: Mode, seen: Seen) -> Result<rustls::ClientConfig, PveError> {
    let failed = |e: rustls::Error| PveError::Offline(e.to_string());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let system = rustls_platform_verifier::Verifier::new(provider.clone()).map_err(failed)?;
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone()).with_safe_default_protocol_versions().map_err(failed)?;
    Ok(builder.dangerous().with_custom_certificate_verifier(Arc::new(Check { mode, system, provider, seen })).with_no_client_auth())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_read_the_way_proxmox_shows_them() {
        let mut fingerprint = [0u8; 32];
        for (i, byte) in fingerprint.iter_mut().enumerate() {
            *byte = (i * 8 + 5) as u8;
        }
        let shown = fingerprint_text(&fingerprint);
        assert!(shown.starts_with("05:0D:15:1D") && shown.len() == 95);
        assert_eq!(parse_fingerprint(&shown), Some(fingerprint));
        assert_eq!(parse_fingerprint(&shown.to_lowercase().replace(':', "")), Some(fingerprint));
        for bad in ["", "05:0D", &shown[..94], &format!("{shown}:00"), &shown.replace("05", "ZZ"), &"ä".repeat(32)] {
            assert_eq!(parse_fingerprint(bad), None, "{bad}");
        }
    }
}

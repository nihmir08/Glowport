//! TLS to an FTP server. Many servers come with a self-signed certificate; as with Proxmox and RDP,
//! the user then confirms its fingerprint once.
//!
//! An FTP connection sets up TLS several times: once for the commands, then for every transfer. The first
//! certificate is recorded (and, if one is expected, measured against it); **every further setup must show exactly
//! the same.** Whether the first one applies is decided by the caller after setup and before signing in.

use std::sync::{Arc, Mutex};

use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::CryptoProvider,
    pki_types::{CertificateDer, ServerName, UnixTime},
    CertificateError, DigitallySignedStruct, SignatureScheme,
};
use sha2::{Digest, Sha256};

/// SHA-256 over the server's certificate.
pub type Fingerprint = [u8; 32];

/// What was seen at the first setup: the fingerprint, and whether the system trusts the certificate.
pub(crate) type Seen = Arc<Mutex<Option<(Fingerprint, bool)>>>;

struct Check {
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
        let mut seen = self.seen.lock().unwrap_or_else(|p| p.into_inner());
        match *seen {
            Some((first, _)) if first == fingerprint => Ok(ServerCertVerified::assertion()),
            Some(_) => Err(rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure)),
            None => {
                let recognised = self.system.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now).is_ok();
                *seen = Some((fingerprint, recognised));
                Ok(ServerCertVerified::assertion())
            }
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

pub(crate) fn config(seen: Seen) -> Result<rustls::ClientConfig, rustls::Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let system = rustls_platform_verifier::Verifier::new(provider.clone())?;
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone()).with_safe_default_protocol_versions()?;
    Ok(builder.dangerous().with_custom_certificate_verifier(Arc::new(Check { system, provider, seen })).with_no_client_auth())
}

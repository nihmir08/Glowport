//! TLS to an RDP server. Windows ships a self-signed certificate that no computer trusts on its own.
//! Setup therefore lets every certificate pass and records what was seen; whether it is valid is decided by the
//! caller afterwards, and only then does a password go over the line.

use std::sync::{Arc, Mutex};

use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::CryptoProvider,
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, SignatureScheme,
};
use sha2::{Digest, Sha256};

/// SHA-256 over the server's certificate.
pub type Fingerprint = [u8; 32];

/// What was seen while connecting: the fingerprint, and whether the system trusts the certificate.
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
        let recognised = self.system.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now).is_ok();
        *self.seen.lock().unwrap_or_else(|p| p.into_inner()) = Some((fingerprint, recognised));
        Ok(ServerCertVerified::assertion())
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
    let mut config = builder.dangerous().with_custom_certificate_verifier(Arc::new(Check { system, provider, seen })).with_no_client_auth();
    // The sign-in via NLA (CredSSP) does not tolerate resumed TLS sessions.
    config.resumption = rustls::client::Resumption::disabled();
    Ok(config)
}

/// The public key from a certificate, as the sign-in via NLA expects it.
pub(crate) fn public_key(certificate: &[u8]) -> Option<Vec<u8>> {
    use x509_cert::der::Decode as _;
    let certificate = x509_cert::Certificate::from_der(certificate).ok()?;
    certificate.tbs_certificate.subject_public_key_info.subject_public_key.as_bytes().map(<[u8]>::to_vec)
}

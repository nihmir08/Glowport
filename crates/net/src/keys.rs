//! Generating, reading and writing key pairs.
//!
//! In go files as `ssh-keygen`, OpenSSL or PuTTY write them. Out always comes the same form:
//! the private key in OpenSSH format without passphrase, as stored in the vault.

use russh::keys::{
    self,
    ssh_key::{
        certificate::CertType,
        private::{KeypairData, RsaKeypair},
        Algorithm, Certificate, EcdsaCurve, HashAlg, LineEnding, PrivateKey, PublicKey,
    },
};

use crate::Secret;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Ed25519,
    Ecdsa,
    Rsa,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Openssh,
    /// PKCS#1, PKCS#8 or SEC1 in a PEM wrapper.
    Pem,
    /// PuTTY, version 2 or 3.
    Ppk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    /// No private key in a known format.
    Unreadable,
    /// Readable, but a kind Glowport does not support (e.g. DSA).
    Unsupported,
    PassphraseRequired,
    WrongPassphrase,
    /// This length is not generated for this kind.
    InvalidSize,
    /// Not a certificate in OpenSSH format.
    CertificateUnreadable,
    /// The certificate belongs to a different key.
    CertificateMismatch,
    /// A certificate for a server where one for a user is needed.
    CertificateWrongType,
}

/// What a user certificate states. Times in seconds since 1970.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertInfo {
    /// The line without comment, as it is stored.
    pub text: String,
    /// Name the certificate authority gave the certificate.
    pub key_id: String,
    /// User names it applies to. Empty means: for everyone.
    pub principals: Vec<String>,
    pub valid_after: u64,
    /// `None`: it does not expire.
    pub valid_before: Option<u64>,
    /// Fingerprint of the certificate authority that signed.
    pub authority: String,
}

/// What installing a public key on a server resulted in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Installed {
    Added,
    /// The key was already in the file.
    Present,
}

const ADDED: &str = "glowport:added";
const PRESENT: &str = "glowport:present";

/// A key pair in the form in which it is stored in the vault.
#[derive(Debug)]
pub struct Material {
    pub kind: Kind,
    /// Length in bits: Ed25519 256, ECDSA 256/384/521, RSA the modulus length.
    pub bits: u32,
    /// Fingerprint as in OpenSSH: `SHA256:…`.
    pub fingerprint: String,
    /// Public key in OpenSSH format without comment.
    pub public: String,
    /// Private key in OpenSSH format, unencrypted.
    pub private: Secret,
    /// Comment from the file, often `user@machine`.
    pub comment: String,
}

/// What can be said about a key file. Kind, length and fingerprint are missing as long as the file
/// is encrypted and its format does not name the public part openly.
#[derive(Debug, PartialEq, Eq)]
pub struct Info {
    pub format: Format,
    pub encrypted: bool,
    pub kind: Option<Kind>,
    pub bits: Option<u32>,
    pub fingerprint: Option<String>,
    pub comment: String,
}

fn describe(public: &PublicKey) -> Result<(Kind, u32), KeyError> {
    match public.algorithm() {
        Algorithm::Ed25519 => Ok((Kind::Ed25519, 256)),
        Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 } => Ok((Kind::Ecdsa, 256)),
        Algorithm::Ecdsa { curve: EcdsaCurve::NistP384 } => Ok((Kind::Ecdsa, 384)),
        Algorithm::Ecdsa { curve: EcdsaCurve::NistP521 } => Ok((Kind::Ecdsa, 521)),
        Algorithm::Rsa { .. } => public.key_data().rsa().map(|rsa| (Kind::Rsa, rsa.key_size())).ok_or(KeyError::Unreadable),
        _ => Err(KeyError::Unsupported),
    }
}

/// Kind and length for display: “Ed25519”, “ECDSA P-256”, “RSA 4096”. `None` for kinds Glowport does not support.
pub(crate) fn label(public: &PublicKey) -> Option<String> {
    Some(match describe(public).ok()? {
        (Kind::Ed25519, _) => "Ed25519".into(),
        (Kind::Ecdsa, bits) => format!("ECDSA P-{bits}"),
        (Kind::Rsa, bits) => format!("RSA {bits}"),
    })
}

fn fingerprint(public: &PublicKey) -> String {
    public.fingerprint(HashAlg::Sha256).to_string()
}

fn material(mut key: PrivateKey) -> Result<Material, KeyError> {
    let (kind, bits) = describe(key.public_key())?;
    let comment = key.comment().as_str_lossy().to_string();
    // The comment is not part of the key; in the vault the name carries it.
    key.set_comment("");
    let public = key.public_key().to_openssh().map_err(|_| KeyError::Unreadable)?.trim().to_string();
    let private = key.to_openssh(LineEnding::LF).map_err(|_| KeyError::Unreadable)?;
    Ok(Material { kind, bits, fingerprint: fingerprint(key.public_key()), public, private, comment })
}

/// Generates a new key pair. RSA computes for a few seconds; do not call on a runtime thread.
pub fn generate(kind: Kind, bits: u32) -> Result<Material, KeyError> {
    let mut rng = rand::rng();
    let key = match (kind, bits) {
        (Kind::Ed25519, 256) => PrivateKey::random(&mut rng, Algorithm::Ed25519),
        (Kind::Ecdsa, 256) => PrivateKey::random(&mut rng, Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 }),
        (Kind::Ecdsa, 384) => PrivateKey::random(&mut rng, Algorithm::Ecdsa { curve: EcdsaCurve::NistP384 }),
        (Kind::Ecdsa, 521) => PrivateKey::random(&mut rng, Algorithm::Ecdsa { curve: EcdsaCurve::NistP521 }),
        (Kind::Rsa, 3072 | 4096) => RsaKeypair::random(&mut rng, bits as usize).and_then(|pair| PrivateKey::new(KeypairData::from(pair), "")),
        _ => return Err(KeyError::InvalidSize),
    };
    material(key.map_err(|_| KeyError::Unreadable)?)
}

/// Recognises format and encryption from the text without decrypting anything.
fn sniff(text: &str) -> Result<(Format, bool), KeyError> {
    if text.trim_start().starts_with("PuTTY-User-Key-File-") {
        let encrypted = text.lines().find_map(|line| line.strip_prefix("Encryption:")).is_some_and(|value| value.trim() != "none");
        return Ok((Format::Ppk, encrypted));
    }
    if text.contains("-----BEGIN OPENSSH PRIVATE KEY-----") {
        let encrypted = PrivateKey::from_openssh(text).map_err(|_| KeyError::Unreadable)?.is_encrypted();
        return Ok((Format::Openssh, encrypted));
    }
    if text.contains("-----BEGIN ") && text.contains("PRIVATE KEY-----") {
        return Ok((Format::Pem, text.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----") || text.contains("Proc-Type: 4,ENCRYPTED")));
    }
    Err(KeyError::Unreadable)
}

/// Reads a private key. Decrypting takes noticeable time; do not call on a runtime thread.
pub fn import(text: &str, passphrase: Option<&str>) -> Result<Material, KeyError> {
    let (_, encrypted) = sniff(text)?;
    let passphrase = passphrase.filter(|p| !p.is_empty());
    if encrypted && passphrase.is_none() {
        return Err(KeyError::PassphraseRequired);
    }
    // A wrong passphrase and a damaged file cannot be told apart after decrypting.
    let failed = if encrypted { KeyError::WrongPassphrase } else { KeyError::Unreadable };
    material(keys::decode_secret_key(text, passphrase.filter(|_| encrypted)).map_err(|_| failed)?)
}

/// Says what is inside a key file without taking it over. Without a passphrase, an encrypted file
/// yields as much as it names openly.
pub fn inspect(text: &str, passphrase: Option<&str>) -> Result<Info, KeyError> {
    let (format, encrypted) = sniff(text)?;
    if encrypted && passphrase.is_none_or(str::is_empty) {
        // OpenSSH names the public part even in an encrypted file.
        let open = (format == Format::Openssh).then(|| PrivateKey::from_openssh(text).ok()).flatten();
        let known = open.as_ref().and_then(|key| describe(key.public_key()).ok());
        let fingerprint = open.as_ref().map(|key| fingerprint(key.public_key()));
        return Ok(Info { format, encrypted, kind: known.map(|(kind, _)| kind), bits: known.map(|(_, bits)| bits), fingerprint, comment: String::new() });
    }
    let key = import(text, passphrase)?;
    Ok(Info { format, encrypted, kind: Some(key.kind), bits: Some(key.bits), fingerprint: Some(key.fingerprint), comment: key.comment })
}

/// Private key as an OpenSSH file, optionally with passphrase. `comment` is then in the file.
pub fn export(private: &str, comment: &str, passphrase: Option<&str>) -> Result<Secret, KeyError> {
    let mut key = PrivateKey::from_openssh(private).map_err(|_| KeyError::Unreadable)?;
    key.set_comment(comment);
    if let Some(passphrase) = passphrase.filter(|p| !p.is_empty()) {
        key = key.encrypt(&mut rand::rng(), passphrase).map_err(|_| KeyError::Unreadable)?;
    }
    key.to_openssh(LineEnding::LF).map_err(|_| KeyError::Unreadable)
}

/// A public key, e.g. that of a certificate authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicInfo {
    /// Kind and length for display, e.g. “Ed25519”.
    pub label: String,
    pub fingerprint: String,
    /// The line in OpenSSH format without comment.
    pub public: String,
}

/// Reads a public key in OpenSSH format (one line, as in a `.pub` file).
pub fn inspect_public(text: &str) -> Result<PublicInfo, KeyError> {
    let mut key = PublicKey::from_openssh(text.trim()).map_err(|_| KeyError::Unreadable)?;
    key.set_comment("");
    let label = label(&key).ok_or(KeyError::Unsupported)?;
    Ok(PublicInfo { label, fingerprint: fingerprint(&key), public: key.to_openssh().map_err(|_| KeyError::Unreadable)?.trim().to_string() })
}

/// Reads a user certificate and checks that it belongs to this public key. Whether the certificate
/// authority's signature counts for anything is decided by the server, which trusts it or not.
pub fn inspect_certificate(text: &str, public: &str) -> Result<CertInfo, KeyError> {
    let certificate = Certificate::from_openssh(text.trim()).map_err(|_| KeyError::CertificateUnreadable)?;
    let key = PublicKey::from_openssh(public).map_err(|_| KeyError::Unreadable)?;
    if certificate.public_key() != key.key_data() {
        return Err(KeyError::CertificateMismatch);
    }
    if certificate.cert_type() != CertType::User {
        return Err(KeyError::CertificateWrongType);
    }
    let line = certificate.to_openssh().map_err(|_| KeyError::Unreadable)?;
    Ok(CertInfo {
        text: line.split_whitespace().take(2).collect::<Vec<_>>().join(" "),
        key_id: certificate.key_id().to_string(),
        principals: certificate.valid_principals().to_vec(),
        valid_after: certificate.valid_after(),
        valid_before: Some(certificate.valid_before()).filter(|end| *end != u64::MAX),
        authority: certificate.signature_key().fingerprint(HashAlg::Sha256).to_string(),
    })
}

/// Command that adds a public key to `~/.ssh/authorized_keys` if it is not there yet.
///
/// Runs in any POSIX shell. New files and folders belong only to the user (`umask 077`), a last line
/// without a line ending is terminated first. Only the newly written key and a comment of harmless
/// characters go into the command; none of it can be read by the shell as anything else.
pub fn install_command(public: &str, comment: &str) -> Result<String, KeyError> {
    let mut key = PublicKey::from_openssh(public).map_err(|_| KeyError::Unreadable)?;
    key.set_comment("");
    let body = key.to_openssh().map_err(|_| KeyError::Unreadable)?;
    let body = body.trim();
    let comment: String = comment.chars().map(|c| if c.is_ascii_alphanumeric() || "@._-".contains(c) { c } else { '_' }).collect();
    Ok(format!(
        "umask 077; mkdir -p \"$HOME/.ssh\" && f=\"$HOME/.ssh/authorized_keys\" && touch \"$f\" && \
         if grep -qF -- '{body}' \"$f\"; then echo {PRESENT}; \
         else {{ [ -z \"$(tail -c1 \"$f\")\" ] || echo >> \"$f\"; }} && printf '%s\\n' '{body} {comment}' >> \"$f\" && echo {ADDED}; fi"
    ))
}

/// Reads from the output of [`install_command`] what happened. `None`: the command did not run through.
pub fn install_outcome(stdout: &[u8]) -> Option<Installed> {
    let text = String::from_utf8_lossy(stdout);
    text.lines().rev().find_map(|line| match line.trim() {
        ADDED => Some(Installed::Added),
        PRESENT => Some(Installed::Present),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Throwaway keys only for these tests: `ssh-keygen` (OpenSSH, PEM, PKCS#8, passphrase “geheim”) and the
    // `ssh-key` crate's examples for PuTTY (passphrase “123”).
    const OPENSSH: &str = include_str!("../tests/keys/openssh_ed25519");
    const OPENSSH_ENC: &str = include_str!("../tests/keys/openssh_ed25519_enc");
    const PEM_RSA: &str = include_str!("../tests/keys/pem_rsa");
    const PEM_RSA_ENC: &str = include_str!("../tests/keys/pem_rsa_enc");
    const PKCS8_ECDSA: &str = include_str!("../tests/keys/pkcs8_ecdsa");
    const PKCS8_ECDSA_ENC: &str = include_str!("../tests/keys/pkcs8_ecdsa_enc");
    const PUTTY: &str = include_str!("../tests/keys/putty_ed25519.ppk");
    const PUTTY_ENC: &str = include_str!("../tests/keys/putty_ed25519_enc.ppk");
    const PUTTY_V2_ENC: &str = include_str!("../tests/keys/putty_rsa_v2_enc.ppk");

    #[test]
    fn every_format_is_read_and_ends_up_as_plain_openssh() {
        // The fingerprints come from `ssh-keygen -lf`.
        let cases = [
            (OPENSSH, None, Kind::Ed25519, 256, "SHA256:TsL9IGRVqns40u3YoWfwomDoZn8GBnoLI+M0IJ2tUAU"),
            (OPENSSH_ENC, Some("geheim"), Kind::Ed25519, 256, "SHA256:+mcbLMkgoIlEAnnSBVbTyfVSZUNm5w/PZWj1l+QQtwg"),
            (PEM_RSA, None, Kind::Rsa, 2048, "SHA256:LMGL2G3fnl52tk+EDkXDw2ACtvJSuJTLC5QNA4c0/Tc"),
            (PEM_RSA_ENC, Some("geheim"), Kind::Rsa, 2048, "SHA256:ZPyUqikSqcwzcgFhbkOFYxsUGAy2aj6eDSHpwRN+90c"),
            (PKCS8_ECDSA, None, Kind::Ecdsa, 384, "SHA256:fQjljuXjTJd/SPboGzj2S9M9DVh4lJRe2egE8cCmAIo"),
            (PKCS8_ECDSA_ENC, Some("geheim"), Kind::Ecdsa, 256, "SHA256:UQ6cjAmQaMFZIbs+cI+Yvu1L95dJGCimU6rxG0NHDNw"),
        ];
        for (text, passphrase, kind, bits, fingerprint) in cases {
            let key = import(text, passphrase).unwrap_or_else(|e| panic!("{fingerprint}: {e:?}"));
            assert_eq!((key.kind, key.bits, key.fingerprint.as_str()), (kind, bits, fingerprint));
            assert_eq!(key.public.split(' ').count(), 2, "without comment: {}", key.public);
            // What ends up in the vault can be read again without passphrase and is the same key.
            let again = import(&key.private, None).unwrap();
            assert_eq!((again.fingerprint, again.public, again.comment.as_str()), (key.fingerprint, key.public, ""));
        }
        assert_eq!(import(OPENSSH, None).unwrap().comment, "ich@laptop");
    }

    #[test]
    fn putty_files_are_read() {
        let plain = import(PUTTY, None).unwrap();
        assert_eq!((plain.kind, plain.bits, plain.comment.as_str()), (Kind::Ed25519, 256, "user@example.com"));
        let encrypted = import(PUTTY_ENC, Some("123")).unwrap();
        assert_eq!((encrypted.kind, encrypted.bits), (Kind::Ed25519, 256));
        let old = import(PUTTY_V2_ENC, Some("123")).unwrap();
        assert_eq!((old.kind, old.bits), (Kind::Rsa, 3072));
        assert_eq!(import(&old.private, None).unwrap().fingerprint, old.fingerprint);
        assert_eq!(import(PUTTY_ENC, None).unwrap_err(), KeyError::PassphraseRequired);
        assert_eq!(import(PUTTY_ENC, Some("wrong")).unwrap_err(), KeyError::WrongPassphrase);
    }

    #[test]
    fn passphrases_are_demanded_and_checked() {
        for text in [OPENSSH_ENC, PEM_RSA_ENC, PKCS8_ECDSA_ENC] {
            assert_eq!(import(text, None).unwrap_err(), KeyError::PassphraseRequired);
            assert_eq!(import(text, Some("")).unwrap_err(), KeyError::PassphraseRequired);
            assert_eq!(import(text, Some("wrong")).unwrap_err(), KeyError::WrongPassphrase);
        }
        // A superfluous passphrase does no harm.
        assert!(import(OPENSSH, Some("unneeded")).is_ok());
        assert_eq!(import("not a key", None).unwrap_err(), KeyError::Unreadable);
        assert_eq!(import("-----BEGIN OPENSSH PRIVATE KEY-----\njunk\n-----END OPENSSH PRIVATE KEY-----\n", None).unwrap_err(), KeyError::Unreadable);
        assert_eq!(import(&OPENSSH.replace("\n", "\r\n"), None).unwrap().comment, "ich@laptop", "Windows line ends");
    }

    #[test]
    fn inspecting_says_what_a_file_holds_before_it_is_opened() {
        let plain = inspect(OPENSSH, None).unwrap();
        assert_eq!((plain.format, plain.encrypted, plain.kind, plain.bits, plain.comment.as_str()), (Format::Openssh, false, Some(Kind::Ed25519), Some(256), "ich@laptop"));

        // OpenSSH names kind and fingerprint even when encrypted, PEM and PuTTY only after the passphrase.
        let locked = inspect(OPENSSH_ENC, None).unwrap();
        assert_eq!((locked.encrypted, locked.kind, locked.fingerprint.as_deref()), (true, Some(Kind::Ed25519), Some("SHA256:+mcbLMkgoIlEAnnSBVbTyfVSZUNm5w/PZWj1l+QQtwg")));
        assert_eq!(inspect(PEM_RSA_ENC, None).unwrap(), Info { format: Format::Pem, encrypted: true, kind: None, bits: None, fingerprint: None, comment: String::new() });
        assert_eq!(inspect(PUTTY_ENC, Some("")).unwrap().kind, None);

        let opened = inspect(PEM_RSA_ENC, Some("geheim")).unwrap();
        assert_eq!((opened.format, opened.kind, opened.bits), (Format::Pem, Some(Kind::Rsa), Some(2048)));
        assert_eq!(inspect(PUTTY_ENC, Some("123")).unwrap().format, Format::Ppk);
        assert_eq!(inspect(PEM_RSA_ENC, Some("wrong")).unwrap_err(), KeyError::WrongPassphrase);
        assert_eq!(inspect("Hallo", None).unwrap_err(), KeyError::Unreadable);
    }

    #[test]
    fn generated_keys_are_usable_and_differ() {
        for (kind, bits, algorithm) in [(Kind::Ed25519, 256, "ssh-ed25519"), (Kind::Ecdsa, 256, "ecdsa-sha2-nistp256"), (Kind::Ecdsa, 384, "ecdsa-sha2-nistp384"), (Kind::Ecdsa, 521, "ecdsa-sha2-nistp521")] {
            let key = generate(kind, bits).unwrap();
            assert_eq!((key.kind, key.bits), (kind, bits));
            assert!(key.public.starts_with(&format!("{algorithm} ")) && key.fingerprint.starts_with("SHA256:"), "{}", key.public);
            assert_eq!(import(&key.private, None).unwrap().fingerprint, key.fingerprint);
        }
        assert_ne!(generate(Kind::Ed25519, 256).unwrap().fingerprint, generate(Kind::Ed25519, 256).unwrap().fingerprint);
        for (kind, bits) in [(Kind::Ed25519, 512), (Kind::Ecdsa, 255), (Kind::Rsa, 1024), (Kind::Rsa, 2048)] {
            assert_eq!(generate(kind, bits).unwrap_err(), KeyError::InvalidSize);
        }
    }

    #[test]
    fn rsa_keys_are_generated() {
        let key = generate(Kind::Rsa, 3072).unwrap();
        assert_eq!((key.kind, key.bits), (Kind::Rsa, 3072));
        assert!(key.public.starts_with("ssh-rsa "));
        assert_eq!(import(&key.private, None).unwrap().fingerprint, key.fingerprint);
    }

    #[test]
    fn install_command_adds_a_key_exactly_once_in_a_real_shell() {
        let run = |home: &std::path::Path, command: &str| std::process::Command::new("sh").arg("-c").arg(command).env("HOME", home.to_string_lossy().replace('\\', "/")).output();
        let home = std::env::temp_dir().join(format!("glowport-install-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        let Ok(probe) = run(&home, "true") else {
            eprintln!("skipped without sh in the path");
            return;
        };
        assert!(probe.status.success());

        // An existing file whose last line has no line ending.
        let file = home.join(".ssh").join("authorized_keys");
        std::fs::write(&file, "ssh-rsa AAAAexisting before").unwrap();
        let key = generate(Kind::Ed25519, 256).unwrap();
        let command = install_command(&key.public, "My key'; rm -rf ~").unwrap();
        assert!(!command.contains("rm -rf"), "the comment is defused: {command}");

        let first = run(&home, &command).unwrap();
        assert_eq!(install_outcome(&first.stdout), Some(Installed::Added), "{}", String::from_utf8_lossy(&first.stderr));
        let second = run(&home, &command).unwrap();
        assert_eq!(install_outcome(&second.stdout), Some(Installed::Present));
        let lines: Vec<String> = std::fs::read_to_string(&file).unwrap().lines().map(String::from).collect();
        assert_eq!(lines, ["ssh-rsa AAAAexisting before".to_string(), format!("{} My_key___rm_-rf__", key.public)]);

        // Without an existing folder the command creates it.
        std::fs::remove_dir_all(home.join(".ssh")).unwrap();
        assert_eq!(install_outcome(&run(&home, &command).unwrap().stdout), Some(Installed::Added));
        assert!(file.exists());
        let _ = std::fs::remove_dir_all(&home);

        assert_eq!(install_outcome(b"sh: grep: not found\n"), None);
        assert_eq!(install_command("not a key", "x").unwrap_err(), KeyError::Unreadable);
    }

    #[test]
    fn export_writes_openssh_with_comment_and_optional_passphrase() {
        let key = generate(Kind::Ed25519, 256).unwrap();
        let plain = export(&key.private, "arbeit-2026", None).unwrap();
        assert_eq!(inspect(&plain, None).unwrap().comment, "arbeit-2026");
        assert_eq!(import(&plain, None).unwrap().fingerprint, key.fingerprint);

        let locked = export(&key.private, "arbeit-2026", Some("new")).unwrap();
        assert!(inspect(&locked, None).unwrap().encrypted);
        assert_eq!(import(&locked, Some("wrong")).unwrap_err(), KeyError::WrongPassphrase);
        let opened = import(&locked, Some("new")).unwrap();
        assert_eq!((opened.fingerprint, opened.comment.as_str()), (key.fingerprint, "arbeit-2026"));
        assert_eq!(export("not a key", "x", None).unwrap_err(), KeyError::Unreadable);
    }
}

//! Building blocks of the key chain. The format is defined in `docs/vault.md`; this is only the implementation.
//!
//! Algorithms: Argon2id (password → key), HKDF-SHA-256 (subkeys), XChaCha20-Poly1305 (encryption).

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const SALT_LEN: usize = 16;

/// Key that is overwritten when dropped.
pub type Key = Zeroizing<[u8; KEY_LEN]>;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("Key derivation failed")]
    Kdf,
    /// Wrong key or altered data; the two cannot be told apart from outside.
    #[error("Decryption failed")]
    Decrypt,
}

/// Cost of Argon2id. Stored in the vault file and can be raised on a password change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub passes: u32,
    pub lanes: u32,
}

impl KdfParams {
    /// Measured on 2026-10-04 on the development machine: 385 ms. With 64 MiB and 3 passes it was only 67 ms.
    pub const DEFAULT: Self = Self { memory_kib: 256 * 1024, passes: 4, lanes: 4 };

    pub fn to_bytes(self) -> [u8; 12] {
        let mut out = [0u8; 12];
        out[..4].copy_from_slice(&self.memory_kib.to_le_bytes());
        out[4..8].copy_from_slice(&self.passes.to_le_bytes());
        out[8..].copy_from_slice(&self.lanes.to_le_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let word = |i: usize| bytes.get(i..i + 4)?.try_into().ok().map(u32::from_le_bytes);
        (bytes.len() == 12).then_some(Self { memory_kib: word(0)?, passes: word(4)?, lanes: word(8)? })
    }
}

/// Operating system randomness.
pub fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

pub fn random_key() -> Key {
    Zeroizing::new(random())
}

pub fn derive_master_key(password: &[u8], salt: &[u8; SALT_LEN], params: KdfParams) -> Result<Key, CryptoError> {
    let params = Params::new(params.memory_kib, params.passes, params.lanes, Some(KEY_LEN)).map_err(|_| CryptoError::Kdf)?;
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|_| CryptoError::Kdf)?;
    Ok(key)
}

/// Subkey for exactly one purpose. No subkey can be computed from another.
pub fn derive_subkey(master: &Key, info: &[u8]) -> Key {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    Hkdf::<Sha256>::new(None, master.as_ref()).expand(info, key.as_mut()).expect("32 bytes are always valid for HKDF-SHA-256");
    key
}

/// Key from a negotiated secret (X25519). The salt binds it to the public keys involved.
pub fn derive_shared(secret: &[u8], salt: &[u8], info: &[u8]) -> Key {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    Hkdf::<Sha256>::new(Some(salt), secret).expand(info, key.as_mut()).expect("32 bytes are always valid for HKDF-SHA-256");
    key
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Reads exactly `N` bytes from hex digits.
pub fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let mut out = [0u8; N];
    if text.len() != N * 2 || !text.is_ascii() {
        return None;
    }
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Assembles bound data unambiguously: purpose, then every part prefixed with its length.
/// The lengths prevent two different splits from producing the same bytes.
pub fn aad(label: &str, parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(label.len() + parts.iter().map(|p| p.len() + 4).sum::<usize>() + 4);
    out.extend_from_slice(&(label.len() as u32).to_le_bytes());
    out.extend_from_slice(label.as_bytes());
    for part in parts {
        out.extend_from_slice(&(part.len() as u32).to_le_bytes());
        out.extend_from_slice(part);
    }
    out
}

pub struct Sealed {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

/// Encrypts with a fresh random nonce.
pub fn seal(key: &Key, aad: &[u8], plaintext: &[u8]) -> Sealed {
    let nonce = random();
    Sealed { nonce, ciphertext: seal_with_nonce(key, &nonce, aad, plaintext) }
}

/// Only meant for test vectors: a nonce must never be used twice with the same key.
pub fn seal_with_nonce(key: &Key, nonce: &[u8; NONCE_LEN], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    XChaCha20Poly1305::new(key.as_ref().into())
        .encrypt(XNonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .expect("records are far smaller than the algorithm's limit")
}

pub fn open(key: &Key, nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if nonce.len() != NONCE_LEN {
        return Err(CryptoError::Decrypt);
    }
    XChaCha20Poly1305::new(key.as_ref().into())
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Small Argon2 values so the tests stay fast. The default is measured in `vault`.
    const FAST: KdfParams = KdfParams { memory_kib: 64, passes: 1, lanes: 1 };

    /// Fixed test vectors: if anything changes here, a new version no longer opens old vaults.
    #[test]
    fn pinned_vectors() {
        let master = derive_master_key(b"korrekt pferd batterie", &[7u8; SALT_LEN], FAST).unwrap();
        assert_eq!(hex(master.as_ref()), "6e462f0f1577cbbb21de979da94f0dec2e75c6d391c8722dd181290b704e99d8", "Argon2id");

        let kek = derive_subkey(&master, b"glowport/kek/v1");
        let auth = derive_subkey(&master, b"glowport/auth/v1");
        assert_ne!(kek.as_ref(), auth.as_ref());
        // Cross-checked against Node's HKDF implementation (crypto.hkdfSync).
        assert_eq!(hex(kek.as_ref()), "af0c9ba13d82de22bdf265bd5c17df1b0597ffbf8565b69a2b692c0ceeb2038c", "HKDF kek");
        assert_eq!(hex(auth.as_ref()), "bfe910e1ac326913f6b9ff0d42b7b6a2b2a4636cae77036adb8c8eb80bd096eb", "HKDF auth");

        let aad = aad("glowport/record/v1", &[&[1u8; 16], &[2u8; 16], &7u64.to_le_bytes(), &[0]]);
        let sealed = seal_with_nonce(&kek, &[9u8; NONCE_LEN], &aad, b"{\"t\":\"host\",\"v\":1}");
        assert_eq!(hex(&sealed), "8514b9c91dee318c30fec1e18c2a4d3ede35fc2ef66f2606742aeb402d3a22f14526", "XChaCha20-Poly1305");
        assert_eq!(open(&kek, &[9u8; NONCE_LEN], &aad, &sealed).unwrap().as_slice(), b"{\"t\":\"host\",\"v\":1}");
    }

    /// Independent reference value: HKDF-SHA-256 from RFC 5869, test case 3 (no salt, no info).
    #[test]
    fn hkdf_matches_rfc5869() {
        let mut okm = [0u8; 42];
        Hkdf::<Sha256>::new(None, &[0x0b; 22]).expand(&[], &mut okm).unwrap();
        assert_eq!(hex(&okm), "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");
    }

    #[test]
    fn open_rejects_any_change() {
        let key = random_key();
        let sealed = seal(&key, b"purpose", b"geheim");
        assert_eq!(open(&key, &sealed.nonce, b"purpose", &sealed.ciphertext).unwrap().as_slice(), b"geheim");

        assert_eq!(open(&random_key(), &sealed.nonce, b"purpose", &sealed.ciphertext), Err(CryptoError::Decrypt), "different key");
        assert_eq!(open(&key, &sealed.nonce, b"other purpose", &sealed.ciphertext), Err(CryptoError::Decrypt), "different associated data");
        assert_eq!(open(&key, &sealed.nonce[..23], b"purpose", &sealed.ciphertext), Err(CryptoError::Decrypt), "kurze Nonce");
        for i in 0..sealed.ciphertext.len() {
            let mut changed = sealed.ciphertext.clone();
            changed[i] ^= 1;
            assert_eq!(open(&key, &sealed.nonce, b"purpose", &changed), Err(CryptoError::Decrypt), "byte {i} changed");
        }
        let mut nonce = sealed.nonce;
        nonce[0] ^= 1;
        assert_eq!(open(&key, &nonce, b"purpose", &sealed.ciphertext), Err(CryptoError::Decrypt), "nonce changed");
    }

    #[test]
    fn aad_parts_cannot_be_shifted() {
        assert_ne!(aad("x", &[b"ab", b"c"]), aad("x", &[b"a", b"bc"]));
        assert_ne!(aad("x", &[b"ab"]), aad("xa", &[b"b"]));
    }

    #[test]
    fn nonces_and_keys_are_fresh() {
        let key = random_key();
        assert_ne!(seal(&key, b"", b"x").nonce, seal(&key, b"", b"x").nonce);
        assert_ne!(random_key().as_ref(), random_key().as_ref());
    }

    #[test]
    fn kdf_params_round_trip() {
        assert_eq!(KdfParams::from_bytes(&KdfParams::DEFAULT.to_bytes()), Some(KdfParams::DEFAULT));
        assert_eq!(KdfParams::from_bytes(&[0; 11]), None);
    }
}

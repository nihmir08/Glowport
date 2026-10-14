//! Wraps a vault key for a member. Format and reasoning: `docs/sync.md`, section “Inviting”.
//!
//! One-time X25519 key pair of the sender → shared secret with the recipient's public key
//! → HKDF-SHA-256 → XChaCha20-Poly1305. Structure of the package: one-time public key (32),
//! nonce (24), ciphertext (48).

use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::crypto::{self, CryptoError, Key, KEY_LEN, NONCE_LEN};

const LABEL: &str = "glowport/share/v1";
pub const SEALED_LEN: usize = 32 + NONCE_LEN + KEY_LEN + 16;

fn secrets(shared: &[u8; 32], ephemeral: &[u8; 32], recipient: &[u8; 32], vault: &[u8; 16], epoch: u64) -> (Key, Vec<u8>) {
    let key = crypto::derive_shared(shared, &[ephemeral.as_slice(), recipient].concat(), LABEL.as_bytes());
    (key, crypto::aad(LABEL, &[vault, &epoch.to_le_bytes(), recipient, ephemeral]))
}

/// With a fixed one-time key and fixed nonce, only for test vectors. Fails on a public key
/// that yields no secret (e.g. all zeros).
pub fn seal_with(ephemeral: &StaticSecret, nonce: &[u8; NONCE_LEN], vault_key: &Key, vault: &[u8; 16], epoch: u64, recipient: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
    let shared = ephemeral.diffie_hellman(&PublicKey::from(*recipient));
    if !shared.was_contributory() {
        return Err(CryptoError::Decrypt);
    }
    let public = PublicKey::from(ephemeral).to_bytes();
    let (key, aad) = secrets(shared.as_bytes(), &public, recipient, vault, epoch);
    let mut out = Vec::with_capacity(SEALED_LEN);
    out.extend_from_slice(&public);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&crypto::seal_with_nonce(&key, nonce, &aad, vault_key.as_ref()));
    Ok(out)
}

/// Wraps a vault's key for the holder of `recipient`.
pub fn seal(vault_key: &Key, vault: &[u8; 16], epoch: u64, recipient: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
    let secret = Zeroizing::new(crypto::random::<KEY_LEN>());
    seal_with(&StaticSecret::from(*secret), &crypto::random(), vault_key, vault, epoch, recipient)
}

/// Unwraps with the own private key. Vault and key generation must be those it was wrapped for.
pub fn open(sealed: &[u8], vault: &[u8; 16], epoch: u64, secret: &StaticSecret) -> Result<Key, CryptoError> {
    if sealed.len() != SEALED_LEN {
        return Err(CryptoError::Decrypt);
    }
    let ephemeral: [u8; 32] = sealed[..32].try_into().expect("length checked");
    let shared = secret.diffie_hellman(&PublicKey::from(ephemeral));
    if !shared.was_contributory() {
        return Err(CryptoError::Decrypt);
    }
    let recipient = PublicKey::from(secret).to_bytes();
    let (key, aad) = secrets(shared.as_bytes(), &ephemeral, &recipient, vault, epoch);
    let plain = crypto::open(&key, &sealed[32..32 + NONCE_LEN], &aad, &sealed[32 + NONCE_LEN..])?;
    let bytes: [u8; KEY_LEN] = plain.as_slice().try_into().map_err(|_| CryptoError::Decrypt)?;
    Ok(Zeroizing::new(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(seed: u8) -> (StaticSecret, [u8; 32]) {
        let secret = StaticSecret::from([seed; 32]);
        let public = PublicKey::from(&secret).to_bytes();
        (secret, public)
    }

    /// Fixed test vector: if anything changes here, a new version opens no invitation of an old one.
    #[test]
    fn pinned_vector() {
        let (bob, bob_public) = pair(2);
        let vault_key: Key = Zeroizing::new([5; 32]);
        let sealed = seal_with(&StaticSecret::from([1; 32]), &[9; NONCE_LEN], &vault_key, &[7; 16], 3, &bob_public).unwrap();
        assert_eq!(sealed.len(), SEALED_LEN);
        assert_eq!(crypto::hex(&sealed), include_str!("share.vector").trim());
        assert_eq!(open(&sealed, &[7; 16], 3, &bob).unwrap().as_ref(), vault_key.as_ref());
    }

    #[test]
    fn only_the_recipient_and_only_for_this_vault_and_epoch() {
        let (bob, bob_public) = pair(2);
        let (eve, _) = pair(3);
        let vault_key = crypto::random_key();
        let sealed = seal(&vault_key, &[7; 16], 3, &bob_public).unwrap();
        assert_eq!(open(&sealed, &[7; 16], 3, &bob).unwrap().as_ref(), vault_key.as_ref());
        assert!(open(&sealed, &[7; 16], 3, &eve).is_err(), "foreign key");
        assert!(open(&sealed, &[8; 16], 3, &bob).is_err(), "different vault");
        assert!(open(&sealed, &[7; 16], 4, &bob).is_err(), "different key epoch");
        assert!(open(&sealed[1..], &[7; 16], 3, &bob).is_err(), "wrong length");
        for i in 0..sealed.len() {
            let mut changed = sealed.clone();
            changed[i] ^= 1;
            assert!(open(&changed, &[7; 16], 3, &bob).is_err(), "byte {i} changed");
        }
        assert_ne!(seal(&vault_key, &[7; 16], 3, &bob_public).unwrap(), sealed, "every package is fresh");
    }

    #[test]
    fn a_key_without_contribution_is_refused() {
        assert!(seal(&crypto::random_key(), &[7; 16], 1, &[0; 32]).is_err());
    }
}

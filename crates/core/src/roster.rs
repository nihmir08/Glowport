//! Member list of a shared vault. The owner signs it; the server only keeps it.
//! Rules and reasoning: `docs/sync.md`, section “Member list”.
//!
//! Stored and transferred as one piece: signature (64 bytes), followed by the list as JSON. Exactly these
//! JSON bytes are signed, which is why they are never rewritten, only read.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto;

const LABEL: &str = "glowport/roster/v1";
const SIGNATURE_LEN: usize = 64;
pub const MAX_MEMBERS: usize = 50;
pub const MAX_NAME: usize = 32;
/// This many times the ownership of a vault can change.
pub const MAX_HANDOVERS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Owner,
    Write,
    Read,
}

impl Role {
    pub fn may_write(self) -> bool {
        !matches!(self, Role::Read)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    /// ID of the account on the server (16 bytes as hex).
    pub account: String,
    pub name: String,
    pub ed25519: String,
    pub x25519: String,
    pub role: Role,
}

impl Member {
    pub fn signing_key(&self) -> Option<[u8; 32]> {
        crypto::unhex(&self.ed25519)
    }

    pub fn exchange_key(&self) -> Option<[u8; 32]> {
        crypto::unhex(&self.x25519)
    }
}

/// A transfer of ownership, signed by the previous owner. Every list carries all transfers that ever
/// happened; so even a device that missed one can verify from the owner it knows up to today's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Handover {
    /// Signing keys of the previous and the new owner.
    pub from: String,
    pub to: String,
    /// Number of the list with which the transfer applies.
    pub version: u64,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roster {
    pub vault: String,
    /// Key generation of the vault this list applies to.
    pub epoch: u64,
    /// Sequence number; a list only replaces one with a smaller number.
    pub version: u64,
    pub members: Vec<Member>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub handovers: Vec<Handover>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RosterError {
    #[error("Die Mitgliederliste ist unlesbar oder widerspricht sich")]
    Malformed,
    #[error("Die Mitgliederliste gehört zu einem anderen Tresor")]
    WrongVault,
    #[error("Die Mitgliederliste trägt nicht die Signatur des Besitzers")]
    BadSignature,
    #[error("Die Mitgliederliste ist älter als die bekannte")]
    Stale,
    #[error("Rechte zu entziehen braucht einen Schlüsseltausch")]
    NeedsRotation,
}

impl Roster {
    pub fn owner(&self) -> Option<&Member> {
        self.members.iter().find(|m| m.role == Role::Owner)
    }

    pub fn member(&self, signing_key: &[u8; 32]) -> Option<&Member> {
        self.members.iter().find(|m| m.signing_key().as_ref() == Some(signing_key))
    }

    pub fn role(&self, signing_key: &[u8; 32]) -> Option<Role> {
        self.member(signing_key).map(|m| m.role)
    }

    /// May the holder of this key write records?
    pub fn may_write(&self, signing_key: &[u8; 32]) -> bool {
        self.role(signing_key).is_some_and(Role::may_write)
    }

    fn owner_key(&self) -> Option<[u8; 32]> {
        self.owner().and_then(Member::signing_key)
    }

    /// Exactly one owner, no account and no key twice, all keys readable.
    fn consistent(&self) -> bool {
        let mut accounts = std::collections::BTreeSet::new();
        let mut keys = std::collections::BTreeSet::new();
        self.epoch >= 1
            && self.version >= 1
            && crypto::unhex::<16>(&self.vault).is_some()
            && (1..=MAX_MEMBERS).contains(&self.members.len())
            && self.handovers.len() <= MAX_HANDOVERS
            && self.members.iter().filter(|m| m.role == Role::Owner).count() == 1
            && self.members.iter().all(|m| {
                crypto::unhex::<16>(&m.account).is_some()
                    && m.signing_key().is_some()
                    && m.exchange_key().is_some()
                    && !m.name.is_empty()
                    && m.name.chars().count() <= MAX_NAME
                    && accounts.insert(m.account.clone())
                    && keys.insert(m.ed25519.clone())
            })
    }

    /// The transfers form a chain: each signed by the previous owner, each continuing the one before,
    /// the last one ending at the owner the list names.
    fn handovers_valid(&self, vault: &[u8; 16]) -> bool {
        let (mut holder, mut last_version) = (None, 0);
        for (index, handover) in self.handovers.iter().enumerate() {
            let (Some(from), Some(to), Some(signature)) = (crypto::unhex::<32>(&handover.from), crypto::unhex::<32>(&handover.to), crypto::unhex::<64>(&handover.signature)) else { return false };
            let continues = holder.is_none_or(|holder| holder == from) && handover.version > last_version && handover.version <= self.version;
            if !continues || !signed_by(&from, &handover_message(vault, index as u64, handover.version, &from, &to), &signature) {
                return false;
            }
            (holder, last_version) = (Some(to), handover.version);
        }
        holder.is_none_or(|holder| self.owner_key() == Some(holder))
    }
}

fn message(json: &[u8]) -> Vec<u8> {
    crypto::aad(LABEL, &[json])
}

/// What the previous owner signs for a transfer. The position in the chain and the list number
/// are part of it, so an old transfer cannot be used a second time.
fn handover_message(vault: &[u8; 16], index: u64, version: u64, from: &[u8; 32], to: &[u8; 32]) -> Vec<u8> {
    crypto::aad("glowport/handover/v1", &[vault, &index.to_le_bytes(), &version.to_le_bytes(), from, to])
}

fn signed_by(key: &[u8; 32], message: &[u8], signature: &[u8]) -> bool {
    match (VerifyingKey::from_bytes(key), Signature::from_slice(signature)) {
        (Ok(key), Ok(signature)) => key.verify_strict(message, &signature).is_ok(),
        _ => false,
    }
}

/// Signs a list and checks it right away the way every other device will check it. Fails if it
/// contradicts itself or `key` may not sign it.
pub fn sign(roster: &Roster, previous: Option<&Roster>, key: &SigningKey) -> Result<Vec<u8>, RosterError> {
    let json = serde_json::to_vec(roster).map_err(|_| RosterError::Malformed)?;
    let mut out = key.sign(&message(&json)).to_bytes().to_vec();
    out.extend_from_slice(&json);
    let vault = crypto::unhex(&roster.vault).ok_or(RosterError::Malformed)?;
    verify(&out, &vault, previous)?;
    Ok(out)
}

/// Transfers ownership to a member: the previous owner keeps write permission and signs the
/// transfer. The list number must already be the new one; afterwards they sign the list one last time.
pub fn hand_over(roster: &mut Roster, to: &[u8; 32], key: &SigningKey) -> Result<(), RosterError> {
    let vault = crypto::unhex(&roster.vault).ok_or(RosterError::Malformed)?;
    let from = key.verifying_key().to_bytes();
    if roster.owner_key() != Some(from) {
        return Err(RosterError::BadSignature);
    }
    if from == *to || roster.member(to).is_none() {
        return Err(RosterError::Malformed);
    }
    for member in &mut roster.members {
        member.role = match member.signing_key() {
            Some(key) if key == *to => Role::Owner,
            Some(key) if key == from => Role::Write,
            _ => member.role,
        };
    }
    let signature = key.sign(&handover_message(&vault, roster.handovers.len() as u64, roster.version, &from, to));
    roster.handovers.push(Handover { from: crypto::hex(&from), to: crypto::hex(to), version: roster.version, signature: crypto::hex(&signature.to_bytes()) });
    Ok(())
}

/// Checks a piece from the server.
///
/// A list carries the signature of the owner it names; only the one list with which ownership
/// passes on is signed by the previous owner. With `previous` it must also be newer and name the same
/// owner or reach them through signed transfers: so the server can make neither itself nor anyone else
/// the owner. Without `previous` (the first list this device sees of the vault), whoever it names applies.
pub fn verify(blob: &[u8], vault: &[u8; 16], previous: Option<&Roster>) -> Result<Roster, RosterError> {
    if blob.len() <= SIGNATURE_LEN {
        return Err(RosterError::Malformed);
    }
    let (signature, json) = blob.split_at(SIGNATURE_LEN);
    let roster: Roster = serde_json::from_slice(json).map_err(|_| RosterError::Malformed)?;
    if !roster.consistent() {
        return Err(RosterError::Malformed);
    }
    if crypto::unhex(&roster.vault) != Some(*vault) {
        return Err(RosterError::WrongVault);
    }
    let owner = roster.owner_key().ok_or(RosterError::Malformed)?;
    if !roster.handovers_valid(vault) {
        return Err(RosterError::BadSignature);
    }
    if let Some(previous) = previous {
        if roster.version <= previous.version || roster.epoch < previous.epoch {
            return Err(RosterError::Stale);
        }
        // The transfers continue the known ones and start at the known owner.
        let known = previous.handovers.len();
        let continues = roster.handovers.len() >= known
            && roster.handovers[..known] == previous.handovers[..]
            && match roster.handovers.get(known) {
                Some(next) => crypto::unhex::<32>(&next.from) == previous.owner_key(),
                None => Some(owner) == previous.owner_key(),
            };
        if !continues {
            return Err(RosterError::BadSignature);
        }
    }
    let handing = roster.handovers.last().filter(|handover| handover.version == roster.version).and_then(|handover| crypto::unhex::<32>(&handover.from));
    let message = message(json);
    if signed_by(&owner, &message, signature) || handing.is_some_and(|from| signed_by(&from, &message, signature)) {
        Ok(roster)
    } else {
        Err(RosterError::BadSignature)
    }
}

/// Does someone lose membership or write permission with the new list? Then their records would no longer
/// count, and they would keep the key: that is only possible together with a key rotation.
pub fn reduces(previous: &Roster, next: &Roster) -> bool {
    previous.members.iter().any(|old| match old.signing_key().and_then(|key| next.role(&key)) {
        Some(role) => old.role.may_write() && !role.may_write(),
        None => true,
    })
}

/// Hash over both public keys of an account. The safety code is derived from it,
/// which two people can compare through another channel.
pub fn fingerprint(ed25519: &[u8; 32], x25519: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(crypto::aad("glowport/fingerprint/v1", &[ed25519, x25519])).into()
}

/// The words of the safety code. The list is fixed: changing it would change every account's code.
const WORDS: &str = include_str!("words.txt");

/// An account's safety code: six words from the hash of its keys (54 bits). Two people
/// compare it through another channel; if it matches, the server has not slipped in false
/// keys. Forging a matching code would take generating quadrillions of key pairs.
pub fn safety_code(ed25519: &[u8; 32], x25519: &[u8; 32]) -> String {
    let print = fingerprint(ed25519, x25519);
    let bits = u64::from_be_bytes(print[..8].try_into().expect("acht Byte"));
    let words: Vec<&str> = WORDS.lines().collect();
    (0..6).map(|i| words[((bits >> (64 - 9 * (i + 1))) & 511) as usize]).collect::<Vec<_>>().join(" · ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_safety_code_is_six_words_from_a_fixed_list() {
        let words: Vec<&str> = WORDS.lines().collect();
        let unique: std::collections::BTreeSet<&str> = words.iter().copied().collect();
        assert_eq!((words.len(), unique.len()), (512, 512));
        assert!(words.iter().all(|w| w.len() >= 2 && w.bytes().all(|b| b.is_ascii_lowercase())), "nur Kleinbuchstaben ohne Umlaute: überall gleich zu lesen und zu tippen");
        assert_eq!(crypto::hex(&Sha256::digest(WORDS.as_bytes())), "a52c086639c7e6e0cb1ffbc0295a66266cbb8b18d21efa15fdbe676c2ec7b059", "die Liste darf sich nie ändern");
        // Recomputed independently (Python: SHA-256 over the bound data, nine bits per word).
        assert_eq!(safety_code(&[1; 32], &[2; 32]), "wiese · krabbe · wippe · hahn · holz · drossel");
        assert_ne!(safety_code(&[1; 32], &[2; 32]), safety_code(&[1; 32], &[3; 32]));
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn member(seed: u8, role: Role) -> Member {
        Member {
            account: crypto::hex(&[seed; 16]),
            name: format!("konto{seed}"),
            ed25519: crypto::hex(&key(seed).verifying_key().to_bytes()),
            x25519: crypto::hex(&[seed; 32]),
            role,
        }
    }

    const VAULT: [u8; 16] = [7; 16];

    fn roster(version: u64, members: Vec<Member>) -> Roster {
        Roster { vault: crypto::hex(&VAULT), epoch: 1, version, members, handovers: Vec::new() }
    }

    fn public(seed: u8) -> [u8; 32] {
        key(seed).verifying_key().to_bytes()
    }

    #[test]
    fn signed_by_the_owner_and_bound_to_the_vault() {
        let first = roster(1, vec![member(1, Role::Owner), member(2, Role::Read)]);
        let blob = sign(&first, None, &key(1)).unwrap();
        assert_eq!(verify(&blob, &VAULT, None).unwrap(), first);
        assert_eq!(verify(&blob, &[8; 16], None), Err(RosterError::WrongVault));
        assert_eq!(sign(&first, None, &key(2)), Err(RosterError::BadSignature), "ein Mitglied ist nicht der Besitzer");
        for i in [0, SIGNATURE_LEN + 3, blob.len() - 2] {
            let mut changed = blob.clone();
            changed[i] ^= 1;
            assert!(verify(&changed, &VAULT, None).is_err(), "Byte {i} verändert");
        }
        assert!(first.may_write(&key(1).verifying_key().to_bytes()));
        assert!(!first.may_write(&key(2).verifying_key().to_bytes()), "Leserecht schreibt nicht");
        assert!(!first.may_write(&key(3).verifying_key().to_bytes()), "kein Mitglied");
    }

    /// The server cannot add itself: a new list only counts with the previous owner's signature.
    #[test]
    fn a_new_roster_needs_the_previous_owner() {
        let first = roster(1, vec![member(1, Role::Owner), member(2, Role::Write)]);
        let second = roster(2, vec![member(1, Role::Owner), member(2, Role::Read), member(3, Role::Write)]);
        let blob = sign(&second, Some(&first), &key(1)).unwrap();
        assert_eq!(verify(&blob, &VAULT, Some(&first)).unwrap(), second);
        assert_eq!(verify(&blob, &VAULT, Some(&second)), Err(RosterError::Stale), "dieselbe Nummer noch einmal");

        // An attacker names themselves owner and signs accordingly.
        let forged = roster(3, vec![member(9, Role::Owner), member(1, Role::Read)]);
        let blob = sign(&forged, None, &key(9)).unwrap();
        assert_eq!(verify(&blob, &VAULT, Some(&second)), Err(RosterError::BadSignature));

        let mut older = roster(4, vec![member(1, Role::Owner), member(2, Role::Read)]);
        older.epoch = 1;
        let mut newer = second.clone();
        newer.epoch = 2;
        assert_eq!(sign(&older, Some(&newer), &key(1)), Err(RosterError::Stale), "Schlüsselstand geht nicht zurück");
    }

    #[test]
    fn ownership_is_handed_over_by_the_owner_and_stays_verifiable() {
        let first = roster(1, vec![member(1, Role::Owner), member(2, Role::Write), member(3, Role::Read)]);
        // Simply writing in a different owner does not work, not even for the owner themselves.
        let renamed = roster(2, vec![member(1, Role::Write), member(2, Role::Owner), member(3, Role::Read)]);
        assert_eq!(sign(&renamed, Some(&first), &key(1)), Err(RosterError::BadSignature));
        assert_eq!(sign(&renamed, Some(&first), &key(2)), Err(RosterError::BadSignature));

        let mut handed = first.clone();
        handed.version = 2;
        assert_eq!(hand_over(&mut handed.clone(), &public(2), &key(3)), Err(RosterError::BadSignature), "nur der Besitzer übergibt");
        assert_eq!(hand_over(&mut handed.clone(), &public(9), &key(1)), Err(RosterError::Malformed), "nur an ein Mitglied");
        hand_over(&mut handed, &public(2), &key(1)).unwrap();
        assert_eq!(handed.members.iter().map(|m| m.role).collect::<Vec<_>>(), [Role::Write, Role::Owner, Role::Read]);
        let blob = sign(&handed, Some(&first), &key(1)).unwrap();
        verify(&blob, &VAULT, Some(&first)).unwrap();
        verify(&blob, &VAULT, None).unwrap();

        // The new owner continues the list. Whoever missed the transfer or joins later can verify it.
        let mut third = handed.clone();
        third.version = 3;
        third.members.push(member(4, Role::Read));
        let blob = sign(&third, Some(&handed), &key(2)).unwrap();
        verify(&blob, &VAULT, Some(&first)).unwrap();
        verify(&blob, &VAULT, None).unwrap();
        assert_eq!(sign(&third, Some(&handed), &key(1)), Err(RosterError::BadSignature), "die frühere Besitzerin signiert nichts mehr");

        // A transfer can neither be left out nor rewritten.
        let mut stripped = third.clone();
        stripped.version = 4;
        stripped.handovers.clear();
        assert_eq!(sign(&stripped, Some(&third), &key(2)), Err(RosterError::BadSignature));
        let mut redirected = third.clone();
        redirected.version = 4;
        redirected.handovers[0].to = crypto::hex(&public(3));
        assert_eq!(sign(&redirected, Some(&third), &key(2)), Err(RosterError::BadSignature));

        // There and back: the first transfer cannot be used again afterwards.
        let mut back = third.clone();
        back.version = 4;
        hand_over(&mut back, &public(1), &key(2)).unwrap();
        sign(&back, Some(&third), &key(2)).unwrap();
        let mut replay = back.clone();
        replay.version = 5;
        replay.handovers.push(Handover { version: 5, ..replay.handovers[0].clone() });
        replay.members[0].role = Role::Write;
        replay.members[1].role = Role::Owner;
        assert_eq!(sign(&replay, Some(&back), &key(2)), Err(RosterError::BadSignature));
    }

    #[test]
    fn contradictory_rosters_are_refused() {
        let cases = [
            ("kein Besitzer", roster(1, vec![member(1, Role::Write)])),
            ("zwei Besitzer", roster(1, vec![member(1, Role::Owner), member(2, Role::Owner)])),
            ("Konto doppelt", roster(1, vec![member(1, Role::Owner), member(1, Role::Read)])),
            ("leer", roster(1, vec![])),
            ("Nummer null", roster(0, vec![member(1, Role::Owner)])),
        ];
        for (what, roster) in cases {
            assert_eq!(sign(&roster, None, &key(1)), Err(RosterError::Malformed), "{what}");
        }
        let mut bad = member(2, Role::Read);
        bad.ed25519 = "zz".into();
        assert_eq!(sign(&roster(1, vec![member(1, Role::Owner), bad]), None, &key(1)), Err(RosterError::Malformed));
    }

    #[test]
    fn fingerprint_depends_on_both_keys() {
        assert_ne!(fingerprint(&[1; 32], &[2; 32]), fingerprint(&[2; 32], &[1; 32]));
        assert_eq!(fingerprint(&[1; 32], &[2; 32]), fingerprint(&[1; 32], &[2; 32]));
    }
}

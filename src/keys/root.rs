//! The IS root key — the head of the hierarchy, the only "magic"
//! secret.
//!
//! One offline key, created ONCE (`root genkey`, the wg
//! convention). The secret exists ONLY as a 24-word seed phrase
//! (`mnemonic`): paper in a safe (later k-of-n over the same secret).
//! There are no root files at all: the pubkey (= the service is_id) is
//! a pure function of the phrase (`root pubkey`); no separate storage needed.
//! The root signs the head entries of the chains (`signer new`, the
//! phrase on stdin) and future Root entries (re-root). It never touches
//! the IS host: the identity `is_id = pubkey(root)` is anchored in
//! a key that has never been near a networked machine.
//!
//! Generation ownership: [`generate`] is the only production
//! constructor and pulls its seed from the crate CSPRNG itself —
//! production code CANNOT hand in a chosen (e.g. constant) seed.
//! [`from_seed`] is private (used by [`from_phrase`] and tests).

use crate::crypto::SecretKey;
use crate::keys::mnemonic;

/// A fresh root from the crate CSPRNG (the only production path).
pub fn generate() -> SecretKey {
    SecretKey::generate()
}

/// Root from seed bytes (private: tests and `from_phrase` only).
fn from_seed(seed: &[u8; 32]) -> SecretKey {
    SecretKey::from_bytes(seed)
}

/// Root from a seed phrase (`mnemonic::decode` + `from_seed`): a
/// typo is caught by the checksum. The human-readable and only
/// storage form of the secret: `mnemonic::encode(root.bytes())`.
pub fn from_phrase(phrase: &str) -> Result<SecretKey, String> {
    Ok(from_seed(&mnemonic::decode(phrase)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phrase_is_the_root() {
        let sk = generate();
        let phrase = mnemonic::encode(sk.bytes());
        assert_eq!(phrase.split_whitespace().count(), 24);
        // phrase → the same secret → the same is_id: pubkey is a pure
        // function of the phrase; no other root forms exist
        assert_eq!(from_phrase(&phrase).unwrap().public(), sk.public());
        // a typo — the checksum catches it
        assert!(from_phrase(&format!("{}ship", "abandon ".repeat(23))).is_err());
        // determinism of the private constructor (test seeds)
        assert_eq!(
            from_seed(&[3u8; 32]).public(),
            from_seed(&[3u8; 32]).public()
        );
    }
}

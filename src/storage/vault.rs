//! Pure (all derivations are functions of the pepper); Edge: fs —
//! `Vault::load` reads the pepper file.
//!
//! Vault: pepper and typed storage strings.
//!
//! All kv strings pass through here: `k = HMAC(pepper,
//! "key-v1/{key}")` hides the namespace; every value is sealed with
//! `seal(KDF(pepper, "value-v1", {key}), value)` — a per-record key
//! (envelope encryption). Public rows no longer exist: v7 does not
//! store profile data, so everything is sealed (`auth/…`, `account/…`).
//! Session rows live in their own table under the `"session-v1"`
//! domain (same envelope scheme, separate domain from the kv strings).
//!
//! The pepper lives outside the state directory (0400/0600) and never
//! enters the DB: without it a stolen state.redb is just a set of
//! opaque strings.

use crate::crypto;
use crate::storage::store::{Op, Store};
use crate::wire::Jti;
use std::path::Path;

pub struct Vault {
    pepper: Vec<u8>,
}

impl Vault {
    /// Pepper: exactly 32 bytes, mode 0400/0600 (guard against
    /// accidental writes with group/world read permission).
    pub fn load(path: &Path) -> Result<Vault, String> {
        let b = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        if b.len() != 32 {
            return Err(format!(
                "{}: pepper must be exactly 32 bytes",
                path.display()
            ));
        }
        if !crypto::is_private_mode(path) {
            return Err(format!(
                "{}: pepper must be chmod 0400/0600",
                path.display()
            ));
        }
        Ok(Vault { pepper: b })
    }

    fn k(&self, key_string: &str) -> [u8; 32] {
        crypto::kv_key(&self.pepper, key_string)
    }

    fn vk(&self, key_string: &str) -> [u8; 32] {
        crypto::kv_value_key(&self.pepper, key_string)
    }

    // ------------------------------------------------------------ reading

    /// Unseal a secret value; foreign/corrupt data fails to open.
    pub fn get_sealed(&self, s: &Store, key: &str) -> Result<Option<Vec<u8>>, String> {
        match s.kv_get(&self.k(key))? {
            None => Ok(None),
            Some(sealed) => crypto::open(&self.vk(key), &sealed)
                .map(Some)
                .ok_or_else(|| format!("{key}: value fails authenticity check")),
        }
    }

    // ------------------------------------------------------------ operations

    /// Sealed value (string is unguessable).
    pub fn put_sealed(&self, key: &str, v: &[u8]) -> Op {
        Op::Put {
            k: self.k(key),
            v: crypto::seal(&self.vk(key), v),
        }
    }

    /// Insert-if-absent for a secret (`auth/{cred_id}` during
    /// find-or-create: a two-tab race is resolved by transaction rollback).
    pub fn put_if_absent_sealed(&self, key: &str, v: &[u8]) -> Op {
        Op::PutIfAbsent {
            k: self.k(key),
            v: crypto::seal(&self.vk(key), v),
        }
    }

    pub fn del(&self, key: &str) -> Op {
        Op::Del { k: self.k(key) }
    }

    // ------------------------------------------------------------ sessions table

    /// The sessions-table key of a jti: HMAC(pepper,
    /// "session-v1/{hex(jti)}") — the hex is debuggability only (the
    /// string is HMAC'd before it touches the DB); the domain is
    /// separate from the kv strings.
    pub fn session_key(&self, jti: &Jti) -> [u8; 32] {
        self.k(&format!("session-v1/{}", crypto::hex(jti.bytes())))
    }

    /// Seal a session row body (same envelope as kv values, keyed by
    /// the row string).
    pub fn session_seal(&self, jti: &Jti, v: &[u8]) -> Vec<u8> {
        let key = format!("session-v1/{}", crypto::hex(jti.bytes()));
        crypto::seal(&self.vk(&key), v)
    }

    /// Open a session row body; foreign/corrupt data fails to open.
    pub fn session_open(&self, jti: &Jti, sealed: &[u8]) -> Option<Vec<u8>> {
        let key = format!("session-v1/{}", crypto::hex(jti.bytes()));
        crypto::open(&self.vk(&key), sealed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pepper_guards() {
        let d =
            std::env::temp_dir().join(format!("vault-{}-{}", std::process::id(), crypto::now()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("pepper");
        // not 32 bytes
        std::fs::write(&p, b"short").unwrap();
        assert!(Vault::load(&p).is_err());
        // world-readable
        std::fs::remove_file(&p).unwrap();
        crypto::write_secret_0400(&p, &[7u8; 32]).unwrap();
        let mut perms = std::fs::metadata(&p).unwrap().permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            perms.set_mode(0o644);
        }
        std::fs::set_permissions(&p, perms).unwrap();
        assert!(Vault::load(&p).is_err());
        // valid
        std::fs::remove_file(&p).unwrap();
        crypto::write_secret_0400(&p, &[7u8; 32]).unwrap();
        assert!(Vault::load(&p).is_ok());
        let _ = std::fs::remove_dir_all(&d);
    }
}

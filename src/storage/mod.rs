//! Edge: fs/redb. Layer 4 of the lib.rs tower (builds on wire, codec,
//! crypto). The persistence layer — THE state.redb schema lives here
//! and nowhere else:
//!
//! ```text
//! table    key                             value
//! -------  ------------------------------  ----------------------------------------
//! kv       auth/{cred_id}                  (sealed) AuthRef    V1: the account key
//! kv       account/{hex(account_key)}      (sealed) Account    V1: keys, bio, creds, UA
//! sessions session-v1/{hex(jti)}           (sealed) SessionRow V1: account key,
//!                                                   session pk, exact exp
//!          ‖ the coarse public EOL (u64) — a GC hint, NOT auth data
//! ```
//!
//! Row keys never reach redb in the clear: kv rows are keyed by
//! `HMAC(pepper, "key-v1/{row}")`, session rows by `HMAC(pepper,
//! "session-v1/{hex(jti)}")`, and every sealed body is encrypted
//! per-row (envelope encryption, see [`vault`]). The `hex` in row
//! names is debuggability only — the string is HMAC'd before it
//! touches the DB, so the encoding is invisible on disk.
//!
//! Every sealed plaintext starts with a version byte (`[V:u8][body]`,
//! codecs in [`records`] — all record types live there). While
//! pre-release every row is V1 and there are NO migration arms: a
//! format change wipes the dev database. Two things are deliberately
//! NOT row-versioned here: the crypto envelope itself (the seal
//! format), and the table set — the latter is guarded by SCHEMA in
//! [`store`] (a table-set change is a new schema, old databases
//! refused; pre-release policy).
//!
//! # The coarse public EOL
//!
//! The sessions table stores, next to the sealed row, a COARSE
//! approximation of the expiry: `(exp/30d + 1)*30d` — month precision
//! — plus a random +30d jitter (so the public column never reveals
//! even the month exactly). The invariant `coarse > exp` always
//! holds. The column is a GC hint ONLY: authentication reads the
//! sealed exp (AEAD-sealed — a tampered DB cannot extend a session),
//! and the boot sweep deletes rows whose coarse EOL has passed.
//!
//! API shape: reads are immediate; writes return an [`Op`] (a pure
//! value) that the caller composes into one atomic batch via
//! [`Storage::commit`] — transaction boundaries stay at the flows.

use crate::crypto::{self, SecretKey};
use crate::storage::records::{AuthRef, SessionRow};
use crate::storage::store::Store;
use crate::wire::Jti;
use std::path::Path;

pub mod records;
pub mod store;
pub mod vault;

pub use records::{Account, Cred};
pub use store::Op;
pub use vault::Vault;

/// 30 days in seconds — the coarse-EOL bucket size.
const MONTH: u64 = 30 * 86400;

/// The coarse public EOL of a session: the month bucket AFTER exp,
/// plus a one-bucket jitter with probability ½. Month precision at
/// most (the jitter breaks even that), and STRICTLY greater than exp
/// — the sweep can never take a live session. Pure.
fn coarse_eol(exp: u64, jitter: bool) -> u64 {
    let bucket_end = (exp / MONTH + 1).saturating_mul(MONTH);
    bucket_end.saturating_add(u64::from(jitter) * MONTH)
}

pub struct Storage {
    store: Store,
    vault: Vault,
}

impl Storage {
    /// Open: state.redb (schema check, auto-created) under the
    /// already-loaded pepper, then the boot sweep (GC of dead
    /// sessions by coarse EOL).
    pub fn open(dir: &Path, vault: Vault) -> Result<Storage, String> {
        let store = Store::open(dir)?;
        store.sweep_sessions(crypto::now())?;
        Ok(Storage { store, vault })
    }

    /// Storage directory (for IS service files).
    pub fn dir(&self) -> &Path {
        self.store.dir()
    }

    /// Atomic batch: all ops of both tables in one redb transaction
    /// (fsync on commit); a PutIfAbsent collision rolls the whole
    /// batch back.
    pub fn commit(&self, ops: Vec<Op>) -> Result<(), String> {
        self.store.commit(&ops)
    }

    // ------------------------------------------------------------ auth/

    /// The account key behind a login credential; None — unknown cred.
    pub fn auth_ref(&self, cred_id: &str) -> Result<Option<SecretKey>, String> {
        match self.vault.get_sealed(&self.store, &row_auth(cred_id))? {
            None => Ok(None),
            Some(b) => Ok(Some(AuthRef::decode(&b)?.account_key)),
        }
    }

    /// Insert-if-absent of the credential row (find-or-create races
    /// are resolved by transaction rollback).
    pub fn put_auth_ref(&self, cred_id: &str, account_key: &SecretKey) -> Op {
        self.vault.put_if_absent_sealed(
            &row_auth(cred_id),
            &AuthRef {
                account_key: *account_key,
            }
            .encode(),
        )
    }

    pub fn del_auth_ref(&self, cred_id: &str) -> Op {
        self.vault.del(&row_auth(cred_id))
    }

    // ------------------------------------------------------------ account/

    pub fn account(&self, account_key: &SecretKey) -> Result<Option<Account>, String> {
        match self
            .vault
            .get_sealed(&self.store, &row_account(account_key))?
        {
            None => Ok(None),
            Some(b) => Account::decode(&b)
                .map(Some)
                .map_err(|_| "account row: malformed".to_string()),
        }
    }

    pub fn put_account(&self, account_key: &SecretKey, a: &Account) -> Op {
        self.vault
            .put_sealed(&row_account(account_key), &a.encode())
    }

    // ------------------------------------------------------------ session/

    /// A live session by jti (the reverse index of issued certs).
    /// Reads ONLY the sealed row: the coarse EOL column is GC data,
    /// never auth data.
    pub fn session(&self, jti: &Jti) -> Result<Option<SessionRow>, String> {
        match self.store.session_get(&self.vault.session_key(jti))? {
            None => Ok(None),
            Some((sealed, _coarse)) => {
                let body = self
                    .vault
                    .session_open(jti, &sealed)
                    .ok_or_else(|| "session row: value fails authenticity check".to_string())?;
                Ok(Some(SessionRow::decode(&body)?))
            }
        }
    }

    /// Write a session row: sealed body + the coarse public EOL
    /// (bucket + random jitter — see the module docs).
    pub fn put_session(&self, jti: &Jti, row: &SessionRow) -> Op {
        let jitter = crypto::random_arr::<1>()[0] & 1 == 1;
        Op::SessionPut {
            k: self.vault.session_key(jti),
            sealed: self.vault.session_seal(jti, &row.encode()),
            coarse_eol: coarse_eol(row.exp, jitter),
        }
    }

    pub fn del_session(&self, jti: &Jti) -> Op {
        Op::SessionDel {
            k: self.vault.session_key(jti),
        }
    }
}

// ------------------------------------------------------------ row names

// The ONLY place kv row names exist (hex: debuggability only — the
// string is HMAC'd before it reaches redb).

fn row_auth(cred_id: &str) -> String {
    format!("auth/{cred_id}")
}

fn row_account(account_key: &SecretKey) -> String {
    format!("account/{}", crypto::hex(account_key.bytes()))
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random_arr;
    use crate::storage::records::Cred;
    use crate::wire::SessionPk;

    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(tag: &str) -> TempDir {
            let d = std::env::temp_dir().join(format!(
                "dentrado-auth-storage-{}-{}-{tag}",
                std::process::id(),
                crate::crypto::now()
            ));
            std::fs::create_dir_all(&d).unwrap();
            TempDir(d)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn storage(tag: &str) -> Storage {
        let dir = TempDir::new(tag);
        let pepper = dir.0.join("pepper.bin");
        crate::crypto::write_secret_0400(&pepper, &[9u8; 32]).unwrap();
        let vault = Vault::load(&pepper).unwrap();
        // keep the dir alive for the Storage lifetime: leak it (test-only)
        let d = dir.0.clone();
        std::mem::forget(dir);
        Storage::open(&d, vault).unwrap()
    }

    #[test]
    fn coarse_eol_is_strictly_after_exp() {
        // the invariant the sweep relies on: never below exp
        for _ in 0..100 {
            let exp = u64::from_be_bytes(random_arr::<8>()) % (1 << 40);
            assert!(coarse_eol(exp, false) > exp);
            assert!(coarse_eol(exp, true) > exp);
        }
        // month precision at most: without jitter the difference is
        // under one bucket, with jitter under two
        let exp = 1_700_000_000u64;
        assert!(coarse_eol(exp, false) - exp <= MONTH);
        assert!(coarse_eol(exp, true) - exp <= 2 * MONTH);
        // the exp edge of a bucket
        assert_eq!(coarse_eol(0, false), MONTH);
        assert_eq!(coarse_eol(MONTH, false), 2 * MONTH);
    }

    #[test]
    fn rows_roundtrip_all_families() {
        let s = storage("rows");

        // one account (its key born inside generate) — all three row
        // families hang off the same key
        let mut a = Account::generate();
        let sk = a.secret;
        a.creds.push(Cred {
            id: "cred-x".into(),
            pk: b"cose".to_vec(),
            added_at: 1,
            ua: None,
        });

        // auth/
        assert!(s.auth_ref("cred-x").unwrap().is_none());
        s.commit(vec![s.put_auth_ref("cred-x", &sk)]).unwrap();
        assert_eq!(s.auth_ref("cred-x").unwrap(), Some(sk));

        // account/
        s.commit(vec![s.put_account(&sk, &a)]).unwrap();
        assert_eq!(s.account(&sk).unwrap(), Some(a));

        // session/
        let row = SessionRow {
            account_key: sk,
            session_pk: SessionPk::from_bytes(&[3u8; 64]),
            exp: 123,
        };
        let jti = Jti::from_bytes(&[7u8; 16]);
        s.commit(vec![s.put_session(&jti, &row)]).unwrap();
        assert_eq!(s.session(&jti).unwrap(), Some(row));

        // deletions
        s.commit(vec![s.del_auth_ref("cred-x"), s.del_session(&jti)])
            .unwrap();
        assert!(s.auth_ref("cred-x").unwrap().is_none());
        assert!(s.session(&jti).unwrap().is_none());
    }

    #[test]
    fn auth_ref_insert_if_absent_conflict_rolls_back() {
        let s = storage("ifabsent");
        let sk = SecretKey::from_bytes(&[1u8; 32]);
        s.commit(vec![s.put_auth_ref("cred", &sk)]).unwrap();
        // a second insert-if-absent on the same cred + a fresh session
        // row in one batch: the WHOLE batch rolls back
        let jti = Jti::from_bytes(&[2u8; 16]);
        let row = SessionRow {
            account_key: sk,
            session_pk: SessionPk::from_bytes(&[0u8; 64]),
            exp: 1,
        };
        assert!(
            s.commit(vec![
                s.put_session(&jti, &row),
                s.put_auth_ref("cred", &SecretKey::from_bytes(&[9u8; 32])),
            ])
            .is_err()
        );
        assert_eq!(s.auth_ref("cred").unwrap(), Some(sk), "old value in place");
        assert!(s.session(&jti).unwrap().is_none(), "batch rolled back");
    }

    #[test]
    fn boot_sweep_gcs_dead_sessions_only() {
        // one dead + one live session; a RE-open (fresh Storage over
        // the same dir — the boot sweep) must delete only the dead one
        let dir = TempDir::new("sweep");
        let pepper = dir.0.join("pepper.bin");
        crate::crypto::write_secret_0400(&pepper, &[9u8; 32]).unwrap();
        let vault = Vault::load(&pepper).unwrap();
        let d = dir.0.clone();
        std::mem::forget(dir);
        let s = Storage::open(&d, vault).unwrap();

        let now = crate::crypto::now();
        let live = SessionRow {
            account_key: SecretKey::from_bytes(&[1u8; 32]),
            session_pk: SessionPk::from_bytes(&[1u8; 64]),
            exp: now + 3600,
        };
        let dead = SessionRow {
            account_key: SecretKey::from_bytes(&[2u8; 32]),
            session_pk: SessionPk::from_bytes(&[2u8; 64]),
            exp: now - 10 * MONTH, // long expired; its coarse EOL passed too
        };
        let j_live = Jti::from_bytes(&[3u8; 16]);
        let j_dead = Jti::from_bytes(&[4u8; 16]);
        s.commit(vec![
            s.put_session(&j_live, &live),
            s.put_session(&j_dead, &dead),
        ])
        .unwrap();

        // re-open: the old handle dies first (redb is exclusive),
        // the boot sweep runs against the coarse EOL
        drop(s);
        let vault = Vault::load(&pepper).unwrap();
        let s2 = Storage::open(&d, vault).unwrap();
        assert!(
            s2.session(&j_dead).unwrap().is_none(),
            "the dead session is swept on boot"
        );
        assert_eq!(
            s2.session(&j_live).unwrap(),
            Some(live),
            "a live session survives the sweep"
        );
    }
}

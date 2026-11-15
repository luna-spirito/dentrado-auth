//! Persistence (Edge: fs/redb): three redb tables — `meta`, `kv`
//! (sealed rows; the vault gives the bytes meaning: `k = HMAC(pepper,
//! "key-v1/{key}")`, `v = seal(KDF(pepper,"value-v1", {key}), value)`)
//! and `sessions` (the live-session index: key = HMAC(pepper,
//! "session-v1/{jti}"), value = (sealed SessionRow, coarse public
//! EOL) — the coarse half is a GC hint ONLY, the exact exp is sealed;
//! see [`crate::storage`] for the policy). The Store knows neither
//! the pepper nor the row formats — the "value sensitivity ↔
//! unguessable row key" invariant holds by itself.
//!
//! There is no RECS journal anymore (CRL deferred — README §×); v1 revocation
//! is deleting the session row (the cert lives out its exp, see README).
//!
//! Atomicity: `commit` writes all ops of BOTH data tables in one redb
//! transaction (fsync at commit); `PutIfAbsent` on an occupied row
//! rolls back the whole transaction — transactional insert-if-absent
//! (find-or-create).
//!
//! Schema 1 (dev): the sessions table is part of the first schema;
//! the project is pre-release, so an incompatible database is refused
//! and simply deleted — no migrations.

use redb::{Database, ReadableTable, TableDefinition};
use std::path::{Path, PathBuf};

const META: TableDefinition<&str, u64> = TableDefinition::new("meta");
const KV: TableDefinition<&[u8], &[u8]> = TableDefinition::new("kv");
/// (sealed row body, coarse public EOL) — the coarse half is a
/// months-precision GC hint; the exact exp lives inside the seal.
const SESSIONS: TableDefinition<&[u8], (&[u8], u64)> = TableDefinition::new("sessions");

const META_SCHEMA: &str = "schema";
const SCHEMA: u64 = 1;

fn redb_err<E: std::fmt::Display>(e: E) -> String {
    format!("redb: {e}")
}

/// One operation inside a commit batch — kv rows and session rows
/// share the transaction (a register/eroll batch stays atomic).
#[derive(Clone, Debug)]
pub enum Op {
    Put {
        k: [u8; 32],
        v: Vec<u8>,
    },
    PutIfAbsent {
        k: [u8; 32],
        v: Vec<u8>,
    },
    Del {
        k: [u8; 32],
    },
    /// Insert/overwrite a session row: sealed body + coarse EOL.
    SessionPut {
        k: [u8; 32],
        sealed: Vec<u8>,
        coarse_eol: u64,
    },
    SessionDel {
        k: [u8; 32],
    },
}

pub struct Store {
    db: Database,
    dir: PathBuf,
}

impl Store {
    pub fn open(dir: &Path) -> Result<Store, String> {
        let db =
            Database::create(dir.join("state.redb")).map_err(|e| format!("state.redb: {e}"))?;
        let store = Store {
            db,
            dir: dir.to_path_buf(),
        };
        store.ensure_schema()?;
        Ok(store)
    }

    fn ensure_schema(&self) -> Result<(), String> {
        let txn = self.db.begin_read().map_err(redb_err)?;
        let schema = match txn.open_table(META) {
            Ok(t) => t.get(META_SCHEMA).map_err(redb_err)?.map(|g| g.value()),
            Err(redb::TableError::TableDoesNotExist(_)) => None,
            Err(e) => return Err(redb_err(e)),
        };
        drop(txn);
        match schema {
            None => {
                let w = self.db.begin_write().map_err(redb_err)?;
                {
                    let mut m = w.open_table(META).map_err(redb_err)?;
                    m.insert(META_SCHEMA, SCHEMA).map_err(redb_err)?;
                    // declarative boot: the tables exist right after the
                    // open (a read before the first commit must not fail)
                    let _kv = w.open_table(KV).map_err(redb_err)?;
                    let _sessions = w.open_table(SESSIONS).map_err(redb_err)?;
                }
                w.commit().map_err(redb_err)?;
            }
            Some(s) if s == SCHEMA => {}
            Some(_) => {
                return Err(
                    "state.redb: incompatible database (pre-production); delete and re-serve"
                        .into(),
                );
            }
        }
        Ok(())
    }

    /// Atomic (one redb transaction, fsync on commit): all ops across
    /// the kv and sessions tables. PutIfAbsent on a collision rolls
    /// everything back.
    pub fn commit(&self, ops: &[Op]) -> Result<(), String> {
        if ops.is_empty() {
            return Ok(());
        }
        let txn = self.db.begin_write().map_err(redb_err)?;
        {
            let mut kv_t = txn.open_table(KV).map_err(redb_err)?;
            let mut sess_t = txn.open_table(SESSIONS).map_err(redb_err)?;
            for op in ops {
                match op {
                    Op::Put { k, v } => {
                        kv_t.insert(k.as_slice(), v.as_slice()).map_err(redb_err)?;
                    }
                    Op::PutIfAbsent { k, v } => {
                        if kv_t.get(k.as_slice()).map_err(redb_err)?.is_some() {
                            return Err("kv: key already exists (insert-if-absent)".into());
                        }
                        kv_t.insert(k.as_slice(), v.as_slice()).map_err(redb_err)?;
                    }
                    Op::Del { k } => {
                        kv_t.remove(k.as_slice()).map_err(redb_err)?;
                    }
                    Op::SessionPut {
                        k,
                        sealed,
                        coarse_eol,
                    } => {
                        sess_t
                            .insert(k.as_slice(), (sealed.as_slice(), *coarse_eol))
                            .map_err(redb_err)?;
                    }
                    Op::SessionDel { k } => {
                        sess_t.remove(k.as_slice()).map_err(redb_err)?;
                    }
                }
            }
        }
        txn.commit().map_err(redb_err)?;
        Ok(())
    }

    // ------------------------------------------------------------ kv

    pub fn kv_get(&self, k: &[u8; 32]) -> Result<Option<Vec<u8>>, String> {
        let txn = self.db.begin_read().map_err(redb_err)?;
        let t = txn.open_table(KV).map_err(redb_err)?;
        Ok(t.get(k.as_slice())
            .map_err(redb_err)?
            .map(|g| g.value().to_vec()))
    }

    // ------------------------------------------------------------ sessions

    /// A session row by storage key: (sealed body, coarse EOL).
    pub fn session_get(&self, k: &[u8; 32]) -> Result<Option<(Vec<u8>, u64)>, String> {
        let txn = self.db.begin_read().map_err(redb_err)?;
        let t = txn.open_table(SESSIONS).map_err(redb_err)?;
        Ok(t.get(k.as_slice())
            .map_err(redb_err)?
            .map(|g| (g.value().0.to_vec(), g.value().1)))
    }

    /// The boot sweep (GC): delete session rows whose COARSE EOL has
    /// passed — the sealed exp is never consulted here (the coarse
    /// column over-estimates it, so a live session is never swept).
    /// One transaction; returns the number of rows deleted.
    pub fn sweep_sessions(&self, now: u64) -> Result<usize, String> {
        let mut dead: Vec<[u8; 32]> = Vec::new();
        {
            let txn = self.db.begin_read().map_err(redb_err)?;
            let t = txn.open_table(SESSIONS).map_err(redb_err)?;
            for g in t.iter().map_err(redb_err)? {
                let (kg, vg) = g.map_err(redb_err)?;
                if vg.value().1 < now {
                    dead.push(kg.value().to_vec().try_into().expect("32-byte key"));
                }
            }
        }
        if dead.is_empty() {
            return Ok(0);
        }
        let n = dead.len();
        let ops: Vec<Op> = dead.drain(..).map(|k| Op::SessionDel { k }).collect();
        self.commit(&ops)?;
        Ok(n)
    }

    // ------------------------------------------------------------ misc

    /// Storage directory (for IS service files).
    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> TempDir {
            let d = std::env::temp_dir().join(format!(
                "dentrado-auth-store8-{}-{}-{}",
                tag,
                std::process::id(),
                crate::crypto::now()
            ));
            std::fs::create_dir_all(&d).unwrap();
            TempDir(d)
        }
        fn join(&self, p: &str) -> PathBuf {
            self.0.join(p)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn kv_roundtrip_and_atomic_if_absent() {
        let dir = TempDir::new("kv");
        let s = Store::open(&dir.0).unwrap();
        let k1 = [1u8; 32];
        let k2 = [2u8; 32];

        s.commit(&[Op::Put {
            k: k1,
            v: b"v1".to_vec(),
        }])
        .unwrap();
        assert_eq!(s.kv_get(&k1).unwrap().as_deref(), Some(&b"v1"[..]));
        assert!(s.kv_get(&k2).unwrap().is_none());

        // overwrite
        s.commit(&[Op::Put {
            k: k1,
            v: b"v1b".to_vec(),
        }])
        .unwrap();
        assert_eq!(s.kv_get(&k1).unwrap().as_deref(), Some(&b"v1b"[..]));

        // PutIfAbsent over an existing one — fails, the WHOLE batch rolls back
        let err = s.commit(&[
            Op::Put {
                k: k2,
                v: b"tmp".to_vec(),
            },
            Op::PutIfAbsent {
                k: k1,
                v: b"x".to_vec(),
            },
        ]);
        assert!(err.is_err());
        assert_eq!(
            s.kv_get(&k1).unwrap().as_deref(),
            Some(&b"v1b"[..]),
            "old value in place"
        );
        assert!(s.kv_get(&k2).unwrap().is_none(), "batch rolled back");

        // onto a free string — ok
        s.commit(&[Op::PutIfAbsent {
            k: k2,
            v: b"v2".to_vec(),
        }])
        .unwrap();
        assert_eq!(s.kv_get(&k2).unwrap().as_deref(), Some(&b"v2"[..]));

        // deletion
        s.commit(&[Op::Del { k: k1 }]).unwrap();
        assert!(s.kv_get(&k1).unwrap().is_none());
    }

    #[test]
    fn sessions_table_and_sweep() {
        let dir = TempDir::new("sess");
        let s = Store::open(&dir.0).unwrap();
        let live = [1u8; 32];
        let dead = [2u8; 32];

        // one live (coarse in the future), one dead (coarse in the past)
        s.commit(&[
            Op::SessionPut {
                k: live,
                sealed: b"sealed-live".to_vec(),
                coarse_eol: 10_000,
            },
            Op::SessionPut {
                k: dead,
                sealed: b"sealed-dead".to_vec(),
                coarse_eol: 500,
            },
        ])
        .unwrap();
        assert_eq!(
            s.session_get(&live).unwrap(),
            Some((b"sealed-live".to_vec(), 10_000))
        );

        // sweep at now=1000: only the row whose COARSE eol passed dies
        assert_eq!(s.sweep_sessions(1_000).unwrap(), 1);
        assert!(s.session_get(&dead).unwrap().is_none());
        assert_eq!(
            s.session_get(&live).unwrap().map(|(v, _)| v),
            Some(b"sealed-live".to_vec()),
            "a live session is never swept"
        );
        // idempotent
        assert_eq!(s.sweep_sessions(1_000).unwrap(), 0);

        // overwrite + delete through Op
        s.commit(&[Op::SessionPut {
            k: live,
            sealed: b"sealed-2".to_vec(),
            coarse_eol: 20_000,
        }])
        .unwrap();
        s.commit(&[Op::SessionDel { k: live }]).unwrap();
        assert!(s.session_get(&live).unwrap().is_none());
    }

    #[test]
    fn rejects_incompatible_schema_database() {
        let dir = TempDir::new("old");
        let db = Database::create(dir.join("state.redb")).unwrap();
        let txn = db.begin_write().unwrap();
        {
            let mut m = txn.open_table(META).unwrap();
            m.insert(META_SCHEMA, SCHEMA + 1).unwrap();
        }
        txn.commit().unwrap();
        drop(db);
        let err = match Store::open(&dir.0) {
            Err(e) => e,
            Ok(_) => panic!("incompatible-schema database must be rejected"),
        };
        assert!(err.contains("incompatible"), "got: {err}");
    }
}

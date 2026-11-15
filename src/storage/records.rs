//! Pure (layer 4's codec sublayer). Row codecs — the sealed plaintext
//! format of EVERY state.redb row: the schema overview lives in the
//! [`crate::storage`] module docs, and all record types live HERE
//! (Account, AuthRef, SessionRow — one place, no scattering).
//!
//! Convention: a row body is `[V:u8][body]`. While pre-release every
//! row is V1: there are no migration arms — a format change wipes the
//! dev database instead. The wire documents (`crate::wire`) follow the
//! same shape with the family version `codec::bin::V`.

use crate::codec::bin::{R, W, WireErr};
use crate::crypto::{PublicKey, SecretKey, hex};
use crate::wire::SessionPk;

fn corrupt(_: WireErr) -> String {
    "record: corrupt".into()
}

fn unsupported(v: u8) -> String {
    format!("record version {v} is not supported by this build")
}

// ---------------------------------------------------------------- auth/

/// The `auth/{cred_id}` row: the account key behind a login
/// credential (the credential → account index).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthRef {
    /// The account this credential logs into.
    pub account_key: SecretKey,
}

const AUTH_REF_V: u8 = 1;

impl AuthRef {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = W::new();
        w.u8(AUTH_REF_V);
        w.a32(self.account_key.bytes());
        w.out
    }

    pub fn decode(b: &[u8]) -> Result<AuthRef, String> {
        let mut r = R::new(b);
        match r.u8().map_err(corrupt)? {
            AUTH_REF_V => {}
            v => return Err(unsupported(v)),
        }
        let account_key = SecretKey::from_bytes(&r.a32().map_err(corrupt)?);
        r.done().map_err(corrupt)?;
        Ok(AuthRef { account_key })
    }
}

// ---------------------------------------------------------------- account/

/// An account: 1 account = 1 "profile", and the IS does NOT store its
/// data — only the account key, the login methods (WebAuthn creds),
/// an optional user-facing name and the optional bio homeserver (the
/// Dentrado instance holding the profile details). Live sessions live
/// in their own table (`SessionRow`), NOT here.
///
/// `secret` — an Ed25519 seed: the second signature of every cert
/// (stealing the signer bundle does not allow minting other accounts'
/// certs). The account key is born ONLY inside [`Account::generate`]
/// (crate CSPRNG); `from_seed` is test-only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    pub secret: SecretKey,
    pub public: PublicKey,
    /// User-facing profile name (optional). Shown by credential managers
    /// and in the profile switcher; sealed with the rest of the row.
    pub name: Option<String>,
    /// The bio homeserver (URL of the Dentrado instance storing the
    /// profile details). Empty → no homeserver.
    pub bio_homeserver: Option<String>,
    pub creds: Vec<Cred>,
}

/// Login credential (WebAuthn): b64u(cred_id) → COSE key.
///
/// Credentials are ordered by addition: `creds[0]` is the account's
/// first (and permanent) key. Unlinking a credential requires a step-up
/// by an OLDER one — see [`crate::server::login`].
///
/// `ua` — an optional, client-supplied User Agent string. It is a hint
/// for the dashboard only; the server never derives authority from it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cred {
    pub id: String,
    pub pk: Vec<u8>,
    pub added_at: u64,
    pub ua: Option<String>,
}

/// All rows are V1 while the project is pre-release. There are NO
/// migration arms: a format change is accompanied by wiping
/// `state.redb` (dev-only policy), so version 1 is always the only
/// version the code understands.
const ACCOUNT_V: u8 = 1;

impl Account {
    /// A new account with a chosen seed (private: tests only —
    /// production code cannot hand in a chosen account key; use
    /// [`Account::generate`]).
    #[cfg(test)]
    fn from_seed(seed: &[u8; 32]) -> Account {
        let sk = SecretKey::from_bytes(seed);
        Account {
            public: sk.public(),
            secret: sk,
            name: None,
            bio_homeserver: None,
            creds: Vec::new(),
        }
    }

    /// A fresh account — the ONLY production constructor: the account
    /// key is born here from the crate CSPRNG.
    pub fn generate() -> Account {
        let sk = SecretKey::generate();
        Account {
            public: sk.public(),
            secret: sk,
            name: None,
            bio_homeserver: None,
            creds: Vec::new(),
        }
    }

    pub fn has_cred(&self, id: &str) -> bool {
        self.creds.iter().any(|c| c.id == id)
    }

    /// Stable fallback label derived from the account public key.
    pub fn short_name(&self) -> String {
        format!("Profile {}", &hex(self.public.bytes())[..8])
    }

    /// Name shown by credential managers and the profile switcher.
    pub fn display_name(&self) -> String {
        self.name.clone().unwrap_or_else(|| self.short_name())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = W::new();
        w.u8(ACCOUNT_V);
        w.a32(self.secret.bytes());
        w.a32(self.public.bytes());
        match &self.bio_homeserver {
            Some(b) => {
                w.u8(1);
                w.str(b);
            }
            None => w.u8(0),
        }
        match &self.name {
            Some(n) => {
                w.u8(1);
                w.str(n);
            }
            None => w.u8(0),
        }
        w.u64(self.creds.len() as u64);
        for c in &self.creds {
            w.str(&c.id);
            w.bytes(&c.pk);
            w.u64(c.added_at);
            match &c.ua {
                Some(ua) => {
                    w.u8(1);
                    w.str(ua);
                }
                None => w.u8(0),
            }
        }
        w.out
    }

    pub fn decode(b: &[u8]) -> Result<Account, WireErr> {
        let mut r = R::new(b);
        let version = r.u8()?;
        if version != ACCOUNT_V {
            return Err(WireErr);
        }
        let secret = SecretKey::from_bytes(&r.a32()?);
        let public = PublicKey::from_bytes(&r.a32()?);
        // The stored public half must match the secret: a row where they
        // disagree is corrupt (or tampered) and must not load — the
        // public key is what certs and lookups are keyed by.
        if public != secret.public() {
            return Err(WireErr);
        }
        let bio_homeserver = if r.u8()? != 0 { Some(r.str()?) } else { None };
        let name = if r.u8()? != 0 { Some(r.str()?) } else { None };
        let mut creds = Vec::new();
        for _ in 0..r.u64()? {
            let id = r.str()?;
            let pk = r.bytes()?;
            let added_at = r.u64()?;
            let ua = if r.u8()? != 0 { Some(r.str()?) } else { None };
            creds.push(Cred {
                id,
                pk,
                added_at,
                ua,
            });
        }
        r.done()?;
        Ok(Account {
            secret,
            public,
            name,
            bio_homeserver,
            creds,
        })
    }
}

// ---------------------------------------------------------------- session/

/// The `session/{jti}` row (the sealed half of the sessions-table
/// value): the live-session reverse index — one row per issued cert,
/// deleted by logout and by the boot sweep.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionRow {
    pub account_key: SecretKey,
    pub session_pk: SessionPk,
    /// The exact expiry — SECRET (sealed); the public column next to
    /// it carries only a coarse EOL (see [`crate::storage`]).
    pub exp: u64,
}

const SESSION_ROW_V: u8 = 1;

impl SessionRow {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = W::new();
        w.u8(SESSION_ROW_V);
        w.a32(self.account_key.bytes());
        w.a64(self.session_pk.bytes());
        w.u64(self.exp);
        w.out
    }

    pub fn decode(b: &[u8]) -> Result<SessionRow, String> {
        let mut r = R::new(b);
        match r.u8().map_err(corrupt)? {
            SESSION_ROW_V => {}
            v => return Err(unsupported(v)),
        }
        let row = SessionRow {
            account_key: SecretKey::from_bytes(&r.a32().map_err(corrupt)?),
            session_pk: SessionPk::from_bytes(&r.a64().map_err(corrupt)?),
            exp: r.u64().map_err(corrupt)?,
        };
        r.done().map_err(corrupt)?;
        Ok(row)
    }
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_ref_roundtrip() {
        let a = AuthRef {
            account_key: SecretKey::from_bytes(&[7u8; 32]),
        };
        assert_eq!(AuthRef::decode(&a.encode()).unwrap(), a);
        // the version byte is the first plaintext byte
        assert_eq!(a.encode()[0], AUTH_REF_V);
    }

    #[test]
    fn unknown_version_is_explicit() {
        let mut b = AuthRef {
            account_key: SecretKey::from_bytes(&[7u8; 32]),
        }
        .encode();
        b[0] = 2;
        let e = AuthRef::decode(&b).unwrap_err();
        assert!(e.contains("version 2"), "{e}");
        // the same for account and session rows
        let mut b = Account::from_seed(&[1u8; 32]).encode();
        b[0] = ACCOUNT_V + 1;
        assert!(Account::decode(&b).is_err(), "unknown account version");
        let mut b = SessionRow {
            account_key: SecretKey::from_bytes(&[1; 32]),
            session_pk: SessionPk::from_bytes(&[2; 64]),
            exp: 42,
        }
        .encode();
        b[0] = 99;
        assert!(SessionRow::decode(&b).unwrap_err().contains("version 99"));
    }

    #[test]
    fn account_roundtrip() {
        let mut a = Account::from_seed(&[9u8; 32]);
        assert_eq!(
            a.public,
            SecretKey::from_bytes(&[9u8; 32]).public(),
            "public is a pure function of the seed"
        );
        a.name = Some("Alice".into());
        a.bio_homeserver = Some("https://home.example".into());
        a.creds.push(Cred {
            id: "cred-abc".into(),
            pk: b"cose-key".to_vec(),
            added_at: 1001,
            ua: Some("Mozilla/5.0 (X11; Linux x86_64)".into()),
        });
        let b = a.encode();
        assert_eq!(b[0], ACCOUNT_V, "the version byte leads the body");
        let a2 = Account::decode(&b).unwrap();
        assert_eq!(a, a2);
        // tail is rejected
        let mut b2 = b;
        b2.push(0);
        assert!(Account::decode(&b2).is_err());
    }

    #[test]
    fn account_public_must_match_secret() {
        // A row whose public half disagrees with the secret is corrupt
        // (or tampered): decode must refuse it before it can load.
        let mut b = Account::from_seed(&[7u8; 32]).encode();
        let other = SecretKey::from_bytes(&[8u8; 32]).public();
        b[33..65].copy_from_slice(other.bytes()); // public starts at offset 33
        assert!(
            Account::decode(&b).is_err(),
            "mismatched public/secret is refused"
        );
    }

    #[test]
    fn legacy_account_versions_are_not_migrated() {
        // Pre-release: every row is V1; a different version is an
        // explicit error, not a migration (wipe the dev DB instead).
        let mut b = Account::from_seed(&[5u8; 32]).encode();
        b[0] = 0;
        assert!(Account::decode(&b).is_err(), "non-V1 rows are refused");
    }

    #[test]
    fn seed_determinism() {
        let a = Account::from_seed(&[3u8; 32]);
        let b = Account::from_seed(&[3u8; 32]);
        assert_eq!(a.public, b.public);
        let c = Account::from_seed(&[4u8; 32]);
        assert_ne!(a.public, c.public);
    }

    #[test]
    fn session_row_roundtrip_and_corruption() {
        let s = SessionRow {
            account_key: SecretKey::from_bytes(&[1u8; 32]),
            session_pk: SessionPk::from_bytes(&[2u8; 64]),
            exp: 1_700_000_000,
        };
        assert_eq!(SessionRow::decode(&s.encode()).unwrap(), s);
        // trailing junk / truncation / empty — corrupt, not a version error
        let mut b = s.encode();
        b.push(0);
        assert_eq!(SessionRow::decode(&b).unwrap_err(), "record: corrupt");
        assert_eq!(SessionRow::decode(&b[..10]).unwrap_err(), "record: corrupt");
        assert_eq!(SessionRow::decode(&[]).unwrap_err(), "record: corrupt");
    }
}

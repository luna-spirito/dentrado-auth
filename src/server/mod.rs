//! Edge: fs/net/clock/random (via [`crate::crypto`], the store and
//! the vault); layer 6 of the lib.rs tower. The decisions are pure
//! functions of the request + state.
//!
//! Identity service (IS): WebAuthn-only login, session certificates
//! on client-generated keys, device enrollment codes, attestations
//! for third-party instances. No profile data is stored — one optional
//! field (bio homeserver); an account = key + creds (sessions live in
//! their own table).
//!
//! Invariants:
//! - the DB never stores names or profile data in the clear — only
//!   HMAC keys of strings and sealed values (vault);
//! - pending states (webauthn challenges, PoP, enroll codes) are
//!   RAM-only with TTL;
//! - the pepper lives elsewhere (0400/0600, outside the state dir);
//! - the signer key lives ONLY in the boot bundle — `Is::open` takes
//!   the bundle at EVERY start (a permanent server secret);
//!   state.redb is auto-created, accounts/sessions survive a
//!   re-issue (the pepper is orthogonal to the keys). No init, no
//!   rotate.
//!
//! Session model: the browser generates a P-256 keypair, proves it to
//! the server (PoP) together with a WebAuthn assertion, and receives
//! a double-signed `Cert`. The session lands in the sessions table
//! (sealed row + coarse public EOL); every authenticated request
//! carries x-jti/x-ts/x-sig (proof-of-possession) — no cookies, no
//! CSRF.
//!
//! Layout: this file — the IS core (config, keys, lifecycle `open`,
//! cert minting). The flows live in submodules: `login`
//! (login/logout/PoP/authorize), `passkey` (webauthn ceremonies),
//! `connect` (enrollment codes), `route` (API), `www` (frontend).
//! Persistence goes through `crate::storage` — the schema (row
//! names, formats, versions) lives there, not here.

use crate::crypto::{self, SecretKey};
use crate::keys::header::Header;
use crate::keys::signer;
use crate::storage::records::{Account, SessionRow};
use crate::storage::{Storage, Vault};
use crate::wire::{Cert, SessionPk};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

pub mod connect;
pub mod login;
pub mod passkey;
pub mod route;
pub mod webauthn;
pub mod www;

use connect::{ConnectPending, EnrollPending, StepPending};
use login::DropPending;
use passkey::PendingWa;

// ---------------------------------------------------------------- config

pub struct IsConfig {
    pub host: String,        // override; default — host part of the bundle origin (rpId)
    pub web_origin: String,  // override; default — the bundle origin (webauthn origin)
    pub cert_ttl: u64,       // cert lifetime, sec (7 days)
    pub att_ttl: u64,        // attestation lifetime, sec
    pub pending_ttl: u64,    // TTL of RAM ceremonies, sec
    pub request_window: u64, // freshness window for x-ts in PoP requests
    pub bio_default: Option<String>, // copied into new accounts (from --bio-homeserver)
}

impl Default for IsConfig {
    fn default() -> Self {
        IsConfig {
            host: "localhost".into(),
            web_origin: String::new(),
            cert_ttl: 7 * 86400,
            att_ttl: 300,
            pending_ttl: 300,
            request_window: 300,
            bio_default: None,
        }
    }
}

/// Host part of an HTTP(S) origin (scheme and port stripped; IPv6
/// literals handled). This is the rpId — ports are never part of it.
fn host_of_origin(origin: &str) -> String {
    let rest = origin
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    match rest.strip_prefix('[') {
        // [v6-literal]:port — everything up to `]`
        Some(inner) => inner
            .split_once(']')
            .map(|(h, _)| h.to_string())
            .unwrap_or_else(|| rest.to_string()),
        None => rest.split(':').next().unwrap_or(rest).to_string(),
    }
}

pub struct Keys {
    /// The signer key (seed from the boot bundle) — ONE, forever.
    pub signing: SecretKey,
    /// The root-signed header: travels inside every minted document.
    pub header: Header,
}

impl Keys {
    /// Signer key id.
    pub fn key_id(&self) -> [u8; 8] {
        self.header.key_id()
    }
    /// IS identity: pubkey(root), the instances' trust line.
    pub fn is_id(&self) -> &crate::crypto::PublicKey {
        self.header.is_id()
    }
}

// ---------------------------------------------------------------- pending

// (see submodules: LoginPending, PendingWa, ConnectPending, StepPending)

// ---------------------------------------------------------------- IS

pub struct Is {
    pub cfg: IsConfig,
    pub keys: Keys,
    pub(crate) storage: Storage,
    wa_pending: Mutex<HashMap<String, PendingWa>>,
    connect_pending: Mutex<HashMap<[u8; 32], ConnectPending>>,
    enroll_pending: Mutex<HashMap<String, EnrollPending>>,
    step_pending: Mutex<HashMap<String, StepPending>>,
    drop_pending: Mutex<HashMap<String, DropPending>>,
}

impl Is {
    /// Open the IS: the bundle (`signer new`) is the secret entry of
    /// EVERY start (mode 0400/0600; the signer seed lives only in it);
    /// `state.redb` in the directory is created automatically. A re-issue
    /// = a fresh bundle + restart: accounts and sessions survive it
    /// (the pepper is independent of the keys); the instances' trust
    /// lines do not change.
    pub fn open(dir: &Path, bundle: &Path, cfg: IsConfig, vault: Vault) -> Result<Arc<Is>, String> {
        // the bundle is the server's permanent secret: the mode must
        // already be 0400/0600 (a "0644 before chmod" window is not tolerated here either);
        // reading (fs) happens here; parsing/checks are pure, in keys::signer
        if !crypto::is_private_mode(bundle) {
            return Err(format!(
                "{} must have mode 0400/0600 — create it under umask 077 (README \"Quick start\")",
                bundle.display()
            ));
        }
        let bytes = std::fs::read(bundle).map_err(|e| format!("{}: {e}", bundle.display()))?;
        let (signing, header) =
            signer::decode_bundle(&bytes).map_err(|e| format!("{}: {e}", bundle.display()))?;
        std::fs::create_dir_all(dir).map_err(|e| format!("mkdir: {e}"))?;
        let storage = Storage::open(dir, vault)?; // schema 1 (dev), auto-created + swept
        let host = if cfg.host.is_empty() {
            host_of_origin(&header.origin)
        } else {
            cfg.host.clone()
        };
        let web_origin = if cfg.web_origin.is_empty() {
            header.origin.clone()
        } else {
            cfg.web_origin.clone()
        };
        Ok(Arc::new(Is {
            keys: Keys { signing, header },
            cfg: IsConfig {
                host,
                web_origin,
                ..cfg
            },
            storage,
            wa_pending: Mutex::new(HashMap::new()),
            connect_pending: Mutex::new(HashMap::new()),
            enroll_pending: Mutex::new(HashMap::new()),
            step_pending: Mutex::new(HashMap::new()),
            drop_pending: Mutex::new(HashMap::new()),
        }))
    }

    pub(crate) fn now(&self) -> u64 {
        crypto::now()
    }

    pub(crate) fn web_origin(&self) -> &str {
        &self.cfg.web_origin
    }

    // ------------------------------------------------------------ public documents

    pub fn keys_doc(&self) -> String {
        format!(
            "{}\n# origin={} signer_key={}\n",
            crypto::hex(self.keys.is_id().bytes()),
            self.keys.header.origin,
            crypto::hex(&self.keys.key_id())
        )
    }

    // ------------------------------------------------------------ account IO

    /// Load an account by its key (row formats live in `storage`).
    pub(crate) fn load_account(&self, account_key: &SecretKey) -> Result<Account, String> {
        self.storage
            .account(account_key)?
            .ok_or_else(|| "account not found".to_string())
    }

    // ------------------------------------------------------------ cert minting

    /// Mint a cert: the root header from the bundle + the cert part
    /// double-signed — by the signer AND the account key (stealing the
    /// bundle does not allow minting other accounts' certs: the account key is under the pepper).
    pub(crate) fn mint_cert(&self, account: &Account, session_pk: &SessionPk, now: u64) -> Cert {
        let mut cert = Cert {
            header: self.keys.header.clone(),
            session_pk: *session_pk,
            account_pk: account.public,
            iat: now,
            exp: now + self.cfg.cert_ttl,
            jti: crate::wire::Jti::generate(),
            authorizer_sig: crypto::Signature::from_bytes(&[0; 64]),
            account_sig: crypto::Signature::from_bytes(&[0; 64]),
        };
        let unsigned = cert.unsigned_cert();
        cert.authorizer_sig = crypto::sign(&self.keys.signing, &unsigned);
        cert.account_sig = crypto::sign(&account.secret, &unsigned);
        cert
    }

    /// Persist a fresh session: ONE row in the sessions table (sealed
    /// body + coarse public EOL). The account row is not touched —
    /// logins no longer race on it.
    pub(crate) fn register_session(
        &self,
        account_key: &SecretKey,
        cert: &Cert,
    ) -> Result<(), String> {
        self.storage.commit(vec![self.storage.put_session(
            &cert.jti,
            &SessionRow {
                account_key: *account_key,
                session_pk: cert.session_pk,
                exp: cert.exp,
            },
        )])
    }
}

// ---------------------------------------------------------------- misc

/// Walk down nested JSON keys.
pub(crate) fn jget<'a>(
    j: &'a crate::codec::json::Json,
    path: &[&str],
) -> Option<&'a crate::codec::json::Json> {
    let mut cur = j;
    for k in path {
        cur = cur.get(k)?;
    }
    Some(cur)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_of_origin_strips_scheme_and_port() {
        assert_eq!(
            host_of_origin("https://auth.example.org"),
            "auth.example.org"
        );
        assert_eq!(
            host_of_origin("https://auth.example.org:8443"),
            "auth.example.org",
            "the port is never part of the rpId"
        );
        assert_eq!(host_of_origin("http://localhost:8080"), "localhost");
        assert_eq!(host_of_origin("https://[::1]:7443"), "::1", "IPv6 literal");
        assert_eq!(host_of_origin("https://[2001:db8::1]"), "2001:db8::1");
    }
}

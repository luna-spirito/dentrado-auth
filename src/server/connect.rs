//! Connect: how a NEW device joins an EXISTING account.
//!
//! A live session shows a one-time 12-word code (128 bits entropy +
//! checksum, TTL = pending_ttl, single-use); the new device redeems the
//! code and receives a session of its own. The code is an admission
//! ticket, NEVER key material: it grants a session, not a passkey — the
//! new device can add its own passkey later from the dashboard.
//!
//! v7: an account always has webauthn (the only login method), so
//! issuing a code ALWAYS requires a step-up — a fresh assertion by one
//! of the account's creds (UV required). A stolen session by itself
//! hands the attacker no key.
//!
//! Burn: the code is consumed by a SUCCESSFUL enrollment finish, not
//! by its begin (a flappy browser does not eat the code).

use super::*;
use crate::crypto::{SecretKey, random_arr};
use crate::keys::mnemonic;
use crate::server::webauthn;

/// A connect code awaiting redemption: key = sha256(entropy16), value
/// — the owning account and the expiry.
pub(super) struct ConnectPending {
    pub account_key: SecretKey,
    pub expires: u64,
}

/// A redeemed connect code awaiting the new device's PoP: the code is
/// only an admission ticket, so no authenticator ceremony is needed.
pub(super) struct EnrollPending {
    pub account_key: SecretKey,
    pub burn: [u8; 32],
    pub expires: u64,
}

/// A step-up challenge (b64u) → the account proving itself by webauthn
/// (no session issued — only the right to perform the action).
pub(super) struct StepPending {
    pub account_key: SecretKey,
    pub expires: u64,
}

impl Is {
    /// Issue a one-time code for an account. RAM-only, keyed by
    /// sha256(entropy16); the words are shown once, never stored.
    fn connect_issue(&self, account_key: &SecretKey) -> Result<(String, u64), String> {
        let ent = random_arr::<16>();
        let id = crypto::sha256(&ent);
        let now = self.now();
        let expires = now + self.cfg.pending_ttl;
        let mut m = self
            .connect_pending
            .lock()
            .map_err(|_| "connect pending poisoned")?;
        m.retain(|_, v| v.expires > now);
        m.insert(
            id,
            ConnectPending {
                account_key: *account_key,
                expires,
            },
        );
        Ok((mnemonic::encode128(&ent), expires))
    }

    /// `POST /connect/start` (a PoP session): a step-up challenge, scoped to
    /// the account's own credentials (the authenticator picker won't
    /// offer another account's key). Returns (challenge, options).
    pub(crate) fn connect_start(
        &self,
        account_key: &SecretKey,
    ) -> Result<(String, String), String> {
        let account = self.load_account(account_key)?;
        let now = self.now();
        let challenge = crypto::b64u_encode(&random_arr::<32>());
        let allow: Vec<String> = account.creds.iter().map(|c| c.id.clone()).collect();
        let options = webauthn::begin_login_json(&challenge, &self.cfg.host, &allow);
        let mut m = self
            .step_pending
            .lock()
            .map_err(|_| "step pending poisoned")?;
        m.retain(|_, v| v.expires > now);
        m.insert(
            challenge.clone(),
            StepPending {
                account_key: *account_key,
                expires: now + self.cfg.pending_ttl,
            },
        );
        Ok((challenge, options))
    }

    /// Step-up finish: verify the assertion against one of the
    /// account's credentials → issue the code. No session is created.
    /// `sk_expected` — the account of the PoP session finishing this: the
    /// challenge must be its own (another session never yields someone else's code).
    pub(crate) fn connect_step_finish(
        &self,
        sk_expected: &SecretKey,
        challenge: &str,
        body: &crate::codec::json::Json,
    ) -> Result<(String, u64), String> {
        let now = self.now();
        let sk = {
            let mut m = self
                .step_pending
                .lock()
                .map_err(|_| "step pending poisoned")?;
            match m.remove(challenge) {
                Some(v) if v.expires > now => v.account_key,
                _ => return Err("unknown or expired challenge".into()),
            }
        };
        if &sk != sk_expected {
            return Err("challenge belongs to another account".into());
        }
        let account = self.load_account(&sk)?;
        self.wa_step_check(challenge, body, &account)?;
        self.connect_issue(&sk)
    }

    /// Validate a code WITHOUT burning it (the burn happens when the
    /// enrollment ceremony completes). Returns the owning account key
    /// and the burn id.
    pub(super) fn connect_resolve(&self, words: &str) -> Result<(SecretKey, [u8; 32]), String> {
        let ent: [u8; 16] = mnemonic::decode128(words)?;
        let id = crypto::sha256(&ent);
        let now = self.now();
        let sk = {
            let m = self
                .connect_pending
                .lock()
                .map_err(|_| "connect pending poisoned")?;
            match m.get(&id) {
                Some(v) if v.expires > now => v.account_key,
                _ => return Err("unknown or expired connect code".into()),
            }
        };
        Ok((sk, id))
    }

    /// Atomically claim a code at finish. The caller restores it if the
    /// finish fails, so a flaky ceremony does not eat the code while a
    /// second begin cannot race past a successful burn.
    fn connect_claim(&self, id: &[u8; 32]) -> Result<ConnectPending, String> {
        let now = self.now();
        let mut m = self
            .connect_pending
            .lock()
            .map_err(|_| "connect pending poisoned")?;
        match m.get(id) {
            Some(v) if v.expires > now => Ok(m.remove(id).expect("checked present")),
            _ => Err("unknown or expired connect code".into()),
        }
    }

    fn connect_restore(&self, id: [u8; 32], pending: ConnectPending) {
        if let Ok(mut m) = self.connect_pending.lock() {
            m.insert(id, pending);
        }
    }

    /// Redemption, part 1: words → a challenge bound to the code's
    /// account. No authenticator options: the code itself (issued after
    /// a step-up) is the admission ticket. The device proves possession
    /// of its fresh session key at finish and gets a cert.
    pub(crate) fn connect_enroll_begin(&self, words: &str) -> Result<String, String> {
        let (account_key, burn) = self.connect_resolve(words)?;
        let now = self.now();
        let challenge = crypto::b64u_encode(&random_arr::<32>());
        let mut m = self
            .enroll_pending
            .lock()
            .map_err(|_| "enroll pending poisoned")?;
        m.retain(|_, v| v.expires > now);
        m.insert(
            challenge.clone(),
            EnrollPending {
                account_key,
                burn,
                expires: now + self.cfg.pending_ttl,
            },
        );
        Ok(challenge)
    }

    /// Redemption, part 2: the new device's PoP → session for the code's
    /// account. The code is claimed before the cert is issued and
    /// restored on failure. The account's credential list is untouched.
    pub(crate) fn connect_enroll_finish(
        &self,
        body: &crate::codec::json::Json,
    ) -> Result<(Cert, Account, SecretKey), String> {
        let fb = self.parse_finish("enroll-pop", body)?;
        let now = self.now();
        let pending = {
            let mut m = self
                .enroll_pending
                .lock()
                .map_err(|_| "enroll pending poisoned")?;
            match m.remove(&fb.challenge) {
                Some(v) if v.expires > now => v,
                _ => return Err("unknown or expired challenge".into()),
            }
        };
        let claimed = self.connect_claim(&pending.burn)?;
        let sk = pending.account_key;
        let issued = self.load_account(&sk).and_then(|account| {
            let cert = self.issue_cert(&sk, &account, &fb.session_pk)?;
            Ok((account, cert))
        });
        match issued {
            Ok((account, cert)) => Ok((cert, account, sk)),
            Err(e) => {
                self.connect_restore(pending.burn, claimed);
                Err(e)
            }
        }
    }
}

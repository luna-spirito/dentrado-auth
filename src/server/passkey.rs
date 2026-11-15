//! WebAuthn/passkey ceremonies: registration and assertion checks.
//!
//! The only v7 login method. Pending state is RAM with a TTL
//! (`wa_pending`); the session key is NOT stored in the pending: it
//! arrives in the finish body and is bound to the challenge by a PoP
//! signature (`msg_pop(kind, challenge, session_pk)`), so the key cannot
//! be swapped after begin — and there is nothing stored to steal.

use super::*;
use crate::codec::json::Json;
use crate::crypto::{SecretKey, random_arr};
use crate::server::webauthn;

/// WebAuthn ceremony: challenge (b64u) → context. account_key = None
/// registers a new account at finish, Some adds a credential to an
/// existing one. `new_account` is pre-generated at begin so the
/// credential-manager label and user handle stay stable when the
/// account later gains more passkeys.
pub(super) struct PendingWa {
    pub account_key: Option<SecretKey>,
    pub new_account: Option<Account>,
    pub expires: u64,
}

/// A parsed authenticator response.
pub(super) struct WaParsed {
    pub json: Json,
    pub cd_bytes: Vec<u8>,
    pub ad: Vec<u8>,
}

/// Registration verified and ready to be applied to an account.
pub(super) struct WaRegister {
    pub pending: PendingWa,
    pub cred_id: String,
    pub cose: Vec<u8>,
}

impl Is {
    pub(super) fn wa_prune(m: &mut HashMap<String, PendingWa>, now: u64) {
        m.retain(|_, v| v.expires > now);
    }

    /// Registration start. `exclude` — already-linked creds (for
    /// add-cred into an existing account). Returns (challenge, options).
    ///
    /// A brand-new account is generated here (not at finish) so the
    /// discoverable credential is born with its final `user.id` and a
    /// readable `user.name`; otherwise every credential of the same
    /// account would appear as a different user in the picker.
    pub(super) fn wa_register_begin(
        &self,
        account_key: Option<&SecretKey>,
        exclude: &[String],
        name: Option<&str>,
    ) -> Result<(String, String), String> {
        let now = self.now();
        let challenge = crypto::b64u_encode(&random_arr::<32>());
        let (user_id, display_name, new_account) = match account_key {
            Some(sk) => (
                crypto::b64u_encode(&crypto::sha256(sk.bytes())),
                name.unwrap_or("Dentrado profile").to_string(),
                None,
            ),
            None => {
                let mut account = Account::generate();
                account.name = name.map(str::to_string);
                // The homeserver default applies at account creation; after
                // that the stored value is the whole truth (empty = unset).
                account.bio_homeserver = self.cfg.bio_default.clone();
                (
                    crypto::b64u_encode(&crypto::sha256(account.secret.bytes())),
                    account.display_name(),
                    Some(account),
                )
            }
        };
        let options = webauthn::begin_register_json(
            &challenge,
            &user_id,
            &display_name,
            &self.cfg.host,
            exclude,
        );
        let mut m = self.wa_pending.lock().map_err(|_| "wa poisoned")?;
        Self::wa_prune(&mut m, now);
        m.insert(
            challenge.clone(),
            PendingWa {
                account_key: account_key.copied(),
                new_account,
                expires: now + self.cfg.pending_ttl,
            },
        );
        Ok((challenge, options))
    }

    /// Registration finish (verify only): take the pending, verify the
    /// attestation response, return the new credential. Applying it to
    /// the account (new or existing) — in the calling flows.
    pub(super) fn wa_register_finish(
        &self,
        challenge: &str,
        body: &Json,
    ) -> Result<WaRegister, String> {
        let pending = self.take_wa_pending(challenge)?;
        let parsed = self.wa_parse(body, "webauthn.create", challenge)?;
        webauthn::check_auth_data(&parsed.ad, &self.cfg.host)?;
        let att = webauthn::parse_attested(&parsed.ad)?;
        webauthn::CredKey::parse_cose(&att.cose)?; // the key must be valid
        Ok(WaRegister {
            pending,
            cred_id: crypto::b64u_encode(&att.cred_id),
            cose: att.cose,
        })
    }

    /// Login start: resident credentials, empty allowList.
    pub(super) fn wa_login_begin(&self) -> Result<(String, String), String> {
        let now = self.now();
        let challenge = crypto::b64u_encode(&random_arr::<32>());
        let options = webauthn::begin_login_json(&challenge, &self.cfg.host, &[]);
        let mut m = self.wa_pending.lock().map_err(|_| "wa poisoned")?;
        Self::wa_prune(&mut m, now);
        m.insert(
            challenge.clone(),
            PendingWa {
                account_key: None,
                new_account: None,
                expires: now + self.cfg.pending_ttl,
            },
        );
        Ok((challenge, options))
    }

    /// Assertion verified against THIS account's credential. UV
    /// is always required (v7: platform authenticators and the
    /// synthetic authenticator always provide it). Returns the id of the
    /// credential that made the assertion.
    pub(super) fn wa_check_assertion(
        &self,
        parsed: &WaParsed,
        account: &Account,
    ) -> Result<String, String> {
        let cred_id = wa_cred_id(parsed)?;
        if !webauthn::user_verified(&parsed.ad) {
            return Err("user verification required".into());
        }
        let sig = crypto::b64u_decode(
            jget(&parsed.json, &["response", "signature"])
                .and_then(Json::as_str)
                .ok_or("assertion: signature")?,
        )
        .ok_or("assertion: bad signature encoding")?;
        let cred = account
            .creds
            .iter()
            .find(|c| c.id == cred_id)
            .ok_or("credential not linked to this account")?;
        let key = webauthn::CredKey::parse_cose(&cred.pk)?;
        let mut msg = parsed.ad.clone();
        msg.extend_from_slice(&crypto::sha256(&parsed.cd_bytes)); // ad ‖ H(clientDataJSON)
        if !key.verify(&msg, &sig) {
            return Err("bad assertion signature".into());
        }
        Ok(cred_id)
    }

    /// Step-up (connect issuance, credential unlink): a fresh assertion
    /// by one of THIS account's OWN creds, UV required. No session is
    /// issued — it is only the right to perform the action. Returns the
    /// asserting credential id so callers can enforce ordering rules.
    pub(super) fn wa_step_check(
        &self,
        challenge: &str,
        body: &Json,
        account: &Account,
    ) -> Result<String, String> {
        let parsed = self.wa_parse(body, "webauthn.get", challenge)?;
        webauthn::check_auth_data(&parsed.ad, &self.cfg.host)?;
        self.wa_check_assertion(&parsed, account)
    }

    pub(super) fn take_wa_pending(&self, challenge: &str) -> Result<PendingWa, String> {
        let mut m = self.wa_pending.lock().map_err(|_| "wa poisoned")?;
        match m.remove(challenge) {
            Some(v) if v.expires > self.now() => Ok(v),
            _ => Err("unknown or expired challenge".into()),
        }
    }

    /// Parse an authenticator response: check type/challenge/origin.
    pub(super) fn wa_parse(
        &self,
        body: &Json,
        want_type: &str,
        challenge: &str,
    ) -> Result<WaParsed, String> {
        let json = body;
        let cd_bytes = crypto::b64u_decode(
            jget(json, &["response", "clientDataJSON"])
                .and_then(Json::as_str)
                .ok_or("missing clientDataJSON")?,
        )
        .ok_or("bad clientDataJSON encoding")?;
        let cd = webauthn::parse_client_data(&cd_bytes)?;
        if cd.type_ != want_type {
            return Err(format!("clientData: wrong type {}", cd.type_));
        }
        if cd.challenge != challenge {
            return Err("clientData: challenge mismatch".into());
        }
        if cd.origin != self.web_origin() {
            return Err("clientData: origin mismatch".into());
        }
        // W3C: a cross-origin ceremony (an iframe on another origin
        // relaying the challenge) must be refused even when the
        // embedded origin string matches — a top-level ceremony only.
        if cd.cross_origin == Some(true) {
            return Err("clientData: crossOrigin ceremony refused".into());
        }
        let ad = if want_type == "webauthn.create" {
            let ao = crypto::b64u_decode(
                jget(json, &["response", "attestationObject"])
                    .and_then(Json::as_str)
                    .ok_or("missing attestationObject")?,
            )
            .ok_or("bad attestationObject encoding")?;
            let c = crate::codec::cbor::decode(&ao).map_err(|e| format!("attestation: {e}"))?;
            c.map_get_text("authData")
                .and_then(crate::codec::cbor::Cbor::as_bytes)
                .map(<[u8]>::to_vec)
                .ok_or("attestation: no authData")?
        } else {
            crypto::b64u_decode(
                jget(json, &["response", "authenticatorData"])
                    .and_then(Json::as_str)
                    .ok_or("missing authenticatorData")?,
            )
            .ok_or("bad authenticatorData encoding")?
        };
        Ok(WaParsed {
            json: body.clone(),
            cd_bytes,
            ad,
        })
    }
}

pub(super) fn wa_cred_id(parsed: &WaParsed) -> Result<String, String> {
    parsed
        .json
        .get("rawId")
        .and_then(Json::as_str)
        .ok_or("assertion: rawId".into())
        .map(str::to_string)
}

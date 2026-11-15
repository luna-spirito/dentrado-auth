//! Login/logout, cert issuance flows and the PoP middleware.
//!
//! The v7 scheme: the browser generates a session keypair (P-256,
//! non-extractable), passes WebAuthn, and proves possession of the
//! session key with a PoP signature in the finish request
//! (`msg_pop(kind, challenge, session_pk)`) — the server mints a
//! double-signed [`Cert`] and persists the session in the sessions
//! table (sealed row + coarse EOL). Every authenticated request then
//! carries the `x-jti`/`x-ts`/`x-sig` headers — the session key's
//! signature over (method, path, ts, body). No cookies → no CSRF.

use super::*;
use crate::codec::json::Json;
use crate::crypto::{SecretKey, Signature, random_arr};
use crate::storage::Cred;
use crate::wire::{self, Attestation, Cert, Jti, SessionPk};

/// Parsed finish body: {challenge, session_pk, pop} with the PoP verified.
pub(super) struct FinishBody {
    pub challenge: String,
    pub session_pk: SessionPk,
}

/// An authenticated request: the session row resolved + the account.
pub struct Authed {
    pub account_key: SecretKey,
    pub session_pk: SessionPk,
    pub jti: Jti,
    pub account: Account,
}

/// A pending credential unlink: the account, the target cred, and the
/// expiry. The step-up challenge itself is the map key.
pub(super) struct DropPending {
    pub account_key: SecretKey,
    pub target: String,
    pub expires: u64,
}

impl Is {
    // ------------------------------------------------------------ PoP middleware

    /// Verify x-jti/x-ts/x-sig against the session row. `method` and
    /// `path` — how and where the request arrived (path without the
    /// query): both are inside the signed message, so a signature
    /// minted for one route or verb is worthless on another. The
    /// sealed session row is the single source of truth (the coarse
    /// EOL column is GC data only).
    pub(crate) fn authenticate(
        &self,
        method: &str,
        path: &str,
        jti_h: Option<&str>,
        ts_h: Option<&str>,
        sig_h: Option<&str>,
        body: &[u8],
    ) -> Result<Authed, String> {
        let jti_b = crypto::b64u_decode(jti_h.ok_or("auth: no x-jti")?).ok_or("auth: x-jti")?;
        let jti = Jti::from_bytes(jti_b.as_slice().try_into().map_err(|_| "auth: x-jti")?);
        let ts: u64 = ts_h
            .ok_or("auth: no x-ts")?
            .parse()
            .map_err(|_| "auth: x-ts")?;
        let sig = crypto::b64u_decode(sig_h.ok_or("auth: no x-sig")?).ok_or("auth: x-sig")?;
        let now = self.now();
        if ts.abs_diff(now) > self.cfg.request_window {
            return Err("auth: stale timestamp".into());
        }
        let row = self.storage.session(&jti)?.ok_or("auth: unknown session")?;
        if row.exp <= now {
            return Err("auth: session expired".into());
        }
        if !crypto::verify_p256(
            row.session_pk.bytes(),
            &wire::msg_request(method, path, ts, body),
            &sig,
        ) {
            return Err("auth: bad request signature".into());
        }
        let account = self.load_account(&row.account_key)?;
        Ok(Authed {
            account_key: row.account_key,
            session_pk: row.session_pk,
            jti,
            account,
        })
    }

    // ------------------------------------------------------------ issuance

    /// Mint a cert for a session key and persist the session (one
    /// row in the sessions table; the account row is untouched).
    pub(super) fn issue_cert(
        &self,
        account_key: &SecretKey,
        account: &Account,
        session_pk: &SessionPk,
    ) -> Result<Cert, String> {
        let cert = self.mint_cert(account, session_pk, self.now());
        self.register_session(account_key, &cert)?;
        Ok(cert)
    }

    /// PoP check of finish bodies: the session key signs
    /// (kind ‖ challenge ‖ session_pk) — possession proven, the key
    /// bound to the challenge.
    pub(super) fn check_pop(
        &self,
        kind: &str,
        challenge: &str,
        session_pk: &SessionPk,
        pop: &str,
    ) -> Result<(), String> {
        let sig = crypto::b64u_decode(pop).ok_or("pop: bad encoding")?;
        if sig.len() != 64 {
            return Err("pop: bad length".into());
        }
        if !crypto::verify_p256(
            session_pk.bytes(),
            &wire::msg_pop(kind, challenge, session_pk.bytes()),
            &sig,
        ) {
            return Err("pop: signature mismatch".into());
        }
        Ok(())
    }

    // ------------------------------------------------------------ register (new account)

    /// `POST /webauthn/register/begin`. `name` is the optional
    /// user-facing profile name stored in the account (and shown by
    /// credential managers).
    pub(crate) fn register_begin(&self, name: Option<&str>) -> Result<(String, String), String> {
        let name = validate_profile_name(name)?;
        self.wa_register_begin(None, &[], name.as_deref())
    }

    /// Parse {challenge, session_pk, pop} and verify the PoP.
    pub(super) fn parse_finish(&self, kind: &str, body: &Json) -> Result<FinishBody, String> {
        let challenge = jget(body, &["challenge"])
            .and_then(Json::as_str)
            .ok_or("missing challenge")?
            .to_string();
        let pk_b = crypto::b64u_decode(
            jget(body, &["session_pk"])
                .and_then(Json::as_str)
                .ok_or("missing session_pk")?,
        )
        .ok_or("bad session_pk encoding")?;
        let session_pk = SessionPk::from_bytes(
            pk_b.as_slice()
                .try_into()
                .map_err(|_| "session_pk: 64 bytes")?,
        );
        let pop = jget(body, &["pop"])
            .and_then(Json::as_str)
            .ok_or("missing pop")?;
        self.check_pop(kind, &challenge, &session_pk, pop)?;
        Ok(FinishBody {
            challenge,
            session_pk,
        })
    }

    /// `POST /webauthn/register/finish`: a new account is born here —
    /// atomic (insert-if-absent of the credential row), then a cert for
    /// the session key.
    pub(crate) fn register_finish(
        &self,
        body: &Json,
    ) -> Result<(Cert, Account, SecretKey), String> {
        let fb = self.parse_finish("register-pop", body)?;
        let reg = self.wa_register_finish(&fb.challenge, body)?;
        if self.storage.auth_ref(&reg.cred_id)?.is_some() {
            return Err("credential already linked".into());
        }
        let now = self.now();
        // the account key was born at begin (see `wa_register_begin`)
        let mut account = reg
            .pending
            .new_account
            .ok_or("not a new-account registration")?;
        let sk = account.secret;
        account.creds.push(Cred {
            id: reg.cred_id,
            pk: reg.cose,
            added_at: now,
            ua: parse_ua(body),
        });
        self.storage
            .commit(vec![
                self.storage.put_auth_ref(&account.creds[0].id, &sk),
                self.storage.put_account(&sk, &account),
            ])
            .map_err(|e| format!("register: {e}"))?;
        let cert = self.issue_cert(&sk, &account, &fb.session_pk)?;
        Ok((cert, account, sk))
    }

    // ------------------------------------------------------------ login

    /// `POST /webauthn/login/begin` — resident credentials.
    pub(crate) fn login_begin(&self) -> Result<(String, String), String> {
        self.wa_login_begin()
    }

    /// `POST /webauthn/login/finish`: assertion → cert for the session key.
    pub(crate) fn login_finish(&self, body: &Json) -> Result<(Cert, Account, SecretKey), String> {
        let fb = self.parse_finish("login-pop", body)?;
        self.take_wa_pending(&fb.challenge)?;
        let parsed = self.wa_parse(body, "webauthn.get", &fb.challenge)?;
        crate::server::webauthn::check_auth_data(&parsed.ad, &self.cfg.host)?;
        let cred_id = super::passkey::wa_cred_id(&parsed)?;
        let sk = self
            .storage
            .auth_ref(&cred_id)?
            .ok_or("unknown credential")?;
        let account = self.load_account(&sk)?;
        self.wa_check_assertion(&parsed, &account)?;
        let cert = self.issue_cert(&sk, &account, &fb.session_pk)?;
        Ok((cert, account, sk))
    }

    // ------------------------------------------------------------ cred management (PoP)

    /// `POST /cred/add/begin`: register ceremony scoped to the account.
    pub(crate) fn cred_add_begin(
        &self,
        secret_key: &SecretKey,
    ) -> Result<(String, String), String> {
        let account = self.load_account(secret_key)?;
        let exclude = account
            .creds
            .iter()
            .map(|c| c.id.clone())
            .collect::<Vec<_>>();
        let name = account.display_name();
        self.wa_register_begin(Some(secret_key), &exclude, Some(&name))
    }

    /// `POST /cred/add/finish` (PoP): adds a credential, no new session.
    pub(crate) fn cred_add_finish(
        &self,
        secret_key: &SecretKey,
        body: &Json,
    ) -> Result<Account, String> {
        let challenge = jget(body, &["challenge"])
            .and_then(Json::as_str)
            .ok_or("missing challenge")?;
        let reg = self.wa_register_finish(challenge, body)?;
        let cred_id = reg.cred_id;
        if reg.pending.account_key.as_ref() != Some(secret_key) {
            return Err("challenge belongs to another session".into());
        }
        if self.storage.auth_ref(&cred_id)?.is_some() {
            return Err("credential already linked".into());
        }
        let mut account = self.load_account(secret_key)?;
        account.creds.push(Cred {
            id: cred_id.clone(),
            pk: reg.cose,
            added_at: self.now(),
            ua: parse_ua(body),
        });
        self.storage
            .commit(vec![
                self.storage.put_auth_ref(&cred_id, secret_key),
                self.storage.put_account(secret_key, &account),
            ])
            .map_err(|e| format!("cred add: {e}"))?;
        Ok(account)
    }

    /// `POST /cred/drop/begin` (PoP). Unlink authority is ORDERED: a
    /// credential may only be unlinked by one that was added BEFORE it.
    /// The step-up allowList is therefore restricted to older creds.
    /// `creds[0]` (the account's first key) can never be unlinked.
    pub(crate) fn cred_drop_begin(
        &self,
        account_key: &SecretKey,
        cred_id: &str,
    ) -> Result<(String, String), String> {
        let account = self.load_account(account_key)?;
        let target = account
            .creds
            .iter()
            .position(|c| c.id == cred_id)
            .ok_or("unknown credential")?;
        if target == 0 {
            return Err("cannot unlink the first credential".into());
        }
        let allow: Vec<String> = account.creds[..target]
            .iter()
            .map(|c| c.id.clone())
            .collect();
        let now = self.now();
        let challenge = crypto::b64u_encode(&random_arr::<32>());
        let options = crate::server::webauthn::begin_login_json(&challenge, &self.cfg.host, &allow);
        let mut m = self
            .drop_pending
            .lock()
            .map_err(|_| "drop pending poisoned")?;
        m.retain(|_, v| v.expires > now);
        m.insert(
            challenge.clone(),
            DropPending {
                account_key: *account_key,
                target: cred_id.to_string(),
                expires: now + self.cfg.pending_ttl,
            },
        );
        Ok((challenge, options))
    }

    /// `POST /cred/drop/finish` (PoP): verify the step-up by an older
    /// credential, then unlink the target. The ordering invariant is
    /// re-checked against the CURRENT account (not the begin snapshot).
    pub(crate) fn cred_drop_finish(
        &self,
        account_key: &SecretKey,
        challenge: &str,
        body: &Json,
    ) -> Result<Account, String> {
        let pending = {
            let mut m = self
                .drop_pending
                .lock()
                .map_err(|_| "drop pending poisoned")?;
            match m.remove(challenge) {
                Some(v) if v.expires > self.now() => v,
                _ => return Err("unknown or expired challenge".into()),
            }
        };
        if &pending.account_key != account_key {
            return Err("challenge belongs to another account".into());
        }
        let mut account = self.load_account(account_key)?;
        let asserting = self.wa_step_check(challenge, body, &account)?;
        let target = account
            .creds
            .iter()
            .position(|c| c.id == pending.target)
            .ok_or("unknown credential")?;
        if target == 0 {
            return Err("cannot unlink the first credential".into());
        }
        let by = account
            .creds
            .iter()
            .position(|c| c.id == asserting)
            .ok_or("credential not linked to this account")?;
        if by >= target {
            return Err("step-up credential must be older than the target".into());
        }
        let removed = account.creds.remove(target);
        self.storage.commit(vec![
            self.storage.put_account(account_key, &account),
            self.storage.del_auth_ref(&removed.id),
        ])?;
        Ok(account)
    }

    // ------------------------------------------------------------ account (PoP)

    /// `POST /account` without bio_homeserver reads; with it — sets
    /// (an empty string or null clears it).
    pub(crate) fn account_set_bio(
        &self,
        authed: &Authed,
        bio: Option<String>,
    ) -> Result<Account, String> {
        let bio = bio.filter(|url| !url.is_empty());
        if let Some(url) = &bio {
            let ok =
                (url.starts_with("https://") || url.starts_with("http://")) && url.len() <= 256;
            if !ok {
                return Err("bio homeserver: http(s) URL expected".into());
            }
        }
        let mut account = self.load_account(&authed.account_key)?;
        account.bio_homeserver = bio;
        self.storage.commit(vec![
            self.storage.put_account(&authed.account_key, &account),
        ])?;
        Ok(account)
    }

    // ------------------------------------------------------------ logout (PoP)

    /// `POST /logout`: delete the session row (no new attestations and
    /// no signed requests anymore; the cert itself lives out its exp —
    /// CRL deferred, README §×). One op — the account row is not
    /// involved.
    pub(crate) fn logout(&self, authed: &Authed) -> Result<(), String> {
        self.storage
            .commit(vec![self.storage.del_session(&authed.jti)])?;
        Ok(())
    }

    // ------------------------------------------------------------ authorize (PoP)

    /// `POST /authorize {aud, nonce}`: an attestation binding the session
    /// key to the account FOR ONE instance. The frontend wraps it into an
    /// Oneshot: the nonce does not enter the attestation — the session key
    /// signs it, and the instance itself checks freshness (its own nonce).
    ///
    /// `aud` must be a BARE ORIGIN. An attestation is addressed to an
    /// origin, not to a document: a path/query/fragment (or userinfo)
    /// would let the caller decide which PAGE on that origin receives
    /// the token, which is exactly what an open redirect or a wiki page
    /// needs in order to forward it elsewhere.
    pub(crate) fn authorize(
        &self,
        authed: &Authed,
        aud: &str,
    ) -> Result<(Attestation, u64), String> {
        if !is_bare_origin(aud) {
            return Err(
                "aud: a bare http(s) origin (scheme://host[:port], no path/query/fragment, no userinfo) is expected"
                    .into(),
            );
        }
        let now = self.now();
        let mut att = Attestation {
            header: self.keys.header.clone(),
            session_pk: authed.session_pk,
            account_pk: authed.account.public,
            aud: aud.to_string(),
            iat: now,
            exp: now + self.cfg.att_ttl,
            authorizer_sig: Signature::from_bytes(&[0; 64]),
            account_sig: Signature::from_bytes(&[0; 64]),
        };
        let unsigned = att.unsigned();
        att.authorizer_sig = crypto::sign(&self.keys.signing, &unsigned);
        att.account_sig = crypto::sign(&authed.account.secret, &unsigned);
        Ok((att, now + self.cfg.att_ttl))
    }

    // ------------------------------------------------------------ JSON docs

    /// Account document for the frontend.
    pub(crate) fn account_doc(&self, account: &Account) -> String {
        let mut creds = String::new();
        for c in &account.creds {
            creds.push_str(&format!(
                "{{\"id\":{},\"added_at\":{},\"ua\":{}}},",
                crate::codec::json::quote(&c.id),
                c.added_at,
                match &c.ua {
                    Some(ua) => crate::codec::json::quote(ua),
                    None => "null".into(),
                }
            ));
        }
        creds.pop();
        let identity = format!(
            "@{}@{}",
            crypto::hex(account.public.bytes()),
            self.keys.header.origin
        );
        let jopt = |v: Option<&str>| -> String {
            match v {
                Some(s) => crate::codec::json::quote(s),
                None => "null".into(),
            }
        };
        let display_name = account.display_name();
        format!(
            concat!(
                "{{\"account_pk\":\"{}\",\"name\":{},\"identity\":{},",
                "\"bio_homeserver\":{},",
                "\"creds\":[{}]}}"
            ),
            crypto::hex(account.public.bytes()),
            jopt(Some(&display_name)),
            crate::codec::json::quote(&identity),
            jopt(account.bio_homeserver.as_deref()),
            creds
        )
    }
}

/// A client-supplied User Agent: a display hint, never authority. We
/// trim it, drop control characters, and cap it so a hostile client
/// cannot bloat account rows.
fn parse_ua(body: &Json) -> Option<String> {
    let raw = jget(body, &["ua"]).and_then(Json::as_str)?;
    let ua: String = raw.chars().filter(|c| !c.is_control()).take(200).collect();
    let ua = ua.trim();
    if ua.is_empty() {
        None
    } else {
        Some(ua.to_string())
    }
}

/// Trim and validate an optional profile name. Empty means "use the
/// stable fallback label"; control characters are never welcome.
fn validate_profile_name(name: Option<&str>) -> Result<Option<String>, String> {
    let Some(raw) = name else {
        return Ok(None);
    };
    let name = raw.trim();
    if name.is_empty() {
        return Ok(None);
    }
    if name.chars().count() > 64 {
        return Err("profile name: at most 64 characters".into());
    }
    if name.chars().any(char::is_control) {
        return Err("profile name: control characters are not allowed".into());
    }
    Ok(Some(name.to_string()))
}

/// `aud` is a bare ORIGIN — `scheme://host[:port]` and nothing else.
///
/// The check is deliberately stricter than the URL spec: the frontend
/// sends `url.origin`, which is already canonical, so a legitimate
/// caller never needs uppercase, a default port, a trailing slash, a
/// query, a fragment or userinfo. Everything the parser would have to
/// normalize is refused instead of guessed at.
fn is_bare_origin(s: &str) -> bool {
    if s.len() > 256 || s.is_empty() {
        return false;
    }
    let rest = match s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
    {
        Some(r) => r,
        None => return false,
    };
    if rest.is_empty() {
        return false;
    }
    // Only authority material may remain.
    if rest.bytes().any(|b| {
        b.is_ascii_whitespace()
            || b.is_ascii_control()
            || matches!(b, b'/' | b'?' | b'#' | b'@' | b'\\' | b'%')
    }) {
        return false;
    }

    // host[:port]; IPv6 literals need brackets, so an unbracketed host
    // may contain at most one colon.
    let (host, port) = if let Some(inner) = rest.strip_prefix('[') {
        let Some((h, tail)) = inner.split_once(']') else {
            return false;
        };
        let port = match tail {
            "" => None,
            _ => match tail.strip_prefix(':') {
                Some(p) => Some(p),
                None => return false,
            },
        };
        (h, port)
    } else {
        match rest.split_once(':') {
            Some((h, p)) if !p.contains(':') => (h, Some(p)),
            Some(_) => return false,
            None => (rest, None),
        }
    };
    if host.is_empty() || host.starts_with('.') || host.ends_with('.') {
        return false;
    }
    if let Some(p) = port {
        match p.parse::<u32>() {
            Ok(n) if (1..=65535).contains(&n) => {}
            _ => return false,
        }
    }
    // Hosts are letters, digits, dots and dashes (plus the colons of a
    // bracketed IPv6 literal, already stripped above). Underscores and
    // IDNs are out of scope: the RP sends its canonical origin.
    host.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'))
}

#[cfg(test)]
mod tests {
    use super::is_bare_origin;

    #[test]
    fn aud_is_a_bare_origin() {
        for ok in [
            "https://wiki.example",
            "http://localhost:8080",
            "https://wiki.example:8443",
            "https://[::1]:7443",
        ] {
            assert!(is_bare_origin(ok), "{ok} must be accepted");
        }
        for bad in [
            "",
            "wiki.example",
            "ftp://wiki.example",
            "https://",
            "https://wiki.example/",
            "https://wiki.example/wiki/Page",
            "https://wiki.example/?a=b",
            "https://wiki.example/#frag",
            "https://user@wiki.example",
            "https://wiki.example:0",
            "https://wiki.example:99999",
            "https://wiki.example:80:80",
            "https://wiki.example\\evil",
            "https://wiki%2eexample",
            "https://.wiki.example",
        ] {
            assert!(!is_bare_origin(bad), "{bad} must be refused");
        }
    }
}

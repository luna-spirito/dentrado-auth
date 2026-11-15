//! HTTP routing: the JSON API (v7) + the frontend statics (`www`).
//!
//! All API answers are JSON: success `{...}` (200), error
//! `{"error":"..."}` (400/401/404/405). PoP paths (x-jti/x-ts/x-sig) are
//! everything that mutates an account: no cookies → no CSRF; the body
//! is signed along with path+ts → no cross-endpoint replay.

use super::login::Authed;
use super::*;
use crate::codec::json::Json;
use crate::crypto::{self, SecretKey};
use crate::net::http::{Req, Resp};
use crate::wire::Cert;

pub fn route(is: &Is, req: &Req) -> Resp {
    let route_result = match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/keys") => return Resp::text(is.keys_doc()),
        ("POST", "/webauthn/register/begin") => json_req(req, |j| {
            let name = match j.get("name") {
                None | Some(Json::Null) => None,
                Some(Json::Str(s)) => Some(s.as_str()),
                Some(_) => return Err((400, "name: string expected".into())),
            };
            begin2(is.register_begin(name))
        }),
        ("POST", "/webauthn/register/finish") => {
            json_req(req, |j| cert2(is, is.register_finish(&j)))
        }
        ("POST", "/webauthn/login/begin") => json_req(req, |j| {
            let _ = j;
            begin2(is.login_begin())
        }),
        ("POST", "/webauthn/login/finish") => json_req(req, |j| cert2(is, is.login_finish(&j))),
        ("POST", "/connect/enroll/begin") => json_req(req, |j| {
            let words = j
                .get("words")
                .and_then(Json::as_str)
                .ok_or((400, "missing words".into()))?;
            let challenge = is.connect_enroll_begin(words).map_err(bad)?;
            Ok(format!(
                "{{\"challenge\":{}}}",
                crate::codec::json::quote(&challenge)
            ))
        }),
        ("POST", "/connect/enroll/finish") => {
            json_req(req, |j| cert2(is, is.connect_enroll_finish(&j)))
        }
        // ---- PoP paths ----
        ("POST", "/connect/start") => authed_req(is, req, |is, a, _j| {
            begin2(is.connect_start(&a.account_key)).map_err(|(_, m)| m)
        }),
        ("POST", "/connect/finish") => authed_req(is, req, |is, a, j| {
            let ch = j
                .get("challenge")
                .and_then(Json::as_str)
                .ok_or("missing challenge")?;
            let resp = j.get("response").cloned().ok_or("missing response")?;
            let (words, expires) = is.connect_step_finish(&a.account_key, ch, &resp)?;
            Ok(format!(
                "{{\"words\":{},\"expires\":{}}}",
                crate::codec::json::quote(&words),
                expires
            ))
        }),
        ("POST", "/cred/add/begin") => authed_req(is, req, |is, a, _j| {
            begin2(is.cred_add_begin(&a.account_key)).map_err(|(_, m)| m)
        }),
        ("POST", "/cred/add/finish") => authed_req(is, req, |is, a, j| {
            let account = is.cred_add_finish(&a.account_key, j)?;
            Ok(is.account_doc(&account))
        }),
        ("POST", "/cred/drop/begin") => authed_req(is, req, |is, a, j| {
            let id = j.get("id").and_then(Json::as_str).ok_or("missing id")?;
            begin2(is.cred_drop_begin(&a.account_key, id)).map_err(|(_, m)| m)
        }),
        ("POST", "/cred/drop/finish") => authed_req(is, req, |is, a, j| {
            let ch = j
                .get("challenge")
                .and_then(Json::as_str)
                .ok_or("missing challenge")?;
            let resp = j.get("response").cloned().ok_or("missing response")?;
            let account = is.cred_drop_finish(&a.account_key, ch, &resp)?;
            Ok(is.account_doc(&account))
        }),
        ("POST", "/authorize") => authed_req(is, req, |is, a, j| {
            let aud = j.get("aud").and_then(Json::as_str).ok_or("missing aud")?;
            // the nonce format is checked right away; the server does not store
            // the nonce itself — the session key signs it, the instance checks freshness
            let nonce_b = crypto::b64u_decode(
                j.get("nonce")
                    .and_then(Json::as_str)
                    .ok_or("missing nonce")?,
            )
            .ok_or("bad nonce encoding")?;
            if nonce_b.len() != 32 {
                return Err("nonce: 32 bytes expected".into());
            }
            let (att, exp) = is.authorize(a, aud)?;
            Ok(format!(
                "{{\"attestation\":\"{}\",\"expires\":{}}}",
                crypto::b64u_encode(&att.encode()),
                exp
            ))
        }),
        ("POST", "/account") => authed_req(is, req, |is, a, j| {
            let account = match j.get("bio_homeserver") {
                None => a.account.clone(), // read
                Some(Json::Null) => is.account_set_bio(a, None)?,
                Some(Json::Str(s)) => is.account_set_bio(a, Some(s.clone()))?,
                Some(_) => return Err("bio_homeserver: string or null".into()),
            };
            Ok(is.account_doc(&account))
        }),
        ("POST", "/logout") => authed_req(is, req, |is, a, _j| {
            is.logout(a)?;
            Ok("{\"ok\":true}".into())
        }),
        _ => return crate::server::www::route(is, req),
    };
    match route_result {
        Ok(resp) => resp,
        Err((status, msg)) => json_err(status, msg),
    }
}

// ---------------------------------------------------------------- helpers

type R = Result<Resp, (u16, String)>;
/// A JSON-body handler: a response string or (status, message).
type RJ = Result<String, (u16, String)>;

fn json_req(req: &Req, f: impl FnOnce(Json) -> RJ) -> R {
    match req.json() {
        Ok(j) => f(j).map(Resp::json),
        Err(e) => Err((400, format!("bad json: {e}"))),
    }
}

fn authed_req(
    is: &Is,
    req: &Req,
    f: impl FnOnce(&Is, &Authed, &Json) -> Result<String, String>,
) -> R {
    let j = match req.json() {
        Ok(j) => j,
        Err(e) => return Err((400, format!("bad json: {e}"))),
    };
    let authed = is
        .authenticate(
            req.method.as_str(),
            &req.path,
            req.header("x-jti"),
            req.header("x-ts"),
            req.header("x-sig"),
            &req.body,
        )
        .map_err(|e| (401u16, e))?;
    let body = f(is, &authed, &j).map_err(|e| (400u16, e))?;
    Ok(Resp::json(body))
}

/// {challenge, options} from (challenge, options_json).
fn begin2(r: Result<(String, String), String>) -> RJ {
    let (challenge, options) = r.map_err(bad)?;
    Ok(format!(
        "{{\"challenge\":{},\"options\":{}}}",
        crate::codec::json::quote(&challenge),
        options
    ))
}

/// {cert, account} from the finish flows; jti/exp go out for the PoP
/// headers and the expiry display on the dashboard.
fn cert2(is: &Is, r: Result<(Cert, Account, SecretKey), String>) -> RJ {
    let (cert, account, _sk) = r.map_err(bad)?;
    Ok(format!(
        "{{\"cert\":\"{}\",\"jti\":\"{}\",\"exp\":{},\"account\":{}}}",
        crypto::b64u_encode(&cert.encode()),
        crypto::b64u_encode(cert.jti.bytes()),
        cert.exp,
        is.account_doc(&account)
    ))
}

fn bad(e: String) -> (u16, String) {
    (400, e)
}

fn json_err(status: u16, msg: String) -> Resp {
    Resp::json(format!("{{\"error\":{}}}", crate::codec::json::quote(&msg))).with_status(status)
}

impl Resp {
    fn with_status(mut self, status: u16) -> Resp {
        self.status = status;
        self
    }
}

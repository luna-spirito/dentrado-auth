//! Pure. WebAuthn (FINAL_DESIGN): resident credentials as the primary login method.
//!
//! Only pure parse/verify functions live here; the ceremony state
//! (challenges) lives in RAM at the idp. Exactly two algorithms are
//! supported: ES256 (P-256, COSE -7) and Ed25519 (COSE -8).
//!
//! Authenticator response format:
//! - clientDataJSON — JSON {type, challenge, origin, crossOrigin};
//! - attestationObject — CBOR {fmt, attStmt, authData}; only authData
//!   is of interest (rpIdHash ‖ flags ‖ signCount ‖ attestedCredData);
//! - an assertion signs `authenticatorData ‖ SHA-256(clientDataJSON)`
//!   with the COSE key (ES256 signs with a pre-hash SHA-256, Ed25519
//!   as-is).

use crate::codec::cbor::{self, Cbor};
use crate::codec::json::{self, Json};
use crate::crypto;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};

pub const ALG_ES256: i128 = -7;
pub const ALG_ED25519: i128 = -8;

// ---------------------------------------------------------------- keys

/// A credential key from a COSE body (stored in the person as-is, parsed here).
pub enum CredKey {
    Es256(VerifyingKey),
    Ed25519([u8; 32]),
}

impl CredKey {
    /// COSE key: EC2(kty 2, crv P-256, x, y) or OKP(kty 1, crv Ed25519, x).
    pub fn parse_cose(b: &[u8]) -> Result<CredKey, String> {
        let k = cbor::decode(b)?;
        let kty = k.map_get(1).and_then(Cbor::as_int).ok_or("cose: kty")?;
        let alg = k.map_get(3).and_then(Cbor::as_int).ok_or("cose: alg")?;
        let crv = k.map_get(-1).and_then(Cbor::as_int).ok_or("cose: crv")?;
        let x = k.map_get(-2).and_then(Cbor::as_bytes).ok_or("cose: x")?;
        match (kty, alg, crv) {
            (2, ALG_ES256, 1) => {
                let y = k.map_get(-3).and_then(Cbor::as_bytes).ok_or("cose: y")?;
                if x.len() != 32 || y.len() != 32 {
                    return Err("cose: p-256 coords must be 32 bytes".into());
                }
                let mut sec1 = Vec::with_capacity(65);
                sec1.push(0x04);
                sec1.extend_from_slice(x);
                sec1.extend_from_slice(y);
                Ok(CredKey::Es256(
                    VerifyingKey::from_sec1_bytes(&sec1).map_err(|e| format!("cose: {e}"))?,
                ))
            }
            (1, ALG_ED25519, 6) => {
                let mut pk = [0u8; 32];
                if x.len() != 32 {
                    return Err("cose: ed25519 key must be 32 bytes".into());
                }
                pk.copy_from_slice(x);
                Ok(CredKey::Ed25519(pk))
            }
            _ => Err("cose: unsupported kty/alg/crv combination".into()),
        }
    }

    /// Signature over `authData ‖ SHA-256(clientDataJSON)`.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        match self {
            CredKey::Es256(vk) => {
                let digest = crypto::sha256(msg);
                let parsed = Signature::from_der(sig)
                    .or_else(|_| Signature::from_slice(sig))
                    .ok();
                parsed.is_some_and(|s| vk.verify_prehash(&digest, &s).is_ok())
            }
            CredKey::Ed25519(pk) => {
                let mut s = [0u8; 64];
                if sig.len() != 64 || pk.len() != 32 {
                    return false;
                }
                s.copy_from_slice(sig);
                crypto::verify(
                    &crypto::PublicKey::from_bytes(pk),
                    msg,
                    &crypto::Signature::from_bytes(&s),
                )
            }
        }
    }
}

// ---------------------------------------------------------------- clientData

pub struct ClientData {
    pub type_: String,
    pub challenge: String, // b64u, compared against the issued one
    pub origin: String,
    /// The W3C cross-origin flag (absent/absent-false = a top-level
    /// ceremony). `Some(true)` — the ceremony ran inside a cross-origin
    /// iframe; the caller must refuse it.
    pub cross_origin: Option<bool>,
}

pub fn parse_client_data(b: &[u8]) -> Result<ClientData, String> {
    let j = json::parse(b)?;
    let get = |k: &str| -> Result<String, String> {
        j.get(k)
            .and_then(Json::as_str)
            .map(str::to_string)
            .ok_or_else(|| format!("clientData: missing {k}"))
    };
    Ok(ClientData {
        type_: get("type")?,
        challenge: get("challenge")?,
        origin: get("origin")?,
        cross_origin: j.get("crossOrigin").and_then(Json::as_bool),
    })
}

// ---------------------------------------------------------------- authData

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_AT: u8 = 0x40;

/// Parsing of authData: rpIdHash(32) ‖ flags(1) ‖ signCount(4) [‖
/// aaguid(16) ‖ credIdLen(2) ‖ credId ‖ COSE key], [‖ extensions].
pub struct AttestedData {
    pub cred_id: Vec<u8>,
    pub cose: Vec<u8>,
}

/// Minimal authData checks: length, rpIdHash, user-present.
pub fn check_auth_data(b: &[u8], rp_id: &str) -> Result<(), String> {
    if b.len() < 37 {
        return Err("authData: too short".into());
    }
    if b[0..32] != crypto::sha256(rp_id.as_bytes())[..] {
        return Err("authData: rpIdHash mismatch".into());
    }
    if b[32] & FLAG_UP == 0 {
        return Err("authData: user not present".into());
    }
    Ok(())
}

/// Extract a new credential (the AT flag is mandatory).
pub fn parse_attested(b: &[u8]) -> Result<AttestedData, String> {
    if b.len() < 37 {
        return Err("authData: too short".into());
    }
    if b[32] & FLAG_AT == 0 {
        return Err("authData: no attested credential data".into());
    }
    let cred_len = u16::from_be_bytes([b[53], b[54]]) as usize;
    let cose_at = 55 + cred_len;
    if b.len() < cose_at {
        return Err("authData: credential id out of range".into());
    }
    // the COSE key is a CBOR element; find its end by poking the decoder at the offset
    let cose_end = cbor::element_len(&b[cose_at..])?;
    Ok(AttestedData {
        cred_id: b[37 + 16 + 2..cose_at].to_vec(),
        cose: b[cose_at..cose_at + cose_end].to_vec(),
    })
}

/// The UV flag (user-verified) — the "aliveness" of the login; required
/// always for simplicity — the synthetics and all platform
/// authenticators provide it.
pub fn user_verified(b: &[u8]) -> bool {
    b.len() > 32 && b[32] & FLAG_UV != 0
}

// ---------------------------------------------------------------- begin-JSON

/// PublicKeyCredentialCreationOptions (no ephemeral junk).
pub fn begin_register_json(
    challenge: &str,
    user_id_b64u: &str,
    name: &str,
    rp_id: &str,
    exclude: &[String],
) -> String {
    let mut excl = String::new();
    for id in exclude {
        excl.push_str(&format!(
            "{{\"type\":\"public-key\",\"id\":{}}},",
            crate::codec::json::quote(id)
        ));
    }
    excl.pop();
    format!(
        concat!(
            "{{\"challenge\":{ch},",
            "\"rp\":{{\"id\":{rp},\"name\":\"Dentrado\"}},",
            "\"user\":{{\"id\":{uid},\"name\":{name},\"displayName\":{name}}},",
            "\"pubKeyCredParams\":[{{\"type\":\"public-key\",\"alg\":-7}},{{\"type\":\"public-key\",\"alg\":-8}}],",
            "\"excludeCredentials\":[{excl}],",
            "\"authenticatorSelection\":{{\"residentKey\":\"required\",\"requireResidentKey\":true,\"userVerification\":\"required\"}},",
            "\"attestation\":\"none\",\"timeout\":60000}}"
        ),
        ch = crate::codec::json::quote(challenge),
        rp = crate::codec::json::quote(rp_id),
        uid = crate::codec::json::quote(user_id_b64u),
        name = crate::codec::json::quote(name),
        excl = excl,
    )
}

/// PublicKeyCredentialRequestOptions. `allow` empty = discoverable
/// (login); an account's cred list = a step-up with a restricted picker.
pub fn begin_login_json(challenge: &str, rp_id: &str, allow: &[String]) -> String {
    let mut list = String::new();
    for id in allow {
        list.push_str(&format!(
            "{{\"type\":\"public-key\",\"id\":{}}},",
            crate::codec::json::quote(id)
        ));
    }
    list.pop();
    format!(
        concat!(
            "{{\"challenge\":{ch},\"rpId\":{rp},",
            "\"allowCredentials\":[{list}],",
            "\"userVerification\":\"required\",\"timeout\":60000}}"
        ),
        ch = crate::codec::json::quote(challenge),
        rp = crate::codec::json::quote(rp_id),
        list = list,
    )
}

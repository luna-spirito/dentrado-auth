//! Pure (layer 3 of the lib.rs tower: builds on `crypto`, `codec`
//! and `keys::header`; nothing above `wire` is used). The canonical
//! binary documents of the v7 wire format — strictly instead of JWT:
//! no alg confusion, no JSON canonicalization pitfalls. The
//! primitives live in [`crate::codec::bin`], the root-signed signer
//! header in [`crate::keys::header`] (re-exported here: it embeds
//! into every document).
//!
//! V7 (minimal rewrite): Event/CRL/level are GONE (CRL and events are
//! deferred, see README). What remains is three self-contained documents:
//! - `Header` — the root-signed header of the signer key (as in V6);
//! - `Cert` (ex-Fullchain) — the session certificate: the session key
//!   (P-256, 64B x‖y, born client-side) ↔ account; the double
//!   signature (signer + account) is kept — stealing the bundle does
//!   not allow minting other accounts' certs without pepper+DB;
//! - `Attestation` — the server confirms the binding of a session key
//!   to an account FOR ONE audience (a Dentrado instance);
//! - `Oneshot` — assembled by the client: attestation + instance nonce +
//!   session-key signature. Client clocks take no part in the document:
//!   freshness comes only from the attestation and the nonce.

pub use crate::codec::bin::V;
use crate::codec::bin::{R, W, WResult};
use crate::crypto::{self, PublicKey, Signature, hex};
pub use crate::keys::header::Header;

// ---------------------------------------------------------------- ids

/// A session public key: a P-256 point, 64 bytes x‖y. The keypair is
/// generated CLIENT-SIDE (browser WebCrypto, non-extractable); the
/// server never holds the private half — it only verifies (see
/// [`crypto::verify_p256`], byte-based: crypto holds no P-256
/// secrets).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionPk([u8; 64]);

impl SessionPk {
    pub fn from_bytes(b: &[u8; 64]) -> SessionPk {
        SessionPk(*b)
    }

    pub fn bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

/// jti — an IS-internal session id (opaque 128 bits, one per issued
/// cert; the storage row name of the session derives from it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Jti([u8; 16]);

impl Jti {
    /// A fresh id from the crate CSPRNG (minted with the cert).
    pub fn generate() -> Jti {
        Jti(crypto::random_arr::<16>())
    }

    pub fn from_bytes(b: &[u8; 16]) -> Jti {
        Jti(*b)
    }

    pub fn bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

// ================================================================ Cert

/// Session certificate — a self-contained document (TLS-fullchain
/// model): a root-signed [`Header`] + the double-signed cert part.
/// The session keypair is generated CLIENT-SIDE (browser WebCrypto,
/// P-256, non-extractable); the server only attests that this key
/// passed WebAuthn for the account. The cert part is signed TWICE: by
/// the signer key AND by the account key — stealing only the signer
/// bundle does not allow minting certs of existing accounts (the
/// account key lives sealed under the pepper). `account_pk` is the
/// public identity; the person never sticks out. `jti` is an
/// IS-internal session id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cert {
    pub header: Header,
    /// Session public key: P-256 point, 64 bytes x‖y.
    pub session_pk: SessionPk,
    pub account_pk: PublicKey,
    pub iat: u64,
    pub exp: u64,
    pub jti: Jti,
    pub authorizer_sig: Signature,
    pub account_sig: Signature,
}

impl Cert {
    fn write_unsigned_cert(&self, w: &mut W) {
        w.a64(self.session_pk.bytes());
        w.a32(self.account_pk.bytes());
        w.u64(self.iat);
        w.u64(self.exp);
        w.a16(self.jti.bytes());
    }
    /// Signable bytes of the cert part (what BOTH signatures cover).
    pub fn unsigned_cert(&self) -> Vec<u8> {
        let mut w = W::new();
        w.u8(V);
        self.write_unsigned_cert(&mut w);
        w.out
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut w = W::new();
        w.u8(V);
        self.header.write_unsigned(&mut w);
        w.a64(self.header.root_sig.bytes());
        self.write_unsigned_cert(&mut w);
        w.a64(self.authorizer_sig.bytes());
        w.a64(self.account_sig.bytes());
        w.out
    }
    pub fn decode(b: &[u8]) -> WResult<Cert> {
        let mut r = R::new(b);
        if r.u8()? != V {
            return Err(crate::codec::bin::WireErr);
        }
        let header = Header {
            root_pk: PublicKey::from_bytes(&r.a32()?),
            authorizer_pk: PublicKey::from_bytes(&r.a32()?),
            origin: r.str()?,
            issued_at: r.u64()?,
            root_sig: Signature::from_bytes(&r.a64()?),
        };
        let fc = Cert {
            header,
            session_pk: SessionPk::from_bytes(&r.a64()?),
            account_pk: PublicKey::from_bytes(&r.a32()?),
            iat: r.u64()?,
            exp: r.u64()?,
            jti: Jti::from_bytes(&r.a16()?),
            authorizer_sig: Signature::from_bytes(&r.a64()?),
            account_sig: Signature::from_bytes(&r.a64()?),
        };
        r.done()?;
        Ok(fc)
    }
    /// Signer key id, straight from the header.
    pub fn key_id(&self) -> [u8; 8] {
        self.header.key_id()
    }
    pub fn origin(&self) -> &str {
        &self.header.origin
    }
    /// Full identity form: @<hex(account_pk)>@<origin>.
    pub fn identity(&self) -> String {
        format!("@{}@{}", hex(self.account_pk.bytes()), self.header.origin)
    }
    /// Short: @<hex8>@<origin>.
    pub fn short_identity(&self) -> String {
        format!(
            "@{}@{}",
            &hex(self.account_pk.bytes())[..8],
            self.header.origin
        )
    }
}

// ================================================================ Attestation

/// Server attestation: "the session key `session_pk` passed WebAuthn
/// for account `account_pk`, and may speak for it to `aud`". Issued on
/// request of an authenticated session; the frontend wraps it into a
/// [`Oneshot`]. Short-lived; the audience binds it to one instance so
/// a stolen attestation is useless elsewhere.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attestation {
    pub header: Header,
    pub session_pk: SessionPk,
    pub account_pk: PublicKey,
    pub aud: String,
    pub iat: u64,
    pub exp: u64,
    pub authorizer_sig: Signature,
    pub account_sig: Signature,
}

impl Attestation {
    fn write_unsigned(&self, w: &mut W) {
        self.header.write_unsigned(w);
        w.a64(self.header.root_sig.bytes());
        w.a64(self.session_pk.bytes());
        w.a32(self.account_pk.bytes());
        w.str(&self.aud);
        w.u64(self.iat);
        w.u64(self.exp);
    }
    /// Signable bytes (what BOTH signatures cover).
    pub fn unsigned(&self) -> Vec<u8> {
        let mut w = W::new();
        w.u8(V);
        self.write_unsigned(&mut w);
        w.out
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.unsigned();
        out.extend_from_slice(self.authorizer_sig.bytes());
        out.extend_from_slice(self.account_sig.bytes());
        out
    }
    pub fn decode(b: &[u8]) -> WResult<Attestation> {
        let mut r = R::new(b);
        if r.u8()? != V {
            return Err(crate::codec::bin::WireErr);
        }
        let header = Header {
            root_pk: PublicKey::from_bytes(&r.a32()?),
            authorizer_pk: PublicKey::from_bytes(&r.a32()?),
            origin: r.str()?,
            issued_at: r.u64()?,
            root_sig: Signature::from_bytes(&r.a64()?),
        };
        let a = Attestation {
            header,
            session_pk: SessionPk::from_bytes(&r.a64()?),
            account_pk: PublicKey::from_bytes(&r.a32()?),
            aud: r.str()?,
            iat: r.u64()?,
            exp: r.u64()?,
            authorizer_sig: Signature::from_bytes(&r.a64()?),
            account_sig: Signature::from_bytes(&r.a64()?),
        };
        r.done()?;
        Ok(a)
    }
}

// ================================================================ Oneshot

/// One-shot authorization document, assembled CLIENT-SIDE: the
/// attestation (server-signed) + the instance's nonce + the session
/// key's signature. No client clock inside: freshness comes from the
/// attestation (`exp`) and from the instance's own nonce check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Oneshot {
    pub attestation: Attestation,
    /// The instance's nonce (raw bytes: an arbitrary challenge, not a key).
    pub nonce: [u8; 32],
    pub session_sig: Signature,
}
impl Oneshot {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = W::new();
        w.u8(V);
        w.bytes(&self.attestation.encode());
        w.a32(&self.nonce);
        w.a64(self.session_sig.bytes());
        w.out
    }
    pub fn decode(b: &[u8]) -> WResult<Oneshot> {
        let mut r = R::new(b);
        if r.u8()? != V {
            return Err(crate::codec::bin::WireErr);
        }
        let att_bytes = r.bytes()?;
        let o = Oneshot {
            attestation: Attestation::decode(&att_bytes)?,
            nonce: r.a32()?,
            session_sig: Signature::from_bytes(&r.a64()?),
        };
        r.done()?;
        Ok(o)
    }
    /// The message the session key signs (also what an instance
    /// verifies against `attestation.session_pk`).
    pub fn msg(attestation_bytes: &[u8], nonce: &[u8; 32]) -> Vec<u8> {
        let mut w = W::new();
        w.u8(V);
        w.str("oneshot");
        w.bytes(attestation_bytes);
        w.a32(nonce);
        w.out
    }
    /// Verify the whole document against the PINNED root (the
    /// relying party's `is_id`), its OWN audience, and the nonce it
    /// issued.
    ///
    /// This is the check an instance performs; it lives here so tests
    /// and future instances share one implementation. It deliberately
    /// requires `pinned_is_id`, `aud` and `nonce` — verifying
    /// signatures alone is not enough: the root signature only proves
    /// SELF-consistency (an attacker's own root/signer chain mints
    /// one just fine), so the document must first match the pinned
    /// trust line, and a token minted for another instance (or for
    /// another login attempt) must never be accepted.
    ///
    /// Still stateful and OUT of scope here: the caller must remember
    /// the nonce it issued and burn it after a successful verification
    /// (single-use), and must have bound it to the browser/user that
    /// started the flow. Pass the nonce from that store — NEVER
    /// `self.nonce`, which would accept any nonce an attacker supplied.
    pub fn verify(
        &self,
        now: u64,
        pinned_is_id: &PublicKey,
        aud: &str,
        nonce: &[u8; 32],
    ) -> Result<(), String> {
        let att = &self.attestation;
        // The pin check comes FIRST: everything below is self-
        // consistency an attacker can satisfy with their own key
        // hierarchy; only the pin ties the document to the real IS.
        if att.header.root_pk != *pinned_is_id {
            return Err("unpinned root (not our IS)".into());
        }
        if !crypto::verify(
            &att.header.root_pk,
            &att.header.unsigned(),
            &att.header.root_sig,
        ) {
            return Err("bad root signature".into());
        }
        if !crypto::verify(
            &att.header.authorizer_pk,
            &att.unsigned(),
            &att.authorizer_sig,
        ) {
            return Err("bad authorizer signature".into());
        }
        if !crypto::verify(&att.account_pk, &att.unsigned(), &att.account_sig) {
            return Err("bad account signature".into());
        }
        if att.exp <= now {
            return Err("attestation expired".into());
        }
        if att.aud != aud {
            return Err("wrong audience".into());
        }
        if &self.nonce != nonce {
            return Err("wrong nonce".into());
        }
        let msg = Self::msg(&att.encode(), &self.nonce);
        if !crypto::verify_p256(att.session_pk.bytes(), &msg, self.session_sig.bytes()) {
            return Err("bad session signature".into());
        }
        Ok(())
    }
}

// ================================================================ signature messages

/// Proof-of-possession at a login/register/enroll finish: the session
/// key signs (kind ‖ challenge ‖ session_pk).
pub fn msg_pop(kind: &str, challenge: &str, pk: &[u8; 64]) -> Vec<u8> {
    let mut w = W::new();
    w.u8(V);
    w.str(kind);
    w.str(challenge);
    w.a64(pk);
    w.out
}

/// Proof-of-possession for an authenticated API request (headers
/// x-jti/x-ts/x-sig): binds the signature to the method, the path, a
/// fresh timestamp and the exact body — no cross-endpoint replay and
/// no cross-method reuse (a future GET handler cannot inherit a
/// signature minted for POST).
pub fn msg_request(method: &str, path: &str, ts: u64, body: &[u8]) -> Vec<u8> {
    let mut w = W::new();
    w.u8(V);
    w.str("request");
    w.str(method);
    w.str(path);
    w.u64(ts);
    w.bytes(body);
    w.out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SecretKey;

    fn key_of(n: u8) -> SecretKey {
        SecretKey::from_bytes(&[n; 32])
    }

    /// Honest header: root [0xab] signs signer [0x01].
    fn header() -> (Header, SecretKey, SecretKey) {
        let root = key_of(0xab);
        let signer = key_of(0x01);
        let mut h = Header {
            root_pk: root.public(),
            authorizer_pk: signer.public(),
            origin: "https://auth.example".into(),
            issued_at: 1_700_000_000,
            root_sig: Signature::from_bytes(&[0; 64]),
        };
        h.root_sig = crypto::sign(&root, &h.unsigned());
        (h, root, signer)
    }

    /// Honest cert: both signatures over the cert part are genuine.
    fn cert() -> (Cert, SecretKey) {
        let (h, _root, signer) = header();
        let account = key_of(0x03);
        let mut fc = Cert {
            header: h,
            session_pk: SessionPk::from_bytes(&[7u8; 64]),
            account_pk: account.public(),
            iat: 1000,
            exp: 1000 + 604800,
            jti: Jti::from_bytes(&[4; 16]),
            authorizer_sig: Signature::from_bytes(&[0; 64]),
            account_sig: Signature::from_bytes(&[0; 64]),
        };
        let unsigned = fc.unsigned_cert();
        fc.authorizer_sig = crypto::sign(&signer, &unsigned);
        fc.account_sig = crypto::sign(&account, &unsigned);
        (fc, account)
    }

    #[test]
    fn header_roundtrip_and_strictness() {
        let (h, root, _signer) = header();
        let b = h.encode();
        let h2 = Header::decode(&b).unwrap();
        assert_eq!(h, h2);
        assert_eq!(h.key_id(), crypto::key_id(&h.authorizer_pk));
        assert_eq!(h.is_id(), &h.root_pk);
        assert!(crypto::verify(&root.public(), &h.unsigned(), &h.root_sig));
        // extra tail is rejected
        let mut b2 = b.clone();
        b2.push(0);
        assert!(Header::decode(&b2).is_err());
        // the old format version is rejected
        let mut old = b;
        old[0] = 6;
        assert!(Header::decode(&old).is_err());
    }

    #[test]
    fn cert_roundtrip_and_no_malleability() {
        let (fc, _) = cert();
        let b = fc.encode();
        let fc2 = Cert::decode(&b).unwrap();
        assert_eq!(fc, fc2);
        assert_eq!(
            fc.identity(),
            format!("@{}@https://auth.example", hex(fc.account_pk.bytes()))
        );
        assert_eq!(fc.key_id(), fc.header.key_id());
        // extra tail is rejected
        let mut b2 = b;
        b2.push(0);
        assert!(Cert::decode(&b2).is_err());
    }

    #[test]
    fn attestation_roundtrip() {
        let (h, _root, signer) = header();
        let account = key_of(0x09);
        let mut a = Attestation {
            header: h,
            session_pk: SessionPk::from_bytes(&[5u8; 64]),
            account_pk: account.public(),
            aud: "https://wiki.example".into(),
            iat: 100,
            exp: 400,
            authorizer_sig: Signature::from_bytes(&[0; 64]),
            account_sig: Signature::from_bytes(&[0; 64]),
        };
        a.authorizer_sig = crypto::sign(&signer, &a.unsigned());
        a.account_sig = crypto::sign(&account, &a.unsigned());
        let b = a.encode();
        let a2 = Attestation::decode(&b).unwrap();
        assert_eq!(a, a2);
        let mut b2 = b.clone();
        b2.push(0);
        assert!(Attestation::decode(&b2).is_err());
        assert!(a2.aud == "https://wiki.example");
    }

    #[test]
    fn oneshot_roundtrip_and_verify() {
        let (h, root, signer) = header();
        let account = key_of(0x09);
        let mut a = Attestation {
            header: h,
            session_pk: SessionPk::from_bytes(&[5u8; 64]),
            account_pk: account.public(),
            aud: "https://wiki.example".into(),
            iat: 100,
            exp: 400,
            authorizer_sig: Signature::from_bytes(&[0; 64]),
            account_sig: Signature::from_bytes(&[0; 64]),
        };
        a.authorizer_sig = crypto::sign(&signer, &a.unsigned());
        a.account_sig = crypto::sign(&account, &a.unsigned());
        let att_bytes = a.encode();
        let nonce = [3u8; 32];
        // honest "session" signature (ed25519 won't do here:
        // verify_p256 expects P-256; we only exercise codec + negatives)
        let msg = Oneshot::msg(&att_bytes, &nonce);
        assert!(!msg.is_empty());
        let os = Oneshot {
            attestation: a.clone(),
            nonce,
            session_sig: Signature::from_bytes(&[1; 64]),
        };
        let b = os.encode();
        let os2 = Oneshot::decode(&b).unwrap();
        assert_eq!(os2, os);
        // a document with genuine signatures but a junk session sig —
        // is rejected at the session step
        let pin = root.public();
        assert!(
            os2.verify(200, &pin, "https://wiki.example", &nonce)
                .is_err()
        );
        assert_eq!(
            os2.verify(200, &pin, "https://other.example", &nonce)
                .unwrap_err(),
            "wrong audience"
        );
        assert_eq!(
            os2.verify(200, &pin, "https://wiki.example", &[4u8; 32])
                .unwrap_err(),
            "wrong nonce"
        );
        // an expired attestation — also
        assert!(
            os2.verify(401, &pin, "https://wiki.example", &nonce)
                .is_err()
        );
        // a foreign root (an attacker's own self-consistent chain) is
        // cut off by the pin before any signature is even looked at
        let foreign_root = key_of(0xcd);
        assert_eq!(
            os2.verify(200, &foreign_root.public(), "https://wiki.example", &nonce)
                .unwrap_err(),
            "unpinned root (not our IS)"
        );
        let _ = msg;
    }

    #[test]
    fn msg_builders_are_version_bound() {
        let m = msg_pop("login-pop", "ch", &[0; 64]);
        assert_eq!(m[0], V);
        let m = msg_request("POST", "/account", 1, b"{}");
        assert_eq!(m[0], V);
    }
}

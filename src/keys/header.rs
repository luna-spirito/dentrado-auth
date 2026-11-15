//! Pure. The root-signed signer header (v1) — the head document of
//! the key hierarchy, so it lives in `keys`, not in `wire`: it
//! authorizes a signer key, it is not an exchange document (the wire
//! module re-exports it — certs and attestations embed it).
//!
//! `root_pk` is what relying parties pin (= is_id); the signer (the
//! IS cert-minting key) is ONE and lives forever — no rotation, no
//! EOL; a re-issue (fresh bundle + restart) is an incident procedure,
//! not a calendar one. The header's authority is the ROOT's
//! signature, not the signer's own. It lives both in the server's
//! bundle and inside every cert and attestation — an instance needs
//! nothing beyond its pin.

use crate::codec::bin::{R, V, W, WResult};
use crate::crypto::{PublicKey, Signature, key_id};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    /// = is_id, the instances' trust line.
    pub root_pk: PublicKey,
    pub authorizer_pk: PublicKey,
    /// HTTP(S) origin of this IS.
    pub origin: String,
    pub issued_at: u64,
    pub root_sig: Signature,
}

impl Header {
    /// The unsigned body writer (shared with the cert/attestation
    /// encoders in `wire`, which embed the header).
    pub(crate) fn write_unsigned(&self, w: &mut W) {
        w.a32(self.root_pk.bytes());
        w.a32(self.authorizer_pk.bytes());
        w.str(&self.origin);
        w.u64(self.issued_at);
    }
    /// Signable bytes (what `root_sig` covers).
    pub fn unsigned(&self) -> Vec<u8> {
        let mut w = W::new();
        w.u8(V);
        self.write_unsigned(&mut w);
        w.out
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.unsigned();
        out.extend_from_slice(self.root_sig.bytes());
        out
    }
    pub fn decode(b: &[u8]) -> WResult<Header> {
        let mut r = R::new(b);
        if r.u8()? != V {
            return Err(crate::codec::bin::WireErr);
        }
        let h = Header {
            root_pk: PublicKey::from_bytes(&r.a32()?),
            authorizer_pk: PublicKey::from_bytes(&r.a32()?),
            origin: r.str()?,
            issued_at: r.u64()?,
            root_sig: Signature::from_bytes(&r.a64()?),
        };
        r.done()?;
        Ok(h)
    }
    /// IS identity: pubkey(root).
    pub fn is_id(&self) -> &PublicKey {
        &self.root_pk
    }
    /// Signer key id.
    pub fn key_id(&self) -> [u8; 8] {
        key_id(&self.authorizer_pk)
    }
}

//! The signer-key bundle under the root (Pure): one key, forever.
//!
//! Issued any number of times (`signer new --origin URL`), each time
//! with a fresh signer key: [`issue`] takes the root key and
//! pulls the authorizer seed from the crate CSPRNG itself — production
//! code cannot hand in a chosen seed. The deterministic core
//! (`issue_from_seeds`, private) is what tests drive.
//! The header {root_pk, authorizer_pk, origin, issued_at} is signed by
//! the ROOT — the cert author's authority comes from the offline key,
//! not from the signer itself. No rotations and no EOL (v1): a re-issue
//! is an incident procedure (new bundle + restart), not a calendar.
//! All bundles of one root share `is_id` (= pubkey(root));
//! the instances' trust line does NOT change on re-issue.
//!
//! Transport is a stream (wg convention): `signer new` writes the
//! bundle to stdout, `signer verify` reads it from stdin; the shell
//! redirection puts it on disk — no chmod window, under umask 077:
//! `(umask 077; auth signer new --origin https://auth.example < phrase.txt > signer.bin)`.
//! The bundle is the server's PERMANENT secret: `auth serve --bundle`
//! takes it as input at EVERY start (the signer seed lives only
//! here). The instances' trust line is `root pubkey` (= pubkey(root));
//! there is no separate trust file.

use crate::crypto::{self, SecretKey};
use crate::keys::header::Header;

/// Issue a bundle: a fresh signer key + a root-signed header. The
/// authorizer seed comes from the crate CSPRNG (the only production
/// path); the root arrives as the key object (`root::from_phrase`).
pub fn issue(root: &SecretKey, now: u64, origin: &str) -> Result<(SecretKey, Header), String> {
    issue_from_seeds(root.bytes(), &crypto::random_arr::<32>(), now, origin)
}

/// The deterministic core of [`issue`] (private: tests only).
fn issue_from_seeds(
    root_seed: &[u8; 32],
    authorizer_seed: &[u8; 32],
    now: u64,
    origin: &str,
) -> Result<(SecretKey, Header), String> {
    let root = SecretKey::from_bytes(root_seed);
    let authorizer = SecretKey::from_bytes(authorizer_seed);
    let root_pk = root.public();
    let authorizer_pk = authorizer.public();
    if root_pk == authorizer_pk {
        return Err("authorizer must differ from the root key".into());
    }
    let origin = origin.trim_end_matches('/');
    if !origin.starts_with("http://") && !origin.starts_with("https://") {
        return Err(format!(
            "origin must be an HTTP(S) origin, e.g. https://idp.example (got {origin:?})"
        ));
    }
    let mut header = Header {
        root_pk,
        authorizer_pk,
        origin: origin.to_string(),
        issued_at: now,
        root_sig: crypto::Signature::from_bytes(&[0; 64]),
    };
    header.root_sig = crypto::sign(&root, &header.unsigned());
    // verify the fresh header in full: codec + signature
    let rt = Header::decode(&header.encode()).map_err(|e| e.to_string())?;
    if rt != header || !crypto::verify(&root_pk, &rt.unsigned(), &rt.root_sig) {
        return Err("keys: freshly signed header does not verify".into());
    }
    Ok((authorizer, header))
}

/// Encode a bundle (stdout of `signer new`): `[32B authorizer seed]
/// [header + root signature]`.
pub fn bundle(authorizer: &SecretKey, header: &Header) -> Vec<u8> {
    let mut b = authorizer.bytes().to_vec();
    b.extend_from_slice(&header.encode());
    b
}

/// Parse a bundle: the authorizer + the verified header (root
/// signature), with a seed ↔ authorizer_pk cross-check.
pub fn decode_bundle(b: &[u8]) -> Result<(SecretKey, Header), String> {
    if b.len() <= 32 {
        return Err("not a bundle".into());
    }
    let (seed, hb) = b.split_at(32);
    let seed: &[u8; 32] = seed.try_into().expect("split_at(32)");
    let header = Header::decode(hb).map_err(|_| "bad header wire".to_string())?;
    if !crypto::verify(&header.root_pk, &header.unsigned(), &header.root_sig) {
        return Err("bundle: bad root signature".into());
    }
    let authorizer = SecretKey::from_bytes(seed);
    if authorizer.public() != header.authorizer_pk {
        return Err("seed does not match the authorizer pubkey".into());
    }
    Ok((authorizer, header))
}

/// Public digest of a bundle (reveals no secret).
#[derive(Debug)]
pub struct Info {
    pub is_id: crate::crypto::PublicKey,
    pub key_id: [u8; 8],
    pub origin: String,
    pub issued_at: u64,
}

/// Verify a bundle (stdin of `signer verify`).
pub fn verify_bundle(b: &[u8]) -> Result<Info, String> {
    let (_, header) = decode_bundle(b)?;
    Ok(Info {
        is_id: *header.is_id(),
        key_id: header.key_id(),
        origin: header.origin.clone(),
        issued_at: header.issued_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORIGIN: &str = "https://idp.example";

    fn root_pk_of(seed: &[u8; 32]) -> crate::crypto::PublicKey {
        SecretKey::from_bytes(seed).public()
    }

    #[test]
    fn bundle_roundtrip_and_tamper() {
        let root_seed = [1u8; 32];
        let (authorizer, header) =
            issue_from_seeds(&root_seed, &[2u8; 32], 1_700_000_000, ORIGIN).expect("issue");
        let b = bundle(&authorizer, &header);

        let info = verify_bundle(&b).expect("verify");
        assert_eq!(info.is_id, root_pk_of(&root_seed));
        assert_eq!(info.origin, ORIGIN);
        assert_eq!(info.key_id, header.key_id());

        // tampered header signature (last byte of the bundle)
        let mut t = b.clone();
        let last = t.len() - 1;
        t[last] ^= 1;
        assert!(verify_bundle(&t).is_err());

        // tampered authorizer seed — cross-check against authorizer_pk
        let mut t = b.clone();
        t[0] ^= 1;
        assert!(verify_bundle(&t).is_err());

        // junk instead of a bundle
        assert!(verify_bundle(b"junk").is_err());
    }

    #[test]
    fn issue_rejects_bad_inputs() {
        let root_seed = [2u8; 32];
        // root == authorizer — a pointless root
        assert!(issue_from_seeds(&root_seed, &root_seed, 1, ORIGIN).is_err());
        // not an HTTP(S) origin
        assert!(issue_from_seeds(&root_seed, &[3u8; 32], 1, "idp.example").is_err());
        assert!(issue_from_seeds(&root_seed, &[3u8; 32], 1, "ftp://idp.example").is_err());
        // //idp.example is an acceptable form; a trailing slash is trimmed
        let (_, h) = issue_from_seeds(&root_seed, &[3u8; 32], 1, "https://idp.example/").unwrap();
        assert_eq!(h.origin, ORIGIN);
    }

    #[test]
    fn public_issue_generates_fresh_authorizer() {
        let root = SecretKey::from_bytes(&[9u8; 32]);
        let (a1, h1) = issue(&root, 1, ORIGIN).unwrap();
        let (a2, h2) = issue(&root, 2, ORIGIN).unwrap();
        assert_eq!(h1.is_id(), h2.is_id(), "one root — one is_id");
        assert_ne!(
            a1.public(),
            a2.public(),
            "fresh CSPRNG authorizer per issue"
        );
    }

    #[test]
    fn second_bundle_same_root_same_is_id() {
        let root_seed = [4u8; 32];
        let (a1, h1) = issue_from_seeds(&root_seed, &[5u8; 32], 1, ORIGIN).unwrap();
        let (a2, h2) = issue_from_seeds(&root_seed, &[6u8; 32], 2, ORIGIN).unwrap();
        assert_eq!(h1.is_id(), h2.is_id(), "one root — one is_id");
        assert_ne!(h1.key_id(), h2.key_id(), "fresh authorizer per bundle");
        assert_ne!(a1.public(), a2.public(), "fresh authorizer key per bundle");
    }
}

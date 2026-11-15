//! Cryptographic primitives (layer 0, the tower base — Pure, except
//! the explicitly marked edge): Ed25519 (the named key types
//! [`SecretKey`]/[`PublicKey`]/[`Signature`]), HMAC-SHA256,
//! envelope-seal, P-256-verify, hex/base64url.
//!
//! The only place where dependencies live; the rest of the code is
//! std. Functions are deterministic: time and randomness enter
//! as parameters. The module's entire imperative edge lives in the final
//! EFFECTS section — [`random`]/[`random_arr`], [`now`],
//! [`write_secret_0400`]/[`is_private_mode`], and the [`seal`]
//! wrapper (random nonce); there is no other impurity here.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature as P256Sig, VerifyingKey as P256Vk};
use sha2::{Digest, Sha256};

pub type HmacSha256 = Hmac<Sha256>;

// ------------------------------------------------------------- key types

// Named Ed25519 material: a bare `[u8; 32]` says nothing about its
// role (a key? a hash? a random id?), so keys crossing a module
// boundary carry their concept in the type. The symmetric derivations
// below (HMAC keys, seal keys, the pepper) stay as raw `[u8; 32]`:
// a different concept, and they never leave crypto/vault.

/// An Ed25519 secret key (a 32-byte seed). Fresh keys are born inside
/// [`SecretKey::generate`] (the crate CSPRNG — the production path);
/// `from_bytes` exists for bundle decoding and tests.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SecretKey([u8; 32]);

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // never print the seed
        f.write_str("SecretKey(REDACTED)")
    }
}

impl SecretKey {
    /// A fresh key from the crate CSPRNG (the only production birth).
    pub fn generate() -> SecretKey {
        SecretKey(random_arr::<32>())
    }

    pub fn from_bytes(b: &[u8; 32]) -> SecretKey {
        SecretKey(*b)
    }

    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The dalek signing key (signing only; lives no longer than the call).
    pub fn key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.0)
    }

    pub fn public(&self) -> PublicKey {
        PublicKey(self.key().verifying_key().to_bytes())
    }
}

/// An Ed25519 public key (= an identity: root, signer, account).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    pub fn from_bytes(b: &[u8; 32]) -> PublicKey {
        PublicKey(*b)
    }

    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// An Ed25519 signature (64 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature([u8; 64]);

impl Signature {
    pub fn from_bytes(b: &[u8; 64]) -> Signature {
        Signature(*b)
    }

    pub fn bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// In-place byte access (tamper tests, wire surgery).
    pub fn bytes_mut(&mut self) -> &mut [u8; 64] {
        &mut self.0
    }
}

// ------------------------------------------------------------ digests & sigs

pub fn sha256(b: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b);
    h.finalize().into()
}

/// key_id = first 8 bytes of sha256(pubkey). Self-describing, survives rotation.
pub fn key_id(pk: &PublicKey) -> [u8; 8] {
    let d = sha256(pk.bytes());
    let mut k = [0u8; 8];
    k.copy_from_slice(&d[..8]);
    k
}

pub fn sign(sk: &SecretKey, msg: &[u8]) -> Signature {
    Signature(sk.key().sign(msg).to_bytes())
}

pub fn verify(pk: &PublicKey, msg: &[u8], sig: &Signature) -> bool {
    match VerifyingKey::from_bytes(pk.bytes()) {
        Ok(vk) => vk
            .verify(msg, &ed25519_dalek::Signature::from_bytes(sig.bytes()))
            .is_ok(),
        Err(_) => false,
    }
}

/// P-256 session-key signature (WebCrypto ES256): raw 64-byte r‖s over
/// SHA-256(msg). `pk` — 64 bytes x‖y (as in [`crate::wire`] documents;
/// a 65-byte 0x04-prefixed form is accepted too). The browser never
/// exports the private half (non-extractable CryptoKey).
pub fn verify_p256(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let point: &[u8] = match pk.len() {
        64 => pk,
        65 if pk[0] == 0x04 => &pk[1..],
        _ => return false,
    };
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(point);
    if sig.len() != 64 {
        return false;
    }
    let mut s = [0u8; 64];
    s.copy_from_slice(sig);
    let Ok(sig) = P256Sig::from_slice(&s) else {
        return false;
    };
    match P256Vk::from_sec1_bytes(&sec1) {
        Ok(vk) => vk.verify_prehash(&sha256(msg), &sig).is_ok(),
        Err(_) => false,
    }
}

// ------------------------------------------------------- HMAC domains (KDF)

/// KDF(pepper, domain, part0, part1) — wrapping key for a storage
/// string. Domains do not overlap.
pub fn blob_key(pepper: &[u8], domain: &str, part0: &str, part1: &str) -> [u8; 32] {
    // HKDF-extract(pepper, domain‖part0‖part1) → expand(1 block)
    let mut prk = HmacSha256::new_from_slice(pepper).expect("hmac accepts any key len");
    prk.update(domain.as_bytes());
    prk.update(b"\x00");
    prk.update(part0.as_bytes());
    prk.update(b"\x00");
    prk.update(part1.as_bytes());
    let prk = prk.finalize().into_bytes();
    let mut okm = HmacSha256::new_from_slice(&prk).expect("hmac accepts any key len");
    okm.update(b"\x01");
    okm.finalize().into_bytes().into()
}

/// KV string key: HMAC(pepper, "key-v1/" ‖ key_string). The "key-v1"
/// domain is separate from "link-v1" and "blob-v1" — lookup keys don't
/// collide with the other schemes. Same string → same key (lookup).
pub fn kv_key(pepper: &[u8], key_string: &str) -> [u8; 32] {
    let mut m = HmacSha256::new_from_slice(pepper).expect("hmac accepts any key len");
    m.update(b"key-v1/");
    m.update(key_string.as_bytes());
    m.finalize().into_bytes().into()
}

/// Value encryption key for a KV string: KDF(pepper, "value-v1", key_string).
/// Domain separation of lookup vs encryption (FINAL_DESIGN "DB"): knowing
/// the algorithm does not derive the plaintext key from the string key
/// without the pepper.
pub fn kv_value_key(pepper: &[u8], key_string: &str) -> [u8; 32] {
    blob_key(pepper, "value-v1", key_string, "")
}

fn hmac_parts(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = HmacSha256::new_from_slice(key).expect("hmac accepts any key len");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

// ------------------------------------------------------------ seal (AEAD)

fn xor_keystream(enc: &[u8; 32], nonce: &[u8; 16], data: &[u8], out: &mut Vec<u8>) {
    for (ctr, chunk) in data.chunks(32).enumerate() {
        let mut m = HmacSha256::new_from_slice(enc).expect("hmac accepts any key len");
        m.update(b"ks");
        m.update(nonce);
        m.update(&(ctr as u64).to_le_bytes());
        let ks = m.finalize().into_bytes();
        for (i, b) in chunk.iter().enumerate() {
            out.push(b ^ ks[i]);
        }
    }
}

/// Seal with an EXPLICIT nonce — pure. AEAD on HMAC-SHA256: CTR
/// keystream + encrypt-then-MAC (no external AEAD dependency;
/// supply policy: 5 direct deps). Format: nonce(16) ‖ ct ‖ tag(32).
/// Key is 32 bytes (e.g. blob_key or ak). Same (key, nonce, pt) →
/// same bytes: hidden entropy is absent here by construction.
pub fn seal_with(nonce: &[u8; 16], key: &[u8; 32], pt: &[u8]) -> Vec<u8> {
    let enc = hmac_parts(key, &[b"enc"]);
    let mac = hmac_parts(key, &[b"mac"]);
    let mut out = Vec::with_capacity(16 + pt.len() + 32);
    out.extend_from_slice(nonce);
    xor_keystream(&enc, nonce, pt, &mut out);
    let ct_end = out.len();
    let tag = hmac_parts(&mac, &[b"tag", nonce, &out[16..ct_end]]);
    out.extend_from_slice(&tag);
    out
}

/// Seal with a random nonce — the ONLY impure function outside the
/// EFFECTS section (see the module doc). Deterministic core:
/// [`seal_with`].
pub fn seal(key: &[u8; 32], pt: &[u8]) -> Vec<u8> {
    seal_with(&random_arr::<16>(), key, pt)
}

pub fn open(key: &[u8; 32], sealed: &[u8]) -> Option<Vec<u8>> {
    if sealed.len() < 48 {
        return None;
    }
    let (nonce, rest) = sealed.split_at(16);
    let (ct, tag) = rest.split_at(rest.len() - 32);
    let mac = hmac_parts(key, &[b"mac"]);
    let mut m = HmacSha256::new_from_slice(&mac).ok()?;
    m.update(b"tag");
    m.update(nonce);
    m.update(ct);
    m.verify_slice(tag).ok()?; // constant-time comparison
    let enc = hmac_parts(key, &[b"enc"]);
    let nonce: [u8; 16] = nonce.try_into().ok()?;
    let mut pt = Vec::with_capacity(ct.len());
    xor_keystream(&enc, &nonce, ct, &mut pt);
    Some(pt)
}

// ---------------------------------------------------------------- codecs

pub fn hex(b: &[u8]) -> String {
    const T: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(T[(x >> 4) as usize] as char);
        s.push(T[(x & 0xf) as usize] as char);
    }
    s
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut v = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    for c in b.chunks(2) {
        let hi = (c[0] as char).to_digit(16)?;
        let lo = (c[1] as char).to_digit(16)?;
        v.push((hi * 16 + lo) as u8);
    }
    Some(v)
}

const B64U: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// base64url without padding (WebAuthn, JWT pieces, cookie tokens).
pub fn b64u_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len().div_ceil(3) * 4);
    for chunk in b.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        s.push(B64U[(n >> 18) as usize & 63] as char);
        s.push(B64U[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            s.push(B64U[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            s.push(B64U[n as usize & 63] as char);
        }
    }
    s
}

fn b64u_val(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some((c - b'A') as u32),
        b'a'..=b'z' => Some((c - b'a' + 26) as u32),
        b'0'..=b'9' => Some((c - b'0' + 52) as u32),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

/// base64url without padding; trailing '=' is accepted and ignored.
pub fn b64u_decode(s: &str) -> Option<Vec<u8>> {
    let s: Vec<u8> = s
        .trim_end_matches('=')
        .bytes()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    if s.is_empty() {
        return Some(Vec::new());
    }
    if s.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for chunk in s.chunks(4) {
        let mut n: u32 = 0;
        for &c in chunk {
            n = (n << 6) | b64u_val(c)?;
        }
        match chunk.len() {
            4 => {
                out.push((n >> 16) as u8);
                out.push((n >> 8) as u8);
                out.push(n as u8);
            }
            3 => {
                out.push((n >> 10) as u8);
                out.push((n >> 2) as u8);
            }
            2 => out.push((n >> 4) as u8),
            _ => return None,
        }
    }
    Some(out)
}

// ---------------------------------------------------------------- EFFECTS
// The module's only non-deterministic/system functions (see the
// doc header). Everything else is a pure function of explicit inputs.

pub fn random(n: usize) -> Vec<u8> {
    use getrandom::getrandom;
    let mut v = vec![0u8; n];
    getrandom(&mut v).expect("system RNG unavailable");
    v
}

pub fn random_arr<const N: usize>() -> [u8; N] {
    let mut a = [0u8; N];
    a.copy_from_slice(&random(N));
    a
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Write a secret with 0400 permissions; fails if the file exists.
pub fn write_secret_0400(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::File::options()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(path)?;
    f.write_all(data)?;
    f.flush()
}

/// Is the file unreadable by group/others?
pub fn is_private_mode(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o077 == 0)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let k = [7u8; 32];
        let pt = b"account_privkey || graph".to_vec();
        let s = seal(&k, &pt);
        assert_eq!(open(&k, &s).as_deref(), Some(&pt[..]));
        // empty plaintext is a valid frame
        let s0 = seal(&k, b"");
        assert_eq!(open(&k, &s0).as_deref(), Some(&[][..]));
    }

    #[test]
    fn seal_with_is_deterministic() {
        // explicit nonce → deterministic sealed byte stream; all of
        // seal's randomness lives in the nonce only
        let k = [7u8; 32];
        let n = [9u8; 16];
        let a = seal_with(&n, &k, b"graph");
        let b = seal_with(&n, &k, b"graph");
        assert_eq!(a, b);
        assert_eq!(open(&k, &a).as_deref(), Some(&b"graph"[..]));
        assert_ne!(a, seal_with(&[1u8; 16], &k, b"graph"), "nonce matters");
    }

    #[test]
    fn seal_rejects_wrong_key_and_tamper() {
        let k = [7u8; 32];
        let s = seal(&k, b"secret graph");
        assert!(open(&[8u8; 32], &s).is_none());
        let mut t = s.clone();
        let last = t.len() - 1;
        t[last] ^= 1; // tag
        assert!(open(&k, &t).is_none());
        let mut t = s.clone();
        t[16] ^= 1; // ciphertext
        assert!(open(&k, &t).is_none());
        assert!(open(&k, &s[..40]).is_none()); // truncated
    }

    #[test]
    fn blob_key_domains_do_not_collide() {
        let p = [1u8; 32];
        let a = blob_key(&p, "link-v1", "dev", "sub");
        let b = blob_key(&p, "blob-v1", "dev", "sub");
        let c = blob_key(&p, "blob-v1", "dev", "sub2");
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_eq!(b, blob_key(&p, "blob-v1", "dev", "sub"));
    }

    #[test]
    fn kv_key_and_value_key_domains() {
        let p = [2u8; 32];
        // determinism
        assert_eq!(kv_key(&p, "auth/google/123"), kv_key(&p, "auth/google/123"));
        // domains and strings don't collide
        assert_ne!(kv_key(&p, "auth/google/123"), kv_key(&p, "auth/google/124"));
        assert_ne!(kv_key(&p, "a/b"), kv_value_key(&p, "a/b"));
        assert_ne!(kv_key(&p, "x"), kv_key(&p, "y"));
        // 'x/y' and 'x' + junk don't overlap: the whole prefix goes into the HMAC
        assert_ne!(
            kv_value_key(&p, "person/abc"),
            kv_value_key(&p, "person/abcdef")
        );
    }

    #[test]
    fn b64url_roundtrip() {
        for len in 0..40 {
            let data: Vec<u8> = (0..len as u8).collect();
            let s = b64u_encode(&data);
            assert!(!s.contains('='), "no padding");
            assert_eq!(b64u_decode(&s).unwrap(), data);
        }
        assert_eq!(b64u_encode(b"\xff\xef"), "_-8");
        assert_eq!(b64u_decode("_-8").unwrap(), b"\xff\xef");
        // padding and junk are rejected/ignored per the contract
        assert_eq!(b64u_decode("QQ==").unwrap(), b"A");
        assert!(b64u_decode("A").is_none(), "impossible length");
        assert!(b64u_decode("*").is_none(), "invalid character");
        assert_eq!(b64u_decode("").unwrap(), b"");
    }
}

//! Pure. The length-prefixed binary codec of versioned documents
//! (strictly instead of JWT: no alg confusion, no canonicalization
//! pitfalls). Generic primitives — no domain types; the documents
//! built on it live in [`crate::keys::header`] and [`crate::wire`],
//! the stored records in [`crate::storage::records`].
//!
//! Encoding rules:
//! - all u64 — little-endian, 8 bytes;
//! - byte strings — u64 len + bytes;
//! - structs — fixed field order, version in the first byte;
//! - the decoder requires full buffer consumption (anti-malleability).

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireErr;

impl fmt::Display for WireErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bin: malformed or truncated input")
    }
}

pub type WResult<T> = Result<T, WireErr>;

/// The version byte of the binary document format family (v7): the
/// first byte of every versioned document (header, cert, attestation,
/// oneshot, signature messages). A stored record carries its own
/// per-row version instead (see `crate::storage::records`).
pub const V: u8 = 7;

// ---------------------------------------------------------------- encoder

#[derive(Default)]
pub struct W {
    pub out: Vec<u8>,
}

impl W {
    pub fn new() -> Self {
        W { out: Vec::new() }
    }
    pub fn u8(&mut self, v: u8) {
        self.out.push(v);
    }
    pub fn u64(&mut self, v: u64) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }
    pub fn bytes(&mut self, b: &[u8]) {
        self.u64(b.len() as u64);
        self.out.extend_from_slice(b);
    }
    pub fn str(&mut self, s: &str) {
        self.bytes(s.as_bytes());
    }
    pub fn a8(&mut self, b: &[u8; 8]) {
        self.out.extend_from_slice(b);
    }
    pub fn a16(&mut self, b: &[u8; 16]) {
        self.out.extend_from_slice(b);
    }
    pub fn a32(&mut self, b: &[u8; 32]) {
        self.out.extend_from_slice(b);
    }
    pub fn a64(&mut self, b: &[u8; 64]) {
        self.out.extend_from_slice(b);
    }
}

// ---------------------------------------------------------------- decoder

pub struct R<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> R<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        R { b, p: 0 }
    }
    fn need(&mut self, n: usize) -> WResult<&'a [u8]> {
        if n > 1 << 22 || self.p + n > self.b.len() {
            return Err(WireErr);
        }
        let s = &self.b[self.p..self.p + n];
        self.p += n;
        Ok(s)
    }
    pub fn u8(&mut self) -> WResult<u8> {
        Ok(self.need(1)?[0])
    }
    pub fn u64(&mut self) -> WResult<u64> {
        let s = self.need(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Ok(u64::from_le_bytes(a))
    }
    pub fn bytes(&mut self) -> WResult<Vec<u8>> {
        let n = self.u64()? as usize;
        Ok(self.need(n)?.to_vec())
    }
    pub fn str(&mut self) -> WResult<String> {
        String::from_utf8(self.bytes()?).map_err(|_| WireErr)
    }
    pub fn a8(&mut self) -> WResult<[u8; 8]> {
        let s = self.need(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Ok(a)
    }
    pub fn a16(&mut self) -> WResult<[u8; 16]> {
        let s = self.need(16)?;
        let mut a = [0u8; 16];
        a.copy_from_slice(s);
        Ok(a)
    }
    pub fn a32(&mut self) -> WResult<[u8; 32]> {
        let s = self.need(32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(s);
        Ok(a)
    }
    pub fn a64(&mut self) -> WResult<[u8; 64]> {
        let s = self.need(64)?;
        let mut a = [0u8; 64];
        a.copy_from_slice(s);
        Ok(a)
    }
    /// The buffer must be fully consumed.
    pub fn done(&self) -> WResult<()> {
        if self.p == self.b.len() {
            Ok(())
        } else {
            Err(WireErr)
        }
    }
}

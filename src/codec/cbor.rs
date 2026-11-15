//! Pure. Minimal CBOR decoder (std-only): just enough for WebAuthn —
//! attestationObject and COSE keys. No outbound encoding needed.

#[derive(Clone, Debug, PartialEq)]
pub enum Cbor {
    Uint(u64),
    /// Negative: value = -1 - n.
    Nint(u64),
    Bytes(Vec<u8>),
    Text(String),
    Arr(Vec<Cbor>),
    Map(Vec<(Cbor, Cbor)>),
    /// Simple values (false/true/null); floats don't occur in COSE.
    Simple(u8),
}

impl Cbor {
    /// Map lookup by INTEGER key (COSE keys: 1, 3, -1, -2, -3...).
    pub fn map_get(&self, key: i64) -> Option<&Cbor> {
        let k = match key {
            k if k >= 0 => Cbor::Uint(k as u64),
            k => Cbor::Nint((-1 - k) as u64),
        };
        match self {
            Cbor::Map(m) => m.iter().find(|(kk, _)| *kk == k).map(|(_, v)| v),
            _ => None,
        }
    }
    /// Map lookup by string key (attestationObject: "fmt", "authData"...).
    pub fn map_get_text(&self, key: &str) -> Option<&Cbor> {
        match self {
            Cbor::Map(m) => m
                .iter()
                .find(|(k, _)| k.as_text() == Some(key))
                .map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Cbor::Bytes(b) => Some(b),
            _ => None,
        }
    }
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Cbor::Text(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Cbor::Uint(n) => Some(*n),
            _ => None,
        }
    }
    /// Integer of either sign → i128 (for keys -2, 3, ...).
    pub fn as_int(&self) -> Option<i128> {
        match self {
            Cbor::Uint(n) => Some(*n as i128),
            Cbor::Nint(n) => Some(-1 - *n as i128),
            _ => None,
        }
    }
}

struct Dec<'a> {
    b: &'a [u8],
    i: usize,
    depth: u32,
}

const MAX_DEPTH: u32 = 16;

impl<'a> Dec<'a> {
    fn head(&mut self) -> Result<(u8, u64), String> {
        let ib = *self.b.get(self.i).ok_or_else(|| "cbor: eof".to_string())?;
        self.i += 1;
        let major = ib >> 5;
        let info = ib & 0x1f;
        let arg = match info {
            n if n < 24 => n as u64,
            24 => self.take(1)?[0] as u64,
            25 => {
                let s = self.take(2)?;
                u16::from_be_bytes([s[0], s[1]]) as u64
            }
            26 => {
                let s = self.take(4)?;
                u32::from_be_bytes([s[0], s[1], s[2], s[3]]) as u64
            }
            27 => {
                let s = self.take(8)?;
                u64::from_be_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]])
            }
            _ => return Err("cbor: indefinite length not supported".into()),
        };
        Ok((major, arg))
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let s = self.b.get(self.i..self.i + n).ok_or("cbor: truncated")?;
        self.i += n;
        Ok(s)
    }
    fn item(&mut self) -> Result<Cbor, String> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err("cbor: too deep".into());
        }
        let (major, arg) = self.head()?;
        let v = match major {
            0 => Cbor::Uint(arg),
            1 => Cbor::Nint(arg),
            2 => Cbor::Bytes(self.take(arg as usize)?.to_vec()),
            3 => Cbor::Text(
                String::from_utf8(self.take(arg as usize)?.to_vec())
                    .map_err(|_| "cbor: bad utf-8".to_string())?,
            ),
            4 => {
                let mut a = Vec::with_capacity(arg.min(64) as usize);
                for _ in 0..arg {
                    a.push(self.item()?);
                }
                Cbor::Arr(a)
            }
            5 => {
                let mut m = Vec::with_capacity(arg.min(64) as usize);
                for _ in 0..arg {
                    let k = self.item()?;
                    let v = self.item()?;
                    m.push((k, v));
                }
                Cbor::Map(m)
            }
            7 => match arg {
                20..=23 => Cbor::Simple(arg as u8),
                _ => return Err("cbor: unsupported simple/float".into()),
            },
            _ => return Err("cbor: major 6 (tag) unsupported".into()),
        };
        self.depth -= 1;
        Ok(v)
    }
}

/// Decode a single CBOR element; trailing bytes must be fully consumed.
pub fn decode(b: &[u8]) -> Result<Cbor, String> {
    let mut d = Dec { b, i: 0, depth: 0 };
    let v = d.item()?;
    if d.i != b.len() {
        return Err("cbor: trailing bytes".into());
    }
    Ok(v)
}

/// Length of the first CBOR element in bytes (to slice a COSE key off
/// the end of authData without parsing the surroundings).
pub fn element_len(b: &[u8]) -> Result<usize, String> {
    let mut d = Dec { b, i: 0, depth: 0 };
    d.item()?;
    Ok(d.i)
}

/// Encode a byte-string (major 2, length < 256) — for test-synthetic
/// attestationObject.
pub fn bytes(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len() + 2);
    out.push(0x58); // bytes, length in the next byte
    out.push(b.len() as u8);
    out.extend_from_slice(b);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_cose_key() {
        // COSE ES256 key: {1:2, 3:-7, -1:1, -2:h'x', -3:h'y'} (small
        // args — one-byte headers)
        let mut b = vec![0xa5];
        b.extend_from_slice(&[0x01, 0x02]); // 1: 2 (EC2)
        b.extend_from_slice(&[0x03, 0x26]); // 3: -7 (ES256)
        b.extend_from_slice(&[0x20, 0x01]); // -1: 1 (P-256)
        b.extend_from_slice(&[0x21, 0x41, 0xaa]); // -2: bytes(1) aa
        b.extend_from_slice(&[0x22, 0x41, 0xbb]); // -3: bytes(1) bb
        let c = decode(&b).unwrap();
        assert_eq!(c.map_get(1).unwrap().as_u64(), Some(2));
        assert_eq!(c.map_get(3).unwrap().as_int(), Some(-7));
        assert_eq!(c.map_get(-1).unwrap().as_u64(), Some(1));
        assert_eq!(c.map_get(-2).unwrap().as_bytes(), Some(&[0xaa][..]));
        assert_eq!(c.map_get(-3).unwrap().as_bytes(), Some(&[0xbb][..]));
        assert!(c.map_get(9).is_none());
    }

    #[test]
    fn decode_nested_and_rejects() {
        // {"fmt":"none","attStmt":{},"authData":h'01 02'}
        let mut b = vec![0xa3];
        b.extend_from_slice(&[0x63, b'f', b'm', b't']); // text(3) "fmt"
        b.extend_from_slice(&[0x64, b'n', b'o', b'n', b'e']); // "none"
        b.extend_from_slice(&[0x67]); // text(7)
        b.extend_from_slice(b"attStmt");
        b.push(0xa0); // {}
        b.extend_from_slice(&[0x68]); // text(8)
        b.extend_from_slice(b"authData");
        b.extend_from_slice(&[0x42, 0x01, 0x02]); // bytes(2)
        let c = decode(&b).unwrap();
        assert_eq!(c.map_get_text("fmt").unwrap().as_text(), Some("none"));
        assert_eq!(
            c.map_get_text("authData").unwrap().as_bytes(),
            Some(&[0x01, 0x02][..])
        );
        assert!(c.map_get_text("missing").is_none());
        assert!(decode(&b[..b.len() - 1]).is_err(), "truncated");
        assert!(decode(&[0x1f]).is_err(), "indefinite forbidden");
    }

    #[test]
    fn uint_widths() {
        assert_eq!(decode(&[0x00]).unwrap(), Cbor::Uint(0));
        assert_eq!(decode(&[0x17]).unwrap(), Cbor::Uint(23));
        assert_eq!(decode(&[0x18, 0xff]).unwrap(), Cbor::Uint(255));
        assert_eq!(decode(&[0x19, 0x01, 0x00]).unwrap(), Cbor::Uint(256));
        assert_eq!(decode(&[0x1a, 0, 0, 0x01, 0x00]).unwrap(), Cbor::Uint(256));
        assert_eq!(
            decode(&[0x1b, 0, 0, 0, 0, 0, 0, 0, 1]).unwrap(),
            Cbor::Uint(1)
        );
        assert_eq!(decode(&[0x20]).unwrap(), Cbor::Nint(0)); // -1
        assert_eq!(decode(&[0x38, 0x63]).unwrap(), Cbor::Nint(99)); // -100
    }
}

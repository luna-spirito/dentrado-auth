//! Pure. Minimal JSON parser (std-only): Google/Bluesky egress responses,
//! WebAuthn clientDataJSON, JS responses of the web UI.
//!
//! Deliberately no serialization into a full type: outbound JSON is
//! written with small format!-helpers (quote/esc), inbound goes through
//! this parser. Numbers are f64: counters and codes fit, and the APIs
//! we use carry no real-valued fields.

#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Json::Num(n) => Some(*n),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }
    pub fn as_arr(&self) -> Option<&[Json]> {
        match self {
            Json::Arr(a) => Some(a),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------- parser

struct P<'a> {
    b: &'a [u8],
    i: usize,
    depth: u32,
}

const MAX_DEPTH: u32 = 32;

impl<'a> P<'a> {
    fn ws(&mut self) {
        while self.i < self.b.len() && self.b[self.i].is_ascii_whitespace() {
            self.i += 1;
        }
    }
    fn peek(&self) -> Result<u8, String> {
        self.b
            .get(self.i)
            .copied()
            .ok_or_else(|| "json: eof".into())
    }
    fn expect(&mut self, c: u8) -> Result<(), String> {
        if self.peek()? == c {
            self.i += 1;
            Ok(())
        } else {
            Err(format!("json: expected '{}' at {}", c as char, self.i))
        }
    }
    fn literal(&mut self, s: &str, v: Json) -> Result<Json, String> {
        if self.b[self.i..].starts_with(s.as_bytes()) {
            self.i += s.len();
            Ok(v)
        } else {
            Err(format!("json: bad literal at {}", self.i))
        }
    }
    fn string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let c = self.peek()?;
            self.i += 1;
            match c {
                b'"' => return Ok(out),
                b'\\' => {
                    let e = self.peek()?;
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let cp = self.hex4()?;
                            // Surrogate pairs: a high surrogate must be
                            // followed by a \u low surrogate and the two
                            // combine into one astral codepoint; a lone
                            // surrogate (either half) stays an error.
                            let ch = if (0xD800..=0xDBFF).contains(&cp) {
                                if self.b.get(self.i) != Some(&b'\\')
                                    || self.b.get(self.i + 1) != Some(&b'u')
                                {
                                    return Err("json: lone high surrogate".into());
                                }
                                self.i += 2;
                                let lo = self.hex4()?;
                                if !(0xDC00..=0xDFFF).contains(&lo) {
                                    return Err("json: lone high surrogate".into());
                                }
                                let c = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                                char::from_u32(c).ok_or("json: bad codepoint")?
                            } else if (0xDC00..=0xDFFF).contains(&cp) {
                                return Err("json: lone low surrogate".into());
                            } else {
                                char::from_u32(cp).ok_or("json: bad codepoint")?
                            };
                            out.push(ch);
                        }
                        _ => return Err("json: bad escape".into()),
                    }
                }
                _ if c < 0x20 => return Err("json: control char in string".into()),
                _ => {
                    // multibyte UTF-8 is copied as-is
                    let start = self.i - 1;
                    let len = utf8_len(c);
                    let end = start + len;
                    let s = self.b.get(start..end).ok_or("json: truncated utf-8")?;
                    out.push_str(std::str::from_utf8(s).map_err(|_| "json: bad utf-8")?);
                    self.i = end;
                }
            }
        }
    }
    /// Four hex digits of a \u escape.
    fn hex4(&mut self) -> Result<u32, String> {
        let h = self
            .b
            .get(self.i..self.i + 4)
            .ok_or("json: bad \\u escape")?;
        let s = std::str::from_utf8(h).map_err(|_| "json: bad \\u")?;
        let cp = u32::from_str_radix(s, 16).map_err(|_| "json: bad \\u hex")?;
        self.i += 4;
        Ok(cp)
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.i;
        while self.i < self.b.len()
            && matches!(
                self.b[self.i],
                b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E'
            )
        {
            self.i += 1;
        }
        let s = std::str::from_utf8(&self.b[start..self.i]).map_err(|_| "json: bad num")?;
        s.parse::<f64>()
            .map(Json::Num)
            .map_err(|_| "json: bad number".into())
    }
    fn value(&mut self) -> Result<Json, String> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err("json: too deep".into());
        }
        let v = match self.peek()? {
            b'{' => {
                self.i += 1;
                let mut m = Vec::new();
                self.ws();
                if self.peek()? == b'}' {
                    self.i += 1;
                } else {
                    loop {
                        self.ws();
                        let k = self.string()?;
                        self.ws();
                        self.expect(b':')?;
                        self.ws();
                        let v = self.value()?;
                        m.push((k, v));
                        self.ws();
                        match self.peek()? {
                            b',' => self.i += 1,
                            b'}' => {
                                self.i += 1;
                                break;
                            }
                            _ => return Err("json: expected ',' or '}'".into()),
                        }
                    }
                }
                Json::Obj(m)
            }
            b'[' => {
                self.i += 1;
                let mut a = Vec::new();
                self.ws();
                if self.peek()? == b']' {
                    self.i += 1;
                } else {
                    loop {
                        self.ws();
                        a.push(self.value()?);
                        self.ws();
                        match self.peek()? {
                            b',' => self.i += 1,
                            b']' => {
                                self.i += 1;
                                break;
                            }
                            _ => return Err("json: expected ',' or ']'".into()),
                        }
                    }
                }
                Json::Arr(a)
            }
            b'"' => Json::Str(self.string()?),
            b't' => self.literal("true", Json::Bool(true))?,
            b'f' => self.literal("false", Json::Bool(false))?,
            b'n' => self.literal("null", Json::Null)?,
            _ => self.number()?,
        };
        self.depth -= 1;
        Ok(v)
    }
}

fn utf8_len(first: u8) -> usize {
    match first {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        _ => 4,
    }
}

/// Parse the whole JSON document (trailing garbage is forbidden).
pub fn parse(s: &[u8]) -> Result<Json, String> {
    let mut p = P {
        b: s,
        i: 0,
        depth: 0,
    };
    p.ws();
    let v = p.value()?;
    p.ws();
    if p.i != p.b.len() {
        return Err("json: trailing garbage".into());
    }
    Ok(v)
}

// ---------------------------------------------------------------- writer

/// A JSON string in quotes, with escaping.
pub fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_objects_and_arrays() {
        let j = parse(br#"{"sub":"12345","verified":true,"n":42,"a":[1,2,{"k":"v"}],"nil":null}"#)
            .unwrap();
        assert_eq!(j.get("sub").unwrap().as_str(), Some("12345"));
        assert_eq!(j.get("verified"), Some(&Json::Bool(true)));
        assert_eq!(j.get("n").unwrap().as_f64(), Some(42.0));
        assert_eq!(j.get("a").unwrap().as_arr().unwrap().len(), 3);
        assert_eq!(
            j.get("a").unwrap().as_arr().unwrap()[2]
                .get("k")
                .unwrap()
                .as_str(),
            Some("v")
        );
        assert_eq!(j.get("nil"), Some(&Json::Null));
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(parse(b"{").is_err());
        assert!(parse(b"{}x").is_err());
        assert!(parse(br#"{"a":"b""#).is_err());
        assert!(parse(b"\"\\ud800\"").is_err(), "surrogate");
        assert!(parse(&[0xff, 0xfe]).is_err());
    }

    #[test]
    fn surrogate_pairs_decode() {
        // a proper pair combines into one astral codepoint
        assert_eq!(parse(br#""\ud83d\ude00""#).unwrap().as_str(), Some("😀"));
        // a lone low half is refused too
        assert!(parse(b"\"\\ude00\"").is_err());
        // a high half not followed by \u is refused
        assert!(parse(b"\"\\ud800x\"").is_err());
    }

    #[test]
    fn roundtrip_quote_and_utf8() {
        let j = parse(br#""a\"bA-\u00e9A""#).unwrap();
        assert_eq!(j.as_str(), Some("a\"bA-éA"));
        assert_eq!(
            parse(quote("x\"y\n€").as_bytes()).unwrap().as_str(),
            Some("x\"y\n€")
        );
    }

    #[test]
    fn depth_limit() {
        let deep = "[".repeat(64) + &"]".repeat(64);
        assert!(parse(deep.as_bytes()).is_err());
    }
}

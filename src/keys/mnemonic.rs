//! Pure. The BIP39 wordlist codec (public domain, `mnemonic_wordlist.txt`)
//! in two circuits:
//!
//! - **root phrase**: 24 words = 256 bits of entropy + 8 bits of sha256
//!   checksum (the BIP39 ENT/32 rule) — a third-party BIP39 decoder
//!   will extract the same bytes. A deviation from BIP39: no key
//!   derivation (no PBKDF2), the entropy IS the Ed25519 seed.
//! - **connect code**: 12 words = 128 bits of entropy + 4 checksum bits.
//!   This is a ONE-TIME admission code (not key material): a device
//!   redeems it to enroll ITS OWN fresh key into the account.
//!
//! The different lengths are structural domain separation: a root phrase
//! will not be taken for a connect code and vice versa (each decoder
//! requires its own word count).
//!
//! Only the root phrase is a key; session and account keys are random,
//! have no human-readable representation and must not have one.

use crate::crypto::sha256;

const WORDLIST: &str = include_str!("mnemonic_wordlist.txt");

fn to_bits(bytes: &[u8]) -> Vec<bool> {
    bytes
        .iter()
        .flat_map(|b| (0..8).map(|i| b & (1 << (7 - i)) != 0).collect::<Vec<_>>())
        .collect()
}

fn to_index(bits: &[bool]) -> usize {
    bits.iter().fold(0, |a, b| (a << 1) | *b as usize)
}

/// The common core: entropy + the first `n*11 - ent_bits` bits of sha256(entropy),
/// an MSB-first bit stream, 11 bits per word (the standard BIP39 layout).
fn encode_core(ent: &[u8], n_words: usize) -> String {
    let words: Vec<&str> = WORDLIST.lines().collect();
    let mut bits = to_bits(ent);
    bits.extend(to_bits(&sha256(ent))[..n_words * 11 - ent.len() * 8].iter());
    (0..n_words)
        .map(|i| words[to_index(&bits[i * 11..i * 11 + 11])])
        .collect::<Vec<_>>()
        .join(" ")
}

fn decode_core(
    phrase: &str,
    n_words: usize,
    ent_len: usize,
    what: &str,
) -> Result<Vec<u8>, String> {
    let words: Vec<&str> = WORDLIST.lines().collect();
    let toks: Vec<&str> = phrase.split_whitespace().collect();
    if toks.len() != n_words {
        return Err(format!(
            "{what}: expected {n_words} words, got {}",
            toks.len()
        ));
    }
    let mut bits = Vec::with_capacity(n_words * 11);
    for t in &toks {
        let i = words
            .binary_search(t)
            .map_err(|_| format!("{what}: unknown word {t:?}"))?;
        bits.extend((0..11).map(|b| (i >> (10 - b)) & 1 == 1));
    }
    let ent_bits = ent_len * 8;
    let mut ent = vec![0u8; ent_len];
    for (b, bit) in bits[..ent_bits].iter().enumerate() {
        ent[b / 8] |= (*bit as u8) << (7 - b % 8);
    }
    if to_index(&bits[ent_bits..]) != (sha256(&ent)[0] >> (8 - (n_words * 11 - ent_bits))) as usize
    {
        return Err(format!("{what}: checksum mismatch (typo in a word?)"));
    }
    Ok(ent)
}

/// 24 words for a seed. Whoever holds the phrase holds the key.
pub fn encode(seed: &[u8; 32]) -> String {
    encode_core(seed, 24)
}

/// The inverse: 24 words (any letter case and line breaking).
/// An unknown word, a wrong count or a broken checksum (a
/// typo) is an error.
pub fn decode(phrase: &str) -> Result<[u8; 32], String> {
    let v = decode_core(phrase, 24, 32, "seed-phrase")?;
    Ok(v.try_into().expect("32 bytes"))
}

/// 12 words for a one-time connect code (128 bits of entropy).
pub fn encode128(ent: &[u8; 16]) -> String {
    encode_core(ent, 12)
}

/// The inverse for a connect code: exactly 12 words, the checksum
/// is mandatory. NOT a key — only an admission ticket for a new key
/// to join the account.
pub fn decode128(phrase: &str) -> Result<[u8; 16], String> {
    let v = decode_core(phrase, 12, 16, "connect-code")?;
    Ok(v.try_into().expect("16 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random_arr;

    /// Vectors cross-checked against an independent BIP39 implementation (python).
    #[test]
    fn known_vectors() {
        let zero = [0u8; 32];
        assert_eq!(encode(&zero), format!("{}art", "abandon ".repeat(23)));
        let seq: [u8; 32] = core::array::from_fn(|i| i as u8);
        assert_eq!(
            encode(&seq),
            "abandon amount liar amount expire adjust cage candy arch gather \
             drum bullet absurd math era live bid rhythm alien crouch range \
             attend journey unaware"
        );
    }

    #[test]
    fn known_vectors_128() {
        let zero = [0u8; 16];
        assert_eq!(encode128(&zero), format!("{}about", "abandon ".repeat(11)));
        let max = [0x7fu8; 16];
        assert_eq!(
            encode128(&max),
            "legal winner thank year wave sausage worth useful legal winner thank yellow"
        );
    }

    #[test]
    fn roundtrip_and_rejects() {
        let seed = random_arr::<32>();
        let p = encode(&seed);
        assert_eq!(decode(&p).unwrap(), seed);
        assert_eq!(
            decode(&format!("  \n{p}\n")).unwrap(),
            seed,
            "whitespace is free"
        );

        let corrupt = format!("{}zoo", "abandon ".repeat(23));
        assert!(decode(&corrupt).is_err(), "checksum catches a wrong word");

        let mut ws: Vec<&str> = p.split(' ').collect();
        ws[0] = "notaword";
        assert!(decode(&ws.join(" ")).is_err(), "unknown word rejected");
        ws[0] = "abandon";
        ws.pop();
        assert!(decode(&ws.join(" ")).is_err(), "23 words rejected");
    }

    #[test]
    fn roundtrip_and_rejects_128() {
        let ent = random_arr::<16>();
        let p = encode128(&ent);
        assert_eq!(decode128(&p).unwrap(), ent);

        // A single wrong word has a 1/16 chance of a checksum collision;
        // scan the list so the assertion is deterministic.
        let caught = WORDLIST.lines().any(|w| {
            let mut ws: Vec<&str> = p.split(' ').collect();
            ws[3] = w;
            decode128(&ws.join(" ")).is_err()
        });
        assert!(caught, "checksum catches a wrong word");

        let mut ws: Vec<&str> = p.split(' ').collect();
        ws.pop();
        assert!(decode128(&ws.join(" ")).is_err(), "11 words rejected");

        // domain separation: the circuits do not mix
        assert!(
            decode128(&encode(&random_arr::<32>())).is_err(),
            "24-word root phrase is not a connect code"
        );
        assert!(
            decode(&encode128(&ent)).is_err(),
            "12-word connect code is not a root phrase"
        );
    }

    #[test]
    fn wordlist_canonical_shape() {
        let w: Vec<&str> = WORDLIST.lines().collect();
        assert_eq!(w.len(), 2048);
        assert!(w.windows(2).all(|p| p[0] < p[1]), "sorted and unique");
        assert_eq!(w.first(), Some(&"abandon"));
        assert_eq!(w.last(), Some(&"zoo"));
    }
}

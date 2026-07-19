//! Deterministic CBOR (RFC 8949 §4.2 / DMTAP §18.1.1) for the Sync substrate.
//!
//! ## Why a value type of its own, rather than `dmtap_core::cbor::Cv`
//!
//! Core's [`Cv`](dmtap_core::cbor::Cv) is the §18 *mail-object* wire subset, and that subset
//! deliberately admits **only unsigned integers** ("DMTAP uses only unsigned integers on the
//! wire"). The Sync substrate's `cv = ext-value` (`SYNC.md` §4.1, §18.3.6) additionally admits
//! **negative** integers — a PN-counter delta of `−2` is the canonical case (`SYNC-PN-01` encodes
//! it as the major-type-1 head `0x21`), and an LWW register may legitimately hold a negative
//! scalar. Encoding a sync op through a codec that cannot represent a negative integer would
//! either lose the vector or force a lossy re-spelling, so this module carries the *same*
//! canonical rules over a value type that spans the whole `ext-value` domain.
//!
//! The rules enforced here are exactly §18.1.1's, and this codec is strict in **both** directions:
//! it only ever *emits* canonical bytes, and it **rejects** on decode (fail closed, never
//! re-canonicalize silently) any of:
//!
//! 1. non-shortest-form integer or length heads,
//! 2. indefinite-length strings/arrays/maps,
//! 3. floats, tags, `null`, `undefined`, or any other simple value than `true`/`false`,
//! 4. map keys that are not unsigned integers, or that are unsorted or duplicated,
//! 5. trailing bytes after a complete top-level item.

use std::fmt;

/// A deterministic-CBOR value in the Sync substrate's domain: the §18.3.6 `ext-value` subset
/// (text, byte strings, unsigned **and negative** integers, booleans, and arrays thereof) plus the
/// integer-keyed maps every `SyncOp`/`Hlc`/`AddTag`/`OpRef` object is built from.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SVal {
    /// Unsigned integer (major type 0).
    Uint(u64),
    /// Negative integer (major type 1). The held value is the CBOR *argument* `n`, encoding the
    /// number `−1 − n`, so the full 64-bit negative range is representable without an `i128`.
    Nint(u64),
    /// Byte string (major type 2).
    Bytes(Vec<u8>),
    /// UTF-8 text string (major type 3).
    Text(String),
    /// Boolean (major type 7, `0xf4`/`0xf5`).
    Bool(bool),
    /// Definite-length array (major type 4).
    Array(Vec<SVal>),
    /// Integer-keyed, ascending-sorted map (major type 5) — the DMTAP object encoding (§18.1.2).
    Map(Vec<(u64, SVal)>),
    /// Byte-string-keyed map (major type 5), sorted ascending by **encoded key**. The substrate
    /// needs exactly one of these: the §5.1 `VersionVector = { * ik-pub => Hlc }`, whose keys are
    /// author public keys rather than schema labels. It is deliberately NOT admitted as a `cv`
    /// ([`is_ext_value`](SVal::is_ext_value) rejects every map), so it can only ever appear where a
    /// schema names it.
    BytesMap(Vec<(Vec<u8>, SVal)>),
}

impl SVal {
    /// A signed integer as its canonical CBOR value (`i64` covers every value the substrate mints;
    /// counters and deltas are §4.6 scalars).
    pub fn int(v: i64) -> SVal {
        if v < 0 {
            // −1 − n = v  ⇒  n = −1 − v, computed without overflowing at i64::MIN.
            SVal::Nint((-(v as i128) - 1) as u64)
        } else {
            SVal::Uint(v as u64)
        }
    }

    /// The signed value of an integer node, or `None` for a non-integer / out-of-`i64` value.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            SVal::Uint(u) => i64::try_from(*u).ok(),
            SVal::Nint(n) => i64::try_from(-1i128 - (*n as i128)).ok(),
            _ => None,
        }
    }

    /// The text of a `Text` node.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            SVal::Text(t) => Some(t),
            _ => None,
        }
    }

    /// The bytes of a `Bytes` node.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            SVal::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// The elements of an `Array` node.
    pub fn as_array(&self) -> Option<&[SVal]> {
        match self {
            SVal::Array(a) => Some(a),
            _ => None,
        }
    }

    /// Whether this value is a legal §4.1 `cv` (`ext-value`, §18.3.6): a text/byte string, an
    /// integer of either sign, a boolean, or a **homogeneous** array of those. Integer-keyed maps
    /// (which could smuggle a whole object into a value slot) and everything outside the subset are
    /// excluded, so a value can never carry an un-canonicalizable or ambiguous encoding.
    pub fn is_ext_value(&self) -> bool {
        match self {
            SVal::Uint(_) | SVal::Nint(_) | SVal::Bytes(_) | SVal::Text(_) | SVal::Bool(_) => true,
            SVal::Map(_) | SVal::BytesMap(_) => false,
            SVal::Array(items) => {
                if !items.iter().all(SVal::is_ext_value) {
                    return false;
                }
                // Homogeneous: every element shares the first element's major type.
                let mut it = items.iter();
                match it.next() {
                    None => true,
                    Some(first) => it.all(|v| major(v) == major(first)),
                }
            }
        }
    }

    /// This value's canonical encoding — the byte string every §2.2 "larger `det_cbor(value)`
    /// wins" tiebreak and every §6.1.1 section sort compares.
    pub fn det_cbor(&self) -> Vec<u8> {
        encode(self)
    }
}

fn major(v: &SVal) -> u8 {
    match v {
        SVal::Uint(_) => 0,
        SVal::Nint(_) => 1,
        SVal::Bytes(_) => 2,
        SVal::Text(_) => 3,
        SVal::Array(_) => 4,
        SVal::Map(_) | SVal::BytesMap(_) => 5,
        SVal::Bool(_) => 7,
    }
}

/// A canonical-CBOR decode failure. Every variant is a **refusal**: the substrate never guesses at
/// a non-canonical encoding, because two replicas that disagree about how to re-canonicalize the
/// same bytes would diverge (`SYNC.md` §11 item 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetCborError {
    /// Truncated or structurally malformed input.
    Malformed,
    /// A non-shortest-form integer or length head (§18.1.1 rule 1).
    NonShortestForm,
    /// An indefinite-length string, array, or map (§18.1.1 rule 4).
    IndefiniteLength,
    /// A float, tag, `null`, `undefined`, or an unsupported major type (§18.1.1 rule 5).
    UnsupportedType,
    /// A map key that is not an unsigned integer (§18.1.2).
    NonIntegerKey,
    /// Map keys that are not in strictly ascending order (unsorted, or duplicated).
    UnsortedKeys,
    /// Bytes remaining after a complete top-level item.
    TrailingBytes,
    /// A text string that is not valid UTF-8.
    InvalidUtf8,
}

impl fmt::Display for DetCborError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            DetCborError::Malformed => "malformed CBOR",
            DetCborError::NonShortestForm => "non-shortest-form integer/length (§18.1.1)",
            DetCborError::IndefiniteLength => "indefinite-length item (§18.1.1)",
            DetCborError::UnsupportedType => "float/tag/null/undefined or unsupported major type",
            DetCborError::NonIntegerKey => "non-integer map key (§18.1.2)",
            DetCborError::UnsortedKeys => "unsorted or duplicate map keys (§18.1.1)",
            DetCborError::TrailingBytes => "trailing bytes after top-level item",
            DetCborError::InvalidUtf8 => "invalid UTF-8 in a text string",
        };
        f.write_str(s)
    }
}

impl std::error::Error for DetCborError {}

// --- encoding -------------------------------------------------------------------------------

fn put_head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let m = major << 5;
    match arg {
        0..=23 => out.push(m | arg as u8),
        24..=0xff => {
            out.push(m | 24);
            out.push(arg as u8);
        }
        0x100..=0xffff => {
            out.push(m | 25);
            out.extend_from_slice(&(arg as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(m | 26);
            out.extend_from_slice(&(arg as u32).to_be_bytes());
        }
        _ => {
            out.push(m | 27);
            out.extend_from_slice(&arg.to_be_bytes());
        }
    }
}

/// Encode `v` as canonical deterministic CBOR. Map entries are emitted in ascending key order
/// regardless of the order they appear in the `Map` vector, so an encoder can never leak a
/// construction-order dependency into the bytes.
pub fn encode(v: &SVal) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(v, &mut out);
    out
}

fn encode_into(v: &SVal, out: &mut Vec<u8>) {
    match v {
        SVal::Uint(u) => put_head(out, 0, *u),
        SVal::Nint(n) => put_head(out, 1, *n),
        SVal::Bytes(b) => {
            put_head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        SVal::Text(t) => {
            put_head(out, 3, t.len() as u64);
            out.extend_from_slice(t.as_bytes());
        }
        SVal::Array(items) => {
            put_head(out, 4, items.len() as u64);
            for i in items {
                encode_into(i, out);
            }
        }
        SVal::Map(entries) => {
            let mut sorted: Vec<&(u64, SVal)> = entries.iter().collect();
            sorted.sort_by_key(|(k, _)| *k);
            put_head(out, 5, sorted.len() as u64);
            for (k, val) in sorted {
                put_head(out, 0, *k);
                encode_into(val, out);
            }
        }
        SVal::BytesMap(entries) => {
            // Keys are sorted by their ENCODED bytes (RFC 8949 §4.2.1): for byte strings of the
            // same length — which author keys always are — that is plain lexicographic order.
            let mut sorted: Vec<&(Vec<u8>, SVal)> = entries.iter().collect();
            sorted.sort_by(|(a, _), (b, _)| {
                (a.len(), a.as_slice()).cmp(&(b.len(), b.as_slice()))
            });
            put_head(out, 5, sorted.len() as u64);
            for (k, val) in sorted {
                put_head(out, 2, k.len() as u64);
                out.extend_from_slice(k);
                encode_into(val, out);
            }
        }
        SVal::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
    }
}

// --- decoding -------------------------------------------------------------------------------

/// Decode a single canonical-CBOR item from `bytes`, **rejecting** any non-canonical encoding and
/// any trailing byte (fail closed, §18.1.1).
pub fn decode(bytes: &[u8]) -> Result<SVal, DetCborError> {
    let mut p = Parser { b: bytes, i: 0 };
    let v = p.item()?;
    if p.i != bytes.len() {
        return Err(DetCborError::TrailingBytes);
    }
    Ok(v)
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn byte(&mut self) -> Result<u8, DetCborError> {
        let b = *self.b.get(self.i).ok_or(DetCborError::Malformed)?;
        self.i += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DetCborError> {
        let end = self.i.checked_add(n).ok_or(DetCborError::Malformed)?;
        let s = self.b.get(self.i..end).ok_or(DetCborError::Malformed)?;
        self.i = end;
        Ok(s)
    }

    /// Read a major type + its argument, enforcing shortest-form and rejecting indefinite lengths.
    fn head(&mut self) -> Result<(u8, u64), DetCborError> {
        let ib = self.byte()?;
        let major = ib >> 5;
        let ai = ib & 0x1f;
        let arg = match ai {
            0..=23 => ai as u64,
            24 => {
                let v = self.byte()? as u64;
                if v < 24 {
                    return Err(DetCborError::NonShortestForm);
                }
                v
            }
            25 => {
                let s = self.take(2)?;
                let v = u16::from_be_bytes([s[0], s[1]]) as u64;
                if v <= 0xff {
                    return Err(DetCborError::NonShortestForm);
                }
                v
            }
            26 => {
                let s = self.take(4)?;
                let v = u32::from_be_bytes([s[0], s[1], s[2], s[3]]) as u64;
                if v <= 0xffff {
                    return Err(DetCborError::NonShortestForm);
                }
                v
            }
            27 => {
                let s = self.take(8)?;
                let v = u64::from_be_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]);
                if v <= 0xffff_ffff {
                    return Err(DetCborError::NonShortestForm);
                }
                v
            }
            31 => return Err(DetCborError::IndefiniteLength),
            _ => return Err(DetCborError::Malformed),
        };
        Ok((major, arg))
    }

    fn item(&mut self) -> Result<SVal, DetCborError> {
        let start = self.i;
        let ib = *self.b.get(start).ok_or(DetCborError::Malformed)?;
        // Major type 7 is handled before the generic head reader: only the two boolean simple
        // values are admitted; floats (0xf9..0xfb), null (0xf6), undefined (0xf7) and every other
        // simple value are refused outright.
        if ib >> 5 == 7 {
            self.i += 1;
            return match ib {
                0xf4 => Ok(SVal::Bool(false)),
                0xf5 => Ok(SVal::Bool(true)),
                _ => Err(DetCborError::UnsupportedType),
            };
        }
        let (major, arg) = self.head()?;
        match major {
            0 => Ok(SVal::Uint(arg)),
            1 => Ok(SVal::Nint(arg)),
            2 => {
                let n = usize::try_from(arg).map_err(|_| DetCborError::Malformed)?;
                Ok(SVal::Bytes(self.take(n)?.to_vec()))
            }
            3 => {
                let n = usize::try_from(arg).map_err(|_| DetCborError::Malformed)?;
                let s = self.take(n)?;
                Ok(SVal::Text(
                    std::str::from_utf8(s).map_err(|_| DetCborError::InvalidUtf8)?.to_owned(),
                ))
            }
            4 => {
                let n = usize::try_from(arg).map_err(|_| DetCborError::Malformed)?;
                let mut items = Vec::with_capacity(n.min(1024));
                for _ in 0..n {
                    items.push(self.item()?);
                }
                Ok(SVal::Array(items))
            }
            5 => {
                let n = usize::try_from(arg).map_err(|_| DetCborError::Malformed)?;
                // A map's keys are homogeneous: either all unsigned integers (a DMTAP object) or
                // all byte strings (a §5.1 VersionVector). A mixed-key map is refused.
                let mut int_entries: Vec<(u64, SVal)> = Vec::new();
                let mut bytes_entries: Vec<(Vec<u8>, SVal)> = Vec::new();
                for i in 0..n {
                    let (kmajor, karg) = self.head()?;
                    match kmajor {
                        0 => {
                            if i > 0 && !bytes_entries.is_empty() {
                                return Err(DetCborError::NonIntegerKey);
                            }
                            if let Some((prev, _)) = int_entries.last() {
                                if karg <= *prev {
                                    return Err(DetCborError::UnsortedKeys);
                                }
                            }
                            let val = self.item()?;
                            int_entries.push((karg, val));
                        }
                        2 => {
                            if i > 0 && !int_entries.is_empty() {
                                return Err(DetCborError::NonIntegerKey);
                            }
                            let len = usize::try_from(karg).map_err(|_| DetCborError::Malformed)?;
                            let key = self.take(len)?.to_vec();
                            if let Some((prev, _)) = bytes_entries.last() {
                                if (key.len(), key.as_slice()) <= (prev.len(), prev.as_slice()) {
                                    return Err(DetCborError::UnsortedKeys);
                                }
                            }
                            let val = self.item()?;
                            bytes_entries.push((key, val));
                        }
                        _ => return Err(DetCborError::NonIntegerKey),
                    }
                }
                if bytes_entries.is_empty() {
                    Ok(SVal::Map(int_entries))
                } else {
                    Ok(SVal::BytesMap(bytes_entries))
                }
            }
            6 => Err(DetCborError::UnsupportedType), // tags
            _ => Err(DetCborError::UnsupportedType),
        }
    }
}

/// Field-taking helper over a decoded integer-keyed map: takes required/optional keys and then
/// **denies any unknown key** — the §18.1.2 fail-closed rule for signed objects.
pub struct Fields {
    entries: Vec<(u64, SVal)>,
}

impl Fields {
    /// Wrap a decoded map (fails if `cv` is not a map).
    pub fn new(cv: SVal) -> Result<Self, DetCborError> {
        match cv {
            SVal::Map(entries) => Ok(Fields { entries }),
            _ => Err(DetCborError::Malformed),
        }
    }

    /// Remove and return the value at `k`, if present.
    pub fn take(&mut self, k: u64) -> Option<SVal> {
        let pos = self.entries.iter().position(|(key, _)| *key == k)?;
        Some(self.entries.remove(pos).1)
    }

    /// Remove and return a required key, failing closed when absent.
    pub fn req(&mut self, k: u64) -> Result<SVal, DetCborError> {
        self.take(k).ok_or(DetCborError::Malformed)
    }

    /// Fail if any key was not consumed (unknown-key rejection).
    pub fn deny_unknown(&self) -> Result<(), DetCborError> {
        if self.entries.is_empty() {
            Ok(())
        } else {
            Err(DetCborError::Malformed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn negative_integers_round_trip() {
        assert_eq!(hex(&encode(&SVal::int(-2))), "21");
        assert_eq!(hex(&encode(&SVal::int(-8))), "27");
        assert_eq!(SVal::int(-2).as_int(), Some(-2));
        assert_eq!(decode(&[0x21]).unwrap(), SVal::int(-2));
        assert_eq!(SVal::int(i64::MIN).as_int(), Some(i64::MIN));
    }

    #[test]
    fn maps_encode_ascending_regardless_of_construction_order() {
        let a = SVal::Map(vec![(4, SVal::Uint(1)), (1, SVal::Uint(0))]);
        let b = SVal::Map(vec![(1, SVal::Uint(0)), (4, SVal::Uint(1))]);
        assert_eq!(encode(&a), encode(&b));
        assert_eq!(hex(&encode(&a)), "a2010004 01".replace(' ', ""));
    }

    #[test]
    fn rejects_non_canonical_and_forbidden_encodings() {
        assert_eq!(decode(&[0x18, 0x01]), Err(DetCborError::NonShortestForm));
        assert_eq!(decode(&[0x19, 0x00, 0x01]), Err(DetCborError::NonShortestForm));
        assert_eq!(decode(&[0x5f, 0xff]), Err(DetCborError::IndefiniteLength));
        assert_eq!(decode(&[0xf6]), Err(DetCborError::UnsupportedType)); // null
        assert_eq!(decode(&[0xfb, 0, 0, 0, 0, 0, 0, 0, 0]), Err(DetCborError::UnsupportedType));
        assert_eq!(decode(&[0xc0, 0x01]), Err(DetCborError::UnsupportedType)); // tag
        // unsorted map keys {4:0, 1:0}
        assert_eq!(decode(&[0xa2, 0x04, 0x00, 0x01, 0x00]), Err(DetCborError::UnsortedKeys));
        // duplicate map keys
        assert_eq!(decode(&[0xa2, 0x01, 0x00, 0x01, 0x00]), Err(DetCborError::UnsortedKeys));
        // text key
        assert_eq!(decode(&[0xa1, 0x61, 0x61, 0x00]), Err(DetCborError::NonIntegerKey));
        assert_eq!(decode(&[0x00, 0x00]), Err(DetCborError::TrailingBytes));
    }

    #[test]
    fn ext_value_subset() {
        assert!(SVal::Text("v".into()).is_ext_value());
        assert!(SVal::int(-9).is_ext_value());
        assert!(SVal::Array(vec![SVal::Uint(1), SVal::Uint(2)]).is_ext_value());
        assert!(!SVal::Array(vec![SVal::Uint(1), SVal::Text("a".into())]).is_ext_value());
        assert!(!SVal::Map(vec![(1, SVal::Uint(1))]).is_ext_value());
    }
}

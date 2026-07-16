//! Canonical deterministic CBOR — spec §18.1.1 / §18.1.2.
//!
//! DMTAP wire objects are **integer-keyed** CBOR maps (COSE/CWT style, §18.1.2) encoded with
//! RFC 8949 Core Deterministic Encoding (§18.1.1). This module is the single canonical codec:
//! serde/`ciborium`-derived encodings are **text-keyed** (struct field names) and MUST NOT be
//! used on the wire — a second implementer following §18 would produce different bytes, so the
//! conformance vectors would validate the code only against itself. Everything the reference
//! serializes for the wire, signs, or content-addresses flows through [`encode`]/[`decode`].
//!
//! ## Encoding rules enforced here (§18.1.1)
//! 1. Shortest-form integers / lengths / counts (RFC 8949 §4.2.1); no indefinite-length items.
//! 2. Map keys sorted by their **encoded bytes**, ascending (for the small unsigned keys used
//!    everywhere this equals numeric key order).
//! 3. No duplicate keys (rejected on decode).
//! 4. No floating-point values anywhere.
//! 5. No NaN/Infinity, no tags, no `undefined`; and no `null` on the wire (an absent optional is
//!    simply omitted from the map, never present as `null`).

use std::collections::BTreeSet;

/// A canonical CBOR value restricted to the DMTAP wire subset (§18.1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cv {
    /// Unsigned integer (major type 0). DMTAP uses only unsigned integers on the wire.
    U64(u64),
    /// Byte string (major type 2).
    Bytes(Vec<u8>),
    /// UTF-8 text string (major type 3).
    Text(String),
    /// Boolean (major type 7, `0xf4`/`0xf5`) — admitted only where a rule allows `bool`.
    Bool(bool),
    /// Definite-length array (major type 4).
    Array(Vec<Cv>),
    /// Integer-keyed map (major type 5) — the DMTAP object encoding (§18.1.2).
    Map(Vec<(u64, Cv)>),
    /// Text-keyed map (major type 5) — the **only** place text keys are admitted:
    /// `Headers.ext` (§18.3.6). Values are still restricted to this `Cv` subset.
    TextMap(Vec<(String, Cv)>),
}

/// Errors from decoding / validating canonical CBOR (fail closed, §18.1.1).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CborError {
    #[error("malformed CBOR")]
    Malformed,
    #[error("floating-point value is forbidden on the DMTAP wire (§18.1.1 rule 4)")]
    FloatPresent,
    #[error("CBOR null is forbidden on the wire — absent optionals are omitted (§18.1.1)")]
    NullPresent,
    #[error("CBOR tag / undefined is forbidden on the DMTAP wire (§18.1.1 rule 5)")]
    TagOrUndefined,
    #[error("duplicate map key {0} (§18.1.1 rule 3)")]
    DuplicateKey(u64),
    #[error("duplicate text map key")]
    DuplicateTextKey,
    #[error("map mixes integer and text keys")]
    MixedMapKeys,
    #[error("negative or out-of-range integer")]
    IntRange,
    #[error("unexpected CBOR type for this field")]
    TypeMismatch,
    #[error("unknown key {0} in a signed object (fail closed, §18.1.2)")]
    UnknownKey(u64),
    #[error("missing required key {0}")]
    MissingKey(u64),
    #[error("Manifest carries forbidden key 5 (ERR_MANIFEST_KEY_PRESENT, §18.3.8)")]
    ManifestKeyPresent,
    #[error("unsupported / unknown algorithm suite byte {0:#04x} (fail closed)")]
    UnknownSuite(u8),
    #[error("unknown enum discriminator {0}")]
    UnknownDiscriminant(u64),
}

// ── Encoding ───────────────────────────────────────────────────────────────────────────────

/// Write a CBOR head: major type (top 3 bits) + shortest-form argument (§18.1.1 rule 1).
fn write_head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let m = major << 5;
    if arg < 24 {
        out.push(m | arg as u8);
    } else if arg <= u8::MAX as u64 {
        out.push(m | 24);
        out.push(arg as u8);
    } else if arg <= u16::MAX as u64 {
        out.push(m | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg <= u32::MAX as u64 {
        out.push(m | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

/// Encode a [`Cv`] as deterministic CBOR (§18.1.1). Infallible: `Cv` cannot hold a forbidden value.
pub fn encode(v: &Cv) -> Vec<u8> {
    let mut out = Vec::new();
    enc(v, &mut out);
    out
}

fn enc(v: &Cv, out: &mut Vec<u8>) {
    match v {
        Cv::U64(n) => write_head(out, 0, *n),
        Cv::Bytes(b) => {
            write_head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Cv::Text(s) => {
            write_head(out, 3, s.len() as u64);
            out.extend_from_slice(s.as_bytes());
        }
        Cv::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
        Cv::Array(a) => {
            write_head(out, 4, a.len() as u64);
            for e in a {
                enc(e, out);
            }
        }
        Cv::Map(m) => {
            // Sort by the *encoded key bytes*, ascending (§18.1.1 rule 2). For the shortest-form
            // unsigned keys used throughout DMTAP this is identical to numeric key order.
            let mut items: Vec<(Vec<u8>, &Cv)> = m
                .iter()
                .map(|(k, val)| {
                    let mut kb = Vec::new();
                    write_head(&mut kb, 0, *k);
                    (kb, val)
                })
                .collect();
            items.sort_by(|a, b| a.0.cmp(&b.0));
            write_head(out, 5, items.len() as u64);
            for (kb, val) in items {
                out.extend_from_slice(&kb);
                enc(val, out);
            }
        }
        Cv::TextMap(m) => {
            let mut items: Vec<(Vec<u8>, &Cv)> = m
                .iter()
                .map(|(k, val)| {
                    let mut kb = Vec::new();
                    write_head(&mut kb, 3, k.len() as u64);
                    kb.extend_from_slice(k.as_bytes());
                    (kb, val)
                })
                .collect();
            items.sort_by(|a, b| a.0.cmp(&b.0));
            write_head(out, 5, items.len() as u64);
            for (kb, val) in items {
                out.extend_from_slice(&kb);
                enc(val, out);
            }
        }
    }
}

// ── Decoding ───────────────────────────────────────────────────────────────────────────────

/// Parse and validate canonical CBOR into a [`Cv`], **failing closed** on any value outside the
/// DMTAP wire subset: floats, NaN/Infinity, tags, `undefined`, `null`, negative integers, and
/// duplicate map keys are all rejected here (§18.1.1). Higher layers additionally reject unknown
/// keys in *signed* objects (§18.1.2).
pub fn decode(bytes: &[u8]) -> Result<Cv, CborError> {
    let value: ciborium::value::Value =
        ciborium::de::from_reader(bytes).map_err(|_| CborError::Malformed)?;
    from_value(&value)
}

fn from_value(v: &ciborium::value::Value) -> Result<Cv, CborError> {
    use ciborium::value::Value as V;
    match v {
        V::Integer(i) => {
            let n: i128 = (*i).into();
            if n < 0 || n > u64::MAX as i128 {
                return Err(CborError::IntRange);
            }
            Ok(Cv::U64(n as u64))
        }
        V::Bytes(b) => Ok(Cv::Bytes(b.clone())),
        V::Text(s) => Ok(Cv::Text(s.clone())),
        V::Bool(b) => Ok(Cv::Bool(*b)),
        V::Float(_) => Err(CborError::FloatPresent),
        V::Null => Err(CborError::NullPresent),
        V::Tag(..) => Err(CborError::TagOrUndefined),
        V::Array(a) => Ok(Cv::Array(a.iter().map(from_value).collect::<Result<_, _>>()?)),
        V::Map(m) => from_map(m),
        // `Value` is not marked non-exhaustive in this version; a future variant would land here.
        #[allow(unreachable_patterns)]
        _ => Err(CborError::TagOrUndefined),
    }
}

fn from_map(m: &[(ciborium::value::Value, ciborium::value::Value)]) -> Result<Cv, CborError> {
    use ciborium::value::Value as V;
    if m.is_empty() {
        return Ok(Cv::Map(Vec::new()));
    }
    let all_int = m.iter().all(|(k, _)| matches!(k, V::Integer(_)));
    let all_text = m.iter().all(|(k, _)| matches!(k, V::Text(_)));
    if all_int {
        let mut seen = BTreeSet::new();
        let mut out = Vec::with_capacity(m.len());
        for (k, val) in m {
            let key: i128 = match k {
                V::Integer(i) => (*i).into(),
                _ => unreachable!(),
            };
            if key < 0 || key > u64::MAX as i128 {
                return Err(CborError::IntRange);
            }
            let key = key as u64;
            if !seen.insert(key) {
                return Err(CborError::DuplicateKey(key));
            }
            out.push((key, from_value(val)?));
        }
        Ok(Cv::Map(out))
    } else if all_text {
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut out = Vec::with_capacity(m.len());
        for (k, val) in m {
            let key = match k {
                V::Text(s) => s.clone(),
                _ => unreachable!(),
            };
            if !seen.insert(key.clone()) {
                return Err(CborError::DuplicateTextKey);
            }
            out.push((key, from_value(val)?));
        }
        Ok(Cv::TextMap(out))
    } else {
        Err(CborError::MixedMapKeys)
    }
}

// ── Field extraction helpers ─────────────────────────────────────────────────────────────────

/// A consuming reader over an integer-keyed map, used by every object's decoder. Take the keys
/// you know, then call [`Fields::deny_unknown`] on a **signed** object so any leftover key fails
/// closed (§18.1.2).
pub struct Fields {
    map: Vec<(u64, Cv)>,
}

impl Fields {
    /// Wrap a decoded map (expects [`Cv::Map`]).
    pub fn from_cv(cv: Cv) -> Result<Self, CborError> {
        match cv {
            Cv::Map(map) => Ok(Fields { map }),
            _ => Err(CborError::TypeMismatch),
        }
    }

    /// Whether key `k` is present (without removing it).
    pub fn has(&self, k: u64) -> bool {
        self.map.iter().any(|(kk, _)| *kk == k)
    }

    /// Remove and return the value at key `k`, if present.
    pub fn take(&mut self, k: u64) -> Option<Cv> {
        self.map
            .iter()
            .position(|(kk, _)| *kk == k)
            .map(|pos| self.map.remove(pos).1)
    }

    /// Remove and return the value at required key `k`, or [`CborError::MissingKey`].
    pub fn req(&mut self, k: u64) -> Result<Cv, CborError> {
        self.take(k).ok_or(CborError::MissingKey(k))
    }

    /// Consume the reader, yielding every remaining `(key, value)` pair (for maps whose keys are
    /// data, e.g. `Identity.iks`, rather than a fixed schema).
    pub fn into_pairs(self) -> Vec<(u64, Cv)> {
        self.map
    }

    /// After taking every recognized key, reject any that remain (signed-object rule, §18.1.2).
    pub fn deny_unknown(&self) -> Result<(), CborError> {
        match self.map.first() {
            Some((k, _)) => Err(CborError::UnknownKey(*k)),
            None => Ok(()),
        }
    }
}

// Coercions from `Cv` to concrete types (fail closed on the wrong CBOR type).

pub fn as_u64(cv: Cv) -> Result<u64, CborError> {
    match cv {
        Cv::U64(n) => Ok(n),
        _ => Err(CborError::TypeMismatch),
    }
}

pub fn as_u8(cv: Cv) -> Result<u8, CborError> {
    let n = as_u64(cv)?;
    u8::try_from(n).map_err(|_| CborError::IntRange)
}

pub fn as_u32(cv: Cv) -> Result<u32, CborError> {
    let n = as_u64(cv)?;
    u32::try_from(n).map_err(|_| CborError::IntRange)
}

pub fn as_bytes(cv: Cv) -> Result<Vec<u8>, CborError> {
    match cv {
        Cv::Bytes(b) => Ok(b),
        _ => Err(CborError::TypeMismatch),
    }
}

pub fn as_text(cv: Cv) -> Result<String, CborError> {
    match cv {
        Cv::Text(s) => Ok(s),
        _ => Err(CborError::TypeMismatch),
    }
}

pub fn as_bool(cv: Cv) -> Result<bool, CborError> {
    match cv {
        Cv::Bool(b) => Ok(b),
        _ => Err(CborError::TypeMismatch),
    }
}

pub fn as_array(cv: Cv) -> Result<Vec<Cv>, CborError> {
    match cv {
        Cv::Array(a) => Ok(a),
        _ => Err(CborError::TypeMismatch),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shortest_form_integer_heads() {
        assert_eq!(encode(&Cv::U64(0)), vec![0x00]);
        assert_eq!(encode(&Cv::U64(23)), vec![0x17]);
        assert_eq!(encode(&Cv::U64(24)), vec![0x18, 0x18]);
        assert_eq!(encode(&Cv::U64(255)), vec![0x18, 0xff]);
        assert_eq!(encode(&Cv::U64(256)), vec![0x19, 0x01, 0x00]);
        assert_eq!(encode(&Cv::U64(1_700_000_000_000)), {
            let mut e = vec![0x1b];
            e.extend_from_slice(&1_700_000_000_000u64.to_be_bytes());
            e
        });
    }

    #[test]
    fn map_keys_emitted_ascending_regardless_of_insertion_order() {
        let m = Cv::Map(vec![
            (10, Cv::U64(1)),
            (2, Cv::U64(2)),
            (1, Cv::U64(3)),
            (24, Cv::U64(4)),
        ]);
        let bytes = encode(&m);
        // map(4) then keys 1,2,10,24 (24 is two-byte-encoded, sorts after single-byte 10).
        assert_eq!(bytes[0], 0xa4);
        assert_eq!(&bytes[1..], &[0x01, 0x03, 0x02, 0x02, 0x0a, 0x01, 0x18, 0x18, 0x04]);
    }

    #[test]
    fn round_trip_through_decode() {
        let v = Cv::Map(vec![
            (1, Cv::U64(0)),
            (2, Cv::Bytes(vec![0xde, 0xad])),
            (3, Cv::Text("hi".into())),
            (4, Cv::Array(vec![Cv::U64(7), Cv::Bool(true)])),
        ]);
        let bytes = encode(&v);
        assert_eq!(decode(&bytes).unwrap(), v);
    }

    #[test]
    fn rejects_float() {
        // A CBOR half-float 0xf9 0x00 0x00 (0.0).
        assert_eq!(decode(&[0xf9, 0x00, 0x00]), Err(CborError::FloatPresent));
    }

    #[test]
    fn rejects_null_on_the_wire() {
        // map{1: null}
        assert_eq!(decode(&[0xa1, 0x01, 0xf6]), Err(CborError::NullPresent));
    }

    #[test]
    fn rejects_duplicate_key() {
        // map claiming 2 entries, both key 1.
        assert_eq!(
            decode(&[0xa2, 0x01, 0x00, 0x01, 0x01]),
            Err(CborError::DuplicateKey(1))
        );
    }

    #[test]
    fn rejects_tag() {
        // tag(0) "text" — tag major type 6.
        assert_eq!(decode(&[0xc0, 0x61, 0x41]), Err(CborError::TagOrUndefined));
    }

    #[test]
    fn deny_unknown_flags_leftover_key() {
        let mut f = Fields::from_cv(Cv::Map(vec![(1, Cv::U64(0)), (99, Cv::U64(0))])).unwrap();
        let _ = f.take(1);
        assert_eq!(f.deny_unknown(), Err(CborError::UnknownKey(99)));
    }
}

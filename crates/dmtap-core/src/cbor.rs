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
    #[error("non-shortest-form integer/length encoding (§18.1.1 rule 1)")]
    NonShortestForm,
    #[error("indefinite-length item is forbidden (§18.1.1 rule 1)")]
    IndefiniteLength,
    #[error("map keys are not in strictly ascending encoded-byte order (§18.1.1 rule 2)")]
    MapKeyOrder,
    #[error("trailing bytes after the top-level CBOR item (§18.1.1)")]
    TrailingData,
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
    #[error("Manifest chunk list is empty — a manifest MUST carry ≥ 1 chunk (§18.3.8, fail closed)")]
    ManifestEmptyChunks,
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

/// Parse and validate **canonical** CBOR into a [`Cv`], **failing closed** on any deviation from
/// RFC 8949 Core Deterministic Encoding as profiled by §18.1.1. This is a *strict* decoder written
/// against the raw bytes (not a lenient library normalize-and-accept), so it enforces the input
/// side of §18.1.1 that a canonical decoder MUST re-check:
///
/// 1. **Shortest-form** integers, string/array/map lengths (rule 1) — a longer-than-minimal head
///    (`0x18 0x0a` for 10, etc.) is rejected ([`CborError::NonShortestForm`]).
/// 2. **Definite-length only** — no indefinite-length items or the `break` code
///    ([`CborError::IndefiniteLength`]).
/// 3. **Strictly ascending map keys**, compared by their *encoded bytes* (rule 2), with **no
///    duplicates** (rule 3) ([`CborError::MapKeyOrder`] / [`CborError::DuplicateKey`]).
/// 4. **No floats / NaN / Infinity** (rule 4), **no tags / `undefined` / simple values**, **no
///    `null` on the wire** (rule 5), **no negative integers**, and **no trailing bytes** after the
///    top-level item.
///
/// Because the decoder accepts *only* the canonical encoding of a value, `encode(decode(b)) == b`
/// for every accepted `b` — the malleability/ signature-reproducibility guarantee §18.1.1 exists
/// to provide. Higher layers additionally reject unknown keys in *signed* objects (§18.1.2).
pub fn decode(bytes: &[u8]) -> Result<Cv, CborError> {
    let mut d = Decoder { b: bytes, pos: 0 };
    let cv = d.value(0)?;
    if d.pos != bytes.len() {
        return Err(CborError::TrailingData); // one, and only one, top-level item (§18.1.1)
    }
    Ok(cv)
}

/// A strict, byte-level recursive-descent canonical-CBOR reader (§18.1.1). Every method advances
/// `pos` and fails closed on the first non-canonical byte.
struct Decoder<'a> {
    b: &'a [u8],
    pos: usize,
}

/// Maximum container-nesting depth accepted by [`Decoder::value`]. Every nested array/map adds one
/// native stack frame per level, so an unbounded decoder lets ~50 KB of `0x81` (nested one-element
/// arrays) overflow the stack and abort — a DoS reachable from any `*::from_det_cbor` on untrusted
/// bytes. DMTAP wire objects are shallow (a handful of levels: object → field → array/map → scalar),
/// so 64 is comfortably above any real message yet far below the overflow threshold. Exceeding it
/// fails closed with [`CborError::Malformed`] instead of panicking.
const MAX_NESTING_DEPTH: u32 = 64;

impl<'a> Decoder<'a> {
    fn byte(&mut self) -> Result<u8, CborError> {
        let b = *self.b.get(self.pos).ok_or(CborError::Malformed)?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CborError> {
        let end = self.pos.checked_add(n).ok_or(CborError::Malformed)?;
        let s = self.b.get(self.pos..end).ok_or(CborError::Malformed)?;
        self.pos = end;
        Ok(s)
    }

    /// Read the argument for a head whose additional-info is `ai`, enforcing shortest form
    /// (rule 1) and rejecting indefinite-length / reserved additional-info values.
    fn argument(&mut self, ai: u8) -> Result<u64, CborError> {
        match ai {
            0..=23 => Ok(ai as u64),
            24 => {
                let v = self.byte()? as u64;
                if v < 24 {
                    return Err(CborError::NonShortestForm); // fits in the 1-byte head
                }
                Ok(v)
            }
            25 => {
                let b = self.take(2)?;
                let v = u16::from_be_bytes([b[0], b[1]]) as u64;
                if v <= u8::MAX as u64 {
                    return Err(CborError::NonShortestForm);
                }
                Ok(v)
            }
            26 => {
                let b = self.take(4)?;
                let v = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64;
                if v <= u16::MAX as u64 {
                    return Err(CborError::NonShortestForm);
                }
                Ok(v)
            }
            27 => {
                let b = self.take(8)?;
                let v = u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
                if v <= u32::MAX as u64 {
                    return Err(CborError::NonShortestForm);
                }
                Ok(v)
            }
            28 | 29 | 30 => Err(CborError::Malformed), // reserved additional-info
            _ => Err(CborError::IndefiniteLength),     // 31 = indefinite / break
        }
    }

    fn value(&mut self, depth: u32) -> Result<Cv, CborError> {
        // Bound recursion before descending into any container: reject over-deep nesting
        // fail-closed rather than exhausting the native stack (DoS guard).
        if depth > MAX_NESTING_DEPTH {
            return Err(CborError::Malformed);
        }
        let ib = self.byte()?;
        let major = ib >> 5;
        let ai = ib & 0x1f;
        match major {
            0 => Ok(Cv::U64(self.argument(ai)?)), // unsigned integer
            1 => {
                // negative integer — read (and length-check) the argument, then reject the value.
                let _ = self.argument(ai)?;
                Err(CborError::IntRange)
            }
            2 => {
                let n = self.argument(ai)? as usize;
                Ok(Cv::Bytes(self.take(n)?.to_vec()))
            }
            3 => {
                let n = self.argument(ai)? as usize;
                let s = self.take(n)?;
                let s = std::str::from_utf8(s).map_err(|_| CborError::Malformed)?;
                Ok(Cv::Text(s.to_owned()))
            }
            4 => {
                let n = self.argument(ai)? as usize;
                let mut out = Vec::with_capacity(n.min(1024));
                for _ in 0..n {
                    out.push(self.value(depth + 1)?);
                }
                Ok(Cv::Array(out))
            }
            5 => self.map(ai, depth),
            6 => {
                // tag — read (and length-check) the tag number, then reject.
                let _ = self.argument(ai)?;
                Err(CborError::TagOrUndefined)
            }
            _ => self.simple(ai), // major 7: bool / null / undefined / floats / simple
        }
    }

    fn map(&mut self, ai: u8, depth: u32) -> Result<Cv, CborError> {
        let n = self.argument(ai)? as usize;
        if n == 0 {
            return Ok(Cv::Map(Vec::new())); // empty map (variant-neutral; matches encode)
        }
        // Track key type from the first key; every key must match it (no mixed maps), and each
        // key's *encoded bytes* must be strictly greater than the previous (rule 2 + rule 3).
        let mut prev_key: Vec<u8> = Vec::new();
        enum KeyKind {
            Int,
            Text,
        }
        let mut kind: Option<KeyKind> = None;
        let mut int_out: Vec<(u64, Cv)> = Vec::new();
        let mut text_out: Vec<(String, Cv)> = Vec::new();
        for i in 0..n {
            let key_start = self.pos;
            let key = self.value(depth + 1)?;
            let key_bytes = self.b[key_start..self.pos].to_vec();
            if i > 0 {
                match key_bytes.as_slice().cmp(prev_key.as_slice()) {
                    std::cmp::Ordering::Less => return Err(CborError::MapKeyOrder),
                    std::cmp::Ordering::Equal => {
                        // A duplicate key: same encoded bytes ⇒ same key (rule 3).
                        return match &key {
                            Cv::U64(k) => Err(CborError::DuplicateKey(*k)),
                            _ => Err(CborError::DuplicateTextKey),
                        };
                    }
                    std::cmp::Ordering::Greater => {}
                }
            }
            prev_key = key_bytes;
            let val = self.value(depth + 1)?;
            match (&kind, key) {
                (None, Cv::U64(k)) => {
                    kind = Some(KeyKind::Int);
                    int_out.push((k, val));
                }
                (None, Cv::Text(s)) => {
                    kind = Some(KeyKind::Text);
                    text_out.push((s, val));
                }
                (Some(KeyKind::Int), Cv::U64(k)) => int_out.push((k, val)),
                (Some(KeyKind::Text), Cv::Text(s)) => text_out.push((s, val)),
                // A key that is neither a small unsigned int nor a text string, or a map that
                // mixes the two — neither is a DMTAP wire map (§18.1.2).
                _ => return Err(CborError::MixedMapKeys),
            }
        }
        match kind {
            Some(KeyKind::Text) => Ok(Cv::TextMap(text_out)),
            _ => Ok(Cv::Map(int_out)),
        }
    }

    fn simple(&mut self, ai: u8) -> Result<Cv, CborError> {
        match ai {
            20 => Ok(Cv::Bool(false)),
            21 => Ok(Cv::Bool(true)),
            22 => Err(CborError::NullPresent),    // null — never on the wire (§18.1.1)
            23 => Err(CborError::TagOrUndefined), // undefined
            24 => {
                // one-byte simple value — none are used by DMTAP; reject fail-closed.
                let _ = self.byte()?;
                Err(CborError::TagOrUndefined)
            }
            25 | 26 | 27 => {
                // half / single / double float — forbidden anywhere (rule 4). Consume the bytes
                // for a clean cursor, then reject.
                let n = match ai {
                    25 => 2,
                    26 => 4,
                    _ => 8,
                };
                let _ = self.take(n)?;
                Err(CborError::FloatPresent)
            }
            28 | 29 | 30 => Err(CborError::Malformed),
            _ => Err(CborError::IndefiniteLength), // 31 = break
        }
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

    // ── Strict-canonical decode: each §18.1.1 rejection the harness proved was missing ──────

    #[test]
    fn rejects_non_shortest_integer() {
        // uint 10 encoded in a two-byte head (0x18 0x0a); preferred form is the single byte 0x0a.
        assert_eq!(decode(&[0x18, 0x0a]), Err(CborError::NonShortestForm));
        // uint 23 in a two-byte head (DMTAP-CBOR-05: 0x18 0x17).
        assert_eq!(decode(&[0x18, 0x17]), Err(CborError::NonShortestForm));
        // uint 200 encoded in a two-byte (0x19) head when one-byte (0x18 0xc8) suffices.
        assert_eq!(decode(&[0x19, 0x00, 0xc8]), Err(CborError::NonShortestForm));
        // uint 0 encoded 8-wide.
        assert_eq!(
            decode(&[0x1b, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(CborError::NonShortestForm)
        );
        // A non-shortest *length* head on a byte string is equally rejected.
        assert_eq!(decode(&[0x58, 0x01, 0xaa]), Err(CborError::NonShortestForm));
    }

    #[test]
    fn accepts_genuine_shortest_forms() {
        // These are the *canonical* two-byte forms (value truly needs the wider head) — accepted.
        assert_eq!(decode(&[0x18, 0x18]).unwrap(), Cv::U64(24));
        assert_eq!(decode(&[0x19, 0x01, 0x00]).unwrap(), Cv::U64(256));
    }

    #[test]
    fn rejects_indefinite_length_items() {
        // Indefinite-length array (DMTAP-CBOR-06: 0x9f … 0xff).
        assert_eq!(decode(&[0x9f, 0xff]), Err(CborError::IndefiniteLength));
        // Indefinite-length byte string, text string, and map.
        assert_eq!(decode(&[0x5f, 0xff]), Err(CborError::IndefiniteLength));
        assert_eq!(decode(&[0x7f, 0xff]), Err(CborError::IndefiniteLength));
        assert_eq!(decode(&[0xbf, 0xff]), Err(CborError::IndefiniteLength));
    }

    #[test]
    fn rejects_descending_map_keys() {
        // map {2:0, 1:0} — keys 2 then 1 are descending (DMTAP-CBOR-07: 0xa2 02 00 01 00).
        assert_eq!(decode(&[0xa2, 0x02, 0x00, 0x01, 0x00]), Err(CborError::MapKeyOrder));
    }

    #[test]
    fn accepts_ascending_map_keys() {
        let cv = decode(&[0xa2, 0x01, 0x00, 0x02, 0x00]).unwrap();
        assert_eq!(cv, Cv::Map(vec![(1, Cv::U64(0)), (2, Cv::U64(0))]));
    }

    #[test]
    fn rejects_descending_text_map_keys() {
        // map {"b":0, "a":0} — text keys 0x62.. then 0x61.. are descending.
        assert_eq!(
            decode(&[0xa2, 0x61, 0x62, 0x00, 0x61, 0x61, 0x00]),
            Err(CborError::MapKeyOrder)
        );
    }

    #[test]
    fn rejects_negative_integer() {
        // -1 is major type 1; DMTAP wire maps carry only unsigned integers.
        assert_eq!(decode(&[0x20]), Err(CborError::IntRange));
    }

    #[test]
    fn rejects_undefined_and_simple() {
        assert_eq!(decode(&[0xf7]), Err(CborError::TagOrUndefined)); // undefined (DMTAP-CBOR-10)
        assert_eq!(decode(&[0xf8, 0xff]), Err(CborError::TagOrUndefined)); // simple(255)
    }

    #[test]
    fn rejects_trailing_bytes() {
        // A valid single item (0x00) followed by a stray byte MUST be rejected — exactly one
        // top-level item is permitted, else re-encoding would silently drop the tail.
        assert_eq!(decode(&[0x00, 0x00]), Err(CborError::TrailingData));
    }

    #[test]
    fn strict_decode_is_reencode_idempotent_on_canonical_bytes() {
        // Every accepted encoding round-trips byte-for-byte (the malleability guarantee).
        let v = Cv::Map(vec![
            (1, Cv::U64(24)),
            (2, Cv::Bytes(vec![0xde, 0xad, 0xbe, 0xef])),
            (3, Cv::Text("hi".into())),
            (7, Cv::Array(vec![Cv::U64(256), Cv::Bool(true), Cv::Bool(false)])),
            (24, Cv::U64(1_700_000_000_000)),
        ]);
        let bytes = encode(&v);
        assert_eq!(decode(&bytes).unwrap(), v);
        assert_eq!(encode(&decode(&bytes).unwrap()), bytes);
    }

    #[test]
    fn rejects_over_deep_nesting_without_stack_overflow() {
        // ~50 KB of single-element-array heads (0x81 = array(1)) would recurse per level and
        // overflow the native stack on an unbounded decoder. It MUST fail closed instead.
        let deep = vec![0x81u8; 50_000];
        assert_eq!(decode(&deep), Err(CborError::Malformed));
        // Right at the boundary: MAX_NESTING_DEPTH + 1 nested arrays around a scalar exceed the
        // bound and are rejected — no panic, a clean error.
        let mut too_deep = vec![0x81u8; (MAX_NESTING_DEPTH as usize) + 2];
        too_deep.push(0x00); // innermost scalar
        assert_eq!(decode(&too_deep), Err(CborError::Malformed));
    }

    #[test]
    fn accepts_nesting_up_to_the_bound() {
        // A structure nested right up to the limit still decodes (real objects are far shallower).
        // depth 0 is the outermost value; children sit at depth 1.., so MAX_NESTING_DEPTH nested
        // arrays around a scalar is the deepest accepted shape.
        let n = MAX_NESTING_DEPTH as usize;
        let mut buf = vec![0x81u8; n];
        buf.push(0x00);
        let decoded = decode(&buf).expect("nesting at the bound must decode");
        // And it re-encodes byte-for-byte (idempotence holds for the deep-but-legal case).
        assert_eq!(encode(&decoded), buf);
    }
}

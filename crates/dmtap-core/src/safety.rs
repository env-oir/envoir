//! Safety numbers — out-of-band key verification (spec §3.4.1).
//!
//! A **safety number** is a deterministic fingerprint of a *pair* of identity keys, compared
//! out-of-band (in person, over a trusted channel, or by QR) to confirm that the key you pinned
//! is the key your correspondent meant (§3.4.1). It is **verification, not an address**: it is
//! never used to route or reach anyone and never appears in `Identity.names`.
//!
//! ## Construction (reference)
//! The spec fixes the *properties* — a deterministic function over the **full** identity keys,
//! order-independent so both parties compute the same value, carrying the keys' full strength —
//! but leaves the exact rendering **optional** (§3.4.1 "Word rendering (optional)"). This module
//! pins one concrete, documented construction for the reference crate so the value is
//! reproducible and machine-checkable:
//!
//! ```text
//! lo, hi      = sort_bytewise(ik_a, ik_b)            ; order independence
//! fingerprint = BLAKE3( "dmtap-safety-number-v0" || lo || hi )   ; 32 bytes, domain-separated
//! ```
//!
//! `fingerprint` is rendered two ways, both deterministic:
//! - [`safety_number`] — a Signal-style **decimal** string: 6 groups of 5 digits (30 digits),
//!   each group = 5 big-endian fingerprint bytes reduced mod 100000, space-separated.
//! - [`safety_number_hex`] — the raw 32-byte fingerprint as lowercase hex, for exact comparison.
//!
//! Rendering the same bits as a §3.4.1 word sequence reuses the [`crate::keyname`] wordlist
//! mechanism and is intentionally left to that module; only the numeric forms are pinned here.

/// Domain-separation label for the safety-number fingerprint, so it can never collide with any
/// other BLAKE3 use in the protocol (content addresses, key-names, …).
const SAFETY_DS: &[u8] = b"dmtap-safety-number-v0";

/// The raw 32-byte safety fingerprint of the pair `(ik_a, ik_b)` (spec §3.4.1).
///
/// **Order-independent:** the two keys are sorted bytewise before hashing, so both correspondents
/// derive the identical value regardless of who is "a" and who is "b". Domain-separated.
pub fn fingerprint(ik_a: &[u8], ik_b: &[u8]) -> [u8; 32] {
    let (lo, hi) = if ik_a <= ik_b { (ik_a, ik_b) } else { (ik_b, ik_a) };
    let mut h = blake3::Hasher::new();
    h.update(SAFETY_DS);
    h.update(lo);
    h.update(hi);
    *h.finalize().as_bytes()
}

/// The Signal-style decimal safety number for `(ik_a, ik_b)`: 6 groups of 5 digits, space-
/// separated (spec §3.4.1). Deterministic and order-independent (see [`fingerprint`]).
pub fn safety_number(ik_a: &[u8], ik_b: &[u8]) -> String {
    let fp = fingerprint(ik_a, ik_b);
    let mut groups = Vec::with_capacity(6);
    for g in 0..6 {
        // 5 big-endian bytes → a 40-bit integer → reduced into a 5-digit group.
        let mut acc: u64 = 0;
        for b in &fp[g * 5..g * 5 + 5] {
            acc = (acc << 8) | *b as u64;
        }
        groups.push(format!("{:05}", acc % 100_000));
    }
    groups.join(" ")
}

/// The raw safety fingerprint as lowercase hex (spec §3.4.1) — the exact-comparison form.
pub fn safety_number_hex(ik_a: &[u8], ik_b: &[u8]) -> String {
    fingerprint(ik_a, ik_b)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_order_independent() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_eq!(fingerprint(&a, &b), fingerprint(&b, &a));
        assert_eq!(safety_number(&a, &b), safety_number(&b, &a));
    }

    #[test]
    fn distinct_pairs_differ() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];
        assert_ne!(fingerprint(&a, &b), fingerprint(&a, &c));
    }

    #[test]
    fn number_shape_is_six_groups_of_five() {
        let n = safety_number(&[7u8; 32], &[8u8; 32]);
        let groups: Vec<&str> = n.split(' ').collect();
        assert_eq!(groups.len(), 6);
        assert!(groups.iter().all(|g| g.len() == 5 && g.chars().all(|c| c.is_ascii_digit())));
    }

    #[test]
    fn hex_is_64_chars() {
        assert_eq!(safety_number_hex(&[0u8; 32], &[1u8; 32]).len(), 64);
    }

    #[test]
    fn is_deterministic() {
        let a = [42u8; 32];
        let b = [99u8; 32];
        assert_eq!(safety_number_hex(&a, &b), safety_number_hex(&a, &b));
    }
}

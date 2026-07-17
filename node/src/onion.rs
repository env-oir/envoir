//! Sender-side Sphinx onion wrapping for the `private` tier (spec §4.4.1, §4.4.3–§4.4.4, §20.1).
//!
//! A `private`-tier MOTE does not travel as its bare sealed [`Envelope`](dmtap_core::mote::Envelope):
//! it is **onion-wrapped** into constant-length Sphinx cells (§4.4.1) drawn over a freshly-selected
//! 3-hop mix path (§4.4.3) with a **fresh `α`** and **current-epoch** mix keys (§4.4.4). This module
//! builds that wrap on the send side.
//!
//! ## Why the wrap must be *fresh* on every attempt (the §20.1 `RETRY (private)` fix)
//! Every honest first hop keeps a per-hop-tag **replay cache** (§4.4.6): the second time it sees the
//! *same* Sphinx tag it drops the packet (`ERR_MIX_REPLAY_DETECTED`, `0x030E`). So re-dispatching
//! the **identical** onion on a `RETRY` — which is exactly what the `fast` tier is allowed to do —
//! can **never** deliver a `private` MOTE under any packet loss: the retry is indistinguishable from
//! a replay and is dropped until the MOTE `EXPIRED`s. The node therefore **re-onion-wraps** a
//! `private` MOTE on every (re)dispatch, drawing a fresh `α` so the per-hop tags differ, while
//! keeping the **stable envelope `id`** (§2.2) — the inner sealed envelope is retained and re-wrapped,
//! never re-sealed. [`wrap`] is that operation; [`OnionWrap::replay_tags`] exposes the per-cell
//! entry-hop tags a fresh draw makes distinct.
//!
//! ## Scope (honest)
//! This models the onion's **structure and freshness contract** on the real §18.5.4 Sphinx cell
//! layout ([`dmtap_core::sphinx`]): the bucket-ladder fragmentation (§4.4.1), the constant-length
//! `α ‖ β ‖ γ ‖ δ` cell, the per-hop [`RoutingCommand`] onion in `β`, and a per-hop-tag `γ` +
//! re-randomized `α` **derived from a fresh per-wrap seed** so the replay-distinctness this fix
//! turns on is real and testable. The full Sphinx *cryptographic* construction (real X25519 `α`
//! blinding, ChaCha20 `β` stream, Poly1305 `γ`, LIONESS wide-block `δ` PRP) is the separate mixnet
//! transport frontier (see [`crate::transport`]) and is **not** reproduced here — the derivations
//! below are keyed BLAKE3 stand-ins, not the on-wire mix crypto.

use dmtap_core::id::ContentId;
use dmtap_core::sphinx::{
    RoutingCommand, SphinxCell, SphinxFragmentHeader, ALPHA_LEN, CELL_LEN, DELTA_LEN,
    FRAGMENT_DATA_LEN, GAMMA_LEN, R_MAX, ROUTING_COMMAND_LEN,
};

/// The minimum viable `private` path: 3 hops, 1 per stratified layer (§16.3, §4.4.9). Below this the
/// sender fails closed — it never downgrades a `private` MOTE onto a shorter path.
pub const MIN_PRIVATE_HOPS: usize = 3;

/// One hop of a drawn `private` path (§4.4.3): the mix's identity plus the current-epoch Sphinx key
/// its layer is sealed to (§4.4.4) and the Poisson-sampled per-hop delay (§16.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MixHop {
    /// The mix node's long-term identity key (§18.5.2 `node_ik`).
    pub node_ik: Vec<u8>,
    /// The mix's **current-epoch** Sphinx public key (§4.4.4 `MixKeyEntry.mix_key`).
    pub mix_key: [u8; 32],
    /// Poisson-sampled hop delay in ms (§16.3), carried in this hop's `RoutingCommand`.
    pub delay_ms: u32,
}

/// A drawn mixnet path (stratified, one mix per layer, §4.4.3), tagged with the mix-key epoch the
/// keys belong to (§4.4.4). Standard profile = 3 hops (§16.3); High-security = up to [`R_MAX`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MixPath {
    pub hops: Vec<MixHop>,
    /// The mix-key epoch these hop keys are valid for (§4.4.4). Folded into every derivation so a
    /// wrap is bound to the epoch it was built under.
    pub epoch: u64,
}

impl MixPath {
    /// Build a path from `hops` valid at `epoch`. No validation here — [`wrap`] enforces the
    /// §4.4.9 hop bounds fail-closed.
    pub fn new(hops: Vec<MixHop>, epoch: u64) -> Self {
        MixPath { hops, epoch }
    }
}

/// Why a `private` onion could not be built (fail closed, §4.4.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnionError {
    /// Fewer than [`MIN_PRIVATE_HOPS`] hops — below the minimum viable `private` path (`0x0310`).
    PathTooShort,
    /// More than [`R_MAX`] hops — the header `β` cannot carry the routing onion.
    TooManyHops,
    /// The sealed envelope exceeds the top bucket rung (32 cells / ~64 KiB) — it is a `normal`/`large`
    /// file whose bulk travels the fast path (§4.5), not inline `private` cells (§4.4.1).
    PayloadTooLarge,
}

impl std::fmt::Display for OnionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OnionError::PathTooShort => {
                write!(f, "private path below the 3-hop minimum (§4.4.9, 0x0310)")
            }
            OnionError::TooManyHops => write!(f, "private path exceeds r_max = {R_MAX} hops"),
            OnionError::PayloadTooLarge => {
                write!(f, "payload exceeds the top inline bucket (32 cells) — use the fast bulk path")
            }
        }
    }
}
impl std::error::Error for OnionError {}

/// A wrapped `private`-tier MOTE: the constant-length Sphinx cells handed to the entry mix, all
/// drawn under one fresh `α` seed (so a re-wrap is a distinct onion). One cell per bucket-ladder
/// fragment (§4.4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnionWrap {
    pub cells: Vec<SphinxCell>,
    /// The mix-key epoch the wrap was drawn under (§4.4.4).
    pub epoch: u64,
}

impl OnionWrap {
    /// The per-cell **entry-hop tag** (`α ‖ γ`) the first honest mix keys its replay cache on
    /// (§4.4.6). A re-wrap draws a fresh `α`, so these differ between attempts — which is exactly
    /// what makes a `private` `RETRY` a genuine fresh delivery rather than a dropped replay.
    pub fn replay_tags(&self) -> Vec<Vec<u8>> {
        self.cells
            .iter()
            .map(|c| {
                let mut t = c.alpha.to_vec();
                t.extend_from_slice(&c.gamma);
                t
            })
            .collect()
    }

    /// The concatenated on-wire cells (each constant [`CELL_LEN`]).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.cells.len() * CELL_LEN);
        for c in &self.cells {
            out.extend_from_slice(&c.to_bytes());
        }
        out
    }

    /// Number of Sphinx cells (bucket-ladder fragments) this MOTE occupies.
    pub fn cell_count(&self) -> usize {
        self.cells.len()
    }
}

/// Onion-wrap `inner` (the sealed envelope's canonical CBOR) over `path` with the fresh per-wrap
/// seed `alpha_seed` (spec §4.4.1, §4.4.3–§4.4.4). Fails closed on a sub-minimum / over-long path or
/// an over-ladder payload (§4.4.9). Draw a **new** `alpha_seed` on every call — that is what makes a
/// `RETRY` produce distinct per-hop tags (§4.4.6) and is the whole point of re-wrapping.
pub fn wrap(inner: &[u8], path: &MixPath, alpha_seed: &[u8; 32]) -> Result<OnionWrap, OnionError> {
    if path.hops.len() < MIN_PRIVATE_HOPS {
        return Err(OnionError::PathTooShort);
    }
    if path.hops.len() > R_MAX {
        return Err(OnionError::TooManyHops);
    }
    let frag_count = ladder(inner.len()).ok_or(OnionError::PayloadTooLarge)?;

    // A fresh per-MOTE fragment id linking this wrap's cells (§18.5.4). Derived from the fresh seed
    // so it, too, is unlinkable to a prior attempt.
    let epoch_be = path.epoch.to_be_bytes();
    let msg_full = h(&[alpha_seed, b"msg-id", &epoch_be]);
    let mut msg_id = [0u8; 8];
    msg_id.copy_from_slice(&msg_full[..8]);

    let mut cells = Vec::with_capacity(frag_count as usize);
    for i in 0..frag_count {
        // The fragment's slice of the padded MOTE, zero-padded to the fixed fragment-data length.
        let start = i as usize * FRAGMENT_DATA_LEN;
        let mut frag = [0u8; FRAGMENT_DATA_LEN];
        if start < inner.len() {
            let end = (start + FRAGMENT_DATA_LEN).min(inner.len());
            frag[..end - start].copy_from_slice(&inner[start..end]);
        }
        let hdr = SphinxFragmentHeader {
            msg_id,
            frag_index: i,
            frag_count,
            total_len: inner.len() as u32,
        };
        // δ plaintext = fixed fragment header ‖ fragment data (exactly DELTA_LEN).
        let mut delta = Vec::with_capacity(DELTA_LEN);
        delta.extend_from_slice(&hdr.to_bytes());
        delta.extend_from_slice(&frag);
        debug_assert_eq!(delta.len(), DELTA_LEN);

        // A fresh per-cell header group element `α`, derived from the fresh per-wrap seed (§4.4.4).
        let idx_be = i.to_be_bytes();
        let cell_alpha = h(&[alpha_seed, &idx_be, &epoch_be, b"alpha"]);

        // Per-hop shared secrets: models the §4.4.4 DH(α, mix_key) + per-hop α re-randomization. Each
        // depends on the fresh `cell_alpha`, so a new wrap yields new secrets → new tags.
        let mut secrets: Vec<[u8; 32]> = Vec::with_capacity(path.hops.len());
        let mut a = cell_alpha;
        for (hi, hop) in path.hops.iter().enumerate() {
            let s = h(&[&a, &hop.mix_key, &epoch_be, &[hi as u8]]);
            secrets.push(s);
            a = h(&[&a, &s]); // re-randomize α for the next hop
        }

        // β: one RoutingCommand per hop, the rest zero-padded to r_max (constant length, §4.4.1).
        let mut beta = Vec::with_capacity(R_MAX * ROUTING_COMMAND_LEN);
        for (hi, hop) in path.hops.iter().enumerate() {
            let last = hi + 1 == path.hops.len();
            let next_hop = if last {
                [0u8; 32]
            } else {
                let mut nh = [0u8; 32];
                nh.copy_from_slice(&h(&[path.hops[hi + 1].node_ik.as_slice()]));
                nh
            };
            let cmd = RoutingCommand {
                cmd: if last { 0x01 } else { 0x00 }, // exit vs. forward-to-mix (§18.5.4)
                flags: if last { 0x01 } else { 0x00 }, // last-hop flag
                delay_ms: hop.delay_ms,
                next_hop,
            };
            beta.extend_from_slice(&cmd.to_bytes());
        }
        beta.resize(R_MAX * ROUTING_COMMAND_LEN, 0);
        // Onion-encrypt β from the innermost hop outward (models the layered β onion).
        for s in secrets.iter().rev() {
            keystream_xor(&mut beta, s, b"beta");
        }

        // γ: the entry-hop MAC over β — the per-hop tag the first mix's replay cache keys on (§4.4.6).
        let gamma = mac(&secrets[0], &beta);

        // δ: wide-block-model transform keyed from every hop secret (LIONESS stand-in), applied
        // outer-last so the exit peels it first; constant length preserved.
        for s in secrets.iter().rev() {
            keystream_xor(&mut delta, s, b"delta");
        }

        let mut alpha = [0u8; ALPHA_LEN];
        alpha.copy_from_slice(&cell_alpha);
        cells.push(SphinxCell { alpha, beta, gamma, delta });
    }
    Ok(OnionWrap { cells, epoch: path.epoch })
}

/// The smallest bucket-ladder cell count (§4.4.1, §16.3: {1, 4, 16, 32}) that holds `len` fragment
/// bytes, or `None` if `len` exceeds the top rung.
fn ladder(len: usize) -> Option<u16> {
    for &n in &[1u16, 4, 16, 32] {
        if len <= n as usize * FRAGMENT_DATA_LEN {
            return Some(n);
        }
    }
    None
}

/// BLAKE3-256 of the concatenated parts, as a raw 32-byte value (the multihash prefix stripped).
/// Used only as a keyed derivation for the onion-structure model, not the on-wire mix crypto.
fn h(parts: &[&[u8]]) -> [u8; 32] {
    let mut buf = Vec::new();
    for p in parts {
        buf.extend_from_slice(p);
    }
    let cid = ContentId::of(&buf);
    let mut out = [0u8; 32];
    out.copy_from_slice(&cid.0[1..33]);
    out
}

/// The 16-byte entry-hop MAC over `data` keyed by `key` (Poly1305-`γ` stand-in).
fn mac(key: &[u8; 32], data: &[u8]) -> [u8; GAMMA_LEN] {
    let full = h(&[key, data]);
    let mut m = [0u8; GAMMA_LEN];
    m.copy_from_slice(&full[..GAMMA_LEN]);
    m
}

/// XOR `buf` in place with a keyed BLAKE3 keystream (a constant-length, key-dependent transform —
/// the β/δ onion-layer stand-in). Not a stream cipher / PRP; models only the length-preserving,
/// key-dependence property the freshness contract relies on.
fn keystream_xor(buf: &mut [u8], key: &[u8; 32], label: &[u8]) {
    let mut counter: u64 = 0;
    let mut i = 0;
    while i < buf.len() {
        let ctr_be = counter.to_be_bytes();
        let block = h(&[key, label, &ctr_be]);
        for &b in &block {
            if i >= buf.len() {
                break;
            }
            buf[i] ^= b;
            i += 1;
        }
        counter += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(epoch: u64) -> MixPath {
        MixPath::new(
            vec![
                MixHop { node_ik: b"entry-mix".to_vec(), mix_key: [1u8; 32], delay_ms: 5000 },
                MixHop { node_ik: b"middle-mix".to_vec(), mix_key: [2u8; 32], delay_ms: 5000 },
                MixHop { node_ik: b"exit-mix".to_vec(), mix_key: [3u8; 32], delay_ms: 5000 },
            ],
            epoch,
        )
    }

    #[test]
    fn wrap_produces_constant_length_cells() {
        let onion = wrap(b"a small sealed envelope", &path(7), &[9u8; 32]).unwrap();
        assert_eq!(onion.cell_count(), 1, "a small MOTE is one 2 KiB cell");
        for c in &onion.cells {
            assert_eq!(c.to_bytes().len(), CELL_LEN, "every cell is the constant Sphinx length");
        }
    }

    #[test]
    fn fresh_seed_yields_distinct_per_hop_tags_same_path() {
        // The load-bearing property for the §20.1 private-RETRY fix: re-wrapping the SAME inner MOTE
        // over the SAME path with a FRESH α seed yields DIFFERENT per-hop tags — so the first honest
        // mix does not drop the retry as a replay (§4.4.6). Nothing about the inner MOTE changed.
        let inner = b"identical inner sealed envelope bytes";
        let p = path(7);
        let first = wrap(inner, &p, &[0xAA; 32]).unwrap();
        let second = wrap(inner, &p, &[0xBB; 32]).unwrap();
        assert_ne!(first.replay_tags(), second.replay_tags(), "fresh α ⇒ distinct per-hop tags");
        assert_ne!(first.to_bytes(), second.to_bytes(), "the whole onion differs");
    }

    #[test]
    fn same_seed_is_deterministic() {
        // Determinism under a fixed seed keeps the model testable — the freshness comes from the
        // caller drawing a new seed per attempt, not from hidden nondeterminism.
        let a = wrap(b"x", &path(1), &[5u8; 32]).unwrap();
        let b = wrap(b"x", &path(1), &[5u8; 32]).unwrap();
        assert_eq!(a.to_bytes(), b.to_bytes());
    }

    #[test]
    fn multi_cell_payload_uses_the_bucket_ladder() {
        // A payload spanning >1 fragment climbs to the next ladder rung (1→4 cells).
        let big = vec![0x5A; FRAGMENT_DATA_LEN + 10];
        let onion = wrap(&big, &path(1), &[7u8; 32]).unwrap();
        assert_eq!(onion.cell_count(), 4, "just over one fragment ⇒ the 4-cell rung");
    }

    #[test]
    fn sub_minimum_path_fails_closed() {
        let two_hops = MixPath::new(
            vec![
                MixHop { node_ik: b"a".to_vec(), mix_key: [1; 32], delay_ms: 0 },
                MixHop { node_ik: b"b".to_vec(), mix_key: [2; 32], delay_ms: 0 },
            ],
            1,
        );
        assert_eq!(wrap(b"x", &two_hops, &[0; 32]), Err(OnionError::PathTooShort));
    }

    #[test]
    fn over_ladder_payload_is_rejected() {
        let too_big = vec![0u8; 33 * FRAGMENT_DATA_LEN];
        assert_eq!(wrap(&too_big, &path(1), &[0; 32]), Err(OnionError::PayloadTooLarge));
    }
}

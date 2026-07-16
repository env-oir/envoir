//! RFC 6962 Merkle math for KT — spec §3.5, §18.4.10, §18.9.5.
//!
//! DMTAP's KT log is an **RFC 6962-profiled** append-only Merkle tree whose leaf/node hashing uses
//! the §18.9.5 domain-separated prefixes over BLAKE3-256:
//!
//! ```text
//! leaf digest  = the 32-byte digest of the §18.4.9 leaf_hash (0x1e ‖ BLAKE3(0x00 ‖ leaf_data))
//! node(l, r)   = BLAKE3-256( 0x01 ‖ l ‖ r )        ; l, r are 32-byte digests, no prefix
//! root         = 0x1e ‖ MTH(leaf digests)          ; a ContentId
//! ```
//!
//! The [`identity_leaf_hash`](dmtap_core::kt::identity_leaf_hash) rule already applies the RFC 6962
//! leaf prefix `0x00`, so this module treats each `leaf_hash`'s 32-byte digest as an MTH leaf and
//! only ever applies the node prefix `0x01` when folding. [`verify_inclusion`] is the arithmetic
//! §18.4.10 requires (it is not in `dmtap-core`); [`MerkleTree`] builds a tree and emits audit
//! paths so an in-memory log can produce real, verifiable proofs.

use dmtap_core::id::{ContentId, MH_BLAKE3_256};

/// Extract the 32-byte BLAKE3 digest from a v0 [`ContentId`] (`0x1e ‖ 32-byte digest`), or `None`
/// if the id is not a well-formed BLAKE3-256 content address — a malformed hash in a proof fails
/// closed (§2.2, §18.4.10).
fn digest32(id: &ContentId) -> Option<[u8; 32]> {
    if id.algorithm() == Some(MH_BLAKE3_256) && id.digest().len() == 32 {
        let mut a = [0u8; 32];
        a.copy_from_slice(id.digest());
        Some(a)
    } else {
        None
    }
}

/// Wrap a 32-byte digest as a v0 [`ContentId`] (`0x1e ‖ digest`).
fn as_content_id(digest: [u8; 32]) -> ContentId {
    let mut v = Vec::with_capacity(33);
    v.push(MH_BLAKE3_256);
    v.extend_from_slice(&digest);
    ContentId(v)
}

/// RFC 6962 interior node hash with the §18.9.5 node prefix `0x01`.
fn node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(1 + 32 + 32);
    buf.push(0x01);
    buf.extend_from_slice(left);
    buf.extend_from_slice(right);
    *blake3::hash(&buf).as_bytes()
}

/// The largest power of two **strictly less than** `n` (RFC 6962 split point `k`), for `n ≥ 2`.
fn split_point(n: usize) -> usize {
    let mut k = 1usize;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// RFC 6962 Merkle Tree Hash over already-hashed leaf digests (no padding; unpaired subtrees are
/// carried up per the non-power-of-two split). Panics only on an empty slice — callers pass `n ≥ 1`.
fn mth(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        1 => leaves[0],
        n => {
            let k = split_point(n);
            node(&mth(&leaves[..k]), &mth(&leaves[k..]))
        }
    }
}

/// RFC 6962 audit path (`PATH(m, D)`) for the `m`-th leaf of `leaves`, bottom-to-top.
fn audit_path(m: usize, leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let n = leaves.len();
    if n <= 1 {
        return Vec::new();
    }
    let k = split_point(n);
    if m < k {
        let mut p = audit_path(m, &leaves[..k]);
        p.push(mth(&leaves[k..]));
        p
    } else {
        let mut p = audit_path(m - k, &leaves[k..]);
        p.push(mth(&leaves[..k]));
        p
    }
}

/// RFC 6962 `SUBPROOF(m, D, b)` for a consistency proof (§18.4.11): the audit path proving the
/// first `m` leaves of `leaves` are a genuine prefix. `b` tracks whether the recursion is still on
/// the exact boundary subtree (an optimization RFC 6962 uses to omit a redundant hash there).
/// Ported verbatim from the identical fold this crate's `InclusionProof` verification already
/// exercises — same node/leaf hashing, so a consistency proof folds under exactly the same rules
/// an inclusion proof does.
fn subproof(m: usize, leaves: &[[u8; 32]], b: bool) -> Vec<[u8; 32]> {
    let n = leaves.len();
    if m == n {
        if b {
            Vec::new()
        } else {
            vec![mth(leaves)]
        }
    } else {
        let k = split_point(n);
        if m <= k {
            let mut p = subproof(m, &leaves[..k], b);
            p.push(mth(&leaves[k..]));
            p
        } else {
            let mut p = subproof(m - k, &leaves[k..], false);
            p.push(mth(&leaves[..k]));
            p
        }
    }
}

/// Verify an RFC 6962 inclusion proof against an STH `root_hash` (spec §18.4.10). Folds
/// `proof.leaf_hash` with `proof.audit_path` using the node rule and checks it reconstructs
/// `root` at exactly `proof.tree_size`. This is the arithmetic [`InclusionProof`] carries but
/// **does not** self-verify (it is unsigned; §18.4.10). Returns `false` — never panics — on any
/// malformed hash, an out-of-range index, a wrong-length path, or a root mismatch, so a bad proof
/// fails closed into `ERR_KT_PROOF_INVALID` (§21.3 `0x0108`).
///
/// [`InclusionProof`]: dmtap_core::kt::InclusionProof
pub fn verify_inclusion(proof: &dmtap_core::kt::InclusionProof, root: &ContentId) -> bool {
    let leaf = match digest32(&proof.leaf_hash) {
        Some(d) => d,
        None => return false,
    };
    let root_d = match digest32(root) {
        Some(d) => d,
        None => return false,
    };
    // A leaf index must lie inside the committed tree.
    if proof.leaf_index >= proof.tree_size {
        return false;
    }
    // RFC 6962 §2.1.1 verification: fold with node index `fn` and last index `sn`.
    let mut node_idx = proof.leaf_index;
    let mut last_idx = proof.tree_size - 1;
    let mut r = leaf;
    for p in &proof.audit_path {
        let pd = match digest32(p) {
            Some(d) => d,
            None => return false,
        };
        if last_idx == 0 {
            return false; // proof longer than the tree height allows
        }
        if node_idx & 1 == 1 || node_idx == last_idx {
            r = node(&pd, &r);
            if node_idx & 1 == 0 {
                // right-shift both until the LSB of node_idx is set or node_idx is 0
                loop {
                    node_idx >>= 1;
                    last_idx >>= 1;
                    if node_idx & 1 == 1 || node_idx == 0 {
                        break;
                    }
                }
            }
        } else {
            r = node(&r, &pd);
        }
        node_idx >>= 1;
        last_idx >>= 1;
    }
    last_idx == 0 && r == root_d
}

/// An in-memory RFC 6962 Merkle tree over leaf hashes (§18.4.9), used by the reference KT log to
/// compute roots and emit real audit paths. Not a persistent log — a test/reference structure that
/// produces proofs [`verify_inclusion`] accepts.
#[derive(Debug, Default, Clone)]
pub struct MerkleTree {
    leaves: Vec<[u8; 32]>,
}

impl MerkleTree {
    /// An empty tree.
    pub fn new() -> Self {
        MerkleTree { leaves: Vec::new() }
    }

    /// Append a leaf (its §18.4.9 `leaf_hash`), returning its 0-based index. A malformed
    /// (non-BLAKE3) leaf hash is rejected so the tree can only hold well-formed leaves.
    pub fn append(&mut self, leaf_hash: &ContentId) -> Option<u64> {
        let d = digest32(leaf_hash)?;
        self.leaves.push(d);
        Some((self.leaves.len() - 1) as u64)
    }

    /// The number of leaves (RFC 6962 tree size).
    pub fn size(&self) -> u64 {
        self.leaves.len() as u64
    }

    /// The Merkle tree root as a [`ContentId`] (`0x1e ‖ MTH`), or `None` for an empty tree.
    pub fn root(&self) -> Option<ContentId> {
        if self.leaves.is_empty() {
            None
        } else {
            Some(as_content_id(mth(&self.leaves)))
        }
    }

    /// The audit path (bottom-to-top sibling hashes) for leaf `index`, or `None` if out of range.
    pub fn inclusion_path(&self, index: u64) -> Option<Vec<ContentId>> {
        let idx = index as usize;
        if idx >= self.leaves.len() {
            return None;
        }
        Some(audit_path(idx, &self.leaves).into_iter().map(as_content_id).collect())
    }

    /// The RFC 6962 consistency-proof nodes proving the current tree extends its own prefix of
    /// size `first` (§18.4.11, §3.5.2(a)/(d)): the append-only evidence a log presents between two
    /// STHs it issued at different sizes. `None` if `first == 0` or `first` exceeds the current
    /// size — a proof against a nonexistent prefix is meaningless (an empty path for `first ==
    /// size`, the trivial no-growth case).
    pub fn consistency_path(&self, first: u64) -> Option<Vec<ContentId>> {
        let m = first as usize;
        let n = self.leaves.len();
        if m == 0 || m > n {
            return None;
        }
        let path = if m == n { Vec::new() } else { subproof(m, &self.leaves, true) };
        Some(path.into_iter().map(as_content_id).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dmtap_core::kt::InclusionProof;

    fn leaf(n: u8) -> ContentId {
        ContentId::of(&[n, n, n, n])
    }

    fn proof_for(tree: &MerkleTree, index: u64, leaf_hash: &ContentId) -> InclusionProof {
        InclusionProof {
            tree_size: tree.size(),
            leaf_index: index,
            leaf_hash: leaf_hash.clone(),
            audit_path: tree.inclusion_path(index).unwrap(),
        }
    }

    #[test]
    fn single_leaf_tree_root_is_the_leaf() {
        let mut t = MerkleTree::new();
        let l = leaf(1);
        t.append(&l).unwrap();
        // MTH([leaf]) == leaf digest, wrapped as a ContentId.
        assert_eq!(t.root().unwrap(), l);
        let p = proof_for(&t, 0, &l);
        assert!(p.audit_path.is_empty());
        assert!(verify_inclusion(&p, &t.root().unwrap()));
    }

    #[test]
    fn inclusion_verifies_for_every_leaf_across_tree_sizes() {
        // Non-power-of-two sizes exercise the RFC 6962 split rule.
        for n in 1u8..=13 {
            let mut t = MerkleTree::new();
            let leaves: Vec<ContentId> = (0..n).map(leaf).collect();
            for l in &leaves {
                t.append(l).unwrap();
            }
            let root = t.root().unwrap();
            for (i, l) in leaves.iter().enumerate() {
                let p = proof_for(&t, i as u64, l);
                assert!(verify_inclusion(&p, &root), "n={n} i={i} must verify");
            }
        }
    }

    #[test]
    fn wrong_root_fails() {
        let mut t = MerkleTree::new();
        for i in 0..5 {
            t.append(&leaf(i)).unwrap();
        }
        let p = proof_for(&t, 2, &leaf(2));
        assert!(!verify_inclusion(&p, &ContentId::of(b"not the root")));
    }

    #[test]
    fn tampered_audit_path_fails() {
        let mut t = MerkleTree::new();
        for i in 0..8 {
            t.append(&leaf(i)).unwrap();
        }
        let root = t.root().unwrap();
        let mut p = proof_for(&t, 3, &leaf(3));
        p.audit_path[0] = ContentId::of(b"tampered sibling");
        assert!(!verify_inclusion(&p, &root));
    }

    #[test]
    fn wrong_leaf_index_fails() {
        let mut t = MerkleTree::new();
        for i in 0..6 {
            t.append(&leaf(i)).unwrap();
        }
        let root = t.root().unwrap();
        // Path is for leaf 4 but we claim index 1.
        let mut p = proof_for(&t, 4, &leaf(4));
        p.leaf_index = 1;
        assert!(!verify_inclusion(&p, &root));
    }

    #[test]
    fn out_of_range_index_fails_closed() {
        let mut t = MerkleTree::new();
        t.append(&leaf(0)).unwrap();
        let p = InclusionProof {
            tree_size: 1,
            leaf_index: 5,
            leaf_hash: leaf(0),
            audit_path: vec![],
        };
        assert!(!verify_inclusion(&p, &t.root().unwrap()));
    }

    // ── consistency_path — the §18.4.11 append-only proof this crate's KT logs emit ─────────────

    #[test]
    fn consistency_path_bounds_and_trivial_cases() {
        let mut t = MerkleTree::new();
        for i in 0..6 {
            t.append(&leaf(i)).unwrap();
        }
        // Nonexistent prefixes fail closed rather than yielding a plausible-looking empty proof.
        assert_eq!(t.consistency_path(0), None, "first == 0 is not a valid prefix");
        assert_eq!(t.consistency_path(7), None, "first > size is not a valid prefix");
        // The trivial no-growth case: consistency with the tree's own current size is an empty
        // path (there is nothing to prove — the trees are identical).
        assert_eq!(t.consistency_path(6), Some(Vec::new()));
        // A genuine growth prefix yields a nonempty path across non-power-of-two sizes too.
        for first in 1u64..6 {
            let path = t.consistency_path(first).expect("valid prefix must yield a path");
            assert!(!path.is_empty(), "first={first} of size 6 needs at least one sibling hash");
        }
    }
}

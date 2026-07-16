//! Key-transparency objects — spec §3.5, §18.4.9 / §18.4.10 / §18.4.11, §18.9.13.
//!
//! DMTAP's KT is an **RFC 6962-profiled** append-only Merkle log. This module models its three
//! wire objects:
//!
//! - [`SignedTreeHead`] — the signed tree head (STH) a verifier fetches, gossips, and freshness-
//!   checks. It is signed **by the log's own key** (`log_id`, field 2), not by any DMTAP identity
//!   (§18.9.13, DS-tag `DMTAP-v0/kt-sth`).
//! - [`InclusionProof`] — an RFC 6962 Merkle audit path proving a `leaf_hash` sits at `leaf_index`
//!   of the tree an STH commits to. **Unsigned** — verified arithmetically against the STH root.
//! - [`ConsistencyProof`] — an RFC 6962 consistency proof that one STH's tree is an append-only
//!   prefix of a later STH's. **Unsigned.**
//!
//! The **Identity-entry leaf-hash rule** (§18.4.9) is [`identity_leaf_hash`]: a leaf commits to the
//! *exact* `[name, ik, version, identity_id]` tuple so the log **indexes** bindings, never
//! redefines them. All objects are integer-keyed canonical CBOR (§18.1.2).

use crate::cbor::{self, as_array, as_bytes, as_u64, as_u8, CborError, Cv, Fields};
use crate::id::{ContentId, MH_BLAKE3_256};
use crate::identity::{verify_domain, Identity, IdentityError, IdentityKey};
use crate::suite::Suite;
use crate::TimestampMs;

/// §18.9.13 domain-separation tag (ASCII ‖ trailing `0x00`; `sign_domain` prepends it).
pub const KT_STH_DS: &[u8] = b"DMTAP-v0/kt-sth\x00";

fn suite_from_cv(cv: Cv) -> Result<Suite, CborError> {
    let b = as_u8(cv)?;
    Suite::from_u8(b).ok_or(CborError::UnknownSuite(b))
}

/// The Identity-entry **leaf-hash** (§18.4.9 / §18.9.13):
/// `0x1e ‖ BLAKE3-256( 0x00 ‖ det_cbor([ name, ik, version, identity_id ]) )`, using the RFC 6962
/// leaf prefix `0x00`. A verifier recomputes this from the pinned/resolved `Identity` and MUST
/// reject a proof whose committed leaf differs (`ERR_KT_LEAF_HASH_MISMATCH`, `0x0117`).
/// `RecoveryPolicy`/`KeyRotation`/`MoveRecord` leaves use the same rule with their own content
/// address in place of `identity_id`.
pub fn identity_leaf_hash(
    name: &str,
    ik: &[u8],
    version: u64,
    identity_id: &ContentId,
) -> ContentId {
    let leaf_data = cbor::encode(&Cv::Array(vec![
        Cv::Text(name.to_owned()),
        Cv::Bytes(ik.to_vec()),
        Cv::U64(version),
        Cv::Bytes(identity_id.as_bytes().to_vec()),
    ]));
    let mut buf = Vec::with_capacity(1 + leaf_data.len());
    buf.push(0x00); // RFC 6962 leaf prefix
    buf.extend_from_slice(&leaf_data);
    let digest = blake3::hash(&buf);
    let mut v = Vec::with_capacity(33);
    v.push(MH_BLAKE3_256);
    v.extend_from_slice(digest.as_bytes());
    ContentId(v)
}

// --- SignedTreeHead (§18.4.9) --------------------------------------------------------------

/// The signed tree head of a KT log (§18.4.9). Signed by the log's own key (`log_id`), versioned
/// by `tree_size` (§18.9.13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTreeHead {
    pub suite: Suite,          // key 1
    pub log_id: Vec<u8>,       // key 2 — the log's public signing key (the log IS its key)
    pub tree_size: u64,        // key 3 — number of log entries (RFC 6962 tree size)
    pub timestamp: TimestampMs, // key 4 — STH issuance time (freshness / MMD)
    pub root_hash: ContentId,  // key 5 — RFC 6962 Merkle Tree Hash (prefix ‖ digest)
    pub sig: Vec<u8>,          // key 6 — §18.9.13, over det_cbor(STH ∖ {6}) under log_id
}

impl SignedTreeHead {
    /// Integer-keyed canonical map (§18.4.9). `include_sig=false` omits key 6 for the §18.9.13
    /// signing body.
    fn to_cv(&self, include_sig: bool) -> Cv {
        let mut m = vec![
            (1u64, Cv::U64(self.suite.as_u8() as u64)),
            (2, Cv::Bytes(self.log_id.clone())),
            (3, Cv::U64(self.tree_size)),
            (4, Cv::U64(self.timestamp)),
            (5, Cv::Bytes(self.root_hash.as_bytes().to_vec())),
        ];
        if include_sig {
            m.push((6, Cv::Bytes(self.sig.clone())));
        }
        Cv::Map(m)
    }

    /// The exact wire bytes: §18-canonical integer-keyed CBOR.
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(true))
    }

    /// The §18.9.13 signing body: deterministic CBOR of the STH with `sig` (key 6) omitted.
    pub fn signing_body(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(false))
    }

    /// Decode an STH (§18.4.9), failing closed on any violation.
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cbor::decode(bytes)?)?;
        let suite = suite_from_cv(f.req(1)?)?;
        let log_id = as_bytes(f.req(2)?)?;
        let tree_size = as_u64(f.req(3)?)?;
        let timestamp = as_u64(f.req(4)?)?;
        let root_hash = ContentId(as_bytes(f.req(5)?)?);
        let sig = as_bytes(f.req(6)?)?;
        f.deny_unknown()?;
        Ok(SignedTreeHead { suite, log_id, tree_size, timestamp, root_hash, sig })
    }

    /// Sign an STH with the log's key (§18.9.13); `log_id` is set from the signer.
    pub fn issue(
        log_key: &IdentityKey,
        tree_size: u64,
        timestamp: TimestampMs,
        root_hash: ContentId,
    ) -> SignedTreeHead {
        let mut s = SignedTreeHead {
            suite: Suite::Classical,
            log_id: log_key.public(),
            tree_size,
            timestamp,
            root_hash,
            sig: Vec::new(),
        };
        s.sig = log_key.sign_domain(KT_STH_DS, &s.signing_body());
        s
    }

    /// Verify the STH signature under `log_id` (§18.9.13). Failure ⇒ `ERR_KT_PROOF_INVALID`.
    pub fn verify(&self) -> Result<(), IdentityError> {
        if !self.suite.is_supported() {
            return Err(IdentityError::UnsupportedSuite(self.suite.as_u8()));
        }
        verify_domain(&self.log_id, KT_STH_DS, &self.signing_body(), &self.sig)
    }
}

// --- InclusionProof (§18.4.10) -------------------------------------------------------------

/// An RFC 6962 Merkle audit path (§18.4.10). **Unsigned** — verified against an STH `root_hash`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    pub tree_size: u64,          // key 1 — the STH tree_size this path reconstructs to
    pub leaf_index: u64,         // key 2 — 0-based index of the leaf (< tree_size)
    pub leaf_hash: ContentId,    // key 3 — the leaf being proven (§18.4.9 rule)
    pub audit_path: Vec<ContentId>, // key 4 — sibling hashes bottom-to-top; MAY be empty
}

impl InclusionProof {
    fn to_cv(&self) -> Cv {
        Cv::Map(vec![
            (1, Cv::U64(self.tree_size)),
            (2, Cv::U64(self.leaf_index)),
            (3, Cv::Bytes(self.leaf_hash.as_bytes().to_vec())),
            (4, Cv::Array(self.audit_path.iter().map(|h| Cv::Bytes(h.as_bytes().to_vec())).collect())),
        ])
    }

    /// The exact wire bytes: §18-canonical integer-keyed CBOR.
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv())
    }

    /// Decode an inclusion proof (§18.4.10), failing closed on any violation.
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cbor::decode(bytes)?)?;
        let tree_size = as_u64(f.req(1)?)?;
        let leaf_index = as_u64(f.req(2)?)?;
        let leaf_hash = ContentId(as_bytes(f.req(3)?)?);
        let audit_path = as_array(f.req(4)?)?
            .into_iter()
            .map(|c| as_bytes(c).map(ContentId))
            .collect::<Result<_, _>>()?;
        f.deny_unknown()?;
        Ok(InclusionProof { tree_size, leaf_index, leaf_hash, audit_path })
    }

    /// Verify this RFC 6962 audit path folds `leaf_hash` to `root` (spec §18.4.10). A wrong path,
    /// wrong root, malformed hash, or out-of-range index fails closed with
    /// [`KtError::ProofInvalid`] (`0x0108`). This is the arithmetic the proof carries but does
    /// **not** self-verify (it is unsigned).
    pub fn verify_root(&self, root: &ContentId) -> Result<(), KtError> {
        if fold_inclusion(self, root) {
            Ok(())
        } else {
            Err(KtError::ProofInvalid)
        }
    }

    /// Verify this proof against a [`SignedTreeHead`] (spec §18.4.10): the proof MUST be relative to
    /// the STH's `tree_size` and fold to its `root_hash`, else [`KtError::ProofInvalid`] (`0x0108`).
    /// (The STH's own signature is verified separately via [`SignedTreeHead::verify`].)
    pub fn verify_against(&self, sth: &SignedTreeHead) -> Result<(), KtError> {
        if self.tree_size != sth.tree_size {
            return Err(KtError::ProofInvalid);
        }
        self.verify_root(&sth.root_hash)
    }

    /// Full KT **identity-binding** check (spec §18.4.9, §3.5): recompute the §18.4.9 leaf from the
    /// resolved `identity` under `name` and confirm it equals this proof's committed `leaf_hash`
    /// (else [`KtError::LeafHashMismatch`], `0x0117` — the log **indexes** a binding, it does not
    /// **redefine** it), then verify the inclusion path against `sth` (else
    /// [`KtError::ProofInvalid`], `0x0108`). The caller MUST have already verified `identity` itself
    /// (`identity.verify`) and the STH signature (`sth.verify`).
    pub fn verify_identity(
        &self,
        sth: &SignedTreeHead,
        identity: &Identity,
        name: &str,
    ) -> Result<(), KtError> {
        let expected = identity_leaf_for(identity, name).ok_or(KtError::LeafHashMismatch)?;
        if self.leaf_hash != expected {
            return Err(KtError::LeafHashMismatch);
        }
        self.verify_against(sth)
    }
}

// --- ConsistencyProof (§18.4.11) -----------------------------------------------------------

/// An RFC 6962 consistency proof that an earlier STH's tree is a prefix of a later one's
/// (§18.4.11). **Unsigned** — verified against the two STH roots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsistencyProof {
    pub first_size: u64,          // key 1 — earlier tree size (≤ second_size)
    pub second_size: u64,         // key 2 — later tree size
    pub proof_path: Vec<ContentId>, // key 3 — RFC 6962 consistency nodes; MAY be empty
}

impl ConsistencyProof {
    fn to_cv(&self) -> Cv {
        Cv::Map(vec![
            (1, Cv::U64(self.first_size)),
            (2, Cv::U64(self.second_size)),
            (3, Cv::Array(self.proof_path.iter().map(|h| Cv::Bytes(h.as_bytes().to_vec())).collect())),
        ])
    }

    /// The exact wire bytes: §18-canonical integer-keyed CBOR.
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv())
    }

    /// Decode a consistency proof (§18.4.11), failing closed on any violation.
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cbor::decode(bytes)?)?;
        let first_size = as_u64(f.req(1)?)?;
        let second_size = as_u64(f.req(2)?)?;
        let proof_path = as_array(f.req(3)?)?
            .into_iter()
            .map(|c| as_bytes(c).map(ContentId))
            .collect::<Result<_, _>>()?;
        f.deny_unknown()?;
        Ok(ConsistencyProof { first_size, second_size, proof_path })
    }
}

// --- KT verification errors (§21.3) --------------------------------------------------------

/// A KT proof-verification failure, each carrying its §21.3 wire error code via [`KtError::code`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KtError {
    /// An inclusion proof does not fold to the STH `root_hash`, or a malformed/out-of-range proof
    /// (§18.4.10). `ERR_KT_PROOF_INVALID` (`0x0108`), FAIL_CLOSED_BLOCK.
    #[error("KT inclusion proof does not fold to the STH root (ERR_KT_PROOF_INVALID, 0x0108)")]
    ProofInvalid,
    /// The committed leaf ≠ the leaf recomputed from the resolved identity (§18.4.9). The log
    /// presented a binding whose leaf does not match the identity. `ERR_KT_LEAF_HASH_MISMATCH`
    /// (`0x0117`), FAIL_CLOSED_BLOCK — the log indexes, it does not redefine.
    #[error("KT committed leaf ≠ leaf recomputed from the resolved identity \
             (ERR_KT_LEAF_HASH_MISMATCH, 0x0117)")]
    LeafHashMismatch,
    /// A consistency proof between two STHs fails — the later tree is **not** an append-only
    /// extension of the earlier (a forked / non-extending log). `ERR_KT_STH_INCONSISTENT`
    /// (`0x0110`), HALT_ALERT — the append-only-violation evidence for equivocation (§3.5.2).
    #[error("KT consistency proof fails — the log is not append-only / forked \
             (ERR_KT_STH_INCONSISTENT, 0x0110)")]
    NotConsistent,
}

impl KtError {
    /// The normative DMTAP wire error code (§21.3).
    pub fn code(&self) -> u16 {
        match self {
            KtError::ProofInvalid => 0x0108,
            KtError::LeafHashMismatch => 0x0117,
            KtError::NotConsistent => 0x0110,
        }
    }
}

// --- RFC 6962 Merkle math (§3.5, §18.4.10, §18.9.5) ----------------------------------------
//
// Ported from the proven reference fold in `dmtap-naming::merkle`, using the §18.9.5 leaf prefix
// `0x00` (already applied inside `identity_leaf_hash`) and node prefix `0x01` over BLAKE3-256. Each
// `leaf_hash`'s 32-byte digest is an MTH leaf; only the node prefix is applied when folding.

/// Extract the 32-byte BLAKE3 digest from a v0 [`ContentId`] (`0x1e ‖ 32-byte digest`), or `None`
/// if the id is not a well-formed BLAKE3-256 content address — a malformed hash fails closed.
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

/// RFC 6962 Merkle Tree Hash over already-hashed leaf digests. Panics only on an empty slice —
/// callers pass `n ≥ 1`.
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

/// RFC 6962 `SUBPROOF(m, D, b)` for the consistency proof.
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

/// Fold an [`InclusionProof`] against a `root` digest. Returns `false` — never panics — on any
/// malformed hash, out-of-range index, wrong-length path, or root mismatch (RFC 6962 §2.1.1).
fn fold_inclusion(proof: &InclusionProof, root: &ContentId) -> bool {
    let leaf = match digest32(&proof.leaf_hash) {
        Some(d) => d,
        None => return false,
    };
    let root_d = match digest32(root) {
        Some(d) => d,
        None => return false,
    };
    if proof.leaf_index >= proof.tree_size {
        return false;
    }
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

/// Verify an RFC 6962 **consistency proof** that `new` is an append-only extension of `old` (spec
/// §18.4.11, §3.5.2). Checks the proof binds `old.tree_size → new.tree_size`, then folds the
/// [`ConsistencyProof`] to reconstruct **both** the old root (from a prefix of the later tree) and
/// the new root; any divergence — a forked or non-extending log — fails closed with
/// [`KtError::NotConsistent`] (`0x0110`, the append-only-violation evidence for equivocation). The
/// two STHs' own signatures are verified separately.
pub fn verify_consistency(
    old: &SignedTreeHead,
    new: &SignedTreeHead,
    proof: &ConsistencyProof,
) -> Result<(), KtError> {
    let m = old.tree_size;
    let n = new.tree_size;
    // The proof must bind exactly these two tree sizes and be an extension (m ≤ n).
    if proof.first_size != m || proof.second_size != n || m > n {
        return Err(KtError::NotConsistent);
    }
    let old_root = digest32(&old.root_hash).ok_or(KtError::NotConsistent)?;
    let new_root = digest32(&new.root_hash).ok_or(KtError::NotConsistent)?;
    // Equal sizes: the proof MUST be empty and the roots MUST match.
    if m == n {
        return if proof.proof_path.is_empty() && old_root == new_root {
            Ok(())
        } else {
            Err(KtError::NotConsistent)
        };
    }
    // Empty first tree: every later tree extends it; an empty proof is consistent.
    if m == 0 {
        return if proof.proof_path.is_empty() { Ok(()) } else { Err(KtError::NotConsistent) };
    }
    // Decode the proof-path digests up front (any malformed hash fails closed).
    let mut path: Vec<[u8; 32]> = Vec::with_capacity(proof.proof_path.len());
    for h in &proof.proof_path {
        path.push(digest32(h).ok_or(KtError::NotConsistent)?);
    }
    let mut it = path.iter();

    // RFC 6962 §2.1.2 verification (the canonical CT `merkle_verifier` fold).
    let mut node_idx = m - 1;
    let mut last_idx = n - 1;
    while node_idx & 1 == 1 {
        node_idx >>= 1;
        last_idx >>= 1;
    }
    let next = |it: &mut std::slice::Iter<'_, [u8; 32]>| it.next().copied();

    let (mut old_hash, mut new_hash) = if node_idx > 0 {
        match next(&mut it) {
            Some(h) => (h, h),
            None => return Err(KtError::NotConsistent),
        }
    } else {
        // `m` is a power of two: the first subtree root is the old root itself.
        (old_root, old_root)
    };

    while node_idx > 0 {
        if node_idx & 1 == 1 {
            // right child: combine with the left sibling from the proof.
            let s = match next(&mut it) {
                Some(h) => h,
                None => return Err(KtError::NotConsistent),
            };
            old_hash = node(&s, &old_hash);
            new_hash = node(&s, &new_hash);
        } else if node_idx < last_idx {
            // left child with a right sibling: only the new tree grows to the right.
            let s = match next(&mut it) {
                Some(h) => h,
                None => return Err(KtError::NotConsistent),
            };
            new_hash = node(&new_hash, &s);
        }
        // else: left child, no sibling — carry up unchanged.
        node_idx >>= 1;
        last_idx >>= 1;
    }

    // Fold the remaining right-hand nodes into the new-tree hash.
    while last_idx > 0 {
        let s = match next(&mut it) {
            Some(h) => h,
            None => return Err(KtError::NotConsistent),
        };
        new_hash = node(&new_hash, &s);
        last_idx >>= 1;
    }

    // The proof must be fully consumed, and both reconstructed roots must match.
    if it.next().is_some() || old_hash != old_root || new_hash != new_root {
        return Err(KtError::NotConsistent);
    }
    Ok(())
}

// --- Identity leaf binding (§18.4.9) -------------------------------------------------------

/// Recompute the §18.4.9 KT leaf for `name`'s current [`Identity`]: the [`identity_leaf_hash`] over
/// `[name, ik, version, identity_id]`, where `ik` is the identity's classical key and `identity_id`
/// is its content address. `None` if the identity has no classical suite key. This is the value a
/// verifier compares against a presented [`InclusionProof::leaf_hash`] (see
/// [`InclusionProof::verify_identity`]).
pub fn identity_leaf_for(identity: &Identity, name: &str) -> Option<ContentId> {
    let ik = identity.iks.get(&Suite::Classical.as_u8())?;
    Some(identity_leaf_hash(name, ik, identity.version, &identity.content_id()))
}

// --- In-memory RFC 6962 tree (reference log) -----------------------------------------------

/// An in-memory RFC 6962 Merkle tree over leaf hashes (§18.4.9), used to compute roots and emit
/// real audit / consistency paths. Not a persistent log — a reference structure whose proofs
/// [`InclusionProof::verify_root`] and [`verify_consistency`] accept.
#[derive(Debug, Default, Clone)]
pub struct MerkleTree {
    leaves: Vec<[u8; 32]>,
}

impl MerkleTree {
    /// An empty tree.
    pub fn new() -> Self {
        MerkleTree { leaves: Vec::new() }
    }

    /// Append a leaf (its §18.4.9 `leaf_hash`), returning its 0-based index, or `None` on a
    /// malformed (non-BLAKE3) leaf hash so the tree only ever holds well-formed leaves.
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

    /// The RFC 6962 consistency-proof nodes proving the current tree extends its own prefix of size
    /// `first`, or `None` if `first == 0` or `first > size` (an empty proof for `first == size`).
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

    fn key(seed: u8) -> IdentityKey {
        IdentityKey::from_seed(&[seed; 32])
    }

    #[test]
    fn sth_signs_verifies_and_round_trips() {
        let sth = SignedTreeHead::issue(
            &key(0x11),
            7,
            1_700_000_000_000,
            ContentId::of(b"kt-root"),
        );
        assert!(sth.verify().is_ok());
        let bytes = sth.det_cbor();
        assert_eq!(bytes[0] & 0xe0, 0xa0, "STH is a CBOR map");
        assert_eq!(bytes[1], 0x01, "first key is integer 1 (suite), not a text key");
        let back = SignedTreeHead::from_det_cbor(&bytes).unwrap();
        assert_eq!(sth, back);
        assert_eq!(bytes, back.det_cbor());
        assert!(back.verify().is_ok());
    }

    #[test]
    fn tampered_sth_fails_signature() {
        let mut sth = SignedTreeHead::issue(&key(0x11), 7, 1, ContentId::of(b"kt-root"));
        sth.tree_size = 8; // signed field changed
        assert_eq!(sth.verify(), Err(IdentityError::BadSignature));
    }

    #[test]
    fn inclusion_proof_round_trips() {
        let p = InclusionProof {
            tree_size: 5,
            leaf_index: 2,
            leaf_hash: ContentId::of(b"leaf"),
            audit_path: vec![ContentId::of(b"s0"), ContentId::of(b"s1")],
        };
        let bytes = p.det_cbor();
        let back = InclusionProof::from_det_cbor(&bytes).unwrap();
        assert_eq!(p, back);
        assert_eq!(bytes, back.det_cbor());
    }

    #[test]
    fn consistency_proof_round_trips_including_empty_path() {
        let p = ConsistencyProof { first_size: 3, second_size: 7, proof_path: vec![] };
        let bytes = p.det_cbor();
        let back = ConsistencyProof::from_det_cbor(&bytes).unwrap();
        assert_eq!(p, back);
        assert_eq!(bytes, back.det_cbor());
    }

    #[test]
    fn identity_leaf_hash_is_prefixed_and_deterministic() {
        let ik = key(0x22).public();
        let id = ContentId::of(b"the-identity");
        let a = identity_leaf_hash("alice@abc.com", &ik, 3, &id);
        let b = identity_leaf_hash("alice@abc.com", &ik, 3, &id);
        assert_eq!(a, b, "leaf hash is a pure function of the tuple");
        assert_eq!(a.algorithm(), Some(MH_BLAKE3_256));
        assert_eq!(a.digest().len(), 32);
        // Any change to the tuple changes the leaf.
        assert_ne!(a, identity_leaf_hash("alice@abc.com", &ik, 4, &id));
    }

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
    fn inclusion_verifies_and_bad_path_or_root_fails_closed() {
        for n in 1u8..=13 {
            let mut t = MerkleTree::new();
            let leaves: Vec<ContentId> = (0..n).map(leaf).collect();
            for l in &leaves {
                t.append(l).unwrap();
            }
            let root = t.root().unwrap();
            for (i, l) in leaves.iter().enumerate() {
                let p = proof_for(&t, i as u64, l);
                assert!(p.verify_root(&root).is_ok(), "n={n} i={i} must verify");
            }
        }
        // Wrong root and tampered path fail closed with 0x0108.
        let mut t = MerkleTree::new();
        for i in 0..8 {
            t.append(&leaf(i)).unwrap();
        }
        let root = t.root().unwrap();
        let mut p = proof_for(&t, 3, &leaf(3));
        assert_eq!(p.verify_root(&ContentId::of(b"nope")), Err(KtError::ProofInvalid));
        p.audit_path[0] = ContentId::of(b"tampered sibling");
        let err = p.verify_root(&root).unwrap_err();
        assert_eq!(err, KtError::ProofInvalid);
        assert_eq!(err.code(), 0x0108);
    }

    #[test]
    fn inclusion_verify_against_sth_checks_tree_size() {
        let mut t = MerkleTree::new();
        for i in 0..5 {
            t.append(&leaf(i)).unwrap();
        }
        let sth = SignedTreeHead::issue(&key(9), t.size(), 1, t.root().unwrap());
        let good = proof_for(&t, 2, &leaf(2));
        assert!(good.verify_against(&sth).is_ok());
        // A proof claiming a different tree_size than the STH is rejected.
        let mut wrong = good.clone();
        wrong.tree_size = 4;
        assert_eq!(wrong.verify_against(&sth), Err(KtError::ProofInvalid));
    }

    fn test_identity(name: &str, seed: u8) -> Identity {
        use crate::identity::KeyPackageBundleRef;
        Identity::create_classical(
            &key(seed),
            0,
            vec![],
            KeyPackageBundleRef::new("/mesh/kp", ContentId::of(b"kp")),
            ContentId::of(b"rec"),
            vec![name.to_owned()],
            None,
            1_700_000_000_000,
        )
    }

    #[test]
    fn leaf_binding_rejects_a_leaf_for_a_different_identity() {
        let name = "alice@abc.com";
        let id = test_identity(name, 1);
        let evil = test_identity(name, 2); // same name, different ik
        let evil_leaf = identity_leaf_for(&evil, name).unwrap();

        let mut t = MerkleTree::new();
        t.append(&ContentId::of(b"filler")).unwrap();
        let idx = t.append(&evil_leaf).unwrap();
        let sth = SignedTreeHead::issue(&key(9), t.size(), 1, t.root().unwrap());
        let proof = InclusionProof {
            tree_size: t.size(),
            leaf_index: idx,
            leaf_hash: evil_leaf.clone(),
            audit_path: t.inclusion_path(idx).unwrap(),
        };
        // The inclusion path itself is valid (the evil leaf IS in the tree) ...
        assert!(proof.verify_against(&sth).is_ok());
        // ... but the committed leaf does not match the leaf recomputed for the REAL identity.
        let err = proof.verify_identity(&sth, &id, name).unwrap_err();
        assert_eq!(err, KtError::LeafHashMismatch);
        assert_eq!(err.code(), 0x0117);
        // The honest binding verifies end to end.
        let real_leaf = identity_leaf_for(&id, name).unwrap();
        let mut t2 = MerkleTree::new();
        let i2 = t2.append(&real_leaf).unwrap();
        let sth2 = SignedTreeHead::issue(&key(9), t2.size(), 1, t2.root().unwrap());
        let good = InclusionProof {
            tree_size: t2.size(),
            leaf_index: i2,
            leaf_hash: real_leaf,
            audit_path: t2.inclusion_path(i2).unwrap(),
        };
        assert!(good.verify_identity(&sth2, &id, name).is_ok());
    }

    fn tree_of(n: u64) -> MerkleTree {
        let mut t = MerkleTree::new();
        for i in 0..n {
            t.append(&ContentId::of(&i.to_be_bytes())).unwrap();
        }
        t
    }

    #[test]
    fn consistency_accepts_append_only_and_rejects_forks() {
        // For every (m ≤ n), a genuine append-only extension verifies; a forged root fails 0x0110.
        for n in 1u64..=12 {
            for m in 1..=n {
                let older = tree_of(m);
                let newer = tree_of(n); // same first m leaves, then extended
                let old_sth = SignedTreeHead::issue(&key(9), m, 1, older.root().unwrap());
                let new_sth = SignedTreeHead::issue(&key(9), n, 2, newer.root().unwrap());
                let proof = ConsistencyProof {
                    first_size: m,
                    second_size: n,
                    proof_path: newer.consistency_path(m).unwrap(),
                };
                assert!(
                    verify_consistency(&old_sth, &new_sth, &proof).is_ok(),
                    "m={m} n={n} append-only extension must verify"
                );
            }
        }
        // A forked newer tree (different leaf at an earlier index) is NOT an extension.
        let older = tree_of(4);
        // Size-7 tree but with a divergent leaf at index 0.
        let mut forked = MerkleTree::new();
        forked.append(&ContentId::of(b"DIVERGENT")).unwrap();
        for i in 1..7u64 {
            forked.append(&ContentId::of(&i.to_be_bytes())).unwrap();
        }
        let old_sth = SignedTreeHead::issue(&key(9), 4, 1, older.root().unwrap());
        let new_sth = SignedTreeHead::issue(&key(9), 7, 2, forked.root().unwrap());
        // Use the (honest-shaped) consistency path from the forked tree; verification must still
        // reject because the reconstructed old root will not match the pinned older STH.
        let proof = ConsistencyProof {
            first_size: 4,
            second_size: 7,
            proof_path: forked.consistency_path(4).unwrap(),
        };
        let err = verify_consistency(&old_sth, &new_sth, &proof).unwrap_err();
        assert_eq!(err, KtError::NotConsistent);
        assert_eq!(err.code(), 0x0110);
    }
}

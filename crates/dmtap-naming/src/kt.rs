//! KT-verified binding checks — spec §3.5, §3.5.2, §18.4.9/.10.
//!
//! This module turns a fetched `Identity` + a log's `SignedTreeHead` + `InclusionProof` into a
//! **verified, pinnable binding**, or a typed fail-closed error. It implements:
//!
//! - [`verify_attestation`] — the single-log §3.5 check: the STH is signed by the *pinned* log key,
//!   the inclusion proof folds to the STH root, and the committed leaf equals the leaf recomputed
//!   from the resolved `Identity` (§18.4.9). No TOFU, no downgrade.
//! - [`verify_quorum`] — the §3.5.2(b) v1 path: accept a binding only on a **strict `> n/2`
//!   majority** of the pinned log set; below quorum fail closed (`0x0111`).
//! - [`detect_equivocation`] / [`check_freshness`] — the §3.5.2(a)/(d) split-view and freeze-attack
//!   detectors.
//!
//! The [`KtLog`] trait is the fetch seam: an [`InMemoryKtLog`] backs unit tests with real STHs and
//! audit paths; an [`UnreachableLog`] models a partitioned/censored log so the §3.3 fail-closed
//! (no-TOFU) path is exercised; a real HTTP KT client is a thin later layer implementing the same
//! trait.

use dmtap_core::id::ContentId;
use dmtap_core::identity::{Identity, IdentityKey};
use dmtap_core::kt::{
    identity_leaf_hash, verify_consistency as core_verify_consistency, ConsistencyProof,
    InclusionProof, SignedTreeHead,
};
use dmtap_core::{Suite, TimestampMs};

use crate::error::ResolveError;
use crate::merkle::{self, MerkleTree};

/// A log's response to a proof request: the current STH plus an inclusion proof for the leaf. The
/// KT analog of a resolved record — verified, never trusted, by [`verify_attestation`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KtProof {
    pub sth: SignedTreeHead,
    pub proof: InclusionProof,
}

/// The KT log fetch seam (§3.5). A verifier pins a log by its `log_id` (the log's own signing key,
/// §18.4.9) and asks it to prove a leaf's inclusion. `prove` returning `None` models an
/// **unreachable/partitioned/censored** log — the §3.3 condition that MUST fail closed rather than
/// TOFU-pin.
pub trait KtLog {
    /// The pinned log signing key (§18.4.9 `log_id`).
    fn log_id(&self) -> Vec<u8>;
    /// Prove `leaf`'s inclusion, returning the log's current STH + an audit path, or `None` if the
    /// log is unreachable. The STH carries the log's own issuance timestamp (§18.4.9) — which MAY be
    /// old, the freeze/withholding attack the verifier's freshness check ([`check_freshness`])
    /// catches — not the verifier's clock.
    fn prove(&self, leaf: &ContentId) -> Option<KtProof>;
}

/// A reachable in-memory KT log (§3.5.1 v0-minimal profile): a real RFC 6962 Merkle tree signed by
/// the log's own key. Appends identity leaves, issues signed tree heads, and emits verifiable
/// inclusion proofs — the reference backing for offline tests.
pub struct InMemoryKtLog {
    log_key: IdentityKey,
    tree: MerkleTree,
    /// leaf_hash bytes → leaf index, for `prove`-by-leaf lookup.
    index: std::collections::HashMap<Vec<u8>, u64>,
    /// The timestamp this log stamps on the STHs it issues (§18.4.9). Independent of the verifier's
    /// clock, so a fixed/old value models a **frozen** head (freeze attack, §3.5.2(a)).
    issued_at: TimestampMs,
}

impl InMemoryKtLog {
    /// A new empty log signed by `log_key`, issuing STHs stamped at time 0 (override with
    /// [`set_issued_at`](InMemoryKtLog::set_issued_at)).
    pub fn new(log_key: IdentityKey) -> Self {
        InMemoryKtLog {
            log_key,
            tree: MerkleTree::new(),
            index: std::collections::HashMap::new(),
            issued_at: 0,
        }
    }

    /// Set the timestamp this log stamps on issued STHs (§18.4.9) — a stale value models a frozen
    /// head for the freeze-attack test.
    pub fn set_issued_at(&mut self, t: TimestampMs) {
        self.issued_at = t;
    }

    /// Append a raw leaf hash (§18.4.9), returning its index.
    pub fn append_leaf(&mut self, leaf: &ContentId) -> u64 {
        let idx = self.tree.append(leaf).expect("well-formed leaf hash");
        self.index.insert(leaf.as_bytes().to_vec(), idx);
        idx
    }

    /// Append the KT leaf for `name`'s current `Identity` (the common case): computes the §18.4.9
    /// `[name, ik, version, identity_id]` leaf and appends it. Returns the leaf index (or `None` if
    /// the identity has no classical `ik`).
    pub fn append_identity(&mut self, name: &str, identity: &Identity) -> Option<u64> {
        let leaf = leaf_for(name, identity)?;
        Some(self.append_leaf(&leaf))
    }

    /// Issue a signed tree head over the current tree at the log's `issued_at` time (§18.4.9).
    pub fn sth(&self) -> SignedTreeHead {
        let root = self.tree.root().unwrap_or_else(|| ContentId::of(b""));
        SignedTreeHead::issue(&self.log_key, self.tree.size(), self.issued_at, root)
    }

    /// Build the RFC 6962 consistency proof (§18.4.11) that the log's *current* tree is an
    /// append-only extension of its own earlier state at size `first` — the wire object a verifier
    /// checks with [`verify_sth_consistency`]. `None` if `first` is not a valid earlier size (`0`
    /// or greater than the current size).
    pub fn consistency_proof(&self, first_size: u64) -> Option<ConsistencyProof> {
        let proof_path = self.tree.consistency_path(first_size)?;
        Some(ConsistencyProof { first_size, second_size: self.tree.size(), proof_path })
    }
}

impl KtLog for InMemoryKtLog {
    fn log_id(&self) -> Vec<u8> {
        self.log_key.public()
    }

    fn prove(&self, leaf: &ContentId) -> Option<KtProof> {
        let idx = *self.index.get(leaf.as_bytes())?;
        let path = self.tree.inclusion_path(idx)?;
        let sth = self.sth();
        let proof = InclusionProof {
            tree_size: sth.tree_size,
            leaf_index: idx,
            leaf_hash: leaf.clone(),
            audit_path: path,
        };
        Some(KtProof { sth, proof })
    }
}

/// A log that is always unreachable (§3.3 partition/censorship). Its `prove` always returns `None`,
/// so a resolver relying on it fails closed with `ERR_KT_UNREACHABLE` (`0x0106`) — never TOFU.
pub struct UnreachableLog {
    pub log_id: Vec<u8>,
}

impl KtLog for UnreachableLog {
    fn log_id(&self) -> Vec<u8> {
        self.log_id.clone()
    }
    fn prove(&self, _leaf: &ContentId) -> Option<KtProof> {
        None
    }
}

/// Recompute the §18.4.9 KT leaf for `name`'s current `Identity`: the leaf hash over
/// `[name, ik, version, identity_id]`, where `ik` is the identity's classical key and
/// `identity_id` is its content address. `None` if the identity has no classical suite key.
pub fn leaf_for(name: &str, identity: &Identity) -> Option<ContentId> {
    let ik = identity.iks.get(&Suite::Classical.as_u8())?;
    Some(identity_leaf_hash(name, ik, identity.version, &identity.content_id()))
}

/// Cross-check the DNS pointer against the fetched `Identity` (§3.3 step 3–4): the DNS `id` MUST be
/// the identity's content address and the DNS `ik` MUST be its classical key. A mismatch means the
/// pointer and the signed object disagree — fail closed, never trust the pointer.
pub fn check_dns_matches_identity(
    dns_ik: &[u8],
    dns_id: &ContentId,
    identity: &Identity,
) -> Result<(), ResolveError> {
    if &identity.content_id() != dns_id {
        return Err(ResolveError::DnsIdentityMismatch("DNS id ≠ Identity content address"));
    }
    match identity.iks.get(&Suite::Classical.as_u8()) {
        Some(ik) if ik.as_slice() == dns_ik => Ok(()),
        Some(_) => Err(ResolveError::DnsIdentityMismatch("DNS ik ≠ Identity classical ik")),
        None => Err(ResolveError::DnsIdentityMismatch("Identity has no classical ik")),
    }
}

/// Verify one log's attestation of `name → Identity` (§3.5, single-log v0 path). Steps, all
/// fail-closed:
///
/// 1. The STH is signed by **this pinned** `log_id` (§18.4.9) — else `ERR_KT_PROOF_INVALID`.
/// 2. The proof is relative to the STH's `tree_size` (§18.4.10).
/// 3. The committed `leaf_hash` equals the leaf recomputed from the resolved `Identity` (§18.4.9) —
///    else `ERR_KT_LEAF_HASH_MISMATCH` (`0x0117`): the log indexes, it does not redefine.
/// 4. The inclusion proof folds to the STH `root_hash` (§18.4.10) — else `ERR_KT_PROOF_INVALID`.
///
/// The caller MUST have already verified the `Identity` itself (`identity.verify`) and the
/// DNS↔identity match ([`check_dns_matches_identity`]); this function proves the KT binding.
pub fn verify_attestation(
    name: &str,
    identity: &Identity,
    pinned_log_id: &[u8],
    att: &KtProof,
) -> Result<(), ResolveError> {
    // 1. STH must be signed by the pinned log key.
    if att.sth.log_id.as_slice() != pinned_log_id {
        return Err(ResolveError::KtProofInvalid);
    }
    att.sth.verify().map_err(|_| ResolveError::KtProofInvalid)?;

    // 2. Proof is relative to this STH.
    if att.proof.tree_size != att.sth.tree_size {
        return Err(ResolveError::KtProofInvalid);
    }

    // 3. Committed leaf must equal the leaf recomputed from the resolved identity.
    let expected = leaf_for(name, identity)
        .ok_or(ResolveError::DnsIdentityMismatch("Identity has no classical ik"))?;
    if att.proof.leaf_hash != expected {
        return Err(ResolveError::KtLeafHashMismatch);
    }

    // 4. Inclusion proof must fold to the STH root.
    if !merkle::verify_inclusion(&att.proof, &att.sth.root_hash) {
        return Err(ResolveError::KtProofInvalid);
    }
    Ok(())
}

/// Verify a binding against a **pinned set** of logs under the v1 quorum rule (§3.5.2(b)).
///
/// `attestations` pairs each `(pinned_log_id, Option<KtProof>)`: `None` = the log was unreachable
/// (partitioned/censored). A binding is accepted only when a **strict `> n/2` majority** of the
/// pinned set both attest and *agree* (a valid attestation for the recomputed leaf). Below that,
/// resolution fails closed with `ERR_KT_LOG_QUORUM_UNMET` (`0x0111`) — a minority of malicious or
/// partitioned logs can therefore neither forge nor suppress a binding, and no single log is
/// authoritative. Returns the list of `log_id`s that attested on success.
pub fn verify_quorum(
    name: &str,
    identity: &Identity,
    attestations: &[(Vec<u8>, Option<KtProof>)],
) -> Result<Vec<Vec<u8>>, ResolveError> {
    let n = attestations.len();
    let mut agreeing: Vec<Vec<u8>> = Vec::new();
    for (log_id, maybe) in attestations {
        if let Some(att) = maybe {
            // A single bad/forged proof from one log is not fatal — it simply does not count toward
            // the quorum (a minority cannot forge). Only a genuine, agreeing attestation counts.
            if verify_attestation(name, identity, log_id, att).is_ok() {
                agreeing.push(log_id.clone());
            }
        }
    }
    // Strict majority: |agree| > n/2  ⇔  2·|agree| > n.
    if agreeing.len() * 2 > n {
        Ok(agreeing)
    } else {
        Err(ResolveError::KtQuorumUnmet)
    }
}

/// Detect equivocation between two STHs claimed to come from the **same** log (§3.5.2(d)(i)). Two
/// validly-signed heads of one `log_id` with **equal `tree_size` but differing `root_hash`** are
/// self-contained, transferable proof the log showed two histories — `ERR_KT_EQUIVOCATION`
/// (`0x0107`), the HALT_ALERT the split-view response mandates. STHs from different logs, or with
/// different sizes, are not comparable here (a consistency proof handles the append-only case).
/// A head that does not validly sign under its stated key is `ERR_KT_PROOF_INVALID`.
pub fn detect_equivocation(a: &SignedTreeHead, b: &SignedTreeHead) -> Result<(), ResolveError> {
    a.verify().map_err(|_| ResolveError::KtProofInvalid)?;
    b.verify().map_err(|_| ResolveError::KtProofInvalid)?;
    if a.log_id != b.log_id {
        return Ok(()); // different logs — not an equivocation of one log
    }
    if a.tree_size == b.tree_size && a.root_hash != b.root_hash {
        return Err(ResolveError::KtEquivocation);
    }
    Ok(())
}

/// STH freshness check (§3.5.2(a), §16.2): an STH older than `window` ms relative to `now` is stale
/// — `ERR_KT_STH_STALE` (`0x0112`), the freeze-attack defense where a log serves an old but
/// self-consistent head to a targeted observer.
pub fn check_freshness(
    sth: &SignedTreeHead,
    now: TimestampMs,
    window: TimestampMs,
) -> Result<(), ResolveError> {
    if now.saturating_sub(sth.timestamp) > window {
        Err(ResolveError::KtSthStale)
    } else {
        Ok(())
    }
}

/// Verify that `new`'s tree is a genuine append-only extension of `old`'s, both signed by the
/// **same pinned log** (§3.5.2(a)/(d)) — the append-only-violation evidence for equivocation. A
/// consistency proof is only meaningful between two heads of one log, so both STH signatures are
/// checked against `pinned_log_id` first (a proof relating an unpinned or mismatched log proves
/// nothing about *this* log's history); the RFC 6962 fold itself is `dmtap-core`'s
/// [`core_verify_consistency`]. Any failure — a forged/tampered proof path, a genuinely forked or
/// non-extending history, or a tree that shrank — fails closed as `ERR_KT_STH_INCONSISTENT`
/// (`0x0110`), HALT_ALERT: the log must be treated as equivocating, never silently trusted.
pub fn verify_sth_consistency(
    pinned_log_id: &[u8],
    old: &SignedTreeHead,
    new: &SignedTreeHead,
    proof: &ConsistencyProof,
) -> Result<(), ResolveError> {
    if old.log_id.as_slice() != pinned_log_id || new.log_id.as_slice() != pinned_log_id {
        return Err(ResolveError::KtProofInvalid);
    }
    old.verify().map_err(|_| ResolveError::KtProofInvalid)?;
    new.verify().map_err(|_| ResolveError::KtProofInvalid)?;
    core_verify_consistency(old, new, proof).map_err(|_| ResolveError::KtSthInconsistent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dmtap_core::identity::KeyPackageBundleRef;

    const NOW: TimestampMs = 1_700_000_000_000;

    fn identity_for(name: &str, seed: u8) -> (IdentityKey, Identity) {
        let ik = IdentityKey::from_seed(&[seed; 32]);
        let id = Identity::create_classical(
            &ik,
            0,
            vec![],
            KeyPackageBundleRef::new("/mesh/kp", ContentId::of(b"kp")),
            ContentId::of(b"recovery"),
            vec![name.to_owned()],
            None,
            NOW,
        );
        (ik, id)
    }

    fn log_with(name: &str, identity: &Identity, seed: u8) -> InMemoryKtLog {
        let mut log = InMemoryKtLog::new(IdentityKey::from_seed(&[seed; 32]));
        // Add some unrelated leaves so the tree is non-trivial and the proof has a real path.
        log.append_leaf(&ContentId::of(b"unrelated-a"));
        log.append_identity(name, identity).unwrap();
        log.append_leaf(&ContentId::of(b"unrelated-b"));
        log
    }

    #[test]
    fn happy_path_single_log_verifies() {
        let (_ik, id) = identity_for("alice@example.com", 1);
        let log = log_with("alice@example.com", &id, 9);
        let leaf = leaf_for("alice@example.com", &id).unwrap();
        let att = log.prove(&leaf).unwrap();
        assert!(verify_attestation("alice@example.com", &id, &log.log_id(), &att).is_ok());
    }

    #[test]
    fn forged_sth_signature_fails() {
        let (_ik, id) = identity_for("alice@example.com", 1);
        let log = log_with("alice@example.com", &id, 9);
        let leaf = leaf_for("alice@example.com", &id).unwrap();
        let mut att = log.prove(&leaf).unwrap();
        att.sth.sig[0] ^= 0xff; // tamper the log signature
        assert_eq!(
            verify_attestation("alice@example.com", &id, &log.log_id(), &att),
            Err(ResolveError::KtProofInvalid)
        );
    }

    #[test]
    fn wrong_pinned_log_key_fails() {
        let (_ik, id) = identity_for("alice@example.com", 1);
        let log = log_with("alice@example.com", &id, 9);
        let leaf = leaf_for("alice@example.com", &id).unwrap();
        let att = log.prove(&leaf).unwrap();
        let other = IdentityKey::from_seed(&[0xaa; 32]).public();
        assert_eq!(
            verify_attestation("alice@example.com", &id, &other, &att),
            Err(ResolveError::KtProofInvalid)
        );
    }

    #[test]
    fn bad_inclusion_proof_fails() {
        let (_ik, id) = identity_for("alice@example.com", 1);
        let log = log_with("alice@example.com", &id, 9);
        let leaf = leaf_for("alice@example.com", &id).unwrap();
        let mut att = log.prove(&leaf).unwrap();
        att.proof.audit_path[0] = ContentId::of(b"tampered");
        assert_eq!(
            verify_attestation("alice@example.com", &id, &log.log_id(), &att),
            Err(ResolveError::KtProofInvalid)
        );
    }

    #[test]
    fn leaf_hash_mismatch_fails() {
        // The log commits a leaf for a DIFFERENT ik; the resolver recomputes the real leaf and the
        // committed leaf will not match -> 0x0117.
        let (_ik, id) = identity_for("alice@example.com", 1);
        let (_ik2, evil) = identity_for("alice@example.com", 2);
        let mut log = InMemoryKtLog::new(IdentityKey::from_seed(&[9; 32]));
        let evil_leaf = leaf_for("alice@example.com", &evil).unwrap();
        log.append_leaf(&evil_leaf);
        // The log can only prove the leaf it holds (evil_leaf); verify against the real identity.
        let att = log.prove(&evil_leaf).unwrap();
        assert_eq!(
            verify_attestation("alice@example.com", &id, &log.log_id(), &att),
            Err(ResolveError::KtLeafHashMismatch)
        );
    }

    #[test]
    fn quorum_accepts_strict_majority_and_fails_below() {
        let (_ik, id) = identity_for("alice@example.com", 1);
        let name = "alice@example.com";
        let leaf = leaf_for(name, &id).unwrap();

        let logs: Vec<InMemoryKtLog> =
            (0..3).map(|s| log_with(name, &id, 20 + s as u8)).collect();
        let ids: Vec<Vec<u8>> = logs.iter().map(|l| l.log_id()).collect();

        // All three reachable -> quorum met.
        let all: Vec<(Vec<u8>, Option<KtProof>)> = logs
            .iter()
            .zip(&ids)
            .map(|(l, lid)| (lid.clone(), l.prove(&leaf)))
            .collect();
        assert_eq!(verify_quorum(name, &id, &all).unwrap().len(), 3);

        // 2 of 3 reachable -> still > n/2.
        let two = vec![
            (ids[0].clone(), logs[0].prove(&leaf)),
            (ids[1].clone(), logs[1].prove(&leaf)),
            (ids[2].clone(), None),
        ];
        assert_eq!(verify_quorum(name, &id, &two).unwrap().len(), 2);

        // 1 of 3 reachable -> sub-quorum, fail closed.
        let one = vec![
            (ids[0].clone(), logs[0].prove(&leaf)),
            (ids[1].clone(), None),
            (ids[2].clone(), None),
        ];
        assert_eq!(verify_quorum(name, &id, &one), Err(ResolveError::KtQuorumUnmet));
    }

    #[test]
    fn quorum_ignores_a_forged_minority_log() {
        // Two honest logs + one forger (commits an evil leaf). The forger cannot count toward
        // quorum, but the two honest logs still form a strict majority.
        let (_ik, id) = identity_for("alice@example.com", 1);
        let (_e, evil) = identity_for("alice@example.com", 2);
        let name = "alice@example.com";
        let leaf = leaf_for(name, &id).unwrap();
        let evil_leaf = leaf_for(name, &evil).unwrap();

        let h1 = log_with(name, &id, 30);
        let h2 = log_with(name, &id, 31);
        let mut forger = InMemoryKtLog::new(IdentityKey::from_seed(&[32; 32]));
        forger.append_leaf(&evil_leaf);

        let atts = vec![
            (h1.log_id(), h1.prove(&leaf)),
            (h2.log_id(), h2.prove(&leaf)),
            (forger.log_id(), forger.prove(&evil_leaf)),
        ];
        let ok = verify_quorum(name, &id, &atts).unwrap();
        assert_eq!(ok.len(), 2, "only the two honest logs count");
        assert!(!ok.contains(&forger.log_id()));
    }

    #[test]
    fn equivocation_detected_on_equal_size_different_root() {
        let log_key = IdentityKey::from_seed(&[40; 32]);
        let a = SignedTreeHead::issue(&log_key, 5, NOW, ContentId::of(b"root-A"));
        let b = SignedTreeHead::issue(&log_key, 5, NOW, ContentId::of(b"root-B"));
        assert_eq!(detect_equivocation(&a, &b), Err(ResolveError::KtEquivocation));
        // Same head is consistent.
        assert!(detect_equivocation(&a, &a).is_ok());
        // Different logs are not comparable as one log's equivocation.
        let other = IdentityKey::from_seed(&[41; 32]);
        let c = SignedTreeHead::issue(&other, 5, NOW, ContentId::of(b"root-B"));
        assert!(detect_equivocation(&a, &c).is_ok());
    }

    #[test]
    fn stale_sth_is_rejected() {
        let log_key = IdentityKey::from_seed(&[42; 32]);
        let window = 3_600_000; // 1h
        let fresh = SignedTreeHead::issue(&log_key, 1, NOW, ContentId::of(b"r"));
        assert!(check_freshness(&fresh, NOW + window, window).is_ok());
        assert_eq!(
            check_freshness(&fresh, NOW + window + 1, window),
            Err(ResolveError::KtSthStale)
        );
    }

    #[test]
    fn dns_identity_mismatch_detected() {
        let (ik, id) = identity_for("alice@example.com", 1);
        // Correct match.
        assert!(check_dns_matches_identity(&ik.public(), &id.content_id(), &id).is_ok());
        // Wrong ik.
        let wrong_ik = IdentityKey::from_seed(&[2; 32]).public();
        assert!(matches!(
            check_dns_matches_identity(&wrong_ik, &id.content_id(), &id),
            Err(ResolveError::DnsIdentityMismatch(_))
        ));
        // Wrong id.
        assert!(matches!(
            check_dns_matches_identity(&ik.public(), &ContentId::of(b"nope"), &id),
            Err(ResolveError::DnsIdentityMismatch(_))
        ));
    }

    // ── STH consistency (§18.4.11, §3.5.2(a)/(d)) — the append-only-violation / forged-proof and
    // ── forked-history (split-view) rejections `ResolveError::KtSthInconsistent` exists for. ────

    #[test]
    fn consistency_accepted_for_honest_append_only_growth() {
        let mut log = InMemoryKtLog::new(IdentityKey::from_seed(&[70; 32]));
        log.append_leaf(&ContentId::of(b"a"));
        log.append_leaf(&ContentId::of(b"b"));
        let old_sth = log.sth();
        log.append_leaf(&ContentId::of(b"c"));
        log.append_leaf(&ContentId::of(b"d"));
        let new_sth = log.sth();
        let proof = log.consistency_proof(old_sth.tree_size).expect("valid prefix");
        assert!(verify_sth_consistency(&log.log_id(), &old_sth, &new_sth, &proof).is_ok());
    }

    #[test]
    fn consistency_rejects_a_forged_proof_path() {
        let mut log = InMemoryKtLog::new(IdentityKey::from_seed(&[71; 32]));
        log.append_leaf(&ContentId::of(b"a"));
        log.append_leaf(&ContentId::of(b"b"));
        let old_sth = log.sth();
        log.append_leaf(&ContentId::of(b"c"));
        log.append_leaf(&ContentId::of(b"d"));
        let new_sth = log.sth();
        let mut proof = log.consistency_proof(old_sth.tree_size).expect("valid prefix");
        assert!(!proof.proof_path.is_empty(), "size 2 -> 4 needs at least one consistency node");
        proof.proof_path[0] = ContentId::of(b"forged consistency node");
        assert_eq!(
            verify_sth_consistency(&log.log_id(), &old_sth, &new_sth, &proof),
            Err(ResolveError::KtSthInconsistent)
        );
    }

    #[test]
    fn consistency_rejects_a_forked_non_extending_history() {
        // The same log key signs an "old" head over [a, b], then presents a "new" larger tree
        // whose first two leaves have been REWRITTEN ([a, X, c, d]) rather than genuinely extended
        // ([a, b, c, d]) — a forked / non-append-only history, i.e. the log showed two different
        // pasts under one signing identity (§3.5.2(d)). The consistency proof folds against the
        // forked tree's own structure but must NOT reconstruct the honest old root.
        let key = IdentityKey::from_seed(&[72; 32]);

        let mut honest = InMemoryKtLog::new(IdentityKey::from_seed(&[72; 32]));
        honest.append_leaf(&ContentId::of(b"a"));
        honest.append_leaf(&ContentId::of(b"b"));
        let old_sth = honest.sth(); // size 2, root over [a, b], signed by `key`

        let mut forked = InMemoryKtLog::new(IdentityKey::from_seed(&[72; 32]));
        forked.append_leaf(&ContentId::of(b"a"));
        forked.append_leaf(&ContentId::of(b"X")); // diverges from the honest "b" at the same index
        forked.append_leaf(&ContentId::of(b"c"));
        forked.append_leaf(&ContentId::of(b"d"));
        let new_sth = forked.sth(); // size 4, signed by the SAME `key`

        let proof = forked.consistency_proof(2).expect("valid prefix of the forked tree");
        assert_eq!(
            verify_sth_consistency(&key.public(), &old_sth, &new_sth, &proof),
            Err(ResolveError::KtSthInconsistent),
            "a forked history must not verify as a consistent extension of the honest one"
        );
    }

    #[test]
    fn consistency_rejects_wrong_pinned_log_id() {
        let mut log = InMemoryKtLog::new(IdentityKey::from_seed(&[73; 32]));
        log.append_leaf(&ContentId::of(b"a"));
        log.append_leaf(&ContentId::of(b"b"));
        let old_sth = log.sth();
        log.append_leaf(&ContentId::of(b"c"));
        let new_sth = log.sth();
        let proof = log.consistency_proof(old_sth.tree_size).unwrap();
        let other = IdentityKey::from_seed(&[0xbb; 32]).public();
        assert_eq!(
            verify_sth_consistency(&other, &old_sth, &new_sth, &proof),
            Err(ResolveError::KtProofInvalid),
            "a consistency proof against an unpinned log id proves nothing"
        );
    }

    #[test]
    fn consistency_rejects_tampered_sth_signature() {
        let mut log = InMemoryKtLog::new(IdentityKey::from_seed(&[74; 32]));
        log.append_leaf(&ContentId::of(b"a"));
        let mut old_sth = log.sth();
        log.append_leaf(&ContentId::of(b"b"));
        let new_sth = log.sth();
        let proof = log.consistency_proof(1).unwrap();
        old_sth.sig[0] ^= 0xff; // tamper the earlier STH's own signature
        assert_eq!(
            verify_sth_consistency(&log.log_id(), &old_sth, &new_sth, &proof),
            Err(ResolveError::KtProofInvalid)
        );
    }
}

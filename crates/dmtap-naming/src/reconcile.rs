//! **Multi-resolver cross-check** — the anti-equivocation reconciliation of spec §3.12.3.
//!
//! Because **KT anchors every binding to the same key** (§3.5), the resolver types of §3.12 are not
//! merely alternatives — they are **mutual auditors**. A client MAY query several resolvers for one
//! name *in parallel* (e.g. a `name@domain`'s `dns` `_dmtap` pointer **and** a `name-chain` record
//! the owner also publishes for the same name). Since a genuine identity has exactly one key,
//! **independent resolvers MUST agree on the resolved `ik`** (§3.12.3).
//!
//! This module is the reconciliation step every resolver type feeds into. It takes the per-resolver
//! **answers** for one name and cross-checks their identity keys:
//!
//! - **Agreement** — every resolver that returned a **step-2-verified** key returned the *same* key
//!   ⇒ resolution succeeds ([`ReconciledResolution`]).
//! - **Disagreement** — two **verified** resolvers returned **different** keys for the same name ⇒
//!   **fail closed** with [`ResolveError::ResolverDisagreement`] (`ERR_RESOLVER_DISAGREEMENT`,
//!   `0x0120`, HALT_ALERT, §3.12.3): the client MUST NOT pin, MUST raise a security alert, and MUST
//!   fall back to KT-quorum (§3.5.2(b)) or out-of-band verification (§3.4.1) to decide the true key.
//!   It is **never** silently reconciled to one key.
//! - **Single resolver** — one verified answer passes through unchanged; there is nothing to
//!   cross-check.
//!
//! ## The cross-check runs only over *step-2-verified* pointers (normative, §3.12.3)
//! The agreement test applies **exclusively** to pointers that each **independently passed step 2**
//! (§3.12.1: KT verification per §3.5, and — for a `name-chain` — the bidirectional key↔name binding
//! per §3.12.5(b)). A positive answer that **failed** its own step 2 is carried as an
//! [`ResolverAnswer::unverified`] pointer and is **discarded** here: it becomes **"one fewer
//! resolver,"** **not** a "disagreeing peer." Consequently `0x0120` is raised **only** when **two or
//! more** pointers *each passed* step 2 yet resolve to **different** keys — a genuine equivocation
//! across trusted channels.
//!
//! This closes an availability attack: an adversary who can publish **one** bogus record (a stray
//! `.eth` entry, a poisoned `_dmtap` DNS answer) for a name that *also* resolves elsewhere would
//! otherwise force every client into a `HALT_ALERT` fail-to-pin — a denial of resolution. Because the
//! bogus pointer never clears step 2, it is dropped, and resolution proceeds on the surviving
//! verified pointer(s). An attacker must still corrupt **every** *verified* channel *and* the KT
//! quorum consistently — strengthening, not weakening, the anti-equivocation posture of §3.5.
//!
//! ## Abstain / unverified vs. disagree (the non-voting policy, chosen and documented)
//! Two kinds of answer **do not vote**:
//!
//! - **Abstain** ([`ResolverAnswer::abstain`], `key == None`): the resolver has **no binding** at all
//!   for the name under its type — a vote of silence (§3.12.2/§3.12.3: a name absent under one
//!   resolver type is "undiscovered by this node, not invalid").
//! - **Unverified** ([`ResolverAnswer::unverified`]): the resolver *discovered* a pointer, but it
//!   **failed its own step-2 verification** (KT / bidirectional binding). Discovery is never proof
//!   (§3.1), so an unproven pointer is discarded as unresolved under its own error — never counted.
//!
//! Concretely:
//!
//! - At least **one** step-2-**verified** positive answer is required. If **every** resolver abstains
//!   or is unverified, that is the ordinary **not-found** outcome
//!   ([`ResolveError::NameResolution`], `0x0109`) — the existing resolution-miss path, **not**
//!   `0x0120`. All-silence and all-forged are both not-found, never a disagreement.
//! - Among the resolvers whose answer is **verified**, agreement must be **unanimous**. Any two
//!   verified answers that name **different** keys are a disagreement (`0x0120`) — regardless of how
//!   many others abstained or were dropped as unverified. One attacker-controlled resolver returning
//!   a *verified-but-different* key alongside one honest resolver is exactly the split-view this
//!   catches; a merely *forged, unverified* record is not.
//!
//! This is deliberately strict: reconciliation never picks a "majority key" among disagreeing
//! verified resolvers here (that quorum decision belongs to KT, §3.5.2(b), which §3.12.3 mandates as
//! the fallback). Any inter-resolver conflict among verified pointers halts and alerts.

use crate::error::ResolveError;
use crate::restype::{ResolvedBinding, ResolverType};

/// One resolver's answer for a single name, tagged with which resolver type produced it (§3.12.4)
/// for diagnostics. Three shapes:
///
/// - a **step-2-verified positive** binding ([`ResolverAnswer::found`]) — a pointer that *passed*
///   its own §3.12.1 step-2 verification (KT / bidirectional binding); it **votes** in the
///   cross-check;
/// - an **unverified positive** binding ([`ResolverAnswer::unverified`]) — a pointer the resolver
///   *discovered* but which **failed** its own step-2 verification; it is **discarded** ("one fewer
///   resolver", §3.12.3), never a disagreeing peer;
/// - an **abstain** ([`ResolverAnswer::abstain`]) — the name is absent under this resolver type (a
///   vote of silence).
///
/// Only a `found` (verified) answer participates in the agreement test (§3.12.3); `unverified` and
/// `abstain` both **do not vote**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolverAnswer {
    /// Which resolver type produced this answer (§3.12.4).
    pub resolver_type: ResolverType,
    /// The identity key this resolver bound the name to, or `None` if it has no binding (abstain).
    pub key: Option<Vec<u8>>,
    /// Whether this pointer **passed its own §3.12.1 step-2 verification** (KT per §3.5, and — for a
    /// `name-chain` — the bidirectional key↔name binding per §3.12.5(b)). Only a *verified* positive
    /// answer votes in the cross-check; an unverified pointer is discarded as "one fewer resolver"
    /// (§3.12.3), never counted as a disagreeing peer. Meaningless (and left `false`) for an abstain,
    /// which has no key to verify.
    pub verified: bool,
}

impl ResolverAnswer {
    /// A **step-2-verified positive** answer: `resolver_type` resolved the name to `ik` **and** that
    /// pointer passed its own §3.12.1 step-2 verification (KT / bidirectional binding). This is the
    /// only shape that **votes** in the cross-check.
    pub fn found(resolver_type: ResolverType, ik: impl Into<Vec<u8>>) -> Self {
        ResolverAnswer { resolver_type, key: Some(ik.into()), verified: true }
    }

    /// An **unverified positive** answer: `resolver_type` *discovered* a pointer to `ik`, but that
    /// pointer **failed** its own §3.12.1 step-2 verification (e.g. KT quorum unmet `0x0111`, a
    /// directory entry that does not forward-verify `0x0114`, or a `name-chain` whose bidirectional
    /// binding disagrees `0x011E`). Discovery is never proof (§3.1); this answer is **discarded** by
    /// [`reconcile`] as "one fewer resolver" (§3.12.3) — it is **never** counted as a disagreeing
    /// peer, so a single forged/poisoned record cannot force a `0x0120` halt.
    pub fn unverified(resolver_type: ResolverType, ik: impl Into<Vec<u8>>) -> Self {
        ResolverAnswer { resolver_type, key: Some(ik.into()), verified: false }
    }

    /// An **abstain**: `resolver_type` has no binding for the name (a vote of silence, §3.12.3). It
    /// neither agrees nor disagrees.
    pub fn abstain(resolver_type: ResolverType) -> Self {
        ResolverAnswer { resolver_type, key: None, verified: false }
    }

    /// Whether this answer is a **step-2-verified positive** binding — the only shape that votes in
    /// the §3.12.3 cross-check. An abstain (no key) or an unverified pointer both return `false`.
    pub fn is_verified_vote(&self) -> bool {
        self.verified && self.key.is_some()
    }

    /// Lift a resolved binding (from any resolver type — `dns`, `name-chain`, `self`, `petname`) into
    /// a **verified positive** answer, carrying its `resolver_type` and `ik`. A [`ResolvedBinding`]
    /// exists only *after* step 2 (it carries a [`Verification`](crate::restype::Verification)), so
    /// it is verified by construction — the uniform bridge from the §3.12 resolvers into this
    /// cross-check, since **everything resolves to a key** (§1.2, §3).
    pub fn from_binding(binding: &ResolvedBinding) -> Self {
        ResolverAnswer::found(binding.resolver_type, binding.ik.clone())
    }
}

/// A `name → key` binding that survived the §3.12.3 multi-resolver cross-check: every resolver that
/// voted agreed on `ik`. `agreed_by` lists the resolver types that positively attested it (abstains
/// are not listed). The caller pins this exactly as a single-resolver binding — the cross-check adds
/// anti-equivocation assurance, it does not change what a binding *is*.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconciledResolution {
    /// The name that was reconciled.
    pub name: String,
    /// The identity key all voting resolvers agreed on.
    pub ik: Vec<u8>,
    /// The resolver types that returned this key (the positive voters; abstains excluded).
    pub agreed_by: Vec<ResolverType>,
}

/// Cross-check the answers several resolvers returned for **one** `name` (§3.12.3), fail-closed.
///
/// The agreement test runs **only over step-2-verified pointers** (§3.12.3): an [`ResolverAnswer`]
/// that abstained (no key) or that failed its own step-2 verification
/// ([`ResolverAnswer::unverified`]) **does not vote** — it is discarded as "one fewer resolver,"
/// never treated as a disagreeing peer. Among the *verified* answers, this requires **unanimity**:
///
/// - No verified positive answer (all abstained, all unverified, or empty) ⇒
///   [`ResolveError::NameResolution`] (`0x0109`), the ordinary not-found path — **not** a
///   disagreement. A lone forged/poisoned record therefore degrades to not-found, never a halt.
/// - All verified positive answers name the **same** key ⇒ [`Ok`] with that key and the list of
///   resolver types that agreed. A **single** verified answer (the rest abstaining or unverified, or
///   a one-resolver call) passes through unchanged.
/// - Any two **verified** positive answers name **different** keys ⇒
///   [`ResolveError::ResolverDisagreement`] (`0x0120`, HALT_ALERT): the caller MUST NOT pin, MUST
///   alert, and MUST fall back to KT-quorum (§3.5.2(b)) or OOB verification (§3.4.1). Never silently
///   reconciled. This fires **only** for equivocation across channels that *each* cleared step 2.
pub fn reconcile(name: &str, answers: &[ResolverAnswer]) -> Result<ReconciledResolution, ResolveError> {
    // Take the identity key each resolver voted for. Only a step-2-VERIFIED positive answer votes:
    // abstains (`None`) and unverified pointers (discovery that failed its own step 2) are both
    // discarded here as "one fewer resolver" (§3.12.3), never counted as a disagreeing peer.
    let mut agreed: Option<&[u8]> = None;
    let mut agreed_by: Vec<ResolverType> = Vec::new();

    for answer in answers {
        if !answer.verified {
            // Abstain (no key) or a pointer that FAILED its own step-2 verification (§3.12.1): it is
            // dropped under its own error (`0x011E`/`0x0114`/`0x0111`/…), never a disagreeing peer.
            // This is what stops one bogus published record from forcing a `0x0120` denial of
            // resolution (§3.12.3).
            continue;
        }
        let Some(key) = answer.key.as_deref() else {
            // Defensive: a `verified` answer with no key is not a vote (constructors never build one).
            continue;
        };
        match agreed {
            None => agreed = Some(key),
            // A genuine identity has exactly one key: two step-2-VERIFIED answers naming different
            // keys is a §3.12.3 inter-resolver disagreement — fail closed, never reconcile to one.
            Some(first) if first != key => {
                return Err(ResolveError::ResolverDisagreement(
                    "independent verified resolvers returned different keys for the same name",
                ));
            }
            Some(_) => {}
        }
        agreed_by.push(answer.resolver_type);
    }

    match agreed {
        // At least one verified positive answer, and all verified positives agreed.
        Some(ik) => Ok(ReconciledResolution {
            name: name.to_owned(),
            ik: ik.to_vec(),
            agreed_by,
        }),
        // No verified positive answer (all abstained and/or all unverified): ordinary not-found, not
        // a disagreement (0x0109, not 0x0120). A lone forged record degrades here, it does not halt.
        None => Err(ResolveError::NameResolution(
            "no verified resolver returned a binding for the name",
        )),
    }
}

/// Cross-check a set of resolved [`ResolvedBinding`]s for one `name` (§3.12.3) — the ergonomic form
/// when every resolver *did* return a **step-2-verified** positive binding (a `name-chain` and a
/// `self`/`petname` resolution of the same name, say — a [`ResolvedBinding`] exists only after step
/// 2, so all inputs here are verified by construction). Equivalent to [`reconcile`] over
/// [`ResolverAnswer::from_binding`] of each. To include a resolver that **abstained** or a pointer
/// that **failed step 2**, build [`ResolverAnswer`]s directly ([`ResolverAnswer::abstain`] /
/// [`ResolverAnswer::unverified`]) and use [`reconcile`] so the non-vote is represented.
pub fn reconcile_bindings(
    name: &str,
    bindings: &[ResolvedBinding],
) -> Result<ReconciledResolution, ResolveError> {
    let answers: Vec<ResolverAnswer> = bindings.iter().map(ResolverAnswer::from_binding).collect();
    reconcile(name, &answers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::restype::{Chain, Verification};

    // Two illustrative keys; the reconciler only compares bytes, so raw vectors suffice.
    fn key_a() -> Vec<u8> {
        vec![0xAA; 32]
    }
    fn key_b() -> Vec<u8> {
        vec![0xBB; 32]
    }

    #[test]
    fn two_resolvers_agree_resolves_to_that_key() {
        // A `dns` pointer and a `name-chain` record for the same name both name key A.
        let name = "alice@example.com";
        let answers = [
            ResolverAnswer::found(ResolverType::Dns, key_a()),
            ResolverAnswer::found(ResolverType::NameChain(Chain::Ens), key_a()),
        ];
        let res = reconcile(name, &answers).unwrap();
        assert_eq!(res.name, name);
        assert_eq!(res.ik, key_a());
        assert_eq!(res.agreed_by.len(), 2, "both resolvers voted and agreed");
        assert!(res.agreed_by.contains(&ResolverType::Dns));
        assert!(res.agreed_by.contains(&ResolverType::NameChain(Chain::Ens)));
    }

    #[test]
    fn two_resolvers_disagree_fails_closed_0120() {
        // The DNS pointer names key A, the chain record names key B — a split view. Never reconciled.
        let name = "alice@example.com";
        let answers = [
            ResolverAnswer::found(ResolverType::Dns, key_a()),
            ResolverAnswer::found(ResolverType::NameChain(Chain::Ens), key_b()),
        ];
        let err = reconcile(name, &answers).unwrap_err();
        assert!(matches!(err, ResolveError::ResolverDisagreement(_)));
        assert_eq!(err.code(), 0x0120, "HALT_ALERT inter-resolver disagreement");
    }

    #[test]
    fn disagreement_order_independent() {
        // The conflict is caught whichever resolver is listed first.
        let name = "alice@example.com";
        let err = reconcile(
            name,
            &[
                ResolverAnswer::found(ResolverType::NameChain(Chain::Sns), key_b()),
                ResolverAnswer::found(ResolverType::Dns, key_a()),
            ],
        )
        .unwrap_err();
        assert_eq!(err.code(), 0x0120);
    }

    #[test]
    fn three_resolvers_one_dissenter_fails_closed() {
        // Two honest resolvers agree on A; a third (compromised) names B. The lone dissenter still
        // halts resolution — reconciliation never takes a majority key (that is KT's job, §3.5.2(b)).
        let name = "alice@example.com";
        let answers = [
            ResolverAnswer::found(ResolverType::Dns, key_a()),
            ResolverAnswer::found(ResolverType::NameChain(Chain::Ens), key_a()),
            ResolverAnswer::found(ResolverType::Petname, key_b()),
        ];
        assert_eq!(reconcile(name, &answers).unwrap_err().code(), 0x0120);
    }

    #[test]
    fn one_answers_one_abstains_resolves() {
        // The chain has no record for this name (abstain); DNS answers with key A. An abstain does
        // not vote, so the single positive answer resolves.
        let name = "alice@example.com";
        let answers = [
            ResolverAnswer::found(ResolverType::Dns, key_a()),
            ResolverAnswer::abstain(ResolverType::NameChain(Chain::Ens)),
        ];
        let res = reconcile(name, &answers).unwrap();
        assert_eq!(res.ik, key_a());
        assert_eq!(res.agreed_by, vec![ResolverType::Dns], "only the positive voter is listed");
    }

    #[test]
    fn abstain_listed_first_still_resolves() {
        let name = "alice@example.com";
        let res = reconcile(
            name,
            &[
                ResolverAnswer::abstain(ResolverType::NameChain(Chain::Ens)),
                ResolverAnswer::found(ResolverType::Dns, key_a()),
            ],
        )
        .unwrap();
        assert_eq!(res.ik, key_a());
    }

    #[test]
    fn all_abstain_is_not_found_not_0120() {
        // Every resolver is silent: the ordinary not-found path (0x0109), never a disagreement.
        let name = "ghost@example.com";
        let answers = [
            ResolverAnswer::abstain(ResolverType::Dns),
            ResolverAnswer::abstain(ResolverType::NameChain(Chain::Ens)),
        ];
        let err = reconcile(name, &answers).unwrap_err();
        assert!(matches!(err, ResolveError::NameResolution(_)));
        assert_eq!(err.code(), 0x0109);
        assert_ne!(err.code(), 0x0120, "all-silence is not an inter-resolver disagreement");
    }

    #[test]
    fn empty_answer_set_is_not_found() {
        // No resolvers queried at all: not-found, fail-closed, never a spurious success.
        let err = reconcile("nobody@example.com", &[]).unwrap_err();
        assert!(matches!(err, ResolveError::NameResolution(_)));
    }

    #[test]
    fn single_resolver_passes_through_unchanged() {
        // A one-resolver resolution has nothing to cross-check: it resolves to exactly its key.
        let name = "solo@example.com";
        let res = reconcile(name, &[ResolverAnswer::found(ResolverType::Dns, key_a())]).unwrap();
        assert_eq!(res.ik, key_a());
        assert_eq!(res.agreed_by, vec![ResolverType::Dns]);
    }

    #[test]
    fn many_resolvers_all_agree() {
        // Unanimity across four voters.
        let name = "alice@example.com";
        let answers = [
            ResolverAnswer::found(ResolverType::Dns, key_a()),
            ResolverAnswer::found(ResolverType::NameChain(Chain::Ens), key_a()),
            ResolverAnswer::found(ResolverType::NameChain(Chain::Sns), key_a()),
            ResolverAnswer::found(ResolverType::Petname, key_a()),
        ];
        let res = reconcile(name, &answers).unwrap();
        assert_eq!(res.ik, key_a());
        assert_eq!(res.agreed_by.len(), 4);
    }

    #[test]
    fn reconcile_bindings_bridges_resolved_bindings() {
        // The ergonomic form over ResolvedBinding: two bindings (dns + name-chain) that agree.
        let name = "alice@example.com";
        let dns = ResolvedBinding {
            name: name.to_owned(),
            ik: key_a(),
            resolver_type: ResolverType::Dns,
            verification: Verification::LocalPetname, // verification field is not consulted here
        };
        let chain = ResolvedBinding {
            name: name.to_owned(),
            ik: key_a(),
            resolver_type: ResolverType::NameChain(Chain::Ens),
            verification: Verification::ChainBound,
        };
        let res = reconcile_bindings(name, &[dns.clone(), chain.clone()]).unwrap();
        assert_eq!(res.ik, key_a());
        assert_eq!(res.agreed_by.len(), 2);

        // And it catches disagreement across bindings.
        let evil = ResolvedBinding { ik: key_b(), ..chain };
        assert_eq!(
            reconcile_bindings(name, &[dns, evil]).unwrap_err().code(),
            0x0120
        );
    }

    // ---- D8 (§3.12.3): the cross-check runs ONLY over step-2-verified pointers ----

    #[test]
    fn found_is_a_verified_vote_unverified_and_abstain_are_not() {
        // The three answer shapes and their voting status.
        assert!(ResolverAnswer::found(ResolverType::Dns, key_a()).is_verified_vote());
        assert!(!ResolverAnswer::unverified(ResolverType::Dns, key_a()).is_verified_vote());
        assert!(!ResolverAnswer::abstain(ResolverType::Dns).is_verified_vote());
        // from_binding lifts a (post-step-2) ResolvedBinding into a VERIFIED vote.
        assert!(ResolverAnswer::found(ResolverType::Dns, key_a()).verified);
        assert!(!ResolverAnswer::unverified(ResolverType::Dns, key_a()).verified);
    }

    #[test]
    fn verified_vs_verified_disagreement_is_0120() {
        // Both pointers CLEARED their own step 2 yet name different keys: a genuine equivocation
        // across trusted channels — HALT_ALERT (0x0120). (Same as the classic disagreement case,
        // now stated explicitly in terms of verified pointers.)
        let name = "alice@example.com";
        let answers = [
            ResolverAnswer::found(ResolverType::Dns, key_a()),
            ResolverAnswer::found(ResolverType::NameChain(Chain::Ens), key_b()),
        ];
        let err = reconcile(name, &answers).unwrap_err();
        assert!(matches!(err, ResolveError::ResolverDisagreement(_)));
        assert_eq!(err.code(), 0x0120);
    }

    #[test]
    fn verified_plus_forged_unverified_resolves_to_verified_no_0120() {
        // THE bogus-record DoS defense (§3.12.3): a DNS pointer passed step 2 and names key A; an
        // attacker also publishes a `.eth` record naming key B, but it FAILS its own step 2
        // (bidirectional binding, §3.12.5(b)) — so it is UNVERIFIED. The unverified pointer is
        // discarded ("one fewer resolver"), NOT counted as a disagreeing peer: resolution proceeds
        // on the surviving verified pointer, with NO 0x0120 halt.
        let name = "alice@example.com";
        let answers = [
            ResolverAnswer::found(ResolverType::Dns, key_a()),
            ResolverAnswer::unverified(ResolverType::NameChain(Chain::Ens), key_b()),
        ];
        let res = reconcile(name, &answers).unwrap();
        assert_eq!(res.ik, key_a(), "resolves to the sole verified pointer");
        assert_eq!(
            res.agreed_by,
            vec![ResolverType::Dns],
            "the forged/unverified pointer does not vote and is not listed"
        );
    }

    #[test]
    fn forged_unverified_listed_first_still_ignored() {
        // Order independence: the forged pointer is dropped whether it is seen before or after the
        // verified one — a single bogus record never forces a halt.
        let name = "alice@example.com";
        let res = reconcile(
            name,
            &[
                ResolverAnswer::unverified(ResolverType::NameChain(Chain::Ens), key_b()),
                ResolverAnswer::found(ResolverType::Dns, key_a()),
            ],
        )
        .unwrap();
        assert_eq!(res.ik, key_a());
        assert_eq!(res.agreed_by, vec![ResolverType::Dns]);
    }

    #[test]
    fn two_verified_agree_one_forged_unverified_dissents_still_resolves() {
        // Two honest resolvers passed step 2 and agree on A; a third publishes a forged B that fails
        // step 2. The forged dissenter is discarded, so resolution succeeds on the verified quorum —
        // an attacker who only forges (does not break a verified channel) cannot even downgrade to a
        // one-resolver view here, let alone force 0x0120.
        let name = "alice@example.com";
        let answers = [
            ResolverAnswer::found(ResolverType::Dns, key_a()),
            ResolverAnswer::found(ResolverType::NameChain(Chain::Ens), key_a()),
            ResolverAnswer::unverified(ResolverType::Petname, key_b()),
        ];
        let res = reconcile(name, &answers).unwrap();
        assert_eq!(res.ik, key_a());
        assert_eq!(res.agreed_by.len(), 2, "only the two verified pointers voted");
    }

    #[test]
    fn all_unverified_is_not_found_not_0120() {
        // Every pointer FAILED its own step 2 (all forged / poisoned): no verified vote survives, so
        // this is the ordinary not-found path (0x0109) — NOT a disagreement. All-forged, like
        // all-silence, degrades gracefully; it never halts every client (§3.12.3).
        let name = "victim@example.com";
        let answers = [
            ResolverAnswer::unverified(ResolverType::Dns, key_a()),
            ResolverAnswer::unverified(ResolverType::NameChain(Chain::Ens), key_b()),
        ];
        let err = reconcile(name, &answers).unwrap_err();
        assert!(matches!(err, ResolveError::NameResolution(_)));
        assert_eq!(err.code(), 0x0109);
        assert_ne!(err.code(), 0x0120, "all-unverified is not an inter-resolver disagreement");
    }

    #[test]
    fn abstain_and_unverified_mixed_is_not_found() {
        // A silent resolver plus a forged one: still no verified vote — not-found (0x0109).
        let name = "victim@example.com";
        let answers = [
            ResolverAnswer::abstain(ResolverType::Dns),
            ResolverAnswer::unverified(ResolverType::NameChain(Chain::Ens), key_b()),
        ];
        assert_eq!(reconcile(name, &answers).unwrap_err().code(), 0x0109);
    }

    #[test]
    fn lone_verified_pointer_among_forged_and_silent_resolves() {
        // One verified pointer, one forged (unverified), one abstain: the single verified answer
        // passes through unchanged — the noise around it is all discarded.
        let name = "alice@example.com";
        let answers = [
            ResolverAnswer::unverified(ResolverType::NameChain(Chain::Sns), key_b()),
            ResolverAnswer::found(ResolverType::Dns, key_a()),
            ResolverAnswer::abstain(ResolverType::NameChain(Chain::Ens)),
        ];
        let res = reconcile(name, &answers).unwrap();
        assert_eq!(res.ik, key_a());
        assert_eq!(res.agreed_by, vec![ResolverType::Dns]);
    }

    #[test]
    fn verified_disagreement_survives_forged_noise() {
        // Two VERIFIED channels genuinely disagree (A vs B) — that is a real equivocation and MUST
        // still halt (0x0120), even with an extra forged/unverified pointer in the mix. The
        // verification gate must not swallow a genuine cross-verified disagreement.
        let name = "alice@example.com";
        let answers = [
            ResolverAnswer::found(ResolverType::Dns, key_a()),
            ResolverAnswer::unverified(ResolverType::Petname, key_a()),
            ResolverAnswer::found(ResolverType::NameChain(Chain::Ens), key_b()),
        ];
        assert_eq!(reconcile(name, &answers).unwrap_err().code(), 0x0120);
    }

    // ---- Property test (D8, §3.12.3): the reconcile outcome is a pure function of ONLY the ----
    // ---- step-2-verified positive answers. Over many random answer sets, `0x0120` fires iff ----
    // ---- ≥2 distinct VERIFIED keys appear; unverified/abstain answers never change the verdict. ----

    /// A tiny deterministic SplitMix64 PRNG — dependency-free, reproducible generative testing.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    // A three-key alphabet so verified disagreement is common in random sets.
    fn key_for(i: u64) -> Vec<u8> {
        vec![[0xAA, 0xBB, 0xCC][(i % 3) as usize]; 32]
    }
    fn rtype(i: u64) -> ResolverType {
        match i % 4 {
            0 => ResolverType::Dns,
            1 => ResolverType::Petname,
            2 => ResolverType::NameChain(Chain::Ens),
            _ => ResolverType::NameChain(Chain::Sns),
        }
    }

    #[test]
    fn reconcile_outcome_depends_only_on_verified_votes_d8() {
        let name = "prop@example.com";
        let mut rng = Rng(0xD8D8_D8D8);
        for _ in 0..50_000 {
            let n = rng.below(6); // 0..=5 answers
            let mut answers: Vec<ResolverAnswer> = Vec::new();
            // The oracle: the multiset of DISTINCT keys among step-2-VERIFIED positive answers.
            let mut verified_keys: std::collections::BTreeSet<Vec<u8>> = Default::default();
            for _ in 0..n {
                let t = rtype(rng.next());
                match rng.below(3) {
                    0 => {
                        // step-2-verified positive: it VOTES.
                        let k = key_for(rng.next());
                        verified_keys.insert(k.clone());
                        answers.push(ResolverAnswer::found(t, k));
                    }
                    1 => {
                        // forged/unverified positive: MUST NOT vote (discovery is never proof).
                        answers.push(ResolverAnswer::unverified(t, key_for(rng.next())));
                    }
                    _ => answers.push(ResolverAnswer::abstain(t)), // silence: MUST NOT vote.
                }
            }

            let result = reconcile(name, &answers);
            match verified_keys.len() {
                // ≥2 distinct verified keys ⇒ genuine equivocation across trusted channels ⇒ 0x0120,
                // regardless of how many forged/abstaining answers surround them.
                k if k >= 2 => {
                    let err = result.expect_err("≥2 verified keys must be a disagreement");
                    assert!(matches!(err, ResolveError::ResolverDisagreement(_)));
                    assert_eq!(err.code(), 0x0120);
                }
                // Exactly one verified key ⇒ resolves to it; forged/abstain noise is discarded.
                1 => {
                    let res = result.expect("a lone verified key must resolve");
                    assert_eq!(&res.ik, verified_keys.iter().next().unwrap());
                    // Only verified voters are listed (all with that key); none are the forged key.
                    assert!(!res.agreed_by.is_empty());
                }
                // No verified vote (all forged and/or all silent) ⇒ ordinary not-found (0x0109),
                // NEVER a spurious 0x0120 disagreement. Forged-only degrades like silence.
                _ => {
                    let err = result.expect_err("no verified vote must be not-found");
                    assert!(matches!(err, ResolveError::NameResolution(_)));
                    assert_eq!(err.code(), 0x0109);
                    assert_ne!(err.code(), 0x0120);
                }
            }

            // Order-independence: shuffling the answers (reverse) yields the SAME verdict code.
            let mut reversed = answers.clone();
            reversed.reverse();
            assert_eq!(
                reconcile(name, &answers).map(|r| r.ik).map_err(|e| e.code()),
                reconcile(name, &reversed).map(|r| r.ik).map_err(|e| e.code()),
                "reconcile verdict must be order-independent"
            );
        }
    }
}

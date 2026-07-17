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
//! - **Agreement** — every resolver that returned a key returned the *same* key ⇒ resolution
//!   succeeds ([`ReconciledResolution`]).
//! - **Disagreement** — two resolvers returned **different** keys for the same name ⇒ **fail closed**
//!   with [`ResolveError::ResolverDisagreement`] (`ERR_RESOLVER_DISAGREEMENT`, `0x0120`, HALT_ALERT,
//!   §3.12.3): the client MUST NOT pin, MUST raise a security alert, and MUST fall back to KT-quorum
//!   (§3.5.2(b)) or out-of-band verification (§3.4.1) to decide the true key. It is **never** silently
//!   reconciled to one key.
//! - **Single resolver** — one answer passes through unchanged; there is nothing to cross-check.
//!
//! ## Abstain vs. disagree (the `None` policy, chosen and documented)
//! A resolver that has **no binding** for the name under its type returns [`ResolverAnswer::abstain`]
//! (`None`). An abstain is **neither agreement nor disagreement** — it simply *does not vote*. This
//! follows §3.12.2/§3.12.3 directly: a name absent under one resolver type is "undiscovered by this
//! node, not invalid", and the identity stays reachable via any resolver type that *does* carry it.
//! Concretely:
//!
//! - At least **one** positive (key-bearing) answer is required. If **every** resolver abstains, that
//!   is the ordinary **not-found** outcome ([`ResolveError::NameResolution`], `0x0109`) — the existing
//!   resolution-miss path, **not** `0x0120`. All-silence is not a disagreement.
//! - Among the resolvers that *do* answer, agreement must be **unanimous**. Any two positive answers
//!   that name **different** keys are a disagreement (`0x0120`) — regardless of how many others
//!   abstained. One attacker-controlled resolver returning a forged key alongside one honest resolver
//!   is exactly the split-view this catches.
//!
//! This is deliberately strict: reconciliation never picks a "majority key" among disagreeing
//! resolvers here (that quorum decision belongs to KT, §3.5.2(b), which §3.12.3 mandates as the
//! fallback). Any inter-resolver conflict halts and alerts.

use crate::error::ResolveError;
use crate::restype::{ResolvedBinding, ResolverType};

/// One resolver's answer for a single name, tagged with which resolver type produced it (§3.12.4)
/// for diagnostics. Either a **positive** identity-key binding ([`ResolverAnswer::found`]) or an
/// **abstain** ([`ResolverAnswer::abstain`], the name is absent under this resolver type — a vote of
/// silence, per this module's `None` policy).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolverAnswer {
    /// Which resolver type produced this answer (§3.12.4).
    pub resolver_type: ResolverType,
    /// The identity key this resolver bound the name to, or `None` if it has no binding (abstain).
    pub key: Option<Vec<u8>>,
}

impl ResolverAnswer {
    /// A **positive** answer: `resolver_type` resolved the name to `ik`.
    pub fn found(resolver_type: ResolverType, ik: impl Into<Vec<u8>>) -> Self {
        ResolverAnswer { resolver_type, key: Some(ik.into()) }
    }

    /// An **abstain**: `resolver_type` has no binding for the name (a vote of silence, §3.12.3). It
    /// neither agrees nor disagrees.
    pub fn abstain(resolver_type: ResolverType) -> Self {
        ResolverAnswer { resolver_type, key: None }
    }

    /// Lift a resolved binding (from any resolver type — `dns`, `name-chain`, `self`, `petname`) into
    /// a positive answer, carrying its `resolver_type` and `ik`. The uniform bridge from the §3.12
    /// resolvers into this cross-check, since **everything resolves to a key** (§1.2, §3).
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
/// Collects each resolver's identity-key answer and requires **unanimity among those that answer**:
///
/// - No positive answer (all abstained / empty) ⇒ [`ResolveError::NameResolution`] (`0x0109`), the
///   ordinary not-found path — **not** a disagreement.
/// - All positive answers name the **same** key ⇒ [`Ok`] with that key and the list of resolver types
///   that agreed. A **single** positive answer (the rest abstaining, or a one-resolver call) passes
///   through unchanged.
/// - Any two positive answers name **different** keys ⇒ [`ResolveError::ResolverDisagreement`]
///   (`0x0120`, HALT_ALERT): the caller MUST NOT pin, MUST alert, and MUST fall back to KT-quorum
///   (§3.5.2(b)) or OOB verification (§3.4.1). Never silently reconciled.
pub fn reconcile(name: &str, answers: &[ResolverAnswer]) -> Result<ReconciledResolution, ResolveError> {
    // Take the identity key each resolver voted for; abstains (`None`) do not vote (§3.12.3).
    let mut agreed: Option<&[u8]> = None;
    let mut agreed_by: Vec<ResolverType> = Vec::new();

    for answer in answers {
        let Some(key) = answer.key.as_deref() else {
            // Abstain: the name is absent under this resolver type — neither agree nor disagree.
            continue;
        };
        match agreed {
            None => agreed = Some(key),
            // A genuine identity has exactly one key: any differing positive answer is a §3.12.3
            // inter-resolver disagreement — fail closed, never reconcile to one key.
            Some(first) if first != key => {
                return Err(ResolveError::ResolverDisagreement(
                    "independent resolvers returned different keys for the same name",
                ));
            }
            Some(_) => {}
        }
        agreed_by.push(answer.resolver_type);
    }

    match agreed {
        // At least one positive answer, and all positives agreed.
        Some(ik) => Ok(ReconciledResolution {
            name: name.to_owned(),
            ik: ik.to_vec(),
            agreed_by,
        }),
        // Every resolver abstained: ordinary not-found, not a disagreement (0x0109, not 0x0120).
        None => Err(ResolveError::NameResolution(
            "no resolver returned a binding for the name",
        )),
    }
}

/// Cross-check a set of resolved [`ResolvedBinding`]s for one `name` (§3.12.3) — the ergonomic form
/// when every resolver *did* return a positive binding (a `name-chain` and a `self`/`petname`
/// resolution of the same name, say). Equivalent to [`reconcile`] over [`ResolverAnswer::from_binding`]
/// of each. To include a resolver that **abstained**, build [`ResolverAnswer`]s directly and use
/// [`reconcile`] so the abstain is represented.
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
}

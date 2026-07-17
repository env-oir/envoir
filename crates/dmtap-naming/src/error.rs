//! Typed, fail-closed resolution errors — spec §3.3, §3.5, §21.3.
//!
//! Every variant carries its normative DMTAP error code (§21.3) via [`ResolveError::code`], so a
//! caller can map a resolution failure onto the wire error registry and the mandated response
//! disposition. Resolution is **fail-closed**: there is no variant that silently downgrades to an
//! unverified pin (§3.3's TOFU prohibition on unreachable KT), and none that "best-effort accepts"
//! a sub-quorum view (§3.5.2(b)).

use dmtap_core::identity::IdentityError;

/// A name→key resolution or KT-verification failure. Each maps to a §21.3 code and a fail-closed
/// (or halt-alert) disposition; none permits a silent downgrade.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ResolveError {
    /// The `name@domain` string is not a well-formed DMTAP address (§3.9.1).
    #[error("malformed name: {0}")]
    MalformedName(&'static str),

    /// A DNS TXT/SVCB record is missing, malformed, or carries a bad field (§3.2). Maps to
    /// `ERR_NAME_RESOLUTION_FAILED` (`0x0109`).
    #[error("malformed DNS record: {0}")]
    MalformedDns(&'static str),

    /// DNS/name backend returned no binding for the name (§3.3, §3.6). `ERR_NAME_RESOLUTION_FAILED`
    /// (`0x0109`).
    #[error("name resolution failed: {0}")]
    NameResolution(&'static str),

    /// The DNS `ik`/`id` pointer does not match the fetched/pinned `Identity` (§3.3 step 3–4). The
    /// pointer and the signed object disagree — fail closed, never trust the pointer. Rendered as a
    /// binding mismatch; `0x0109` at the resolution layer.
    #[error("DNS binding does not match the resolved identity: {0}")]
    DnsIdentityMismatch(&'static str),

    /// KT log is unreachable/partitioned/censored at first contact (§3.3). MUST NOT silently
    /// TOFU-pin. `ERR_KT_UNREACHABLE` (`0x0106`), FAIL_CLOSED_BLOCK.
    #[error("KT log unreachable at first contact — fail closed, no TOFU pin (0x0106)")]
    KtUnreachable,

    /// An STH signature or an inclusion proof failed to verify against the log key/root (§3.5).
    /// `ERR_KT_PROOF_INVALID` (`0x0108`), FAIL_CLOSED_BLOCK.
    #[error("KT proof invalid — STH signature or inclusion proof does not verify (0x0108)")]
    KtProofInvalid,

    /// The leaf a proof commits to ≠ the leaf recomputed from the resolved `Identity` (§18.4.9).
    /// The log presented a binding whose leaf does not match the identity. `ERR_KT_LEAF_HASH_MISMATCH`
    /// (`0x0117`), FAIL_CLOSED_BLOCK.
    #[error("KT inclusion-proof leaf-hash mismatch — log indexes, it does not redefine (0x0117)")]
    KtLeafHashMismatch,

    /// Fewer than a strict-majority `> n/2` of the pinned log set attested the binding (§3.5.2(b)).
    /// `ERR_KT_LOG_QUORUM_UNMET` (`0x0111`), FAIL_CLOSED_BLOCK — MUST NOT pin on a sub-quorum view.
    #[error("KT log quorum unmet — sub-quorum view, fail closed (0x0111)")]
    KtQuorumUnmet,

    /// A log showed different histories to different observers (§3.5.2(d)). `ERR_KT_EQUIVOCATION`
    /// (`0x0107`), HALT_ALERT — stop trusting the log.
    #[error("KT equivocation detected — split view, halt and alert (0x0107)")]
    KtEquivocation,

    /// Two validly-signed STHs of one log are mutually inconsistent — equal `tree_size`, differing
    /// `root_hash`, or no valid consistency proof (§3.5.2(a),(d)). `ERR_KT_STH_INCONSISTENT`
    /// (`0x0110`), HALT_ALERT — the append-only-violation evidence for equivocation.
    #[error("KT STH inconsistent — append-only violation (0x0110)")]
    KtSthInconsistent,

    /// A presented STH is older than the freshness window / not refreshed within the MMD — the
    /// freeze/withholding attack (§3.5.2(a), §16.2). `ERR_KT_STH_STALE` (`0x0112`), HOLD_RESYNC.
    #[error("KT STH stale — freeze attack, refresh required (0x0112)")]
    KtSthStale,

    /// The fetched `Identity` failed its own verification (signature/chain/suite, §1.3). Carries the
    /// underlying [`IdentityError`]; mapped to `0x0103`/`0x0104`/`0x0105`/`0x0101` per its kind.
    #[error("identity verification failed: {0}")]
    Identity(#[from] IdentityError),

    /// A KeyPackage bundle could not be fetched or failed its content-address check (§5.3, §18.4.3).
    #[error("keypackage fetch failed: {0}")]
    KeyPackage(&'static str),

    /// A name is written in a resolver type (§3.12.2, §21.18) this node does not implement, or one
    /// that is unregistered — the "unknown ⇒ reject, never guess" discipline (as for an unknown
    /// suite §1.1 or transport substrate §4.1). The name is unresolvable; the identity is
    /// unaffected (its other resolvers, and always the key-name floor §3.9.6, still resolve it).
    /// `ERR_RESOLVER_TYPE_UNSUPPORTED` (`0x011F`), FAIL_CLOSED_BLOCK — MUST NOT guess a binding.
    #[error("resolver type unsupported — unresolvable, never guessed (0x011F): {0}")]
    ResolverTypeUnsupported(&'static str),

    /// A crypto name-chain (`.eth`/`.sol`, resolver-type `name-chain`, §3.12.5, §21.18) resolution
    /// whose two binding directions **disagree** (§3.12.5(b)): the on-chain `name → ik` record names
    /// a key that does not claim the name in its signed `Identity.names`, or a claimed name whose
    /// chain record names a different key. The chain is a discovery pointer KT audits (§3.3–§3.5),
    /// never a trust root. `ERR_NAMECHAIN_BINDING_UNVERIFIED` (`0x011E`), FAIL_CLOSED_BLOCK — render
    /// the name **unverified**; MUST NOT display it as authenticated nor use it to address mail.
    #[error("name-chain binding unverified — bidirectional key↔name check failed (0x011E): {0}")]
    NameChainBindingUnverified(&'static str),

    /// A key-name (resolver-type `self`, §3.9.6) failed to verify against the candidate key: its
    /// internal checksum did not hold (a typo/mishear) or it does not derive from the key. The `self`
    /// resolver derives, it never guesses — a bad key-name **fails closed** rather than resolving to a
    /// *different* key. Rendered at the resolution layer as `ERR_NAME_RESOLUTION_FAILED` (`0x0109`).
    #[error("key-name unverified — checksum/derivation mismatch, fail closed (0x0109): {0}")]
    KeyNameUnverified(&'static str),

    /// Two independent resolvers returned **different** `ik` for the **same** name (§3.12.3): e.g. a
    /// `dns` `_dmtap` pointer and a `name-chain` record the owner also publishes disagree. Because a
    /// genuine identity has exactly one key, an *inter-resolver* disagreement is treated as a
    /// potential attack (split view / a corrupted registrar or chain), never silently reconciled to
    /// one key. Distinct from `0x011E` ([`ResolveError::NameChainBindingUnverified`], the
    /// *bidirectional* key↔name mismatch **within one** name-chain resolution): this is disagreement
    /// **across** resolver types, strengthening the anti-equivocation posture of §3.5.
    /// `ERR_RESOLVER_DISAGREEMENT` (`0x0120`), HALT_ALERT — MUST NOT pin; raise a security alert and
    /// fall back to KT-quorum (§3.5.2(b)) or out-of-band verification (§3.4.1) to decide the true key.
    #[error("resolver disagreement — resolvers returned different keys for one name, halt and alert (0x0120): {0}")]
    ResolverDisagreement(&'static str),
}

impl ResolveError {
    /// The normative DMTAP wire error code (§21.3) for this failure.
    pub fn code(&self) -> u16 {
        match self {
            ResolveError::MalformedName(_) => 0x0109,
            ResolveError::MalformedDns(_) => 0x0109,
            ResolveError::NameResolution(_) => 0x0109,
            ResolveError::DnsIdentityMismatch(_) => 0x0109,
            ResolveError::KtUnreachable => 0x0106,
            ResolveError::KtProofInvalid => 0x0108,
            ResolveError::KtLeafHashMismatch => 0x0117,
            ResolveError::KtQuorumUnmet => 0x0111,
            ResolveError::KtEquivocation => 0x0107,
            ResolveError::KtSthInconsistent => 0x0110,
            ResolveError::KtSthStale => 0x0112,
            ResolveError::ResolverTypeUnsupported(_) => 0x011F,
            ResolveError::NameChainBindingUnverified(_) => 0x011E,
            ResolveError::KeyNameUnverified(_) => 0x0109,
            ResolveError::ResolverDisagreement(_) => 0x0120,
            ResolveError::KeyPackage(_) => 0x0109,
            ResolveError::Identity(e) => match e {
                IdentityError::BadSignature => 0x0103,
                IdentityError::BrokenChain => 0x0104,
                IdentityError::UnsupportedSuite(_) => 0x0101,
                _ => 0x0103,
            },
        }
    }
}

//! Delegated capability objects — spec §13.5 / §13.5.1, §18.7.3, §18.9.14.
//!
//! A [`CapabilityToken`] is a **profile of UCAN v1.0**: a signed, offline-verifiable, *attenuable*
//! grant of a specific least-privilege right from an issuer key (`iss`) to an audience key (`aud`),
//! chainable via `prnt` so each link may only **narrow** its parent. A [`Capability`] is one
//! `(resource, ability, caveats)` grant. A [`CapabilityRevocation`] is the separately published,
//! KT-logged object that revokes a token (and its descendants).
//!
//! Both signed objects sign under the **issuer** key with the general §18.9.14 rule
//! (`Sign(sk_iss, DS-tag ‖ 0x00 ‖ det_cbor(object ∖ {sig}))`). The `Capability` sub-map carries no
//! signature of its own — it is covered by the enclosing token's `sig`. All are integer-keyed
//! canonical CBOR (§18.1.2); `Capability.caveats` is the one text-keyed sub-map (an `ext-value`
//! map, §18.3.6), so its values are restricted to the deterministic-safe CBOR subset the strict
//! codec already enforces.

use std::collections::BTreeMap;

use crate::cbor::{self, as_array, as_bytes, as_text, as_u64, as_u8, CborError, Cv, Fields};
use crate::id::ContentId;
use crate::identity::{verify_domain, IdentityError, IdentityKey};
use crate::suite::Suite;
use crate::TimestampMs;

/// §18.9.14 domain-separation tags (ASCII ‖ trailing `0x00`; `sign_domain` prepends them).
pub const CAP_TOKEN_DS: &[u8] = b"DMTAP-v0/cap-token\x00";
pub const CAP_REVOCATION_DS: &[u8] = b"DMTAP-v0/cap-revocation\x00";
/// §18.9.14 DS tag for the `system`-MOTE capability announcement (§10.2).
pub const CAP_ANNOUNCE_DS: &[u8] = b"DMTAP-v0/cap-announce\x00";

/// A capability-chain / invocation / announcement enforcement failure, each carrying its §21.3
/// wire error code via [`CapabilityError::code`].
///
/// Failures of the token's own signature, the delegation chain, the attenuation invariant, or the
/// validity window are `ERR_CAPABILITY_DELEGATION_INVALID` (`0x0508`, §13.5). A revocation hit is
/// the distinct `ERR_CAPABILITY_REVOKED` (`0x050B`) — a *validly-formed but revoked* grant. A stale
/// capability-announcement replay is `ERR_CAPABILITY_ANNOUNCE_ROLLBACK` (`0x030A`, §10.2).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CapabilityError {
    /// A token in the chain does not verify under its own `iss` (§18.9.14).
    #[error("capability token signature invalid (ERR_CAPABILITY_DELEGATION_INVALID, 0x0508)")]
    BadSignature,
    /// A child grant exceeds what its parent granted — the attenuation invariant is violated
    /// (§18.7.3: each link MUST be same-or-narrower `resource`, same/narrower `ability`, caveats
    /// only added/tightened).
    #[error("attenuation invariant violated — a child grant exceeds its parent \
             (ERR_CAPABILITY_DELEGATION_INVALID, 0x0508)")]
    AttenuationViolation,
    /// A chain link is discontinuous: `prnt` is not the parent's content-address, `iss` ≠ the
    /// parent's `aud`, or the walk did not terminate at a token rooted at its `iss` (§18.7.3).
    #[error("broken delegation chain — prnt/iss/aud discontinuity or unrooted chain \
             (ERR_CAPABILITY_DELEGATION_INVALID, 0x0508)")]
    BrokenChain,
    /// Invocation clock is before `nbf` — the token is not yet valid (§18.7.3 step 3).
    #[error("capability not yet valid — now < nbf (ERR_CAPABILITY_DELEGATION_INVALID, 0x0508)")]
    NotYetValid,
    /// Invocation clock is at/after `exp` — the token has expired (§18.7.3 step 3; no eternal cap).
    #[error("capability expired — now ≥ exp (ERR_CAPABILITY_DELEGATION_INVALID, 0x0508)")]
    Expired,
    /// The token (or a chain ancestor) is covered by a published revocation (§13.5.1).
    #[error("capability revoked (ERR_CAPABILITY_REVOKED, 0x050B)")]
    Revoked,
    /// A `caps_version` older-than-or-equal-to the last accepted from that peer — a stale replay
    /// (§10.2).
    #[error("capability announcement rollback — caps_version ≤ last accepted \
             (ERR_CAPABILITY_ANNOUNCE_ROLLBACK, 0x030A)")]
    AnnounceRollback,
}

impl CapabilityError {
    /// The normative DMTAP wire error code (§21.3).
    pub fn code(&self) -> u16 {
        match self {
            CapabilityError::BadSignature
            | CapabilityError::AttenuationViolation
            | CapabilityError::BrokenChain
            | CapabilityError::NotYetValid
            | CapabilityError::Expired => 0x0508,
            CapabilityError::Revoked => 0x050B,
            CapabilityError::AnnounceRollback => 0x030A,
        }
    }
}

fn suite_from_cv(cv: Cv) -> Result<Suite, CborError> {
    let b = as_u8(cv)?;
    Suite::from_u8(b).ok_or(CborError::UnknownSuite(b))
}

/// Scope covering for the attenuation invariant: `parent` covers `child` iff they are equal or
/// `child` is a `/`-delimited sub-scope of `parent` (so `"directory"` covers `"directory/write"`,
/// and `"mailbox:calendar"` covers `"mailbox:calendar/events"`). A child scope the parent never
/// held is **not** covered — the widening the invariant forbids.
fn scope_covers(parent: &str, child: &str) -> bool {
    parent == child
        || child.strip_prefix(parent).map(|rest| rest.starts_with('/')).unwrap_or(false)
}

/// Caveats may only be **added or tightened**, never removed (§18.7.3). A child is a valid
/// narrowing iff every caveat key present on the parent is present on the child with the same value
/// (the child MAY add more). A parent with no caveats is covered by any child.
fn caveats_tightened(parent: Option<&Cv>, child: Option<&Cv>) -> bool {
    let parent_pairs: &[(String, Cv)] = match parent {
        Some(Cv::TextMap(m)) => m,
        Some(_) => return false, // malformed caveats never cover
        None => return true,     // parent unconditional ⇒ any child narrows it
    };
    let child_pairs: &[(String, Cv)] = match child {
        Some(Cv::TextMap(m)) => m,
        Some(_) => return false,
        None => return parent_pairs.is_empty(),
    };
    parent_pairs.iter().all(|(k, v)| child_pairs.iter().any(|(ck, cv)| ck == k && cv == v))
}

/// The attenuation invariant for one `(parent, child)` capability pair (§18.7.3): the child's
/// `resource` and `ability` MUST be same-or-narrower and its caveats only added/tightened.
fn capability_covers(parent: &Capability, child: &Capability) -> bool {
    scope_covers(&parent.resource, &child.resource)
        && scope_covers(&parent.ability, &child.ability)
        && caveats_tightened(parent.caveats.as_ref(), child.caveats.as_ref())
}

// --- Capability (§18.7.3) ------------------------------------------------------------------

/// One granted capability (§18.7.3): a scoped `resource`, a permitted `ability`, and OPTIONAL
/// attenuating `caveats`. Caveats are a text-keyed `{ * tstr => ext-value }` map preserved
/// verbatim (as a canonical [`Cv::TextMap`]) so the enclosing token's signature reproduces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    pub resource: String,        // key 1 — e.g. "mailbox:calendar"
    pub ability: String,         // key 2 — the verb, e.g. "read"
    pub caveats: Option<Cv>,     // key 3 — Cv::TextMap of attenuating conditions; None ⇒ absent
}

impl Capability {
    pub(crate) fn to_cv(&self) -> Cv {
        let mut m = vec![
            (1u64, Cv::Text(self.resource.clone())),
            (2, Cv::Text(self.ability.clone())),
        ];
        if let Some(c) = &self.caveats {
            m.push((3, c.clone()));
        }
        Cv::Map(m)
    }

    pub(crate) fn from_cv(cv: Cv) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cv)?;
        let resource = as_text(f.req(1)?)?;
        let ability = as_text(f.req(2)?)?;
        // caveats (key 3) is a text-keyed ext-value map; require the map shape and reject any
        // other CBOR type fail-closed (a non-map caveats field is malformed).
        let caveats = match f.take(3) {
            Some(c @ Cv::TextMap(_)) => Some(c),
            // An empty caveats map decodes as Cv::Map([]) (variant-neutral); accept it as no caveats.
            Some(Cv::Map(m)) if m.is_empty() => Some(Cv::TextMap(Vec::new())),
            Some(_) => return Err(CborError::TypeMismatch),
            None => None,
        };
        f.deny_unknown()?;
        Ok(Capability { resource, ability, caveats })
    }
}

// --- CapabilityToken (§18.7.3) -------------------------------------------------------------

/// A signed, attenuable delegation token (§18.7.3) — a profile of UCAN v1.0. Verified offline;
/// `prnt` chains it to a parent whose `aud` MUST equal this token's `iss`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityToken {
    pub suite: Suite,             // key 1
    pub iss: Vec<u8>,             // key 2 — issuer (delegator) key
    pub aud: Vec<u8>,             // key 3 — audience (delegatee) key
    pub caps: Vec<Capability>,    // key 4 — granted capabilities (≥ 1)
    pub nbf: u64,                 // key 5 — not-before (ms epoch)
    pub exp: u64,                 // key 6 — expiry (ms epoch); MUST be present
    pub nonce: Vec<u8>,           // key 7 — uniqueness / anti-replay salt
    pub prnt: Option<ContentId>,  // key 8 — content-addr of the PARENT token; absent ⇒ rooted at iss
    pub sig: Vec<u8>,             // key 9 — §18.9.14, over det_cbor(token ∖ {9}) under iss
}

impl CapabilityToken {
    /// Integer-keyed canonical map (§18.7.3). `include_sig=false` omits key 9 for the §18.9.14
    /// signing body.
    fn to_cv(&self, include_sig: bool) -> Cv {
        let mut m = vec![
            (1u64, Cv::U64(self.suite.as_u8() as u64)),
            (2, Cv::Bytes(self.iss.clone())),
            (3, Cv::Bytes(self.aud.clone())),
            (4, Cv::Array(self.caps.iter().map(Capability::to_cv).collect())),
            (5, Cv::U64(self.nbf)),
            (6, Cv::U64(self.exp)),
            (7, Cv::Bytes(self.nonce.clone())),
        ];
        if let Some(p) = &self.prnt {
            m.push((8, Cv::Bytes(p.as_bytes().to_vec())));
        }
        if include_sig {
            m.push((9, Cv::Bytes(self.sig.clone())));
        }
        Cv::Map(m)
    }

    /// The exact wire bytes: §18-canonical integer-keyed CBOR.
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(true))
    }

    /// The §18.9.14 signing body: deterministic CBOR of the token with `sig` (key 9) omitted.
    pub fn signing_body(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(false))
    }

    /// Decode a capability token (§18.7.3), failing closed on any violation (including an empty
    /// `caps` — `[+ Capability]` requires ≥ 1).
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cbor::decode(bytes)?)?;
        let suite = suite_from_cv(f.req(1)?)?;
        let iss = as_bytes(f.req(2)?)?;
        let aud = as_bytes(f.req(3)?)?;
        let caps: Vec<Capability> = as_array(f.req(4)?)?
            .into_iter()
            .map(Capability::from_cv)
            .collect::<Result<_, _>>()?;
        if caps.is_empty() {
            return Err(CborError::TypeMismatch); // [+ Capability] requires ≥ 1
        }
        let nbf = as_u64(f.req(5)?)?;
        let exp = as_u64(f.req(6)?)?;
        let nonce = as_bytes(f.req(7)?)?;
        let prnt = f.take(8).map(as_bytes).transpose()?.map(ContentId);
        let sig = as_bytes(f.req(9)?)?;
        f.deny_unknown()?;
        Ok(CapabilityToken { suite, iss, aud, caps, nbf, exp, nonce, prnt, sig })
    }

    /// Mint (sign) a token with the issuer key (§18.9.14); `iss` is set from the signer.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        iss: &IdentityKey,
        aud: Vec<u8>,
        caps: Vec<Capability>,
        nbf: u64,
        exp: u64,
        nonce: Vec<u8>,
        prnt: Option<ContentId>,
    ) -> CapabilityToken {
        let mut t = CapabilityToken {
            suite: Suite::Classical,
            iss: iss.public(),
            aud,
            caps,
            nbf,
            exp,
            nonce,
            prnt,
            sig: Vec::new(),
        };
        t.sig = iss.sign_domain(CAP_TOKEN_DS, &t.signing_body());
        t
    }

    /// Verify the token's own signature under `iss` (§18.9.14). Does **not** walk the delegation
    /// chain or check attenuation/revocation — the caller does (§18.7.3 verification steps). Kept
    /// as the signature-only primitive that [`verify_chain`](CapabilityToken::verify_chain) and
    /// [`verify_at`](CapabilityToken::verify_at) build on and that existing callers depend on.
    pub fn verify(&self) -> Result<(), IdentityError> {
        if !self.suite.is_supported() {
            return Err(IdentityError::UnsupportedSuite(self.suite.as_u8()));
        }
        verify_domain(&self.iss, CAP_TOKEN_DS, &self.signing_body(), &self.sig)
    }

    /// The content-address of this token (`0x1e ‖ BLAKE3-256(det_cbor(token))`) — the value a child
    /// names in its `prnt` and a [`CapabilityRevocation`] names in its `token` field (§18.7.3).
    pub fn content_id(&self) -> ContentId {
        ContentId::of(&self.det_cbor())
    }

    /// Walk the **entire delegation chain to a trusted root** (§18.7.3 verification steps 1–2),
    /// enforcing the attenuation invariant at every link. This is the check `verify()` deliberately
    /// omits.
    ///
    /// `chain` lists the ancestor tokens **nearest-parent first**: `chain[0]` is this token's direct
    /// parent, `chain[1]` its grandparent, …, and the final element MUST be the root (its `prnt`
    /// absent, so it is rooted at its own `iss`). At every `(child, parent)` link this checks, all
    /// fail-closed:
    ///
    /// 1. both tokens' own signatures verify (`0x0508` on failure);
    /// 2. the child's `prnt` equals the parent's content-address, and the child's `iss` equals the
    ///    parent's `aud` (`BrokenChain`, `0x0508`);
    /// 3. **every** child capability is `≤` some parent capability — same-or-narrower `resource`,
    ///    same/narrower `ability`, caveats only added/tightened (`AttenuationViolation`, `0x0508`).
    ///
    /// A widened child grant (a child claiming a right its parent never held) is rejected — the
    /// privilege-escalation the §10.7.3 row forbids. Verification is offline: no issuer round-trip.
    pub fn verify_chain(&self, chain: &[CapabilityToken]) -> Result<(), CapabilityError> {
        self.verify().map_err(|_| CapabilityError::BadSignature)?;
        let mut child = self;
        for parent in chain {
            parent.verify().map_err(|_| CapabilityError::BadSignature)?;
            match &child.prnt {
                Some(p) if *p == parent.content_id() => {}
                _ => return Err(CapabilityError::BrokenChain),
            }
            if child.iss != parent.aud {
                return Err(CapabilityError::BrokenChain);
            }
            for c in &child.caps {
                if !parent.caps.iter().any(|p| capability_covers(p, c)) {
                    return Err(CapabilityError::AttenuationViolation);
                }
            }
            child = parent;
        }
        // The walk MUST terminate at a token rooted at its own `iss` (no dangling parent link).
        if child.prnt.is_some() {
            return Err(CapabilityError::BrokenChain);
        }
        Ok(())
    }

    /// Enforce the invocation-time validity window and revocation set (§18.7.3 steps 3 & 6). `now`
    /// is the caller's clock — a **parameter**, never a wall-clock read in core (§16.1).
    ///
    /// - `now < nbf` ⇒ [`NotYetValid`](CapabilityError::NotYetValid) (`0x0508`);
    /// - `now ≥ exp` ⇒ [`Expired`](CapabilityError::Expired) (`0x0508`) — no eternal capability;
    /// - this token's content-address present in `revocations` ⇒ [`Revoked`](CapabilityError::Revoked)
    ///   (`0x050B`). Passing an ancestor's content-address here rejects a descendant too, per
    ///   "revoking a chain root revokes all descendants" (§18.7.3): the caller supplies every
    ///   chain-link id it wishes checked.
    ///
    /// The token's own signature is verified first (`0x0508` on failure).
    pub fn verify_at(&self, now: TimestampMs, revocations: &[ContentId]) -> Result<(), CapabilityError> {
        self.verify().map_err(|_| CapabilityError::BadSignature)?;
        if now < self.nbf {
            return Err(CapabilityError::NotYetValid);
        }
        if now >= self.exp {
            return Err(CapabilityError::Expired);
        }
        if revocations.iter().any(|r| *r == self.content_id()) {
            return Err(CapabilityError::Revoked);
        }
        Ok(())
    }
}

// --- CapabilityRevocation (§18.7.3) --------------------------------------------------------

/// A published, KT-logged revocation of a previously issued token (§18.7.3). Signed by the token's
/// `iss` (or an ancestor issuer in its chain).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityRevocation {
    pub suite: Suite,      // key 1
    pub iss: Vec<u8>,      // key 2 — the revoker (token's iss or an ancestor)
    pub token: ContentId,  // key 3 — content-addr of the revoked CapabilityToken
    pub ts: TimestampMs,   // key 4 — revocation time
    pub sig: Vec<u8>,      // key 5 — §18.9.14, over det_cbor(revocation ∖ {5}) under iss
}

impl CapabilityRevocation {
    fn to_cv(&self, include_sig: bool) -> Cv {
        let mut m = vec![
            (1u64, Cv::U64(self.suite.as_u8() as u64)),
            (2, Cv::Bytes(self.iss.clone())),
            (3, Cv::Bytes(self.token.as_bytes().to_vec())),
            (4, Cv::U64(self.ts)),
        ];
        if include_sig {
            m.push((5, Cv::Bytes(self.sig.clone())));
        }
        Cv::Map(m)
    }

    /// The exact wire bytes: §18-canonical integer-keyed CBOR.
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(true))
    }

    /// The §18.9.14 signing body: deterministic CBOR of the revocation with `sig` (key 5) omitted.
    pub fn signing_body(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(false))
    }

    /// Decode a revocation (§18.7.3), failing closed on any violation.
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cbor::decode(bytes)?)?;
        let suite = suite_from_cv(f.req(1)?)?;
        let iss = as_bytes(f.req(2)?)?;
        let token = ContentId(as_bytes(f.req(3)?)?);
        let ts = as_u64(f.req(4)?)?;
        let sig = as_bytes(f.req(5)?)?;
        f.deny_unknown()?;
        Ok(CapabilityRevocation { suite, iss, token, ts, sig })
    }

    /// Sign a revocation with the issuer key (§18.9.14); `iss` is set from the signer.
    pub fn issue(iss: &IdentityKey, token: ContentId, ts: TimestampMs) -> CapabilityRevocation {
        let mut r = CapabilityRevocation {
            suite: Suite::Classical,
            iss: iss.public(),
            token,
            ts,
            sig: Vec::new(),
        };
        r.sig = iss.sign_domain(CAP_REVOCATION_DS, &r.signing_body());
        r
    }

    /// Verify the revocation signature under `iss` (§18.9.14).
    pub fn verify(&self) -> Result<(), IdentityError> {
        if !self.suite.is_supported() {
            return Err(IdentityError::UnsupportedSuite(self.suite.as_u8()));
        }
        verify_domain(&self.iss, CAP_REVOCATION_DS, &self.signing_body(), &self.sig)
    }
}

// --- CapabilityAnnouncement (§10.2) --------------------------------------------------------

/// A `system`-MOTE **capability announcement** (spec §10.2). A peer advertises the capability set /
/// protocol extensions it supports, authenticated to the recipient (it rides inside a `system`
/// MOTE, kind `0x0a`). Announcements are **monotonic**: each carries a `caps_version` (`u64`) and a
/// receiver retains the highest version seen per peer, rejecting any announcement older-or-equal to
/// it (a stale replay attempting to suppress an advertised capability — a downgrade). See
/// [`CapsVersionTracker`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityAnnouncement {
    pub suite: Suite,          // key 1
    pub iss: Vec<u8>,          // key 2 — the announcing peer's key
    pub caps_version: u64,     // key 3 — monotonic per peer (§10.2)
    pub caps: Vec<Capability>, // key 4 — the advertised capability set
    pub ts: TimestampMs,       // key 5
    pub sig: Vec<u8>,          // key 6 — §18.9.14, over det_cbor(announce ∖ {6}) under iss
}

impl CapabilityAnnouncement {
    fn to_cv(&self, include_sig: bool) -> Cv {
        let mut m = vec![
            (1u64, Cv::U64(self.suite.as_u8() as u64)),
            (2, Cv::Bytes(self.iss.clone())),
            (3, Cv::U64(self.caps_version)),
            (4, Cv::Array(self.caps.iter().map(Capability::to_cv).collect())),
            (5, Cv::U64(self.ts)),
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

    /// The §18.9.14 signing body: deterministic CBOR of the announcement with `sig` (key 6) omitted.
    pub fn signing_body(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(false))
    }

    /// Decode an announcement (§10.2), failing closed on any violation.
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cbor::decode(bytes)?)?;
        let suite = suite_from_cv(f.req(1)?)?;
        let iss = as_bytes(f.req(2)?)?;
        let caps_version = as_u64(f.req(3)?)?;
        let caps: Vec<Capability> = as_array(f.req(4)?)?
            .into_iter()
            .map(Capability::from_cv)
            .collect::<Result<_, _>>()?;
        let ts = as_u64(f.req(5)?)?;
        let sig = as_bytes(f.req(6)?)?;
        f.deny_unknown()?;
        Ok(CapabilityAnnouncement { suite, iss, caps_version, caps, ts, sig })
    }

    /// Mint (sign) an announcement with the announcing peer's key (§18.9.14); `iss` is set from the
    /// signer.
    pub fn issue(
        iss: &IdentityKey,
        caps_version: u64,
        caps: Vec<Capability>,
        ts: TimestampMs,
    ) -> CapabilityAnnouncement {
        let mut a = CapabilityAnnouncement {
            suite: Suite::Classical,
            iss: iss.public(),
            caps_version,
            caps,
            ts,
            sig: Vec::new(),
        };
        a.sig = iss.sign_domain(CAP_ANNOUNCE_DS, &a.signing_body());
        a
    }

    /// Verify the announcement signature under `iss` (§18.9.14).
    pub fn verify(&self) -> Result<(), IdentityError> {
        if !self.suite.is_supported() {
            return Err(IdentityError::UnsupportedSuite(self.suite.as_u8()));
        }
        verify_domain(&self.iss, CAP_ANNOUNCE_DS, &self.signing_body(), &self.sig)
    }
}

/// Per-peer capability-announcement **anti-rollback** state (spec §10.2, §10.7.1). Retains the
/// highest `caps_version` accepted from each peer (keyed by `iss`). [`accept`](CapsVersionTracker::accept)
/// verifies an announcement and rejects any whose `caps_version` is `≤` the last accepted from that
/// peer — [`CapabilityError::AnnounceRollback`] (`0x030A`) — so a global active adversary cannot
/// replay a stale announcement to suppress a capability the peer already advertised (retain the
/// higher-versioned set; do not roll back).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CapsVersionTracker {
    seen: BTreeMap<Vec<u8>, u64>,
}

impl CapsVersionTracker {
    /// A tracker with no peers seen.
    pub fn new() -> Self {
        CapsVersionTracker { seen: BTreeMap::new() }
    }

    /// The highest `caps_version` accepted from `peer`, or `None` if none seen.
    pub fn last_version(&self, peer: &[u8]) -> Option<u64> {
        self.seen.get(peer).copied()
    }

    /// Verify and accept an announcement, failing closed on a stale/replayed one. The signature is
    /// checked first (`BadSignature`, `0x0508`); then a `caps_version ≤` the last accepted from that
    /// peer is rejected as [`CapabilityError::AnnounceRollback`] (`0x030A`) **without** mutating
    /// state. A strictly-newer announcement is accepted and becomes the new floor.
    pub fn accept(&mut self, ann: &CapabilityAnnouncement) -> Result<(), CapabilityError> {
        ann.verify().map_err(|_| CapabilityError::BadSignature)?;
        if let Some(&last) = self.seen.get(&ann.iss) {
            if ann.caps_version <= last {
                return Err(CapabilityError::AnnounceRollback);
            }
        }
        self.seen.insert(ann.iss.clone(), ann.caps_version);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> IdentityKey {
        IdentityKey::from_seed(&[seed; 32])
    }

    fn sample_caps() -> Vec<Capability> {
        vec![
            Capability {
                resource: "mailbox:calendar".into(),
                ability: "read".into(),
                caveats: Some(Cv::TextMap(vec![("before".into(), Cv::U64(1_800_000_000_000))])),
            },
            Capability { resource: "domain:abc.com/members".into(), ability: "directory/write".into(), caveats: None },
        ]
    }

    #[test]
    fn token_signs_verifies_and_round_trips() {
        let t = CapabilityToken::issue(
            &key(0x11),
            key(0x22).public(),
            sample_caps(),
            1_700_000_000_000,
            1_700_000_600_000,
            b"nonce-01".to_vec(),
            Some(ContentId::of(b"parent-token")),
        );
        assert!(t.verify().is_ok());
        let bytes = t.det_cbor();
        assert_eq!(bytes[0] & 0xe0, 0xa0, "token is a CBOR map");
        assert_eq!(bytes[1], 0x01, "first key is integer 1 (suite), not a text key");
        let back = CapabilityToken::from_det_cbor(&bytes).unwrap();
        assert_eq!(t, back);
        assert_eq!(bytes, back.det_cbor());
        assert!(back.verify().is_ok());
    }

    #[test]
    fn tampered_token_fails_signature() {
        let mut t = CapabilityToken::issue(
            &key(0x11), key(0x22).public(), sample_caps(), 1, 2, b"n".to_vec(), None,
        );
        t.exp = 3; // signed field changed
        assert_eq!(t.verify(), Err(IdentityError::BadSignature));
    }

    #[test]
    fn empty_caps_fails_closed() {
        let mut t = CapabilityToken::issue(
            &key(0x11), key(0x22).public(), sample_caps(), 1, 2, b"n".to_vec(), None,
        );
        t.caps.clear();
        t.sig.clear();
        let bytes = t.det_cbor();
        assert_eq!(CapabilityToken::from_det_cbor(&bytes), Err(CborError::TypeMismatch));
    }

    #[test]
    fn revocation_signs_verifies_and_round_trips() {
        let r = CapabilityRevocation::issue(&key(0x11), ContentId::of(b"revoked-token"), 1_700_000_000_000);
        assert!(r.verify().is_ok());
        let bytes = r.det_cbor();
        let back = CapabilityRevocation::from_det_cbor(&bytes).unwrap();
        assert_eq!(r, back);
        assert_eq!(bytes, back.det_cbor());
        assert!(back.verify().is_ok());
    }

    fn cap(resource: &str, ability: &str) -> Capability {
        Capability { resource: resource.into(), ability: ability.into(), caveats: None }
    }

    // A rooted parent (prnt=None) delegating `caps`, and a child rooted at the parent.
    fn rooted(iss: &IdentityKey, aud: Vec<u8>, caps: Vec<Capability>) -> CapabilityToken {
        CapabilityToken::issue(iss, aud, caps, 1_000, 9_000, b"root-nonce".to_vec(), None)
    }

    #[test]
    fn honest_attenuated_chain_verifies() {
        let root_k = key(0x11);
        let mid_k = key(0x22);
        let leaf_aud = key(0x33).public();
        // root grants directory (broad); child narrows to directory/write (a sub-scope).
        let parent = rooted(&root_k, mid_k.public(), vec![cap("domain:abc.com/members", "directory")]);
        let child = CapabilityToken::issue(
            &mid_k,
            leaf_aud,
            vec![cap("domain:abc.com/members", "directory/write")],
            1_000,
            9_000,
            b"child-nonce".to_vec(),
            Some(parent.content_id()),
        );
        assert!(child.verify_chain(&[parent]).is_ok());
    }

    #[test]
    fn widened_child_grant_is_rejected() {
        let root_k = key(0x11);
        let mid_k = key(0x22);
        let leaf_aud = key(0x33).public();
        // parent grants only "read"; child tries to grant "write" — a privilege escalation.
        let parent = rooted(&root_k, mid_k.public(), vec![cap("mailbox:calendar", "read")]);
        let child = CapabilityToken::issue(
            &mid_k,
            leaf_aud,
            vec![cap("mailbox:calendar", "write")],
            1_000,
            9_000,
            b"child-nonce".to_vec(),
            Some(parent.content_id()),
        );
        let err = child.verify_chain(&[parent]).unwrap_err();
        assert_eq!(err, CapabilityError::AttenuationViolation);
        assert_eq!(err.code(), 0x0508);
    }

    #[test]
    fn chain_discontinuity_is_rejected() {
        let root_k = key(0x11);
        let mid_k = key(0x22);
        let other = key(0x44); // NOT the parent
        let leaf_aud = key(0x33).public();
        let parent = rooted(&root_k, mid_k.public(), vec![cap("mailbox:calendar", "read")]);
        // Child names a wrong prnt (points at `other`, not `parent`).
        let child = CapabilityToken::issue(
            &mid_k,
            leaf_aud,
            vec![cap("mailbox:calendar", "read")],
            1_000,
            9_000,
            b"child-nonce".to_vec(),
            Some(rooted(&other, mid_k.public(), vec![cap("mailbox:calendar", "read")]).content_id()),
        );
        assert_eq!(child.verify_chain(&[parent]), Err(CapabilityError::BrokenChain));
    }

    #[test]
    fn expiry_not_yet_valid_and_revocation_enforced() {
        let iss = key(0x11);
        let t = CapabilityToken::issue(
            &iss,
            key(0x22).public(),
            vec![cap("mailbox:calendar", "read")],
            1_000, // nbf
            2_000, // exp
            b"n".to_vec(),
            None,
        );
        // Inside the window, no revocations: OK.
        assert!(t.verify_at(1_500, &[]).is_ok());
        // Before nbf.
        let e = t.verify_at(500, &[]).unwrap_err();
        assert_eq!(e, CapabilityError::NotYetValid);
        assert_eq!(e.code(), 0x0508);
        // At/after exp.
        let e = t.verify_at(2_000, &[]).unwrap_err();
        assert_eq!(e, CapabilityError::Expired);
        assert_eq!(e.code(), 0x0508);
        // Revoked (its own content-address in the set) — distinct 0x050B.
        let e = t.verify_at(1_500, &[t.content_id()]).unwrap_err();
        assert_eq!(e, CapabilityError::Revoked);
        assert_eq!(e.code(), 0x050B);
    }

    #[test]
    fn announcement_anti_rollback_rejects_stale_version() {
        let peer = key(0x55);
        let a1 = CapabilityAnnouncement::issue(&peer, 5, vec![cap("ext:mls", "support")], 10);
        let a2 = CapabilityAnnouncement::issue(&peer, 7, vec![cap("ext:mls", "support")], 20);
        // Round-trip.
        assert_eq!(CapabilityAnnouncement::from_det_cbor(&a1.det_cbor()).unwrap(), a1);

        let mut tr = CapsVersionTracker::new();
        assert!(tr.accept(&a2).is_ok());
        assert_eq!(tr.last_version(&peer.public()), Some(7));
        // Replaying the older (v5 ≤ 7) announcement is a rollback.
        let err = tr.accept(&a1).unwrap_err();
        assert_eq!(err, CapabilityError::AnnounceRollback);
        assert_eq!(err.code(), 0x030A);
        // Equal version is also rejected; the retained floor is unchanged.
        let a_eq = CapabilityAnnouncement::issue(&peer, 7, vec![], 30);
        assert_eq!(tr.accept(&a_eq), Err(CapabilityError::AnnounceRollback));
        assert_eq!(tr.last_version(&peer.public()), Some(7));
    }
}

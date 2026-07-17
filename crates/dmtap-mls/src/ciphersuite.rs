//! MLS-ciphersuite PQ gating & downgrade defense (spec §5.1, `ERR_MLS_CIPHERSUITE_DOWNGRADE`
//! `0x0414`).
//!
//! Message confidentiality in DMTAP rides the **MLS ciphersuite** — a separate RFC 9420 `u16`,
//! **not** `Envelope.suite`. The §1.3 suite high-water-mark ([`SuiteRatchet`]) polices only the
//! identity / sealed-sender layer (`Envelope.suite`); a group could therefore run a **classical**
//! MLS ciphersuite while every member's *identity* is already PQ, silently leaving message content
//! exposed to harvest-now-decrypt-later even though the §1.3 mark reads "PQ." The spec closes that
//! gap by policing message-PQ on its **own** axis (§5.1), and this module implements that gate:
//!
//! - **All-members-PQ ⇒ PQ MLS ciphersuite REQUIRED.** When **every** current member advertises a
//!   PQ identity suite *and* a supported PQ MLS ciphersuite, a Commit that keeps or moves the group
//!   to a **classical** ciphersuite MUST be rejected (`0x0414`).
//! - **Per-group MLS-ciphersuite high-water-mark.** Each member tracks, **per group**, the highest
//!   MLS ciphersuite the group has used, exactly as [`SuiteRatchet`] ratchets `Envelope.suite` per
//!   contact (§1.3). A Welcome / GroupInfo / Commit selecting a ciphersuite **below** that mark is a
//!   downgrade and MUST be rejected (`0x0414`); the mark ratchets **up only**, lowering solely via
//!   an explicit member-agreed retirement Commit, never via an inbound handshake.
//!
//! The two agility axes (`Envelope.suite` via `dmtap_core::suite::SuiteRatchet`, MLS ciphersuite via
//! [`MlsCiphersuiteRatchet`]) are policed **independently** so neither can silently mask a downgrade
//! on the other.

use std::collections::BTreeMap;

use openmls::prelude::Ciphersuite;

/// The `0x0414` MLS-ciphersuite downgrade / PQ-gate rejection (spec §5.1, §21.6).
///
/// Both variants resolve to the **same** wire code `0x0414` (`ERR_MLS_CIPHERSUITE_DOWNGRADE`) with
/// disposition `FAIL_CLOSED_BLOCK`: the downgrading handshake is rejected and the high-water-mark is
/// **not** lowered. The two variants distinguish *why* the handshake is a downgrade, mirroring how
/// `dmtap_core::suite::SuiteRatchetError` names its single downgrade case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MlsCiphersuiteError {
    /// The selected MLS ciphersuite is **below the group's MLS-ciphersuite high-water-mark** — a
    /// classic downgrade (e.g. a classical suite offered after the group ran a PQ one).
    BelowHighWaterMark,

    /// **Every** current member advertises a PQ identity suite *and* a supported PQ MLS ciphersuite,
    /// yet the handshake keeps/moves the group to a **classical** MLS ciphersuite — the all-members-PQ
    /// gate. Even a *first* ciphersuite (no prior high-water-mark) is rejected under this condition,
    /// so a group whose members are all PQ-capable can never silently run classical message crypto.
    AllMembersPqRequiresPq,
}

impl MlsCiphersuiteError {
    /// The normative DMTAP wire error code (§21.6): always `0x0414` for both variants.
    pub fn code(&self) -> u16 {
        0x0414
    }
}

impl std::fmt::Display for MlsCiphersuiteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MlsCiphersuiteError::BelowHighWaterMark => f.write_str(
                "selected MLS ciphersuite is below the group's MLS-ciphersuite high-water-mark — \
                 message-PQ downgrade (ERR_MLS_CIPHERSUITE_DOWNGRADE, §21.6 0x0414)",
            ),
            MlsCiphersuiteError::AllMembersPqRequiresPq => f.write_str(
                "all members advertise PQ identity + PQ MLS ciphersuite support, but the handshake \
                 selects a classical MLS ciphersuite — message-PQ downgrade \
                 (ERR_MLS_CIPHERSUITE_DOWNGRADE, §21.6 0x0414)",
            ),
        }
    }
}

impl std::error::Error for MlsCiphersuiteError {}

/// What one current member of a group advertises about its PQ capability (spec §5.1, §10.2). Both
/// conditions must hold for the member to count toward the all-members-PQ gate: a PQ *identity*
/// suite (`Envelope.suite` `0x02`/`0x03`) **and** support for a PQ *MLS* ciphersuite. A member that
/// is PQ on only one axis does **not** force the group to PQ message crypto (the group must be able
/// to actually run the PQ MLS ciphersuite for every member).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemberPqCapability {
    /// The member's DMTAP **identity** suite is PQ/hybrid (`Envelope.suite` `0x02` or `0x03`, §1.1).
    pub pq_identity: bool,
    /// The member advertises support for a PQ/hybrid **MLS** ciphersuite (§10.2 capability token).
    pub pq_mls_ciphersuite: bool,
}

impl MemberPqCapability {
    /// A member that is PQ on **both** axes (identity suite and MLS-ciphersuite support).
    pub fn fully_pq() -> Self {
        MemberPqCapability { pq_identity: true, pq_mls_ciphersuite: true }
    }

    /// A member with no PQ capability on either axis (a purely classical peer).
    pub fn classical() -> Self {
        MemberPqCapability { pq_identity: false, pq_mls_ciphersuite: false }
    }

    /// Whether this member counts toward the all-members-PQ gate: PQ on **both** axes.
    fn counts_as_pq(self) -> bool {
        self.pq_identity && self.pq_mls_ciphersuite
    }
}

/// Whether an MLS ciphersuite (RFC 9420 `u16`) uses a **post-quantum / hybrid** KEM — the property
/// that makes group *message* content PQ-safe (spec §5.1).
///
/// The only PQ/hybrid MLS ciphersuite registered so far is
/// `MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519` (`0x004D`) — an **X-Wing** (X25519 + ML-KEM-768)
/// hybrid KEM (`draft-ietf-mls-pq-ciphersuites`). Every classical suite (`0x0001`..=`0x0007`) is not
/// PQ. An unknown/unregistered `u16` is treated as **not** PQ (fail-closed toward the gate: it can
/// never *satisfy* the all-members-PQ requirement).
pub fn is_pq_ciphersuite(cs: u16) -> bool {
    cs == u16::from(Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519)
}

/// The **security level** of an MLS ciphersuite for high-water-mark ordering (spec §5.1).
///
/// MLS ciphersuite `u16` code points are **not** ordered by strength (e.g. classical ChaCha `0x0003`
/// > PQ X-Wing `0x004D` numerically would be nonsense), so the ratchet cannot compare the raw code
/// the way `dmtap_core::suite::SuiteRatchet` compares the `Envelope.suite` byte. Instead the mark is
/// a monotone **security ladder**, PQ strictly above classical, and (within classical) 256-bit above
/// 128-bit:
///
/// | level | ciphersuites |
/// |------:|--------------|
/// | `2`   | PQ/hybrid — X-Wing `0x004D` |
/// | `1`   | 256-bit classical — `0x0004`,`0x0005`,`0x0006`,`0x0007` |
/// | `0`   | 128-bit classical — `0x0001`,`0x0002`,`0x0003`, and any unknown code |
///
/// "Below the high-water-mark" (`0x0414`) means a **strictly lower level** than the highest the group
/// has used. The top level is the PQ gate; an unknown code sits at the floor so it can never be a
/// silent *upgrade* that later masks a downgrade.
pub fn security_level(cs: u16) -> u8 {
    if is_pq_ciphersuite(cs) {
        2
    } else if matches!(cs, 0x0004 | 0x0005 | 0x0006 | 0x0007) {
        1 // 256-bit classical (P-521 / X448 / P-384)
    } else {
        0 // 128-bit classical (0x0001..=0x0003) or any unknown/unregistered code
    }
}

/// Whether **every** member counts as fully PQ, so the group MUST run a PQ MLS ciphersuite (spec
/// §5.1). An **empty** roster does not trigger the gate (there is no member to protect).
pub fn all_members_pq(members: &[MemberPqCapability]) -> bool {
    !members.is_empty() && members.iter().all(|m| m.counts_as_pq())
}

/// Per-group **MLS-ciphersuite high-water-mark ratchet** (spec §5.1, §21.6 `0x0414`) — the
/// message-PQ analogue of `dmtap_core::suite::SuiteRatchet`.
///
/// A member tracks, per group (keyed by `group_id`), the highest **security level**
/// ([`security_level`]) of any MLS ciphersuite the group has used. A Welcome / GroupInfo / Commit
/// selecting a ciphersuite **below** that level is a downgrade and is rejected
/// ([`MlsCiphersuiteError::BelowHighWaterMark`], `0x0414`). The mark ratchets **up only** —
/// [`observe`](MlsCiphersuiteRatchet::observe) never lowers it — so an active adversary cannot replay
/// a weaker (classical) MLS ciphersuite past a group that has already migrated to PQ. Lowering the
/// mark is possible **only** via an explicit member-agreed retirement Commit
/// ([`retire_to`](MlsCiphersuiteRatchet::retire_to)), never via an inbound handshake.
///
/// The [`accept`](MlsCiphersuiteRatchet::accept) path additionally enforces the **all-members-PQ**
/// gate: if every current member is fully PQ ([`all_members_pq`]) the selected ciphersuite MUST be
/// PQ, even when there is no prior high-water-mark yet.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MlsCiphersuiteRatchet {
    /// group id → highest MLS-ciphersuite **security level** the group has used.
    marks: BTreeMap<Vec<u8>, u8>,
}

impl MlsCiphersuiteRatchet {
    /// A ratchet with no tracked groups.
    pub fn new() -> Self {
        MlsCiphersuiteRatchet { marks: BTreeMap::new() }
    }

    /// The current high-water-mark **security level** for `group`, or `None` if never seen.
    pub fn high_water_mark(&self, group: &[u8]) -> Option<u8> {
        self.marks.get(group).copied()
    }

    /// Check `selected` against `group`'s high-water-mark **and** the all-members-PQ gate, **without**
    /// mutating state (spec §5.1). Two independent ways to be a `0x0414` downgrade:
    ///
    /// 1. **All-members-PQ ⇒ PQ required.** If every current member is fully PQ ([`all_members_pq`])
    ///    but `selected` is classical → [`MlsCiphersuiteError::AllMembersPqRequiresPq`]. Checked first
    ///    so an all-PQ group rejects a classical *first* ciphersuite (no prior mark needed).
    /// 2. **Below high-water-mark.** If `selected`'s [`security_level`] is strictly below the pinned
    ///    mark → [`MlsCiphersuiteError::BelowHighWaterMark`].
    ///
    /// A first-contact (unpinned) ciphersuite that satisfies the PQ gate always passes.
    pub fn check(
        &self,
        group: &[u8],
        selected: u16,
        members: &[MemberPqCapability],
    ) -> Result<(), MlsCiphersuiteError> {
        if all_members_pq(members) && !is_pq_ciphersuite(selected) {
            return Err(MlsCiphersuiteError::AllMembersPqRequiresPq);
        }
        if let Some(&mark) = self.marks.get(group) {
            if security_level(selected) < mark {
                return Err(MlsCiphersuiteError::BelowHighWaterMark);
            }
        }
        Ok(())
    }

    /// Ratchet `group`'s high-water-mark **up** to `selected`'s [`security_level`] (never down).
    /// Idempotent for a ciphersuite at or below the current mark. Does **not** enforce the gate — use
    /// [`accept`](MlsCiphersuiteRatchet::accept) for the check-then-observe path.
    pub fn observe(&mut self, group: &[u8], selected: u16) {
        let level = security_level(selected);
        let e = self.marks.entry(group.to_vec()).or_insert(0);
        if level > *e {
            *e = level;
        }
    }

    /// [`check`](MlsCiphersuiteRatchet::check) then, on success, [`observe`](MlsCiphersuiteRatchet::observe):
    /// accept the MLS ciphersuite `selected` for `group`, rejecting a `0x0414` downgrade (below the
    /// mark, or a classical suite under all-members-PQ) and otherwise ratcheting the mark up. A
    /// rejected downgrade leaves the mark **untouched** (never ratchets down).
    pub fn accept(
        &mut self,
        group: &[u8],
        selected: u16,
        members: &[MemberPqCapability],
    ) -> Result<(), MlsCiphersuiteError> {
        self.check(group, selected, members)?;
        self.observe(group, selected);
        Ok(())
    }

    /// **Explicit member-agreed retirement** (spec §5.1): lower `group`'s high-water-mark to
    /// `selected`'s level. This is the *only* way the mark ever goes down — it models the
    /// member-agreed retirement Commit, **not** an inbound handshake (which can only ratchet up via
    /// [`accept`]). The caller is responsible for having verified the retirement carried the required
    /// member agreement (roster quorum, §16.8); this crate does not model that authorization here.
    ///
    /// [`accept`]: MlsCiphersuiteRatchet::accept
    pub fn retire_to(&mut self, group: &[u8], selected: u16) {
        self.marks.insert(group.to_vec(), security_level(selected));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The two DMTAP v0 classical MLS suites and the PQ one, by raw code point.
    const MLS_AES128: u16 = 0x0001; // MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 (v0 default)
    const MLS_CHACHA: u16 = 0x0003; // MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
    const MLS_256_X448: u16 = 0x0004; // MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448 (256-bit classical)
    const MLS_XWING: u16 = 0x004D; // MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 (PQ/hybrid)

    #[test]
    fn pq_classification_matches_the_registered_suites() {
        assert!(is_pq_ciphersuite(MLS_XWING), "X-Wing is the PQ/hybrid MLS suite");
        for classical in [MLS_AES128, MLS_CHACHA, MLS_256_X448, 0x0002, 0x0005, 0x0006, 0x0007] {
            assert!(!is_pq_ciphersuite(classical), "classical suite {classical:#06x} is not PQ");
        }
        // Unknown codes are not PQ (fail-closed toward the gate).
        assert!(!is_pq_ciphersuite(0xFFFF));
    }

    #[test]
    fn security_ladder_puts_pq_above_all_classical() {
        assert_eq!(security_level(MLS_XWING), 2, "PQ is the top tier");
        assert_eq!(security_level(MLS_256_X448), 1, "256-bit classical is the middle tier");
        assert_eq!(security_level(MLS_AES128), 0, "128-bit classical is the floor");
        assert_eq!(security_level(MLS_CHACHA), 0);
        assert_eq!(security_level(0xFFFF), 0, "unknown code sits at the floor, never an upgrade");
        assert!(security_level(MLS_XWING) > security_level(MLS_256_X448));
        assert!(security_level(MLS_256_X448) > security_level(MLS_AES128));
    }

    #[test]
    fn below_high_water_mark_is_rejected_equal_or_higher_accepted() {
        let g = b"group-1".to_vec();
        let mut r = MlsCiphersuiteRatchet::new();
        // Mixed roster (not all-PQ), so only the high-water-mark rule is in play.
        let members = [MemberPqCapability::fully_pq(), MemberPqCapability::classical()];

        // Ratchet up to the PQ suite.
        r.accept(&g, MLS_XWING, &members).unwrap();
        assert_eq!(r.high_water_mark(&g), Some(2));

        // A below-water-mark (classical) Commit is rejected with 0x0414, mark untouched.
        let err = r.accept(&g, MLS_AES128, &members).unwrap_err();
        assert_eq!(err, MlsCiphersuiteError::BelowHighWaterMark);
        assert_eq!(err.code(), 0x0414);
        assert_eq!(r.high_water_mark(&g), Some(2), "a rejected downgrade never ratchets the mark down");

        // The middle tier is also below the PQ mark → rejected.
        assert_eq!(
            r.check(&g, MLS_256_X448, &members),
            Err(MlsCiphersuiteError::BelowHighWaterMark)
        );

        // Equal (the same PQ suite) is accepted; higher-or-equal always passes.
        r.accept(&g, MLS_XWING, &members).unwrap();
        assert_eq!(r.high_water_mark(&g), Some(2));
    }

    #[test]
    fn ratchet_climbs_classical_tiers_then_rejects_a_drop() {
        let g = b"group-tiers".to_vec();
        let mut r = MlsCiphersuiteRatchet::new();
        let members = [MemberPqCapability::classical(), MemberPqCapability::classical()];

        // Start at 128-bit, climb to 256-bit classical.
        r.accept(&g, MLS_AES128, &members).unwrap();
        assert_eq!(r.high_water_mark(&g), Some(0));
        r.accept(&g, MLS_256_X448, &members).unwrap();
        assert_eq!(r.high_water_mark(&g), Some(1));

        // Dropping back to a 128-bit suite is a downgrade.
        assert_eq!(
            r.accept(&g, MLS_CHACHA, &members),
            Err(MlsCiphersuiteError::BelowHighWaterMark)
        );
        assert_eq!(r.high_water_mark(&g), Some(1));
    }

    #[test]
    fn all_pq_members_reject_a_classical_ciphersuite_even_as_the_first() {
        let g = b"group-allpq".to_vec();
        let mut r = MlsCiphersuiteRatchet::new();
        let all_pq = [MemberPqCapability::fully_pq(), MemberPqCapability::fully_pq()];

        assert!(all_members_pq(&all_pq));

        // No prior mark, yet an all-PQ group MUST NOT run a classical MLS ciphersuite.
        let err = r.check(&g, MLS_AES128, &all_pq).unwrap_err();
        assert_eq!(err, MlsCiphersuiteError::AllMembersPqRequiresPq);
        assert_eq!(err.code(), 0x0414);
        // accept() rejects it too and does not pin a classical mark.
        assert!(r.accept(&g, MLS_AES128, &all_pq).is_err());
        assert_eq!(r.high_water_mark(&g), None, "a rejected first ciphersuite pins nothing");

        // The PQ ciphersuite is accepted and pins the top tier.
        r.accept(&g, MLS_XWING, &all_pq).unwrap();
        assert_eq!(r.high_water_mark(&g), Some(2));
    }

    #[test]
    fn all_pq_gate_needs_pq_on_both_axes() {
        let g = b"group-oneaxis".to_vec();
        let r = MlsCiphersuiteRatchet::new();

        // Every member is PQ on IDENTITY but not one on MLS-ciphersuite support: the group cannot
        // actually run the PQ MLS suite for everyone, so the gate does NOT fire — a classical suite
        // is allowed (no prior mark).
        let identity_only = [
            MemberPqCapability { pq_identity: true, pq_mls_ciphersuite: false },
            MemberPqCapability { pq_identity: true, pq_mls_ciphersuite: true },
        ];
        assert!(!all_members_pq(&identity_only));
        assert!(r.check(&g, MLS_AES128, &identity_only).is_ok());
    }

    #[test]
    fn empty_roster_does_not_trigger_the_pq_gate() {
        let r = MlsCiphersuiteRatchet::new();
        assert!(!all_members_pq(&[]));
        assert!(r.check(b"g", MLS_AES128, &[]).is_ok());
    }

    #[test]
    fn retirement_is_the_only_way_the_mark_lowers() {
        let g = b"group-retire".to_vec();
        let mut r = MlsCiphersuiteRatchet::new();
        let members = [MemberPqCapability::classical(), MemberPqCapability::classical()];
        r.accept(&g, MLS_XWING, &members).unwrap();
        assert_eq!(r.high_water_mark(&g), Some(2));

        // An inbound handshake can never lower it...
        assert!(r.accept(&g, MLS_AES128, &members).is_err());
        assert_eq!(r.high_water_mark(&g), Some(2));

        // ...only an explicit member-agreed retirement Commit does.
        r.retire_to(&g, MLS_AES128);
        assert_eq!(r.high_water_mark(&g), Some(0));
        // After retirement the (now-higher) classical suite is accepted again.
        assert!(r.accept(&g, MLS_AES128, &members).is_ok());
    }
}

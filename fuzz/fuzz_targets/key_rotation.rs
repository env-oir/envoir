#![no_main]
use libfuzzer_sys::fuzz_target;

use dmtap_core::identity::{
    authorize_key_rotation, key_rotation_is_quorum_backed, IdentityKey, KeyRotation, MethodPredicate,
    RecoveryMethod, RecoveryPolicy, Threshold,
};
use dmtap_core::suite::Suite;

// KeyRotation decode (§18.4.5) + the S1 stolen-`IK` takeover-defense authorization
// (`authorize_key_rotation`, §1.5 / `ERR_KEYROTATION_UNAUTHORIZED` `0x0121`), fed fully
// attacker-controlled bytes. A `KeyRotation` reconstructed from hostile bytes MUST:
//
//  1. never panic on decode, `verify()`, `content_id()`, or re-encode;
//  2. **fail closed** through the authorization gate: with a published `RecoveryPolicy` and no valid
//     quorum co-signature (and before any veto window elapses), the gate MUST NOT return `Ok` — a
//     rotation signed by `old_ik` alone can never silently evict the recovery quorum. Only the
//     no-policy case (`old_ik` alone suffices, §1.5) legitimately returns `Ok`.
//
// The rotation object is fuzzer-controlled; the `RecoveryPolicy` is synthesized from the same bytes
// (varying the guardian set / threshold) so the quorum-bar arithmetic runs on a real policy on every
// input. Guardian approvals/vetoes are deliberately EMPTY: the fuzzer cannot mint a guardian
// co-signature, so `key_rotation_is_quorum_backed` must be false and path (a) must never open — the
// core fail-closed property this target pins.
fuzz_target!(|data: &[u8]| {
    let Ok(rot) = KeyRotation::from_det_cbor(data) else { return };

    // Structural surface — none of these may panic on an arbitrary decoded rotation.
    let _ = rot.verify();
    let _ = rot.content_id();
    let _ = rot.det_cbor();

    // Derive some fuzzed-but-bounded scalars from the tail bytes.
    let n_guardians = (data.first().copied().unwrap_or(0) % 6) as usize; // 0..=5 guardians
    let threshold = data.get(1).copied().unwrap_or(1).max(1); // ≥ 1
    let announced_at = 1_000u64;
    let now = u64::from(data.get(2).copied().unwrap_or(0)) * 100_000_000; // 0 .. ~25.5e9 ms

    // §1.5: with NO published policy, `old_ik` alone remains sufficient — this is the one Ok path.
    assert!(
        authorize_key_rotation(&rot, None, &[], &[], announced_at, now).is_ok(),
        "no-policy authorization must always succeed (old_ik alone suffices, §1.5)"
    );

    // A real published social RecoveryPolicy synthesized from the fuzz input.
    let guardians: Vec<Vec<u8>> = (0..n_guardians)
        .map(|i| IdentityKey::from_seed(&[i as u8; 32]).public())
        .collect();
    let policy = RecoveryPolicy {
        suite: Suite::Classical,
        ik: rot.old_ik.clone(),
        version: 1,
        methods: vec![RecoveryMethod::Social { guardians: guardians.clone(), threshold }],
        recover_threshold: Threshold { any_of: vec![MethodPredicate::Guardians(threshold)] },
        rotate_threshold: Threshold { any_of: vec![MethodPredicate::Guardians(threshold)] },
        prev: None,
        ts: 0,
        sig: Vec::new(),
    };

    // With EMPTY approvals the fuzzer cannot forge a quorum: path (a) must never be satisfied.
    assert!(
        !key_rotation_is_quorum_backed(&rot, &policy, &[]),
        "an unsigned/empty approval set can never be quorum-backed"
    );

    // The full authorization gate must never panic and must never spuriously authorize: with a
    // published policy, no approvals, and no vetoes, only the elapsed-veto-window path (b) may return
    // Ok — and only for an `old_ik`-alone (no rotate_quorum) record. Any Ok therefore implies the
    // window has fully elapsed; any not-yet-elapsed / quorum-claiming record must be Unauthorized.
    let res = authorize_key_rotation(&rot, Some(&policy), &[], &[], announced_at, now);
    if res.is_ok() {
        assert!(
            rot.rotate_quorum.is_none(),
            "a quorum-claiming record with no valid approvals must not authorize via the delay path"
        );
        assert!(
            now >= announced_at.saturating_add(dmtap_core::identity::RECOVERY_VETO_WINDOW_MS),
            "the delay-path Ok requires the veto window to have fully elapsed"
        );
    }
});

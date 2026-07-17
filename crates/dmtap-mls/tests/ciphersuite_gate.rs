//! MLS-ciphersuite PQ gate + high-water-mark, grounded on a **real** openmls group (spec §5.1,
//! `ERR_MLS_CIPHERSUITE_DOWNGRADE` `0x0414`).
//!
//! Message confidentiality rides the MLS ciphersuite (a separate `u16`), **not** `Envelope.suite`,
//! so PQ must be policed on the MLS-ciphersuite axis. These tests read the ciphersuite off a live
//! MLS `Session` and drive it through the `MlsCiphersuiteRatchet`, showing the gate rejects (a) a
//! classical suite when every member is fully PQ, and (b) any below-high-water-mark downgrade — both
//! with code `0x0414` — while the DMTAP v0 default (`0x0001`) is accepted for a not-all-PQ roster.

use dmtap_mls::{
    is_pq_ciphersuite, security_level, Committer, Handshake, Member, MemberPqCapability,
    MlsCiphersuiteError, MlsCiphersuiteRatchet, Session,
};

const GROUP_ID: &[u8] = b"dmtap-ciphersuite-gate";
const MLS_XWING: u16 = 0x004D; // MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 (PQ/hybrid)

/// Order a handshake and apply it to every existing session (same helper shape as `groups.rs`).
fn order_and_apply(committer: &mut Committer, sessions: &mut [&mut Session], author_idx: usize, hs: Handshake) {
    let seq = committer.submit(hs);
    sessions[author_idx].note_authored(seq);
    for s in sessions.iter_mut() {
        s.advance(committer).expect("member advances along the committer log");
    }
}

/// Build a real 2-member MLS group and return one live session, so we can read its actual MLS
/// ciphersuite (the DMTAP v0 default `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`, `0x0001`).
fn live_group() -> Session {
    let mut committer = Committer::new();
    let alice = Member::new(b"alice".to_vec(), "phone").unwrap();
    let bob = Member::new(b"bob".to_vec(), "phone").unwrap();
    let mut alice = alice.create_group(GROUP_ID).unwrap();
    let hs = alice.add_member(&bob.publish_key_package().unwrap()).unwrap();
    order_and_apply(&mut committer, &mut [&mut alice], 0, hs);
    alice
}

#[test]
fn a_real_group_runs_the_classical_v0_ciphersuite() {
    let alice = live_group();
    assert_eq!(alice.ciphersuite(), 0x0001, "DMTAP v0 default MLS ciphersuite");
    assert!(!is_pq_ciphersuite(alice.ciphersuite()), "the v0 default is classical, not PQ");
    assert_eq!(security_level(alice.ciphersuite()), 0, "128-bit classical sits at the floor");
}

#[test]
fn all_pq_members_reject_the_real_classical_group_ciphersuite_0x0414() {
    let alice = live_group();
    let cs = alice.ciphersuite(); // 0x0001, classical
    let mut ratchet = MlsCiphersuiteRatchet::new();

    // Every member advertises PQ identity + PQ MLS ciphersuite support: the group MUST run PQ, so
    // the real classical ciphersuite is a message-PQ downgrade → 0x0414.
    let all_pq = [MemberPqCapability::fully_pq(), MemberPqCapability::fully_pq()];
    let err = ratchet.accept(GROUP_ID, cs, &all_pq).unwrap_err();
    assert_eq!(err, MlsCiphersuiteError::AllMembersPqRequiresPq);
    assert_eq!(err.code(), 0x0414);
    assert_eq!(ratchet.high_water_mark(GROUP_ID), None, "a rejected ciphersuite pins nothing");

    // The same group ciphersuite is fine when the roster is NOT all-PQ (a classical member present).
    let mixed = [MemberPqCapability::fully_pq(), MemberPqCapability::classical()];
    assert!(ratchet.accept(GROUP_ID, cs, &mixed).is_ok());
    assert_eq!(ratchet.high_water_mark(GROUP_ID), Some(0));
}

#[test]
fn once_a_group_has_gone_pq_a_classical_commit_is_rejected_0x0414() {
    let alice = live_group();
    let mut ratchet = MlsCiphersuiteRatchet::new();
    let mixed = [MemberPqCapability::fully_pq(), MemberPqCapability::classical()];

    // The group starts on the real classical ciphersuite (pins level 0), then migrates up to PQ.
    ratchet.accept(GROUP_ID, alice.ciphersuite(), &mixed).unwrap();
    ratchet.accept(GROUP_ID, MLS_XWING, &mixed).unwrap();
    assert_eq!(ratchet.high_water_mark(GROUP_ID), Some(2), "high-water-mark ratcheted to PQ");

    // A later Commit that moves the group BACK to the classical ciphersuite is a downgrade → 0x0414;
    // the high-water-mark never ratchets down on an inbound handshake.
    let err = ratchet.accept(GROUP_ID, alice.ciphersuite(), &mixed).unwrap_err();
    assert_eq!(err, MlsCiphersuiteError::BelowHighWaterMark);
    assert_eq!(err.code(), 0x0414);
    assert_eq!(ratchet.high_water_mark(GROUP_ID), Some(2));
}

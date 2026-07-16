//! Real MLS group tests (spec §5): 3-member convergence + application messages, async **Add** of
//! a 4th member (sees subsequent, not prior), **Remove** with post-compromise security, and
//! **multi-device** (two devices of one owner both in the group). Every operation flows through the
//! [`Committer`] ordering seam (§5.1): a Commit is submitted for a total-order sequence, then every
//! member advances by applying committed handshakes in that order.

use dmtap_mls::{Committer, Handshake, Member, Session};

/// Order a member-authored [`Handshake`] through the committer and apply it to every existing
/// member's view (§5.1): submit for a sequence, tell the author it authored `seq` (so it merges its
/// own pending commit), then advance all views to the log head. `sessions[author_idx]` is the
/// author; a member being *added* by this handshake is NOT yet in `sessions` (it joins after).
fn order_and_apply(
    committer: &mut Committer,
    sessions: &mut [&mut Session],
    author_idx: usize,
    hs: Handshake,
) -> u64 {
    let seq = committer.submit(hs);
    sessions[author_idx].note_authored(seq);
    for s in sessions.iter_mut() {
        s.advance(committer).expect("member advances along the committer log");
    }
    seq
}

/// Assert every session shares one epoch + epoch authenticator — the test-visible proof that all
/// members converged on the same group state / epoch secret (§5.1).
fn assert_converged(sessions: &[&Session]) {
    let (epoch, auth) = (sessions[0].epoch(), sessions[0].epoch_authenticator());
    for s in sessions {
        assert_eq!(s.epoch(), epoch, "all members on the same MLS epoch");
        assert_eq!(
            s.epoch_authenticator(),
            auth,
            "all members share the epoch authenticator (converged on one epoch secret)"
        );
    }
}

const GROUP_ID: &[u8] = b"dmtap-test-group";

// --- 3-member convergence + application messages -------------------------------------------

#[test]
fn three_member_group_converges_and_exchanges_application_messages() {
    let mut committer = Committer::new();

    // Alice founds the group; Bob and Charlie publish KeyPackages for async join (§5.3).
    let alice = Member::new(b"alice".to_vec(), "phone").unwrap();
    let bob = Member::new(b"bob".to_vec(), "phone").unwrap();
    let charlie = Member::new(b"charlie".to_vec(), "phone").unwrap();
    let bob_kp = bob.publish_key_package().unwrap();
    let charlie_kp = charlie.publish_key_package().unwrap();

    let mut alice = alice.create_group(GROUP_ID).unwrap();
    assert_eq!(alice.epoch(), 0);

    // Alice adds Bob (Add Commit + Welcome), ordered by the committer, then applied by Alice.
    let hs = alice.add_member(&bob_kp).unwrap();
    let welcome_bob = hs.welcome.clone().expect("an Add produces a Welcome");
    order_and_apply(&mut committer, &mut [&mut alice], 0, hs);
    let mut bob = bob.join_from_welcome(&welcome_bob).unwrap();
    bob.note_joined_at(committer.head());
    assert_converged(&[&alice, &bob]);

    // Alice adds Charlie; Alice + Bob apply the commit, Charlie bootstraps from the Welcome.
    let hs = alice.add_member(&charlie_kp).unwrap();
    let welcome_charlie = hs.welcome.clone().unwrap();
    order_and_apply(&mut committer, &mut [&mut alice, &mut bob], 0, hs);
    let mut charlie = charlie.join_from_welcome(&welcome_charlie).unwrap();
    charlie.note_joined_at(committer.head());

    // All three converged on the same epoch + epoch secret, with a 3-leaf roster.
    assert_converged(&[&alice, &bob, &charlie]);
    assert_eq!(alice.roster().len(), 3, "three members in the group");

    // An application message from Charlie decrypts for every other member (§5.4).
    let msg = b"the substrate carries mail, chat, and files";
    let ct = charlie.create_message(msg).unwrap();
    assert_eq!(alice.receive_message(&ct).unwrap(), msg, "Alice decrypts Charlie's message");
    assert_eq!(bob.receive_message(&ct).unwrap(), msg, "Bob decrypts Charlie's message");

    // And a message the other direction, to show it is a real bidirectional group session.
    let reply = b"acknowledged";
    let ct = alice.create_message(reply).unwrap();
    assert_eq!(bob.receive_message(&ct).unwrap(), reply);
    assert_eq!(charlie.receive_message(&ct).unwrap(), reply);
}

// --- async Add of a 4th member: sees subsequent, not prior ---------------------------------

#[test]
fn added_member_sees_subsequent_but_not_prior_messages() {
    let mut committer = Committer::new();
    let alice = Member::new(b"alice".to_vec(), "phone").unwrap();
    let bob = Member::new(b"bob".to_vec(), "phone").unwrap();
    let charlie = Member::new(b"charlie".to_vec(), "phone").unwrap();
    let dave = Member::new(b"dave".to_vec(), "phone").unwrap();

    // Build the {alice, bob, charlie} group.
    let mut alice = alice.create_group(GROUP_ID).unwrap();
    let hs = alice.add_member(&bob.publish_key_package().unwrap()).unwrap();
    let w = hs.welcome.clone().unwrap();
    order_and_apply(&mut committer, &mut [&mut alice], 0, hs);
    let mut bob = bob.join_from_welcome(&w).unwrap();
    bob.note_joined_at(committer.head());
    let hs = alice.add_member(&charlie.publish_key_package().unwrap()).unwrap();
    let w = hs.welcome.clone().unwrap();
    order_and_apply(&mut committer, &mut [&mut alice, &mut bob], 0, hs);
    let mut charlie = charlie.join_from_welcome(&w).unwrap();
    charlie.note_joined_at(committer.head());

    // A message sent BEFORE Dave joins (epoch without Dave).
    let prior = b"secret said before Dave arrived";
    let prior_ct = alice.create_message(prior).unwrap();
    assert_eq!(bob.receive_message(&prior_ct).unwrap(), prior);

    // Now add Dave (a new epoch); Dave bootstraps from the Welcome.
    let hs = alice.add_member(&dave.publish_key_package().unwrap()).unwrap();
    let w = hs.welcome.clone().unwrap();
    order_and_apply(&mut committer, &mut [&mut alice, &mut bob, &mut charlie], 0, hs);
    let mut dave = dave.join_from_welcome(&w).unwrap();
    dave.note_joined_at(committer.head());
    assert_converged(&[&alice, &bob, &charlie, &dave]);

    // Dave decrypts a message sent AFTER he joined...
    let after = b"welcome to the group, Dave";
    let after_ct = alice.create_message(after).unwrap();
    assert_eq!(dave.receive_message(&after_ct).unwrap(), after, "Dave sees subsequent messages");

    // ...but CANNOT decrypt the message from the epoch before he joined (forward secrecy / he was
    // never given that epoch's secrets, §5.2). Fail-closed: it is an error, not silent plaintext.
    assert!(
        dave.receive_message(&prior_ct).is_err(),
        "a newly-added member must NOT be able to read messages from before it joined"
    );
}

// --- Remove with post-compromise security --------------------------------------------------

#[test]
fn removed_member_cannot_read_future_epochs_pcs() {
    let mut committer = Committer::new();
    let alice = Member::new(b"alice".to_vec(), "phone").unwrap();
    let bob = Member::new(b"bob".to_vec(), "phone").unwrap();
    let charlie = Member::new(b"charlie".to_vec(), "phone").unwrap();

    let mut alice = alice.create_group(GROUP_ID).unwrap();
    let hs = alice.add_member(&bob.publish_key_package().unwrap()).unwrap();
    let w = hs.welcome.clone().unwrap();
    order_and_apply(&mut committer, &mut [&mut alice], 0, hs);
    let mut bob = bob.join_from_welcome(&w).unwrap();
    bob.note_joined_at(committer.head());
    let hs = alice.add_member(&charlie.publish_key_package().unwrap()).unwrap();
    let w = hs.welcome.clone().unwrap();
    order_and_apply(&mut committer, &mut [&mut alice, &mut bob], 0, hs);
    let mut charlie = charlie.join_from_welcome(&w).unwrap();
    charlie.note_joined_at(committer.head());
    assert_converged(&[&alice, &bob, &charlie]);

    // Before removal, Charlie is a full member and reads group traffic.
    let pre = b"charlie can read this";
    let pre_ct = alice.create_message(pre).unwrap();
    assert_eq!(charlie.receive_message(&pre_ct).unwrap(), pre);
    let epoch_before = alice.epoch();

    // Alice removes Charlie (Remove Commit). Alice + Bob apply it and advance a full epoch; the
    // TreeKEM path secrets are re-keyed. Charlie is NOT advanced — modeling a removed member cut
    // off from the group, holding only its now-stale epoch state.
    let charlie_leaf = charlie.own_leaf_index();
    let hs = alice.remove_member(charlie_leaf).unwrap();
    assert!(hs.welcome.is_none(), "a Remove yields no Welcome");
    order_and_apply(&mut committer, &mut [&mut alice, &mut bob], 0, hs);

    assert!(alice.epoch() > epoch_before, "the Remove advanced the epoch");
    assert_converged(&[&alice, &bob]);
    assert_eq!(alice.roster().len(), 2, "Charlie is gone from the roster");

    // POST-COMPROMISE SECURITY: a message in the new epoch decrypts for the remaining members but
    // Charlie's old key/state decrypts NOTHING further — the whole point of a Remove Commit (§5.2).
    let post = b"charlie must never read this";
    let post_ct = alice.create_message(post).unwrap();
    assert_eq!(bob.receive_message(&post_ct).unwrap(), post, "remaining member still reads");
    assert!(
        charlie.receive_message(&post_ct).is_err(),
        "the removed member's old key must decrypt nothing in later epochs (PCS)"
    );
    // Charlie's stale epoch authenticator no longer matches the live group.
    assert_ne!(charlie.epoch_authenticator(), alice.epoch_authenticator());
}

// --- multi-device: two devices of one owner in the same group (§5.6) -----------------------

#[test]
fn multi_device_owner_has_two_leaves_in_the_group() {
    let mut committer = Committer::new();

    // Alice owns two devices; each is its OWN MLS leaf (§5.6). Bob is a separate owner.
    let alice_phone = Member::new(b"alice".to_vec(), "phone").unwrap();
    let alice_laptop = Member::new(b"alice".to_vec(), "laptop").unwrap();
    let bob = Member::new(b"bob".to_vec(), "phone").unwrap();
    assert_eq!(alice_phone.owner(), alice_laptop.owner(), "two devices, one owner");

    // Phone founds the group and adds the laptop (the owner's second device).
    let mut phone = alice_phone.create_group(GROUP_ID).unwrap();
    let hs = phone.add_member(&alice_laptop.publish_key_package().unwrap()).unwrap();
    let w = hs.welcome.clone().unwrap();
    order_and_apply(&mut committer, &mut [&mut phone], 0, hs);
    let mut laptop = alice_laptop.join_from_welcome(&w).unwrap();
    laptop.note_joined_at(committer.head());

    // Then the phone adds Bob.
    let hs = phone.add_member(&bob.publish_key_package().unwrap()).unwrap();
    let w = hs.welcome.clone().unwrap();
    order_and_apply(&mut committer, &mut [&mut phone, &mut laptop], 0, hs);
    let mut bob = bob.join_from_welcome(&w).unwrap();
    bob.note_joined_at(committer.head());

    // All three leaves converge; the roster shows two of them belong to owner "alice".
    assert_converged(&[&phone, &laptop, &bob]);
    let alice_leaves = phone
        .roster()
        .iter()
        .filter(|(_, id)| Member::owner_of_identity(id) == b"alice")
        .count();
    assert_eq!(alice_leaves, 2, "both of Alice's devices are leaves in the group (§5.6)");
    assert_eq!(phone.roster().len(), 3);

    // Either of Alice's devices can send; the other device AND Bob receive — the cluster shares
    // one MLS tree rather than pairwise ratchets (§5.6).
    let from_laptop = b"typed on the laptop";
    let ct = laptop.create_message(from_laptop).unwrap();
    assert_eq!(phone.receive_message(&ct).unwrap(), from_laptop, "the phone sees the laptop's msg");
    assert_eq!(bob.receive_message(&ct).unwrap(), from_laptop, "Bob sees it too");
}

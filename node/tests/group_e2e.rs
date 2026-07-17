//! Node-level MLS group integration (spec §5): real [`Node`]s form a real RFC 9420 group and
//! exchange application messages over the mesh transport, with membership handshakes ordered by the
//! in-process [`Committer`] (the §5.1 DS ordering seam). This exercises the node's group surface
//! (`found_group`/`publish_group_keypackage`/`group_add_member`/`join_group`/`group_broadcast`/
//! `poll`/`poll_group_messages`) end-to-end, alongside the untouched 1:1 path.

use dmtap::groups::Committer;
use dmtap::identity::IdentityKey;
use dmtap::mote::SealKeypair;
use dmtap::node::Node;
use dmtap::transport::{Frame, InMemoryNetwork, InMemoryTransport, Transport};

/// A node whose transport address equals its identity key (the in-process addressing model),
/// returned with its identity public bytes.
fn make_node(net: &InMemoryNetwork) -> (Node<InMemoryTransport>, Vec<u8>) {
    let ik = IdentityKey::generate();
    let seal = SealKeypair::generate();
    let ik_pub = ik.public();
    let transport = net.endpoint(ik_pub.clone());
    (Node::with_identity(ik, seal, transport), ik_pub)
}

const GID: &[u8] = b"node-group";

#[test]
fn three_nodes_form_a_real_mls_group_and_exchange_messages() {
    let net = InMemoryNetwork::new();
    let mut committer = Committer::new();

    let (mut alice, _a) = make_node(&net);
    let (mut bob, _b) = make_node(&net);
    let (mut charlie, _c) = make_node(&net);

    // Bob and Charlie pre-publish KeyPackages (§5.3 async join); Alice founds the group.
    let bob_kp = bob.publish_group_keypackage().unwrap();
    let charlie_kp = charlie.publish_group_keypackage().unwrap();
    alice.found_group(GID).unwrap();
    assert_eq!(alice.group_epoch(GID), Some(0));

    // Alice adds Bob: the Commit is ordered by the committer; Bob joins from the Welcome.
    let add = alice.group_add_member(GID, &bob_kp, &mut committer).unwrap();
    bob.join_group(GID, &add.welcome, &committer).unwrap();

    // Alice adds Charlie; Bob catches up along the committer log; Charlie joins from the Welcome.
    let add = alice.group_add_member(GID, &charlie_kp, &mut committer).unwrap();
    bob.apply_committed(GID, &committer).unwrap();
    charlie.join_group(GID, &add.welcome, &committer).unwrap();

    // All three converged on the same epoch with a 3-member roster.
    let epoch = alice.group_epoch(GID).unwrap();
    assert_eq!(bob.group_epoch(GID), Some(epoch));
    assert_eq!(charlie.group_epoch(GID), Some(epoch));
    assert_eq!(alice.group_roster(GID).unwrap().len(), 3);

    // Alice broadcasts a group application message over the mesh; Bob & Charlie receive it via the
    // real transport (Frame::Group), then decrypt it through their MLS sessions.
    let secret = b"one substrate for mail, chat, and files";
    let sent = alice.group_broadcast(GID, secret).unwrap();
    assert_eq!(sent, 2, "fanned out to Bob and Charlie");

    bob.poll();
    charlie.poll();
    let bob_msgs = bob.poll_group_messages();
    let charlie_msgs = charlie.poll_group_messages();
    assert_eq!(bob_msgs.len(), 1);
    assert_eq!(bob_msgs[0].1.as_ref().unwrap().as_slice(), secret, "Bob decrypts the group message");
    assert_eq!(charlie_msgs[0].1.as_ref().unwrap().as_slice(), secret, "Charlie decrypts it too");
}

#[test]
fn removed_node_cannot_read_future_group_messages_pcs() {
    let net = InMemoryNetwork::new();
    let mut committer = Committer::new();
    let (mut alice, _a) = make_node(&net);
    let (mut bob, _b) = make_node(&net);
    let (mut charlie, charlie_addr) = make_node(&net);

    let bob_kp = bob.publish_group_keypackage().unwrap();
    let charlie_kp = charlie.publish_group_keypackage().unwrap();
    alice.found_group(GID).unwrap();
    let add = alice.group_add_member(GID, &bob_kp, &mut committer).unwrap();
    bob.join_group(GID, &add.welcome, &committer).unwrap();
    let add = alice.group_add_member(GID, &charlie_kp, &mut committer).unwrap();
    bob.apply_committed(GID, &committer).unwrap();
    charlie.join_group(GID, &add.welcome, &committer).unwrap();

    // Alice removes Charlie. Alice + Bob advance a full epoch (TreeKEM re-keys); Charlie is cut off
    // and NOT advanced — holding only its stale epoch state.
    let charlie_leaf = charlie.group_leaf_index(GID).unwrap();
    alice.group_remove_member(GID, charlie_leaf, &mut committer).unwrap();
    bob.apply_committed(GID, &committer).unwrap();
    assert_eq!(alice.group_roster(GID).unwrap().len(), 2, "Charlie removed");

    // A post-removal message is read by Bob (it reaches him via the normal broadcast fan-out)...
    let after = b"charlie must never read this";
    let mote = alice.group_send(GID, after).unwrap();
    alice.group_broadcast(GID, after).unwrap();
    bob.poll();
    assert_eq!(bob.poll_group_messages()[0].1.as_ref().unwrap().as_slice(), after);

    // ...but if we hand Charlie the very same new-epoch ciphertext off the mesh, his stale key opens
    // NOTHING (post-compromise security, §5.2) — surfaced as an error, not silent plaintext.
    let injector = net.endpoint(b"injector".to_vec());
    injector
        .send(&charlie_addr, Frame::Group { group_id: GID.to_vec(), body: mote.encode() })
        .unwrap();
    charlie.poll();
    let charlie_msgs = charlie.poll_group_messages();
    assert_eq!(charlie_msgs.len(), 1, "Charlie received the frame off the mesh...");
    assert!(charlie_msgs[0].1.is_err(), "...but cannot decrypt it (PCS)");
}

// --- H-B: the real daemon serve loop drains + delivers group messages ------------------------

/// Before the fix, `Node::poll_group_messages` was called only in tests — never by the daemon serve
/// loop — so group application messages a running node received were buffered forever (dead feature)
/// and an unbounded buffer besides. The loop now drains + delivers them each tick.
#[tokio::test]
async fn daemon_run_loop_delivers_a_received_group_message() {
    use dmtap::daemon::run_loop;
    use std::time::Duration;

    let net = InMemoryNetwork::new();
    let mut committer = Committer::new();
    let (mut alice, _a) = make_node(&net);
    let (mut bob, _b) = make_node(&net);

    // Form a 2-member group: Alice founds, adds Bob, Bob joins from the Welcome.
    let bob_kp = bob.publish_group_keypackage().unwrap();
    alice.found_group(GID).unwrap();
    let add = alice.group_add_member(GID, &bob_kp, &mut committer).unwrap();
    bob.join_group(GID, &add.welcome, &committer).unwrap();

    // Alice broadcasts an application message over the mesh; it lands on Bob's transport.
    let secret = b"delivered by the real daemon loop";
    assert_eq!(alice.group_broadcast(GID, secret).unwrap(), 1, "fanned out to Bob");
    assert_eq!(bob.inbox().exists(), 0, "nothing delivered yet");

    // Run Bob's real serve loop for a few ticks: it must drain the buffered group MOTE and DELIVER it.
    let shutdown = tokio::time::sleep(Duration::from_millis(40));
    let _ = run_loop(&mut bob, Duration::from_millis(5), shutdown).await;

    assert_eq!(bob.inbox().exists(), 1, "the daemon loop drained + delivered the group message");
    let raw = &bob.inbox().messages[0].raw;
    assert!(
        raw.windows(secret.len()).any(|w| w == secret),
        "the decrypted group plaintext was filed to the store"
    );
}

// --- H-B: the group inbox is bounded (a Frame::Group flood cannot OOM the node) --------------

/// A peer streaming `Frame::Group` faster than the node drains must not grow `group_inbox` without
/// bound. Past the cap the frames are dropped (fail-safe backpressure), mirroring the transport inbox.
#[test]
fn group_inbox_is_bounded_under_a_flood() {
    // MAX_GROUP_INBOX (node.rs) — kept in step with the internal cap.
    const CAP: usize = 1024;
    let net = InMemoryNetwork::new();
    let (mut bob, bob_addr) = make_node(&net);
    let flooder = net.endpoint(b"flooder".to_vec());

    let pushed = CAP + 300;
    for _ in 0..pushed {
        flooder
            .send(&bob_addr, Frame::Group { group_id: b"g".to_vec(), body: vec![0xAB] })
            .unwrap();
    }

    bob.poll(); // drains the transport into the (bounded) group_inbox
    let drained = bob.poll_group_messages().len();
    assert!(drained < pushed, "the flood was NOT buffered wholesale ({drained} of {pushed})");
    assert!(drained <= CAP, "group_inbox stayed within its cap: {drained} > {CAP}");
}

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

//! MLS group lifecycle over the **real libp2p mesh** (spec §5, §4.1): a real RFC 9420 group
//! (via `dmtap-mls`/`openmls`) exchanges an application message over a real `dmtap-p2p` swarm, a
//! member is removed, and the removed member cannot read a message created after removal —
//! post-compromise security (§5.2), proven against real socket delivery, not just in-process state.
//!
//! `node/tests/group_e2e.rs` already proves this whole lifecycle (found → add → broadcast →
//! remove → PCS) against the node crate's in-process [`dmtap::transport::InMemoryNetwork`]. What's
//! missing — and what this file adds — is the same lifecycle carried over the actual §4.1 wire
//! (`dmtap-p2p`'s TCP + Noise + Yamux swarm), the same real-transport upgrade `p2p_delivery.rs`
//! makes over `dmtap_to_dmtap.rs`'s 1:1 path. [`dmtap::transport::Frame::Group`] is transport-generic
//! (`dmtap_p2p`'s `WireFrame::Group` carries it over the real wire), so this is a genuine new
//! three-crate composition (`dmtap-mls` + `envoir-node` + `dmtap-p2p`), not a re-run of the
//! in-memory test.

use std::time::{Duration, Instant};

use dmtap::group::GroupError;
use dmtap::groups::Committer;
use dmtap::identity::IdentityKey;
use dmtap::mote::SealKeypair;
use dmtap::node::Node;
use dmtap::transport::{Frame, Transport};

use dmtap_p2p::Libp2pTransport;

/// Generous loopback bound: real dialing + Noise handshake + Yamux, same bound `p2p_delivery.rs`
/// and `full_roundtrip.rs` use.
const SPIN: Duration = Duration::from_secs(15);
const GID: &[u8] = b"mesh-group";

fn tcp_listener(t: &Libp2pTransport) -> libp2p::Multiaddr {
    t.wait_for_listener(SPIN)
        .into_iter()
        .find(|a| a.iter().any(|p| matches!(p, libp2p::multiaddr::Protocol::Tcp(_))))
        .expect("a bound TCP listen addr")
}

/// Poll the real transport until at least one group application message has been buffered and
/// decrypted, or the deadline passes. `poll_group_messages` drains its buffer, so this loop must
/// call it exactly once per iteration rather than in the predicate itself.
fn wait_for_group_message(
    node: &mut Node<Libp2pTransport>,
) -> Vec<(Vec<u8>, Result<Vec<u8>, GroupError>)> {
    let deadline = Instant::now() + SPIN;
    loop {
        node.poll();
        let msgs = node.poll_group_messages();
        if !msgs.is_empty() || Instant::now() >= deadline {
            return msgs;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn real_libp2p_mesh_carries_mls_group_lifecycle_and_removed_member_loses_pcs() {
    let mut committer = Committer::new();

    let alice_ik = IdentityKey::generate();
    let alice_seal = SealKeypair::generate();
    let bob_ik = IdentityKey::generate();
    let bob_ik_pub = bob_ik.public();
    let bob_seal = SealKeypair::generate();

    // Two real libp2p swarms, plus a third ("mallory") used only to model a network observer who
    // later replays an intercepted group ciphertext straight at Bob.
    let alice_tp =
        Libp2pTransport::new(alice_ik.public(), &["/ip4/127.0.0.1/tcp/0".parse().unwrap()])
            .expect("alice swarm starts");
    let bob_tp = Libp2pTransport::new(bob_ik_pub.clone(), &["/ip4/127.0.0.1/tcp/0".parse().unwrap()])
        .expect("bob swarm starts");
    let mallory_tp = Libp2pTransport::new(
        IdentityKey::generate().public(),
        &["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
    )
    .expect("mallory swarm starts");

    let bob_peer_id = bob_tp.peer_id();
    let bob_addr = tcp_listener(&bob_tp);
    alice_tp.add_peer(bob_ik_pub.clone(), bob_peer_id, bob_addr.clone());
    mallory_tp.add_peer(bob_ik_pub.clone(), bob_peer_id, bob_addr);

    let mut alice = Node::with_identity(alice_ik, alice_seal, alice_tp);
    let mut bob = Node::with_identity(bob_ik, bob_seal, bob_tp);

    // Bob pre-publishes a real MLS KeyPackage (§5.3 async join); Alice founds the group and Adds
    // him. The Commit/Welcome handshake travels the ordered committer log (the DS seam, §5.1),
    // never the mesh — only application traffic rides the real libp2p wire.
    let bob_kp = bob.publish_group_keypackage().unwrap();
    alice.found_group(GID).unwrap();
    assert_eq!(alice.group_epoch(GID), Some(0));
    let add = alice.group_add_member(GID, &bob_kp, &mut committer).unwrap();
    bob.join_group(GID, &add.welcome, &committer).unwrap();
    assert_eq!(bob.group_epoch(GID), alice.group_epoch(GID));
    assert_eq!(alice.group_roster(GID).unwrap().len(), 2);

    // Alice encrypts a real MLS application message and fans it out over the real libp2p swarm as
    // `Frame::Group`.
    let secret = b"a real MLS ciphertext over a real socket";
    let sent = alice.group_broadcast(GID, secret).unwrap();
    assert_eq!(sent, 1, "fanned out to Bob over the real transport");

    let bob_msgs = wait_for_group_message(&mut bob);
    assert_eq!(bob_msgs.len(), 1, "the group frame arrived over the real libp2p wire");
    assert_eq!(
        bob_msgs[0].1.as_ref().unwrap().as_slice(),
        secret,
        "Bob decrypts the real MLS application message"
    );

    // Alice removes Bob: a Remove Commit re-keys TreeKEM, advancing Alice past any epoch Bob still
    // holds. Bob is deliberately never told to `apply_committed` — cut off, per the node's own
    // `group_e2e.rs` model of a removed member.
    let bob_leaf = bob.group_leaf_index(GID).unwrap();
    alice.group_remove_member(GID, bob_leaf, &mut committer).unwrap();
    assert_eq!(alice.group_roster(GID).unwrap().len(), 1, "Bob removed");

    // A NEW post-removal application message, encrypted at the new epoch. `group_broadcast` would
    // fan out to zero remaining external members (Alice is now alone), so the ciphertext is built
    // directly and a network observer ("mallory") relays the exact same real-wire frame straight at
    // Bob — the realistic "an eavesdropper captured this packet" case §5.2 exists to defeat.
    let after = b"bob must never read this post-removal";
    let mote = alice.group_send(GID, after).unwrap();
    mallory_tp
        .send(&bob_ik_pub, Frame::Group { group_id: GID.to_vec(), body: mote.encode() })
        .expect("mallory relays the intercepted post-removal frame over the real wire");

    let after_msgs = wait_for_group_message(&mut bob);
    assert_eq!(after_msgs.len(), 1, "Bob receives the frame off the real mesh...");
    assert!(
        after_msgs[0].1.is_err(),
        "...but his stale pre-removal MLS state cannot decrypt it (post-compromise security, §5.2)"
    );
}

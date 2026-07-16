//! Comprehensive local tests for the real libp2p transport (spec §4).
//!
//! These stand up **actual libp2p swarms on `127.0.0.1`** and drive real [`Node`]s over them —
//! not the in-process fabric. The headline test proves a real, HPKE-sealed MOTE crosses a real
//! libp2p swarm (TCP + Noise + Yamux), is decrypted by the receiver, and the delivery `ack`
//! travels back over the same connection until the sender's queue reaches `ACKED`. A second test
//! exercises a Kademlia PUT/GET of a `LocationRecord`-shaped value (§4.2 `key → location`).
//!
//! Scope is honest: this is **loopback** — both peers are directly reachable, so the relay + DCUtR
//! NAT-traversal path (wired and live in the swarm) is not exercised end-to-end here.

use super::*;
use dmtap::identity::IdentityKey;
use dmtap::mote::SealKeypair;
use dmtap::node::Node;
use dmtap::outbound::OutState;

/// A generous loopback timeout: real dialing + Noise handshake + Yamux + request-response take
/// tens of ms, occasionally more under load; poll loops below spin up to this bound.
const SPIN: Duration = Duration::from_secs(15);

/// Take the first TCP listen multiaddr the transport has bound (waits for it to appear).
fn tcp_listener(t: &Libp2pTransport) -> Multiaddr {
    let ls = t.wait_for_listener(SPIN);
    ls.into_iter()
        .find(|a| a.iter().any(|p| matches!(p, libp2p::multiaddr::Protocol::Tcp(_))))
        .expect("a bound TCP listen addr")
}

/// Poll `node` (draining the live swarm inbox) until `pred` holds or `SPIN` elapses.
fn poll_until<T: Transport>(node: &mut Node<T>, mut pred: impl FnMut(&Node<T>) -> bool) -> bool {
    let deadline = std::time::Instant::now() + SPIN;
    loop {
        node.poll();
        if pred(node) {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return pred(node);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn builds_and_listens() {
    let t = Libp2pTransport::new(b"node".to_vec(), &["/ip4/127.0.0.1/tcp/0".parse().unwrap()])
        .unwrap();
    assert!(!t.wait_for_listener(SPIN).is_empty(), "should bind a listen addr");
}

/// THE milestone test: two real libp2p nodes on loopback exchange a real sealed MOTE + ack.
#[test]
fn two_real_libp2p_nodes_exchange_sealed_mote_and_ack() {
    // Real DMTAP identities + sealing keys for both nodes.
    let alice_ik = IdentityKey::generate();
    let alice_seal = SealKeypair::generate();
    let alice_ik_pub = alice_ik.public();
    let alice_seal_pub = *alice_seal.public();

    let bob_ik = IdentityKey::generate();
    let bob_seal = SealKeypair::generate();
    let bob_ik_pub = bob_ik.public();
    let bob_seal_pub = *bob_seal.public();

    // Two real libp2p swarms, each bound to an ephemeral loopback TCP port.
    let alice_tp =
        Libp2pTransport::new(alice_ik_pub.clone(), &["/ip4/127.0.0.1/tcp/0".parse().unwrap()])
            .unwrap();
    let bob_tp =
        Libp2pTransport::new(bob_ik_pub.clone(), &["/ip4/127.0.0.1/tcp/0".parse().unwrap()])
            .unwrap();

    // Alice learns how to reach Bob (his PeerId + a dialable multiaddr) — the §4.2 record stand-in.
    // Bob will AUTO-LEARN Alice from her inbound frame, so the ack routes back with no lookup.
    let bob_addr = tcp_listener(&bob_tp);
    alice_tp.add_peer(bob_ik_pub.clone(), bob_tp.peer_id(), bob_addr);

    let mut alice = Node::with_identity(alice_ik, alice_seal, alice_tp);
    let mut bob = Node::with_identity(bob_ik, bob_seal, bob_tp);
    alice.add_contact(&bob_ik_pub, bob_seal_pub);
    bob.add_contact(&alice_ik_pub, alice_seal_pub);

    // Alice seals + dispatches a real MOTE onto the swarm.
    let secret = b"a real MOTE crossing a real libp2p swarm";
    let id = alice.send_mail(&bob_ik_pub, "hello over libp2p", secret).expect("send");
    assert_eq!(alice.outbound_state(&id), Some(OutState::InFlight), "handed to the swarm");

    // Bob receives it off the wire, runs §2.7 validation, decrypts, stores.
    assert!(
        poll_until(&mut bob, |b| b.inbox().exists() == 1),
        "the sealed MOTE should arrive + decrypt over libp2p"
    );
    let outcomes = bob.poll();
    let _ = outcomes; // dispositions already asserted via inbox growth above.
    let raw = &bob.inbox().messages[0].raw;
    assert!(
        raw.windows(secret.len()).any(|w| w == secret),
        "the decrypted plaintext round-trips over the real swarm"
    );

    // The ack travels back over the same connection until Alice's queue reaches ACKED.
    assert!(
        poll_until(&mut alice, |a| a.outbound_state(&id) == Some(OutState::Acked)),
        "the ack returns over libp2p and the sender queue reaches ACKED"
    );
}

/// Prove the sender-retry contract holds on the real transport: an unresolved peer is `Unreachable`
/// (drives §20.1 `RETRY`), and once its route is learned a re-dispatch reaches `ACKED`.
#[test]
fn unknown_peer_is_unreachable_then_reachable_after_learning_route() {
    let alice_ik = IdentityKey::generate();
    let alice_seal = SealKeypair::generate();
    let alice_ik_pub = alice_ik.public();
    let alice_seal_pub = *alice_seal.public();

    let bob_ik = IdentityKey::generate();
    let bob_seal = SealKeypair::generate();
    let bob_ik_pub = bob_ik.public();
    let bob_seal_pub = *bob_seal.public();

    let alice_tp =
        Libp2pTransport::new(alice_ik_pub.clone(), &["/ip4/127.0.0.1/tcp/0".parse().unwrap()])
            .unwrap();
    let bob_tp =
        Libp2pTransport::new(bob_ik_pub.clone(), &["/ip4/127.0.0.1/tcp/0".parse().unwrap()])
            .unwrap();
    let bob_addr = tcp_listener(&bob_tp);
    let bob_peer = bob_tp.peer_id();

    // Capture a control handle before Alice's transport is moved into her Node, so we can teach her
    // the route at runtime (mid-flight route learning, §4.2/§20.1).
    let alice_route = alice_tp.handle();

    let mut alice = Node::with_identity(alice_ik, alice_seal, alice_tp);
    let mut bob = Node::with_identity(bob_ik, bob_seal, bob_tp);
    alice.add_contact(&bob_ik_pub, bob_seal_pub);
    bob.add_contact(&alice_ik_pub, alice_seal_pub);

    // No route yet ⇒ the transport reports the peer unreachable ⇒ the entry parks in RETRY (§20.1).
    let id = alice.send_mail(&bob_ik_pub, "before route", b"queued while unreachable").unwrap();
    assert_eq!(alice.outbound_state(&id), Some(OutState::Retry), "unreachable ⇒ RETRY");

    // Learn the route and re-fire the retry timer: the same immutable MOTE now reaches ACKED.
    alice_route.add_peer(bob_ik_pub.clone(), bob_peer, bob_addr);
    alice.retry_pending();
    assert!(
        poll_until(&mut bob, |b| b.inbox().exists() == 1),
        "the retried MOTE arrives once the route is known"
    );
    bob.poll();
    assert!(
        poll_until(&mut alice, |a| a.outbound_state(&id) == Some(OutState::Acked)),
        "retry ⇒ delivered ⇒ ACKED over libp2p"
    );
}

/// Kademlia PUT/GET of a signed-`LocationRecord`-shaped value across two connected DHT nodes
/// (§4.2 `key → location`). Node A stores the record under `hash(ik)`; node B resolves it.
#[test]
fn kademlia_put_get_location_record() {
    let a = Libp2pTransport::new(b"kad-a".to_vec(), &["/ip4/127.0.0.1/tcp/0".parse().unwrap()])
        .unwrap();
    let b = Libp2pTransport::new(b"kad-b".to_vec(), &["/ip4/127.0.0.1/tcp/0".parse().unwrap()])
        .unwrap();
    let a_addr = tcp_listener(&a);
    let b_addr = tcp_listener(&b);

    // Introduce the two nodes to each other's routing tables (the DHT is not self-forming on
    // loopback; a fresh contact needs a non-DHT bootstrap path, §4.2).
    a.add_peer(b"kad-b".to_vec(), b.peer_id(), b_addr);
    b.add_peer(b"kad-a".to_vec(), a.peer_id(), a_addr);
    // Give identify/connection a moment so the buckets are populated before the query.
    std::thread::sleep(Duration::from_millis(300));

    // A location record keyed by (a stand-in for) hash(ik).
    let key = b"loc:00112233445566778899aabbccddeeff";
    let record = b"LocationRecord{peer_id,addrs,seq,ttl,sig}";
    assert!(a.kad_put(key, record), "PUT should store on >=1 peer");

    // B resolves the same key from the DHT.
    let got = b.kad_get(key);
    assert_eq!(got.as_deref(), Some(&record[..]), "B resolves the record A published");
}

// --- Test helpers for driving raw transports directly (no `Node`) ----------------------------
//
// The tests above prove the sealed-MOTE path through a `Node`; the tests below drive
// `Libp2pTransport` directly so they can exercise transport-only concerns (relay routing, size
// limits, connection lifecycle) without dragging identity/sealing into the picture.

/// Poll `t.drain()` until it yields something or `SPIN` elapses; returns whatever was drained
/// (possibly empty, on timeout).
fn drain_until_nonempty(t: &Libp2pTransport) -> Vec<InboundFrame> {
    let deadline = std::time::Instant::now() + SPIN;
    loop {
        let msgs = t.drain();
        if !msgs.is_empty() || std::time::Instant::now() >= deadline {
            return msgs;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Re-send `frame` to `to` (retrying every 300ms) until `receiver` drains something or `SPIN`
/// elapses. A single [`Transport::send`] call only makes ONE outbound-request attempt — this
/// crate's connections are ephemeral (no behaviour here asks to keep one alive past its current
/// work, so a connection routinely tears itself down within milliseconds of finishing a round
/// trip, observed empirically while building these tests) and a `send` racing that teardown can
/// hit a one-shot `OutboundFailure` instead of transparently redialing. That is exactly what the
/// real sender-retry machinery (§20.1) exists to paper over above this layer; a raw-transport
/// test reaching for the same redial behaviour needs to supply its own retry loop rather than
/// assume a single `send` is durable.
fn send_until_delivered(
    sender: &Libp2pTransport,
    to: &[u8],
    frame: Frame,
    receiver: &Libp2pTransport,
) -> Vec<InboundFrame> {
    let deadline = std::time::Instant::now() + SPIN;
    loop {
        let _ = sender.send(to, frame.clone());
        std::thread::sleep(Duration::from_millis(300));
        let msgs = receiver.drain();
        if !msgs.is_empty() || std::time::Instant::now() >= deadline {
            return msgs;
        }
    }
}

/// Find this node's listen address that carries the `/p2p-circuit` component (waits for the
/// relay reservation to be confirmed and the listener reported, up to `SPIN`).
fn wait_for_circuit_listener(t: &Libp2pTransport) -> Multiaddr {
    let deadline = std::time::Instant::now() + SPIN;
    loop {
        if let Some(a) = t
            .listeners()
            .into_iter()
            .find(|a| a.iter().any(|p| matches!(p, libp2p::multiaddr::Protocol::P2pCircuit)))
        {
            return a;
        }
        if std::time::Instant::now() >= deadline {
            panic!("no circuit listen addr reported within {SPIN:?}: {:?}", t.listeners());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Poll a boolean-returning connectivity check until it matches `want` or `SPIN` elapses;
/// returns whether it ever matched (NOT the raw last-observed value — a caller doing
/// `assert!(poll_bool(false, check), ..)` needs "did we see `false`?", not "what did we see?").
fn poll_bool(want: bool, mut check: impl FnMut() -> bool) -> bool {
    let deadline = std::time::Instant::now() + SPIN;
    loop {
        if check() == want {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Circuit-Relay-v2 (§4.3 rung 3), for real: a third node acts as a public relay (every
/// [`Libp2pTransport`] runs the relay server role unconditionally, so no special setup beyond
/// [`Libp2pTransport::add_external_address`] — the opt-in that lets it hand out its own address
/// in a reservation ack). `dst` reserves a slot on it and **never advertises a direct address to
/// `src` at all** — `src` learns `dst` only as a circuit multiaddr through the relay, so if the
/// frame arrives, it can only have crossed via the relayed connection.
#[test]
fn relay_v2_reservation_and_relayed_connection_delivers_a_frame() {
    let relay_tp =
        Libp2pTransport::new(b"relay".to_vec(), &["/ip4/127.0.0.1/tcp/0".parse().unwrap()])
            .unwrap();
    let relay_addr = tcp_listener(&relay_tp);
    // Opt this node in to serving as a public relay: without a confirmed external address the
    // relay still *accepts* the reservation at the protocol level, but hands back an empty
    // address list and the reserving client's listener fails closed with `NoAddressesInReservation`
    // (proven empirically while building this test) — the opt-in below is what makes it usable.
    relay_tp.add_external_address(relay_addr.clone());

    // `dst`'s only listen address is a reservation request on the relay — no plain TCP listener
    // of its own, exactly like a node with no directly-reachable address (§4.3's premise).
    let circuit_listen: Multiaddr =
        relay_addr.with(libp2p::multiaddr::Protocol::P2pCircuit);
    let dst_tp = Libp2pTransport::new(b"dst".to_vec(), &[circuit_listen]).unwrap();
    let dst_circuit_addr = wait_for_circuit_listener(&dst_tp);
    assert!(
        dst_circuit_addr.iter().any(|p| matches!(p, libp2p::multiaddr::Protocol::P2pCircuit)),
        "the confirmed reservation address should still carry /p2p-circuit"
    );

    let src_tp =
        Libp2pTransport::new(b"src".to_vec(), &["/ip4/127.0.0.1/tcp/0".parse().unwrap()])
            .unwrap();
    // The ONLY route `src` ever learns to `dst` is the relayed one.
    src_tp.add_peer(b"dst".to_vec(), dst_tp.peer_id(), dst_circuit_addr);

    src_tp.send(b"dst", Frame::Mote(b"hi via relay".to_vec())).expect("known route ⇒ Ok");

    let msgs = drain_until_nonempty(&dst_tp);
    assert_eq!(
        msgs.first().map(|(_, f)| f.clone()),
        Some(Frame::Mote(b"hi via relay".to_vec())),
        "the frame should cross the Circuit-Relay-v2 hop and reach dst"
    );
}

/// DCUtR (§4.3 rung 2) is wired into every swarm's behaviour and, empirically, a hole-punch
/// attempt *does* fire automatically once a relayed connection is up and identify has exchanged
/// observed addresses (confirmed while building [`relay_v2_reservation_and_relayed_connection_delivers_a_frame`]:
/// the background swarm logs `Dialing` + `OutgoingConnectionError` for the peer right after the
/// relayed circuit is established). It doesn't reliably *succeed* on loopback, and that's
/// structural, not a bug to chase here: DCUtR's whole premise is two peers behind *different*
/// NATs guessing each other's externally-mapped port from observed addresses and dialing
/// simultaneously; on loopback there is no NAT mapping to guess, both peers already listening on
/// their own real ports on the SAME address, so the guessed target is simply the wrong (or a
/// since-closed) port and the direct dial fails closed — which is what was observed
/// (`ConnectionRefused` / stream-select failure), harmlessly, after the relayed delivery had
/// already succeeded. Exercising a genuine hole-punch *upgrade* needs two distinct NAT'd
/// endpoints (real infra: two hosts behind separate NATs, or a NAT simulator), not loopback.
#[test]
#[ignore = "DCUtR hole-punch upgrade needs two peers behind distinct NATs; on loopback the \
            punch reliably attempts (observed empirically) but cannot meaningfully succeed \
            since there is no NAT mapping to traverse — needs real multi-host/NAT-sim infra"]
fn dcutr_hole_punch_upgrade_needs_real_nat_infra() {
    unreachable!("intentionally not run — see the #[ignore] reason");
}

/// A payload comfortably inside [`MAX_REQUEST_SIZE`] but well past the cbor codec's *default*
/// 1 MiB cap (§16.4 "Normal" file tier is inline up to 4 MiB) round-trips whole, proving the
/// explicit size-limit bump isn't just configured but actually exercised, and that yamux's flow
/// control doesn't stall/truncate a multi-megabyte single frame.
#[test]
fn large_frame_within_configured_limit_round_trips_intact() {
    let a =
        Libp2pTransport::new(b"a".to_vec(), &["/ip4/127.0.0.1/tcp/0".parse().unwrap()]).unwrap();
    let b =
        Libp2pTransport::new(b"b".to_vec(), &["/ip4/127.0.0.1/tcp/0".parse().unwrap()]).unwrap();
    let b_addr = tcp_listener(&b);
    a.add_peer(b"b".to_vec(), b.peer_id(), b_addr);

    // 6 MiB: past the codec default (1 MiB) and past the "Normal" tier's 4 MiB inline ceiling,
    // still under this crate's 8 MiB `MAX_REQUEST_SIZE`.
    let big: Vec<u8> = (0..6 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    a.send(b"b", Frame::Mote(big.clone())).expect("known route ⇒ Ok");

    let msgs = drain_until_nonempty(&b);
    match msgs.into_iter().next() {
        Some((_, Frame::Mote(got))) => {
            assert_eq!(got.len(), big.len(), "no truncation across the wire");
            assert_eq!(got, big, "bytes round-trip exactly, not just the length");
        }
        other => panic!("expected a Mote frame, got {other:?}"),
    }
}

/// Hardening: a frame bigger than [`MAX_REQUEST_SIZE`] is exactly what a malformed/hostile peer
/// looks like from the wire's perspective (the codec reads only up to the cap, then fails to
/// decode the truncated remainder — see `crate::MAX_REQUEST_SIZE`'s doc comment). Proves it fails
/// **closed** — never silently delivered, not even truncated — and that the swarm task does not
/// panic and keeps working afterward (a panicked background task would hang/abort the rest of
/// this test, not just this one send).
///
/// This does NOT additionally assert that b disconnects a, even though this crate wires exactly
/// that reaction (see [`handle_event`]'s `InboundFailure::Io` arm) — an upstream gap in
/// `libp2p-request-response` 0.29.0 means that reaction is not reachable from *this specific*
/// failure mode. Traced empirically while building this test: `Handler::on_fully_negotiated_inbound`
/// (`libp2p-request-response-0.29.0/src/handler.rs`) does `let request = read.await?;` *before*
/// ever notifying the `Behaviour` of the inbound request; when `codec.read_request` itself fails
/// (exactly the truncated-oversized-frame case), that early `?` return means the `Behaviour` was
/// never told a request existed, so `remove_pending_inbound_response` finds nothing to remove and
/// the crate falls into `tracing::debug!("Inbound failure is reported for an unknown
/// request_id...")` instead of emitting a public `InboundFailure` — the event this crate's
/// disconnect hook needs never arrives. The disconnect *primitive* is still proven for real (see
/// [`connection_close_and_redial_resilience`], which drives it directly), and the hook itself
/// compiles against the real `InboundFailure` enum and will start firing the day upstream closes
/// this gap — it is dead code only for this one trigger, not unreachable in general (a stream
/// that fails for `Timeout`/other `Io` reasons after the `Behaviour` already knows about it is
/// unaffected).
#[test]
fn oversized_inbound_frame_fails_closed_without_panicking() {
    let a =
        Libp2pTransport::new(b"a".to_vec(), &["/ip4/127.0.0.1/tcp/0".parse().unwrap()]).unwrap();
    let b =
        Libp2pTransport::new(b"b".to_vec(), &["/ip4/127.0.0.1/tcp/0".parse().unwrap()]).unwrap();
    let b_addr = tcp_listener(&b);
    let b_peer = b.peer_id();
    a.add_peer(b"b".to_vec(), b_peer, b_addr);

    // Establish a real, stable connection first (a small, legitimate frame) — verified
    // empirically to stay up indefinitely with no further activity (a fresh connection is not
    // torn down out from under a slow write; only an explicit disconnect-then-immediately-redial
    // cycle was ever observed to race), so the oversized frame below reuses THIS connection
    // instead of forcing a fresh one.
    a.send(b"b", Frame::Mote(b"hello".to_vec())).unwrap();
    assert!(!drain_until_nonempty(&b).is_empty(), "the warm-up frame should arrive normally");
    assert!(poll_bool(true, || a.is_connected(b_peer)), "a should be connected to b by now");

    // Oversized: past MAX_REQUEST_SIZE (8 MiB), so b's codec truncates the read and fails to
    // decode. The stream carrying it fails (observed as an `OutboundFailure::Io` on a's side —
    // yamux tearing down the one broken stream, not the whole connection); either way `send`
    // itself never errors synchronously, since handing off to the swarm always succeeds.
    let oversized: Vec<u8> = vec![0u8; 9 * 1024 * 1024];
    a.send(b"b", Frame::Mote(oversized)).expect("send hands off to the swarm regardless of size");

    // It must never show up in b's inbox (fail closed, not "deliver truncated").
    std::thread::sleep(Duration::from_millis(1500));
    assert!(b.drain().is_empty(), "an oversized frame must never be delivered, not even truncated");

    // The swarm task is alive and well: a normal frame afterward still gets through (retrying the
    // send, per `send_until_delivered`, in case the failed stream left anything to settle).
    // Proves no panic took the background task down.
    let msgs = send_until_delivered(&a, b"b", Frame::Mote(b"still works".to_vec()), &b);
    assert_eq!(
        msgs.into_iter().next().map(|(_, f)| f),
        Some(Frame::Mote(b"still works".to_vec())),
        "the transport recovers and keeps delivering after the hostile frame"
    );
}

/// Resilience: a connection dropping (a network blip, an idle timeout, an operator-initiated
/// reset — anything short of the peer being untrusted) must not strand the route. Force-close
/// the connection with [`Libp2pTransport::disconnect_peer`] (the same primitive the hardening
/// above uses defensively) and prove a subsequent send still re-dials and delivers using the
/// route already on file — no fresh `add_peer` call, no restart.
#[test]
fn connection_close_and_redial_resilience() {
    let a =
        Libp2pTransport::new(b"a".to_vec(), &["/ip4/127.0.0.1/tcp/0".parse().unwrap()]).unwrap();
    let b =
        Libp2pTransport::new(b"b".to_vec(), &["/ip4/127.0.0.1/tcp/0".parse().unwrap()]).unwrap();
    let b_addr = tcp_listener(&b);
    let b_peer = b.peer_id();
    let a_peer = a.peer_id();
    a.add_peer(b"b".to_vec(), b_peer, b_addr);

    a.send(b"b", Frame::Mote(b"before the blip".to_vec())).unwrap();
    assert_eq!(
        drain_until_nonempty(&b).into_iter().next().map(|(_, f)| f),
        Some(Frame::Mote(b"before the blip".to_vec()))
    );
    assert!(poll_bool(true, || a.is_connected(b_peer)), "connected after the first exchange");

    // Simulate the blip from b's side (as if b's process restarted the socket, or an idle reap
    // fired) — a's peer-book entry for b is untouched.
    b.disconnect_peer(a_peer);
    assert!(poll_bool(false, || a.is_connected(b_peer)), "the connection should actually drop");

    // No new `add_peer`: the same on-file route re-dials on demand. Retried (see
    // `send_until_delivered`'s doc comment) because a single `send` racing the tail end of the
    // just-closed connection's teardown can itself hit a one-shot dial hiccup — the sender-retry
    // machinery (§20.1) is what absorbs that in the real system; this loop stands in for it here.
    let msgs = send_until_delivered(&a, b"b", Frame::Mote(b"after the blip".to_vec()), &b);
    assert_eq!(
        msgs.into_iter().next().map(|(_, f)| f),
        Some(Frame::Mote(b"after the blip".to_vec())),
        "a re-dials b and delivery resumes without re-learning the route"
    );
}

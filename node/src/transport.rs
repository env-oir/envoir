//! Transport — spec §4.
//!
//! The delivery engine ([`crate::node::Node`]) does not care *how* a MOTE reaches a peer: the
//! real protocol offers a mixnet (`private` tier, §4.4) and a direct/relay reachability ladder
//! (`fast` tier, §4.3, §20.4). All of that is abstracted behind the [`Transport`] trait: a node
//! hands sealed [`Frame`]s to a peer address and drains inbound frames addressed to itself.
//!
//! Building a real libp2p transport (Kademlia/Relay/DCUtR/QUIC — the `Cargo.toml` stack) is a
//! separate frontier task. This module ships the trait plus an **in-process** implementation
//! ([`InMemoryNetwork`]) so two `Node`s can exchange real end-to-end-encrypted MOTEs over
//! channels, exercising the full seal → validate → ack path without any sockets.
//!
//! ## Simplifications vs. the real transport (documented, not hidden)
//! - **Addressing.** A peer's transport address here is simply its identity-key bytes. The real
//!   mesh routes via per-epoch `peer_id`s discovered through signed `LocationRecord`s (§4.2);
//!   the engine never assumes the address *is* the identity key beyond this in-process stand-in.
//! - **Sealed sender.** [`Frame`] carries a `from` return path so an `ack` can travel "back over
//!   the same channel the Envelope arrived on" (§19.3.2). Over a real mixnet that return path is
//!   a single-use reply block, and `from` is *not* the sender's identity in the clear (§6.2). The
//!   in-process transport exposes it directly; the engine treats it only as an opaque reply path
//!   and as the cheap pre-decryption sender hint (§2.7 step 5), never as authenticated identity —
//!   identity is proven only by `Payload.sig` after decryption (§2.7 step 8).

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};

/// A unit handed to the transport: either a sealed MOTE envelope or a delivery acknowledgement.
///
/// `ack` is deliberately *not* a distinct wire object beyond the acknowledged `id` (§19.3.2): it
/// "is routed like any other small MOTE-adjacent message". Modeling it as a frame variant keeps
/// the transport a single send/recv channel while preserving that distinction for the engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// A sealed [`Envelope`](dmtap_core::mote::Envelope) in its canonical §18 CBOR wire form.
    Mote(Vec<u8>),
    /// An `ack(id)` (§19.3.2): the content address being acknowledged.
    Ack(Vec<u8>),
}

/// Why a [`Transport::send`] attempt failed. Distinct from delivery failure — this is the
/// transport rung reporting it could not hand the frame off, which drives the sender-retry
/// machine's `tier_unreachable` event (§20.1, §19.2.3 `PEER_UNREACHABLE`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// No route to the peer (offline, unknown address, all reachability rungs failed).
    Unreachable,
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::Unreachable => f.write_str("peer unreachable"),
        }
    }
}
impl std::error::Error for TransportError {}

/// Move MOTE/ack frames to and from peers (spec §4). The engine is generic over this trait so the
/// in-process transport used in tests can be swapped for a real mixnet/libp2p transport later.
pub trait Transport {
    /// This node's own transport address (what peers pass as `to` to reach us).
    fn local_addr(&self) -> Vec<u8>;

    /// Hand `frame` to the peer at address `to`. `Err(Unreachable)` means the transport could not
    /// deliver it *right now* (the caller's retry loop, §20.1, decides what happens next).
    fn send(&self, to: &[u8], frame: Frame) -> Result<(), TransportError>;

    /// Drain every frame currently addressed to this node, each tagged with its sender's return
    /// path (`from`). Non-blocking: returns whatever has arrived, possibly nothing.
    fn drain(&self) -> Vec<(Vec<u8>, Frame)>;
}

// --- In-process implementation -------------------------------------------------------------

#[derive(Default)]
struct NetInner {
    /// Per-peer inbound queues: `addr → [(from, frame)]`.
    queues: HashMap<Vec<u8>, VecDeque<(Vec<u8>, Frame)>>,
    /// Peers currently simulated as offline; `send` to them fails `Unreachable`.
    down: HashSet<Vec<u8>>,
}

/// A shared in-process network fabric. Clone it to hand each node a [`InMemoryTransport`]; all
/// clones route through the same fabric. Cheap to clone (an `Arc`).
#[derive(Clone, Default)]
pub struct InMemoryNetwork {
    inner: Arc<Mutex<NetInner>>,
}

impl InMemoryNetwork {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `addr` on the fabric and return a transport bound to it.
    pub fn endpoint(&self, addr: impl Into<Vec<u8>>) -> InMemoryTransport {
        let addr = addr.into();
        self.inner.lock().unwrap().queues.entry(addr.clone()).or_default();
        InMemoryTransport { addr, net: self.clone() }
    }

    /// Simulate a peer going offline: subsequent `send`s to it fail `Unreachable`.
    pub fn set_down(&self, addr: &[u8], down: bool) {
        let mut g = self.inner.lock().unwrap();
        if down {
            g.down.insert(addr.to_vec());
        } else {
            g.down.remove(addr);
        }
    }

    /// Total frames buffered across all peers (test/inspection aid).
    pub fn in_flight(&self) -> usize {
        self.inner.lock().unwrap().queues.values().map(|q| q.len()).sum()
    }
}

/// A single node's handle onto an [`InMemoryNetwork`].
pub struct InMemoryTransport {
    addr: Vec<u8>,
    net: InMemoryNetwork,
}

impl Transport for InMemoryTransport {
    fn local_addr(&self) -> Vec<u8> {
        self.addr.clone()
    }

    fn send(&self, to: &[u8], frame: Frame) -> Result<(), TransportError> {
        let mut g = self.net.inner.lock().unwrap();
        // A peer is unreachable if it was never registered or is simulated down.
        if g.down.contains(to) || !g.queues.contains_key(to) {
            return Err(TransportError::Unreachable);
        }
        g.queues.get_mut(to).unwrap().push_back((self.addr.clone(), frame));
        Ok(())
    }

    fn drain(&self) -> Vec<(Vec<u8>, Frame)> {
        let mut g = self.net.inner.lock().unwrap();
        match g.queues.get_mut(&self.addr) {
            Some(q) => q.drain(..).collect(),
            None => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_route_between_endpoints() {
        let net = InMemoryNetwork::new();
        let a = net.endpoint(b"alice".to_vec());
        let b = net.endpoint(b"bob".to_vec());

        a.send(b"bob", Frame::Mote(vec![1, 2, 3])).unwrap();
        assert_eq!(net.in_flight(), 1);
        // Alice has nothing inbound; Bob has one frame tagged with alice's return path.
        assert!(a.drain().is_empty());
        let got = b.drain();
        assert_eq!(got, vec![(b"alice".to_vec(), Frame::Mote(vec![1, 2, 3]))]);
        // Drained; the fabric is empty again.
        assert_eq!(net.in_flight(), 0);
    }

    #[test]
    fn unknown_or_down_peer_is_unreachable() {
        let net = InMemoryNetwork::new();
        let a = net.endpoint(b"alice".to_vec());
        // Never-registered peer.
        assert_eq!(a.send(b"ghost", Frame::Ack(vec![9])), Err(TransportError::Unreachable));
        // Registered but downed peer.
        let _b = net.endpoint(b"bob".to_vec());
        net.set_down(b"bob", true);
        assert_eq!(a.send(b"bob", Frame::Ack(vec![9])), Err(TransportError::Unreachable));
        net.set_down(b"bob", false);
        assert!(a.send(b"bob", Frame::Ack(vec![9])).is_ok());
    }
}

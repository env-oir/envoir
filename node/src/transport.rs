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
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

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
    /// A **group** MOTE (spec §5): an MLS application message for a group session. `group_id`
    /// names the group; `body` is the encoded [`GroupMote`](crate::group::GroupMote) carrying the
    /// MLS ciphertext. Group **application** messages travel the mesh like any MOTE (§5.1);
    /// group **handshakes** do NOT — they go over the ordered committer log (the DS), never here.
    Group { group_id: Vec<u8>, body: Vec<u8> },
}

/// An inbound frame paired with its sender's return path (`from`), as yielded by
/// [`Transport::drain`]. Named to keep the transport queue/type signatures legible.
pub type InboundFrame = (Vec<u8>, Frame);

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

/// A boxed transport is itself a [`Transport`], so the engine can be made **transport-agnostic at
/// runtime** — `Node<Box<dyn Transport>>` — and the concrete transport chosen dynamically rather
/// than monomorphized. This is the seam through which the out-of-tree **libp2p mesh transport**
/// ([`dmtap_p2p::Libp2pTransport`], spec §4) is selected: that crate depends on THIS one and
/// implements this very trait, so `Box::new(Libp2pTransport::new(..)?) as Box<dyn Transport>` drops
/// straight into a `Node` with no cyclic dependency and no change to the engine.
///
/// [`dmtap_p2p::Libp2pTransport`]: https://docs.rs/dmtap-p2p (the separate mesh-transport crate)
impl Transport for Box<dyn Transport> {
    fn local_addr(&self) -> Vec<u8> {
        (**self).local_addr()
    }
    fn send(&self, to: &[u8], frame: Frame) -> Result<(), TransportError> {
        (**self).send(to, frame)
    }
    fn drain(&self) -> Vec<(Vec<u8>, Frame)> {
        (**self).drain()
    }
}

/// A runtime-**selectable** transport: pick the in-tree in-process fabric or the loopback-TCP
/// transport (or, via [`SelectableTransport::Boxed`], *any* [`Transport`] impl — the real
/// `dmtap_p2p::Libp2pTransport` mesh, §4) behind one concrete type, so a caller can choose the
/// delivery substrate at run time without the engine being generic over each one. Every variant
/// simply forwards the [`Transport`] method to the selected leg.
///
/// This is what makes the mesh transport *selectable from the node* even though the node cannot
/// depend on `dmtap-p2p` (that would be a cycle): the boxed variant accepts the p2p transport
/// through the trait object, keeping the existing in-memory/TCP transports fully working.
pub enum SelectableTransport {
    /// The deterministic in-process fabric ([`InMemoryTransport`]) — fast, socket-free tests.
    InMemory(InMemoryTransport),
    /// The loopback/real-socket [`TcpTransport`] — two OS processes over TCP.
    Tcp(TcpTransport),
    /// Any other [`Transport`] behind a trait object — notably the out-of-tree libp2p mesh
    /// transport (spec §4). The escape hatch that keeps the mesh selectable without a dependency
    /// cycle.
    Boxed(Box<dyn Transport>),
}

impl Transport for SelectableTransport {
    fn local_addr(&self) -> Vec<u8> {
        match self {
            SelectableTransport::InMemory(t) => t.local_addr(),
            SelectableTransport::Tcp(t) => t.local_addr(),
            SelectableTransport::Boxed(t) => t.local_addr(),
        }
    }
    fn send(&self, to: &[u8], frame: Frame) -> Result<(), TransportError> {
        match self {
            SelectableTransport::InMemory(t) => t.send(to, frame),
            SelectableTransport::Tcp(t) => t.send(to, frame),
            SelectableTransport::Boxed(t) => t.send(to, frame),
        }
    }
    fn drain(&self) -> Vec<(Vec<u8>, Frame)> {
        match self {
            SelectableTransport::InMemory(t) => t.drain(),
            SelectableTransport::Tcp(t) => t.drain(),
            SelectableTransport::Boxed(t) => t.drain(),
        }
    }
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
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).queues.entry(addr.clone()).or_default();
        InMemoryTransport { addr, net: self.clone() }
    }

    /// Simulate a peer going offline: subsequent `send`s to it fail `Unreachable`.
    pub fn set_down(&self, addr: &[u8], down: bool) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if down {
            g.down.insert(addr.to_vec());
        } else {
            g.down.remove(addr);
        }
    }

    /// Total frames buffered across all peers (test/inspection aid).
    pub fn in_flight(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).queues.values().map(|q| q.len()).sum()
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
        let mut g = self.net.inner.lock().unwrap_or_else(|e| e.into_inner());
        // A peer is unreachable if it was never registered or is simulated down.
        if g.down.contains(to) || !g.queues.contains_key(to) {
            return Err(TransportError::Unreachable);
        }
        g.queues.get_mut(to).unwrap().push_back((self.addr.clone(), frame));
        Ok(())
    }

    fn drain(&self) -> Vec<(Vec<u8>, Frame)> {
        let mut g = self.net.inner.lock().unwrap_or_else(|e| e.into_inner());
        match g.queues.get_mut(&self.addr) {
            Some(q) => q.drain(..).collect(),
            None => Vec::new(),
        }
    }
}

// --- TCP/loopback implementation -----------------------------------------------------------
//
// A concrete [`Transport`] over real sockets (std `TcpStream`/`TcpListener`), so two nodes in
// **separate OS processes** can exchange a MOTE over `127.0.0.1` (or any TCP address). It keeps the
// same trait shape as [`InMemoryTransport`]; the in-memory one stays for fast, deterministic tests.
//
// ## Wire format (length-prefixed frames)
// Each send opens a connection, writes exactly one framed message, and closes it. A message is:
//
// ```text
//   u32be from_len ‖ from_bytes ‖ u8 tag ‖ u32be payload_len ‖ payload_bytes
// ```
//
// `from` is the sender's logical DMTAP address (its identity bytes) so the receiver has a return
// path for the `ack` (§19.3.2) — exactly the role [`Frame`]'s `from` plays for the in-memory
// fabric. `tag` is `0` for a MOTE, `1` for an ack. Both lengths are bounded by [`MAX_FRAME`] so a
// malformed/hostile peer cannot make the reader allocate unboundedly.
//
// ## Simplifications vs. a production mesh transport (documented, not hidden)
// - **Addressing** is a static peer book (`add_peer`: DMTAP address → `SocketAddr`), a stand-in for
//   the real mesh's signed `LocationRecord` discovery (§4.2). A real transport also pools
//   connections rather than dialing per send; connect-per-send is simplest and correct for a
//   reference/loopback transport.
// - **No TLS.** A real reachability-ladder leg terminates TLS (§8.2/§4.3); this raw loopback
//   transport carries the already-end-to-end-sealed MOTE in the clear over the socket. The MOTE
//   payload is HPKE-sealed regardless, so the socket sees only ciphertext either way.

/// Frame tag for a MOTE envelope on the TCP wire.
const TCP_TAG_MOTE: u8 = 0;
/// Frame tag for an ack on the TCP wire.
const TCP_TAG_ACK: u8 = 1;
/// Frame tag for a group MOTE on the TCP wire (spec §5). Its payload is `u32be group_id_len ‖
/// group_id ‖ body`, so the single length-prefixed payload slot carries both fields.
const TCP_TAG_GROUP: u8 = 2;
/// Upper bound on any single length-prefixed field (16 MiB) — guards the reader's allocation.
const MAX_FRAME: u32 = 16 * 1024 * 1024;
/// How long a `send` waits to establish a connection before reporting the peer unreachable.
const CONNECT_TIMEOUT: Duration = Duration::from_millis(500);
/// Read timeout on an accepted connection, so a stalled peer cannot wedge the accept loop.
const READ_TIMEOUT: Duration = Duration::from_millis(500);
/// Upper bound on the depth of the inbound frame backlog awaiting [`drain`](Transport::drain). The
/// inbox is emptied only on poll, so without a cap a peer streaming frames faster than the engine
/// drains them grows it without bound — each frame is [`MAX_FRAME`]-bounded but the *aggregate* is
/// not, an out-of-memory vector. At the cap the accept loop refuses further frames on that
/// connection (fail-safe backpressure: the peer's socket writes block/reset), so the backlog can
/// never exceed `MAX_INBOX_FRAMES`.
const MAX_INBOX_FRAMES: usize = 1024;

fn invalid(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg.to_string())
}

fn read_u32(stream: &mut TcpStream) -> std::io::Result<u32> {
    let mut b = [0u8; 4];
    stream.read_exact(&mut b)?;
    Ok(u32::from_be_bytes(b))
}

/// Write one framed `(from, frame)` message. Flushes so the whole message is on the wire before the
/// connection is dropped by the caller.
fn write_tcp_frame(stream: &mut TcpStream, from: &[u8], frame: &Frame) -> std::io::Result<()> {
    // A group frame packs `group_id_len ‖ group_id ‖ body` into the single payload slot; the
    // owned buffer must outlive the borrow below, so build it before matching.
    let group_packed: Vec<u8>;
    let (tag, payload): (u8, &[u8]) = match frame {
        Frame::Mote(b) => (TCP_TAG_MOTE, b),
        Frame::Ack(b) => (TCP_TAG_ACK, b),
        Frame::Group { group_id, body } => {
            let mut p = Vec::with_capacity(4 + group_id.len() + body.len());
            p.extend_from_slice(&(group_id.len() as u32).to_be_bytes());
            p.extend_from_slice(group_id);
            p.extend_from_slice(body);
            group_packed = p;
            (TCP_TAG_GROUP, &group_packed)
        }
    };
    stream.write_all(&(from.len() as u32).to_be_bytes())?;
    stream.write_all(from)?;
    stream.write_all(&[tag])?;
    stream.write_all(&(payload.len() as u32).to_be_bytes())?;
    stream.write_all(payload)?;
    stream.flush()
}

/// Read one framed `(from, frame)` message, failing closed on an over-long field or unknown tag.
fn read_tcp_frame(stream: &mut TcpStream) -> std::io::Result<(Vec<u8>, Frame)> {
    let from_len = read_u32(stream)?;
    if from_len > MAX_FRAME {
        return Err(invalid("from field too large"));
    }
    let mut from = vec![0u8; from_len as usize];
    stream.read_exact(&mut from)?;

    let mut tag = [0u8; 1];
    stream.read_exact(&mut tag)?;

    let payload_len = read_u32(stream)?;
    if payload_len > MAX_FRAME {
        return Err(invalid("payload field too large"));
    }
    let mut payload = vec![0u8; payload_len as usize];
    stream.read_exact(&mut payload)?;

    let frame = match tag[0] {
        TCP_TAG_MOTE => Frame::Mote(payload),
        TCP_TAG_ACK => Frame::Ack(payload),
        TCP_TAG_GROUP => {
            // Unpack `group_id_len ‖ group_id ‖ body` from the payload slot, failing closed on a
            // length that overruns the buffer (a malformed/hostile peer).
            if payload.len() < 4 {
                return Err(invalid("group frame too short"));
            }
            let gid_len = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
            if payload.len() < 4 + gid_len {
                return Err(invalid("group_id length overruns frame"));
            }
            let group_id = payload[4..4 + gid_len].to_vec();
            let body = payload[4 + gid_len..].to_vec();
            Frame::Group { group_id, body }
        }
        _ => return Err(invalid("unknown frame tag")),
    };
    Ok((from, frame))
}

/// The accept loop run on a background thread: pull framed messages off inbound connections into the
/// shared inbox until `shutdown` is set. Uses a non-blocking listener polled on a short interval so
/// the thread exits promptly on drop (no dangling accept).
fn tcp_accept_loop(
    listener: TcpListener,
    inbox: Arc<Mutex<VecDeque<InboundFrame>>>,
    shutdown: Arc<AtomicBool>,
) {
    loop {
        if shutdown.load(Ordering::SeqCst) {
            return;
        }
        match listener.accept() {
            Ok((mut stream, _peer)) => {
                // The accepted stream may inherit the listener's non-blocking flag on some
                // platforms — force blocking + a read timeout so `read_exact` behaves.
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
                // A connection carries one message (connect-per-send); read until EOF/timeout.
                // On a clean EOF, timeout, or malformed frame we are simply done with this conn.
                while let Ok(msg) = read_tcp_frame(&mut stream) {
                    let mut q = inbox.lock().unwrap_or_else(|e| e.into_inner());
                    if q.len() >= MAX_INBOX_FRAMES {
                        // Backlog full: refuse further frames and stop reading this connection so
                        // the inbox cannot grow past the cap (memory-exhaustion backpressure). The
                        // conn drops as the loop iterates; the peer's next write blocks/resets.
                        break;
                    }
                    q.push_back(msg);
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(_) => return, // listener broke; stop the thread.
        }
    }
}

/// A [`Transport`] over real TCP sockets. Its listener runs on a background thread that fills an
/// inbox drained by [`drain`](Transport::drain); [`send`](Transport::send) dials the peer's
/// registered socket and writes one framed message. Drops cleanly (signals + joins the listener).
pub struct TcpTransport {
    /// This node's logical DMTAP address (identity bytes) — the `from` return path it stamps on
    /// every frame and the address peers look up in their own peer book.
    local_addr: Vec<u8>,
    /// Where this node's listener is bound (tell peers to `add_peer(local_addr, this)`).
    socket_addr: SocketAddr,
    /// Peer book: logical DMTAP address → TCP socket to dial. A stand-in for §4.2 mesh discovery.
    peers: Arc<Mutex<HashMap<Vec<u8>, SocketAddr>>>,
    /// Frames received by the listener thread, awaiting [`drain`](Transport::drain).
    inbox: Arc<Mutex<VecDeque<InboundFrame>>>,
    /// Set on drop to stop the accept loop.
    shutdown: Arc<AtomicBool>,
    /// The listener thread handle, joined on drop.
    listener: Option<JoinHandle<()>>,
}

impl TcpTransport {
    /// Bind a listener at `bind_to` (e.g. `"127.0.0.1:0"` for an ephemeral port) and start serving.
    /// `local_addr` is this node's logical DMTAP address (typically its identity public bytes).
    pub fn bind(local_addr: impl Into<Vec<u8>>, bind_to: &str) -> std::io::Result<Self> {
        let listener = TcpListener::bind(bind_to)?;
        let socket_addr = listener.local_addr()?;
        listener.set_nonblocking(true)?;

        let inbox: Arc<Mutex<VecDeque<InboundFrame>>> = Arc::new(Mutex::new(VecDeque::new()));
        let shutdown = Arc::new(AtomicBool::new(false));
        let handle = {
            let inbox = inbox.clone();
            let shutdown = shutdown.clone();
            std::thread::spawn(move || tcp_accept_loop(listener, inbox, shutdown))
        };

        Ok(TcpTransport {
            local_addr: local_addr.into(),
            socket_addr,
            peers: Arc::new(Mutex::new(HashMap::new())),
            inbox,
            shutdown,
            listener: Some(handle),
        })
    }

    /// The socket this node's listener is bound to — hand it to peers so they can reach this node.
    pub fn local_socket_addr(&self) -> SocketAddr {
        self.socket_addr
    }

    /// Register how to reach a peer: its logical DMTAP `addr` maps to a TCP `socket` to dial
    /// (a stand-in for signed `LocationRecord` discovery, §4.2).
    pub fn add_peer(&self, addr: impl Into<Vec<u8>>, socket: SocketAddr) {
        self.peers.lock().unwrap_or_else(|e| e.into_inner()).insert(addr.into(), socket);
    }
}

impl Drop for TcpTransport {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = self.listener.take() {
            let _ = handle.join();
        }
    }
}

impl Transport for TcpTransport {
    fn local_addr(&self) -> Vec<u8> {
        self.local_addr.clone()
    }

    fn send(&self, to: &[u8], frame: Frame) -> Result<(), TransportError> {
        // Resolve the peer's socket from the book; an unknown peer is unreachable (§20.1).
        let socket = self
            .peers
            .lock()
            .unwrap()
            .get(to)
            .copied()
            .ok_or(TransportError::Unreachable)?;
        // Dial + write one framed message; any I/O failure is `Unreachable` (drives sender retry).
        let mut stream = TcpStream::connect_timeout(&socket, CONNECT_TIMEOUT)
            .map_err(|_| TransportError::Unreachable)?;
        write_tcp_frame(&mut stream, &self.local_addr, &frame)
            .map_err(|_| TransportError::Unreachable)?;
        Ok(())
    }

    fn drain(&self) -> Vec<(Vec<u8>, Frame)> {
        self.inbox.lock().unwrap_or_else(|e| e.into_inner()).drain(..).collect()
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
    fn poisoned_fabric_mutex_is_recovered_not_wedged() {
        // A thread that panics while holding the fabric lock POISONS the mutex. With `.lock().unwrap()`
        // every subsequent send/drain would panic — one panic anywhere silently wedges the whole
        // transport (accept loop + all sends). With poison recovery the fabric keeps working.
        let net = InMemoryNetwork::new();
        let a = net.endpoint(b"alice".to_vec());
        let b = net.endpoint(b"bob".to_vec());

        let net2 = net.clone();
        let poisoned = std::thread::spawn(move || {
            let _g = net2.inner.lock().unwrap_or_else(|e| e.into_inner());
            panic!("holder panics while holding the lock → poisons the mutex");
        })
        .join();
        assert!(poisoned.is_err(), "the holder thread panicked (poisoning the mutex)");

        // Despite the poisoned mutex, the transport is not wedged: send + drain still succeed.
        a.send(b"bob", Frame::Mote(vec![1, 2, 3])).expect("send survives a poisoned lock");
        let got = b.drain();
        assert_eq!(got, vec![(b"alice".to_vec(), Frame::Mote(vec![1, 2, 3]))]);
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

    // --- TCP/loopback transport ------------------------------------------------------------

    /// Spin-wait up to ~2 s for `pred` to hold, draining nothing itself — used to bridge the async
    /// gap between a `send` returning and the listener thread enqueuing the frame.
    fn wait_until(mut pred: impl FnMut() -> bool) -> bool {
        for _ in 0..1000 {
            if pred() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        pred()
    }

    #[test]
    fn tcp_frames_route_over_loopback_with_return_path() {
        let a = TcpTransport::bind(b"alice".to_vec(), "127.0.0.1:0").unwrap();
        let b = TcpTransport::bind(b"bob".to_vec(), "127.0.0.1:0").unwrap();
        // Each learns how to dial the other.
        a.add_peer(b"bob".to_vec(), b.local_socket_addr());
        b.add_peer(b"alice".to_vec(), a.local_socket_addr());

        a.send(b"bob", Frame::Mote(vec![1, 2, 3])).unwrap();

        // The frame arrives at Bob, tagged with Alice's return path.
        let mut got = Vec::new();
        assert!(
            wait_until(|| {
                got = b.drain();
                !got.is_empty()
            }),
            "frame should arrive over the socket"
        );
        assert_eq!(got, vec![(b"alice".to_vec(), Frame::Mote(vec![1, 2, 3]))]);
        // Alice received nothing.
        assert!(a.drain().is_empty());
    }

    #[test]
    fn tcp_ack_travels_back_over_a_fresh_connection() {
        let a = TcpTransport::bind(b"alice".to_vec(), "127.0.0.1:0").unwrap();
        let b = TcpTransport::bind(b"bob".to_vec(), "127.0.0.1:0").unwrap();
        a.add_peer(b"bob".to_vec(), b.local_socket_addr());
        b.add_peer(b"alice".to_vec(), a.local_socket_addr());

        // Bob acks back to Alice's return path.
        b.send(b"alice", Frame::Ack(vec![0xaa, 0xbb])).unwrap();
        let mut got = Vec::new();
        assert!(wait_until(|| {
            got = a.drain();
            !got.is_empty()
        }));
        assert_eq!(got, vec![(b"bob".to_vec(), Frame::Ack(vec![0xaa, 0xbb]))]);
    }

    #[test]
    fn tcp_unknown_peer_is_unreachable() {
        let a = TcpTransport::bind(b"alice".to_vec(), "127.0.0.1:0").unwrap();
        // Never registered → no route.
        assert_eq!(a.send(b"ghost", Frame::Ack(vec![1])), Err(TransportError::Unreachable));
    }

    #[test]
    fn tcp_dead_socket_is_unreachable() {
        let a = TcpTransport::bind(b"alice".to_vec(), "127.0.0.1:0").unwrap();
        // Bind a peer, capture its socket, then drop it so nothing is listening there.
        let dead_socket = {
            let b = TcpTransport::bind(b"bob".to_vec(), "127.0.0.1:0").unwrap();
            b.local_socket_addr()
        };
        a.add_peer(b"bob".to_vec(), dead_socket);
        assert_eq!(a.send(b"bob", Frame::Mote(vec![1])), Err(TransportError::Unreachable));
    }

    /// A peer that streams far more frames than the engine drains cannot grow the inbound backlog
    /// without bound: the listener refuses frames past `MAX_INBOX_FRAMES`, so memory stays capped
    /// (the aggregate-exhaustion vector — each frame is bounded, the queue was not). We flood a
    /// single connection with many small frames and never drain, then assert the depth never exceeds
    /// the cap.
    #[test]
    fn tcp_inbox_depth_is_bounded_under_a_flood() {
        let b = TcpTransport::bind(b"bob".to_vec(), "127.0.0.1:0").unwrap();
        let flood = MAX_INBOX_FRAMES + 512;

        // One connection carrying a back-to-back frame stream; the accept loop reads many per conn.
        std::thread::spawn({
            let addr = b.local_socket_addr();
            move || {
                if let Ok(mut stream) = TcpStream::connect(addr) {
                    for _ in 0..flood {
                        // Ignore write errors: once the reader hits the cap it drops the connection,
                        // and further writes reset — exactly the backpressure being exercised.
                        if write_tcp_frame(&mut stream, b"alice", &Frame::Ack(vec![0xAB])).is_err() {
                            break;
                        }
                    }
                }
            }
        });

        // Wait until the backlog fills to the cap (proves the flood reached the inbox), never
        // draining. The depth must never exceed the cap no matter how much more the peer streams.
        assert!(
            wait_until(|| b.inbox.lock().unwrap_or_else(|e| e.into_inner()).len() >= MAX_INBOX_FRAMES),
            "the flood should fill the inbox up to its cap"
        );
        // Give the sender extra time to keep pushing; the cap must still hold.
        for _ in 0..50 {
            let depth = b.inbox.lock().unwrap_or_else(|e| e.into_inner()).len();
            assert!(
                depth <= MAX_INBOX_FRAMES,
                "inbox depth {depth} exceeded the cap {MAX_INBOX_FRAMES} — backlog grew unbounded"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

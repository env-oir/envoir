//! # dmtap-p2p — the real libp2p mesh transport (spec §4)
//!
//! DMTAP's `Transport` trait (defined in `envoir-node`, spec §4) abstracts *how* a sealed
//! [`Frame`] reaches a peer. The node ships two in-tree transports — an in-process fabric and a
//! raw-TCP loopback — for fast, deterministic tests. This crate adds the **real** one: a live
//! **libp2p** swarm, the substrate the spec profiles in §4.1.
//!
//! ## What is wired (spec §4.1 stack)
//! - **Transports:** TCP + QUIC, secured by **Noise**, multiplexed by **Yamux** (QUIC carries its
//!   own TLS 1.3 + streams).
//! - **[`kad`](libp2p::kad) — Kademlia DHT:** peer/record routing, modelling the §4.2
//!   `key → location` record store. [`Libp2pTransport::kad_put`] / [`Libp2pTransport::kad_get`]
//!   store and resolve a signed location record by `hash(ik)`-style key.
//! - **[`request_response`](libp2p::request_response):** the carrier for DMTAP [`Frame`] bytes — a
//!   request delivers a `(from, Frame)` unit; the response is a transport-level receipt (the
//!   DMTAP `ack` is itself a separate [`Frame::Ack`], §19.3.2, and travels back the same way).
//! - **[`identify`](libp2p::identify):** peer metadata exchange (agent/protocols/observed addr).
//! - **[`relay`](libp2p::relay) (Circuit Relay v2) + [`dcutr`](libp2p::dcutr):** the NAT-traversal
//!   ladder of §4.3 — a public node relays, DCUtR hole-punches to upgrade to a direct hop.
//!
//! ## Containing the async runtime (the design constraint)
//! libp2p is async (tokio). The rest of the node is **synchronous** and stays that way: this
//! transport spawns a tokio runtime on its own thread pool, runs the swarm in a background task,
//! and bridges the synchronous [`Transport`] trait to it over channels. [`Transport::send`] just
//! resolves the target's [`PeerId`] and hands the frame to the swarm task (non-blocking);
//! [`Transport::drain`] pops an inbox the swarm task fills. The Kademlia calls block on a reply
//! channel with a timeout. No async leaks past this module.
//!
//! ## PeerId ↔ DMTAP identity mapping (§4.2)
//! A peer's *transport address* in the node model is its DMTAP identity bytes; libp2p addresses by
//! [`PeerId`]. This transport keeps a `dmtap_addr → PeerId` book: [`Libp2pTransport::add_peer`]
//! seeds it from a resolved location record, and inbound requests **auto-learn** the mapping from
//! the frame's `from` field + the request's source peer, so an `ack` can route back over the
//! established connection without a fresh lookup (mirroring §19.3.2's "back over the same channel").
//!
//! ## Honest scope (loopback only)
//! The comprehensive test drives two real libp2p swarms on `127.0.0.1` exchanging a real sealed
//! MOTE + ack across the wire, plus a Kademlia PUT/GET. Circuit-Relay-v2 is proven for real on
//! loopback too — a reservation, then a frame delivered over a relayed connection to a peer that
//! never advertises a direct address at all (see [`tests::relay_v2_reservation_and_relayed_connection_delivers_a_frame`]).
//! DCUtR is wired and *attempts* a hole-punch automatically once a relayed connection is up
//! (observed empirically), but a genuine NAT-traversed upgrade needs two peers behind distinct
//! NATs — not reproducible on loopback, so it is an honest `#[ignore]` (see
//! [`tests::dcutr_hole_punch_upgrade_needs_real_nat_infra`]). The test suite also covers
//! connection-close/re-dial resilience, oversized-frame hardening (fails closed, no panic), and
//! large-message round-tripping near the configured size cap — see the crate tests for exactly
//! what is proven and what each honest gap is.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use libp2p::futures::StreamExt;
use libp2p::kad::{self, store::MemoryStore as KadMemoryStore};
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{dcutr, identify, noise, ping, relay, tcp, yamux};
use libp2p::{Multiaddr, PeerId, StreamProtocol, Swarm};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

// Re-export the trait surface this crate implements, so callers can `use dmtap_p2p::{...}`.
pub use dmtap::transport::{Frame, InboundFrame, Transport, TransportError};

/// The application protocol carried over libp2p request-response — one sealed DMTAP frame per
/// exchange. Versioned in its name so a future frame layout is an additive protocol (spec §10.2).
const FRAME_PROTOCOL: &str = "/dmtap/frame/1.0.0";
/// Identify protocol version advertised to peers (spec §4.1 identify).
const IDENTIFY_PROTOCOL: &str = "/dmtap/id/1.0.0";
/// How long a blocking Kademlia call waits for its query to resolve before giving up.
const KAD_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a blocking connectivity check ([`Libp2pTransport::is_connected`]) waits for the swarm
/// task to answer before reporting `false`. The swarm task only stalls this long if it is gone.
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
/// Idle-connection keep-alive so a connection used for a MOTE stays up for the returning ack.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Upper bound on a single wire request (a [`WireFrame`]) the frame protocol will read off the
/// wire. Spec §16.4 inlines a MOTE body up to the "Normal" file tier (4 MiB) before a file falls
/// back to the chunked bulk path, so the cap must clear that with headroom for the CBOR envelope
/// + `from` field; anything larger is presumed hostile/malformed and the codec fails the read
/// closed (never allocates past this bound). Deliberately well under the raw-TCP transport's own
/// 16 MiB `MAX_FRAME` bound (`envoir_node::transport`) so the two transports' failure envelopes
/// agree in spirit without coupling the crates.
const MAX_REQUEST_SIZE: u64 = 8 * 1024 * 1024;
/// Upper bound on a response: the frame protocol's response is only ever the empty
/// [`WireReceipt`] marker, so this is deliberately tiny — a peer sending anything larger is
/// misbehaving, not merely slow.
const MAX_RESPONSE_SIZE: u64 = 4 * 1024;

/// A boxed, thread-safe error for transport construction (libp2p builder + bind failures).
pub type BuildError = Box<dyn std::error::Error + Send + Sync>;

// --- Wire frame ------------------------------------------------------------------------------

/// The request payload on the wire: a DMTAP [`Frame`] plus the sender's return path (`from`),
/// exactly the `(from, frame)` pair the [`Transport`] contract moves. Serialized as CBOR by
/// [`request_response::cbor`]. Kept as its own serializable mirror because [`Frame`] lives in
/// `envoir-node` and is transport-agnostic (no serde dependency there).
///
/// Every `Vec<u8>` field is `#[serde(with = "serde_bytes")]`: plain serde serializes a `Vec<u8>`
/// as a generic sequence (CBOR array, ~1-2 bytes of overhead *per byte* of payload) rather than a
/// compact CBOR byte string. For a MOTE `body` that can legitimately be megabytes (spec §16.4),
/// that blowup silently eats most of [`MAX_REQUEST_SIZE`]'s budget before the real payload gets
/// anywhere near the configured cap — `serde_bytes` is what makes the size limit mean what its
/// doc comment says.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum WireFrame {
    Mote {
        #[serde(with = "serde_bytes")]
        from: Vec<u8>,
        #[serde(with = "serde_bytes")]
        body: Vec<u8>,
    },
    Ack {
        #[serde(with = "serde_bytes")]
        from: Vec<u8>,
        #[serde(with = "serde_bytes")]
        id: Vec<u8>,
    },
    Group {
        #[serde(with = "serde_bytes")]
        from: Vec<u8>,
        #[serde(with = "serde_bytes")]
        group_id: Vec<u8>,
        #[serde(with = "serde_bytes")]
        body: Vec<u8>,
    },
}

impl WireFrame {
    /// Build the wire form from this node's return path + an outbound [`Frame`].
    fn from_frame(from: Vec<u8>, frame: Frame) -> Self {
        match frame {
            Frame::Mote(body) => WireFrame::Mote { from, body },
            Frame::Ack(id) => WireFrame::Ack { from, id },
            Frame::Group { group_id, body } => WireFrame::Group { from, group_id, body },
        }
    }

    /// Split back into the `(from, frame)` pair the inbox stores.
    fn into_inbound(self) -> InboundFrame {
        match self {
            WireFrame::Mote { from, body } => (from, Frame::Mote(body)),
            WireFrame::Ack { from, id } => (from, Frame::Ack(id)),
            WireFrame::Group { from, group_id, body } => (from, Frame::Group { group_id, body }),
        }
    }
}

/// The response payload: a transport-level receipt that the request was accepted for processing.
/// Delivery *semantics* (the DMTAP `ack`, §19.3.2) ride a separate [`Frame::Ack`]; this is only
/// the request-response protocol's mandatory reply.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WireReceipt;

// --- Swarm behaviour (spec §4.1 stack) -------------------------------------------------------

/// The composed libp2p behaviour: the full §4.1 stack in one swarm.
#[derive(NetworkBehaviour)]
struct MeshBehaviour {
    /// Kademlia DHT — peer routing + the §4.2 `key → location` record store.
    kad: kad::Behaviour<KadMemoryStore>,
    /// Carries DMTAP [`Frame`] bytes between peers (one frame per request).
    frame: request_response::cbor::Behaviour<WireFrame, WireReceipt>,
    /// Peer metadata exchange (§4.1).
    identify: identify::Behaviour,
    /// Circuit Relay v2 **server** role — this node can relay for NAT'd peers (§4.3 rung 3).
    relay: relay::Behaviour,
    /// Circuit Relay v2 **client** role — reserve a slot on / dial through a relay.
    relay_client: relay::client::Behaviour,
    /// Direct Connection Upgrade through Relay — hole-punch to a direct hop (§4.3 rung 2).
    dcutr: dcutr::Behaviour,
    /// Liveness (§4.1 ping).
    ping: ping::Behaviour,
}

// --- Commands from the sync transport to the async swarm task --------------------------------

/// Work items handed from the synchronous [`Transport`] API to the background swarm task.
enum Command {
    /// Register how to reach a peer: seed Kademlia with its address so a dial can find it.
    AddPeer { peer: PeerId, addr: Multiaddr },
    /// Declare `addr` as one of *this* node's externally-reachable addresses (§4.3 rung 3): a
    /// node that chooses to act as a public Circuit-Relay-v2 server needs at least one confirmed
    /// external address to hand out in a reservation ack, or the reservation is accepted at the
    /// protocol level but the client-side listener fails closed with `NoAddressesInReservation`
    /// and never reports a dialable circuit address. Deliberately **not** automatic on every
    /// bound listener: a NAT'd node auto-declaring its LAN address as "external" would hand peers
    /// a useless address, so this is an opt-in the operator of a genuinely public relay makes.
    AddExternalAddress { addr: Multiaddr },
    /// Send one frame to a connected/dialable peer (best-effort; drives the sender-retry machine).
    Send { peer: PeerId, wire: Box<WireFrame> },
    /// Store a value under `key` in the DHT (§4.2 location record PUT).
    KadPut { key: Vec<u8>, value: Vec<u8>, reply: std::sync::mpsc::Sender<bool> },
    /// Resolve `key` from the DHT (§4.2 location record GET).
    KadGet { key: Vec<u8>, reply: std::sync::mpsc::Sender<Option<Vec<u8>>> },
    /// Force-close any open connection(s) to `peer`. Used both defensively (a peer that violates
    /// the frame protocol, e.g. an oversized/malformed request, is disconnected rather than kept
    /// around as a trusted stream — see [`handle_event`]'s `InboundFailure::Io` arm) and to
    /// simulate/recover from a connection blip in tests (re-dial resilience, §20.1).
    Disconnect { peer: PeerId },
    /// Report whether the swarm currently has an open connection to `peer` (test/inspection aid
    /// for connection-lifecycle behaviour; not needed by the delivery path itself, which only
    /// cares whether `send` succeeds).
    IsConnected { peer: PeerId, reply: std::sync::mpsc::Sender<bool> },
}

// --- The transport ---------------------------------------------------------------------------

/// A live-libp2p [`Transport`] (spec §4). Construct it with [`Libp2pTransport::new`]; it starts a
/// background swarm and is dropped cleanly when the last handle goes away (the owned runtime aborts
/// the swarm task on drop).
pub struct Libp2pTransport {
    /// This node's DMTAP address (identity bytes) — the `from` it stamps and its `local_addr`.
    local_addr: Vec<u8>,
    /// This node's libp2p peer id (its transport-layer identity).
    peer_id: PeerId,
    /// Channel to the swarm task.
    cmd_tx: mpsc::UnboundedSender<Command>,
    /// Inbound frames the swarm task has received, awaiting [`Transport::drain`].
    inbox: Arc<Mutex<VecDeque<InboundFrame>>>,
    /// `dmtap_addr → PeerId` book (seeded by [`add_peer`](Self::add_peer), grown by inbound frames).
    peers: Arc<Mutex<HashMap<Vec<u8>, PeerId>>>,
    /// Bound listen multiaddrs, filled as `NewListenAddr` events arrive.
    listeners: Arc<Mutex<Vec<Multiaddr>>>,
    /// Owns the tokio runtime; dropping it stops the swarm task. `Arc` so the transport is cheap to
    /// keep alive across the node without exposing the runtime.
    _runtime: Arc<tokio::runtime::Runtime>,
}

impl Libp2pTransport {
    /// Start a libp2p node bound to `listen_on` (e.g. `/ip4/127.0.0.1/tcp/0` and/or a `quic-v1`
    /// addr), using `local_addr` as this node's DMTAP identity address. The libp2p keypair is
    /// freshly generated; `local_addr` is the DMTAP identity (the two are mapped, not equal, §4.2).
    ///
    /// Blocks only briefly to build the swarm and start listening; the swarm then runs in the
    /// background. Use [`wait_for_listener`](Self::wait_for_listener) to learn the bound address.
    pub fn new(local_addr: impl Into<Vec<u8>>, listen_on: &[Multiaddr]) -> Result<Self, BuildError> {
        // >1 worker thread matters, not just for parallelism: Kademlia's background bootstrap /
        // bucket-refresh queries and the frame request-response protocol otherwise compete for
        // the SAME single thread, and a burst of Kademlia activity can starve an in-flight
        // frame write/read for hundreds of milliseconds (observed empirically) — a real latency
        // hazard for larger MOTEs, not just a test artifact.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;

        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let inbox: Arc<Mutex<VecDeque<InboundFrame>>> = Arc::new(Mutex::new(VecDeque::new()));
        let peers: Arc<Mutex<HashMap<Vec<u8>, PeerId>>> = Arc::new(Mutex::new(HashMap::new()));
        let listeners: Arc<Mutex<Vec<Multiaddr>>> = Arc::new(Mutex::new(Vec::new()));

        // Build the swarm and spawn its event loop *inside* the runtime (the tokio transports and
        // `tokio::spawn` require an active runtime context).
        let listen_on = listen_on.to_vec();
        let (inbox_t, peers_t, listeners_t) = (inbox.clone(), peers.clone(), listeners.clone());
        let peer_id = runtime.block_on(async move {
            let mut swarm = build_swarm()?;
            for addr in &listen_on {
                swarm.listen_on(addr.clone())?;
            }
            let peer_id = *swarm.local_peer_id();
            tokio::spawn(swarm_loop(swarm, cmd_rx, inbox_t, peers_t, listeners_t));
            Ok::<PeerId, BuildError>(peer_id)
        })?;

        Ok(Libp2pTransport {
            local_addr: local_addr.into(),
            peer_id,
            cmd_tx,
            inbox,
            peers,
            listeners,
            _runtime: Arc::new(runtime),
        })
    }

    /// This node's libp2p [`PeerId`] — hand it (with a listen addr) to peers so they can dial.
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// The listen multiaddrs bound so far (may be empty right after construction until the swarm
    /// reports `NewListenAddr`). Each already carries the `/p2p/<peer_id>` suffix appended here for
    /// convenience if absent.
    pub fn listeners(&self) -> Vec<Multiaddr> {
        self.listeners.lock().unwrap().clone()
    }

    /// Spin up to `timeout` for at least one bound listen addr, returning them (empty on timeout).
    /// A `tcp`/`quic` `:0` bind resolves its real port asynchronously; peers need the resolved addr.
    pub fn wait_for_listener(&self, timeout: Duration) -> Vec<Multiaddr> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let ls = self.listeners();
            if !ls.is_empty() || std::time::Instant::now() >= deadline {
                return ls;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Register how to reach a peer: map its DMTAP `addr` to its libp2p `peer_id` and seed the
    /// swarm (Kademlia) with a dialable `multiaddr` (a stand-in for signed §4.2 record discovery).
    pub fn add_peer(&self, addr: impl Into<Vec<u8>>, peer_id: PeerId, multiaddr: Multiaddr) {
        self.handle().add_peer(addr, peer_id, multiaddr);
    }

    /// Declare `addr` (typically one of this node's own [`listeners`](Self::listeners)) as an
    /// externally-reachable address, opting this node in to serving as a public Circuit-Relay-v2
    /// relay (§4.3 rung 3) for others. See [`Command::AddExternalAddress`] for why this is opt-in
    /// rather than automatic.
    pub fn add_external_address(&self, addr: Multiaddr) {
        let _ = self.cmd_tx.send(Command::AddExternalAddress { addr });
    }

    /// A cheap, cloneable control handle that can learn new routes at runtime — kept usable *after*
    /// the transport is moved into a [`Node`] (which takes it by value). This is how a node learns a
    /// peer's location record mid-flight (e.g. between a `RETRY` and a re-dispatch, §20.1).
    pub fn handle(&self) -> Libp2pHandle {
        Libp2pHandle { cmd_tx: self.cmd_tx.clone(), peers: self.peers.clone() }
    }

    /// Store `value` under `key` in the Kademlia DHT (§4.2 `key → location` PUT). Blocks until the
    /// PUT quorum resolves or [`KAD_TIMEOUT`] elapses; returns whether it was stored on ≥1 peer.
    pub fn kad_put(&self, key: &[u8], value: &[u8]) -> bool {
        let (tx, rx) = std::sync::mpsc::channel();
        if self
            .cmd_tx
            .send(Command::KadPut { key: key.to_vec(), value: value.to_vec(), reply: tx })
            .is_err()
        {
            return false;
        }
        rx.recv_timeout(KAD_TIMEOUT).unwrap_or(false)
    }

    /// Resolve `key` from the Kademlia DHT (§4.2 `key → location` GET). Blocks until a record is
    /// found or the query finishes / [`KAD_TIMEOUT`] elapses; `None` means not found.
    pub fn kad_get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let (tx, rx) = std::sync::mpsc::channel();
        if self.cmd_tx.send(Command::KadGet { key: key.to_vec(), reply: tx }).is_err() {
            return None;
        }
        rx.recv_timeout(KAD_TIMEOUT).ok().flatten()
    }

    /// Force-close any open connection to `peer`. A best-effort nudge, not a ban: the frame
    /// protocol will happily re-dial `peer` on the next [`Transport::send`] if its address is
    /// still known (that re-dial is exactly what proves connection-close resilience, §20.1).
    pub fn disconnect_peer(&self, peer: PeerId) {
        let _ = self.cmd_tx.send(Command::Disconnect { peer });
    }

    /// Whether the swarm currently holds an open connection to `peer`. Blocks briefly on the
    /// swarm task; `false` on timeout (swarm gone) as well as on a genuinely absent connection.
    pub fn is_connected(&self, peer: PeerId) -> bool {
        let (tx, rx) = std::sync::mpsc::channel();
        if self.cmd_tx.send(Command::IsConnected { peer, reply: tx }).is_err() {
            return false;
        }
        rx.recv_timeout(QUERY_TIMEOUT).unwrap_or(false)
    }
}

/// A cloneable control handle onto a [`Libp2pTransport`]'s route book + swarm command channel.
/// Outlives moving the transport into a [`Node`], so routes can be learned at runtime (§4.2).
#[derive(Clone)]
pub struct Libp2pHandle {
    cmd_tx: mpsc::UnboundedSender<Command>,
    peers: Arc<Mutex<HashMap<Vec<u8>, PeerId>>>,
}

impl Libp2pHandle {
    /// Learn how to reach a peer (see [`Libp2pTransport::add_peer`]).
    pub fn add_peer(&self, addr: impl Into<Vec<u8>>, peer_id: PeerId, multiaddr: Multiaddr) {
        self.peers.lock().unwrap().insert(addr.into(), peer_id);
        let _ = self.cmd_tx.send(Command::AddPeer { peer: peer_id, addr: multiaddr });
    }
}

impl Transport for Libp2pTransport {
    fn local_addr(&self) -> Vec<u8> {
        self.local_addr.clone()
    }

    fn send(&self, to: &[u8], frame: Frame) -> Result<(), TransportError> {
        // Resolve the DMTAP address to a libp2p peer id; an unknown peer is unreachable (§20.1),
        // which drives the sender's retry machine exactly as the other transports do.
        let peer = self
            .peers
            .lock()
            .unwrap()
            .get(to)
            .copied()
            .ok_or(TransportError::Unreachable)?;
        let wire = WireFrame::from_frame(self.local_addr.clone(), frame);
        // Hand off to the swarm task; a closed channel (swarm gone) is unreachable.
        self.cmd_tx
            .send(Command::Send { peer, wire: Box::new(wire) })
            .map_err(|_| TransportError::Unreachable)?;
        Ok(())
    }

    fn drain(&self) -> Vec<InboundFrame> {
        self.inbox.lock().unwrap().drain(..).collect()
    }
}

// --- Swarm construction ----------------------------------------------------------------------

/// Build the libp2p swarm with the full §4.1 behaviour stack over TCP + QUIC, Noise + Yamux.
fn build_swarm() -> Result<Swarm<MeshBehaviour>, BuildError> {
    let swarm = libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)?
        .with_quic()
        .with_relay_client(noise::Config::new, yamux::Config::default)?
        .with_behaviour(|key, relay_client| {
            let peer_id = key.public().to_peer_id();

            let mut kad = kad::Behaviour::new(peer_id, KadMemoryStore::new(peer_id));
            // Serve records so a two-node DHT actually stores/answers on loopback (default is a
            // client that never becomes a server without external "confirmed reachability").
            kad.set_mode(Some(kad::Mode::Server));

            let frame_codec = request_response::cbor::codec::Codec::default()
                .set_request_size_maximum(MAX_REQUEST_SIZE)
                .set_response_size_maximum(MAX_RESPONSE_SIZE);
            let frame = request_response::Behaviour::with_codec(
                frame_codec,
                [(StreamProtocol::new(FRAME_PROTOCOL), ProtocolSupport::Full)],
                request_response::Config::default(),
            );

            let identify = identify::Behaviour::new(identify::Config::new(
                IDENTIFY_PROTOCOL.to_string(),
                key.public(),
            ));

            let relay = relay::Behaviour::new(peer_id, relay::Config::default());
            let dcutr = dcutr::Behaviour::new(peer_id);
            let ping = ping::Behaviour::new(ping::Config::new());

            MeshBehaviour { kad, frame, identify, relay, relay_client, dcutr, ping }
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(IDLE_TIMEOUT))
        .build();
    Ok(swarm)
}

// --- The background swarm task ---------------------------------------------------------------

/// Per-query reply routing for in-flight Kademlia calls initiated by the sync API.
#[derive(Default)]
struct PendingKad {
    puts: HashMap<kad::QueryId, std::sync::mpsc::Sender<bool>>,
    gets: HashMap<kad::QueryId, std::sync::mpsc::Sender<Option<Vec<u8>>>>,
}

/// The swarm event loop: drive libp2p, service [`Command`]s from the sync transport, and fill the
/// shared inbox / listener list / peer book. Runs until the command channel closes (transport
/// dropped).
async fn swarm_loop(
    mut swarm: Swarm<MeshBehaviour>,
    mut cmd_rx: mpsc::UnboundedReceiver<Command>,
    inbox: Arc<Mutex<VecDeque<InboundFrame>>>,
    peers: Arc<Mutex<HashMap<Vec<u8>, PeerId>>>,
    listeners: Arc<Mutex<Vec<Multiaddr>>>,
) {
    let mut pending = PendingKad::default();
    loop {
        tokio::select! {
            command = cmd_rx.recv() => {
                match command {
                    Some(cmd) => handle_command(&mut swarm, &mut pending, cmd),
                    // Transport dropped: shut the swarm task down.
                    None => return,
                }
            }
            event = swarm.select_next_some() => {
                handle_event(&mut swarm, &mut pending, &inbox, &peers, &listeners, event);
            }
        }
    }
}

/// Apply one [`Command`] to the swarm.
fn handle_command(swarm: &mut Swarm<MeshBehaviour>, pending: &mut PendingKad, cmd: Command) {
    match cmd {
        Command::AddPeer { peer, addr } => {
            // Teach both Kademlia (so a dial-by-peer-id can find an address) and the swarm's dialer.
            swarm.behaviour_mut().kad.add_address(&peer, addr.clone());
            swarm.add_peer_address(peer, addr);
        }
        Command::AddExternalAddress { addr } => {
            swarm.add_external_address(addr);
        }
        Command::Send { peer, wire } => {
            // request-response dials using addresses supplied by the behaviours (Kademlia) if not
            // already connected, then delivers the frame. Best-effort: failures surface as an
            // OutboundFailure event, absorbed by the sender's retry + dedup (§19.3.2).
            swarm.behaviour_mut().frame.send_request(&peer, *wire);
        }
        Command::KadPut { key, value, reply } => {
            let record = kad::Record::new(kad::RecordKey::new(&key), value);
            match swarm.behaviour_mut().kad.put_record(record, kad::Quorum::One) {
                Ok(qid) => {
                    pending.puts.insert(qid, reply);
                }
                // No peers to store on / local error: report failure now.
                Err(_) => {
                    let _ = reply.send(false);
                }
            }
        }
        Command::KadGet { key, reply } => {
            let qid = swarm.behaviour_mut().kad.get_record(kad::RecordKey::new(&key));
            pending.gets.insert(qid, reply);
        }
        Command::Disconnect { peer } => {
            // Best-effort: a peer already gone is not an error.
            let _ = swarm.disconnect_peer_id(peer);
        }
        Command::IsConnected { peer, reply } => {
            let _ = reply.send(swarm.is_connected(&peer));
        }
    }
}

/// Handle one swarm event: record listen addrs, deliver inbound frames + auto-learn peers, and
/// resolve pending Kademlia queries.
fn handle_event(
    swarm: &mut Swarm<MeshBehaviour>,
    pending: &mut PendingKad,
    inbox: &Arc<Mutex<VecDeque<InboundFrame>>>,
    peers: &Arc<Mutex<HashMap<Vec<u8>, PeerId>>>,
    listeners: &Arc<Mutex<Vec<Multiaddr>>>,
    event: SwarmEvent<MeshBehaviourEvent>,
) {
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            // Append the peer-id suffix so the stored addr is directly dialable by a remote.
            let full = address.clone().with_p2p(*swarm.local_peer_id()).unwrap_or(address);
            listeners.lock().unwrap().push(full);
        }
        SwarmEvent::Behaviour(MeshBehaviourEvent::Frame(request_response::Event::Message {
            peer,
            message,
            ..
        })) => match message {
            request_response::Message::Request { request, channel, .. } => {
                // Auto-learn `dmtap_from → peer` so an ack can route back over this connection
                // (§19.3.2 "back over the same channel"), then enqueue for the node to drain.
                let (from, frame) = request.into_inbound();
                peers.lock().unwrap().entry(from.clone()).or_insert(peer);
                inbox.lock().unwrap().push_back((from, frame));
                // The response is a transport-level receipt; ignore a closed channel.
                let _ = swarm.behaviour_mut().frame.send_response(channel, WireReceipt);
            }
            request_response::Message::Response { .. } => {
                // Transport-level receipt; DMTAP delivery semantics ride a separate Frame::Ack.
            }
        },
        // A request we couldn't even read (truncated by the codec's size cap, or plain garbage
        // that fails CBOR decode) is a protocol violation, not a transient hiccup — fail closed
        // and drop the connection rather than keep talking to a peer that just misbehaved. Other
        // `InboundFailure` reasons (`Timeout`/`ConnectionClosed`/`UnsupportedProtocols`/
        // `ResponseOmission`) are not evidence of hostile behaviour and are left alone; the
        // sender's own retry/ack machinery (§20.1) already tolerates a dropped request.
        SwarmEvent::Behaviour(MeshBehaviourEvent::Frame(request_response::Event::InboundFailure {
            peer,
            error: request_response::InboundFailure::Io(_),
            ..
        })) => {
            let _ = swarm.disconnect_peer_id(peer);
        }
        SwarmEvent::Behaviour(MeshBehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
            id,
            result,
            step,
            ..
        })) => resolve_kad(pending, id, result, step.last),
        // Identify / relay / dcutr / ping / connection lifecycle: driven by the swarm, nothing to
        // surface to the synchronous node here.
        _ => {}
    }
}

/// Route a completed/updated Kademlia query result back to its blocking caller.
fn resolve_kad(
    pending: &mut PendingKad,
    id: kad::QueryId,
    result: kad::QueryResult,
    last: bool,
) {
    match result {
        kad::QueryResult::PutRecord(res) => {
            if let Some(reply) = pending.puts.remove(&id) {
                let _ = reply.send(res.is_ok());
            }
        }
        kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FoundRecord(peer_record))) => {
            // First hit wins; hand the value up and stop tracking this query.
            if let Some(reply) = pending.gets.remove(&id) {
                let _ = reply.send(Some(peer_record.record.value));
            }
        }
        kad::QueryResult::GetRecord(_) => {
            // A non-found GetRecord progress step: only report "not found" once the query is done.
            if last {
                if let Some(reply) = pending.gets.remove(&id) {
                    let _ = reply.send(None);
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests;

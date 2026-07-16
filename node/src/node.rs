//! The node delivery engine (spec §0.2, §2, §4.7, §19.3, §20).
//!
//! A [`Node`] is the running whole-client side: it holds an identity ([`IdentityKey`] + an HPKE
//! [`SealKeypair`]), a MOTE-backed mail store, a dedup/replay set, an outbound retry queue
//! (§20.1), and a [`Transport`] onto the mesh. It wires the shared crates into an end-to-end
//! path: resolve a recipient's keys, build + HPKE-seal a real MOTE to them (§2.4), dispatch it
//! over the transport, and — on the receiving side — run the §2.7 validation pipeline, decrypt,
//! store, and `ack` (§19.3). The sender's queue advances to `ACKED` when that ack returns.
//!
//! ## What is real vs. stubbed
//! - **Real:** Ed25519 identities, HPKE payload sealing/opening (suite `0x01`), content
//!   addressing, the full §2.7 ordered validation (via [`dmtap_core::mote::validate`]), the
//!   §20.1 sender-retry machine, dedup/idempotent ack (§2.6), and RFC 5322 projection into an
//!   IMAP/JMAP-visible [`MemoryStore`].
//! - **Stubbed / in-process:** recipient resolution is a local `directory` map (a stand-in for
//!   naming/KeyPackage fetch, §3/§5.3); sender classification uses the transport return path
//!   rather than blinded tags (§2.2a); the transport is [`InMemoryNetwork`], not libp2p; MLS
//!   group sessions (§5) are not modeled (1:1 HPKE only); timers are event-driven off an
//!   injected clock.
//!
//! [`IdentityKey`]: dmtap_core::identity::IdentityKey
//! [`SealKeypair`]: dmtap_core::mote::SealKeypair
//! [`InMemoryNetwork`]: crate::transport::InMemoryNetwork

use std::collections::{HashMap, HashSet};

use dmtap_core::identity::IdentityKey;
use dmtap_core::mote::{
    build_mote, validate, Envelope, Headers, Hpke, Kind, MoteDraft, MoteError, Outcome, Payload,
    RecipientCtx, SealKeypair,
};
use dmtap_core::{ContentId, TimestampMs};
use dmtap_mail::store::{MailStore, Mailbox, MemoryStore};

use crate::inbound::{DropReason, InboundOutcome};
use crate::journal::{Journal, JournalError, NullJournal, PersistedEntry, Snapshot};
use crate::outbound::{OutEvent, OutState, OutboundEntry};
use crate::transport::{Frame, Transport, TransportError};

/// The requests-area mailbox for deferred cold-sender MOTEs (§2.7a: never the inbox). Mapped onto
/// the Junk SPECIAL-USE folder so existing IMAP/JMAP clients surface it distinctly from the inbox.
const REQUESTS_MAILBOX: &str = "Junk";

/// Why a [`Node::send_mail`] could not admit a MOTE for delivery.
#[derive(Debug, PartialEq, Eq)]
pub enum SendError {
    /// The recipient's sealing key is not known — resolve them first (`add_contact`/`learn_key`).
    /// Models §20.1's `resolve_or_seal_blocked` as a synchronous failure in the in-process model
    /// (there is no async DHT/KT lookup here); the pure `Blocked → RETRY` transition is exercised
    /// at the state-machine level in `outbound`'s tests.
    Unresolved,
    /// The core rejected the build/seal (should not happen for a well-formed draft).
    Mote(MoteError),
}

impl From<MoteError> for SendError {
    fn from(e: MoteError) -> Self {
        SendError::Mote(e)
    }
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendError::Unresolved => f.write_str("recipient sealing key not resolved"),
            SendError::Mote(e) => write!(f, "seal failed: {e}"),
        }
    }
}
impl std::error::Error for SendError {}

/// A running DMTAP node. Generic over its [`Transport`] so the in-process fabric used in tests
/// swaps cleanly for a real mesh transport.
pub struct Node<T: Transport> {
    /// This node's root identity key (§1.2); its public bytes are its address and `to` target.
    ik: IdentityKey,
    /// The X25519 KEM keypair correspondents seal payloads to (§5.3, advertised via KeyPackages).
    seal: SealKeypair,
    /// The MOTE-store projection every mail client is a view of (§8).
    store: MemoryStore,
    /// Dedup / replay set: `id → sender return path`, so a re-delivered `id` is acked without
    /// reprocessing (§2.6) and the ack can be routed even for a duplicate we no longer decrypt.
    seen: HashMap<Vec<u8>, Vec<u8>>,
    /// The sender-side retry queue, keyed by MOTE `id` (§20.1).
    outbound: HashMap<Vec<u8>, OutboundEntry>,
    /// Known-contact identity keys — the fast-path sender classification (§2.7 step 5) and the
    /// pin the decrypted `Payload.from` is checked against (§2.7 step 8).
    contacts: HashSet<Vec<u8>>,
    /// Naming/KeyPackage resolution stand-in: recipient IK → their sealing (X25519) public key.
    directory: HashMap<Vec<u8>, [u8; 32]>,
    /// The mesh transport.
    transport: T,
    /// Injected clock (ms). Explicit so deadline/backoff behavior is deterministic in tests.
    now: TimestampMs,
    /// Durable store for the outbound retry queue + dedup set (§19.3.3). Every mutation of that
    /// state is checkpointed here so a restarted node resumes its pending sends; the default
    /// [`NullJournal`] persists nothing (ephemeral node).
    journal: Box<dyn Journal>,
}

impl<T: Transport> Node<T> {
    /// Build a node with a fresh identity + sealing key over `transport`. The transport's
    /// `local_addr` SHOULD equal this identity's public bytes (the in-process addressing model).
    pub fn new(transport: T) -> Self {
        Node::with_identity(IdentityKey::generate(), SealKeypair::generate(), transport)
    }

    /// Build a node from explicit keys (for reproducible tests / persisted identities). Uses a
    /// [`NullJournal`] — the outbound queue is **not** durable; use [`with_journal`](Self::with_journal)
    /// for a node that must resume its pending sends across restart (§19.3.3).
    pub fn with_identity(ik: IdentityKey, seal: SealKeypair, transport: T) -> Self {
        Node {
            ik,
            seal,
            store: MemoryStore::new(),
            seen: HashMap::new(),
            outbound: HashMap::new(),
            contacts: HashSet::new(),
            directory: HashMap::new(),
            transport,
            now: 1_700_000_000_000,
            journal: Box::new(NullJournal),
        }
    }

    /// Build a node backed by a durable [`Journal`], **resuming** any previously-persisted outbound
    /// retry queue and dedup set (spec §19.3.3: the queue MUST survive restart). Rebuild the node
    /// with the same identity + the same journal after a restart and its pending sends come back;
    /// call [`retry_pending`](Self::retry_pending) to re-dispatch them.
    ///
    /// The identity keys and the delivered-mail store are **not** restored from the journal (that
    /// state lives elsewhere, see [`crate::journal`]); the caller supplies the identity, and only
    /// the in-flight delivery state is recovered here.
    pub fn with_journal(
        ik: IdentityKey,
        seal: SealKeypair,
        transport: T,
        journal: Box<dyn Journal>,
    ) -> Result<Self, JournalError> {
        let snapshot = journal.load()?;
        let mut node = Node {
            ik,
            seal,
            store: MemoryStore::new(),
            seen: HashMap::new(),
            outbound: HashMap::new(),
            contacts: HashSet::new(),
            directory: HashMap::new(),
            transport,
            now: 1_700_000_000_000,
            journal,
        };
        for pe in snapshot.outbound {
            let entry = pe.into_entry()?;
            node.outbound.insert(entry.id.as_bytes().to_vec(), entry);
        }
        for (id, from) in snapshot.seen {
            node.seen.insert(id, from);
        }
        Ok(node)
    }

    // --- identity / directory ---------------------------------------------------------------

    /// This node's identity public key (§1.2) — its `to` address.
    pub fn ik_public(&self) -> Vec<u8> {
        self.ik.public()
    }

    /// This node's sealing (X25519) public key, which peers must learn to send to it.
    pub fn seal_public(&self) -> [u8; 32] {
        *self.seal.public()
    }

    /// Record how to reach a peer: pin them as a known contact and learn their sealing key
    /// (§3.4 pin + §5.3 KeyPackage, collapsed into one directory entry for the in-process model).
    pub fn add_contact(&mut self, ik: &[u8], seal_pub: [u8; 32]) {
        self.contacts.insert(ik.to_vec());
        self.directory.insert(ik.to_vec(), seal_pub);
    }

    /// Learn a recipient's sealing key *without* pinning them as a contact — used to model a
    /// cold-sender send (the recipient will classify us as unknown until they pin us).
    pub fn learn_key(&mut self, ik: &[u8], seal_pub: [u8; 32]) {
        self.directory.insert(ik.to_vec(), seal_pub);
    }

    /// Advance the injected clock to `now` (ms since epoch).
    pub fn set_now(&mut self, now: TimestampMs) {
        self.now = now;
    }

    // --- store views ------------------------------------------------------------------------

    /// The mail-store projection (IMAP/JMAP view of delivered MOTEs).
    pub fn store(&self) -> &MemoryStore {
        &self.store
    }

    /// Mutable access to the mail-store projection — lets a JMAP handler
    /// ([`dmtap_mail::jmap::process`]) or IMAP session run directly against the node's live store.
    pub fn store_mut(&mut self) -> &mut MemoryStore {
        &mut self.store
    }

    // --- durability (§19.3.3) ----------------------------------------------------------------

    /// The current durable state (outbound queue + dedup set) as a serializable [`Snapshot`].
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            outbound: self.outbound.values().map(PersistedEntry::from_entry).collect(),
            seen: self.seen.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        }
    }

    /// Persist the current delivery state to the journal (§19.3.3). Called after every mutation of
    /// the outbound queue / dedup set. Best-effort: a journal write failure is swallowed here (there
    /// is no useful in-line recovery mid-operation), matching a durable-queue node that logs and
    /// continues; [`flush`](Self::flush) exposes the same write with its error for explicit checks.
    fn checkpoint(&self) {
        let _ = self.journal.save(&self.snapshot());
    }

    /// Force a durable checkpoint, surfacing any journal error (for callers that want to confirm
    /// the queue is committed — e.g. before reporting a send accepted).
    pub fn flush(&self) -> Result<(), JournalError> {
        self.journal.save(&self.snapshot())
    }

    /// The INBOX mailbox (delivered, accepted MOTEs).
    pub fn inbox(&self) -> &Mailbox {
        self.store.mailbox("INBOX").expect("INBOX always exists")
    }

    /// The requests-area mailbox (deferred cold-sender MOTEs, §2.7a).
    pub fn requests(&self) -> &Mailbox {
        self.store.mailbox(REQUESTS_MAILBOX).expect("requests mailbox always exists")
    }

    /// The sender-side state of a tracked outbound MOTE, by `id`.
    pub fn outbound_state(&self, id: &ContentId) -> Option<OutState> {
        self.outbound.get(id.as_bytes()).map(|e| e.state)
    }

    // --- sending (§20.1 outbound) -----------------------------------------------------------

    /// Send a mail MOTE to `to_ik`: build the draft, resolve + seal, and dispatch. Drives the
    /// §20.1 machine `QUEUED → SEALED → IN_FLIGHT` (or `→ RETRY` if the transport is unreachable).
    /// Returns the MOTE's stable content address (§2.2) for tracking.
    pub fn send_mail(
        &mut self,
        to_ik: &[u8],
        subject: &str,
        body: &[u8],
    ) -> Result<ContentId, SendError> {
        let mut draft = MoteDraft::new(Kind::Mail, self.now, body.to_vec());
        draft.headers = Headers { subject: Some(subject.to_string()), ..Headers::default() };
        self.enqueue_and_dispatch(to_ik, draft)
    }

    /// Like [`send_mail`](Self::send_mail) but with a caller-supplied draft — used to send a chat
    /// MOTE carrying an explicit challenge (a cold sender clearing the §9 gate).
    pub fn send_with_draft(
        &mut self,
        to_ik: &[u8],
        draft: MoteDraft,
    ) -> Result<ContentId, SendError> {
        self.enqueue_and_dispatch(to_ik, draft)
    }

    fn enqueue_and_dispatch(
        &mut self,
        to_ik: &[u8],
        draft: MoteDraft,
    ) -> Result<ContentId, SendError> {
        // Resolve the recipient's sealing key (naming/KeyPackage stand-in).
        let seal_pub = self.directory.get(to_ik).copied().ok_or(SendError::Unresolved)?;
        let expires = draft.expires;

        // enqueue → QUEUED, then resolve_and_seal_ok → SEALED (real HPKE seal, stable `id`).
        let ephemeral = IdentityKey::generate();
        let env = build_mote(&Hpke, &self.ik, &ephemeral, to_ik, &seal_pub, draft)?;
        let id = env.id.clone();

        let mut entry = OutboundEntry::enqueue(id.clone(), to_ik.to_vec(), self.now, expires);
        entry.apply(OutEvent::SealOk).expect("QUEUED→SEALED");
        entry.sealed = Some(env);
        self.dispatch(&mut entry); // SEALED → IN_FLIGHT (or → RETRY if unreachable)
        self.outbound.insert(id.as_bytes().to_vec(), entry);
        self.checkpoint(); // §19.3.3: the queued MOTE is now durable before we return.
        Ok(id)
    }

    /// Hand a SEALED entry's envelope to the transport, driving `dispatch_ok`/`tier_unreachable`
    /// (§20.1). Requires `entry.sealed` to be present.
    fn dispatch(&mut self, entry: &mut OutboundEntry) {
        let env = entry.sealed.clone().expect("dispatch requires a sealed envelope");
        let frame = Frame::Mote(env.det_cbor());
        match self.transport.send(&entry.to, frame) {
            Ok(()) => {
                entry.apply(OutEvent::DispatchOk).expect("SEALED→IN_FLIGHT");
            }
            Err(TransportError::Unreachable) => {
                // Move SEALED→IN_FLIGHT→RETRY so `attempts` bookkeeping matches §20.1 (the table
                // routes an unreachable tier out of IN_FLIGHT).
                entry.apply(OutEvent::DispatchOk).expect("SEALED→IN_FLIGHT");
                entry.apply(OutEvent::TierUnreachable).expect("IN_FLIGHT→RETRY");
            }
        }
    }

    /// Fire the retry timer for every `RETRY` entry: re-dispatch the same immutable envelope
    /// (§20.1 `retry_timer_fires`, §19.3.3 step 4 — a fresh, idempotent send of the same `id`).
    /// Call this after a transient failure clears (e.g. the peer comes back online). Returns the
    /// number of entries re-dispatched.
    pub fn retry_pending(&mut self) -> usize {
        let retry_ids: Vec<Vec<u8>> = self
            .outbound
            .iter()
            .filter(|(_, e)| e.state == OutState::Retry)
            .map(|(k, _)| k.clone())
            .collect();
        let mut redispatched = 0;
        for key in &retry_ids {
            let mut entry = self.outbound.remove(key).expect("just enumerated");
            entry.apply(OutEvent::RetryTimerFires).expect("RETRY→IN_FLIGHT");
            let env = entry.sealed.clone().expect("a RETRY entry is always sealed");
            match self.transport.send(&entry.to, Frame::Mote(env.det_cbor())) {
                Ok(()) => redispatched += 1,
                Err(TransportError::Unreachable) => {
                    entry.apply(OutEvent::TierUnreachable).expect("IN_FLIGHT→RETRY");
                }
            }
            self.outbound.insert(key.clone(), entry);
        }
        self.checkpoint(); // attempts/state advanced — persist the new queue state.
        redispatched
    }

    /// Check every non-terminal entry against the deadline, expiring those past it (§16.1). Uses
    /// the injected clock; returns the ids that transitioned to `EXPIRED`.
    pub fn tick_deadlines(&mut self) -> Vec<ContentId> {
        let mut expired = Vec::new();
        for entry in self.outbound.values_mut() {
            if entry.deadline_passed(self.now) {
                entry.apply(OutEvent::DeadlineExceeded).expect("→EXPIRED");
                expired.push(entry.id.clone());
            }
        }
        if !expired.is_empty() {
            self.checkpoint(); // some entries reached the EXPIRED terminal — persist it.
        }
        expired
    }

    // --- receiving (§19.3, §20.2) -----------------------------------------------------------

    /// Drain the transport and process every inbound frame: MOTEs run the §2.7 pipeline (and are
    /// acked when eligible), acks advance the matching outbound entry (§20.1). Returns the list of
    /// inbound MOTE dispositions for inspection/testing (acks produce no entry here).
    pub fn poll(&mut self) -> Vec<InboundOutcome> {
        let mut outcomes = Vec::new();
        for (from, frame) in self.transport.drain() {
            match frame {
                Frame::Mote(bytes) => outcomes.push(self.receive_mote(&from, &bytes)),
                Frame::Ack(id) => self.receive_ack(&id),
            }
        }
        outcomes
    }

    /// Consume an `ack(id)`: advance the tracked outbound entry to `ACKED`, or apply a late ack to
    /// an already-`EXPIRED` one, or ignore it (idempotent, §19.3.2). Unknown ids are ignored.
    pub fn receive_ack(&mut self, id: &[u8]) {
        if let Some(entry) = self.outbound.get_mut(id) {
            let ev = match entry.state {
                OutState::InFlight | OutState::Retry | OutState::Acked => OutEvent::AckReceived,
                OutState::Expired => OutEvent::LateAck,
                // An ack before we ever dispatched is anomalous (a buggy/forging relay); ignore it
                // rather than force an undefined transition.
                OutState::Sealed | OutState::Queued => return,
            };
            let _ = entry.apply(ev);
            self.checkpoint(); // ACKED/late-ack state change — persist it.
        }
    }

    /// The recipient-side §2.7 pipeline for one received envelope, with node-level dedup (§2.6)
    /// and ack (§19.3.2) wrapped around the shared [`validate`] core. `from` is the transport
    /// return path (used to route the ack and as the cheap pre-decryption sender hint).
    pub fn receive_mote(&mut self, from: &[u8], bytes: &[u8]) -> InboundOutcome {
        // §20.2 RECEIVED: decode the envelope. Malformed input is dropped silently (no ack).
        let env = match Envelope::from_det_cbor(bytes) {
            Ok(env) => env,
            Err(_) => return InboundOutcome::Dropped(DropReason::Malformed),
        };

        // §20.2 ADDR_OK → duplicate: a MOTE whose `id` we already hold is acked immediately,
        // without reprocessing (§2.6, §19.3.1 step 9). Verify the content address first (cheap)
        // so a forged `id` cannot spoof a dedup-ack for a body we never actually stored.
        if env.id.verify(&env.ciphertext) && self.seen.contains_key(env.id.as_bytes()) {
            self.send_ack(from, &env.id);
            return InboundOutcome::Duplicate { id: env.id.clone() };
        }

        // §2.7 steps 1–8, in order, cheapest-and-anonymous-first (shared core). Sender is
        // classified `known` iff its transport return path is a pinned contact (§2.7 step 5). Bind
        // the recipient context to locals (not `self`) so the accept path can take `&mut self`.
        let our_ik = self.ik.public();
        let seal_secret = *self.seal.secret();
        let sender_is_known = self.contacts.contains(from);
        let ctx = RecipientCtx { our_ik: &our_ik, seal_secret: &seal_secret, sender_is_known };
        // `ctx` borrows only these locals (not `self`), so the accept path below is free to take
        // `&mut self`; NLL ends the borrow at this call.
        let outcome = validate(&Hpke, &env, &ctx);

        match outcome {
            Ok(Outcome::Accepted(payload)) => self.accept(from, &env.id, *payload),
            Ok(Outcome::Deferred) => {
                // §2.7a / §19.3.1 step 9 / §20.2: hold in the requests area (never the inbox) but
                // do NOT ack — an unproven cold sender is not owed a receipt (acking would confirm
                // existence and falsely signal *delivered*); the sender's own retry EXPIREs. We do
                // NOT add the id to the ack-dedup `seen` set, precisely so a redelivery re-defers
                // (and stays unacked) rather than hitting the dedup-ack fast path above.
                self.store.deliver_mote(&placeholder_payload(from), REQUESTS_MAILBOX, env.ts);
                InboundOutcome::Deferred { id: env.id.clone() }
            }
            Err(e) => InboundOutcome::Dropped(drop_reason(e)),
        }
    }

    /// §2.7 step 8 (node-level) + step 9: for a pinned contact, the decrypted `Payload.from` MUST
    /// match the pin, else the message is a forgery/relay and is dropped, not acked (§19.3.1). On
    /// success, file to the inbox, record dedup, and ack.
    fn accept(&mut self, from: &[u8], id: &ContentId, payload: Payload) -> InboundOutcome {
        if self.contacts.contains(from) && payload.from != from {
            // A pinned contact's envelope whose sealed identity does not match the pin.
            return InboundOutcome::Dropped(DropReason::BadPayloadSig);
        }
        // First-contact TOFU-pin (§3.4): remember the now-revealed sender identity.
        self.contacts.insert(payload.from.clone());

        let uid = self
            .store
            .deliver_mote(&payload, "INBOX", self.now)
            .expect("INBOX always exists");
        self.seen.insert(id.as_bytes().to_vec(), from.to_vec());
        self.checkpoint(); // dedup set grew — persist so a post-restart redelivery is still re-acked.
        self.send_ack(from, id);
        InboundOutcome::Stored { id: id.clone(), uid }
    }

    /// Route an `ack(id)` back to the sender over the transport (§19.3.2). Best-effort: an ack
    /// that fails to send is absorbed by the sender's retry + our dedup (§19.3.2 failure modes).
    fn send_ack(&self, to: &[u8], id: &ContentId) {
        let _ = self.transport.send(to, Frame::Ack(id.as_bytes().to_vec()));
    }
}

/// Map a core [`MoteError`] to the node-level [`DropReason`] for the failure it represents.
fn drop_reason(e: MoteError) -> DropReason {
    match e {
        MoteError::UnknownVersion(_) | MoteError::UnsupportedSuite(_) => {
            DropReason::BadVersionOrSuite
        }
        MoteError::BadContentAddress => DropReason::BadContentAddress,
        MoteError::MissingSenderKey => DropReason::BadSenderSig,
        MoteError::NotForUs => DropReason::NotForUs,
        MoteError::DecryptFailed | MoteError::BadKey => DropReason::DecryptFailed,
        // BadSignature covers both the envelope `sender_sig` (step 3) and `Payload.sig` (step 8);
        // the core checks the envelope sig first, so map it to the payload-authenticity reason
        // only when decryption has necessarily succeeded is not distinguishable here — both are
        // "authentication failed", reported as BadPayloadSig for the caller.
        MoteError::BadSignature => DropReason::BadPayloadSig,
        // Sealing/encoding errors cannot arise from a decode+validate path, but map defensively.
        MoteError::SealFailed | MoteError::BadEncoding(_) => DropReason::Malformed,
    }
}

/// A minimal payload used only to render a requests-area preview for a deferred MOTE we did not
/// decrypt (§2.7a lets an implementation preview-or-not; we file a routing-only stub so the
/// requests count is visible to IMAP/JMAP without decrypting cold-sender content).
fn placeholder_payload(from: &[u8]) -> Payload {
    Payload {
        from: from.to_vec(),
        sig: Vec::new(),
        headers: Headers {
            subject: Some("(request — pending review)".into()),
            ..Headers::default()
        },
        body: b"A message from an unknown sender is awaiting your review.".to_vec(),
        refs: Vec::new(),
        attach: Vec::new(),
        expires: None,
    }
}

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
//! - **Real (groups, §5):** the node also holds **real MLS group sessions** (RFC 9420 via the
//!   [`dmtap_mls`] crate / `openmls`) alongside the 1:1 HPKE path — found/join a group, Add/Remove
//!   members (post-compromise security on Remove), and send/receive group application messages.
//!   Handshakes are ordered by an in-process [`Committer`] (the §5.1 DS ordering seam); group
//!   application messages ride the mesh as [`Frame::Group`]. See [`crate::group`].
//! - **Real (naming, §3):** recipient resolution is the KT-verified, fail-closed
//!   [`dmtap_naming`] resolver ([`resolve_and_pin`](Node::resolve_and_pin) /
//!   [`send_mail_to_name`](Node::send_mail_to_name)): DNS `_dmtap` → fetched `Identity` → RFC 6962
//!   inclusion/STH/leaf/quorum verification before anything is pinned — never a TOFU pin on an
//!   unreachable/sub-quorum/stale/equivocating KT (§3.3). The local `directory` is now purely the
//!   *pin cache* that verification populates; the network fetch is the `Resolver`/`KeyPackageSource`
//!   trait seam (in-memory harness where no socket layer is wired).
//! - **Real (auth, §13):** the node runs its own DMTAP-Auth login ([`login`](Node::login)) — its
//!   root `IK` signs an RP's origin-bound challenge to establish a key-bound session.
//! - **Real (deniable, §5.2.1):** an optional repudiable 1:1 channel (X3DH + Double Ratchet, shared
//!   -key-MAC) distinct from the MLS group path — see [`crate::deniable`].
//! - **Stubbed / in-process:** sender classification uses the transport return path rather than
//!   blinded tags (§2.2a); the in-tree transport is [`InMemoryNetwork`] (the real libp2p mesh lives
//!   in the separate `dmtap-p2p` crate, selectable through the [`Transport`] seam); the group
//!   committer is a single in-process ordered log (real mesh committer succession/takeover/
//!   fork-recovery of §5.1 is out of scope); timers are event-driven off an injected clock.
//!
//! [`IdentityKey`]: dmtap_core::identity::IdentityKey
//! [`SealKeypair`]: dmtap_core::mote::SealKeypair
//! [`InMemoryNetwork`]: crate::transport::InMemoryNetwork

use std::collections::{BTreeSet, HashMap, HashSet};

use dmtap_core::identity::IdentityKey;
use dmtap_core::mote::{
    build_mote, validate_pinned, Envelope, Headers, Hpke, Kind, MoteDraft, MoteError, Outcome,
    Payload, RecipientCtx, SealKeypair, ValidateError,
};
use dmtap_core::suite::SuiteRatchet;
use dmtap_core::{ContentId, Suite, TimestampMs};
use dmtap_mail::store::{MailStore, Mailbox, MemoryStore};
use dmtap_mls::{Committer, Member, Session};

use dmtap_core::deniable::{DeniableMessage, DeniablePayload};

use crate::auth::{Challenge, Login, TrustedClient};
use crate::deniable::{
    self, CertifiedBundle, CertifiedInit, DeniableAcceptLimits, DeniableAdmission,
    DeniableRouteError, DeniableState, DEFAULT_OPKS,
};
use crate::group::{GroupAdd, GroupError, GroupMote};
use crate::inbound::{DropReason, InboundOutcome};
use crate::journal::{
    Journal, JournalError, NullJournal, PersistedEntry, PersistedSuiteMark, Snapshot,
};
use crate::mixdir::{MixDirError, MixDirectoryTracker};
use crate::naming::{self, classify, AddressError, KeyPackageSource, NameForm, Resolver};
use crate::outbound::{OutEvent, OutState, OutboundEntry};
use crate::transport::{Frame, Transport, TransportError};
use dmtap_auth::AuthError;
use dmtap_core::mixnet::MixDirectory;

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
    /// The X25519 KEM **secret** correspondents' payloads are sealed to (§5.3). Stored as raw bytes
    /// (rather than a [`SealKeypair`]) so a persisted sealing key can be reloaded on daemon restart:
    /// the reference [`SealKeypair`] exposes no `from_secret` constructor, but the HPKE open path
    /// (via [`RecipientCtx`]) consumes the secret as `&[u8; 32]` regardless — so raw bytes are the
    /// faithful, round-trippable representation the durable keystore persists (§1.2 identity durability).
    seal_secret: [u8; 32],
    /// The matching X25519 **public** sealing key (advertised via KeyPackages, §5.3) — the value
    /// peers seal to and the node publishes in its `_dmtap` record / KeyPackage bundle.
    seal_public: [u8; 32],
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
    /// This node's live MLS group sessions (spec §5), keyed by group id. Each is this node's own
    /// leaf's view of a real RFC 9420 group; membership/handshakes are ordered by a [`Committer`].
    groups: HashMap<Vec<u8>, Session>,
    /// A pre-published MLS leaf ([`Member`]) awaiting a Welcome to join a group (§5.3 async join).
    /// Provisioned by [`Node::publish_group_keypackage`], consumed by [`Node::join_group`].
    pending_leaf: Option<Member>,
    /// The deniable 1:1 subsystem (spec §5.2.1): a dedicated deniable identity, an optional
    /// responder half, and live pairwise ratchet sessions — distinct from the MLS group path.
    deniable: DeniableState,
    /// The inbound deniable-init admission gate (audit #4): a per-source + global token bucket that
    /// throttles unsolicited [`CertifiedInit`]s **before** an X3DH one-time prekey is consumed, so an
    /// attacker cannot cheaply deplete the OPK pool and force the weak last-resort prekey (§5.2.1).
    deniable_admission: DeniableAdmission,
    /// Per-contact suite **high-water-mark ratchet** (§1.3, §2.7 step 8, §10.7.1): the highest
    /// `Envelope.suite` accepted from each authenticated sender. [`receive_mote`](Node::receive_mote)
    /// feeds it via [`validate_pinned`], so an on-the-wire suite downgrade is rejected *at the node*.
    suite_ratchet: SuiteRatchet,
    /// The set of contacts the [`suite_ratchet`](Self::suite_ratchet) holds a high-water-mark for
    /// (their `Payload.from` keys). The ratchet itself exposes no iteration, so the node tracks the
    /// keyset here to enumerate the marks when [`snapshot`](Self::snapshot)ing them for the journal;
    /// restored alongside the marks so persistence round-trips (§1.3, §2.7 step 8).
    suite_contacts: BTreeSet<Vec<u8>>,
    /// Per-authority mix-directory anti-rollback tracker (§4.4.2, §18.5.3): the monotonic
    /// `(epoch, version)` high-water-mark that rejects a replayed/stale mix-fleet snapshot at the node.
    mix_directory: MixDirectoryTracker,
    /// Inbound group **application** MOTEs pulled off the transport by [`Node::poll`], buffered for
    /// [`Node::poll_group_messages`] to decrypt — kept off the 1:1 outcome path so the 1:1
    /// pipeline is untouched. Each entry is the `(group_id, encoded GroupMote)` from a
    /// [`Frame::Group`].
    group_inbox: Vec<(Vec<u8>, Vec<u8>)>,
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
        Self::bare(ik, *seal.secret(), *seal.public(), transport, Box::new(NullJournal))
    }

    /// The common field initializer shared by every constructor: a node with the given identity +
    /// raw sealing key bytes over `transport`, backed by `journal`, with all delivery/anti-abuse
    /// state fresh. Callers that resume from a journal restore that state afterwards.
    fn bare(
        ik: IdentityKey,
        seal_secret: [u8; 32],
        seal_public: [u8; 32],
        transport: T,
        journal: Box<dyn Journal>,
    ) -> Self {
        Node {
            ik,
            seal_secret,
            seal_public,
            store: MemoryStore::new(),
            seen: HashMap::new(),
            outbound: HashMap::new(),
            contacts: HashSet::new(),
            directory: HashMap::new(),
            groups: HashMap::new(),
            pending_leaf: None,
            deniable: DeniableState::default(),
            deniable_admission: DeniableAdmission::new(
                DeniableAcceptLimits::default(),
                1_700_000_000_000,
            ),
            suite_ratchet: SuiteRatchet::new(),
            suite_contacts: BTreeSet::new(),
            mix_directory: MixDirectoryTracker::new(),
            group_inbox: Vec::new(),
            transport,
            now: 1_700_000_000_000,
            journal,
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
        Self::with_journal_bytes(ik, *seal.secret(), *seal.public(), transport, journal)
    }

    /// Like [`with_journal`](Self::with_journal) but taking the sealing keypair as **raw bytes** —
    /// the constructor the daemon uses to rebuild a node from a persisted keystore (the reference
    /// [`SealKeypair`] has no `from_secret`, and the node only ever needs the secret/public bytes:
    /// the secret for the HPKE open path, the public to advertise). `seal_public` MUST be the
    /// X25519 public derived from `seal_secret` (the keystore persists both, captured at generation).
    pub fn with_journal_bytes(
        ik: IdentityKey,
        seal_secret: [u8; 32],
        seal_public: [u8; 32],
        transport: T,
        journal: Box<dyn Journal>,
    ) -> Result<Self, JournalError> {
        let snapshot = journal.load()?;
        let mut node = Self::bare(ik, seal_secret, seal_public, transport, journal);
        for pe in snapshot.outbound {
            let entry = pe.into_entry()?;
            node.outbound.insert(entry.id.as_bytes().to_vec(), entry);
        }
        for (id, from) in snapshot.seen {
            node.seen.insert(id, from);
        }
        // Restore the per-contact suite high-water-marks (§1.3, §2.7 step 8), fail-closed on a bad
        // suite byte. A restored mark is authoritative: `observe` re-establishes the floor so a
        // post-restart downgrade below it is still rejected (never re-pinned on first contact).
        for mark in snapshot.suite_marks {
            let (contact, suite) = mark.into_mark()?;
            node.suite_ratchet.observe(&contact, suite);
            node.suite_contacts.insert(contact);
        }
        // Restore the per-authority mix-directory high-water-marks (§4.4.2, §18.5.3) by re-verifying
        // and re-ingesting each persisted directory into the fresh tracker. Fail-closed: a directory
        // that no longer decodes/verifies is corruption and is refused, not silently dropped — the
        // mark it stood for is not defaulted away.
        for dir_cbor in snapshot.mix_directories {
            node.mix_directory.ingest(&dir_cbor).map_err(|e| {
                JournalError::Corrupt(match e {
                    MixDirError::Malformed => "persisted mix directory is malformed",
                    MixDirError::Unverified => "persisted mix directory failed authority verification",
                    // A fresh tracker has no pinned mark, so a persisted dir cannot be Stale; treat
                    // an unexpected rollback as corruption too rather than silently accepting.
                    MixDirError::Stale { .. } => "persisted mix directory is internally inconsistent",
                })
            })?;
        }
        // Restore the deniable-init admission token buckets (audit #4, §5.2.1) verbatim, so a restart
        // does not refill the anti-abuse gate to a fresh full burst against the OPK pool.
        if let Some(gate) = snapshot.deniable_admission {
            node.deniable_admission = DeniableAdmission::restore(gate);
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
        self.seal_public
    }

    /// This node's **key-derived legacy gateway alias** local-part (§3.9, §7) — a stateless,
    /// registration-free address for legacy SMTP↔DMTAP bridging. It is a pure function of the
    /// identity key ([`naming::gateway_alias_local`]), so it is identical at every gateway and any
    /// gateway can decode it straight back to this node's key ([`naming::ik_from_gateway_alias`])
    /// with no directory lookup. Combined with a gateway's domain it forms a full legacy address,
    /// e.g. `dmtap1-…@gateway.example`.
    pub fn gateway_alias(&self) -> String {
        naming::gateway_alias_local(&self.ik.public())
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

    // --- name → key resolution (spec §3.3) --------------------------------------------------

    /// Resolve `name@domain` to a **KT-verified, pinned** recipient and cache the binding, the real
    /// §3.3 path that replaces any hardcoded/stub lookup before addressing outbound mail.
    ///
    /// The `resolver` runs the full fail-closed verification (DNS `_dmtap` parse → fetched
    /// `Identity` signature/chain → DNS⇄Identity cross-check → RFC 6962 inclusion/STH/leaf-hash +
    /// v1 quorum/freshness/equivocation gates). **Only** on a verified binding does this fetch the
    /// recipient's content-addressed sealing KeyPackage (via `kps`) and pin `name → (ik, seal)` into
    /// the node's contact/directory cache. An unverifiable KT (unreachable / sub-quorum / stale /
    /// equivocating / proof-invalid) returns the typed [`ResolveError`](crate::naming::ResolveError)
    /// and pins **nothing** — never a TOFU pin on unverifiable KT (§3.3). Returns the verified IK.
    pub fn resolve_and_pin(
        &mut self,
        name: &str,
        resolver: &dyn Resolver,
        kps: &dyn KeyPackageSource,
    ) -> Result<Vec<u8>, crate::naming::ResolveError> {
        // Route the name by its FORM (§3.9): `local@domain` → the wired DNS+KT resolver; a
        // self-authenticating key-name (§3.9.1) → the *derive* resolver; `name.eth`/`name.sol` →
        // the on-chain name registry. Only the DNS form has a networked resolver wired today, so the
        // other two are routed to their documented seams and **fail closed** (never a silent accept)
        // — the per-form resolvers ([`KeyNameResolver`]/[`NameChainResolver`]) drop into this match
        // once `dmtap-naming` exposes them.
        match classify(name)? {
            NameForm::Dns => {}
            NameForm::KeyName => {
                return Err(crate::naming::ResolveError::NameResolution(
                    "key-name (derive) resolver not wired — fail closed (§3.9.1 seam)",
                ));
            }
            NameForm::NameChain(_) => {
                return Err(crate::naming::ResolveError::NameResolution(
                    "name-chain (.eth/.sol) resolver not wired — fail closed (§3.9 seam)",
                ));
            }
        }
        // KT-verify the binding (fail-closed) BEFORE trusting anything about the recipient (§3.3).
        let res = resolver.resolve(name)?;
        // Fetch + content-verify (§2.2) the sealing KeyPackage the verified identity advertises.
        let bundle = kps.fetch_bundle(&res.keypkgs)?;
        let seal_pub = naming::seal_key_from_bundle(&bundle)?;
        // Pin the verified binding into the local cache (§3.4): only now is it addressable.
        self.add_contact(&res.ik, seal_pub);
        Ok(res.ik)
    }

    /// Resolve `name@domain` KT-verified (fail-closed, §3.3) and, only on success, send a mail MOTE
    /// to the resolved key. The one-call name-addressed send: resolution and sealing failures are
    /// kept distinguishable via [`AddressError`](crate::naming::AddressError).
    pub fn send_mail_to_name(
        &mut self,
        name: &str,
        resolver: &dyn Resolver,
        kps: &dyn KeyPackageSource,
        subject: &str,
        body: &[u8],
    ) -> Result<ContentId, AddressError> {
        let to_ik = self.resolve_and_pin(name, resolver, kps)?;
        Ok(self.send_mail(&to_ik, subject, body)?)
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

    /// The current durable state as a serializable [`Snapshot`]: the outbound queue + dedup set
    /// (§19.3.3) plus the security-critical high-water-marks — the per-contact suite floors (§1.3,
    /// §2.7 step 8), the per-authority mix-directory `(epoch, version)` marks (§4.4.2, §18.5.3), and
    /// the deniable-init admission buckets (§5.2.1). Persisting the marks keeps the downgrade/rollback
    /// defenses authoritative across a restart instead of re-pinning on first contact.
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            outbound: self.outbound.values().map(PersistedEntry::from_entry).collect(),
            seen: self.seen.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            suite_marks: self
                .suite_contacts
                .iter()
                .filter_map(|contact| {
                    self.suite_ratchet
                        .high_water_mark(contact)
                        .map(|suite| PersistedSuiteMark { contact: contact.clone(), suite: suite.as_u8() })
                })
                .collect(),
            mix_directories: self
                .mix_directory
                .latest_directories()
                .map(|d| d.det_cbor())
                .collect(),
            deniable_admission: Some(self.deniable_admission.snapshot()),
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

    /// The number of MOTEs currently tracked in the outbound retry queue (§20.1) — how many pending
    /// sends a restarted daemon resumed from its durable journal (§19.3.3).
    pub fn outbound_len(&self) -> usize {
        self.outbound.len()
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
                // A group application MOTE (§5): buffer it for `poll_group_messages` to decrypt,
                // keeping the 1:1 outcome list clean. (Group handshakes never arrive here — they
                // travel the ordered committer log, not the mesh, §5.1.)
                Frame::Group { group_id, body } => self.group_inbox.push((group_id, body)),
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
        let seal_secret = self.seal_secret;
        let sender_is_known = self.contacts.contains(from);
        let ctx = RecipientCtx { our_ik: &our_ik, seal_secret: &seal_secret, sender_is_known };
        // `ctx` borrows only these locals (not `self`), so the accept path below is free to take
        // `&mut self`; NLL ends the borrow at this call. The per-contact `suite_ratchet` enforces the
        // §2.7 step 8 / §10.7.1 suite high-water-mark: an authenticated sender's `Envelope.suite` may
        // never drop below the highest we have accepted from them (a downgrade), and each accept
        // ratchets that mark up. The mutable ratchet borrow also ends at this call (the returned
        // outcome holds no reference to it), so the `&mut self` accept path below is unaffected.
        let outcome = validate_pinned(&Hpke, &env, &ctx, Some(&mut self.suite_ratchet));

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
            Err(ValidateError::Suite(_)) => {
                // §2.7 step 8 / §10.7.1 / §21.3 (0x020F): the object authenticated but asserts a suite
                // *below* this contact's established high-water-mark — a downgrade. Disposition is
                // DEFER_REQUESTS (§21.3): hold in the requests area, never the inbox, and do NOT ack
                // (acking would signal *delivered*). `validate_pinned` guarantees the mark is NOT
                // ratcheted down. Not added to `seen`, so a redelivery re-defers rather than fast-ack.
                self.store.deliver_mote(&placeholder_payload(from), REQUESTS_MAILBOX, env.ts);
                InboundOutcome::Deferred { id: env.id.clone() }
            }
            Err(ValidateError::Mote(e)) => InboundOutcome::Dropped(drop_reason(e)),
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
        // `validate_pinned` just ratcheted this sender's suite high-water-mark up (§2.7 step 8);
        // record the keyset entry so the mark is enumerated into the durable snapshot below.
        self.suite_contacts.insert(payload.from.clone());

        let uid = self
            .store
            .deliver_mote(&payload, "INBOX", self.now)
            .expect("INBOX always exists");
        self.seen.insert(id.as_bytes().to_vec(), from.to_vec());
        // dedup set grew and the suite mark advanced — persist so a post-restart redelivery is still
        // re-acked and a post-restart downgrade below this sender's mark is still rejected.
        self.checkpoint();
        self.send_ack(from, id);
        InboundOutcome::Stored { id: id.clone(), uid }
    }

    /// Route an `ack(id)` back to the sender over the transport (§19.3.2). Best-effort: an ack
    /// that fails to send is absorbed by the sender's retry + our dedup (§19.3.2 failure modes).
    fn send_ack(&self, to: &[u8], id: &ContentId) {
        let _ = self.transport.send(to, Frame::Ack(id.as_bytes().to_vec()));
    }

    // --- MLS groups (spec §5) ---------------------------------------------------------------
    //
    // Real RFC 9420 group sessions via `dmtap_mls`/`openmls`, alongside the 1:1 HPKE path above.
    // Each of this node's leaves is credentialed as `ik_public ‖ "#" ‖ device_label`, binding the
    // MLS leaf to this node's DMTAP identity (§5.6). Handshakes are ordered by the caller-supplied
    // [`Committer`] (the §5.1 DS ordering seam); application messages ride the mesh transport.

    /// The label this node uses for its own MLS leaf. Single-leaf-per-node in the reference model;
    /// the multi-device cluster (multiple leaves per owner, §5.6) is exercised in `dmtap-mls`.
    fn group_device_label() -> &'static str {
        "node"
    }

    /// Pre-publish a signed **KeyPackage** for this node so a group initiator can **Add** it while
    /// offline (spec §5.3 async join). Retains the provisioned leaf ([`Member`]) so a later
    /// [`join_group`](Self::join_group) uses the *same* key material. Returns the KeyPackage wire
    /// bytes to hand (out of band / via naming) to the initiator.
    pub fn publish_group_keypackage(&mut self) -> Result<Vec<u8>, GroupError> {
        let member = Member::new(self.ik.public(), Self::group_device_label())?;
        let kp = member.publish_key_package()?;
        self.pending_leaf = Some(member);
        Ok(kp)
    }

    /// Found a **new MLS group** `group_id` with this node as the initial member/committer (§5.1).
    pub fn found_group(&mut self, group_id: &[u8]) -> Result<(), GroupError> {
        let member = Member::new(self.ik.public(), Self::group_device_label())?;
        let session = member.create_group(group_id)?;
        self.groups.insert(group_id.to_vec(), session);
        Ok(())
    }

    /// **Add** the member whose published KeyPackage is `kp_bytes` to `group_id` (spec §5.3): build
    /// the Add **Commit** + **Welcome**, order the Commit through `committer` (the DS), and apply it
    /// to this node's own view. Returns the [`GroupAdd`] (the `group_event` MOTE, the Welcome to
    /// hand the joiner, and the committer sequence). Other existing members catch up via
    /// [`apply_committed`](Self::apply_committed).
    pub fn group_add_member(
        &mut self,
        group_id: &[u8],
        kp_bytes: &[u8],
        committer: &mut Committer,
    ) -> Result<GroupAdd, GroupError> {
        let session = self.groups.get_mut(group_id).ok_or(GroupError::UnknownGroup)?;
        let hs = session.add_member(kp_bytes)?;
        let commit = hs.commit.clone();
        let welcome = hs.welcome.clone().ok_or(GroupError::Malformed)?;
        let seq = committer.submit(hs);
        session.note_authored(seq);
        session.advance(committer)?;
        let event = GroupMote {
            group_id: group_id.to_vec(),
            kind: Kind::GroupEvent,
            epoch: session.epoch(),
            body: commit,
        };
        Ok(GroupAdd { event, welcome, seq })
    }

    /// **Remove** the member at `leaf_index` from `group_id` (spec §5.8.2): build + order the Remove
    /// **Commit** and apply it here. After every member advances, MLS's TreeKEM has re-keyed, so the
    /// removed leaf's key opens nothing in the new epoch (post-compromise security, §5.2). Returns
    /// the `group_event` MOTE.
    pub fn group_remove_member(
        &mut self,
        group_id: &[u8],
        leaf_index: u32,
        committer: &mut Committer,
    ) -> Result<GroupMote, GroupError> {
        let session = self.groups.get_mut(group_id).ok_or(GroupError::UnknownGroup)?;
        let hs = session.remove_member(leaf_index)?;
        let commit = hs.commit.clone();
        let seq = committer.submit(hs);
        session.note_authored(seq);
        session.advance(committer)?;
        let _ = seq;
        Ok(GroupMote {
            group_id: group_id.to_vec(),
            kind: Kind::GroupEvent,
            epoch: session.epoch(),
            body: commit,
        })
    }

    /// **Advance** this node's view of `group_id` along the committer's ordered log, applying every
    /// handshake it has not yet applied (spec §5.1). Returns the number newly applied. This is how
    /// a member that did not author a Commit catches up to the current epoch.
    pub fn apply_committed(
        &mut self,
        group_id: &[u8],
        committer: &Committer,
    ) -> Result<usize, GroupError> {
        let session = self.groups.get_mut(group_id).ok_or(GroupError::UnknownGroup)?;
        Ok(session.advance(committer)?)
    }

    /// **Join** `group_id` from a `welcome_bytes` produced by an Add (spec §5.3), consuming the leaf
    /// pre-published by [`publish_group_keypackage`](Self::publish_group_keypackage). The new view's
    /// committer baseline is set to the log head, so it applies only Commits ordered after it joined.
    pub fn join_group(
        &mut self,
        group_id: &[u8],
        welcome_bytes: &[u8],
        committer: &Committer,
    ) -> Result<(), GroupError> {
        let member = self.pending_leaf.take().ok_or(GroupError::NoPendingLeaf)?;
        let mut session = member.join_from_welcome(welcome_bytes)?;
        session.note_joined_at(committer.head());
        self.groups.insert(group_id.to_vec(), session);
        Ok(())
    }

    /// Encrypt `plaintext` as an MLS **application message** for `group_id` (spec §5.4), returning
    /// the `group_event`-sibling content MOTE (kind `chat`) to route over the mesh. See
    /// [`group_broadcast`](Self::group_broadcast) to also fan it out to members over the transport.
    pub fn group_send(
        &mut self,
        group_id: &[u8],
        plaintext: &[u8],
    ) -> Result<GroupMote, GroupError> {
        let session = self.groups.get_mut(group_id).ok_or(GroupError::UnknownGroup)?;
        let body = session.create_message(plaintext)?;
        Ok(GroupMote { group_id: group_id.to_vec(), kind: Kind::Chat, epoch: session.epoch(), body })
    }

    /// Encrypt `plaintext` for `group_id` and **fan it out** to every other member over the mesh
    /// transport as a [`Frame::Group`] (spec §5.4/§5.8.4). Members' transport addresses are their
    /// owner identity bytes (the in-process addressing model); this node itself is skipped. Returns
    /// how many members it was dispatched to (best-effort per §20.1; unreachable members are not
    /// retried here).
    pub fn group_broadcast(
        &mut self,
        group_id: &[u8],
        plaintext: &[u8],
    ) -> Result<usize, GroupError> {
        let mote = self.group_send(group_id, plaintext)?;
        let frame_body = mote.encode();
        let me = self.ik.public();
        // Collect distinct member owner addresses (a multi-device owner maps many leaves → one
        // address here), excluding ourselves, before borrowing the transport.
        let session = self.groups.get(group_id).ok_or(GroupError::UnknownGroup)?;
        let mut targets: Vec<Vec<u8>> = Vec::new();
        for (_, leaf_id) in session.roster() {
            let owner = Member::owner_of_identity(&leaf_id).to_vec();
            if owner != me && !targets.contains(&owner) {
                targets.push(owner);
            }
        }
        let mut sent = 0;
        for to in &targets {
            if self
                .transport
                .send(to, Frame::Group { group_id: group_id.to_vec(), body: frame_body.clone() })
                .is_ok()
            {
                sent += 1;
            }
        }
        Ok(sent)
    }

    /// Drain group **application** MOTEs buffered by [`poll`](Self::poll) and decrypt each against
    /// its group session (spec §5.4). Returns `(group_id, plaintext-or-error)` per message. A
    /// decrypt error is surfaced, not swallowed — e.g. a message from an epoch this node was
    /// removed from cannot be read (post-compromise security, §5.2).
    #[allow(clippy::type_complexity)]
    pub fn poll_group_messages(&mut self) -> Vec<(Vec<u8>, Result<Vec<u8>, GroupError>)> {
        let inbox = std::mem::take(&mut self.group_inbox);
        let mut out = Vec::with_capacity(inbox.len());
        for (group_id, body) in inbox {
            let result = self.decrypt_group_frame(&group_id, &body);
            out.push((group_id, result));
        }
        out
    }

    /// Decode one [`Frame::Group`] body into a [`GroupMote`] and decrypt its application ciphertext
    /// against the named group session. Fails closed on a malformed frame, an unknown group, a
    /// non-application kind, or an MLS decrypt failure.
    fn decrypt_group_frame(&mut self, group_id: &[u8], body: &[u8]) -> Result<Vec<u8>, GroupError> {
        let mote = GroupMote::decode(body)?;
        if mote.kind == Kind::GroupEvent {
            // Handshakes are ordered via the committer, never decrypted off the mesh (§5.1).
            return Err(GroupError::Malformed);
        }
        let session = self.groups.get_mut(group_id).ok_or(GroupError::UnknownGroup)?;
        Ok(session.receive_message(&mote.body)?)
    }

    /// The current MLS **epoch** of `group_id` on this node (§5.2), or `None` if not a member.
    pub fn group_epoch(&self, group_id: &[u8]) -> Option<u64> {
        self.groups.get(group_id).map(|s| s.epoch())
    }

    /// This node's own leaf index in `group_id` (for addressing a Remove, §5.8.2).
    pub fn group_leaf_index(&self, group_id: &[u8]) -> Option<u32> {
        self.groups.get(group_id).map(|s| s.own_leaf_index())
    }

    /// The roster of `group_id` as `(leaf_index, leaf_identity)` pairs (§5.8) — `leaf_identity` is
    /// `ik_public ‖ "#" ‖ label`; use `Member::owner_of_identity` to map a leaf to its owner.
    pub fn group_roster(&self, group_id: &[u8]) -> Option<Vec<(u32, Vec<u8>)>> {
        self.groups.get(group_id).map(|s| s.roster())
    }

    // --- DMTAP-Auth: the node's own login/session (spec §13) --------------------------------

    /// Run the **client side** of the native login ceremony (§13.3): the node's root `IK` is the
    /// identity-revealing login signer over the RP's origin-bound `challenge`. The `client` (a
    /// WebAuthn/PRF authenticator or paired companion, [`TrustedClient`]) enforces origin binding
    /// against the machine-observed origin and gates signing on user-verification (§13.3.1) — the
    /// crypto core never trusts an origin handed to it by the RP. Returns the [`Login`]: the signed
    /// assertion to transmit plus the retained per-RP session key for DPoP-style proof-of-possession
    /// on every subsequent request (§13.4). Fails closed on an origin mismatch or declined UV.
    pub fn login(
        &self,
        client: &impl TrustedClient,
        challenge: &Challenge,
    ) -> Result<Login, AuthError> {
        dmtap_auth::create_login(client, challenge, &self.ik)
    }

    // --- deniable 1:1 messaging (spec §5.2.1) -----------------------------------------------
    //
    // A repudiable pairwise channel — X3DH over a dedicated IK-certified `idk`, then a Double
    // Ratchet whose only authentication is the AEAD tag (shared-key MAC). Distinct from the MLS
    // group path above: no committer, no epoch log. See [`crate::deniable`].

    /// Publish this node's deniable **prekey bundle** so a peer can open a deniable 1:1 session to
    /// it (§5.2.1): provisions the responder half (a dedicated deniable identity + one-time prekeys)
    /// and returns a [`CertifiedBundle`] to advertise — the signed [`DeniablePrekeyBundle`](dmtap_core::deniable::DeniablePrekeyBundle) plus a
    /// root-IK [`DeviceCert`](dmtap_core::identity::DeviceCert) binding the bundle's dedicated deniable identity key to this node's
    /// root identity (§5.2.1(a), §1.2). A peer verifies that cert against this node's KT-resolved
    /// root IK before trusting the bundle. Uses [`DEFAULT_OPKS`] one-time prekeys and the node's
    /// injected clock for the bundle timestamp and the cert `created`.
    pub fn deniable_publish_bundle(&mut self) -> CertifiedBundle {
        let bundle = self.deniable.publish_bundle(DEFAULT_OPKS, 1, self.now);
        let cert = deniable::issue_deniable_binding(&self.ik, &bundle.ik, self.now);
        CertifiedBundle { bundle, cert }
    }

    /// **Initiator:** open a deniable 1:1 session to the peer described by `peer` (their advertised
    /// [`CertifiedBundle`]), routing `first` (a [`DeniablePayload`] — a MOTE with its signature
    /// removed, §18.3.10) as the embedded first ratchet message.
    ///
    /// `peer_root_ik` is the peer's **KT-resolved root identity key** (e.g. from
    /// [`resolve_and_pin`](Self::resolve_and_pin)). Before running X3DH this fails closed unless the
    /// bundle's [`DeviceCert`](dmtap_core::identity::DeviceCert) binds `peer.bundle.ik` to `peer_root_ik` (§5.2.1(a), §1.2) — so a
    /// session is never established with a deniable prekey the peer's identity has not vouched for.
    ///
    /// Returns a [`CertifiedInit`]: the [`DeniableInit`](dmtap_core::deniable::DeniableInit) to hand to the peer plus *this* node's
    /// root-IK cert over its own deniable identity key, which the peer verifies symmetrically. The
    /// live session is retained, keyed by the peer's deniable IK.
    pub fn deniable_open(
        &mut self,
        peer_root_ik: &[u8],
        peer: &CertifiedBundle,
        first: &DeniablePayload,
    ) -> Result<CertifiedInit, DeniableRouteError> {
        deniable::verify_deniable_binding(peer_root_ik, &peer.bundle.ik, &peer.cert)?;
        let init = self.deniable.open(&peer.bundle, first)?;
        let cert = deniable::issue_deniable_binding(&self.ik, &init.ik_a, self.now);
        Ok(CertifiedInit { init, cert })
    }

    /// **Responder:** accept an incoming [`CertifiedInit`], establishing the session and decrypting
    /// its embedded first payload (§5.2.1(a)). Requires a prior
    /// [`deniable_publish_bundle`](Self::deniable_publish_bundle).
    ///
    /// `peer_root_ik` is the initiator's **KT-resolved root identity key**. Before touching any
    /// prekey this fails closed unless the init's [`DeviceCert`](dmtap_core::identity::DeviceCert) binds `init.ik_a` to `peer_root_ik`
    /// (§5.2.1(a), §1.2). It then also fails closed on a bad `idk` certification, a consumed/absent
    /// prekey, or a replayed last-resort init.
    pub fn deniable_accept(
        &mut self,
        peer_root_ik: &[u8],
        certified: &CertifiedInit,
    ) -> Result<DeniablePayload, DeniableRouteError> {
        deniable::verify_deniable_binding(peer_root_ik, &certified.init.ik_a, &certified.cert)?;
        // Audit #4 — OPK-depletion gate. The `idk_a_cert` chain verified above is *self-signable*
        // (an attacker mints their own root IK + deniable IK), so cert-verification alone does not
        // make an init trustworthy — it only proves who the deniable key claims to be. X3DH `accept`
        // then consumes a one-time prekey *before* the ratchet MAC can authenticate the init, so an
        // unsolicited flood would burn the OPK pool and force the weak last-resort prekey. Throttle
        // (per-source + global token bucket) BEFORE touching a prekey; a genuine init retried after
        // the bucket refills still succeeds. Keyed on the claimed root IK; the global bucket is what
        // bounds a Sybil flood of throwaway identities.
        let admitted = self.deniable_admission.admit(peer_root_ik, self.now);
        if !admitted {
            // Rejected path — do NOT checkpoint. The only mutation here is deterministic bucket
            // bookkeeping (a clock-keyed refill/prune plus a lazy per-source entry), all recomputable
            // at the next `admit`, so dropping it fails safe. Persisting per rejected init would let a
            // cheap flood of self-signed `CertifiedInit`s force a full-node-Snapshot disk write each
            // (outbound queue, seen-set, every mix directory re-encoded, admission buckets) — an
            // I/O+CPU amplification the OPK/rate gate never covered (audit #4).
            return Err(DeniableRouteError::RateLimited);
        }
        let payload = self.deniable.accept(&certified.init)?;
        // Admitted *and* accepted — the path an attacker cannot cheaply spam (bounded by the global
        // burst). Persist here so the drained admission token survives a restart rather than
        // refilling to a fresh full burst against the OPK pool (audit #4).
        self.checkpoint();
        Ok(payload)
    }

    /// Reconfigure the inbound deniable-init admission gate (audit #4 OPK-depletion defense),
    /// reseeding its token buckets full at the node's current clock. The defaults
    /// ([`DeniableAcceptLimits::default`]) already keep an unsolicited burst below the published OPK
    /// count; this is for callers/tests that want an explicit policy.
    pub fn configure_deniable_accept_gate(&mut self, limits: DeniableAcceptLimits) {
        self.deniable_admission.configure(limits, self.now);
        self.checkpoint(); // the gate's policy + bucket state changed — persist it.
    }

    /// The number of unspent one-time prekeys remaining in this node's published deniable bundle, or
    /// `None` if none has been published. The admission gate exists to keep this above zero under an
    /// unsolicited-init flood (so the weak last-resort prekey is never forced, §5.2.1).
    pub fn deniable_opks_remaining(&self) -> Option<usize> {
        self.deniable.opks_remaining()
    }

    /// Seal `payload` into a [`DeniableMessage`] on the live deniable session with `peer_ik`
    /// (§5.2.1(b)). The message carries no signature — the ratchet's AEAD tag is the only
    /// authenticator (the property that makes the transcript repudiable).
    pub fn deniable_send(
        &mut self,
        peer_ik: &[u8],
        payload: &DeniablePayload,
    ) -> Result<DeniableMessage, DeniableRouteError> {
        self.deniable.send(peer_ik, payload)
    }

    /// Open a [`DeniableMessage`] back into a [`DeniablePayload`] on the deniable session with
    /// `peer_ik`. A tampered header/ciphertext, a wrong key, or a rewound (already-consumed)
    /// message fails closed (§5.2.1).
    pub fn deniable_recv(
        &mut self,
        peer_ik: &[u8],
        msg: &DeniableMessage,
    ) -> Result<DeniablePayload, DeniableRouteError> {
        self.deniable.recv(peer_ik, msg)
    }

    /// This node's initiator deniable identity public key, once one has been provisioned (by opening
    /// a session). Peers key their side of the session by this value (§5.2.1).
    pub fn deniable_identity_public(&self) -> Option<Vec<u8>> {
        self.deniable.identity_public()
    }

    /// Snapshot the live deniable session with `peer_ik` — the constructive-repudiation
    /// demonstration surface (§5.2.1(e)). From the snapshot a recipient can forge a peer-authored
    /// message with no signing key, proving the IK-certification binds the *key* to the identity
    /// without making message *content* non-repudiable. Returns `None` if no session exists.
    pub fn deniable_session_snapshot(
        &self,
        peer_ik: &[u8],
    ) -> Option<dmtap_deniable::DeniableSession> {
        self.deniable.session_snapshot(peer_ik)
    }

    // --- suite high-water-mark (spec §1.3, §2.7 step 8, §10.7.1) ----------------------------

    /// This node's pinned suite **high-water-mark** for an authenticated contact (keyed by their
    /// `Payload.from` identity key), or `None` if none has been accepted from them yet.
    /// [`receive_mote`](Self::receive_mote) ratchets this up on every accepted MOTE and rejects any
    /// later object below it as a downgrade (§2.7 step 8).
    pub fn suite_high_water_mark(&self, contact: &[u8]) -> Option<Suite> {
        self.suite_ratchet.high_water_mark(contact)
    }

    /// Pin (ratchet **up**) `contact`'s suite high-water-mark to `suite` from out-of-band knowledge —
    /// e.g. a contact known to have migrated to a stronger suite, so a *first* on-the-wire MOTE that
    /// silently offers a weaker one is already rejected as a downgrade. Never lowers an existing mark
    /// ([`SuiteRatchet::observe`] semantics).
    pub fn pin_suite_floor(&mut self, contact: &[u8], suite: Suite) {
        self.suite_ratchet.observe(contact, suite);
        self.suite_contacts.insert(contact.to_vec());
        self.checkpoint(); // the pinned floor is security-critical state — persist it immediately.
    }

    // --- mix-directory anti-rollback (spec §4.4.2, §18.5.3) ---------------------------------

    /// Ingest an inbound, wire-encoded [`MixDirectory`] (§18.5.3), **fail-closed**: verify the
    /// authority signature and enforce the per-authority monotonic `(epoch, version)` high-water-mark,
    /// rejecting a replayed/stale snapshot as a rollback ([`MixDirError`]). On success the mark
    /// ratchets up and the fleet is retained (see [`mix_directory`](Self::mix_directory)). This is the
    /// node-layer half of the crate's monotonic-`version` contract (§4.4.2): the rollback is rejected
    /// *here*, using state held in the node, not merely rejectable in `dmtap_core`.
    pub fn ingest_mix_directory(&mut self, bytes: &[u8]) -> Result<(), MixDirError> {
        self.mix_directory.ingest(bytes)?;
        self.checkpoint(); // the mark ratcheted up — persist so a post-restart rollback is rejected.
        Ok(())
    }

    /// The latest mix-directory this node has accepted from `authority`, if any (§4.4.2).
    pub fn mix_directory(&self, authority: &[u8]) -> Option<&MixDirectory> {
        self.mix_directory.latest(authority)
    }

    /// The pinned mix-directory high-water-mark `(epoch, version)` for `authority`, or `None`.
    pub fn mix_directory_high_water_mark(&self, authority: &[u8]) -> Option<(u64, u64)> {
        self.mix_directory.high_water_mark(authority)
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

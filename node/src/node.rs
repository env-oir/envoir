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
//!   §20.1 sender-retry machine, dedup/idempotent ack (§2.6), and RFC 5322 projection into a
//!   JMAP-visible [`MemoryStore`] (JMAP is the node's native client surface, §8.1).
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
    build_mote, validate_pinned, ChallengeResponse, Envelope, Headers, Hpke, Kind, MoteDraft,
    MoteError, Outcome, Payload, RecipientCtx, SealKeypair, ValidateError,
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
use crate::naming::{
    self, AddressError, KeyPackageSource, NameChainClient, NameChainResolver, ResolveError,
    Resolver, ResolverKind, ResolverRegistry, ResolverType, SelfResolver,
};
use dmtap_core::identity::Identity;
use crate::onion::{self, MixPath};
use crate::outbound::{OutEvent, OutState, OutboundEntry, Tier, TERMINAL_GRACE_MS};
use crate::pow::{PowCheck, PowGate};
use crate::reassembly::{Reassembled, ReassemblyCache};
use crate::seen::SeenSet;
use crate::transport::{Frame, Transport, TransportError};
use crate::usage::{
    NodeUsageMeter, NullUsageMeter, QuotaDecision, StorageQuota, UnlimitedStorage, UsageEvent,
};
use dmtap_auth::AuthError;
use dmtap_core::mixnet::MixDirectory;

/// The requests-area mailbox for deferred cold-sender MOTEs (§2.7a: never the inbox). Mapped onto
/// the Junk SPECIAL-USE folder so existing IMAP/JMAP clients surface it distinctly from the inbox.
const REQUESTS_MAILBOX: &str = "Junk";

/// Upper bound on buffered inbound group **application** MOTEs awaiting decrypt (§5.4). The buffer is
/// drained each tick by [`Node::pump_group_inbox`] (the serve loops) / [`Node::poll_group_messages`],
/// but without a cap a peer streaming [`Frame::Group`] faster than it drains would grow it without
/// bound (an OOM vector). At the cap further group frames are dropped (fail-safe backpressure),
/// mirroring the transport's `MAX_INBOX_FRAMES`.
const MAX_GROUP_INBOX: usize = 1024;

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
    /// A `private`-tier send could not be onion-wrapped over the supplied mix path — fail closed,
    /// never downgraded onto a shorter/direct path (§4.4.9, §20.1).
    Onion(onion::OnionError),
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
            SendError::Onion(e) => write!(f, "private onion-wrap failed: {e}"),
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
    /// Dedup / replay set (§2.6): a re-delivered `id` is acked without reprocessing. **Bounded** by a
    /// sliding receive-time window + a hard LRU cap ([`SeenSet`]) so it — and the durable snapshot it
    /// feeds (§19.3.3) — cannot grow without limit on a long-running or flooded node.
    seen: SeenSet,
    /// The sender-side retry queue, keyed by MOTE `id` (§20.1).
    outbound: HashMap<Vec<u8>, OutboundEntry>,
    /// Known-contact identity keys — the fast-path sender classification (§2.7 step 5) and the
    /// pin the decrypted `Payload.from` is checked against (§2.7 step 8).
    contacts: HashSet<Vec<u8>>,
    /// Naming/KeyPackage resolution stand-in: recipient IK → their sealing (X25519) public key.
    directory: HashMap<Vec<u8>, [u8; 32]>,
    /// The pluggable **resolver-type registry** (spec §3.12): routes a recipient name by form
    /// (§3.12.4) and gates it against the types this node implements (§3.12.2). Owned by the node so
    /// [`resolve_and_pin`](Self::resolve_and_pin) delegates form dispatch to `dmtap-naming`'s one
    /// source of truth instead of a duplicate classifier. `self`/`petname`/`dns` are on by default;
    /// the OPTIONAL `name-chain` type (§3.12.5(a)) stays off until [`enable_name_chain`](Self::enable_name_chain).
    resolvers: ResolverRegistry,
    /// The OPTIONAL `name-chain` (ENS `.eth` / SNS `.sol`) client seam (§3.12.5): `None` ⇒ the node
    /// does not implement name-chain and every chain name fails closed (`0x011F`); a test/deployment
    /// injects one via [`enable_name_chain`](Self::enable_name_chain) to opt in.
    name_chain: Option<Box<dyn NameChainClient>>,
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
    /// Checkpoint **coalescing** (§19.3.3 write-amplification): while `true`, per-mutation
    /// [`checkpoint`](Self::checkpoint) calls only set `checkpoint_dirty` instead of rewriting the
    /// whole snapshot — the enclosing batch (a [`poll`](Self::poll) tick) writes once at the end. This
    /// turns a K-frame tick from K full-snapshot writes into one, without weakening the send path's
    /// "durable before return" guarantee (which runs outside a batch).
    checkpoint_deferred: bool,
    /// Set by a deferred [`checkpoint`](Self::checkpoint) call to mark the batch needs a flush.
    checkpoint_dirty: bool,
    /// Durable store for the outbound retry queue + dedup set (§19.3.3). Every mutation of that
    /// state is checkpointed here so a restarted node resumes its pending sends; the default
    /// [`NullJournal`] persists nothing (ephemeral node).
    journal: Box<dyn Journal>,
    /// The hosted-mailbox **storage Policy** seam (spec §12.2, §12.3). Consulted before a stored MOTE
    /// is durably filed to the inbox: a `Deny` is enforced fail-closed (not stored, not acked). The
    /// default [`UnlimitedStorage`] never denies, so self-host is unaffected. This gates a storage
    /// *operation* only — never crypto, access to keys, or access to already-stored mail (§12.3).
    storage_quota: Box<dyn StorageQuota>,
    /// The append-only **node-usage meter** seam (spec §12.2, §12.4): the node emits a
    /// [`UsageEvent::Stored`] on each durable inbox accept for the operator's billing (a separate
    /// repo) to consume. The default [`NullUsageMeter`] is a no-op, so self-host bills no one.
    usage_meter: Box<dyn NodeUsageMeter>,
    /// The cold-sender **memory-hard PoW** verification gate (spec §9.4, §16.5): a per-connection
    /// budget in front of the symmetric-cost Argon2id verifier. A cold MOTE whose PoW would push a
    /// delivering connection past its budget is deferred **without** being verified, so a bogus-PoW
    /// flood cannot turn the cold-sender gate into a memory/CPU DoS.
    pow_gate: PowGate,
    /// The bounded **multi-cell reassembly** cache (spec §4.4.1 safety part, §16.3): partial
    /// `private`-tier MOTEs held with a reassembly timeout so a lost fragment cannot pin memory.
    /// Pruned each deadline tick. Per-cell ARQ/FEC recovery is the tracked follow-up.
    reassembly: ReassemblyCache,
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
            seen: SeenSet::new(),
            outbound: HashMap::new(),
            contacts: HashSet::new(),
            directory: HashMap::new(),
            resolvers: ResolverRegistry::with_defaults(),
            name_chain: None,
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
            checkpoint_deferred: false,
            checkpoint_dirty: false,
            journal,
            // Self-host defaults: unlimited storage, no-op meter (§12.2). A hosted deployment injects
            // a cloud impl via `set_storage_quota` / `set_usage_meter`.
            storage_quota: Box::new(UnlimitedStorage),
            usage_meter: Box::new(NullUsageMeter),
            pow_gate: PowGate::new(),
            reassembly: ReassemblyCache::new(),
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
            // Stamp restored entries at the node's current clock: a fresh (never shorter) dedup window
            // so re-ack-on-redelivery still works across the restart (§2.6, §19.3.3), still bounded.
            node.seen.restore(id, from, node.now);
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
    /// equivocating / proof-invalid) returns the typed [`ResolveError`]
    /// and pins **nothing** — never a TOFU pin on unverifiable KT (§3.3). Returns the verified IK.
    pub fn resolve_and_pin(
        &mut self,
        name: &str,
        resolver: &dyn Resolver,
        kps: &dyn KeyPackageSource,
    ) -> Result<Vec<u8>, ResolveError> {
        // Route the name by its FORM through `dmtap-naming`'s pluggable resolver-type registry
        // (§3.12.4) and gate it against the types this node implements (§3.12.2) — one source of
        // truth, no duplicate classifier. An unimplemented/unregistered type fails closed here with
        // `ERR_RESOLVER_TYPE_UNSUPPORTED` (`0x011F`) before any resolver is consulted (never guessed).
        match self.resolvers.route(name)? {
            // `local@domain` → the wired DNS `_dmtap` + KT [`Resolver`] path (§3.3), unchanged.
            ResolverType::Dns => {
                // KT-verify the binding (fail-closed) BEFORE trusting anything about the recipient.
                let res = resolver.resolve(name)?;
                // Fetch + content-verify (§2.2) the sealing KeyPackage the verified identity advertises.
                let bundle = kps.fetch_bundle(&res.keypkgs)?;
                let seal_pub = naming::seal_key_from_bundle(&bundle)?;
                // Pin the verified binding into the local cache (§3.4): only now is it addressable.
                self.add_contact(&res.ik, seal_pub);
                Ok(res.ik)
            }
            // A self-authenticating **key-name** (§3.9.6) → the crate's real [`SelfResolver`], which
            // now derives/verifies against a key this node already holds rather than a fail-closed stub.
            ResolverType::SelfKeyName => self.resolve_key_name(name),
            // A local **petname** (§3.9.3) resolves only against an out-of-band pin held in a local
            // petname book; the node carries none in the by-name send path, so it fails closed here
            // (never a guess) rather than being coerced onto the DNS resolver.
            ResolverType::Petname => Err(ResolveError::NameResolution(
                "petname resolves only against a local out-of-band pin, not by name here",
            )),
            // A **name-chain** name (`.eth`/`.sol`, §3.12.5) enforces the §3.12.5(b) bidirectional
            // key↔name binding, which needs the owner's signed `Identity` — an input the DNS
            // `(resolver, kps)` seams cannot supply. Route it to [`resolve_name_chain`](Self::resolve_name_chain).
            // (Off by default, `route` above already returned `0x011F`; this arm is reached only once
            // name-chain is explicitly enabled via [`enable_name_chain`](Self::enable_name_chain).)
            ResolverType::NameChain(_) => Err(ResolveError::NameResolution(
                "name-chain resolution requires the owner's Identity — use resolve_name_chain",
            )),
        }
    }

    /// Opt into the OPTIONAL `name-chain` resolver type (ENS `.eth` / SNS `.sol`, spec §3.12.5(a))
    /// by attaching a [`NameChainClient`] and enabling `name-chain` in this node's registry. Until
    /// this is called a chain name fails closed (`0x011F`); after it, [`resolve_name_chain`](Self::resolve_name_chain)
    /// resolves one by enforcing the §3.12.5(b) bidirectional binding through the crate's real resolver.
    pub fn enable_name_chain(&mut self, client: impl NameChainClient + 'static) {
        self.resolvers = self.resolvers.clone().enable(ResolverKind::NameChain);
        self.name_chain = Some(Box::new(client));
    }

    /// Resolve a self-authenticating **key-name** (spec §3.9.6) via the crate's real [`SelfResolver`].
    ///
    /// A key-name is a one-way word-encoding of `BLAKE3-256(ik)` — it carries no locator, so it can
    /// only resolve against a candidate key the node already holds. This searches the learned
    /// directory for the key the name derives from; [`SelfResolver::resolve`] enforces the internal
    /// checksum (typo/mishear defense) **and** the full `keyname::encode(ik) == name` derivation, so
    /// the match is exact and never a guess. On a match the binding is (re-)pinned as a contact and
    /// the identity key returned. Fail-closed: a bad checksum is [`ResolveError::KeyNameUnverified`],
    /// a well-formed key-name deriving from no known key is a [`ResolveError::NameResolution`] miss.
    pub fn resolve_key_name(&mut self, key_name: &str) -> Result<Vec<u8>, ResolveError> {
        let found = self
            .directory
            .keys()
            .find(|candidate| SelfResolver::resolve(key_name, candidate).is_ok())
            .cloned();
        match found {
            Some(ik) => {
                // The key-name is the key's own derivation (§3.9.6) — pinning it is authority-free.
                self.contacts.insert(ik.clone());
                Ok(ik)
            }
            // Distinguish a typo (fails the checksum) from an unknown-but-well-formed key-name, so a
            // mistyped name reports as a bad key-name rather than merely "not found".
            None if !dmtap_core::keyname::verify(key_name) => Err(ResolveError::KeyNameUnverified(
                "key-name checksum failed — typo/mishear, fail closed",
            )),
            None => Err(ResolveError::NameResolution(
                "key-name does not derive from any key known to this node",
            )),
        }
    }

    /// Resolve a **name-chain** name (`name@.eth` / `name.eth`, spec §3.12.5) via the node's injected
    /// [`NameChainClient`], enforcing the crate's §3.12.5(b) **bidirectional key↔name binding**
    /// against the owner's self-asserted `claimed` [`Identity`]. The chain record is only a discovery
    /// pointer; the returned key is the identity's classical `IK`, pinned with `seal_pub`.
    ///
    /// Fail-closed, delegating to `dmtap-naming`'s real [`NameChainResolver`]: name-chain not enabled
    /// / no client ⇒ [`ResolveError::ResolverTypeUnsupported`] (`0x011F`); the two binding directions
    /// disagreeing ⇒ [`ResolveError::NameChainBindingUnverified`] (`0x011E`); no on-chain record ⇒ a
    /// [`ResolveError::NameResolution`] miss.
    pub fn resolve_name_chain(
        &mut self,
        name: &str,
        claimed: &Identity,
        seal_pub: [u8; 32],
    ) -> Result<Vec<u8>, ResolveError> {
        // Gate on the registry first (name-chain is OPTIONAL, §3.12.5(a)): an unconfigured node
        // treats a chain name as unimplemented and fails closed (`0x011F`), never guessing.
        match self.resolvers.route(name)? {
            ResolverType::NameChain(_) => {}
            _ => {
                return Err(ResolveError::ResolverTypeUnsupported(
                    "not a name-chain name",
                ))
            }
        }
        let client = self.name_chain.as_deref().ok_or(
            ResolveError::ResolverTypeUnsupported("no name-chain client configured"),
        )?;
        // Reuse the crate's real resolver (the §3.12.5(b) bidirectional enforcement, `0x011E` on
        // mismatch) over a thin borrow adapter — one source of truth, no re-implemented binding check.
        let binding = NameChainResolver::new(ClientRef(client)).resolve(name, claimed)?;
        // A verified binding — pin the classical IK the chain and the identity agree on (§3.4).
        self.add_contact(&binding.ik, seal_pub);
        Ok(binding.ik)
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

    /// Inject the hosted-mailbox **storage Policy** seam (spec §12.2). By default a node uses
    /// [`UnlimitedStorage`] (never denies); a hosted deployment drops in a cloud impl here so
    /// [`receive_mote`](Self::receive_mote) consults it before durably filing a MOTE to the inbox. The
    /// node links no billing crate — this takes any `dyn StorageQuota`. Purely a storage-operation
    /// gate: it never affects crypto, keys, or already-stored mail (§12.3).
    pub fn set_storage_quota(&mut self, quota: Box<dyn StorageQuota>) {
        self.storage_quota = quota;
    }

    /// Inject the append-only **node-usage meter** seam (spec §12.2, §12.4). By default a node uses
    /// [`NullUsageMeter`] (no-op); a hosted deployment drops in a cloud sink here to receive a
    /// [`UsageEvent::Stored`] on each durable inbox accept. The node links no billing crate.
    pub fn set_usage_meter(&mut self, meter: Box<dyn NodeUsageMeter>) {
        self.usage_meter = meter;
    }

    /// The account a storage decision / usage event is attributed to: this node's root identity public
    /// bytes (§1.2). One node hosts one mailbox in the reference model; a hosted deployment maps this
    /// identity to its billing account.
    fn storage_account(&self) -> Vec<u8> {
        self.ik.public()
    }

    // --- store views ------------------------------------------------------------------------

    /// The mail-store projection (JMAP view of delivered MOTEs — the node's native surface, §8.1).
    pub fn store(&self) -> &MemoryStore {
        &self.store
    }

    /// Mutable access to the mail-store projection — lets a JMAP handler
    /// ([`dmtap_mail::jmap::process`]) run directly against the node's live store.
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
            seen: self.seen.persist_pairs(),
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
    ///
    /// **Coalescing:** inside a [`poll`](Self::poll) batch this only marks the batch dirty; the batch
    /// writes one full snapshot at the end instead of one per frame — bounding write amplification
    /// (§19.3.3) so a K-frame tick is one disk write, not K.
    fn checkpoint(&mut self) {
        if self.checkpoint_deferred {
            self.checkpoint_dirty = true;
            return;
        }
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

    /// Admit an **already-sealed** MOTE into this node's real §20.1 outbound retry queue and dispatch
    /// it over the mesh transport — the exact delivery machinery [`send_mail`](Self::send_mail) drives
    /// (`QUEUED → SEALED → IN_FLIGHT`, or `→ RETRY` if the transport is unreachable), for a MOTE that
    /// was built + HPKE-sealed upstream (the Envoir Send capability pipeline, [`crate::send_api`]).
    ///
    /// The envelope's own content address (§2.2) is authoritative and this **never re-seals** — the
    /// sealed object is retained verbatim so a retry re-dispatches the same immutable `id` (idempotent
    /// against recipient dedup, §2.6). The queued MOTE is checkpointed durably before returning
    /// (§19.3.3). Returns the tracked content id.
    pub fn dispatch_sealed(&mut self, to_ik: &[u8], env: Envelope) -> ContentId {
        let id = env.id.clone();
        // The wire [`Envelope`] (§18.3.1) carries no `expires` field — the requested expiry lives in
        // the sealed [`Payload`] (§2.4), opaque to us here — so the queue uses the 72 h default (§16.1).
        let mut entry = OutboundEntry::enqueue(id.clone(), to_ik.to_vec(), self.now, None);
        entry.apply(OutEvent::SealOk).expect("QUEUED→SEALED");
        entry.sealed = Some(env);
        self.dispatch(&mut entry); // SEALED → IN_FLIGHT (or → RETRY if unreachable)
        self.outbound.insert(id.as_bytes().to_vec(), entry);
        self.checkpoint(); // §19.3.3: the queued MOTE is durable before we return.
        id
    }

    /// The sealed [`Envelope`] of a tracked outbound MOTE (a clone), by `id`, if it has reached
    /// `SEALED` — for inspecting/verifying a queued MOTE (e.g. proving an Envoir-Send output is a
    /// real, decryptable MOTE without draining the transport).
    pub fn outbound_sealed(&self, id: &ContentId) -> Option<Envelope> {
        self.outbound.get(id.as_bytes()).and_then(|e| e.sealed.clone())
    }

    /// A snapshot of this node's learned recipient sealing keys (identity key → X25519 seal public,
    /// §5.3). The Envoir Send resolver ([`crate::send_api`]) reads this to seal to peers this node
    /// already knows (`add_contact`/`learn_key`), taking an owned copy so it holds no borrow on the
    /// node across a send.
    pub fn directory_snapshot(&self) -> HashMap<Vec<u8>, [u8; 32]> {
        self.directory.clone()
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

    /// Hand a SEALED entry to the transport, driving `dispatch_ok`/`tier_unreachable` (§20.1).
    /// Requires `entry.sealed` to be present. The wire form is tier-dependent ([`Self::wire_frame`]):
    /// a `fast` MOTE ships its identical sealed bytes to the recipient; a `private` MOTE ships a
    /// **fresh** Sphinx onion to its entry mix (§4.4).
    fn dispatch(&mut self, entry: &mut OutboundEntry) {
        let (dest, frame) = Self::wire_frame(entry);
        match self.transport.send(&dest, frame) {
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

    /// Build the `(destination, frame)` to hand the transport for `entry`, **tier-aware** (§20.1):
    ///
    /// - **`fast`** (§4.3): the sealed [`Envelope`] CBOR, to the recipient — **identical** bytes on
    ///   every attempt (a direct resend carries no per-hop mix tag, so a retry is just a retransmit).
    /// - **`private`** (§4.4): a **fresh** Sphinx onion of the sealed envelope, drawn over the
    ///   retained path with a fresh `α` + current-epoch keys ([`onion::wrap`]), handed to the entry
    ///   mix. Re-building it on **every** call is the §20.1 `RETRY (private)` fix: the retry's per-hop
    ///   tags differ from the first attempt's (§4.4.6), so the first honest hop does not drop it as a
    ///   replay. The stable envelope `id` is untouched (the inner envelope is re-wrapped, never
    ///   re-sealed, §2.2). The wrap is stored on the entry ([`OutboundEntry::last_onion`]) for
    ///   inspection. A `private` entry with no retained path (e.g. restored from the journal) or an
    ///   unwrappable payload falls back to shipping the sealed bytes so the state machine still
    ///   advances — a real node re-draws the path from the live mix directory / fails closed (§4.4.9).
    fn wire_frame(entry: &mut OutboundEntry) -> (Vec<u8>, Frame) {
        let env = entry.sealed.clone().expect("dispatch requires a sealed envelope");
        match (entry.tier, entry.mix_path.clone()) {
            (Tier::Private, Some(path)) => {
                let seed = fresh_seed();
                match onion::wrap(&env.det_cbor(), &path, &seed) {
                    Ok(wrap) => {
                        let dest = path.hops[0].node_ik.clone();
                        let bytes = wrap.to_bytes();
                        entry.last_onion = Some(wrap);
                        (dest, Frame::Mote(bytes))
                    }
                    // Should not happen (the path was validated at send time); ship sealed bytes so
                    // the SM advances rather than wedging.
                    Err(_) => (entry.to.clone(), Frame::Mote(env.det_cbor())),
                }
            }
            // `fast`, or a `private` entry whose path was not restored (never replay an old onion).
            _ => (entry.to.clone(), Frame::Mote(env.det_cbor())),
        }
    }

    /// Send a `private`-tier mail MOTE to `to_ik` over the mixnet `path` (spec §4.4, §4.6). Builds +
    /// HPKE-seals the MOTE exactly as [`send_mail`](Self::send_mail), then **onion-wraps** it over
    /// `path` (fail-closed on a sub-3-hop / over-long path or over-ladder payload, §4.4.9) and
    /// dispatches the onion to the entry mix. The path is retained so a `RETRY` **re-onion-wraps**
    /// with a fresh `α` rather than replaying (§20.1 `RETRY (private)`). Returns the stable `id`.
    pub fn send_mail_private(
        &mut self,
        to_ik: &[u8],
        subject: &str,
        body: &[u8],
        path: MixPath,
    ) -> Result<ContentId, SendError> {
        let seal_pub = self.directory.get(to_ik).copied().ok_or(SendError::Unresolved)?;
        let mut draft = MoteDraft::new(Kind::Mail, self.now, body.to_vec());
        draft.headers = Headers { subject: Some(subject.to_string()), ..Headers::default() };
        let expires = draft.expires;

        let ephemeral = IdentityKey::generate();
        let env = build_mote(&Hpke, &self.ik, &ephemeral, to_ik, &seal_pub, draft)?;
        let id = env.id.clone();
        // Validate the path up front by wrapping once (fail closed here, §4.4.9) — the retry path then
        // never fails to re-wrap.
        onion::wrap(&env.det_cbor(), &path, &fresh_seed()).map_err(SendError::Onion)?;

        let mut entry = OutboundEntry::enqueue(id.clone(), to_ik.to_vec(), self.now, expires);
        entry.tier = Tier::Private;
        entry.mix_path = Some(path);
        entry.apply(OutEvent::SealOk).expect("QUEUED→SEALED");
        entry.sealed = Some(env);
        self.dispatch(&mut entry); // SEALED → IN_FLIGHT (or → RETRY if the entry mix is unreachable)
        self.outbound.insert(id.as_bytes().to_vec(), entry);
        self.checkpoint(); // §19.3.3: the queued MOTE (with its tier) is durable before we return.
        Ok(id)
    }

    /// The most recent onion a `private`-tier outbound MOTE was dispatched as, by `id` — the fresh
    /// wrap from its last (re)dispatch. `None` for a `fast` MOTE or one never dispatched as `private`.
    /// Its [`OnionWrap::replay_tags`](crate::onion::OnionWrap::replay_tags) differ across a retry,
    /// proving the §20.1 `RETRY (private)` re-onion-wrap (§4.4.6).
    pub fn outbound_onion(&self, id: &ContentId) -> Option<crate::onion::OnionWrap> {
        self.outbound.get(id.as_bytes()).and_then(|e| e.last_onion.clone())
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
            // Defensive: a RETRY entry should always carry its sealed envelope (dispatch seals before
            // it can reach RETRY). If a future async-resolution path ever leaves one unsealed, SKIP it
            // (re-insert untouched) rather than panicking the whole delivery task — one malformed entry
            // must not take down every other pending send.
            let env = match entry.sealed.clone() {
                Some(env) => env,
                None => {
                    self.outbound.insert(key.clone(), entry);
                    continue;
                }
            };
            entry.apply(OutEvent::RetryTimerFires).expect("RETRY→IN_FLIGHT");
            // Tier-aware re-dispatch (§20.1): a `fast` MOTE re-sends its identical sealed bytes; a
            // `private` MOTE **re-onion-wraps** (fresh `α`) so its per-hop tags differ from the prior
            // attempt and the first honest hop does not drop it as a replay (§4.4.6). `env` is unused
            // for a re-wrapped private entry but kept as the defensive "sealed present" proof above.
            let _ = &env;
            let (dest, frame) = Self::wire_frame(&mut entry);
            match self.transport.send(&dest, frame) {
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

    /// Check every non-terminal entry against the deadline, expiring those past it (§16.1), then
    /// garbage-collect terminal entries whose grace window has elapsed (§20.1). Uses the injected
    /// clock; returns the ids that transitioned to `EXPIRED` this tick.
    pub fn tick_deadlines(&mut self) -> Vec<ContentId> {
        let mut expired = Vec::new();
        for entry in self.outbound.values_mut() {
            if entry.deadline_passed(self.now) {
                entry.apply(OutEvent::DeadlineExceeded).expect("→EXPIRED");
                expired.push(entry.id.clone());
            }
        }
        let gc = self.gc_terminal_outbound();
        if !expired.is_empty() || gc {
            self.checkpoint(); // terminal transitions and/or GC removals — persist the queue.
        }
        // Prune timed-out partial reassemblies (§4.4.1, §16.3) and stale PoW-budget bookkeeping
        // (§16.5) — soft, non-durable state, so no checkpoint is owed.
        let _ = self.reassembly.prune(self.now);
        self.pow_gate.prune(self.now);
        expired
    }

    /// Accept one **peeled** `private`-tier fragment cell (its δ plaintext: fixed
    /// [`SphinxFragmentHeader`](dmtap_core::sphinx::SphinxFragmentHeader) + fragment data) into the
    /// bounded reassembly cache (§4.4.1 safety part, §16.3). Returns
    /// [`Reassembled::Complete`](crate::reassembly::Reassembled::Complete) with the reconstructed MOTE
    /// when the final missing cell arrives, [`Reassembled::Pending`](crate::reassembly::Reassembled::Pending)
    /// while incomplete, or [`Reassembled::Rejected`](crate::reassembly::Reassembled::Rejected) on a
    /// malformed / inconsistent / over-cap cell. A partial that never completes is evicted after the
    /// reassembly timeout by [`tick_deadlines`](Self::tick_deadlines). Per-cell ARQ/FEC recovery is
    /// the tracked follow-up (not in this pass).
    pub fn accept_fragment(
        &mut self,
        hdr: &dmtap_core::sphinx::SphinxFragmentHeader,
        data: &[u8],
    ) -> Reassembled {
        self.reassembly.accept(hdr, data, self.now)
    }

    /// The number of partial multi-cell MOTEs currently held in the reassembly cache (§4.4.1).
    pub fn reassembly_pending(&self) -> usize {
        self.reassembly.len()
    }

    /// Total memory-hard PoW verifications performed so far (§16.5) — observable proof the
    /// per-connection budget held (over-budget cold MOTEs are deferred *without* verifying).
    pub fn pow_verifications(&self) -> u64 {
        self.pow_gate.verifications()
    }

    /// Reconfigure the per-connection memory-hard PoW verification budget (operator-tunable, §16.5).
    pub fn set_pow_budget(&mut self, window_ms: u64, max_per_window: u32) {
        self.pow_gate.set_budget(window_ms, max_per_window);
    }

    /// Garbage-collect terminal (`ACKED`/`EXPIRED`) outbound entries once their grace window has
    /// elapsed (§20.1: terminal slots "may be GC'd"), so the queue — and the durable snapshot it
    /// feeds (§19.3.3) — cannot accumulate terminal entries without bound on a long-running node. A
    /// terminal entry is first *stamped* with the current clock (`terminal_at`) on the tick it is
    /// observed terminal, then removed once `now >= terminal_at + TERMINAL_GRACE_MS`. The grace keeps
    /// a late ack (§20.1 fill) able to find its entry before it is dropped. Returns `true` if anything
    /// was stamped or removed (so the caller persists).
    fn gc_terminal_outbound(&mut self) -> bool {
        let now = self.now;
        let mut changed = false;
        let mut remove: Vec<Vec<u8>> = Vec::new();
        for (key, entry) in self.outbound.iter_mut() {
            if !entry.state.is_terminal() {
                continue;
            }
            match entry.terminal_at {
                None => {
                    // First observation of this terminal entry — start its grace window.
                    entry.terminal_at = Some(now);
                    changed = true;
                }
                Some(since) if now.saturating_sub(since) >= TERMINAL_GRACE_MS => {
                    remove.push(key.clone());
                }
                Some(_) => {}
            }
        }
        for key in remove {
            self.outbound.remove(&key);
            changed = true;
        }
        changed
    }

    // --- receiving (§19.3, §20.2) -----------------------------------------------------------

    /// Drain the transport and process every inbound frame: MOTEs run the §2.7 pipeline (and are
    /// acked when eligible), acks advance the matching outbound entry (§20.1). Returns the list of
    /// inbound MOTE dispositions for inspection/testing (acks produce no entry here).
    pub fn poll(&mut self) -> Vec<InboundOutcome> {
        // Coalesce the batch's checkpoints into a single write at the end (§19.3.3 write-amplification):
        // a K-frame tick that accepts/acks K MOTEs otherwise rewrote the full snapshot K times.
        self.checkpoint_deferred = true;
        self.checkpoint_dirty = false;
        let mut outcomes = Vec::new();
        for (from, frame) in self.transport.drain() {
            match frame {
                Frame::Mote(bytes) => outcomes.push(self.receive_mote(&from, &bytes)),
                // Bind the ack to its transport return path: only an ack arriving from the entry's
                // tracked recipient advances it (§19.3.2). An on-path relay that echoes `Ack(id)` (the
                // id = BLAKE3(ciphertext) is visible to it) can no longer forge a delivery receipt.
                Frame::Ack(id) => self.receive_ack(&from, &id),
                // A group application MOTE (§5): buffer it for `poll_group_messages` to decrypt,
                // keeping the 1:1 outcome list clean. (Group handshakes never arrive here — they
                // travel the ordered committer log, not the mesh, §5.1.) BOUNDED: past the cap the
                // frame is dropped rather than growing the buffer without limit (a peer streaming
                // `Frame::Group` must not be able to OOM the node), mirroring the transport inbox cap.
                Frame::Group { group_id, body } => {
                    if self.group_inbox.len() < MAX_GROUP_INBOX {
                        self.group_inbox.push((group_id, body));
                    }
                }
            }
        }
        // Flush the batch once (if anything mutated durable state).
        self.checkpoint_deferred = false;
        if self.checkpoint_dirty {
            self.checkpoint();
        }
        outcomes
    }

    /// Consume an `ack(id)` arriving over the transport from `from`: advance the tracked outbound entry
    /// to `ACKED`, or apply a late ack to an already-`EXPIRED` one, or ignore it (idempotent,
    /// §19.3.2). Unknown ids are ignored.
    ///
    /// **Fail-closed against a forged ack:** the ack `id` is `BLAKE3(ciphertext)` (§2.2), visible to
    /// any on-path relay, so an attacker can inject `Ack(id)` to *suppress the sender's retries* and
    /// falsely report the send delivered. We therefore honor an ack only when `from` matches the
    /// entry's tracked recipient (`entry.to`) — the return path over the shipped transports (§4). A
    /// mismatched `from` is dropped without advancing the entry, so a legitimate retry continues.
    ///
    /// NOTE (deeper binding): over a real sealed-sender mixnet the ack rides a single-use reply block
    /// (§6.2, §19.3.2) and `from` is not the recipient's identity in the clear — that path must bind
    /// the ack to the specific outbound MOTE via the reply-block/DR token it was sent under, not this
    /// return-path equality. This check is the correct, sufficient defense for the shipped transports.
    pub fn receive_ack(&mut self, from: &[u8], id: &[u8]) {
        if let Some(entry) = self.outbound.get_mut(id) {
            if entry.to != from {
                // The ack did not come from this MOTE's recipient — a forged/misrouted receipt. Ignore
                // it: retries keep going and the send is not falsely marked delivered.
                return;
            }
            let ev = match entry.state {
                OutState::InFlight | OutState::Retry | OutState::Acked => OutEvent::AckReceived,
                OutState::Expired => OutEvent::LateAck,
                // An ack before we ever dispatched is anomalous (a buggy/forging relay); ignore it
                // rather than force an undefined transition.
                OutState::Sealed | OutState::Queued => return,
            };
            let before = (entry.state, entry.delivered_late);
            let _ = entry.apply(ev);
            // Only persist on an actual state change (a duplicate ack on an already-ACKED entry is a
            // no-op) — no pointless full-snapshot write per redundant/forged-but-matching ack.
            if before != (entry.state, entry.delivered_late) {
                self.checkpoint();
            }
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
        if env.id.verify(&env.ciphertext) && self.seen.contains(env.id.as_bytes(), self.now) {
            self.send_ack(from, &env.id);
            return InboundOutcome::Duplicate { id: env.id.clone() };
        }

        // §2.7 steps 1–8, in order, cheapest-and-anonymous-first (shared core). Sender is
        // classified `known` iff its transport return path is a pinned contact (§2.7 step 5). Bind
        // the recipient context to locals (not `self`) so the accept path can take `&mut self`.
        let our_ik = self.ik.public();
        let seal_secret = self.seal_secret;
        let sender_is_known = self.contacts.contains(from);

        // §9.4 / §16.5 (S3): a cold sender presenting a **memory-hard** Argon2id PoW forces a
        // symmetric-cost verification, and this gate runs *before* any per-source cap can apply — so a
        // flood of **bogus** PoW attachments is itself a memory/CPU DoS. Bound the number of PoW
        // verifications per delivering connection: past the budget the MOTE is DEFERRED to the
        // requests area **without** running Argon2id (never unbounded memory-hard work on
        // unauthenticated input, never fail open). Cheap ARC / postage / vouch proofs are not gated
        // here (they impose no symmetric-cost DoS surface, §9.3, §9.5).
        if !sender_is_known {
            if let Some(ChallengeResponse::Pow(sol)) = env.challenge.as_ref() {
                match self.pow_gate.check(from, env.id.as_bytes(), &our_ik, sol, self.now) {
                    // Past the per-connection budget: DEFER to the requests area (§2.7a) WITHOUT ever
                    // running Argon2id — the flood tail costs the recipient no memory-hard work
                    // (§9.4, §16.5). Not added to `seen`, so a redelivery is re-evaluated against a
                    // fresh window rather than hitting the dedup-ack fast path. This is the only new
                    // rejection S3 introduces.
                    PowCheck::OverBudget => {
                        self.store.deliver_mote(&placeholder_payload(from), REQUESTS_MAILBOX, env.ts);
                        return InboundOutcome::Deferred { id: env.id.clone() };
                    }
                    // Within budget the memory-hard verification was *spent* (the cost this bound
                    // exists to cap). Inbox acceptance itself still follows the core's reference limit
                    // (§9.4: a *present* challenge is treated as meeting threshold) — the node does not
                    // newly gate delivery on PoW *validity* here; it only bounds how much verification
                    // work it performs. Fall through to full §2.7 validation either way.
                    PowCheck::Verified | PowCheck::Failed => {}
                }
            }
        }

        let ctx = RecipientCtx { our_ik: &our_ik, seal_secret: &seal_secret, sender_is_known };
        // `ctx` borrows only these locals (not `self`), so the accept path below is free to take
        // `&mut self`; NLL ends the borrow at this call. The per-contact `suite_ratchet` enforces the
        // §2.7 step 8 / §10.7.1 suite high-water-mark: an authenticated sender's `Envelope.suite` may
        // never drop below the highest we have accepted from them (a downgrade), and each accept
        // ratchets that mark up. The mutable ratchet borrow also ends at this call (the returned
        // outcome holds no reference to it), so the `&mut self` accept path below is unaffected.
        let outcome = validate_pinned(&Hpke, &env, &ctx, Some(&mut self.suite_ratchet));

        match outcome {
            Ok(Outcome::Accepted(payload)) => {
                // §12.2 Policy: consult the hosted-mailbox storage quota BEFORE durably filing this
                // MOTE. The delta is the MOTE's durable wire size (the bytes the node commits to
                // hold). Fail-closed: a `Deny` is neither stored nor acked, so the sender's own retry
                // holds it and EXPIREs — the mailbox is never partially/over-written past its cap.
                // This gates a storage *operation* only; the crypto pipeline above already ran and
                // nothing already stored is touched (§12.3). Self-host uses `UnlimitedStorage`, which
                // always admits, so this is a pure no-op there.
                let account = self.storage_account();
                let delta = bytes.len() as u64;
                match self.storage_quota.admit(&account, delta) {
                    QuotaDecision::Deny { reason, .. } => {
                        // Not added to `seen`, so a later redelivery (e.g. after the cap is raised)
                        // is re-evaluated rather than hitting the dedup-ack fast path.
                        InboundOutcome::StorageDenied { id: env.id.clone(), reason }
                    }
                    QuotaDecision::Allow { .. } => self.accept(from, &env.id, *payload, delta),
                }
            }
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
    /// success, file to the inbox, record dedup, ack, and meter the durable storage. `stored_bytes`
    /// is the MOTE's durable wire size — the quota already admitted it in [`receive_mote`], and the
    /// emitted [`UsageEvent::Stored`] bills the very same amount (§12.2, §12.4).
    fn accept(
        &mut self,
        from: &[u8],
        id: &ContentId,
        payload: Payload,
        stored_bytes: u64,
    ) -> InboundOutcome {
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
        self.seen.record(id.as_bytes().to_vec(), from.to_vec(), self.now);
        // dedup set grew and the suite mark advanced — persist so a post-restart redelivery is still
        // re-acked and a post-restart downgrade below this sender's mark is still rejected.
        self.checkpoint();
        // §12.2 Metering: emit the append-only node-usage event for the durable storage just
        // committed. Best-effort (the no-op default records nothing); it runs only on a real accept,
        // so a self-hoster with `NullUsageMeter` is unaffected and a dropped/deferred MOTE is never
        // billed.
        self.usage_meter.record(&UsageEvent::Stored {
            account: self.storage_account(),
            delta_bytes: stored_bytes,
            at: self.now,
        });
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

    /// Drain the buffered inbound group **application** MOTEs and **deliver** each successfully
    /// decrypted plaintext into the mail store (INBOX), returning how many were delivered. This is the
    /// serve-loop drainer (called each tick by [`crate::daemon::run_loop`] /
    /// [`crate::send_api::run_loop_with_send_api`]) so group messages the real daemon receives are
    /// actually delivered — and so the bounded `group_inbox` is emptied rather than merely capped. A
    /// decrypt failure (e.g. a message from an epoch this node was removed from, §5.2) is dropped, not
    /// delivered. Group content is filed under the `group_id` as its `from` (the reference store has no
    /// separate group surface; §8.1 JMAP renders it in INBOX).
    pub fn pump_group_inbox(&mut self) -> usize {
        let mut delivered = 0;
        for (group_id, result) in self.poll_group_messages() {
            if let Ok(plaintext) = result {
                let payload = group_message_payload(&group_id, &plaintext);
                if self.store.deliver_mote(&payload, "INBOX", self.now).is_some() {
                    delivered += 1;
                }
            }
        }
        delivered
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

/// A thin borrow adapter so a node-held `&dyn NameChainClient` can drive `dmtap-naming`'s
/// [`NameChainResolver`] (which takes its client **by value**): it forwards both trait methods to
/// the borrowed client, letting the node reuse the crate's real §3.12.5(b) bidirectional-binding
/// enforcement without owning or cloning the client per resolution. Pure delegation, no logic.
struct ClientRef<'a>(&'a dyn NameChainClient);

impl NameChainClient for ClientRef<'_> {
    fn chain(&self) -> naming::Chain {
        self.0.chain()
    }
    fn resolve(&self, name: &str) -> Option<Vec<u8>> {
        self.0.resolve(name)
    }
}

/// A fresh 32-byte seed for a `private`-tier onion wrap (the per-wrap `α`, §4.4.4). Drawn from the
/// OS CSPRNG; a re-wrap MUST get a NEW seed, which is what makes a `RETRY` onion distinct from the
/// prior attempt (§4.4.6). On the (practically impossible) RNG failure it falls back to a
/// clock-derived seed so the value is still non-repeating rather than a fixed one that would defeat
/// the whole re-wrap property.
fn fresh_seed() -> [u8; 32] {
    let mut s = [0u8; 32];
    if getrandom::getrandom(&mut s).is_err() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        s[..16].copy_from_slice(&nanos.to_be_bytes());
    }
    s
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
        // Sealing/encoding errors, and the §5.5 file-tier / durability / spool failures (raised at
        // MOTE construction and by the file-durability helpers, not by this decode+validate path),
        // cannot arise here but map defensively to Malformed.
        // A §2.7-step-8 envelope-context mismatch (`0x0211`): the envelope `kind`/`ts`/`to` were
        // altered after `Payload.sig` was signed (a re-emit of the sealed ciphertext). Like the
        // other decode/authenticity failures it drops silently; map it defensively to Malformed.
        MoteError::EnvelopeContextMismatch
        | MoteError::SealFailed
        | MoteError::BadEncoding(_)
        | MoteError::FileManifestInvalid
        | MoteError::FileRetentionExpired
        | MoteError::FileUnavailable
        | MoteError::SpoolOverflow
        | MoteError::SizeTierViolation => DropReason::Malformed,
    }
}

/// A payload projecting a decrypted group **application** message (§5.4) into the mail store. The
/// `group_id` stands in as `from` (the reference store has no dedicated group surface); the plaintext
/// is the body. Signature-free — MLS already authenticated it inside the group session.
fn group_message_payload(group_id: &[u8], plaintext: &[u8]) -> Payload {
    Payload {
        from: group_id.to_vec(),
        sig: Vec::new(),
        headers: Headers { subject: Some("(group message)".into()), ..Headers::default() },
        body: plaintext.to_vec(),
        refs: Vec::new(),
        attach: Vec::new(),
        expires: None,
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

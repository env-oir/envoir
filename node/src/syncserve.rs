//! Sync-substrate reconciliation serving (`substrate/SYNC.md` §5.2, §5.3) — the node's optional
//! replica-sync HTTP surface.
//!
//! [`dmtap_sync`] implements the CRDT algebra, the signed-op envelope, snapshots and range-Merkle
//! reconciliation, but none of it was reachable over the wire. This module binds the four §5.2/§5.3
//! operations to HTTP, following the DMTAP-PUB gateway ([`crate::pubserve`]) exactly: an operator
//! opt-in that is **off by default**, a capability gate (`sync-1` here, `pub-1` there), a pure
//! router with the transport bolted on separately, and bounded read/write timeouts.
//!
//! Where it deliberately differs from the pub surface:
//!
//! - **Reads are not anonymous.** §5.2's endpoints mutate (`POST /sync/ops`) and disclose a
//!   replica's whole op set, so every request carries the `sync-1` capability as a `Bearer` token
//!   (§5.4: "the transport gate controls *who may sync*").
//! - **The transport is never the only authenticator** (§5.4). Every op is verified through
//!   [`dmtap_sync::verify_op_bytes`] on ingest *regardless of transport* — a valid bearer token
//!   authorizes a peer to sync, it never makes that peer's ops authentic. An op whose COSE_Sign1
//!   fails under its own `hlc.author` is rejected with `ERR_SYNC_OP_SIG_INVALID` (`0x0A02`) even
//!   when it arrived over a fully trusted link.
//!
//! Bodies are deterministic CBOR (§2.2), integer-keyed like every other DMTAP object.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::time::Duration;

use dmtap_core::capability::CapabilityToken;
use dmtap_core::id::ContentId;
use dmtap_core::TimestampMs;
use dmtap_sync::detcbor::{decode, encode};
use dmtap_sync::recon::{summarize, OpEntry, RangeFingerprint};
use dmtap_sync::{verify_op_bytes, Hlc, SVal, SyncError, SyncOp, SyncState, VersionVector};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// The §5.3 / §10.2 capability resource string a `sync-1`-granting [`CapabilityToken`] carries.
pub const SYNC1_RESOURCE: &str = "sync-1";
/// The ability verb paired with [`SYNC1_RESOURCE`] — the bearer is authorized to reconcile.
pub const SYNC1_ABILITY: &str = "sync";

/// The base path of the §5.2/§5.3 surface.
pub const SYNC_BASE: &str = "/sync/";

/// Hard cap on how many ops one `POST /sync/pull` returns (§5.2: "up to a batch limit"). Bounds the
/// response a single caller can force a responder to build.
pub const PULL_BATCH_LIMIT: usize = 512;
/// Hard cap on how many ops one `POST /sync/ops` push may carry.
pub const PUSH_BATCH_LIMIT: usize = 512;
/// Hard cap on how many ranges one `POST /sync/fingerprint` may ask about — each costs a fold over
/// the responder's op set, so an unbounded list is an amplification lever.
pub const FINGERPRINT_RANGE_LIMIT: usize = 64;

/// Verify that `token` authorizes its `aud` peer to reconcile with `operator` at `now` (§5.4): the
/// token MUST cryptographically verify, be valid at `now` (nbf ≤ now < exp, not revoked), name
/// `operator` as its audience, and grant [`SYNC1_RESOURCE`]/[`SYNC1_ABILITY`]. Fail-closed on any
/// gap — the same shape as [`crate::pubserve::pub1_authorizes`].
pub fn sync1_authorizes(token: &CapabilityToken, operator: &[u8], now: TimestampMs) -> bool {
    if token.aud != operator {
        return false;
    }
    if token.verify().is_err() {
        return false;
    }
    if token.verify_at(now, &[]).is_err() {
        return false;
    }
    token
        .caps
        .iter()
        .any(|c| c.resource == SYNC1_RESOURCE && c.ability == SYNC1_ABILITY)
}

// ── The replica (state + journal) ────────────────────────────────────────────────────────────

/// One journalled op: the verified envelope plus the exact `COSE_Sign1` bytes it arrived as.
///
/// The bytes are retained verbatim because §5.2's `pull` must return *signed* ops — a responder
/// that re-encoded and re-signed would be forging, and a responder that shipped bare `SyncOp`s
/// would be asking the caller to trust the transport, which §5.4 forbids.
#[derive(Debug, Clone)]
struct Journalled {
    op: SyncOp,
    cose: Vec<u8>,
}

/// A replica: the converged [`SyncState`] plus the op journal `pull`/`fingerprint` serve from.
///
/// [`SyncState`] deliberately keeps only the *result* of applying ops (it is the state machine),
/// so reconciliation needs this journal alongside it to answer "which ops do you hold".
#[derive(Debug, Default)]
pub struct SyncReplica {
    state: SyncState,
    /// Journalled ops keyed by `op-id` — the dedup + retrieval index.
    journal: BTreeMap<Vec<u8>, Journalled>,
    /// The namespaces this replica subscribes to (§7 sparse sync). Empty = the default namespace
    /// `""` only.
    ns: BTreeSet<String>,
}

impl SyncReplica {
    /// A replica subscribed to `ns` (an empty list means the default namespace `""`).
    pub fn new(ns: Vec<String>) -> Self {
        let ns: BTreeSet<String> =
            if ns.is_empty() { [String::new()].into_iter().collect() } else { ns.into_iter().collect() };
        SyncReplica { state: SyncState::new(), journal: BTreeMap::new(), ns }
    }

    /// The namespaces this replica subscribes to, canonically ordered.
    pub fn namespaces(&self) -> Vec<String> {
        self.ns.iter().cloned().collect()
    }

    /// This replica's §5.1 version vector.
    pub fn vector(&self) -> &VersionVector {
        &self.state.vector
    }

    /// Read-only access to the converged state (for callers that observe rather than sync).
    pub fn state(&self) -> &SyncState {
        &self.state
    }

    /// Ingest one `COSE_Sign1(SyncOp)` from the wire (§5.2 `ops` / §5.4).
    ///
    /// **The signature is verified here, always.** This is the ingest path for every transport, so
    /// a trusted link, a bearer-authenticated peer and an anonymous relay all land on the same
    /// check: `0x0A02` if the COSE_Sign1 does not verify under the op's own `hlc.author`. Then the
    /// §7 namespace scope is enforced (`0x0A0A` for an op outside the subscription — a peer cannot
    /// push into a namespace this replica did not ask for), then §4 CRDT validation and the
    /// idempotent §5.2 dedup+merge.
    ///
    /// Returns `true` if the op was **newly** applied, `false` for a duplicate (a no-op, never an
    /// error — a relayed op arriving twice is normal).
    pub fn ingest_cose(&mut self, cose: &[u8], now_ms: u64) -> Result<bool, SyncError> {
        let op = verify_op_bytes(cose)?;
        if !self.ns.contains(&op.ns) {
            return Err(SyncError::NsLeak);
        }
        let applied = self.state.ingest(&op, now_ms)?;
        if applied {
            let id = op.op_id().as_bytes().to_vec();
            self.journal.insert(id, Journalled { op, cose: cose.to_vec() });
        }
        Ok(applied)
    }

    /// The ops the holder of `vector` lacks (§5.2 `pull`): every journalled op in a requested
    /// namespace whose `hlc` exceeds the caller's mark for that op's author (or whose author the
    /// vector omits entirely), **oldest HLC first**, capped at `limit`.
    ///
    /// Oldest-first matters: a truncated batch is then a prefix of the difference, so the caller's
    /// vector advances monotonically and the next round resumes exactly where this one stopped.
    pub fn ops_after(&self, vector: &VersionVector, ns: &[String], limit: usize) -> Vec<Vec<u8>> {
        let mut wanted: Vec<&Journalled> = self
            .journal
            .values()
            .filter(|j| ns.is_empty() || ns.contains(&j.op.ns))
            .filter(|j| self.ns.contains(&j.op.ns))
            .filter(|j| vector.lacks(&j.op.hlc))
            .collect();
        wanted.sort_by(|a, b| a.op.hlc.cmp(&b.op.hlc).then_with(|| a.cose.cmp(&b.cose)));
        wanted.into_iter().take(limit).map(|j| j.cose.clone()).collect()
    }

    /// This replica's [`OpEntry`] set for `ns` — the `(hlc, op-id)` pairs §5.3 fingerprints fold.
    pub fn entries(&self, ns: &str) -> Vec<OpEntry> {
        let mut v: Vec<OpEntry> = self
            .journal
            .iter()
            .filter(|(_, j)| j.op.ns == ns)
            .map(|(id, j)| OpEntry { hlc: j.op.hlc.clone(), id: ContentId(id.clone()) })
            .collect();
        v.sort();
        v
    }

    /// The `COSE_Sign1` bytes of a journalled op, by `op-id`.
    pub fn op_bytes(&self, id: &ContentId) -> Option<&[u8]> {
        self.journal.get(id.as_bytes()).map(|j| j.cose.as_slice())
    }

    /// How many ops are journalled.
    pub fn len(&self) -> usize {
        self.journal.len()
    }

    /// Whether the journal is empty.
    pub fn is_empty(&self) -> bool {
        self.journal.is_empty()
    }
}

// ── The gateway (operator opt-in) ────────────────────────────────────────────────────────────

/// The operator's opt-in sync surface. Constructed **disabled**: until the operator presents a
/// verified `sync-1` capability, every `/sync/*` path answers `404` — a node that never advertises
/// `sync-1` is never expected to reconcile.
#[derive(Debug)]
pub struct SyncGateway {
    /// The replica this gateway reconciles; `pub` so the node's own writes land in the same journal.
    pub replica: SyncReplica,
    /// This node's identity key — the `node` field of `GET /sync/vector` (§5.2).
    node: Vec<u8>,
    /// The operator identity a peer's `sync-1` token must name as its audience (§5.4).
    operator: Vec<u8>,
    enabled: bool,
}

impl SyncGateway {
    /// A new, **disabled** gateway for `node`/`operator`, subscribed to `ns`.
    pub fn new(node: Vec<u8>, operator: Vec<u8>, ns: Vec<String>) -> Self {
        SyncGateway { replica: SyncReplica::new(ns), node, operator, enabled: false }
    }

    /// Enable the surface iff `token` is a valid `sync-1` capability for this gateway's operator at
    /// `now` ([`sync1_authorizes`]). Returns whether it is now enabled.
    pub fn enable_with_capability(&mut self, token: &CapabilityToken, now: TimestampMs) -> bool {
        if sync1_authorizes(token, &self.operator, now) {
            self.enabled = true;
        }
        self.enabled
    }

    /// Whether this gateway advertises `sync-1` / serves the reconciliation surface.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// This node's identity key as advertised by `GET /sync/vector`.
    pub fn node_key(&self) -> &[u8] {
        &self.node
    }

    /// Whether `authorization` presents a `sync-1` capability this gateway accepts (§5.4). A
    /// missing, malformed, wrong-audience, expired or insufficiently-scoped token is a refusal —
    /// never a downgrade to anonymous access.
    pub fn peer_authorized(&self, authorization: Option<&str>, now: TimestampMs) -> bool {
        let Some(raw) = authorization.and_then(|h| h.strip_prefix("Bearer ")) else {
            return false;
        };
        let Some(bytes) = b64url_decode(raw.trim()) else {
            return false;
        };
        let Ok(token) = CapabilityToken::from_det_cbor(&bytes) else {
            return false;
        };
        sync1_authorizes(&token, &self.operator, now)
    }
}

// ── HTTP response ────────────────────────────────────────────────────────────────────────────

/// A reconciliation HTTP response. Bodies are deterministic CBOR (§2.2); the surface is
/// uncacheable by construction — a version vector and an op difference are live state, and a cached
/// `pull` would hand a peer a stale difference it would then believe it had fully consumed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncResponse {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

impl SyncResponse {
    fn cbor(body: Vec<u8>) -> Self {
        SyncResponse { status: 200, content_type: "application/cbor", body }
    }

    fn text(status: u16, msg: &str) -> Self {
        SyncResponse { status, content_type: "text/plain", body: msg.as_bytes().to_vec() }
    }

    fn not_found() -> Self {
        SyncResponse::text(404, "not found")
    }

    /// A §12 fail-closed refusal, reported with the substrate error's own code and name so a peer
    /// learns *why* — `0x0A02` for a bad signature, `0x0A0A` for a namespace leak, and so on.
    fn sync_error(e: &SyncError) -> Self {
        SyncResponse::text(422, &format!("{} ({:#06x})", e.name(), e.code()))
    }
}

// ── The router ───────────────────────────────────────────────────────────────────────────────

/// Route one request onto the §5.2/§5.3 surface.
///
/// Order is deliberate and fail-closed: not-our-path → `404`; gateway disabled → `404` (the surface
/// does not exist, and its existence is not disclosed); unauthorized → `401`; wrong method → `405`;
/// then, and only then, is a body parsed.
///
/// `now_ms` is the receiver clock, used both for capability validity (§5.4) and for the §3 HLC skew
/// window on ingest.
pub fn handle(
    gw: &mut SyncGateway,
    method: &str,
    raw_path: &str,
    authorization: Option<&str>,
    body: &[u8],
    now_ms: u64,
) -> SyncResponse {
    let path = raw_path.split_once('?').map_or(raw_path, |(p, _)| p);
    let Some(rest) = path.strip_prefix(SYNC_BASE) else {
        return SyncResponse::not_found();
    };
    if !gw.is_enabled() {
        return SyncResponse::not_found();
    }
    if !gw.peer_authorized(authorization, now_ms) {
        return SyncResponse::text(401, "sync-1 capability required");
    }

    match (method, rest) {
        ("GET", "vector") => vector_response(gw),
        ("POST", "pull") => pull_response(gw, body),
        ("POST", "ops") => ops_response(gw, body, now_ms),
        ("POST", "fingerprint") => fingerprint_response(gw, body),
        (_, "vector") => SyncResponse::text(405, "method not allowed"),
        (_, "pull" | "ops" | "fingerprint") => SyncResponse::text(405, "method not allowed"),
        _ => SyncResponse::not_found(),
    }
}

/// `GET /sync/vector` → `{1: node ik-pub, 2: [ns], 3: VersionVector}` (§5.2).
fn vector_response(gw: &SyncGateway) -> SyncResponse {
    let ns = SVal::Array(gw.replica.namespaces().into_iter().map(SVal::Text).collect());
    SyncResponse::cbor(encode(&SVal::Map(vec![
        (1, SVal::Bytes(gw.node.clone())),
        (2, ns),
        (3, gw.replica.vector().to_sval()),
    ])))
}

/// `POST /sync/pull {1: vector, 2: [ns]}` → `{1: [COSE_Sign1(SyncOp)]}` (§5.2).
fn pull_response(gw: &SyncGateway, body: &[u8]) -> SyncResponse {
    let (vector, ns) = match parse_vector_request(body) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let ops = gw.replica.ops_after(&vector, &ns, PULL_BATCH_LIMIT);
    SyncResponse::cbor(encode(&SVal::Map(vec![(
        1,
        SVal::Array(ops.into_iter().map(SVal::Bytes).collect()),
    )])))
}

/// `POST /sync/ops {1: [COSE_Sign1(SyncOp)]}` → `{1: applied}` (§5.2).
///
/// Every op is verified and validated individually ([`SyncReplica::ingest_cose`]). A batch is
/// **all-or-nothing on error**: one bad op fails the whole push with that op's §12 code rather than
/// silently applying its neighbours, so a peer can never learn which of its ops were rejected by
/// diffing counts, and a partially-applied batch never leaves the replica in a state the pusher
/// disagrees with.
fn ops_response(gw: &mut SyncGateway, body: &[u8], now_ms: u64) -> SyncResponse {
    let Ok(cv) = decode(body) else {
        return SyncResponse::text(400, "malformed CBOR body");
    };
    let SVal::Map(fields) = cv else {
        return SyncResponse::text(400, "body must be an integer-keyed map");
    };
    let Some((_, SVal::Array(items))) = fields.into_iter().find(|(k, _)| *k == 1) else {
        return SyncResponse::text(400, "missing key 1 (ops)");
    };
    if items.len() > PUSH_BATCH_LIMIT {
        return SyncResponse::text(413, "batch exceeds the push limit");
    }

    // Verify + validate every op before mutating anything, so a rejected batch leaves no trace.
    let mut verified: Vec<Vec<u8>> = Vec::with_capacity(items.len());
    for item in &items {
        let Some(bytes) = item.as_bytes() else {
            return SyncResponse::text(400, "op must be a byte string");
        };
        if let Err(e) = verify_op_bytes(bytes) {
            return SyncResponse::sync_error(&e);
        }
        verified.push(bytes.to_vec());
    }

    let mut applied = 0u64;
    for bytes in &verified {
        match gw.replica.ingest_cose(bytes, now_ms) {
            Ok(true) => applied += 1,
            Ok(false) => {}
            Err(e) => return SyncResponse::sync_error(&e),
        }
    }
    SyncResponse::cbor(encode(&SVal::Map(vec![(1, SVal::Uint(applied))])))
}

/// `POST /sync/fingerprint {1: ns, 2: [{1: lo, 2: hi, 3: fp, 4: count}]}` →
/// `{1: [{1: lo, 2: hi, 3: fp, 4: count, 5: [op-id]}]}` (§5.3).
///
/// For each range the caller summarizes, the responder folds its **own** ops over the same
/// `[lo, hi)` and answers only the ranges whose `(fp, count)` differ — an identical range costs one
/// comparison and ships nothing, which is the whole point of the mode. A mismatched range comes
/// back with the responder's fingerprint (so the caller can split it and recurse) *and* the op ids
/// the responder holds in it (so a range small enough to settle here settles in one round trip).
///
/// This is discovery only: the ids it surfaces are fetched through `pull`/`ops` and applied through
/// the same verify+merge path, so a lying responder can withhold or stall, never forge.
fn fingerprint_response(gw: &SyncGateway, body: &[u8]) -> SyncResponse {
    let Ok(cv) = decode(body) else {
        return SyncResponse::text(400, "malformed CBOR body");
    };
    let SVal::Map(fields) = cv else {
        return SyncResponse::text(400, "body must be an integer-keyed map");
    };
    let mut ns = String::new();
    let mut ranges: Vec<SVal> = Vec::new();
    for (k, v) in fields {
        match (k, v) {
            (1, SVal::Text(t)) => ns = t,
            (2, SVal::Array(a)) => ranges = a,
            _ => return SyncResponse::text(400, "unexpected field in fingerprint request"),
        }
    }
    if ranges.len() > FINGERPRINT_RANGE_LIMIT {
        return SyncResponse::text(413, "too many ranges");
    }
    let mine = gw.replica.entries(&ns);

    let mut mismatched: Vec<SVal> = Vec::new();
    for r in &ranges {
        let Some(theirs) = parse_range_fingerprint(r) else {
            return SyncResponse::text(400, "malformed range fingerprint");
        };
        let ours = summarize(&mine, &theirs.lo, &theirs.hi);
        if ours.fp.as_bytes() == theirs.fp.as_bytes() && ours.count == theirs.count {
            continue; // identical range — nothing exchanged (§5.3)
        }
        let ids: Vec<SVal> = dmtap_sync::recon::in_range(&mine, &theirs.lo, &theirs.hi)
            .into_iter()
            .map(|e| SVal::Bytes(e.id.as_bytes().to_vec()))
            .collect();
        mismatched.push(SVal::Map(vec![
            (1, ours.lo.to_sval()),
            (2, ours.hi.to_sval()),
            (3, SVal::Bytes(ours.fp.as_bytes().to_vec())),
            (4, SVal::Uint(ours.count)),
            (5, SVal::Array(ids)),
        ]));
    }
    SyncResponse::cbor(encode(&SVal::Map(vec![(1, SVal::Array(mismatched))])))
}

/// Parse `{1: VersionVector, 2: [ns]}` — the `pull` request body.
fn parse_vector_request(body: &[u8]) -> Result<(VersionVector, Vec<String>), SyncResponse> {
    let cv = decode(body).map_err(|_| SyncResponse::text(400, "malformed CBOR body"))?;
    let SVal::Map(fields) = cv else {
        return Err(SyncResponse::text(400, "body must be an integer-keyed map"));
    };
    let mut vector = VersionVector::new();
    let mut ns: Vec<String> = Vec::new();
    for (k, v) in fields {
        match (k, v) {
            (1, v) => {
                vector = VersionVector::from_sval(v)
                    .map_err(|_| SyncResponse::text(400, "malformed version vector"))?;
            }
            (2, SVal::Array(items)) => {
                for it in items {
                    match it {
                        SVal::Text(t) => ns.push(t),
                        _ => return Err(SyncResponse::text(400, "ns must be text")),
                    }
                }
            }
            _ => return Err(SyncResponse::text(400, "unexpected field in pull request")),
        }
    }
    Ok((vector, ns))
}

/// Parse one `{1: lo, 2: hi, 3: fp, 4: count}` range summary.
fn parse_range_fingerprint(cv: &SVal) -> Option<RangeFingerprint> {
    let SVal::Map(fields) = cv else {
        return None;
    };
    let mut lo = None;
    let mut hi = None;
    let mut fp = None;
    let mut count = None;
    for (k, v) in fields {
        match (k, v) {
            (1, v) => lo = Hlc::from_sval(v.clone()).ok(),
            (2, v) => hi = Hlc::from_sval(v.clone()).ok(),
            (3, SVal::Bytes(b)) => fp = Some(ContentId(b.clone())),
            (4, SVal::Uint(n)) => count = Some(*n),
            _ => return None,
        }
    }
    Some(RangeFingerprint { lo: lo?, hi: hi?, fp: fp?, count: count? })
}

/// Decode unpadded (or padded) base64url — the capability token's header encoding.
fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for c in s.bytes() {
        if c == b'=' {
            break;
        }
        let idx = TABLE.iter().position(|&t| t == c)? as u32;
        acc = (acc << 6) | idx;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// Encode bytes as unpadded base64url — the form [`b64url_decode`] accepts, exposed so a peer (and
/// the tests) can build the `Authorization: Bearer` header for a `sync-1` token.
pub fn b64url_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        let take = chunk.len() + 1;
        for i in 0..take {
            out.push(TABLE[((n >> (18 - 6 * i)) & 0x3f) as usize] as char);
        }
    }
    out
}

// ── Live HTTP serving ────────────────────────────────────────────────────────────────────────

/// How long one connection may take to deliver its request before it is dropped.
const SYNC_READ_TIMEOUT: Duration = Duration::from_secs(15);
/// Bound the write too: a slow-reading peer must not pin a connection (and the replica lock) open.
const SYNC_WRITE_TIMEOUT: Duration = Duration::from_secs(15);

/// Serve one accepted connection against `gw`.
///
/// The gateway is behind a [`std::sync::Mutex`] because — unlike the read-only pub surface —
/// `POST /sync/ops` mutates the replica. The lock is held only across the pure, non-async router
/// call and never across a socket read or write, so one slow peer can never stall every other
/// peer's reconciliation (and the guard is never held across an `.await`, so a blocking mutex is
/// the correct choice here rather than an async one).
pub async fn handle_connection(
    gw: &std::sync::Mutex<SyncGateway>,
    mut stream: TcpStream,
    now_ms: u64,
) -> io::Result<()> {
    let resp = match tokio::time::timeout(
        SYNC_READ_TIMEOUT,
        crate::send_api::read_request(&mut stream),
    )
    .await
    {
        Ok(Ok(Some(req))) => {
            let mut guard = gw.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            handle(&mut guard, &req.method, &req.path, req.authorization.as_deref(), &req.body, now_ms)
        }
        Ok(Ok(None)) => return Ok(()),
        Ok(Err(e)) => SyncResponse::text(400, &format!("bad request: {e}")),
        Err(_) => SyncResponse::text(408, "request timeout"),
    };
    match tokio::time::timeout(SYNC_WRITE_TIMEOUT, write_response(&resp, &mut stream)).await {
        Ok(r) => r,
        Err(_) => Ok(()),
    }
}

/// Write one [`SyncResponse`] as an HTTP/1.1 `Connection: close` reply.
async fn write_response(resp: &SyncResponse, stream: &mut TcpStream) -> io::Result<()> {
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\n\
         Connection: close\r\n\r\n",
        resp.status,
        reason_phrase(resp.status),
        resp.content_type,
        resp.body.len(),
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&resp.body).await?;
    stream.flush().await
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Payload Too Large",
        422 => "Unprocessable Entity",
        _ => "",
    }
}

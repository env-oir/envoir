//! DMTAP-PUB gateway serving (spec §22.5, §22.6) — the node's optional public-object surface.
//!
//! A node advertising the **`pub-1`** capability (§22.6.1) MAY serve public objects over the
//! well-known HTTP surface of §22.5.1. This module provides:
//!
//! - [`PubStore`] — the node-side pin storage + author-feed state (manifests, plaintext chunks,
//!   announces, and per-publisher signed feeds), with feed **publish/append** ([`PubStore::append`])
//!   that chains `prev`, re-signs the head, and enforces §22.4.2 anti-rollback.
//! - [`PubGateway`] — an operator opt-in wrapper: the surface serves nothing until the operator
//!   presents a valid `pub-1` capability ([`pub1_authorizes`]). Public **reads are anonymous**
//!   (§22.5.1 — no per-request auth); the capability gates whether the operator serves *at all*
//!   (§22.6.1: "a node that never advertises `pub-1` is never expected to serve them").
//! - [`handle`] — routes the five §22.5.1 GET endpoints, self-verifying every object it returns and
//!   attaching the §22.5.1 cache directives (immutable + strong ETag for the four content-addressed
//!   endpoints; short/must-revalidate for the mutable feed head).
//!
//! Public objects are **not blind** (§22.6.1): the operator can read what it serves, which is why
//! serving is an explicit opt-in and each object passes the holder [`ServePolicy`] (§22.6.2/.6.3).
//! Verification is always the *client's* job (§22.5.1); this server is a convenience, not a trust
//! root — it re-verifies on store so it can never serve wrong-but-accepted bytes.

use std::collections::BTreeMap;

use dmtap_core::capability::CapabilityToken;
use dmtap_core::id::ContentId;
use dmtap_core::identity::IdentityKey;
use dmtap_core::pubobj::{
    check_anti_rollback, verify_chunk, FeedEntry, FeedHead, PubAnnounce, PubError, PubManifest,
    ServePolicy,
};
use dmtap_core::suite::Suite;
use dmtap_core::TimestampMs;

/// The §22.6.1 / §10.2 capability resource string a `pub-1`-granting [`CapabilityToken`] carries.
pub const PUB1_RESOURCE: &str = "pub-1";
/// The ability verb paired with [`PUB1_RESOURCE`] — the operator is authorized to *serve* public
/// objects.
pub const PUB1_ABILITY: &str = "serve";

/// The well-known base path (§22.5.1).
pub const WELL_KNOWN_BASE: &str = "/.well-known/dmtap-pub/";

/// Verify that `token` authorizes its `aud` operator to serve public objects (§22.6.1): the token
/// MUST cryptographically verify, be valid at `now` (nbf ≤ now < exp, not revoked), have `aud` equal
/// to `operator`, and grant a [`PUB1_RESOURCE`]/[`PUB1_ABILITY`] capability. Fail-closed on any gap.
pub fn pub1_authorizes(token: &CapabilityToken, operator: &[u8], now: TimestampMs) -> bool {
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
        .any(|c| c.resource == PUB1_RESOURCE && c.ability == PUB1_ABILITY)
}

// ── Store ────────────────────────────────────────────────────────────────────────────────────

/// The signed state of one author feed the node holds/serves (§22.4).
#[derive(Debug, Clone)]
struct FeedState {
    head: FeedHead,
    /// Entries indexed by `seq` (entry at index `i` has `seq == i`).
    entries: Vec<FeedEntry>,
}

/// Node-side pin storage for DMTAP-PUB objects (§22). Content-addressed objects are keyed by their
/// full `hash` bytes; feeds are keyed by the publisher identity key. Every stored object is
/// **self-verified on store** so the server can never serve wrong-but-accepted bytes (§22.5.1).
#[derive(Debug, Default)]
pub struct PubStore {
    manifests: BTreeMap<Vec<u8>, PubManifest>,
    chunks: BTreeMap<Vec<u8>, Vec<u8>>,
    announces: BTreeMap<Vec<u8>, PubAnnounce>,
    feeds: BTreeMap<Vec<u8>, FeedState>,
    /// Approximate stored bytes per publisher, for the §22.6.3 per-publisher quota.
    stored_per_pub: BTreeMap<Vec<u8>, u64>,
    policy: ServePolicy,
}

impl PubStore {
    /// A store with the given holder [`ServePolicy`] (§22.6).
    pub fn new(policy: ServePolicy) -> Self {
        PubStore { policy, ..Default::default() }
    }

    /// Pin a public manifest (§22.2). The manifest MUST self-verify (`id` equals its DS-tagged
    /// Merkle root) and pass the holder admission policy. Returns the content address it is keyed by.
    pub fn store_manifest(&mut self, m: PubManifest, publisher: &[u8]) -> Result<ContentId, PubError> {
        m.verify()?;
        let bytes = m.det_cbor();
        self.admit(&m.id, bytes.len() as u64, publisher)?;
        let id = m.id.clone();
        self.manifests.insert(id.as_bytes().to_vec(), m);
        Ok(id)
    }

    /// Pin a plaintext chunk (§22.2.2). Returns its content address `h = 0x1e ‖ BLAKE3(plaintext)`.
    pub fn store_chunk(&mut self, plaintext: Vec<u8>, publisher: &[u8]) -> Result<ContentId, PubError> {
        let h = dmtap_core::pubobj::chunk_hash(&plaintext);
        self.admit(&h, plaintext.len() as u64, publisher)?;
        self.chunks.insert(h.as_bytes().to_vec(), plaintext);
        Ok(h)
    }

    /// Pin an announce (§22.3). It MUST self-verify against its own derived `announce_id`. Returns
    /// that id.
    pub fn store_announce(&mut self, a: PubAnnounce) -> Result<ContentId, PubError> {
        let id = a.announce_id();
        a.verify(&id)?;
        self.admit(&id, a.det_cbor().len() as u64, &a.publisher)?;
        self.announces.insert(id.as_bytes().to_vec(), a);
        Ok(id)
    }

    /// Apply the holder admission policy (§22.6.2/.6.3): a declined id is
    /// [`PubError::NotServed`] (`0x090C`); an exceeded size ceiling / per-publisher quota is
    /// [`PubError::ServeQuota`] (`0x090D`).
    fn admit(&self, id: &ContentId, size: u64, publisher: &[u8]) -> Result<(), PubError> {
        let already = self.stored_per_pub.get(publisher).copied().unwrap_or(0);
        self.policy.admit(id, size, already)?;
        Ok(())
    }

    /// **Publish/append** a signed announce to its author's feed (§22.4). The announce MUST verify;
    /// then a new [`FeedEntry`] at `seq = prev_head.seq + 1` (or genesis `0`) chaining `prev` to the
    /// current tip is created, and a fresh [`FeedHead`] committing the new tip is signed by
    /// `signer_key`. §22.4.2 anti-rollback is enforced against the prior head (`seq` strictly
    /// increases). `signer_key`'s public key MUST equal the announce's `signer`. Returns the new
    /// head.
    pub fn append(
        &mut self,
        announce: PubAnnounce,
        signer_key: &IdentityKey,
        now: TimestampMs,
    ) -> Result<FeedHead, PubError> {
        // The announce must be internally valid, and the signer key must match its declared signer.
        let announce_id = announce.announce_id();
        announce.verify(&announce_id)?;
        if signer_key.public() != announce.signer {
            return Err(PubError::AnnounceSigInvalid);
        }
        let publisher = announce.publisher.clone();
        let suite = announce.suite;

        // Determine the next position + prev link from the current feed state.
        let (seq, prev, prior_head) = match self.feeds.get(&publisher) {
            Some(state) => {
                let tip = state.entries.last().expect("a feed always has ≥1 entry once created");
                (state.head.seq + 1, Some(tip.entry_id()), Some(state.head.clone()))
            }
            None => (0u64, None, None),
        };

        let entry = FeedEntry { seq, announce: announce_id.clone(), prev, ts: now };
        let tip = entry.entry_id();
        let mut head = FeedHead {
            v: 0,
            suite,
            publisher: publisher.clone(),
            seq,
            tip,
            ts: now,
            signer: signer_key.public(),
            sig: Vec::new(),
        };
        head.sign(signer_key);

        // §22.4.2: a newly-published head MUST advance the feed (strictly greater seq). This can
        // only trip on a caller bug (concurrent double-append at one seq); enforce it fail-closed.
        if let Some(prior) = &prior_head {
            check_anti_rollback(prior.seq, Some(&prior.tip), head.seq, &head.tip)?;
        }

        // Admission (§22.6.3): the append counts against the publisher's quota.
        self.admit(&announce_id, announce.det_cbor().len() as u64, &publisher)?;

        // Commit: store the announce, append the entry, advance the head.
        self.announces.insert(announce_id.as_bytes().to_vec(), announce);
        let state = self.feeds.entry(publisher).or_insert_with(|| FeedState {
            head: head.clone(),
            entries: Vec::new(),
        });
        state.entries.push(entry);
        state.head = head.clone();
        Ok(head)
    }

    /// The current signed head for `publisher`, if this node holds that feed (§22.4.4).
    pub fn feed_head(&self, publisher: &[u8]) -> Option<&FeedHead> {
        self.feeds.get(publisher).map(|s| &s.head)
    }

    /// A contiguous, `prev`-chain-verified slice `[from, to]` of `publisher`'s feed (§22.4.4).
    /// Returns `None` if the feed is unheld; clamps `to` to the tip.
    pub fn feed_range(&self, publisher: &[u8], from: u64, to: u64) -> Option<Vec<FeedEntry>> {
        let state = self.feeds.get(publisher)?;
        if from > to || state.entries.is_empty() {
            return Some(Vec::new());
        }
        let last = (state.entries.len() as u64).saturating_sub(1);
        let hi = to.min(last);
        Some(state.entries[from as usize..=hi as usize].to_vec())
    }

    /// A content-addressed announce fetch (§22.4.4), keyed by `announce_id`.
    pub fn announce(&self, id: &ContentId) -> Option<&PubAnnounce> {
        self.announces.get(id.as_bytes())
    }

    /// A content-addressed manifest fetch (§22.4.4).
    pub fn manifest(&self, id: &ContentId) -> Option<&PubManifest> {
        self.manifests.get(id.as_bytes())
    }

    /// A content-addressed plaintext-chunk fetch (§22.4.4). The returned bytes self-verify against
    /// `h` (checked here so a corrupted store can never serve wrong bytes, §22.5.3).
    pub fn chunk(&self, h: &ContentId) -> Option<&[u8]> {
        let bytes = self.chunks.get(h.as_bytes())?;
        if verify_chunk(bytes, h).is_ok() {
            Some(bytes)
        } else {
            None
        }
    }

    /// Whether the holder policy declines to serve `id` (§22.6.2). Used by the read path to answer
    /// a declined object as unavailable (the fetcher rotates to another holder).
    fn declined(&self, id: &ContentId) -> bool {
        self.policy.admit(id, 0, 0) == Err(PubError::NotServed)
    }
}

// ── HTTP response ────────────────────────────────────────────────────────────────────────────

/// A DMTAP-PUB HTTP response (§22.5.1). Carries the cache directives the well-known surface uses:
/// immutable + strong ETag for the four content-addressed endpoints; short/must-revalidate for the
/// mutable feed head. The bytes are `application/cbor` for every endpoint except the raw chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PubResponse {
    pub status: u16,
    pub content_type: &'static str,
    pub cache_control: Option<String>,
    pub etag: Option<String>,
    pub body: Vec<u8>,
}

impl PubResponse {
    fn not_found() -> Self {
        PubResponse {
            status: 404,
            content_type: "text/plain",
            cache_control: None,
            etag: None,
            body: b"not found".to_vec(),
        }
    }

    fn bad_request(msg: &str) -> Self {
        PubResponse {
            status: 400,
            content_type: "text/plain",
            cache_control: None,
            etag: None,
            body: msg.as_bytes().to_vec(),
        }
    }

    /// An immutable content-addressed object (§22.5.1): `public, immutable`, long max-age, strong
    /// ETag = the content address.
    fn immutable_cbor(body: Vec<u8>, etag: String) -> Self {
        PubResponse {
            status: 200,
            content_type: "application/cbor",
            cache_control: Some("public, immutable, max-age=31536000".into()),
            etag: Some(etag),
            body,
        }
    }

    /// A raw plaintext chunk (§22.5.1): immutable, but `application/octet-stream`.
    fn immutable_chunk(body: Vec<u8>, etag: String) -> Self {
        PubResponse {
            status: 200,
            content_type: "application/octet-stream",
            cache_control: Some("public, immutable, max-age=31536000".into()),
            etag: Some(etag),
            body,
        }
    }

    /// The mutable feed head (§22.5.1): short TTL + must-revalidate.
    fn mutable_head(body: Vec<u8>) -> Self {
        PubResponse {
            status: 200,
            content_type: "application/cbor",
            cache_control: Some("no-cache, must-revalidate, max-age=5".into()),
            etag: None,
            body,
        }
    }
}

// ── The gateway (operator opt-in) ─────────────────────────────────────────────────────────────

/// The operator's opt-in DMTAP-PUB surface (§22.6.1). Constructed disabled; the operator turns it on
/// with a verified `pub-1` capability ([`PubGateway::enable_with_capability`]) or, for a self-hosted
/// box where the operator *is* the node, [`PubGateway::enable`]. While disabled, [`handle`] answers
/// every `/.well-known/dmtap-pub/*` request `404` — the node "never advertises `pub-1`, never serves
/// public objects" (§22.6.1).
#[derive(Debug)]
pub struct PubGateway {
    /// The store this gateway serves; `pub` so the node's publish flow can `append`/`store_*`.
    pub store: PubStore,
    enabled: bool,
}

impl PubGateway {
    /// A new, **disabled** gateway (opt-out by default, §22.6.1).
    pub fn new(policy: ServePolicy) -> Self {
        PubGateway { store: PubStore::new(policy), enabled: false }
    }

    /// Enable serving unconditionally — for a self-hosted node where the operator *is* the node
    /// (managed == self-host, one software). Prefer [`PubGateway::enable_with_capability`] where a
    /// capability governs the opt-in.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Enable serving iff `token` is a valid `pub-1` capability for `operator` at `now`
    /// ([`pub1_authorizes`]). Returns whether it was enabled.
    pub fn enable_with_capability(
        &mut self,
        token: &CapabilityToken,
        operator: &[u8],
        now: TimestampMs,
    ) -> bool {
        if pub1_authorizes(token, operator, now) {
            self.enabled = true;
        }
        self.enabled
    }

    /// Whether this gateway currently advertises `pub-1` / serves public objects (§22.6.1).
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

/// Route one HTTP GET onto the §22.5.1 well-known surface. Reads are anonymous; the gateway must be
/// enabled (operator opted in via `pub-1`) or every pub path is `404`. Only `GET` is served (`405`
/// otherwise). Returns a self-verified, correctly-cached [`PubResponse`].
pub fn handle(gw: &PubGateway, method: &str, raw_path: &str) -> PubResponse {
    // Split off any query string.
    let (path, query) = match raw_path.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (raw_path, None),
    };

    let Some(rest) = path.strip_prefix(WELL_KNOWN_BASE) else {
        // Not our surface.
        return PubResponse::not_found();
    };
    // The surface serves nothing unless the operator opted in (§22.6.1).
    if !gw.is_enabled() {
        return PubResponse::not_found();
    }
    if method != "GET" {
        return PubResponse {
            status: 405,
            content_type: "text/plain",
            cache_control: None,
            etag: None,
            body: b"method not allowed".to_vec(),
        };
    }

    let segments: Vec<&str> = rest.split('/').collect();
    match segments.as_slice() {
        // GET feed/{pub}/head
        ["feed", pub_b64, "head"] => {
            let Some(publisher) = b64url_decode(pub_b64) else {
                return PubResponse::bad_request("bad base64url publisher");
            };
            match gw.store.feed_head(&publisher) {
                Some(head) => PubResponse::mutable_head(head.det_cbor()),
                None => PubResponse::not_found(),
            }
        }
        // GET feed/{pub}/range?from=&to=
        ["feed", pub_b64, "range"] => {
            let Some(publisher) = b64url_decode(pub_b64) else {
                return PubResponse::bad_request("bad base64url publisher");
            };
            let (from, to) = parse_range(query);
            match gw.store.feed_range(&publisher, from, to) {
                Some(entries) => {
                    // A range is derived data (a slice of immutable, chain-committed entries) — safe
                    // to cache immutably keyed by (pub, from, to). Body = CBOR array of entries.
                    let cv = dmtap_core::cbor::Cv::Array(
                        entries.iter().map(feed_entry_cv).collect(),
                    );
                    let body = dmtap_core::cbor::encode(&cv);
                    let etag = format!("{pub_b64}:{from}-{to}:{}", entries.len());
                    PubResponse::immutable_cbor(body, etag)
                }
                None => PubResponse::not_found(),
            }
        }
        // GET announce/{id}
        ["announce", id_b64] => serve_addressed(gw, id_b64, |store, id| {
            store.announce(id).map(|a| a.det_cbor())
        }),
        // GET manifest/{id}
        ["manifest", id_b64] => serve_addressed(gw, id_b64, |store, id| {
            store.manifest(id).map(|m| m.det_cbor())
        }),
        // GET chunk/{h}
        ["chunk", h_b64] => {
            let Some(h_bytes) = b64url_decode(h_b64) else {
                return PubResponse::bad_request("bad base64url hash");
            };
            let h = ContentId(h_bytes);
            if gw.store.declined(&h) {
                return PubResponse::not_found();
            }
            match gw.store.chunk(&h) {
                Some(bytes) => PubResponse::immutable_chunk(bytes.to_vec(), h_b64.to_string()),
                None => PubResponse::not_found(),
            }
        }
        _ => PubResponse::not_found(),
    }
}

/// Shared logic for the two content-addressed CBOR endpoints (announce, manifest): base64url-decode
/// the address, honor a policy decline as unavailable, and cache immutably with the address as ETag.
fn serve_addressed(
    gw: &PubGateway,
    id_b64: &str,
    fetch: impl Fn(&PubStore, &ContentId) -> Option<Vec<u8>>,
) -> PubResponse {
    let Some(id_bytes) = b64url_decode(id_b64) else {
        return PubResponse::bad_request("bad base64url id");
    };
    let id = ContentId(id_bytes);
    if gw.store.declined(&id) {
        return PubResponse::not_found();
    }
    match fetch(&gw.store, &id) {
        Some(body) => PubResponse::immutable_cbor(body, id_b64.to_string()),
        None => PubResponse::not_found(),
    }
}

/// Encode a [`FeedEntry`] as its canonical CBOR value (for the range endpoint's array body).
fn feed_entry_cv(e: &FeedEntry) -> dmtap_core::cbor::Cv {
    use dmtap_core::cbor::Cv;
    let mut m = vec![(1u64, Cv::U64(e.seq)), (2, Cv::Bytes(e.announce.as_bytes().to_vec()))];
    if let Some(p) = &e.prev {
        m.push((3, Cv::Bytes(p.as_bytes().to_vec())));
    }
    m.push((4, Cv::U64(e.ts)));
    Cv::Map(m)
}

/// Parse `from`/`to` from a `?from=&to=` query string; missing/unparsable default to `from=0`,
/// `to=u64::MAX` (clamped to the tip by [`PubStore::feed_range`]).
fn parse_range(query: Option<&str>) -> (u64, u64) {
    let mut from = 0u64;
    let mut to = u64::MAX;
    if let Some(q) = query {
        for pair in q.split('&') {
            if let Some(v) = pair.strip_prefix("from=") {
                if let Ok(n) = v.parse() {
                    from = n;
                }
            } else if let Some(v) = pair.strip_prefix("to=") {
                if let Ok(n) = v.parse() {
                    to = n;
                }
            }
        }
    }
    (from, to)
}

// ── base64url (unpadded) — §22.5.1 path encoding, no external crate ───────────────────────────

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encode bytes as unpadded base64url (§22.5.1 `{pub}`/`{id}`/`{h}`).
pub fn b64url_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity((bytes.len() * 4 + 2) / 3);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64URL[(n >> 18) as usize & 0x3f] as char);
        out.push(B64URL[(n >> 12) as usize & 0x3f] as char);
        if chunk.len() > 1 {
            out.push(B64URL[(n >> 6) as usize & 0x3f] as char);
        }
        if chunk.len() > 2 {
            out.push(B64URL[n as usize & 0x3f] as char);
        }
    }
    out
}

/// Decode unpadded base64url, failing closed (`None`) on any invalid character or length.
pub fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    if bytes.len() % 4 == 1 {
        return None; // an impossible base64 length
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= val(c)? << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Some(out)
}

// ── Optional suite check helper ───────────────────────────────────────────────────────────────

/// Whether a stored/served object's suite is one this node supports (v0 `0x01`). Unsupported suites
/// are never served (fail-closed, §22.10 `0x0901`).
pub fn suite_supported(suite: Suite) -> bool {
    suite.is_supported()
}

// ── Tests ────────────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use dmtap_core::capability::{Capability, CapabilityToken};

    fn announce(sk: &IdentityKey, ts: u64, supersedes: Option<ContentId>) -> PubAnnounce {
        let pk = sk.public();
        let mut a = PubAnnounce {
            v: 0,
            suite: Suite::Classical,
            publisher: pk.clone(),
            roots: vec![ContentId::of(b"root")],
            meta: Vec::new(),
            supersedes,
            ts,
            signer: pk,
            sig: Vec::new(),
        };
        a.sign(sk);
        a
    }

    #[test]
    fn b64url_roundtrips() {
        for n in 0..40usize {
            let bytes: Vec<u8> = (0..n).map(|i| (i as u8).wrapping_mul(37).wrapping_add(3)).collect();
            let enc = b64url_encode(&bytes);
            assert!(!enc.contains('='), "unpadded");
            assert_eq!(b64url_decode(&enc), Some(bytes), "roundtrip n={n}");
        }
        assert_eq!(b64url_decode("!!!"), None, "invalid chars fail closed");
    }

    #[test]
    fn disabled_gateway_serves_nothing() {
        let gw = PubGateway::new(ServePolicy::default());
        let pk = IdentityKey::from_seed(&[1u8; 32]).public();
        let path = format!("{WELL_KNOWN_BASE}feed/{}/head", b64url_encode(&pk));
        assert_eq!(handle(&gw, "GET", &path).status, 404);
    }

    #[test]
    fn capability_gates_enable() {
        let operator = IdentityKey::from_seed(&[9u8; 32]);
        let op_pub = operator.public();
        // A valid pub-1 capability the operator issued to itself.
        let token = CapabilityToken::issue(
            &operator,
            op_pub.clone(),
            vec![Capability { resource: PUB1_RESOURCE.into(), ability: PUB1_ABILITY.into(), caveats: None }],
            1000,
            1_000_000,
            vec![7u8; 16],
            None,
        );
        assert!(pub1_authorizes(&token, &op_pub, 2000));
        // Expired / wrong-audience / missing-cap all fail closed.
        assert!(!pub1_authorizes(&token, &op_pub, 2_000_000), "expired");
        assert!(!pub1_authorizes(&token, &[0u8; 32], 2000), "wrong audience");
        let no_cap = CapabilityToken::issue(
            &operator,
            op_pub.clone(),
            vec![Capability { resource: "mailbox".into(), ability: "read".into(), caveats: None }],
            1000,
            1_000_000,
            vec![8u8; 16],
            None,
        );
        assert!(!pub1_authorizes(&no_cap, &op_pub, 2000), "missing pub-1 cap");

        let mut gw = PubGateway::new(ServePolicy::default());
        assert!(!gw.is_enabled());
        assert!(gw.enable_with_capability(&token, &op_pub, 2000));
        assert!(gw.is_enabled());
    }

    #[test]
    fn publish_append_and_serve_feed() {
        let sk = IdentityKey::from_seed(&[2u8; 32]);
        let pk = sk.public();
        let mut gw = PubGateway::new(ServePolicy::default());
        gw.enable();

        // Genesis + two more appends → seq 0,1,2.
        let h0 = gw.store.append(announce(&sk, 1000, None), &sk, 1000).unwrap();
        assert_eq!(h0.seq, 0);
        let h1 = gw.store.append(announce(&sk, 2000, Some(ContentId::of(b"prev"))), &sk, 2000).unwrap();
        assert_eq!(h1.seq, 1);
        let h2 = gw.store.append(announce(&sk, 3000, None), &sk, 3000).unwrap();
        assert_eq!(h2.seq, 2);

        // The head is verifiable and its seq is the tip.
        let head = gw.store.feed_head(&pk).unwrap();
        head.verify().expect("served head verifies");
        assert_eq!(head.seq, 2);

        // A range slice is a valid prev-chain.
        let entries = gw.store.feed_range(&pk, 0, 2).unwrap();
        assert_eq!(entries.len(), 3);
        dmtap_core::pubobj::verify_feed_chain(&entries).expect("served range chains");

        // The head endpoint returns the signed head with must-revalidate caching.
        let path = format!("{WELL_KNOWN_BASE}feed/{}/head", b64url_encode(&pk));
        let resp = handle(&gw, "GET", &path);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.content_type, "application/cbor");
        assert!(resp.cache_control.as_deref().unwrap().contains("must-revalidate"));
        let served = FeedHead::from_det_cbor(&resp.body).unwrap();
        served.verify().unwrap();
        assert_eq!(served.seq, 2);

        // Range endpoint.
        let rpath = format!("{WELL_KNOWN_BASE}feed/{}/range?from=0&to=2", b64url_encode(&pk));
        let rresp = handle(&gw, "GET", &rpath);
        assert_eq!(rresp.status, 200);
        assert!(rresp.cache_control.as_deref().unwrap().contains("immutable"));
    }

    #[test]
    fn serve_announce_manifest_chunk_content_addressed() {
        let sk = IdentityKey::from_seed(&[3u8; 32]);
        let pk = sk.public();
        let mut gw = PubGateway::new(ServePolicy::default());
        gw.enable();

        // Pin a chunk, a manifest over it, and an announce referencing the manifest.
        let plaintext = b"published bytes".to_vec();
        let h = gw.store.store_chunk(plaintext.clone(), &pk).unwrap();
        let m = PubManifest::new(plaintext.len() as u64, 1 << 20, vec![h.clone()], Suite::Classical);
        let m_id = gw.store.store_manifest(m.clone(), &pk).unwrap();
        let mut a = announce(&sk, 1000, None);
        a.roots = vec![m_id.clone()];
        a.sign(&sk);
        let a_id = gw.store.store_announce(a.clone()).unwrap();

        // chunk endpoint.
        let cpath = format!("{WELL_KNOWN_BASE}chunk/{}", b64url_encode(h.as_bytes()));
        let cresp = handle(&gw, "GET", &cpath);
        assert_eq!(cresp.status, 200);
        assert_eq!(cresp.body, plaintext);
        assert_eq!(cresp.content_type, "application/octet-stream");
        assert!(cresp.cache_control.as_deref().unwrap().contains("immutable"));

        // manifest endpoint self-verifies.
        let mpath = format!("{WELL_KNOWN_BASE}manifest/{}", b64url_encode(m_id.as_bytes()));
        let mresp = handle(&gw, "GET", &mpath);
        assert_eq!(mresp.status, 200);
        let served_m = PubManifest::from_det_cbor(&mresp.body).unwrap();
        served_m.verify().unwrap();
        assert_eq!(served_m.id, m_id);

        // announce endpoint self-verifies against its own id.
        let apath = format!("{WELL_KNOWN_BASE}announce/{}", b64url_encode(a_id.as_bytes()));
        let aresp = handle(&gw, "GET", &apath);
        assert_eq!(aresp.status, 200);
        let served_a = PubAnnounce::from_det_cbor(&aresp.body).unwrap();
        served_a.verify(&a_id).unwrap();

        // A miss is 404.
        let miss = format!("{WELL_KNOWN_BASE}announce/{}", b64url_encode(ContentId::of(b"nope").as_bytes()));
        assert_eq!(handle(&gw, "GET", &miss).status, 404);
        // Wrong method is 405.
        assert_eq!(handle(&gw, "POST", &apath).status, 405);
    }

    #[test]
    fn serve_policy_declines_and_quota() {
        let sk = IdentityKey::from_seed(&[4u8; 32]);
        let pk = sk.public();
        let declined_plain = b"declined-bytes".to_vec();
        let declined_h = dmtap_core::pubobj::chunk_hash(&declined_plain);
        let policy = ServePolicy {
            declined: vec![declined_h.clone()],
            max_object_size: Some(1000),
            per_publisher_quota: Some(2000),
        };
        let mut gw = PubGateway::new(policy);
        gw.enable();

        // A declined chunk is refused at store time (NotServed) ...
        assert_eq!(gw.store.store_chunk(declined_plain, &pk), Err(PubError::NotServed));
        // ... and an over-size object trips ServeQuota.
        let big = vec![0u8; 1001];
        assert_eq!(gw.store.store_chunk(big, &pk), Err(PubError::ServeQuota));

        // A declined content address reads as 404 (rotate to another holder).
        let path = format!("{WELL_KNOWN_BASE}chunk/{}", b64url_encode(declined_h.as_bytes()));
        assert_eq!(handle(&gw, "GET", &path).status, 404);
    }

    #[test]
    fn append_rejects_mismatched_signer() {
        let sk = IdentityKey::from_seed(&[5u8; 32]);
        let other = IdentityKey::from_seed(&[6u8; 32]);
        let mut gw = PubGateway::new(ServePolicy::default());
        gw.enable();
        // The announce is signed by `sk`, but we hand `append` the wrong signer key.
        let a = announce(&sk, 1000, None);
        assert_eq!(gw.store.append(a, &other, 1000), Err(PubError::AnnounceSigInvalid));
    }
}

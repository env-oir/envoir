//! DMTAP-PUB: Public Objects (spec §22) — the additive "authenticity without confidentiality"
//! quadrant. Signed-in-the-clear objects, plaintext content addressing (global cross-user dedup),
//! author feeds with anti-rollback and equivocation detection.
//!
//! This is a **reference implementation, not normative** — where this code and the spec disagree,
//! the spec (`../../../dmtap/22-public-objects.md`) governs (§10.4). Every wire object here is an
//! integer-keyed canonical CBOR map (§18.1.2) that flows through [`crate::cbor`], exactly like the
//! MOTE layer ([`crate::mote`]).
//!
//! ## Object model
//! - [`PubManifest`] (§22.2.1) — a plaintext-addressed Merkle-DAG manifest, the structural twin of
//!   the sealed [`crate::mote::Manifest`] with three deliberate differences: the tree is
//!   DS-tag-domain-separated (§22.2.2) so a public root can never collide with a sealed one, the
//!   chunk hashes are over **plaintext** (not ciphertext), and key `5` (the AEAD key) is
//!   **forbidden by construction** (a public blob has no key).
//! - [`PubAnnounce`] (kind `0x40`, §22.3) — a bare, unsealed, signed announcement carrying the
//!   publisher's identity in the clear. Content-addressed by the derived-anchor rule (§18.9.4).
//! - [`FeedEntry`] / [`FeedHead`] (§22.4) — the per-identity, append-only, signed author feed. The
//!   head signs the tip, which transitively commits the whole `prev`-chained log, so entries need
//!   no per-entry signature (as with cluster-journal entries, §5.6.3(b), and KT leaves, §3.5).
//!
//! ## Error registry (`ERR_PUB_*`, `0x0900`–`0x09FF`, §22.10)
//! Every fail-closed check maps to a [`PubError`] with its spec error code; see [`PubError::code`].

use blake3;

use crate::cbor::{self, as_bytes, as_u32, as_u64, as_u8, Cv, Fields};
use crate::id::{ContentId, MH_BLAKE3_256};
use crate::identity::{verify_domain, IdentityKey};
use crate::suite::Suite;

// ── Domain-separation tags (§18.1.6, §22.2.2/.3.1/.4.1) ──────────────────────────────────────
//
// Each ends in a trailing `0x00`, matching the reference's `DMTAP-v0/*` tags (§18.9). The
// manifest tag additionally participates in the tree leaf/node construction below.

/// `DMTAP-PUB-v0/manifest\x00` — folded into every Merkle leaf/node so a public root can never
/// collide with a sealed one over the same chunk-hash list (§22.2.2, §22.2.3).
pub const PUB_MANIFEST_DS: &[u8] = b"DMTAP-PUB-v0/manifest\x00";
/// `DMTAP-PUB-v0/announce\x00` — the `PubAnnounce.sig` signing-preimage prefix (§22.3.1).
pub const PUB_ANNOUNCE_DS: &[u8] = b"DMTAP-PUB-v0/announce\x00";
/// `DMTAP-PUB-v0/feed\x00` — the `FeedHead.sig` signing-preimage prefix (§22.4.1).
pub const PUB_FEED_DS: &[u8] = b"DMTAP-PUB-v0/feed\x00";

/// The only PUB object-format version wired in v0 (`PubAnnounce.v` / `FeedHead.v`, §22.3.1/.4.1).
pub const PUB_V0: u8 = 0;

// ── Errors (§22.10) ─────────────────────────────────────────────────────────────────────────

/// A DMTAP-PUB fail-closed error. Each variant carries its spec error code (§22.10); see
/// [`PubError::code`] and [`PubError::name`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PubError {
    /// `0x0901` — a `v`/`suite` this implementation does not support (§22.3.1, §22.4.1).
    #[error("ERR_PUB_UNSUPPORTED_VERSION (0x0901)")]
    UnsupportedVersion,
    /// `0x0902` — a `PubManifest` carrying the forbidden key `5` (§22.2.1).
    #[error("ERR_PUB_MANIFEST_KEY_PRESENT (0x0902)")]
    ManifestKeyPresent,
    /// `0x0903` — sealed/public manifest DS-tag confusion (§22.2.3).
    #[error("ERR_PUB_MANIFEST_TYPE_MISMATCH (0x0903)")]
    ManifestTypeMismatch,
    /// `0x0904` — `sig` fails under `signer`, or `signer` not authorized by `pub` (§22.3.3).
    #[error("ERR_PUB_ANNOUNCE_SIG_INVALID (0x0904)")]
    AnnounceSigInvalid,
    /// `0x0905` — recomputed `announce_id` ≠ the address it was fetched by (§22.3.1).
    #[error("ERR_PUB_ANNOUNCE_ID_MISMATCH (0x0905)")]
    AnnounceIdMismatch,
    /// `0x0906` — `FeedHead.sig` fails under `signer`/`pub` chain (§22.4.1).
    #[error("ERR_PUB_FEED_SIG_INVALID (0x0906)")]
    FeedSigInvalid,
    /// `0x0907` — a `FeedHead` with `seq` strictly below the highest accepted (§22.4.2).
    #[error("ERR_PUB_FEED_ROLLBACK (0x0907)")]
    FeedRollback,
    /// `0x0908` — feed fork/rewrite: two entries at one `seq`, or a broken `prev`-chain (§22.4.2).
    #[error("ERR_PUB_FEED_CHAIN_BROKEN (0x0908)")]
    FeedChainBroken,
    /// `0x0909` — recomputed DS-tagged Merkle root ≠ `PubManifest.id` (§22.2.2).
    #[error("ERR_PUB_MANIFEST_HASH_MISMATCH (0x0909)")]
    ManifestHashMismatch,
    /// `0x090A` — a fetched plaintext chunk ≠ its listed `h_i` (§22.5.3).
    #[error("ERR_PUB_CHUNK_HASH_MISMATCH (0x090A)")]
    ChunkHashMismatch,
    /// `0x090B` — `supersedes` references an announce whose `pub` differs (§22.3.4).
    #[error("ERR_PUB_SUPERSEDE_INVALID (0x090B)")]
    SupersedeInvalid,
    /// `0x090C` — a holder declines to serve per its own policy (§22.6.2). A policy deny, never a
    /// correctness fault, never a protocol takedown; the fetcher rotates to another holder.
    #[error("ERR_PUB_NOT_SERVED (0x090C)")]
    NotServed,
    /// `0x090D` — a serving node's admission policy (size/quota/rate) is exceeded (§22.6.3).
    #[error("ERR_PUB_SERVE_QUOTA (0x090D)")]
    ServeQuota,
    /// A lower-level canonical-CBOR violation on decode (§18.1.1) — malformed bytes, wrong type,
    /// unknown key in a signed object, etc.
    #[error("CBOR: {0}")]
    Cbor(#[from] cbor::CborError),
}

impl PubError {
    /// The §22.10 error code (`0x0900`–`0x09FF`). CBOR-level errors report `0x0900` (the subsystem
    /// base) since they are decode faults with no dedicated PUB code.
    pub fn code(&self) -> u16 {
        match self {
            PubError::UnsupportedVersion => 0x0901,
            PubError::ManifestKeyPresent => 0x0902,
            PubError::ManifestTypeMismatch => 0x0903,
            PubError::AnnounceSigInvalid => 0x0904,
            PubError::AnnounceIdMismatch => 0x0905,
            PubError::FeedSigInvalid => 0x0906,
            PubError::FeedRollback => 0x0907,
            PubError::FeedChainBroken => 0x0908,
            PubError::ManifestHashMismatch => 0x0909,
            PubError::ChunkHashMismatch => 0x090A,
            PubError::SupersedeInvalid => 0x090B,
            PubError::NotServed => 0x090C,
            PubError::ServeQuota => 0x090D,
            PubError::Cbor(_) => 0x0900,
        }
    }

    /// The spec `ERR_PUB_*` name for this error (§22.10).
    pub fn name(&self) -> &'static str {
        match self {
            PubError::UnsupportedVersion => "ERR_PUB_UNSUPPORTED_VERSION",
            PubError::ManifestKeyPresent => "ERR_PUB_MANIFEST_KEY_PRESENT",
            PubError::ManifestTypeMismatch => "ERR_PUB_MANIFEST_TYPE_MISMATCH",
            PubError::AnnounceSigInvalid => "ERR_PUB_ANNOUNCE_SIG_INVALID",
            PubError::AnnounceIdMismatch => "ERR_PUB_ANNOUNCE_ID_MISMATCH",
            PubError::FeedSigInvalid => "ERR_PUB_FEED_SIG_INVALID",
            PubError::FeedRollback => "ERR_PUB_FEED_ROLLBACK",
            PubError::FeedChainBroken => "ERR_PUB_FEED_CHAIN_BROKEN",
            PubError::ManifestHashMismatch => "ERR_PUB_MANIFEST_HASH_MISMATCH",
            PubError::ChunkHashMismatch => "ERR_PUB_CHUNK_HASH_MISMATCH",
            PubError::SupersedeInvalid => "ERR_PUB_SUPERSEDE_INVALID",
            PubError::NotServed => "ERR_PUB_NOT_SERVED",
            PubError::ServeQuota => "ERR_PUB_SERVE_QUOTA",
            PubError::Cbor(_) => "ERR_PUB_CBOR",
        }
    }
}

// ── Plaintext content addressing (§22.2.2) ───────────────────────────────────────────────────

/// `h_i = 0x1e ‖ BLAKE3-256(plaintext_i)` — the public (plaintext) per-chunk content address
/// (§22.2.2). Contrast the sealed `h_i = prefix ‖ BLAKE3-256(AEAD(key, plaintext_i))` of §18.9.5:
/// public blobs are plaintext-addressed **on purpose**, for global cross-user dedup (§22.2.4).
pub fn chunk_hash(plaintext: &[u8]) -> ContentId {
    ContentId::of(plaintext)
}

/// A DS-tagged Merkle leaf: `leaf(h) = BLAKE3-256( DS ‖ 0x00 ‖ h )`, DS = [`PUB_MANIFEST_DS`]
/// (which already carries its own trailing `0x00`, §22.2.2).
fn pub_leaf(h: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(PUB_MANIFEST_DS.len() + 1 + h.len());
    buf.extend_from_slice(PUB_MANIFEST_DS);
    buf.push(0x00);
    buf.extend_from_slice(h);
    *blake3::hash(&buf).as_bytes()
}

/// A DS-tagged Merkle internal node: `node(l, r) = BLAKE3-256( DS ‖ 0x01 ‖ l ‖ r )` (§22.2.2).
fn pub_node(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(PUB_MANIFEST_DS.len() + 1 + 64);
    buf.extend_from_slice(PUB_MANIFEST_DS);
    buf.push(0x01);
    buf.extend_from_slice(l);
    buf.extend_from_slice(r);
    *blake3::hash(&buf).as_bytes()
}

/// RFC 6962-style Merkle Tree Head over pre-computed leaf digests, folding an internal-node
/// function `f`. The non-power-of-two split takes `k` = the largest power of two strictly less
/// than `n` (no padding); requires `n ≥ 1`.
fn mth<F: Fn(&[u8; 32], &[u8; 32]) -> [u8; 32] + Copy>(leaves: &[[u8; 32]], f: F) -> [u8; 32] {
    match leaves.len() {
        0 => panic!("merkle root requires at least one leaf (§22.2.2)"),
        1 => leaves[0],
        n => {
            let mut k = 1usize;
            while k << 1 < n {
                k <<= 1;
            }
            f(&mth(&leaves[..k], f), &mth(&leaves[k..], f))
        }
    }
}

/// The §22.2.2 public-manifest content address: `0x1e ‖ MTH(h_0 … h_{n-1})`, RFC 6962 tree with
/// the [`PUB_MANIFEST_DS`] DS-tag folded into every leaf and node. `chunks` is the ordered list of
/// stored `h_i` values (each already `0x1e ‖ BLAKE3(plaintext_i)`, §22.2.2). Requires `n ≥ 1`.
pub fn pub_manifest_root(chunks: &[ContentId]) -> ContentId {
    let leaves: Vec<[u8; 32]> = chunks.iter().map(|c| pub_leaf(c.as_bytes())).collect();
    let root = mth(&leaves, pub_node);
    let mut v = Vec::with_capacity(33);
    v.push(MH_BLAKE3_256);
    v.extend_from_slice(&root);
    ContentId(v)
}

/// The §18.9.5 **sealed-style** bare Merkle root over the same ordered chunk-hash list:
/// `leaf(h) = BLAKE3-256(0x00 ‖ h)`, `node(l, r) = BLAKE3-256(0x01 ‖ l ‖ r)`, **no DS fold**. Used
/// only to demonstrate the §22.2.3 type-incompatibility: over an identical `h_i` list this yields a
/// value that MUST differ from [`pub_manifest_root`] — the DS-tag alone prevents a sealed↔public
/// root collision (before even considering that real sealed `h_i` are over ciphertext).
pub fn sealed_style_root(chunks: &[ContentId]) -> ContentId {
    fn leaf(h: &[u8]) -> [u8; 32] {
        *blake3::hash(&[&[0x00u8], h].concat()).as_bytes()
    }
    fn node(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
        let mut buf = Vec::with_capacity(1 + 64);
        buf.push(0x01);
        buf.extend_from_slice(l);
        buf.extend_from_slice(r);
        *blake3::hash(&buf).as_bytes()
    }
    let leaves: Vec<[u8; 32]> = chunks.iter().map(|c| leaf(c.as_bytes())).collect();
    let root = mth(&leaves, node);
    let mut v = Vec::with_capacity(33);
    v.push(MH_BLAKE3_256);
    v.extend_from_slice(&root);
    ContentId(v)
}

/// Decode a `suite` byte, mapping an unknown suite to [`PubError::UnsupportedVersion`] (`0x0901`,
/// the §22 analogue of the unknown-suite rule §1.1/`0x0101`).
fn pub_suite(cv: Cv) -> Result<Suite, PubError> {
    let b = as_u8(cv)?;
    Suite::from_u8(b).ok_or(PubError::UnsupportedVersion)
}

// ── PubManifest (§22.2.1) ────────────────────────────────────────────────────────────────────

/// The plaintext-addressed public-blob manifest (§22.2.1) — the structural twin of the sealed
/// [`crate::mote::Manifest`]. Key `5` is **forbidden by construction**: a public blob is
/// unencrypted, so there is no key to carry (contrast the sealed manifest, which forbids key 5
/// *lest it leak*; this one forbids it *because none exists*).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PubManifest {
    /// key 1 — content address = DS-tagged Merkle root over `chunks` (§22.2.2).
    pub id: ContentId,
    /// key 2 — total plaintext size in bytes.
    pub size: u64,
    /// key 3 — fixed chunk size (every chunk except possibly the last is exactly this many bytes).
    pub chunk_sz: u32,
    /// key 4 — ordered list of plaintext chunk content addresses `h_i` (≥ 1).
    pub chunks: Vec<ContentId>,
    /// key 6 — hash suite governing each `h_i` and `id` (no AEAD selector; public chunks are not
    /// encrypted, §18.1.4).
    pub suite: Suite,
}

impl PubManifest {
    /// Build a manifest from an ordered plaintext-chunk-hash list, computing `id` = the §22.2.2 root.
    pub fn new(size: u64, chunk_sz: u32, chunks: Vec<ContentId>, suite: Suite) -> Self {
        let id = pub_manifest_root(&chunks);
        PubManifest { id, size, chunk_sz, chunks, suite }
    }

    fn to_cv(&self) -> Cv {
        // Keys 1,2,3,4,6 (key 5 FORBIDDEN by construction, §22.2.1).
        Cv::Map(vec![
            (1, Cv::Bytes(self.id.as_bytes().to_vec())),
            (2, Cv::U64(self.size)),
            (3, Cv::U64(self.chunk_sz as u64)),
            (4, Cv::Array(self.chunks.iter().map(|c| Cv::Bytes(c.as_bytes().to_vec())).collect())),
            (6, Cv::U64(self.suite.as_u8() as u64)),
        ])
    }

    /// The exact wire bytes: §18-canonical integer-keyed CBOR.
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv())
    }

    /// The §22.2.2 DS-tagged Merkle root over `chunks` (the value `id` MUST equal).
    pub fn merkle_root(&self) -> ContentId {
        pub_manifest_root(&self.chunks)
    }

    /// Verify `id` self-consistency: the recomputed DS-tagged root MUST equal `id`
    /// ([`PubError::ManifestHashMismatch`], `0x0909`), so a fetcher rejects before beginning a fetch.
    pub fn verify(&self) -> Result<(), PubError> {
        if self.chunks.is_empty() {
            return Err(PubError::Cbor(cbor::CborError::ManifestEmptyChunks));
        }
        if self.id != self.merkle_root() {
            return Err(PubError::ManifestHashMismatch);
        }
        Ok(())
    }

    /// Decode a `PubManifest` (§22.2.1). Rejects a present key `5` as [`PubError::ManifestKeyPresent`]
    /// (`0x0902`) **before anything else** — a leaked sealed manifest or a malformation, never
    /// honored. An unknown suite is [`PubError::UnsupportedVersion`] (`0x0901`); an empty chunk list
    /// is rejected fail-closed.
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, PubError> {
        let mut f = Fields::from_cv(cbor::decode(bytes)?)?;
        if f.has(5) {
            return Err(PubError::ManifestKeyPresent);
        }
        let id = ContentId(as_bytes(f.req(1)?)?);
        let size = as_u64(f.req(2)?)?;
        let chunk_sz = as_u32(f.req(3)?)?;
        let chunks: Vec<ContentId> = cbor::as_array(f.req(4)?)?
            .into_iter()
            .map(|c| as_bytes(c).map(ContentId))
            .collect::<Result<_, _>>()?;
        if chunks.is_empty() {
            return Err(PubError::Cbor(cbor::CborError::ManifestEmptyChunks));
        }
        let suite = pub_suite(f.req(6)?)?;
        f.deny_unknown()?;
        Ok(PubManifest { id, size, chunk_sz, chunks, suite })
    }
}

// ── PubAnnounce (kind 0x40, §22.3) ───────────────────────────────────────────────────────────

/// A bare, unsealed, signed public announcement (§22.3.1). Carries the publisher's identity in the
/// clear (`publisher`/`signer`) — authenticity, not anonymity; the deliberate inverse of a MOTE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PubAnnounce {
    /// key 1 — PUB object version; MUST be [`PUB_V0`] in v0.
    pub v: u8,
    /// key 2 — signature/hash suite (§18.1.4).
    pub suite: Suite,
    /// key 3 — publisher root identity key `IK` (the point of the object).
    pub publisher: Vec<u8>,
    /// key 4 — referenced `PubManifest.id` content addresses (≥ 1).
    pub roots: Vec<ContentId>,
    /// key 5 — structured, text-keyed metadata (profile-defined, §23). MAY be empty.
    pub meta: Vec<(String, Cv)>,
    /// key 6 — content address of a prior `PubAnnounce` this revises (revision chain, §22.3.4).
    pub supersedes: Option<ContentId>,
    /// key 7 — publish timestamp (ms epoch).
    pub ts: u64,
    /// key 8 — operational key that produced `sig`; a `DeviceCert` chains it to `publisher`.
    pub signer: Vec<u8>,
    /// key 9 — `signer` over `DMTAP-PUB-v0/announce ‖ 0x00 ‖ det_cbor(PubAnnounce ∖ {9})`.
    pub sig: Vec<u8>,
}

impl PubAnnounce {
    fn to_cv(&self, include_sig: bool) -> Cv {
        let mut m = vec![
            (1u64, Cv::U64(self.v as u64)),
            (2, Cv::U64(self.suite.as_u8() as u64)),
            (3, Cv::Bytes(self.publisher.clone())),
            (4, Cv::Array(self.roots.iter().map(|r| Cv::Bytes(r.as_bytes().to_vec())).collect())),
            (5, Cv::TextMap(self.meta.clone())),
        ];
        if let Some(s) = &self.supersedes {
            m.push((6, Cv::Bytes(s.as_bytes().to_vec())));
        }
        m.push((7, Cv::U64(self.ts)));
        m.push((8, Cv::Bytes(self.signer.clone())));
        if include_sig {
            m.push((9, Cv::Bytes(self.sig.clone())));
        }
        Cv::Map(m)
    }

    /// The §22.3.1 signing preimage body: `det_cbor(PubAnnounce ∖ {9})` (sig excluded).
    pub fn signing_preimage(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(false))
    }

    /// The exact wire bytes of the complete, signed object.
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(true))
    }

    /// `announce_id = 0x1e ‖ BLAKE3-256(det_cbor(PubAnnounce))` over the **complete, signed** object
    /// — the derived-anchor rule of §18.9.4 (an object cannot contain its own hash, §22.3.1).
    pub fn announce_id(&self) -> ContentId {
        ContentId::of(&self.det_cbor())
    }

    /// Sign this announce: `signer_key` produces `sig` over the DS-tagged preimage (§22.3.1). The
    /// caller is responsible for `signer_key`'s public key matching `self.signer`.
    pub fn sign(&mut self, signer_key: &IdentityKey) {
        self.sig = signer_key.sign_domain(PUB_ANNOUNCE_DS, &self.signing_preimage());
    }

    /// Verify a fetched announce in §22.3.3 order:
    /// 1. reject unknown `v`/`suite` (`0x0901`);
    /// 2. `announce_id` MUST equal `fetched_by` (`0x0905`);
    /// 3. `sig` MUST verify under `signer` over the DS-tagged preimage (`0x0904`);
    /// 4. `signer` MUST be authorized by `publisher` — here either `signer == publisher`, or the
    ///    caller supplies a verified [`crate::identity::DeviceCert`] chain via
    ///    [`PubAnnounce::verify_with_cert`] (`0x0904` on a broken chain).
    ///
    /// Replay/ordering are the feed's job (§22.4), never a bare announce's.
    pub fn verify(&self, fetched_by: &ContentId) -> Result<(), PubError> {
        if self.v != PUB_V0 || !self.suite.is_supported() {
            return Err(PubError::UnsupportedVersion);
        }
        if &self.announce_id() != fetched_by {
            return Err(PubError::AnnounceIdMismatch);
        }
        verify_domain(&self.signer, PUB_ANNOUNCE_DS, &self.signing_preimage(), &self.sig)
            .map_err(|_| PubError::AnnounceSigInvalid)?;
        // §22.3.3 step 4: signer authorized by pub. The direct case (`signer == pub`, IK signs
        // directly). For an operational signer, the caller must present a DeviceCert
        // (`verify_with_cert`); a bare announce whose signer ≠ pub without one is rejected.
        if self.signer != self.publisher {
            return Err(PubError::AnnounceSigInvalid);
        }
        Ok(())
    }

    /// Like [`PubAnnounce::verify`] but authorizing an operational `signer` via a
    /// [`crate::identity::DeviceCert`] chaining it to `publisher` (§22.3.3 step 4, §1.2). The cert
    /// MUST itself verify, its `ik` MUST equal `publisher`, and its `device_key` MUST equal `signer`.
    pub fn verify_with_cert(
        &self,
        fetched_by: &ContentId,
        cert: &crate::identity::DeviceCert,
    ) -> Result<(), PubError> {
        if self.v != PUB_V0 || !self.suite.is_supported() {
            return Err(PubError::UnsupportedVersion);
        }
        if &self.announce_id() != fetched_by {
            return Err(PubError::AnnounceIdMismatch);
        }
        verify_domain(&self.signer, PUB_ANNOUNCE_DS, &self.signing_preimage(), &self.sig)
            .map_err(|_| PubError::AnnounceSigInvalid)?;
        if self.signer == self.publisher {
            return Ok(());
        }
        cert.verify().map_err(|_| PubError::AnnounceSigInvalid)?;
        if cert.ik != self.publisher || cert.device_key != self.signer {
            return Err(PubError::AnnounceSigInvalid);
        }
        Ok(())
    }

    /// Decode a `PubAnnounce` (§22.3.1). Rejects unknown `v`/`suite` fail-closed (`0x0901`).
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, PubError> {
        let mut f = Fields::from_cv(cbor::decode(bytes)?)?;
        let v = as_u8(f.req(1)?)?;
        if v != PUB_V0 {
            return Err(PubError::UnsupportedVersion);
        }
        let suite = pub_suite(f.req(2)?)?;
        let publisher = as_bytes(f.req(3)?)?;
        let roots: Vec<ContentId> = cbor::as_array(f.req(4)?)?
            .into_iter()
            .map(|c| as_bytes(c).map(ContentId))
            .collect::<Result<_, _>>()?;
        if roots.is_empty() {
            // §22.3.1: an announce with empty `roots` is malformed.
            return Err(PubError::Cbor(cbor::CborError::TypeMismatch));
        }
        let meta = match f.req(5)? {
            Cv::TextMap(m) => m,
            Cv::Map(m) if m.is_empty() => Vec::new(),
            _ => return Err(PubError::Cbor(cbor::CborError::TypeMismatch)),
        };
        let supersedes = f.take(6).map(as_bytes).transpose()?.map(ContentId);
        let ts = as_u64(f.req(7)?)?;
        let signer = as_bytes(f.req(8)?)?;
        let sig = as_bytes(f.req(9)?)?;
        f.deny_unknown()?;
        Ok(PubAnnounce { v, suite, publisher, roots, meta, supersedes, ts, signer, sig })
    }
}

/// §22.3.4 / §22.3.3 step 5: a publisher may only supersede its **own** announcements. Rejects a
/// cross-author `supersedes` link as [`PubError::SupersedeInvalid`] (`0x090B`).
pub fn check_supersede(predecessor_pub: &[u8], successor_pub: &[u8]) -> Result<(), PubError> {
    if predecessor_pub == successor_pub {
        Ok(())
    } else {
        Err(PubError::SupersedeInvalid)
    }
}

/// §22.5.3 / §5.5.3: a fetched plaintext chunk MUST self-verify against its listed `h_i`. A
/// mismatch is [`PubError::ChunkHashMismatch`] (`0x090A`, ROTATE_RETRY) — rotate to another holder;
/// a holder cannot serve wrong-but-accepted bytes (BLAKE3 collision resistance).
pub fn verify_chunk(plaintext: &[u8], listed_h: &ContentId) -> Result<(), PubError> {
    if &chunk_hash(plaintext) == listed_h {
        Ok(())
    } else {
        Err(PubError::ChunkHashMismatch)
    }
}

// ── Holder serve policy (§22.6.2/.6.3) ───────────────────────────────────────────────────────

/// A holder's per-object serve policy (§22.6). Serving public objects is opt-in and a holder is
/// **not blind** (§22.6.1), so admission is a discretionary operator decision. Refusal is a policy
/// deny, never a correctness/crypto fault and never a protocol takedown; a fetcher responds by
/// rotating to another holder.
#[derive(Debug, Clone, Default)]
pub struct ServePolicy {
    /// Content addresses this holder declines to serve, for any reason (content, publisher,
    /// jurisdiction) — a §22.6.2 discretionary refusal → [`PubError::NotServed`] (`0x090C`).
    pub declined: Vec<ContentId>,
    /// Maximum admitted object size in bytes, or `None` for no ceiling (§22.6.3).
    pub max_object_size: Option<u64>,
    /// Maximum total bytes stored per publisher, or `None` for no quota (§22.6.3).
    pub per_publisher_quota: Option<u64>,
}

impl ServePolicy {
    /// Decide whether to serve/store object `id` of `size` bytes given `already_stored` bytes for
    /// that publisher. A declined id is [`PubError::NotServed`] (`0x090C`); an exceeded size ceiling
    /// or per-publisher quota is [`PubError::ServeQuota`] (`0x090D`). Both are `DENY_POLICY` — a
    /// policy deny, never a security/crypto gate, never a silent hole.
    pub fn admit(&self, id: &ContentId, size: u64, already_stored: u64) -> Result<(), PubError> {
        if self.declined.iter().any(|d| d == id) {
            return Err(PubError::NotServed);
        }
        if let Some(max) = self.max_object_size {
            if size > max {
                return Err(PubError::ServeQuota);
            }
        }
        if let Some(quota) = self.per_publisher_quota {
            if already_stored.saturating_add(size) > quota {
                return Err(PubError::ServeQuota);
            }
        }
        Ok(())
    }
}

// ── Author feeds (§22.4) ─────────────────────────────────────────────────────────────────────

/// One position in an author feed (§22.4.1). Carries no signature of its own; its authenticity
/// flows from the signed [`FeedHead`]'s transitive `tip` commitment down the `prev`-chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedEntry {
    /// key 1 — strictly increasing per feed, genesis `= 0`.
    pub seq: u64,
    /// key 2 — the `announce_id` (§22.3.1) published at this position.
    pub announce: ContentId,
    /// key 3 — content address of the entry at `seq-1`; ABSENT iff `seq == 0` (genesis).
    pub prev: Option<ContentId>,
    /// key 4 — entry time (ms epoch).
    pub ts: u64,
}

impl FeedEntry {
    fn to_cv(&self) -> Cv {
        let mut m = vec![(1u64, Cv::U64(self.seq)), (2, Cv::Bytes(self.announce.as_bytes().to_vec()))];
        if let Some(p) = &self.prev {
            m.push((3, Cv::Bytes(p.as_bytes().to_vec())));
        }
        m.push((4, Cv::U64(self.ts)));
        Cv::Map(m)
    }

    /// The exact wire bytes: §18-canonical integer-keyed CBOR.
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv())
    }

    /// `entry_id = 0x1e ‖ BLAKE3-256(det_cbor(FeedEntry))` — the generic §18.9.4 anchor rule, with
    /// **no** DS-tag fold (an unsigned entry's authenticity flows solely from the signed head's
    /// transitive `tip` commitment, §22.4.1).
    pub fn entry_id(&self) -> ContentId {
        ContentId::of(&self.det_cbor())
    }

    /// Decode a `FeedEntry` (§22.4.1), enforcing the genesis/`prev` structural rule fail-closed: a
    /// genesis entry (`seq == 0`) carrying `prev`, or a non-genesis entry lacking it, is malformed
    /// ([`PubError::FeedChainBroken`], `0x0908`).
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, PubError> {
        let mut f = Fields::from_cv(cbor::decode(bytes)?)?;
        let seq = as_u64(f.req(1)?)?;
        let announce = ContentId(as_bytes(f.req(2)?)?);
        let prev = f.take(3).map(as_bytes).transpose()?.map(ContentId);
        let ts = as_u64(f.req(4)?)?;
        f.deny_unknown()?;
        match (seq, &prev) {
            (0, Some(_)) => return Err(PubError::FeedChainBroken), // genesis MUST NOT carry prev
            (n, None) if n != 0 => return Err(PubError::FeedChainBroken), // non-genesis MUST carry prev
            _ => {}
        }
        Ok(FeedEntry { seq, announce, prev, ts })
    }
}

/// Validate an ordered slice of feed entries by the §22.4.1 `prev`-chain rules: `seq` strictly
/// increasing by 1 from the first entry, genesis (`seq == 0`) carries no `prev`, and every
/// non-genesis entry's `prev` resolves to its predecessor's [`FeedEntry::entry_id`]. A break is
/// [`PubError::FeedChainBroken`] (`0x0908`, HALT_ALERT).
pub fn verify_feed_chain(entries: &[FeedEntry]) -> Result<(), PubError> {
    for (i, e) in entries.iter().enumerate() {
        match (e.seq, &e.prev) {
            (0, Some(_)) => return Err(PubError::FeedChainBroken),
            (n, None) if n != 0 => return Err(PubError::FeedChainBroken),
            _ => {}
        }
        if i > 0 {
            let prev_entry = &entries[i - 1];
            if e.seq != prev_entry.seq + 1 {
                return Err(PubError::FeedChainBroken);
            }
            match &e.prev {
                Some(p) if p == &prev_entry.entry_id() => {}
                _ => return Err(PubError::FeedChainBroken),
            }
        }
    }
    Ok(())
}

/// The signed head of an author feed (§22.4.1) — the current tip. Signing the head authenticates
/// every entry transitively reachable from `tip` via the `prev`-chain, so entries carry no
/// signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedHead {
    /// key 1 — PUB object version; MUST be [`PUB_V0`].
    pub v: u8,
    /// key 2 — signature/hash suite.
    pub suite: Suite,
    /// key 3 — the feed's author identity key `IK` (a feed is single-author by construction).
    pub publisher: Vec<u8>,
    /// key 4 — the tip's `seq` (highest position this head commits to).
    pub seq: u64,
    /// key 5 — content address of the `FeedEntry` at `seq` (transitively commits the whole log).
    pub tip: ContentId,
    /// key 6 — head publication time (ms epoch).
    pub ts: u64,
    /// key 7 — operational key; authorized by `publisher` via a `DeviceCert` (§1.2).
    pub signer: Vec<u8>,
    /// key 8 — `signer` over `DMTAP-PUB-v0/feed ‖ 0x00 ‖ det_cbor(FeedHead ∖ {8})`.
    pub sig: Vec<u8>,
}

impl FeedHead {
    fn to_cv(&self, include_sig: bool) -> Cv {
        let mut m = vec![
            (1u64, Cv::U64(self.v as u64)),
            (2, Cv::U64(self.suite.as_u8() as u64)),
            (3, Cv::Bytes(self.publisher.clone())),
            (4, Cv::U64(self.seq)),
            (5, Cv::Bytes(self.tip.as_bytes().to_vec())),
            (6, Cv::U64(self.ts)),
            (7, Cv::Bytes(self.signer.clone())),
        ];
        if include_sig {
            m.push((8, Cv::Bytes(self.sig.clone())));
        }
        Cv::Map(m)
    }

    /// The §22.4.1 signing preimage body: `det_cbor(FeedHead ∖ {8})` (sig excluded).
    pub fn signing_preimage(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(false))
    }

    /// The exact wire bytes of the complete, signed head.
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(true))
    }

    /// Sign this head with `signer_key` over the DS-tagged preimage (§22.4.1).
    pub fn sign(&mut self, signer_key: &IdentityKey) {
        self.sig = signer_key.sign_domain(PUB_FEED_DS, &self.signing_preimage());
    }

    /// Verify the head's signature (§22.4.1): reject unknown `v`/`suite` (`0x0901`), then check
    /// `sig` under `signer` over the DS-tagged preimage ([`PubError::FeedSigInvalid`], `0x0906`).
    /// As with [`PubAnnounce::verify`], the direct `signer == publisher` case is checked here;
    /// operational signers are authorized via [`FeedHead::verify_with_cert`].
    pub fn verify(&self) -> Result<(), PubError> {
        if self.v != PUB_V0 || !self.suite.is_supported() {
            return Err(PubError::UnsupportedVersion);
        }
        verify_domain(&self.signer, PUB_FEED_DS, &self.signing_preimage(), &self.sig)
            .map_err(|_| PubError::FeedSigInvalid)?;
        if self.signer != self.publisher {
            return Err(PubError::FeedSigInvalid);
        }
        Ok(())
    }

    /// Verify the head authorizing an operational `signer` via a `DeviceCert` (§22.4.1, §1.2).
    pub fn verify_with_cert(&self, cert: &crate::identity::DeviceCert) -> Result<(), PubError> {
        if self.v != PUB_V0 || !self.suite.is_supported() {
            return Err(PubError::UnsupportedVersion);
        }
        verify_domain(&self.signer, PUB_FEED_DS, &self.signing_preimage(), &self.sig)
            .map_err(|_| PubError::FeedSigInvalid)?;
        if self.signer == self.publisher {
            return Ok(());
        }
        cert.verify().map_err(|_| PubError::FeedSigInvalid)?;
        if cert.ik != self.publisher || cert.device_key != self.signer {
            return Err(PubError::FeedSigInvalid);
        }
        Ok(())
    }

    /// Decode a `FeedHead` (§22.4.1), rejecting unknown `v`/`suite` fail-closed (`0x0901`).
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, PubError> {
        let mut f = Fields::from_cv(cbor::decode(bytes)?)?;
        let v = as_u8(f.req(1)?)?;
        if v != PUB_V0 {
            return Err(PubError::UnsupportedVersion);
        }
        let suite = pub_suite(f.req(2)?)?;
        let publisher = as_bytes(f.req(3)?)?;
        let seq = as_u64(f.req(4)?)?;
        let tip = ContentId(as_bytes(f.req(5)?)?);
        let ts = as_u64(f.req(6)?)?;
        let signer = as_bytes(f.req(7)?)?;
        let sig = as_bytes(f.req(8)?)?;
        f.deny_unknown()?;
        Ok(FeedHead { v, suite, publisher, seq, tip, ts, signer, sig })
    }
}

/// The outcome of the §22.4.2 anti-rollback check on a freshly-fetched [`FeedHead`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RollbackDecision {
    /// `presented_seq > last_accepted_seq`: a genuine advance — accept and retain the new tip.
    AcceptNew,
    /// `presented_seq == last_accepted_seq` with an identical `tip`: an idempotent re-fetch of a
    /// cacheable head — accept as a no-op (NOT a rollback, NOT an error).
    AcceptIdempotent,
}

/// The §22.4.2 anti-rollback rule (the standard monotonic-`seq` family, relaxed to strict-`<` for
/// pull-fetched heads):
/// - `presented_seq < last_accepted_seq` ⇒ [`PubError::FeedRollback`] (`0x0907`) — a stale head
///   cannot suppress announcements the publisher has since made; retain the higher tip.
/// - `presented_seq == last_accepted_seq`: an **equal** seq is not a rollback. Identical `tip` ⇒
///   [`RollbackDecision::AcceptIdempotent`]; **different** `tip` ⇒ two heads claim the same
///   position — equivocation, [`PubError::FeedChainBroken`] (`0x0908`, HALT_ALERT), never a rollback.
/// - `presented_seq > last_accepted_seq` ⇒ [`RollbackDecision::AcceptNew`].
///
/// `last_tip` MAY be `None` on first contact (no prior tip retained); an equal-seq comparison then
/// cannot be made, so it is treated as `AcceptIdempotent`.
pub fn check_anti_rollback(
    last_accepted_seq: u64,
    last_tip: Option<&ContentId>,
    presented_seq: u64,
    presented_tip: &ContentId,
) -> Result<RollbackDecision, PubError> {
    use std::cmp::Ordering;
    match presented_seq.cmp(&last_accepted_seq) {
        Ordering::Less => Err(PubError::FeedRollback),
        Ordering::Greater => Ok(RollbackDecision::AcceptNew),
        Ordering::Equal => match last_tip {
            Some(t) if t != presented_tip => Err(PubError::FeedChainBroken),
            _ => Ok(RollbackDecision::AcceptIdempotent),
        },
    }
}

/// Bind a fetched entry range to the **signed** head that authenticates it (§22.4.1): a `FeedHead`
/// authenticates entries *only* transitively through `tip`, so a consumer that validates a range
/// with [`verify_feed_chain`] alone has validated internal linkage and nothing else — an
/// equivocating publisher can serve a signed head at `seq = N` alongside a *different*,
/// internally-consistent chain also ending at `seq = N`, and the range would pass.
///
/// This closes that: the range MUST be non-empty, end exactly at `head.seq`, and its last entry's
/// [`FeedEntry::entry_id`] MUST equal `head.tip`. Any mismatch is
/// [`PubError::FeedChainBroken`] (`0x0908`, HALT_ALERT) — never a rollback (`0x0907`), which is
/// reserved for a *stale but honest* head.
///
/// This does not verify `head.sig`; call [`FeedHead::verify`] / [`FeedHead::verify_with_cert`]
/// first (or use [`FeedFollower`], which sequences both).
pub fn verify_feed_chain_to_head(entries: &[FeedEntry], head: &FeedHead) -> Result<(), PubError> {
    verify_feed_chain(entries)?;
    let last = entries.last().ok_or(PubError::FeedChainBroken)?;
    if last.seq != head.seq || last.entry_id() != head.tip {
        return Err(PubError::FeedChainBroken);
    }
    Ok(())
}

/// A stateful consumer of one author feed (§22.4.2) — the piece that makes equivocation detectable
/// **across separate fetches**.
///
/// The per-call primitives ([`check_anti_rollback`], [`verify_feed_chain`],
/// [`verify_feed_chain_to_head`]) are each individually correct, but a follower that keeps no memory
/// of what it already accepted cannot see a publisher who serves one history to one fetch and a
/// forked history to the next. This type retains the accepted `entry_id` at every `seq` it has ever
/// seen and rejects any later fetch that contradicts it.
///
/// Every rejection is fail-closed. Fork/rewrite/mis-binding is
/// [`PubError::FeedChainBroken`] (`0x0908`, HALT_ALERT); only a strictly-lower `seq` from an
/// otherwise-consistent publisher is [`PubError::FeedRollback`] (`0x0907`).
#[derive(Debug, Clone)]
pub struct FeedFollower {
    publisher: Vec<u8>,
    last_seq: Option<u64>,
    last_tip: Option<ContentId>,
    /// The `entry_id` this follower has committed to at each `seq` — the equivocation memory.
    accepted: std::collections::BTreeMap<u64, ContentId>,
}

impl FeedFollower {
    /// A follower on first contact with `publisher` (no retained tip).
    pub fn new(publisher: Vec<u8>) -> Self {
        FeedFollower { publisher, last_seq: None, last_tip: None, accepted: Default::default() }
    }

    /// The highest `seq` accepted so far, if any.
    pub fn last_seq(&self) -> Option<u64> {
        self.last_seq
    }

    /// The tip retained at [`FeedFollower::last_seq`], if any.
    pub fn last_tip(&self) -> Option<&ContentId> {
        self.last_tip.as_ref()
    }

    /// Ingest one `(head, entries)` fetch (§22.4.4 head + range), fail-closed in this order:
    ///
    /// 1. `head.publisher` MUST be this feed's publisher, and `head.sig` MUST verify (`0x0906`).
    /// 2. §22.4.2 anti-rollback against the retained `(seq, tip)`: lower `seq` ⇒ `0x0907`; equal
    ///    `seq` with a *different* tip ⇒ `0x0908` (equivocation, never a rollback).
    /// 3. An advancing head MUST be accompanied by entries; the range MUST chain internally and
    ///    bind to `head.tip` ([`verify_feed_chain_to_head`], `0x0908`).
    /// 4. The range MUST join the retained history: no gap, and its first entry's `prev` (or its
    ///    `entry_id`, when it re-covers an already-accepted position) MUST agree with what was
    ///    accepted before (`0x0908`).
    /// 5. No entry may contradict the `entry_id` already accepted at its `seq` (`0x0908`) — this is
    ///    the cross-fetch check no stateless primitive can make.
    ///
    /// State advances only after every check passes, so a rejected fetch can never partially
    /// corrupt the follower.
    pub fn accept(
        &mut self,
        head: &FeedHead,
        entries: &[FeedEntry],
    ) -> Result<RollbackDecision, PubError> {
        if head.publisher != self.publisher {
            return Err(PubError::FeedSigInvalid);
        }
        head.verify()?;

        let decision = match self.last_seq {
            Some(last) => check_anti_rollback(last, self.last_tip.as_ref(), head.seq, &head.tip)?,
            None => RollbackDecision::AcceptNew,
        };

        // An idempotent re-fetch of the exact retained tip may legitimately carry no entries.
        if entries.is_empty() {
            if decision == RollbackDecision::AcceptNew {
                // A head claiming to advance, with no chain proving it: unprovable, so refuse.
                return Err(PubError::FeedChainBroken);
            }
            return Ok(decision);
        }

        verify_feed_chain_to_head(entries, head)?;

        let first = &entries[0];
        // (4) join the retained history — no silent gap, and an honest continuation.
        if let Some(last) = self.last_seq {
            if first.seq > last + 1 {
                return Err(PubError::FeedChainBroken);
            }
            if first.seq == last + 1 {
                match (&first.prev, &self.last_tip) {
                    (Some(p), Some(t)) if p == t => {}
                    _ => return Err(PubError::FeedChainBroken),
                }
            }
        }

        // (5) cross-fetch equivocation: nothing may contradict an already-committed position.
        for e in entries {
            if let Some(known) = self.accepted.get(&e.seq) {
                if known != &e.entry_id() {
                    return Err(PubError::FeedChainBroken);
                }
            }
        }

        for e in entries {
            self.accepted.insert(e.seq, e.entry_id());
        }
        if self.last_seq.is_none_or(|l| head.seq >= l) {
            self.last_seq = Some(head.seq);
            self.last_tip = Some(head.tip.clone());
        }
        Ok(decision)
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn cid(hexs: &str) -> ContentId {
        let bytes: Vec<u8> = (0..hexs.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hexs[i..i + 2], 16).unwrap())
            .collect();
        ContentId(bytes)
    }
    fn hexs(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    // ── Known-answer vectors from dmtap/conformance/vectors/pub_vectors.json ─────────────────
    // These prove the Rust reference reproduces the spec's independent (Python) reference exactly.

    #[test]
    fn kat_manifest_single_chunk() {
        let pt = cid("646d7461702d7075623a206f6e65207075626c6973686564206368756e6b").0;
        let h0 = chunk_hash(&pt);
        assert_eq!(hexs(h0.as_bytes()), "1e458cd8409c3b46d1e59eebedaab232ae9054e51d2cc01e3a0ef7447017301eaf");
        let root = pub_manifest_root(&[h0]);
        assert_eq!(hexs(root.as_bytes()), "1ea74194f80ea2c6c6d52f8de31300613f75341413f10fda061c063c660989db7e");
    }

    #[test]
    fn kat_manifest_three_chunks_and_type_incompatibility() {
        let chunks = vec![
            cid("1ed05624f0d4ec1a79f25d095591bc89945532a00c71232b19664c8c41b10f17fc"),
            cid("1e7e458601f67eeefdf879baf940b61272e4cf4ce91c27db4b311b459eb6b666a6"),
            cid("1e609e5ba5844b77afa5f9c6852f0675cf490b0f0ee6a9bcd9d52985e126d40e78"),
        ];
        let pub_root = pub_manifest_root(&chunks);
        assert_eq!(hexs(pub_root.as_bytes()), "1ebc3469f4fea824d224a14b01f8da10bb2a326a4c577585342f255cd93ea64bb5");
        let sealed = sealed_style_root(&chunks);
        assert_eq!(hexs(sealed.as_bytes()), "1efbcedd64dffb0196ff9c49e13bc9d3e10ba16296273bc96e0a08fa71cb2ed700");
        // §22.2.3: the DS-tag alone makes the two roots differ over an identical chunk list.
        assert_ne!(pub_root, sealed);
    }

    #[test]
    fn kat_manifest_key5_forbidden_rejected() {
        // The pub_manifest_single_chunk manifest with a forbidden key 5 (32 zero bytes) inserted.
        let bytes = cid("a60158211ea74194f80ea2c6c6d52f8de31300613f75341413f10fda061c063c660989db7e02181e03190400048158211e458cd8409c3b46d1e59eebedaab232ae9054e51d2cc01e3a0ef7447017301eaf05582000000000000000000000000000000000000000000000000000000000000000000601").0;
        assert_eq!(PubManifest::from_det_cbor(&bytes), Err(PubError::ManifestKeyPresent));
        // The valid manifest (keys 1,2,3,4,6) decodes and self-verifies.
        let valid = cid("a50158211ea74194f80ea2c6c6d52f8de31300613f75341413f10fda061c063c660989db7e02181e03190400048158211e458cd8409c3b46d1e59eebedaab232ae9054e51d2cc01e3a0ef7447017301eaf0601").0;
        let m = PubManifest::from_det_cbor(&valid).expect("valid PubManifest decodes");
        m.verify().expect("valid PubManifest self-verifies");
        assert_eq!(m.det_cbor(), valid, "re-encode is byte-identical (canonical)");
    }

    #[test]
    fn kat_announce_signing_and_id() {
        let seed = [0xAAu8; 32];
        let sk = IdentityKey::from_seed(&seed);
        let pk = sk.public();
        let pm_id = cid("1ea74194f80ea2c6c6d52f8de31300613f75341413f10fda061c063c660989db7e");
        let mut a = PubAnnounce {
            v: 0,
            suite: Suite::Classical,
            publisher: pk.clone(),
            roots: vec![pm_id],
            meta: Vec::new(),
            supersedes: None,
            ts: 1700000050000,
            signer: pk.clone(),
            sig: Vec::new(),
        };
        // Signing preimage matches the spec vector byte-for-byte.
        assert_eq!(
            hexs(&a.signing_preimage()),
            "a701000201035820e734ea6c2b6257de72355e472aa05a4c487e6b463c029ed306df2f01b5636b58048158211ea74194f80ea2c6c6d52f8de31300613f75341413f10fda061c063c660989db7e05a0071b0000018bcfe62b50085820e734ea6c2b6257de72355e472aa05a4c487e6b463c029ed306df2f01b5636b58"
        );
        a.sign(&sk);
        assert_eq!(
            hexs(&a.sig),
            "4e2ac80c0ac66668b4efdb058dc1c4c92ffad16f0db73e84118f6c9b7baeb10f0194daad7cff28669e0a9efbccd20057126abb929c69576853e779162cec1202"
        );
        let id = a.announce_id();
        assert_eq!(hexs(id.as_bytes()), "1e5928d22f36318ece11ae4b307456a4dc120e63c4deb749c35a87cc12443ccd30");
        // Full verify against the derived id.
        a.verify(&id).expect("announce verifies");
        // A one-byte mutation of the fetched-by address is rejected (0x0905): the recomputed
        // announce_id no longer equals the address it was fetched by.
        let mut wrong = id.clone();
        wrong.0[5] ^= 1;
        assert_eq!(a.verify(&wrong), Err(PubError::AnnounceIdMismatch));
        // A genuine bad signature (signed by a DIFFERENT key while `signer` still names A) is
        // rejected (0x0904). We verify against the object's OWN id so the id check passes and the
        // sig check is the one that fails.
        let sk_b = IdentityKey::from_seed(&[0xBBu8; 32]);
        let mut bad = a.clone();
        bad.sig = sk_b.sign_domain(PUB_ANNOUNCE_DS, &bad.signing_preimage());
        assert_eq!(bad.verify(&bad.announce_id()), Err(PubError::AnnounceSigInvalid));
        // An announce whose `signer` is not authorized by `pub` (and no DeviceCert) is 0x0904.
        let mut mism = a.clone();
        mism.signer = sk_b.public();
        mism.sig = sk_b.sign_domain(PUB_ANNOUNCE_DS, &mism.signing_preimage());
        assert_eq!(mism.verify(&mism.announce_id()), Err(PubError::AnnounceSigInvalid));
    }

    #[test]
    fn kat_supersede_same_and_cross_author() {
        let pk_a = IdentityKey::from_seed(&[0xAAu8; 32]).public();
        let pk_b = IdentityKey::from_seed(&[0xBBu8; 32]).public();
        assert_eq!(check_supersede(&pk_a, &pk_a), Ok(()));
        assert_eq!(check_supersede(&pk_a, &pk_b), Err(PubError::SupersedeInvalid));
    }

    #[test]
    fn kat_feed_entry_chain() {
        let entry0 = cid("a301000258211e5928d22f36318ece11ae4b307456a4dc120e63c4deb749c35a87cc12443ccd30041b0000018bcfe62b50").0;
        let entry1 = cid("a401010258211e93b2a0f58389a40c269021b596b16e104fa486d7560a32022569725c1c3dfcb30358211ebb9bb7604544aed78ee40bc1949cb8cb06b49946aaf0f41f88d59e7eeb9ae591041b0000018bcfe62f38").0;
        let entry2 = cid("a401020258211e5928d22f36318ece11ae4b307456a4dc120e63c4deb749c35a87cc12443ccd300358211e7c793c9de9a7e7beddaf08c291787845f5145c6b8d41bbd4fb8b9e00aebcc4b2041b0000018bcfe63320").0;
        let e0 = FeedEntry::from_det_cbor(&entry0).unwrap();
        let e1 = FeedEntry::from_det_cbor(&entry1).unwrap();
        let e2 = FeedEntry::from_det_cbor(&entry2).unwrap();
        assert_eq!(hexs(e0.entry_id().as_bytes()), "1ebb9bb7604544aed78ee40bc1949cb8cb06b49946aaf0f41f88d59e7eeb9ae591");
        assert_eq!(hexs(e1.entry_id().as_bytes()), "1e7c793c9de9a7e7beddaf08c291787845f5145c6b8d41bbd4fb8b9e00aebcc4b2");
        assert_eq!(hexs(e2.entry_id().as_bytes()), "1e5b1ed9cb2801ffab0e62900292e4239838694dfcf8ce59209c8d680c5710dd44");
        verify_feed_chain(&[e0, e1, e2]).expect("valid prev-chain");
    }

    #[test]
    fn kat_feed_entry_malformed_genesis_and_nongenesis() {
        // Genesis (seq=0) carrying prev → CHAIN_BROKEN.
        let genesis_with_prev = cid("a401000258211e5928d22f36318ece11ae4b307456a4dc120e63c4deb749c35a87cc12443ccd300358211ebb9bb7604544aed78ee40bc1949cb8cb06b49946aaf0f41f88d59e7eeb9ae591041b0000018bcfe62b50").0;
        assert_eq!(FeedEntry::from_det_cbor(&genesis_with_prev), Err(PubError::FeedChainBroken));
        // Non-genesis (seq=1) missing prev → CHAIN_BROKEN.
        let nongenesis_no_prev = cid("a301010258211e93b2a0f58389a40c269021b596b16e104fa486d7560a32022569725c1c3dfcb3041b0000018bcfe62f38").0;
        assert_eq!(FeedEntry::from_det_cbor(&nongenesis_no_prev), Err(PubError::FeedChainBroken));
    }

    #[test]
    fn kat_feed_head_signing() {
        let sk = IdentityKey::from_seed(&[0xAAu8; 32]);
        let pk = sk.public();
        let tip = cid("1e7c793c9de9a7e7beddaf08c291787845f5145c6b8d41bbd4fb8b9e00aebcc4b2");
        let mut head = FeedHead {
            v: 0,
            suite: Suite::Classical,
            publisher: pk.clone(),
            seq: 1,
            tip,
            ts: 1700000051500,
            signer: pk.clone(),
            sig: Vec::new(),
        };
        assert_eq!(
            hexs(&head.signing_preimage()),
            "a701000201035820e734ea6c2b6257de72355e472aa05a4c487e6b463c029ed306df2f01b5636b5804010558211e7c793c9de9a7e7beddaf08c291787845f5145c6b8d41bbd4fb8b9e00aebcc4b2061b0000018bcfe6312c075820e734ea6c2b6257de72355e472aa05a4c487e6b463c029ed306df2f01b5636b58"
        );
        head.sign(&sk);
        assert_eq!(
            hexs(&head.sig),
            "51bdb93c2b0094534f7376254d679c76ccb7d0160a9dfcd960aaf6028b2d559096ef59127c7779b48969caf7eb2c4d301c41cf8a72f1d6f528a0c157a8b89707"
        );
        head.verify().expect("head verifies");
        let mut bad = head.clone();
        bad.sig[0] ^= 1;
        assert_eq!(bad.verify(), Err(PubError::FeedSigInvalid));
    }

    #[test]
    fn kat_anti_rollback() {
        let tip1 = cid("1e7c793c9de9a7e7beddaf08c291787845f5145c6b8d41bbd4fb8b9e00aebcc4b2");
        // seq=0 presented after accepting seq=1 → rollback.
        assert_eq!(
            check_anti_rollback(1, Some(&tip1), 0, &cid("1ebb9bb7604544aed78ee40bc1949cb8cb06b49946aaf0f41f88d59e7eeb9ae591")),
            Err(PubError::FeedRollback)
        );
        // equal seq, identical tip → idempotent accept.
        assert_eq!(check_anti_rollback(1, Some(&tip1), 1, &tip1), Ok(RollbackDecision::AcceptIdempotent));
        // equal seq, different tip → equivocation (CHAIN_BROKEN), never rollback.
        let alt = cid("1e24b7f5c8891b690e1f438cba3990f80a6481fa4a8a1c40fba232a17c13dcfd8b");
        assert_eq!(check_anti_rollback(1, Some(&tip1), 1, &alt), Err(PubError::FeedChainBroken));
        // higher seq → accept new.
        assert_eq!(check_anti_rollback(1, Some(&tip1), 2, &alt), Ok(RollbackDecision::AcceptNew));
    }

    #[test]
    fn version_and_suite_fail_closed() {
        // PubAnnounce with v=1 → UnsupportedVersion (0x0901). Build one and mutate the version byte.
        let sk = IdentityKey::from_seed(&[0xAAu8; 32]);
        let pk = sk.public();
        let a = PubAnnounce {
            v: 1,
            suite: Suite::Classical,
            publisher: pk.clone(),
            roots: vec![ContentId::of(b"x")],
            meta: Vec::new(),
            supersedes: None,
            ts: 1,
            signer: pk,
            sig: vec![0u8; 64],
        };
        assert_eq!(PubAnnounce::from_det_cbor(&a.det_cbor()), Err(PubError::UnsupportedVersion));
    }

    // ── Property tests (mirroring the rigor of dmtap-clustersync/src/crdt.rs) ─────────────────

    #[test]
    fn prop_manifest_root_deterministic_and_order_sensitive() {
        let a = ContentId::of(b"alpha");
        let b = ContentId::of(b"beta");
        let c = ContentId::of(b"gamma");
        // Deterministic.
        assert_eq!(pub_manifest_root(&[a.clone(), b.clone(), c.clone()]), pub_manifest_root(&[a.clone(), b.clone(), c.clone()]));
        // Order-sensitive (a Merkle tree over an ordered list).
        assert_ne!(pub_manifest_root(&[a.clone(), b.clone()]), pub_manifest_root(&[b.clone(), a.clone()]));
        // Single-chunk root = leaf(h0), and always differs from the raw chunk hash.
        assert_ne!(pub_manifest_root(&[a.clone()]), a);
    }

    #[test]
    fn prop_public_and_sealed_roots_always_differ() {
        // Over many random-ish chunk lists, the DS-tag guarantees no sealed↔public collision.
        for n in 1..=16usize {
            let chunks: Vec<ContentId> = (0..n).map(|i| ContentId::of(format!("chunk-{i}").as_bytes())).collect();
            assert_ne!(pub_manifest_root(&chunks), sealed_style_root(&chunks), "n={n}");
        }
    }

    #[test]
    fn prop_announce_roundtrip_and_id_binding() {
        let sk = IdentityKey::from_seed(&[7u8; 32]);
        let pk = sk.public();
        for i in 0..8u8 {
            let mut a = PubAnnounce {
                v: 0,
                suite: Suite::Classical,
                publisher: pk.clone(),
                roots: vec![ContentId::of(&[i]), ContentId::of(&[i, i])],
                meta: vec![("title".into(), Cv::Text(format!("rev{i}")))],
                supersedes: if i > 0 { Some(ContentId::of(&[i - 1])) } else { None },
                ts: 1700000000000 + i as u64,
                signer: pk.clone(),
                sig: Vec::new(),
            };
            a.sign(&sk);
            let bytes = a.det_cbor();
            let decoded = PubAnnounce::from_det_cbor(&bytes).expect("roundtrip");
            assert_eq!(decoded, a);
            assert_eq!(decoded.det_cbor(), bytes, "canonical re-encode");
            let id = a.announce_id();
            a.verify(&id).expect("verify");
        }
    }

    #[test]
    fn prop_feed_chain_detects_breaks() {
        let sk = IdentityKey::from_seed(&[9u8; 32]);
        let pk = sk.public();
        // Build a valid 4-entry chain.
        let mut entries: Vec<FeedEntry> = Vec::new();
        for seq in 0..4u64 {
            let announce = ContentId::of(format!("ann-{seq}").as_bytes());
            let prev = if seq == 0 { None } else { Some(entries[seq as usize - 1].entry_id()) };
            entries.push(FeedEntry { seq, announce, prev, ts: 1000 + seq });
        }
        verify_feed_chain(&entries).expect("valid chain");
        // Break the prev link of entry 2.
        let mut broken = entries.clone();
        broken[2].prev = Some(ContentId::of(b"wrong"));
        assert_eq!(verify_feed_chain(&broken), Err(PubError::FeedChainBroken));
        // Skip a seq.
        let mut skipped = entries.clone();
        skipped[2].seq = 5;
        assert_eq!(verify_feed_chain(&skipped), Err(PubError::FeedChainBroken));
        let _ = (sk, pk);
    }

    // ── Adversarial feed-acceptance suite (§22.4.2) ──────────────────────────────────────────
    //
    // Cross-implementation motivation: an independent §22 implementation was found to accept a
    // DIFFERENT TIP at an already-accepted `seq` because its acceptance step compared only `seq`.
    // These tests pin every member of that bug class in this implementation: same-seq/different-tip,
    // prev-chain mismatch, tip regression, head-not-bound-to-range, and equivocation split across
    // two separate fetches (the case no stateless primitive can see).

    /// Build a `[0, n)` feed chain for `sk` plus the signed head committing its tip. `salt`
    /// distinguishes forked histories (different announce content ⇒ different `entry_id`s).
    fn feed_of(sk: &IdentityKey, n: u64, salt: &str) -> (Vec<FeedEntry>, FeedHead) {
        let mut entries: Vec<FeedEntry> = Vec::new();
        for seq in 0..n {
            let announce = ContentId::of(format!("{salt}-ann-{seq}").as_bytes());
            let prev = if seq == 0 { None } else { Some(entries[seq as usize - 1].entry_id()) };
            entries.push(FeedEntry { seq, announce, prev, ts: 1000 + seq });
        }
        let last = entries.last().expect("non-empty");
        let mut head = FeedHead {
            v: PUB_V0,
            suite: Suite::Classical,
            publisher: sk.public(),
            seq: last.seq,
            tip: last.entry_id(),
            ts: 2000 + last.seq,
            signer: sk.public(),
            sig: Vec::new(),
        };
        head.sign(sk);
        (entries, head)
    }

    #[test]
    fn adversarial_same_seq_different_tip_is_chain_broken_not_accepted() {
        let sk = IdentityKey::from_seed(&[0x11u8; 32]);
        let mut f = FeedFollower::new(sk.public());
        let (honest, honest_head) = feed_of(&sk, 3, "honest");
        assert_eq!(f.accept(&honest_head, &honest), Ok(RollbackDecision::AcceptNew));

        // The publisher now presents a FORK: same seq (2), validly signed, but a different tip.
        let (forked, forked_head) = feed_of(&sk, 3, "forked");
        assert_ne!(forked_head.tip, honest_head.tip);
        assert_eq!(forked_head.seq, honest_head.seq);
        forked_head.verify().expect("the fork is genuinely signed — only the tip betrays it");
        let err = f.accept(&forked_head, &forked).expect_err("a fork MUST NOT be accepted");
        assert_eq!(err, PubError::FeedChainBroken);
        assert_eq!(err.code(), 0x0908, "equivocation is CHAIN_BROKEN, never ROLLBACK 0x0907");
        // The rejected fetch left the follower on the honest tip.
        assert_eq!(f.last_tip(), Some(&honest_head.tip));
    }

    #[test]
    fn adversarial_equivocation_across_separate_fetches_is_caught() {
        // THE cross-implementation bug: fetch #1 commits history A; fetch #2 ADVANCES the seq (so
        // no anti-rollback rule fires) while silently rewriting an already-accepted position.
        let sk = IdentityKey::from_seed(&[0x22u8; 32]);
        let mut f = FeedFollower::new(sk.public());
        let (a, a_head) = feed_of(&sk, 2, "A");
        assert_eq!(f.accept(&a_head, &a), Ok(RollbackDecision::AcceptNew));

        let (b, b_head) = feed_of(&sk, 4, "B"); // internally perfect, strictly higher seq
        verify_feed_chain(&b).expect("the rewritten history is internally consistent");
        verify_feed_chain_to_head(&b, &b_head).expect("and correctly bound to its own head");
        assert!(b_head.seq > a_head.seq, "an advance, so seq-only logic would accept");
        assert_ne!(b[1].entry_id(), a[1].entry_id(), "but seq=1 was rewritten");
        assert_eq!(
            f.accept(&b_head, &b),
            Err(PubError::FeedChainBroken),
            "a rewrite of an accepted position MUST be caught even when the head advances"
        );
        assert_eq!(f.last_seq(), Some(1), "state unchanged by the rejected fetch");
    }

    #[test]
    fn adversarial_head_not_bound_to_range_is_chain_broken() {
        // A head signed over history A, served alongside history B's entries. Each object is valid
        // on its own; only the tip binding exposes the swap.
        let sk = IdentityKey::from_seed(&[0x33u8; 32]);
        let (a, a_head) = feed_of(&sk, 3, "A");
        let (b, _b_head) = feed_of(&sk, 3, "B");
        verify_feed_chain(&b).expect("B chains internally — verify_feed_chain ALONE is not enough");
        assert_eq!(verify_feed_chain_to_head(&b, &a_head), Err(PubError::FeedChainBroken));
        assert_eq!(verify_feed_chain_to_head(&a, &a_head), Ok(()));

        let mut f = FeedFollower::new(sk.public());
        assert_eq!(f.accept(&a_head, &b), Err(PubError::FeedChainBroken));
        assert_eq!(f.last_seq(), None, "nothing committed");

        // A range that stops short of the head's seq is equally unbound.
        assert_eq!(verify_feed_chain_to_head(&a[..2], &a_head), Err(PubError::FeedChainBroken));
        assert_eq!(verify_feed_chain_to_head(&[], &a_head), Err(PubError::FeedChainBroken));
    }

    #[test]
    fn adversarial_prev_chain_mismatch_is_chain_broken() {
        let sk = IdentityKey::from_seed(&[0x44u8; 32]);
        let mut f = FeedFollower::new(sk.public());

        // (a) A break INSIDE the presented range.
        let (mut entries, head) = feed_of(&sk, 4, "P");
        entries[2].prev = Some(ContentId::of(b"not-the-predecessor"));
        assert_eq!(f.accept(&head, &entries), Err(PubError::FeedChainBroken));

        // (b) A break at the JOIN with already-accepted history: the continuation's `prev` must
        // resolve to the retained tip, not to some other entry.
        let (a, a_head) = feed_of(&sk, 2, "A");
        assert_eq!(f.accept(&a_head, &a), Ok(RollbackDecision::AcceptNew));
        let (b, b_head) = feed_of(&sk, 3, "B");
        assert_eq!(b[2].seq, a_head.seq + 1, "same position, wrong ancestry");
        assert_eq!(f.accept(&b_head, &b[2..]), Err(PubError::FeedChainBroken));

        // (c) A gap in the history is never silently swallowed.
        let (c, c_head) = feed_of(&sk, 6, "A");
        assert_eq!(f.accept(&c_head, &c[4..]), Err(PubError::FeedChainBroken));
        // …while the honest contiguous continuation of the SAME history is accepted.
        assert_eq!(f.accept(&c_head, &c[2..]), Ok(RollbackDecision::AcceptNew));
        assert_eq!(f.last_seq(), Some(5));
    }

    #[test]
    fn adversarial_tip_regression_is_rollback_and_idempotent_refetch_is_not() {
        let sk = IdentityKey::from_seed(&[0x55u8; 32]);
        let mut f = FeedFollower::new(sk.public());
        let (full, full_head) = feed_of(&sk, 5, "R");
        assert_eq!(f.accept(&full_head, &full), Ok(RollbackDecision::AcceptNew));

        // A stale-but-honest head from the SAME history: rollback (0x0907), not a fork.
        let (short, short_head) = feed_of(&sk, 3, "R");
        let err = f.accept(&short_head, &short).expect_err("a lower seq MUST NOT be accepted");
        assert_eq!(err, PubError::FeedRollback);
        assert_eq!(err.code(), 0x0907);
        assert_eq!(f.last_seq(), Some(4), "the higher tip is retained");

        // Re-fetching the identical head is a no-op, not an error — with or without entries.
        assert_eq!(f.accept(&full_head, &full), Ok(RollbackDecision::AcceptIdempotent));
        assert_eq!(f.accept(&full_head, &[]), Ok(RollbackDecision::AcceptIdempotent));
    }

    #[test]
    fn adversarial_unprovable_advance_and_foreign_head_refused() {
        let sk = IdentityKey::from_seed(&[0x66u8; 32]);
        let mut f = FeedFollower::new(sk.public());
        let (e0, h0) = feed_of(&sk, 1, "U");

        // A head with no chain proving it can never move the follower's tip.
        assert_eq!(f.accept(&h0, &[]), Err(PubError::FeedChainBroken));
        assert_eq!(f.accept(&h0, &e0), Ok(RollbackDecision::AcceptNew));
        let (_e3, h3) = feed_of(&sk, 4, "U");
        assert_eq!(f.accept(&h3, &[]), Err(PubError::FeedChainBroken));
        assert_eq!(f.last_seq(), Some(0));

        // Another identity's (validly signed) head is not this feed's history.
        let other = IdentityKey::from_seed(&[0x77u8; 32]);
        let (oe, oh) = feed_of(&other, 3, "U");
        oh.verify().expect("valid — for a different publisher");
        assert_eq!(f.accept(&oh, &oe), Err(PubError::FeedSigInvalid));

        // A forged signature over an otherwise-correct head is 0x0906.
        let (fe, mut fh) = feed_of(&sk, 3, "U");
        fh.sig = other.sign_domain(PUB_FEED_DS, &fh.signing_preimage());
        assert_eq!(f.accept(&fh, &fe), Err(PubError::FeedSigInvalid));
    }
}

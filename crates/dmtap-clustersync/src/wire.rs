//! The device-cluster sync wire objects (spec §18.6.3), encoded in canonical §18.1 CBOR.
//!
//! Every object here is an **integer-keyed** CBOR map (COSE/CWT style) encoded through
//! dmtap-core's single canonical codec ([`dmtap_core::cbor`]) — exactly like `DeviceCert`,
//! `CapabilityToken`, `DeniablePayload`, and every other DMTAP wire object. Using that codec (not
//! a serde-derived text-keyed encoding) is what makes a second implementer reproduce these bytes
//! and lets the objects ride, unsigned, inside the encrypted+authenticated MLS cluster group
//! (§18.6.3): the group supplies confidentiality and membership auth, each frame merely names its
//! origin `device_id`.
//!
//! Decoding fails **closed**: any non-canonical byte is rejected by the core decoder, an unknown
//! frame `type` or CRDT `kind` is rejected here, and every sub-object denies unknown keys.

use dmtap_core::cbor::{
    self, as_array, as_bytes, as_text, as_u32, as_u64, as_u8, CborError, Cv, Fields,
};

/// A content-address / suite-hash byte string (§2.2): a 1-byte multihash prefix + digest, as
/// produced by [`dmtap_core::ContentId`]. Object ids, range bounds, fingerprints, and journal
/// links all travel as this CBOR byte string (`hash` in the §18.6.3 CDDL).
pub type Hash = Vec<u8>;

// ── Frame type discriminants (§18.6.3, ClusterSyncFrame key 1) ───────────────────────────────
/// Announce new object ids the sender holds (type 1, live replication §5.6.2).
pub const FRAME_ANNOUNCE: u8 = 1;
/// A range-based Merkle reconciliation summary (type 2, backfill §5.6.3(a)).
pub const FRAME_RECON: u8 = 2;
/// A pull: fetch-request for object bytes by id (type 3, §5.6.2).
pub const FRAME_FETCH: u8 = 3;
/// An append-only hash-chained journal segment for replay-backfill (type 4, §5.6.3(b)).
pub const FRAME_JOURNAL: u8 = 4;
/// Per-device max-applied-HLC stability marks for tombstone GC (type 5, §5.6.5).
pub const FRAME_STABILITY: u8 = 5;

// ── CRDT op kind discriminants (§18.6.3, ClusterOp key 1) ────────────────────────────────────
/// OR-Set add: element gains a unique add-tag `{device, HLC}` (§5.6.4).
pub const OP_SET_ADD: u8 = 1;
/// OR-Set remove: tombstones the specific observed add-tags (§5.6.4).
pub const OP_SET_REMOVE: u8 = 2;
/// Per-field LWW-Register write, keyed by HLC (§5.6.4).
pub const OP_LWW_SET: u8 = 3;

/// Hybrid logical clock (§5.6.4). The **total order is lexicographic `(wall, counter, device)`** —
/// which is exactly the derived field order below, so `derive(Ord)` yields the normative tiebreak:
/// larger `wall` wins, ties broken by larger `counter`, any remaining tie by the larger
/// `device_id` bytes. That determinism is what makes the LWW winner identical on every replica.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hlc {
    /// Wall-clock milliseconds since the Unix epoch (§18.6.3 key 1).
    pub wall: u64,
    /// Monotonic counter breaking equal-`wall` ties (§18.6.3 key 2).
    pub counter: u32,
    /// Origin device id — an `ik-pub` (§18.6.3 key 3).
    pub device: Vec<u8>,
}

impl Hlc {
    /// Integer-keyed canonical map (§18.6.3).
    pub fn to_cv(&self) -> Cv {
        Cv::Map(vec![
            (1, Cv::U64(self.wall)),
            (2, Cv::U64(self.counter as u64)),
            (3, Cv::Bytes(self.device.clone())),
        ])
    }

    /// Decode from canonical CBOR, denying unknown keys (fail closed).
    pub fn from_cv(cv: Cv) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cv)?;
        let wall = as_u64(f.req(1)?)?;
        let counter = as_u32(f.req(2)?)?;
        let device = as_bytes(f.req(3)?)?;
        f.deny_unknown()?;
        Ok(Hlc { wall, counter, device })
    }
}

/// A unique OR-Set add-tag: which device added an element, and when (§5.6.4 / §18.6.3). The pair
/// `{device, HLC}` is globally unique, so the same logical element added on two devices carries two
/// distinct tags — the property that makes a concurrent add win over a remove that never saw it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AddTag {
    /// The adding device's id (`ik-pub`, §18.6.3 key 1).
    pub device: Vec<u8>,
    /// The add's hybrid logical clock (§18.6.3 key 2).
    pub hlc: Hlc,
}

impl AddTag {
    /// Integer-keyed canonical map (§18.6.3).
    pub fn to_cv(&self) -> Cv {
        Cv::Map(vec![(1, Cv::Bytes(self.device.clone())), (2, self.hlc.to_cv())])
    }

    /// Decode from canonical CBOR, denying unknown keys (fail closed).
    pub fn from_cv(cv: Cv) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cv)?;
        let device = as_bytes(f.req(1)?)?;
        let hlc = Hlc::from_cv(f.req(2)?)?;
        f.deny_unknown()?;
        Ok(AddTag { device, hlc })
    }
}

/// A CRDT metadata op (§5.6.4 / §18.6.3). `kind` 1/2 are OR-Set add/remove (membership, folders,
/// labels, deletes); `kind` 3 is a per-field LWW-Register write (read/unread, star, current
/// folder), keyed by `hlc`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterOp {
    /// `1`=set-add, `2`=set-remove, `3`=lww-set (§18.6.3 key 1).
    pub kind: u8,
    /// The object / folder / label id the op applies to (§18.6.3 key 2).
    pub target: String,
    /// The LWW field name — present iff `kind = 3` (§18.6.3 key 3).
    pub field: Option<String>,
    /// The LWW value — present iff `kind = 3`. An `ext-value` (bool/int/bytes/tstr and nestings,
    /// §18.3.6); integer-keyed maps, floats, tags, and null are rejected on decode (§18.6.3 key 4).
    pub value: Option<Cv>,
    /// The op's hybrid logical clock — add-tag time (kind 1) / LWW key (kind 3) / remove time
    /// (kind 2) (§18.6.3 key 5).
    pub hlc: Hlc,
    /// The add-tags this remove tombstones — present (non-empty) iff `kind = 2` (§18.6.3 key 6).
    pub observed: Option<Vec<AddTag>>,
}

/// Whether `v` lies inside the `ext-value` subset (§18.3.6): bool / unsigned int / bytes / text, or
/// an array / **text-keyed** map recursively of the same. An **integer-keyed** map is *not* an
/// `ext-value` — that is how a smuggled integer-keyed wire object (e.g. a `DeniablePayload`, whose
/// keys are `1..=7`) is kept out of an LWW value structurally, before the semantic guard in
/// [`crate::crdt`] even runs.
fn is_ext_value(v: &Cv) -> bool {
    match v {
        Cv::U64(_) | Cv::Bytes(_) | Cv::Text(_) | Cv::Bool(_) => true,
        Cv::Array(a) => a.iter().all(is_ext_value),
        Cv::TextMap(m) => m.iter().all(|(_, val)| is_ext_value(val)),
        Cv::Map(_) => false,
    }
}

impl ClusterOp {
    /// Integer-keyed canonical map (§18.6.3). Optional fields are omitted when absent (never `null`).
    pub fn to_cv(&self) -> Cv {
        let mut m = vec![(1u64, Cv::U64(self.kind as u64)), (2, Cv::Text(self.target.clone()))];
        if let Some(field) = &self.field {
            m.push((3, Cv::Text(field.clone())));
        }
        if let Some(value) = &self.value {
            m.push((4, value.clone()));
        }
        m.push((5, self.hlc.to_cv()));
        if let Some(obs) = &self.observed {
            m.push((6, Cv::Array(obs.iter().map(AddTag::to_cv).collect())));
        }
        Cv::Map(m)
    }

    /// Decode from canonical CBOR, denying unknown keys and rejecting a non-`ext-value` LWW value
    /// (fail closed). Structural presence is checked here; the §5.6.4 semantic validity of the op
    /// (kind range, skew bound, observed-tag causality, deniable-embed guard) is enforced by
    /// [`crate::crdt::validate_op`].
    pub fn from_cv(cv: Cv) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cv)?;
        let kind = as_u8(f.req(1)?)?;
        let target = as_text(f.req(2)?)?;
        let field = f.take(3).map(as_text).transpose()?;
        let value = match f.take(4) {
            Some(v) if is_ext_value(&v) => Some(v),
            Some(_) => return Err(CborError::TypeMismatch), // not an ext-value ⇒ fail closed
            None => None,
        };
        let hlc = Hlc::from_cv(f.req(5)?)?;
        let observed = match f.take(6) {
            Some(cv) => Some(
                as_array(cv)?.into_iter().map(AddTag::from_cv).collect::<Result<Vec<_>, _>>()?,
            ),
            None => None,
        };
        f.deny_unknown()?;
        Ok(ClusterOp { kind, target, field, value, hlc, observed })
    }

    /// The content-address of this op's canonical bytes — the value a `JournalEntry.ref` records
    /// for a CRDT op (§5.6.3(b)).
    pub fn op_hash(&self) -> Hash {
        dmtap_core::ContentId::of(&cbor::encode(&self.to_cv())).0
    }
}

/// One id-range and the sender's fingerprint over the ids it holds there (§5.6.3(a) / §18.6.3).
/// **Self-verifying**: the receiver recomputes `fp` over the sender's revealed sorted ids in
/// `[lo, hi)` and rejects a mismatch (`0x0411`), so a peer cannot forge a "we match" claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeFingerprint {
    /// Inclusive low id bound of the range (§18.6.3 key 1).
    pub lo: Hash,
    /// Exclusive high id bound of the range (§18.6.3 key 2).
    pub hi: Hash,
    /// Number of ids the sender holds in `[lo, hi)` (§18.6.3 key 3).
    pub count: u64,
    /// Suite hash over the sender's **sorted** ids in `[lo, hi)` (§18.6.3 key 4).
    pub fp: Hash,
}

impl RangeFingerprint {
    /// Integer-keyed canonical map (§18.6.3).
    pub fn to_cv(&self) -> Cv {
        Cv::Map(vec![
            (1, Cv::Bytes(self.lo.clone())),
            (2, Cv::Bytes(self.hi.clone())),
            (3, Cv::U64(self.count)),
            (4, Cv::Bytes(self.fp.clone())),
        ])
    }

    /// Decode from canonical CBOR, denying unknown keys (fail closed).
    pub fn from_cv(cv: Cv) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cv)?;
        let lo = as_bytes(f.req(1)?)?;
        let hi = as_bytes(f.req(2)?)?;
        let count = as_u64(f.req(3)?)?;
        let fp = as_bytes(f.req(4)?)?;
        f.deny_unknown()?;
        Ok(RangeFingerprint { lo, hi, count, fp })
    }
}

/// One append-only, hash-chained per-account journal entry (§5.6.3(b) / §18.6.3). A rejoining
/// device replays these in `seq` order, applying each referenced object/op; a broken `prev` chain
/// is a fork of the owner's own log (`0x0412`, HALT_ALERT).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalEntry {
    /// Strictly-increasing sequence number (§18.6.3 key 1).
    pub seq: u64,
    /// Hash of the prior entry (genesis = the all-zero v0-prefixed digest) (§18.6.3 key 2).
    pub prev: Hash,
    /// The object id or op hash this entry records (§18.6.3 key 3).
    pub reference: Hash,
}

impl JournalEntry {
    /// Integer-keyed canonical map (§18.6.3).
    pub fn to_cv(&self) -> Cv {
        Cv::Map(vec![
            (1, Cv::U64(self.seq)),
            (2, Cv::Bytes(self.prev.clone())),
            (3, Cv::Bytes(self.reference.clone())),
        ])
    }

    /// Decode from canonical CBOR, denying unknown keys (fail closed).
    pub fn from_cv(cv: Cv) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cv)?;
        let seq = as_u64(f.req(1)?)?;
        let prev = as_bytes(f.req(2)?)?;
        let reference = as_bytes(f.req(3)?)?;
        f.deny_unknown()?;
        Ok(JournalEntry { seq, prev, reference })
    }

    /// The content-address of this entry's canonical bytes — the value the *next* entry's `prev`
    /// MUST equal (§5.6.3(b)).
    pub fn entry_hash(&self) -> Hash {
        dmtap_core::ContentId::of(&cbor::encode(&self.to_cv())).0
    }
}

/// A device's advertised stability point: the max HLC it has durably applied (tombstone GC,
/// §5.6.5 / §18.6.3). Every device computes the same stability cut from the same marks, so GC is
/// leaderless and deterministic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StabilityMark {
    /// The advertising device's id (`ik-pub`, §18.6.3 key 1).
    pub device: Vec<u8>,
    /// The max HLC that device has durably applied (§18.6.3 key 2).
    pub hlc: Hlc,
}

impl StabilityMark {
    /// Integer-keyed canonical map (§18.6.3).
    pub fn to_cv(&self) -> Cv {
        Cv::Map(vec![(1, Cv::Bytes(self.device.clone())), (2, self.hlc.to_cv())])
    }

    /// Decode from canonical CBOR, denying unknown keys (fail closed).
    pub fn from_cv(cv: Cv) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cv)?;
        let device = as_bytes(f.req(1)?)?;
        let hlc = Hlc::from_cv(f.req(2)?)?;
        f.deny_unknown()?;
        Ok(StabilityMark { device, hlc })
    }
}

/// The top-level cluster-sync frame (§18.6.3). `frame_type` (key 1) selects which body fields carry
/// meaning; `device` (key 2) names the origin, whose non-revoked `DeviceCert` a receiver MUST check
/// before acting (`0x0410`). The frame carries **no separate DMTAP signature** — it rides inside the
/// authenticated MLS cluster group (§18.6.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterSyncFrame {
    /// `1`=announce `2`=recon `3`=fetch-request `4`=journal `5`=stability (§18.6.3 key 1).
    pub frame_type: u8,
    /// Origin device key; MUST be a non-revoked cluster member (§18.6.3 key 2).
    pub device: Vec<u8>,
    /// Announced (type 1) or requested (type 3) content-addresses (§18.6.3 key 3).
    pub ids: Vec<Hash>,
    /// The reconciliation summary (type 2) (§18.6.3 key 4).
    pub ranges: Vec<RangeFingerprint>,
    /// CRDT metadata ops to merge (§18.6.3 key 5).
    pub ops: Vec<ClusterOp>,
    /// Append-only journal segment for replay-backfill (type 4) (§18.6.3 key 6).
    pub journal: Vec<JournalEntry>,
    /// Per-device max-applied-HLC stability marks (type 5) (§18.6.3 key 7).
    pub stability: Vec<StabilityMark>,
}

impl ClusterSyncFrame {
    /// A bare frame of `frame_type` from `device` with every optional body empty. Use the
    /// `announce`/`recon`/… constructors for the common shapes.
    pub fn new(frame_type: u8, device: Vec<u8>) -> Self {
        ClusterSyncFrame {
            frame_type,
            device,
            ids: Vec::new(),
            ranges: Vec::new(),
            ops: Vec::new(),
            journal: Vec::new(),
            stability: Vec::new(),
        }
    }

    /// A type-1 announce of held object ids (§5.6.2).
    pub fn announce(device: Vec<u8>, ids: Vec<Hash>) -> Self {
        ClusterSyncFrame { ids, ..Self::new(FRAME_ANNOUNCE, device) }
    }

    /// A type-2 recon summary (§5.6.3(a)).
    pub fn recon(device: Vec<u8>, ranges: Vec<RangeFingerprint>) -> Self {
        ClusterSyncFrame { ranges, ..Self::new(FRAME_RECON, device) }
    }

    /// A type-3 fetch-request for object bytes by id (§5.6.2).
    pub fn fetch(device: Vec<u8>, ids: Vec<Hash>) -> Self {
        ClusterSyncFrame { ids, ..Self::new(FRAME_FETCH, device) }
    }

    /// A type-4 journal segment (§5.6.3(b)).
    pub fn journal(device: Vec<u8>, journal: Vec<JournalEntry>) -> Self {
        ClusterSyncFrame { journal, ..Self::new(FRAME_JOURNAL, device) }
    }

    /// A type-5 stability-mark frame (§5.6.5).
    pub fn stability(device: Vec<u8>, stability: Vec<StabilityMark>) -> Self {
        ClusterSyncFrame { stability, ..Self::new(FRAME_STABILITY, device) }
    }

    /// Attach CRDT ops to any frame (ops ride as an independent optional field, §18.6.3 key 5).
    pub fn with_ops(mut self, ops: Vec<ClusterOp>) -> Self {
        self.ops = ops;
        self
    }

    /// Integer-keyed canonical map (§18.6.3); empty optional bodies are omitted, never `null`.
    fn to_cv(&self) -> Cv {
        let mut m =
            vec![(1u64, Cv::U64(self.frame_type as u64)), (2, Cv::Bytes(self.device.clone()))];
        if !self.ids.is_empty() {
            m.push((3, Cv::Array(self.ids.iter().map(|h| Cv::Bytes(h.clone())).collect())));
        }
        if !self.ranges.is_empty() {
            m.push((4, Cv::Array(self.ranges.iter().map(RangeFingerprint::to_cv).collect())));
        }
        if !self.ops.is_empty() {
            m.push((5, Cv::Array(self.ops.iter().map(ClusterOp::to_cv).collect())));
        }
        if !self.journal.is_empty() {
            m.push((6, Cv::Array(self.journal.iter().map(JournalEntry::to_cv).collect())));
        }
        if !self.stability.is_empty() {
            m.push((7, Cv::Array(self.stability.iter().map(StabilityMark::to_cv).collect())));
        }
        Cv::Map(m)
    }

    /// The exact wire bytes of this frame: §18-canonical integer-keyed CBOR.
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv())
    }

    /// Decode a frame from canonical CBOR, **failing closed** on any non-canonical byte (via the
    /// core decoder), an unknown frame `type` outside `1..=5`, an out-of-`ext-value` op value, or
    /// any unknown key. Returns a wrapped [`CborError`]; membership/semantic checks come after.
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cbor::decode(bytes)?)?;
        let frame_type = as_u8(f.req(1)?)?;
        if !(FRAME_ANNOUNCE..=FRAME_STABILITY).contains(&frame_type) {
            return Err(CborError::UnknownDiscriminant(frame_type as u64)); // fail closed
        }
        let device = as_bytes(f.req(2)?)?;
        let ids = match f.take(3) {
            Some(cv) => as_array(cv)?.into_iter().map(as_bytes).collect::<Result<Vec<_>, _>>()?,
            None => Vec::new(),
        };
        let ranges = match f.take(4) {
            Some(cv) => as_array(cv)?
                .into_iter()
                .map(RangeFingerprint::from_cv)
                .collect::<Result<Vec<_>, _>>()?,
            None => Vec::new(),
        };
        let ops = match f.take(5) {
            Some(cv) => {
                as_array(cv)?.into_iter().map(ClusterOp::from_cv).collect::<Result<Vec<_>, _>>()?
            }
            None => Vec::new(),
        };
        let journal = match f.take(6) {
            Some(cv) => as_array(cv)?
                .into_iter()
                .map(JournalEntry::from_cv)
                .collect::<Result<Vec<_>, _>>()?,
            None => Vec::new(),
        };
        let stability = match f.take(7) {
            Some(cv) => as_array(cv)?
                .into_iter()
                .map(StabilityMark::from_cv)
                .collect::<Result<Vec<_>, _>>()?,
            None => Vec::new(),
        };
        f.deny_unknown()?;
        Ok(ClusterSyncFrame { frame_type, device, ids, ranges, ops, journal, stability })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hlc(w: u64, c: u32, d: u8) -> Hlc {
        Hlc { wall: w, counter: c, device: vec![d] }
    }

    #[test]
    fn hlc_total_order_is_wall_then_counter_then_device() {
        // Larger wall wins outright.
        assert!(hlc(2, 0, 0) > hlc(1, 9, 9));
        // Equal wall ⇒ larger counter wins.
        assert!(hlc(1, 2, 0) > hlc(1, 1, 9));
        // Equal wall+counter ⇒ larger device bytes win.
        assert!(hlc(1, 1, 2) > hlc(1, 1, 1));
        // Reflexive equality.
        assert_eq!(hlc(1, 1, 1), hlc(1, 1, 1));
    }

    #[test]
    fn frame_round_trips_every_body() {
        let dev = vec![0xAAu8; 32];
        let frames = vec![
            ClusterSyncFrame::announce(dev.clone(), vec![vec![0x1e; 33], vec![0x1e; 33]]),
            ClusterSyncFrame::fetch(dev.clone(), vec![vec![1, 2, 3]]),
            ClusterSyncFrame::recon(
                dev.clone(),
                vec![RangeFingerprint {
                    lo: vec![0x00; 33],
                    hi: vec![0xff; 33],
                    count: 7,
                    fp: vec![0x1e; 33],
                }],
            ),
            ClusterSyncFrame::journal(
                dev.clone(),
                vec![JournalEntry { seq: 0, prev: vec![0x1e; 33], reference: vec![0x1e; 33] }],
            ),
            ClusterSyncFrame::stability(
                dev.clone(),
                vec![StabilityMark { device: dev.clone(), hlc: hlc(5, 1, 7) }],
            ),
        ];
        for frame in frames {
            let bytes = frame.det_cbor();
            let back = ClusterSyncFrame::from_det_cbor(&bytes).expect("decode");
            assert_eq!(back, frame, "round-trip must preserve the frame");
            // Canonical encoding is a fixed point: re-encoding the decoded value is byte-identical.
            assert_eq!(back.det_cbor(), bytes);
        }
    }

    #[test]
    fn every_cluster_op_shape_round_trips() {
        let ops = vec![
            ClusterOp {
                kind: OP_SET_ADD,
                target: "inbox/msg-1".into(),
                field: None,
                value: None,
                hlc: hlc(10, 0, 1),
                observed: None,
            },
            ClusterOp {
                kind: OP_SET_REMOVE,
                target: "inbox/msg-1".into(),
                field: None,
                value: None,
                hlc: hlc(11, 0, 1),
                observed: Some(vec![AddTag { device: vec![1], hlc: hlc(10, 0, 1) }]),
            },
            ClusterOp {
                kind: OP_LWW_SET,
                target: "inbox/msg-1".into(),
                field: Some("read".into()),
                value: Some(Cv::Bool(true)),
                hlc: hlc(12, 3, 2),
                observed: None,
            },
        ];
        let frame = ClusterSyncFrame::new(FRAME_ANNOUNCE, vec![9]).with_ops(ops.clone());
        let back = ClusterSyncFrame::from_det_cbor(&frame.det_cbor()).unwrap();
        assert_eq!(back.ops, ops);
    }

    #[test]
    fn unknown_frame_type_is_rejected_fail_closed() {
        let mut frame = ClusterSyncFrame::new(FRAME_ANNOUNCE, vec![1]);
        frame.frame_type = 9; // outside 1..=5
        let bytes = frame.det_cbor();
        assert_eq!(
            ClusterSyncFrame::from_det_cbor(&bytes),
            Err(CborError::UnknownDiscriminant(9))
        );
    }

    #[test]
    fn integer_keyed_map_lww_value_is_rejected() {
        // A DeniablePayload is an integer-keyed map (keys 1..=7). Smuggled as an LWW value it is
        // NOT an ext-value (which admits only text-keyed maps) and must be rejected structurally.
        let smuggled = Cv::Map(vec![(1, Cv::Bytes(vec![0xAB])), (2, Cv::U64(0))]);
        let op = Cv::Map(vec![
            (1, Cv::U64(OP_LWW_SET as u64)),
            (2, Cv::Text("t".into())),
            (3, Cv::Text("f".into())),
            (4, smuggled),
            (5, hlc(1, 0, 1).to_cv()),
        ]);
        assert_eq!(ClusterOp::from_cv(op), Err(CborError::TypeMismatch));
    }

    #[test]
    fn text_keyed_ext_value_map_is_accepted() {
        let op = ClusterOp {
            kind: OP_LWW_SET,
            target: "t".into(),
            field: Some("labels".into()),
            value: Some(Cv::TextMap(vec![("color".into(), Cv::Text("red".into()))])),
            hlc: hlc(1, 0, 1),
            observed: None,
        };
        assert_eq!(ClusterOp::from_cv(op.to_cv()).unwrap(), op);
    }

    #[test]
    fn malformed_bytes_fail_closed() {
        // Truncated / garbage bytes surface as a core decode error, never a panic.
        assert!(ClusterSyncFrame::from_det_cbor(&[0xff, 0x00, 0x11]).is_err());
        assert!(ClusterSyncFrame::from_det_cbor(&[]).is_err());
        // An unknown key in the frame map is denied (signed-object rule).
        let mut cv = ClusterSyncFrame::announce(vec![1], vec![vec![2]]).to_cv();
        if let Cv::Map(m) = &mut cv {
            m.push((99, Cv::U64(0)));
        }
        assert_eq!(
            ClusterSyncFrame::from_det_cbor(&cbor::encode(&cv)),
            Err(CborError::UnknownKey(99))
        );
    }
}

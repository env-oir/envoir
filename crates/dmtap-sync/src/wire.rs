//! The `SyncOp` wire objects (`SYNC.md` §3, §4.1): [`Hlc`], [`AddTag`], [`OpRef`], [`SyncOp`],
//! their canonical deterministic-CBOR encodings, and the op content address (`op-id`).

use crate::detcbor::{decode, encode, DetCborError, Fields, SVal};
use crate::error::SyncError;
use dmtap_core::id::ContentId;

/// DS-tag for the per-op `COSE_Sign1` signable preimage (§4.1). Carried in `external_aad`.
pub const DS_OP: &[u8] = b"DMTAP-SYNC-v0/op";
/// DS-tag for the op content address (§4.1).
pub const DS_OP_ID: &[u8] = b"DMTAP-SYNC-v0/op-id";
/// DS-tag for a range-Merkle fingerprint (§5.3).
pub const DS_RECON_FP: &[u8] = b"DMTAP-SYNC-v0/recon-fp";
/// DS-tag for the canonical observable-state root hashed into `Snapshot.root` (§6.1).
pub const DS_SNAPSHOT_STATE: &[u8] = b"DMTAP-SYNC-v0/snapshot-state";
/// DS-tag for a `Snapshot`'s own signature preimage (§6.1).
pub const DS_SNAPSHOT: &[u8] = b"DMTAP-SYNC-v0/snapshot";

/// `kind` 1 — OR-Set add (§4.2).
pub const OP_SET_ADD: u8 = 1;
/// `kind` 2 — OR-Set observed-remove (§4.2).
pub const OP_SET_REMOVE: u8 = 2;
/// `kind` 3 — LWW register write (§4.2).
pub const OP_LWW_SET: u8 = 3;
/// `kind` 4 — remove-wins death certificate (§4.2).
pub const OP_DEATH: u8 = 4;
/// `kind` 5 — PN-counter delta (§4.2).
pub const OP_COUNTER: u8 = 5;
/// `kind` 6 — RGA sequence insert (§4.2).
pub const OP_SEQ_INSERT: u8 = 6;
/// `kind` 7 — RGA sequence remove (§4.2).
pub const OP_SEQ_REMOVE: u8 = 7;
/// `kind` 8 — movable-tree move (§4.2).
pub const OP_TREE_MOVE: u8 = 8;

/// The `field` token of an explicit un-delete (§4.5).
pub const DEATH_LIVE: &str = "live";
/// The reserved movable-tree root node id (§6.1.1): the empty string, which is never itself a
/// `node` entry, only the `parent` of a top-level node.
pub const TREE_ROOT: &str = "";

/// HLC wall-clock skew bound: ±120 s (§3, = the §5.6 `HLC_SKEW_MS`).
pub const HLC_SKEW_MS: u64 = 120_000;

/// A Hybrid Logical Clock (§3). The derived `Ord` is exactly the normative total order —
/// lexicographic by `(wall, counter, author)` — and because `author` is a public key, two
/// **distinct** authors never tie, so the order is total across every replica.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Hlc {
    /// Unix milliseconds (key 1): an ordering hint and skew bound, never relied on for correctness.
    pub wall: u64,
    /// Logical tick within a wall-ms (key 2).
    pub counter: u32,
    /// The author key producing this timestamp (key 3) — the globally unique tiebreak.
    pub author: Vec<u8>,
}

impl Hlc {
    /// Canonical integer-keyed map `{1: wall, 2: counter, 3: author}` (§3).
    pub fn to_sval(&self) -> SVal {
        SVal::Map(vec![
            (1, SVal::Uint(self.wall)),
            (2, SVal::Uint(self.counter as u64)),
            (3, SVal::Bytes(self.author.clone())),
        ])
    }

    /// Decode, denying unknown keys (fail closed).
    pub fn from_sval(cv: SVal) -> Result<Self, DetCborError> {
        let mut f = Fields::new(cv)?;
        let wall = f.req(1)?.as_int().ok_or(DetCborError::Malformed)? as u64;
        let counter = u32::try_from(f.req(2)?.as_int().ok_or(DetCborError::Malformed)? as u64)
            .map_err(|_| DetCborError::Malformed)?;
        let author = f.req(3)?.as_bytes().ok_or(DetCborError::Malformed)?.to_vec();
        f.deny_unknown()?;
        Ok(Hlc { wall, counter, author })
    }

    /// This HLC's canonical bytes.
    pub fn det_cbor(&self) -> Vec<u8> {
        encode(&self.to_sval())
    }

    /// **Tick** (§3): mint the next local HLC for `author` given the wall clock reading `now_ms`.
    /// Strictly monotonic per author — if the clock did not advance, the counter does.
    pub fn tick(&mut self, now_ms: u64) -> Hlc {
        if now_ms > self.wall {
            self.wall = now_ms;
            self.counter = 0;
        } else {
            self.counter = self.counter.saturating_add(1);
        }
        self.clone()
    }

    /// **Observe** (§3): fold a remote HLC forward into the local clock so that every future local
    /// tick sorts after every op already seen — which is what makes a backwards or fast wall clock
    /// unable to mint a stale-ordering timestamp.
    pub fn observe(&mut self, remote: &Hlc) {
        if remote.wall > self.wall {
            self.wall = remote.wall;
            self.counter = remote.counter;
        } else if remote.wall == self.wall && remote.counter >= self.counter {
            self.counter = remote.counter;
        }
    }
}

/// A globally-unique OR-Set add identity `{author, hlc}` (§4.1).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AddTag {
    /// The adding author key (key 1).
    pub author: Vec<u8>,
    /// The add's HLC (key 2).
    pub hlc: Hlc,
}

impl AddTag {
    /// Canonical map `{1: author, 2: hlc}`.
    pub fn to_sval(&self) -> SVal {
        SVal::Map(vec![(1, SVal::Bytes(self.author.clone())), (2, self.hlc.to_sval())])
    }

    /// Decode, denying unknown keys.
    pub fn from_sval(cv: SVal) -> Result<Self, DetCborError> {
        let mut f = Fields::new(cv)?;
        let author = f.req(1)?.as_bytes().ok_or(DetCborError::Malformed)?.to_vec();
        let hlc = Hlc::from_sval(f.req(2)?)?;
        f.deny_unknown()?;
        Ok(AddTag { author, hlc })
    }
}

/// A reference to another element by `(target[, hlc])` (§4.1): an RGA left-origin, a tree parent,
/// or a `SyncFrame` back-link.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpRef {
    /// The referenced object id (key 1). For a tree move this is the new parent (`""` = root).
    pub target: String,
    /// The referenced element's HLC (key 2) — present for RGA element references, absent when the
    /// reference names an object rather than an element.
    pub hlc: Option<Hlc>,
}

impl OpRef {
    /// Canonical map `{1: target, ?2: hlc}`.
    pub fn to_sval(&self) -> SVal {
        let mut m = vec![(1, SVal::Text(self.target.clone()))];
        if let Some(h) = &self.hlc {
            m.push((2, h.to_sval()));
        }
        SVal::Map(m)
    }

    /// Decode, denying unknown keys.
    pub fn from_sval(cv: SVal) -> Result<Self, DetCborError> {
        let mut f = Fields::new(cv)?;
        let target = f.req(1)?.as_text().ok_or(DetCborError::Malformed)?.to_owned();
        let hlc = match f.take(2) {
            Some(v) => Some(Hlc::from_sval(v)?),
            None => None,
        };
        f.deny_unknown()?;
        Ok(OpRef { target, hlc })
    }
}

/// The single signed operation envelope shared by all six CRDT types (§4.1). `kind` selects the
/// type and dictates which optional fields are meaningful (§4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncOp {
    /// CRDT/op discriminator (key 1).
    pub kind: u8,
    /// Namespace (key 2); `""` is the default single collection.
    pub ns: String,
    /// Object id (key 3).
    pub target: String,
    /// Register/counter field, death class, or tree ordering key (key 4).
    pub field: Option<String>,
    /// The `ext-value` payload (key 5): LWW value, OR-Set element, counter delta, RGA atom.
    pub value: Option<SVal>,
    /// This op's HLC (key 6); `hlc.author` is the producing key and the signer.
    pub hlc: Hlc,
    /// OR-Set remove: the specific add-tags this remove cancels (key 7).
    pub observed: Option<Vec<AddTag>>,
    /// RGA left-origin / tree parent / frame back-link (key 8).
    pub reference: Option<OpRef>,
}

impl SyncOp {
    /// Canonical integer-keyed map, ascending keys, optionals omitted when absent (§4.1).
    pub fn to_sval(&self) -> SVal {
        let mut m: Vec<(u64, SVal)> = vec![
            (1, SVal::Uint(self.kind as u64)),
            (2, SVal::Text(self.ns.clone())),
            (3, SVal::Text(self.target.clone())),
        ];
        if let Some(f) = &self.field {
            m.push((4, SVal::Text(f.clone())));
        }
        if let Some(v) = &self.value {
            m.push((5, v.clone()));
        }
        m.push((6, self.hlc.to_sval()));
        if let Some(obs) = &self.observed {
            m.push((7, SVal::Array(obs.iter().map(AddTag::to_sval).collect())));
        }
        if let Some(r) = &self.reference {
            m.push((8, r.to_sval()));
        }
        SVal::Map(m)
    }

    /// Decode from canonical CBOR, denying unknown keys (fail closed).
    pub fn from_sval(cv: SVal) -> Result<Self, DetCborError> {
        let mut f = Fields::new(cv)?;
        let kind = u8::try_from(f.req(1)?.as_int().ok_or(DetCborError::Malformed)? as u64)
            .map_err(|_| DetCborError::Malformed)?;
        let ns = f.req(2)?.as_text().ok_or(DetCborError::Malformed)?.to_owned();
        let target = f.req(3)?.as_text().ok_or(DetCborError::Malformed)?.to_owned();
        let field = match f.take(4) {
            Some(v) => Some(v.as_text().ok_or(DetCborError::Malformed)?.to_owned()),
            None => None,
        };
        let value = f.take(5);
        let hlc = Hlc::from_sval(f.req(6)?)?;
        let observed = match f.take(7) {
            Some(v) => {
                let items = match v {
                    SVal::Array(a) => a,
                    _ => return Err(DetCborError::Malformed),
                };
                Some(items.into_iter().map(AddTag::from_sval).collect::<Result<Vec<_>, _>>()?)
            }
            None => None,
        };
        let reference = match f.take(8) {
            Some(v) => Some(OpRef::from_sval(v)?),
            None => None,
        };
        f.deny_unknown()?;
        Ok(SyncOp { kind, ns, target, field, value, hlc, observed, reference })
    }

    /// This op's canonical bytes — the `COSE_Sign1` payload and the `op-id` preimage body.
    pub fn det_cbor(&self) -> Vec<u8> {
        encode(&self.to_sval())
    }

    /// Decode an op from wire bytes, failing closed on any non-canonical encoding
    /// (`ERR_SYNC_OP_INVALID`, `0x0A03`).
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, SyncError> {
        let cv = decode(bytes).map_err(|_| SyncError::OpInvalid)?;
        SyncOp::from_sval(cv).map_err(|_| SyncError::OpInvalid)
    }

    /// The op content address (§4.1):
    /// `op-id = 0x1e ‖ BLAKE3-256("DMTAP-SYNC-v0/op-id" ‖ 0x00 ‖ det_cbor(SyncOp))`.
    ///
    /// Computed over the **`SyncOp`**, never over the `COSE_Sign1` envelope, so a per-op-signed op
    /// and the identical op carried inside a `SyncFrame` share one dedup/fingerprint identity.
    pub fn op_id(&self) -> ContentId {
        op_id_of(&self.det_cbor())
    }
}

/// The §4.1 `op-id` over already-encoded op bytes.
pub fn op_id_of(op_det_cbor: &[u8]) -> ContentId {
    ds_hash(DS_OP_ID, op_det_cbor)
}

/// A §18.1.5 v0 content address over a DS-tagged preimage:
/// `0x1e ‖ BLAKE3-256(ds ‖ 0x00 ‖ body)` — the one hashing shape every Sync DS-tag uses.
pub fn ds_hash(ds: &[u8], body: &[u8]) -> ContentId {
    let mut pre = Vec::with_capacity(ds.len() + 1 + body.len());
    pre.extend_from_slice(ds);
    pre.push(0x00);
    pre.extend_from_slice(body);
    ContentId::of(&pre)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn author() -> Vec<u8> {
        vec![0xaa; 32]
    }

    #[test]
    fn op_round_trips_byte_for_byte() {
        let op = SyncOp {
            kind: OP_LWW_SET,
            ns: String::new(),
            target: "a".into(),
            field: Some("x".into()),
            value: Some(SVal::Text("v".into())),
            hlc: Hlc { wall: 1, counter: 2, author: author() },
            observed: None,
            reference: None,
        };
        let bytes = op.det_cbor();
        let back = SyncOp::from_det_cbor(&bytes).unwrap();
        assert_eq!(back, op);
        assert_eq!(back.det_cbor(), bytes);
    }

    #[test]
    fn hlc_total_order_is_wall_counter_author() {
        let a = Hlc { wall: 1, counter: 0, author: vec![0xff] };
        let b = Hlc { wall: 1, counter: 1, author: vec![0x00] };
        assert!(b > a, "counter outranks author");
        let c = Hlc { wall: 2, counter: 0, author: vec![0x00] };
        assert!(c > b, "wall outranks counter");
        let d = Hlc { wall: 1, counter: 0, author: vec![0x01] };
        assert!(a > d, "author is the final tiebreak");
    }

    #[test]
    fn observe_then_tick_sorts_after_every_seen_op() {
        let mut clock = Hlc { wall: 10, counter: 0, author: author() };
        let remote = Hlc { wall: 5, counter: 9, author: vec![0xbb; 32] };
        clock.observe(&remote);
        // A backwards remote wall must not drag the local clock back...
        assert_eq!(clock.wall, 10);
        let ahead = Hlc { wall: 50, counter: 3, author: vec![0xbb; 32] };
        clock.observe(&ahead);
        let next = clock.tick(0); // a stalled/backwards local wall clock
        assert!(next > ahead, "next local tick must sort after every observed op");
    }

    #[test]
    fn unknown_key_is_rejected() {
        // {1:3, 2:"", 3:"a", 6:{…}, 9:1} — key 9 is not in the schema.
        let mut m = SyncOp {
            kind: OP_LWW_SET,
            ns: String::new(),
            target: "a".into(),
            field: None,
            value: None,
            hlc: Hlc { wall: 1, counter: 0, author: author() },
            observed: None,
            reference: None,
        }
        .to_sval();
        if let SVal::Map(entries) = &mut m {
            entries.push((9, SVal::Uint(1)));
        }
        assert!(SyncOp::from_det_cbor(&encode(&m)).is_err());
    }
}

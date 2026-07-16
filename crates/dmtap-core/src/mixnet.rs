//! Mixnet directory objects — spec §4.4, §18.5.2 / §18.5.3.
//!
//! A [`MixNodeDescriptor`] is a mix node's signed self-descriptor (its per-epoch Sphinx mix
//! public keys, reachability, and stratified layer). A [`MixDirectory`] is the signed,
//! KT-anchored snapshot of the mix fleet for an epoch — the mixnet analogue of the
//! [`crate::directory::DomainDirectory`], subject to the same "indexes, does not forge"
//! discipline: the authority attests *membership of the set*, while each descriptor self-verifies
//! under its own `node_ik`.
//!
//! Both are **integer-keyed canonical CBOR** maps (§18.1.2); serde is deliberately not derived
//! (text keys are not the wire form). Signing follows §18.9.9 — the general rule
//! `Sign(sk, DS-tag ‖ 0x00 ‖ det_cbor(object ∖ {sig}))`.

use crate::cbor::{self, as_array, as_bytes, as_text, as_u64, as_u8, CborError, Cv, Fields};
use crate::id::ContentId;
use crate::identity::{verify_domain, IdentityError, IdentityKey};
use crate::suite::Suite;
use crate::TimestampMs;

/// §18.9.9 domain-separation tags (ASCII ‖ trailing `0x00`; `sign_domain` prepends them).
pub const MIX_DESCRIPTOR_DS: &[u8] = b"DMTAP-v0/mix-descriptor\x00";
pub const MIX_DIRECTORY_DS: &[u8] = b"DMTAP-v0/mix-directory\x00";

/// Decode a `suite` field (a `u8`), failing closed on any unknown byte (§18.1.4).
fn suite_from_cv(cv: Cv) -> Result<Suite, CborError> {
    let b = as_u8(cv)?;
    Suite::from_u8(b).ok_or(CborError::UnknownSuite(b))
}

/// One Sphinx mix key valid for a given epoch (spec §18.5.2 `MixKeyEntry`).
/// `{ 1 => u64 epoch, 2 => enc-key mix_key, 3 => ts valid_until }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MixKeyEntry {
    pub epoch: u64,        // key 1
    pub mix_key: Vec<u8>,  // key 2 — Sphinx per-hop public key for this epoch (v0 X25519)
    pub valid_until: TimestampMs, // key 3
}

impl MixKeyEntry {
    fn to_cv(&self) -> Cv {
        Cv::Map(vec![
            (1, Cv::U64(self.epoch)),
            (2, Cv::Bytes(self.mix_key.clone())),
            (3, Cv::U64(self.valid_until)),
        ])
    }

    fn from_cv(cv: Cv) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cv)?;
        let epoch = as_u64(f.req(1)?)?;
        let mix_key = as_bytes(f.req(2)?)?;
        let valid_until = as_u64(f.req(3)?)?;
        f.deny_unknown()?;
        Ok(MixKeyEntry { epoch, mix_key, valid_until })
    }
}

/// A signed mix-node self-descriptor (spec §4.4.2, §18.5.2). Signed by an `IK`-authorized device
/// key of `node_ik` (§18.9.9); the reference signs with `node_ik` itself (an `IK` is trivially
/// `IK`-authorized) and self-verifies under `node_ik`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MixNodeDescriptor {
    pub suite: Suite,               // key 1
    pub node_ik: Vec<u8>,           // key 2 — the mix node's long-term identity key
    pub addrs: Vec<String>,         // key 3 — reachability hints (maddr = tstr); MAY be empty
    pub mix_keys: Vec<MixKeyEntry>, // key 4 — current + next Sphinx keys, keyed by epoch (≥ 1)
    pub layer: u8,                  // key 5 — stratified layer 0=entry / 1=middle / 2=exit
    pub ts: TimestampMs,            // key 6
    pub sig: Vec<u8>,               // key 7 — §18.9.9
    pub substrate: Option<u8>,      // key 8 — transport-substrate tag; absent ⇒ 0x01 libp2p
    pub operator: Option<Vec<u8>>,  // key 9 — operator identity; absent ⇒ node_ik
}

impl MixNodeDescriptor {
    /// Integer-keyed canonical map (§18.5.2). `include_sig=false` omits key 7 for the §18.9.9
    /// signing body.
    fn to_cv(&self, include_sig: bool) -> Cv {
        let mut m = vec![
            (1u64, Cv::U64(self.suite.as_u8() as u64)),
            (2, Cv::Bytes(self.node_ik.clone())),
            (3, Cv::Array(self.addrs.iter().map(|a| Cv::Text(a.clone())).collect())),
            (4, Cv::Array(self.mix_keys.iter().map(MixKeyEntry::to_cv).collect())),
            (5, Cv::U64(self.layer as u64)),
            (6, Cv::U64(self.ts)),
        ];
        if let Some(s) = self.substrate {
            m.push((8, Cv::U64(s as u64)));
        }
        if let Some(op) = &self.operator {
            m.push((9, Cv::Bytes(op.clone())));
        }
        if include_sig {
            m.push((7, Cv::Bytes(self.sig.clone())));
        }
        Cv::Map(m)
    }

    /// The exact wire bytes: §18-canonical integer-keyed CBOR.
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(true))
    }

    /// The §18.9.9 signing body: deterministic CBOR of the descriptor with `sig` (key 7) omitted.
    pub fn signing_body(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(false))
    }

    /// Decode a descriptor (§18.5.2), failing closed on any violation (including a `layer` outside
    /// `0..=2`, §18.5.2 `mix-layer`, and a missing/empty `mix_keys`).
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cbor::decode(bytes)?)?;
        let suite = suite_from_cv(f.req(1)?)?;
        let node_ik = as_bytes(f.req(2)?)?;
        let addrs = as_array(f.req(3)?)?
            .into_iter()
            .map(as_text)
            .collect::<Result<_, _>>()?;
        let mix_keys: Vec<MixKeyEntry> = as_array(f.req(4)?)?
            .into_iter()
            .map(MixKeyEntry::from_cv)
            .collect::<Result<_, _>>()?;
        if mix_keys.is_empty() {
            return Err(CborError::TypeMismatch); // [+ MixKeyEntry] requires ≥ 1
        }
        let layer = as_u8(f.req(5)?)?;
        if layer > 2 {
            return Err(CborError::UnknownDiscriminant(layer as u64)); // mix-layer = 0..2
        }
        let ts = as_u64(f.req(6)?)?;
        let sig = as_bytes(f.req(7)?)?;
        let substrate = f.take(8).map(as_u8).transpose()?;
        let operator = f.take(9).map(as_bytes).transpose()?;
        f.deny_unknown()?;
        Ok(MixNodeDescriptor { suite, node_ik, addrs, mix_keys, layer, ts, sig, substrate, operator })
    }

    /// Issue (sign) a descriptor with the node's `IK` (§18.9.9); `node_ik` is set from the signer.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        node_ik: &IdentityKey,
        addrs: Vec<String>,
        mix_keys: Vec<MixKeyEntry>,
        layer: u8,
        ts: TimestampMs,
        substrate: Option<u8>,
        operator: Option<Vec<u8>>,
    ) -> MixNodeDescriptor {
        let mut d = MixNodeDescriptor {
            suite: Suite::Classical,
            node_ik: node_ik.public(),
            addrs,
            mix_keys,
            layer,
            ts,
            sig: Vec::new(),
            substrate,
            operator,
        };
        d.sig = node_ik.sign_domain(MIX_DESCRIPTOR_DS, &d.signing_body());
        d
    }

    /// Verify the descriptor's signature under its own `node_ik` (§18.9.9).
    pub fn verify(&self) -> Result<(), IdentityError> {
        if !self.suite.is_supported() {
            return Err(IdentityError::UnsupportedSuite(self.suite.as_u8()));
        }
        verify_domain(&self.node_ik, MIX_DESCRIPTOR_DS, &self.signing_body(), &self.sig)
    }
}

/// The signed, versioned, KT-anchored mix-fleet snapshot for an epoch (spec §4.4.2, §18.5.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MixDirectory {
    pub suite: Suite,                  // key 1
    pub authority: Vec<u8>,            // key 2 — directory-authority identity key (pinned via DNS/KT)
    pub epoch: u64,                    // key 3
    pub version: u64,                  // key 4 — monotonic; reject older-or-equal
    pub mixes: Vec<MixNodeDescriptor>, // key 5 — the fleet, each independently signed (≥ 1)
    pub prev: ContentId,              // key 6 — content address of the previous directory (chain)
    pub ts: TimestampMs,              // key 7
    pub sig: Vec<u8>,                 // key 8 — §18.9.9
}

impl MixDirectory {
    /// Integer-keyed canonical map (§18.5.3). `include_sig=false` omits key 8 for the §18.9.9
    /// signing body.
    fn to_cv(&self, include_sig: bool) -> Cv {
        let mut m = vec![
            (1u64, Cv::U64(self.suite.as_u8() as u64)),
            (2, Cv::Bytes(self.authority.clone())),
            (3, Cv::U64(self.epoch)),
            (4, Cv::U64(self.version)),
            (5, Cv::Array(self.mixes.iter().map(|d| d.to_cv(true)).collect())),
            (6, Cv::Bytes(self.prev.as_bytes().to_vec())),
            (7, Cv::U64(self.ts)),
        ];
        if include_sig {
            m.push((8, Cv::Bytes(self.sig.clone())));
        }
        Cv::Map(m)
    }

    /// The exact wire bytes: §18-canonical integer-keyed CBOR.
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(true))
    }

    /// The §18.9.9 signing body: deterministic CBOR of the directory with `sig` (key 8) omitted.
    pub fn signing_body(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(false))
    }

    /// Decode a directory (§18.5.3), failing closed on any violation (including an empty `mixes`).
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cbor::decode(bytes)?)?;
        let suite = suite_from_cv(f.req(1)?)?;
        let authority = as_bytes(f.req(2)?)?;
        let epoch = as_u64(f.req(3)?)?;
        let version = as_u64(f.req(4)?)?;
        let mixes: Vec<MixNodeDescriptor> = as_array(f.req(5)?)?
            .into_iter()
            .map(|c| MixNodeDescriptor::from_det_cbor(&cbor::encode(&c)))
            .collect::<Result<_, _>>()?;
        if mixes.is_empty() {
            return Err(CborError::TypeMismatch); // [+ MixNodeDescriptor] requires ≥ 1
        }
        let prev = ContentId(as_bytes(f.req(6)?)?);
        let ts = as_u64(f.req(7)?)?;
        let sig = as_bytes(f.req(8)?)?;
        f.deny_unknown()?;
        Ok(MixDirectory { suite, authority, epoch, version, mixes, prev, ts, sig })
    }

    /// Sign a directory with the authority `IK` (§18.9.9); `authority` is set from the signer.
    pub fn issue(
        authority: &IdentityKey,
        epoch: u64,
        version: u64,
        mixes: Vec<MixNodeDescriptor>,
        prev: ContentId,
        ts: TimestampMs,
    ) -> MixDirectory {
        let mut d = MixDirectory {
            suite: Suite::Classical,
            authority: authority.public(),
            epoch,
            version,
            mixes,
            prev,
            ts,
            sig: Vec::new(),
        };
        d.sig = authority.sign_domain(MIX_DIRECTORY_DS, &d.signing_body());
        d
    }

    /// Verify the authority signature (§18.9.9). Does **not** re-verify each descriptor — the
    /// caller MUST (the authority attests membership, not descriptor content).
    ///
    /// Note this is a *signature* check only. It does **not** enforce the §4.4.2 `version`
    /// monotonicity — an attacker can replay an older, validly-signed directory to freeze the
    /// client on a small, possibly-compromised fleet view. Pair this with a
    /// [`MixDirectoryTracker`] to reject a stale/rolled-back directory fail-closed (`0x0311`).
    pub fn verify(&self) -> Result<(), IdentityError> {
        if !self.suite.is_supported() {
            return Err(IdentityError::UnsupportedSuite(self.suite.as_u8()));
        }
        verify_domain(&self.authority, MIX_DIRECTORY_DS, &self.signing_body(), &self.sig)
    }
}

/// A [`MixDirectoryTracker::accept`] failure, each carrying its §21.5 wire error code via
/// [`MixDirectoryError::code`].
///
/// A signature that does not verify under the pinned authority is `ERR_MIX_DIRECTORY_SIG_INVALID`
/// (`0x030B`, §4.4.2 / §18.5.3). A directory whose `version` is older-than-or-equal-to the last
/// accepted from that authority is `ERR_MIX_DIRECTORY_STALE` (`0x0311`, §4.4.2 / §16.3) — a stale,
/// possibly-frozen fleet view an adversary replays to keep the client's anonymity set small (the
/// mixnet analogue of the KT STH-freshness freeze defense `0x0112`).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MixDirectoryError {
    /// The directory is not validly signed by the pinned directory authority (§4.4.2, §18.5.3).
    #[error("mix directory signature invalid (ERR_MIX_DIRECTORY_SIG_INVALID, 0x030B)")]
    SigInvalid,
    /// The directory's `version` is ≤ the last accepted from this authority — a rollback/replay of
    /// a superseded-but-validly-signed directory (freeze attack, §4.4.2, §16.3).
    #[error("mix directory rollback — version ≤ last accepted (ERR_MIX_DIRECTORY_STALE, 0x0311)")]
    Stale,
}

impl MixDirectoryError {
    /// The normative DMTAP wire error code (§21.5).
    pub fn code(&self) -> u16 {
        match self {
            MixDirectoryError::SigInvalid => 0x030B,
            MixDirectoryError::Stale => 0x0311,
        }
    }
}

/// Per-authority mix-directory **anti-rollback** state (spec §4.4.2, §16.3). Retains the highest
/// `MixDirectory.version` accepted from each directory authority (keyed by the authority identity
/// key). [`accept`](MixDirectoryTracker::accept) verifies a directory's authority signature and
/// then rejects any whose `version` is `≤` the last accepted from that authority
/// ([`MixDirectoryError::Stale`], `0x0311`) — so a global active adversary cannot replay a stale,
/// frozen fleet view to shrink the client's diversity/anonymity set (freeze attack).
///
/// This mirrors [`SuiteRatchet`](crate::suite::SuiteRatchet) and
/// [`CapsVersionTracker`](crate::capability::CapsVersionTracker): an **additive, opt-in** helper
/// the caller layers over [`MixDirectory::verify`], not forced into `verify()` (the core holds no
/// state and reads no clock). The mark ratchets **up only** — a rejected rollback never mutates it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MixDirectoryTracker {
    /// authority identity key → highest `version` accepted from that authority.
    seen: std::collections::BTreeMap<Vec<u8>, u64>,
}

impl MixDirectoryTracker {
    /// A tracker with no authorities seen.
    pub fn new() -> Self {
        MixDirectoryTracker { seen: std::collections::BTreeMap::new() }
    }

    /// The highest `version` accepted from `authority`, or `None` if none seen.
    pub fn last_version(&self, authority: &[u8]) -> Option<u64> {
        self.seen.get(authority).copied()
    }

    /// Verify and accept a directory, failing closed on a stale/rolled-back one. The authority
    /// signature is checked first ([`MixDirectoryError::SigInvalid`], `0x030B`); then a `version`
    /// `≤` the last accepted from `dir.authority` is rejected as [`MixDirectoryError::Stale`]
    /// (`0x0311`) **without** mutating state. A strictly-newer directory is accepted and its
    /// `version` becomes the new floor. The first directory from an authority always passes the
    /// freshness gate (there is no prior mark to roll back from).
    pub fn accept(&mut self, dir: &MixDirectory) -> Result<(), MixDirectoryError> {
        dir.verify().map_err(|_| MixDirectoryError::SigInvalid)?;
        if let Some(&last) = self.seen.get(&dir.authority) {
            if dir.version <= last {
                return Err(MixDirectoryError::Stale);
            }
        }
        self.seen.insert(dir.authority.clone(), dir.version);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> IdentityKey {
        IdentityKey::from_seed(&[seed; 32])
    }

    fn descriptor(seed: u8, layer: u8) -> MixNodeDescriptor {
        MixNodeDescriptor::issue(
            &key(seed),
            vec!["/ip4/198.51.100.7/udp/443/quic-v1".into()],
            vec![MixKeyEntry { epoch: 42, mix_key: vec![seed; 32], valid_until: 1_700_000_600_000 }],
            layer,
            1_700_000_000_000,
            None,
            None,
        )
    }

    #[test]
    fn descriptor_signs_verifies_and_round_trips() {
        let d = descriptor(0x11, 0);
        assert!(d.verify().is_ok());
        let bytes = d.det_cbor();
        assert_eq!(bytes[0] & 0xe0, 0xa0, "descriptor is a CBOR map");
        assert_eq!(bytes[1], 0x01, "first key is integer 1 (suite), not a text key");
        let back = MixNodeDescriptor::from_det_cbor(&bytes).unwrap();
        assert_eq!(d, back);
        assert_eq!(bytes, back.det_cbor());
        assert!(back.verify().is_ok());
    }

    #[test]
    fn tampered_descriptor_fails_signature() {
        let mut d = descriptor(0x11, 1);
        d.layer = 2; // signed field changed
        assert_eq!(d.verify(), Err(IdentityError::BadSignature));
    }

    #[test]
    fn layer_out_of_range_fails_closed() {
        let mut d = descriptor(0x11, 0);
        // Hand-encode with layer = 3 (illegal, mix-layer = 0..2).
        let mut m = match cbor::decode(&d.det_cbor()).unwrap() {
            Cv::Map(m) => m,
            _ => unreachable!(),
        };
        for (k, v) in m.iter_mut() {
            if *k == 5 {
                *v = Cv::U64(3);
            }
        }
        d.sig.clear();
        assert!(matches!(
            MixNodeDescriptor::from_det_cbor(&cbor::encode(&Cv::Map(m))),
            Err(CborError::UnknownDiscriminant(3))
        ));
    }

    #[test]
    fn directory_signs_verifies_and_round_trips() {
        let dir = MixDirectory::issue(
            &key(0x22),
            42,
            1,
            vec![descriptor(0x11, 0), descriptor(0x33, 1), descriptor(0x44, 2)],
            ContentId::of(b"genesis-mix-directory"),
            1_700_000_000_000,
        );
        assert!(dir.verify().is_ok());
        let bytes = dir.det_cbor();
        let back = MixDirectory::from_det_cbor(&bytes).unwrap();
        assert_eq!(dir, back);
        assert_eq!(bytes, back.det_cbor());
        // Each embedded descriptor still self-verifies.
        for m in &back.mixes {
            assert!(m.verify().is_ok());
        }
    }

    #[test]
    fn empty_mix_keys_fails_closed() {
        let mut d = descriptor(0x11, 0);
        d.mix_keys.clear();
        d.sig.clear();
        let bytes = cbor::encode(&d.to_cv(true));
        assert_eq!(MixNodeDescriptor::from_det_cbor(&bytes), Err(CborError::TypeMismatch));
    }

    fn directory_at(authority: &IdentityKey, version: u64) -> MixDirectory {
        MixDirectory::issue(
            authority,
            42,
            version,
            vec![descriptor(0x11, 0), descriptor(0x33, 1), descriptor(0x44, 2)],
            ContentId::of(b"genesis-mix-directory"),
            1_700_000_000_000,
        )
    }

    #[test]
    fn directory_tracker_first_accept_marks() {
        let auth = key(0x22);
        let mut tr = MixDirectoryTracker::new();
        let dir = directory_at(&auth, 5);
        assert_eq!(tr.last_version(&auth.public()), None);
        assert_eq!(tr.accept(&dir), Ok(()));
        assert_eq!(tr.last_version(&auth.public()), Some(5));
    }

    #[test]
    fn directory_tracker_higher_version_ratchets() {
        let auth = key(0x22);
        let mut tr = MixDirectoryTracker::new();
        assert_eq!(tr.accept(&directory_at(&auth, 5)), Ok(()));
        assert_eq!(tr.accept(&directory_at(&auth, 6)), Ok(()));
        assert_eq!(tr.last_version(&auth.public()), Some(6));
    }

    #[test]
    fn directory_tracker_older_or_equal_rejected_fail_closed() {
        let auth = key(0x22);
        let mut tr = MixDirectoryTracker::new();
        assert_eq!(tr.accept(&directory_at(&auth, 7)), Ok(()));
        // Equal version — a replay of the current directory — is a rollback.
        let eq = tr.accept(&directory_at(&auth, 7));
        assert_eq!(eq, Err(MixDirectoryError::Stale));
        assert_eq!(eq.unwrap_err().code(), 0x0311);
        // Strictly-older version is a rollback.
        assert_eq!(tr.accept(&directory_at(&auth, 3)), Err(MixDirectoryError::Stale));
        // A rejected rollback never lowers the mark.
        assert_eq!(tr.last_version(&auth.public()), Some(7));
    }

    #[test]
    fn directory_tracker_rejects_bad_signature() {
        let auth = key(0x22);
        let mut tr = MixDirectoryTracker::new();
        let mut dir = directory_at(&auth, 5);
        dir.version = 6; // signed body no longer matches sig
        let err = tr.accept(&dir);
        assert_eq!(err, Err(MixDirectoryError::SigInvalid));
        assert_eq!(err.unwrap_err().code(), 0x030B);
        // A rejected directory never marks the authority.
        assert_eq!(tr.last_version(&auth.public()), None);
    }

    #[test]
    fn directory_tracker_is_per_authority() {
        let a = key(0x22);
        let b = key(0x55);
        let mut tr = MixDirectoryTracker::new();
        assert_eq!(tr.accept(&directory_at(&a, 9)), Ok(()));
        // A different authority is tracked independently; its low version still passes first-contact.
        assert_eq!(tr.accept(&directory_at(&b, 1)), Ok(()));
        assert_eq!(tr.last_version(&a.public()), Some(9));
        assert_eq!(tr.last_version(&b.public()), Some(1));
    }
}

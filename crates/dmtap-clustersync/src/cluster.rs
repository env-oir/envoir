//! Cluster membership, eager replication, and backfill (spec §5.6.1, §5.6.2, §5.6.3).
//!
//! **Membership (§5.6.1).** The cluster is **exactly the identity's non-revoked devices** (§1.2):
//! each authenticated by a `DeviceCert` chaining to the root `IK`; a device removed by a
//! `KeyRotation`/revocation is simply absent from the current `Identity` and therefore not a member.
//! Replication is **mutually authenticated** — a frame or op from a device that is not a current,
//! non-revoked member is refused fail-closed (`ERR_CLUSTER_DEVICE_UNAUTHORIZED`, `0x0410`). Because
//! the sync channel is the devices' encrypted+authenticated MLS cluster group, the frames carry no
//! separate signature; [`Cluster`] performs the `DeviceCert` membership check the receiver owes.
//!
//! **Live replication (§5.6.2).** Immutable, content-addressed objects gossip leaderless: a device
//! announces the ids it holds ([`Replica::announce`]); a peer lacking one pulls the bytes; a peer
//! holding it ignores the offer (dedup by content address). Ordering is irrelevant.
//!
//! **Backfill (§5.6.3).** A joining or long-offline device catches up either by range
//! reconciliation ([`crate::recon`]) or journal replay ([`crate::journal`]), then merges the CRDT
//! metadata state ([`crate::crdt`]). All three converge to the identical state.

use crate::crdt::ClusterState;
use crate::error::SyncError;
use crate::journal::Journal;
use crate::recon::{reconcile, ReconConfig};
use crate::wire::{ClusterSyncFrame, Hash};
use dmtap_core::identity::Identity;
use dmtap_core::ContentId;
use std::collections::{BTreeMap, BTreeSet};

/// The authenticated membership view of an owner's device cluster (§5.6.1), derived from a **pinned,
/// verified `Identity`**. Construction fails closed if the identity does not verify; membership is
/// then the set of device keys whose `DeviceCert` verifies under the identity's `IK` and is present
/// in the current (non-revoked) device list.
#[derive(Debug, Clone)]
pub struct Cluster {
    members: BTreeSet<Vec<u8>>,
}

impl Cluster {
    /// Build the membership view from a pinned `Identity`. The identity is verified (§1.3); then
    /// each `DeviceCert` is checked to (a) verify under its own `IK`, and (b) carry an `IK` that is
    /// one of the identity's suite keys — so only certs genuinely chaining to *this* identity count.
    /// A revoked device, having been dropped from `Identity.devices` in the rotation that removed
    /// it, is simply not in the resulting set.
    ///
    /// Fails closed ([`SyncError::DeviceUnauthorized`]) if the identity itself does not verify — an
    /// unverifiable identity yields no trustworthy membership, so no peer may be authorised.
    pub fn from_identity(identity: &Identity) -> Result<Self, SyncError> {
        identity.verify(None).map_err(|_| SyncError::DeviceUnauthorized)?;
        let iks: BTreeSet<&Vec<u8>> = identity.iks.values().collect();
        let members = identity
            .devices
            .iter()
            .filter(|cert| cert.verify().is_ok() && iks.contains(&cert.ik))
            .map(|cert| cert.device_key.clone())
            .collect();
        Ok(Cluster { members })
    }

    /// Whether `device_key` is a current, non-revoked cluster member (§5.6.1).
    pub fn is_member(&self, device_key: &[u8]) -> bool {
        self.members.contains(device_key)
    }

    /// The number of member devices (replicas).
    pub fn size(&self) -> usize {
        self.members.len()
    }

    /// Authorise a device before exchanging any object or op with it (§5.6.1). A non-member is
    /// refused fail-closed (`ERR_CLUSTER_DEVICE_UNAUTHORIZED`, `0x0410`).
    pub fn authorize(&self, device_key: &[u8]) -> Result<(), SyncError> {
        if self.is_member(device_key) {
            Ok(())
        } else {
            Err(SyncError::DeviceUnauthorized)
        }
    }

    /// Authorise the origin device named by a frame (`0x0410` if it is not a member). A receiver
    /// MUST call this before acting on any [`ClusterSyncFrame`].
    pub fn authorize_frame(&self, frame: &ClusterSyncFrame) -> Result<(), SyncError> {
        self.authorize(&frame.device)
    }
}

/// One device's replica: its content-addressed object store, its CRDT metadata state, and its
/// append-only journal, plus the [`Cluster`] membership view it authenticates peers against. This
/// is the reference engine for §5.6.2 live replication and §5.6.3 backfill; every method that
/// consumes a peer frame authorises the peer's device first (`0x0410`).
#[derive(Debug, Clone)]
pub struct Replica {
    device: Vec<u8>,
    cluster: Cluster,
    objects: BTreeMap<Hash, Vec<u8>>,
    state: ClusterState,
    journal: Journal,
}

impl Replica {
    /// A fresh, empty replica for `device` (which SHOULD itself be a cluster member) against the
    /// membership view `cluster`.
    pub fn new(device: Vec<u8>, cluster: Cluster) -> Self {
        Replica {
            device,
            cluster,
            objects: BTreeMap::new(),
            state: ClusterState::new(),
            journal: Journal::new(),
        }
    }

    /// This replica's device key.
    pub fn device(&self) -> &[u8] {
        &self.device
    }

    /// The CRDT metadata state (read-only).
    pub fn state(&self) -> &ClusterState {
        &self.state
    }

    /// Mutable access to the CRDT state, e.g. to `ingest` a locally-authored op.
    pub fn state_mut(&mut self) -> &mut ClusterState {
        &mut self.state
    }

    /// The append-only journal (read-only).
    pub fn journal(&self) -> &Journal {
        &self.journal
    }

    /// The sorted set of object ids this replica holds.
    pub fn object_ids(&self) -> BTreeSet<Hash> {
        self.objects.keys().cloned().collect()
    }

    /// Whether this replica holds the object with content-address `id`.
    pub fn has_object(&self, id: &Hash) -> bool {
        self.objects.contains_key(id)
    }

    /// Store a locally-created immutable object (§5.6.2): content-address it, insert (dedup), and
    /// record it in the journal. Returns its id.
    pub fn put_object(&mut self, bytes: Vec<u8>) -> Hash {
        let id = ContentId::of(&bytes).0;
        if self.objects.insert(id.clone(), bytes).is_none() {
            self.journal.append(id.clone());
        }
        id
    }

    /// Accept a `(id, bytes)` object pulled from a peer (§5.6.2). The content address is
    /// **re-verified** (a peer cannot substitute bytes under a claimed id) — a mismatch fails closed
    /// as a malformed object. Already-held ids are a no-op (dedup, `STATUS_DUPLICATE_ID`).
    pub fn accept_object(&mut self, id: &Hash, bytes: Vec<u8>) -> Result<(), SyncError> {
        let ok = ContentId(id.clone()).verify(&bytes);
        if !ok {
            return Err(SyncError::Cbor(dmtap_core::cbor::CborError::Malformed));
        }
        if self.objects.insert(id.clone(), bytes).is_none() {
            self.journal.append(id.clone());
        }
        Ok(())
    }

    /// Build a type-1 announce frame offering every id this replica holds (§5.6.2, eager
    /// replication for redundancy nodes).
    pub fn announce(&self) -> ClusterSyncFrame {
        ClusterSyncFrame::announce(self.device.clone(), self.object_ids().into_iter().collect())
    }

    /// Consume a peer's announce (§5.6.2): authorise the peer (`0x0410`), then return a type-3
    /// fetch-request for exactly the announced ids this replica lacks (empty ⇒ nothing to pull).
    pub fn on_announce(&self, frame: &ClusterSyncFrame) -> Result<ClusterSyncFrame, SyncError> {
        self.cluster.authorize_frame(frame)?;
        let want: Vec<Hash> =
            frame.ids.iter().filter(|id| !self.objects.contains_key(*id)).cloned().collect();
        Ok(ClusterSyncFrame::fetch(self.device.clone(), want))
    }

    /// Serve a peer's fetch-request (§5.6.2): authorise the peer (`0x0410`), then return the
    /// `(id, bytes)` pairs for the requested ids this replica holds.
    pub fn serve_fetch(
        &self,
        frame: &ClusterSyncFrame,
    ) -> Result<Vec<(Hash, Vec<u8>)>, SyncError> {
        self.cluster.authorize_frame(frame)?;
        Ok(frame
            .ids
            .iter()
            .filter_map(|id| self.objects.get(id).map(|b| (id.clone(), b.clone())))
            .collect())
    }

    /// Apply a frame's CRDT ops (§5.6.4): authorise the origin (`0x0410`), then validate + apply
    /// each op fail-closed (`0x0413`), recording each in the journal by its op hash. A single
    /// invalid op rejects the whole frame's ops before any is applied (all-or-nothing ingest).
    pub fn apply_ops(&mut self, frame: &ClusterSyncFrame, now_ms: u64) -> Result<(), SyncError> {
        self.cluster.authorize_frame(frame)?;
        // Validate every op first, so a poisoned op cannot leave a half-applied frame.
        for op in &frame.ops {
            crate::crdt::validate_op(op, now_ms)?;
        }
        for op in &frame.ops {
            self.state.apply(op);
            self.journal.append(op.op_hash());
        }
        Ok(())
    }

    /// Merge a peer's CRDT metadata state into this replica's (§5.6.4). A CvRDT join —
    /// commutative, associative, idempotent — so it is always safe regardless of what else has been
    /// applied. Used during backfill to converge mutable metadata alongside the object set.
    pub fn merge_state(&mut self, other: &ClusterState) {
        self.state.merge(other);
    }

    /// **Backfill** this replica against `peer` by range reconciliation (§5.6.3(a)) + CRDT merge
    /// (§5.6.4). Authenticates in both directions (`0x0410`), reconciles the object-id sets with
    /// **minimal exchange**, pulls only the ids this replica lacks (re-verifying each), pushes the
    /// ids the peer lacks, and merges the peer's metadata state. Returns the number of range
    /// comparisons the reconciliation took (its cost). Both replicas converge to parity.
    pub fn backfill_from(&mut self, peer: &mut Replica, cfg: &ReconConfig) -> Result<usize, SyncError> {
        // Mutual authentication: each side is a non-revoked member of the other's cluster view.
        self.cluster.authorize(&peer.device)?;
        peer.cluster.authorize(&self.device)?;

        let out = reconcile(&self.object_ids(), &peer.object_ids(), cfg);
        // Pull the ids the peer holds that we lack.
        for id in &out.local_missing {
            if let Some(bytes) = peer.objects.get(id).cloned() {
                self.accept_object(id, bytes)?;
            }
        }
        // Push the ids we hold that the peer lacks (leaderless — replication is symmetric).
        for id in &out.peer_missing {
            if let Some(bytes) = self.objects.get(id).cloned() {
                peer.accept_object(id, bytes)?;
            }
        }
        // Converge mutable metadata both ways.
        let peer_state = peer.state.clone();
        self.merge_state(&peer_state);
        let self_state = self.state.clone();
        peer.merge_state(&self_state);
        Ok(out.ranges_compared)
    }

    /// **Backfill** this replica by replaying `peer`'s journal from this replica's next-expected
    /// position (§5.6.3(b)): authorise the peer, verify the peer's whole chain fail-closed
    /// (`0x0412`, a fork of the owner's own log halts replay), then pull every referenced object id
    /// this replica lacks. Returns the ids learned. (Journal entries also reference op hashes; those
    /// are applied via [`Replica::apply_ops`] on the same frames — here we backfill the object set.)
    pub fn backfill_via_journal(&mut self, peer: &mut Replica) -> Result<Vec<Hash>, SyncError> {
        self.cluster.authorize(&peer.device)?;
        let refs = peer.journal.replay()?; // verifies the chain (0x0412) before yielding refs
        let mut learned = Vec::new();
        for id in refs {
            if !self.objects.contains_key(&id) {
                if let Some(bytes) = peer.objects.get(&id).cloned() {
                    self.accept_object(&id, bytes)?;
                    learned.push(id);
                }
            }
        }
        Ok(learned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{ClusterOp, Hlc, OP_LWW_SET, OP_SET_ADD};
    use dmtap_core::cbor::Cv;
    use dmtap_core::identity::{DeviceCert, Identity, IdentityKey, KeyPackageBundleRef};

    /// A signed test identity with `n` device certs, plus the owner's `IdentityKey` and the device
    /// public keys. All certs chain to the same `IK`, so all `n` devices are members.
    fn identity_with_devices(n: usize) -> (IdentityKey, Identity, Vec<Vec<u8>>) {
        let ik = IdentityKey::from_seed(&[7u8; 32]);
        let mut certs = Vec::new();
        let mut device_keys = Vec::new();
        for i in 0..n {
            let dk = IdentityKey::from_seed(&[100 + i as u8; 32]);
            let cert = DeviceCert::issue(&ik, dk.public(), format!("device-{i}"), 1_000, None, vec![]);
            device_keys.push(dk.public());
            certs.push(cert);
        }
        let kpref = KeyPackageBundleRef::new("loc", ContentId::of(b"kp"));
        let identity = Identity::create_classical(
            &ik,
            0,
            certs,
            kpref,
            ContentId::of(b"recovery"),
            vec!["alice".into()],
            None,
            1_000,
        );
        (ik, identity, device_keys)
    }

    #[test]
    fn membership_admits_all_certified_devices() {
        let (_ik, identity, dks) = identity_with_devices(3);
        let cluster = Cluster::from_identity(&identity).unwrap();
        assert_eq!(cluster.size(), 3);
        for dk in &dks {
            assert!(cluster.is_member(dk));
            cluster.authorize(dk).expect("a certified device is authorised");
        }
    }

    #[test]
    fn frame_from_non_member_is_refused_0x0410() {
        // SYNC-01: a frame whose origin device is not a non-revoked member of the identity's
        // cluster is refused fail-closed.
        let (_ik, identity, _dks) = identity_with_devices(2);
        let cluster = Cluster::from_identity(&identity).unwrap();
        // A device that was never certified by this identity (a stranger, or a revoked device that
        // an honest Identity no longer lists).
        let stranger = IdentityKey::from_seed(&[200u8; 32]).public();
        assert!(!cluster.is_member(&stranger));
        let frame = ClusterSyncFrame::announce(stranger, vec![vec![0x1e; 33]]);
        let err = cluster.authorize_frame(&frame).unwrap_err();
        assert_eq!(err, SyncError::DeviceUnauthorized);
        assert_eq!(err.code(), 0x0410);
    }

    #[test]
    fn cert_signed_by_a_foreign_ik_is_not_a_member() {
        // A DeviceCert that verifies under some *other* IK (not this identity's) must not be
        // admitted — membership requires chaining to THIS identity. The owner re-signs an identity
        // doc that (maliciously or by confusion) lists a foreign-IK cert; it must still be excluded.
        let owner = IdentityKey::from_seed(&[7u8; 32]);
        let owner_dk = IdentityKey::from_seed(&[100u8; 32]);
        let owner_cert =
            DeviceCert::issue(&owner, owner_dk.public(), "device-0", 1_000, None, vec![]);

        let foreign_ik = IdentityKey::from_seed(&[1u8; 32]);
        let foreign_dk = IdentityKey::from_seed(&[2u8; 32]);
        let foreign_cert =
            DeviceCert::issue(&foreign_ik, foreign_dk.public(), "intruder", 1_000, None, vec![]);

        let identity = Identity::create_classical(
            &owner,
            0,
            vec![owner_cert, foreign_cert],
            KeyPackageBundleRef::new("loc", ContentId::of(b"kp")),
            ContentId::of(b"recovery"),
            vec!["alice".into()],
            None,
            1_000,
        );
        let cluster = Cluster::from_identity(&identity).unwrap();
        // The owner's own device is a member; the foreign-IK cert's subject is not.
        assert!(cluster.is_member(&owner_dk.public()));
        assert!(!cluster.is_member(&foreign_dk.public()), "foreign-IK cert must be excluded");
    }

    #[test]
    fn eager_replication_and_backfill_brings_empty_device_to_parity() {
        let (_ik, identity, dks) = identity_with_devices(2);
        let cluster = Cluster::from_identity(&identity).unwrap();

        // Device 0 is a full always-on box; device 1 is brand new (empty).
        let mut full = Replica::new(dks[0].clone(), cluster.clone());
        let mut fresh = Replica::new(dks[1].clone(), cluster.clone());
        let mut ids = Vec::new();
        for n in 0..200u64 {
            ids.push(full.put_object(format!("object-{n}").into_bytes()));
        }
        // Some CRDT metadata on the full device too.
        let hlc = Hlc { wall: 5_000, counter: 0, device: dks[0].clone() };
        full.state_mut()
            .ingest(
                &ClusterOp {
                    kind: OP_SET_ADD,
                    target: ids[0].iter().map(|b| format!("{b:02x}")).collect::<String>(),
                    field: None,
                    value: None,
                    hlc: hlc.clone(),
                    observed: None,
                },
                10_000,
            )
            .unwrap();
        full.state_mut()
            .ingest(
                &ClusterOp {
                    kind: OP_LWW_SET,
                    target: "inbox/msg".into(),
                    field: Some("read".into()),
                    value: Some(Cv::Bool(true)),
                    hlc,
                    observed: None,
                },
                10_000,
            )
            .unwrap();

        assert_eq!(fresh.object_ids().len(), 0);
        // Reconciliation of a brand-new (empty) device against a full peer necessarily drills the
        // whole tree — range recon is the O(diff·log n) path for *similar* sets; a from-scratch
        // device is the disjoint case (see `journal_backfill_learns_missing_objects` for the linear
        // path). Here we assert the parity outcome, not a sublinear cost.
        let _cost = fresh.backfill_from(&mut full, &ReconConfig::default()).unwrap();

        // The fresh device now holds every object and the same metadata snapshot.
        assert_eq!(fresh.object_ids(), full.object_ids());
        assert_eq!(fresh.state().snapshot(), full.state().snapshot());
    }

    #[test]
    fn journal_backfill_learns_missing_objects() {
        let (_ik, identity, dks) = identity_with_devices(2);
        let cluster = Cluster::from_identity(&identity).unwrap();
        let mut full = Replica::new(dks[0].clone(), cluster.clone());
        for n in 0..10u64 {
            full.put_object(format!("j-{n}").into_bytes());
        }
        let mut fresh = Replica::new(dks[1].clone(), cluster);
        let learned = fresh.backfill_via_journal(&mut full).unwrap();
        assert_eq!(learned.len(), 10);
        assert_eq!(fresh.object_ids(), full.object_ids());
    }

    #[test]
    fn accept_object_rejects_content_address_mismatch() {
        let (_ik, identity, dks) = identity_with_devices(1);
        let cluster = Cluster::from_identity(&identity).unwrap();
        let mut r = Replica::new(dks[0].clone(), cluster);
        let real_id = ContentId::of(b"real").0;
        // Bytes that do not hash to the claimed id ⇒ fail closed, never stored.
        assert!(r.accept_object(&real_id, b"tampered".to_vec()).is_err());
        assert!(!r.has_object(&real_id));
    }
}

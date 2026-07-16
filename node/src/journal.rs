//! Node durability seam — the persistence of the sender-side retry queue (spec §19.3.3, §0.5, §4.7).
//!
//! DMTAP puts durability **entirely** in the sender's outbound queue: the mixnet/relay middle holds
//! nothing (§0.5), so an implementation that loses queued-but-unacked MOTEs when the node process
//! restarts violates the "durability lives entirely in this sender-side queue" invariant (§4.7,
//! §19.3.3 failure table: *"the retry queue MUST be durable across restart"*).
//!
//! This module abstracts that durability behind the [`Journal`] trait — a node checkpoints a
//! [`Snapshot`] of its delivery state after every mutation, and reloads it on restart. Two impls
//! ship:
//! - [`MemoryJournal`] — a shared, cloneable in-memory cell, for fast tests (a node can be dropped
//!   and rebuilt against the same journal in-process, proving the resume path without touching the
//!   filesystem).
//! - [`FileJournal`] — a JSON file at a path, written atomically (temp-file + rename), for a real
//!   node whose durability must survive an actual process restart.
//! - [`NullJournal`] — a no-op, the default when a node is constructed without persistence.
//!
//! ## What is persisted (and what is not)
//! A [`Snapshot`] captures the two delivery-state maps a node must not lose across restart: the
//! **outbound retry queue** (§19.3.3, the normative requirement) and the **dedup/ack set** (§2.6,
//! so a redelivered `id` is still re-acked without reprocessing after a restart). The sealed
//! [`Envelope`] inside each queued entry is stored as its canonical §18 CBOR (`det_cbor`) so it
//! round-trips byte-exactly — a retry re-dispatches the *same* immutable object (same `id`), which
//! is what makes retry idempotent against recipient dedup (§19.3.3 idempotency note).
//!
//! The node's **identity keys** and its **delivered-mail store** are deliberately out of scope
//! here: identity persistence is the §1.2 lifecycle's concern (a restarting node is reconstructed
//! from its persisted identity by the caller), and the mail store is a separate durability surface.
//! A resumed node is rebuilt with its identity + a journal; this seam restores only the in-flight
//! delivery state.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use dmtap_core::mote::Envelope;
use dmtap_core::ContentId;

use crate::deniable::DeniableAdmissionSnapshot;
use crate::outbound::{OutState, OutboundEntry};

/// The durable delivery + anti-rollback/anti-abuse state a node must survive restart with. Beyond
/// the §19.3.3 outbound retry queue and the §2.6 dedup/ack set, this also carries the
/// **security-critical high-water-marks** that would otherwise re-pin on first contact after a
/// restart — weakening the downgrade/rollback defenses across restarts:
/// - the per-contact **suite** high-water-mark ([`SuiteRatchet`](dmtap_core::suite::SuiteRatchet), §1.3, §2.7 step 8);
/// - the per-authority **mix-directory** `(epoch, version)` high-water-mark (§4.4.2, §18.5.3);
/// - the inbound deniable-init **admission** token buckets (audit #4 OPK-depletion defense, §5.2.1).
///
/// Serializable so any [`Journal`] can round-trip it. New fields default-in
/// ([`serde(default)`](https://serde.rs/field-attrs.html#default)) so an older journal (queue + dedup
/// only) still loads — an additive, backward-compatible extension.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Snapshot {
    /// The sender-side retry queue (§20.1 / §19.3.3), one [`PersistedEntry`] per tracked MOTE.
    pub outbound: Vec<PersistedEntry>,
    /// The dedup/ack set (§2.6): `(id, sender-return-path)` pairs, so a MOTE whose `id` we already
    /// hold is re-acked after a restart without being reprocessed.
    pub seen: Vec<(Vec<u8>, Vec<u8>)>,
    /// The per-contact suite high-water-marks (§1.3, §2.7 step 8): one [`PersistedSuiteMark`] per
    /// contact the node has pinned a suite floor for. Restored authoritatively so a post-restart
    /// downgrade below the pinned mark is *still* rejected (never re-pinned on first contact).
    #[serde(default)]
    pub suite_marks: Vec<PersistedSuiteMark>,
    /// Each directory authority's latest accepted [`MixDirectory`](dmtap_core::mixnet::MixDirectory),
    /// stored as its canonical §18.5.3 CBOR. On restore each is re-verified + re-ingested through the
    /// tracker (fail-closed), restoring the monotonic `(epoch, version)` high-water-mark so a
    /// post-restart rollback is *still* rejected (§4.4.2).
    #[serde(default)]
    pub mix_directories: Vec<Vec<u8>>,
    /// The inbound deniable-init admission gate's token buckets (audit #4, §5.2.1), so a restart does
    /// not hand an attacker a fresh, full burst against the responder's one-time-prekey pool. `None`
    /// in a legacy journal ⇒ the node keeps its freshly-seeded gate.
    #[serde(default)]
    pub deniable_admission: Option<DeniableAdmissionSnapshot>,
}

/// A single persisted per-contact suite high-water-mark (spec §1.3, §2.7 step 8). The `suite` byte is
/// validated fail-closed on restore ([`into_mark`](Self::into_mark)) — an unknown suite byte is
/// corruption, refused, never silently defaulted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedSuiteMark {
    /// The contact identity key the mark is keyed on (their `Payload.from`).
    pub contact: Vec<u8>,
    /// The pinned suite byte (the §1.1 suite id) — the highest accepted from this contact.
    pub suite: u8,
}

impl PersistedSuiteMark {
    /// Decode the persisted `(contact, suite)` pair, **failing closed** on an unknown suite byte
    /// (corruption is refused, not defaulted to a weaker suite — that would silently drop the
    /// downgrade floor). Returns the contact key and its validated [`Suite`](dmtap_core::Suite).
    pub fn into_mark(self) -> Result<(Vec<u8>, dmtap_core::Suite), JournalError> {
        let suite = dmtap_core::Suite::from_u8(self.suite)
            .ok_or(JournalError::Corrupt("unknown suite in persisted high-water-mark"))?;
        Ok((self.contact, suite))
    }
}

/// A single outbound queue entry in serializable form. The sealed envelope is stored as its
/// canonical §18 CBOR (`sealed_cbor`) rather than a structural mirror, so it decodes back to the
/// exact same bytes — the property retry idempotency depends on (same `id` across re-dispatch).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedEntry {
    pub id: Vec<u8>,
    pub to: Vec<u8>,
    pub state: u8,
    pub attempts: u32,
    pub deadline: u64,
    pub delivered_late: bool,
    pub sealed_cbor: Option<Vec<u8>>,
}

impl PersistedEntry {
    /// Snapshot a live [`OutboundEntry`].
    pub fn from_entry(e: &OutboundEntry) -> Self {
        PersistedEntry {
            id: e.id.as_bytes().to_vec(),
            to: e.to.clone(),
            state: e.state.as_u8(),
            attempts: e.attempts,
            deadline: e.deadline,
            delivered_late: e.delivered_late,
            sealed_cbor: e.sealed.as_ref().map(|env| env.det_cbor()),
        }
    }

    /// Rebuild a live [`OutboundEntry`], failing closed on a corrupt discriminant or envelope.
    pub fn into_entry(self) -> Result<OutboundEntry, JournalError> {
        let state =
            OutState::from_u8(self.state).ok_or(JournalError::Corrupt("unknown outbound state"))?;
        let sealed = match self.sealed_cbor {
            Some(bytes) => Some(
                Envelope::from_det_cbor(&bytes)
                    .map_err(|_| JournalError::Corrupt("undecodable sealed envelope"))?,
            ),
            None => None,
        };
        Ok(OutboundEntry {
            id: ContentId(self.id),
            to: self.to,
            state,
            sealed,
            attempts: self.attempts,
            deadline: self.deadline,
            delivered_late: self.delivered_late,
        })
    }
}

/// Something went wrong reading or writing the durable journal.
#[derive(Debug)]
pub enum JournalError {
    /// Underlying filesystem I/O failed.
    Io(std::io::Error),
    /// (De)serialization failed — a truncated or non-JSON journal.
    Serde(String),
    /// A structurally-decoded journal held an impossible value (bad state discriminant, undecodable
    /// envelope) — treated as corruption and refused rather than silently dropped.
    Corrupt(&'static str),
}

impl std::fmt::Display for JournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JournalError::Io(e) => write!(f, "journal I/O error: {e}"),
            JournalError::Serde(e) => write!(f, "journal (de)serialization error: {e}"),
            JournalError::Corrupt(what) => write!(f, "corrupt journal: {what}"),
        }
    }
}
impl std::error::Error for JournalError {}

impl From<std::io::Error> for JournalError {
    fn from(e: std::io::Error) -> Self {
        JournalError::Io(e)
    }
}

/// The persistence seam for a node's durable delivery state (spec §19.3.3). A node calls
/// [`save`](Journal::save) after every mutation and [`load`](Journal::load) once on restart.
pub trait Journal {
    /// Durably persist the whole snapshot, replacing any previous one. On return the state is
    /// committed (a real impl fsyncs / renames atomically).
    fn save(&self, snapshot: &Snapshot) -> Result<(), JournalError>;

    /// Load the last-persisted snapshot, or an empty one if nothing was ever persisted (a
    /// first boot). Errors only on genuine corruption/I/O failure — a missing store is not an error.
    fn load(&self) -> Result<Snapshot, JournalError>;
}

/// A no-op journal: persists nothing, always loads empty. The default for a node built without
/// durability (fast in-process tests, ephemeral nodes). A node using this loses its queue on drop —
/// acceptable only when there is nothing to resume.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullJournal;

impl Journal for NullJournal {
    fn save(&self, _snapshot: &Snapshot) -> Result<(), JournalError> {
        Ok(())
    }
    fn load(&self) -> Result<Snapshot, JournalError> {
        Ok(Snapshot::default())
    }
}

/// A shared in-memory journal. Clone it to hold a handle that outlives the node, so a node can be
/// dropped and a fresh one rebuilt against the same journal — the in-process analogue of a restart.
/// Cheap to clone (an `Arc`).
#[derive(Debug, Default, Clone)]
pub struct MemoryJournal {
    inner: Arc<Mutex<Option<Snapshot>>>,
}

impl MemoryJournal {
    pub fn new() -> Self {
        Self::default()
    }

    /// The currently-persisted snapshot (inspection aid for tests).
    pub fn snapshot(&self) -> Option<Snapshot> {
        self.inner.lock().unwrap().clone()
    }
}

impl Journal for MemoryJournal {
    fn save(&self, snapshot: &Snapshot) -> Result<(), JournalError> {
        *self.inner.lock().unwrap() = Some(snapshot.clone());
        Ok(())
    }
    fn load(&self) -> Result<Snapshot, JournalError> {
        Ok(self.inner.lock().unwrap().clone().unwrap_or_default())
    }
}

/// A JSON-file-backed journal at a path — the durable option for a real node whose queue must
/// survive an actual process restart (§19.3.3). Writes are atomic: the snapshot is written to a
/// sibling `*.tmp` file and renamed over the target, so a crash mid-write never leaves a torn
/// journal (the reader sees either the old complete file or the new complete file).
#[derive(Debug, Clone)]
pub struct FileJournal {
    path: PathBuf,
}

impl FileJournal {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        FileJournal { path: path.into() }
    }

    /// The path this journal reads and writes.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Journal for FileJournal {
    fn save(&self, snapshot: &Snapshot) -> Result<(), JournalError> {
        let bytes =
            serde_json::to_vec_pretty(snapshot).map_err(|e| JournalError::Serde(e.to_string()))?;
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, &bytes)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    fn load(&self) -> Result<Snapshot, JournalError> {
        match std::fs::read(&self.path) {
            Ok(bytes) => {
                serde_json::from_slice(&bytes).map_err(|e| JournalError::Serde(e.to_string()))
            }
            // A journal that was never written is a first boot, not an error.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Snapshot::default()),
            Err(e) => Err(JournalError::Io(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::OutEvent;

    fn sample_entry(seed: u8) -> OutboundEntry {
        // A QUEUED→SEALED entry carrying a real sealed envelope, so the CBOR round-trip is exercised.
        use dmtap_core::identity::IdentityKey;
        use dmtap_core::mote::{build_mote, Hpke, Kind, MoteDraft, SealKeypair};

        let sender = IdentityKey::from_seed(&[seed; 32]);
        let eph = IdentityKey::from_seed(&[seed.wrapping_add(1); 32]);
        let recip = IdentityKey::from_seed(&[seed.wrapping_add(2); 32]);
        let recip_seal = SealKeypair::generate();
        let draft = MoteDraft::new(Kind::Mail, 1_700_000_000_000, b"durable body".to_vec());
        let env =
            build_mote(&Hpke, &sender, &eph, &recip.public(), recip_seal.public(), draft).unwrap();
        let id = env.id.clone();
        let mut e = OutboundEntry::enqueue(id, recip.public(), 1_700_000_000_000, None);
        e.apply(OutEvent::SealOk).unwrap();
        e.sealed = Some(env);
        e.apply(OutEvent::DispatchOk).unwrap();
        e.apply(OutEvent::TierUnreachable).unwrap(); // → RETRY, attempts=1
        e
    }

    #[test]
    fn persisted_entry_round_trips_including_sealed_envelope() {
        let original = sample_entry(1);
        let persisted = PersistedEntry::from_entry(&original);
        let restored = persisted.into_entry().unwrap();

        assert_eq!(restored.id, original.id);
        assert_eq!(restored.to, original.to);
        assert_eq!(restored.state, OutState::Retry);
        assert_eq!(restored.attempts, 1);
        assert_eq!(restored.deadline, original.deadline);
        // The sealed envelope survives byte-exactly (same wire bytes ⇒ same content address).
        let a = original.sealed.as_ref().unwrap().det_cbor();
        let b = restored.sealed.as_ref().unwrap().det_cbor();
        assert_eq!(a, b, "sealed envelope round-trips byte-exactly");
    }

    #[test]
    fn memory_journal_saves_and_loads() {
        let j = MemoryJournal::new();
        assert_eq!(j.load().unwrap().outbound.len(), 0, "empty on first load");

        let snap = Snapshot {
            outbound: vec![PersistedEntry::from_entry(&sample_entry(2))],
            seen: vec![(vec![1, 2, 3], vec![4, 5, 6])],
            suite_marks: vec![PersistedSuiteMark { contact: vec![7, 8], suite: 0x02 }],
            ..Snapshot::default()
        };
        j.save(&snap).unwrap();

        let loaded = j.load().unwrap();
        assert_eq!(loaded.outbound.len(), 1);
        assert_eq!(loaded.seen, vec![(vec![1, 2, 3], vec![4, 5, 6])]);
        assert_eq!(loaded.suite_marks.len(), 1);
        assert_eq!(loaded.suite_marks[0].suite, 0x02);
    }

    #[test]
    fn file_journal_persists_across_reopen() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "envoir-journal-{}-{}.json",
            std::process::id(),
            unique()
        ));
        let _ = std::fs::remove_file(&path);

        // Missing file loads empty (first boot), not an error.
        let j = FileJournal::new(&path);
        assert_eq!(j.load().unwrap().outbound.len(), 0);

        let snap = Snapshot {
            outbound: vec![PersistedEntry::from_entry(&sample_entry(3))],
            seen: vec![(vec![9], vec![8, 7])],
            mix_directories: vec![vec![0xDE, 0xAD]],
            ..Snapshot::default()
        };
        j.save(&snap).unwrap();

        // A brand-new handle to the same path sees the persisted state (an actual restart).
        let reopened = FileJournal::new(&path);
        let loaded = reopened.load().unwrap();
        assert_eq!(loaded.outbound.len(), 1);
        assert_eq!(loaded.outbound[0].state, OutState::Retry.as_u8());
        assert_eq!(loaded.seen, vec![(vec![9], vec![8, 7])]);
        assert_eq!(loaded.mix_directories, vec![vec![0xDE, 0xAD]], "new fields round-trip on disk");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn corrupt_state_discriminant_is_refused() {
        let mut pe = PersistedEntry::from_entry(&sample_entry(4));
        pe.state = 200; // no such OutState
        assert!(matches!(pe.into_entry(), Err(JournalError::Corrupt(_))));
    }

    fn unique() -> u128 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    }
}

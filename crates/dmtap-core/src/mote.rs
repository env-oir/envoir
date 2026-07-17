//! The MOTE object — spec §2.
//!
//! A MOTE is a signed, encrypted, content-addressed message object: the atomic unit of DMTAP.
//! Mail, chat, files, group events, and identity announcements are all MOTEs. Three nested
//! layers: outer (mixnet / sealed-sender, §4/§6 — not modeled here), **envelope** (signed,
//! per-recipient, §2.2), and **payload** (E2E ciphertext, §2.4).
//!
//! This module implements the envelope + payload, real Ed25519 signatures, HPKE payload
//! sealing (suite `0x01`), content addressing, and the **ordered recipient validation** of
//! §2.7 — cheap/anonymous checks *before* any decryption (a decryption-DoS defense).
//!
//! ## Reference-implementation notes (where the wire shape is pinned down)
//! - `sender_sig` is a detached signature by an *ephemeral* per-message key (§2.2). The wire
//!   format carries the matching public key explicitly in `Envelope.sender_key` (§2.2 field 12,
//!   CDDL key 12, §18.3.1) so the recipient can verify it in step 3 without decrypting; this
//!   reference exposes it as `Envelope.sender_eph`. The `challenge` proof is bound to that key
//!   (§9.2a) so a stripped proof cannot be replayed under a different ephemeral key.
//! - Payload sealing is abstracted behind [`PayloadSeal`]; [`Hpke`] is the real suite-`0x01`
//!   implementation (RFC 9180 DHKEM(X25519)/HKDF-SHA256/ChaCha20-Poly1305 via the `hpke`
//!   crate). Suite `0x02` (PQ) would supply a different `PayloadSeal`.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, Kem as KemTrait,
    OpModeR, OpModeS, Serializable,
};
use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

use crate::cbor::{self, as_array, as_bytes, as_text, as_u32, as_u64, as_u8, CborError, Cv, Fields};
use crate::id::ContentId;
use crate::identity::{verify_domain, IdentityKey};
use crate::pq::{verify_hybrid_domain, HybridSigningKey};
use crate::suite::{Suite, SuiteRatchet, SuiteRatchetError};
use crate::TimestampMs;

/// Current envelope format version (spec §2.2, `v`).
pub const MOTE_VERSION: u8 = 0;

const HPKE_INFO: &[u8] = b"dmtap-mote-payload-v0";

// Domain-separation tags (§18.9), each an ASCII string terminated by one `0x00` byte. The
// signing preimage is `DS-tag ‖ body`; `sign_domain` concatenates `domain ‖ msg`, so these
// constants carry the trailing NUL and callers pass the §18.9 body as `msg`. Public so
// conformance vectors and independent implementations can reconstruct the exact preimages.
pub const PAYLOAD_SIG_DS: &[u8] = b"DMTAP-v0/payload\x00";
pub const ENVELOPE_SENDER_DS: &[u8] = b"DMTAP-v0/envelope-sender\x00";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MoteError {
    #[error("unknown envelope version {0} (fail closed)")]
    UnknownVersion(u8),
    #[error("suite {0:#04x} is not supported (fail closed)")]
    UnsupportedSuite(u8),
    #[error("content address does not match ciphertext")]
    BadContentAddress,
    #[error("envelope `to` does not resolve to this node")]
    NotForUs,
    #[error("envelope carries a sender signature but no ephemeral key")]
    MissingSenderKey,
    #[error("signature verification failed")]
    BadSignature,
    #[error("payload decryption failed")]
    DecryptFailed,
    #[error("payload sealing failed")]
    SealFailed,
    #[error("malformed key material")]
    BadKey,
    /// A **Referenced**-tier file's `ManifestRef` is missing its REQUIRED `durability`, carries an
    /// unknown `class`, a `cluster-replicated` (class 2) with `replicas < 1`, or a `pinned`
    /// (class 3) with no `retention` — a malformed/underspecified durability contract
    /// (`ERR_FILE_MANIFEST_INVALID` `0x080A`, FAIL_CLOSED_BLOCK, §5.5.2/§18.3.7).
    #[error("file durability contract missing/malformed (ERR_FILE_MANIFEST_INVALID 0x080A)")]
    FileManifestInvalid,
    /// A `pinned(term)` (class 3) contract's `retention` term has elapsed (the host MAY have GC'd
    /// the bytes) — a fetch past expiry (`ERR_FILE_RETENTION_EXPIRED` `0x080B`, §5.5.4/§5.5.2).
    #[error("pinned-file retention term elapsed (ERR_FILE_RETENTION_EXPIRED 0x080B)")]
    FileRetentionExpired,
    /// A **Referenced** file has no reachable holder and no satisfiable durability contract — the
    /// disclosed origin-hold residual realized (whole-file loss, distinct from a single missing
    /// chunk `0x0803`) (`ERR_FILE_UNAVAILABLE` `0x0809`, §5.5.2/§5.5.3/§6.6).
    #[error("referenced file has no reachable holder (ERR_FILE_UNAVAILABLE 0x0809)")]
    FileUnavailable,
    /// A **pushed** Inline/Attached file would exceed the recipient's inbound spool cap for that
    /// sender — a storage-based DoS (spool-fill); refused, never silently accepted or dropped
    /// (`ERR_SPOOL_OVERFLOW` `0x080C`, DENY_POLICY, §5.5.5/§16.4).
    #[error("inbound spool cap exceeded (ERR_SPOOL_OVERFLOW 0x080C)")]
    SpoolOverflow,
    /// An `Attachment`'s declared delivery mechanism does not match its size tier (§5.5.1/§16.4):
    /// an `inline` attachment above the inline cap, a `manifest` reference below it, an attachment
    /// carrying **both** or **neither** of `{inline, manifest}` (§18.3.7 requires exactly one), or
    /// inline bytes whose length disagrees with the declared `size`. Fails closed at construction.
    ///
    /// NOTE: §21 has no dedicated size-tier-violation code; [`MoteError::code`] maps this to the
    /// closest existing `0x080A` (`ERR_FILE_MANIFEST_INVALID`, "malformed delivery contract").
    #[error("attachment size does not match its declared delivery tier (fail closed, §5.5.1)")]
    SizeTierViolation,
    #[error("canonical CBOR decode failed: {0}")]
    BadEncoding(#[from] CborError),
}

impl MoteError {
    /// The normative DMTAP wire error code (§21) when this failure carries one. The file/durability
    /// failures (§21.8 `0x08xx`) each map to their assigned code; structural envelope/crypto
    /// failures (bad signature, decrypt failure, …) have no assigned wire code and return `None`.
    ///
    /// [`MoteError::SizeTierViolation`] has no dedicated §21 code and is mapped to the closest
    /// existing `0x080A` (`ERR_FILE_MANIFEST_INVALID`) — see that variant's note.
    pub fn code(&self) -> Option<u16> {
        match self {
            MoteError::FileUnavailable => Some(0x0809),
            MoteError::FileManifestInvalid => Some(0x080A),
            MoteError::FileRetentionExpired => Some(0x080B),
            MoteError::SpoolOverflow => Some(0x080C),
            MoteError::SizeTierViolation => Some(0x080A),
            _ => None,
        }
    }
}

/// Error type of [`validate_pinned`]: either a base [`validate`] failure ([`MoteError`]) or a
/// per-contact suite **downgrade** rejection ([`SuiteRatchetError`], `ERR_SUITE_DOWNGRADE`, §21.3
/// `0x020F`). Kept as a *separate, additive* type so [`validate`]'s public `Result<_, MoteError>`
/// signature — and every downstream `match` on `MoteError` — is untouched (backward compatible).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ValidateError {
    /// A base recipient-validation failure (steps 1–8, §2.7).
    #[error(transparent)]
    Mote(#[from] MoteError),
    /// The object's asserted suite is below the sender-contact's established high-water-mark — a
    /// suite downgrade (`ERR_SUITE_DOWNGRADE`, §21.3 `0x020F`).
    #[error(transparent)]
    Suite(#[from] SuiteRatchetError),
}

impl ValidateError {
    /// The normative DMTAP wire error code (§21.3) when this failure carries one — currently the
    /// suite downgrade (`0x020F`). Base [`MoteError`] structural failures have no assigned code.
    pub fn code(&self) -> Option<u16> {
        match self {
            ValidateError::Suite(e) => Some(e.code()),
            // Base structural failures have no code (`None`); the file/durability failures
            // (§21.8 `0x08xx`) carry theirs via [`MoteError::code`].
            ValidateError::Mote(e) => e.code(),
        }
    }
}

// --- Message kinds (§2.3) ------------------------------------------------------------------

/// Message kinds (spec §2.3). `mail` defaults to the private tier; `chat` may use fast.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Mail = 0x00,
    Chat = 0x01,
    Reaction = 0x02,
    Edit = 0x03,
    Redact = 0x04,
    FileOffer = 0x05,
    GroupEvent = 0x06,
    Receipt = 0x07,
    Presence = 0x08,
    Identity = 0x09,
    System = 0x0a,
}

impl Kind {
    pub fn from_u8(b: u8) -> Option<Self> {
        use Kind::*;
        Some(match b {
            0x00 => Mail,
            0x01 => Chat,
            0x02 => Reaction,
            0x03 => Edit,
            0x04 => Redact,
            0x05 => FileOffer,
            0x06 => GroupEvent,
            0x07 => Receipt,
            0x08 => Presence,
            0x09 => Identity,
            0x0a => System,
            _ => return None, // reserved/unknown — do not guess
        })
    }
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

impl Serialize for Kind {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u8(self.as_u8())
    }
}
impl<'de> Deserialize<'de> for Kind {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let b = u8::deserialize(d)?;
        Kind::from_u8(b).ok_or_else(|| serde::de::Error::custom(format!("unknown kind 0x{b:02x}")))
    }
}

/// Privacy tier (spec §6.5). Default `Private` (full mixnet).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tier {
    #[default]
    Private,
    Fast,
}

impl Tier {
    /// Privacy **strength rank** — higher means stronger metadata privacy. `Private` (full mixnet +
    /// cover, strong against a global passive adversary, §6.5) outranks `Fast` (direct/few-hop,
    /// content-only). Used to compare tiers by privacy strength; note this is deliberately *not* a
    /// derived `Ord` on the enum, since enum declaration order does not encode strength.
    pub fn privacy_rank(self) -> u8 {
        match self {
            Tier::Private => 1,
            Tier::Fast => 0,
        }
    }
}

/// A [`tier_enforce`] failure (`ERR_PRIVATE_TIER_DOWNGRADE_REFUSED`, §21.5 `0x0310`).
///
/// Disposition per §21.5/§4.4.9: `FAIL_CLOSED_BLOCK` — a message a party required at a given
/// minimum privacy tier MUST NOT be silently demoted to a weaker one (`private → fast`). An
/// adversary DoSing the mixnet can **delay** delivery but MUST NOT be able to strip the tier.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TierEnforcementError {
    /// The offered/incoming tier is below the required minimum — a silent privacy downgrade.
    #[error(
        "offered privacy tier is below the required minimum — silent downgrade refused \
         (ERR_PRIVATE_TIER_DOWNGRADE_REFUSED, §21.5 0x0310)"
    )]
    DowngradeRefused,
}

impl TierEnforcementError {
    /// The normative DMTAP wire error code (§21.5).
    pub fn code(&self) -> u16 {
        match self {
            TierEnforcementError::DowngradeRefused => 0x0310,
        }
    }
}

/// Enforce a **minimum privacy tier** (spec §4.4.9, §6.5): refuse to accept an `offered` tier that
/// is weaker than the `required` floor.
///
/// A message flagged (by sender or recipient policy) to travel at least at `required` strength MUST
/// NOT be silently routed over a weaker tier — that covert `private → fast` demotion is exactly what
/// an adversary DoSing the mixnet tries to force (§4.4.9). An `offered` tier at or above `required`
/// (compared by [`Tier::privacy_rank`]) is accepted and returned; a strictly-weaker one **fails
/// closed** with [`TierEnforcementError::DowngradeRefused`] (`0x0310`). Downgrading is only ever a
/// deliberate, user-surfaced choice, never an automatic reaction — so this helper never downgrades.
pub fn tier_enforce(required: Tier, offered: Tier) -> Result<Tier, TierEnforcementError> {
    if offered.privacy_rank() < required.privacy_rank() {
        return Err(TierEnforcementError::DowngradeRefused);
    }
    Ok(offered)
}

// --- Anti-abuse challenge (§2.2b, §9) ------------------------------------------------------

/// A cold-sender anti-abuse proof carried in the *envelope* so the recipient can evaluate
/// policy **without decrypting** (spec §2.2b/§18.3.3, validated at §2.7 step 6). A tagged choice:
/// key `0` is the variant discriminator (§18.1.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChallengeResponse {
    /// ARC anonymous rate-limited credential (disc 1, §9.3, §18.3.3).
    Arc(ArcToken),
    /// Memory-hard proof-of-work (disc 2, §9.4, §16.5).
    Pow(PowSolution),
    /// Prepaid real-money stamp (disc 3, §9.5).
    Postage(PostageStamp),
    /// Social introduction (disc 4, §9.7).
    Vouch(Vouch),
}

/// ARC presentation (§18.3.3, disc 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArcToken {
    pub issuer: Vec<u8>,
    pub token: Vec<u8>,
    pub origin: Vec<u8>,
    pub nonce: Option<Vec<u8>>,
}

/// Memory-hard PoW solution (§18.3.3, disc 2). `params` = Argon2id `(m_KiB, t_iters, p_lanes)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PowSolution {
    pub algo: String,
    pub params: [u32; 3],
    pub epoch_nonce: Vec<u8>,
    pub solution: Vec<u8>,
    pub difficulty: u8,
}

/// Prepaid postage stamp (§18.3.3, disc 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostageStamp {
    pub issuer: Vec<u8>,
    pub serial: Vec<u8>,
    pub amount: u64,
    pub currency: String,
    pub expiry: TimestampMs,
    pub audience: Option<Vec<u8>>,
    pub sig: Vec<u8>,
}

/// Social vouch (§18.3.3, disc 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vouch {
    pub voucher: Vec<u8>,
    pub subject: Vec<u8>,
    pub recipient: Vec<u8>,
    pub exp: TimestampMs,
    pub sig: Vec<u8>,
}

impl ChallengeResponse {
    /// Integer-keyed canonical form (§18.3.3); key 0 is the variant discriminator.
    pub fn to_cv(&self) -> Cv {
        match self {
            ChallengeResponse::Arc(a) => {
                let mut m = vec![
                    (0u64, Cv::U64(1)),
                    (1, Cv::Bytes(a.issuer.clone())),
                    (2, Cv::Bytes(a.token.clone())),
                    (3, Cv::Bytes(a.origin.clone())),
                ];
                if let Some(n) = &a.nonce {
                    m.push((4, Cv::Bytes(n.clone())));
                }
                Cv::Map(m)
            }
            ChallengeResponse::Pow(p) => Cv::Map(vec![
                (0, Cv::U64(2)),
                (1, Cv::Text(p.algo.clone())),
                (
                    2,
                    Cv::Array(vec![
                        Cv::U64(p.params[0] as u64),
                        Cv::U64(p.params[1] as u64),
                        Cv::U64(p.params[2] as u64),
                    ]),
                ),
                (3, Cv::Bytes(p.epoch_nonce.clone())),
                (4, Cv::Bytes(p.solution.clone())),
                (5, Cv::U64(p.difficulty as u64)),
            ]),
            ChallengeResponse::Postage(s) => {
                let mut m = vec![
                    (0u64, Cv::U64(3)),
                    (1, Cv::Bytes(s.issuer.clone())),
                    (2, Cv::Bytes(s.serial.clone())),
                    (3, Cv::U64(s.amount)),
                    (4, Cv::Text(s.currency.clone())),
                    (5, Cv::U64(s.expiry)),
                ];
                if let Some(a) = &s.audience {
                    m.push((6, Cv::Bytes(a.clone())));
                }
                m.push((7, Cv::Bytes(s.sig.clone())));
                Cv::Map(m)
            }
            ChallengeResponse::Vouch(vch) => Cv::Map(vec![
                (0, Cv::U64(4)),
                (1, Cv::Bytes(vch.voucher.clone())),
                (2, Cv::Bytes(vch.subject.clone())),
                (3, Cv::Bytes(vch.recipient.clone())),
                (4, Cv::U64(vch.exp)),
                (5, Cv::Bytes(vch.sig.clone())),
            ]),
        }
    }

    /// Deterministic CBOR of the challenge (§18.3.3), as fed into the `sender_sig` preimage.
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv())
    }

    fn from_cv(cv: Cv) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cv)?;
        let disc = as_u64(f.req(0)?)?;
        let out = match disc {
            1 => ChallengeResponse::Arc(ArcToken {
                issuer: as_bytes(f.req(1)?)?,
                token: as_bytes(f.req(2)?)?,
                origin: as_bytes(f.req(3)?)?,
                nonce: f.take(4).map(as_bytes).transpose()?,
            }),
            2 => {
                let algo = as_text(f.req(1)?)?;
                let params = as_array(f.req(2)?)?;
                if params.len() != 3 {
                    return Err(CborError::TypeMismatch);
                }
                let mut it = params.into_iter();
                let params = [
                    as_u32(it.next().unwrap())?,
                    as_u32(it.next().unwrap())?,
                    as_u32(it.next().unwrap())?,
                ];
                ChallengeResponse::Pow(PowSolution {
                    algo,
                    params,
                    epoch_nonce: as_bytes(f.req(3)?)?,
                    solution: as_bytes(f.req(4)?)?,
                    difficulty: as_u8(f.req(5)?)?,
                })
            }
            3 => ChallengeResponse::Postage(PostageStamp {
                issuer: as_bytes(f.req(1)?)?,
                serial: as_bytes(f.req(2)?)?,
                amount: as_u64(f.req(3)?)?,
                currency: as_text(f.req(4)?)?,
                expiry: as_u64(f.req(5)?)?,
                audience: f.take(6).map(as_bytes).transpose()?,
                sig: as_bytes(f.req(7)?)?,
            }),
            4 => ChallengeResponse::Vouch(Vouch {
                voucher: as_bytes(f.req(1)?)?,
                subject: as_bytes(f.req(2)?)?,
                recipient: as_bytes(f.req(3)?)?,
                exp: as_u64(f.req(4)?)?,
                sig: as_bytes(f.req(5)?)?,
            }),
            other => return Err(CborError::UnknownDiscriminant(other)),
        };
        f.deny_unknown()?;
        Ok(out)
    }
}

// --- Delivery tag (§2.2a) ------------------------------------------------------------------

/// A routing target (spec §2.2a). On the wire `Envelope.to` is the tag's bytes; this enum is a
/// convenience for constructing them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryTag {
    /// The recipient's identity key (default, simplest).
    Key(Vec<u8>),
    /// An MLS group id (§5).
    Group(Vec<u8>),
    /// A blinded per-contact tag, unlinkable across time (§2.2a).
    Blinded(Vec<u8>),
}

impl DeliveryTag {
    /// The tag's opaque value bytes (recipient key, group id, or blinded tag).
    pub fn value_bytes(&self) -> &[u8] {
        match self {
            DeliveryTag::Key(b) | DeliveryTag::Group(b) | DeliveryTag::Blinded(b) => b,
        }
    }

    /// True iff this is a [`DeliveryTag::Key`] naming exactly `ik` (default-tag resolution, §2.7
    /// step 4). Group/blinded-tag recognition is out of the core's scope (see [`validate`]).
    pub fn resolves_to_key(&self, ik: &[u8]) -> bool {
        matches!(self, DeliveryTag::Key(k) if k.as_slice() == ik)
    }

    /// Integer-keyed canonical form (§18.3.2). Key `0` is the variant discriminator
    /// (`KeyTag`=1, `GroupTag`=2, `BlindedTag`=3); key `1` carries the value.
    pub fn to_cv(&self) -> Cv {
        let (disc, val) = match self {
            DeliveryTag::Key(b) => (1u64, b),
            DeliveryTag::Group(b) => (2, b),
            DeliveryTag::Blinded(b) => (3, b),
        };
        Cv::Map(vec![(0, Cv::U64(disc)), (1, Cv::Bytes(val.clone()))])
    }

    /// Deterministic CBOR of the tag (§18.3.2), as fed into the `sender_sig` preimage (§18.9.1).
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv())
    }

    fn from_cv(cv: Cv) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cv)?;
        let disc = as_u64(f.req(0)?)?;
        let val = as_bytes(f.req(1)?)?;
        f.deny_unknown()?;
        match disc {
            1 => Ok(DeliveryTag::Key(val)),
            2 => Ok(DeliveryTag::Group(val)),
            3 => Ok(DeliveryTag::Blinded(val)),
            other => Err(CborError::UnknownDiscriminant(other)),
        }
    }
}

/// Reference to a single recipient KeyPackage consumed to initiate an MLS session (§18.3.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPackageRef {
    pub reference: ContentId, // key 1 (`ref` in the grammar)
    pub suite: Suite,         // key 2
    pub loc: Option<String>,  // key 3 (optional locator hint)
}

impl KeyPackageRef {
    fn to_cv(&self) -> Cv {
        let mut m = vec![
            (1u64, Cv::Bytes(self.reference.as_bytes().to_vec())),
            (2, Cv::U64(self.suite.as_u8() as u64)),
        ];
        if let Some(l) = &self.loc {
            m.push((3, Cv::Text(l.clone())));
        }
        Cv::Map(m)
    }

    fn from_cv(cv: Cv) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cv)?;
        let reference = ContentId(as_bytes(f.req(1)?)?);
        let suite = suite_from_cv(f.req(2)?)?;
        let loc = f.take(3).map(as_text).transpose()?;
        f.deny_unknown()?;
        Ok(KeyPackageRef { reference, suite, loc })
    }
}

/// Decode a `suite` field (a `u8`), failing closed on any unknown byte (§18.1.4).
fn suite_from_cv(cv: Cv) -> Result<Suite, CborError> {
    let b = as_u8(cv)?;
    Suite::from_u8(b).ok_or(CborError::UnknownSuite(b))
}

/// Derive a blinded delivery tag `BT = HKDF(shared_secret, epoch_day)` (spec §2.2a). The
/// recipient's node recognizes it but it is unlinkable across time to the persistent key.
pub fn blinded_tag(shared_secret: &[u8], epoch_day: u64) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(&epoch_day.to_be_bytes()), shared_secret);
    let mut okm = [0u8; 16];
    hk.expand(b"dmtap-blinded-tag-v0", &mut okm)
        .expect("16 bytes is a valid HKDF-SHA256 output length");
    okm.to_vec()
}

// --- Envelope & payload (§2.2, §2.4) -------------------------------------------------------

/// The signed, per-recipient envelope (spec §2.2, §18.3.1). `id = [0x1e] || BLAKE3-256(ciphertext)`.
/// Encoded as an integer-keyed canonical CBOR map (§18.1.2) — the field/key mapping is in
/// [`Envelope::to_cv`]; serde is deliberately **not** derived (text keys are not the wire form).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub v: u8,                          // key 1  — format version (0)
    pub suite: Suite,                   // key 2  — algorithm suite (§1.1)
    pub id: ContentId,                  // key 3  — content address of `ciphertext` (§2.2)
    pub to: DeliveryTag,                // key 4  — routing target (§18.3.2)
    pub epoch: Option<Vec<u8>>,         // key 5  — MLS epoch / group-context ref, if group (§5)
    pub ts: TimestampMs,                // key 6  — sender timestamp (ms epoch)
    pub kind: Kind,                     // key 7  — message kind (§2.3)
    pub keypkg: Option<KeyPackageRef>,  // key 8  — present iff this initiates an MLS session (§5.3)
    pub challenge: Option<ChallengeResponse>, // key 9 — anti-abuse proof for cold senders (§2.2b)
    pub ciphertext: Vec<u8>,            // key 10 — HPKE-sealed Payload (§2.4)
    /// Key 11 — detached signature by an EPHEMERAL per-message key over the §18.9.1 preimage.
    pub sender_sig: Option<Vec<u8>>,
    /// Key 12 (`sender_key`, §18.3.1) — the ephemeral public key that verifies `sender_sig`.
    pub sender_eph: Option<Vec<u8>>,
}

impl Envelope {
    /// Integer-keyed canonical map (§18.3.1). Absent optionals are omitted (§18.1.1); when
    /// `include_sig` is false, key 11 (`sender_sig`) is dropped — but `sender_sig` is not part
    /// of a whole-object signing preimage (its preimage is the §18.9.1 concatenation), so this
    /// full form (with key 11 present when set) is the wire encoding.
    fn to_cv(&self) -> Cv {
        let mut m = vec![
            (1u64, Cv::U64(self.v as u64)),
            (2, Cv::U64(self.suite.as_u8() as u64)),
            (3, Cv::Bytes(self.id.as_bytes().to_vec())),
            (4, self.to.to_cv()),
        ];
        if let Some(e) = &self.epoch {
            m.push((5, Cv::Bytes(e.clone())));
        }
        m.push((6, Cv::U64(self.ts)));
        m.push((7, Cv::U64(self.kind.as_u8() as u64)));
        if let Some(k) = &self.keypkg {
            m.push((8, k.to_cv()));
        }
        if let Some(c) = &self.challenge {
            m.push((9, c.to_cv()));
        }
        m.push((10, Cv::Bytes(self.ciphertext.clone())));
        if let Some(s) = &self.sender_sig {
            m.push((11, Cv::Bytes(s.clone())));
        }
        if let Some(k) = &self.sender_eph {
            m.push((12, Cv::Bytes(k.clone())));
        }
        Cv::Map(m)
    }

    /// The exact wire bytes of this envelope: §18-canonical integer-keyed CBOR.
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv())
    }

    /// The §18.9.1 `sender_sig` preimage **body** (the [`ENVELOPE_SENDER_DS`] tag is prepended by
    /// `sign_domain`): `id ‖ det_cbor(to) ‖ u64be(ts) ‖ u8(kind) ‖ challenge_enc`. Exposed for
    /// conformance vectors and independent verifiers.
    pub fn sender_sig_body(&self) -> Vec<u8> {
        sender_authed_bytes(self)
    }

    /// Decode an envelope from its canonical CBOR (§18.3.1), failing closed on any violation.
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cbor::decode(bytes)?)?;
        let v = as_u8(f.req(1)?)?;
        let suite = suite_from_cv(f.req(2)?)?;
        let id = ContentId(as_bytes(f.req(3)?)?);
        let to = DeliveryTag::from_cv(f.req(4)?)?;
        let epoch = f.take(5).map(as_bytes).transpose()?;
        let ts = as_u64(f.req(6)?)?;
        let kind = Kind::from_u8(as_u8(f.req(7)?)?).ok_or(CborError::UnknownDiscriminant(0))?;
        let keypkg = f.take(8).map(KeyPackageRef::from_cv).transpose()?;
        let challenge = f.take(9).map(ChallengeResponse::from_cv).transpose()?;
        let ciphertext = as_bytes(f.req(10)?)?;
        let sender_sig = f.take(11).map(as_bytes).transpose()?;
        let sender_eph = f.take(12).map(as_bytes).transpose()?;
        f.deny_unknown()?;
        Ok(Envelope {
            v,
            suite,
            id,
            to,
            epoch,
            ts,
            kind,
            keypkg,
            challenge,
            ciphertext,
            sender_sig,
            sender_eph,
        })
    }
}

/// The end-to-end-encrypted payload (spec §2.4, §18.3.5), sealed into `Envelope.ciphertext`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    pub from: Vec<u8>,           // key 1 — sender IK (sealed sender)
    pub sig: Vec<u8>,            // key 2 — IK/device sig over the payload hash (§18.9.2)
    pub headers: Headers,        // key 3
    pub body: Vec<u8>,           // key 4 — Body (encoded as a CBOR byte string, §18.3.6)
    pub refs: Vec<ContentId>,    // key 5 — threading refs
    pub attach: Vec<Attachment>, // key 6
    pub expires: Option<TimestampMs>, // key 7
}

impl Payload {
    /// Integer-keyed canonical map (§18.3.5). `include_sig=false` omits key 2 for the signing
    /// preimage body of §18.9.2. `refs` (key 5) and `attach` (key 6) are always present (MAY be
    /// empty arrays). `Body` is emitted as a CBOR byte string (the `bytes` branch of §18.3.6).
    fn to_cv(&self, include_sig: bool) -> Cv {
        let mut m = vec![(1u64, Cv::Bytes(self.from.clone()))];
        if include_sig {
            m.push((2, Cv::Bytes(self.sig.clone())));
        }
        m.push((3, self.headers.to_cv()));
        m.push((4, Cv::Bytes(self.body.clone())));
        m.push((
            5,
            Cv::Array(self.refs.iter().map(|r| Cv::Bytes(r.as_bytes().to_vec())).collect()),
        ));
        m.push((6, Cv::Array(self.attach.iter().map(Attachment::to_cv).collect())));
        if let Some(e) = self.expires {
            m.push((7, Cv::U64(e)));
        }
        Cv::Map(m)
    }

    /// The exact wire bytes of this payload: §18-canonical integer-keyed CBOR.
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(true))
    }

    /// The §18.9.2 signing body: deterministic CBOR of the payload with `sig` (key 2) omitted.
    fn signing_body(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(false))
    }

    /// The §18.9.2 payload hash `BLAKE3-256(det_cbor(Payload ∖ {sig}))`, over which `sig` is
    /// signed under the [`PAYLOAD_SIG_DS`] domain. Exposed for conformance vectors.
    pub fn signing_hash(&self) -> [u8; 32] {
        *blake3::hash(&self.signing_body()).as_bytes()
    }

    /// Decode a payload from its canonical CBOR (§18.3.5), failing closed on any violation.
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cbor::decode(bytes)?)?;
        let from = as_bytes(f.req(1)?)?;
        let sig = as_bytes(f.req(2)?)?;
        let headers = Headers::from_cv(f.req(3)?)?;
        let body = as_bytes(f.req(4)?)?;
        let refs = as_array(f.req(5)?)?
            .into_iter()
            .map(|c| as_bytes(c).map(ContentId))
            .collect::<Result<_, _>>()?;
        let attach = as_array(f.req(6)?)?
            .into_iter()
            .map(Attachment::from_cv)
            .collect::<Result<_, _>>()?;
        let expires = f.take(7).map(as_u64).transpose()?;
        f.deny_unknown()?;
        Ok(Payload { from, sig, headers, body, refs, attach, expires })
    }
}

/// Message headers (spec §2.4, §18.3.6). All fields optional except `cc` (key 4, MAY be empty).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Headers {
    pub thread: Option<Vec<u8>>, // key 1
    pub subject: Option<String>, // key 2 — mail only
    pub mime: Option<String>,    // key 3
    pub cc: Vec<Vec<u8>>,        // key 4 — additional recipient keys
}

impl Headers {
    pub(crate) fn to_cv(&self) -> Cv {
        let mut m: Vec<(u64, Cv)> = Vec::new();
        if let Some(t) = &self.thread {
            m.push((1, Cv::Bytes(t.clone())));
        }
        if let Some(s) = &self.subject {
            m.push((2, Cv::Text(s.clone())));
        }
        if let Some(mm) = &self.mime {
            m.push((3, Cv::Text(mm.clone())));
        }
        m.push((4, Cv::Array(self.cc.iter().map(|k| Cv::Bytes(k.clone())).collect())));
        Cv::Map(m)
    }

    pub(crate) fn from_cv(cv: Cv) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cv)?;
        let thread = f.take(1).map(as_bytes).transpose()?;
        let subject = f.take(2).map(as_text).transpose()?;
        let mime = f.take(3).map(as_text).transpose()?;
        let cc = as_array(f.req(4)?)?
            .into_iter()
            .map(as_bytes)
            .collect::<Result<_, _>>()?;
        f.deny_unknown()?;
        Ok(Headers { thread, subject, mime, cc })
    }
}

/// An attachment (spec §2.5, §18.3.7). Small → inline; large → content-addressed manifest (§5.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    pub name: String,                 // key 1
    pub mime: String,                 // key 2
    pub size: u64,                    // key 3
    pub inline: Option<Vec<u8>>,      // key 4 — mutually exclusive with `manifest`
    pub manifest: Option<ManifestRef>, // key 5 — mutually exclusive with `inline`
    /// Key 6 — per-file content key. It lives HERE, inside the sealed MOTE — never inside the
    /// swarm-distributed `Manifest` object (§5.5/§18.3.8): a manifest is a content-addressed
    /// blob any holder may serve, so an embedded key would leak the whole file.
    pub key: Vec<u8>,
}

impl Attachment {
    pub(crate) fn to_cv(&self) -> Cv {
        let mut m = vec![
            (1u64, Cv::Text(self.name.clone())),
            (2, Cv::Text(self.mime.clone())),
            (3, Cv::U64(self.size)),
        ];
        if let Some(i) = &self.inline {
            m.push((4, Cv::Bytes(i.clone())));
        }
        if let Some(mr) = &self.manifest {
            m.push((5, mr.to_cv()));
        }
        m.push((6, Cv::Bytes(self.key.clone())));
        Cv::Map(m)
    }

    pub(crate) fn from_cv(cv: Cv) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cv)?;
        let name = as_text(f.req(1)?)?;
        let mime = as_text(f.req(2)?)?;
        let size = as_u64(f.req(3)?)?;
        let inline = f.take(4).map(as_bytes).transpose()?;
        let manifest = f.take(5).map(ManifestRef::from_cv).transpose()?;
        let key = as_bytes(f.req(6)?)?;
        f.deny_unknown()?;
        Ok(Attachment { name, mime, size, inline, manifest, key })
    }

    /// Fail-closed enforcement that this attachment's declared delivery mechanism matches its size
    /// tier (spec §5.5.1, §16.4). Enforced at MOTE construction (see [`build_mote`]) and available
    /// to a validating receiver:
    ///
    /// - Exactly one of `{inline, manifest}` MUST be present (§18.3.7) — both/neither is malformed.
    /// - An **inline** attachment rides inside the sealed MOTE, so its `size` MUST be within the
    ///   inline cap ([`DeliveryTier::Inline`], ≤ 64 KiB) and its `inline` bytes' length MUST equal
    ///   the declared `size` (no size lying). An oversize inline is [`MoteError::SizeTierViolation`].
    /// - A **manifest** reference is for the Attached/Referenced tiers (> inline cap); an
    ///   undersized one (belongs inline) is [`MoteError::SizeTierViolation`]. A **Referenced**
    ///   (> 25 MiB) reference MUST additionally carry a valid `durability`
    ///   ([`ManifestRef::validate_durability`], [`MoteError::FileManifestInvalid`]).
    pub fn check_delivery_tier(&self) -> Result<(), MoteError> {
        let tier = DeliveryTier::classify(self.size);
        match (&self.inline, &self.manifest) {
            (Some(bytes), None) => {
                if tier != DeliveryTier::Inline {
                    return Err(MoteError::SizeTierViolation); // oversize for the inline tier
                }
                if bytes.len() as u64 != self.size {
                    return Err(MoteError::SizeTierViolation); // inline bytes vs declared size
                }
                Ok(())
            }
            (None, Some(mref)) => {
                if tier == DeliveryTier::Inline {
                    return Err(MoteError::SizeTierViolation); // undersize; belongs inline
                }
                // Attached (push) or Referenced (pull) — the latter MUST carry durability.
                mref.validate_durability()
            }
            // §18.3.7: exactly one of {inline, manifest} MUST be present.
            (Some(_), Some(_)) | (None, None) => Err(MoteError::SizeTierViolation),
        }
    }
}

/// Reference to a file's manifest (spec §2.5, §18.3.7). `chunks` here is a *count* (u32).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestRef {
    pub id: ContentId, // key 1 — BLAKE3 Merkle-DAG root (§18.9.5)
    pub size: u64,     // key 2
    pub chunks: u32,   // key 3 — NUMBER of chunks
    /// Key 4 — the delivery/retention **durability contract** for THIS delivery (§5.5.2). It rides
    /// in the `ManifestRef` **inside the sealed, signed MOTE** — NOT in the content-addressed
    /// [`Manifest`] (§18.3.8) — so re-pinning/upgrading durability never changes the file's content
    /// address, and a holder cannot tamper with it (it is covered by `Payload.sig`, §18.9.2).
    ///
    /// **MUST** be present with a valid, known `class` for the **Referenced** tier (> 25 MiB);
    /// Inline/Attached files are durable by construction (delivery / push) and MAY omit it
    /// ([`ManifestRef::validate_durability`], `ERR_FILE_MANIFEST_INVALID` `0x080A`).
    pub durability: Option<Durability>,
}

impl ManifestRef {
    fn to_cv(&self) -> Cv {
        let mut m = vec![
            (1u64, Cv::Bytes(self.id.as_bytes().to_vec())),
            (2, Cv::U64(self.size)),
            (3, Cv::U64(self.chunks as u64)),
        ];
        // Key 4 is optional and omitted when absent (§18.1.1) — so a `ManifestRef` without a
        // durability contract encodes byte-for-byte as before (wire-compatible, suites 0x01/0x02).
        if let Some(d) = &self.durability {
            m.push((4, d.to_cv()));
        }
        Cv::Map(m)
    }

    fn from_cv(cv: Cv) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cv)?;
        let id = ContentId(as_bytes(f.req(1)?)?);
        let size = as_u64(f.req(2)?)?;
        let chunks = as_u32(f.req(3)?)?;
        let durability = f.take(4).map(Durability::from_cv).transpose()?;
        f.deny_unknown()?;
        Ok(ManifestRef { id, size, chunks, durability })
    }

    /// Fail-closed durability validation of this reference against its size tier (§5.5.2, §18.3.7).
    ///
    /// A **Referenced** file (> 25 MiB, [`DeliveryTier::Referenced`]) **MUST** carry a `durability`
    /// with a **known** `class` (and the per-class `replicas`/`retention` invariants) — a missing or
    /// malformed contract is [`MoteError::FileManifestInvalid`] (`0x080A`), fail closed. Inline and
    /// Attached files MAY omit the descriptor; if one is nonetheless present it must still be
    /// well-formed. Closes DMTAP-FILE-06.
    pub fn validate_durability(&self) -> Result<(), MoteError> {
        match (&self.durability, DeliveryTier::classify(self.size)) {
            (None, DeliveryTier::Referenced) => Err(MoteError::FileManifestInvalid),
            (Some(d), _) => d.validate(),
            (None, _) => Ok(()),
        }
    }
}

/// The swarm-distributed file manifest (spec §5.5, §18.3.8). Here `chunks` is the *ordered list
/// of chunk hashes* (⚠ distinct from `ManifestRef.chunks`, a count — §18.11 item 4). Key `5` is
/// **forbidden**: the content key MUST NOT appear in a Manifest (§18.3.8); a Manifest carrying
/// key 5 is rejected on decode (`ERR_MANIFEST_KEY_PRESENT`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub id: ContentId,          // key 1 — Merkle root / content address
    pub size: u64,              // key 2 — total plaintext size
    pub chunk_sz: u32,          // key 3 — fixed chunk size
    pub chunks: Vec<ContentId>, // key 4 — ordered chunk hashes (≥ 1)
    pub suite: Suite,           // key 6 — chunk AEAD + hash suite
}

impl Manifest {
    fn to_cv(&self) -> Cv {
        Cv::Map(vec![
            (1, Cv::Bytes(self.id.as_bytes().to_vec())),
            (2, Cv::U64(self.size)),
            (3, Cv::U64(self.chunk_sz as u64)),
            (
                4,
                Cv::Array(self.chunks.iter().map(|c| Cv::Bytes(c.as_bytes().to_vec())).collect()),
            ),
            (6, Cv::U64(self.suite.as_u8() as u64)),
        ])
    }

    /// The exact wire bytes of this manifest: §18-canonical integer-keyed CBOR.
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv())
    }

    /// The §18.9.5 Merkle-DAG root over the **ordered** chunk hashes (RFC 6962-style binary tree
    /// with domain-separated leaf/node prefixes), returned as a content address
    /// `0x1e ‖ MTH(chunks)`. This is the value `Manifest.id` (and `ManifestRef.id`) MUST equal.
    /// Panics on an empty chunk list (a manifest MUST carry ≥ 1 chunk, §18.3.8).
    pub fn merkle_root(&self) -> ContentId {
        let leaves: Vec<[u8; 32]> = self
            .chunks
            .iter()
            .map(|c| c.as_bytes().to_vec())
            .map(|h| *blake3::hash(&[&[0x00u8], h.as_slice()].concat()).as_bytes())
            .collect();
        let root = merkle_tree_head(&leaves);
        let mut v = Vec::with_capacity(33);
        v.push(crate::id::MH_BLAKE3_256);
        v.extend_from_slice(&root);
        ContentId(v)
    }

    /// Decode a manifest (§18.3.8), rejecting a present key `5` as `ERR_MANIFEST_KEY_PRESENT`.
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cbor::decode(bytes)?)?;
        // The content key MUST NOT appear here (§18.3.8) — reject before anything else so a
        // leaky manifest is detected, never silently honored.
        if f.has(5) {
            return Err(CborError::ManifestKeyPresent);
        }
        let id = ContentId(as_bytes(f.req(1)?)?);
        let size = as_u64(f.req(2)?)?;
        let chunk_sz = as_u32(f.req(3)?)?;
        let chunks = as_array(f.req(4)?)?
            .into_iter()
            .map(|c| as_bytes(c).map(ContentId))
            .collect::<Result<_, _>>()?;
        let suite = suite_from_cv(f.req(6)?)?;
        f.deny_unknown()?;
        Ok(Manifest { id, size, chunk_sz, chunks, suite })
    }
}

/// RFC 6962-style Merkle Tree Head over already-hashed leaves (§18.9.5). `leaves[i]` is the
/// leaf digest `leaf(h_i) = BLAKE3-256(0x00 ‖ h_i)`; internal nodes are
/// `node(l, r) = BLAKE3-256(0x01 ‖ l ‖ r)`. The non-power-of-two split takes `k` = the largest
/// power of two strictly less than `n` (no padding). Requires `n ≥ 1`.
fn merkle_tree_head(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => panic!("merkle root requires at least one leaf (§18.3.8)"),
        1 => leaves[0],
        n => {
            let mut k = 1usize;
            while k << 1 < n {
                k <<= 1;
            }
            let left = merkle_tree_head(&leaves[..k]);
            let right = merkle_tree_head(&leaves[k..]);
            let mut buf = Vec::with_capacity(1 + 64);
            buf.push(0x01);
            buf.extend_from_slice(&left);
            buf.extend_from_slice(&right);
            *blake3::hash(&buf).as_bytes()
        }
    }
}

/// File-handling tier by size (spec §2.5 / §16.4). The three-tier model is normative; the
/// numeric thresholds are v0 parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileTier {
    /// ≤ 64 KiB — inlined in `Attachment.inline`, rides the message (§2.5).
    Inline,
    /// > inline, ≤ 4 MiB — manifest in MOTE, chunks via the mixnet (full privacy).
    Normal,
    /// > 4 MiB — manifest in MOTE, chunks via the fast/onion bulk path (weaker privacy).
    Large,
}

/// Classify a file by size into its handling tier (spec §16.4 v0 thresholds).
pub fn file_tier(size: u64) -> FileTier {
    const INLINE_MAX: u64 = 64 * 1024;
    const NORMAL_MAX: u64 = 4 * 1024 * 1024;
    if size <= INLINE_MAX {
        FileTier::Inline
    } else if size <= NORMAL_MAX {
        FileTier::Normal
    } else {
        FileTier::Large
    }
}

// --- Delivery tiers & durability contract (§5.5.1, §5.5.2, §16.4) ---------------------------

/// Inline **delivery**-tier cap (§5.5.1, §16.4): ≤ 64 KiB rides *inside* the sealed MOTE
/// (`Attachment.inline`, durable-by-delivery). Deliberately the top Sphinx bucket rung (§16.3) —
/// a larger inline cap would push the MOTE above the top bucket and off the `private` mixnet.
pub const INLINE_TIER_MAX: u64 = 64 * 1024;

/// Attached **delivery**-tier cap (§5.5.1, §16.4): > 64 KiB and ≤ 25 MiB is content-addressed +
/// chunked and **pushed with the message** into the recipient's store (a durable recipient copy
/// that survives the sender dropping). Above this the file is Referenced (pull-on-demand).
pub const ATTACHED_TIER_MAX: u64 = 25 * 1024 * 1024;

/// The **delivery tier** of a file (spec §5.5.1) — the *durability* axis (inline / push / pull).
///
/// This is **orthogonal** to [`FileTier`] (the §16.4 *privacy* sub-tier: mixnet ≤ 4 MiB vs. bulk
/// > 4 MiB). A 25 MiB **Attached** file is *pushed* (durable) *and* transits the weaker bulk path:
/// push-vs-pull governs durability, mixnet-vs-bulk governs metadata privacy (§5.5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryTier {
    /// ≤ 64 KiB — bytes ride inside the sealed MOTE (`Attachment.inline`); durable-by-delivery.
    Inline,
    /// > 64 KiB, ≤ 25 MiB — chunks pushed with the message into the recipient's store; a durable
    /// recipient copy. MAY carry a `durability` descriptor but is durable by construction.
    Attached,
    /// > 25 MiB — `ManifestRef` + key travel in the MOTE; chunks pulled on demand from a holder.
    /// Best-effort by default: it **MUST** carry a [`Durability`] contract (§5.5.2).
    Referenced,
}

impl DeliveryTier {
    /// Classify a plaintext file size into its delivery tier (spec §5.5.1, §16.4 thresholds).
    pub fn classify(size: u64) -> DeliveryTier {
        if size <= INLINE_TIER_MAX {
            DeliveryTier::Inline
        } else if size <= ATTACHED_TIER_MAX {
            DeliveryTier::Attached
        } else {
            DeliveryTier::Referenced
        }
    }
}

/// Durability **class** of a Referenced file (spec §5.5.2, §18.3.7) — who serves the bytes and
/// what guarantee they carry. A decoded value outside `0..=3` is preserved as [`Unknown`] so it
/// fails closed at [`Durability::validate`] (`ERR_FILE_MANIFEST_INVALID`) rather than at CBOR
/// decode — the spec assigns unknown-class its own file-level code, not a generic malformed decode.
///
/// [`Unknown`]: DurabilityClass::Unknown
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurabilityClass {
    /// (0) Served best-effort by the owner's origin node + swarm; MAY become permanently
    /// unavailable if the origin drops before the recipient fetches (`ERR_FILE_UNAVAILABLE`,
    /// §6.6 item 10 — the honest default residual).
    OriginHold,
    /// (1) The recipient pinned a copy; durable at the recipient (survives origin drop).
    RecipientPinned,
    /// (2) A box-cluster (§5.6, §14) holds N replicas (`replicas`, MUST be ≥ 1); tolerates loss of
    /// up to N−1 holders, repaired from any survivor.
    ClusterReplicated,
    /// (3) A paid relay / pinning host holds it for a `retention` term; durable until it elapses,
    /// after which the host MAY GC (`ERR_FILE_RETENTION_EXPIRED`).
    Pinned,
    /// Any other on-the-wire value — always invalid (`ERR_FILE_MANIFEST_INVALID`, §5.5.2).
    Unknown(u8),
}

impl DurabilityClass {
    /// Total decode: `0..=3` map to the known classes; any other byte is [`Unknown`] (never a
    /// decode failure — the invalidity is surfaced fail-closed at [`Durability::validate`]).
    ///
    /// [`Unknown`]: DurabilityClass::Unknown
    pub fn from_u8(b: u8) -> DurabilityClass {
        match b {
            0 => DurabilityClass::OriginHold,
            1 => DurabilityClass::RecipientPinned,
            2 => DurabilityClass::ClusterReplicated,
            3 => DurabilityClass::Pinned,
            other => DurabilityClass::Unknown(other),
        }
    }

    /// The wire byte for this class (round-trips [`DurabilityClass::from_u8`]).
    pub fn as_u8(self) -> u8 {
        match self {
            DurabilityClass::OriginHold => 0,
            DurabilityClass::RecipientPinned => 1,
            DurabilityClass::ClusterReplicated => 2,
            DurabilityClass::Pinned => 3,
            DurabilityClass::Unknown(b) => b,
        }
    }
}

/// The delivery/retention **durability contract** carried in a [`ManifestRef`] (spec §5.5.2,
/// §18.3.7, CDDL `Durability`). Encoded as an integer-keyed canonical CBOR map:
/// `{1 => class, ?2 => retention, ?3 => replicas, ?4 => holder_hint}`.
///
/// It lives inside the **sealed, signed** MOTE (covered by `Payload.sig`, §18.9.2), so it is
/// per-delivery and tamper-proof, and is **not** part of the immutable content-addressed
/// [`Manifest`] — re-pinning/upgrading durability never changes the file's content address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Durability {
    /// Key 1 — durability class (§5.5.2).
    pub class: DurabilityClass,
    /// Key 2 — retention term as Unix seconds; **MUST** be present iff `class = Pinned`; absent ⇒
    /// indefinite. After it elapses the host MAY GC (`ERR_FILE_RETENTION_EXPIRED`).
    pub retention: Option<u64>,
    /// Key 3 — replica count N; **MUST** be present and ≥ 1 iff `class = ClusterReplicated`.
    pub replicas: Option<u32>,
    /// Key 4 — advisory pull-locator hint. **NOT authoritative**: a fetcher MUST still
    /// content-verify every chunk (§18.9.5) regardless of the hint (§5.5.2).
    pub holder_hint: Option<String>,
}

impl Durability {
    /// A best-effort origin-hold contract (the honest default residual, §6.6 item 10).
    pub fn origin_hold() -> Self {
        Durability { class: DurabilityClass::OriginHold, retention: None, replicas: None, holder_hint: None }
    }

    /// A recipient-pinned contract (durable at the recipient).
    pub fn recipient_pinned() -> Self {
        Durability { class: DurabilityClass::RecipientPinned, retention: None, replicas: None, holder_hint: None }
    }

    /// A cluster-replicated contract holding `replicas` copies (§5.5.2; `replicas` MUST be ≥ 1).
    pub fn cluster_replicated(replicas: u32) -> Self {
        Durability {
            class: DurabilityClass::ClusterReplicated,
            retention: None,
            replicas: Some(replicas),
            holder_hint: None,
        }
    }

    /// A pinned(term) contract durable until `retention` (Unix seconds) elapses (§5.5.2/§5.5.4).
    pub fn pinned(retention: u64) -> Self {
        Durability {
            class: DurabilityClass::Pinned,
            retention: Some(retention),
            replicas: None,
            holder_hint: None,
        }
    }

    /// Integer-keyed canonical map (§18.3.7). Absent optionals are omitted (§18.1.1).
    fn to_cv(&self) -> Cv {
        let mut m = vec![(1u64, Cv::U64(self.class.as_u8() as u64))];
        if let Some(r) = self.retention {
            m.push((2, Cv::U64(r)));
        }
        if let Some(n) = self.replicas {
            m.push((3, Cv::U64(n as u64)));
        }
        if let Some(h) = &self.holder_hint {
            m.push((4, Cv::Text(h.clone())));
        }
        Cv::Map(m)
    }

    /// The exact wire bytes of this descriptor: §18-canonical integer-keyed CBOR.
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv())
    }

    fn from_cv(cv: Cv) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cv)?;
        let class = DurabilityClass::from_u8(as_u8(f.req(1)?)?);
        let retention = f.take(2).map(as_u64).transpose()?;
        let replicas = f.take(3).map(as_u32).transpose()?;
        let holder_hint = f.take(4).map(as_text).transpose()?;
        f.deny_unknown()?;
        Ok(Durability { class, retention, replicas, holder_hint })
    }

    /// Decode a durability descriptor from its canonical CBOR (§18.3.7), failing closed on any
    /// structural violation. An unknown *class value* is preserved (not a decode error) so it fails
    /// at [`Durability::validate`] with the file-level `0x080A`.
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        Self::from_cv(cbor::decode(bytes)?)
    }

    /// Fail-closed validation of the contract's internal invariants (§5.5.2, §18.3.7):
    /// an unknown `class`, a `ClusterReplicated` with `replicas` absent or `< 1`, or a `Pinned`
    /// with no `retention` is [`MoteError::FileManifestInvalid`] (`0x080A`). Closes DMTAP-FILE-06.
    pub fn validate(&self) -> Result<(), MoteError> {
        match self.class {
            DurabilityClass::Unknown(_) => Err(MoteError::FileManifestInvalid),
            DurabilityClass::ClusterReplicated => match self.replicas {
                Some(n) if n >= 1 => Ok(()),
                _ => Err(MoteError::FileManifestInvalid),
            },
            DurabilityClass::Pinned => match self.retention {
                Some(_) => Ok(()),
                None => Err(MoteError::FileManifestInvalid),
            },
            DurabilityClass::OriginHold | DurabilityClass::RecipientPinned => Ok(()),
        }
    }

    /// Fail-closed retention check for a `Pinned(term)` contract (spec §5.5.4, §5.5.2): a fetch at
    /// `now_unix_secs` **at or past** the `retention` term is [`MoteError::FileRetentionExpired`]
    /// (`0x080B`) — the host MAY have GC'd the bytes; renew/re-pin before expiry. Non-`Pinned`
    /// classes, and a `Pinned` with no term (indefinite), never expire here. Deterministic — the
    /// caller supplies `now` (no wall clock, §16.1). Closes DMTAP-FILE-08.
    pub fn check_retention(&self, now_unix_secs: u64) -> Result<(), MoteError> {
        if let (DurabilityClass::Pinned, Some(term)) = (self.class, self.retention) {
            if now_unix_secs >= term {
                return Err(MoteError::FileRetentionExpired);
            }
        }
        Ok(())
    }
}

/// Fail-closed whole-file availability check for a **Referenced** fetch (spec §5.5.2, §5.5.3,
/// §6.6): if no holder is reachable and no durability contract can be satisfied, the fetch fails
/// [`MoteError::FileUnavailable`] (`0x0809`) — the disclosed origin-hold residual realized (the
/// origin dropped before the recipient fetched), distinct from a single missing chunk (`0x0803`).
/// Closes DMTAP-FILE-09. `any_holder_reachable` is the caller's swarm/origin reachability verdict.
pub fn check_file_available(any_holder_reachable: bool) -> Result<(), MoteError> {
    if any_holder_reachable {
        Ok(())
    } else {
        Err(MoteError::FileUnavailable)
    }
}

/// The content address of a **ciphertext** file chunk (spec §5.5, §18.9.5): `0x1e ‖ BLAKE3-256(
/// AEAD(key, plaintext_chunk))`. Content addressing is computed over the *encrypted* bytes, never
/// the plaintext — this is the value stored in `Manifest.chunks`, and it is what kills the
/// convergent-encryption / CAS-confirmation **dedup-confirmation leak**: the same plaintext under
/// two different per-file keys yields two different chunk ids (and thus two different `Manifest.id`
/// Merkle roots), so a holder cannot confirm "you have file X" by hash. Feed the AEAD **ciphertext**
/// chunk here; feeding plaintext would reintroduce the leak.
pub fn chunk_content_id(ciphertext_chunk: &[u8]) -> ContentId {
    ContentId::of(ciphertext_chunk)
}

/// A caller-owned, fail-closed **inbound spool cap** for *pushed* Inline/Attached files from a
/// given sender (spec §5.5.5, §16.4). Because Attached files are *pushed* into the recipient's
/// store, a sender can try to fill a victim's spool (a storage-based DoS); a push that would carry
/// the recorded `used` bytes over `cap` is refused [`MoteError::SpoolOverflow`] (`0x080C`), never
/// silently accepted or dropped. Deterministic and caller-owned (no wall clock, §16.1); scope one
/// per (recipient, sender) and persist across pushes. Closes DMTAP-FILE-07.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundSpool {
    used: u64,
    cap: u64,
}

impl InboundSpool {
    /// A spool with the given per-sender aggregate `cap` (bytes) and no bytes used yet.
    pub fn new(cap: u64) -> Self {
        InboundSpool { used: 0, cap }
    }

    /// Bytes currently recorded as used against the cap.
    pub fn used(&self) -> u64 {
        self.used
    }

    /// The aggregate cap (bytes) this sender may fill.
    pub fn cap(&self) -> u64 {
        self.cap
    }

    /// Bytes still admissible before the cap (saturating at 0).
    pub fn remaining(&self) -> u64 {
        self.cap.saturating_sub(self.used)
    }

    /// Fail-closed check-and-record for an incoming pushed file of `incoming` bytes. On success the
    /// bytes are recorded against the cap and `Ok(())` is returned; a push that would exceed the cap
    /// (or overflow the running total) is [`MoteError::SpoolOverflow`] (`0x080C`, DENY_POLICY) and
    /// the recorded total is left **unchanged** (a rejected push admits nothing).
    pub fn admit(&mut self, incoming: u64) -> Result<(), MoteError> {
        match self.used.checked_add(incoming) {
            Some(total) if total <= self.cap => {
                self.used = total;
                Ok(())
            }
            _ => Err(MoteError::SpoolOverflow),
        }
    }
}

/// Pure, stateless spool-cap admission (spec §5.5.5): whether recording `incoming` more bytes on
/// top of `used` stays within `cap`. `Ok(())` to admit, [`MoteError::SpoolOverflow`] (`0x080C`) to
/// refuse fail-closed. Mirrors [`InboundSpool::admit`] without owning state.
pub fn spool_admit(used: u64, incoming: u64, cap: u64) -> Result<(), MoteError> {
    match used.checked_add(incoming) {
        Some(total) if total <= cap => Ok(()),
        _ => Err(MoteError::SpoolOverflow),
    }
}

// --- Payload sealing abstraction (§2.4) ----------------------------------------------------

/// Abstraction over payload sealing so the suite can be swapped (classical HPKE now, PQ later).
pub trait PayloadSeal {
    /// Seal `plaintext` to `recipient_pub`, authenticating `aad`.
    fn seal(&self, recipient_pub: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, MoteError>;
    /// Open a sealed payload with `recipient_secret`, checking `aad`.
    fn open(&self, recipient_secret: &[u8], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, MoteError>;
}

/// The suite-`0x01` sealer: HPKE base-mode, DHKEM(X25519)/HKDF-SHA256/ChaCha20-Poly1305
/// (RFC 9180). Wire format of the sealed blob: `[u16 enc_len][encapped_key][ciphertext]`.
pub struct Hpke;

type HKem = X25519HkdfSha256;

impl PayloadSeal for Hpke {
    fn seal(&self, recipient_pub: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, MoteError> {
        let pk = <HKem as KemTrait>::PublicKey::from_bytes(recipient_pub).map_err(|_| MoteError::BadKey)?;
        let (enc, ct) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, HKem, _>(
            &OpModeS::Base,
            &pk,
            HPKE_INFO,
            plaintext,
            aad,
            &mut OsRng,
        )
        .map_err(|_| MoteError::SealFailed)?;
        let enc_bytes = enc.to_bytes();
        let enc_slice = enc_bytes.as_slice();
        let mut out = Vec::with_capacity(2 + enc_slice.len() + ct.len());
        out.extend_from_slice(&(enc_slice.len() as u16).to_be_bytes());
        out.extend_from_slice(enc_slice);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    fn open(&self, recipient_secret: &[u8], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, MoteError> {
        if sealed.len() < 2 {
            return Err(MoteError::DecryptFailed);
        }
        let enc_len = u16::from_be_bytes([sealed[0], sealed[1]]) as usize;
        if sealed.len() < 2 + enc_len {
            return Err(MoteError::DecryptFailed);
        }
        let enc = &sealed[2..2 + enc_len];
        let ct = &sealed[2 + enc_len..];
        let sk = <HKem as KemTrait>::PrivateKey::from_bytes(recipient_secret).map_err(|_| MoteError::BadKey)?;
        let encapped = <HKem as KemTrait>::EncappedKey::from_bytes(enc).map_err(|_| MoteError::DecryptFailed)?;
        hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, HKem>(
            &OpModeR::Base,
            &sk,
            &encapped,
            HPKE_INFO,
            ct,
            aad,
        )
        .map_err(|_| MoteError::DecryptFailed)
    }
}

/// An X25519 static keypair used for HPKE payload sealing (the recipient's KEM key). Distinct
/// from the Ed25519 identity key; in the full protocol this is advertised via KeyPackages (§5.3).
pub struct SealKeypair {
    secret: [u8; 32],
    public: [u8; 32],
}

impl SealKeypair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = XPublicKey::from(&secret);
        SealKeypair { secret: secret.to_bytes(), public: public.to_bytes() }
    }
    pub fn public(&self) -> &[u8; 32] {
        &self.public
    }
    pub fn secret(&self) -> &[u8; 32] {
        &self.secret
    }
}

// --- Building & validating -----------------------------------------------------------------

/// Everything a sender supplies to build a MOTE (content + routing intent); `from`/`sig`/`id`
/// are computed by [`build_mote`].
pub struct MoteDraft {
    pub kind: Kind,
    pub ts: TimestampMs,
    pub headers: Headers,
    pub body: Vec<u8>,
    pub refs: Vec<ContentId>,
    pub attach: Vec<Attachment>,
    pub expires: Option<TimestampMs>,
    pub epoch: Option<Vec<u8>>,
    pub keypkg: Option<KeyPackageRef>,
    pub challenge: Option<ChallengeResponse>,
}

impl MoteDraft {
    /// A minimal draft: just a kind, timestamp, and body.
    pub fn new(kind: Kind, ts: TimestampMs, body: Vec<u8>) -> Self {
        MoteDraft {
            kind,
            ts,
            headers: Headers::default(),
            body,
            refs: vec![],
            attach: vec![],
            expires: None,
            epoch: None,
            keypkg: None,
            challenge: None,
        }
    }
}

/// AEAD additional-authenticated-data binding the ciphertext to its envelope header (suite,
/// kind, ts, to). `id` is excluded because it is *derived from* the ciphertext. `to_cbor` is the
/// deterministic CBOR of the [`DeliveryTag`] (§18.3.2), so the whole tag is bound.
fn aad_bytes(suite: Suite, kind: Kind, ts: TimestampMs, to_cbor: &[u8]) -> Vec<u8> {
    let mut a = Vec::with_capacity(2 + 8 + to_cbor.len());
    a.push(suite.as_u8());
    a.push(kind.as_u8());
    a.extend_from_slice(&ts.to_be_bytes());
    a.extend_from_slice(to_cbor);
    a
}

/// The §18.9.1 `sender_sig` preimage **body** (the DS-tag is prepended by `sign_domain`):
/// `id_bytes ‖ det_cbor(to) ‖ u64be(ts) ‖ u8(kind) ‖ challenge_enc`, where `challenge_enc` is
/// `det_cbor(challenge)` when present, else the single byte `0xf6` (CBOR null — the only place a
/// `null` appears in a preimage, §18.1.1).
fn sender_authed_bytes(env: &Envelope) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(env.id.as_bytes()); // field 3: raw hash bytes (no CBOR head)
    m.extend_from_slice(&env.to.det_cbor()); // field 4: deterministic CBOR of the DeliveryTag
    m.extend_from_slice(&env.ts.to_be_bytes()); // field 6: u64 big-endian, 8 bytes
    m.push(env.kind.as_u8()); // field 7: 1 byte
    match &env.challenge {
        Some(c) => m.extend_from_slice(&c.det_cbor()), // field 9: det_cbor(ChallengeResponse)
        None => m.push(0xf6),                          // absent ⇒ CBOR null
    }
    m
}

/// Canonical payload hash for signing (§18.9.2): `BLAKE3-256(det_cbor(Payload ∖ {sig}))`.
fn payload_hash(payload: &Payload) -> [u8; 32] {
    *blake3::hash(&payload.signing_body()).as_bytes()
}

/// Verify a detached signature under the object's `suite`, mapping any failure to the existing
/// [`MoteError::BadSignature`] (fail closed). Suite `0x01` uses the classical Ed25519
/// [`verify_domain`]; suite `0x02` uses the hybrid [`verify_hybrid_domain`], which requires **both**
/// the Ed25519 and the ML-DSA-65 components to verify (AND-composition, §1.3). A `0x02` object whose
/// PQ half is missing/stripped/tampered is rejected here — the underlying hybrid check raises
/// `ERR_HYBRID_SUITE_INCOMPLETE` (`0x0210`, exposed via [`crate::pq::HybridError`]), never accepted
/// on the classical half. Suite `0x01`'s path is byte-for-byte the prior behavior.
fn verify_sig_for_suite(
    suite: Suite,
    pk: &[u8],
    domain: &[u8],
    msg: &[u8],
    sig: &[u8],
) -> Result<(), MoteError> {
    match suite {
        Suite::Classical => verify_domain(pk, domain, msg, sig).map_err(|_| MoteError::BadSignature),
        Suite::PqHybrid => {
            verify_hybrid_domain(pk, domain, msg, sig).map_err(|_| MoteError::BadSignature)
        }
    }
}

/// Build a MOTE (spec §2.2, §2.4): construct + sign the payload, HPKE-seal it, content-address
/// the ciphertext, and sign the envelope with an ephemeral per-message key.
///
/// - `sender_ik` signs `Payload.sig` (the identity-authenticating signature, hidden inside the
///   sealed payload — sealed sender).
/// - `ephemeral` is a fresh per-message key producing the unlinkable envelope `sender_sig`.
/// - `recipient_ik` is the routing target (`to`, default `DeliveryTag::Key`).
/// - `recipient_seal_pub` is the recipient's X25519 KEM key the payload is sealed to.
pub fn build_mote(
    sealer: &impl PayloadSeal,
    sender_ik: &IdentityKey,
    ephemeral: &IdentityKey,
    recipient_ik: &[u8],
    recipient_seal_pub: &[u8],
    draft: MoteDraft,
) -> Result<Envelope, MoteError> {
    let suite = Suite::Classical;
    let to = DeliveryTag::Key(recipient_ik.to_vec());
    let to_cbor = to.det_cbor();

    // 0. Enforce the §5.5.1 delivery-size tiers fail-closed at construction: each attachment's
    //    declared mechanism (inline vs. manifest) must match its size tier, and a Referenced
    //    (> 25 MiB) reference must carry a valid durability contract (§5.5.2).
    for att in &draft.attach {
        att.check_delivery_tier()?;
    }

    // 1. Build and sign the payload (identity signature lives inside the ciphertext).
    let mut payload = Payload {
        from: sender_ik.public(),
        sig: Vec::new(),
        headers: draft.headers,
        body: draft.body,
        refs: draft.refs,
        attach: draft.attach,
        expires: draft.expires,
    };
    let ph = payload_hash(&payload);
    payload.sig = sender_ik.sign_domain(PAYLOAD_SIG_DS, &ph);

    // 2. Serialize (canonical §18 CBOR) + HPKE-seal the payload, binding it via AAD.
    let pt = payload.det_cbor();
    let aad = aad_bytes(suite, draft.kind, draft.ts, &to_cbor);
    let ciphertext = sealer.seal(recipient_seal_pub, &aad, &pt)?;

    // 3. Content-address the ciphertext.
    let id = ContentId::of(&ciphertext);

    // 4. Assemble the envelope, then sign (id‖to‖ts‖kind‖challenge) with the ephemeral key.
    let mut env = Envelope {
        v: MOTE_VERSION,
        suite,
        id,
        to,
        epoch: draft.epoch,
        ts: draft.ts,
        kind: draft.kind,
        keypkg: draft.keypkg,
        challenge: draft.challenge,
        ciphertext,
        sender_sig: None,
        sender_eph: Some(ephemeral.public()),
    };
    let authed = sender_authed_bytes(&env);
    env.sender_sig = Some(ephemeral.sign_domain(ENVELOPE_SENDER_DS, &authed));
    Ok(env)
}

/// Build a **suite-`0x02` (PQ hybrid)** MOTE — the post-quantum analogue of [`build_mote`].
///
/// Identical shape to [`build_mote`], but every asymmetric primitive is the hybrid:
/// - `sealer` MUST be a [`crate::pq::HybridSeal`]; `recipient_seal_pub` is the recipient's 1216-byte
///   **X-Wing** encapsulation key ([`crate::pq::HybridKemKeypair::public`]). Confidentiality holds
///   if either the X25519 or the ML-KEM-768 share is unbroken (§1.3).
/// - `sender_hybrid` signs `Payload.sig` with **both** Ed25519 and ML-DSA-65 (concatenated,
///   §18.1.6); `Payload.from` is the 1984-byte hybrid public key.
/// - `ephemeral_hybrid` is a fresh per-message hybrid key producing the unlinkable envelope
///   `sender_sig`, likewise AND-composed.
///
/// The resulting `Envelope.suite` is `0x02`; it round-trips through [`validate`] when the recipient
/// passes the matching [`crate::pq::HybridSeal`]. Both signatures must verify at receipt — a
/// stripped PQ half is rejected fail-closed (§1.3, `0x0210`).
pub fn build_mote_hybrid(
    sealer: &impl PayloadSeal,
    sender_hybrid: &HybridSigningKey,
    ephemeral_hybrid: &HybridSigningKey,
    recipient_ik: &[u8],
    recipient_seal_pub: &[u8],
    draft: MoteDraft,
) -> Result<Envelope, MoteError> {
    let suite = Suite::PqHybrid;
    let to = DeliveryTag::Key(recipient_ik.to_vec());
    let to_cbor = to.det_cbor();

    // 0. Enforce the §5.5.1 delivery-size tiers fail-closed at construction (see [`build_mote`]).
    for att in &draft.attach {
        att.check_delivery_tier()?;
    }

    // 1. Build and hybrid-sign the payload (identity signature lives inside the ciphertext).
    let mut payload = Payload {
        from: sender_hybrid.public(),
        sig: Vec::new(),
        headers: draft.headers,
        body: draft.body,
        refs: draft.refs,
        attach: draft.attach,
        expires: draft.expires,
    };
    let ph = payload_hash(&payload);
    payload.sig = sender_hybrid.sign_domain(PAYLOAD_SIG_DS, &ph);

    // 2. Serialize (canonical §18 CBOR) + X-Wing-seal the payload, binding it via AAD.
    let pt = payload.det_cbor();
    let aad = aad_bytes(suite, draft.kind, draft.ts, &to_cbor);
    let ciphertext = sealer.seal(recipient_seal_pub, &aad, &pt)?;

    // 3. Content-address the ciphertext.
    let id = ContentId::of(&ciphertext);

    // 4. Assemble the envelope, then hybrid-sign (id‖to‖ts‖kind‖challenge) with the ephemeral key.
    let mut env = Envelope {
        v: MOTE_VERSION,
        suite,
        id,
        to,
        epoch: draft.epoch,
        ts: draft.ts,
        kind: draft.kind,
        keypkg: draft.keypkg,
        challenge: draft.challenge,
        ciphertext,
        sender_sig: None,
        sender_eph: Some(ephemeral_hybrid.public()),
    };
    let authed = sender_authed_bytes(&env);
    env.sender_sig = Some(ephemeral_hybrid.sign_domain(ENVELOPE_SENDER_DS, &authed));
    Ok(env)
}

/// Recipient-side context for [`validate`].
pub struct RecipientCtx<'a> {
    /// This node's identity key bytes, for resolving `to` (§2.7 step 4). Default delivery tags
    /// equal the recipient key; blinded-tag recognition (§2.2a) is out of scope for the core.
    pub our_ik: &'a [u8],
    /// The X25519 secret the payload was sealed to.
    pub seal_secret: &'a [u8],
    /// Sender classification (§2.7 step 5): is `to`/pinning state a **known contact** (fast
    /// path, may skip the abuse gate) or a cold sender (must present a challenge)?
    pub sender_is_known: bool,
}

/// Disposition of a validated MOTE (spec §2.7a).
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Decrypted and authenticated — deliver to the inbox.
    Accepted(Box<Payload>),
    /// A cold sender with an absent/below-threshold challenge — hold in the requests area,
    /// never the inbox, never silently dropped (§2.7a).
    Deferred,
}

/// Ordered recipient validation (spec §2.7): **cheap and anonymous checks first**, so a flood
/// of cold junk is rejected before any expensive asymmetric decryption.
///
/// Returns `Err` for anything that must be **discarded silently** (invalid/forged — §2.7a) and
/// `Ok(Outcome::Deferred)` for a well-formed cold MOTE lacking sufficient proof (requests area).
///
/// Reference limits: issuer-trust evaluation of the `challenge` (ARC/PoW/postage grammar, §9)
/// is not implemented — a *present* challenge is treated as meeting threshold; an *absent* one
/// from a cold sender defers.
///
/// This entry point does **not** enforce the per-contact suite high-water-mark (§2.7 step 8,
/// §10.7.1): use [`validate_pinned`] with a [`SuiteRatchet`] to reject on-the-wire suite
/// downgrades against an established contact. Suite *support* (step 1) is still enforced here.
pub fn validate(
    sealer: &impl PayloadSeal,
    env: &Envelope,
    ctx: &RecipientCtx,
) -> Result<Outcome, MoteError> {
    // 1. Reject unknown v / unsupported suite (fail closed).
    if env.v != MOTE_VERSION {
        return Err(MoteError::UnknownVersion(env.v));
    }
    if !env.suite.mote_supported() {
        return Err(MoteError::UnsupportedSuite(env.suite.as_u8()));
    }

    // 2. Verify id matches the content address of ciphertext (cheap; no decryption).
    if !env.id.verify(&env.ciphertext) {
        return Err(MoteError::BadContentAddress);
    }

    // 3. Verify sender_sig over the §18.9.1 preimage under the ephemeral key (cheap).
    if let Some(sig) = &env.sender_sig {
        let eph = env.sender_eph.as_ref().ok_or(MoteError::MissingSenderKey)?;
        let authed = sender_authed_bytes(env);
        verify_sig_for_suite(env.suite, eph, ENVELOPE_SENDER_DS, &authed, sig)?;
    }

    // 4. Resolve `to` to this node (default KeyTag == our identity key, §2.7 step 4).
    if !env.to.resolves_to_key(ctx.our_ik) {
        return Err(MoteError::NotForUs);
    }

    // 5/6. Classify sender; cold senders must clear the anti-abuse gate BEFORE decryption.
    if !ctx.sender_is_known {
        match &env.challenge {
            None => return Ok(Outcome::Deferred), // §2.7a: absent proof → requests area
            Some(_) => { /* present → treated as meeting threshold (see reference limits) */ }
        }
    }

    // 7. Decrypt the payload (only now, after the anonymous gate).
    let aad = aad_bytes(env.suite, env.kind, env.ts, &env.to.det_cbor());
    let pt = sealer.open(ctx.seal_secret, &aad, &env.ciphertext)?;
    let payload = Payload::from_det_cbor(&pt)?;

    // 8. Verify Payload.sig under Payload.from — the authenticated sender identity.
    let ph = payload_hash(&payload);
    verify_sig_for_suite(env.suite, &payload.from, PAYLOAD_SIG_DS, &ph, &payload.sig)?;

    // 9. (Caller applies expires/refs/kind semantics + the step-8 suite pin — see
    //     `validate_pinned` — then stores and acks.)
    Ok(Outcome::Accepted(Box::new(payload)))
}

/// [`validate`] **plus** the §2.7 step 8 / §10.7.1 **suite high-water-mark ratchet**: reject an
/// inbound object whose asserted `Envelope.suite` is *below* the authenticated sender contact's
/// established high-water-mark (a suite downgrade), and otherwise ratchet that mark **up**.
///
/// The ratchet is keyed on the sender's **authenticated identity** (`Payload.from`, verified at
/// [`validate`] step 8) — never the unlinkable per-message `sender_eph`, which carries no pinning
/// authority. The downgrade check therefore runs only *after* the object has fully passed
/// [`validate`] (decrypted + identity-signature-verified), so it composes with every existing
/// check with no regression. `Envelope.suite` is itself authenticated — it is bound into the
/// payload AEAD ([`aad_bytes`]) — so a decrypting object genuinely uses the suite it asserts.
///
/// - **First contact** with a peer establishes the floor at its suite.
/// - An **equal/higher** suite is accepted and ratchets the mark up ([`SuiteRatchet::accept`]).
/// - A **lower** suite is rejected fail-closed with [`ValidateError::Suite`]
///   ([`SuiteRatchetError::SuiteDowngrade`], §21.3 `0x020F`); the mark is left untouched (never
///   ratchets down).
///
/// A `Deferred` outcome (cold sender, no challenge) carries no authenticated identity and does not
/// touch the ratchet. Passing `None` for `ratchet` is exactly [`validate`] (no per-contact
/// pinning). The ratchet is a caller-owned, deterministic store (no wall clock, §16.1); persist it
/// across calls to retain a peer's high-water-mark.
pub fn validate_pinned(
    sealer: &impl PayloadSeal,
    env: &Envelope,
    ctx: &RecipientCtx,
    ratchet: Option<&mut SuiteRatchet>,
) -> Result<Outcome, ValidateError> {
    let outcome = validate(sealer, env, ctx)?;
    // Step 8 suite pin: only an accepted (authenticated) object has a `Payload.from` to key on.
    if let (Outcome::Accepted(payload), Some(ratchet)) = (&outcome, ratchet) {
        ratchet.accept(&payload.from, env.suite)?;
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityKey;

    fn round(kind: Kind) -> (Envelope, IdentityKey, SealKeypair) {
        let sender = IdentityKey::generate();
        let eph = IdentityKey::generate();
        let recipient = IdentityKey::generate();
        let seal = SealKeypair::generate();
        let mut draft = MoteDraft::new(kind, 1_700_000_000_000, b"hello dmtap".to_vec());
        draft.headers.subject = Some("hi".into());
        let env =
            build_mote(&Hpke, &sender, &eph, &recipient.public(), seal.public(), draft).unwrap();
        (env, recipient, seal)
    }

    #[test]
    fn envelope_cbor_round_trip() {
        let (env, _r, _s) = round(Kind::Mail);
        let buf = env.det_cbor();
        // First byte MUST be a CBOR map head, and the first key MUST be integer 1 (not a text key).
        assert_eq!(buf[0] & 0xe0, 0xa0, "top-level object is a CBOR map");
        let back = Envelope::from_det_cbor(&buf).unwrap();
        assert_eq!(env, back, "envelope must survive a canonical CBOR round-trip byte-for-byte");
        assert_eq!(env.det_cbor(), back.det_cbor(), "re-encode is byte-identical");
    }

    #[test]
    fn envelope_is_integer_keyed_not_text_keyed() {
        let (env, _r, _s) = round(Kind::Mail);
        let buf = env.det_cbor();
        // map head, then key 1 encoded as the single byte 0x01 (a small unsigned integer),
        // then value = version 0 (0x00). A text-keyed encoding would start with a 0x6x string head.
        assert_eq!(buf[1], 0x01, "first map key is integer 1 (v), not a text key");
        assert_eq!(buf[2], 0x00, "v = 0");
    }

    #[test]
    fn full_seal_validate_round_trip() {
        let (env, recipient, seal) = round(Kind::Mail);
        let ctx = RecipientCtx {
            our_ik: &recipient.public(),
            seal_secret: seal.secret(),
            sender_is_known: true,
        };
        match validate(&Hpke, &env, &ctx).unwrap() {
            Outcome::Accepted(p) => {
                assert_eq!(p.body, b"hello dmtap");
                assert_eq!(p.headers.subject.as_deref(), Some("hi"));
            }
            Outcome::Deferred => panic!("a known-contact MOTE must be accepted"),
        }
    }

    // --- Suite 0x02 (PQ hybrid) envelope-level tests -------------------------------------

    fn round_hybrid() -> (Envelope, Vec<u8>, crate::pq::HybridKemKeypair) {
        use crate::pq::{HybridKemKeypair, HybridSeal, HybridSigningKey};
        let sender = HybridSigningKey::generate();
        let eph = HybridSigningKey::generate();
        let recipient = HybridSigningKey::generate();
        let recipient_ik = recipient.public();
        let seal = HybridKemKeypair::generate();
        let mut draft = MoteDraft::new(Kind::Mail, 1_700_000_000_000, b"pq hello".to_vec());
        draft.headers.subject = Some("pq".into());
        let env =
            build_mote_hybrid(&HybridSeal, &sender, &eph, &recipient_ik, seal.public(), draft)
                .unwrap();
        (env, recipient_ik, seal)
    }

    #[test]
    fn hybrid_suite_0x02_seal_validate_round_trip() {
        use crate::pq::HybridSeal;
        let (env, recipient_ik, seal) = round_hybrid();
        assert_eq!(env.suite, Suite::PqHybrid, "envelope asserts suite 0x02");
        // A 0x02 envelope survives a canonical CBOR round-trip byte-for-byte.
        let back = Envelope::from_det_cbor(&env.det_cbor()).unwrap();
        assert_eq!(env, back);
        // The X-Wing-sealed payload opens and both hybrid signatures verify.
        let ctx = RecipientCtx {
            our_ik: &recipient_ik,
            seal_secret: seal.secret(),
            sender_is_known: true,
        };
        match validate(&HybridSeal, &env, &ctx).unwrap() {
            Outcome::Accepted(p) => {
                assert_eq!(p.body, b"pq hello");
                assert_eq!(p.headers.subject.as_deref(), Some("pq"));
                assert_eq!(p.from.len(), crate::pq::HYBRID_PK_LEN);
                assert_eq!(p.sig.len(), crate::pq::HYBRID_SIG_LEN);
            }
            Outcome::Deferred => panic!("a known-contact hybrid MOTE must be accepted"),
        }
    }

    #[test]
    fn hybrid_envelope_rejects_stripped_pq_sender_sig() {
        use crate::pq::HybridSeal;
        let (mut env, recipient_ik, seal) = round_hybrid();
        // Strip the ML-DSA half of the *envelope* sender_sig, keeping the valid Ed25519 half — the
        // intra-suite PQ strip the AND-composition must reject (§1.3). Verification is fail-closed:
        // the hybrid check raises 0x0210, surfaced here as BadSignature (existing variant).
        let sig = env.sender_sig.take().unwrap();
        env.sender_sig = Some(sig[..crate::pq::ED25519_SIG_LEN].to_vec());
        let ctx = RecipientCtx {
            our_ik: &recipient_ik,
            seal_secret: seal.secret(),
            sender_is_known: true,
        };
        assert_eq!(validate(&HybridSeal, &env, &ctx), Err(MoteError::BadSignature));
    }

    #[test]
    fn hybrid_envelope_rejects_tampered_pq_sender_sig() {
        use crate::pq::HybridSeal;
        let (mut env, recipient_ik, seal) = round_hybrid();
        // Corrupt a byte inside the ML-DSA half of sender_sig (present but invalid).
        let mut sig = env.sender_sig.take().unwrap();
        let idx = sig.len() - 1;
        sig[idx] ^= 0x01;
        env.sender_sig = Some(sig);
        let ctx = RecipientCtx {
            our_ik: &recipient_ik,
            seal_secret: seal.secret(),
            sender_is_known: true,
        };
        assert_eq!(validate(&HybridSeal, &env, &ctx), Err(MoteError::BadSignature));
    }

    #[test]
    fn hybrid_envelope_wrong_seal_key_fails_closed() {
        use crate::pq::{HybridKemKeypair, HybridSeal};
        let (env, recipient_ik, _seal) = round_hybrid();
        let wrong = HybridKemKeypair::generate();
        let ctx = RecipientCtx {
            our_ik: &recipient_ik,
            seal_secret: wrong.secret(),
            sender_is_known: true,
        };
        // Decapsulation yields a different shared secret ⇒ AEAD auth fails ⇒ DecryptFailed.
        assert_eq!(validate(&HybridSeal, &env, &ctx), Err(MoteError::DecryptFailed));
    }

    #[test]
    fn content_address_tamper_fails_closed() {
        let (mut env, recipient, seal) = round(Kind::Chat);
        env.ciphertext[0] ^= 0xff; // tamper — id no longer matches
        let ctx = RecipientCtx {
            our_ik: &recipient.public(),
            seal_secret: seal.secret(),
            sender_is_known: true,
        };
        assert_eq!(validate(&Hpke, &env, &ctx), Err(MoteError::BadContentAddress));
    }

    #[test]
    fn wrong_recipient_key_cannot_decrypt() {
        let (env, recipient, _seal) = round(Kind::Mail);
        let other = SealKeypair::generate();
        let ctx = RecipientCtx {
            our_ik: &recipient.public(),
            seal_secret: other.secret(), // wrong KEM secret
            sender_is_known: true,
        };
        assert_eq!(validate(&Hpke, &env, &ctx), Err(MoteError::DecryptFailed));
    }

    #[test]
    fn forged_sender_sig_is_discarded() {
        let (mut env, recipient, seal) = round(Kind::Chat);
        if let Some(sig) = env.sender_sig.as_mut() {
            sig[0] ^= 0xff;
        }
        let ctx = RecipientCtx {
            our_ik: &recipient.public(),
            seal_secret: seal.secret(),
            sender_is_known: true,
        };
        assert_eq!(validate(&Hpke, &env, &ctx), Err(MoteError::BadSignature));
    }

    #[test]
    fn cold_sender_without_challenge_defers() {
        let (env, recipient, seal) = round(Kind::Mail);
        let ctx = RecipientCtx {
            our_ik: &recipient.public(),
            seal_secret: seal.secret(),
            sender_is_known: false, // cold sender, draft had no challenge
        };
        assert!(matches!(validate(&Hpke, &env, &ctx).unwrap(), Outcome::Deferred));
    }

    #[test]
    fn cold_sender_with_challenge_is_accepted() {
        let sender = IdentityKey::generate();
        let eph = IdentityKey::generate();
        let recipient = IdentityKey::generate();
        let seal = SealKeypair::generate();
        let mut draft = MoteDraft::new(Kind::Mail, 1, b"cold contact".to_vec());
        draft.challenge = Some(ChallengeResponse::Pow(PowSolution {
            algo: "argon2id".into(),
            params: [65536, 3, 1],
            epoch_nonce: vec![1, 2, 3],
            solution: vec![4, 5, 6],
            difficulty: 20,
        }));
        let env =
            build_mote(&Hpke, &sender, &eph, &recipient.public(), seal.public(), draft).unwrap();
        let ctx = RecipientCtx {
            our_ik: &recipient.public(),
            seal_secret: seal.secret(),
            sender_is_known: false,
        };
        assert!(matches!(validate(&Hpke, &env, &ctx).unwrap(), Outcome::Accepted(_)));
    }

    /// Build a MOTE from a *specific* sender identity (so a per-contact ratchet keyed on
    /// `Payload.from == sender.public()` can be exercised across calls).
    fn mote_from(sender: &IdentityKey, recipient_ik: &[u8], seal_pub: &[u8; 32]) -> Envelope {
        let eph = IdentityKey::generate();
        let draft = MoteDraft::new(Kind::Mail, 1, b"ratchet body".to_vec());
        build_mote(&Hpke, sender, &eph, recipient_ik, seal_pub, draft).unwrap()
    }

    #[test]
    fn ratchet_first_contact_sets_floor_and_accepts() {
        let sender = IdentityKey::generate();
        let recipient = IdentityKey::generate();
        let seal = SealKeypair::generate();
        let env = mote_from(&sender, &recipient.public(), seal.public());
        let ctx = RecipientCtx {
            our_ik: &recipient.public(),
            seal_secret: seal.secret(),
            sender_is_known: true,
        };
        let mut ratchet = SuiteRatchet::new();
        // First contact: unpinned peer is accepted and the floor is established at its suite.
        assert!(matches!(
            validate_pinned(&Hpke, &env, &ctx, Some(&mut ratchet)).unwrap(),
            Outcome::Accepted(_)
        ));
        assert_eq!(ratchet.high_water_mark(&sender.public()), Some(Suite::Classical));
    }

    #[test]
    fn ratchet_equal_suite_is_accepted_and_mark_holds() {
        let sender = IdentityKey::generate();
        let recipient = IdentityKey::generate();
        let seal = SealKeypair::generate();
        let ctx = RecipientCtx {
            our_ik: &recipient.public(),
            seal_secret: seal.secret(),
            sender_is_known: true,
        };
        let mut ratchet = SuiteRatchet::new();
        // Two objects from the SAME peer at the same (supported) suite: both accepted, and the
        // mark stays put (accepting an equal suite ratchets to the same value, never down).
        let a = mote_from(&sender, &recipient.public(), seal.public());
        assert!(validate_pinned(&Hpke, &a, &ctx, Some(&mut ratchet)).is_ok());
        assert_eq!(ratchet.high_water_mark(&sender.public()), Some(Suite::Classical));
        let b = mote_from(&sender, &recipient.public(), seal.public());
        assert!(validate_pinned(&Hpke, &b, &ctx, Some(&mut ratchet)).is_ok());
        assert_eq!(ratchet.high_water_mark(&sender.public()), Some(Suite::Classical));
    }

    #[test]
    fn ratchet_rejects_wire_downgrade_from_established_peer() {
        let sender = IdentityKey::generate();
        let recipient = IdentityKey::generate();
        let seal = SealKeypair::generate();
        // A genuine Classical (0x01) object — the only suite the reference core can seal/open.
        let env = mote_from(&sender, &recipient.public(), seal.public());
        let ctx = RecipientCtx {
            our_ik: &recipient.public(),
            seal_secret: seal.secret(),
            sender_is_known: true,
        };
        // Simulate a prior PQ-suite (0x02) contact establishing a higher high-water-mark for this
        // peer (build_mote can't emit an unsupported suite, so seed the floor directly — the
        // point under test is that `validate_pinned` CONSULTS it, keyed on Payload.from).
        let mut ratchet = SuiteRatchet::new();
        ratchet.observe(&sender.public(), Suite::PqHybrid);
        // The Classical object is now a downgrade against the established floor → 0x020F.
        let err = validate_pinned(&Hpke, &env, &ctx, Some(&mut ratchet)).unwrap_err();
        assert_eq!(err, ValidateError::Suite(SuiteRatchetError::SuiteDowngrade));
        assert_eq!(err.code(), Some(0x020F));
        // Rejected downgrade MUST NOT ratchet the mark down.
        assert_eq!(ratchet.high_water_mark(&sender.public()), Some(Suite::PqHybrid));
    }

    #[test]
    fn ratchet_none_reproduces_plain_validate() {
        // With the same seeded-high floor, passing `None` (or calling `validate`) does NOT enforce
        // the downgrade check — the ratchet is opt-in and additive; no regression to `validate`.
        let sender = IdentityKey::generate();
        let recipient = IdentityKey::generate();
        let seal = SealKeypair::generate();
        let env = mote_from(&sender, &recipient.public(), seal.public());
        let ctx = RecipientCtx {
            our_ik: &recipient.public(),
            seal_secret: seal.secret(),
            sender_is_known: true,
        };
        assert!(matches!(validate(&Hpke, &env, &ctx).unwrap(), Outcome::Accepted(_)));
        assert!(matches!(
            validate_pinned(&Hpke, &env, &ctx, None).unwrap(),
            Outcome::Accepted(_)
        ));
    }

    #[test]
    fn ratchet_does_not_disturb_earlier_failclosed_checks() {
        // A tampered content address must still fail at step 2 (before decryption), and the
        // ratchet must be left untouched — the downgrade gate never masks the cheaper checks.
        let sender = IdentityKey::generate();
        let recipient = IdentityKey::generate();
        let seal = SealKeypair::generate();
        let mut env = mote_from(&sender, &recipient.public(), seal.public());
        env.ciphertext[0] ^= 0xff;
        let ctx = RecipientCtx {
            our_ik: &recipient.public(),
            seal_secret: seal.secret(),
            sender_is_known: true,
        };
        let mut ratchet = SuiteRatchet::new();
        assert_eq!(
            validate_pinned(&Hpke, &env, &ctx, Some(&mut ratchet)),
            Err(ValidateError::Mote(MoteError::BadContentAddress))
        );
        assert_eq!(ratchet.high_water_mark(&sender.public()), None);
    }

    #[test]
    fn file_tiers() {
        assert_eq!(file_tier(1024), FileTier::Inline);
        assert_eq!(file_tier(2 * 1024 * 1024), FileTier::Normal);
        assert_eq!(file_tier(8 * 1024 * 1024), FileTier::Large);
    }

    #[test]
    fn tier_enforce_allows_equal_or_stronger() {
        // Equal tiers are always fine.
        assert_eq!(tier_enforce(Tier::Private, Tier::Private), Ok(Tier::Private));
        assert_eq!(tier_enforce(Tier::Fast, Tier::Fast), Ok(Tier::Fast));
        // A stronger offer than required is accepted (over-delivering privacy is never a downgrade).
        assert_eq!(tier_enforce(Tier::Fast, Tier::Private), Ok(Tier::Private));
    }

    #[test]
    fn tier_enforce_refuses_downgrade_below_required() {
        // Required Private but only Fast offered — a silent privacy downgrade, fail closed 0x0310.
        let err = tier_enforce(Tier::Private, Tier::Fast).unwrap_err();
        assert_eq!(err, TierEnforcementError::DowngradeRefused);
        assert_eq!(err.code(), 0x0310);
        // Private is strictly stronger than Fast per privacy_rank.
        assert!(Tier::Private.privacy_rank() > Tier::Fast.privacy_rank());
    }

    // --- Delivery tiers (§5.5.1, §16.4) — the DURABILITY axis, orthogonal to `FileTier` --------

    #[test]
    fn delivery_tier_boundaries() {
        // Inline: ≤ 64 KiB (each side of the boundary).
        assert_eq!(DeliveryTier::classify(0), DeliveryTier::Inline);
        assert_eq!(DeliveryTier::classify(INLINE_TIER_MAX), DeliveryTier::Inline); // 64 KiB exact
        assert_eq!(DeliveryTier::classify(INLINE_TIER_MAX + 1), DeliveryTier::Attached);
        // Attached: > 64 KiB, ≤ 25 MiB (each side of the boundary).
        assert_eq!(DeliveryTier::classify(ATTACHED_TIER_MAX), DeliveryTier::Attached); // 25 MiB exact
        assert_eq!(DeliveryTier::classify(ATTACHED_TIER_MAX + 1), DeliveryTier::Referenced);
        // Referenced: > 25 MiB (any size).
        assert_eq!(DeliveryTier::classify(100 * 1024 * 1024), DeliveryTier::Referenced);
    }

    #[test]
    fn delivery_tier_is_orthogonal_to_file_tier() {
        // A 25 MiB file is Attached (durability axis) but Large (privacy axis) — the two axes are
        // independent (§5.5.1): push-vs-pull governs durability, mixnet-vs-bulk governs privacy.
        assert_eq!(DeliveryTier::classify(ATTACHED_TIER_MAX), DeliveryTier::Attached);
        assert_eq!(file_tier(ATTACHED_TIER_MAX), FileTier::Large);
    }

    // --- Durability descriptor CBOR round-trip + validation (§5.5.2, §18.3.7) -------------------

    #[test]
    fn durability_cbor_round_trip_all_classes() {
        for d in [
            Durability::origin_hold(),
            Durability::recipient_pinned(),
            Durability::cluster_replicated(3),
            Durability::pinned(1_900_000_000),
            Durability {
                class: DurabilityClass::Pinned,
                retention: Some(1_900_000_000),
                replicas: None,
                holder_hint: Some("relay.example.invalid/pin/abc".into()),
            },
        ] {
            let bytes = d.det_cbor();
            // Integer-keyed canonical map (first key is integer 1, not a text key).
            assert_eq!(bytes[0] & 0xe0, 0xa0, "durability is a CBOR map");
            let back = Durability::from_det_cbor(&bytes).unwrap();
            assert_eq!(back, d, "durability must survive a canonical CBOR round-trip");
            assert_eq!(back.det_cbor(), bytes, "re-encode byte-identical");
        }
    }

    #[test]
    fn durability_unknown_class_decodes_then_fails_validate() {
        // class = 99 is preserved through decode (not a generic malformed-CBOR error) and fails at
        // validate() with the file-level 0x080A (§5.5.2) — the DMTAP-FILE-06 unknown-class variant.
        let bytes = cbor::encode(&Cv::Map(vec![(1, Cv::U64(99))]));
        let d = Durability::from_det_cbor(&bytes).expect("unknown class decodes, not a CBOR error");
        assert_eq!(d.class, DurabilityClass::Unknown(99));
        assert_eq!(d.validate(), Err(MoteError::FileManifestInvalid));
        assert_eq!(d.validate().unwrap_err().code(), Some(0x080A));
    }

    #[test]
    fn durability_class_invariants_fail_closed() {
        // cluster-replicated (2) with replicas absent or < 1 → invalid.
        assert_eq!(
            Durability { class: DurabilityClass::ClusterReplicated, retention: None, replicas: None, holder_hint: None }.validate(),
            Err(MoteError::FileManifestInvalid)
        );
        assert_eq!(
            Durability { class: DurabilityClass::ClusterReplicated, retention: None, replicas: Some(0), holder_hint: None }.validate(),
            Err(MoteError::FileManifestInvalid)
        );
        assert!(Durability::cluster_replicated(1).validate().is_ok());
        // pinned (3) with no retention → invalid; with a term → ok.
        assert_eq!(
            Durability { class: DurabilityClass::Pinned, retention: None, replicas: None, holder_hint: None }.validate(),
            Err(MoteError::FileManifestInvalid)
        );
        assert!(Durability::pinned(1_900_000_000).validate().is_ok());
        // origin-hold / recipient-pinned need no extra fields.
        assert!(Durability::origin_hold().validate().is_ok());
        assert!(Durability::recipient_pinned().validate().is_ok());
    }

    // --- DMTAP-FILE-06: Referenced ManifestRef durability validation ----------------------------

    fn mref(size: u64, durability: Option<Durability>) -> ManifestRef {
        ManifestRef { id: ContentId::of(b"root"), size, chunks: 1, durability }
    }

    #[test]
    fn file06_referenced_missing_durability_rejected() {
        // A Referenced (> 25 MiB) reference with NO durability → 0x080A fail-closed.
        let r = mref(ATTACHED_TIER_MAX + 1, None);
        assert_eq!(r.validate_durability(), Err(MoteError::FileManifestInvalid));
        assert_eq!(r.validate_durability().unwrap_err().code(), Some(0x080A));
        // …and the malformed-contract variants (unknown class / replicas<1 / no retention).
        for bad in [
            Durability { class: DurabilityClass::Unknown(99), retention: None, replicas: None, holder_hint: None },
            Durability { class: DurabilityClass::ClusterReplicated, retention: None, replicas: Some(0), holder_hint: None },
            Durability { class: DurabilityClass::Pinned, retention: None, replicas: None, holder_hint: None },
        ] {
            let r = mref(ATTACHED_TIER_MAX + 1, Some(bad));
            assert_eq!(r.validate_durability(), Err(MoteError::FileManifestInvalid));
        }
    }

    #[test]
    fn file06_referenced_with_valid_durability_accepted() {
        for good in [
            Durability::origin_hold(),
            Durability::recipient_pinned(),
            Durability::cluster_replicated(2),
            Durability::pinned(1_900_000_000),
        ] {
            assert!(mref(ATTACHED_TIER_MAX + 1, Some(good)).validate_durability().is_ok());
        }
    }

    #[test]
    fn inline_and_attached_may_omit_durability() {
        // Inline/Attached tiers are durable by construction and MAY omit the descriptor (§5.5.2).
        assert!(mref(1024, None).validate_durability().is_ok());
        assert!(mref(ATTACHED_TIER_MAX, None).validate_durability().is_ok());
        // …but a present-yet-malformed descriptor is still rejected even below the Referenced tier.
        let bad = Durability { class: DurabilityClass::Pinned, retention: None, replicas: None, holder_hint: None };
        assert_eq!(mref(1024, Some(bad)).validate_durability(), Err(MoteError::FileManifestInvalid));
    }

    #[test]
    fn manifest_ref_wire_compat_when_durability_absent() {
        // A ManifestRef WITHOUT durability must encode exactly as the pre-change {1,2,3} map
        // (wire-compatible with suites 0x01/0x02): key 4 is omitted, no trailing bytes.
        let r = mref(4096, None);
        let bytes = r.to_cv();
        let encoded = cbor::encode(&bytes);
        let expected = cbor::encode(&Cv::Map(vec![
            (1, Cv::Bytes(ContentId::of(b"root").as_bytes().to_vec())),
            (2, Cv::U64(4096)),
            (3, Cv::U64(1)),
        ]));
        assert_eq!(encoded, expected, "absent durability ⇒ byte-identical legacy encoding");
        // And with durability present, key 4 appears and round-trips through Attachment.
        let r2 = mref(ATTACHED_TIER_MAX + 1, Some(Durability::cluster_replicated(3)));
        let att = Attachment {
            name: "big.bin".into(),
            mime: "application/octet-stream".into(),
            size: r2.size,
            inline: None,
            manifest: Some(r2.clone()),
            key: vec![0u8; 32],
        };
        let back = Attachment::from_cv(att.to_cv()).unwrap();
        assert_eq!(back.manifest.unwrap().durability, Some(Durability::cluster_replicated(3)));
    }

    // --- Size-tier enforcement at construction (§5.5.1) -----------------------------------------

    fn attach_inline(size: u64, bytes: Vec<u8>) -> Attachment {
        Attachment { name: "f".into(), mime: "text/plain".into(), size, inline: Some(bytes), manifest: None, key: vec![0u8; 32] }
    }
    fn attach_manifest(size: u64, durability: Option<Durability>) -> Attachment {
        Attachment {
            name: "f".into(),
            mime: "application/octet-stream".into(),
            size,
            inline: None,
            manifest: Some(mref(size, durability)),
            key: vec![0u8; 32],
        }
    }

    #[test]
    fn tier_check_accepts_well_formed_attachments() {
        assert!(attach_inline(5, b"hello".to_vec()).check_delivery_tier().is_ok());
        assert!(attach_manifest(4 * 1024 * 1024, None).check_delivery_tier().is_ok()); // Attached
        assert!(attach_manifest(ATTACHED_TIER_MAX + 1, Some(Durability::origin_hold()))
            .check_delivery_tier()
            .is_ok()); // Referenced + durability
    }

    #[test]
    fn tier_check_rejects_oversize_inline() {
        // An inline attachment above the 64 KiB inline cap must fail closed — it cannot ride the MOTE.
        let big = vec![0u8; (INLINE_TIER_MAX + 1) as usize];
        let att = attach_inline(INLINE_TIER_MAX + 1, big);
        assert_eq!(att.check_delivery_tier(), Err(MoteError::SizeTierViolation));
    }

    #[test]
    fn tier_check_rejects_size_lying_and_wrong_mechanism() {
        // inline bytes length disagreeing with declared size.
        assert_eq!(attach_inline(10, b"short".to_vec()).check_delivery_tier(), Err(MoteError::SizeTierViolation));
        // manifest reference for an inline-sized (≤ 64 KiB) file — belongs inline.
        assert_eq!(attach_manifest(1024, None).check_delivery_tier(), Err(MoteError::SizeTierViolation));
        // both inline AND manifest present (§18.3.7 requires exactly one).
        let both = Attachment {
            name: "f".into(), mime: "x".into(), size: 5, inline: Some(b"hello".to_vec()),
            manifest: Some(mref(5, None)), key: vec![0u8; 32],
        };
        assert_eq!(both.check_delivery_tier(), Err(MoteError::SizeTierViolation));
        // neither present.
        let neither = Attachment { name: "f".into(), mime: "x".into(), size: 5, inline: None, manifest: None, key: vec![] };
        assert_eq!(neither.check_delivery_tier(), Err(MoteError::SizeTierViolation));
    }

    #[test]
    fn tier_check_referenced_without_durability_is_file_manifest_invalid() {
        // A Referenced-tier manifest attachment missing durability surfaces the file-level 0x080A.
        let att = attach_manifest(ATTACHED_TIER_MAX + 1, None);
        assert_eq!(att.check_delivery_tier(), Err(MoteError::FileManifestInvalid));
    }

    #[test]
    fn build_mote_enforces_delivery_tier_fail_closed() {
        // build_mote rejects an oversize inline attachment at construction (fail closed).
        let sender = IdentityKey::generate();
        let eph = IdentityKey::generate();
        let recipient = IdentityKey::generate();
        let seal = SealKeypair::generate();
        let mut draft = MoteDraft::new(Kind::Mail, 1, b"body".to_vec());
        draft.attach = vec![attach_inline(INLINE_TIER_MAX + 1, vec![0u8; (INLINE_TIER_MAX + 1) as usize])];
        assert_eq!(
            build_mote(&Hpke, &sender, &eph, &recipient.public(), seal.public(), draft),
            Err(MoteError::SizeTierViolation)
        );
        // A well-formed Referenced attachment (with durability) builds and validates end-to-end.
        let mut draft = MoteDraft::new(Kind::Mail, 1, b"body".to_vec());
        draft.attach = vec![attach_manifest(ATTACHED_TIER_MAX + 1, Some(Durability::cluster_replicated(3)))];
        let env = build_mote(&Hpke, &sender, &eph, &recipient.public(), seal.public(), draft)
            .expect("well-formed Referenced attachment must build");
        let ctx = RecipientCtx { our_ik: &recipient.public(), seal_secret: seal.secret(), sender_is_known: true };
        assert!(matches!(validate(&Hpke, &env, &ctx).unwrap(), Outcome::Accepted(_)));
    }

    // --- DMTAP-FILE-07: inbound spool cap (§5.5.5) ----------------------------------------------

    #[test]
    fn file07_spool_overflow_rejected_fail_closed() {
        let mut spool = InboundSpool::new(10 * 1024); // 10 KiB per-sender cap
        assert!(spool.admit(6 * 1024).is_ok());
        assert_eq!(spool.used(), 6 * 1024);
        assert_eq!(spool.remaining(), 4 * 1024);
        // A push that would exceed the cap is refused, and the running total is left unchanged.
        let err = spool.admit(5 * 1024).unwrap_err();
        assert_eq!(err, MoteError::SpoolOverflow);
        assert_eq!(err.code(), Some(0x080C));
        assert_eq!(spool.used(), 6 * 1024, "a refused push admits nothing");
        // Exactly filling the cap is admitted (boundary); one more byte overflows.
        assert!(spool.admit(4 * 1024).is_ok());
        assert_eq!(spool.remaining(), 0);
        assert_eq!(spool.admit(1), Err(MoteError::SpoolOverflow));
        // The pure helper agrees, incl. saturating on an arithmetic overflow.
        assert!(spool_admit(0, 10 * 1024, 10 * 1024).is_ok());
        assert_eq!(spool_admit(1, u64::MAX, u64::MAX), Err(MoteError::SpoolOverflow));
    }

    // --- DMTAP-FILE-08: pinned(term) retention expiry (§5.5.4) ----------------------------------

    #[test]
    fn file08_pinned_retention_expiry() {
        let d = Durability::pinned(1_000);
        // A fetch before the term is honored; at/after the term is 0x080B fail-closed.
        assert!(d.check_retention(999).is_ok());
        let err = d.check_retention(1_000).unwrap_err();
        assert_eq!(err, MoteError::FileRetentionExpired);
        assert_eq!(err.code(), Some(0x080B));
        assert_eq!(d.check_retention(2_000), Err(MoteError::FileRetentionExpired));
        // Non-pinned classes never expire on a retention check; an indefinite pin (no term) never
        // expires either.
        assert!(Durability::origin_hold().check_retention(u64::MAX).is_ok());
        assert!(Durability::cluster_replicated(3).check_retention(u64::MAX).is_ok());
        let indefinite = Durability { class: DurabilityClass::Pinned, retention: None, replicas: None, holder_hint: None };
        assert!(indefinite.check_retention(u64::MAX).is_ok());
    }

    // --- DMTAP-FILE-09: whole-file unavailability (§5.5.2/§5.5.3/§6.6) ---------------------------

    #[test]
    fn file09_referenced_no_holder_is_file_unavailable() {
        assert!(check_file_available(true).is_ok());
        let err = check_file_available(false).unwrap_err();
        assert_eq!(err, MoteError::FileUnavailable);
        assert_eq!(err.code(), Some(0x0809));
    }

    // --- Content addressing over CIPHERTEXT (§18.9.5) — dedup-confirmation defence ---------------

    #[test]
    fn chunk_content_id_addresses_ciphertext_not_plaintext() {
        // The SAME plaintext sealed under two different per-file keys yields two different chunk
        // ids (and thus two different Manifest.id Merkle roots): no cross-user/plaintext dedup, so a
        // holder cannot confirm "you have file X" by hash (§5.5, §18.9.5).
        let plaintext = b"the same file content under two unrelated keys".to_vec();
        let aad = b"file-ciphertext-addressing-aad".to_vec();
        let key_a = SealKeypair::generate();
        let key_b = SealKeypair::generate();
        let ct_a = Hpke.seal(key_a.public(), &aad, &plaintext).unwrap();
        let ct_b = Hpke.seal(key_b.public(), &aad, &plaintext).unwrap();
        assert_ne!(ct_a, ct_b, "sanity: two keys produce distinct ciphertext");

        // chunk_content_id addresses the CIPHERTEXT bytes.
        let id_a = chunk_content_id(&ct_a);
        let id_b = chunk_content_id(&ct_b);
        assert_eq!(id_a, ContentId::of(&ct_a), "id is over ciphertext bytes");
        assert_ne!(id_a, id_b, "same plaintext, different keys ⇒ different ciphertext chunk ids");
        // Feeding the plaintext would (wrongly) collide — proving the addressing input matters.
        assert_eq!(chunk_content_id(&plaintext), chunk_content_id(&plaintext));
        assert_ne!(id_a, chunk_content_id(&plaintext), "ciphertext id ≠ plaintext id");

        // And the Manifest Merkle root over the ciphertext-derived chunk ids differs per key.
        let manifest_for = |chunk_id: ContentId| Manifest {
            id: ContentId(Vec::new()),
            size: 0,
            chunk_sz: 0,
            chunks: vec![chunk_id],
            suite: Suite::Classical,
        };
        assert_ne!(
            manifest_for(id_a).merkle_root(),
            manifest_for(id_b).merkle_root(),
            "ciphertext-addressed manifests do not converge for the same plaintext"
        );
    }

    #[test]
    fn blinded_tag_is_deterministic_and_time_varying() {
        let ss = b"shared secret from first contact";
        assert_eq!(blinded_tag(ss, 100), blinded_tag(ss, 100));
        assert_ne!(blinded_tag(ss, 100), blinded_tag(ss, 101));
    }

    #[test]
    fn manifest_round_trips_canonically() {
        let m = Manifest {
            id: ContentId::of(b"manifest-root"),
            size: 3 * 1024 * 1024,
            chunk_sz: 1024 * 1024,
            chunks: vec![ContentId::of(b"c0"), ContentId::of(b"c1"), ContentId::of(b"c2")],
            suite: Suite::Classical,
        };
        let bytes = m.det_cbor();
        assert_eq!(Manifest::from_det_cbor(&bytes).unwrap(), m);
    }

    #[test]
    fn manifest_with_key5_is_rejected() {
        // Hand-build a Manifest map that (illegally) carries key 5 = a content key (§18.3.8).
        let leaky = Cv::Map(vec![
            (1, Cv::Bytes(ContentId::of(b"root").as_bytes().to_vec())),
            (2, Cv::U64(1024)),
            (3, Cv::U64(1024)),
            (4, Cv::Array(vec![Cv::Bytes(ContentId::of(b"c0").as_bytes().to_vec())])),
            (5, Cv::Bytes(vec![0u8; 32])), // FORBIDDEN
            (6, Cv::U64(0x01)),
        ]);
        let bytes = cbor::encode(&leaky);
        assert_eq!(
            Manifest::from_det_cbor(&bytes),
            Err(CborError::ManifestKeyPresent)
        );
    }

    #[test]
    fn envelope_rejects_unknown_key_fail_closed() {
        let (env, _r, _s) = round(Kind::Mail);
        let mut f = match cbor::decode(&env.det_cbor()).unwrap() {
            Cv::Map(m) => m,
            _ => unreachable!(),
        };
        f.push((63, Cv::U64(1))); // an unknown (reserved-range) key
        let bytes = cbor::encode(&Cv::Map(f));
        assert_eq!(Envelope::from_det_cbor(&bytes), Err(CborError::UnknownKey(63)));
    }

    #[test]
    fn challenge_variants_round_trip() {
        for c in [
            ChallengeResponse::Arc(ArcToken {
                issuer: vec![1],
                token: vec![2, 3],
                origin: vec![4],
                nonce: Some(vec![5]),
            }),
            ChallengeResponse::Pow(PowSolution {
                algo: "argon2id".into(),
                params: [65536, 3, 1],
                epoch_nonce: vec![9],
                solution: vec![8, 7],
                difficulty: 22,
            }),
            ChallengeResponse::Postage(PostageStamp {
                issuer: vec![1],
                serial: vec![2],
                amount: 500,
                currency: "USD".into(),
                expiry: 1_700_000_000_000,
                audience: None,
                sig: vec![0u8; 64],
            }),
            ChallengeResponse::Vouch(Vouch {
                voucher: vec![1; 32],
                subject: vec![2; 32],
                recipient: vec![3; 32],
                exp: 1_700_000_000_000,
                sig: vec![0u8; 64],
            }),
        ] {
            let bytes = c.det_cbor();
            assert_eq!(ChallengeResponse::from_cv(cbor::decode(&bytes).unwrap()).unwrap(), c);
        }
    }
}

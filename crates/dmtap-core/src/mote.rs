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
    #[error("canonical CBOR decode failed: {0}")]
    BadEncoding(#[from] CborError),
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
            ValidateError::Mote(_) => None,
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
}

/// Reference to a file's manifest (spec §2.5, §18.3.7). `chunks` here is a *count* (u32).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestRef {
    pub id: ContentId, // key 1 — BLAKE3 Merkle-DAG root (§18.9.5)
    pub size: u64,     // key 2
    pub chunks: u32,   // key 3 — NUMBER of chunks
}

impl ManifestRef {
    fn to_cv(&self) -> Cv {
        Cv::Map(vec![
            (1, Cv::Bytes(self.id.as_bytes().to_vec())),
            (2, Cv::U64(self.size)),
            (3, Cv::U64(self.chunks as u64)),
        ])
    }

    fn from_cv(cv: Cv) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cv)?;
        let id = ContentId(as_bytes(f.req(1)?)?);
        let size = as_u64(f.req(2)?)?;
        let chunks = as_u32(f.req(3)?)?;
        f.deny_unknown()?;
        Ok(ManifestRef { id, size, chunks })
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
    if !env.suite.is_supported() {
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
        verify_domain(eph, ENVELOPE_SENDER_DS, &authed, sig).map_err(|_| MoteError::BadSignature)?;
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
    verify_domain(&payload.from, PAYLOAD_SIG_DS, &ph, &payload.sig)
        .map_err(|_| MoteError::BadSignature)?;

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

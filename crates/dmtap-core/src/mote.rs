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

use crate::id::ContentId;
use crate::identity::{verify_domain, IdentityKey};
use crate::suite::Suite;
use crate::TimestampMs;

/// Current envelope format version (spec §2.2, `v`).
pub const MOTE_VERSION: u8 = 0;

const HPKE_INFO: &[u8] = b"dmtap-mote-payload-v0";
const PAYLOAD_SIG_DOMAIN: &[u8] = b"dmtap-payload-sig-v0";
const SENDER_SIG_DOMAIN: &[u8] = b"dmtap-sender-sig-v0";

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
/// policy **without decrypting** (spec §2.2b, validated at §2.7 step 6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChallengeResponse {
    /// An ARC (Authenticated Received Chain / attested reputation) token (§9).
    ArcToken(Vec<u8>),
    /// A memory-hard proof-of-work solution over `id ‖ recipient ‖ epoch-nonce` (§9.4, §16.5).
    ProofOfWork { nonce: Vec<u8>, solution: Vec<u8> },
    /// A redeemable postage stamp (§9.5).
    Postage(Vec<u8>),
    /// A vouch from an existing contact (§9).
    Vouch(Vec<u8>),
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
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            DeliveryTag::Key(b) | DeliveryTag::Group(b) | DeliveryTag::Blinded(b) => b.clone(),
        }
    }
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

/// The signed, per-recipient envelope (spec §2.2). `id = [0x1e] || BLAKE3-256(ciphertext)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub v: u8,                          // format version (0)
    pub suite: Suite,                   // algorithm suite (§1.1)
    pub id: ContentId,                  // content address of `ciphertext` (§2.2)
    pub to: Vec<u8>,                    // DeliveryTag bytes (§2.2a)
    pub epoch: Option<Vec<u8>>,         // MLS epoch / group-context ref, if group (§5)
    pub ts: TimestampMs,                // sender timestamp (ms epoch)
    pub kind: Kind,                     // message kind (§2.3)
    pub keypkg: Option<ContentId>,      // present iff this initiates an MLS session (§5.3)
    pub challenge: Option<ChallengeResponse>, // anti-abuse proof for cold senders (§2.2b)
    pub ciphertext: Vec<u8>,            // HPKE-sealed Payload (§2.4)
    /// Detached signature by an EPHEMERAL per-message key over `(id‖to‖ts‖kind‖challenge)`;
    /// gates abuse, reveals no identity (§2.2).
    pub sender_sig: Option<Vec<u8>>,
    /// The ephemeral public key that produced `sender_sig`. (Reference-explicit; see module
    /// docs — the spec leaves this distribution implicit.)
    pub sender_eph: Option<Vec<u8>>,
}

/// The end-to-end-encrypted payload (spec §2.4), sealed into `Envelope.ciphertext`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Payload {
    pub from: Vec<u8>, // sender IK — revealed only to the recipient (sealed sender)
    #[serde(default)]
    pub sig: Vec<u8>, // IK/device key over the canonical payload hash (§2.4, §5.2)
    pub headers: Headers,
    pub body: Vec<u8>,
    pub refs: Vec<ContentId>,
    pub attach: Vec<Attachment>,
    pub expires: Option<TimestampMs>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Headers {
    pub thread: Option<Vec<u8>>,
    pub subject: Option<String>, // mail only
    pub mime: Option<String>,
    pub cc: Vec<Vec<u8>>, // fan-out is per-recipient MOTEs
}

/// An attachment (spec §2.5). Small → inline; large → content-addressed manifest (§5.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attachment {
    pub name: String,
    pub mime: String,
    pub size: u64,
    pub inline: Option<Vec<u8>>,
    pub manifest: Option<ManifestRef>,
    pub key: Vec<u8>, // per-file content key
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestRef {
    pub id: ContentId, // BLAKE3 Merkle-DAG root (§5.5)
    pub size: u64,
    pub chunks: u32,
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
    pub keypkg: Option<ContentId>,
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
/// kind, ts, to). `id` is excluded because it is *derived from* the ciphertext.
fn aad_bytes(suite: Suite, kind: Kind, ts: TimestampMs, to: &[u8]) -> Vec<u8> {
    let mut a = Vec::with_capacity(2 + 8 + to.len());
    a.push(suite.as_u8());
    a.push(kind.as_u8());
    a.extend_from_slice(&ts.to_be_bytes());
    a.extend_from_slice(to);
    a
}

/// The bytes covered by `sender_sig`: `id ‖ to ‖ ts ‖ kind ‖ challenge` (spec §2.2, §2.7 step 3).
fn sender_authed_bytes(env: &Envelope) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(env.id.as_bytes());
    m.extend_from_slice(&env.to);
    m.extend_from_slice(&env.ts.to_be_bytes());
    m.push(env.kind.as_u8());
    // Challenge (deterministically encoded; empty when absent).
    if let Some(c) = &env.challenge {
        let mut cb = Vec::new();
        ciborium::into_writer(c, &mut cb).expect("CBOR of challenge is infallible");
        m.extend_from_slice(&cb);
    }
    m
}

/// Canonical hash of a payload for signing: `BLAKE3(CBOR(payload with sig cleared))`.
fn payload_hash(payload: &Payload) -> [u8; 32] {
    let mut p = payload.clone();
    p.sig = Vec::new();
    let mut buf = Vec::new();
    ciborium::into_writer(&p, &mut buf).expect("CBOR of payload is infallible");
    *blake3::hash(&buf).as_bytes()
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
    let to = recipient_ik.to_vec();

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
    payload.sig = sender_ik.sign_domain(PAYLOAD_SIG_DOMAIN, &ph);

    // 2. Serialize + HPKE-seal the payload, binding it to the envelope header via AAD.
    let mut pt = Vec::new();
    ciborium::into_writer(&payload, &mut pt).expect("CBOR of payload is infallible");
    let aad = aad_bytes(suite, draft.kind, draft.ts, &to);
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
    env.sender_sig = Some(ephemeral.sign_domain(SENDER_SIG_DOMAIN, &authed));
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
/// from a cold sender defers. Pinned-identity comparison at step 8 is left to the caller.
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

    // 3. Verify sender_sig over (id‖to‖ts‖kind‖challenge) under the ephemeral key (cheap).
    if let Some(sig) = &env.sender_sig {
        let eph = env.sender_eph.as_ref().ok_or(MoteError::MissingSenderKey)?;
        let authed = sender_authed_bytes(env);
        verify_domain(eph, SENDER_SIG_DOMAIN, &authed, sig).map_err(|_| MoteError::BadSignature)?;
    }

    // 4. Resolve `to` to this node (default tag == our identity key).
    if env.to != ctx.our_ik {
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
    let aad = aad_bytes(env.suite, env.kind, env.ts, &env.to);
    let pt = sealer.open(ctx.seal_secret, &aad, &env.ciphertext)?;
    let payload: Payload = ciborium::from_reader(&pt[..]).map_err(|_| MoteError::DecryptFailed)?;

    // 8. Verify Payload.sig under Payload.from (TOFU-pin / pinned-identity check is the caller's).
    let ph = payload_hash(&payload);
    verify_domain(&payload.from, PAYLOAD_SIG_DOMAIN, &ph, &payload.sig)
        .map_err(|_| MoteError::BadSignature)?;

    // 9. (Caller applies expires/refs/kind semantics, stores, and acks.)
    Ok(Outcome::Accepted(Box::new(payload)))
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
        let mut buf = Vec::new();
        ciborium::into_writer(&env, &mut buf).unwrap();
        let back: Envelope = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(env, back, "envelope must survive a CBOR round-trip byte-for-byte");
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
        draft.challenge = Some(ChallengeResponse::ProofOfWork {
            nonce: vec![1, 2, 3],
            solution: vec![4, 5, 6],
        });
        let env =
            build_mote(&Hpke, &sender, &eph, &recipient.public(), seal.public(), draft).unwrap();
        let ctx = RecipientCtx {
            our_ik: &recipient.public(),
            seal_secret: seal.secret(),
            sender_is_known: false,
        };
        assert!(matches!(validate(&Hpke, &env, &ctx).unwrap(), Outcome::Accepted(_)));
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
}

//! Identity lifecycle — spec §1.
//!
//! Key is identity; domain/IP/provider are replaceable pointers. Every lifecycle operation
//! ([`Identity`], [`DeviceCert`], [`RecoveryPolicy`], [`MoveRecord`]) is a **signed, versioned
//! object** (§1.7). This module implements the classical suite (`0x01`, Ed25519). The
//! `Identity` object holds `suites` as a *set* with a per-suite key map and a per-suite
//! signature list (§1.3), so it is shaped for the PQ transition even though the reference core
//! only validates the classical suite (the PQ suite `0x02` fails closed in [`Identity::verify`],
//! per §1.3's "reject rather than fall back silently").

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

use crate::cbor::{self, as_array, as_bytes, as_text, as_u64, as_u8, CborError, Cv, Fields};
use crate::id::ContentId;
use crate::suite::Suite;
use crate::TimestampMs;

// Domain-separation tags (§18.9.3), each an ASCII string terminated by one `0x00` byte, distinct
// per object type so a signature over one object can never be replayed as another (§18.1.6). The
// signing preimage is `DS-tag ‖ det_cbor(object ∖ {sig})`; `sign_domain`/`verify_domain`
// concatenate `domain ‖ msg`, so these constants carry the trailing NUL and the body is `msg`.
const IDENTITY_DS: &[u8] = b"DMTAP-v0/identity\x00";
const DEVICE_CERT_DS: &[u8] = b"DMTAP-v0/device-cert\x00";
const RECOVERY_POLICY_DS: &[u8] = b"DMTAP-v0/recovery-policy\x00";
const MOVE_RECORD_DS: &[u8] = b"DMTAP-v0/move-record\x00";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IdentityError {
    #[error("signature verification failed")]
    BadSignature,
    #[error("hash chain is broken or inconsistent with the pinned anchor")]
    BrokenChain,
    #[error("suite {0:#04x} is not supported by this implementation (fail closed)")]
    UnsupportedSuite(u8),
    #[error("identity is malformed: {0}")]
    Malformed(&'static str),
    #[error("key or signature had the wrong length")]
    BadKeyLength,
    #[error("canonical CBOR decode failed: {0}")]
    BadEncoding(#[from] CborError),
}

// --- low-level Ed25519 helpers -------------------------------------------------------------

fn verifying_key(bytes: &[u8]) -> Result<VerifyingKey, IdentityError> {
    let arr: [u8; 32] = bytes.try_into().map_err(|_| IdentityError::BadKeyLength)?;
    VerifyingKey::from_bytes(&arr).map_err(|_| IdentityError::BadKeyLength)
}

fn signature(bytes: &[u8]) -> Result<Signature, IdentityError> {
    let arr: [u8; 64] = bytes.try_into().map_err(|_| IdentityError::BadKeyLength)?;
    Ok(Signature::from_bytes(&arr))
}

// --- Root identity key (classical) ---------------------------------------------------------

/// A classical (suite `0x01`) root identity key `IK` (spec §1.2) — an Ed25519 signing keypair.
///
/// In production `IK` is offline/cold-custody and used rarely; day-to-day signing uses device
/// subkeys ([`DeviceCert`]). This wrapper keeps the reference API ergonomic.
pub struct IdentityKey {
    signing: SigningKey,
}

impl IdentityKey {
    /// Generate a fresh `IK` from the OS CSPRNG.
    pub fn generate() -> Self {
        IdentityKey { signing: SigningKey::generate(&mut OsRng) }
    }

    /// Reconstruct from a 32-byte Ed25519 seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        IdentityKey { signing: SigningKey::from_bytes(seed) }
    }

    /// The public half — the stable DMTAP address key correspondents pin (§1.2).
    pub fn public(&self) -> Vec<u8> {
        self.signing.verifying_key().to_bytes().to_vec()
    }

    /// The 32-byte public key as an array.
    pub fn public_array(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Sign `msg` under this key with an explicit domain-separation label. Used by the MOTE
    /// layer for `Payload.sig` and (via an ephemeral key) the envelope `sender_sig` (§2).
    pub fn sign_domain(&self, domain: &[u8], msg: &[u8]) -> Vec<u8> {
        let mut m = Vec::with_capacity(domain.len() + msg.len());
        m.extend_from_slice(domain);
        m.extend_from_slice(msg);
        self.signing.sign(&m).to_bytes().to_vec()
    }
}

/// Verify an Ed25519 signature produced with [`IdentityKey::sign_domain`] under public key
/// `pk`. Fails closed on any malformed key/signature or a bad signature.
pub fn verify_domain(pk: &[u8], domain: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), IdentityError> {
    let vk = verifying_key(pk)?;
    let sig = signature(sig)?;
    let mut m = Vec::with_capacity(domain.len() + msg.len());
    m.extend_from_slice(domain);
    m.extend_from_slice(msg);
    vk.verify(&m, &sig).map_err(|_| IdentityError::BadSignature)
}

/// Decode a `suite` field (a `u8`), failing closed on any unknown byte (§18.1.4).
fn suite_from_cv(cv: Cv) -> Result<Suite, CborError> {
    let b = as_u8(cv)?;
    Suite::from_u8(b).ok_or(CborError::UnknownSuite(b))
}

/// Encode a `hash` reference (a [`ContentId`]) as a CBOR byte string.
fn hash_cv(id: &ContentId) -> Cv {
    Cv::Bytes(id.as_bytes().to_vec())
}

// --- Device capabilities & certs -----------------------------------------------------------

/// Device capabilities (spec §1.2, §18.4.2). On the wire each cap is a capability **string**
/// (`caps = [+ tstr]`, §18.4.2); this enum is the typed reference form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Cap {
    Send,
    Recv,
    Relay,
    Mix,
    Gateway,
    /// Elevated, but never sufficient alone to rewrite recovery policy (§1.2).
    Admin,
}

impl Cap {
    /// The wire capability string (§18.4.2).
    pub fn as_str(self) -> &'static str {
        match self {
            Cap::Send => "send",
            Cap::Recv => "recv",
            Cap::Relay => "relay",
            Cap::Mix => "mix",
            Cap::Gateway => "gateway",
            Cap::Admin => "admin",
        }
    }

    /// Parse a wire capability string, failing closed on an unknown value.
    pub fn from_str(s: &str) -> Result<Cap, CborError> {
        Ok(match s {
            "send" => Cap::Send,
            "recv" => Cap::Recv,
            "relay" => Cap::Relay,
            "mix" => Cap::Mix,
            "gateway" => Cap::Gateway,
            "admin" => Cap::Admin,
            _ => return Err(CborError::TypeMismatch),
        })
    }
}

/// Locates and pins the identity's whole published KeyPackage bundle (spec §18.4.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyPackageBundleRef {
    pub loc: String,               // key 1 — mesh/relay locator
    pub id: ContentId,             // key 2 — content address of the bundle
    pub suites: Option<Vec<Suite>>, // key 3 — suites the bundle advertises
}

impl KeyPackageBundleRef {
    /// A minimal bundle ref (locator + content address, no advertised-suite list).
    pub fn new(loc: impl Into<String>, id: ContentId) -> Self {
        KeyPackageBundleRef { loc: loc.into(), id, suites: None }
    }

    fn to_cv(&self) -> Cv {
        let mut m = vec![(1u64, Cv::Text(self.loc.clone())), (2, hash_cv(&self.id))];
        if let Some(s) = &self.suites {
            m.push((3, Cv::Array(s.iter().map(|x| Cv::U64(x.as_u8() as u64)).collect())));
        }
        Cv::Map(m)
    }

    fn from_cv(cv: Cv) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cv)?;
        let loc = as_text(f.req(1)?)?;
        let id = ContentId(as_bytes(f.req(2)?)?);
        let suites = match f.take(3) {
            Some(c) => Some(
                as_array(c)?
                    .into_iter()
                    .map(suite_from_cv)
                    .collect::<Result<_, _>>()?,
            ),
            None => None,
        };
        f.deny_unknown()?;
        Ok(KeyPackageBundleRef { loc, id, suites })
    }
}

/// A per-device signing subkey, signed by the root identity key (spec §1.2, §18.4.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCert {
    pub suite: Suite,        // key 1
    pub ik: Vec<u8>,         // key 2 — root identity public key
    pub device_key: Vec<u8>, // key 3 — device signing public key
    pub label: String,       // key 4 — "phone", "home-box", ...
    pub created: TimestampMs, // key 5
    pub expires: Option<TimestampMs>, // key 6
    pub caps: Vec<Cap>,      // key 7 — capability strings
    #[serde(default)]
    pub sig: Vec<u8>, // key 8 — IK over det_cbor(cert ∖ {8}) (§18.9.3)
}

impl DeviceCert {
    /// Integer-keyed canonical map (§18.4.2). `include_sig=false` omits key 8 for the §18.9.3
    /// signing body.
    fn to_cv(&self, include_sig: bool) -> Cv {
        let mut m = vec![
            (1u64, Cv::U64(self.suite.as_u8() as u64)),
            (2, Cv::Bytes(self.ik.clone())),
            (3, Cv::Bytes(self.device_key.clone())),
            (4, Cv::Text(self.label.clone())),
            (5, Cv::U64(self.created)),
        ];
        if let Some(e) = self.expires {
            m.push((6, Cv::U64(e)));
        }
        m.push((7, Cv::Array(self.caps.iter().map(|c| Cv::Text(c.as_str().into())).collect())));
        if include_sig {
            m.push((8, Cv::Bytes(self.sig.clone())));
        }
        Cv::Map(m)
    }

    /// The exact wire bytes of this cert: §18-canonical integer-keyed CBOR.
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(true))
    }

    /// The §18.9.3 signing body: deterministic CBOR of the cert with `sig` (key 8) omitted.
    fn signing_body(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(false))
    }

    /// Decode a cert from its canonical CBOR (§18.4.2), failing closed on any violation.
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, IdentityError> {
        Ok(Self::from_cv(cbor::decode(bytes)?)?)
    }

    fn from_cv(cv: Cv) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cv)?;
        let suite = suite_from_cv(f.req(1)?)?;
        let ik = as_bytes(f.req(2)?)?;
        let device_key = as_bytes(f.req(3)?)?;
        let label = as_text(f.req(4)?)?;
        let created = as_u64(f.req(5)?)?;
        let expires = f.take(6).map(as_u64).transpose()?;
        let caps = as_array(f.req(7)?)?
            .into_iter()
            .map(|c| Cap::from_str(&as_text(c)?))
            .collect::<Result<_, _>>()?;
        let sig = as_bytes(f.req(8)?)?;
        f.deny_unknown()?;
        Ok(DeviceCert { suite, ik, device_key, label, created, expires, caps, sig })
    }

    /// Issue a device cert: `IK` signs the (suite, ik, device_key, label, …) tuple (§18.9.3).
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        ik: &IdentityKey,
        device_key: Vec<u8>,
        label: impl Into<String>,
        created: TimestampMs,
        expires: Option<TimestampMs>,
        caps: Vec<Cap>,
    ) -> DeviceCert {
        let mut cert = DeviceCert {
            suite: Suite::Classical,
            ik: ik.public(),
            device_key,
            label: label.into(),
            created,
            expires,
            caps,
            sig: Vec::new(),
        };
        cert.sig = ik.sign_domain(DEVICE_CERT_DS, &cert.signing_body());
        cert
    }

    /// Verify the cert's signature under its own `ik` (spec §1.2, §18.9.3).
    pub fn verify(&self) -> Result<(), IdentityError> {
        if !self.suite.is_supported() {
            return Err(IdentityError::UnsupportedSuite(self.suite.as_u8()));
        }
        verify_domain(&self.ik, DEVICE_CERT_DS, &self.signing_body(), &self.sig)
    }
}

// --- The published Identity object ---------------------------------------------------------

/// The current public identity (spec §1.3) — a signed, versioned object whose hash is the
/// anchor everyone pins. `suites` is a preference-ordered *set*; `iks` maps each suite to its
/// public key; `sig` carries one signature per suite (multi-suite, §1.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub suites: Vec<Suite>,          // key 1 — supported suites, preference-ordered (a set)
    pub iks: BTreeMap<u8, Vec<u8>>,  // key 2 — identity public key per suite
    pub version: u64,                // key 3 — monotonically increasing
    pub devices: Vec<DeviceCert>,    // key 4
    pub keypkgs: KeyPackageBundleRef, // key 5 — current KeyPackage bundle (§18.4.3)
    pub recovery: ContentId,         // key 6 — hash of the current RecoveryPolicy (§1.4)
    pub names: Vec<String>,          // key 7 — canonical human name(s) (§3)
    pub prev: Option<ContentId>,     // key 8 — hash of the previous Identity version (hash chain)
    pub ts: TimestampMs,             // key 9
    #[serde(default)]
    pub sig: Vec<Vec<u8>>, // key 10 — one signature per suite in `suites`, over the body
}

impl Identity {
    /// Integer-keyed canonical map (§18.4.1). `include_sig=false` omits key 10 for the §18.9.3
    /// signing body (the same body is signed once per suite in `suites`).
    fn to_cv(&self, include_sig: bool) -> Cv {
        let mut m = vec![
            (1u64, Cv::Array(self.suites.iter().map(|s| Cv::U64(s.as_u8() as u64)).collect())),
            (
                2,
                Cv::Map(
                    self.iks
                        .iter()
                        .map(|(k, v)| (*k as u64, Cv::Bytes(v.clone())))
                        .collect(),
                ),
            ),
            (3, Cv::U64(self.version)),
            (4, Cv::Array(self.devices.iter().map(|d| d.to_cv(true)).collect())),
            (5, self.keypkgs.to_cv()),
            (6, hash_cv(&self.recovery)),
            (7, Cv::Array(self.names.iter().map(|n| Cv::Text(n.clone())).collect())),
        ];
        if let Some(p) = &self.prev {
            m.push((8, hash_cv(p)));
        }
        m.push((9, Cv::U64(self.ts)));
        if include_sig {
            m.push((10, Cv::Array(self.sig.iter().map(|s| Cv::Bytes(s.clone())).collect())));
        }
        Cv::Map(m)
    }

    /// The §18.9.3 signing body: deterministic CBOR of the identity with `sig` (key 10) omitted.
    fn signing_body(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(false))
    }

    /// The exact wire bytes of this identity: §18-canonical integer-keyed CBOR.
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(true))
    }

    /// Decode an identity from its canonical CBOR (§18.4.1), failing closed on any violation.
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, IdentityError> {
        Ok(Self::from_cv(cbor::decode(bytes)?)?)
    }

    fn from_cv(cv: Cv) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cv)?;
        let suites = as_array(f.req(1)?)?
            .into_iter()
            .map(suite_from_cv)
            .collect::<Result<_, _>>()?;
        let iks = {
            let inner = Fields::from_cv(f.req(2)?)?;
            let mut map = BTreeMap::new();
            for (k, v) in inner.into_pairs() {
                let key = u8::try_from(k).map_err(|_| CborError::IntRange)?;
                map.insert(key, as_bytes(v)?);
            }
            map
        };
        let version = as_u64(f.req(3)?)?;
        let devices = as_array(f.req(4)?)?
            .into_iter()
            .map(DeviceCert::from_cv)
            .collect::<Result<_, _>>()?;
        let keypkgs = KeyPackageBundleRef::from_cv(f.req(5)?)?;
        let recovery = ContentId(as_bytes(f.req(6)?)?);
        let names = as_array(f.req(7)?)?
            .into_iter()
            .map(as_text)
            .collect::<Result<_, _>>()?;
        let prev = f.take(8).map(as_bytes).transpose()?.map(ContentId);
        let ts = as_u64(f.req(9)?)?;
        let sig = as_array(f.req(10)?)?
            .into_iter()
            .map(as_bytes)
            .collect::<Result<_, _>>()?;
        f.deny_unknown()?;
        Ok(Identity { suites, iks, version, devices, keypkgs, recovery, names, prev, ts, sig })
    }

    /// Build and sign a single-suite (classical) `Identity` (spec §1.3). This is the v0 path;
    /// multi-suite objects are constructed by adding more `(suite, key)` entries and one
    /// signature per suite, which the PQ suite would populate once implemented.
    #[allow(clippy::too_many_arguments)]
    pub fn create_classical(
        ik: &IdentityKey,
        version: u64,
        devices: Vec<DeviceCert>,
        keypkgs: KeyPackageBundleRef,
        recovery: ContentId,
        names: Vec<String>,
        prev: Option<ContentId>,
        ts: TimestampMs,
    ) -> Identity {
        let mut iks = BTreeMap::new();
        iks.insert(Suite::Classical.as_u8(), ik.public());
        let mut id = Identity {
            suites: vec![Suite::Classical],
            iks,
            version,
            devices,
            keypkgs,
            recovery,
            names,
            prev,
            ts,
            sig: Vec::new(),
        };
        id.sig = vec![ik.sign_domain(IDENTITY_DS, &id.signing_body())];
        id
    }

    /// Content address of this identity (spec §18.9.4) — the value contacts pin (§3.4):
    /// `0x1e ‖ BLAKE3-256(det_cbor(Identity))` over the complete, signed object.
    pub fn content_id(&self) -> ContentId {
        ContentId::of(&self.det_cbor())
    }

    /// Verify the identity (spec §1.3, §3.4):
    ///
    /// 1. Every suite in `suites` must have a key in `iks` and an index-aligned entry in `sig`.
    /// 2. **Fail closed** on any suite the implementation cannot validate — the reference core
    ///    only validates `0x01`, so a `0x02`-bearing identity is rejected rather than
    ///    silently downgraded (§1.3).
    /// 3. Each signature must verify under the corresponding suite key.
    /// 4. Hash-chain sanity: `version == 0` ⇒ no `prev`; `version > 0` ⇒ `prev` present, and if
    ///    a `pinned` previous-version id is supplied it must equal `prev` (§1.3, §3.4).
    pub fn verify(&self, pinned: Option<&ContentId>) -> Result<(), IdentityError> {
        if self.suites.is_empty() {
            return Err(IdentityError::Malformed("empty suite set"));
        }
        if self.sig.len() != self.suites.len() {
            return Err(IdentityError::Malformed("sig count != suite count"));
        }
        let signing_body = self.signing_body();
        for (i, suite) in self.suites.iter().enumerate() {
            // Fail closed on any suite we cannot validate (no silent downgrade, §1.3).
            if !suite.is_supported() {
                return Err(IdentityError::UnsupportedSuite(suite.as_u8()));
            }
            let key = self
                .iks
                .get(&suite.as_u8())
                .ok_or(IdentityError::Malformed("missing key for a declared suite"))?;
            verify_domain(key, IDENTITY_DS, &signing_body, &self.sig[i])?;
        }
        // Hash-chain sanity.
        match (self.version, &self.prev) {
            (0, Some(_)) => return Err(IdentityError::BrokenChain),
            (v, None) if v > 0 => return Err(IdentityError::BrokenChain),
            _ => {}
        }
        if let (Some(p), Some(prev)) = (pinned, &self.prev) {
            if p != prev {
                return Err(IdentityError::BrokenChain);
            }
        }
        Ok(())
    }
}

// --- Recovery policy (§1.4) ----------------------------------------------------------------

/// A recovery method (spec §1.4, §18.4.4). A tagged choice; key `0` is the variant discriminator.
/// Rotating a method out MUST re-key the underlying secret; this type only carries the
/// *published* material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryMethod {
    /// `PhraseMethod` (disc 1): key derived from a SLIP-0039 mnemonic.
    Phrase { recovery_key: Vec<u8> },
    /// `DeviceMethod` (disc 2): a device signing key + label.
    Device { device_key: Vec<u8>, label: String },
    /// `SocialMethod` (disc 3): guardian keys + M-of-N threshold. Prefer FROST (RFC 9591).
    Social { guardians: Vec<Vec<u8>>, threshold: u8 },
}

impl RecoveryMethod {
    fn to_cv(&self) -> Cv {
        match self {
            RecoveryMethod::Phrase { recovery_key } => {
                Cv::Map(vec![(0, Cv::U64(1)), (1, Cv::Bytes(recovery_key.clone()))])
            }
            RecoveryMethod::Device { device_key, label } => Cv::Map(vec![
                (0, Cv::U64(2)),
                (1, Cv::Bytes(device_key.clone())),
                (2, Cv::Text(label.clone())),
            ]),
            RecoveryMethod::Social { guardians, threshold } => Cv::Map(vec![
                (0, Cv::U64(3)),
                (1, Cv::Array(guardians.iter().map(|g| Cv::Bytes(g.clone())).collect())),
                (2, Cv::U64(*threshold as u64)),
            ]),
        }
    }

    fn from_cv(cv: Cv) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cv)?;
        let disc = as_u64(f.req(0)?)?;
        let out = match disc {
            1 => RecoveryMethod::Phrase { recovery_key: as_bytes(f.req(1)?)? },
            2 => RecoveryMethod::Device {
                device_key: as_bytes(f.req(1)?)?,
                label: as_text(f.req(2)?)?,
            },
            3 => RecoveryMethod::Social {
                guardians: as_array(f.req(1)?)?
                    .into_iter()
                    .map(as_bytes)
                    .collect::<Result<_, _>>()?,
                threshold: as_u8(f.req(2)?)?,
            },
            other => return Err(CborError::UnknownDiscriminant(other)),
        };
        f.deny_unknown()?;
        Ok(out)
    }
}

/// A threshold predicate over recovery methods (e.g. "1 phrase OR 2 devices OR 2 guardians").
/// Encoded as `{ 1 => [+ MethodPredicate] }` (§18.4.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Threshold {
    pub any_of: Vec<MethodPredicate>,
}

impl Threshold {
    fn to_cv(&self) -> Cv {
        Cv::Map(vec![(1, Cv::Array(self.any_of.iter().map(MethodPredicate::to_cv).collect()))])
    }

    fn from_cv(cv: Cv) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cv)?;
        let any_of = as_array(f.req(1)?)?
            .into_iter()
            .map(MethodPredicate::from_cv)
            .collect::<Result<_, _>>()?;
        f.deny_unknown()?;
        Ok(Threshold { any_of })
    }
}

/// One `MethodPredicate` (§18.4.4): `{ 1 => method-type, 2 => count }`, where `method-type` is
/// one of `"phrase"`/`"device"`/`"social"`/`"ik"` (mapping §1.4's `Phrase`/`Devices(n)`/
/// `Guardians(n)`/`Ik`). `"phrase"` and `"ik"` carry count `1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MethodPredicate {
    Phrase,
    Devices(u8),
    Guardians(u8),
    Ik,
}

impl MethodPredicate {
    fn to_cv(&self) -> Cv {
        let (method, count) = match self {
            MethodPredicate::Phrase => ("phrase", 1u64),
            MethodPredicate::Devices(n) => ("device", *n as u64),
            MethodPredicate::Guardians(n) => ("social", *n as u64),
            MethodPredicate::Ik => ("ik", 1),
        };
        Cv::Map(vec![(1, Cv::Text(method.into())), (2, Cv::U64(count))])
    }

    fn from_cv(cv: Cv) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cv)?;
        let method = as_text(f.req(1)?)?;
        let count = as_u64(f.req(2)?)?;
        f.deny_unknown()?;
        let n = u8::try_from(count).map_err(|_| CborError::IntRange)?;
        Ok(match method.as_str() {
            "phrase" => MethodPredicate::Phrase,
            "device" => MethodPredicate::Devices(n),
            "social" => MethodPredicate::Guardians(n),
            "ik" => MethodPredicate::Ik,
            _ => return Err(CborError::TypeMismatch),
        })
    }
}

/// The recovery policy (spec §1.4). Invariant: `rotate_threshold` MUST be at least as strong as
/// `recover_threshold`, so no single compromised factor can rewrite the policy and lock the
/// owner out (§1.4 rule 2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryPolicy {
    pub suite: Suite,
    pub ik: Vec<u8>,
    pub version: u64,
    pub methods: Vec<RecoveryMethod>,
    pub recover_threshold: Threshold,
    pub rotate_threshold: Threshold,
    pub prev: Option<ContentId>,
    pub ts: TimestampMs,
    #[serde(default)]
    pub sig: Vec<u8>, // by IK, or by a satisfied rotate_threshold quorum (reactive)
}

impl RecoveryPolicy {
    /// Integer-keyed canonical map (§18.4.4). `include_sig=false` omits key 9 for the §18.9.3
    /// signing body.
    fn to_cv(&self, include_sig: bool) -> Cv {
        let mut m = vec![
            (1u64, Cv::U64(self.suite.as_u8() as u64)),
            (2, Cv::Bytes(self.ik.clone())),
            (3, Cv::U64(self.version)),
            (4, Cv::Array(self.methods.iter().map(RecoveryMethod::to_cv).collect())),
            (5, self.recover_threshold.to_cv()),
            (6, self.rotate_threshold.to_cv()),
        ];
        if let Some(p) = &self.prev {
            m.push((7, hash_cv(p)));
        }
        m.push((8, Cv::U64(self.ts)));
        if include_sig {
            m.push((9, Cv::Bytes(self.sig.clone())));
        }
        Cv::Map(m)
    }

    /// The §18.9.3 signing body: deterministic CBOR of the policy with `sig` (key 9) omitted.
    fn signing_body(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(false))
    }

    /// The exact wire bytes of this policy: §18-canonical integer-keyed CBOR.
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(true))
    }

    /// Decode a policy from its canonical CBOR (§18.4.4), failing closed on any violation.
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, IdentityError> {
        let mut f = Fields::from_cv(cbor::decode(bytes)?)?;
        let suite = suite_from_cv(f.req(1)?)?;
        let ik = as_bytes(f.req(2)?)?;
        let version = as_u64(f.req(3)?)?;
        let methods = as_array(f.req(4)?)?
            .into_iter()
            .map(RecoveryMethod::from_cv)
            .collect::<Result<_, _>>()?;
        let recover_threshold = Threshold::from_cv(f.req(5)?)?;
        let rotate_threshold = Threshold::from_cv(f.req(6)?)?;
        let prev = f.take(7).map(as_bytes).transpose()?.map(ContentId);
        let ts = as_u64(f.req(8)?)?;
        let sig = as_bytes(f.req(9)?)?;
        f.deny_unknown()?;
        Ok(RecoveryPolicy {
            suite,
            ik,
            version,
            methods,
            recover_threshold,
            rotate_threshold,
            prev,
            ts,
            sig,
        })
    }

    /// Sign a policy version proactively with `IK` (spec §1.4 "proactive rotation", §18.9.3).
    pub fn sign(&mut self, ik: &IdentityKey) {
        self.sig = ik.sign_domain(RECOVERY_POLICY_DS, &self.signing_body());
    }

    /// Verify the policy signature under `ik`. Does not itself evaluate the (reactive) quorum
    /// path — that lives in the recovery flow (§1.4). Also fails closed if the structural
    /// invariant `rotate_threshold ⊇ recover_threshold` is obviously violated (empty rotate).
    pub fn verify(&self) -> Result<(), IdentityError> {
        if !self.suite.is_supported() {
            return Err(IdentityError::UnsupportedSuite(self.suite.as_u8()));
        }
        if self.rotate_threshold.any_of.is_empty() {
            return Err(IdentityError::Malformed("rotate_threshold must not be empty"));
        }
        verify_domain(&self.ik, RECOVERY_POLICY_DS, &self.signing_body(), &self.sig)
    }

    /// Content address of this policy version (`0x1e ‖ BLAKE3-256(det_cbor(policy))`) — the value a
    /// guardian counter-signs when approving or vetoing a change (see [`authorize_recovery_change`]).
    pub fn content_id(&self) -> ContentId {
        ContentId::of(&self.det_cbor())
    }
}

// --- Recovery-weakening quorum + 72h asymmetric veto (§1.4 rules 3–4, §16.8) ---------------

/// §16 recovery-weakening **asymmetric veto window**: 72 hours, in milliseconds. A factor-weakening
/// change MUST be published and take effect only after this window elapses with no valid veto.
pub const RECOVERY_VETO_WINDOW_MS: u64 = 72 * 60 * 60 * 1000;

/// DS tag a guardian signs to **approve** a recovery-weakening change (over the next policy's
/// content-address).
const RECOVERY_APPROVAL_DS: &[u8] = b"DMTAP-v0/recovery-approval\x00";
/// DS tag a guardian signs to **veto** a recovery-weakening change (over the next policy's
/// content-address).
const RECOVERY_VETO_DS: &[u8] = b"DMTAP-v0/recovery-veto\x00";

/// A recovery-weakening guard failure, each carrying its §21.3 code via [`RecoveryGuardError::code`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RecoveryGuardError {
    /// A change that removes/weakens a recovery factor is signed by `IK` alone without satisfying
    /// `rotate_threshold` — the stolen-`IK` takeover defense (§1.4 rule 3).
    /// `ERR_RECOVERY_WEAKENING_UNQUORUMED` (`0x010E`), FAIL_CLOSED_BLOCK + HALT_ALERT.
    #[error("recovery-weakening change lacks the rotate_threshold quorum — IK alone must not weaken \
             recovery (ERR_RECOVERY_WEAKENING_UNQUORUMED, 0x010E)")]
    WeakeningUnquorumed,
    /// A factor-weakening change attempts to take effect before its 72 h veto/delay window elapses
    /// (§1.4 rule 4, §16.8). `ERR_RECOVERY_VETO_WINDOW` (`0x010F`), FAIL_CLOSED_BLOCK — hold until
    /// the window elapses.
    #[error("recovery-weakening change is inside its 72h veto window \
             (ERR_RECOVERY_VETO_WINDOW, 0x010F)")]
    VetoWindowActive,
    /// A `rotate_threshold`-backed veto counter-signature aborted the change (§1.4 rule 4). Same
    /// wire code as the window hold: `ERR_RECOVERY_VETO_WINDOW` (`0x010F`).
    #[error("recovery-weakening change was vetoed by a rotate_threshold-backed quorum \
             (ERR_RECOVERY_VETO_WINDOW, 0x010F)")]
    Vetoed,
}

impl RecoveryGuardError {
    /// The normative DMTAP wire error code (§21.3).
    pub fn code(&self) -> u16 {
        match self {
            RecoveryGuardError::WeakeningUnquorumed => 0x010E,
            RecoveryGuardError::VetoWindowActive | RecoveryGuardError::Vetoed => 0x010F,
        }
    }
}

/// A guardian's counter-signature over a proposed recovery-policy change — used both for an
/// **approval** ([`sign_recovery_approval`]) and a **veto** ([`sign_recovery_veto`]), distinguished
/// by domain-separation tag. `guardian` is the guardian's public key; `sig` covers the next
/// policy's content-address under the relevant DS tag (§18.9.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardianApproval {
    pub guardian: Vec<u8>,
    pub sig: Vec<u8>,
}

/// Produce a guardian's **approval** counter-signature for the proposed `next` policy.
pub fn sign_recovery_approval(guardian: &IdentityKey, next: &RecoveryPolicy) -> GuardianApproval {
    GuardianApproval {
        guardian: guardian.public(),
        sig: guardian.sign_domain(RECOVERY_APPROVAL_DS, next.content_id().as_bytes()),
    }
}

/// Produce a guardian's **veto** counter-signature for the proposed `next` policy.
pub fn sign_recovery_veto(guardian: &IdentityKey, next: &RecoveryPolicy) -> GuardianApproval {
    GuardianApproval {
        guardian: guardian.public(),
        sig: guardian.sign_domain(RECOVERY_VETO_DS, next.content_id().as_bytes()),
    }
}

/// Count **distinct, recognized** guardians whose counter-signature (under `ds`, over `preimage`)
/// verifies. Signatures from non-guardians or duplicates do not count — a minority/forged set
/// cannot inflate the quorum.
fn count_quorum(
    guardians: &[Vec<u8>],
    sigs: &[GuardianApproval],
    ds: &[u8],
    preimage: &[u8],
) -> usize {
    let mut counted: Vec<&[u8]> = Vec::new();
    for s in sigs {
        if !guardians.iter().any(|g| g.as_slice() == s.guardian.as_slice()) {
            continue; // not a recognized guardian
        }
        if counted.iter().any(|c| *c == s.guardian.as_slice()) {
            continue; // already counted this guardian
        }
        if verify_domain(&s.guardian, ds, preimage, &s.sig).is_ok() {
            counted.push(&s.guardian);
        }
    }
    counted.len()
}

fn predicate_count(p: &MethodPredicate) -> u32 {
    match p {
        MethodPredicate::Phrase | MethodPredicate::Ik => 1,
        MethodPredicate::Devices(n) | MethodPredicate::Guardians(n) => *n as u32,
    }
}

/// The **minimum** bar of a threshold: `any_of` is a disjunction (OR), so the easiest predicate
/// defines the effective bar. A lower minimum is a weaker threshold. An empty threshold (rejected
/// elsewhere by [`RecoveryPolicy::verify`]) yields `0`.
fn threshold_min(t: &Threshold) -> u32 {
    t.any_of.iter().map(predicate_count).min().unwrap_or(0)
}

/// Whether `cand` is at least as strong a recovery method as `prev` (same kind, not narrowed).
fn method_at_least_as_strong(prev: &RecoveryMethod, cand: &RecoveryMethod) -> bool {
    use RecoveryMethod::*;
    match (prev, cand) {
        // A change to a factor's **key material** is a removal of the old secret, not a
        // like-for-like carry-over: a stolen-IK holder must not be able to swap a factor's
        // key to their own material silently. Compare the actual material, not just the label.
        (Phrase { recovery_key: a }, Phrase { recovery_key: b }) => a == b,
        (Device { label: la, device_key: ka }, Device { label: lb, device_key: kb }) => {
            la == lb && ka == kb
        }
        (Social { guardians: pg, threshold: pt }, Social { guardians: cg, threshold: ct }) => {
            ct >= pt && pg.iter().all(|g| cg.contains(g))
        }
        _ => false,
    }
}

/// Whether the change **weakens** recovery (spec §1.4 rule 3): a method dropped or narrowed (a
/// guardian/device evicted, a Social threshold lowered), or either threshold's minimum bar lowered.
///
/// Additive, non-weakening changes (adding a redundant factor, raising a bar) return `false` and
/// MAY be signed by `IK` alone without the guardian quorum or the veto delay.
///
/// This is a conservative structural detector: it flags every removal or threshold reduction,
/// **including a guardian-set swap** — replacing any guardian (even at an unchanged M-of-N count)
/// fails [`method_at_least_as_strong`]'s subset test, so a swapped-in attacker guardian cannot slip
/// through as "not weakening". Purely additive changes (adding a redundant factor or an extra
/// guardian at the same threshold, or *raising* a bar) are correctly **not** flagged, so benign
/// hardening still travels the fast path. It does **not** attempt to model the §1.4 rule 5
/// *cryptographic* re-key/resharing obligation (that a rotated-out secret is actually re-keyed) —
/// that is a key-management concern outside this deterministic core; see the crate docs.
pub fn recovery_change_is_weakening(prev: &RecoveryPolicy, next: &RecoveryPolicy) -> bool {
    let methods_weakened = prev
        .methods
        .iter()
        .any(|pm| !next.methods.iter().any(|nm| method_at_least_as_strong(pm, nm)));
    methods_weakened
        || threshold_min(&next.recover_threshold) < threshold_min(&prev.recover_threshold)
        || threshold_min(&next.rotate_threshold) < threshold_min(&prev.rotate_threshold)
}

/// Authorize a recovery-policy change under the §1.4 rules 3–4 / §16.8 weakening guard. Clock and
/// veto-window are **explicit parameters** — this core never reads a wall clock (§16.1).
///
/// A **non-weakening** change ([`recovery_change_is_weakening`] `== false`) is permitted immediately
/// (`Ok`) — `IK` alone may sign an additive change with no delay (§1.4 rule 3).
///
/// A **weakening** change is fail-closed unless, in order:
/// 1. it satisfies the `rotate_threshold` guardian quorum — a strict `> n/2` majority of `guardians`
///    supply a valid [`sign_recovery_approval`] over `next` — else
///    [`WeakeningUnquorumed`](RecoveryGuardError::WeakeningUnquorumed) (`0x010E`); `IK` alone is
///    never sufficient (stolen-`IK` defense);
/// 2. no `rotate_threshold`-backed veto (a strict `> n/2` majority supplying a valid
///    [`sign_recovery_veto`]) is present — else [`Vetoed`](RecoveryGuardError::Vetoed) (`0x010F`);
///    the veto is deliberately quorum-gated so a single not-yet-removed factor cannot block its own
///    eviction;
/// 3. the 72 h veto window (`announced_at + `[`RECOVERY_VETO_WINDOW_MS`]) has elapsed at `now` —
///    else [`VetoWindowActive`](RecoveryGuardError::VetoWindowActive) (`0x010F`); a weakening MUST
///    NOT take effect instantly.
#[allow(clippy::too_many_arguments)]
pub fn authorize_recovery_change(
    prev: &RecoveryPolicy,
    next: &RecoveryPolicy,
    guardians: &[Vec<u8>],
    approvals: &[GuardianApproval],
    vetoes: &[GuardianApproval],
    announced_at: TimestampMs,
    now: TimestampMs,
) -> Result<(), RecoveryGuardError> {
    if !recovery_change_is_weakening(prev, next) {
        return Ok(());
    }
    let n = guardians.len();
    let preimage = next.content_id();
    // Rule 3: weakening needs the rotate_threshold quorum (> n/2), even signed by IK.
    let approve_q = count_quorum(guardians, approvals, RECOVERY_APPROVAL_DS, preimage.as_bytes());
    if approve_q * 2 <= n {
        return Err(RecoveryGuardError::WeakeningUnquorumed);
    }
    // Rule 4: a rotate_threshold-backed veto aborts the change (asymmetric — a single factor cannot).
    let veto_q = count_quorum(guardians, vetoes, RECOVERY_VETO_DS, preimage.as_bytes());
    if veto_q * 2 > n {
        return Err(RecoveryGuardError::Vetoed);
    }
    // Rule 4: hold until the 72h veto window elapses.
    if now < announced_at.saturating_add(RECOVERY_VETO_WINDOW_MS) {
        return Err(RecoveryGuardError::VetoWindowActive);
    }
    Ok(())
}

// --- Name migration (§1.6) -----------------------------------------------------------------

/// Rebinds the human name while preserving the key (spec §1.6). Contacts route by key and
/// verify this against `IK`, so they follow automatically and cannot be redirected by a forgery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoveRecord {
    pub suite: Suite,
    pub ik: Vec<u8>,
    pub from: String,
    pub to: String,
    pub ts: TimestampMs,
    pub prev: Option<ContentId>,
    #[serde(default)]
    pub sig: Vec<u8>, // by IK
}

impl MoveRecord {
    /// Integer-keyed canonical map (§18.4.6). `include_sig=false` omits key 7 for the §18.9.3
    /// signing body.
    fn to_cv(&self, include_sig: bool) -> Cv {
        let mut m = vec![
            (1u64, Cv::U64(self.suite.as_u8() as u64)),
            (2, Cv::Bytes(self.ik.clone())),
            (3, Cv::Text(self.from.clone())),
            (4, Cv::Text(self.to.clone())),
            (5, Cv::U64(self.ts)),
        ];
        if let Some(p) = &self.prev {
            m.push((6, hash_cv(p)));
        }
        if include_sig {
            m.push((7, Cv::Bytes(self.sig.clone())));
        }
        Cv::Map(m)
    }

    /// The §18.9.3 signing body: deterministic CBOR of the record with `sig` (key 7) omitted.
    fn signing_body(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(false))
    }

    /// The exact wire bytes of this record: §18-canonical integer-keyed CBOR.
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(true))
    }

    /// Decode a record from its canonical CBOR (§18.4.6), failing closed on any violation.
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, IdentityError> {
        let mut f = Fields::from_cv(cbor::decode(bytes)?)?;
        let suite = suite_from_cv(f.req(1)?)?;
        let ik = as_bytes(f.req(2)?)?;
        let from = as_text(f.req(3)?)?;
        let to = as_text(f.req(4)?)?;
        let ts = as_u64(f.req(5)?)?;
        let prev = f.take(6).map(as_bytes).transpose()?.map(ContentId);
        let sig = as_bytes(f.req(7)?)?;
        f.deny_unknown()?;
        Ok(MoveRecord { suite, ik, from, to, ts, prev, sig })
    }

    /// Create a signed MoveRecord (spec §1.6, §18.9.3).
    pub fn create(
        ik: &IdentityKey,
        from: impl Into<String>,
        to: impl Into<String>,
        ts: TimestampMs,
        prev: Option<ContentId>,
    ) -> MoveRecord {
        let mut m = MoveRecord {
            suite: Suite::Classical,
            ik: ik.public(),
            from: from.into(),
            to: to.into(),
            ts,
            prev,
            sig: Vec::new(),
        };
        m.sig = ik.sign_domain(MOVE_RECORD_DS, &m.signing_body());
        m
    }

    /// Verify the record is signed by its declared `IK` (spec §1.6, §18.9.3).
    pub fn verify(&self) -> Result<(), IdentityError> {
        if !self.suite.is_supported() {
            return Err(IdentityError::UnsupportedSuite(self.suite.as_u8()));
        }
        verify_domain(&self.ik, MOVE_RECORD_DS, &self.signing_body(), &self.sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cid(b: &[u8]) -> ContentId {
        ContentId::of(b)
    }

    fn bundle(b: &[u8]) -> KeyPackageBundleRef {
        KeyPackageBundleRef::new("/mesh/keypkgs", ContentId::of(b))
    }

    #[test]
    fn identity_signs_and_verifies() {
        let ik = IdentityKey::generate();
        let id = Identity::create_classical(
            &ik,
            0,
            vec![],
            bundle(b"keypkgs"),
            cid(b"recovery"),
            vec!["alice@example.com".into()],
            None,
            1_700_000_000_000,
        );
        assert!(id.verify(None).is_ok(), "a freshly signed identity must verify");
        // Canonical round-trip preserves everything and re-encodes byte-identically.
        let bytes = id.det_cbor();
        let back = Identity::from_det_cbor(&bytes).unwrap();
        assert_eq!(id, back);
        assert_eq!(bytes, back.det_cbor());
    }

    #[test]
    fn tampered_identity_fails_signature() {
        let ik = IdentityKey::generate();
        let mut id = Identity::create_classical(
            &ik,
            0,
            vec![],
            bundle(b"kp"),
            cid(b"rec"),
            vec!["a@b.com".into()],
            None,
            1,
        );
        // Tamper with a signed field; the signature must no longer verify.
        id.names.push("evil@attacker.com".into());
        assert_eq!(id.verify(None), Err(IdentityError::BadSignature));
    }

    #[test]
    fn pq_only_identity_fails_closed() {
        // Hand-build a 0x02-only identity; the reference core cannot validate it and MUST
        // reject rather than silently downgrade (§1.3).
        let mut iks = BTreeMap::new();
        iks.insert(Suite::PqHybrid.as_u8(), vec![0u8; 32]);
        let id = Identity {
            suites: vec![Suite::PqHybrid],
            iks,
            version: 0,
            devices: vec![],
            keypkgs: bundle(b"kp"),
            recovery: cid(b"rec"),
            names: vec![],
            prev: None,
            ts: 0,
            sig: vec![vec![0u8; 64]],
        };
        assert_eq!(id.verify(None), Err(IdentityError::UnsupportedSuite(0x02)));
    }

    #[test]
    fn device_cert_roundtrips_and_verifies() {
        let ik = IdentityKey::generate();
        let dev = IdentityKey::generate();
        let cert = DeviceCert::issue(
            &ik,
            dev.public(),
            "home-box",
            1,
            None,
            vec![Cap::Send, Cap::Recv, Cap::Relay],
        );
        assert!(cert.verify().is_ok());

        // Canonical CBOR round-trip: integer-keyed, byte-identical re-encode.
        let buf = cert.det_cbor();
        assert_eq!(buf[0] & 0xe0, 0xa0, "cert is a CBOR map");
        assert_eq!(buf[1], 0x01, "first key is integer 1 (suite), not a text key");
        let back = DeviceCert::from_det_cbor(&buf).unwrap();
        assert_eq!(cert, back);
        assert!(back.verify().is_ok());

        // A forged cert (wrong IK) must fail.
        let mut forged = cert.clone();
        forged.ik = dev.public();
        assert_eq!(forged.verify(), Err(IdentityError::BadSignature));
    }

    #[test]
    fn recovery_policy_and_move_record_sign_verify() {
        let ik = IdentityKey::generate();
        let mut policy = RecoveryPolicy {
            suite: Suite::Classical,
            ik: ik.public(),
            version: 1,
            methods: vec![RecoveryMethod::Phrase { recovery_key: vec![1, 2, 3] }],
            recover_threshold: Threshold { any_of: vec![MethodPredicate::Phrase] },
            rotate_threshold: Threshold {
                any_of: vec![MethodPredicate::Ik, MethodPredicate::Guardians(2)],
            },
            prev: None,
            ts: 1,
            sig: vec![],
        };
        policy.sign(&ik);
        assert!(policy.verify().is_ok());
        assert_eq!(RecoveryPolicy::from_det_cbor(&policy.det_cbor()).unwrap(), policy);

        let mv = MoveRecord::create(&ik, "a@old.com", "a@new.com", 2, None);
        assert!(mv.verify().is_ok());
        assert_eq!(MoveRecord::from_det_cbor(&mv.det_cbor()).unwrap(), mv);
        let mut forged = mv.clone();
        forged.to = "a@evil.com".into();
        assert_eq!(forged.verify(), Err(IdentityError::BadSignature));
    }

    fn policy(ik: &IdentityKey, methods: Vec<RecoveryMethod>, recover: Threshold, rotate: Threshold, ver: u64) -> RecoveryPolicy {
        let mut p = RecoveryPolicy {
            suite: Suite::Classical,
            ik: ik.public(),
            version: ver,
            methods,
            recover_threshold: recover,
            rotate_threshold: rotate,
            prev: None,
            ts: ver,
            sig: vec![],
        };
        p.sign(ik);
        p
    }

    #[test]
    fn additive_change_needs_no_quorum_or_delay() {
        let ik = IdentityKey::generate();
        let prev = policy(
            &ik,
            vec![RecoveryMethod::Phrase { recovery_key: vec![1] }],
            Threshold { any_of: vec![MethodPredicate::Phrase] },
            Threshold { any_of: vec![MethodPredicate::Ik, MethodPredicate::Guardians(2)] },
            1,
        );
        // Adds a redundant device method — strictly additive, not a weakening.
        let next = policy(
            &ik,
            vec![
                RecoveryMethod::Phrase { recovery_key: vec![1] },
                RecoveryMethod::Device { device_key: vec![9; 32], label: "phone".into() },
            ],
            Threshold { any_of: vec![MethodPredicate::Phrase] },
            Threshold { any_of: vec![MethodPredicate::Ik, MethodPredicate::Guardians(2)] },
            2,
        );
        assert!(!recovery_change_is_weakening(&prev, &next));
        // Even with no guardians, no approvals, and now == announced (window not elapsed): OK.
        assert!(authorize_recovery_change(&prev, &next, &[], &[], &[], 0, 0).is_ok());
    }

    #[test]
    fn guardian_set_swap_and_threshold_drop_are_weakening_but_additions_are_not() {
        let ik = IdentityKey::generate();
        let g: Vec<Vec<u8>> = (0..4u8).map(|s| IdentityKey::from_seed(&[s; 32]).public()).collect();
        let base = |social: RecoveryMethod, ver: u64| {
            policy(
                &ik,
                vec![social],
                Threshold { any_of: vec![MethodPredicate::Guardians(2)] },
                Threshold { any_of: vec![MethodPredicate::Guardians(2)] },
                ver,
            )
        };
        let prev = base(RecoveryMethod::Social { guardians: g[..3].to_vec(), threshold: 2 }, 1);

        // Swap one guardian out for a fresh (possibly attacker-controlled) key at the SAME 2-of-3
        // count: still a weakening — an evicted guardian is a removed factor.
        let swapped = base(
            RecoveryMethod::Social {
                guardians: vec![g[0].clone(), g[1].clone(), g[3].clone()],
                threshold: 2,
            },
            2,
        );
        assert!(recovery_change_is_weakening(&prev, &swapped), "guardian swap must be weakening");

        // Lower the M-of-N threshold on the same guardian set: weakening.
        let lowered = base(RecoveryMethod::Social { guardians: g[..3].to_vec(), threshold: 1 }, 3);
        assert!(recovery_change_is_weakening(&prev, &lowered), "threshold drop must be weakening");

        // Add a guardian while keeping the 2-of-N count (2-of-3 → 2-of-4): purely additive, the
        // collusion bar M is unchanged — must NOT be flagged (no false positive on hardening).
        let widened = base(RecoveryMethod::Social { guardians: g[..4].to_vec(), threshold: 2 }, 4);
        assert!(!recovery_change_is_weakening(&prev, &widened), "adding a guardian is not weakening");
    }

    #[test]
    fn swapping_factor_key_material_is_weakening() {
        let ik = IdentityKey::generate();
        let one = |method: RecoveryMethod, ver: u64| {
            policy(
                &ik,
                vec![method],
                Threshold { any_of: vec![MethodPredicate::Phrase] },
                Threshold { any_of: vec![MethodPredicate::Ik] },
                ver,
            )
        };

        // --- Phrase: swapping the recovery_key to attacker material is a removal ⇒ weakening.
        // A stolen-IK holder must NOT be able to re-point a Phrase factor to their own mnemonic
        // silently (no guardian quorum, no 72 h veto). Compare the MATERIAL, not "Phrase == Phrase".
        let prev_phrase = one(RecoveryMethod::Phrase { recovery_key: vec![0xAA; 32] }, 1);
        let swapped_phrase = one(RecoveryMethod::Phrase { recovery_key: vec![0xBB; 32] }, 2);
        assert!(
            recovery_change_is_weakening(&prev_phrase, &swapped_phrase),
            "swapping a Phrase recovery_key must be weakening"
        );
        // A weakening change is gated: IK alone (no guardians/approvals) is refused.
        assert!(matches!(
            authorize_recovery_change(&prev_phrase, &swapped_phrase, &[], &[], &[], 0, 0),
            Err(RecoveryGuardError::WeakeningUnquorumed)
        ));
        // Identical key material is NOT a change ⇒ not weakening (benign re-sign / version bump).
        let same_phrase = one(RecoveryMethod::Phrase { recovery_key: vec![0xAA; 32] }, 3);
        assert!(!recovery_change_is_weakening(&prev_phrase, &same_phrase));

        // --- Device: swapping device_key at the SAME label is a removal ⇒ weakening. The label
        // alone must not carry a factor over a key change (attacker re-binds "phone" to their key).
        let prev_dev = one(RecoveryMethod::Device { device_key: vec![0x11; 32], label: "phone".into() }, 4);
        let swapped_dev = one(RecoveryMethod::Device { device_key: vec![0x22; 32], label: "phone".into() }, 5);
        assert!(
            recovery_change_is_weakening(&prev_dev, &swapped_dev),
            "swapping a Device device_key at the same label must be weakening"
        );
        // Same label AND same key ⇒ not weakening.
        let same_dev = one(RecoveryMethod::Device { device_key: vec![0x11; 32], label: "phone".into() }, 6);
        assert!(!recovery_change_is_weakening(&prev_dev, &same_dev));

        // Adding a second, distinct Device (keeping the original) is purely additive ⇒ not weakening.
        let added = policy(
            &ik,
            vec![
                RecoveryMethod::Device { device_key: vec![0x11; 32], label: "phone".into() },
                RecoveryMethod::Device { device_key: vec![0x33; 32], label: "laptop".into() },
            ],
            Threshold { any_of: vec![MethodPredicate::Phrase] },
            Threshold { any_of: vec![MethodPredicate::Ik] },
            7,
        );
        assert!(!recovery_change_is_weakening(&prev_dev, &added));
    }

    #[test]
    fn weakening_change_is_gated_by_quorum_veto_and_window() {
        let ik = IdentityKey::generate();
        let guardian_keys: Vec<IdentityKey> = (0..5).map(|s| IdentityKey::from_seed(&[s; 32])).collect();
        let guardians: Vec<Vec<u8>> = guardian_keys.iter().map(|g| g.public()).collect();

        let prev = policy(
            &ik,
            vec![
                RecoveryMethod::Phrase { recovery_key: vec![1] },
                RecoveryMethod::Device { device_key: vec![9; 32], label: "phone".into() },
            ],
            Threshold { any_of: vec![MethodPredicate::Guardians(3)] },
            Threshold { any_of: vec![MethodPredicate::Guardians(3)] },
            1,
        );
        // Weakening: drops the device method AND lowers both thresholds to Guardians(1).
        let next = policy(
            &ik,
            vec![RecoveryMethod::Phrase { recovery_key: vec![1] }],
            Threshold { any_of: vec![MethodPredicate::Guardians(1)] },
            Threshold { any_of: vec![MethodPredicate::Guardians(1)] },
            2,
        );
        assert!(recovery_change_is_weakening(&prev, &next));

        let announced = 1_000_000u64;
        let after_window = announced + RECOVERY_VETO_WINDOW_MS;

        // (a) No quorum — even past the window — fails closed 0x010E.
        let e = authorize_recovery_change(&prev, &next, &guardians, &[], &[], announced, after_window).unwrap_err();
        assert_eq!(e, RecoveryGuardError::WeakeningUnquorumed);
        assert_eq!(e.code(), 0x010E);

        // A strict majority (3 of 5) of guardians approve.
        let approvals: Vec<GuardianApproval> =
            guardian_keys[..3].iter().map(|g| sign_recovery_approval(g, &next)).collect();

        // (b) Quorum met but still inside the 72h window — hold, 0x010F.
        let e = authorize_recovery_change(&prev, &next, &guardians, &approvals, &[], announced, announced + 1).unwrap_err();
        assert_eq!(e, RecoveryGuardError::VetoWindowActive);
        assert_eq!(e.code(), 0x010F);

        // (c) Quorum met + a rotate_threshold-backed veto (3 of 5) — aborted, 0x010F.
        let vetoes: Vec<GuardianApproval> =
            guardian_keys[..3].iter().map(|g| sign_recovery_veto(g, &next)).collect();
        let e = authorize_recovery_change(&prev, &next, &guardians, &approvals, &vetoes, announced, after_window).unwrap_err();
        assert_eq!(e, RecoveryGuardError::Vetoed);

        // (d) A single-guardian veto is NOT a quorum veto and cannot block (asymmetric veto).
        let lone_veto = vec![sign_recovery_veto(&guardian_keys[0], &next)];
        assert!(authorize_recovery_change(&prev, &next, &guardians, &approvals, &lone_veto, announced, after_window).is_ok());

        // (e) Quorum met, no veto, window elapsed — the change is finally authorized.
        assert!(authorize_recovery_change(&prev, &next, &guardians, &approvals, &[], announced, after_window).is_ok());

        // Forged approvals from non-guardians do not count toward quorum.
        let outsiders: Vec<GuardianApproval> = (100..103u8)
            .map(|s| sign_recovery_approval(&IdentityKey::from_seed(&[s; 32]), &next))
            .collect();
        assert_eq!(
            authorize_recovery_change(&prev, &next, &guardians, &outsiders, &[], announced, after_window),
            Err(RecoveryGuardError::WeakeningUnquorumed)
        );
    }
}

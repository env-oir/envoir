//! Push wake-signaling objects — spec §4.9, §18.5.5/.6, §18.9.15.
//!
//! Two objects let a node wake a sleeping device without a persistent connection, and without the
//! push relay learning anything:
//!
//! - [`PushSubscription`] — the **signed** registration a device publishes to its own node so the
//!   node can wake it (§4.9.1). Signed by an `IK`-authorized **device key** (§1.2), held only
//!   within the device cluster — never in the DHT, a directory, or a relay.
//! - [`WakePing`] — the **content-free, sender-blind** wake signal (§4.9.1). It carries *only* the
//!   opaque, RFC 8291-sealed "sync now" token — no sender/subject/recipient/content, and no map key
//!   beyond key `1`. It bears **no** DMTAP `sig-val`: its authentication is the RFC 8291 AEAD tag
//!   under the device push key + `auth_secret` (§18.9.15), so the push relay can neither read nor
//!   forge one.
//!
//! ## Wire shapes (§18.5.5/.6)
//! ```text
//! PushSubscription = {
//!   1 => u8 (provider), 2 => tstr (endpoint), 3 => bytes (push_key),
//!   4 => bytes (auth_secret), 5 => ik-pub (device_key), 6 => ts, 7 => sig-val (sig)
//! }
//! WakePing = { 1 => bytes (token) }          ; NO other key permitted
//! ```
//! `PushSubscription.sig` uses DS-tag `DMTAP-v0/push-subscription` over `det_cbor(∖ {7})`
//! (§18.9.15).

use crate::cbor::{self, as_bytes, as_text, as_u64, as_u8, CborError, Cv, Fields};
use crate::identity::{verify_domain, IdentityKey};
use crate::TimestampMs;

/// Domain-separation tag for `PushSubscription.sig` (§18.9.15), ASCII terminated by one `0x00`.
const PUSH_SUBSCRIPTION_DS: &[u8] = b"DMTAP-v0/push-subscription\x00";

/// Push-provider tags (§4.9.3). An unrecognized tag is a capability-negotiation concern (§10.2),
/// **never** a parse failure — [`PushSubscription`] therefore stores `provider` as a raw `u8`.
pub mod provider {
    /// UnifiedPush (open) — key `1`.
    pub const UNIFIED_PUSH: u8 = 1;
    /// Web Push (open, RFC 8030/8291) — key `2`.
    pub const WEB_PUSH: u8 = 2;
    /// Apple Push Notification service — key `3`.
    pub const APNS: u8 = 3;
    /// Firebase Cloud Messaging — key `4`.
    pub const FCM: u8 = 4;
}

/// Errors from the push wake-signaling layer, each carrying its normative §21 wire code (§18.9.15).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PushError {
    /// A `PushSubscription`'s signature does not verify under its claimed `device_key` — the
    /// subscription is not authenticated to the identity (`ERR_PUSH_SUBSCRIPTION_SIG_INVALID`
    /// `0x0312`, FAIL_CLOSED_BLOCK, §18.9.15).
    #[error("push subscription signature invalid (ERR_PUSH_SUBSCRIPTION_SIG_INVALID 0x0312)")]
    PushSubscriptionSigInvalid,
    /// A `WakePing` carries any field beyond the opaque sealed token (key `1`), or its opened
    /// plaintext decodes to structured content — a wake must be content-free and sender-blind
    /// (`ERR_WAKEPING_CONTENT_PRESENT` `0x0313`, FAIL_CLOSED_BLOCK, §18.5.6).
    #[error("wake ping carries content beyond the sealed token (ERR_WAKEPING_CONTENT_PRESENT 0x0313)")]
    WakePingContentPresent,
    /// The wake token's `aes128gcm` AEAD failed to open under the subscription's
    /// `push_key`/`auth_secret` — a forged or unauthenticated wake (`ERR_WAKEPING_AUTH_FAILED`
    /// `0x0314`, DROP_SILENT, §18.9.15).
    #[error("wake ping AEAD open failed (ERR_WAKEPING_AUTH_FAILED 0x0314)")]
    WakePingAuthFailed,
    /// Wakes to this device exceed its rate budget — a wake spends the target's battery
    /// (`ERR_WAKEPING_RATE_LIMITED` `0x0315`, §4.9.4).
    #[error("wake ping rate-limited (ERR_WAKEPING_RATE_LIMITED 0x0315)")]
    WakePingRateLimited,
    /// The suite is not one this implementation validates (fail closed, §1.1).
    #[error("suite is not supported (fail closed)")]
    UnsupportedSuite,
    /// Canonical CBOR decode failed (`ERR_MALFORMED_OBJECT`, §18.1.1).
    #[error("canonical CBOR decode failed: {0}")]
    BadEncoding(#[from] CborError),
}

impl PushError {
    /// The normative DMTAP wire error code (§21) for this failure.
    pub fn code(&self) -> u16 {
        match self {
            PushError::PushSubscriptionSigInvalid => 0x0312,
            PushError::WakePingContentPresent => 0x0313,
            PushError::WakePingAuthFailed => 0x0314,
            PushError::WakePingRateLimited => 0x0315,
            PushError::UnsupportedSuite => 0x0101,
            PushError::BadEncoding(_) => 0x020D,
        }
    }
}

/// The signed device-wake registration (§18.5.5). Fields are public so a device can build one
/// directly; use [`PushSubscription::sign`] / [`PushSubscription::verify`] for the `device_key`
/// signature (§18.9.15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushSubscription {
    /// Key 1 — push-provider tag (§4.9.3); see [`provider`]. Raw `u8`; unknown ⇒ unsupported
    /// provider, not a parse failure.
    pub provider: u8,
    /// Key 2 — provider endpoint URL (Web Push / UnifiedPush) or opaque device token (APNs / FCM).
    pub endpoint: String,
    /// Key 3 — device public push key (Web Push: uncompressed P-256 point, 65 B, RFC 8291).
    pub push_key: Vec<u8>,
    /// Key 4 — RFC 8291 auth secret (16 B), shared only with the user's own node.
    pub auth_secret: Vec<u8>,
    /// Key 5 — the `IK`-authorized device key that signs this subscription (§1.2).
    pub device_key: Vec<u8>,
    /// Key 6 — registration time (ms epoch).
    pub ts: TimestampMs,
    /// Key 7 — signature by `device_key` over `det_cbor(PushSubscription ∖ {7})` (§18.9.15).
    pub sig: Vec<u8>,
}

impl PushSubscription {
    /// Integer-keyed canonical map (§18.5.5). `include_sig=false` omits key 7 for the §18.9.15
    /// signing body.
    fn to_cv(&self, include_sig: bool) -> Cv {
        let mut m = vec![
            (1u64, Cv::U64(self.provider as u64)),
            (2, Cv::Text(self.endpoint.clone())),
            (3, Cv::Bytes(self.push_key.clone())),
            (4, Cv::Bytes(self.auth_secret.clone())),
            (5, Cv::Bytes(self.device_key.clone())),
            (6, Cv::U64(self.ts)),
        ];
        if include_sig {
            m.push((7, Cv::Bytes(self.sig.clone())));
        }
        Cv::Map(m)
    }

    /// The exact wire bytes: §18-canonical integer-keyed CBOR.
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(true))
    }

    /// The §18.9.15 signing body: deterministic CBOR with `sig` (key 7) omitted.
    fn signing_body(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(false))
    }

    /// Decode from canonical CBOR (§18.5.5), failing closed on any violation.
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, PushError> {
        Ok(Self::from_cv(cbor::decode(bytes)?)?)
    }

    fn from_cv(cv: Cv) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cv)?;
        let provider = as_u8(f.req(1)?)?;
        let endpoint = as_text(f.req(2)?)?;
        let push_key = as_bytes(f.req(3)?)?;
        let auth_secret = as_bytes(f.req(4)?)?;
        let device_key = as_bytes(f.req(5)?)?;
        let ts = as_u64(f.req(6)?)?;
        let sig = as_bytes(f.req(7)?)?;
        f.deny_unknown()?; // signed object: fail closed on unknown keys (§18.1.2)
        Ok(PushSubscription {
            provider,
            endpoint,
            push_key,
            auth_secret,
            device_key,
            ts,
            sig,
        })
    }

    /// Build and sign a subscription: the `IK`-authorized `device` key signs the §18.9.15 body.
    /// `device_key` (key 5) is set to `device`'s public key.
    pub fn create(
        device: &IdentityKey,
        provider: u8,
        endpoint: impl Into<String>,
        push_key: Vec<u8>,
        auth_secret: Vec<u8>,
        ts: TimestampMs,
    ) -> PushSubscription {
        let mut s = PushSubscription {
            provider,
            endpoint: endpoint.into(),
            push_key,
            auth_secret,
            device_key: device.public(),
            ts,
            sig: Vec::new(),
        };
        s.sign(device);
        s
    }

    /// Sign (or re-sign) this subscription in place with the device key over the §18.9.15 body.
    pub fn sign(&mut self, device: &IdentityKey) {
        self.sig = device.sign_domain(PUSH_SUBSCRIPTION_DS, &self.signing_body());
    }

    /// Verify `sig` under `device_key` (§18.9.15). Fails closed with
    /// [`PushError::PushSubscriptionSigInvalid`] (`0x0312`) on tamper/bad signature.
    ///
    /// The caller MUST **additionally** confirm `device_key` (key 5) is authorized by a current
    /// `DeviceCert` under the owner's `Identity` (§1.2) before acting on the subscription; that
    /// cross-object check is outside this object and is also `0x0312` when it fails (§18.9.15).
    pub fn verify(&self) -> Result<(), PushError> {
        verify_domain(&self.device_key, PUSH_SUBSCRIPTION_DS, &self.signing_body(), &self.sig)
            .map_err(|_| PushError::PushSubscriptionSigInvalid)
    }
}

/// The content-free, sender-blind wake signal (§18.5.6). Carries **only** the opaque RFC 8291
/// sealed sync token; no DMTAP signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WakePing {
    /// Key 1 — RFC 8291 `aes128gcm` ciphertext of an opaque sync nonce.
    pub token: Vec<u8>,
}

impl WakePing {
    /// Wrap a sealed token.
    pub fn new(token: Vec<u8>) -> Self {
        WakePing { token }
    }

    /// The exact wire bytes: a one-key canonical CBOR map `{1 => token}` (§18.5.6).
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&Cv::Map(vec![(1, Cv::Bytes(self.token.clone()))]))
    }

    /// Decode a `WakePing` from canonical CBOR (§18.5.6). Fails closed with
    /// [`PushError::WakePingContentPresent`] (`0x0313`) if the map carries **any** key beyond the
    /// sealed token (key `1`) — a wake must be content-free and sender-blind.
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, PushError> {
        let mut f = Fields::from_cv(cbor::decode(bytes)?)?;
        let token = as_bytes(f.req(1).map_err(|_| PushError::WakePingContentPresent)?)?;
        // ANY additional field is forbidden content (§18.5.6) — not merely an "unknown key".
        if !f.into_pairs().is_empty() {
            return Err(PushError::WakePingContentPresent);
        }
        Ok(WakePing { token })
    }

    /// Enforce the sealed-plaintext rule (§18.5.6): the opened token plaintext MUST be an **opaque
    /// fixed-form sync nonce only**. If it decodes to a structured CBOR object (a map or array) —
    /// i.e. anything that could carry sender/subject/recipient/content — reject with
    /// [`PushError::WakePingContentPresent`] (`0x0313`). An opaque nonce (a scalar byte string, or
    /// bytes that are not even valid canonical CBOR) is accepted.
    pub fn check_opened_plaintext(plaintext: &[u8]) -> Result<(), PushError> {
        match cbor::decode(plaintext) {
            Ok(Cv::Map(_)) | Ok(Cv::TextMap(_)) | Ok(Cv::Array(_)) => {
                Err(PushError::WakePingContentPresent)
            }
            // A scalar (bytes / uint / bool / text) or non-CBOR opaque bytes ⇒ a legitimate nonce.
            _ => Ok(()),
        }
    }

    /// Open and validate a wake against a subscription's push secrets. `opener` performs the RFC
    /// 8291 (`aes128gcm`) AEAD open under `push_key`/`auth_secret` and returns the recovered
    /// plaintext, or `None` if the tag does not verify — a forged/unauthenticated wake
    /// ([`PushError::WakePingAuthFailed`], `0x0314`, DROP_SILENT). On success the recovered
    /// plaintext is checked to be content-free ([`WakePing::check_opened_plaintext`], `0x0313`).
    ///
    /// The RFC 8291 crypto itself lives at the transport layer (it needs P-256 ECDH + AES-128-GCM,
    /// a different proof system than DMTAP `sig-val`, §18.9.15); this method composes it with the
    /// two fail-closed content/auth checks the spec mandates.
    pub fn open_with<F>(&self, opener: F) -> Result<Vec<u8>, PushError>
    where
        F: FnOnce(&[u8]) -> Option<Vec<u8>>,
    {
        let pt = opener(&self.token).ok_or(PushError::WakePingAuthFailed)?;
        Self::check_opened_plaintext(&pt)?;
        Ok(pt)
    }
}

/// Per-device wake rate-limit guard (§4.9.4, §16). Deterministic and caller-owned (no wall clock,
/// §16.1): the caller counts wakes emitted to a device inside the current window and asks whether
/// one more is within budget. Beyond the cap a wake is `ERR_WAKEPING_RATE_LIMITED` (`0x0315`); the
/// caller SHOULD coalesce bursts into one wake per window (§4.9.4).
pub fn wake_within_budget(wakes_in_window: u32, max_per_window: u32) -> Result<(), PushError> {
    if wakes_in_window < max_per_window {
        Ok(())
    } else {
        Err(PushError::WakePingRateLimited)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sub(device: &IdentityKey) -> PushSubscription {
        PushSubscription::create(
            device,
            provider::WEB_PUSH,
            "https://push.example.invalid/sub/abc",
            vec![0x04; 65], // uncompressed P-256 point shape
            vec![0xaa; 16], // 16-byte auth secret
            1_700_000_000_000,
        )
    }

    #[test]
    fn subscription_round_trip_and_verify() {
        let device = IdentityKey::generate();
        let s = sub(&device);
        let bytes = s.det_cbor();
        let back = PushSubscription::from_det_cbor(&bytes).unwrap();
        assert_eq!(back, s);
        assert_eq!(back.det_cbor(), bytes, "re-encode byte-identical");
        assert!(s.verify().is_ok());
    }

    #[test]
    fn tampered_endpoint_fails_sig() {
        let device = IdentityKey::generate();
        let mut s = sub(&device);
        s.endpoint = "https://evil.invalid/redirect".into();
        let err = s.verify().unwrap_err();
        assert_eq!(err, PushError::PushSubscriptionSigInvalid);
        assert_eq!(err.code(), 0x0312);
    }

    #[test]
    fn foreign_device_key_fails_sig() {
        let device = IdentityKey::generate();
        let mut s = sub(&device);
        s.device_key = IdentityKey::generate().public(); // claim a different signer
        assert_eq!(s.verify(), Err(PushError::PushSubscriptionSigInvalid));
    }

    #[test]
    fn subscription_unknown_key_fails_closed() {
        let device = IdentityKey::generate();
        let s = sub(&device);
        let mut cv = match cbor::decode(&s.det_cbor()).unwrap() {
            Cv::Map(m) => m,
            _ => unreachable!(),
        };
        cv.push((40, Cv::U64(1)));
        let bytes = cbor::encode(&Cv::Map(cv));
        assert!(matches!(
            PushSubscription::from_det_cbor(&bytes),
            Err(PushError::BadEncoding(CborError::UnknownKey(40)))
        ));
    }

    #[test]
    fn wakeping_round_trip() {
        let w = WakePing::new(vec![1, 2, 3, 4, 5]);
        let bytes = w.det_cbor();
        assert_eq!(WakePing::from_det_cbor(&bytes).unwrap(), w);
        assert_eq!(bytes, vec![0xa1, 0x01, 0x45, 1, 2, 3, 4, 5]); // map(1){1: h'0102030405'}
    }

    #[test]
    fn wakeping_rejects_any_extra_key() {
        // {1: token, 2: "sender@x"} — a plaintext sender field is exactly what MUST be rejected.
        let bytes = cbor::encode(&Cv::Map(vec![
            (1, Cv::Bytes(vec![9, 9])),
            (2, Cv::Text("sender@example".into())),
        ]));
        let err = WakePing::from_det_cbor(&bytes).unwrap_err();
        assert_eq!(err, PushError::WakePingContentPresent);
        assert_eq!(err.code(), 0x0313);
    }

    #[test]
    fn wakeping_missing_token_is_content_present() {
        // An empty map has no sealed token — not a valid content-free wake.
        let bytes = cbor::encode(&Cv::Map(vec![]));
        assert_eq!(
            WakePing::from_det_cbor(&bytes),
            Err(PushError::WakePingContentPresent)
        );
    }

    #[test]
    fn opened_plaintext_rejects_structured_content() {
        // A map bearing a sender/subject inside the opened token — forbidden (§18.5.6).
        let content = cbor::encode(&Cv::Map(vec![
            (1, Cv::Text("alice".into())),
            (2, Cv::Text("re: secret".into())),
        ]));
        assert_eq!(
            WakePing::check_opened_plaintext(&content),
            Err(PushError::WakePingContentPresent)
        );
        // An opaque nonce (raw bytes, not structured) is accepted.
        assert!(WakePing::check_opened_plaintext(&[0x7f, 0x00, 0xab, 0xcd]).is_ok());
    }

    #[test]
    fn open_with_auth_failure_and_success() {
        let w = WakePing::new(vec![0xde, 0xad]);
        // Opener rejects the tag → forged/unauthenticated wake (0x0314).
        let err = w.open_with(|_| None).unwrap_err();
        assert_eq!(err, PushError::WakePingAuthFailed);
        assert_eq!(err.code(), 0x0314);
        // Opener recovers an opaque nonce → accepted, plaintext returned.
        let pt = w.open_with(|_| Some(vec![0x01, 0x02, 0x03])).unwrap();
        assert_eq!(pt, vec![0x01, 0x02, 0x03]);
        // Opener recovers structured content → content-present (0x0313), even though AEAD opened.
        let structured = cbor::encode(&Cv::Map(vec![(1, Cv::Text("from".into()))]));
        assert_eq!(
            w.open_with(|_| Some(structured)),
            Err(PushError::WakePingContentPresent)
        );
    }

    #[test]
    fn rate_limit_budget() {
        assert!(wake_within_budget(0, 3).is_ok());
        assert!(wake_within_budget(2, 3).is_ok());
        let err = wake_within_budget(3, 3).unwrap_err();
        assert_eq!(err, PushError::WakePingRateLimited);
        assert_eq!(err.code(), 0x0315);
        assert!(wake_within_budget(9, 3).is_err());
    }
}

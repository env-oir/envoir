//! Device key-attestation — the **advisory** §1.2a hardening hook (spec §1.2a, §18.4.2).
//!
//! A `DeviceCert` MAY record the keystore class holding its `device_key` (`key_protection`, key 9)
//! and carry platform key-attestation **evidence** that the key is hardware-resident and
//! non-exportable (`attestation`, key 10) — Android Key Attestation, Apple, a TPM `AK` quote, or
//! FIDO (§18.4.2). This module evaluates that evidence for a **relying context** that *requires*
//! hardware backing (a group admit, org provisioning, §3.10).
//!
//! It is **purely advisory**: it never overrides the §1.4 KT/quorum authorization authority. A
//! device authorized under §1.4 stays authorized; a context that *opts into* requiring attestation
//! may additionally reject a device whose evidence is absent/invalid
//! ([`AttestationError::AttestationInvalid`], `0x0116`) or stale
//! ([`AttestationError::AttestationExpired`], `0x0118`). A **non-gated** context is unaffected.
//!
//! There is **no** standalone `DeviceAttestation` wire object: §18.4.2 carries `key_protection` and
//! `attestation` as OPTIONAL fields *inside* `DeviceCert`. [`DeviceAttestation`] is the in-memory
//! advisory view a caller assembles from those fields; verifying the evidence against the platform
//! **attestation root** (a disclosed vendor CA, §1.2a) is out-of-band and is supplied as a caller
//! closure, exactly as RFC 8291 wake-open is supplied to [`crate::push::WakePing::open_with`].

use crate::TimestampMs;

/// Default re-attestation cadence (§1.2a, a §16 profile value): evidence older than this is treated
/// as expired and the device must re-attest over the same non-exportable key. Milliseconds.
pub const REATTEST_CADENCE_MS: u64 = 90 * 24 * 60 * 60 * 1000; // ≤ 90 days

/// The keystore class holding a `device_key` (§18.4.2 `key-protection`, §1.2a). On the wire this is
/// a `tstr`; this enum is the typed reference form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyProtection {
    /// `"software"` — no hardware backing (the policy default when `key_protection` is absent).
    Software,
    /// `"tpm"` — a TPM 2.0.
    Tpm,
    /// `"secure-enclave"` — Apple Secure Enclave.
    SecureEnclave,
    /// `"strongbox"` — Android StrongBox.
    StrongBox,
    /// `"tee"` — a Trusted Execution Environment.
    Tee,
}

impl KeyProtection {
    /// The wire class string (§18.4.2).
    pub fn as_str(self) -> &'static str {
        match self {
            KeyProtection::Software => "software",
            KeyProtection::Tpm => "tpm",
            KeyProtection::SecureEnclave => "secure-enclave",
            KeyProtection::StrongBox => "strongbox",
            KeyProtection::Tee => "tee",
        }
    }

    /// Parse a wire class string; an unknown class fails closed (`None`).
    pub fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "software" => KeyProtection::Software,
            "tpm" => KeyProtection::Tpm,
            "secure-enclave" => KeyProtection::SecureEnclave,
            "strongbox" => KeyProtection::StrongBox,
            "tee" => KeyProtection::Tee,
            _ => return None,
        })
    }

    /// Whether this class is a **hardware** keystore (anything but `software`). An
    /// attestation-gated context requires a hardware class (§1.2a).
    pub fn is_hardware(self) -> bool {
        !matches!(self, KeyProtection::Software)
    }
}

/// Advisory attestation failures, each carrying its normative §21 code (§1.2a, §18.4.2). Both are
/// FAIL_CLOSED_BLOCK **for the attestation-gated context only** — never a §1.4 authority override.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AttestationError {
    /// A gated context finds `key_protection`/`attestation` absent, a non-hardware class, or
    /// evidence that fails to verify against the platform root — `ERR_DEVICE_ATTESTATION_INVALID`
    /// (`0x0116`).
    #[error("device attestation absent or invalid (ERR_DEVICE_ATTESTATION_INVALID 0x0116)")]
    AttestationInvalid,
    /// Evidence older than the re-attestation cadence, past its own expiry, or chaining only to a
    /// retired root — `ERR_DEVICE_ATTESTATION_EXPIRED` (`0x0118`); re-attest over the same key.
    #[error("device attestation expired / stale (ERR_DEVICE_ATTESTATION_EXPIRED 0x0118)")]
    AttestationExpired,
}

impl AttestationError {
    /// The normative DMTAP wire code (§21) for this failure.
    pub fn code(&self) -> u16 {
        match self {
            AttestationError::AttestationInvalid => 0x0116,
            AttestationError::AttestationExpired => 0x0118,
        }
    }
}

/// The in-memory advisory view of a `DeviceCert`'s attestation-related fields (§18.4.2), assembled
/// by a caller from `device_key` (key 3), `key_protection` (key 9) and `attestation` (key 10) plus
/// the evidence's validity window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAttestation {
    /// The `device_key` (key 3) the evidence attests is hardware-resident and non-exportable.
    pub device_key: Vec<u8>,
    /// The keystore class (`DeviceCert.key_protection`, key 9). Absent on the wire ⇒
    /// [`KeyProtection::Software`] for policy (§18.4.2).
    pub key_protection: KeyProtection,
    /// The opaque platform evidence bytes (`DeviceCert.attestation`, key 10); absent ⇒ `None`.
    pub evidence: Option<Vec<u8>>,
    /// When the evidence was produced (ms epoch) — the anchor for the re-attestation cadence.
    pub issued_at: TimestampMs,
    /// The evidence's own expiry (ms epoch), if the platform stamps one.
    pub expires: Option<TimestampMs>,
}

impl DeviceAttestation {
    /// Whether the evidence is stale at `now` (§1.2a): past its own expiry, older than
    /// `max_age_ms` (pass [`REATTEST_CADENCE_MS`] for the default), or chaining only to a retired
    /// root (`root_retired`). Pure predicate; a `true` verdict maps to
    /// [`AttestationError::AttestationExpired`] (`0x0118`).
    pub fn is_stale(&self, now: TimestampMs, max_age_ms: u64, root_retired: bool) -> bool {
        if root_retired {
            return true;
        }
        if matches!(self.expires, Some(e) if now > e) {
            return true;
        }
        now.saturating_sub(self.issued_at) > max_age_ms
    }

    /// Evaluate this attestation for a relying context (§1.2a). **Advisory only** — the result
    /// never changes the device's §1.4 authorization; it gates only the caller's attestation-gated
    /// operation.
    ///
    /// - `require_attested = false` ⇒ a non-gated context: always `Ok(())` regardless of evidence.
    /// - `require_attested = true` ⇒
    ///   1. `key_protection` MUST be a hardware class and `evidence` MUST be present, else
    ///      [`AttestationError::AttestationInvalid`] (`0x0116`);
    ///   2. `verify_root(evidence, device_key)` — the caller's out-of-band check against the
    ///      platform attestation root — MUST return `true`, else `0x0116`;
    ///   3. the evidence MUST NOT be stale ([`DeviceAttestation::is_stale`]), else
    ///      [`AttestationError::AttestationExpired`] (`0x0118`).
    pub fn evaluate<F>(
        &self,
        require_attested: bool,
        now: TimestampMs,
        max_age_ms: u64,
        root_retired: bool,
        verify_root: F,
    ) -> Result<(), AttestationError>
    where
        F: FnOnce(&[u8], &[u8]) -> bool,
    {
        if !require_attested {
            return Ok(()); // non-gated context is unaffected (§1.2a)
        }
        if !self.key_protection.is_hardware() {
            return Err(AttestationError::AttestationInvalid);
        }
        let evidence = self.evidence.as_deref().ok_or(AttestationError::AttestationInvalid)?;
        if !verify_root(evidence, &self.device_key) {
            return Err(AttestationError::AttestationInvalid);
        }
        // Freshness is checked only after the evidence verifies structurally (§1.2a).
        if self.is_stale(now, max_age_ms, root_retired) {
            return Err(AttestationError::AttestationExpired);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attested(now: TimestampMs) -> DeviceAttestation {
        DeviceAttestation {
            device_key: vec![0x11; 32],
            key_protection: KeyProtection::StrongBox,
            evidence: Some(vec![0xAB, 0xCD]),
            issued_at: now,
            expires: None,
        }
    }

    #[test]
    fn key_protection_strings_round_trip() {
        for kp in [
            KeyProtection::Software,
            KeyProtection::Tpm,
            KeyProtection::SecureEnclave,
            KeyProtection::StrongBox,
            KeyProtection::Tee,
        ] {
            assert_eq!(KeyProtection::from_str(kp.as_str()), Some(kp));
        }
        assert_eq!(KeyProtection::from_str("hsm-unknown"), None);
        assert!(!KeyProtection::Software.is_hardware());
        assert!(KeyProtection::SecureEnclave.is_hardware());
    }

    #[test]
    fn non_gated_context_always_ok() {
        let now = 1_700_000_000_000;
        // Even a bare software key with no evidence passes a context that does not require it.
        let bare = DeviceAttestation {
            device_key: vec![0x22; 32],
            key_protection: KeyProtection::Software,
            evidence: None,
            issued_at: now,
            expires: None,
        };
        assert!(bare.evaluate(false, now, REATTEST_CADENCE_MS, false, |_, _| false).is_ok());
    }

    #[test]
    fn gated_valid_attestation_accepted() {
        let now = 1_700_000_000_000;
        let a = attested(now);
        assert!(a
            .evaluate(true, now + 1000, REATTEST_CADENCE_MS, false, |ev, dk| {
                ev == [0xAB, 0xCD] && dk == [0x11; 32]
            })
            .is_ok());
    }

    #[test]
    fn gated_software_key_is_invalid() {
        let now = 1_700_000_000_000;
        let mut a = attested(now);
        a.key_protection = KeyProtection::Software;
        let err = a.evaluate(true, now, REATTEST_CADENCE_MS, false, |_, _| true).unwrap_err();
        assert_eq!(err, AttestationError::AttestationInvalid);
        assert_eq!(err.code(), 0x0116);
    }

    #[test]
    fn gated_missing_evidence_is_invalid() {
        let now = 1_700_000_000_000;
        let mut a = attested(now);
        a.evidence = None;
        assert_eq!(
            a.evaluate(true, now, REATTEST_CADENCE_MS, false, |_, _| true),
            Err(AttestationError::AttestationInvalid)
        );
    }

    #[test]
    fn gated_failing_root_check_is_invalid() {
        let now = 1_700_000_000_000;
        let a = attested(now);
        assert_eq!(
            a.evaluate(true, now, REATTEST_CADENCE_MS, false, |_, _| false),
            Err(AttestationError::AttestationInvalid)
        );
    }

    #[test]
    fn stale_by_age_is_expired() {
        let now = 1_700_000_000_000;
        let a = attested(now);
        let later = now + REATTEST_CADENCE_MS + 1;
        let err = a.evaluate(true, later, REATTEST_CADENCE_MS, false, |_, _| true).unwrap_err();
        assert_eq!(err, AttestationError::AttestationExpired);
        assert_eq!(err.code(), 0x0118);
        // Exactly at the cadence bound is still fresh.
        assert!(a
            .evaluate(true, now + REATTEST_CADENCE_MS, REATTEST_CADENCE_MS, false, |_, _| true)
            .is_ok());
    }

    #[test]
    fn stale_by_own_expiry_is_expired() {
        let now = 1_700_000_000_000;
        let mut a = attested(now);
        a.expires = Some(now + 1000);
        assert_eq!(
            a.evaluate(true, now + 2000, REATTEST_CADENCE_MS, false, |_, _| true),
            Err(AttestationError::AttestationExpired)
        );
    }

    #[test]
    fn retired_root_is_expired() {
        let now = 1_700_000_000_000;
        let a = attested(now);
        assert_eq!(
            a.evaluate(true, now, REATTEST_CADENCE_MS, true, |_, _| true),
            Err(AttestationError::AttestationExpired)
        );
    }
}

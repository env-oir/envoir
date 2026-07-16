//! Profile — the identity's self-asserted, signed human display data (spec §3.9.5, §18.4.12).
//!
//! A [`Profile`] is a **replaceable pointer**, authenticated to the key exactly like
//! `Identity.names` (§3.9.4): the signature proves the key asserts this data, never a real-world
//! identity. It is signed by `IK` (or an `IK`-authorized device key, §1.2), versioned and
//! rollback-protected like [`crate::identity::Identity`], and published/pinned via the
//! directory / DNS / KT path (§3.3–3.5).
//!
//! The avatar is **owner-hosted** — DMTAP stores no image — with an OPTIONAL BLAKE3 content
//! address giving tamper-evidence for the exact bytes the owner signed (§18.4.12).
//!
//! ## Wire shape (§18.4.12)
//! ```text
//! Profile = {
//!   1 => suite, 2 => ik-pub, 3 => u64 (version), 4 => tstr (display_name),
//!   ?5 => tstr (given_name), ?6 => tstr (family_name), ?7 => Avatar,
//!   ?8 => hash (prev), 9 => ts, 10 => sig-val (sig)
//! }
//! Avatar = { 1 => tstr (url), ?2 => hash }
//! ```
//! DS-tag `DMTAP-v0/profile` (§18.9.3); the signing body is `det_cbor(Profile ∖ {10})`.

use crate::cbor::{self, as_bytes, as_text, as_u64, CborError, Cv, Fields};
use crate::id::ContentId;
use crate::identity::{verify_domain, IdentityKey};
use crate::suite::Suite;
use crate::TimestampMs;

/// Domain-separation tag for `Profile.sig` (§18.9.3), ASCII terminated by one `0x00` byte.
const PROFILE_DS: &[u8] = b"DMTAP-v0/profile\x00";

/// Errors from [`Profile`] validation, each carrying its normative §21 wire code where one is
/// assigned (fail closed, §18.4.12).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProfileError {
    /// `Profile.sig` does not verify under the identity's `IK` (or an `IK`-authorized device
    /// key) — `ERR_PROFILE_SIG_INVALID` (`0x0119`, FAIL_CLOSED_BLOCK, §18.4.12).
    #[error("profile signature does not verify (ERR_PROFILE_SIG_INVALID 0x0119)")]
    ProfileSigInvalid,
    /// The bytes fetched from `avatar.url` do not content-address to `avatar.hash` — the
    /// owner-hosted image was swapped/tampered (`ERR_PROFILE_AVATAR_HASH_MISMATCH` `0x011A`,
    /// USER_WARN, §18.4.12).
    #[error("avatar bytes do not match avatar.hash (ERR_PROFILE_AVATAR_HASH_MISMATCH 0x011A)")]
    AvatarHashMismatch,
    /// A `version` ≤ the last pinned version for this identity — a rollback/replay of a
    /// superseded-but-validly-signed object (`ERR_STALE_ROLLBACK` `0x0105`, §18.4.12, §3.9.5).
    #[error("profile version is a rollback of a pinned version (ERR_STALE_ROLLBACK 0x0105)")]
    StaleRollback,
    /// The suite is not one this implementation validates (fail closed, §1.1).
    #[error("suite {0:#04x} is not supported (fail closed)")]
    UnsupportedSuite(u8),
    /// Canonical CBOR decode failed (`ERR_MALFORMED_OBJECT`, §18.1.1).
    #[error("canonical CBOR decode failed: {0}")]
    BadEncoding(#[from] CborError),
}

impl ProfileError {
    /// The normative DMTAP wire error code (§21) for this failure.
    pub fn code(&self) -> u16 {
        match self {
            ProfileError::ProfileSigInvalid => 0x0119,
            ProfileError::AvatarHashMismatch => 0x011A,
            ProfileError::StaleRollback => 0x0105,
            // ERR_UNKNOWN_SUITE / ERR_MALFORMED_OBJECT.
            ProfileError::UnsupportedSuite(_) => 0x0101,
            ProfileError::BadEncoding(_) => 0x020D,
        }
    }
}

/// An owner-set avatar pointer (§18.4.12). DMTAP does **not** host the image — `url` is a pointer
/// the owner controls; `hash`, when present, content-addresses the exact bytes for tamper-evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Avatar {
    /// Key 1 — owner-set public URL of the avatar image (`https` RECOMMENDED).
    pub url: String,
    /// Key 2 — OPTIONAL `0x1e ‖ BLAKE3-256` content address of the image bytes.
    pub hash: Option<ContentId>,
}

impl Avatar {
    fn to_cv(&self) -> Cv {
        let mut m = vec![(1u64, Cv::Text(self.url.clone()))];
        if let Some(h) = &self.hash {
            m.push((2, Cv::Bytes(h.as_bytes().to_vec())));
        }
        Cv::Map(m)
    }

    fn from_cv(cv: Cv) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cv)?;
        let url = as_text(f.req(1)?)?;
        let hash = f.take(2).map(|c| as_bytes(c).map(ContentId)).transpose()?;
        f.deny_unknown()?;
        Ok(Avatar { url, hash })
    }
}

/// The published, signed profile (§18.4.12). Fields are public so callers can build one directly;
/// use [`Profile::sign`] to attach the signature and [`Profile::verify`] to check it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    /// Key 1 — suite of `ik`/`sig`.
    pub suite: Suite,
    /// Key 2 — the identity this profile describes (`ik-pub`).
    pub ik: Vec<u8>,
    /// Key 3 — monotonic version; reject ≤ last pinned (rollback defense).
    pub version: u64,
    /// Key 4 — primary human-shown string (UTF-8, NFC).
    pub display_name: String,
    /// Key 5 — OPTIONAL structured given-name part.
    pub given_name: Option<String>,
    /// Key 6 — OPTIONAL structured family-name part.
    pub family_name: Option<String>,
    /// Key 7 — OPTIONAL owner-set avatar pointer.
    pub avatar: Option<Avatar>,
    /// Key 8 — OPTIONAL hash of the previous `Profile` version (chain).
    pub prev: Option<ContentId>,
    /// Key 9 — publication time (ms epoch).
    pub ts: TimestampMs,
    /// Key 10 — `IK` (or IK-authorized device key) signature over `det_cbor(Profile ∖ {10})`.
    pub sig: Vec<u8>,
}

impl Profile {
    /// Integer-keyed canonical map (§18.4.12). `include_sig=false` omits key 10 for the §18.9.3
    /// signing body.
    fn to_cv(&self, include_sig: bool) -> Cv {
        let mut m = vec![
            (1u64, Cv::U64(self.suite.as_u8() as u64)),
            (2, Cv::Bytes(self.ik.clone())),
            (3, Cv::U64(self.version)),
            (4, Cv::Text(self.display_name.clone())),
        ];
        if let Some(g) = &self.given_name {
            m.push((5, Cv::Text(g.clone())));
        }
        if let Some(fam) = &self.family_name {
            m.push((6, Cv::Text(fam.clone())));
        }
        if let Some(a) = &self.avatar {
            m.push((7, a.to_cv()));
        }
        if let Some(p) = &self.prev {
            m.push((8, Cv::Bytes(p.as_bytes().to_vec())));
        }
        m.push((9, Cv::U64(self.ts)));
        if include_sig {
            m.push((10, Cv::Bytes(self.sig.clone())));
        }
        Cv::Map(m)
    }

    /// The exact wire bytes of this profile: §18-canonical integer-keyed CBOR.
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(true))
    }

    /// The §18.9.3 signing body: deterministic CBOR of the profile with `sig` (key 10) omitted.
    fn signing_body(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(false))
    }

    /// Decode a profile from its canonical CBOR (§18.4.12), failing closed on any violation.
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, ProfileError> {
        Ok(Self::from_cv(cbor::decode(bytes)?)?)
    }

    fn from_cv(cv: Cv) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cv)?;
        let suite = {
            let b = crate::cbor::as_u8(f.req(1)?)?;
            Suite::from_u8(b).ok_or(CborError::UnknownSuite(b))?
        };
        let ik = as_bytes(f.req(2)?)?;
        let version = as_u64(f.req(3)?)?;
        let display_name = as_text(f.req(4)?)?;
        let given_name = f.take(5).map(as_text).transpose()?;
        let family_name = f.take(6).map(as_text).transpose()?;
        let avatar = f.take(7).map(Avatar::from_cv).transpose()?;
        let prev = f.take(8).map(|c| as_bytes(c).map(ContentId)).transpose()?;
        let ts = as_u64(f.req(9)?)?;
        let sig = as_bytes(f.req(10)?)?;
        f.deny_unknown()?; // signed object: any leftover key fails closed (§18.1.2)
        Ok(Profile {
            suite,
            ik,
            version,
            display_name,
            given_name,
            family_name,
            avatar,
            prev,
            ts,
            sig,
        })
    }

    /// Build and sign a profile: the signer (`IK` or an `IK`-authorized device key) signs the
    /// §18.9.3 body under DS-tag `DMTAP-v0/profile`. `ik` (key 2) is set to the signer's public
    /// key; pass a device-key signer whose `DeviceCert` authorizes it if `IK` is cold.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        signer: &IdentityKey,
        version: u64,
        display_name: impl Into<String>,
        given_name: Option<String>,
        family_name: Option<String>,
        avatar: Option<Avatar>,
        prev: Option<ContentId>,
        ts: TimestampMs,
    ) -> Profile {
        let mut p = Profile {
            suite: Suite::Classical,
            ik: signer.public(),
            version,
            display_name: display_name.into(),
            given_name,
            family_name,
            avatar,
            prev,
            ts,
            sig: Vec::new(),
        };
        p.sign(signer);
        p
    }

    /// Sign (or re-sign) this profile in place with `signer` over the §18.9.3 body. Does **not**
    /// overwrite `ik` (key 2): a device-key signer signs on behalf of the identity whose `ik` is
    /// already set. Set `ik` before calling if you want it to match the signer's own key.
    pub fn sign(&mut self, signer: &IdentityKey) {
        self.sig = signer.sign_domain(PROFILE_DS, &self.signing_body());
    }

    /// Verify `sig` under this profile's `ik` (§18.9.3). Fails closed with
    /// [`ProfileError::ProfileSigInvalid`] (`0x0119`) on any tamper or bad signature; retain the
    /// prior pinned profile / fall to the §3.9.5 fallback ladder.
    pub fn verify(&self) -> Result<(), ProfileError> {
        if !self.suite.is_supported() {
            return Err(ProfileError::UnsupportedSuite(self.suite.as_u8()));
        }
        verify_domain(&self.ik, PROFILE_DS, &self.signing_body(), &self.sig)
            .map_err(|_| ProfileError::ProfileSigInvalid)
    }

    /// Verify that `image_bytes` fetched from `avatar.url` content-address to `avatar.hash`
    /// (§18.4.12). Returns `Ok(())` when there is no avatar or no `hash` (best-effort, no integrity
    /// guarantee); [`ProfileError::AvatarHashMismatch`] (`0x011A`) on mismatch — the client MUST
    /// NOT display the fetched bytes and falls back down the §3.9.5 ladder.
    pub fn verify_avatar(&self, image_bytes: &[u8]) -> Result<(), ProfileError> {
        match self.avatar.as_ref().and_then(|a| a.hash.as_ref()) {
            Some(h) if h.verify(image_bytes) => Ok(()),
            Some(_) => Err(ProfileError::AvatarHashMismatch),
            None => Ok(()), // no content address ⇒ best-effort, no guarantee
        }
    }

    /// Rollback guard (§18.4.12, §3.9.5): reject this profile if its `version` is ≤ the
    /// `last_pinned` version for this identity. `None` ⇒ first observation (accepted). Returns
    /// [`ProfileError::StaleRollback`] (`0x0105`) on a replay of a superseded version.
    pub fn check_rollback(&self, last_pinned: Option<u64>) -> Result<(), ProfileError> {
        match last_pinned {
            Some(v) if self.version <= v => Err(ProfileError::StaleRollback),
            _ => Ok(()),
        }
    }

    /// The content address of this fully-signed profile (`0x1e ‖ BLAKE3-256(det_cbor(Profile))`,
    /// §18.9.4) — the value a `Profile.prev` in a later version points back to.
    pub fn content_id(&self) -> ContentId {
        ContentId::of(&self.det_cbor())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(signer: &IdentityKey) -> Profile {
        Profile::create(
            signer,
            1,
            "Ada Lovelace",
            Some("Ada".into()),
            Some("Lovelace".into()),
            Some(Avatar {
                url: "https://example.invalid/a.png".into(),
                hash: Some(ContentId::of(b"avatar-bytes")),
            }),
            None,
            1_700_000_000_000,
        )
    }

    #[test]
    fn round_trip_and_verify() {
        let ik = IdentityKey::generate();
        let p = sample(&ik);
        let bytes = p.det_cbor();
        let back = Profile::from_det_cbor(&bytes).unwrap();
        assert_eq!(back, p);
        assert_eq!(back.det_cbor(), bytes, "re-encode is byte-identical");
        assert!(p.verify().is_ok());
    }

    #[test]
    fn minimal_profile_omits_optionals() {
        let ik = IdentityKey::generate();
        let p = Profile::create(&ik, 3, "Bob", None, None, None, None, 42);
        let back = Profile::from_det_cbor(&p.det_cbor()).unwrap();
        assert_eq!(back.given_name, None);
        assert_eq!(back.avatar, None);
        assert_eq!(back.prev, None);
        assert!(back.verify().is_ok());
    }

    #[test]
    fn tampered_display_name_fails_sig() {
        let ik = IdentityKey::generate();
        let mut p = sample(&ik);
        p.display_name = "Mallory".into(); // tamper after signing
        let err = p.verify().unwrap_err();
        assert_eq!(err, ProfileError::ProfileSigInvalid);
        assert_eq!(err.code(), 0x0119);
    }

    #[test]
    fn wrong_key_fails_sig() {
        let ik = IdentityKey::generate();
        let mut p = sample(&ik);
        let other = IdentityKey::generate();
        p.ik = other.public(); // claim a different identity than signed
        assert_eq!(p.verify(), Err(ProfileError::ProfileSigInvalid));
    }

    #[test]
    fn avatar_hash_mismatch_detected() {
        let ik = IdentityKey::generate();
        let p = sample(&ik);
        assert!(p.verify_avatar(b"avatar-bytes").is_ok());
        let err = p.verify_avatar(b"swapped-image").unwrap_err();
        assert_eq!(err, ProfileError::AvatarHashMismatch);
        assert_eq!(err.code(), 0x011A);
    }

    #[test]
    fn avatar_without_hash_is_best_effort() {
        let ik = IdentityKey::generate();
        let p = Profile::create(
            &ik,
            1,
            "No Hash",
            None,
            None,
            Some(Avatar { url: "https://x.invalid/y".into(), hash: None }),
            None,
            1,
        );
        assert!(p.verify_avatar(b"anything at all").is_ok());
    }

    #[test]
    fn rollback_rejected_at_or_below_pinned() {
        let ik = IdentityKey::generate();
        let p = Profile::create(&ik, 5, "V5", None, None, None, None, 1);
        assert!(p.check_rollback(None).is_ok(), "first observation accepted");
        assert!(p.check_rollback(Some(4)).is_ok(), "higher version accepted");
        assert_eq!(p.check_rollback(Some(5)), Err(ProfileError::StaleRollback));
        assert_eq!(p.check_rollback(Some(6)), Err(ProfileError::StaleRollback));
        assert_eq!(p.check_rollback(Some(5)).unwrap_err().code(), 0x0105);
    }

    #[test]
    fn unknown_key_in_signed_object_fails_closed() {
        let ik = IdentityKey::generate();
        let p = sample(&ik);
        let mut cv = match cbor::decode(&p.det_cbor()).unwrap() {
            Cv::Map(m) => m,
            _ => unreachable!(),
        };
        cv.push((63, Cv::U64(1))); // an unrecognized key
        let bytes = cbor::encode(&Cv::Map(cv));
        assert!(matches!(
            Profile::from_det_cbor(&bytes),
            Err(ProfileError::BadEncoding(CborError::UnknownKey(63)))
        ));
    }

    #[test]
    fn prev_chain_links_by_content_id() {
        let ik = IdentityKey::generate();
        let v1 = Profile::create(&ik, 1, "V1", None, None, None, None, 1);
        let v2 = Profile::create(&ik, 2, "V2", None, None, None, Some(v1.content_id()), 2);
        assert_eq!(v2.prev, Some(v1.content_id()));
        assert!(v2.verify().is_ok());
    }
}

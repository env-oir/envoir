//! The [`Challenge`] — RP-side construction of the origin-bound, single-use, audience-bound login
//! challenge (spec §13.3 step 3; wire object §18.7.1).

use dmtap_core::cbor::{self, as_array, as_bytes, as_text, as_u64, Cv, Fields};
use dmtap_core::TimestampMs;
use rand_core::{OsRng, RngCore};

use crate::error::AuthError;

/// Default validity window for a challenge: 120 s (§18.7.1 / §16.1). The RP creates the challenge
/// with `exp = issued_at + CHALLENGE_TTL_MS`.
pub const CHALLENGE_TTL_MS: u64 = 120_000;

/// Length of the single-use server nonce (§18.7.1). 32 bytes = 256 bits of unguessable entropy.
pub const NONCE_LEN: usize = 32;

/// A login challenge (§18.7.1). Created by the relying party; presented to a **trusted client**
/// (§13.3.1) which binds and displays the verified `rp_origin` before any signature.
///
/// Phishing resistance depends **entirely** on `rp_origin` being injected and enforced by the
/// trusted client (WebAuthn), never a value the signer trusts from the RP (§13.3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    /// key 1 — the RP's true web origin, `scheme://host[:port]`.
    pub rp_origin: String,
    /// key 2 — single-use server nonce; valid ≤ 120 s, reuse rejected by the replay cache.
    pub nonce: Vec<u8>,
    /// key 3 — issue time (ms since Unix epoch).
    pub issued_at: TimestampMs,
    /// key 4 — expiry; an assertion after `exp` MUST be rejected.
    pub exp: TimestampMs,
    /// key 5 — audience identifier binding the assertion to the intended RP.
    pub aud: String,
    /// key 6 (OPTIONAL) — requested login scopes / delegated capabilities (§13.5).
    pub scope: Option<Vec<String>>,
}

impl Challenge {
    /// Create a fresh challenge with a CSPRNG single-use nonce and a [`CHALLENGE_TTL_MS`] window
    /// (§13.3 step 3). `now_ms` is the RP's clock reading (inject via [`crate::Clock`]).
    pub fn new(
        rp_origin: impl Into<String>,
        aud: impl Into<String>,
        now_ms: TimestampMs,
        scope: Option<Vec<String>>,
    ) -> Self {
        let mut nonce = vec![0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        Challenge {
            rp_origin: rp_origin.into(),
            nonce,
            issued_at: now_ms,
            exp: now_ms.saturating_add(CHALLENGE_TTL_MS),
            aud: aud.into(),
            scope,
        }
    }

    /// The canonical integer-keyed CBOR map (§18.7.1). This is the exact wire form the RP hands to
    /// the client.
    fn to_cv(&self) -> Cv {
        let mut m = vec![
            (1u64, Cv::Text(self.rp_origin.clone())),
            (2, Cv::Bytes(self.nonce.clone())),
            (3, Cv::U64(self.issued_at)),
            (4, Cv::U64(self.exp)),
            (5, Cv::Text(self.aud.clone())),
        ];
        if let Some(s) = &self.scope {
            m.push((6, Cv::Array(s.iter().map(|x| Cv::Text(x.clone())).collect())));
        }
        Cv::Map(m)
    }

    /// The exact wire bytes: §18-canonical integer-keyed CBOR.
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv())
    }

    /// Decode a challenge from its canonical CBOR (§18.7.1), failing closed on any violation.
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, AuthError> {
        let cv = cbor::decode(bytes).map_err(|_| AuthError::Malformed("challenge CBOR"))?;
        let mut f = Fields::from_cv(cv).map_err(|_| AuthError::Malformed("challenge not a map"))?;
        let mut take = |k: u64| f.req(k).map_err(|_| AuthError::Malformed("challenge field"));
        let rp_origin = as_text(take(1)?).map_err(|_| AuthError::Malformed("rp_origin"))?;
        let nonce = as_bytes(take(2)?).map_err(|_| AuthError::Malformed("nonce"))?;
        let issued_at = as_u64(take(3)?).map_err(|_| AuthError::Malformed("issued_at"))?;
        let exp = as_u64(take(4)?).map_err(|_| AuthError::Malformed("exp"))?;
        let aud = as_text(take(5)?).map_err(|_| AuthError::Malformed("aud"))?;
        let scope = match f.take(6) {
            Some(c) => Some(
                as_array(c)
                    .map_err(|_| AuthError::Malformed("scope"))?
                    .into_iter()
                    .map(|e| as_text(e).map_err(|_| AuthError::Malformed("scope item")))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            None => None,
        };
        f.deny_unknown().map_err(|_| AuthError::Malformed("unknown challenge key"))?;
        Ok(Challenge { rp_origin, nonce, issued_at, exp, aud, scope })
    }
}

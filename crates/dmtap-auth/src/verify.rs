//! RP-side verification of a login assertion (spec §13.3 step 6, §18.9.8). Establishes a
//! [`BoundSession`] bound **only** to `cnf`.

use dmtap_core::identity::verify_domain;

use crate::assertion::SignedAssertion;
use crate::challenge::Challenge;
use crate::error::AuthError;
use crate::seam::{Clock, DeviceAuthorizer, ReplayCache};
use crate::session::BoundSession;
use crate::AUTH_ASSERTION_DS;

/// Verify a login assertion and establish a key-bound session (§13.3 step 6).
///
/// The RP reconstructs the signed preimage from **the challenge it issued** plus the assertion's
/// `cnf` (§18.9.8), and enforces, in order:
///
/// 1. `rp_origin == expected_origin` — the phishing defense. An assertion minted for another
///    origin (a look-alike site) is rejected here ([`AuthError::OriginMismatch`]).
/// 2. `aud == expected_aud` — audience binding ([`AuthError::AudienceMismatch`]).
/// 3. Every echoed field equals the issued challenge ([`AuthError::ChallengeMismatch`]).
/// 4. Not expired against the RP clock ([`AuthError::Expired`]).
/// 5. `from` is an `IK`-authorized signer for `pinned_ik` ([`AuthError::UnauthorizedSigner`] —
///    the wrong-identity-key / unauthorized-device rejection).
/// 6. The signature verifies under `from` ([`AuthError::BadSignature`]).
/// 7. The nonce is single-use (replay cache) — the **final** gate, so an otherwise-invalid
///    attempt never burns the nonce, and a genuine second presentation is a replay
///    ([`AuthError::Replay`]).
///
/// On success the session is bound **only** to `cnf` (proof-of-possession, §13.4) and to the
/// identity subject — nothing else.
#[allow(clippy::too_many_arguments)]
pub fn verify_login(
    pinned_ik: &[u8],
    expected_origin: &str,
    expected_aud: &str,
    issued: &Challenge,
    assertion: &SignedAssertion,
    authorizer: &dyn DeviceAuthorizer,
    replay: &mut dyn ReplayCache,
    clock: &dyn Clock,
) -> Result<BoundSession, AuthError> {
    // (1) Origin binding — the assertion MUST be for THIS relying party (§13.3.1).
    if assertion.rp_origin != expected_origin {
        return Err(AuthError::OriginMismatch);
    }
    // (2) Audience binding.
    if assertion.aud != expected_aud {
        return Err(AuthError::AudienceMismatch);
    }
    // (3) The assertion must echo exactly the challenge the RP issued. The RP binds to its own
    //     issued values, so a forged echo is inert — but a mismatch is still an early reject.
    if assertion.rp_origin != issued.rp_origin
        || assertion.nonce != issued.nonce
        || assertion.issued_at != issued.issued_at
        || assertion.exp != issued.exp
        || assertion.aud != issued.aud
    {
        return Err(AuthError::ChallengeMismatch);
    }
    // (4) Expiry against the RP's own clock (§16.1 — never trust the assertion's timestamps for
    //     correctness; judge with local time).
    let now = clock.now_ms();
    if now > issued.exp {
        return Err(AuthError::Expired);
    }
    // (5) The login signer must resolve to the pinned name → key identity (§3.4, §13.3 step 6).
    if !authorizer.is_authorized(pinned_ik, &assertion.from, now) {
        return Err(AuthError::UnauthorizedSigner);
    }
    // (6) Verify the signature over the preimage reconstructed from the ISSUED challenge + cnf.
    let hash = assertion.auth_hash_from_issued(issued);
    verify_domain(&assertion.from, AUTH_ASSERTION_DS, &hash, &assertion.sig)?;

    // (7) Consume the single-use nonce last (fail-closed ordering).
    if !replay.check_and_reserve(&issued.nonce, issued.exp, now) {
        return Err(AuthError::Replay);
    }

    // Authenticated: bind the session ONLY to cnf and the identity subject (§13.3 step 6).
    Ok(BoundSession {
        subject_ik: pinned_ik.to_vec(),
        cnf: assertion.cnf.clone(),
        established_at: now,
    })
}

//! Errors for the DMTAP-Auth ceremony. Every variant **fails closed** — the ceremony never
//! degrades to a weaker mode on error (§13.7 limit 1).

use dmtap_core::identity::IdentityError;

/// A failure in the login ceremony or a key-bound-session check. Distinct variants exist so the
/// security-property tests can assert *why* something was rejected (phishing vs. replay vs.
/// session-hijack), not merely that it was.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthError {
    /// The assertion's `rp_origin` does not equal the verifier's own origin — the phishing
    /// defense (§13.3.1). Raised both client-side (trusted client observed a different origin
    /// than the challenge claims) and RP-side (assertion minted for another origin).
    #[error("origin binding failed: assertion origin does not match this relying party (§13.3.1)")]
    OriginMismatch,

    /// The assertion's `aud` does not bind to this RP (§18.7.2 key 5).
    #[error("audience mismatch: assertion is not bound to this relying party")]
    AudienceMismatch,

    /// An echoed field (`rp_origin`/`nonce`/`issued_at`/`exp`/`aud`) does not equal the challenge
    /// the RP actually issued. The RP reconstructs the signed preimage from **its own** issued
    /// challenge (§18.9.8), so any divergence is rejected before signature verification.
    #[error("challenge echo mismatch: assertion does not correspond to the issued challenge")]
    ChallengeMismatch,

    /// `now > exp`: the challenge/assertion window has closed (§18.7.1, ≤120 s; §16.1).
    #[error("expired: the challenge validity window has closed")]
    Expired,

    /// The nonce (login) or `jti` (session proof) was already used — replay rejected
    /// (§18.7.1 replay cache; §13.4 DPoP).
    #[error("replay: this single-use value has already been consumed")]
    Replay,

    /// The login signer (`Assertion.from`) is not an `IK`-authorized device key for the pinned
    /// identity (§3.4, §13.3 step 6) — e.g. a wrong-identity-key or unauthorized-device signature.
    #[error("unauthorized signer: not an IK-authorized device key for the pinned identity")]
    UnauthorizedSigner,

    /// A signature failed to verify (assertion sig, or a DPoP proof sig).
    #[error("bad signature")]
    BadSignature,

    /// A DPoP proof carries a session key whose `H(pubkey)` does not equal the session's bound
    /// `cnf` — the proof-of-possession binding (§13.4). This is the session-hijack rejection: a
    /// captured assertion replayed with an attacker-chosen session key.
    #[error("session-key mismatch: DPoP key does not match the bound cnf (§13.4)")]
    SessionKeyMismatch,

    /// A DPoP proof's HTTP binding (`htu`/`htm`) or freshness (`iat`) does not match the request
    /// being authorized (§13.4, RFC 9449).
    #[error("request binding mismatch: DPoP htu/htm/iat does not match this request")]
    RequestMismatch,

    /// A field had the wrong length (key/signature/nonce/hash), or a malformed wire object.
    #[error("malformed: {0}")]
    Malformed(&'static str),
}

impl From<IdentityError> for AuthError {
    fn from(e: IdentityError) -> Self {
        match e {
            IdentityError::BadSignature => AuthError::BadSignature,
            IdentityError::BadKeyLength => AuthError::Malformed("key or signature length"),
            _ => AuthError::Malformed("identity substrate rejected input"),
        }
    }
}

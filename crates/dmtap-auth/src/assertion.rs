//! The [`SignedAssertion`] (wire object §18.7.2) and the client-side ceremony [`create_login`]
//! (§13.3 steps 4–5). This is the identity-revealing login signature; the fresh per-RP session
//! keypair it commits via `cnf` lives in [`crate::session`].

use dmtap_core::cbor::{self, as_bytes, as_text, as_u64, Cv, Fields};
use dmtap_core::id::ContentId;
use dmtap_core::identity::IdentityKey;
use dmtap_core::TimestampMs;

use crate::challenge::Challenge;
use crate::error::AuthError;
use crate::seam::TrustedClient;
use crate::session::SessionKey;
use crate::AUTH_ASSERTION_DS;

/// Compute the §18.9.8 `auth_hash`: `BLAKE3-256( det_cbor([ rp_origin, nonce, issued_at, exp,
/// aud, cnf ]) )`. A fixed 6-element CBOR array in exactly that order — the five origin-bound
/// `Challenge` fields followed by `cnf` — matching §13.3 step 5's
/// `H(rp_origin ‖ nonce ‖ issued_at ‖ exp ‖ aud ‖ cnf)`. This is the 32-byte raw digest that is
/// signed (the DS-tag is prepended by the signer), NOT a prefixed `hash` wire field.
fn auth_hash(
    rp_origin: &str,
    nonce: &[u8],
    issued_at: TimestampMs,
    exp: TimestampMs,
    aud: &str,
    cnf: &ContentId,
) -> [u8; 32] {
    let arr = Cv::Array(vec![
        Cv::Text(rp_origin.to_string()),
        Cv::Bytes(nonce.to_vec()),
        Cv::U64(issued_at),
        Cv::U64(exp),
        Cv::Text(aud.to_string()),
        Cv::Bytes(cnf.as_bytes().to_vec()), // cnf = 0x1e ‖ BLAKE3-256(session_pubkey), the `hash` field
    ]);
    *blake3::hash(&cbor::encode(&arr)).as_bytes()
}

/// The user's signed login response (§18.7.2). The signature (`sig`) is over the domain-separated
/// §18.9.8 preimage `AUTH_ASSERTION_DS ‖ auth_hash`, so a look-alike origin cannot produce a
/// valid assertion for the real RP (phishing defense), and a captured assertion cannot be
/// replayed with an attacker-chosen session key because `cnf` is inside the signed preimage
/// (session-hijack defense, §13.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedAssertion {
    /// key 1 — echo of `Challenge.rp_origin`; the RP MUST verify it equals its own origin.
    pub rp_origin: String,
    /// key 2 — echo of `Challenge.nonce`; MUST be unused and within its window.
    pub nonce: Vec<u8>,
    /// key 3 — echo of `Challenge.issued_at`.
    pub issued_at: TimestampMs,
    /// key 4 — echo of `Challenge.exp`; RP MUST reject if `now > exp`.
    pub exp: TimestampMs,
    /// key 5 — echo of `Challenge.aud`; MUST match the RP.
    pub aud: String,
    /// key 6 — `from`: the identity-revealing **login signer**, an `IK`-authorized device key (or
    /// `IK` itself, §1.2). NOT the session key.
    pub from: Vec<u8>,
    /// key 7 — signature by `from` over the origin-bound preimage including `cnf` (§18.9.8).
    pub sig: Vec<u8>,
    /// key 8 — `cnf = H(session_pubkey)` (RFC 7800 style): commits the fresh per-RP session key
    /// the client generated **before** signing. The RP binds the session **only** to this.
    pub cnf: ContentId,
}

impl SignedAssertion {
    /// The auth_hash the RP reconstructs from the challenge **it issued** plus this assertion's
    /// `cnf` (§18.9.8: "the RP reconstructs it from its own issued Challenge plus the assertion's
    /// cnf"). Binding to the issued challenge — not the assertion's echo — is what makes a forged
    /// echo useless.
    pub(crate) fn auth_hash_from_issued(&self, issued: &Challenge) -> [u8; 32] {
        auth_hash(
            &issued.rp_origin,
            &issued.nonce,
            issued.issued_at,
            issued.exp,
            &issued.aud,
            &self.cnf,
        )
    }

    /// The canonical integer-keyed CBOR map (§18.7.2) — the exact wire form.
    fn to_cv(&self) -> Cv {
        Cv::Map(vec![
            (1u64, Cv::Text(self.rp_origin.clone())),
            (2, Cv::Bytes(self.nonce.clone())),
            (3, Cv::U64(self.issued_at)),
            (4, Cv::U64(self.exp)),
            (5, Cv::Text(self.aud.clone())),
            (6, Cv::Bytes(self.from.clone())),
            (7, Cv::Bytes(self.sig.clone())),
            (8, Cv::Bytes(self.cnf.as_bytes().to_vec())),
        ])
    }

    /// The exact wire bytes: §18-canonical integer-keyed CBOR.
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv())
    }

    /// Decode an assertion from its canonical CBOR (§18.7.2), failing closed on any violation.
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, AuthError> {
        let cv = cbor::decode(bytes).map_err(|_| AuthError::Malformed("assertion CBOR"))?;
        let mut f = Fields::from_cv(cv).map_err(|_| AuthError::Malformed("assertion not a map"))?;
        let mut take = |k: u64| f.req(k).map_err(|_| AuthError::Malformed("assertion field"));
        let rp_origin = as_text(take(1)?).map_err(|_| AuthError::Malformed("rp_origin"))?;
        let nonce = as_bytes(take(2)?).map_err(|_| AuthError::Malformed("nonce"))?;
        let issued_at = as_u64(take(3)?).map_err(|_| AuthError::Malformed("issued_at"))?;
        let exp = as_u64(take(4)?).map_err(|_| AuthError::Malformed("exp"))?;
        let aud = as_text(take(5)?).map_err(|_| AuthError::Malformed("aud"))?;
        let from = as_bytes(take(6)?).map_err(|_| AuthError::Malformed("from"))?;
        let sig = as_bytes(take(7)?).map_err(|_| AuthError::Malformed("sig"))?;
        let cnf = ContentId(as_bytes(take(8)?).map_err(|_| AuthError::Malformed("cnf"))?);
        f.deny_unknown().map_err(|_| AuthError::Malformed("unknown assertion key"))?;
        Ok(SignedAssertion { rp_origin, nonce, issued_at, exp, aud, from, sig, cnf })
    }
}

/// The result of the client-side ceremony: the [`SignedAssertion`] to send to the RP, plus the
/// **retained** [`SessionKey`] the client keeps private and uses for DPoP-style
/// proof-of-possession on every subsequent request (§13.4). The session private key never leaves
/// the client and is never sent to the RP — only `cnf = H(session_pubkey)` is committed.
#[derive(Debug)]
pub struct Login {
    /// The signed assertion to transmit to the relying party.
    pub assertion: SignedAssertion,
    /// The per-RP, per-device session keypair to keep and prove possession of (§13.4).
    pub session: SessionKey,
}

/// Run the client side of the native login ceremony (§13.3 steps 4–5).
///
/// 1. **Origin binding (§13.3.1).** The `client` (a WebAuthn/PRF authenticator or authenticated
///    companion) supplies the *machine-observed* origin; if it disagrees with the challenge's
///    `rp_origin`, the client refuses — a phisher relaying a real challenge to a look-alike page
///    is caught here, before any signature. The crypto core signs over the client's verified
///    origin, never a value trusted from the RP.
/// 2. **User-verification** gates the signature (biometric/PIN/passkey).
/// 3. A **fresh per-RP, per-device session keypair** is generated and `cnf = H(session_pubkey)`
///    is computed **before** signing (§13.3 step 4).
/// 4. `login_key` — an `IK`-authorized device key (or `IK` itself, §1.2) — signs the
///    domain-separated §18.9.8 preimage.
///
/// `login_key` is the identity-revealing login signer, **not** the session key.
pub fn create_login(
    client: &impl TrustedClient,
    challenge: &Challenge,
    login_key: &IdentityKey,
) -> Result<Login, AuthError> {
    // (1) The trusted client enforces origin binding against the machine-observed origin.
    if client.observed_origin() != challenge.rp_origin {
        return Err(AuthError::OriginMismatch);
    }
    // (2) User-verification gates signing.
    client.user_verify()?;

    // (3) Fresh per-RP, per-device session keypair; cnf committed BEFORE signing (§13.3 step 4).
    let session = SessionKey::generate();
    let cnf = session.cnf();

    // (4) Sign the DS-tagged §18.9.8 preimage under the IK-authorized login signer. `sign_domain`
    //     prepends AUTH_ASSERTION_DS (which carries its terminating 0x00) to the auth_hash.
    let hash = auth_hash(
        &challenge.rp_origin,
        &challenge.nonce,
        challenge.issued_at,
        challenge.exp,
        &challenge.aud,
        &cnf,
    );
    let sig = login_key.sign_domain(AUTH_ASSERTION_DS, &hash);

    Ok(Login {
        assertion: SignedAssertion {
            rp_origin: challenge.rp_origin.clone(),
            nonce: challenge.nonce.clone(),
            issued_at: challenge.issued_at,
            exp: challenge.exp,
            aud: challenge.aud.clone(),
            from: login_key.public(),
            sig,
            cnf,
        },
        session,
    })
}

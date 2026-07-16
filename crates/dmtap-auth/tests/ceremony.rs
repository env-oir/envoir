//! Security-property tests for the DMTAP-Auth ceremony (spec §13).
//!
//! Each test encodes one normative property as an assertion about the crypto core:
//! happy-path login, replay, expiry, origin-binding (phishing), session-key binding (DPoP), and
//! wrong-identity-key. These are the guarantees §13 makes, expressed as executable checks — not
//! coverage of incidental code paths.

use dmtap_auth::{
    create_login, verify_login, AuthError, Challenge, Clock, DeviceCertAuthorizer,
    InMemoryReplayCache, SessionKey, TrustedClientStub,
};
use dmtap_core::identity::{Cap, DeviceCert, IdentityKey};

const ORIGIN: &str = "https://app.example.com";
const AUD: &str = "app.example.com";
const T0: u64 = 1_700_000_000_000; // fixed issue time (ms)

/// A manual, injectable clock so tests control expiry/freshness deterministically (§16.1).
struct ManualClock(std::cell::Cell<u64>);
impl ManualClock {
    fn at(t: u64) -> Self {
        ManualClock(std::cell::Cell::new(t))
    }
    fn set(&self, t: u64) {
        self.0.set(t);
    }
}
impl Clock for ManualClock {
    fn now_ms(&self) -> u64 {
        self.0.get()
    }
}

/// Test fixture: a root identity `IK`, an `IK`-authorized device key that signs the login, and an
/// authorizer that resolves the device key to that identity (the §3.4 `name → key` result).
struct Fixture {
    ik: IdentityKey,
    device: IdentityKey,
    authorizer: DeviceCertAuthorizer,
}

impl Fixture {
    fn new() -> Self {
        let ik = IdentityKey::generate();
        let device = IdentityKey::generate();
        let cert: DeviceCert = DeviceCert::issue(
            &ik,
            device.public(),
            "test-device",
            T0,
            Some(T0 + 10 * 365 * 24 * 3_600_000), // long-lived
            vec![Cap::Send, Cap::Recv],
        );
        let authorizer = DeviceCertAuthorizer::new().with_cert(cert);
        Fixture { ik, device, authorizer }
    }
}

/// Drive the full ceremony once at clock time `now` for a given RP/client origin, returning the
/// verification outcome (and, on success, the bound session + retained session key via `Ok`).
fn run_login(
    fx: &Fixture,
    challenge: &Challenge,
    client_origin: &str,
    verify_origin: &str,
    replay: &mut InMemoryReplayCache,
    clock: &ManualClock,
) -> Result<(dmtap_auth::BoundSession, SessionKey), AuthError> {
    let client = TrustedClientStub::new(client_origin);
    let login = create_login(&client, challenge, &fx.device)?;
    let session = login.session;
    let bound = verify_login(
        &fx.ik.public(),
        verify_origin,
        AUD,
        challenge,
        &login.assertion,
        &fx.authorizer,
        replay,
        clock,
    )?;
    Ok((bound, session))
}

// ── 1. Happy path: challenge → assert → verify → key-bound session ───────────────────────────

#[test]
fn happy_path_login_and_key_bound_request() {
    let fx = Fixture::new();
    let clock = ManualClock::at(T0);
    let mut replay = InMemoryReplayCache::new();

    let challenge = Challenge::new(ORIGIN, AUD, clock.now_ms(), None);
    let (bound, session) =
        run_login(&fx, &challenge, ORIGIN, ORIGIN, &mut replay, &clock).expect("login succeeds");

    // The session is bound to cnf = H(session_pubkey) and to the pinned identity, nothing else.
    assert_eq!(bound.cnf, session.cnf(), "session bound only to cnf");
    assert_eq!(bound.subject_ik, fx.ik.public(), "authenticated as the pinned IK");

    // A request carrying a valid DPoP proof from the session key is honored.
    let mut jti_cache = InMemoryReplayCache::new();
    let proof = session.prove("https://app.example.com/api/x", "GET", &clock);
    bound
        .verify_request(&proof, "https://app.example.com/api/x", "GET", &mut jti_cache, &clock)
        .expect("valid DPoP request authorized");
}

// ── 2. Replay: a reused nonce is rejected ────────────────────────────────────────────────────

#[test]
fn replay_reused_nonce_rejected() {
    let fx = Fixture::new();
    let clock = ManualClock::at(T0);
    let mut replay = InMemoryReplayCache::new();

    let challenge = Challenge::new(ORIGIN, AUD, clock.now_ms(), None);

    // First presentation of an assertion for this nonce succeeds and consumes the nonce.
    run_login(&fx, &challenge, ORIGIN, ORIGIN, &mut replay, &clock).expect("first login ok");

    // A second valid assertion for the SAME challenge/nonce must be rejected as a replay.
    let err = run_login(&fx, &challenge, ORIGIN, ORIGIN, &mut replay, &clock).unwrap_err();
    assert_eq!(err, AuthError::Replay, "reused nonce must be rejected");
}

#[test]
fn replay_dpop_jti_reuse_rejected() {
    let fx = Fixture::new();
    let clock = ManualClock::at(T0);
    let mut replay = InMemoryReplayCache::new();
    let challenge = Challenge::new(ORIGIN, AUD, clock.now_ms(), None);
    let (bound, session) =
        run_login(&fx, &challenge, ORIGIN, ORIGIN, &mut replay, &clock).expect("login ok");

    let mut jti_cache = InMemoryReplayCache::new();
    let proof = session.prove("https://app.example.com/api/x", "POST", &clock);
    bound
        .verify_request(&proof, "https://app.example.com/api/x", "POST", &mut jti_cache, &clock)
        .expect("first request ok");
    // Replaying the exact same DPoP proof (same jti) is rejected.
    let err = bound
        .verify_request(&proof, "https://app.example.com/api/x", "POST", &mut jti_cache, &clock)
        .unwrap_err();
    assert_eq!(err, AuthError::Replay, "reused DPoP jti must be rejected");
}

// ── 3. Expiry: an assertion after exp is rejected ────────────────────────────────────────────

#[test]
fn expired_challenge_rejected() {
    let fx = Fixture::new();
    let clock = ManualClock::at(T0);
    let mut replay = InMemoryReplayCache::new();

    let challenge = Challenge::new(ORIGIN, AUD, clock.now_ms(), None);
    // Advance past exp (120 s window) before verification.
    clock.set(challenge.exp + 1);

    let err = run_login(&fx, &challenge, ORIGIN, ORIGIN, &mut replay, &clock).unwrap_err();
    assert_eq!(err, AuthError::Expired, "assertion after exp must be rejected");
}

// ── 4. Origin binding: an assertion for origin A is rejected at origin B (phishing defense) ──

#[test]
fn origin_binding_rejects_cross_origin_at_rp() {
    let fx = Fixture::new();
    let clock = ManualClock::at(T0);
    let mut replay = InMemoryReplayCache::new();

    // The REAL RP issues a challenge for its true origin. A relayed assertion is minted for that
    // origin, but a DIFFERENT RP (origin B) tries to accept it. The RP-side origin check refuses.
    let challenge = Challenge::new(ORIGIN, AUD, clock.now_ms(), None);
    let err = run_login(
        &fx,
        &challenge,
        ORIGIN,                       // client observed the real origin
        "https://evil.example.net",   // but a look-alike RP tries to verify
        &mut replay,
        &clock,
    )
    .unwrap_err();
    assert_eq!(err, AuthError::OriginMismatch, "assertion for origin A rejected at origin B");
}

#[test]
fn origin_binding_trusted_client_refuses_relayed_challenge() {
    let fx = Fixture::new();
    let clock = ManualClock::at(T0);

    // A phisher relays the REAL RP's challenge (rp_origin = the real site) to the user, but the
    // user's trusted client actually observes the phishing origin. The client refuses to sign —
    // origin binding is enforced on the user's side (§13.3.1), before any signature exists.
    let challenge = Challenge::new(ORIGIN, AUD, clock.now_ms(), None);
    let phishing_client = TrustedClientStub::new("https://evil.example.net");
    let err = create_login(&phishing_client, &challenge, &fx.device).unwrap_err();
    assert_eq!(err, AuthError::OriginMismatch, "trusted client refuses a relayed challenge");
}

// ── 5. Session-key binding (DPoP): valid assertion + WRONG session key is useless ────────────

#[test]
fn session_key_binding_wrong_key_rejected() {
    let fx = Fixture::new();
    let clock = ManualClock::at(T0);
    let mut replay = InMemoryReplayCache::new();
    let challenge = Challenge::new(ORIGIN, AUD, clock.now_ms(), None);
    let (bound, _session) =
        run_login(&fx, &challenge, ORIGIN, ORIGIN, &mut replay, &clock).expect("login ok");

    // An attacker who captured the assertion learns cnf but NOT the session private key. They
    // forge a DPoP proof with THEIR OWN session key: H(their_pubkey) != cnf → rejected.
    let attacker_key = SessionKey::generate();
    let mut jti_cache = InMemoryReplayCache::new();
    let forged = attacker_key.prove("https://app.example.com/api/x", "GET", &clock);
    let err = bound
        .verify_request(&forged, "https://app.example.com/api/x", "GET", &mut jti_cache, &clock)
        .unwrap_err();
    assert_eq!(err, AuthError::SessionKeyMismatch, "wrong session key does not match bound cnf");
}

#[test]
fn session_key_binding_right_key_wrong_signature_rejected() {
    // The subtler attack: the attacker presents the *correct* session public key (so H(pk)==cnf)
    // but cannot sign, because they lack the private key. A proof with the real pubkey but a
    // tampered signature must fail signature verification.
    let fx = Fixture::new();
    let clock = ManualClock::at(T0);
    let mut replay = InMemoryReplayCache::new();
    let challenge = Challenge::new(ORIGIN, AUD, clock.now_ms(), None);
    let (bound, session) =
        run_login(&fx, &challenge, ORIGIN, ORIGIN, &mut replay, &clock).expect("login ok");

    let mut jti_cache = InMemoryReplayCache::new();
    let mut proof = session.prove("https://app.example.com/api/x", "GET", &clock);
    proof.sig[0] ^= 0x01; // tamper the signature; pubkey (hence cnf match) is untouched
    let err = bound
        .verify_request(&proof, "https://app.example.com/api/x", "GET", &mut jti_cache, &clock)
        .unwrap_err();
    assert_eq!(err, AuthError::BadSignature, "cannot prove possession without the private key");
}

#[test]
fn dpop_request_binding_and_freshness_enforced() {
    let fx = Fixture::new();
    let clock = ManualClock::at(T0);
    let mut replay = InMemoryReplayCache::new();
    let challenge = Challenge::new(ORIGIN, AUD, clock.now_ms(), None);
    let (bound, session) =
        run_login(&fx, &challenge, ORIGIN, ORIGIN, &mut replay, &clock).expect("login ok");

    // A proof for one URL/method cannot authorize a different request.
    let proof = session.prove("https://app.example.com/api/x", "GET", &clock);
    let mut jti_cache = InMemoryReplayCache::new();
    let err = bound
        .verify_request(&proof, "https://app.example.com/api/OTHER", "GET", &mut jti_cache, &clock)
        .unwrap_err();
    assert_eq!(err, AuthError::RequestMismatch, "htu binding enforced");

    // A stale proof (issued far in the past) is rejected on freshness.
    let stale = session.prove("https://app.example.com/api/x", "GET", &clock);
    clock.set(T0 + 10 * 60 * 1000); // +10 min, beyond the 5-min window
    let err = bound
        .verify_request(&stale, "https://app.example.com/api/x", "GET", &mut jti_cache, &clock)
        .unwrap_err();
    assert_eq!(err, AuthError::RequestMismatch, "stale DPoP iat rejected");
}

// ── 6. Wrong identity key: an assertion not from the pinned identity is rejected ─────────────

#[test]
fn wrong_identity_key_rejected() {
    let fx = Fixture::new();
    let clock = ManualClock::at(T0);
    let mut replay = InMemoryReplayCache::new();
    let challenge = Challenge::new(ORIGIN, AUD, clock.now_ms(), None);

    // A well-formed assertion signed by a device the RP's pinned identity never authorized.
    let stranger = IdentityKey::generate();
    let client = TrustedClientStub::new(ORIGIN);
    let login = create_login(&client, &challenge, &stranger).expect("stranger can sign locally");

    // The RP pins fx.ik; the stranger's key is not authorized under it → rejected.
    let err = verify_login(
        &fx.ik.public(),
        ORIGIN,
        AUD,
        &challenge,
        &login.assertion,
        &fx.authorizer,
        &mut replay,
        &clock,
    )
    .unwrap_err();
    assert_eq!(err, AuthError::UnauthorizedSigner, "unauthorized signer rejected");
}

#[test]
fn cert_signed_by_other_ik_rejected() {
    // Defense-in-depth: an attacker supplies a device cert for their signer, but signed by their
    // OWN IK. Against a pinned victim IK, DeviceCertAuthorizer must not authorize it.
    let clock = ManualClock::at(T0);
    let mut replay = InMemoryReplayCache::new();
    let challenge = Challenge::new(ORIGIN, AUD, clock.now_ms(), None);

    let attacker_ik = IdentityKey::generate();
    let attacker_device = IdentityKey::generate();
    let attacker_cert = DeviceCert::issue(
        &attacker_ik,
        attacker_device.public(),
        "attacker",
        T0,
        None,
        vec![Cap::Send],
    );
    // The authorizer is fed the attacker's own cert, but the RP pins the VICTIM's IK.
    let authorizer = DeviceCertAuthorizer::new().with_cert(attacker_cert);
    let victim_ik = IdentityKey::generate();

    let client = TrustedClientStub::new(ORIGIN);
    let login = create_login(&client, &challenge, &attacker_device).expect("signs locally");
    let err = verify_login(
        &victim_ik.public(),
        ORIGIN,
        AUD,
        &challenge,
        &login.assertion,
        &authorizer,
        &mut replay,
        &clock,
    )
    .unwrap_err();
    assert_eq!(err, AuthError::UnauthorizedSigner, "cert signed by another IK does not authorize");
}

// ── 7. Tamper / integrity: forged cnf or echoed field breaks the signature ───────────────────

#[test]
fn tampered_cnf_breaks_signature() {
    // If an attacker swaps cnf (to bind an attacker-chosen session key) the signature — taken
    // over a preimage INCLUDING cnf (§18.9.8) — no longer verifies.
    let fx = Fixture::new();
    let clock = ManualClock::at(T0);
    let mut replay = InMemoryReplayCache::new();
    let challenge = Challenge::new(ORIGIN, AUD, clock.now_ms(), None);
    let client = TrustedClientStub::new(ORIGIN);
    let mut login = create_login(&client, &challenge, &fx.device).expect("login ok");

    // Substitute an attacker-controlled session key's cnf; sig is unchanged → must fail.
    login.assertion.cnf = SessionKey::generate().cnf();
    let err = verify_login(
        &fx.ik.public(),
        ORIGIN,
        AUD,
        &challenge,
        &login.assertion,
        &fx.authorizer,
        &mut replay,
        &clock,
    )
    .unwrap_err();
    assert_eq!(err, AuthError::BadSignature, "cnf is inside the signed preimage");
}

// ── 8. Wire round-trips (canonical §18 CBOR) ─────────────────────────────────────────────────

#[test]
fn challenge_and_assertion_wire_round_trip() {
    let fx = Fixture::new();
    let clock = ManualClock::at(T0);
    let challenge = Challenge::new(ORIGIN, AUD, clock.now_ms(), Some(vec!["openid".into()]));
    let rt = Challenge::from_det_cbor(&challenge.det_cbor()).expect("challenge round-trips");
    assert_eq!(rt, challenge);

    let client = TrustedClientStub::new(ORIGIN);
    let login = create_login(&client, &challenge, &fx.device).expect("login ok");
    let rt = dmtap_auth::SignedAssertion::from_det_cbor(&login.assertion.det_cbor())
        .expect("assertion round-trips");
    assert_eq!(rt, login.assertion);
}

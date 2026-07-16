//! Security-property tests for the DMTAP-Auth ceremony (spec §13).
//!
//! Each test encodes one normative property as an assertion about the crypto core:
//! happy-path login, replay, expiry, origin-binding (phishing), session-key binding (DPoP), and
//! wrong-identity-key. These are the guarantees §13 makes, expressed as executable checks — not
//! coverage of incidental code paths.

use dmtap_auth::session::DPOP_FRESHNESS_MS;
use dmtap_auth::{
    create_login, verify_login, AuthError, Challenge, Clock, DeviceCertAuthorizer,
    InMemoryReplayCache, SessionKey, TrustedClientStub,
};
use dmtap_core::cbor::{self, Cv};
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

// ── 7b. Scope binding: an assertion cannot grant a scope broader than the user signed ────────

#[test]
fn matching_scope_verifies() {
    // Happy path with a non-empty scope: the assertion echoes the challenge scope and verifies.
    let fx = Fixture::new();
    let clock = ManualClock::at(T0);
    let mut replay = InMemoryReplayCache::new();
    let challenge = Challenge::new(ORIGIN, AUD, clock.now_ms(), Some(vec!["mail:read".into()]));
    let client = TrustedClientStub::new(ORIGIN);
    let login = create_login(&client, &challenge, &fx.device).expect("login ok");
    assert_eq!(login.assertion.scope, vec!["mail:read".to_string()], "scope echoed into assertion");
    verify_login(
        &fx.ik.public(),
        ORIGIN,
        AUD,
        &challenge,
        &login.assertion,
        &fx.authorizer,
        &mut replay,
        &clock,
    )
    .expect("an assertion whose scope matches the issued challenge verifies");
}

#[test]
fn scope_elevation_broader_echo_rejected() {
    // The user signs a login for scope ["mail:read"]. An attacker broadens the *echoed* scope to
    // ["mail:read","mail:write"] to elevate privilege. The RP grants only the scope of the
    // challenge it issued, so the broadened echo is rejected fail-closed (§18.7.2 key 9).
    let fx = Fixture::new();
    let clock = ManualClock::at(T0);
    let mut replay = InMemoryReplayCache::new();
    let challenge = Challenge::new(ORIGIN, AUD, clock.now_ms(), Some(vec!["mail:read".into()]));
    let client = TrustedClientStub::new(ORIGIN);
    let mut login = create_login(&client, &challenge, &fx.device).expect("login ok");

    login.assertion.scope = vec!["mail:read".into(), "mail:write".into()]; // broadened
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
    assert_eq!(err, AuthError::ScopeMismatch, "a broadened scope is scope-elevation, rejected");
}

#[test]
fn scope_broader_grant_fails_signature() {
    // The cryptographic half of the defense: even if the echoed scope is made to *match* what the
    // RP will grant, a grant broader than what was actually signed still fails, because `scope` is
    // inside the signed preimage (§18.9.8). The user signs for ["mail:read"]; the RP then attempts
    // to reconstruct/grant ["mail:read","mail:write"] — a different preimage → the signature fails.
    let fx = Fixture::new();
    let clock = ManualClock::at(T0);
    let mut replay = InMemoryReplayCache::new();
    let signed = Challenge::new(ORIGIN, AUD, clock.now_ms(), Some(vec!["mail:read".into()]));
    let client = TrustedClientStub::new(ORIGIN);
    let mut login = create_login(&client, &signed, &fx.device).expect("login ok");

    // The RP's issued view carries the broader scope it would grant; make the echo match it so the
    // (3b) echo check passes and we reach the signature check reconstructed from the ISSUED scope.
    let broader = vec!["mail:read".to_string(), "mail:write".to_string()];
    let issued = Challenge { scope: Some(broader.clone()), ..signed };
    login.assertion.scope = broader;
    let err = verify_login(
        &fx.ik.public(),
        ORIGIN,
        AUD,
        &issued,
        &login.assertion,
        &fx.authorizer,
        &mut replay,
        &clock,
    )
    .unwrap_err();
    assert_eq!(err, AuthError::BadSignature, "scope is inside the signed preimage — a broader grant fails to verify");
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

// ── 9. Tampered assertion signature: a bit-flipped `sig` is rejected outright ─────────────────

#[test]
fn tampered_assertion_signature_rejected() {
    let fx = Fixture::new();
    let clock = ManualClock::at(T0);
    let mut replay = InMemoryReplayCache::new();
    let challenge = Challenge::new(ORIGIN, AUD, clock.now_ms(), None);
    let client = TrustedClientStub::new(ORIGIN);
    let mut login = create_login(&client, &challenge, &fx.device).expect("login ok");

    login.assertion.sig[0] ^= 0x01; // flip a bit of the signature itself
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
    assert_eq!(err, AuthError::BadSignature, "a tampered assertion signature must be rejected");
}

// ── 10. Nonce reservation ordering: a failed attempt must NEVER burn the nonce ────────────────

#[test]
fn failed_attempt_does_not_burn_the_nonce() {
    // The nonce/replay-cache reservation is documented as the LAST gate in `verify_login` so an
    // otherwise-invalid attempt (bad signature here) never consumes it. Prove it: a tampered
    // attempt fails, and a SUBSEQUENT genuine assertion for the exact same challenge still
    // succeeds — the failed attempt left the nonce untouched.
    let fx = Fixture::new();
    let clock = ManualClock::at(T0);
    let mut replay = InMemoryReplayCache::new();
    let challenge = Challenge::new(ORIGIN, AUD, clock.now_ms(), None);
    let client = TrustedClientStub::new(ORIGIN);

    // First attempt: tamper the signature so it fails at step 6, before the nonce reservation.
    let mut bad_login = create_login(&client, &challenge, &fx.device).expect("login ok");
    bad_login.assertion.sig[0] ^= 0x01;
    let err = verify_login(
        &fx.ik.public(),
        ORIGIN,
        AUD,
        &challenge,
        &bad_login.assertion,
        &fx.authorizer,
        &mut replay,
        &clock,
    )
    .unwrap_err();
    assert_eq!(err, AuthError::BadSignature);

    // Second attempt: a genuinely signed assertion for the SAME challenge/nonce must still
    // succeed — proof the failed attempt above never reserved the nonce.
    let good_login = create_login(&client, &challenge, &fx.device).expect("login ok");
    let bound = verify_login(
        &fx.ik.public(),
        ORIGIN,
        AUD,
        &challenge,
        &good_login.assertion,
        &fx.authorizer,
        &mut replay,
        &clock,
    )
    .expect("a failed attempt must not burn the nonce for a later genuine one");
    assert_eq!(bound.subject_ik, fx.ik.public());

    // A THIRD attempt — even a genuine re-signature of the same challenge — is now a true replay:
    // the nonce was legitimately consumed by the successful second attempt.
    let third_login = create_login(&client, &challenge, &fx.device).expect("login ok");
    let err = verify_login(
        &fx.ik.public(),
        ORIGIN,
        AUD,
        &challenge,
        &third_login.assertion,
        &fx.authorizer,
        &mut replay,
        &clock,
    )
    .unwrap_err();
    assert_eq!(err, AuthError::Replay, "the nonce IS burned once a verification succeeds");
}

#[test]
fn failed_dpop_attempt_does_not_burn_the_jti() {
    // Symmetric property for the DPoP per-request jti (§13.4): `verify_request` reserves `jti`
    // only after the signature verifies, so a forged proof must not consume a legitimate jti.
    let fx = Fixture::new();
    let clock = ManualClock::at(T0);
    let mut replay = InMemoryReplayCache::new();
    let challenge = Challenge::new(ORIGIN, AUD, clock.now_ms(), None);
    let (bound, session) =
        run_login(&fx, &challenge, ORIGIN, ORIGIN, &mut replay, &clock).expect("login ok");

    let mut jti_cache = InMemoryReplayCache::new();
    let mut proof = session.prove("https://app.example.com/api/x", "GET", &clock);
    proof.sig[0] ^= 0x01; // forged: signature will not verify
    let err = bound
        .verify_request(&proof, "https://app.example.com/api/x", "GET", &mut jti_cache, &clock)
        .unwrap_err();
    assert_eq!(err, AuthError::BadSignature);

    // Re-sign the SAME jti/context genuinely (simulating the honest client's real request that
    // happened to reuse the same random jti is astronomically unlikely, but the point here is
    // narrower: the failed forged proof above must not have reserved anything at all).
    let good = session.prove("https://app.example.com/api/x", "GET", &clock);
    bound
        .verify_request(&good, "https://app.example.com/api/x", "GET", &mut jti_cache, &clock)
        .expect("the forged attempt must not have poisoned the replay cache");
}

// ── 11. Expiry boundary: exactly `now == exp` is still valid; one ms later is not ─────────────

#[test]
fn expiry_boundary_exact_exp_is_still_valid() {
    let fx = Fixture::new();
    let clock = ManualClock::at(T0);
    let mut replay = InMemoryReplayCache::new();
    let challenge = Challenge::new(ORIGIN, AUD, clock.now_ms(), None);
    clock.set(challenge.exp); // exactly at expiry — `now > exp` is false here
    run_login(&fx, &challenge, ORIGIN, ORIGIN, &mut replay, &clock)
        .expect("now == exp must still be accepted (only now > exp is rejected)");
}

// ── 12. DPoP freshness boundary: exactly the window is fresh; one ms past is not ──────────────

#[test]
fn dpop_freshness_boundary_exact_window_is_fresh() {
    let fx = Fixture::new();
    let clock = ManualClock::at(T0);
    let mut replay = InMemoryReplayCache::new();
    let challenge = Challenge::new(ORIGIN, AUD, clock.now_ms(), None);
    let (bound, session) =
        run_login(&fx, &challenge, ORIGIN, ORIGIN, &mut replay, &clock).expect("login ok");

    let proof = session.prove("https://app.example.com/api/x", "GET", &clock); // iat = T0
    let mut jti_cache = InMemoryReplayCache::new();
    clock.set(T0 + DPOP_FRESHNESS_MS); // exactly at the boundary
    bound
        .verify_request(&proof, "https://app.example.com/api/x", "GET", &mut jti_cache, &clock)
        .expect("exactly at the freshness window boundary must still be fresh");
}

#[test]
fn dpop_freshness_boundary_one_ms_past_window_rejected() {
    let fx = Fixture::new();
    let clock = ManualClock::at(T0);
    let mut replay = InMemoryReplayCache::new();
    let challenge = Challenge::new(ORIGIN, AUD, clock.now_ms(), None);
    let (bound, session) =
        run_login(&fx, &challenge, ORIGIN, ORIGIN, &mut replay, &clock).expect("login ok");

    let proof = session.prove("https://app.example.com/api/x", "GET", &clock); // iat = T0
    let mut jti_cache = InMemoryReplayCache::new();
    clock.set(T0 + DPOP_FRESHNESS_MS + 1); // one ms past the boundary
    let err = bound
        .verify_request(&proof, "https://app.example.com/api/x", "GET", &mut jti_cache, &clock)
        .unwrap_err();
    assert_eq!(err, AuthError::RequestMismatch, "one ms past the window must be rejected");
}

// ── 13. Malformed wire input fails closed — never panics (§13, canonical CBOR) ───────────────

#[test]
fn challenge_decode_fails_closed_never_panics() {
    // Empty input.
    assert!(matches!(Challenge::from_det_cbor(&[]), Err(AuthError::Malformed(_))));

    // A truncated, otherwise-valid encoding.
    let fx_clock = ManualClock::at(T0);
    let challenge = Challenge::new(ORIGIN, AUD, fx_clock.now_ms(), None);
    let bytes = challenge.det_cbor();
    let truncated = &bytes[..bytes.len() - 1];
    assert!(matches!(Challenge::from_det_cbor(truncated), Err(AuthError::Malformed(_))));

    // Top-level value is not a map at all (a bare array).
    let not_a_map = cbor::encode(&Cv::Array(vec![Cv::U64(1), Cv::U64(2)]));
    assert!(matches!(Challenge::from_det_cbor(&not_a_map), Err(AuthError::Malformed(_))));

    // A required field has the wrong CBOR type: `aud` (key 5) as bytes instead of text.
    let wrong_type = Cv::Map(vec![
        (1, Cv::Text(ORIGIN.to_string())),
        (2, Cv::Bytes(vec![0u8; 32])),
        (3, Cv::U64(T0)),
        (4, Cv::U64(T0 + 1000)),
        (5, Cv::Bytes(vec![1, 2, 3])), // should be Cv::Text
    ]);
    assert!(matches!(
        Challenge::from_det_cbor(&cbor::encode(&wrong_type)),
        Err(AuthError::Malformed(_))
    ));

    // A required field is missing entirely (no key 5 / aud).
    let missing_field = Cv::Map(vec![
        (1, Cv::Text(ORIGIN.to_string())),
        (2, Cv::Bytes(vec![0u8; 32])),
        (3, Cv::U64(T0)),
        (4, Cv::U64(T0 + 1000)),
    ]);
    assert!(matches!(
        Challenge::from_det_cbor(&cbor::encode(&missing_field)),
        Err(AuthError::Malformed(_))
    ));

    // An unrecognized extra key must be rejected (deny_unknown), not silently ignored.
    let extra_key = Cv::Map(vec![
        (1, Cv::Text(ORIGIN.to_string())),
        (2, Cv::Bytes(vec![0u8; 32])),
        (3, Cv::U64(T0)),
        (4, Cv::U64(T0 + 1000)),
        (5, Cv::Text(AUD.to_string())),
        (99, Cv::U64(0)), // unknown
    ]);
    assert!(matches!(
        Challenge::from_det_cbor(&cbor::encode(&extra_key)),
        Err(AuthError::Malformed(_))
    ));
}

#[test]
fn signed_assertion_decode_fails_closed_never_panics() {
    assert!(matches!(
        dmtap_auth::SignedAssertion::from_det_cbor(&[]),
        Err(AuthError::Malformed(_))
    ));

    let fx = Fixture::new();
    let clock = ManualClock::at(T0);
    let challenge = Challenge::new(ORIGIN, AUD, clock.now_ms(), None);
    let client = TrustedClientStub::new(ORIGIN);
    let login = create_login(&client, &challenge, &fx.device).expect("login ok");
    let bytes = login.assertion.det_cbor();

    // Truncated.
    let truncated = &bytes[..bytes.len() - 2];
    assert!(matches!(
        dmtap_auth::SignedAssertion::from_det_cbor(truncated),
        Err(AuthError::Malformed(_))
    ));

    // Top-level not a map.
    let not_a_map = cbor::encode(&Cv::Text("not an assertion".into()));
    assert!(matches!(
        dmtap_auth::SignedAssertion::from_det_cbor(&not_a_map),
        Err(AuthError::Malformed(_))
    ));

    // A required field wrong-typed: `from` (key 6) as text instead of bytes.
    let mut cv = match cbor::decode(&bytes).unwrap() {
        Cv::Map(m) => m,
        _ => unreachable!(),
    };
    for entry in cv.iter_mut() {
        if entry.0 == 6 {
            entry.1 = Cv::Text("not-bytes".into());
        }
    }
    assert!(matches!(
        dmtap_auth::SignedAssertion::from_det_cbor(&cbor::encode(&Cv::Map(cv))),
        Err(AuthError::Malformed(_))
    ));

    // An unrecognized extra key on a fully valid assertion must be rejected.
    let mut cv2 = match cbor::decode(&bytes).unwrap() {
        Cv::Map(m) => m,
        _ => unreachable!(),
    };
    cv2.push((100, Cv::Bytes(vec![0u8; 4])));
    assert!(matches!(
        dmtap_auth::SignedAssertion::from_det_cbor(&cbor::encode(&Cv::Map(cv2))),
        Err(AuthError::Malformed(_))
    ));
}

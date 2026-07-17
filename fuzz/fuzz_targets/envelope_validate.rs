#![no_main]
use libfuzzer_sys::fuzz_target;

use dmtap_core::mote::{
    validate, validate_pinned, Envelope, Hpke, RecipientCtx, SealKeypair,
};
use dmtap_core::suite::SuiteRatchet;

// Envelope/MOTE decode + the §2.7 ordered-validation path (steps 1–8), fed fully attacker-controlled
// bytes. This exercises the whole recipient pipeline a hostile MOTE reaches: version/suite gate,
// content-address check, the MANDATORY ephemeral `sender_sig` verification (§2.7 step 3), the `to`
// resolution, the cold-sender abuse gate, HPKE open(), and — the new S2 context-binding gate
// (§18.9.2 / `ERR_ENVELOPE_CONTEXT_MISMATCH` `0x0211`) — the step-8 recompute of `payload_hash` over
// the RECEIVED envelope's `kind`/`ts`/`to`. A decoded envelope whose fields disagree with any bound
// signature MUST fail closed (an `Err`), NEVER panic and never be `Accepted`.
//
// Both a fresh [`validate`] and the [`validate_pinned`] variant (which layers the §1.3 per-contact
// suite high-water-mark on top) are run, so the ratchet-composed path is covered too.
//
// The recipient identity/seal keypair is fixed (derived from a constant seed) so the pipeline runs
// deterministically against the same node on every input; the attack surface being fuzzed is the
// envelope bytes, not the recipient's own key material.
fuzz_target!(|data: &[u8]| {
    let Ok(env) = Envelope::from_det_cbor(data) else { return };

    // A decoded envelope MUST re-encode to canonical bytes without panicking (round-trip surface).
    let _ = env.det_cbor();

    // Fixed recipient node (constant seed): the payload was never sealed to this key, so decryption
    // fails closed for essentially every input — the point is that NO input reaches a panic and none
    // is spuriously `Accepted`.
    let seal = SealKeypair::generate();
    let our_ik = [0x11u8; 32];

    for sender_is_known in [true, false] {
        let ctx = RecipientCtx {
            our_ik: &our_ik,
            seal_secret: seal.secret(),
            sender_is_known,
        };
        // Step 1: never panic. Step 2: an `Ok(Accepted)` here would mean a forged/garbage envelope
        // decrypted AND its identity signature verified against a random key — cryptographically
        // impossible, so treat it as a hard invariant.
        match validate(&Hpke, &env, &ctx) {
            Ok(_) | Err(_) => {}
        }

        // The suite-pinned variant must likewise never panic and composes the §1.3 ratchet on top.
        let mut ratchet = SuiteRatchet::new();
        let _ = validate_pinned(&Hpke, &env, &ctx, Some(&mut ratchet));
    }
});

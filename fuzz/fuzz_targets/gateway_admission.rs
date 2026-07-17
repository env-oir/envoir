#![no_main]
use libfuzzer_sys::fuzz_target;
use envoir_gateway::authz::{AdmissionError, IdentityRegistry};

/// The gateway's challenge–response admission (§7.9, §9, `envoir-gateway`'s `authz` module):
/// `IdentityRegistry::admit` is called with a **presented key** and a **signature**, both fully
/// attacker-controlled bytes over the wire (a connecting SMTP client presents whatever it wants) —
/// `admit` hands them straight to `dmtap-core`'s `verify_domain`, which parses the key bytes into an
/// Ed25519 verifying key and the signature bytes into an Ed25519 signature before checking anything.
/// This is exactly the "parse untrusted bytes before any signature is trusted" attack surface the
/// rest of this fuzz suite targets, just at the gateway-admission boundary instead of a CBOR decoder.
///
/// Property checked: for ANY `presented_key`/`sig` byte strings, against a fixed challenge, `admit`
/// must never panic — it must always return one of the documented, fail-closed [`AdmissionError`]
/// variants (or, for the vanishingly unlikely case the fuzzer forges a byte-identical valid signature,
/// `Ok`), never crash or hang.
fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    // First byte picks where to split the rest of `data` into the presented key and the signature —
    // both fully attacker-controlled, exercising every possible pairing and every possible length
    // (including 0, 1, and far-too-long, all of which a real Ed25519 parse must reject cleanly).
    let (split_byte, rest) = data.split_at(1);
    let split = (split_byte[0] as usize) % (rest.len() + 1);
    let (presented_key, sig) = rest.split_at(split);

    // A registry with nothing registered (so a key-registered-mode admit can only ever reach
    // `UnknownKey` past a valid signature — irrelevant to this property, but keeps the harness
    // deterministic) plus a fixed challenge and admission time. The clock/nonce are not the
    // attacker-controlled surface here (production draws the nonce from the OS CSPRNG); only the
    // presented key and signature are.
    let reg = IdentityRegistry::key_registered();
    let challenge = reg.issue_challenge([0x11; 32], 1_000_000);

    match reg.admit(&challenge, presented_key, sig, 1_000_100) {
        Ok(_) | Err(AdmissionError::BadSignature) | Err(AdmissionError::UnknownKey) => {}
        Err(AdmissionError::ChallengeExpired) => {
            unreachable!("fixed challenge/now are inside the default TTL window")
        }
    }
});

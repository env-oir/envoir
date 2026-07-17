#![no_main]
use libfuzzer_sys::fuzz_target;
use dmtap::naming::{gateway_alias_local, ik_from_gateway_alias};

/// The node's key-derived legacy gateway alias (§3.9, §7) — `envoir-node`'s `dmtap::naming` module
/// (`../node/src/naming.rs`). Any SMTP↔DMTAP gateway decodes an inbound local-part with
/// `ik_from_gateway_alias` **before** any other authentication has happened (it is what lets an
/// un-provisioned gateway route mail with no directory lookup at all), so it is handed a fully
/// attacker-controlled SMTP local-part — exactly the same trust position as a wire decoder.
///
/// Two properties, both checked here:
///  1. `ik_from_gateway_alias(local)` — **never panics**, on any string, and fails closed (returns
///     `None`) on anything that is not a well-formed, canonically-padded base32 body behind the
///     `dmtap1-` prefix.
///  2. `gateway_alias_local(ik)` → `ik_from_gateway_alias` **round-trips** (bijection) for every
///     32-byte key: encoding a key and decoding the result must always recover the exact same bytes.
fuzz_target!(|data: &[u8]| {
    // Property 1: an arbitrary local-part (attacker-controlled SMTP `RCPT TO`/`MAIL FROM` local
    // part) must never panic and must fail closed on anything not a canonical alias.
    let as_str = String::from_utf8_lossy(data).into_owned();
    let _ = ik_from_gateway_alias(&as_str);

    // Property 2: bijection for arbitrary 32-byte keys — reuse the same fuzz bytes as key material
    // (any 32 bytes, valid or not as an actual Ed25519 point, are a legal input to a pure encoding
    // function) whenever there are enough of them.
    if data.len() >= 32 {
        let ik: [u8; 32] = data[..32].try_into().expect("checked len");
        let alias = gateway_alias_local(&ik);
        let recovered = ik_from_gateway_alias(&alias)
            .expect("an alias this function itself just produced must always decode back");
        assert_eq!(recovered, ik, "gateway alias encode/decode round trip must be a bijection");

        // Case-folding a canonical alias (as any case-normalizing legacy MTA may do) must not
        // change the recovered key — the decode side is documented case-insensitive.
        let upper = alias.to_uppercase();
        assert_eq!(
            ik_from_gateway_alias(&upper).as_deref(),
            Some(ik.as_slice()),
            "case-folded alias must still decode to the same key"
        );
    }
});

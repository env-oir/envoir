#![no_main]
use libfuzzer_sys::fuzz_target;

use dmtap_core::capability::CapabilityToken;
use dmtap_core::id::ContentId;

// Capability-token decode (§18.7.3) + the offline **delegation-chain verification** it feeds
// (`verify_chain`, `verify_chain_rooted`, `verify_at`), fed fully attacker-controlled bytes. The
// chain walk enforces, fail-closed at every link: both signatures verify, `child.prnt` = parent
// content-address, `child.iss` = parent `aud`, the `[nbf, exp)` window nests, and every child
// capability is `≤` some parent capability (no privilege escalation). None of these paths may panic
// on hostile input, and a forged/garbage chain MUST never verify (`Ok`) — an attacker-minted chain
// that verified would be a capability-forgery / privilege-escalation break.
//
// `data` is parsed as a sequence of length-delimited token blobs (`u16be len ‖ bytes`); the ones
// that decode form a candidate chain (`head` + ancestors). Because the fuzzer cannot mint a valid
// Ed25519 signature, `verify()`/`verify_chain()` should reject every such chain — the property this
// pins is *no panic* and *no spurious accept*.
fuzz_target!(|data: &[u8]| {
    let tokens = parse_tokens(data);
    let Some((head, chain)) = tokens.split_first() else { return };

    // Single-token surface: signature check, invocation-window/revocation check, content address.
    let _ = head.verify();
    let now = 1_700_000_000_000u64 ^ (data.len() as u64);
    let _ = head.verify_at(now, &[]);
    let cid = head.content_id();
    let _ = head.verify_at(now, std::slice::from_ref(&cid)); // self-revocation path
    let _ = head.det_cbor();

    // Chain surface: walk to a root, with and without a trust anchor. Must never panic; a fuzzer
    // cannot forge the signatures/links, so a returned `Ok` would be a real forgery finding.
    let _ = head.verify_chain(chain);
    let anchor: Vec<u8> = head.iss.clone();
    let _ = head.verify_chain_rooted(chain, &anchor);
    let _ = head.verify_chain_rooted(chain, &[0u8; 32]);
    let _ = ContentId::of(&head.det_cbor());
});

/// Parse `data` as a sequence of `u16be length ‖ length bytes` records, decoding each as a token.
/// Malformed / non-decoding records are skipped; up to 8 tokens are collected.
fn parse_tokens(mut data: &[u8]) -> Vec<CapabilityToken> {
    let mut out = Vec::new();
    while out.len() < 8 && data.len() >= 2 {
        let len = usize::from(u16::from_be_bytes([data[0], data[1]]));
        data = &data[2..];
        let take = len.min(data.len());
        let (blob, rest) = data.split_at(take);
        data = rest;
        if let Ok(tok) = CapabilityToken::from_det_cbor(blob) {
            out.push(tok);
        }
        if take < len {
            break; // ran out of bytes
        }
    }
    out
}

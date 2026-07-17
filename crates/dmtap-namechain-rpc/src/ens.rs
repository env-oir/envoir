//! ENS (`.eth`) resolution over **Ethereum JSON-RPC** — spec §3.12.5, EIP-137, ENSIP-10 / EIP-3668.
//!
//! ## Resolution path
//! 1. Normalize the DMTAP name to an ENS name (`alice@.eth` and bare `alice.eth` both → `alice.eth`).
//! 2. [`namehash`] it (EIP-137).
//! 3. `eth_call` the **ENS registry** `resolver(bytes32 node)` → the resolver contract address
//!    (zero address ⇒ unregistered ⇒ [`None`]).
//! 4. `eth_call` that resolver's `text(bytes32 node, string "dmtap")`.
//!    * A normal return is the DMTAP text record (see the convention below).
//!    * An `OffchainLookup` revert triggers **CCIP-Read** (below).
//!
//! ## The DMTAP record convention (this crate defines it)
//! DMTAP publishes the owner's **classical `IK`** in the ENS **text record** under key **`dmtap`**,
//! as a `0x`-prefixed hex string of the 32 raw `IK` bytes (`0x` + 64 hex chars). Text records are the
//! ENS-blessed home for arbitrary app data (ENSIP-5) and, unlike `addr`, carry a full 32-byte key
//! rather than a 20-byte Ethereum address — the DMTAP `IK` is an Ed25519 key, not an EVM account.
//!
//! ## CCIP-Read / off-chain resolvers (ENSIP-10 / EIP-3668)
//! An off-chain resolver reverts `OffchainLookup(sender, urls, callData, callbackFn, extraData)`; the
//! client fetches the first gateway URL (expanding `{sender}`/`{data}`), then `eth_call`s
//! `callbackFn(response, extraData)` on the resolver. Implemented **structurally** for the common
//! case (first URL, `GET` when the template carries `{data}` else `POST`, single hop). What is a
//! deliberate seam: multi-URL failover, POST body edge cases, and any gateway-response signature
//! policy — EIP-3668 delegates the latter to the callback contract, which we faithfully re-`eth_call`.

use serde_json::Value;

use dmtap_naming::namechain::NameChainClient;
use dmtap_naming::restype::Chain;

use crate::abi::{
    self, decode_address, decode_offchain_lookup, decode_string, encode_callback, encode_resolver,
    encode_text, keccak256,
};
use crate::rpc::{decode_hex_0x, eth_call, CallResult};
use crate::transport::HttpTransport;
use crate::NamechainError;

/// The canonical mainnet **ENS registry** address (`ENS.sol`), the fixed root every resolution
/// starts from.
pub const MAINNET_REGISTRY: [u8; 20] = hex_20("00000000000C2E074eC69A0dFb2997BA6C7d2e1e");

/// The text-record key under which DMTAP publishes the classical `IK` (see module docs).
pub const DMTAP_TEXT_KEY: &str = "dmtap";

/// A real, network-backed ENS `NameChainClient` (§3.12.5): resolves `.eth` names to a DMTAP `IK` over
/// Ethereum JSON-RPC via an injected [`HttpTransport`].
#[derive(Debug, Clone)]
pub struct EnsClient<T: HttpTransport> {
    transport: T,
    endpoint: String,
    registry: [u8; 20],
}

impl<T: HttpTransport> EnsClient<T> {
    /// Build a client against the Ethereum JSON-RPC `endpoint`, using the mainnet ENS registry.
    pub fn new(transport: T, endpoint: impl Into<String>) -> Self {
        EnsClient {
            transport,
            endpoint: endpoint.into(),
            registry: MAINNET_REGISTRY,
        }
    }

    /// Override the ENS registry address (for a testnet / alternate deployment).
    pub fn with_registry(mut self, registry: [u8; 20]) -> Self {
        self.registry = registry;
        self
    }

    /// Resolve with full error detail (the trait's `resolve` collapses any error to `None`).
    pub fn resolve_result(&self, name: &str) -> Result<Vec<u8>, NamechainError> {
        let ens_name = ens_name_from_dmtap(name)?;
        let node = namehash(&ens_name);

        // Step 3: registry.resolver(node).
        let resolver = match eth_call(
            &self.transport,
            &self.endpoint,
            &self.registry,
            &encode_resolver(&node),
        )? {
            CallResult::Return(bytes) => decode_address(&bytes)?,
            CallResult::Revert(_) => return Err(NamechainError::Rpc("registry.resolver reverted".into())),
        };
        let resolver = resolver.ok_or(NamechainError::NotFound)?;

        // Step 4: resolver.text(node, "dmtap"), following an OffchainLookup revert if present.
        let text_call = encode_text(&node, DMTAP_TEXT_KEY);
        let record = match eth_call(&self.transport, &self.endpoint, &resolver, &text_call)? {
            CallResult::Return(bytes) => decode_string(&bytes)?,
            CallResult::Revert(revert) => self.ccip_read(&resolver, &revert)?,
        };

        parse_dmtap_text(&record)
    }

    /// EIP-3668 CCIP-Read: follow an `OffchainLookup` revert to its gateway and re-`eth_call` the
    /// resolver's callback with the gateway's answer. Returns the decoded `text()` string.
    fn ccip_read(&self, resolver: &[u8; 20], revert: &[u8]) -> Result<String, NamechainError> {
        // The revert must start with the OffchainLookup selector; anything else is a plain revert.
        let sel = abi::offchain_lookup_selector();
        if revert.len() < 4 || revert[..4] != sel {
            return Err(NamechainError::Rpc("resolver reverted (not OffchainLookup)".into()));
        }
        let lookup = decode_offchain_lookup(&revert[4..])?;
        let url = lookup
            .urls
            .first()
            .ok_or(NamechainError::MalformedRecord("OffchainLookup with no urls"))?;

        // Expand the ENSIP-10 URL template. GET when it carries {data}, else POST the JSON body.
        let sender_hex = format!("0x{}", hex::encode(lookup.sender));
        let data_hex = format!("0x{}", hex::encode(&lookup.call_data));
        let gateway_body = if url.contains("{data}") {
            let expanded = url
                .replace("{sender}", &sender_hex)
                .replace("{data}", &data_hex);
            // The gateway URL is attacker-controlled (anyone can point a name at their resolver) — guard
            // it against SSRF before any socket is opened.
            crate::ssrf::guard_gateway_url(&expanded)?;
            self.transport.get(&expanded)?
        } else {
            let expanded = url.replace("{sender}", &sender_hex);
            crate::ssrf::guard_gateway_url(&expanded)?;
            let payload = serde_json::json!({ "sender": sender_hex, "data": data_hex });
            self.transport
                .post_json(&expanded, payload.to_string().as_bytes())?
        };

        // Gateway answers `{"data":"0x..."}`.
        let gw: Value =
            serde_json::from_slice(&gateway_body).map_err(|e| NamechainError::Rpc(e.to_string()))?;
        let response = decode_hex_0x(
            gw.get("data")
                .and_then(Value::as_str)
                .ok_or(NamechainError::MalformedRecord("CCIP gateway response missing data"))?,
        )?;

        // Re-enter the contract via its callback; the callback verifies the gateway answer (EIP-3668).
        let cb = encode_callback(lookup.callback_function, &response, &lookup.extra_data);
        match eth_call(&self.transport, &self.endpoint, resolver, &cb)? {
            CallResult::Return(bytes) => decode_string(&bytes),
            CallResult::Revert(_) => Err(NamechainError::Rpc("CCIP callback reverted".into())),
        }
    }
}

impl<T: HttpTransport> NameChainClient for EnsClient<T> {
    fn chain(&self) -> Chain {
        Chain::Ens
    }

    fn resolve(&self, name: &str) -> Option<Vec<u8>> {
        // Fail closed: any RPC error / malformed record / miss → no discovered record (§3.12.5).
        self.resolve_result(name).ok()
    }
}

/// EIP-137 **namehash** of an ENS name (e.g. `"alice.eth"`), the 32-byte node id every ENS call keys
/// on. `namehash("")` is 32 zero bytes; each label folds `keccak256(node ‖ keccak256(label))` from
/// the TLD inward. Labels are ASCII-lowercased (full ENSIP-15 normalization is out of scope — a seam).
pub fn namehash(name: &str) -> [u8; 32] {
    let mut node = [0u8; 32];
    if name.is_empty() {
        return node;
    }
    let name = name.to_ascii_lowercase();
    for label in name.split('.').rev() {
        let label_hash = keccak256(label.as_bytes());
        let mut cat = [0u8; 64];
        cat[..32].copy_from_slice(&node);
        cat[32..].copy_from_slice(&label_hash);
        node = keccak256(&cat);
    }
    node
}

/// Map a DMTAP name to its ENS name. `local@.eth` → `local.eth`; a bare `foo.eth` passes through;
/// anything else (wrong TLD, empty label) is [`NamechainError::MalformedName`].
pub fn ens_name_from_dmtap(name: &str) -> Result<String, NamechainError> {
    let name = name.trim().to_ascii_lowercase();
    if let Some((local, ns)) = name.split_once('@') {
        if ns != ".eth" {
            return Err(NamechainError::MalformedName("not a .eth name-chain name"));
        }
        if local.is_empty() {
            return Err(NamechainError::MalformedName("empty local part before @.eth"));
        }
        return Ok(format!("{local}.eth"));
    }
    if let Some(label) = name.strip_suffix(".eth") {
        if label.is_empty() {
            return Err(NamechainError::MalformedName("empty .eth label"));
        }
        return Ok(name);
    }
    Err(NamechainError::MalformedName("not a .eth name"))
}

/// Parse the `dmtap` text record value (`0x` + 64 hex chars) into the 32 raw classical-`IK` bytes.
/// An empty record is "no record" ([`NamechainError::NotFound`]); a wrong length fails closed.
fn parse_dmtap_text(value: &str) -> Result<Vec<u8>, NamechainError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(NamechainError::NotFound);
    }
    let bytes = decode_hex_0x(value)?;
    if bytes.len() != 32 {
        return Err(NamechainError::MalformedRecord(
            "dmtap text record is not a 32-byte ik",
        ));
    }
    Ok(bytes)
}

/// Const hex-decode of a 20-byte address literal (compile-time; panics on a bad literal).
const fn hex_20(s: &str) -> [u8; 20] {
    let b = s.as_bytes();
    assert!(b.len() == 40, "address literal must be 40 hex chars");
    let mut out = [0u8; 20];
    let mut i = 0;
    while i < 20 {
        out[i] = (hex_nib(b[i * 2]) << 4) | hex_nib(b[i * 2 + 1]);
        i += 1;
    }
    out
}

const fn hex_nib(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("bad hex nibble in address literal"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::MockTransport;

    // ---- EIP-137 namehash known-answer vectors ----
    #[test]
    fn namehash_kat() {
        assert_eq!(hex::encode(namehash("")), "0".repeat(64));
        assert_eq!(
            hex::encode(namehash("eth")),
            "93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae"
        );
        assert_eq!(
            hex::encode(namehash("foo.eth")),
            "de9b09fd7c5f901e23a3f19fecc54828e9c848539801e86591bd9801b019f84f"
        );
    }

    #[test]
    fn dmtap_to_ens_name() {
        assert_eq!(ens_name_from_dmtap("alice@.eth").unwrap(), "alice.eth");
        assert_eq!(ens_name_from_dmtap("VITALIK.eth").unwrap(), "vitalik.eth");
        assert_eq!(ens_name_from_dmtap("sub.bob@.eth").unwrap(), "sub.bob.eth");
        assert!(ens_name_from_dmtap("toly@.sol").is_err());
        assert!(ens_name_from_dmtap("plainlabel").is_err());
        assert!(ens_name_from_dmtap("@.eth").is_err());
    }

    #[test]
    fn registry_address_kat() {
        assert_eq!(
            hex::encode(MAINNET_REGISTRY),
            "00000000000c2e074ec69a0dfb2997ba6c7d2e1e"
        );
    }

    /// Build an ABI-encoded `address` return word for a resolver.
    fn addr_word(addr: [u8; 20]) -> Vec<u8> {
        let mut w = vec![0u8; 32];
        w[12..].copy_from_slice(&addr);
        format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x{}\"}}", hex::encode(&w))
            .into_bytes()
    }

    /// Build an ABI-encoded `string` return for a `text()` value.
    fn string_result(s: &str) -> Vec<u8> {
        let mut blob = Vec::new();
        // offset 0x20
        let mut w0 = [0u8; 32];
        w0[31] = 0x20;
        blob.extend_from_slice(&w0);
        // length
        let mut w1 = [0u8; 32];
        w1[24..].copy_from_slice(&(s.len() as u64).to_be_bytes());
        blob.extend_from_slice(&w1);
        // data padded
        blob.extend_from_slice(s.as_bytes());
        let rem = s.len() % 32;
        if rem != 0 {
            blob.extend(std::iter::repeat(0u8).take(32 - rem));
        }
        format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x{}\"}}", hex::encode(&blob)).into_bytes()
    }

    #[test]
    fn resolve_happy_path_returns_ik() {
        let ik = [0xabu8; 32];
        let text = format!("0x{}", hex::encode(ik));
        let resolver = [0x11u8; 20];
        let mock = MockTransport::new(vec![
            Ok(addr_word(resolver)),      // registry.resolver(node)
            Ok(string_result(&text)),     // resolver.text(node,"dmtap")
        ]);
        let client = EnsClient::new(mock, "https://rpc");
        assert_eq!(client.resolve_result("vitalik@.eth").unwrap(), ik.to_vec());
        // And via the trait (a fresh single-use mock, since resolve issues two calls).
        let mock2 = MockTransport::new(vec![Ok(addr_word(resolver)), Ok(string_result(&text))]);
        let client2 = EnsClient::new(mock2, "https://rpc");
        assert_eq!(client2.resolve("vitalik@.eth"), Some(ik.to_vec()));
    }

    #[test]
    fn resolve_unregistered_zero_resolver_is_none() {
        let mock = MockTransport::new(vec![Ok(addr_word([0u8; 20]))]);
        let client = EnsClient::new(mock, "https://rpc");
        assert!(matches!(
            client.resolve_result("ghost@.eth"),
            Err(NamechainError::NotFound)
        ));
        assert_eq!(client.resolve("ghost@.eth"), None);
    }

    #[test]
    fn resolve_empty_text_record_is_none() {
        let resolver = [0x22u8; 20];
        let mock = MockTransport::new(vec![Ok(addr_word(resolver)), Ok(string_result(""))]);
        let client = EnsClient::new(mock, "https://rpc");
        assert!(matches!(
            client.resolve_result("nobody@.eth"),
            Err(NamechainError::NotFound)
        ));
    }

    #[test]
    fn resolve_bad_length_record_fails_closed() {
        let resolver = [0x33u8; 20];
        let mock = MockTransport::new(vec![
            Ok(addr_word(resolver)),
            Ok(string_result("0xdeadbeef")), // 4 bytes, not 32
        ]);
        let client = EnsClient::new(mock, "https://rpc");
        assert!(matches!(
            client.resolve_result("shorty@.eth"),
            Err(NamechainError::MalformedRecord(_))
        ));
        assert_eq!(client.resolve("shorty@.eth"), None);
    }

    #[test]
    fn resolve_via_ccip_read_offchain() {
        let ik = [0xcdu8; 32];
        let text = format!("0x{}", hex::encode(ik));
        let resolver = [0x44u8; 20];

        // Build an OffchainLookup revert body pointing at a {data} gateway.
        let url = "https://gw.example/{sender}/{data}";
        let revert = build_offchain_lookup_revert(resolver, url, &[0x01, 0x02], [0xaa, 0xbb, 0xcc, 0xdd], &[0x77]);

        let mock = MockTransport::new(vec![
            Ok(addr_word(resolver)),                                   // registry.resolver
            Ok(format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{{\"code\":3,\"message\":\"revert\",\"data\":\"0x{}\"}}}}", hex::encode(&revert)).into_bytes()), // text() reverts OffchainLookup
            Ok(br#"{"data":"0xaabb"}"#.to_vec()),                      // gateway GET response
            Ok(string_result(&text)),                                 // callback eth_call returns the record
        ]);
        let client = EnsClient::new(mock, "https://rpc");
        let got = client.resolve_result("offchain@.eth").unwrap();
        assert_eq!(got, ik.to_vec());
    }

    /// Assemble a full `OffchainLookup(...)` revert (selector + ABI body) for the CCIP test.
    fn build_offchain_lookup_revert(
        sender: [u8; 20],
        url: &str,
        call_data: &[u8],
        callback: [u8; 4],
        extra: &[u8],
    ) -> Vec<u8> {
        fn w_usize(n: u64) -> [u8; 32] {
            let mut w = [0u8; 32];
            w[24..].copy_from_slice(&n.to_be_bytes());
            w
        }
        fn dyn_bytes(b: &[u8]) -> Vec<u8> {
            let mut v = w_usize(b.len() as u64).to_vec();
            v.extend_from_slice(b);
            let rem = b.len() % 32;
            if rem != 0 {
                v.extend(std::iter::repeat(0u8).take(32 - rem));
            }
            v
        }
        let mut urls_tail = Vec::new();
        urls_tail.extend_from_slice(&w_usize(1));
        urls_tail.extend_from_slice(&w_usize(0x20));
        urls_tail.extend_from_slice(&dyn_bytes(url.as_bytes()));
        let call_tail = dyn_bytes(call_data);
        let extra_tail = dyn_bytes(extra);

        let head_len = 160usize;
        let urls_off = head_len;
        let call_off = urls_off + urls_tail.len();
        let extra_off = call_off + call_tail.len();

        let mut body = Vec::new();
        let mut sw = [0u8; 32];
        sw[12..].copy_from_slice(&sender);
        body.extend_from_slice(&sw); // head[0]
        body.extend_from_slice(&w_usize(urls_off as u64)); // head[1]
        body.extend_from_slice(&w_usize(call_off as u64)); // head[2]
        let mut cbw = [0u8; 32];
        cbw[..4].copy_from_slice(&callback);
        body.extend_from_slice(&cbw); // head[3]
        body.extend_from_slice(&w_usize(extra_off as u64)); // head[4]
        body.extend_from_slice(&urls_tail);
        body.extend_from_slice(&call_tail);
        body.extend_from_slice(&extra_tail);

        let mut out = abi::offchain_lookup_selector().to_vec();
        out.extend_from_slice(&body);
        out
    }
}

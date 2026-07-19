//! Errors that survive the boundary.
//!
//! A JS `Error` carries only a message, so a `SyncError` crossing into JS would normally arrive as
//! prose — and a caller that has to regex-match prose to tell `0x0A02` (bad signature) from
//! `0x0A0A` (namespace leak) will eventually get it wrong, which for a fail-closed engine means
//! taking the wrong refusal path. So the message **is** a JSON object with the registry code, name
//! and §12 action verbatim from [`dmtap_sync::SyncError`]:
//!
//! ```text
//! {"error":"sync","code":"0x0A02","name":"ERR_SYNC_OP_SIG_INVALID","action":"FAIL_CLOSED_BLOCK"}
//! ```
//!
//! `JSON.parse(e.message)` recovers the structured refusal; the JS wrapper in `dmtap-sync-wasm.js`
//! does exactly that and rethrows a `SyncError` with those fields.
//!
//! Errors that are *not* substrate refusals (a malformed JSON argument, a bad hex string) carry
//! `{"error":"binding", …}` instead, so a caller can always tell "the engine refused your input"
//! from "you called the binding wrong". The two are different bugs with different fixes.
//!
//! ## Two surfaces, one message
//!
//! This crate compiles to two artifacts from one source (see the crate docs): the `js` feature
//! builds the `wasm-bindgen` browser binding, the `abi` feature builds the raw-ABI module the Go
//! binding embeds and runs under `wazero`. Only the *carrier* differs — `JsError` there, a plain
//! string here — and [`BErr`] is the alias that lets every function in `lib.rs` be written once for
//! both. The message text itself is produced by [`sync_err_message`] / [`binding_err_message`] in
//! both builds, which is what lets the Go binding rebuild the identical structured refusal a JS
//! caller sees, rather than a second, parallel error vocabulary that could drift.

use dmtap_sync::SyncError;
use serde_json::json;

/// The message text of a substrate refusal. Split out from [`sync_err`] because constructing a
/// `JsError` calls into the JS host and therefore cannot run under `cargo test` on a native
/// target — the *content* of the message can, and is asserted below.
pub fn sync_err_message(e: SyncError) -> String {
    json!({
        "error": "sync",
        "code": e.code_hex(),
        "name": e.name(),
        "action": e.action_str(),
    })
    .to_string()
}

/// The message text of a binding-level failure.
pub fn binding_err_message(msg: &str) -> String {
    json!({ "error": "binding", "message": msg }).to_string()
}

// --- the carrier -----------------------------------------------------------------------------

/// The error type every entry point in `lib.rs` returns.
///
/// `JsError` under the `js` feature so `wasm-bindgen` can turn it into a thrown JS `Error`; a plain
/// [`BindingError`] under `abi`, where there is no JS host to throw into and the dispatcher
/// serializes the message into the response envelope instead.
#[cfg(feature = "js")]
pub type BErr = wasm_bindgen::prelude::JsError;

/// See [`BErr`].
#[cfg(not(feature = "js"))]
pub type BErr = BindingError;

/// The non-JS carrier: the same message text, held as a string.
///
/// Deliberately opaque — [`message`](BindingError::message) is the only accessor, because the
/// message is a JSON document with a fixed shape and a caller that picks it apart any other way is
/// re-deriving a contract that already exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingError(String);

impl BindingError {
    /// The structured JSON message — `{"error":"sync",…}` or `{"error":"binding",…}`.
    pub fn message(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for BindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for BindingError {}

#[cfg(feature = "js")]
fn carry(message: String) -> BErr {
    wasm_bindgen::prelude::JsError::new(&message)
}

#[cfg(not(feature = "js"))]
fn carry(message: String) -> BErr {
    BindingError(message)
}

/// A substrate refusal, spelled for the boundary.
pub fn sync_err(e: SyncError) -> BErr {
    carry(sync_err_message(e))
}

/// A binding-level failure: the caller handed this crate something it could not parse.
pub fn binding_err(msg: impl AsRef<str>) -> BErr {
    carry(binding_err_message(msg.as_ref()))
}

/// `Result` sugar for the two error classes.
pub trait IntoJs<T> {
    /// Map either error class onto the boundary's carrier.
    fn js(self) -> Result<T, BErr>;
}

impl<T> IntoJs<T> for Result<T, SyncError> {
    fn js(self) -> Result<T, BErr> {
        self.map_err(sync_err)
    }
}

impl<T> IntoJs<T> for Result<T, String> {
    fn js(self) -> Result<T, BErr> {
        self.map_err(binding_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_carries_the_registry_code_name_and_action() {
        let m = sync_err_message(SyncError::NsLeak);
        assert_eq!(
            m,
            r#"{"action":"FAIL_CLOSED_BLOCK","code":"0x0A0A","error":"sync","name":"ERR_SYNC_NS_LEAK"}"#,
            "JS must be able to branch on the code, never on prose"
        );
    }

    #[test]
    fn a_binding_failure_is_distinguishable_from_a_substrate_refusal() {
        assert!(binding_err_message("bad hex").contains(r#""error":"binding""#));
        assert!(sync_err_message(SyncError::OpInvalid).contains(r#""error":"sync""#));
    }
}

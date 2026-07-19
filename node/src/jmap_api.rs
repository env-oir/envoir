//! The node-native **JMAP** listener (spec §8.1) — the node's native, and only, client-sync surface.
//!
//! The JMAP *logic* (Session resource, `process()` over Mailbox/Email/Thread/…, blob up/download,
//! the push/EventSource types) lives in the workspace-shared [`dmtap_mail::jmap`] module, driven
//! against a [`dmtap_mail::MailStore`]. This module binds that logic to a running node: it serves an
//! HTTP listener, authenticates every request against **app-passwords** (spec §8.2, fail-closed,
//! constant-time), and — crucially — backs it with the node's **live** MOTE store
//! ([`Node::store`] / [`Node::store_mut`]), so a client sees the node's actual delivered mail, not a
//! fresh empty [`MemoryStore`]. The node's store *is* a `MailStore`, so this is a direct projection:
//! a delivered MOTE ([`Node::poll`] → `deliver_mote`) is immediately visible over JMAP.
//!
//! ## Transport
//! The same framework-free `std`/`tokio` HTTP/1.1 approach the Envoir Send API uses (a `TcpListener`
//! + [`crate::send_api::read_request`]). A [`Node`] is **not `Send`**, so the listener runs on the
//! daemon's *own* current-thread task ([`run_loop_with_apis`]), handling each connection inline with
//! the live `&mut Node`.
//!
//! ## Routes (all app-password authenticated, fail-closed)
//! - `GET  /jmap/session`, `GET /.well-known/jmap` — the Session resource (RFC 8620 §2).
//! - `POST /jmap/api/` — a JMAP request; delegated to [`dmtap_mail::jmap::process`] over the live store.
//! - `GET  /jmap/download/{accountId}/{blobId}/{name}` — the raw RFC 5322 bytes of an Email blob.
//! - `POST /jmap/upload/{accountId}/` — a blob upload (content-addressed id, RFC 8620 §6.1).
//! - `GET  /jmap/eventsource/…` — a single StateChange event carrying the current state (see below).
//! - `/v1/*` — **delegated wholesale to the node's Envoir Send API** ([`crate::send_api::SendApi`],
//!   spec §13.5.1) when it is enabled, so the browser/webview client can `POST /v1/send` against the
//!   ONE base URL it already holds (this listener) instead of a second port. See
//!   [`JmapApi::handle`] for why this dispatch happens *before* the Basic-auth gate.
//!
//! ## Authentication
//! HTTP **Basic** auth carrying `username:app-password` (spec §8.2 — "legacy clients authenticate
//! without touching the keypair"; native clients likewise). The credential is verified via
//! [`dmtap_mail::StaticAuthenticator`] (constant-time secret compare), and the resolved binding MUST
//! be this node's identity. Any missing / malformed / unknown / wrong credential yields `401` with a
//! `WWW-Authenticate: Basic` challenge — never a silent accept. With **no** app-passwords configured
//! the listener authenticates nobody (fail-closed).
//!
//! ## Failed-auth throttling (online-guessing bound)
//! CORS is **not** the security boundary here — the permissive `Access-Control-Allow-Origin: *`
//! means any drive-by web page can *reach* this loopback listener; the app-password is the boundary.
//! What CORS-wildcarding does change is the *online guessing* budget, so the Basic-auth gate carries
//! a small in-memory fixed-window throttle: after [`AUTH_THROTTLE_MAX_FAILURES`] consecutive
//! failures within [`AUTH_THROTTLE_WINDOW_MS`], every request hitting the gate answers `429` with a
//! `Retry-After` until the window passes; any successful authentication resets the counter. That
//! bounds a drive-by guesser to ~10 attempts/minute regardless of connection volume. The `/v1/*`
//! delegation is deliberately outside this throttle: its capability/admin tokens are high-entropy
//! machine-minted secrets with their own fail-closed (constant-time) gates and per-key rate caveats,
//! whereas app-passwords are the human-scale secret this throttle exists to protect.
//!
//! ## TLS
//! This listener speaks plain HTTP and is bound to **loopback** by default (a native client on the
//! same machine). JMAP terminates TLS on the node (spec §8.2); an off-localhost bind therefore
//! requires a TLS front and is refused fail-closed by the daemon ([`crate::daemon::serve`]).
//!
//! ## Projection limits (honest seams)
//! - **EventSource** (`/jmap/eventsource/`) returns a *single* StateChange with the current state
//!   then closes, rather than holding a long-lived push stream: the listener runs inline on the
//!   daemon's `!Send` task, where an open stream would starve delivery/retry. A client resyncs by
//!   feeding that `state` into `Email/changes` (which is a real modseq-backed delta —
//!   [`dmtap_mail::store::MailStore::jmap_changes`]). Persistent push is the follow-up (a dedicated
//!   push task, or the relay's reachability ingress).
//! - Everything else (`Session`, `/api/`, blob up/download) runs the full shared JMAP handler
//!   against the live store with no reduction.

use std::future::Future;
use std::io;
use std::sync::Mutex;
use std::time::Duration;

use dmtap_core::TimestampMs;
use dmtap_mail::jmap;
use dmtap_mail::util::base64_decode;
use dmtap_mail::{Authenticator, MailStore, StaticAuthenticator};
use dmtap_send::http::HttpRequest;
use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

use crate::daemon::{now_ms, LoopStats};
use crate::node::Node;
use crate::pubserve::PubGateway;
use crate::send_api::{read_request, SendApi};
use crate::transport::Transport;

/// How long a single connection may take to deliver its request before it is dropped (it runs on the
/// daemon's own task, so an unbounded read would stall delivery/retry ticks). Mirrors the Send API.
const READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Bound the write too: a slow-reading client must not pin the inline task and stall the daemon.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// How many consecutive Basic-auth failures within one window trip the throttle (see module doc).
/// Small enough to bound a drive-by guesser to a uselessly slow rate against any credential with
/// real entropy; large enough that a human mistyping a password never plausibly hits it.
const AUTH_THROTTLE_MAX_FAILURES: u32 = 10;
/// The throttle's fixed window. After tripping, `429 Retry-After` is answered until it elapses.
const AUTH_THROTTLE_WINDOW_MS: u64 = 60_000;

/// Fixed-window failed-auth counter guarding the Basic-auth gate (see the module doc's
/// "Failed-auth throttling" section). In-memory only — a restart forgets it, which is fine: the
/// throttle bounds *online* guessing rate, it is not an account-lockout ledger.
#[derive(Debug, Default)]
struct AuthThrottle {
    /// Start of the current failure window (ms). Meaningless while `failures == 0`.
    window_start: TimestampMs,
    /// Failures recorded since `window_start`.
    failures: u32,
}

impl AuthThrottle {
    /// If the gate is currently throttled at `now`, the whole seconds to advertise in `Retry-After`
    /// (always ≥ 1 so a client never busy-loops on `Retry-After: 0`). An elapsed window forgives all
    /// recorded failures — the fixed window is the entire memory of this throttle.
    fn retry_after_secs(&mut self, now: TimestampMs) -> Option<u64> {
        if self.failures > 0 && now.saturating_sub(self.window_start) >= AUTH_THROTTLE_WINDOW_MS {
            self.failures = 0;
        }
        if self.failures >= AUTH_THROTTLE_MAX_FAILURES {
            let remaining = (self.window_start + AUTH_THROTTLE_WINDOW_MS).saturating_sub(now);
            Some(remaining.div_ceil(1000).max(1))
        } else {
            None
        }
    }

    /// Record one failed authentication at `now`, opening a fresh window if none is live.
    fn record_failure(&mut self, now: TimestampMs) {
        if self.failures == 0 || now.saturating_sub(self.window_start) >= AUTH_THROTTLE_WINDOW_MS {
            self.window_start = now;
            self.failures = 1;
        } else {
            self.failures += 1;
        }
    }

    /// A successful authentication resets the counter (the legitimate client is clearly present).
    fn record_success(&mut self) {
        self.failures = 0;
    }
}

/// The node-hosted JMAP service: the account identity it presents, the base URL it advertises, and
/// the app-password table that authenticates clients — all bound to **this node's** identity key.
pub struct JmapApi {
    account_id: String,
    base_url: String,
    auth: StaticAuthenticator,
    identity_pub: Vec<u8>,
    /// The failed-Basic-auth throttle (module doc). A `Mutex` only because [`Self::handle`] takes
    /// `&self`; the listener actually runs single-tasked on the daemon's own `!Send` loop, so the
    /// lock is uncontended. A poisoned lock (impossible without a panic mid-`handle`) recovers via
    /// `into_inner` — the counter state stays usable either way, never silently un-throttled.
    throttle: Mutex<AuthThrottle>,
}

impl JmapApi {
    /// Build a JMAP service for `account_id`, advertising `base_url`, bound to `identity_pub` (this
    /// node's identity key), with the given `(username, app-password)` credentials. An empty
    /// `app_passwords` authenticates nobody (fail-closed).
    pub fn new(
        account_id: impl Into<String>,
        base_url: impl Into<String>,
        identity_pub: Vec<u8>,
        app_passwords: &[(String, String)],
    ) -> Self {
        let mut auth = StaticAuthenticator::new();
        for (user, secret) in app_passwords {
            auth.issue(user.clone(), secret.clone(), identity_pub.clone(), "jmap");
        }
        JmapApi {
            account_id: account_id.into(),
            base_url: base_url.into(),
            auth,
            identity_pub,
            throttle: Mutex::new(AuthThrottle::default()),
        }
    }

    /// The account id this service presents (`accountId`/`username`).
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    /// Whether the presented credential authenticates as **this node's** identity. Fail-closed: any
    /// missing / malformed / unknown / wrong-secret / foreign-identity credential returns `false`.
    /// The secret compare is constant-time (via [`StaticAuthenticator::verify`]).
    fn authorized(&self, req: &HttpRequest) -> bool {
        let header = match req.authorization.as_deref() {
            Some(h) => h,
            None => return false,
        };
        let b64 = match header.strip_prefix("Basic ") {
            Some(v) => v.trim(),
            None => return false,
        };
        let raw = match base64_decode(b64) {
            Some(r) => r,
            None => return false,
        };
        let creds = match std::str::from_utf8(&raw) {
            Ok(s) => s,
            Err(_) => return false,
        };
        // RFC 7617: `user-id ":" password`; the password may itself contain ':'.
        let (user, pass) = match creds.split_once(':') {
            Some(uc) => uc,
            None => return false,
        };
        match self.auth.verify(user, pass) {
            // The credential resolved — it MUST bind to this node's identity (defense in depth: every
            // issued password already does, but a swapped table can't smuggle a foreign identity in).
            Some(bound) => ct_eq(&bound, &self.identity_pub),
            None => false,
        }
    }

    /// Route + serve one parsed request against the live `node`. The whole surface: the `/v1/*`
    /// Send-API delegation and the CORS preflight first, then the throttled Basic-auth gate
    /// (fail-closed), then the JMAP routes over the node's live store. Synchronous + unit-testable.
    ///
    /// `send_api` is the node's Envoir Send service when enabled (`None` ⇒ `/v1/*` is `404`), and
    /// `now` is the caller's clock (the daemon passes [`now_ms`]; tests inject their own).
    pub fn handle<T: Transport>(
        &self,
        node: &mut Node<T>,
        send_api: Option<&mut SendApi>,
        req: &HttpRequest,
        now: TimestampMs,
    ) -> JmapResponse {
        // CORS preflight (spec-neutral, transport concern): a browser/webview client on a different
        // origin (a Tauri app is `tauri://localhost`) sends an `OPTIONS` preflight before the real
        // `Authorization`-bearing request. Preflights **never** carry credentials — the browser strips
        // the Authorization header — so this MUST be answered before the auth gate, and it is
        // fail-safe to do so: this listener is loopback-only and every real route is still
        // app-password gated, so CORS is not the security boundary — the app-password is. See
        // [`JmapResponse`]'s CORS headers (added on every response). Answered before the `/v1/*`
        // dispatch too, so the browser's `/v1/send` preflight succeeds without touching the Send API.
        if req.method.eq_ignore_ascii_case("OPTIONS") {
            return JmapResponse::preflight();
        }
        // Strip any query string for route matching (the EventSource URL carries `?types=…`).
        let path = req.path.split('?').next().unwrap_or(&req.path);
        // `/v1/*` — the Envoir Send API family, served on THIS listener so the client's one base URL
        // (`http://127.0.0.1:4700`) covers both sync (JMAP) and send (§13.5.1). Dispatched **before**
        // the Basic-auth gate, and that pre-gate dispatch is deliberate and safe: the two families
        // authenticate with different credentials (Basic app-password vs. Bearer capability/admin
        // token), so gating `/v1/*` behind Basic here would 401 every legitimate Bearer-only client —
        // exactly the bug that broke real browser send. Nothing is opened up by skipping the Basic
        // gate: every `/v1/*` route keeps its own fail-closed enforcement inside [`SendApi::handle`]
        // (capability verification for `/v1/send`, the constant-time admin token for `/v1/keys*`),
        // so an unauthenticated request still dies at that gate — each family owns its boundary.
        if path == "/v1" || path.starts_with("/v1/") {
            return match send_api {
                Some(api) => {
                    // Wrap the Send API's JSON reply unchanged; [`JmapResponse::header_block`] then
                    // adds the same permissive CORS headers every response on this listener carries,
                    // so the browser can actually read the delegated /v1/* result.
                    let resp = api.handle(node, req, now);
                    JmapResponse::raw(resp.status, "application/json", resp.body)
                }
                // Honest 404 (not 401): the surface is disabled by config, not locked.
                None => JmapResponse::json(
                    404,
                    json!({
                        "error": "not_found",
                        "detail": "the Envoir Send API is not enabled on this node (set ENVOIR_SEND_API=1)"
                    }),
                ),
            };
        }
        // The throttled Basic-auth gate (module doc: this bounds online guessing; CORS is not the
        // boundary). While throttled we answer 429 WITHOUT evaluating the credential — even a correct
        // one — so a tripped window yields a guesser zero verification oracle until it passes (and
        // costs a legitimate client at most one window).
        let mut throttle = self.throttle.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(secs) = throttle.retry_after_secs(now) {
            return JmapResponse::too_many_auth_failures(secs);
        }
        if !self.authorized(req) {
            throttle.record_failure(now);
            return JmapResponse::unauthorized();
        }
        throttle.record_success();
        drop(throttle);
        match (req.method.as_str(), path) {
            ("GET", "/jmap/session") | ("GET", "/.well-known/jmap") => self.session(node),
            ("POST", "/jmap/api") | ("POST", "/jmap/api/") => self.api(node, &req.body),
            ("GET", p) if p.starts_with("/jmap/download/") => self.download(node, p),
            ("POST", p) if p.starts_with("/jmap/upload/") => self.upload(node, p, &req.body),
            ("GET", p) if p.starts_with("/jmap/eventsource") => self.eventsource(node),
            ("POST", _) | ("GET", _) => JmapResponse::json(
                404,
                json!({ "type": "urn:ietf:params:jmap:error:notFound", "detail": path }),
            ),
            _ => JmapResponse::json(
                405,
                json!({ "type": "urn:ietf:params:jmap:error:methodNotAllowed", "detail": req.method }),
            ),
        }
    }

    /// `GET /jmap/session` (RFC 8620 §2): the Session resource, its `state` = the live store's JMAP
    /// state token, its `apiUrl`/`downloadUrl`/`uploadUrl`/`eventSourceUrl` built from `base_url`.
    fn session<T: Transport>(&self, node: &Node<T>) -> JmapResponse {
        let state = node.store().jmap_state();
        JmapResponse::json_value(200, jmap::session_resource(&self.account_id, &self.base_url, &state))
    }

    /// `POST /jmap/api/` (RFC 8620 §3.3): parse the request and run the shared handler over the live
    /// store. An unparseable body is a `400 notRequest` (fail-closed, never a silent empty response).
    fn api<T: Transport>(&self, node: &mut Node<T>, body: &[u8]) -> JmapResponse {
        let req: jmap::Request = match serde_json::from_slice(body) {
            Ok(r) => r,
            Err(e) => {
                return JmapResponse::json(
                    400,
                    json!({ "type": "urn:ietf:params:jmap:error:notRequest", "detail": e.to_string() }),
                )
            }
        };
        let resp = jmap::process(node.store_mut(), &self.account_id, &req);
        match serde_json::to_vec(&resp) {
            Ok(bytes) => JmapResponse::raw(200, "application/json", bytes),
            Err(_) => JmapResponse::json(500, json!({ "type": "serverFail" })),
        }
    }

    /// `GET /jmap/download/{accountId}/{blobId}/{name}` (RFC 8620 §6.2): the raw RFC 5322 bytes of
    /// the blob (an Email id) from the live store. A foreign `accountId` is `404` (account isolation).
    fn download<T: Transport>(&self, node: &Node<T>, path: &str) -> JmapResponse {
        let rest = match path.strip_prefix("/jmap/download/") {
            Some(r) => r,
            None => return JmapResponse::json(404, json!({ "type": "notFound" })),
        };
        let mut parts = rest.splitn(3, '/');
        let account = parts.next().map(percent_decode).unwrap_or_default();
        let blob_id = match parts.next() {
            Some(b) if !b.is_empty() => percent_decode(b),
            _ => return JmapResponse::json(404, json!({ "type": "notFound" })),
        };
        if account != self.account_id {
            return JmapResponse::json(404, json!({ "type": "notFound", "detail": "unknown account" }));
        }
        match jmap::blob_download(node.store(), &blob_id) {
            Some(bytes) => JmapResponse::raw(200, "application/octet-stream", bytes),
            None => JmapResponse::json(404, json!({ "type": "notFound", "detail": "unknown blob" })),
        }
    }

    /// `POST /jmap/upload/{accountId}/` (RFC 8620 §6.1): a blob upload. The blob id is the content
    /// address of the bytes (spec §2.2), tying JMAP blobs to MOTE ids. A foreign account is `404`.
    fn upload<T: Transport>(&self, _node: &Node<T>, path: &str, body: &[u8]) -> JmapResponse {
        let rest = path.strip_prefix("/jmap/upload/").unwrap_or_default();
        let account = percent_decode(rest.trim_end_matches('/'));
        if account != self.account_id {
            return JmapResponse::json(404, json!({ "type": "notFound", "detail": "unknown account" }));
        }
        JmapResponse::json_value(201, jmap::blob_upload(&self.account_id, body, "application/octet-stream"))
    }

    /// `GET /jmap/eventsource/…` (RFC 8620 §7.3): a single StateChange carrying the live store's
    /// current state, then the connection closes. See the module doc's projection-limits note — this
    /// is a bounded projection (the inline `!Send` daemon task cannot hold a long-lived push stream);
    /// a client resyncs by feeding `state` into `Email/changes`.
    fn eventsource<T: Transport>(&self, node: &Node<T>) -> JmapResponse {
        let state = node.store().jmap_state();
        let change = jmap::StateChange::new(&self.account_id, &state);
        let data = serde_json::to_string(&change).unwrap_or_else(|_| "{}".to_string());
        // SSE framing (RFC 8620 §7.3 uses `event: state` records).
        let body = format!("event: state\r\ndata: {data}\r\n\r\n");
        JmapResponse::raw(200, "text/event-stream", body.into_bytes())
    }

    /// Serve one accepted connection: read the request (bounded), dispatch it against the live node,
    /// and write the response. Framing errors become `400`/`408` rather than propagating — one bad
    /// client never takes down the daemon loop. `send_api` is threaded through so `/v1/*` requests
    /// arriving on this listener reach the real Send API (see [`Self::handle`]).
    pub async fn handle_connection<T: Transport>(
        &self,
        node: &mut Node<T>,
        send_api: Option<&mut SendApi>,
        mut stream: TcpStream,
    ) -> io::Result<()> {
        let resp = match tokio::time::timeout(READ_TIMEOUT, read_request(&mut stream)).await {
            Ok(Ok(Some(req))) => self.handle(node, send_api, &req, now_ms()),
            Ok(Ok(None)) => return Ok(()),
            Ok(Err(e)) => {
                JmapResponse::json(400, json!({ "type": "notRequest", "detail": e.to_string() }))
            }
            Err(_) => JmapResponse::json(408, json!({ "type": "requestTimeout" })),
        };
        match tokio::time::timeout(WRITE_TIMEOUT, resp.write(&mut stream)).await {
            Ok(r) => r,
            Err(_) => Ok(()),
        }
    }
}

/// An HTTP response from the JMAP surface: unlike the Send API's JSON-only replies, JMAP serves
/// several content types (JSON, `application/octet-stream` blobs, `text/event-stream`), and issues a
/// `WWW-Authenticate` challenge on `401`.
#[derive(Debug, Clone)]
pub struct JmapResponse {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
    pub www_authenticate: bool,
    /// `Some(secs)` emits a `Retry-After` header — set only by the failed-auth throttle's `429`.
    pub retry_after_secs: Option<u64>,
}

impl JmapResponse {
    /// A response with an explicit content type and raw body.
    pub fn raw(status: u16, content_type: &'static str, body: Vec<u8>) -> Self {
        JmapResponse { status, content_type, body, www_authenticate: false, retry_after_secs: None }
    }

    /// A JSON response from an already-built [`Value`].
    pub fn json_value(status: u16, value: Value) -> Self {
        JmapResponse::raw(status, "application/json", serde_json::to_vec(&value).unwrap_or_default())
    }

    /// A JSON response (convenience for error bodies).
    fn json(status: u16, value: Value) -> Self {
        JmapResponse::json_value(status, value)
    }

    /// A CORS preflight (`OPTIONS`) reply: `204 No Content` with an empty body. The permissive CORS
    /// headers themselves are emitted by [`Self::header_block`] on **every** response, so a browser
    /// client (a Tauri webview at `tauri://localhost`) may then issue its real, app-password
    /// authenticated request. This is not an auth bypass: the preflight carries no credentials and
    /// unlocks nothing — the subsequent request still passes the fail-closed auth gate.
    fn preflight() -> Self {
        JmapResponse::raw(204, "text/plain", Vec::new())
    }

    /// The fail-closed `401` with a Basic challenge — every unauthenticated request lands here.
    fn unauthorized() -> Self {
        let mut r = JmapResponse::json(
            401,
            json!({ "type": "urn:ietf:params:jmap:error:unauthorized", "detail": "app-password required" }),
        );
        r.www_authenticate = true;
        r
    }

    /// The throttled `429` (module doc: online-guessing bound). Carries `Retry-After` so a
    /// well-behaved client backs off for the remainder of the window; deliberately **no** Basic
    /// challenge — this is not an invitation to retry a credential, it is a refusal to look at one.
    fn too_many_auth_failures(retry_after_secs: u64) -> Self {
        let mut r = JmapResponse::json(
            429,
            json!({
                "type": "urn:ietf:params:jmap:error:limit",
                "detail": "too many failed authentication attempts — retry after the window passes"
            }),
        );
        r.retry_after_secs = Some(retry_after_secs);
        r
    }

    /// Build the HTTP/1.1 response head (status line + headers, terminated by the blank line). Split
    /// out from [`Self::write`] so the CORS + auth headers are unit-testable without a socket.
    fn header_block(&self) -> String {
        let mut head = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
            self.status,
            reason_phrase(self.status),
            self.content_type,
            self.body.len(),
        );
        // Permissive CORS for the loopback JMAP listener. `*` is correct and safe here: the client
        // fetch sets `Authorization` explicitly rather than `credentials: 'include'`, so the request
        // is NOT credentialed in the CORS sense and a wildcard origin is honoured. Security is
        // unaffected — the listener is loopback-bound and every route is app-password gated (CORS is
        // not the boundary). The preflight must advertise the `authorization`/`content-type` headers
        // the JMAP client sends, else the browser blocks the real request.
        head.push_str("Access-Control-Allow-Origin: *\r\n");
        head.push_str("Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n");
        head.push_str("Access-Control-Allow-Headers: authorization, content-type, accept\r\n");
        head.push_str("Access-Control-Max-Age: 600\r\n");
        head.push_str("Vary: Origin\r\n");
        if self.www_authenticate {
            head.push_str("WWW-Authenticate: Basic realm=\"dmtap-jmap\"\r\n");
        }
        if let Some(secs) = self.retry_after_secs {
            head.push_str(&format!("Retry-After: {secs}\r\n"));
        }
        head.push_str("\r\n");
        head
    }

    /// Write this response as an HTTP/1.1 `Connection: close` reply.
    async fn write(&self, stream: &mut TcpStream) -> io::Result<()> {
        stream.write_all(self.header_block().as_bytes()).await?;
        stream.write_all(&self.body).await?;
        stream.flush().await
    }
}

/// The daemon's steady-state loop serving the node's client/programmatic surfaces alongside the
/// delivery tick, all **inline on this one task** (a [`Node`] is `!Send`): the delivery/retry/
/// deadline tick, plus — behind their config flags — the Envoir Send API, the native JMAP
/// listener, and the DMTAP-PUB gateway (§22.5/§22.6). Any listener may be absent (`None`); with all
/// absent it is exactly [`crate::daemon::run_loop`]. When both the Send and JMAP APIs are enabled,
/// the JMAP listener additionally serves the `/v1/*` Send routes (one client-facing base URL — see
/// [`JmapApi::handle`]) while the standalone Send listener keeps working unchanged. Runs until
/// `shutdown`, then flushes a final durable checkpoint.
///
/// The PUB gateway is `Send + Sync` (it holds no reference to the `!Send` `Node`) — it does not
/// *need* to run inline here the way the Send/JMAP surfaces do, but it is interleaved into this
/// same `select!` anyway so the one `shutdown` future and the one final flush cover every listener
/// the daemon serves, rather than needing a second supervised task.
///
/// The `select!` is **not** `biased`: ranking `accept` above the delivery `tick` would starve the
/// tick under a stream of connections (each is handled inline). Fair polling keeps delivery/retry
/// making progress; per-connection read/write timeouts still bound any single slow client.
#[allow(clippy::too_many_arguments)]
pub async fn run_loop_with_apis<T: Transport>(
    node: &mut Node<T>,
    mut send_api: Option<&mut SendApi>,
    send_listener: Option<TcpListener>,
    jmap_api: Option<&JmapApi>,
    jmap_listener: Option<TcpListener>,
    pub_gateway: Option<&PubGateway>,
    pub_listener: Option<TcpListener>,
    tick: Duration,
    shutdown: impl Future<Output = ()>,
) -> LoopStats {
    tokio::pin!(shutdown);
    let mut interval = tokio::time::interval(tick);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut stats = LoopStats::default();
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = maybe_accept(send_listener.as_ref()) => {
                if let (Some(api), Ok((stream, _peer))) = (send_api.as_deref_mut(), accepted) {
                    let _ = api.handle_connection(node, stream, now_ms()).await;
                }
            }
            accepted = maybe_accept(jmap_listener.as_ref()) => {
                if let (Some(api), Ok((stream, _peer))) = (jmap_api, accepted) {
                    // The Send API is threaded into the JMAP handler so `/v1/*` on THIS listener
                    // reaches the real capability-gated send path (see `JmapApi::handle`).
                    let _ = api.handle_connection(node, send_api.as_deref_mut(), stream).await;
                }
            }
            accepted = maybe_accept(pub_listener.as_ref()) => {
                if let (Some(gw), Ok((stream, _peer))) = (pub_gateway, accepted) {
                    let _ = crate::pubserve::handle_connection(gw, stream).await;
                }
            }
            _ = interval.tick() => {
                node.set_now(now_ms());
                let inbound = node.poll();
                stats.inbound += inbound.len() as u64;
                node.pump_group_inbox();
                stats.retried += node.retry_pending() as u64;
                node.tick_deadlines();
                stats.ticks += 1;
            }
        }
    }
    stats.flushed_ok = node.flush().is_ok();
    stats
}

/// Accept from an optional listener: `Some` awaits a connection; `None` pends forever so the
/// `select!` arm is simply inert when that surface is disabled.
async fn maybe_accept(listener: Option<&TcpListener>) -> io::Result<(TcpStream, std::net::SocketAddr)> {
    match listener {
        Some(l) => l.accept().await,
        None => std::future::pending().await,
    }
}

/// A conventional reason phrase for the status codes this surface emits (cosmetic). Includes the
/// codes the delegated `/v1/*` Send API family answers (403/422/429/502) and the throttle's 429.
fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        _ => "",
    }
}

/// Minimal percent-decoding for path segments (`%XX` → byte; lone `%` or bad hex passes through).
/// JMAP blob ids are `mailbox|uid`; a client may percent-encode `|` or a mailbox name's bytes.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Constant-time byte equality (length may leak — an identity key's length is not secret).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{InMemoryNetwork, InMemoryTransport};
    use dmtap_core::identity::IdentityKey;
    use dmtap_core::mote::SealKeypair;

    /// The tests' injected clock (the handler never reads a wall clock).
    const NOW: u64 = 1_752_000_000_000;

    fn node_with_mail() -> (Node<InMemoryTransport>, Vec<u8>) {
        let net = InMemoryNetwork::new();
        let ik = IdentityKey::from_seed(&[9u8; 32]);
        let ik_pub = ik.public();
        let transport = net.endpoint(ik_pub.clone());
        let mut node = Node::with_identity(ik, SealKeypair::generate(), transport);
        // File a message directly into the node's LIVE store (the same store a delivered MOTE lands in).
        node.store_mut().deliver_raw(
            "INBOX",
            b"From: Alice <alice@example.com>\r\nSubject: Live mail\r\nMessage-ID: <m1@x>\r\n\r\nHi from the live store".to_vec(),
            vec![],
            NOW,
        );
        (node, ik_pub)
    }

    /// A node + Send API sharing one identity (as the daemon builds them), with a native recipient
    /// this node knows and a minted capability key — the fixture for the `/v1/*` delegation tests.
    fn node_with_send_api() -> (Node<InMemoryTransport>, Vec<u8>, SendApi, String, String) {
        use dmtap_send::{Environment, SendScope};
        let net = InMemoryNetwork::new();
        let ik = IdentityKey::from_seed(&[9u8; 32]);
        let ik_pub = ik.public();
        let transport = net.endpoint(ik_pub.clone());
        let mut node = Node::with_identity(ik, SealKeypair::generate(), transport);
        // A native recipient the resolver can seal to (registered on the fabric so dispatch lands).
        let rik = IdentityKey::from_seed(&[5u8; 32]);
        let rseal = SealKeypair::generate();
        let _rt = net.endpoint(rik.public());
        node.add_contact(&rik.public(), *rseal.public());
        let to = crate::names::base64url::encode(&rik.public());
        let mut send = SendApi::new(IdentityKey::from_seed(&[9u8; 32]), None);
        let key = send.service_mut().issue_key(
            SendScope::account(Environment::Prod),
            NOW,
            365 * 24 * 60 * 60 * 1000,
        );
        let secret = key.secret().to_string();
        (node, ik_pub, send, secret, to)
    }

    fn api(ik_pub: &[u8]) -> JmapApi {
        JmapApi::new(
            "user@dmtap.local",
            "http://127.0.0.1:4700",
            ik_pub.to_vec(),
            &[("user@dmtap.local".to_string(), "app-pw".to_string())],
        )
    }

    fn basic(user: &str, pass: &str) -> String {
        format!("Basic {}", dmtap_mail::util::base64_encode(format!("{user}:{pass}").as_bytes()))
    }

    fn req(method: &str, path: &str, auth: Option<String>, body: Value) -> HttpRequest {
        HttpRequest {
            method: method.into(),
            path: path.into(),
            authorization: auth,
            body: serde_json::to_vec(&body).unwrap(),
        }
    }

    #[test]
    fn missing_or_bad_app_password_is_rejected_fail_closed() {
        let (mut node, ik_pub) = node_with_mail();
        let a = api(&ik_pub);
        // No Authorization header.
        let r = a.handle(&mut node, None, &req("GET", "/jmap/session", None, json!({})), NOW);
        assert_eq!(r.status, 401);
        assert!(r.www_authenticate, "a 401 must carry the Basic challenge");
        // Wrong secret.
        let r = a.handle(&mut node, None, &req("GET", "/jmap/session", Some(basic("user@dmtap.local", "nope")), json!({})), NOW);
        assert_eq!(r.status, 401);
        // Unknown user.
        let r = a.handle(&mut node, None, &req("GET", "/jmap/session", Some(basic("mallory", "app-pw")), json!({})), NOW);
        assert_eq!(r.status, 401);
        // Non-Basic scheme.
        let r = a.handle(&mut node, None, &req("GET", "/jmap/session", Some("Bearer app-pw".into()), json!({})), NOW);
        assert_eq!(r.status, 401);
    }

    #[test]
    fn no_app_passwords_authenticates_nobody() {
        let (mut node, ik_pub) = node_with_mail();
        let a = JmapApi::new("user@dmtap.local", "http://127.0.0.1:4700", ik_pub.clone(), &[]);
        let r = a.handle(&mut node, None, &req("GET", "/jmap/session", Some(basic("user@dmtap.local", "app-pw")), json!({})), NOW);
        assert_eq!(r.status, 401, "with no credentials configured, even a plausible one fails closed");
    }

    #[test]
    fn session_reflects_live_store_state() {
        let (mut node, ik_pub) = node_with_mail();
        let a = api(&ik_pub);
        let r = a.handle(&mut node, None, &req("GET", "/jmap/session", Some(basic("user@dmtap.local", "app-pw")), json!({})), NOW);
        assert_eq!(r.status, 200);
        let v: Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(v["primaryAccounts"][jmap::CAP_MAIL], json!("user@dmtap.local"));
        assert!(v["apiUrl"].as_str().unwrap().starts_with("http://127.0.0.1:4700/jmap/api/"));
        // The state token is the live store's, not a placeholder.
        assert_eq!(v["state"], json!(node.store().jmap_state()));
    }

    #[test]
    fn api_serves_the_live_delivered_mail_not_an_empty_store() {
        let (mut node, ik_pub) = node_with_mail();
        let a = api(&ik_pub);
        let auth = basic("user@dmtap.local", "app-pw");
        // Mailbox/get sees the node's real INBOX with one delivered message.
        let body = json!({
            "using": [jmap::CAP_CORE, jmap::CAP_MAIL],
            "methodCalls": [["Mailbox/get", { "accountId": "user@dmtap.local", "ids": null }, "c1"]]
        });
        let r = a.handle(&mut node, None, &req("POST", "/jmap/api/", Some(auth.clone()), body), NOW);
        assert_eq!(r.status, 200);
        let v: Value = serde_json::from_slice(&r.body).unwrap();
        let inbox = v["methodResponses"][0][1]["list"].as_array().unwrap().iter()
            .find(|m| m["id"] == json!("INBOX")).expect("INBOX present");
        assert_eq!(inbox["totalEmails"], json!(1), "the live INBOX has the delivered message");

        // Email/query + Email/get returns the real subject/body — proving it is the live store.
        let body = json!({
            "using": [jmap::CAP_MAIL],
            "methodCalls": [
                ["Email/query", { "accountId": "user@dmtap.local", "filter": { "inMailbox": "INBOX" } }, "q"],
                ["Email/get", { "accountId": "user@dmtap.local", "#ids": { "resultOf": "q", "name": "Email/query", "path": "/ids" } }, "g"]
            ]
        });
        let r = a.handle(&mut node, None, &req("POST", "/jmap/api/", Some(auth), body), NOW);
        let v: Value = serde_json::from_slice(&r.body).unwrap();
        let email = &v["methodResponses"][1][1]["list"][0];
        assert_eq!(email["subject"], json!("Live mail"));
        assert_eq!(email["from"][0]["email"], json!("alice@example.com"));
    }

    #[test]
    fn blob_download_returns_raw_bytes_and_isolates_accounts() {
        let (mut node, ik_pub) = node_with_mail();
        let a = api(&ik_pub);
        let auth = basic("user@dmtap.local", "app-pw");
        // The Email id is `INBOX|1`; percent-encode the '|' as a client might.
        let r = a.handle(&mut node, None, &req("GET", "/jmap/download/user@dmtap.local/INBOX%7C1/mail.eml", Some(auth.clone()), json!({})), NOW);
        assert_eq!(r.status, 200);
        assert_eq!(r.content_type, "application/octet-stream");
        assert!(String::from_utf8_lossy(&r.body).contains("Hi from the live store"));
        // A foreign accountId is refused (isolation).
        let r = a.handle(&mut node, None, &req("GET", "/jmap/download/someone-else/INBOX%7C1/mail.eml", Some(auth), json!({})), NOW);
        assert_eq!(r.status, 404);
    }

    #[test]
    fn unknown_route_is_404_when_authenticated() {
        let (mut node, ik_pub) = node_with_mail();
        let a = api(&ik_pub);
        let r = a.handle(&mut node, None, &req("GET", "/jmap/bogus", Some(basic("user@dmtap.local", "app-pw")), json!({})), NOW);
        assert_eq!(r.status, 404);
    }

    #[test]
    fn options_preflight_is_answered_without_credentials() {
        let (mut node, ik_pub) = node_with_mail();
        let a = api(&ik_pub);
        // A preflight carries NO Authorization header (the browser strips it) — it must still be
        // answered (204), never a fail-closed 401, so the real authenticated request can follow.
        let r = a.handle(&mut node, None, &req("OPTIONS", "/jmap/api/", None, json!({})), NOW);
        assert_eq!(r.status, 204);
        assert!(!r.www_authenticate, "a preflight is not an auth challenge");
        assert!(r.body.is_empty());
    }

    #[test]
    fn every_response_carries_permissive_cors_headers() {
        let (mut node, ik_pub) = node_with_mail();
        let a = api(&ik_pub);
        // The preflight advertises the headers the JMAP client sends.
        let pre = a.handle(&mut node, None, &req("OPTIONS", "/jmap/api/", None, json!({})), NOW);
        let head = pre.header_block();
        assert!(head.contains("Access-Control-Allow-Origin: *"));
        assert!(head.to_ascii_lowercase().contains("access-control-allow-headers: authorization"));
        assert!(head.contains("Access-Control-Allow-Methods: GET, POST, OPTIONS"));
        // A real (authenticated) response ALSO carries the allow-origin header, else the browser
        // discards the body.
        let ok = a.handle(&mut node, None, &req("GET", "/jmap/session", Some(basic("user@dmtap.local", "app-pw")), json!({})), NOW);
        assert_eq!(ok.status, 200);
        assert!(ok.header_block().contains("Access-Control-Allow-Origin: *"));
        // Even the 401 carries CORS (so the browser surfaces the status instead of a CORS error).
        let no = a.handle(&mut node, None, &req("GET", "/jmap/session", None, json!({})), NOW);
        assert_eq!(no.status, 401);
        let nohead = no.header_block();
        assert!(nohead.contains("Access-Control-Allow-Origin: *"));
        assert!(nohead.contains("WWW-Authenticate: Basic"));
    }

    #[test]
    fn percent_decode_handles_encoded_and_literal() {
        assert_eq!(percent_decode("INBOX%7C1"), "INBOX|1");
        assert_eq!(percent_decode("plain"), "plain");
        assert_eq!(percent_decode("100%"), "100%"); // trailing lone % passes through
    }

    // --- /v1/* delegation to the Send API (the flagship browser-send path) ----------------------

    #[test]
    fn bearer_authed_v1_send_reaches_the_send_api_through_the_jmap_handler() {
        let (mut node, ik_pub, mut send, secret, to) = node_with_send_api();
        let a = api(&ik_pub);
        // The exact request the browser client issues: POST {jmap base}/v1/send with a capability
        // Bearer token — and NO Basic app-password. It must reach the real send pipeline.
        let body = json!({ "from": "hello@example.com", "to": to, "subject": "hi", "body": "from the browser" });
        let r = a.handle(&mut node, Some(&mut send), &req("POST", "/v1/send", Some(format!("Bearer {secret}")), body), NOW);
        assert_eq!(r.status, 200, "a Bearer-authed /v1/send must not die at the Basic gate: {:?}", String::from_utf8_lossy(&r.body));
        let v: Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(v["native"], json!(true));
        // The MOTE genuinely entered the node's §20.1 outbound path via the delegated SendApi.
        assert_eq!(node.outbound_len(), 1);
        // The delegated response still carries the CORS headers, else the browser drops the body.
        assert!(r.header_block().contains("Access-Control-Allow-Origin: *"));
    }

    #[test]
    fn v1_send_keeps_the_send_apis_own_fail_closed_gate() {
        let (mut node, ik_pub, mut send, _secret, to) = node_with_send_api();
        let a = api(&ik_pub);
        let body = json!({ "from": "hello@example.com", "to": to, "subject": "hi", "body": "x" });
        // No Bearer at all: rejected by the SEND API's gate (not the Basic gate — no Basic challenge).
        let r = a.handle(&mut node, Some(&mut send), &req("POST", "/v1/send", None, body.clone()), NOW);
        assert_eq!(r.status, 401);
        assert!(!r.www_authenticate, "a /v1 401 is the Send API's, not a Basic challenge");
        // A bogus Bearer likewise dies at the capability verification, and nothing is dispatched.
        let r = a.handle(&mut node, Some(&mut send), &req("POST", "/v1/send", Some("Bearer envoir_live_bogus".into()), body), NOW);
        assert_eq!(r.status, 401);
        assert_eq!(node.outbound_len(), 0, "no MOTE for an unauthenticated /v1/send");
    }

    #[test]
    fn v1_routes_are_404_when_the_send_api_is_disabled() {
        let (mut node, ik_pub) = node_with_mail();
        let a = api(&ik_pub);
        // With no SendApi wired (config off) the route is honestly absent — 404, not a Basic 401.
        let r = a.handle(&mut node, None, &req("POST", "/v1/send", Some("Bearer x".into()), json!({})), NOW);
        assert_eq!(r.status, 404);
        assert!(!r.www_authenticate);
    }

    #[test]
    fn v1_preflight_is_answered_with_cors_before_any_gate() {
        let (mut node, ik_pub, mut send, _secret, _to) = node_with_send_api();
        let a = api(&ik_pub);
        // The browser preflights /v1/send with NO credentials; it must get 204 + the CORS grant.
        let r = a.handle(&mut node, Some(&mut send), &req("OPTIONS", "/v1/send", None, json!({})), NOW);
        assert_eq!(r.status, 204);
        let head = r.header_block();
        assert!(head.contains("Access-Control-Allow-Origin: *"));
        assert!(head.to_ascii_lowercase().contains("access-control-allow-headers: authorization"));
    }

    // --- the failed-Basic-auth throttle (online-guessing bound; CORS is not the boundary) --------

    /// Trip the throttle: `n` bad-password requests at `now`.
    fn hammer(a: &JmapApi, node: &mut Node<InMemoryTransport>, n: u32, now: u64) {
        for _ in 0..n {
            let r = a.handle(node, None, &req("GET", "/jmap/session", Some(basic("user@dmtap.local", "WRONG")), json!({})), now);
            assert_eq!(r.status, 401);
        }
    }

    #[test]
    fn throttle_answers_429_with_retry_after_after_max_failures() {
        let (mut node, ik_pub) = node_with_mail();
        let a = api(&ik_pub);
        hammer(&a, &mut node, AUTH_THROTTLE_MAX_FAILURES, NOW);
        // The next attempt — even with the CORRECT password — is refused without evaluating it:
        // a tripped window is a zero-oracle refusal, not an invitation to keep guessing.
        let r = a.handle(&mut node, None, &req("GET", "/jmap/session", Some(basic("user@dmtap.local", "app-pw")), json!({})), NOW + 1_000);
        assert_eq!(r.status, 429);
        assert_eq!(r.retry_after_secs, Some(59), "Retry-After = the window's remaining whole seconds");
        assert!(r.header_block().contains("Retry-After: 59"));
        assert!(!r.www_authenticate, "429 carries no Basic challenge");
    }

    #[test]
    fn throttle_resets_after_the_window_passes() {
        let (mut node, ik_pub) = node_with_mail();
        let a = api(&ik_pub);
        hammer(&a, &mut node, AUTH_THROTTLE_MAX_FAILURES, NOW);
        // Window elapsed: the correct credential authenticates again (fixed window fully forgives).
        let r = a.handle(&mut node, None, &req("GET", "/jmap/session", Some(basic("user@dmtap.local", "app-pw")), json!({})), NOW + AUTH_THROTTLE_WINDOW_MS);
        assert_eq!(r.status, 200, "an elapsed window unthrottles the gate");
    }

    #[test]
    fn a_success_resets_the_failure_counter() {
        let (mut node, ik_pub) = node_with_mail();
        let a = api(&ik_pub);
        // One failure short of the limit, then a success: the counter must reset…
        hammer(&a, &mut node, AUTH_THROTTLE_MAX_FAILURES - 1, NOW);
        let ok = a.handle(&mut node, None, &req("GET", "/jmap/session", Some(basic("user@dmtap.local", "app-pw")), json!({})), NOW + 1);
        assert_eq!(ok.status, 200);
        // …so the next bad attempt is an ordinary 401, not a 429.
        let r = a.handle(&mut node, None, &req("GET", "/jmap/session", Some(basic("user@dmtap.local", "WRONG")), json!({})), NOW + 2);
        assert_eq!(r.status, 401);
    }

    #[test]
    fn throttle_does_not_block_preflights_or_v1_dispatch() {
        let (mut node, ik_pub, mut send, secret, to) = node_with_send_api();
        let a = api(&ik_pub);
        hammer(&a, &mut node, AUTH_THROTTLE_MAX_FAILURES, NOW);
        // OPTIONS is answered before the gate — a throttled listener still preflights.
        let pre = a.handle(&mut node, None, &req("OPTIONS", "/jmap/api/", None, json!({})), NOW + 1);
        assert_eq!(pre.status, 204);
        // /v1/* keeps working: its Bearer gate (high-entropy capability tokens, per-key rate
        // caveats) is a separate boundary the Basic throttle deliberately does not police.
        let body = json!({ "from": "hello@example.com", "to": to, "subject": "hi", "body": "x" });
        let r = a.handle(&mut node, Some(&mut send), &req("POST", "/v1/send", Some(format!("Bearer {secret}")), body), NOW + 1);
        assert_eq!(r.status, 200);
    }
}

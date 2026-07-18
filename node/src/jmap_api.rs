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
//!
//! ## Authentication
//! HTTP **Basic** auth carrying `username:app-password` (spec §8.2 — "legacy clients authenticate
//! without touching the keypair"; native clients likewise). The credential is verified via
//! [`dmtap_mail::StaticAuthenticator`] (constant-time secret compare), and the resolved binding MUST
//! be this node's identity. Any missing / malformed / unknown / wrong credential yields `401` with a
//! `WWW-Authenticate: Basic` challenge — never a silent accept. With **no** app-passwords configured
//! the listener authenticates nobody (fail-closed).
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
use std::time::Duration;

use dmtap_mail::jmap;
use dmtap_mail::util::base64_decode;
use dmtap_mail::{Authenticator, MailStore, StaticAuthenticator};
use dmtap_send::http::HttpRequest;
use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

use crate::daemon::{now_ms, LoopStats};
use crate::node::Node;
use crate::send_api::{read_request, SendApi};
use crate::transport::Transport;

/// How long a single connection may take to deliver its request before it is dropped (it runs on the
/// daemon's own task, so an unbounded read would stall delivery/retry ticks). Mirrors the Send API.
const READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Bound the write too: a slow-reading client must not pin the inline task and stall the daemon.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// The node-hosted JMAP service: the account identity it presents, the base URL it advertises, and
/// the app-password table that authenticates clients — all bound to **this node's** identity key.
pub struct JmapApi {
    account_id: String,
    base_url: String,
    auth: StaticAuthenticator,
    identity_pub: Vec<u8>,
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
        JmapApi { account_id: account_id.into(), base_url: base_url.into(), auth, identity_pub }
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

    /// Route + serve one parsed request against the live `node`. The whole surface: auth gate first
    /// (fail-closed), then the JMAP routes over the node's live store. Synchronous + unit-testable.
    pub fn handle<T: Transport>(&self, node: &mut Node<T>, req: &HttpRequest) -> JmapResponse {
        // CORS preflight (spec-neutral, transport concern): a browser/webview client on a different
        // origin (a Tauri app is `tauri://localhost`) sends an `OPTIONS` preflight before the real
        // `Authorization`-bearing request. Preflights **never** carry credentials — the browser strips
        // the Authorization header — so this MUST be answered before the auth gate, and it is
        // fail-safe to do so: this listener is loopback-only and every real route is still
        // app-password gated, so CORS is not the security boundary — the app-password is. See
        // [`JmapResponse`]'s CORS headers (added on every response).
        if req.method.eq_ignore_ascii_case("OPTIONS") {
            return JmapResponse::preflight();
        }
        if !self.authorized(req) {
            return JmapResponse::unauthorized();
        }
        // Strip any query string for route matching (the EventSource URL carries `?types=…`).
        let path = req.path.split('?').next().unwrap_or(&req.path);
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
    /// client never takes down the daemon loop.
    pub async fn handle_connection<T: Transport>(
        &self,
        node: &mut Node<T>,
        mut stream: TcpStream,
    ) -> io::Result<()> {
        let resp = match tokio::time::timeout(READ_TIMEOUT, read_request(&mut stream)).await {
            Ok(Ok(Some(req))) => self.handle(node, &req),
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
}

impl JmapResponse {
    /// A response with an explicit content type and raw body.
    pub fn raw(status: u16, content_type: &'static str, body: Vec<u8>) -> Self {
        JmapResponse { status, content_type, body, www_authenticate: false }
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
/// deadline tick, plus — behind their config flags — the Envoir Send API and the native JMAP
/// listener. Either listener may be absent (`None`); with both absent it is exactly
/// [`crate::daemon::run_loop`]. Runs until `shutdown`, then flushes a final durable checkpoint.
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
                    let _ = api.handle_connection(node, stream).await;
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

/// A conventional reason phrase for the status codes the JMAP surface emits (cosmetic).
fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        500 => "Internal Server Error",
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
            1_752_000_000_000,
        );
        (node, ik_pub)
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
        let r = a.handle(&mut node, &req("GET", "/jmap/session", None, json!({})));
        assert_eq!(r.status, 401);
        assert!(r.www_authenticate, "a 401 must carry the Basic challenge");
        // Wrong secret.
        let r = a.handle(&mut node, &req("GET", "/jmap/session", Some(basic("user@dmtap.local", "nope")), json!({})));
        assert_eq!(r.status, 401);
        // Unknown user.
        let r = a.handle(&mut node, &req("GET", "/jmap/session", Some(basic("mallory", "app-pw")), json!({})));
        assert_eq!(r.status, 401);
        // Non-Basic scheme.
        let r = a.handle(&mut node, &req("GET", "/jmap/session", Some("Bearer app-pw".into()), json!({})));
        assert_eq!(r.status, 401);
    }

    #[test]
    fn no_app_passwords_authenticates_nobody() {
        let (mut node, ik_pub) = node_with_mail();
        let a = JmapApi::new("user@dmtap.local", "http://127.0.0.1:4700", ik_pub.clone(), &[]);
        let r = a.handle(&mut node, &req("GET", "/jmap/session", Some(basic("user@dmtap.local", "app-pw")), json!({})));
        assert_eq!(r.status, 401, "with no credentials configured, even a plausible one fails closed");
    }

    #[test]
    fn session_reflects_live_store_state() {
        let (mut node, ik_pub) = node_with_mail();
        let a = api(&ik_pub);
        let r = a.handle(&mut node, &req("GET", "/jmap/session", Some(basic("user@dmtap.local", "app-pw")), json!({})));
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
        let r = a.handle(&mut node, &req("POST", "/jmap/api/", Some(auth.clone()), body));
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
        let r = a.handle(&mut node, &req("POST", "/jmap/api/", Some(auth), body));
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
        let r = a.handle(&mut node, &req("GET", "/jmap/download/user@dmtap.local/INBOX%7C1/mail.eml", Some(auth.clone()), json!({})));
        assert_eq!(r.status, 200);
        assert_eq!(r.content_type, "application/octet-stream");
        assert!(String::from_utf8_lossy(&r.body).contains("Hi from the live store"));
        // A foreign accountId is refused (isolation).
        let r = a.handle(&mut node, &req("GET", "/jmap/download/someone-else/INBOX%7C1/mail.eml", Some(auth), json!({})));
        assert_eq!(r.status, 404);
    }

    #[test]
    fn unknown_route_is_404_when_authenticated() {
        let (mut node, ik_pub) = node_with_mail();
        let a = api(&ik_pub);
        let r = a.handle(&mut node, &req("GET", "/jmap/bogus", Some(basic("user@dmtap.local", "app-pw")), json!({})));
        assert_eq!(r.status, 404);
    }

    #[test]
    fn options_preflight_is_answered_without_credentials() {
        let (mut node, ik_pub) = node_with_mail();
        let a = api(&ik_pub);
        // A preflight carries NO Authorization header (the browser strips it) — it must still be
        // answered (204), never a fail-closed 401, so the real authenticated request can follow.
        let r = a.handle(&mut node, &req("OPTIONS", "/jmap/api/", None, json!({})));
        assert_eq!(r.status, 204);
        assert!(!r.www_authenticate, "a preflight is not an auth challenge");
        assert!(r.body.is_empty());
    }

    #[test]
    fn every_response_carries_permissive_cors_headers() {
        let (mut node, ik_pub) = node_with_mail();
        let a = api(&ik_pub);
        // The preflight advertises the headers the JMAP client sends.
        let pre = a.handle(&mut node, &req("OPTIONS", "/jmap/api/", None, json!({})));
        let head = pre.header_block();
        assert!(head.contains("Access-Control-Allow-Origin: *"));
        assert!(head.to_ascii_lowercase().contains("access-control-allow-headers: authorization"));
        assert!(head.contains("Access-Control-Allow-Methods: GET, POST, OPTIONS"));
        // A real (authenticated) response ALSO carries the allow-origin header, else the browser
        // discards the body.
        let ok = a.handle(&mut node, &req("GET", "/jmap/session", Some(basic("user@dmtap.local", "app-pw")), json!({})));
        assert_eq!(ok.status, 200);
        assert!(ok.header_block().contains("Access-Control-Allow-Origin: *"));
        // Even the 401 carries CORS (so the browser surfaces the status instead of a CORS error).
        let no = a.handle(&mut node, &req("GET", "/jmap/session", None, json!({})));
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
}

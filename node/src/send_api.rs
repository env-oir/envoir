//! The **Envoir Send** HTTP API surface on the node daemon (spec §13.5.1) — a sovereign / private
//! Resend.
//!
//! The reusable capability core lives in the workspace-shared [`dmtap_send`] crate: an API key **is**
//! a scoped, rotatable, independently-revocable capability token ([`dmtap_send::SendService`]), and a
//! send builds + HPKE-seals a real MOTE (spec §2). This module wires that core into the *running
//! node*: it binds an HTTP listener, authenticates every request against the capability token
//! (fail-closed via [`dmtap_send::SendService::verify_key`]), and — on a valid send — routes the
//! sealed MOTE into the node's **real §20.1 outbound retry queue + mesh dispatch** (the exact path
//! [`Node::send_mail`] drives) through [`Node::dispatch_sealed`].
//!
//! ## Transport
//! A framework-free `std`/`tokio` HTTP/1.1 adapter, the same lightweight approach the §8 client
//! servers use (a `TcpListener` + a minimal request parser) — no web framework. Because a
//! [`Node`] is **not `Send`** (it owns `Box<dyn Journal>` / `Box<dyn NameChainClient>` trait
//! objects), the listener runs on the daemon's *own* current-thread task inside
//! [`run_loop_with_send_api`], handling each connection inline with the live `&mut Node` — so the
//! MOTE genuinely enters this node's outbound path rather than a copy on another thread.
//!
//! ## Routes
//! - `POST /v1/send` — Bearer capability auth; delegated to [`dmtap_send::http::handle_send`], which
//!   verifies the key, enforces the [`dmtap_send::SendScope`], charges the rate caveat, resolves the
//!   recipient, seals the MOTE, and hands it to the node-backed [`Delivery`] seam.
//! - `POST /v1/keys` — issue a scoped key; `POST /v1/keys/rotate` — rotate; `POST /v1/keys/revoke` —
//!   revoke. These management routes are guarded by a separate **admin** Bearer token
//!   ([`SendApi::new`]'s `admin_token`); with no admin token configured they are **disabled**
//!   (fail-closed), so `/v1/send` still works but keys can never be minted without an explicit secret.
//!
//! ## Fail-closed authentication
//! Every unknown / revoked / expired / not-yet-valid / foreign / out-of-scope / rate-limited key
//! resolves to a [`dmtap_send::SendError`] and a non-2xx status — never a silent accept; the enforcement
//! is the offline capability verification in `dmtap-send`, unchanged here. A missing/incorrect admin
//! token on a management route is likewise rejected before any key state is touched.

use std::cell::RefCell;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::time::Duration;

use dmtap_core::identity::IdentityKey;
use dmtap_core::mote::Envelope;
use dmtap_core::TimestampMs;
use dmtap_send::http::{handle_send, HttpRequest, HttpResponse};
use dmtap_send::{
    Delivery, DeliveryError, DeliveryReceipt, Environment, ResolveError, ResolvedRecipient, Resolver,
    SendError, SendScope, SendService,
};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::daemon::{now_ms, LoopStats};
use crate::node::Node;
use crate::transport::Transport;

/// Default key lifetime when a mint request omits `ttl_ms` (one year).
const YEAR_MS: u64 = 365 * 24 * 60 * 60 * 1000;
/// Hard cap on a single request's header block + body — a hostile/oversized request is refused.
const MAX_REQUEST_BYTES: usize = 256 * 1024;
/// How long a single connection may take to deliver its request before it is dropped (it runs on the
/// daemon's own task, so an unbounded read would stall delivery/retry ticks).
const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// The node-hosted Envoir Send service: the capability [`SendService`] plus the admin token that
/// guards key management. Construct with the node's own identity so issued keys delegate from — and
/// sealed MOTEs authenticate as — this node (§13.5.1).
pub struct SendApi {
    service: SendService,
    admin_token: Option<String>,
}

impl SendApi {
    /// Build the service owned by `owner` (this node's identity). `admin_token` guards the
    /// `/v1/keys*` management routes; `None` disables them (fail-closed).
    pub fn new(owner: IdentityKey, admin_token: Option<String>) -> Self {
        SendApi { service: SendService::new(owner), admin_token }
    }

    /// The underlying capability service (for publishing revocations, tests, bootstrap key issuance).
    pub fn service(&self) -> &SendService {
        &self.service
    }

    /// Mutable access to the capability service (e.g. to issue a bootstrap key at startup).
    pub fn service_mut(&mut self) -> &mut SendService {
        &mut self.service
    }

    /// Handle one parsed request against the live `node` at logical time `now`, returning the
    /// response. This is the whole routing + fail-closed authorization surface, synchronous and
    /// directly unit-testable.
    pub fn handle<T: Transport>(
        &mut self,
        node: &mut Node<T>,
        req: &HttpRequest,
        now: TimestampMs,
    ) -> HttpResponse {
        // The send route is delegated wholesale to dmtap-send's adapter (it does its own method/path
        // + Bearer + scope + rate checks, fail-closed).
        if req.path == "/v1/send" {
            return self.handle_send_route(node, req, now);
        }

        // Admin-guarded key-management routes.
        let route = match req.path.as_str() {
            "/v1/keys" | "/v1/keys/rotate" | "/v1/keys/revoke" => req.path.clone(),
            _ => return json_response(404, json!({ "error": "not_found", "detail": req.path })),
        };
        if req.method != "POST" {
            return json_response(405, json!({ "error": "method_not_allowed", "detail": req.method }));
        }
        if let Some(deny) = self.deny_if_not_admin(req) {
            return deny;
        }
        match route.as_str() {
            "/v1/keys" => self.handle_issue(req, now),
            "/v1/keys/rotate" => self.handle_rotate(req, now),
            "/v1/keys/revoke" => self.handle_revoke(req, now),
            _ => unreachable!("route matched above"),
        }
    }

    /// `POST /v1/send`: seal + route into the node's real outbound path. Builds a node-backed
    /// [`Delivery`] seam (which calls [`Node::dispatch_sealed`]) and a resolver over the node's known
    /// contacts, then hands the request to [`dmtap_send::http::handle_send`] — the full verify →
    /// scope → rate → resolve → seal → deliver pipeline, fail-closed at every step.
    fn handle_send_route<T: Transport>(
        &mut self,
        node: &mut Node<T>,
        req: &HttpRequest,
        now: TimestampMs,
    ) -> HttpResponse {
        // Align the node's clock so the queued MOTE's §16.1 deadline is anchored at this request.
        node.set_now(now);
        // Snapshot the contact directory first (owned copy ⇒ the resolver holds no borrow on the node
        // while the delivery seam borrows it mutably).
        let resolver = NativeDirResolver { dir: node.directory_snapshot() };
        let delivery = NodeDelivery { node: RefCell::new(node) };
        handle_send(&mut self.service, &resolver, &delivery, req, now)
    }

    /// `POST /v1/keys`: issue a scoped key. Body: `{ "env": "prod"|"test", "domain": "d"|null,
    /// "rate_per_min": u64|null, "ttl_ms": u64|null }`.
    fn handle_issue(&mut self, req: &HttpRequest, now: TimestampMs) -> HttpResponse {
        let v: Value = match serde_json::from_slice(&req.body) {
            Ok(v) => v,
            Err(e) => return json_response(400, json!({ "error": "bad_request", "detail": e.to_string() })),
        };
        let environment = match v.get("env").and_then(Value::as_str).unwrap_or("prod") {
            "prod" => Environment::Prod,
            "test" => Environment::Test,
            other => {
                return json_response(400, json!({ "error": "bad_request", "detail": format!("unknown env {other}") }))
            }
        };
        let domain = v.get("domain").and_then(Value::as_str).filter(|d| !d.is_empty());
        let mut scope = match domain {
            Some(d) => SendScope::domain(d, environment),
            None => SendScope::account(environment),
        };
        let rate = v.get("rate_per_min").and_then(Value::as_u64);
        if let Some(r) = rate {
            scope = scope.with_rate_per_min(r);
        }
        let ttl = v.get("ttl_ms").and_then(Value::as_u64).unwrap_or(YEAR_MS);
        let key = self.service.issue_key(scope, now, ttl);
        json_response(
            200,
            json!({
                "secret": key.secret(),
                "id": hex(key.content_id().as_bytes()),
                "environment": environment.as_str(),
                "domain": domain,
                "rate_per_min": rate,
            }),
        )
    }

    /// `POST /v1/keys/rotate`: mint a replacement + revoke the old. Body: `{ "secret": "..." }`.
    fn handle_rotate(&mut self, req: &HttpRequest, now: TimestampMs) -> HttpResponse {
        let secret = match body_secret(req) {
            Ok(s) => s,
            Err(resp) => return resp,
        };
        match self.service.rotate_key(&secret, now, YEAR_MS) {
            Ok(key) => json_response(200, json!({ "secret": key.secret(), "id": hex(key.content_id().as_bytes()) })),
            Err(e) => send_error_response(&e),
        }
    }

    /// `POST /v1/keys/revoke`: revoke a key + emit a signed revocation. Body: `{ "secret": "..." }`.
    fn handle_revoke(&mut self, req: &HttpRequest, now: TimestampMs) -> HttpResponse {
        let secret = match body_secret(req) {
            Ok(s) => s,
            Err(resp) => return resp,
        };
        match self.service.revoke_key(&secret, now) {
            Ok(rev) => json_response(200, json!({ "revoked": true, "token": hex(rev.token.as_bytes()) })),
            Err(e) => send_error_response(&e),
        }
    }

    /// Fail-closed admin gate for the key-management routes: `Some(response)` denies, `None` admits.
    /// No admin token configured ⇒ the routes are disabled (`403`); a missing/mismatched token ⇒
    /// `401`. The comparison is constant-time to avoid a token-guessing timing oracle.
    fn deny_if_not_admin(&self, req: &HttpRequest) -> Option<HttpResponse> {
        let expected = match &self.admin_token {
            Some(t) => t,
            None => {
                return Some(json_response(
                    403,
                    json!({ "error": "forbidden", "detail": "key management is disabled (no admin token configured)" }),
                ))
            }
        };
        match req.authorization.as_deref().and_then(parse_bearer) {
            Some(tok) if ct_eq(tok.as_bytes(), expected.as_bytes()) => None,
            Some(_) => Some(json_response(401, json!({ "error": "unauthorized", "detail": "invalid admin token" }))),
            None => Some(json_response(401, json!({ "error": "unauthorized", "detail": "missing admin Bearer token" }))),
        }
    }

    /// Serve one accepted connection: read the request (bounded by [`READ_TIMEOUT`] + size caps),
    /// dispatch it against the live node, and write the JSON response. Errors in framing become a
    /// `400`/`408` rather than propagating — one bad client never takes down the loop.
    pub async fn handle_connection<T: Transport>(
        &mut self,
        node: &mut Node<T>,
        mut stream: TcpStream,
        now: TimestampMs,
    ) -> io::Result<()> {
        let req = match tokio::time::timeout(READ_TIMEOUT, read_request(&mut stream)).await {
            Ok(Ok(Some(req))) => req,
            Ok(Ok(None)) => return Ok(()), // empty connection, nothing to answer
            Ok(Err(e)) => {
                let resp = json_response(400, json!({ "error": "bad_request", "detail": e.to_string() }));
                let _ = write_response(&mut stream, &resp).await;
                return Ok(());
            }
            Err(_) => {
                let resp = json_response(408, json!({ "error": "request_timeout" }));
                let _ = write_response(&mut stream, &resp).await;
                return Ok(());
            }
        };
        let resp = self.handle(node, &req, now);
        write_response(&mut stream, &resp).await
    }
}

/// The node-backed [`Delivery`] seam: hand a **pre-sealed** MOTE to the node's real §20.1 outbound
/// retry queue + mesh dispatch. Interior mutability (`RefCell`) bridges the `&self` trait method to
/// the node's `&mut` API; the borrow is scoped to the single `deliver` call.
struct NodeDelivery<'a, T: Transport> {
    node: RefCell<&'a mut Node<T>>,
}

impl<T: Transport> Delivery for NodeDelivery<'_, T> {
    fn deliver(&self, mote: &Envelope, recipient: &ResolvedRecipient) -> Result<DeliveryReceipt, DeliveryError> {
        let mut node = self.node.borrow_mut();
        let id = node.dispatch_sealed(&recipient.ik, mote.clone());
        Ok(DeliveryReceipt {
            transport: if recipient.is_native { "native-mesh".into() } else { "smtp-gateway".into() },
            accepted: true,
            detail: Some(hex(id.as_bytes())),
        })
    }
}

/// Resolve a recipient against the node's own learned contacts (§5.3). The `to` field is a
/// base64url-encoded DMTAP identity key (§3.2) of a peer this node already knows (`add_contact` /
/// `learn_key`); the reply seals to that peer's advertised X25519 key over the native mesh. Anything
/// not a known base64url contact fails closed — honest, matching the daemon's not-yet-wired live
/// DNS/KT naming seam (§3.3): the send API never guesses an internet recipient it cannot verify.
struct NativeDirResolver {
    dir: HashMap<Vec<u8>, [u8; 32]>,
}

impl Resolver for NativeDirResolver {
    fn resolve(&self, address: &str) -> Result<ResolvedRecipient, ResolveError> {
        let ik = crate::names::base64url::decode(address)
            .ok_or_else(|| ResolveError(format!("recipient {address} is not a base64url DMTAP address")))?;
        let seal_pub = self
            .dir
            .get(&ik)
            .ok_or_else(|| ResolveError(format!("recipient {address} is not a known contact of this node")))?;
        Ok(ResolvedRecipient { address: address.to_string(), ik, seal_pub: seal_pub.to_vec(), is_native: true })
    }
}

/// The daemon's combined steady-state loop **with** the Envoir Send API: identical to
/// [`crate::daemon::run_loop`] (drain inbound / fire retries / expire deadlines each tick) but with a
/// third `select!` arm accepting Send-API connections and handling each **inline on this task** with
/// the live `&mut node` — the only way to route the sealed MOTE into this node's own outbound path,
/// since [`Node`] is not `Send`. Runs until `shutdown`, then flushes a final durable checkpoint.
pub async fn run_loop_with_send_api<T: Transport>(
    node: &mut Node<T>,
    api: &mut SendApi,
    listener: TcpListener,
    tick: Duration,
    shutdown: impl Future<Output = ()>,
) -> LoopStats {
    tokio::pin!(shutdown);
    let mut interval = tokio::time::interval(tick);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut stats = LoopStats::default();
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                if let Ok((stream, _peer)) = accepted {
                    let _ = api.handle_connection(node, stream, now_ms()).await;
                }
            }
            _ = interval.tick() => {
                node.set_now(now_ms());
                let inbound = node.poll();
                stats.inbound += inbound.len() as u64;
                stats.retried += node.retry_pending() as u64;
                node.tick_deadlines();
                stats.ticks += 1;
            }
        }
    }
    stats.flushed_ok = node.flush().is_ok();
    stats
}

// --- minimal HTTP/1.1 framing (no web framework) -------------------------------------------------

/// Read one HTTP/1.1 request off `stream` into an [`HttpRequest`], bounded by [`MAX_REQUEST_BYTES`].
/// Returns `Ok(None)` on a cleanly-empty connection. Only the request line, `Authorization`, and
/// `Content-Length` are interpreted — everything else is ignored (this is a JSON POST endpoint).
async fn read_request(stream: &mut TcpStream) -> io::Result<Option<HttpRequest>> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos;
        }
        if buf.len() > MAX_REQUEST_BYTES {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "request headers too large"));
        }
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            if buf.is_empty() {
                return Ok(None);
            }
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed before request completed"));
        }
        buf.extend_from_slice(&tmp[..n]);
    };

    let head = std::str::from_utf8(&buf[..header_end])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-utf8 request headers"))?;
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next().unwrap_or("").split_whitespace();
    let method = request_line.next().unwrap_or("").to_string();
    let path = request_line.next().unwrap_or("").to_string();

    let mut authorization = None;
    let mut content_length = 0usize;
    for line in lines {
        if let Some((k, val)) = line.split_once(':') {
            let (k, val) = (k.trim(), val.trim());
            if k.eq_ignore_ascii_case("authorization") {
                authorization = Some(val.to_string());
            } else if k.eq_ignore_ascii_case("content-length") {
                content_length = val.parse().unwrap_or(0);
            }
        }
    }
    if content_length > MAX_REQUEST_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "request body too large"));
    }

    let body_start = header_end + 4; // past the CRLFCRLF terminator
    let mut body = buf[body_start..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(content_length);

    Ok(Some(HttpRequest { method, path, authorization, body }))
}

/// Write an [`HttpResponse`] as an HTTP/1.1 `Connection: close` reply with a JSON body.
async fn write_response(stream: &mut TcpStream, resp: &HttpResponse) -> io::Result<()> {
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        resp.status,
        reason_phrase(resp.status),
        resp.body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&resp.body).await?;
    stream.flush().await
}

/// The first index of `needle` in `hay`, if present.
fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// A conventional reason phrase for the status codes this API emits (cosmetic; clients read the code).
fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
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

// --- small helpers -------------------------------------------------------------------------------

/// Build a JSON [`HttpResponse`].
fn json_response(status: u16, value: Value) -> HttpResponse {
    HttpResponse { status, body: serde_json::to_vec(&value).unwrap_or_default() }
}

/// Map a fail-closed [`SendError`] to its `{status, {error, detail}}` response.
fn send_error_response(e: &SendError) -> HttpResponse {
    json_response(e.http_status(), json!({ "error": error_slug(e), "detail": e.to_string() }))
}

/// A stable machine-readable slug for each [`SendError`] (mirrors the send-route adapter's).
fn error_slug(e: &SendError) -> &'static str {
    match e {
        SendError::Unauthorized => "unauthorized",
        SendError::Revoked => "revoked",
        SendError::Expired => "expired",
        SendError::NotYetValid => "not_yet_valid",
        SendError::WrongIssuer => "wrong_issuer",
        SendError::Capability(_) => "capability_invalid",
        SendError::OutOfScope => "out_of_scope",
        SendError::RateLimited => "rate_limited",
        SendError::Resolve(_) => "unresolvable_recipient",
        SendError::Delivery(_) => "delivery_failed",
        SendError::Build(_) => "build_failed",
    }
}

/// Extract a non-empty `{"secret": "..."}` from a request body, or the `400` to return.
fn body_secret(req: &HttpRequest) -> Result<String, HttpResponse> {
    let v: Value = serde_json::from_slice(&req.body)
        .map_err(|e| json_response(400, json!({ "error": "bad_request", "detail": e.to_string() })))?;
    match v.get("secret").and_then(Value::as_str) {
        Some(s) if !s.is_empty() => Ok(s.to_string()),
        _ => Err(json_response(400, json!({ "error": "bad_request", "detail": "missing \"secret\"" }))),
    }
}

/// Extract the token from an `Authorization: Bearer <token>` header value.
fn parse_bearer(header: &str) -> Option<&str> {
    header.strip_prefix("Bearer ").map(str::trim).filter(|t| !t.is_empty())
}

/// Constant-time byte equality (length is allowed to leak — a bearer token's length is not secret).
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

/// Lowercase hex (no extra crate).
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

//! Authenticated admin API for the multi-tenant public gateway (spec §7 "gateway as a business").
//!
//! This is the **control surface** envoir-cloud (the separate, private billing repo) drives to manage
//! a running [`MultiDomainGateway`](crate::multidomain::MultiDomainGateway): add/remove served
//! domains (+ their DKIM keys), manage per-domain recipients and aliases (vanity + random), block or
//! unblock senders, suspend or reinstate local users, set per-domain quotas, and read per-domain
//! usage off the [`UsageMeter`](crate::multidomain::UsageMeter). It is **OSS and billing-free**: it
//! exposes the meter; it never turns usage into money (that lives in envoir-cloud).
//!
//! ## Fail-closed authentication (§18.9.11)
//! Every request is authenticated with a **bearer admin token** (`Authorization: Bearer <token>`),
//! compared in constant time. It is fail-closed on every axis:
//! - a gateway with **no** admin token configured ([`AdminAuth::disabled`]) refuses **every** request
//!   `401` — the API is inert until a token is set, so it is safe by default;
//! - a missing, malformed, or wrong token is `401`;
//! - the [`AdminServer`] listens **only over TLS** (the token must never travel in cleartext), exactly
//!   like the legacy access surfaces (§7.15.1).
//!
//! ## Shape
//! [`AdminApi::handle`] is a pure `AdminRequest → AdminResponse` function (method + path + token +
//! form body + a caller-supplied `now_ms`), so the whole authorization + dispatch surface is unit
//! tested without a socket. [`AdminServer`] is the thin HTTPS/1.1 transport that parses a request off
//! a TLS socket, calls `handle`, and writes the JSON response — modelled on the existing
//! [`crate::imap_access`] / [`crate::inbound_tcp`] accept loops.
//!
//! The request body is a simple, **non-percent-encoded** `key=value` form (pairs separated by `&` or
//! newlines; each split on the first `=`, so base64 values keep their `+`/`/`/`=` intact). Responses
//! are minimal JSON. No serde / no extra deps — consistent with the rest of the crate.

use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::{ServerConfig, ServerConnection, StreamOwned};

use crate::alias_map::AliasTarget;
use crate::authz::Quota;
use crate::inbound::RecipientKey;
use crate::multidomain::{MultiDomainError, MultiDomainGateway, UsageMeter};

/// Largest admin request head (request line + headers) we will buffer — a bounded, fail-closed cap so
/// a hostile client cannot drive the server to OOM before auth.
const MAX_HEAD_BYTES: usize = 64 * 1024;
/// Largest admin request body we will read (recipient keys, alias params — all small).
const MAX_BODY_BYTES: usize = 256 * 1024;

// ── Authentication ────────────────────────────────────────────────────────────────────────────

/// The admin bearer-token authenticator. **Fail-closed**: [`AdminAuth::disabled`] (no token) refuses
/// every request, so the API is inert until an operator explicitly configures a token.
#[derive(Debug, Clone, Default)]
pub struct AdminAuth {
    token: Option<String>,
}

impl AdminAuth {
    /// An authenticator with **no** token configured — every `authorize` is `false` (the API is off).
    pub fn disabled() -> Self {
        AdminAuth { token: None }
    }

    /// An authenticator that accepts exactly `token`. A blank token is treated as **disabled**
    /// (fail-closed): an empty secret must never authorize anything.
    pub fn with_token(token: impl Into<String>) -> Self {
        let t = token.into();
        if t.trim().is_empty() {
            AdminAuth { token: None }
        } else {
            AdminAuth { token: Some(t) }
        }
    }

    /// Whether an admin token is configured at all (the API is live).
    pub fn is_enabled(&self) -> bool {
        self.token.is_some()
    }

    /// Authorize a presented bearer token in **constant time**. `None` (no header) or any mismatch is
    /// `false`; a gateway with no configured token is always `false` (fail-closed).
    pub fn authorize(&self, presented: Option<&str>) -> bool {
        let Some(expected) = &self.token else {
            return false;
        };
        let Some(presented) = presented else {
            return false;
        };
        ct_eq(expected.as_bytes(), presented.as_bytes())
    }
}

/// Constant-time byte-slice equality (no early return on the first differing byte). Length inequality
/// short-circuits (a length difference is not secret), but equal-length comparison is data-independent.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ── Request / response ──────────────────────────────────────────────────────────────────────────

/// A parsed admin request: HTTP method, path, the presented bearer token (if any), the raw form body,
/// and the caller's notion of `now` (ms since epoch) used for alias TTLs — a parameter so dispatch is
/// deterministic in tests.
#[derive(Debug, Clone)]
pub struct AdminRequest {
    /// Uppercased HTTP method (`GET` / `POST` / `PUT` / `DELETE`).
    pub method: String,
    /// The request path (`/v1/domains/host.net`).
    pub path: String,
    /// The bearer token extracted from `Authorization: Bearer <token>`, if present.
    pub token: Option<String>,
    /// The raw request body (a `key=value` form).
    pub body: Vec<u8>,
    /// Wall-clock time (ms since epoch) for alias TTL / metering.
    pub now_ms: u64,
}

impl AdminRequest {
    /// A convenience constructor for tests / callers.
    pub fn new(
        method: impl Into<String>,
        path: impl Into<String>,
        token: Option<String>,
        body: impl Into<Vec<u8>>,
        now_ms: u64,
    ) -> Self {
        AdminRequest {
            method: method.into().to_ascii_uppercase(),
            path: path.into(),
            token,
            body: body.into(),
            now_ms,
        }
    }
}

/// An admin response: an HTTP status and a JSON body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminResponse {
    /// HTTP status code.
    pub status: u16,
    /// JSON body text.
    pub body: String,
}

impl AdminResponse {
    fn ok(body: String) -> Self {
        AdminResponse { status: 200, body }
    }
    fn created(body: String) -> Self {
        AdminResponse { status: 201, body }
    }
    fn err(status: u16, message: &str) -> Self {
        AdminResponse { status, body: format!("{{\"ok\":false,\"error\":{}}}", json_str(message)) }
    }
    /// The HTTP reason phrase for this status (a small fixed set).
    fn reason(&self) -> &'static str {
        match self.status {
            200 => "OK",
            201 => "Created",
            400 => "Bad Request",
            401 => "Unauthorized",
            404 => "Not Found",
            405 => "Method Not Allowed",
            409 => "Conflict",
            _ => "Internal Server Error",
        }
    }
}

// ── The API (auth + dispatch) ─────────────────────────────────────────────────────────────────

/// The authenticated admin API over a shared [`MultiDomainGateway`] + its [`UsageMeter`]. Cheap to
/// clone (everything is behind `Arc`), so each accepted connection thread gets its own handle.
#[derive(Clone)]
pub struct AdminApi {
    gateway: Arc<Mutex<MultiDomainGateway>>,
    meter: UsageMeter,
    auth: AdminAuth,
}

impl AdminApi {
    /// Build the API over a shared gateway, its usage meter, and the admin authenticator.
    pub fn new(
        gateway: Arc<Mutex<MultiDomainGateway>>,
        meter: UsageMeter,
        auth: AdminAuth,
    ) -> Self {
        AdminApi { gateway, meter, auth }
    }

    /// Handle one request: **authenticate first** (fail-closed `401`), then dispatch. Pure — no I/O.
    pub fn handle(&self, req: &AdminRequest) -> AdminResponse {
        if !self.auth.authorize(req.token.as_deref()) {
            return AdminResponse::err(401, "unauthorized");
        }
        let segments: Vec<&str> = req.path.split('/').filter(|s| !s.is_empty()).collect();
        // Every route is versioned under /v1.
        if segments.first() != Some(&"v1") {
            return AdminResponse::err(404, "unknown path");
        }
        let rest = &segments[1..];
        let form = parse_form(&req.body);
        let m = req.method.as_str();

        match rest {
            ["health"] if m == "GET" => {
                AdminResponse::ok("{\"ok\":true,\"status\":\"live\"}".into())
            }

            // ── domains ──
            ["domains"] if m == "GET" => self.list_domains(),
            ["domains"] if m == "POST" => self.add_domain(&form),
            ["domains", d] if m == "GET" => self.get_domain(d),
            ["domains", d] if m == "DELETE" => self.remove_domain(d),

            // ── recipients ──
            ["domains", d, "recipients"] if m == "POST" => self.add_recipient(d, &form),
            ["domains", d, "recipients"] if m == "DELETE" => self.remove_recipient(d, &form),

            // ── aliases ──
            ["domains", d, "aliases", "vanity"] if m == "POST" => self.allocate_vanity(d, &form),
            ["domains", d, "aliases", "vanity"] if m == "DELETE" => self.revoke_vanity(d, &form),
            ["domains", d, "aliases", "random"] if m == "POST" => {
                self.mint_random(d, &form, req.now_ms)
            }
            ["domains", d, "aliases", "random", token] if m == "DELETE" => {
                self.burn_random(d, token)
            }

            // ── blocklist / suspension ──
            ["domains", d, "blocklist"] if m == "POST" => self.block(d, &form),
            ["domains", d, "blocklist"] if m == "DELETE" => self.unblock(d, &form),
            ["domains", d, "suspend"] if m == "POST" => self.suspend(d, &form),
            ["domains", d, "suspend"] if m == "DELETE" => self.unsuspend(d, &form),

            // ── quota ──
            ["domains", d, "quota"] if m == "PUT" => self.set_quota(d, &form),

            // ── usage ──
            ["usage"] if m == "GET" => self.usage(),

            // A known path with the wrong method vs a genuinely unknown path.
            _ => {
                if is_known_path(rest) {
                    AdminResponse::err(405, "method not allowed")
                } else {
                    AdminResponse::err(404, "unknown path")
                }
            }
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MultiDomainGateway> {
        self.gateway.lock().expect("gateway lock poisoned")
    }

    fn list_domains(&self) -> AdminResponse {
        let gw = self.lock();
        let items: Vec<String> = gw.domains().iter().map(|d| json_str(d)).collect();
        AdminResponse::ok(format!("{{\"ok\":true,\"domains\":[{}]}}", items.join(",")))
    }

    fn add_domain(&self, form: &Form) -> AdminResponse {
        let Some(domain) = form.field("domain") else {
            return AdminResponse::err(400, "missing domain");
        };
        let selector = form.field("selector").unwrap_or("gw1");
        let seed = match form.field("dkim_seed_b64") {
            Some(b64) => match decode_seed(b64) {
                Ok(s) => Some(s),
                Err(e) => return AdminResponse::err(400, &e),
            },
            None => None,
        };
        let quota = match parse_quota(form) {
            Ok(q) => q,
            Err(e) => return AdminResponse::err(400, &e),
        };
        let mut gw = self.lock();
        let used_seed = match gw.add_domain(domain, seed, selector) {
            Ok(s) => s,
            Err(e) => return map_md_err(e),
        };
        if let Some(q) = quota {
            let _ = gw.set_domain_quota(domain, q);
        }
        let tenant = gw.tenant(domain).expect("just added");
        AdminResponse::created(format!(
            "{{\"ok\":true,\"domain\":{},\"selector\":{},\"dkim_public\":{},\"dkim_seed_b64\":{}}}",
            json_str(tenant.domain()),
            json_str(tenant.dkim_selector()),
            json_str(&tenant.dkim_public_p_tag()),
            json_str(&crate::b64::encode(&used_seed)),
        ))
    }

    fn get_domain(&self, d: &str) -> AdminResponse {
        let gw = self.lock();
        let Some(t) = gw.tenant(d) else {
            return AdminResponse::err(404, "domain not served");
        };
        let q = t.quota();
        let u = t.usage();
        AdminResponse::ok(format!(
            "{{\"ok\":true,\"domain\":{},\"selector\":{},\"dkim_public\":{},\"recipients\":{},\
             \"quota_messages\":{},\"quota_bytes\":{},\"used_messages\":{},\"used_bytes\":{}}}",
            json_str(t.domain()),
            json_str(t.dkim_selector()),
            json_str(&t.dkim_public_p_tag()),
            t.recipient_count(),
            q.hard_cap_messages,
            q.hard_cap_bytes,
            u.messages,
            u.bytes,
        ))
    }

    fn remove_domain(&self, d: &str) -> AdminResponse {
        if self.lock().remove_domain(d) {
            AdminResponse::ok(format!("{{\"ok\":true,\"removed\":{}}}", json_str(d)))
        } else {
            AdminResponse::err(404, "domain not served")
        }
    }

    fn add_recipient(&self, d: &str, form: &Form) -> AdminResponse {
        let (Some(email), Some(ik), Some(seal)) =
            (form.field("email"), form.field("ik_b64"), form.field("seal_b64"))
        else {
            return AdminResponse::err(400, "missing email/ik_b64/seal_b64");
        };
        // The recipient's domain must match the path domain (no cross-tenant writes).
        if !email.rsplit_once('@').map(|(_, dom)| dom.eq_ignore_ascii_case(d)).unwrap_or(false) {
            return AdminResponse::err(400, "email domain does not match path domain");
        }
        let ik = match crate::b64::decode(ik) {
            Ok(b) => b,
            Err(e) => return AdminResponse::err(400, &format!("bad ik_b64: {e}")),
        };
        let seal_pub = match crate::b64::decode(seal) {
            Ok(b) => b,
            Err(e) => return AdminResponse::err(400, &format!("bad seal_b64: {e}")),
        };
        match self.lock().add_recipient(email, RecipientKey { ik, seal_pub }) {
            Ok(()) => {
                AdminResponse::created(format!("{{\"ok\":true,\"recipient\":{}}}", json_str(email)))
            }
            Err(e) => map_md_err(e),
        }
    }

    fn remove_recipient(&self, d: &str, form: &Form) -> AdminResponse {
        let Some(email) = form.field("email") else {
            return AdminResponse::err(400, "missing email");
        };
        let _ = d;
        match self.lock().remove_recipient(email) {
            Ok(true) => {
                AdminResponse::ok(format!("{{\"ok\":true,\"removed\":{}}}", json_str(email)))
            }
            Ok(false) => AdminResponse::err(404, "recipient not found"),
            Err(e) => map_md_err(e),
        }
    }

    fn allocate_vanity(&self, d: &str, form: &Form) -> AdminResponse {
        let (Some(key_b64), Some(local)) = (form.field("key_b64"), form.field("local_part")) else {
            return AdminResponse::err(400, "missing key_b64/local_part");
        };
        let key = match crate::b64::decode(key_b64) {
            Ok(b) => b,
            Err(e) => return AdminResponse::err(400, &format!("bad key_b64: {e}")),
        };
        match self.lock().allocate_vanity(d, &key, local) {
            Ok(addr) => {
                AdminResponse::created(format!("{{\"ok\":true,\"alias\":{}}}", json_str(&addr)))
            }
            Err(e) => map_md_err(e),
        }
    }

    fn revoke_vanity(&self, d: &str, form: &Form) -> AdminResponse {
        let Some(key_b64) = form.field("key_b64") else {
            return AdminResponse::err(400, "missing key_b64");
        };
        let key = match crate::b64::decode(key_b64) {
            Ok(b) => b,
            Err(e) => return AdminResponse::err(400, &format!("bad key_b64: {e}")),
        };
        match self.lock().revoke_vanity(d, &key) {
            Ok(Some(addr)) => {
                AdminResponse::ok(format!("{{\"ok\":true,\"revoked\":{}}}", json_str(&addr)))
            }
            Ok(None) => AdminResponse::err(404, "key holds no vanity on this domain"),
            Err(e) => map_md_err(e),
        }
    }

    fn mint_random(&self, d: &str, form: &Form, now_ms: u64) -> AdminResponse {
        let Some(target_raw) = form.field("target") else {
            return AdminResponse::err(400, "missing target");
        };
        let target = match parse_target(target_raw) {
            Ok(t) => t,
            Err(e) => return AdminResponse::err(400, &e),
        };
        let correspondent = form.field("correspondent").map(|s| s.to_string());
        let ttl_ms = match form.field("ttl_ms") {
            Some(v) => match v.parse::<u64>() {
                Ok(n) => Some(n),
                Err(_) => return AdminResponse::err(400, "ttl_ms must be a non-negative integer"),
            },
            None => None,
        };
        let one_time = matches!(form.field("one_time"), Some(v) if is_true(v));
        match self.lock().mint_random_alias(d, target, correspondent, ttl_ms, one_time, now_ms) {
            Ok(addr) => {
                AdminResponse::created(format!("{{\"ok\":true,\"alias\":{}}}", json_str(&addr)))
            }
            Err(e) => map_md_err(e),
        }
    }

    fn burn_random(&self, d: &str, token: &str) -> AdminResponse {
        match self.lock().burn_random_alias(d, token) {
            Ok(true) => {
                AdminResponse::ok(format!("{{\"ok\":true,\"burned\":{}}}", json_str(token)))
            }
            Ok(false) => AdminResponse::err(404, "alias token not found"),
            Err(e) => map_md_err(e),
        }
    }

    fn block(&self, d: &str, form: &Form) -> AdminResponse {
        let Some(sender) = form.field("sender") else {
            return AdminResponse::err(400, "missing sender");
        };
        if matches!(form.field("scope"), Some(s) if s.eq_ignore_ascii_case("global")) {
            self.lock().block_sender_global(sender);
            return AdminResponse::ok(format!(
                "{{\"ok\":true,\"blocked\":{},\"scope\":\"global\"}}",
                json_str(sender)
            ));
        }
        match self.lock().block_sender(d, sender) {
            Ok(()) => {
                AdminResponse::ok(format!("{{\"ok\":true,\"blocked\":{}}}", json_str(sender)))
            }
            Err(e) => map_md_err(e),
        }
    }

    fn unblock(&self, d: &str, form: &Form) -> AdminResponse {
        let Some(sender) = form.field("sender") else {
            return AdminResponse::err(400, "missing sender");
        };
        if matches!(form.field("scope"), Some(s) if s.eq_ignore_ascii_case("global")) {
            let was = self.lock().unblock_sender_global(sender);
            return AdminResponse::ok(format!("{{\"ok\":true,\"unblocked\":{}}}", was));
        }
        match self.lock().unblock_sender(d, sender) {
            Ok(was) => AdminResponse::ok(format!("{{\"ok\":true,\"unblocked\":{}}}", was)),
            Err(e) => map_md_err(e),
        }
    }

    fn suspend(&self, d: &str, form: &Form) -> AdminResponse {
        let Some(user) = form.field("user") else {
            return AdminResponse::err(400, "missing user");
        };
        match self.lock().suspend_user(d, user) {
            Ok(()) => {
                AdminResponse::ok(format!("{{\"ok\":true,\"suspended\":{}}}", json_str(user)))
            }
            Err(e) => map_md_err(e),
        }
    }

    fn unsuspend(&self, d: &str, form: &Form) -> AdminResponse {
        let Some(user) = form.field("user") else {
            return AdminResponse::err(400, "missing user");
        };
        match self.lock().unsuspend_user(d, user) {
            Ok(was) => AdminResponse::ok(format!("{{\"ok\":true,\"reinstated\":{}}}", was)),
            Err(e) => map_md_err(e),
        }
    }

    fn set_quota(&self, d: &str, form: &Form) -> AdminResponse {
        let quota = match parse_quota(form) {
            Ok(Some(q)) => q,
            Ok(None) => Quota::messages(0, 0), // both zero ⇒ unlimited
            Err(e) => return AdminResponse::err(400, &e),
        };
        match self.lock().set_domain_quota(d, quota) {
            Ok(()) => AdminResponse::ok(format!(
                "{{\"ok\":true,\"domain\":{},\"quota_messages\":{},\"quota_bytes\":{}}}",
                json_str(d),
                quota.hard_cap_messages,
                quota.hard_cap_bytes
            )),
            Err(e) => map_md_err(e),
        }
    }

    fn usage(&self) -> AdminResponse {
        let snap = self.meter.snapshot();
        let items: Vec<String> = snap
            .iter()
            .map(|(d, u)| {
                format!(
                    "{{\"domain\":{},\"inbound\":{},\"outbound\":{},\"messages\":{}}}",
                    json_str(d),
                    u.inbound,
                    u.outbound,
                    u.messages
                )
            })
            .collect();
        AdminResponse::ok(format!("{{\"ok\":true,\"usage\":[{}]}}", items.join(",")))
    }
}

/// Whether `rest` (the post-`v1` segments) names a route this API knows, so a wrong-method request to
/// it is a `405` rather than a `404`.
fn is_known_path(rest: &[&str]) -> bool {
    matches!(
        rest,
        ["health"]
            | ["domains"]
            | ["domains", _]
            | ["domains", _, "recipients"]
            | ["domains", _, "aliases", "vanity"]
            | ["domains", _, "aliases", "random"]
            | ["domains", _, "aliases", "random", _]
            | ["domains", _, "blocklist"]
            | ["domains", _, "suspend"]
            | ["domains", _, "quota"]
            | ["usage"]
    )
}

/// Map a [`MultiDomainError`] to an HTTP status + JSON error (fail-closed dispositions).
fn map_md_err(e: MultiDomainError) -> AdminResponse {
    let status = match &e {
        MultiDomainError::InvalidDomain(_) => 400,
        MultiDomainError::DomainExists(_) => 409,
        MultiDomainError::NoSuchDomain(_) => 404,
        MultiDomainError::Alias(_) => 409,
        MultiDomainError::BadKey(_) => 400,
    };
    AdminResponse::err(status, &e.to_string())
}

// ── form / json / value helpers ───────────────────────────────────────────────────────────────

/// A parsed form body: `key → value`, values verbatim (never percent-decoded, so base64 survives).
type Form = HashMap<String, String>;

/// Parse a `key=value` form body. Pairs are separated by `&` or newline; each is split on the **first**
/// `=` (so a base64 value's trailing `=` padding is kept). Whitespace and CR around each side are
/// trimmed. A pair with no `=` is ignored.
fn parse_form(body: &[u8]) -> Form {
    let text = String::from_utf8_lossy(body);
    let mut map = HashMap::new();
    for pair in text.split(['&', '\n']) {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        if let Some((k, v)) = pair.split_once('=') {
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    map
}

/// Extend `HashMap<String,String>` with an ergonomic `&str` getter (named `field` to avoid colliding
/// with the inherent `HashMap::get`, which returns `Option<&String>` and would shadow a trait `get`).
/// Treats an empty value as absent (fail-closed: a blank required field is "missing", not "").
trait FormGet {
    fn field(&self, key: &str) -> Option<&str>;
}
impl FormGet for Form {
    fn field(&self, key: &str) -> Option<&str> {
        HashMap::get(self, key).map(|s| s.as_str()).filter(|s| !s.is_empty())
    }
}

/// Parse the optional `quota_messages` / `quota_bytes` form fields into a [`Quota`] (hard cap == the
/// cap; free allowance mirrors it). `None` if neither is present.
fn parse_quota(form: &Form) -> Result<Option<Quota>, String> {
    let msgs = form.field("quota_messages");
    let bytes = form.field("quota_bytes");
    if msgs.is_none() && bytes.is_none() {
        return Ok(None);
    }
    let m: u64 = match msgs {
        Some(v) => {
            v.parse().map_err(|_| "quota_messages must be a non-negative integer".to_string())?
        }
        None => 0,
    };
    let b: u64 = match bytes {
        Some(v) => {
            v.parse().map_err(|_| "quota_bytes must be a non-negative integer".to_string())?
        }
        None => 0,
    };
    Ok(Some(Quota::new(m, m, b, b)))
}

/// Parse a random-alias `target`: `native:<local>@<domain>` or `identity:<pubkey-b64>`.
fn parse_target(raw: &str) -> Result<AliasTarget, String> {
    if let Some(rest) = raw.strip_prefix("native:") {
        let (local, domain) = rest
            .rsplit_once('@')
            .ok_or_else(|| "native target must be native:<local>@<domain>".to_string())?;
        if local.is_empty() || domain.is_empty() {
            return Err("native target local-part and domain must be non-empty".to_string());
        }
        Ok(AliasTarget::Native { local: local.to_string(), domain: domain.to_string() })
    } else if let Some(b64) = raw.strip_prefix("identity:") {
        let key = crate::b64::decode(b64).map_err(|e| format!("bad identity base64: {e}"))?;
        if key.is_empty() {
            return Err("identity target key is empty".to_string());
        }
        Ok(AliasTarget::Identity(key))
    } else {
        Err("target must be native:<local>@<domain> or identity:<b64>".to_string())
    }
}

/// Decode a base64 DKIM seed and require exactly 32 bytes.
fn decode_seed(b64: &str) -> Result<[u8; 32], String> {
    let bytes = crate::b64::decode(b64).map_err(|e| format!("bad dkim_seed_b64: {e}"))?;
    bytes.try_into().map_err(|_| "dkim_seed_b64 must decode to exactly 32 bytes".to_string())
}

/// Whether a form value is truthy (`true`/`1`/`yes`/`on`, case-insensitive).
fn is_true(v: &str) -> bool {
    matches!(v.trim().to_ascii_lowercase().as_str(), "true" | "1" | "yes" | "on")
}

/// Serialize a string as a JSON string literal (escaping the JSON-mandatory characters).
fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

// ── HTTPS/1.1 transport (AdminServer) ───────────────────────────────────────────────────────────

/// The multi-tenant admin API over TLS. Binds a TCP socket, terminates TLS (implicit — the admin
/// token must never travel in cleartext), reads one HTTP request per connection, dispatches it through
/// [`AdminApi::handle`], and writes the JSON response with `Connection: close`.
pub struct AdminServer {
    listener: TcpListener,
    tls: Arc<ServerConfig>,
    api: AdminApi,
}

impl AdminServer {
    /// Bind the admin server on `addr` with the gateway's TLS config and the built [`AdminApi`].
    pub fn bind(
        addr: impl std::net::ToSocketAddrs,
        tls: Arc<ServerConfig>,
        api: AdminApi,
    ) -> io::Result<Self> {
        Ok(AdminServer { listener: TcpListener::bind(addr)?, tls, api })
    }

    /// The bound address (useful with an ephemeral `:0` port in tests).
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// Accept exactly one connection, serve one request, and return (tests / single-shot use).
    pub fn serve_once(&self) -> io::Result<()> {
        let (stream, _peer) = self.listener.accept()?;
        stream.set_nonblocking(false)?;
        handle_connection(stream, self.tls.clone(), &self.api)
    }

    /// Serve until `shutdown` flips, each connection on its own thread — the daemon loop, mirroring
    /// [`crate::imap_access::ImapAccessServer::serve_until`]. A per-connection error is logged and
    /// never stops the accept loop.
    pub fn serve_until(&self, shutdown: &AtomicBool) -> io::Result<()> {
        self.listener.set_nonblocking(true)?;
        let idle = Duration::from_millis(100);
        loop {
            if shutdown.load(Ordering::SeqCst) {
                return Ok(());
            }
            match self.listener.accept() {
                Ok((stream, peer)) => {
                    if let Err(e) = stream.set_nonblocking(false) {
                        eprintln!("gateway[admin]: {peer}: cannot set blocking: {e}");
                        continue;
                    }
                    let tls = self.tls.clone();
                    let api = self.api.clone();
                    std::thread::spawn(move || {
                        if let Err(e) = handle_connection(stream, tls, &api) {
                            if e.kind() != io::ErrorKind::UnexpectedEof {
                                eprintln!("gateway[admin]: session with {peer} ended: {e}");
                            }
                        }
                    });
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => std::thread::sleep(idle),
                Err(e) => {
                    eprintln!("gateway[admin]: accept error: {e}");
                    std::thread::sleep(idle);
                }
            }
        }
    }
}

/// Current wall-clock time in ms since the epoch (for alias TTL / metering on a live server).
fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Terminate TLS, read one HTTP request, dispatch it, and write the response.
fn handle_connection(stream: TcpStream, tls: Arc<ServerConfig>, api: &AdminApi) -> io::Result<()> {
    let conn = ServerConnection::new(tls).map_err(io::Error::other)?;
    let mut tls_stream = StreamOwned::new(conn, stream);
    tls_stream.conn.complete_io(&mut tls_stream.sock)?;
    let mut reader = BufReader::new(tls_stream);

    let response = match read_request(&mut reader) {
        Ok(Some(req)) => api.handle(&req),
        // A malformed/oversized request line or headers: refuse fail-closed with 400.
        Ok(None) => return Ok(()), // clean EOF, nothing to serve
        Err(ParseError::Io(e)) => return Err(e),
        Err(ParseError::Malformed(msg)) => AdminResponse::err(400, &msg),
    };

    let body = response.body.as_bytes();
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.status,
        response.reason(),
        body.len()
    );
    let stream = reader.get_mut();
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

/// A request-parse failure: either an I/O error or a malformed/oversized request (a `400`).
enum ParseError {
    Io(io::Error),
    Malformed(String),
}
impl From<io::Error> for ParseError {
    fn from(e: io::Error) -> Self {
        ParseError::Io(e)
    }
}

/// Read one HTTP/1.1 request off `reader`: the request line, headers (until a blank line), and a body
/// of exactly `Content-Length` bytes. `Ok(None)` is a clean EOF before any request. Bounded by
/// [`MAX_HEAD_BYTES`] / [`MAX_BODY_BYTES`] (fail-closed against a memory-exhaustion client).
fn read_request<R: BufRead>(reader: &mut R) -> Result<Option<AdminRequest>, ParseError> {
    // Request line.
    let mut line = String::new();
    let n = read_line_capped(reader, &mut line, MAX_HEAD_BYTES)?;
    if n == 0 {
        return Ok(None); // clean EOF
    }
    let mut parts = line.split_whitespace();
    let method = parts.next().ok_or_else(|| ParseError::Malformed("empty request line".into()))?;
    let target =
        parts.next().ok_or_else(|| ParseError::Malformed("missing request target".into()))?;
    // Strip any query string; we route on the path only.
    let path = target.split('?').next().unwrap_or(target).to_string();

    // Headers.
    let mut head_budget = MAX_HEAD_BYTES.saturating_sub(n);
    let mut token: Option<String> = None;
    let mut content_length: usize = 0;
    loop {
        let mut hline = String::new();
        let hn = read_line_capped(reader, &mut hline, head_budget)?;
        if hn == 0 {
            return Err(ParseError::Malformed("headers truncated (no blank line)".into()));
        }
        head_budget = head_budget.saturating_sub(hn);
        let trimmed = hline.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break; // end of headers
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim();
            match name.as_str() {
                "authorization" => {
                    token = value
                        .strip_prefix("Bearer ")
                        .or_else(|| value.strip_prefix("bearer "))
                        .map(|t| t.trim().to_string());
                }
                "content-length" => {
                    content_length = value
                        .parse()
                        .map_err(|_| ParseError::Malformed("bad Content-Length".into()))?;
                    if content_length > MAX_BODY_BYTES {
                        return Err(ParseError::Malformed("request body too large".into()));
                    }
                }
                _ => {}
            }
        }
    }

    // Body.
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body).map_err(ParseError::Io)?;

    Ok(Some(AdminRequest {
        method: method.to_ascii_uppercase(),
        path,
        token,
        body,
        now_ms: now_ms(),
    }))
}

/// Read one `\n`-terminated line into `out` (kept), refusing a line longer than `max` (fail-closed).
/// Returns bytes read (`0` at clean EOF).
fn read_line_capped<R: BufRead>(
    reader: &mut R,
    out: &mut String,
    max: usize,
) -> Result<usize, ParseError> {
    let mut buf = Vec::new();
    loop {
        let available = match reader.fill_buf() {
            Ok(b) => b,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(ParseError::Io(e)),
        };
        if available.is_empty() {
            break; // EOF
        }
        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            buf.extend_from_slice(&available[..=pos]);
            reader.consume(pos + 1);
            break;
        }
        let len = available.len();
        buf.extend_from_slice(available);
        reader.consume(len);
        if buf.len() > max {
            return Err(ParseError::Malformed("request line/header too long".into()));
        }
    }
    out.push_str(&String::from_utf8_lossy(&buf));
    Ok(buf.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dmtap_core::identity::IdentityKey;

    const TOKEN: &str = "s3cret-admin-token";

    fn api() -> (AdminApi, UsageMeter, Arc<Mutex<MultiDomainGateway>>) {
        let gw = Arc::new(Mutex::new(MultiDomainGateway::new()));
        let meter = UsageMeter::new();
        let api = AdminApi::new(gw.clone(), meter.clone(), AdminAuth::with_token(TOKEN));
        (api, meter, gw)
    }

    fn req(method: &str, path: &str, body: &str) -> AdminRequest {
        AdminRequest::new(method, path, Some(TOKEN.to_string()), body.as_bytes().to_vec(), 1_000)
    }

    #[test]
    fn constant_time_auth_is_fail_closed() {
        // No token configured ⇒ every request denied.
        assert!(!AdminAuth::disabled().authorize(Some("anything")));
        // A blank token is treated as disabled.
        assert!(!AdminAuth::with_token("   ").authorize(Some("")));
        let a = AdminAuth::with_token(TOKEN);
        assert!(a.authorize(Some(TOKEN)));
        assert!(!a.authorize(Some("wrong")));
        assert!(!a.authorize(Some("")));
        assert!(!a.authorize(None));
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }

    #[test]
    fn every_endpoint_requires_a_valid_token() {
        let (api, _m, _gw) = api();
        // Missing token → 401.
        let r = api.handle(&AdminRequest::new("GET", "/v1/domains", None, vec![], 0));
        assert_eq!(r.status, 401);
        // Wrong token → 401.
        let r =
            api.handle(&AdminRequest::new("GET", "/v1/domains", Some("nope".into()), vec![], 0));
        assert_eq!(r.status, 401);
        // A gateway with a DISABLED authenticator refuses even a correct-looking request.
        let gw = Arc::new(Mutex::new(MultiDomainGateway::new()));
        let disabled = AdminApi::new(gw, UsageMeter::new(), AdminAuth::disabled());
        let r = disabled.handle(&AdminRequest::new(
            "GET",
            "/v1/domains",
            Some(TOKEN.into()),
            vec![],
            0,
        ));
        assert_eq!(r.status, 401);
    }

    #[test]
    fn add_get_and_remove_a_domain() {
        let (api, _m, _gw) = api();
        // Add.
        let r = api.handle(&req("POST", "/v1/domains", "domain=host.net&selector=sel1"));
        assert_eq!(r.status, 201, "{}", r.body);
        assert!(r.body.contains("\"dkim_public\""));
        assert!(r.body.contains("\"dkim_seed_b64\""));
        // Duplicate → 409.
        let r = api.handle(&req("POST", "/v1/domains", "domain=host.net"));
        assert_eq!(r.status, 409);
        // Invalid domain → 400.
        let r = api.handle(&req("POST", "/v1/domains", "domain=not a domain"));
        assert_eq!(r.status, 400);
        // List includes it.
        let r = api.handle(&req("GET", "/v1/domains", ""));
        assert!(r.body.contains("host.net"));
        // Detail.
        let r = api.handle(&req("GET", "/v1/domains/host.net", ""));
        assert_eq!(r.status, 200);
        assert!(r.body.contains("\"selector\":\"sel1\""));
        // Remove, then detail 404.
        let r = api.handle(&req("DELETE", "/v1/domains/host.net", ""));
        assert_eq!(r.status, 200);
        let r = api.handle(&req("GET", "/v1/domains/host.net", ""));
        assert_eq!(r.status, 404);
    }

    #[test]
    fn recipient_and_vanity_alias_lifecycle() {
        let (api, _m, _gw) = api();
        api.handle(&req("POST", "/v1/domains", "domain=host.net"));
        let ik = IdentityKey::generate().public();
        let ik_b64 = crate::b64::encode(&ik);
        let seal_b64 = crate::b64::encode(&[9u8; 32]);
        // Add a recipient (base64 keys survive the form parse intact).
        let r = api.handle(&req(
            "POST",
            "/v1/domains/host.net/recipients",
            &format!("email=alice@host.net&ik_b64={ik_b64}&seal_b64={seal_b64}"),
        ));
        assert_eq!(r.status, 201, "{}", r.body);
        // Cross-tenant email is refused.
        let r = api.handle(&req(
            "POST",
            "/v1/domains/host.net/recipients",
            &format!("email=bob@other.net&ik_b64={ik_b64}&seal_b64={seal_b64}"),
        ));
        assert_eq!(r.status, 400);
        // Allocate a vanity for a fresh key.
        let vk = crate::b64::encode(&IdentityKey::generate().public());
        let r = api.handle(&req(
            "POST",
            "/v1/domains/host.net/aliases/vanity",
            &format!("key_b64={vk}&local_part=hello"),
        ));
        assert_eq!(r.status, 201, "{}", r.body);
        assert!(r.body.contains("hello@host.net"));
        // A vanity that shadows the directory recipient is refused (409).
        let r = api.handle(&req(
            "POST",
            "/v1/domains/host.net/aliases/vanity",
            &format!("key_b64={vk}&local_part=alice"),
        ));
        assert_eq!(r.status, 409, "{}", r.body);
        // Revoke the vanity.
        let r = api.handle(&req(
            "DELETE",
            "/v1/domains/host.net/aliases/vanity",
            &format!("key_b64={vk}"),
        ));
        assert_eq!(r.status, 200);
    }

    #[test]
    fn random_alias_mint_and_burn() {
        let (api, _m, _gw) = api();
        api.handle(&req("POST", "/v1/domains", "domain=host.net"));
        let r = api.handle(&req(
            "POST",
            "/v1/domains/host.net/aliases/random",
            "target=native:imran@native.com&one_time=true",
        ));
        assert_eq!(r.status, 201, "{}", r.body);
        // Pull the token out of "alias":"<token>@host.net".
        let addr = r.body.split("\"alias\":\"").nth(1).unwrap().split('"').next().unwrap();
        let token = addr.rsplit_once('@').unwrap().0;
        let r =
            api.handle(&req("DELETE", &format!("/v1/domains/host.net/aliases/random/{token}"), ""));
        assert_eq!(r.status, 200, "{}", r.body);
        // Burning a never-minted token → 404 (fail-closed: no such row).
        let r = api.handle(&req(
            "DELETE",
            "/v1/domains/host.net/aliases/random/nevermintedtoken234",
            "",
        ));
        assert_eq!(r.status, 404);
        // A malformed target → 400.
        let r = api.handle(&req("POST", "/v1/domains/host.net/aliases/random", "target=bogus"));
        assert_eq!(r.status, 400);
    }

    #[test]
    fn blocklist_suspend_quota_and_usage() {
        let (api, meter, gw) = api();
        api.handle(&req("POST", "/v1/domains", "domain=host.net"));
        // Block a sender.
        let r = api.handle(&req("POST", "/v1/domains/host.net/blocklist", "sender=spam@evil.net"));
        assert_eq!(r.status, 200);
        // Suspend a user.
        let r = api.handle(&req("POST", "/v1/domains/host.net/suspend", "user=alice"));
        assert_eq!(r.status, 200);
        // Set a quota.
        let r =
            api.handle(&req("PUT", "/v1/domains/host.net/quota", "quota_messages=5&quota_bytes=0"));
        assert_eq!(r.status, 200);
        assert_eq!(gw.lock().unwrap().tenant("host.net").unwrap().quota().hard_cap_messages, 5);

        // Drive a metered relay so usage is non-zero, then read it back over the API.
        gw.lock()
            .unwrap()
            .charge_relay(
                "host.net",
                crate::provenance::BridgeDirection::Inbound,
                b"From: a@b\r\n\r\nx",
                1,
                &meter,
            )
            .unwrap();
        let r = api.handle(&req("GET", "/v1/usage", ""));
        assert_eq!(r.status, 200);
        assert!(r.body.contains("\"domain\":\"host.net\""));
        assert!(r.body.contains("\"inbound\":1"));
    }

    #[test]
    fn unknown_path_404_and_wrong_method_405() {
        let (api, _m, _gw) = api();
        assert_eq!(api.handle(&req("GET", "/v1/nope", "")).status, 404);
        assert_eq!(api.handle(&req("GET", "/v2/domains", "")).status, 404);
        // Known path, wrong method → 405.
        assert_eq!(api.handle(&req("PUT", "/v1/domains", "")).status, 405);
    }

    #[test]
    fn form_parse_keeps_base64_padding_and_special_chars() {
        let form = parse_form(b"ik_b64=AAA+bb/cc==&x=1");
        assert_eq!(form.field("ik_b64"), Some("AAA+bb/cc=="));
        assert_eq!(form.field("x"), Some("1"));
        // Newline-separated form is also accepted.
        let form = parse_form(b"a=1\nb=2\n");
        assert_eq!(form.field("a"), Some("1"));
        assert_eq!(form.field("b"), Some("2"));
    }

    #[test]
    fn parse_target_forms() {
        assert!(matches!(parse_target("native:imran@d.com"), Ok(AliasTarget::Native { .. })));
        assert!(matches!(
            parse_target(&format!("identity:{}", crate::b64::encode(&[1u8; 32]))),
            Ok(AliasTarget::Identity(_))
        ));
        assert!(parse_target("native:@d.com").is_err());
        assert!(parse_target("what").is_err());
    }
}

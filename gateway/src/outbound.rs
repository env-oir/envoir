//! Outbound gateway — spec §7.3 / §19.7.2 (`smtp-outbound`).
//!
//! Translate an outbound `kind=0x00 mail` MOTE (decrypted by the node's own gateway over the
//! authenticated mesh channel) into RFC 5322, **DKIM-sign as the sender's domain via a delegated
//! selector** (never the user's DMTAP key, §7.3), enforce TLS to the destination via an MTA-STS/DANE
//! policy hook, and SMTP it to the destination MX. On failure the gateway reports to the node,
//! which owns the retry queue (§7.4) — the gateway itself holds no long-lived queue.
//!
//! Two refusals are hard (§19.7.2 failure table): the gateway MUST NOT sign for a domain it was not
//! delegated for, and MUST NOT fall back to cleartext when policy requires TLS.

use dmtap_core::mote::Payload;
use dmtap_core::TimestampMs;
use dmtap_mail::mime::format_rfc5322_date;

use crate::b64;
use crate::dkim::{self, DkimKey};
use crate::mta_sts::any_pattern_matches;
use crate::mx::{InMemoryMxResolver, MxHost, MxResolver};
use crate::outbound_guard::{OutboundSenderGuard, SenderVerdict};

/// TLS requirement for a destination, from an MTA-STS/DANE policy lookup (§7.3 step 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsRequirement {
    /// MTA-STS `enforce` / a DANE TLSA record present — TLS is mandatory; cleartext is refused.
    Required,
    /// No enforcing policy discovered — opportunistic TLS is used if offered, but not mandated.
    Opportunistic,
}

/// The MTA-STS/DANE policy hook (§7.3 step 4). Abstract so it is testable in-process; the real impl
/// ([`crate::mta_sts::MtaStsTlsPolicy`]) fetches the destination's MTA-STS policy (RFC 8461). DANE
/// (TLSA records) is a documented, unimplemented seam: a `TlsPolicy` impl wanting DANE would consult
/// TLSA lookups here too and fold them into the same `Required`/pattern decision — this crate does
/// not do that lookup itself.
pub trait TlsPolicy {
    fn requirement_for(&self, dest_domain: &str) -> TlsRequirement;

    /// MX hostname patterns (MTA-STS `mx:` lines, RFC 8461 §4.1 syntax) delivery is constrained to
    /// when [`Self::requirement_for`] returns [`TlsRequirement::Required`]. Empty (the default) means
    /// "no hostname constraint" — any resolved MX candidate is acceptable, which is the right
    /// behavior for a policy that mandates TLS but has no MTA-STS-style host allowlist (e.g.
    /// [`AlwaysRequireTls`], or DANE-only enforcement). A real MTA-STS policy in `enforce` mode
    /// returns its `mx:` patterns here, and the outbound gateway refuses to dial (or falls back to)
    /// any resolved MX host that matches none of them (§7.3: never silently relax the policy).
    fn allowed_mx_patterns(&self, _dest_domain: &str) -> Vec<String> {
        Vec::new()
    }
}

/// A policy that treats every destination as TLS-`Required` — a safe, strict default for a gateway
/// that refuses to emit cleartext mail.
#[derive(Debug, Default, Clone, Copy)]
pub struct AlwaysRequireTls;

impl TlsPolicy for AlwaysRequireTls {
    fn requirement_for(&self, _dest_domain: &str) -> TlsRequirement {
        TlsRequirement::Required
    }
}

/// The actual SMTP send to the destination MX (§7.3 step 4). Abstract so the socket + TLS handshake
/// is a thin real impl and the whole outbound flow is driven in tests. The transport is told whether
/// TLS is mandatory and MUST refuse (return [`TransportResult::TlsUnavailable`]) rather than send in
/// cleartext when it is — TLS enforcement genuinely lives at the transport, not just as advice.
pub trait OutboundTransport {
    fn deliver(&self, dest_domain: &str, message: &[u8], require_tls: bool) -> TransportResult;
}

/// The result of an outbound SMTP attempt to the destination MX.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportResult {
    /// 2xx — accepted by the destination.
    Delivered { code: u16 },
    /// 4xx — transient; the node should retry (§19.3.3).
    Transient { code: u16, text: String },
    /// 5xx — permanent reject; surfaced to the user as failed.
    Permanent { code: u16, text: String },
    /// TLS was required by policy but the destination offered none — send aborted, never cleartext.
    TlsUnavailable,
}

/// The outbound gateway: delegated-DKIM signer + TLS-enforcing SMTP relay. Stateless (§7.4).
pub struct OutboundGateway {
    /// Delegated DKIM keys, one per domain the gateway is authorized to sign for.
    dkim_keys: Vec<DkimKey>,
    tls_policy: Box<dyn TlsPolicy>,
    transport: Box<dyn OutboundTransport>,
    mx_resolver: Box<dyn MxResolver>,
    /// Optional outbound anti-spam governor (§7.3, §9): authenticated-senders-only + per-sender
    /// rate-limit / volume cap / reputation backoff. When `None`, the governed egress entry point
    /// [`Self::send_authenticated`] **fails closed** (refuses) rather than relaying ungoverned — so
    /// the gateway can never become an open outbound relay by forgetting to attach a guard.
    sender_guard: Option<OutboundSenderGuard>,
}

/// The result of a governed outbound send ([`OutboundGateway::send_authenticated`]): either the send
/// ran and produced an [`OutboundReport`], or the outbound anti-spam guard refused/deferred it before
/// any SMTP was attempted. Kept distinct from [`OutboundReport`] so the guard's rate/volume/reputation
/// decisions never masquerade as a destination-MX result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernedSend {
    /// The guard allowed the send; this is the destination-MX outcome.
    Sent(OutboundReport),
    /// The guard blocked the send (unauthenticated sender, rate/volume cap, or reputation backoff).
    Blocked(SenderVerdict),
}

/// The report handed back to the node after an outbound attempt (§19.7.2 step 5). The node's
/// sender-retry state machine (§19.3.3) consumes it; the gateway keeps nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundReport {
    /// Delivered to the destination MX with a passing DKIM signature.
    Delivered,
    /// Transient failure — the node should retry (§19.3.3 backoff).
    Deferred { code: u16, text: String },
    /// Permanent failure — surfaced to the user as failed, not retried blindly.
    Failed(OutboundError),
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum OutboundError {
    #[error("no delegated DKIM selector published for the From: domain {0}")]
    NotDelegated(String),
    #[error("malformed From: address {0}")]
    BadFromAddress(String),
    #[error("malformed destination address {0}")]
    BadDestAddress(String),
    #[error("TLS required by policy for {0} but the destination offered none; send aborted")]
    TlsEnforcementFailed(String),
    #[error(
        "MTA-STS enforce policy for {0} lists mx patterns {1:?} but none of the resolved MX hosts \
         {2:?} match; send aborted rather than relaxed to an unconstrained host"
    )]
    NoMxMatchesPolicy(String, Vec<String>, Vec<String>),
    #[error("destination MX permanently rejected the message: {code} {text}")]
    DestinationRejected { code: u16, text: String },
    #[error("no MX candidate host resolved for {0}; send aborted")]
    NoMxHost(String),
    #[error("header field {0} contains a CR, LF, or NUL — refused to avoid header injection")]
    HeaderInjection(&'static str),
}

impl OutboundGateway {
    /// `mx_resolver` defaults to a resolver with no published records for anything, which — per
    /// [`crate::mx::InMemoryMxResolver`]'s RFC 5321 §5.1 A/AAAA-fallback contract — means every
    /// domain resolves to itself as its own single implicit MX. That reproduces the gateway's
    /// pre-MX-resolution behavior (dial `dest_domain` directly) for callers that do not need real MX
    /// preference ordering; use [`Self::with_mx_resolver`] to plug in [`crate::mx::DnsMxResolver`] or
    /// a test double with real MX records.
    pub fn new(
        dkim_keys: Vec<DkimKey>,
        tls_policy: Box<dyn TlsPolicy>,
        transport: Box<dyn OutboundTransport>,
    ) -> Self {
        OutboundGateway {
            dkim_keys,
            tls_policy,
            transport,
            mx_resolver: Box::new(InMemoryMxResolver::new()),
            sender_guard: None,
        }
    }

    /// Attach the outbound anti-spam governor (§7.3, §9). With it set, [`Self::send_authenticated`]
    /// enforces authenticated-senders-only + per-sender rate-limit / volume cap / reputation backoff
    /// so the gateway cannot be turned into a spam relay. See [`OutboundSenderGuard`].
    pub fn with_sender_guard(mut self, guard: OutboundSenderGuard) -> Self {
        self.sender_guard = Some(guard);
        self
    }

    /// Swap in a different MX resolver (spec §7.3 step 4 / RFC 5321 §5.1) — e.g.
    /// [`crate::mx::DnsMxResolver`] for a real deployment, or an [`crate::mx::InMemoryMxResolver`]
    /// pre-loaded with MX records for a test that exercises multi-MX preference ordering.
    pub fn with_mx_resolver(mut self, mx_resolver: Box<dyn MxResolver>) -> Self {
        self.mx_resolver = mx_resolver;
        self
    }

    fn dkim_key_for(&self, domain: &str) -> Option<&DkimKey> {
        self.dkim_keys.iter().find(|k| k.domain().eq_ignore_ascii_case(domain))
    }

    /// Translate a `mail` MOTE payload into RFC 5322 **and** DKIM-sign it as `from_addr`'s domain
    /// using the delegated selector (§19.7.2 steps 2–3). Fails closed if the gateway holds no
    /// delegation for that domain (§7.3: never sign for a domain you aren't delegated for).
    pub fn translate_and_sign(
        &self,
        payload: &Payload,
        from_addr: &str,
        to_addr: &str,
        now: TimestampMs,
    ) -> Result<Vec<u8>, OutboundError> {
        let from_domain =
            domain_of(from_addr).ok_or_else(|| OutboundError::BadFromAddress(from_addr.into()))?;
        let key = self
            .dkim_key_for(from_domain)
            .ok_or_else(|| OutboundError::NotDelegated(from_domain.into()))?;

        let message = render_rfc5322(payload, from_addr, to_addr, now)?;
        let dkim_header = dkim::sign(key, &message, now / 1000);

        // Prepend the DKIM-Signature header (RFC 6376: it precedes the signed headers).
        let mut signed = dkim_header.into_bytes();
        signed.extend_from_slice(&message);
        Ok(signed)
    }

    /// The full `smtp-outbound` operation (§19.7.2): translate + DKIM-sign, enforce TLS policy, send
    /// to the destination MX, and report to the node. The gateway stores nothing (§7.4).
    pub fn send(
        &self,
        payload: &Payload,
        from_addr: &str,
        to_addr: &str,
        now: TimestampMs,
    ) -> OutboundReport {
        let signed = match self.translate_and_sign(payload, from_addr, to_addr, now) {
            Ok(bytes) => bytes,
            Err(e) => return OutboundReport::Failed(e),
        };
        let dest_domain = match domain_of(to_addr) {
            Some(d) => d.to_string(),
            None => return OutboundReport::Failed(OutboundError::BadDestAddress(to_addr.into())),
        };

        // Enforce TLS via the MTA-STS/DANE policy hook (§7.3 step 4).
        let require_tls = matches!(
            self.tls_policy.requirement_for(&dest_domain),
            TlsRequirement::Required
        );
        let allowed_patterns = self.tls_policy.allowed_mx_patterns(&dest_domain);

        // Resolve the destination's MX candidates (RFC 5321 §5.1: sorted by preference, falling
        // back to the domain's own A/AAAA if it has no MX). When the policy constrains delivery to
        // specific MX hostnames (MTA-STS `enforce` `mx:` patterns), only a resolved candidate that
        // matches one of them is eligible — never dial (or accept a cert from) a host the policy did
        // not authorize, and if none match, abort rather than silently falling back to an
        // unconstrained host (§7.3's no-downgrade stance).
        let candidates = self.mx_resolver.resolve_mx(&dest_domain);
        let eligible: Vec<&MxHost> = if allowed_patterns.is_empty() {
            candidates.iter().collect()
        } else {
            candidates.iter().filter(|h| any_pattern_matches(&allowed_patterns, &h.host)).collect()
        };

        let dial_host = match eligible.first() {
            Some(h) => h.host.clone(),
            None if !allowed_patterns.is_empty() => {
                let candidate_hosts: Vec<String> = candidates.iter().map(|h| h.host.clone()).collect();
                return OutboundReport::Failed(OutboundError::NoMxMatchesPolicy(
                    dest_domain,
                    allowed_patterns,
                    candidate_hosts,
                ));
            }
            None => {
                // MxResolver's contract is to always return at least the domain-fallback entry;
                // this is a defensive guard against a resolver implementation that breaks it, not a
                // path the shipped resolvers ever take.
                return OutboundReport::Failed(OutboundError::NoMxHost(dest_domain));
            }
        };

        match self.transport.deliver(&dial_host, &signed, require_tls) {
            TransportResult::Delivered { .. } => OutboundReport::Delivered,
            TransportResult::Transient { code, text } => OutboundReport::Deferred { code, text },
            TransportResult::Permanent { code, text } => {
                OutboundReport::Failed(OutboundError::DestinationRejected { code, text })
            }
            TransportResult::TlsUnavailable => {
                OutboundReport::Failed(OutboundError::TlsEnforcementFailed(dest_domain))
            }
        }
    }

    /// Outbound send **governed by the anti-spam guard** for an authenticated sender `account`
    /// (§7.3, §9). This is the entry point the mesh-ingest path uses once it has admitted the sender
    /// (see [`crate::authz::IdentityRegistry::admit`]): the guard is consulted **before** any SMTP is
    /// attempted, so an unauthenticated sender, a sender over its rate/volume cap, or one in
    /// reputation backoff is blocked without ever touching the destination MX. On an allowed send the
    /// destination outcome is fed back into the sender's reputation (a permanent reject / TLS abort is
    /// a bad signal that arms backoff; a delivery decays it), so a sender that keeps producing
    /// blacklisting outcomes is progressively throttled. With **no** guard configured this path
    /// **fails closed** — it refuses rather than relaying ungoverned — so an operator who forgets to
    /// attach a guard does not silently run an open outbound relay. (The raw, ungoverned
    /// [`Self::send`] remains available for callers that governed the sender upstream and opt in
    /// explicitly.)
    pub fn send_authenticated(
        &self,
        payload: &Payload,
        from_addr: &str,
        to_addr: &str,
        account: &str,
        now: TimestampMs,
    ) -> GovernedSend {
        let Some(guard) = &self.sender_guard else {
            return GovernedSend::Blocked(SenderVerdict::Refuse {
                reason: "5.7.1 outbound relay denied: no sender guard configured (fail-closed)".into(),
            });
        };
        match guard.authorize_send(account) {
            SenderVerdict::Allow => {}
            blocked => return GovernedSend::Blocked(blocked),
        }
        let report = self.send(payload, from_addr, to_addr, now);
        {
            // A permanent destination reject or a TLS-enforcement abort is the kind of outcome that
            // gets a relay blacklisted; feed it into reputation. Transient defers are not penalized.
            let bad = matches!(report, OutboundReport::Failed(_));
            let delivered = matches!(report, OutboundReport::Delivered);
            if bad || delivered {
                guard.report_outcome(account, delivered);
            }
        }
        GovernedSend::Sent(report)
    }
}

/// Render an outbound `mail` MOTE payload to RFC 5322 with the sender's real domain address in
/// `From:` (the delegated-DKIM domain), CRLF line endings. A deterministic `Message-ID` from the
/// body keeps re-renders stable.
pub fn render_rfc5322(
    payload: &Payload,
    from_addr: &str,
    to_addr: &str,
    ts: TimestampMs,
) -> Result<Vec<u8>, OutboundError> {
    // A CR/LF/NUL in any interpolated header field would inject extra headers or a premature body
    // separator into the message the gateway then DKIM-signs. Refuse fail-closed before rendering.
    let no_inject = |field: &str, name: &'static str| -> Result<(), OutboundError> {
        if field.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
            return Err(OutboundError::HeaderInjection(name));
        }
        Ok(())
    };
    no_inject(from_addr, "From")?;
    no_inject(to_addr, "To")?;
    let subject = payload.headers.subject.clone().unwrap_or_default();
    no_inject(&subject, "Subject")?;
    let mime = payload
        .headers
        .mime
        .clone()
        .unwrap_or_else(|| "text/plain; charset=utf-8".into());
    no_inject(&mime, "Content-Type")?;
    let date = format_rfc5322_date(ts);
    let mid = format!("<{}@{}>", b64_id(&payload.body), domain_of(from_addr).unwrap_or("dmtap.local"));

    let mut msg = String::new();
    msg.push_str(&format!("From: {from_addr}\r\n"));
    msg.push_str(&format!("To: {to_addr}\r\n"));
    msg.push_str(&format!("Date: {date}\r\n"));
    msg.push_str(&format!("Subject: {subject}\r\n"));
    msg.push_str(&format!("Message-ID: {mid}\r\n"));
    msg.push_str("MIME-Version: 1.0\r\n");
    msg.push_str(&format!("Content-Type: {mime}\r\n"));
    msg.push_str("Content-Transfer-Encoding: 8bit\r\n");
    msg.push_str("\r\n");
    let mut bytes = msg.into_bytes();
    bytes.extend_from_slice(&payload.body);
    if !payload.body.ends_with(b"\n") {
        bytes.extend_from_slice(b"\r\n");
    }
    Ok(bytes)
}

/// A short, URL-safe-ish stable token from the body's content address, for Message-ID.
fn b64_id(body: &[u8]) -> String {
    let cid = dmtap_core::ContentId::of(body);
    b64::encode(&cid.digest()[..12]).replace(['+', '/', '='], "0")
}

/// Extract the domain part of an address like `<a@b.com>` / `a@b.com`.
fn domain_of(addr: &str) -> Option<&str> {
    let a = addr.trim().trim_start_matches('<').trim_end_matches('>');
    a.rsplit_once('@').map(|(_, d)| d).filter(|d| !d.is_empty())
}

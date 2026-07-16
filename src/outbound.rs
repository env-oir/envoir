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

/// TLS requirement for a destination, from an MTA-STS/DANE policy lookup (§7.3 step 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsRequirement {
    /// MTA-STS `enforce` / a DANE TLSA record present — TLS is mandatory; cleartext is refused.
    Required,
    /// No enforcing policy discovered — opportunistic TLS is used if offered, but not mandated.
    Opportunistic,
}

/// The MTA-STS/DANE policy hook (§7.3 step 4). Abstract so it is testable in-process; a real impl
/// fetches the destination's MTA-STS policy and/or DANE TLSA records.
pub trait TlsPolicy {
    fn requirement_for(&self, dest_domain: &str) -> TlsRequirement;
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
    #[error("destination MX permanently rejected the message: {code} {text}")]
    DestinationRejected { code: u16, text: String },
}

impl OutboundGateway {
    pub fn new(
        dkim_keys: Vec<DkimKey>,
        tls_policy: Box<dyn TlsPolicy>,
        transport: Box<dyn OutboundTransport>,
    ) -> Self {
        OutboundGateway { dkim_keys, tls_policy, transport }
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

        let message = render_rfc5322(payload, from_addr, to_addr, now);
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
        match self.transport.deliver(&dest_domain, &signed, require_tls) {
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
}

/// Render an outbound `mail` MOTE payload to RFC 5322 with the sender's real domain address in
/// `From:` (the delegated-DKIM domain), CRLF line endings. A deterministic `Message-ID` from the
/// body keeps re-renders stable.
pub fn render_rfc5322(payload: &Payload, from_addr: &str, to_addr: &str, ts: TimestampMs) -> Vec<u8> {
    let subject = payload.headers.subject.clone().unwrap_or_default();
    let mime = payload
        .headers
        .mime
        .clone()
        .unwrap_or_else(|| "text/plain; charset=utf-8".into());
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
    bytes
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

//! Inbound gateway — spec §7.2 / §19.7.1 (`smtp-inbound`).
//!
//! Accept a legacy SMTP transaction acting as MX for a domain, reject spam **before DATA**, resolve
//! the recipient's DMTAP key, wrap the RFC 5322 message into an encrypted `kind=0x00 mail` MOTE,
//! **attest** it under the domain-anchored attestation key (§7.2a), deliver into the mesh, and —
//! critically — return SMTP **`250` only after a durable `ack`**, else **`451`** (the §19.7.1
//! silent-loss-avoidance rule: never `250` on mere hand-off). The gateway stores nothing (§7.4):
//! durability lives in the legacy sender's own SMTP retry queue.
//!
//! All network effects are behind traits ([`KeyDirectory`], [`MeshDelivery`], [`AntiAbuse`]) so the
//! whole transaction is driven in-process by tests; a real deployment supplies socket-backed impls.

use dmtap_core::mote::{build_mote, Envelope, Hpke};
use dmtap_core::identity::IdentityKey;
use dmtap_core::TimestampMs;
use dmtap_mail::smtp::build_mote_draft;

use crate::attestation::{Attestation, AttestationKey};

/// A recipient's DMTAP key material, resolved from `RCPT TO` (§3 `resolve`, run by the gateway on
/// the recipient's behalf, §19.7.1 step 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientKey {
    /// The recipient's Ed25519 identity key (the delivery target `K`).
    pub ik: Vec<u8>,
    /// The recipient's X25519 sealing (KEM) public key the MOTE payload is encrypted to.
    pub seal_pub: Vec<u8>,
}

/// Resolves a legacy `RCPT TO` address to a DMTAP recipient key (§3.2/§19.1.1). Abstract so it is
/// testable in-process; a real impl performs the DNS/directory lookup + KT verification.
pub trait KeyDirectory {
    /// Return the recipient key for `rcpt`, or `None` if no DMTAP recipient resolves (→ SMTP 550).
    fn resolve(&self, rcpt: &str) -> Option<RecipientKey>;
}

/// Outcome of handing a MOTE into the mesh (§4 / §19.2.3 reachability ladder + §19.3.1 `deliver`).
/// The gateway maps this straight onto its SMTP reply per the silent-loss-avoidance rule (§19.7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryOutcome {
    /// The recipient node (or a relay-mailbox that itself acked durable custody, §14.5) has
    /// **durably** acked the MOTE. Only this permits a `250`.
    Acked,
    /// The recipient could not be reached, or was reached but did not durably ack within the
    /// transaction window (all ladder rungs + buffering exhausted, or only a best-effort buffer
    /// accepted the packet). → SMTP `451`; the legacy sender's queue retries.
    NoAck,
}

/// Delivers an attested MOTE into the mesh and reports whether a **durable** ack came back inside
/// the inbound SMTP transaction window (§19.7.1 step 6). The gateway does NOT queue: a `NoAck` here
/// becomes a `451` so durability stays with the legacy sender. Abstract for in-process testing.
pub trait MeshDelivery {
    fn deliver(&self, env: &Envelope, attestation: &Attestation) -> DeliveryOutcome;
}

/// Pre-`DATA` anti-abuse gate (§9 / §19.7.1 step 1): RBL/DNSBL, SPF/DMARC, greylisting, per-IP rate
/// limits — evaluated on connection/envelope metadata so the bulk of spam is refused before the
/// message body is ever accepted onto the wire.
pub trait AntiAbuse {
    /// Decide from the connecting peer IP and `MAIL FROM` whether to proceed. Runs at `MAIL FROM`,
    /// strictly before `DATA`.
    fn check(&self, peer_ip: &str, mail_from: &str) -> AbuseDecision;
}

/// The anti-abuse verdict (§9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbuseDecision {
    Accept,
    /// Refuse before DATA. `code` is the SMTP status (a 5xx hard-reject or 4xx greylist defer) and
    /// `reason` the enhanced text.
    Reject { code: u16, reason: String },
}

/// A permissive anti-abuse policy that accepts everything — the self-host default (you are the only
/// one sending through your own gateway). Production operators plug in RBL/SPF/rate-limit checks.
#[derive(Debug, Default, Clone, Copy)]
pub struct AllowAllAbuse;

impl AntiAbuse for AllowAllAbuse {
    fn check(&self, _peer_ip: &str, _mail_from: &str) -> AbuseDecision {
        AbuseDecision::Accept
    }
}

/// The inbound gateway: MX for one or more domains, stateless (§7.4).
pub struct InboundGateway {
    /// The gateway's own identity key. An inbound legacy MOTE is *from* the gateway (legacy-origin);
    /// `Payload.from` is this key and the attestation vouches for the legacy SMTP envelope.
    ik: IdentityKey,
    /// Domain-anchored attestation keys (§7.2a), one per domain this gateway is MX for.
    attest_keys: Vec<AttestationKey>,
    directory: Box<dyn KeyDirectory>,
    delivery: Box<dyn MeshDelivery>,
    abuse: Box<dyn AntiAbuse>,
}

/// Why an inbound message could not be wrapped/delivered — mapped to an SMTP reply by the session.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum InboundError {
    #[error("no DMTAP recipient resolves for {0}")]
    NoRecipient(String),
    #[error("no attestation key configured for domain {0}")]
    NoAttestationKey(String),
    #[error("malformed recipient address {0}")]
    BadAddress(String),
    #[error("failed to seal MOTE to recipient key")]
    SealFailed,
}

impl InboundGateway {
    pub fn new(
        ik: IdentityKey,
        attest_keys: Vec<AttestationKey>,
        directory: Box<dyn KeyDirectory>,
        delivery: Box<dyn MeshDelivery>,
        abuse: Box<dyn AntiAbuse>,
    ) -> Self {
        InboundGateway { ik, attest_keys, directory, delivery, abuse }
    }

    fn attest_key_for(&self, domain: &str) -> Option<&AttestationKey> {
        self.attest_keys.iter().find(|k| k.domain().eq_ignore_ascii_case(domain))
    }

    /// Wrap + attest a single legacy message for one resolved recipient (§19.7.1 steps 3–4),
    /// producing the encrypted MOTE and its attestation. Does **not** deliver — that is the
    /// caller's step so the ack-before-250 decision stays explicit.
    pub fn wrap_and_attest(
        &self,
        mail_from: &str,
        rcpt_to: &str,
        data: &[u8],
        now: TimestampMs,
    ) -> Result<(Envelope, Attestation), InboundError> {
        let domain = domain_of(rcpt_to).ok_or_else(|| InboundError::BadAddress(rcpt_to.into()))?;
        let recip = self
            .directory
            .resolve(rcpt_to)
            .ok_or_else(|| InboundError::NoRecipient(rcpt_to.into()))?;
        let att_key = self
            .attest_key_for(domain)
            .ok_or_else(|| InboundError::NoAttestationKey(domain.into()))?;

        // 3. Wrap the RFC 5322 message into a kind=mail MOTE, encrypted to the recipient's key.
        //    Payload.from is the gateway (legacy-origin); a fresh ephemeral key signs the envelope.
        let draft = build_mote_draft(data, now);
        let ephemeral = IdentityKey::generate();
        let env = build_mote(&Hpke, &self.ik, &ephemeral, &recip.ik, &recip.seal_pub, draft)
            .map_err(|_| InboundError::SealFailed)?;

        // 4. Attest under the domain-anchored key, bound to this MOTE's content address (§7.2a).
        let attestation = att_key.attest(&env.id, mail_from, rcpt_to, now);
        Ok((env, attestation))
    }

    /// The full `smtp-inbound` decision for one recipient (§19.7.1 steps 3–6): wrap, attest,
    /// deliver, and return the SMTP reply — `250` only on a durable ack, else `451`.
    pub fn accept_message(
        &self,
        mail_from: &str,
        rcpt_to: &str,
        data: &[u8],
        now: TimestampMs,
    ) -> SmtpReply {
        let (env, attestation) = match self.wrap_and_attest(mail_from, rcpt_to, data, now) {
            Ok(pair) => pair,
            Err(InboundError::NoRecipient(_)) | Err(InboundError::BadAddress(_)) => {
                return SmtpReply::new(550, "5.1.1 no such user here");
            }
            Err(InboundError::NoAttestationKey(_)) => {
                // Operator misconfiguration (§19.7.1 failure table): the gateway MUST NOT deliver an
                // unattestable MOTE as if attested. Defer with 451 so the sender's queue holds it.
                return SmtpReply::new(451, "4.3.5 gateway not configured for this domain");
            }
            Err(InboundError::SealFailed) => {
                return SmtpReply::new(451, "4.3.0 temporary failure wrapping message");
            }
        };

        // 6. Deliver, then reply strictly on the durable-ack outcome (silent-loss avoidance).
        match self.delivery.deliver(&env, &attestation) {
            DeliveryOutcome::Acked => SmtpReply::new(250, "2.6.0 message durably accepted"),
            DeliveryOutcome::NoAck => {
                SmtpReply::new(451, "4.4.1 recipient has not durably accepted yet, try again later")
            }
        }
    }

    /// Run the pre-`DATA` anti-abuse gate for `MAIL FROM` (§19.7.1 step 1).
    fn abuse_check(&self, peer_ip: &str, mail_from: &str) -> AbuseDecision {
        self.abuse.check(peer_ip, mail_from)
    }

    /// Whether a `RCPT TO` resolves to a known DMTAP recipient AND the gateway can attest for its
    /// domain — evaluated at `RCPT TO`, before `DATA` (so a bad recipient is refused early).
    fn rcpt_acceptable(&self, rcpt: &str) -> Result<(), SmtpReply> {
        let domain = domain_of(rcpt).ok_or_else(|| SmtpReply::new(501, "5.1.3 bad recipient address"))?;
        if self.directory.resolve(rcpt).is_none() {
            return Err(SmtpReply::new(550, "5.1.1 no such user here"));
        }
        if self.attest_key_for(domain).is_none() {
            return Err(SmtpReply::new(451, "4.3.5 gateway not configured for this domain"));
        }
        Ok(())
    }
}

/// An SMTP reply: a status code plus enhanced text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtpReply {
    pub code: u16,
    pub text: String,
}

impl SmtpReply {
    pub fn new(code: u16, text: impl Into<String>) -> Self {
        SmtpReply { code, text: text.into() }
    }
    /// True for a 2xx success reply.
    pub fn is_ok(&self) -> bool {
        (200..300).contains(&self.code)
    }
    /// The wire form, e.g. `250 2.6.0 message durably accepted`.
    pub fn wire(&self) -> String {
        format!("{} {}\r\n", self.code, self.text)
    }
}

/// Extract the domain part of an SMTP address like `<alice@example.org>` or `alice@example.org`.
fn domain_of(addr: &str) -> Option<&str> {
    let a = addr.trim().trim_start_matches('<').trim_end_matches('>');
    a.rsplit_once('@').map(|(_, d)| d).filter(|d| !d.is_empty())
}

// --- A minimal MX SMTP transaction driver (line-fed, in-process) ---------------------------

/// The transaction phase of the inbound MX session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Command,
    Data,
}

/// A line-fed inbound MX SMTP session (RFC 5321 server side): unauthenticated inbound from external
/// MTAs, with the anti-abuse gate at `MAIL FROM` and recipient resolution at `RCPT TO` — both
/// **before `DATA`** — and the wrap/attest/deliver/ack decision on the terminating `.`.
///
/// This is deliberately synchronous and std-only; the caller pumps lines from a real socket. It
/// holds no durable state (§7.4) — each transaction is independent and nothing survives the reply.
pub struct MxSession<'g> {
    gw: &'g InboundGateway,
    peer_ip: String,
    now: TimestampMs,
    phase: Phase,
    mail_from: Option<String>,
    rcpt_to: Option<String>,
    data: Vec<u8>,
}

impl<'g> MxSession<'g> {
    pub fn new(gw: &'g InboundGateway, peer_ip: impl Into<String>, now: TimestampMs) -> Self {
        MxSession {
            gw,
            peer_ip: peer_ip.into(),
            now,
            phase: Phase::Command,
            mail_from: None,
            rcpt_to: None,
            data: Vec::new(),
        }
    }

    /// The 220 service banner.
    pub fn greeting(&self) -> SmtpReply {
        SmtpReply::new(220, "envoir-gateway DMTAP MX ready")
    }

    fn reset_transaction(&mut self) {
        self.mail_from = None;
        self.rcpt_to = None;
        self.data.clear();
    }

    /// Feed one command line (no CRLF), or — during `DATA` — one data line. A lone `.` ends DATA.
    pub fn feed_line(&mut self, line: &str) -> SmtpReply {
        if self.phase == Phase::Data {
            return self.feed_data(line);
        }
        let (verb, rest) = match line.split_once(' ') {
            Some((v, r)) => (v.to_ascii_uppercase(), r.trim()),
            None => (line.trim().to_ascii_uppercase(), ""),
        };
        match verb.as_str() {
            "HELO" | "EHLO" => SmtpReply::new(250, "envoir-gateway at your service"),
            "MAIL" => self.cmd_mail(rest),
            "RCPT" => self.cmd_rcpt(rest),
            "DATA" => self.cmd_data(),
            "RSET" => {
                self.reset_transaction();
                SmtpReply::new(250, "2.0.0 flushed")
            }
            "NOOP" => SmtpReply::new(250, "2.0.0 ok"),
            "QUIT" => SmtpReply::new(221, "2.0.0 bye"),
            _ => SmtpReply::new(502, "5.5.1 command not implemented"),
        }
    }

    fn cmd_mail(&mut self, rest: &str) -> SmtpReply {
        // `FROM:<addr>` — run the pre-DATA anti-abuse gate on (peer_ip, mail_from).
        let addr = match rest.strip_prefix("FROM:").or_else(|| rest.strip_prefix("from:")) {
            Some(a) => a.trim().to_string(),
            None => return SmtpReply::new(501, "5.5.4 syntax: MAIL FROM:<address>"),
        };
        match self.gw.abuse_check(&self.peer_ip, &addr) {
            AbuseDecision::Accept => {
                self.mail_from = Some(addr);
                SmtpReply::new(250, "2.1.0 sender ok")
            }
            AbuseDecision::Reject { code, reason } => SmtpReply::new(code, reason),
        }
    }

    fn cmd_rcpt(&mut self, rest: &str) -> SmtpReply {
        if self.mail_from.is_none() {
            return SmtpReply::new(503, "5.5.1 need MAIL before RCPT");
        }
        let addr = match rest.strip_prefix("TO:").or_else(|| rest.strip_prefix("to:")) {
            Some(a) => a.trim().trim_start_matches('<').trim_end_matches('>').to_string(),
            None => return SmtpReply::new(501, "5.5.4 syntax: RCPT TO:<address>"),
        };
        // Resolve recipient + attestation availability BEFORE DATA (§19.7.1 step 1 ordering).
        if let Err(reply) = self.gw.rcpt_acceptable(&addr) {
            return reply;
        }
        self.rcpt_to = Some(addr);
        SmtpReply::new(250, "2.1.5 recipient ok")
    }

    fn cmd_data(&mut self) -> SmtpReply {
        if self.mail_from.is_none() || self.rcpt_to.is_none() {
            return SmtpReply::new(503, "5.5.1 need MAIL and RCPT before DATA");
        }
        self.phase = Phase::Data;
        SmtpReply::new(354, "start mail input; end with <CRLF>.<CRLF>")
    }

    fn feed_data(&mut self, line: &str) -> SmtpReply {
        if line == "." {
            self.phase = Phase::Command;
            let mail_from = self.mail_from.clone().unwrap_or_default();
            let rcpt_to = self.rcpt_to.clone().unwrap_or_default();
            let data = std::mem::take(&mut self.data);
            self.reset_transaction();
            // The whole silent-loss-avoidance decision happens here: 250 only on a durable ack.
            return self.gw.accept_message(&mail_from, &rcpt_to, &data, self.now);
        }
        // Undo SMTP dot-stuffing (RFC 5321 §4.5.2), then append the line with CRLF.
        let unstuffed = line.strip_prefix('.').unwrap_or(line);
        self.data.extend_from_slice(unstuffed.as_bytes());
        self.data.extend_from_slice(b"\r\n");
        // No reply mid-DATA.
        SmtpReply::new(0, "")
    }
}

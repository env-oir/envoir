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
use crate::dkim::{verify_with_resolver, DkimKeyResolver, DkimVerdict};
use crate::dmarc::{self, DmarcDisposition, DmarcTxtResolver, DmarcVerdict};
use crate::provenance::{GatewayAttestation, Profile, ProvenanceRecord, Tier};
use crate::spf::{self, SpfOutcome, SpfResolver, SpfResult};

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

/// A monotonic-ish wall-clock source, abstracted so the greylist/rate windows in [`ColdSenderGate`]
/// are testable without sleeping. The real impl reads the system clock.
pub trait Clock: Send + Sync {
    /// Milliseconds since the Unix epoch.
    fn now_ms(&self) -> u64;
}

/// The production clock: `SystemTime::now()`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
    }
}

use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Default)]
struct GateState {
    /// (peer_ip, mail_from) → first-seen ms, for greylisting cold triples.
    greylist: HashMap<(String, String), u64>,
    /// peer_ip → timestamps (ms) of recently *accepted* messages, for the per-IP rate window.
    accepts: HashMap<String, Vec<u64>>,
}

/// A real **cold-sender anti-abuse gate** for the inbound legacy MX (spec §9, §7.2 step 2).
///
/// Legacy senders cannot present a DMTAP anonymous-token / PoW / postage proof (§9.3–§9.5) — those
/// live inside the sealed mesh envelope, which a legacy MTA never produces. So the gateway applies
/// §9's **"cost for cold contact"** principle in the terms the SMTP world *does* support, evaluated
/// entirely on connection/envelope metadata **before `DATA`** (§7.2 step 2):
///
/// - **Known contacts are free (§9.1).** A peer IP on the allow-prefix list, or a `MAIL FROM` on
///   the known-sender list, is accepted immediately with no greylist delay and no rate cost.
/// - **Explicit blocks (RBL-style).** A blocked IP prefix or sender is hard-rejected `554`.
/// - **Greylisting = the cost for cold contact.** A never-before-seen `(ip, from)` pair is
///   deferred `451` on first sight; a legitimate MTA retries after its queue delay and is then
///   accepted, while spam cannons that never retry are shed. This is the SMTP-native analogue of
///   §9.3's cold-contact cost — imposing a real (time/retry) cost without deanonymizing anyone.
/// - **Per-IP rate limiting.** More than `rate_limit` *accepted* messages from one IP within
///   `rate_window_ms` is deferred `451` (§7.2 step 2 "per-IP rate limits").
///
/// State is in-memory and ephemeral (it is operational anti-abuse state, **not** message durability
/// — the gateway remains stateless about mail, §7.4): losing it just means a cold sender is
/// greylisted again, which is safe. Interior mutability + a [`Clock`] seam keep it testable.
pub struct ColdSenderGate {
    known_ip_prefixes: Vec<String>,
    known_senders: Vec<String>,
    blocked_ip_prefixes: Vec<String>,
    blocked_senders: Vec<String>,
    /// Minimum delay before a greylisted triple's retry is accepted.
    greylist_min_retry_ms: u64,
    /// How long a greylist entry is remembered; a retry after this is treated as a fresh cold sighting.
    greylist_ttl_ms: u64,
    /// Max accepted messages per IP within `rate_window_ms` before deferring.
    rate_limit: u32,
    rate_window_ms: u64,
    clock: Box<dyn Clock>,
    state: Mutex<GateState>,
}

impl ColdSenderGate {
    /// A gate with sensible defaults: 60 s greylist retry delay, 12 h greylist memory, and a
    /// per-IP budget of 60 accepted messages per 60 s. Tune via the builder methods.
    pub fn new() -> Self {
        Self::with_clock(Box::new(SystemClock))
    }

    /// As [`Self::new`] but with an explicit clock (tests inject a manual clock).
    pub fn with_clock(clock: Box<dyn Clock>) -> Self {
        ColdSenderGate {
            known_ip_prefixes: Vec::new(),
            known_senders: Vec::new(),
            blocked_ip_prefixes: Vec::new(),
            blocked_senders: Vec::new(),
            greylist_min_retry_ms: 60_000,
            greylist_ttl_ms: 12 * 3_600_000,
            rate_limit: 60,
            rate_window_ms: 60_000,
            clock,
            state: Mutex::new(GateState::default()),
        }
    }

    /// Trust a peer-IP prefix as a known contact (free, no greylist/rate cost).
    pub fn allow_ip_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.known_ip_prefixes.push(prefix.into());
        self
    }
    /// Trust a `MAIL FROM` address as a known contact (free). Matched case-insensitively.
    pub fn allow_sender(mut self, addr: impl Into<String>) -> Self {
        self.known_senders.push(addr.into().to_ascii_lowercase());
        self
    }
    /// Hard-block a peer-IP prefix (RBL-style `554`).
    pub fn block_ip_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.blocked_ip_prefixes.push(prefix.into());
        self
    }
    /// Hard-block a `MAIL FROM` address (`554`). Matched case-insensitively.
    pub fn block_sender(mut self, addr: impl Into<String>) -> Self {
        self.blocked_senders.push(addr.into().to_ascii_lowercase());
        self
    }
    /// Set the greylist retry delay / memory TTL (ms).
    pub fn with_greylist(mut self, min_retry_ms: u64, ttl_ms: u64) -> Self {
        self.greylist_min_retry_ms = min_retry_ms;
        self.greylist_ttl_ms = ttl_ms;
        self
    }
    /// Set the per-IP accepted-message rate limit (`max` per `window_ms`).
    pub fn with_rate_limit(mut self, max: u32, window_ms: u64) -> Self {
        self.rate_limit = max;
        self.rate_window_ms = window_ms;
        self
    }

    fn is_known(&self, peer_ip: &str, from: &str) -> bool {
        let from_l = from.to_ascii_lowercase();
        self.known_ip_prefixes.iter().any(|p| peer_ip.starts_with(p.as_str()))
            || self.known_senders.iter().any(|s| *s == from_l)
    }
    fn is_blocked(&self, peer_ip: &str, from: &str) -> bool {
        let from_l = from.to_ascii_lowercase();
        self.blocked_ip_prefixes.iter().any(|p| peer_ip.starts_with(p.as_str()))
            || self.blocked_senders.iter().any(|s| *s == from_l)
    }
}

impl Default for ColdSenderGate {
    fn default() -> Self {
        Self::new()
    }
}

impl AntiAbuse for ColdSenderGate {
    fn check(&self, peer_ip: &str, mail_from: &str) -> AbuseDecision {
        // 1. Explicit block wins (RBL-style hard reject).
        if self.is_blocked(peer_ip, mail_from) {
            return AbuseDecision::Reject { code: 554, reason: "5.7.1 sender blocked by policy".into() };
        }
        // 2. Known contacts are free (§9.1) — no greylist, no rate cost.
        if self.is_known(peer_ip, mail_from) {
            return AbuseDecision::Accept;
        }

        let now = self.clock.now_ms();
        let mut st = self.state.lock().expect("gate state poisoned");

        // 3. Per-IP rate limit over accepted messages in the sliding window.
        {
            let window_start = now.saturating_sub(self.rate_window_ms);
            let hits = st.accepts.entry(peer_ip.to_string()).or_default();
            hits.retain(|&t| t >= window_start);
            if hits.len() as u32 >= self.rate_limit {
                return AbuseDecision::Reject {
                    code: 451,
                    reason: "4.7.1 rate limit exceeded, slow down and retry later".into(),
                };
            }
        }

        // 4. Greylist the cold (ip, from) pair: defer on first sight; accept a retry after the delay.
        let key = (peer_ip.to_string(), mail_from.to_string());
        let first_seen = st.greylist.get(&key).copied();
        let cold = match first_seen {
            // Expired entry ⇒ treat as never-seen (a fresh cold sighting).
            Some(ts) if now.saturating_sub(ts) > self.greylist_ttl_ms => true,
            Some(_) => false,
            None => true,
        };
        if cold {
            st.greylist.insert(key, now);
            return AbuseDecision::Reject {
                code: 451,
                reason: "4.7.1 greylisted — please retry shortly (cost for cold contact, §9)".into(),
            };
        }
        // Seen before: enforce the minimum retry delay so an instant re-send does not pass.
        let ts = first_seen.expect("cold==false implies a stored timestamp");
        if now.saturating_sub(ts) < self.greylist_min_retry_ms {
            return AbuseDecision::Reject {
                code: 451,
                reason: "4.7.1 greylisted — retry interval not yet elapsed".into(),
            };
        }

        // Accept: record it against the per-IP rate window.
        st.accepts.entry(peer_ip.to_string()).or_default().push(now);
        AbuseDecision::Accept
    }
}

/// How the inbound gateway treats an incoming legacy message's DKIM signature (spec §7.2 step 2 /
/// §9 — DKIM/DMARC-style validation is part of the pre-delivery spam checks).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DkimPolicy {
    /// Verify the DKIM signature (if a resolver is configured) and let the verdict inform
    /// downstream policy, but **deliver regardless** of the verdict. This is the honest default:
    /// full DMARC alignment (fetching the sender domain's `_dmarc` `p=` record and requiring an
    /// aligned pass) is a documented seam this gateway does not implement, so it does not
    /// unilaterally bounce unsigned or unaligned mail.
    #[default]
    Annotate,
    /// **Reject** (SMTP `550`) an inbound message that carries a DKIM-Signature which does **not**
    /// verify. A present-but-broken signature is a strong forgery/tamper signal, so it is refused
    /// before it is ever wrapped into a MOTE. Unsigned mail and mail whose key cannot be resolved
    /// are still delivered (that is DMARC-`p=` territory — the seam above), not hard-bounced here.
    Enforce,
}

/// How the inbound gateway treats the SPF verdict for a legacy `MAIL FROM` (spec item 1, RFC 7208,
/// evaluated at `MAIL FROM` by [`MxSession`] — see [`InboundGateway::evaluate_spf`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SpfPolicy {
    /// Evaluate SPF and make the outcome available (via [`InboundGateway::evaluate_spf`]) but never
    /// reject on it. The honest default: SPF alone is a weak, forwarding-fragile signal, so this
    /// gateway does not unilaterally bounce on it unless explicitly asked to enforce.
    #[default]
    Annotate,
    /// Reject (`550`) a hard `Fail` (RFC 7208 `-all`-style) sender before `DATA`, and defer (`451`)
    /// a genuine DNS `TempError` so the sender's queue retries rather than the gateway guessing.
    /// Every other result (`Pass`/`SoftFail`/`Neutral`/`None`/`PermError`) still proceeds to
    /// `DATA` — `SoftFail`/`Neutral`/`PermError` are advisory-only per RFC 7208 and are DMARC's (or
    /// a dedicated spam scorer's) territory, not a hard SMTP-level bounce on their own.
    Enforce,
}

/// How the inbound gateway treats the combined DMARC verdict (spec item 2, RFC 7489, evaluated once
/// the full message is in hand — see [`InboundGateway::evaluate_dmarc`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DmarcHandling {
    /// Evaluate DMARC and make the verdict available (via [`InboundGateway::evaluate_dmarc`]) but
    /// never reject on it.
    #[default]
    Annotate,
    /// Reject (`550`) a message whose effective DMARC policy is `p=reject` (or an organizational
    /// domain's `sp=reject`) and which fails SPF+DKIM alignment. A `quarantine` verdict is **not**
    /// turned into an SMTP-level rejection: a stateless bridge with no mailbox has nowhere to
    /// quarantine a message into (a documented, honest narrowing — quarantine is still surfaced in
    /// the verdict for a caller with somewhere to route it; this gateway's only SMTP-level lever is
    /// accept/refuse).
    Enforce,
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
    /// Optional inbound-DKIM key resolver (the `_domainkey` TXT lookup seam). `None` ⇒ inbound DKIM
    /// verification is not performed (the DNS resolver is the documented external dependency).
    dkim_resolver: Option<Box<dyn DkimKeyResolver>>,
    /// What to do with the DKIM verdict (see [`DkimPolicy`]).
    dkim_policy: DkimPolicy,
    /// Optional SPF resolver (spec item 1, RFC 7208). `None` ⇒ SPF is never evaluated.
    spf_resolver: Option<Box<dyn SpfResolver>>,
    /// What to do with the SPF verdict (see [`SpfPolicy`]).
    spf_policy: SpfPolicy,
    /// Optional `_dmarc` TXT resolver (spec item 2, RFC 7489). `None` ⇒ DMARC is never evaluated.
    dmarc_resolver: Option<Box<dyn DmarcTxtResolver>>,
    /// What to do with the DMARC verdict (see [`DmarcHandling`]).
    dmarc_policy: DmarcHandling,
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

/// The full output of bridging one legacy message into the mesh with provenance stamped
/// ([`InboundGateway::wrap_attest_and_stamp`]): the sealed MOTE, the §7.2a [`Attestation`], the
/// normative signed [`GatewayAttestation`] (§18.3.11), and the derived client-facing
/// [`ProvenanceRecord`] (§18.8.1). A stateless gateway holds none of this after handing it off.
#[derive(Debug, Clone)]
pub struct InboundBridged {
    /// The encrypted MOTE sealed to the recipient's key.
    pub env: Envelope,
    /// The §7.2a attestation bound to the MOTE's content address.
    pub attestation: Attestation,
    /// The normative gateway attestation (§18.3.11) signed over the exact RFC 5322 bytes.
    pub gateway_attestation: GatewayAttestation,
    /// The client-facing transport-path record (§18.8.1): a single `gateway` hop, gateway-touched.
    pub provenance: ProvenanceRecord,
}

impl InboundGateway {
    pub fn new(
        ik: IdentityKey,
        attest_keys: Vec<AttestationKey>,
        directory: Box<dyn KeyDirectory>,
        delivery: Box<dyn MeshDelivery>,
        abuse: Box<dyn AntiAbuse>,
    ) -> Self {
        InboundGateway {
            ik,
            attest_keys,
            directory,
            delivery,
            abuse,
            dkim_resolver: None,
            dkim_policy: DkimPolicy::Annotate,
            spf_resolver: None,
            spf_policy: SpfPolicy::Annotate,
            dmarc_resolver: None,
            dmarc_policy: DmarcHandling::Annotate,
        }
    }

    /// Enable inbound DKIM verification (spec §7.2 step 2): resolve the sender's
    /// `<selector>._domainkey.<domain>` key via `resolver` and apply `policy` to the verdict.
    pub fn with_dkim(mut self, resolver: Box<dyn DkimKeyResolver>, policy: DkimPolicy) -> Self {
        self.dkim_resolver = Some(resolver);
        self.dkim_policy = policy;
        self
    }

    /// Enable inbound SPF verification (spec item 1, RFC 7208): evaluate the `MAIL FROM` (or
    /// `HELO`) domain's SPF record against the connecting peer IP via `resolver`, applying `policy`
    /// to the verdict at `MAIL FROM` time (see [`Self::evaluate_spf`] / [`MxSession`]).
    pub fn with_spf(mut self, resolver: Box<dyn SpfResolver>, policy: SpfPolicy) -> Self {
        self.spf_resolver = Some(resolver);
        self.spf_policy = policy;
        self
    }

    /// Enable inbound DMARC verification (spec item 2, RFC 7489): resolve `_dmarc` policy via
    /// `resolver` and apply `policy` to the combined SPF+DKIM alignment verdict.
    pub fn with_dmarc(mut self, resolver: Box<dyn DmarcTxtResolver>, policy: DmarcHandling) -> Self {
        self.dmarc_resolver = Some(resolver);
        self.dmarc_policy = policy;
        self
    }

    fn attest_key_for(&self, domain: &str) -> Option<&AttestationKey> {
        self.attest_keys.iter().find(|k| k.domain().eq_ignore_ascii_case(domain))
    }

    /// Verify the inbound message's DKIM signature against the configured resolver (spec §7.2
    /// step 2). Returns [`DkimVerdict::NoSignature`] when no resolver is configured (the DNS seam is
    /// absent) — i.e. verification is simply not attempted, never falsely reported as a pass.
    pub fn verify_inbound_dkim(&self, message: &[u8]) -> DkimVerdict {
        match &self.dkim_resolver {
            Some(resolver) => verify_with_resolver(message, resolver.as_ref()),
            None => DkimVerdict::NoSignature,
        }
    }

    /// Apply the DKIM policy as a pre-delivery gate against an already-computed verdict. Returns
    /// `Err(reply)` only under [`DkimPolicy::Enforce`] when a present signature fails to verify;
    /// otherwise `Ok(())`. (Takes the verdict rather than `data` so [`Self::accept_message_with_spf`]
    /// computes it exactly once and reuses it for the DMARC gate too.)
    fn dkim_gate(&self, verdict: &DkimVerdict) -> Result<(), SmtpReply> {
        if self.dkim_policy != DkimPolicy::Enforce {
            return Ok(());
        }
        match verdict {
            DkimVerdict::Fail(_) => {
                Err(SmtpReply::new(550, "5.7.20 DKIM signature present but does not verify"))
            }
            // Pass, NoSignature, KeyUnavailable → not hard-bounced here (unsigned/unaligned mail is
            // DMARC-`p=` territory, now real — see `dmarc_gate` — rather than a documented seam).
            _ => Ok(()),
        }
    }

    /// Evaluate SPF (spec item 1, RFC 7208) for this transaction: resolves and checks the sender
    /// domain's SPF record against the connecting `peer_ip`, falling back to the `helo` domain per
    /// RFC 7208 §2.4 when `mail_from` is the null reverse-path or lacks a domain. Returns the
    /// honest "never evaluated" outcome ([`SpfOutcome::unevaluated`]) when no [`SpfResolver`] is
    /// configured, or `peer_ip` does not even parse as an IP — never a fabricated verdict.
    pub fn evaluate_spf(&self, peer_ip: &str, mail_from: &str, helo: Option<&str>) -> SpfOutcome {
        let resolver = match &self.spf_resolver {
            Some(r) => r.as_ref(),
            None => return SpfOutcome::unevaluated(),
        };
        let ip: std::net::IpAddr = match peer_ip.trim().parse() {
            Ok(ip) => ip,
            Err(_) => return SpfOutcome::unevaluated(),
        };
        spf::evaluate(resolver, ip, mail_from, helo)
    }

    /// Apply the SPF policy (spec item 1) at `MAIL FROM` time. See [`SpfPolicy`] for what each
    /// result does under [`SpfPolicy::Enforce`]; [`SpfPolicy::Annotate`] never rejects.
    fn spf_gate(&self, outcome: &SpfOutcome) -> Result<(), SmtpReply> {
        if self.spf_policy != SpfPolicy::Enforce {
            return Ok(());
        }
        match outcome.result {
            SpfResult::Fail => Err(SmtpReply::new(
                550,
                "5.7.23 SPF hard fail (RFC 7208): sender IP not authorized for this domain",
            )),
            SpfResult::TempError => Err(SmtpReply::new(
                451,
                "4.4.3 SPF temporary DNS error evaluating sender policy, please retry",
            )),
            _ => Ok(()),
        }
    }

    /// Evaluate DMARC (spec item 2, RFC 7489) for an already-received message, combining the DKIM
    /// verdict [`Self::verify_inbound_dkim`] computes with `spf` and domain alignment against the
    /// `_dmarc` policy published for the message's `RFC5322.From` domain. Exposed publicly
    /// (mirroring [`Self::verify_inbound_dkim`]) so a caller can inspect the raw verdict regardless
    /// of [`DmarcHandling`] policy.
    pub fn evaluate_dmarc(&self, data: &[u8], spf: Option<&SpfOutcome>, mail_from: &str) -> DmarcVerdict {
        let dkim_verdict = self.verify_inbound_dkim(data);
        self.dmarc_verdict_with_dkim(data, spf, &dkim_verdict, mail_from)
    }

    /// As [`Self::evaluate_dmarc`], but takes an already-computed DKIM verdict so the hot
    /// (`accept_message_with_spf`) path never resolves the DKIM key twice.
    fn dmarc_verdict_with_dkim(
        &self,
        data: &[u8],
        spf: Option<&SpfOutcome>,
        dkim_verdict: &DkimVerdict,
        mail_from: &str,
    ) -> DmarcVerdict {
        let resolver = match &self.dmarc_resolver {
            Some(r) => r.as_ref(),
            None => return DmarcVerdict::NoPolicy,
        };
        let header_domain = match dmarc::header_from_domain(data) {
            Some(d) => d,
            // No parseable `From:` header/domain at all — nothing to align against. Malformed
            // legacy mail is `dkim_gate`/recipient-resolution's problem, not fabricated here.
            None => return DmarcVerdict::PermError,
        };
        let envelope_domain = domain_of(mail_from).unwrap_or("").to_string();
        dmarc::evaluate(resolver, &header_domain, &envelope_domain, spf.map(|o| o.result), dkim_verdict)
    }

    /// Apply the DMARC policy (spec item 2) as a pre-delivery gate. Only `p=reject`/`sp=reject`
    /// failures become an SMTP-level `550` under [`DmarcHandling::Enforce`] — see its docs on why
    /// `quarantine` is not enacted here.
    fn dmarc_gate(
        &self,
        data: &[u8],
        spf: Option<&SpfOutcome>,
        dkim_verdict: &DkimVerdict,
        mail_from: &str,
    ) -> Result<(), SmtpReply> {
        if self.dmarc_policy != DmarcHandling::Enforce {
            return Ok(());
        }
        match self.dmarc_verdict_with_dkim(data, spf, dkim_verdict, mail_from) {
            DmarcVerdict::Fail { disposition: DmarcDisposition::Reject } => Err(SmtpReply::new(
                550,
                "5.7.1 message failed DMARC (RFC 7489): policy=reject and SPF/DKIM not aligned",
            )),
            // Pass, NoPolicy, PermError, or a Fail whose effective disposition is none/quarantine —
            // none of these are an SMTP-level bounce here (see DmarcHandling::Enforce docs).
            _ => Ok(()),
        }
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

    /// Wrap + attest **and** stamp the normative transport-path provenance (spec §7.8 / §18.3.11 /
    /// §18.8.1) for a single legacy message. In addition to the sealed MOTE and the §7.2a
    /// [`Attestation`], this signs a [`GatewayAttestation`] over the **exact RFC 5322 bytes** with
    /// the same domain-anchored `_dmtap-gw` key (via [`crate::provenance`]) and assembles the
    /// `gateway`-touched [`ProvenanceRecord`] a recipient node derives from it — so the message
    /// carries a *provable* `gateway` hop (its presence is the non-forgeable §7.8.1(b) marker),
    /// not merely an inbox-visible "from a gateway" claim. `seq` is `0`: this is the (single)
    /// legacy-inbound bridge hop.
    pub fn wrap_attest_and_stamp(
        &self,
        mail_from: &str,
        rcpt_to: &str,
        data: &[u8],
        now: TimestampMs,
    ) -> Result<InboundBridged, InboundError> {
        let domain = domain_of(rcpt_to).ok_or_else(|| InboundError::BadAddress(rcpt_to.into()))?;
        let att_key = self
            .attest_key_for(domain)
            .ok_or_else(|| InboundError::NoAttestationKey(domain.into()))?;

        let (env, attestation) = self.wrap_and_attest(mail_from, rcpt_to, data, now)?;

        // Sign the normative gateway attestation over the exact legacy bytes (§18.9.11), then
        // assemble the client-facing provenance record the recipient would surface: a single
        // gateway hop, gateway-touched origin (never pure-mesh). Legacy delivery arrives fast/direct
        // (not off the mixnet), so tier=Fast / profile=NotApplicable; min_hops/observed_at are
        // recipient-node observations, left unset by the gateway.
        let gateway_attestation =
            GatewayAttestation::sign(att_key, data, Some(mail_from), now, 0);
        let provenance = ProvenanceRecord::assemble(
            Tier::Fast,
            Profile::NotApplicable,
            None,
            None,
            vec![gateway_attestation.clone()],
        );

        Ok(InboundBridged { env, attestation, gateway_attestation, provenance })
    }

    /// The full `smtp-inbound` decision for one recipient (§19.7.1 steps 3–6): wrap, attest,
    /// deliver, and return the SMTP reply — `250` only on a durable ack, else `451`. A thin
    /// convenience over [`Self::accept_message_with_spf`] for callers with no SPF outcome to feed
    /// (no live `MAIL FROM` step, e.g. a caller driving the gateway directly) — DMARC then treats
    /// SPF as not contributing a pass, never as a forged one.
    pub fn accept_message(
        &self,
        mail_from: &str,
        rcpt_to: &str,
        data: &[u8],
        now: TimestampMs,
    ) -> SmtpReply {
        self.accept_message_with_spf(mail_from, rcpt_to, data, now, None)
    }

    /// As [`Self::accept_message`], but also takes the SPF outcome already evaluated for this
    /// transaction (spec item 1: [`MxSession`] computes it at `MAIL FROM`, since SPF needs the
    /// connecting peer IP, which this method alone does not receive). The outcome feeds DMARC
    /// alignment (spec item 2, §7.2 step 2) alongside the existing DKIM gate.
    pub fn accept_message_with_spf(
        &self,
        mail_from: &str,
        rcpt_to: &str,
        data: &[u8],
        now: TimestampMs,
        spf: Option<&SpfOutcome>,
    ) -> SmtpReply {
        // Pre-delivery DKIM gate (§7.2 step 2): under an enforce policy, a present-but-invalid
        // signature is refused here, before the body is ever wrapped into a MOTE. Computed once and
        // reused by the DMARC gate below (avoids a second DKIM-key resolution).
        let dkim_verdict = self.verify_inbound_dkim(data);
        if let Err(reply) = self.dkim_gate(&dkim_verdict) {
            return reply;
        }
        // DMARC (spec item 2, RFC 7489): combines the DKIM verdict above with `spf` and header-from
        // alignment. Fail-closed only on an effective `reject` policy under Enforce (see docs).
        if let Err(reply) = self.dmarc_gate(data, spf, &dkim_verdict, mail_from) {
            return reply;
        }
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
    /// The `HELO`/`EHLO` argument, if any. Persists across `RSET`/transactions (RFC 5321 §4.1.1.1:
    /// `RSET` resets the mail transaction, not the session's identification) — used as the SPF
    /// fallback domain (spec item 1, RFC 7208 §2.4) when `MAIL FROM` is the null reverse-path.
    helo: Option<String>,
    mail_from: Option<String>,
    rcpt_to: Option<String>,
    data: Vec<u8>,
    /// The SPF outcome evaluated at `MAIL FROM` (spec item 1) for the current transaction, carried
    /// through to the DMARC gate at the end of `DATA`.
    spf_outcome: Option<SpfOutcome>,
}

impl<'g> MxSession<'g> {
    pub fn new(gw: &'g InboundGateway, peer_ip: impl Into<String>, now: TimestampMs) -> Self {
        MxSession {
            gw,
            peer_ip: peer_ip.into(),
            now,
            phase: Phase::Command,
            helo: None,
            mail_from: None,
            rcpt_to: None,
            data: Vec::new(),
            spf_outcome: None,
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
        self.spf_outcome = None;
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
            "HELO" | "EHLO" => {
                // Captured for the SPF null-reverse-path fallback (spec item 1, RFC 7208 §2.4).
                let arg = rest.trim();
                self.helo = if arg.is_empty() { None } else { Some(arg.to_string()) };
                SmtpReply::new(250, "envoir-gateway at your service")
            }
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
            AbuseDecision::Accept => {}
            AbuseDecision::Reject { code, reason } => return SmtpReply::new(code, reason),
        }
        // SPF (spec item 1, RFC 7208): evaluated here, before DATA, since it needs the connecting
        // peer IP, which only this MX session (not `InboundGateway::accept_message` alone) has. The
        // outcome is stashed for the DMARC alignment gate at the end of DATA.
        let spf_outcome = self.gw.evaluate_spf(&self.peer_ip, &addr, self.helo.as_deref());
        if let Err(reply) = self.gw.spf_gate(&spf_outcome) {
            return reply;
        }
        self.mail_from = Some(addr);
        self.spf_outcome = Some(spf_outcome);
        SmtpReply::new(250, "2.1.0 sender ok")
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
            let spf_outcome = self.spf_outcome.clone();
            self.reset_transaction();
            // The whole silent-loss-avoidance decision happens here: 250 only on a durable ack.
            // Feeds the MAIL-FROM-time SPF outcome into the DKIM/DMARC gates (spec items 1-2).
            return self.gw.accept_message_with_spf(
                &mail_from,
                &rcpt_to,
                &data,
                self.now,
                spf_outcome.as_ref(),
            );
        }
        // Undo SMTP dot-stuffing (RFC 5321 §4.5.2), then append the line with CRLF.
        let unstuffed = line.strip_prefix('.').unwrap_or(line);
        self.data.extend_from_slice(unstuffed.as_bytes());
        self.data.extend_from_slice(b"\r\n");
        // No reply mid-DATA.
        SmtpReply::new(0, "")
    }
}

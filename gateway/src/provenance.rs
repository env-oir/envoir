//! Transport-path provenance + self-host billing seam — spec §7.8, §7.9, §18.3.11, §18.8.1.
//!
//! This module makes the gateway's role in a message's path **provable, not guessable** (§7.8).
//! Two wire objects and two seams:
//!
//! - [`GatewayAttestation`] (§18.3.11) — the **normative wire form** of the §7.2a domain-anchored
//!   attestation the gateway signs when it **bridges** a message across the legacy↔mesh boundary.
//!   Its *presence* proves the hop was `gateway` (plaintext at a real, declared gateway before the
//!   mesh); its *absence* proves the hop was `mesh` (never plaintext at any gateway). It is signed
//!   with the **same** `_dmtap-gw` Ed25519 key published in DNS (§7.2a) via `dmtap-core`
//!   primitives and canonical §18 CBOR — so a mesh-only path cannot forge an *absence* and a
//!   gateway hop cannot forge an *identity*.
//! - [`ProvenanceRecord`] (§18.8.1) — the **client-facing** record the recipient's node assembles
//!   at reception, composing the observed transport tier with the **verified** attestation chain,
//!   so a client can render a transport-path graph (§8.6): walk `mesh` segments (gaps in the
//!   chain) vs `gateway`-touched segments (chained [`GatewayAttestation`]s, ordered by `seq`).
//!   It carries **no signature** (§18.9.12) — every trust claim in it is derived, not asserted.
//! - [`GatewayAuthz`] (§7.9, §12.2) — the policy seam gating whether a self-hosted `@host.net`
//!   domain may relay legacy mail **through** this gateway. Native mesh delivery never reaches
//!   this seam (it does not use the gateway), so it is never gated and never billed (§7.9, §12.3).
//! - [`GatewayMeter`] (§7.9, §12.2, §12.6) — the metering seam envoir-cloud consumes. It is
//!   incremented **only** on an actual gateway relay (the billable event); a pure-mesh message
//!   never calls into the gateway, so it never meters. This closes the §12.7 loop: exactly the
//!   messages carrying a verifiable [`GatewayAttestation`] are the ones a bill can reference.
//!
//! Fail-closed throughout (§18.9.11): a tampered attestation, an unknown discriminator, a
//! digest that does not bind the delivered bytes, or a key not published under the domain all
//! reject with a `dmtap-core`-mapped error rather than silently accepting.

use dmtap_core::cbor::{self, as_array, as_bytes, as_text, as_u64, as_u8, CborError, Cv, Fields};
use dmtap_core::id::ContentId;
use dmtap_core::identity::verify_domain;
use dmtap_core::TimestampMs;

use crate::attestation::AttestationKey;

/// Domain-separation label for the [`GatewayAttestation`] signature (§18.9.11): the exact
/// preimage is `"DMTAP-v0/gateway-attest" ‖ 0x00 ‖ det_cbor(GatewayAttestation ∖ {7})`. Distinct
/// from the §7.2a legacy-framing label used by [`crate::attestation::Attestation`] so a signature
/// over one object can never be replayed as the other (§18.1.6).
const GATEWAY_ATTEST_DS: &[u8] = b"DMTAP-v0/gateway-attest\x00";

/// The only currently-defined `GatewayAttestation` discriminator (key 0): a legacy-inbound bridge
/// attestation (§18.3.11). Any other value MUST be treated as an unverifiable attestation.
const DISC_LEGACY_BRIDGE: u8 = 1;

/// `msg_digest = 0x1e ‖ BLAKE3-256(rfc5322_bytes)` (§18.9.11) — a content address over the **exact**
/// legacy bytes the gateway bridged. Reusing [`ContentId::of`] yields precisely the `0x1e`-prefixed
/// BLAKE3-256 the spec mandates, so a verifier recomputes it the same way and rejects a mismatch.
pub fn msg_digest(rfc5322_bytes: &[u8]) -> Vec<u8> {
    ContentId::of(rfc5322_bytes).as_bytes().to_vec()
}

// ── GatewayAttestation (§18.3.11) ────────────────────────────────────────────────────────────

/// The normative wire form of the domain-anchored gateway attestation (§18.3.11, §7.2a). Signed by
/// the `<selector>._dmtap-gw.<domain>` Ed25519 key; one or more chain (by `seq`) in a message's
/// provenance, sealed inside the recipient's `Payload` (§18.3.5 key 9). Its presence is the
/// non-forgeable `gateway`-hop marker (§7.8.1(b)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayAttestation {
    /// Discriminator (key 0): always [`DISC_LEGACY_BRIDGE`]; other values are reserved.
    pub disc: u8,
    /// The domain whose `_dmtap-gw` key signs this entry (key 1). For the entry that bridged mail
    /// for the recipient this MUST equal the recipient's own domain (checked at verify time).
    pub domain: String,
    /// The `_dmtap-gw` selector naming the attestation key in DNS/KT (key 2).
    pub selector: String,
    /// Gateway receipt time `T` — "received via gateway `domain` at `T`" (key 3).
    pub recv_at: TimestampMs,
    /// `0x1e ‖ BLAKE3-256(rfc5322_bytes)` binding this attestation to one message (key 4).
    pub msg_digest: Vec<u8>,
    /// SMTP `MAIL FROM` of the legacy sender — recipient-visible, sealed, informational (key 5).
    pub legacy_from: Option<String>,
    /// 0-based position in a multi-gateway chain (key 6); `None` ⇒ 0 (single gateway).
    pub seq: Option<u8>,
    /// Signature by the domain-anchored `_dmtap-gw` key over §18.9.11's preimage (key 7).
    pub sig: Vec<u8>,
}

impl GatewayAttestation {
    /// Build **and sign** an attestation for the `rfc5322_bytes` this gateway bridged, under the
    /// domain-anchored key `att_key` (§18.9.11). `seq` is the hop's 0-based chain position (the
    /// prior-hop link: `prior_chain.len()`); `0` is emitted as an omitted key 6.
    pub fn sign(
        att_key: &AttestationKey,
        rfc5322_bytes: &[u8],
        legacy_from: Option<&str>,
        recv_at: TimestampMs,
        seq: u8,
    ) -> GatewayAttestation {
        let mut att = GatewayAttestation {
            disc: DISC_LEGACY_BRIDGE,
            domain: att_key.domain().to_string(),
            selector: att_key.selector().to_string(),
            recv_at,
            msg_digest: msg_digest(rfc5322_bytes),
            legacy_from: legacy_from.map(|s| s.to_string()),
            seq: if seq == 0 { None } else { Some(seq) },
            sig: Vec::new(),
        };
        att.sig = att_key.sign_ds(GATEWAY_ATTEST_DS, &att.signing_body());
        att
    }

    /// Integer-keyed canonical map (§18.3.11). `include_sig=false` omits key 7 for the §18.9.11
    /// signing preimage.
    fn to_cv(&self, include_sig: bool) -> Cv {
        let mut m: Vec<(u64, Cv)> = vec![
            (0, Cv::U64(self.disc as u64)),
            (1, Cv::Text(self.domain.clone())),
            (2, Cv::Text(self.selector.clone())),
            (3, Cv::U64(self.recv_at)),
            (4, Cv::Bytes(self.msg_digest.clone())),
        ];
        if let Some(lf) = &self.legacy_from {
            m.push((5, Cv::Text(lf.clone())));
        }
        if let Some(seq) = self.seq {
            m.push((6, Cv::U64(seq as u64)));
        }
        if include_sig {
            m.push((7, Cv::Bytes(self.sig.clone())));
        }
        Cv::Map(m)
    }

    /// The exact wire bytes of this attestation: §18-canonical integer-keyed CBOR.
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(true))
    }

    /// The §18.9.11 signing body: `det_cbor(GatewayAttestation ∖ {7})`.
    fn signing_body(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(false))
    }

    /// Decode from canonical CBOR (§18.3.11), failing closed on any violation (§18.1.2).
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        Self::from_cv(cbor::decode(bytes)?)
    }

    fn from_cv(cv: Cv) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cv)?;
        let disc = as_u8(f.req(0)?)?;
        let domain = as_text(f.req(1)?)?;
        let selector = as_text(f.req(2)?)?;
        let recv_at = as_u64(f.req(3)?)?;
        let msg_digest = as_bytes(f.req(4)?)?;
        let legacy_from = f.take(5).map(as_text).transpose()?;
        let seq = f.take(6).map(as_u8).transpose()?;
        let sig = as_bytes(f.req(7)?)?;
        f.deny_unknown()?;
        Ok(GatewayAttestation { disc, domain, selector, recv_at, msg_digest, legacy_from, seq, sig })
    }

    /// Verify this attestation (§18.9.11, §7.2a) — **fail-closed**. `expected_domain` is the domain
    /// the verifier requires this entry to be anchored to — for the entry that bridged mail *for the
    /// recipient* this is the recipient's own domain (the §18.3.11 key-1 binding, now enforced here
    /// rather than only documented). `published_key` is the `_dmtap-gw` public key the verifier
    /// looked up under **this entry's own `domain`** (`None` ⇒ the domain published no key or is
    /// untrusted). `rfc5322_bytes` is the decrypted legacy body the recipient reconstructed. Rejects
    /// if:
    /// - the discriminator is not a known bridge kind ([`ProvenanceError::Invalid`]),
    /// - the entry's `domain` is not the `expected_domain` ([`ProvenanceError::KeyUntrusted`] — the
    ///   entry is anchored to a domain outside the recipient's trusted gateway set, so a signature
    ///   valid for domain A cannot be presented as covering domain B),
    /// - the digest does not bind these exact bytes ([`ProvenanceError::Invalid`]),
    /// - no key is published under the domain ([`ProvenanceError::KeyUntrusted`]),
    /// - the signature does not verify under that key ([`ProvenanceError::Invalid`]).
    pub fn verify(
        &self,
        expected_domain: &str,
        published_key: Option<&[u8]>,
        rfc5322_bytes: &[u8],
    ) -> Result<(), ProvenanceError> {
        if self.disc != DISC_LEGACY_BRIDGE {
            return Err(ProvenanceError::Invalid);
        }
        // Bind the entry to the domain the verifier expects (§18.3.11 key 1). Fail closed on a
        // mismatch so an attestation genuinely signed for domain A cannot be replayed as covering a
        // different recipient domain B — even if A's key is published and the signature is valid.
        if !self.domain.eq_ignore_ascii_case(expected_domain) {
            return Err(ProvenanceError::KeyUntrusted);
        }
        // Bind to the delivered content: recompute the digest and compare (constant work, no early
        // return on content). A lifted attestation fails here even with a valid signature.
        if self.msg_digest != msg_digest(rfc5322_bytes) {
            return Err(ProvenanceError::Invalid);
        }
        let key = published_key.ok_or(ProvenanceError::KeyUntrusted)?;
        verify_domain(key, GATEWAY_ATTEST_DS, &self.signing_body(), &self.sig)
            .map_err(|_| ProvenanceError::Invalid)
    }
}

/// Verification errors, mapped to the spec's IANA error registry (§21, §19.3.1). Every one is a
/// hard reject: a legacy-origin message whose required attestation fails to verify MUST NOT be
/// surfaced as legacy-origin-verified (§7.2a).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProvenanceError {
    /// `ERR_GATEWAY_ATTESTATION_INVALID` (`0x0601`): unknown discriminator, digest mismatch, or a
    /// signature that does not verify under the published key.
    #[error("gateway attestation invalid (ERR_GATEWAY_ATTESTATION_INVALID, 0x0601)")]
    Invalid,
    /// `ERR_GATEWAY_ATTESTATION_KEY_UNTRUSTED` (`0x0602`): no `_dmtap-gw` key is published under
    /// this entry's domain, or the domain is not in the recipient's trusted gateway set.
    #[error("gateway attestation key untrusted (ERR_GATEWAY_ATTESTATION_KEY_UNTRUSTED, 0x0602)")]
    KeyUntrusted,
}

impl ProvenanceError {
    /// The spec's numeric error code (§21) for wire/telemetry reporting.
    pub fn code(&self) -> u16 {
        match self {
            ProvenanceError::Invalid => 0x0601,
            ProvenanceError::KeyUntrusted => 0x0602,
        }
    }
}

// ── ProvenanceRecord (§18.8.1) ────────────────────────────────────────────────────────────────

/// Observed arrival tier (§18.8.1 key 1; §4.6). Never a sender claim — the recipient node knows it
/// from *how it received the packet*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Peeled off the mixnet (§4.4).
    Private,
    /// Direct / low-hop (§4.5).
    Fast,
}

impl Tier {
    fn as_u8(self) -> u8 {
        match self {
            Tier::Private => 1,
            Tier::Fast => 2,
        }
    }
    fn from_u8(b: u8) -> Result<Self, CborError> {
        match b {
            1 => Ok(Tier::Private),
            2 => Ok(Tier::Fast),
            _ => Err(CborError::UnknownDiscriminant(b as u64)),
        }
    }
}

/// The mix profile an arrival is consistent with (§18.8.1 key 2; §4.4.10). States the *minimum
/// guaranteed* path length, never a measured path (§6.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// Not applicable — `tier = fast`.
    NotApplicable,
    /// Standard: ≥ 3 hops.
    Standard,
    /// High-security: ≥ 5 hops.
    HighSecurity,
}

impl Profile {
    fn as_u8(self) -> u8 {
        match self {
            Profile::NotApplicable => 0,
            Profile::Standard => 1,
            Profile::HighSecurity => 2,
        }
    }
    fn from_u8(b: u8) -> Result<Self, CborError> {
        match b {
            0 => Ok(Profile::NotApplicable),
            1 => Ok(Profile::Standard),
            2 => Ok(Profile::HighSecurity),
            _ => Err(CborError::UnknownDiscriminant(b as u64)),
        }
    }
}

/// Verified transport-path origin (§18.8.1 key 3, §7.8.1(b)) — the provable `gateway` vs `mesh`
/// verdict a client renders. Derived **solely** from the verified attestation chain, never asserted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// No verified attestation ⇒ the message was **never plaintext at any gateway**.
    PureMesh,
    /// ≥ 1 verified attestation ⇒ plaintext at a declared gateway before the mesh.
    GatewayTouched,
}

impl Origin {
    fn as_u8(self) -> u8 {
        match self {
            Origin::PureMesh => 0,
            Origin::GatewayTouched => 1,
        }
    }
}

/// The client-facing transport-path record (§18.8.1). Assembled by the recipient node from an
/// **already-verified** attestation chain plus the observed transport; served only to the owner's
/// own devices (§8.1) and never attached to a MOTE (§6.8). Carries **no signature** (§18.9.12): its
/// `origin`/`gateways` are derived from the sealed, verified chain, its `tier`/`profile` are node
/// observations, so there is nothing for a third party to forge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenanceRecord {
    /// Observed arrival tier (key 1).
    pub tier: Tier,
    /// Mix profile evidenced (key 2).
    pub profile: Profile,
    /// Verified pure-mesh vs gateway-touched verdict (key 3). Always consistent with `gateways`.
    pub origin: Origin,
    /// The verified attestation chain (key 4), temporal order (ascending `seq`); empty iff
    /// `origin = PureMesh`.
    pub gateways: Vec<GatewayAttestation>,
    /// Coarse, privacy-safe lower-bound hop count (key 5) — a profile floor, never a path (§6.8).
    pub min_hops: Option<u8>,
    /// Recipient-node reception time (key 6); local, never leaves the device cluster.
    pub observed_at: Option<TimestampMs>,
}

impl ProvenanceRecord {
    /// Assemble a record from the observed transport and a chain of **already-verified**
    /// attestations (§18.8.1). `origin` is derived from the chain — empty ⇒ [`Origin::PureMesh`],
    /// non-empty ⇒ [`Origin::GatewayTouched`] — so a caller can never claim gateway-touched without
    /// producing the verifying attestations, nor claim pure-mesh while carrying one. This is the
    /// walk-mesh-vs-gateway invariant of §7.8.1(b) enforced structurally.
    pub fn assemble(
        tier: Tier,
        profile: Profile,
        min_hops: Option<u8>,
        observed_at: Option<TimestampMs>,
        verified_gateways: Vec<GatewayAttestation>,
    ) -> ProvenanceRecord {
        let origin = if verified_gateways.is_empty() {
            Origin::PureMesh
        } else {
            Origin::GatewayTouched
        };
        ProvenanceRecord { tier, profile, origin, gateways: verified_gateways, min_hops, observed_at }
    }

    /// True iff this message is **provably pure-mesh** — never plaintext at any gateway (§7.8.1(b)).
    pub fn is_pure_mesh(&self) -> bool {
        matches!(self.origin, Origin::PureMesh)
    }

    /// The number of gateway hops on the path (0 ⇒ a mesh-only path). A client renders each as a
    /// `gateway` segment and the gaps between them as `mesh` segments (§8.6).
    pub fn gateway_hops(&self) -> usize {
        self.gateways.len()
    }

    fn to_cv(&self) -> Cv {
        let mut m: Vec<(u64, Cv)> = vec![
            (1, Cv::U64(self.tier.as_u8() as u64)),
            (2, Cv::U64(self.profile.as_u8() as u64)),
            (3, Cv::U64(self.origin.as_u8() as u64)),
            (4, Cv::Array(self.gateways.iter().map(|g| g.to_cv(true)).collect())),
        ];
        if let Some(h) = self.min_hops {
            m.push((5, Cv::U64(h as u64)));
        }
        if let Some(t) = self.observed_at {
            m.push((6, Cv::U64(t)));
        }
        Cv::Map(m)
    }

    /// The exact wire bytes served to the owner's client surface: §18-canonical CBOR (§18.8.1).
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv())
    }

    /// Decode from canonical CBOR (§18.8.1), failing closed. Rejects the impossible combinations
    /// (`origin`/`gateways` disagreeing) so a decoded record always upholds §7.8.1(b).
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cbor::decode(bytes)?)?;
        let tier = Tier::from_u8(as_u8(f.req(1)?)?)?;
        let profile = Profile::from_u8(as_u8(f.req(2)?)?)?;
        let origin_byte = as_u8(f.req(3)?)?;
        let gateways = as_array(f.req(4)?)?
            .into_iter()
            .map(GatewayAttestation::from_cv)
            .collect::<Result<Vec<_>, _>>()?;
        let min_hops = f.take(5).map(as_u8).transpose()?;
        let observed_at = f.take(6).map(as_u64).transpose()?;
        f.deny_unknown()?;
        // origin MUST be consistent with the chain (§18.8.1: "empty iff origin = 0").
        let origin = match (origin_byte, gateways.is_empty()) {
            (0, true) => Origin::PureMesh,
            (1, false) => Origin::GatewayTouched,
            _ => return Err(CborError::UnknownDiscriminant(origin_byte as u64)),
        };
        Ok(ProvenanceRecord { tier, profile, origin, gateways, min_hops, observed_at })
    }
}

// ── Self-host authorization seam (§7.9, §12.2 GatewayAuthz) ───────────────────────────────────

/// Which leg of a bridge a message is crossing (§7.9). Both are gateway operations and both meter;
/// the direction distinguishes an inbound legacy *receipt* from an outbound legacy *send*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeDirection {
    /// Legacy SMTP → mesh: the gateway received legacy mail for a self-hosted recipient (§7.2).
    Inbound,
    /// Mesh → legacy SMTP: the gateway sent a self-hoster's mail to the legacy world (§7.3).
    Outbound,
}

/// The policy verdict for a self-hoster's use of this gateway (§7.9, §12.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthzDecision {
    /// Authorized; `account` is the billing subject the operator meters against (§12.2 token).
    Allowed { account: String },
    /// Refused — the self-hoster is not authorized to relay through this gateway.
    Denied { reason: String },
}

/// Gates whether a self-hosted `@host.net` domain may relay legacy mail through this gateway
/// (§7.9, §12.2). Using someone else's gateway is a **relationship the operator's policy governs**,
/// not a protocol entitlement — so this is a seam, and native mesh delivery (which never touches a
/// gateway) never consults it. A real operator backs this with the per-identity accountable-token
/// store (§9); the in-memory [`StaticGatewayAuthz`] models the operator's own single-domain case.
pub trait GatewayAuthz {
    fn authorize(&self, direction: BridgeDirection, domain: &str) -> AuthzDecision;
}

/// An in-memory allowlist of `domain → billing account`, modelling a self-host operator authorizing
/// their own domain(s) (§7.9). A domain not on the list is [`AuthzDecision::Denied`] (fail-closed).
#[derive(Debug, Default, Clone)]
pub struct StaticGatewayAuthz {
    entries: Vec<(String, String)>,
}

impl StaticGatewayAuthz {
    pub fn new() -> Self {
        Self::default()
    }

    /// Authorize `domain`, billed to `account`.
    pub fn allow(mut self, domain: impl Into<String>, account: impl Into<String>) -> Self {
        self.entries.push((domain.into(), account.into()));
        self
    }
}

impl GatewayAuthz for StaticGatewayAuthz {
    fn authorize(&self, _direction: BridgeDirection, domain: &str) -> AuthzDecision {
        match self.entries.iter().find(|(d, _)| d.eq_ignore_ascii_case(domain)) {
            Some((_, account)) => AuthzDecision::Allowed { account: account.clone() },
            None => AuthzDecision::Denied {
                reason: format!("domain {domain} not authorized to relay through this gateway"),
            },
        }
    }
}

// ── Metering seam (§7.9, §12.2, §12.6 GatewayMeter) ───────────────────────────────────────────

/// One metered gateway operation — the billable event (§7.9, §12.6). Emitted **only** on an actual
/// relay, and each carries the `msg_digest` of the very message it bills, so the §12.7 audit loop
/// holds: a user can match a billed event to the `GatewayAttestation` in that message's
/// [`ProvenanceRecord`], and a pure-mesh message (which never produces one of these) can never
/// appear on a bill.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeterEvent {
    /// Inbound (legacy receipt) or outbound (legacy send).
    pub direction: BridgeDirection,
    /// The billing subject the operator's authz resolved (§12.2 accountable token).
    pub account: String,
    /// The self-hosted domain that relayed.
    pub domain: String,
    /// `0x1e ‖ BLAKE3-256(rfc5322_bytes)` of the metered message — links the bill to the message.
    pub msg_digest: Vec<u8>,
    /// Gateway receipt/relay time.
    pub at: TimestampMs,
}

/// The metering seam envoir-cloud consumes (§12.2, §12.6). The gateway calls [`Self::record`]
/// exactly once per gateway relay; the backend (a **separate repo**) turns events into a bill. The
/// gateway itself is stateless (§7.4) and holds nothing after emitting.
pub trait GatewayMeter {
    fn record(&self, event: &MeterEvent);
}

/// A no-op meter — the self-host default when the operator runs their own gateway and bills no one
/// (§7.9: they bear only the IP-reputation cost, there is no third-party bill).
#[derive(Debug, Default, Clone, Copy)]
pub struct NullMeter;

impl GatewayMeter for NullMeter {
    fn record(&self, _event: &MeterEvent) {}
}

/// An in-memory counting meter for tests and single-node deployments: records every event and
/// exposes the running count, so a test can prove the meter increments **only** on gateway relay.
/// Cloning shares the same underlying log (via [`std::rc::Rc`]), so a clone handed to a [`Bridge`]
/// and a clone retained by the caller observe the **same** counter.
#[derive(Debug, Default, Clone)]
pub struct CountingMeter {
    events: std::rc::Rc<std::cell::RefCell<Vec<MeterEvent>>>,
}

impl CountingMeter {
    pub fn new() -> Self {
        Self::default()
    }
    /// Number of metered gateway operations so far.
    pub fn count(&self) -> usize {
        self.events.borrow().len()
    }
    /// A snapshot of the recorded events (for audit / assertions).
    pub fn events(&self) -> Vec<MeterEvent> {
        self.events.borrow().clone()
    }
}

impl GatewayMeter for CountingMeter {
    fn record(&self, event: &MeterEvent) {
        self.events.borrow_mut().push(event.clone());
    }
}

// ── Bridge orchestrator — ties authz + attestation + metering (§7.8, §7.9) ────────────────────

/// The bridging seam: on each legacy↔mesh crossing it (1) authorizes the self-hoster (§7.9), (2)
/// stamps a signed [`GatewayAttestation`] chained onto the prior hop (§18.3.11), and (3) meters the
/// operation (§12.6) — in that order, so an **unauthorized** relay is refused **before** it is
/// attested or billed. A pure-mesh message never calls this, which is exactly why it is neither
/// attested nor metered (§7.8.1(b), §7.9).
pub struct Bridge {
    att_key: AttestationKey,
    authz: Box<dyn GatewayAuthz>,
    meter: Box<dyn GatewayMeter>,
}

/// Why a bridge was refused (before any attestation or meter event).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BridgeError {
    #[error("self-host relay not authorized: {0}")]
    NotAuthorized(String),
}

impl Bridge {
    pub fn new(
        att_key: AttestationKey,
        authz: Box<dyn GatewayAuthz>,
        meter: Box<dyn GatewayMeter>,
    ) -> Self {
        Bridge { att_key, authz, meter }
    }

    /// The gateway's own domain (the `_dmtap-gw` anchor).
    pub fn domain(&self) -> &str {
        self.att_key.domain()
    }

    /// Bridge one message across the legacy↔mesh boundary. `self_host_domain` is the self-hosted
    /// domain whose relay is authorized/billed; `rfc5322_bytes` are the exact legacy bytes;
    /// `prior_chain` are the attestations already accumulated (its length is the new hop's `seq`,
    /// i.e. the prior-hop link). On success returns the signed [`GatewayAttestation`] for this hop
    /// **and** has already recorded exactly one [`MeterEvent`]. On [`AuthzDecision::Denied`] it
    /// records nothing and signs nothing (fail-closed).
    pub fn bridge(
        &self,
        direction: BridgeDirection,
        self_host_domain: &str,
        rfc5322_bytes: &[u8],
        legacy_from: Option<&str>,
        recv_at: TimestampMs,
        prior_chain: &[GatewayAttestation],
    ) -> Result<GatewayAttestation, BridgeError> {
        let account = match self.authz.authorize(direction, self_host_domain) {
            AuthzDecision::Allowed { account } => account,
            AuthzDecision::Denied { reason } => return Err(BridgeError::NotAuthorized(reason)),
        };

        let seq = prior_chain.len() as u8;
        let att = GatewayAttestation::sign(&self.att_key, rfc5322_bytes, legacy_from, recv_at, seq);

        // Meter exactly the relayed message (the billable event, §7.9); the digest links the bill
        // to this attestation for the §12.7 user-side audit.
        self.meter.record(&MeterEvent {
            direction,
            account,
            domain: self_host_domain.to_string(),
            msg_digest: att.msg_digest.clone(),
            at: recv_at,
        });

        Ok(att)
    }
}

/// Extend a provenance chain with a freshly-signed hop, preserving temporal (`seq`) order (§7.8.3).
pub fn chain_append(
    prior: &[GatewayAttestation],
    hop: GatewayAttestation,
) -> Vec<GatewayAttestation> {
    let mut chain = prior.to_vec();
    chain.push(hop);
    chain
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::AttestationKey;

    const RFC: &[u8] = b"From: a@gmail.com\r\nTo: you@host.net\r\nSubject: hi\r\n\r\nbody\r\n";

    fn key(domain: &str) -> AttestationKey {
        AttestationKey::generate(domain, "gw1")
    }

    #[test]
    fn bridged_message_carries_a_verifiable_attestation_chain() {
        let k = key("host.net");
        let att = GatewayAttestation::sign(&k, RFC, Some("a@gmail.com"), 1_700_000_000_000, 0);
        // Verifies under the published key over the exact bytes, anchored to its own domain.
        att.verify("host.net", Some(&k.public()), RFC).unwrap();

        // Assembled into a client-facing record: gateway-touched, one hop, round-trips.
        let rec = ProvenanceRecord::assemble(
            Tier::Fast,
            Profile::NotApplicable,
            Some(1),
            Some(1_700_000_000_001),
            vec![att],
        );
        assert_eq!(rec.origin, Origin::GatewayTouched);
        assert_eq!(rec.gateway_hops(), 1);
        assert!(!rec.is_pure_mesh());
        let decoded = ProvenanceRecord::from_det_cbor(&rec.det_cbor()).unwrap();
        assert_eq!(decoded, rec);
    }

    #[test]
    fn attestation_round_trips_through_canonical_cbor() {
        let k = key("host.net");
        let att = GatewayAttestation::sign(&k, RFC, Some("a@gmail.com"), 42, 3);
        let decoded = GatewayAttestation::from_det_cbor(&att.det_cbor()).unwrap();
        assert_eq!(decoded, att);
        assert_eq!(decoded.seq, Some(3));
        decoded.verify("host.net", Some(&k.public()), RFC).unwrap();
    }

    #[test]
    fn tampered_attestation_fails_verification() {
        let k = key("host.net");
        let att = GatewayAttestation::sign(&k, RFC, None, 100, 0);

        // (a) flipped signature byte.
        let mut bad_sig = att.clone();
        bad_sig.sig[0] ^= 0xff;
        assert_eq!(bad_sig.verify("host.net", Some(&k.public()), RFC), Err(ProvenanceError::Invalid));

        // (b) attestation lifted onto different content — digest no longer binds.
        assert_eq!(
            att.verify("host.net", Some(&k.public()), b"different bytes entirely"),
            Err(ProvenanceError::Invalid)
        );

        // (c) a mutated signed field (recv_at) invalidates the signature.
        let mut bad_field = att.clone();
        bad_field.recv_at = 999;
        assert_eq!(bad_field.verify("host.net", Some(&k.public()), RFC), Err(ProvenanceError::Invalid));

        // (d) unknown discriminator is rejected outright, never silently accepted.
        let mut bad_disc = att.clone();
        bad_disc.disc = 7;
        assert_eq!(bad_disc.verify("host.net", Some(&k.public()), RFC), Err(ProvenanceError::Invalid));
    }

    #[test]
    fn attestation_from_untrusted_domain_key_is_rejected() {
        let k = key("host.net");
        let att = GatewayAttestation::sign(&k, RFC, None, 100, 0);
        // No key published under the domain ⇒ untrusted (0x0602), not silently trusted.
        assert_eq!(att.verify("host.net", None, RFC), Err(ProvenanceError::KeyUntrusted));
        assert_eq!(ProvenanceError::KeyUntrusted.code(), 0x0602);
        assert_eq!(ProvenanceError::Invalid.code(), 0x0601);

        // A different domain's key does not verify this entry (domain matches, key is wrong).
        let other = key("evil.example");
        assert_eq!(att.verify("host.net", Some(&other.public()), RFC), Err(ProvenanceError::Invalid));
    }

    #[test]
    fn attestation_for_one_domain_cannot_be_presented_for_another() {
        // An attestation genuinely signed (and key-published) for domain A must be rejected when a
        // verifier presents it as covering a different recipient domain B — the §18.3.11 key-1
        // binding, enforced fail-closed inside `verify` (not merely documented).
        let a = key("alpha.example");
        let att = GatewayAttestation::sign(&a, RFC, None, 100, 0);
        // Presented for its own domain with its own key ⇒ verifies.
        att.verify("alpha.example", Some(&a.public()), RFC).unwrap();
        // Presented as covering domain B (even with A's real, published key) ⇒ KeyUntrusted.
        assert_eq!(
            att.verify("beta.example", Some(&a.public()), RFC),
            Err(ProvenanceError::KeyUntrusted)
        );
    }

    #[test]
    fn mesh_only_path_yields_zero_gateway_records() {
        let rec = ProvenanceRecord::assemble(
            Tier::Private,
            Profile::HighSecurity,
            Some(5),
            None,
            Vec::new(),
        );
        assert_eq!(rec.origin, Origin::PureMesh);
        assert_eq!(rec.gateway_hops(), 0);
        assert!(rec.is_pure_mesh());
        // Round-trips as pure-mesh, and the wire form carries an empty gateways array.
        let decoded = ProvenanceRecord::from_det_cbor(&rec.det_cbor()).unwrap();
        assert_eq!(decoded, rec);
        assert!(decoded.gateways.is_empty());
    }

    #[test]
    fn decoding_rejects_origin_chain_disagreement() {
        // A record claiming pure-mesh but carrying an attestation (or vice-versa) is impossible and
        // MUST be rejected on decode — a forged "pure-mesh" label over gateway-touched bytes fails.
        let k = key("host.net");
        let att = GatewayAttestation::sign(&k, RFC, None, 1, 0);
        // Hand-build the inconsistent wire map: origin=0 but a non-empty gateways array.
        let cv = Cv::Map(vec![
            (1, Cv::U64(2)),
            (2, Cv::U64(0)),
            (3, Cv::U64(0)), // origin = pure-mesh
            (4, Cv::Array(vec![att.to_cv(true)])), // ...but a gateway is present
        ]);
        let bytes = cbor::encode(&cv);
        assert!(ProvenanceRecord::from_det_cbor(&bytes).is_err());
    }

    #[test]
    fn multi_gateway_chain_each_verifies_under_its_own_domain() {
        // Two gateways bridge the same message (§7.8.3): each entry verifies only under its own
        // domain's key, and seq order is preserved.
        let g1 = key("relay.example"); // an intermediate gateway
        let g2 = key("host.net"); // the recipient-domain bridge (last)
        let a1 = GatewayAttestation::sign(&g1, RFC, Some("a@gmail.com"), 10, 0);
        let chain = chain_append(&[], a1);
        let a2 = GatewayAttestation::sign(&g2, RFC, Some("a@gmail.com"), 11, chain.len() as u8);
        let chain = chain_append(&chain, a2);

        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].seq, None); // seq 0 omitted
        assert_eq!(chain[1].seq, Some(1));
        chain[0].verify("relay.example", Some(&g1.public()), RFC).unwrap();
        chain[1].verify("host.net", Some(&g2.public()), RFC).unwrap();
        // Cross-check: entry 1 does NOT verify under g1's key (wrong signing key, right domain).
        assert_eq!(chain[1].verify("host.net", Some(&g1.public()), RFC), Err(ProvenanceError::Invalid));
    }

    #[test]
    fn meter_increments_only_on_authorized_gateway_relay() {
        let k = key("host.net");
        let pubkey = k.public();
        let meter = CountingMeter::new();
        let bridge = Bridge::new(
            k,
            Box::new(StaticGatewayAuthz::new().allow("host.net", "acct-42")),
            Box::new(meter.clone()), // shares the same log as `meter`
        );

        // Nothing bridged yet ⇒ zero (a pure-mesh message never calls bridge()).
        assert_eq!(meter.count(), 0);

        // One authorized inbound relay: meter increments exactly once, and the returned attestation
        // both verifies and matches the metered digest (the §12.7 audit link).
        let att = bridge
            .bridge(BridgeDirection::Inbound, "host.net", RFC, Some("a@gmail.com"), 5, &[])
            .unwrap();
        assert_eq!(meter.count(), 1);
        att.verify("host.net", Some(&pubkey), RFC).unwrap();
        let ev = &meter.events()[0];
        assert_eq!(ev.account, "acct-42");
        assert_eq!(ev.msg_digest, att.msg_digest);
        assert_eq!(ev.direction, BridgeDirection::Inbound);

        // A denied relay (unauthorized domain) meters NOTHING — the count stays at 1.
        let denied = bridge.bridge(BridgeDirection::Outbound, "someone-else.net", RFC, None, 8, &[]);
        assert!(matches!(denied, Err(BridgeError::NotAuthorized(_))));
        assert_eq!(meter.count(), 1);
    }

    #[test]
    fn bridge_denies_unauthorized_self_host_and_meters_nothing() {
        let meter = CountingMeter::new();
        let bridge = Bridge::new(
            key("host.net"),
            Box::new(StaticGatewayAuthz::new()), // empty allowlist ⇒ everything denied
            Box::new(meter.clone()),
        );
        let r = bridge.bridge(BridgeDirection::Outbound, "host.net", RFC, None, 1, &[]);
        assert!(matches!(r, Err(BridgeError::NotAuthorized(_))));
        assert_eq!(meter.count(), 0);
    }

    #[test]
    fn bridge_chains_seq_across_hops() {
        let bridge = Bridge::new(
            key("host.net"),
            Box::new(StaticGatewayAuthz::new().allow("host.net", "acct")),
            Box::new(NullMeter),
        );
        let a0 = bridge
            .bridge(BridgeDirection::Inbound, "host.net", RFC, None, 1, &[])
            .unwrap();
        let chain = chain_append(&[], a0);
        let a1 = bridge
            .bridge(BridgeDirection::Inbound, "host.net", RFC, None, 2, &chain)
            .unwrap();
        assert_eq!(a1.seq, Some(1));
    }
}

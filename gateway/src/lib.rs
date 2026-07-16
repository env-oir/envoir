//! # envoir-gateway — the DMTAP legacy SMTP bridge (spec §7)
//!
//! The **optional**, **stateless** component that bridges legacy SMTP ↔ DMTAP MOTEs — the only
//! part of the system that speaks SMTP and the only one not content-blind (the legacy leg is
//! unavoidably plaintext). A node with no legacy correspondents never uses it; at full DMTAP
//! adoption it is unnecessary (spec §7, `../dmtap/07-gateway.md`).
//!
//! This crate is a **reference implementation, not normative** — where it and the spec disagree,
//! the spec governs (spec §10.4).
//!
//! ## What is real here
//! - **Inbound** ([`inbound`], spec §7.2 / §19.7.1): a line-fed MX SMTP transaction with a pre-`DATA`
//!   anti-abuse gate, recipient-key resolution, real MOTE sealing to the recipient (via
//!   `dmtap-core`'s HPKE `build_mote`), a **domain-anchored gateway attestation** ([`attestation`],
//!   §7.2a), and the **ack-before-`250` / `451`-on-no-ack** silent-loss-avoidance rule (§19.7.1).
//! - **Outbound** ([`outbound`], spec §7.3 / §19.7.2): MOTE → RFC 5322, real **delegated-selector
//!   DKIM** signing ([`dkim`], ed25519-sha256 / relaxed-relaxed, RFC 8463 / RFC 6376) with a
//!   verifiable signature and a hard refusal to sign undelegated domains, plus **TLS enforcement**
//!   via an MTA-STS/DANE policy hook that refuses cleartext fallback.
//!
//! ## Statelessness (spec §7.4)
//! The gateway holds no queue and no mailbox. Durability is punted to the edges: inbound → the
//! legacy sender's SMTP retry (hence `451`, never `250`, without a durable ack); outbound → the
//! user's node retry queue. Every network effect — mesh delivery, the outbound SMTP socket, and the
//! DNS lookups for recipient keys, attestation keys, and DKIM delegation — is abstracted behind a
//! trait, so the whole bridge is exercised in-process and a real deployment supplies thin socket
//! impls.

pub mod attestation;
pub mod b64;
pub mod dkim;
pub mod inbound;
pub mod outbound;

pub use attestation::{Attestation, AttestationError, AttestationKey, GwKeyResolver, StaticGwKeys};
pub use dkim::{DkimError, DkimKey};
pub use inbound::{
    AbuseDecision, AllowAllAbuse, AntiAbuse, DeliveryOutcome, InboundError, InboundGateway,
    KeyDirectory, MeshDelivery, MxSession, RecipientKey, SmtpReply,
};
pub use outbound::{
    AlwaysRequireTls, OutboundError, OutboundGateway, OutboundReport, OutboundTransport, TlsPolicy,
    TlsRequirement, TransportResult,
};

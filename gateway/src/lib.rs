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
//!   verifiable signature and a hard refusal to sign undelegated domains, plus real **MX resolution**
//!   ([`mx`], RFC 5321 §5.1: preference-ordered, falling back to A/AAAA when a domain has no MX) and
//!   real **MTA-STS enforcement** ([`mta_sts`], RFC 8461: TXT signal + HTTPS policy fetch/parse,
//!   `enforce` mode requires TLS to an `mx:`-pattern-matching host and aborts rather than downgrading
//!   otherwise). DANE (TLSA) is a documented, unimplemented seam (see [`outbound::TlsPolicy`] docs).
//! - **Legacy interoperability hardening**: real **SPF** ([`spf`], RFC 7208 `check_host()` —
//!   mechanisms, `include`/`redirect` chaining, a DNS-lookup budget, macro use rejected as a
//!   documented narrowing) evaluated at `MAIL FROM`, and real **DMARC** ([`dmarc`], RFC 7489 —
//!   alignment combining the SPF result with the existing DKIM verdict, `_dmarc` two-level policy
//!   discovery, `p=`/`sp=` disposition) evaluated once the message is in hand — both wired into
//!   [`inbound::InboundGateway`]'s annotate/enforce policy seams (spec §7.2 step 2, §9).
//! - **Recipient directory** ([`directory`], §3 resolve): [`directory::FileDirectory`] /
//!   [`directory::InMemoryDirectory`] map an inbound `user@domain` to a DMTAP [`inbound::RecipientKey`]
//!   from a configurable file, so a message for a configured local recipient is sealed to their key
//!   (the KT inclusion proof is the documented next seam on top of the raw mapping).
//! - **Mesh delivery** ([`mesh`], §4): [`mesh::HttpMeshDelivery`] hands the converted MOTE to a
//!   node's HTTP ingest endpoint (a `2xx` = durable-custody ack → SMTP `250`), with
//!   [`mesh::NullMesh`] the honest unconfigured default and the `dmtap-p2p` node transport the
//!   documented drop-in behind the same [`inbound::MeshDelivery`] trait (kept above the gateway to
//!   avoid a dependency cycle). The `run` binary composes these into a real daemon with graceful
//!   `SIGINT`/`SIGTERM` shutdown ([`inbound_tcp::MxListener::serve_until`]).
//!
//! ## Statelessness (spec §7.4)
//! The gateway holds no queue and no mailbox. Durability is punted to the edges: inbound → the
//! legacy sender's SMTP retry (hence `451`, never `250`, without a durable ack); outbound → the
//! user's node retry queue. Every network effect — mesh delivery, the outbound SMTP socket, and the
//! DNS lookups for recipient keys, attestation keys, MX records, MTA-STS TXT/HTTPS, and DKIM
//! delegation — is abstracted behind a trait, so the whole bridge is exercised in-process. One
//! consequence of statelessness specific to MTA-STS: there is no policy cache, so a policy
//! fetch failure (as opposed to a fetched `enforce` policy) falls back to opportunistic TLS rather
//! than fail-closed — see [`mta_sts`] module docs.
//!
//! ## Real sockets
//! The trait-abstracted network legs now have concrete socket/DNS impls: [`inbound_tcp::MxListener`]
//! is a real `TcpListener` MX that runs the SMTP dialog (with STARTTLS termination via rustls) and
//! feeds the assembled message into the verified [`inbound::MxSession`] pipeline; [`SmtpTcpTransport`]
//! is a real SMTP client that opens a TCP connection to the destination MX, negotiates STARTTLS, and
//! enforces the TLS-required-never-cleartext rule (§7.3); [`mx::DnsMxResolver`] and
//! [`mta_sts::DnsTxtResolver`] are a minimal dependency-free DNS-over-UDP client ([`dns`]) rather than
//! a full async resolver crate (this crate is deliberately std-only and synchronous); and
//! [`mta_sts::HttpsPolicyFetcher`] is a minimal HTTP/1.1-over-rustls GET. The in-process trait
//! doubles remain for unit tests; the socket/DNS impls are the production leg (unit-tested via pure
//! wire-format round-trips, not live network calls).

pub mod attestation;
pub mod authz;
pub mod b64;
pub mod directory;
pub mod dkim;
pub mod dmarc;
pub mod dns;
pub mod forwarded_addr;
pub mod inbound;
pub mod inbound_tcp;
pub mod mesh;
pub mod mta_sts;
pub mod mx;
pub mod net;
pub mod outbound;
pub mod outbound_guard;
pub mod outbound_tcp;
pub mod personal;
pub mod provenance;
pub mod spf;

pub use attestation::{Attestation, AttestationError, AttestationKey, GwKeyResolver, StaticGwKeys};
pub use authz::{
    key_derived_localpart, random_nonce, Admission, AdmissionError, AliasAllocator, AliasError,
    AuthzMode, Challenge, IdentityRegistry, Quota, QuotaError, QuotaLedger, RegisteredIdentity,
    Usage, RESERVED_ALIAS_PREFIX,
};
pub use dkim::{
    parse_public_key_txt, signing_domain_selector, verify_with_resolver, DkimError, DkimKey,
    DkimKeyResolver, DkimVerdict, DnsDkimKeyResolver, StaticDkimKeys,
};
pub use directory::{DirectoryError, FileDirectory, InMemoryDirectory};
pub use forwarded_addr::{decode as decode_forwarded, encode as encode_forwarded, ForwardedAddrError};
pub use dmarc::{
    organizational_domain, DmarcDisposition, DmarcPolicy, DmarcRecord, DmarcTxtResolver,
    DmarcVerdict, DnsDmarcResolver, InMemoryDmarcResolver,
};
pub use mesh::{HttpMeshDelivery, MeshConfigError, NullMesh};
pub use inbound::{
    AbuseDecision, AllowAllAbuse, AntiAbuse, Clock, ColdSenderGate, DeliveryOutcome, DkimPolicy,
    DmarcHandling, InboundBridged, InboundError, InboundGateway, KeyDirectory, MeshDelivery,
    MxSession, RecipientKey, SmtpReply, SpfPolicy, SystemClock,
};
pub use inbound_tcp::{
    load_certs, load_private_key, server_config, server_config_from_pem, MxListener,
};
pub use mta_sts::{
    DnsTxtResolver, HttpsPolicyFetcher, InMemoryPolicyFetcher, InMemoryTxtResolver, MtaStsTlsPolicy,
    PolicyFetcher, PolicyMode, StsParseError, StsPolicy, TxtResolver,
};
pub use mx::{DnsMxResolver, InMemoryMxResolver, MxHost, MxResolver};
pub use outbound::{
    AlwaysRequireTls, GovernedSend, OutboundError, OutboundGateway, OutboundReport,
    OutboundTransport, TlsPolicy, TlsRequirement, TransportResult,
};
pub use outbound_guard::{OutboundSenderGuard, SenderVerdict};
pub use personal::{ConfigError, DirectorySource, PersonalConfig};
pub use provenance::{
    chain_append, msg_digest, AuthzDecision, Bridge, BridgeDirection, BridgeError, CountingMeter,
    GatewayAttestation, GatewayAuthz, GatewayMeter, MeterEvent, NullMeter, Origin, Profile,
    ProvenanceError, ProvenanceRecord, StaticGatewayAuthz, Tier,
};
pub use outbound_tcp::SmtpTcpTransport;
pub use spf::{DnsSpfResolver, InMemorySpfResolver, SpfOutcome, SpfResolver, SpfResult};

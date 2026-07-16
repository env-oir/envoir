//! DMTAP legacy SMTP gateway — CLI entry point (spec §7).
//!
//! Optional, stateless bridge: SMTP <-> MOTE. Carries the one irreducible operational cost
//! (IP reputation) and quarantines it to legacy traffic.
//!
//! `run` starts a **real** inbound MX listener ([`envoir_gateway::MxListener`], a `TcpListener`
//! SMTP server with STARTTLS termination) wired to the verified inbound pipeline, and configures a
//! **real** outbound transport ([`envoir_gateway::SmtpTcpTransport`], SMTP-over-STARTTLS to the
//! destination MX). The recipient directory (§3 resolve) and the mesh-delivery adapter (§4) are the
//! operator-supplied seams — wired here to placeholders so the daemon shape is complete and runnable.

use std::net::SocketAddr;

use dmtap_core::identity::IdentityKey;
use dmtap_core::mote::Envelope;

use envoir_gateway::dkim::DnsDkimKeyResolver;
use envoir_gateway::dmarc::DnsDmarcResolver;
use envoir_gateway::inbound::{DkimPolicy, DmarcHandling, SpfPolicy};
use envoir_gateway::spf::DnsSpfResolver;
use envoir_gateway::{
    AllowAllAbuse, Attestation, AttestationKey, DeliveryOutcome, DnsMxResolver, DnsTxtResolver,
    HttpsPolicyFetcher, InboundGateway, KeyDirectory, MeshDelivery, MtaStsTlsPolicy, MxListener,
    OutboundGateway, RecipientKey, SmtpTcpTransport,
};

/// Parse an opt-in boolean env var (`1`/`true`/`yes`, case-insensitive) — everything else,
/// including unset, is `false`. Used for the SPF/DKIM/DMARC enforce switches: the safe default is
/// the non-rejecting `Annotate` policy; an operator opts into `Enforce` explicitly.
fn env_flag(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"),
        Err(_) => false,
    }
}

/// The operator-supplied §3 recipient directory seam. The reference build resolves nobody: a real
/// deployment plugs in the DNS/directory + key-transparency lookup here. Until then every `RCPT`
/// is refused (`550`), which is the safe default for an unconfigured gateway.
struct EmptyDirectory;
impl KeyDirectory for EmptyDirectory {
    fn resolve(&self, _rcpt: &str) -> Option<RecipientKey> {
        None
    }
}

/// The operator-supplied §4 mesh-delivery seam. The reference build never durably acks, so inbound
/// returns `451` and the legacy sender's queue retries (statelessness, §7.4). A real deployment
/// wires the node/relay mesh here and returns [`DeliveryOutcome::Acked`] on durable custody.
struct UnreachableMesh;
impl MeshDelivery for UnreachableMesh {
    fn deliver(&self, _env: &Envelope, _att: &Attestation) -> DeliveryOutcome {
        DeliveryOutcome::NoAck
    }
}

fn run() -> std::io::Result<()> {
    let domain = std::env::var("GATEWAY_DOMAIN").unwrap_or_else(|_| "localhost".to_string());
    let listen = std::env::var("GATEWAY_LISTEN").unwrap_or_else(|_| "127.0.0.1:2525".to_string());
    let selector = std::env::var("GATEWAY_GW_SELECTOR").unwrap_or_else(|_| "gw1".to_string());
    let dns_server: SocketAddr = std::env::var("GATEWAY_DNS_SERVER")
        .unwrap_or_else(|_| "1.1.1.1:53".to_string())
        .parse()
        .unwrap_or_else(|_| "1.1.1.1:53".parse().expect("valid fallback DNS server addr"));

    // Optional STARTTLS: if the operator supplies a cert+key PEM pair, the listener offers and
    // terminates STARTTLS; otherwise it is a plaintext dev listener.
    let tls = match (std::env::var("GATEWAY_TLS_CERT"), std::env::var("GATEWAY_TLS_KEY")) {
        (Ok(cert_path), Ok(key_path)) => {
            let cert_pem = std::fs::read(&cert_path)?;
            let key_pem = std::fs::read(&key_path)?;
            let cfg = envoir_gateway::server_config_from_pem(&cert_pem, &key_pem)?;
            eprintln!("gateway: STARTTLS enabled (cert={cert_path})");
            Some(cfg)
        }
        _ => {
            eprintln!("gateway: no GATEWAY_TLS_CERT/GATEWAY_TLS_KEY — STARTTLS NOT offered (dev mode)");
            None
        }
    };

    // Inbound pipeline (§7.2): gateway identity + domain-anchored attestation key + the operator
    // seams (directory + mesh) + anti-abuse, plus real DNS-backed DKIM/SPF/DMARC (spec §7.2 step 2,
    // items 1-2). All three default to the non-rejecting `Annotate` policy — an operator opts into
    // `Enforce` per-check via env, so a fresh deployment never bounces legitimate legacy mail on a
    // check it hasn't deliberately turned on.
    let dkim_policy = if env_flag("GATEWAY_DKIM_ENFORCE") { DkimPolicy::Enforce } else { DkimPolicy::Annotate };
    let spf_policy = if env_flag("GATEWAY_SPF_ENFORCE") { SpfPolicy::Enforce } else { SpfPolicy::Annotate };
    let dmarc_policy =
        if env_flag("GATEWAY_DMARC_ENFORCE") { DmarcHandling::Enforce } else { DmarcHandling::Annotate };
    let gw = InboundGateway::new(
        IdentityKey::generate(),
        vec![AttestationKey::generate(&domain, &selector)],
        Box::new(EmptyDirectory),
        Box::new(UnreachableMesh),
        Box::new(AllowAllAbuse),
    )
    .with_dkim(Box::new(DnsDkimKeyResolver::new(dns_server)), dkim_policy)
    .with_spf(Box::new(DnsSpfResolver::new(dns_server)), spf_policy)
    .with_dmarc(Box::new(DnsDmarcResolver::new(dns_server)), dmarc_policy);
    eprintln!(
        "gateway: inbound DKIM/SPF/DMARC via DNS {dns_server} (dkim={dkim_policy:?} spf={spf_policy:?} \
         dmarc={dmarc_policy:?}; set GATEWAY_{{DKIM,SPF,DMARC}}_ENFORCE=1 to reject on failure)"
    );

    // Outbound leg (§7.3): a real SMTP-over-STARTTLS transport, real MX resolution (RFC 5321 §5.1),
    // and real MTA-STS policy discovery (RFC 8461), configured and ready. Outbound sends are driven
    // by the node over the mesh (a MOTE marked for a legacy address); wiring that mesh ingress is the
    // operator seam. We build the outbound gateway now so the daemon is fully configured.
    let transport = SmtpTcpTransport::new(domain.clone());
    let mx_resolver = DnsMxResolver::new(dns_server);
    let tls_policy = MtaStsTlsPolicy::new(
        Box::new(DnsTxtResolver::new(dns_server)),
        Box::new(HttpsPolicyFetcher::new()),
    );
    let _outbound = OutboundGateway::new(Vec::new(), Box::new(tls_policy), Box::new(transport))
        .with_mx_resolver(Box::new(mx_resolver));
    eprintln!(
        "gateway: outbound configured — SMTP-STARTTLS transport, MX resolution + MTA-STS via DNS {dns_server} \
         (delegated-DKIM keys loaded on demand)"
    );

    let listener = MxListener::bind(&listen, tls)?;
    let bound = listener.local_addr()?;
    eprintln!("gateway: inbound MX listening on {bound} for domain {domain} (stateless; §7)");
    eprintln!("gateway: recipient directory + mesh delivery are unconfigured seams (RCPT→550 / no durable ack→451)");

    listener.serve_forever(&gw)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("help");

    match cmd {
        "version" => {
            println!("envoir-gateway {}", env!("CARGO_PKG_VERSION"));
        }
        "run" => {
            if let Err(e) = run() {
                eprintln!("gateway: fatal: {e}");
                std::process::exit(1);
            }
        }
        _ => {
            println!(
                "envoir-gateway — optional DMTAP <-> legacy SMTP bridge (reference)\n\
                 \n\
                 USAGE:\n\
                 \x20 envoir-gateway <command>\n\
                 \n\
                 COMMANDS:\n\
                 \x20 run        run the gateway (inbound MX + outbound submission)\n\
                 \x20 version    print version\n\
                 \x20 help       show this help\n\
                 \n\
                 ENV (run):\n\
                 \x20 GATEWAY_LISTEN     bind address (default 127.0.0.1:2525)\n\
                 \x20 GATEWAY_DOMAIN     domain this gateway is MX for (default localhost)\n\
                 \x20 GATEWAY_TLS_CERT   PEM cert chain to enable STARTTLS (with GATEWAY_TLS_KEY)\n\
                 \x20 GATEWAY_TLS_KEY    PEM private key to enable STARTTLS\n\
                 \x20 GATEWAY_DNS_SERVER DNS server (ip:port) for outbound MX/MTA-STS + inbound\n\
                 \x20                    DKIM/SPF/DMARC TXT lookups (default 1.1.1.1:53)\n\
                 \x20 GATEWAY_DKIM_ENFORCE  1/true/yes: reject inbound mail with a present-but-\n\
                 \x20                       invalid DKIM signature (default: annotate only)\n\
                 \x20 GATEWAY_SPF_ENFORCE   1/true/yes: reject inbound mail on an SPF hard fail\n\
                 \x20                       (RFC 7208; default: annotate only)\n\
                 \x20 GATEWAY_DMARC_ENFORCE 1/true/yes: reject inbound mail on an unaligned\n\
                 \x20                       DMARC p=reject/sp=reject policy (RFC 7489; default:\n\
                 \x20                       annotate only)\n\
                 \n\
                 Spec: ../dmtap/07-gateway.md — the DMTAP spec repo (normative). Stateless; needs a reputable IP."
            );
        }
    }
}

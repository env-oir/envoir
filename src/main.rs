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

use dmtap_core::identity::IdentityKey;
use dmtap_core::mote::Envelope;

use envoir_gateway::{
    AllowAllAbuse, Attestation, AttestationKey, DeliveryOutcome, InboundGateway, KeyDirectory,
    MeshDelivery, MxListener, OutboundGateway, RecipientKey, SmtpTcpTransport,
};

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
    // seams (directory + mesh) + anti-abuse.
    let gw = InboundGateway::new(
        IdentityKey::generate(),
        vec![AttestationKey::generate(&domain, &selector)],
        Box::new(EmptyDirectory),
        Box::new(UnreachableMesh),
        Box::new(AllowAllAbuse),
    );

    // Outbound leg (§7.3): a real SMTP-over-STARTTLS transport, configured and ready. Outbound sends
    // are driven by the node over the mesh (a MOTE marked for a legacy address); wiring that mesh
    // ingress is the operator seam. We build the transport now so the daemon is fully configured.
    let transport = SmtpTcpTransport::new(domain.clone());
    let _outbound = OutboundGateway::new(Vec::new(), Box::new(envoir_gateway::AlwaysRequireTls), Box::new(transport));
    eprintln!("gateway: outbound SMTP transport configured (delegated-DKIM keys loaded on demand)");

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
                 \n\
                 Spec: ../dmtap/07-gateway.md — the DMTAP spec repo (normative). Stateless; needs a reputable IP."
            );
        }
    }
}

//! DMTAP legacy SMTP gateway — CLI entry point (spec §7).
//!
//! Optional, stateless bridge: SMTP <-> MOTE. Carries the one irreducible operational cost
//! (IP reputation) and quarantines it to legacy traffic.
//!
//! `run` is a **real long-running daemon**: a `TcpListener` inbound MX ([`envoir_gateway::MxListener`],
//! with STARTTLS termination) wired to the verified inbound pipeline, an operator-configurable
//! recipient directory (§3 resolve) loaded from a file, and a real mesh-delivery adapter (§4) that
//! POSTs converted MOTEs toward a node's ingest endpoint. It stays up until `SIGINT`/`SIGTERM`, then
//! shuts down gracefully. Every knob is an env var (see `help`).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};

use dmtap_core::identity::IdentityKey;

use envoir_gateway::dkim::DnsDkimKeyResolver;
use envoir_gateway::dmarc::DnsDmarcResolver;
use envoir_gateway::inbound::{DkimPolicy, DmarcHandling, MeshDelivery, SpfPolicy};
use envoir_gateway::spf::DnsSpfResolver;
use envoir_gateway::{
    AllowAllAbuse, AttestationKey, DnsMxResolver, DnsTxtResolver, FileDirectory, HttpMeshDelivery,
    HttpsPolicyFetcher, InboundGateway, KeyDirectory, MtaStsTlsPolicy, MxListener, NullMesh,
    OutboundGateway, SmtpTcpTransport,
};

/// The process-wide shutdown flag. Flipped by the async-signal-safe [`handle_signal`] handler on
/// `SIGINT`/`SIGTERM`; polled by [`MxListener::serve_until`] between accepts so the daemon stops
/// gracefully rather than being killed mid-transaction.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Async-signal-safe signal handler: does nothing but set the atomic flag (the only operation the
/// POSIX async-signal-safety rules permit here). The accept loop observes it and returns.
extern "C" fn handle_signal(_sig: libc::c_int) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

/// Install `handle_signal` for `SIGINT` and `SIGTERM`.
fn install_signal_handlers() {
    // SAFETY: `signal` is being called with a valid function pointer for the two standard signals,
    // and the handler only performs an atomic store (async-signal-safe).
    let handler = handle_signal as *const () as libc::sighandler_t;
    unsafe {
        libc::signal(libc::SIGINT, handler);
        libc::signal(libc::SIGTERM, handler);
    }
}

/// Parse an opt-in boolean env var (`1`/`true`/`yes`, case-insensitive) — everything else,
/// including unset, is `false`. Used for the SPF/DKIM/DMARC enforce switches: the safe default is
/// the non-rejecting `Annotate` policy; an operator opts into `Enforce` explicitly.
fn env_flag(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"),
        Err(_) => false,
    }
}

/// Load the §3 recipient directory. `GATEWAY_DIRECTORY` points at the reference directory file
/// (`<email> <ik-b64> <seal-b64>` per line). Unset ⇒ the safe empty default (every `RCPT`→`550`),
/// which is honest for an unconfigured gateway; a malformed file is a hard startup error (fail
/// closed — never silently resolve nobody because a line was garbled).
fn load_directory() -> std::io::Result<Box<dyn KeyDirectory>> {
    match std::env::var("GATEWAY_DIRECTORY") {
        Ok(path) => {
            let dir = FileDirectory::load(&path).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{e}"))
            })?;
            eprintln!("gateway: recipient directory loaded from {path} ({} recipients)", dir.len());
            Ok(Box::new(dir))
        }
        Err(_) => {
            eprintln!(
                "gateway: no GATEWAY_DIRECTORY — recipient directory is empty (every RCPT → 550). \
                 Point GATEWAY_DIRECTORY at a '<email> <ik-b64> <seal-b64>' file to resolve recipients."
            );
            Ok(Box::new(envoir_gateway::InMemoryDirectory::new()))
        }
    }
}

/// Build the §4 mesh-delivery adapter. `GATEWAY_MESH_ENDPOINT` (an `http://host:port/path` node
/// ingest URL) selects the real [`HttpMeshDelivery`]; unset ⇒ the honest [`NullMesh`] (durable-acks
/// nothing → inbound `451`, sender retries), never a silent drop.
fn build_mesh() -> std::io::Result<Box<dyn MeshDelivery>> {
    match std::env::var("GATEWAY_MESH_ENDPOINT") {
        Ok(endpoint) => {
            let mesh = HttpMeshDelivery::new(&endpoint).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("{e}"))
            })?;
            eprintln!("gateway: mesh delivery → node ingest {} (POST MOTE; 2xx = durable ack → 250)", mesh.authority());
            Ok(Box::new(mesh))
        }
        Err(_) => {
            eprintln!(
                "gateway: no GATEWAY_MESH_ENDPOINT — mesh delivery is the NullMesh seam (inbound → 451, \
                 sender retries). Set GATEWAY_MESH_ENDPOINT=http://127.0.0.1:PORT/path to deliver."
            );
            Ok(Box::new(NullMesh))
        }
    }
}

fn run() -> std::io::Result<()> {
    let domain = std::env::var("GATEWAY_DOMAIN").unwrap_or_else(|_| "localhost".to_string());
    // Default binds all interfaces on 2525 so the daemon is reachable as a real MX out of the box;
    // override with GATEWAY_LISTEN (e.g. `0.0.0.0:25` in production, `127.0.0.1:2525` for local dev).
    let listen = std::env::var("GATEWAY_LISTEN").unwrap_or_else(|_| "0.0.0.0:2525".to_string());
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

    // The operator seams, now real: a file-backed recipient directory (§3) and an HTTP node-ingest
    // mesh-delivery adapter (§4). Both fall back to honest, safe defaults when unconfigured.
    let directory = load_directory()?;
    let mesh = build_mesh()?;

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
        directory,
        mesh,
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

    // Long-running daemon loop with graceful shutdown on SIGINT/SIGTERM.
    install_signal_handlers();
    eprintln!("gateway: daemon up — send SIGINT/SIGTERM to shut down gracefully");
    listener.serve_until(&gw, &SHUTDOWN)?;
    eprintln!("gateway: shutdown signal received — stopped accepting, exiting cleanly");
    Ok(())
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
                 \x20 run        run the gateway daemon (inbound MX + directory + mesh delivery)\n\
                 \x20 version    print version\n\
                 \x20 help       show this help\n\
                 \n\
                 ENV (run):\n\
                 \x20 GATEWAY_LISTEN        bind address (default 0.0.0.0:2525)\n\
                 \x20 GATEWAY_DOMAIN        domain this gateway is MX for (default localhost)\n\
                 \x20 GATEWAY_DIRECTORY     path to the recipient directory file (§3 resolve):\n\
                 \x20                       one '<email> <ik-b64> <seal-b64>' line per recipient;\n\
                 \x20                       unset ⇒ empty directory (every RCPT → 550)\n\
                 \x20 GATEWAY_MESH_ENDPOINT node ingest URL (http://host:port/path) the converted\n\
                 \x20                       MOTE is POSTed to (§4 delivery); a 2xx = durable ack →\n\
                 \x20                       SMTP 250; unset ⇒ NullMesh (inbound → 451, sender retries)\n\
                 \x20 GATEWAY_TLS_CERT      PEM cert chain to enable STARTTLS (with GATEWAY_TLS_KEY)\n\
                 \x20 GATEWAY_TLS_KEY       PEM private key to enable STARTTLS\n\
                 \x20 GATEWAY_DNS_SERVER    DNS server (ip:port) for outbound MX/MTA-STS + inbound\n\
                 \x20                       DKIM/SPF/DMARC TXT lookups (default 1.1.1.1:53)\n\
                 \x20 GATEWAY_DKIM_ENFORCE  1/true/yes: reject inbound mail with a present-but-\n\
                 \x20                       invalid DKIM signature (default: annotate only)\n\
                 \x20 GATEWAY_SPF_ENFORCE   1/true/yes: reject inbound mail on an SPF hard fail\n\
                 \x20                       (RFC 7208; default: annotate only)\n\
                 \x20 GATEWAY_DMARC_ENFORCE 1/true/yes: reject inbound mail on an unaligned\n\
                 \x20                       DMARC p=reject/sp=reject policy (RFC 7489; default:\n\
                 \x20                       annotate only)\n\
                 \n\
                 The daemon runs until SIGINT/SIGTERM, then shuts down gracefully.\n\
                 Spec: ../dmtap/07-gateway.md — the DMTAP spec repo (normative). Stateless; needs a reputable IP."
            );
        }
    }
}

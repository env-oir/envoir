//! DMTAP legacy SMTP gateway — CLI entry point (spec §7).
//!
//! Optional, stateless bridge: SMTP <-> MOTE. Carries the one irreducible operational cost
//! (IP reputation) and quarantines it to legacy traffic.
//!
//! Two ways to launch the same real, long-running daemon (both compose the pieces in
//! [`envoir_gateway::PersonalConfig`] and serve until `SIGINT`/`SIGTERM`, then shut down gracefully):
//!
//! - `envoir-gateway personal <config.toml>` — the **personal / single-operator** mode: bridge your
//!   OWN domain and account(s) from one small config file. This is the "just a gateway for my own
//!   email" path (see `gateway/README.md`, `gateway/examples/personal.toml`).
//! - `envoir-gateway run` — the same daemon configured from `GATEWAY_*` environment variables
//!   (handy for containers / systemd drop-ins). Equivalent to `personal` with an env-sourced config.

use std::sync::atomic::{AtomicBool, Ordering};

use envoir_gateway::PersonalConfig;

/// The process-wide shutdown flag. Flipped by the async-signal-safe [`handle_signal`] handler on
/// `SIGINT`/`SIGTERM`; polled by the accept loop between accepts so the daemon stops gracefully
/// rather than being killed mid-transaction.
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

/// Serve a fully-built config: install signal handlers, then run the daemon until shutdown.
fn serve(cfg: &PersonalConfig) -> std::io::Result<()> {
    install_signal_handlers();
    eprintln!("gateway: daemon up — send SIGINT/SIGTERM to shut down gracefully");
    cfg.serve(&SHUTDOWN)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("help");

    match cmd {
        "version" => {
            println!("envoir-gateway {}", env!("CARGO_PKG_VERSION"));
        }
        "personal" => {
            let Some(path) = args.get(2) else {
                eprintln!(
                    "gateway: usage: envoir-gateway personal <config.toml>\n\
                     See gateway/examples/personal.toml for a commented template."
                );
                std::process::exit(2);
            };
            let cfg = match PersonalConfig::load(path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("gateway: fatal: cannot load personal config {path}: {e}");
                    std::process::exit(1);
                }
            };
            if let Err(e) = serve(&cfg) {
                eprintln!("gateway: fatal: {e}");
                std::process::exit(1);
            }
        }
        "run" => {
            // The same daemon, configured from GATEWAY_* environment variables.
            let cfg = PersonalConfig::from_env();
            if let Err(e) = serve(&cfg) {
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
                 \x20 personal <config.toml>  run the daemon for YOUR OWN domain from a config file\n\
                 \x20                          (the single-operator personal gateway; see README)\n\
                 \x20 run                      run the daemon configured from GATEWAY_* env vars\n\
                 \x20 version                  print version\n\
                 \x20 help                     show this help\n\
                 \n\
                 PERSONAL CONFIG (personal <config.toml>):\n\
                 \x20 A flat `key = value` file. Keys (all optional, safe defaults):\n\
                 \x20   domain          the domain this gateway is MX for (your own domain)\n\
                 \x20   listen          bind address (default 0.0.0.0:2525; use 0.0.0.0:25 in prod)\n\
                 \x20   selector        DKIM / attestation selector under your domain (default gw1)\n\
                 \x20   dns_server      recursive DNS ip:port (default 1.1.1.1:53)\n\
                 \x20   directory       path to '<email> <ik-b64> <seal-b64>' recipient file\n\
                 \x20   mesh_endpoint   your node's ingest URL (http://host:port/path)\n\
                 \x20   tls_cert        PEM cert chain to enable STARTTLS (with tls_key)\n\
                 \x20   tls_key         PEM private key to enable STARTTLS\n\
                 \x20   authz_mode      key-registered (default) | open-public (spam risk)\n\
                 \x20   dkim_enforce    true/false — reject present-but-invalid DKIM (default false)\n\
                 \x20   spf_enforce     true/false — reject SPF hard fails (default false)\n\
                 \x20   dmarc_enforce   true/false — reject unaligned p=reject/sp=reject (default false)\n\
                 \x20   quota_messages  per-identity message cap (0 = unlimited)\n\
                 \x20   quota_bytes     per-identity byte cap (0 = unlimited)\n\
                 \x20 LEGACY CLIENT ACCESS (spec §7.15; all OFF by default, need tls_*):\n\
                 \x20   gateway_mode    private (default) | registered-clients-only | public\n\
                 \x20                    who the legacy surfaces serve; non-private CAN read the mail\n\
                 \x20   imap_enable     serve legacy IMAP to old clients (RFC 9051; read)\n\
                 \x20   imap_listen     IMAP bind address (default 127.0.0.1:1143)\n\
                 \x20   imap_tls        starttls (default) | implicit\n\
                 \x20   imap_credentials app-password file: '<user> <app-pw> [<ik-b64>]' per line\n\
                 \x20                    (shared by IMAP/POP3/submission)\n\
                 \x20   imap_maildir    dir of .eml files to project into the served INBOX (IMAP+POP3)\n\
                 \x20   pop3_enable     serve legacy POP3 maildrop (RFC 1939; read)\n\
                 \x20   pop3_listen     POP3 bind address (default 127.0.0.1:1110)\n\
                 \x20   pop3_tls        starttls (default, STLS) | implicit\n\
                 \x20   submission_enable        serve legacy SMTP submission (RFC 6409; outbound)\n\
                 \x20   submission_listen        bind address (default 127.0.0.1:1587)\n\
                 \x20   submission_tls           starttls (default) | implicit\n\
                 \x20   submission_spool         hand-off dir your node picks up (REQUIRED when enabled)\n\
                 \x20   submission_native_domains domains treated as native (default: domain)\n\
                 \x20   (CalDAV/CardDAV are NOT served — dmtap-mail has no DAV server yet; see README)\n\
                 \n\
                 ENV (run): the same keys as GATEWAY_DOMAIN, GATEWAY_LISTEN, GATEWAY_GW_SELECTOR,\n\
                 \x20 GATEWAY_DNS_SERVER, GATEWAY_DIRECTORY, GATEWAY_MESH_ENDPOINT, GATEWAY_TLS_CERT,\n\
                 \x20 GATEWAY_TLS_KEY, GATEWAY_AUTHZ_MODE, GATEWAY_{{DKIM,SPF,DMARC}}_ENFORCE,\n\
                 \x20 GATEWAY_QUOTA_MESSAGES, GATEWAY_QUOTA_BYTES, GATEWAY_MODE, GATEWAY_IMAP_ENABLE,\n\
                 \x20 GATEWAY_IMAP_LISTEN, GATEWAY_IMAP_TLS, GATEWAY_IMAP_CREDENTIALS, GATEWAY_IMAP_MAILDIR,\n\
                 \x20 GATEWAY_POP3_ENABLE, GATEWAY_POP3_LISTEN, GATEWAY_POP3_TLS, GATEWAY_SUBMISSION_ENABLE,\n\
                 \x20 GATEWAY_SUBMISSION_LISTEN, GATEWAY_SUBMISSION_TLS, GATEWAY_SUBMISSION_SPOOL,\n\
                 \x20 GATEWAY_SUBMISSION_NATIVE_DOMAINS.\n\
                 \n\
                 The daemon runs until SIGINT/SIGTERM, then shuts down gracefully.\n\
                 Spec: ../dmtap/07-gateway.md (normative). Stateless; needs a reputable public IP for real mail."
            );
        }
    }
}

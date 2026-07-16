//! DMTAP legacy SMTP gateway — CLI entry point (spec §7).
//!
//! Optional, stateless bridge: SMTP <-> MOTE. Carries the one irreducible operational cost
//! (IP reputation) and quarantines it to legacy traffic. This is a scaffold.

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("help");

    match cmd {
        "version" => {
            println!("envoir-gateway {}", env!("CARGO_PKG_VERSION"));
        }
        "run" => {
            // TODO: start inbound MX (SMTP server) + outbound submission path.
            // Inbound:  accept SMTP -> spam-gate before DATA (§9) -> lookup recipient key (§3)
            //           -> wrap+attest+encrypt to MOTE (§7.2) -> deliver to mesh, or 4xx.
            // Outbound: MOTE -> RFC 5322 -> DKIM-sign via delegated selector (§7.3)
            //           -> SMTP w/ MTA-STS/DANE; node retries on failure.
            // Stateless: hold no queue, no mailbox.
            eprintln!("`run` not yet implemented — see spec §7 (gateway)");
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
                 Spec: ../dmtap/07-gateway.md — the DMTAP spec repo (normative). Stateless; needs a reputable IP."
            );
        }
    }
}

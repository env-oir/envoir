//! Envoir reference node — CLI entry point.
//!
//! The node is the whole client side (spec §0.2): identity, mailbox, mesh participation,
//! delivery, messaging, files, and client protocols. It *is* the mesh. See the DMTAP spec
//! repo (../dmtap/).
//!
//! This is a scaffold: subsystems are stubbed. Build order (spec §10.6):
//!   identity → mote → naming → transport → messaging → privacy → clients → abuse.

use dmtap::Suite;

use dmtap::clients::auth::StaticAuthenticator;
use dmtap::clients::imap::Session;
use dmtap::clients::pop3::Pop3Session;
use dmtap::clients::smtp::SmtpSession;
use dmtap::clients::store::MemoryStore;
use dmtap::clients::{autodiscover, net};

/// Demo: run the §8 client servers (IMAP/POP3/SMTP-submission) on localhost against a fresh
/// in-memory MOTE-store projection, using a fixed demo app-password. A real node terminates TLS
/// and mounts its own encrypted store; this proves the servers end-to-end.
fn serve_mail() -> std::io::Result<()> {
    use std::net::TcpListener;

    // Demo credential bound to a placeholder identity key (spec §8.2 app-passwords).
    let make_auth = || {
        let mut a = StaticAuthenticator::new();
        a.issue("owner@dmtap.local", "app-password", vec![0u8; 32], "demo");
        a
    };

    let cfg = autodiscover::HostConfig::standard("dmtap.local", "127.0.0.1");
    println!("Envoir client servers (spec §8) — demo store, user owner@dmtap.local / app-password");
    println!("IMAP :1143  POP3 :1110  Submission :1587");
    println!("\nAutodiscovery SRV records a node would publish:\n{}", autodiscover::srv_zone(&cfg));

    let imap = TcpListener::bind("127.0.0.1:1143")?;
    let pop3 = TcpListener::bind("127.0.0.1:1110")?;
    let smtp = TcpListener::bind("127.0.0.1:1587")?;

    let a1 = make_auth;
    let a2 = make_auth;
    let a3 = make_auth;
    let t_imap = std::thread::spawn(move || {
        let _ = net::serve_imap(imap, move || Session::new(MemoryStore::new(), a1(), true));
    });
    let t_pop3 = std::thread::spawn(move || {
        let _ = net::serve_pop3(pop3, move || Pop3Session::new(MemoryStore::new(), a2(), true));
    });
    let t_smtp = std::thread::spawn(move || {
        let _ = net::serve_smtp(smtp, move || SmtpSession::new(a3(), true));
    });
    let _ = t_imap.join();
    let _ = t_pop3.join();
    let _ = t_smtp.join();
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("help");

    match cmd {
        "version" => {
            println!("envoir-node {} (pre-alpha scaffold)", env!("CARGO_PKG_VERSION"));
            println!("default suite: {:?}", Suite::Classical);
        }
        "init" => {
            // TODO: generate root identity key (Ed25519), device key, recovery policy
            // (spec §1.2, §1.4), and publish Identity + KeyPackages.
            eprintln!("`init` not yet implemented — see spec §1 (identity lifecycle)");
        }
        "run" => {
            // TODO: start libp2p mesh (Kad/Relay/DCUtR/AutoNAT/mDNS), mixnet client,
            // MLS delivery service, client protocol servers (JMAP/IMAP), retry queue.
            // NOTE: MLS handshakes go over an ORDERED channel, not the mixnet (spec §5.1).
            // The client-access surface (spec §8) is implemented in `dmtap::clients`
            // (the `dmtap-mail` crate); `serve-mail` runs its IMAP/POP/SMTP listeners.
            eprintln!("`run` not yet implemented — see spec §4 (transport), §5 (messaging)");
            eprintln!("try `envoir-node serve-mail` to run the §8 client servers (IMAP/POP/SMTP)");
        }
        "serve-mail" => {
            if let Err(e) = serve_mail() {
                eprintln!("serve-mail error: {e}");
            }
        }
        "gateway" => {
            // A node MAY run in gateway mode if it has a reputable IP + domain (spec §7);
            // the dedicated implementation lives in ../gateway/.
            eprintln!("run the dedicated `envoir-gateway` binary — see ../gateway/ and spec §7");
        }
        _ => {
            println!(
                "envoir-node — Decentralized Message Transfer & Access Protocol (reference)\n\
                 \n\
                 USAGE:\n\
                 \x20 envoir-node <command>\n\
                 \n\
                 COMMANDS:\n\
                 \x20 init         create a new identity (keys + recovery policy)\n\
                 \x20 run          run the node (mesh + mixnet + delivery + clients)\n\
                 \x20 serve-mail   run the §8 client servers (IMAP/POP/SMTP) on localhost\n\
                 \x20 version      print version and default suite\n\
                 \x20 help         show this help\n\
                 \n\
                 Spec: ../dmtap/  (the DMTAP spec repo is normative; this binary is a reference)."
            );
        }
    }
}

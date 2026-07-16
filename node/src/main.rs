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

/// Demo: two in-process nodes exchange a real end-to-end-encrypted MOTE (spec §2, §19.3, §20).
/// Alice seals a MOTE to Bob over the in-memory transport; Bob runs the §2.7 validation pipeline,
/// decrypts, stores it (visible via the §8 mail projection), and acks; Alice's queue reaches ACKED.
fn run_delivery_demo() {
    use dmtap::node::Node;
    use dmtap::transport::InMemoryNetwork;

    let net = InMemoryNetwork::new();
    let alice_ik = dmtap::identity::IdentityKey::generate();
    let bob_ik = dmtap::identity::IdentityKey::generate();
    let alice_t = net.endpoint(alice_ik.public());
    let bob_t = net.endpoint(bob_ik.public());
    let mut alice = Node::with_identity(alice_ik, dmtap::mote::SealKeypair::generate(), alice_t);
    let mut bob = Node::with_identity(bob_ik, dmtap::mote::SealKeypair::generate(), bob_t);

    // Mutual pinning: each learns the other's identity + sealing key (naming/KeyPackage stand-in).
    let (a_ik, a_seal) = (alice.ik_public(), alice.seal_public());
    let (b_ik, b_seal) = (bob.ik_public(), bob.seal_public());
    alice.add_contact(&b_ik, b_seal);
    bob.add_contact(&a_ik, a_seal);

    println!("Envoir node delivery engine — in-process two-node demo (spec §2, §19.3, §20)\n");
    let id = alice
        .send_mail(&b_ik, "hello from Alice", b"the atomic unit of DMTAP is the MOTE")
        .expect("send");
    println!("A: sealed + dispatched MOTE {}", hex8(id.as_bytes()));
    println!("A: outbound state = {:?}", alice.outbound_state(&id).unwrap());

    for outcome in bob.poll() {
        println!("B: {outcome:?}");
    }
    println!("B: INBOX now holds {} message(s) (IMAP/JMAP-visible)", bob.inbox().exists());

    alice.poll(); // consume Bob's ack
    println!("A: outbound state = {:?} (delivered)", alice.outbound_state(&id).unwrap());
}

/// First 8 bytes of a content id as hex, for compact logging.
fn hex8(bytes: &[u8]) -> String {
    bytes.iter().take(8).map(|b| format!("{b:02x}")).collect::<String>() + "…"
}

/// Full-hex encode of a byte string.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `init`: create a new §1.2 root identity + its HPKE sealing keypair and show the resulting
/// address material — the real key generation, with the durable-keystore write and the naming/KT
/// publish honestly called out as the network-bound seams (this binary carries no keystore/socket
/// layer; those live in the node runtime and the naming crate).
fn init_identity() {
    use dmtap::identity::IdentityKey;
    use dmtap::mote::SealKeypair;

    // A real Ed25519 root identity (spec §1.2) and the X25519 sealing keypair peers seal to (§5.3).
    let ik = IdentityKey::generate();
    let seal = SealKeypair::generate();
    let ik_pub = ik.public();

    println!("Envoir node — new identity (spec §1.2)\n");
    println!("  root identity key (Ed25519, hex) : {}", hex(&ik_pub));
    // The §3.9.1 8-word key-name: the safety-number/verbal fingerprint of the identity key.
    println!("  key-name (§3.9.1, 8 words)        : {}", dmtap::keyname::encode(&ik_pub));
    println!("  sealing key (X25519 HPKE, hex)    : {}", hex(seal.public()));
    println!("  default suite                     : {:?}", Suite::Classical);
    println!(
        "\nGenerated in memory. Persisting this identity to a durable keystore and publishing the\n\
         Identity + KeyPackages to naming/key-transparency (spec §1.2, §3, §5.3) are network-bound\n\
         steps handled by the node runtime and the `dmtap-naming` crate — not this scaffold binary."
    );
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
            init_identity();
        }
        "run" => {
            // The real `run` starts the libp2p mesh (Kad/Relay/DCUtR/AutoNAT/mDNS), mixnet client,
            // and MLS delivery service (spec §4/§5) — those transports are a separate frontier
            // task, abstracted behind `dmtap::transport::Transport`. What IS implemented is the
            // delivery engine (`dmtap::node`): identity + MOTE store + the §20.1 sender-retry queue
            // and §20.2 inbound validation. This demo drives it over the in-process transport so
            // the whole seal → validate → decrypt → ack path is observable end-to-end.
            run_delivery_demo();
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

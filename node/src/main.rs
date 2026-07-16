//! Envoir reference node — CLI entry point.
//!
//! The node is the whole client side (spec §0.2): identity, mailbox, mesh participation, delivery,
//! messaging, files, and client protocols. It *is* the mesh. See the DMTAP spec repo (../dmtap/).
//!
//! Unlike the earlier scaffold, `init` and `run` are now **real**: `init` writes a durable keystore
//! to disk (encrypted-at-rest with a passphrase, or a clearly-marked plaintext-for-dev keystore) and
//! prints the `_dmtap` DNS record to publish; `run` loads that identity + the durable outbound
//! journal and runs a long-lived daemon with graceful shutdown. Configuration is via environment
//! (see [`dmtap::config`]).

use std::error::Error;

use dmtap::config::NodeConfig;
use dmtap::keystore::Keystore;
use dmtap::{daemon, Suite};

/// `init`: generate a new §1.2 root identity + X25519 sealing keypair, persist them to the durable
/// keystore under the configured data dir, and print the address material + the `_dmtap` DNS TXT
/// record an operator publishes (§3.2). Refuses to overwrite an existing keystore unless
/// `ENVOIR_FORCE_INIT` is set (so a re-run never silently destroys an identity).
fn init_identity(config: &NodeConfig) -> Result<(), Box<dyn Error>> {
    let path = config.keystore_path();
    let force = std::env::var("ENVOIR_FORCE_INIT").map(|v| v == "1").unwrap_or(false);
    if Keystore::exists(&path) && !force {
        eprintln!(
            "envoir-node: keystore already exists at {} — refusing to overwrite \
             (set ENVOIR_FORCE_INIT=1 to replace the identity).",
            path.display()
        );
        return Ok(());
    }

    let now = daemon::now_ms();
    let ks = Keystore::generate(
        now,
        config.names.clone(),
        config.kt_anchors.clone(),
        config.keypkgs_loc.clone(),
    )?;
    ks.save(&path, config.passphrase.as_deref())?;

    let enc = if config.passphrase.is_some() {
        "encrypted (argon2id + chacha20poly1305)"
    } else {
        "PLAINTEXT-for-dev (set ENVOIR_PASSPHRASE to encrypt)"
    };

    println!("Envoir node — new identity (spec §1.2)\n");
    println!("  keystore                          : {} [{}]", path.display(), enc);
    // §3.9.1 / §3.2 base64url — the spec wire encoding for keys (fixes the old hex output).
    println!("  root identity key (Ed25519, b64url): {}", b64(&ks.ik_public));
    println!("  key-name (§3.9.1, 8 words)        : {}", dmtap::keyname::encode(&ks.ik_public));
    println!("  sealing key (X25519 HPKE, b64url) : {}", b64(&ks.seal_public));
    println!("  default suite                     : {:?}", Suite::Classical);
    println!("\nPublish this `_dmtap` TXT record so peers can resolve you (spec §3.2):\n");
    println!("  {}._dmtap.<zone>  TXT  \"{}\"", record_owner(config), daemon::dmtap_txt_record(&ks));
    println!(
        "\nNOTE: the `kt=` anchor + `keypkgs=` locator above are operator config \
         (ENVOIR_KT_ANCHORS / ENVOIR_KEYPKGS_LOC); the recovery policy (§1.4) is a separate object.\n\
         Start the node with `envoir-node run`."
    );
    Ok(())
}

/// The left-most label an operator would place the TXT record under (a hint; the real owner name is
/// derived from the claimed name's local-part, §3.2). Falls back to `_self` when no name is set.
fn record_owner(config: &NodeConfig) -> String {
    config
        .names
        .first()
        .and_then(|n| n.split('@').next())
        .filter(|s| !s.is_empty())
        .unwrap_or("_self")
        .to_string()
}

/// `record`: reload the keystore and print just the `_dmtap` TXT record (operator convenience).
fn print_record(config: &NodeConfig) -> Result<(), Box<dyn Error>> {
    let path = config.keystore_path();
    if !Keystore::exists(&path) {
        eprintln!("envoir-node: no keystore at {} — run `envoir-node init` first.", path.display());
        return Ok(());
    }
    let ks = Keystore::load(&path, config.passphrase.as_deref())?;
    println!("{}._dmtap.<zone>  TXT  \"{}\"", record_owner(config), daemon::dmtap_txt_record(&ks));
    Ok(())
}

/// `run` / `serve`: the real long-running daemon. Builds a current-thread tokio runtime and serves
/// until SIGINT/SIGTERM.
fn run_daemon(config: NodeConfig) -> Result<(), Box<dyn Error>> {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    rt.block_on(async move { daemon::serve(config).await })?;
    Ok(())
}

/// `serve-mail`: start only the §8 client servers on the configured interface (default `0.0.0.0`,
/// so a container port-map reaches them — the old demo hardcoded `127.0.0.1`) and park. A no-keystore
/// run still works (the servers use a demo store); `run` is the full node.
fn serve_mail(config: &NodeConfig) -> Result<(), Box<dyn Error>> {
    let servers = daemon::start_mail_servers(config)?;
    println!("Envoir §8 client servers (spec §8) — user {}", config.names.first().map(String::as_str).unwrap_or("owner@dmtap.local"));
    println!(
        "  IMAP {}  POP3 {}  SMTP-submission {}",
        servers.imap_addr, servers.pop3_addr, servers.smtp_addr
    );
    println!("Press Ctrl-C to stop.");
    // Park on the listener threads; they run until the process is signalled.
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    rt.block_on(daemon::shutdown_signal());
    println!("envoir-node: serve-mail stopping.");
    Ok(())
}

/// Demo: two in-process nodes exchange a real end-to-end-encrypted MOTE (spec §2, §19.3, §20).
/// The former `run` behavior, kept as `demo` for a zero-setup end-to-end sanity check.
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

    alice.poll();
    println!("A: outbound state = {:?} (delivered)", alice.outbound_state(&id).unwrap());
}

/// First 8 bytes of a content id as hex, for compact logging.
fn hex8(bytes: &[u8]) -> String {
    bytes.iter().take(8).map(|b| format!("{b:02x}")).collect::<String>() + "…"
}

/// Unpadded base64url (spec §3.2/§3.9.1) — the wire key encoding.
fn b64(bytes: &[u8]) -> String {
    dmtap::names::base64url::encode(bytes)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("help");
    let config = NodeConfig::from_env();

    let result: Result<(), Box<dyn Error>> = match cmd {
        "version" => {
            println!("envoir-node {} (pre-alpha)", env!("CARGO_PKG_VERSION"));
            println!("default suite: {:?}", Suite::Classical);
            Ok(())
        }
        "init" => init_identity(&config),
        "record" => print_record(&config),
        "run" | "serve" => run_daemon(config),
        "serve-mail" => serve_mail(&config),
        "demo" => {
            run_delivery_demo();
            Ok(())
        }
        "gateway" => {
            eprintln!("run the dedicated `envoir-gateway` binary — see ../gateway/ and spec §7");
            Ok(())
        }
        _ => {
            println!(
                "envoir-node — Decentralized Message Transfer & Access Protocol (reference)\n\
                 \n\
                 USAGE:\n\
                 \x20 envoir-node <command>\n\
                 \n\
                 COMMANDS:\n\
                 \x20 init         generate + persist a new identity keystore; print the _dmtap record\n\
                 \x20 run          run the node daemon (mesh + delivery + §8 clients), until SIGINT/SIGTERM\n\
                 \x20 record       print this identity's _dmtap DNS TXT record\n\
                 \x20 serve-mail   run only the §8 client servers (IMAP/POP/SMTP) on the configured bind\n\
                 \x20 demo         two in-process nodes exchange a real E2E-encrypted MOTE\n\
                 \x20 version      print version and default suite\n\
                 \x20 help         show this help\n\
                 \n\
                 CONFIG (env): ENVOIR_DATA_DIR, ENVOIR_NODE_BIND, ENVOIR_MAIL_HOST, ENVOIR_IMAP_PORT,\n\
                 \x20 ENVOIR_POP3_PORT, ENVOIR_SMTP_PORT, ENVOIR_PASSPHRASE, ENVOIR_NAMES,\n\
                 \x20 ENVOIR_KT_ANCHORS, ENVOIR_KEYPKGS_LOC, ENVOIR_TICK_SECS. See `dmtap::config`.\n\
                 \n\
                 Spec: ../dmtap/  (the DMTAP spec repo is normative; this binary is a reference)."
            );
            Ok(())
        }
    };

    if let Err(e) = result {
        eprintln!("envoir-node: {e}");
        std::process::exit(1);
    }
}

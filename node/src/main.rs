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
//!
//! ## Gateway mode and privilege separation
//!
//! Spec §0.2 allows "the gateway MAY be the node binary run in `--gateway` mode" — `envoir-node
//! gateway <args>` (or `envoir-node --gateway <args>`) is that mode. Gateway duty terminates
//! untrusted legacy SMTP/IMAP/POP3 connections on the open internet and runs the corresponding
//! parsers, historically the most exploited code in mail; it MUST NOT run in a process that has,
//! or could ever load, this node's `IK`, device keys, or MOTE store.
//!
//! This binary satisfies that by **never linking the gateway's code in at all** — `envoir-gateway`
//! (`../gateway`) has zero dependency on this crate and vice versa, so the node executable cannot
//! contain gateway parser code in its address space even in principle. `--gateway` dispatch
//! ([`run_gateway_mode`]) is the very first thing [`main`] checks, before [`NodeConfig::from_env`]
//! or any keystore access, and it hands off to the **separate, already-built** `envoir-gateway`
//! executable as a genuinely separate OS process (via `exec` on Unix, replacing this process's
//! image entirely; via spawn+wait elsewhere) — so a `envoir-node gateway` invocation never shares
//! a process, and therefore never shares an address space, with a `envoir-node run` invocation that
//! holds identity key material. See `run_gateway_mode`'s doc for the precise `TODO(privsep)` that
//! remains.

use std::path::PathBuf;

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
    println!("B: INBOX now holds {} message(s) (JMAP-visible)", bob.inbox().exists());

    alice.poll();
    println!("A: outbound state = {:?} (delivered)", alice.outbound_state(&id).unwrap());
}

/// Find the dedicated `envoir-gateway` executable, in priority order:
///
/// 1. `ENVOIR_GATEWAY_BIN` — an explicit operator override (a custom install location, a wrapper
///    script, a different privilege-separated launcher).
/// 2. Next to this `envoir-node` executable — where `cargo build --workspace` / a release archive
///    puts both binaries by default, so `envoir-node gateway` works with zero configuration.
/// 3. Otherwise, the bare command name, left for the OS to resolve against `PATH` at exec time.
fn locate_gateway_binary() -> PathBuf {
    if let Ok(p) = std::env::var("ENVOIR_GATEWAY_BIN") {
        return PathBuf::from(p);
    }
    let bin_name = if cfg!(windows) { "envoir-gateway.exe" } else { "envoir-gateway" };
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join(bin_name);
            if candidate.is_file() {
                return candidate;
            }
        }
    }
    PathBuf::from(bin_name)
}

/// Dispatch `--gateway`/`gateway` to the dedicated `envoir-gateway` binary as a genuinely separate
/// OS process — see the module-level privilege-separation note. Never returns: on Unix the process
/// image is replaced outright (`exec`, so there is no lingering parent and nothing of this
/// process's memory survives); elsewhere this process waits for the child and exits with its
/// status code.
///
/// TODO(privsep): today this relies on locating a sibling executable at runtime (env override,
/// then "next to `envoir-node`", then `PATH`) rather than a single self-contained multicall
/// binary; a hardened deployment would also drop privileges / apply seccomp-or-equivalent before
/// the gateway process touches its listening sockets, and would pass any configuration that must
/// cross this boundary through an explicit, minimal channel rather than inherited env/argv. None
/// of that is required for the address-space-separation guarantee above, which already holds
/// today because `envoir-gateway` is a distinct executable this crate never links against.
fn run_gateway_mode(gateway_args: &[String]) -> ! {
    let bin = locate_gateway_binary();

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // `exec` only returns if it FAILED to replace the process image — it never returns on
        // success, so anything after this call is strictly an error path.
        let err = std::process::Command::new(&bin).args(gateway_args).exec();
        eprintln!(
            "envoir-node: gateway: failed to exec {} ({err}) — build it with \
             `cargo build --workspace` (it ships next to envoir-node), or point \
             ENVOIR_GATEWAY_BIN at its path.",
            bin.display()
        );
        std::process::exit(1);
    }
    #[cfg(not(unix))]
    {
        match std::process::Command::new(&bin).args(gateway_args).status() {
            Ok(status) => std::process::exit(status.code().unwrap_or(1)),
            Err(e) => {
                eprintln!(
                    "envoir-node: gateway: failed to launch {} ({e}) — build it with \
                     `cargo build --workspace` (it ships next to envoir-node), or point \
                     ENVOIR_GATEWAY_BIN at its path.",
                    bin.display()
                );
                std::process::exit(1);
            }
        }
    }
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

    // Gateway dispatch happens FIRST — before `NodeConfig::from_env()` or any keystore access —
    // so a `envoir-node gateway`/`envoir-node --gateway` invocation never touches this node's
    // identity/config code at all. See the module doc's privilege-separation note.
    if cmd == "gateway" || cmd == "--gateway" {
        run_gateway_mode(&args[2..]);
    }

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
        "demo" => {
            run_delivery_demo();
            Ok(())
        }
        // "gateway" / "--gateway" are handled above, before `config` is even built — they never
        // reach this match. Listed in the help text below for discoverability.
        _ => {
            println!(
                "envoir-node — Decentralized Message Transfer & Access Protocol (reference)\n\
                 \n\
                 USAGE:\n\
                 \x20 envoir-node <command>\n\
                 \n\
                 COMMANDS:\n\
                 \x20 init             generate + persist a new identity keystore; print the _dmtap record\n\
                 \x20 run              run the native node daemon (mesh + delivery + Send API), until SIGINT/SIGTERM\n\
                 \x20 record           print this identity's _dmtap DNS TXT record\n\
                 \x20 demo             two in-process nodes exchange a real E2E-encrypted MOTE\n\
                 \x20 gateway <args>   run the legacy SMTP/IMAP/POP3 bridge (spec §7) as a SEPARATE\n\
                 \x20                  process (execs the dedicated envoir-gateway binary — see below);\n\
                 \x20                  `--gateway <args>` is accepted as an alias\n\
                 \x20 version          print version and default suite\n\
                 \x20 help             show this help\n\
                 \n\
                 The node itself is native-only (spec §8.5): mesh + JMAP (§8.1) + Send API. Legacy\n\
                 IMAP/POP/SMTP surfaces are gateway duty (spec §7) — the one component that terminates\n\
                 untrusted internet connections and parses legacy mail formats. `envoir-node gateway`\n\
                 is that role \"the node binary run in --gateway mode\" (spec §0.2): it hands off to the\n\
                 dedicated `envoir-gateway` executable (built alongside this one by\n\
                 `cargo build --workspace`) as a genuinely separate OS process — never in-process,\n\
                 so a gateway invocation never shares memory with one holding this node's identity\n\
                 key. `envoir-node gateway help` shows the gateway's own commands; see gateway/README.md.\n\
                 \n\
                 CONFIG (env): ENVOIR_DATA_DIR, ENVOIR_NODE_BIND, ENVOIR_PASSPHRASE, ENVOIR_NAMES,\n\
                 \x20 ENVOIR_KT_ANCHORS, ENVOIR_KEYPKGS_LOC, ENVOIR_TICK_SECS,\n\
                 \x20 ENVOIR_SUPERVISED (=1: `run` treats stdin EOF as shutdown — for a supervising shell),\n\
                 \x20 ENVOIR_SEND_API, ENVOIR_SEND_API_BIND, ENVOIR_SEND_ADMIN_TOKEN (Envoir Send §13.5.1),\n\
                 \x20 ENVOIR_GATEWAY_BIN (override where `gateway`/`--gateway` looks for envoir-gateway).\n\
                 \x20 See `dmtap::config`.\n\
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

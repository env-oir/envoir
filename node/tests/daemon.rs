//! Daemon lifecycle + persistence integration tests (spec §0.2, §1.2, §19.3.3, §3).
//!
//! These prove the reference node is now a **real daemon**, not a one-shot demo:
//! 1. `init` writes a durable keystore that round-trips the identity across a process restart, and
//!    the daemon reloads that identity + the persisted outbound journal on startup.
//! 2. the steady-state loop runs on a tick and shuts down gracefully, committing a final checkpoint.
//! 3. a *running* node resolves a peer by name (§3) over the real `dmtap_naming` seams and delivers.

use std::path::PathBuf;
use std::time::Duration;

use dmtap::config::NodeConfig;
use dmtap::daemon::{load_node, run_loop};
use dmtap::identity::{Identity, IdentityKey, KeyPackageBundleRef};
use dmtap::journal::FileJournal;
use dmtap::keystore::Keystore;
use dmtap::mote::SealKeypair;
use dmtap::names::{DmtapTxtRecord, InMemoryKeyPackages, InMemoryKtLog, InMemoryResolver};
use dmtap::naming::seal_key_bundle;
use dmtap::node::Node;
use dmtap::transport::{InMemoryNetwork, TcpTransport};
use dmtap::{ContentId, Journal};

const NOW: u64 = 1_700_000_000_000;

fn temp_dir(tag: &str) -> PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let p = std::env::temp_dir().join(format!("envoir-daemon-{}-{}-{}", std::process::id(), tag, n));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn test_config(data_dir: PathBuf) -> NodeConfig {
    NodeConfig {
        data_dir,
        node_bind: "127.0.0.1:0".to_string(), // ephemeral port — no fixed-port collisions in CI
        mail_enabled: false,
        passphrase: None,
        tick: Duration::from_millis(5),
        ..NodeConfig::default()
    }
}

/// `init` persists an identity; a fresh `load_node` rebuilds the SAME identity and **resumes** the
/// outbound retry queue from the durable journal (spec §1.2 identity durability, §19.3.3 queue).
#[test]
fn daemon_loads_persisted_identity_and_resumed_journal_on_startup() {
    let dir = temp_dir("resume");
    let config = test_config(dir.clone());

    // `init`: generate + persist the keystore.
    let ks = Keystore::generate(NOW, vec!["me@example.com".into()], vec!["https://kt/log".into()], "/kp")
        .unwrap();
    ks.save(&config.keystore_path(), None).unwrap();
    let expected_ik = ks.ik_public.clone();

    // Pre-populate the durable journal with a stuck (unreachable) send, exactly as a running node
    // would have, using the SAME persisted identity so the resume is faithful.
    {
        let net = InMemoryNetwork::new();
        let t = net.endpoint(ks.ik_public.clone());
        let journal = Box::new(FileJournal::new(config.journal_path()));
        let mut node = Node::with_journal_bytes(
            ks.identity_key(),
            ks.seal_secret(),
            ks.seal_public,
            t,
            journal,
        )
        .unwrap();
        // Learn a peer's sealing key but never register it on the fabric ⇒ dispatch is Unreachable ⇒
        // the MOTE stays in the retry queue and is checkpointed to the journal.
        let peer = IdentityKey::from_seed(&[9u8; 32]).public();
        node.learn_key(&peer, [7u8; 32]);
        let _id: ContentId = node.send_mail(&peer, "queued", b"survive a restart").expect("queued");
        assert_eq!(node.outbound_len(), 1);
        // The journal on disk now holds the queued MOTE.
        let snap = FileJournal::new(config.journal_path()).load().unwrap();
        assert_eq!(snap.outbound.len(), 1, "queued MOTE is durable on disk");
    }

    // Startup: the daemon loads the node from the data dir — same identity, resumed queue.
    let node = load_node(&config).expect("daemon loads persisted node");
    assert_eq!(node.ik_public(), expected_ik, "same identity reloaded across restart");
    assert_eq!(node.outbound_len(), 1, "outbound retry queue resumed from journal (§19.3.3)");

    std::fs::remove_dir_all(&dir).ok();
}

/// A no-keystore data dir fails closed with a clear "run init first" error (not a silent new identity).
#[test]
fn daemon_refuses_to_start_without_a_keystore() {
    let dir = temp_dir("nokeystore");
    let config = test_config(dir.clone());
    let err = match load_node(&config) {
        Err(e) => e,
        Ok(_) => panic!("expected a no-keystore error, got a node"),
    };
    assert!(format!("{err}").contains("run `envoir-node init`"), "actionable error: {err}");
    std::fs::remove_dir_all(&dir).ok();
}

/// The steady-state loop ticks and then shuts down gracefully, committing a final durable checkpoint.
#[tokio::test]
async fn run_loop_ticks_then_shuts_down_gracefully() {
    let net = InMemoryNetwork::new();
    let ik = IdentityKey::generate();
    let t = net.endpoint(ik.public());
    // A FileJournal so the final graceful checkpoint is a real on-disk write.
    let dir = temp_dir("shutdown");
    let journal = Box::new(FileJournal::new(dir.join("journal.json")));
    let mut node = Node::with_journal(ik, SealKeypair::generate(), t, journal).unwrap();

    // Shutdown after ~40ms; with a 5ms tick the loop runs several iterations first.
    let shutdown = tokio::time::sleep(Duration::from_millis(40));
    let stats = run_loop(&mut node, Duration::from_millis(5), shutdown).await;

    assert!(stats.ticks >= 1, "the loop ran at least one tick before shutdown");
    assert!(stats.flushed_ok, "graceful shutdown committed a final durable checkpoint");
    std::fs::remove_dir_all(&dir).ok();
}

/// A **running** node (driven by the daemon loop) resolves a peer by name over the real
/// `dmtap_naming` KT-verified seams and delivers a MOTE to the resolved key (spec §3, §19.3).
#[tokio::test]
async fn running_daemon_resolves_and_delivers_by_name() {
    // --- Bob: a resolvable identity + a live node built from the same seed/seal ---
    let bob_seed = [3u8; 32];
    let bob_id_key = IdentityKey::from_seed(&bob_seed);
    let bob_ik = bob_id_key.public();
    let bob_seal = SealKeypair::generate();
    let bob_seal_pub = *bob_seal.public();

    let mut bob_kps = InMemoryKeyPackages::new();
    let bref: KeyPackageBundleRef =
        bob_kps.publish("/mesh/kp/bob", seal_key_bundle(&bob_seal_pub));
    let bob_identity = Identity::create_classical(
        &bob_id_key,
        0,
        vec![],
        bref.clone(),
        ContentId::of(b"recovery"),
        vec!["bob@example.com".into()],
        None,
        NOW,
    );
    let bob_txt = DmtapTxtRecord {
        version: "dmtap1".into(),
        suite: 1,
        ik: bob_ik.clone(),
        id: bob_identity.content_id(),
        kt: vec!["https://kt.example/log".into()],
        keypkgs: bref.loc.clone(),
    }
    .to_txt();

    // Bob's live node over TCP (its listener thread is the mesh ingress the daemon loop drains).
    let bob_transport = TcpTransport::bind(bob_ik.clone(), "127.0.0.1:0").unwrap();
    let bob_socket = bob_transport.local_socket_addr();
    let mut bob = Node::with_identity(bob_id_key, bob_seal, bob_transport);

    // --- Alice: resolves Bob by NAME (KT-verified) and dispatches over TCP ---
    let mut resolver = InMemoryResolver::new(NOW);
    resolver.set_txt("bob._dmtap.example.com", &bob_txt);
    resolver.publish_identity(bob_identity.clone());
    let mut log = InMemoryKtLog::new(IdentityKey::from_seed(&[9u8; 32]));
    log.append_identity("bob@example.com", &bob_identity).unwrap();
    resolver.pin_log(log);
    let mut kps = InMemoryKeyPackages::new();
    kps.publish("/mesh/kp/bob", seal_key_bundle(&bob_seal_pub));

    let alice_ik = IdentityKey::generate();
    let alice_ik_pub = alice_ik.public();
    let alice_seal = SealKeypair::generate();
    let alice_transport = TcpTransport::bind(alice_ik_pub.clone(), "127.0.0.1:0").unwrap();
    // The "directory" wiring: Alice learns Bob's mesh socket for the resolved address.
    alice_transport.add_peer(bob_ik.clone(), bob_socket);
    let mut alice = Node::with_identity(alice_ik, alice_seal, alice_transport);
    // Bob knows Alice (so she is not classified as a cold sender at §2.7 step 5).
    bob.add_contact(&alice_ik_pub, alice.seal_public());

    // Resolve + seal + dispatch over TCP — the frame lands in Bob's transport inbox.
    let body = b"resolved you by name, KT-verified, over a running node";
    alice
        .send_mail_to_name("bob@example.com", &resolver, &kps, "hi", body)
        .expect("name-addressed send");

    // Run Bob's daemon loop; it polls the inbound MOTE, validates, stores, and acks. Shut it down
    // after a short window (enough ticks at 5ms to drain + process).
    let shutdown = tokio::time::sleep(Duration::from_millis(120));
    let stats = run_loop(&mut bob, Duration::from_millis(5), shutdown).await;

    assert!(stats.inbound >= 1, "the running loop observed the inbound MOTE");
    assert_eq!(bob.inbox().exists(), 1, "delivered to the KT-resolved key via the running node");
    let raw = &bob.inbox().messages[0].raw;
    assert!(raw.windows(body.len()).any(|w| w == body), "correct plaintext delivered");
}

/// Sanity: two consecutive `Keystore` loads of the same encrypted keystore reconstruct an identical
/// node identity — the property daemon restart relies on (spec §1.2).
#[test]
fn encrypted_keystore_backed_identity_is_stable_across_reload() {
    let dir = temp_dir("stable");
    let mut config = test_config(dir.clone());
    config.passphrase = Some("s3cret".into());

    let ks = Keystore::generate(NOW, vec![], vec![], "/kp").unwrap();
    ks.save(&config.keystore_path(), config.passphrase.as_deref()).unwrap();
    let want = ks.ik_public.clone();

    let a = Keystore::load(&config.keystore_path(), config.passphrase.as_deref()).unwrap();
    let b = Keystore::load(&config.keystore_path(), config.passphrase.as_deref()).unwrap();
    assert_eq!(a.identity_key().public(), want);
    assert_eq!(b.identity_key().public(), want);
    assert_eq!(a.seal_public, b.seal_public);
    std::fs::remove_dir_all(&dir).ok();
}

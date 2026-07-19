//! The long-running node daemon (spec §0.2).
//!
//! The node is **native-only** (spec §8.5): it serves the libp2p mesh, JMAP (§8.1 — the node's
//! native and only client surface), and the optional Envoir Send API (§13.5.1). The legacy
//! IMAP/POP3/SMTP-submission surfaces live **only on the separate gateway** and are no longer
//! started here.
//!
//! This turns the reference node from a one-shot in-process demo into a **persistent process**: it
//! loads the identity from the durable [`Keystore`] and the outbound retry queue from the
//! [`FileJournal`] (spec §19.3.3 — the queue MUST survive restart), binds its mesh transport on a
//! **configurable** interface (defaulting to `0.0.0.0` so a container port-map reaches it), then
//! stays up — draining inbound MOTEs, firing retries, and expiring deadlines on a fixed tick —
//! until SIGINT/SIGTERM, on which it flushes a final durable checkpoint and exits cleanly.
//!
//! ## What is real vs. an honest seam
//! - **Real:** identity + sealing-key reload from disk; journal resume; the [`TcpTransport`] mesh
//!   ingress (a background accept loop feeding [`Node::poll`]); the retry/deadline engine; graceful
//!   shutdown.
//! - **Seam (name resolution, §3):** a running node resolves + delivers **by name** through the real
//!   [`dmtap_naming::Resolver`] / [`KeyPackageSource`](dmtap_naming::KeyPackageSource) seams already
//!   wired into [`Node::send_mail_to_name`]. The *networked* DNS `_dmtap` + KT-log clients behind
//!   those traits are the remaining swap — [`resolver_seam`] returns the in-memory harness and logs
//!   that live DNS is not yet wired, rather than silently pretending to resolve. The
//!   `daemon_resolves_and_delivers_by_name` integration test drives the whole path against a live,
//!   running node.
//! - **Real (JMAP, §8.1):** the node's native + only client-sync surface. [`serve`] binds a
//!   node-native JMAP listener ([`crate::jmap_api`]) behind [`NodeConfig::jmap_enabled`], serving
//!   [`dmtap_mail::jmap`] over the node's **live** MOTE store (so a client sees actual delivered
//!   mail) with app-password auth (fail-closed). It binds **loopback** by default; an off-localhost
//!   bind is refused fail-closed (JMAP terminates TLS on the node, spec §8.2 — front it with TLS).

use std::future::Future;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dmtap_core::identity::{Identity, IdentityKey, KeyPackageBundleRef};
use dmtap_core::id::ContentId;
use dmtap_core::TimestampMs;

use crate::config::NodeConfig;
use crate::journal::{FileJournal, JournalError};
use crate::keystore::{Keystore, KeystoreError};
use crate::naming::seal_key_bundle;
use crate::node::Node;
use crate::transport::{TcpTransport, Transport};

/// A placeholder recovery-policy content address for the generated `Identity` (spec §1.4). The real
/// recovery policy (guardians / threshold, §1.4) is a separate object the operator provisions; this
/// keeps the `Identity` well-formed + content-addressable so its `id=` in the `_dmtap` record is real.
const RECOVERY_PLACEHOLDER: &[u8] = b"envoir-node/recovery-policy/unset";

/// Why the daemon could not start or run.
#[derive(Debug)]
pub enum DaemonError {
    /// The keystore is missing — run `envoir-node init` first.
    NoKeystore(std::path::PathBuf),
    /// Loading/decrypting the keystore failed.
    Keystore(KeystoreError),
    /// Binding a listener (mesh transport or the Send API) failed.
    Bind(std::io::Error),
    /// Resuming the durable journal failed.
    Journal(JournalError),
    /// The JMAP listener was configured to bind an off-localhost interface without TLS. JMAP
    /// terminates TLS on the node (spec §8.2) and this listener speaks plain HTTP, so a non-loopback
    /// bind is refused fail-closed — front it with a TLS reverse proxy (and point `ENVOIR_JMAP_BASE_URL`
    /// at it), or keep the default loopback bind.
    JmapInsecureBind(String),
}

impl std::fmt::Display for DaemonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DaemonError::NoKeystore(p) => {
                write!(f, "no keystore at {} — run `envoir-node init` first", p.display())
            }
            DaemonError::Keystore(e) => write!(f, "{e}"),
            DaemonError::Bind(e) => write!(f, "bind failed: {e}"),
            DaemonError::Journal(e) => write!(f, "journal resume failed: {e}"),
            DaemonError::JmapInsecureBind(bind) => write!(
                f,
                "refusing to serve JMAP on non-loopback bind {bind} without TLS (spec §8.2): \
                 bind loopback (default 127.0.0.1:4700) or front it with a TLS reverse proxy"
            ),
        }
    }
}
impl std::error::Error for DaemonError {}
impl From<KeystoreError> for DaemonError {
    fn from(e: KeystoreError) -> Self {
        DaemonError::Keystore(e)
    }
}
impl From<JournalError> for DaemonError {
    fn from(e: JournalError) -> Self {
        DaemonError::Journal(e)
    }
}

/// What one run of the daemon loop did (for logging/tests).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LoopStats {
    /// Number of tick iterations executed before shutdown.
    pub ticks: u64,
    /// Inbound MOTE dispositions observed across all ticks.
    pub inbound: u64,
    /// Retry re-dispatches performed across all ticks.
    pub retried: u64,
    /// Whether the final durable checkpoint on shutdown succeeded.
    pub flushed_ok: bool,
}

/// Load the persisted identity + sealing key and rebuild a journal-backed [`Node`] over a
/// [`TcpTransport`] bound to `config.node_bind`. The node **resumes** its outbound retry queue from
/// the durable journal (§19.3.3). Fails closed if no keystore exists (run `init` first).
pub fn load_node(config: &NodeConfig) -> Result<Node<TcpTransport>, DaemonError> {
    let ks_path = config.keystore_path();
    if !Keystore::exists(&ks_path) {
        return Err(DaemonError::NoKeystore(ks_path));
    }
    let ks = Keystore::load(&ks_path, config.passphrase.as_deref())?;
    let ik = ks.identity_key();
    let addr = ik.public();
    let transport = TcpTransport::bind(addr, &config.node_bind).map_err(DaemonError::Bind)?;
    let journal = Box::new(FileJournal::new(config.journal_path()));
    let node = Node::with_journal_bytes(ik, ks.seal_secret(), ks.seal_public, transport, journal)?;
    Ok(node)
}

/// The daemon's steady-state loop: on every `tick`, drain inbound MOTEs (§20.2), fire due retries
/// (§20.1), and expire deadlines (§16.1); each mutation is checkpointed to the journal by the node.
/// Runs until `shutdown` resolves, then flushes a final durable checkpoint and returns. Generic over
/// the transport so tests drive it over TCP or the in-process fabric.
pub async fn run_loop<T: Transport>(
    node: &mut Node<T>,
    tick: Duration,
    shutdown: impl Future<Output = ()>,
) -> LoopStats {
    tokio::pin!(shutdown);
    let mut interval = tokio::time::interval(tick);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut stats = LoopStats::default();
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => break,
            _ = interval.tick() => {
                node.set_now(now_ms());
                let inbound = node.poll();
                stats.inbound += inbound.len() as u64;
                // Deliver any inbound group application messages buffered by `poll` (§5.4) — the real
                // daemon must drain + deliver them, not just the tests.
                node.pump_group_inbox();
                stats.retried += node.retry_pending() as u64;
                node.tick_deadlines();
                stats.ticks += 1;
            }
        }
    }
    // Graceful shutdown: one last durable checkpoint so nothing in-flight is lost (§19.3.3).
    stats.flushed_ok = node.flush().is_ok();
    stats
}

/// How often the supervised-mode shutdown future re-checks the stdin-EOF flag. Coarse is fine: this
/// bounds only how long an *orphaned* daemon lingers after its supervisor died, not request latency.
const SUPERVISED_POLL: Duration = Duration::from_millis(200);

/// A future that resolves on SIGINT (Ctrl-C) or, on unix, SIGTERM — the container stop signal.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = ctrl_c => {},
                    _ = term.recv() => {},
                }
            }
            // If the SIGTERM handler cannot be installed, still honor Ctrl-C.
            Err(_) => ctrl_c.await,
        }
    }
    #[cfg(not(unix))]
    {
        ctrl_c.await;
    }
}

/// The daemon's shutdown future, extended for **supervised mode** (`ENVOIR_SUPERVISED=1`,
/// [`crate::config::NodeConfig::supervised`]): resolves on SIGINT/SIGTERM as always, and
/// additionally when **stdin reaches EOF**. The supervisor (the desktop shell that spawned this
/// daemon as a sidecar) holds the write end of the stdin pipe for the process's whole life; if the
/// shell dies — even abnormally, with no chance to signal — the OS closes the pipe, stdin EOFs, and
/// the daemon shuts itself down instead of lingering as an orphan. Signals alone cannot cover that
/// case: a crashed supervisor sends nothing.
pub async fn shutdown_signal_supervised(supervised: bool) {
    if !supervised {
        return shutdown_signal().await;
    }
    let eof = watch_reader_eof(std::io::stdin());
    tokio::select! {
        _ = shutdown_signal() => {}
        _ = flag_raised(eof) => {
            eprintln!("envoir-node: stdin closed — supervisor gone (ENVOIR_SUPERVISED=1); shutting down");
        }
    }
}

/// Spawn a **detached** OS thread that drains `reader` to EOF, then raise the returned flag.
///
/// Why a plain `std::thread` over `tokio::io::stdin()`: tokio's stdin is itself a blocking read on
/// a worker thread, and a read blocked on an open-but-idle stdin would stall the runtime's own
/// drop-time shutdown (blocking tasks are waited on). A detached thread costs nothing at process
/// exit — it simply dies with the process — so a SIGTERM'd supervised daemon still exits promptly
/// even though its supervisor never closed the pipe. Any bytes read before EOF are discarded:
/// supervised-mode stdin is a *liveness channel*, never a command channel (commands on stdin would
/// invite injection from whatever inherited the pipe).
pub fn watch_reader_eof<R: io::Read + Send + 'static>(mut reader: R) -> Arc<AtomicBool> {
    let flag = Arc::new(AtomicBool::new(false));
    let raised = flag.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 256];
        loop {
            match reader.read(&mut buf) {
                // EOF — or a read error, which also means the pipe is unusable: treat both as
                // "supervisor gone" (fail-closed toward shutting down, never toward lingering).
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        raised.store(true, Ordering::SeqCst);
    });
    flag
}

/// Resolve once `flag` is raised. Polled on [`SUPERVISED_POLL`] — a plain atomic + interval rather
/// than a channel because the node crate's tokio has no `sync` feature, and a 200ms orphan-detection
/// latency is far below the cost of enabling one for this alone.
pub async fn flag_raised(flag: Arc<AtomicBool>) {
    while !flag.load(Ordering::SeqCst) {
        tokio::time::sleep(SUPERVISED_POLL).await;
    }
}

/// Start and run the daemon to completion: load the node and run the steady-state loop (mesh +
/// optional Send API) until a shutdown signal. The one call `main`'s `run`/`serve` wraps in a
/// runtime. The node is native-only (spec §8.5) — no legacy §8 servers are started here.
pub async fn serve(config: NodeConfig) -> Result<LoopStats, DaemonError> {
    let mut node = load_node(&config)?;
    let addr = node.ik_public();

    eprintln!("envoir-node: mesh transport bound on {}", config.node_bind);
    eprintln!("envoir-node: node address (ik) {}", dmtap_naming::base64url::encode(&addr));
    eprintln!(
        "envoir-node: resumed {} queued MOTE(s) from {}",
        node.outbound_len(),
        config.journal_path().display()
    );

    eprintln!(
        "envoir-node: name resolution seam — live DNS `_dmtap` + KT clients not wired; \
         resolve/deliver-by-name available via Node::send_mail_to_name over a dmtap_naming::Resolver"
    );
    if config.supervised {
        eprintln!(
            "envoir-node: supervised mode (ENVOIR_SUPERVISED=1) — stdin EOF also triggers shutdown"
        );
    }
    eprintln!("envoir-node: running — SIGINT/SIGTERM to stop");

    // The Envoir Send HTTP API (spec §13.5.1), opt-in. Owner identity = this node's identity
    // (reloaded from the same keystore), so a capability-authorized send seals a MOTE authenticated
    // as from this node and enters the node's real §20.1 outbound path.
    let mut send_api = if config.send_api_enabled {
        let owner_ik = {
            let ks = Keystore::load(&config.keystore_path(), config.passphrase.as_deref())?;
            ks.identity_key()
        };
        Some(crate::send_api::SendApi::new(owner_ik, config.send_admin_token.clone()))
    } else {
        None
    };
    let send_listener = if config.send_api_enabled {
        let l = tokio::net::TcpListener::bind(&config.send_api_bind).await.map_err(DaemonError::Bind)?;
        eprintln!(
            "envoir-node: Envoir Send HTTP API on {} — POST /v1/send (capability Bearer); \
             key-management {}",
            config.send_api_bind,
            if config.send_admin_token.is_some() {
                "enabled (ENVOIR_SEND_ADMIN_TOKEN set)"
            } else {
                "DISABLED (no ENVOIR_SEND_ADMIN_TOKEN)"
            }
        );
        Some(l)
    } else {
        None
    };

    // The node-native JMAP listener (spec §8.1) — the native, and only, client-sync surface, opt-in.
    // Backed by the node's LIVE store (a client sees actual delivered mail), app-password
    // authenticated (fail-closed). Bound loopback by default; an off-localhost bind without TLS is
    // refused fail-closed BEFORE binding (§8.2).
    let jmap_api = if config.jmap_enabled {
        if !config.jmap_bind_is_loopback() {
            return Err(DaemonError::JmapInsecureBind(config.jmap_bind.clone()));
        }
        let account_id = config.jmap_account_id(&addr);
        let base_url = config.jmap_base_url_resolved();
        let app_passwords = config.jmap_app_passwords_resolved(&account_id);
        if app_passwords.is_empty() {
            eprintln!(
                "envoir-node: WARNING — JMAP enabled with NO app-passwords \
                 (ENVOIR_JMAP_APP_PASSWORDS); no client can authenticate (fail-closed)"
            );
        }
        Some(crate::jmap_api::JmapApi::new(account_id, base_url, addr.clone(), &app_passwords))
    } else {
        None
    };
    let jmap_listener = if config.jmap_enabled {
        let l = tokio::net::TcpListener::bind(&config.jmap_bind).await.map_err(DaemonError::Bind)?;
        eprintln!(
            "envoir-node: JMAP listener on {} (account {}) — Basic app-password auth; \
             Session at /jmap/session, API at /jmap/api/{}",
            config.jmap_bind,
            jmap_api.as_ref().map(crate::jmap_api::JmapApi::account_id).unwrap_or(""),
            // The /v1/* Send routes ride on this listener too (one client base URL) when enabled.
            if config.send_api_enabled { "; Envoir Send at /v1/* (capability Bearer)" } else { "" }
        );
        Some(l)
    } else {
        None
    };

    // The DMTAP-PUB gateway (spec §22.5/§22.6) — the node's optional public-object HTTP surface,
    // opt-in. Reads are anonymous (§22.5.1); the capability gate governs whether the operator serves
    // *at all* (§22.6.1). This node self-issues its own `pub-1` capability (audience = itself) and
    // presents it to `enable_with_capability` rather than bypassing the gate with an unconditional
    // `enable()` — the fail-closed verification in `pub1_authorizes` genuinely runs, it is simply
    // this node that both issues and holds the grant (the self-host case: operator == node).
    let pub_gateway = if config.pub_serve_enabled {
        let mut gw = crate::pubserve::PubGateway::new(dmtap_core::pubobj::ServePolicy::default());
        let now = now_ms();
        let owner_ik = {
            let ks = Keystore::load(&config.keystore_path(), config.passphrase.as_deref())?;
            ks.identity_key()
        };
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce)
            .map_err(|_| DaemonError::Bind(io::Error::other("rng failure minting the pub-1 capability")))?;
        let token = dmtap_core::capability::CapabilityToken::issue(
            &owner_ik,
            addr.clone(),
            vec![dmtap_core::capability::Capability {
                resource: crate::pubserve::PUB1_RESOURCE.to_string(),
                ability: crate::pubserve::PUB1_ABILITY.to_string(),
                caveats: None,
            }],
            now.saturating_sub(1_000),
            now.saturating_add(365 * 24 * 60 * 60 * 1000),
            nonce.to_vec(),
            None,
        );
        let enabled = gw.enable_with_capability(&token, &addr, now);
        eprintln!(
            "envoir-node: DMTAP-PUB gateway {} (self-issued pub-1 capability; operator == this node)",
            if enabled { "ENABLED" } else { "FAILED TO ENABLE — capability did not verify" }
        );
        Some(gw)
    } else {
        None
    };
    let pub_listener = if config.pub_serve_enabled {
        let l = tokio::net::TcpListener::bind(&config.pub_bind).await.map_err(DaemonError::Bind)?;
        eprintln!(
            "envoir-node: DMTAP-PUB listener on {} — anonymous reads under {} (feed head/range, \
             announce, manifest, chunk)",
            config.pub_bind,
            crate::pubserve::WELL_KNOWN_BASE
        );
        Some(l)
    } else {
        None
    };

    // The Sync-substrate reconciliation surface (`substrate/SYNC.md` §5.2/§5.3) — opt-in, same
    // shape as the DMTAP-PUB gateway above. This node self-issues its own `sync-1` capability
    // (audience = itself) and presents it to `enable_with_capability`, so the fail-closed
    // verification in `sync1_authorizes` genuinely runs; a *peer* still presents its own `sync-1`
    // Bearer token per request (§5.4), and every op is COSE-verified on ingest regardless.
    let sync_gateway = if config.sync_serve_enabled {
        let owner_ik = {
            let ks = Keystore::load(&config.keystore_path(), config.passphrase.as_deref())?;
            ks.identity_key()
        };
        let mut gw = crate::syncserve::SyncGateway::new(
            owner_ik.public(),
            addr.clone(),
            config.sync_namespaces.clone(),
        );
        let now = now_ms();
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce)
            .map_err(|_| DaemonError::Bind(io::Error::other("rng failure minting the sync-1 capability")))?;
        let token = dmtap_core::capability::CapabilityToken::issue(
            &owner_ik,
            addr.clone(),
            vec![dmtap_core::capability::Capability {
                resource: crate::syncserve::SYNC1_RESOURCE.to_string(),
                ability: crate::syncserve::SYNC1_ABILITY.to_string(),
                caveats: None,
            }],
            now.saturating_sub(1_000),
            now.saturating_add(365 * 24 * 60 * 60 * 1000),
            nonce.to_vec(),
            None,
        );
        let enabled = gw.enable_with_capability(&token, now);
        eprintln!(
            "envoir-node: Sync substrate gateway {} (namespaces: {:?})",
            if enabled { "ENABLED" } else { "FAILED TO ENABLE — capability did not verify" },
            gw.replica.namespaces()
        );
        Some(std::sync::Mutex::new(gw))
    } else {
        None
    };
    let sync_listener = if config.sync_serve_enabled {
        let l = tokio::net::TcpListener::bind(&config.sync_bind).await.map_err(DaemonError::Bind)?;
        eprintln!(
            "envoir-node: Sync listener on {} — {}{{vector,pull,ops,fingerprint}} (sync-1 Bearer required)",
            config.sync_bind,
            crate::syncserve::SYNC_BASE
        );
        Some(l)
    } else {
        None
    };

    let stats = crate::jmap_api::run_loop_with_apis(
        &mut node,
        send_api.as_mut(),
        send_listener,
        jmap_api.as_ref(),
        jmap_listener,
        pub_gateway.as_ref(),
        pub_listener,
        sync_gateway.as_ref(),
        sync_listener,
        config.tick,
        // Supervised mode (ENVOIR_SUPERVISED=1) adds stdin-EOF to the shutdown causes, so a sidecar
        // whose supervising shell died abnormally terminates itself instead of orphaning.
        shutdown_signal_supervised(config.supervised),
    )
    .await;
    eprintln!(
        "envoir-node: shutdown after {} tick(s); final checkpoint {}",
        stats.ticks,
        if stats.flushed_ok { "committed" } else { "FAILED" }
    );
    Ok(stats)
}

/// Render this identity's `_dmtap` DNS TXT record content (spec §3.2) so an operator can publish it.
/// Builds a real, signed §1.2 `Identity` (version 0) from the keystore to derive the `id=` content
/// address, and advertises the sealing key as the `keypkgs` bundle. The `kt=` anchors + `keypkgs`
/// locator are operator config carried in the keystore. The Identity's timestamp is the keystore's
/// **creation** time, so the derived `id=` content address is **stable** across every render (not the
/// wall clock — that would change the published address on each print).
pub fn dmtap_txt_record(ks: &Keystore) -> String {
    let ik = ks.identity_key();
    let identity = build_identity(ks, &ik);
    let record = dmtap_naming::DmtapTxtRecord {
        version: "dmtap1".to_string(),
        suite: 1,
        ik: ik.public(),
        id: identity.content_id(),
        kt: ks.kt_anchors.clone(),
        keypkgs: ks.keypkgs_loc.clone(),
    };
    record.to_txt()
}

/// Build the node's signed §1.2 `Identity` object (version 0) from its keystore, timestamped at the
/// keystore's creation time so its content address is deterministic.
fn build_identity(ks: &Keystore, ik: &IdentityKey) -> Identity {
    let seal_bundle = seal_key_bundle(&ks.seal_public);
    let keypkgs = KeyPackageBundleRef::new(ks.keypkgs_loc.clone(), ContentId::of(&seal_bundle));
    let recovery = ContentId::of(RECOVERY_PLACEHOLDER);
    Identity::create_classical(ik, 0, vec![], keypkgs, recovery, ks.names.clone(), None, ks.created_ms)
}

/// Current wall-clock in ms since the epoch (the daemon's live clock; tests inject their own).
pub fn now_ms() -> TimestampMs {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

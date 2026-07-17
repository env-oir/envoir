//! The long-running node daemon (spec §0.2).
//!
//! This turns the reference node from a one-shot in-process demo into a **persistent process**: it
//! loads the identity from the durable [`Keystore`] and the outbound retry queue from the
//! [`FileJournal`] (spec §19.3.3 — the queue MUST survive restart), binds its mesh transport +
//! the §8 client servers on **configurable** interfaces (the `127.0.0.1` hardcode that made the
//! servers unreachable through a container port-map is gone), then stays up — draining inbound
//! MOTEs, firing retries, and expiring deadlines on a fixed tick — until SIGINT/SIGTERM, on which it
//! flushes a final durable checkpoint and exits cleanly.
//!
//! ## What is real vs. an honest seam
//! - **Real:** identity + sealing-key reload from disk; journal resume; the [`TcpTransport`] mesh
//!   ingress (a background accept loop feeding [`Node::poll`]); the retry/deadline engine; graceful
//!   shutdown; the §8 IMAP/POP3/SMTP-submission servers on a configurable bind.
//! - **Seam (name resolution, §3):** a running node resolves + delivers **by name** through the real
//!   [`dmtap_naming::Resolver`] / [`KeyPackageSource`](dmtap_naming::KeyPackageSource) seams already
//!   wired into [`Node::send_mail_to_name`]. The *networked* DNS `_dmtap` + KT-log clients behind
//!   those traits are the remaining swap — [`resolver_seam`] returns the in-memory harness and logs
//!   that live DNS is not yet wired, rather than silently pretending to resolve. The
//!   `daemon_resolves_and_delivers_by_name` integration test drives the whole path against a live,
//!   running node.
//! - **Seam (mail store):** the §8 servers currently project a per-connection demo store; sharing the
//!   node's *live* delivered-mail store into those sessions (an `Arc`-shared [`MailStore`]) is a
//!   follow-up — [`dmtap_mail::store::MemoryStore`] is `Clone`-by-copy, not shared-backing.

use std::future::Future;
use std::net::TcpListener;
use std::thread::JoinHandle;
use std::time::Duration;

use dmtap_core::identity::{Identity, IdentityKey, KeyPackageBundleRef};
use dmtap_core::id::ContentId;
use dmtap_core::TimestampMs;
use dmtap_mail::auth::StaticAuthenticator;
use dmtap_mail::imap::Session as ImapSession;
use dmtap_mail::net::{serve_imap, serve_pop3, serve_smtp};
use dmtap_mail::pop3::Pop3Session;
use dmtap_mail::smtp::SmtpSession;
use dmtap_mail::store::MemoryStore;

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
    /// Binding a listener (mesh transport or a §8 server) failed.
    Bind(std::io::Error),
    /// Resuming the durable journal failed.
    Journal(JournalError),
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

/// The §8 client servers' lifetime: their listener threads. Dropped when the daemon exits; the
/// threads are detached (the accept loops block on `incoming()`), so process exit reaps them.
pub struct MailServers {
    _threads: Vec<JoinHandle<()>>,
    pub imap_addr: std::net::SocketAddr,
    pub pop3_addr: std::net::SocketAddr,
    pub smtp_addr: std::net::SocketAddr,
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

/// Bind + start the §8 client servers on `config.mail_host` (default `0.0.0.0`, container-reachable).
/// Returns their bound addresses (ephemeral ports resolved). Each listener runs a blocking
/// thread-per-connection accept loop (spec §8.2 semantics; TLS terminated upstream).
pub fn start_mail_servers(config: &NodeConfig) -> Result<MailServers, DaemonError> {
    let user = config.names.first().cloned().unwrap_or_else(|| "owner@dmtap.local".to_string());
    let app_password =
        std::env::var("ENVOIR_APP_PASSWORD").unwrap_or_else(|_| "app-password".to_string());

    let make_auth = move || {
        let mut a = StaticAuthenticator::new();
        a.issue(user.clone(), app_password.clone(), vec![0u8; 32], "daemon");
        a
    };

    let bind = |port: u16| -> Result<TcpListener, DaemonError> {
        TcpListener::bind((config.mail_host.as_str(), port)).map_err(DaemonError::Bind)
    };
    let imap = bind(config.imap_port)?;
    let pop3 = bind(config.pop3_port)?;
    let smtp = bind(config.smtp_port)?;
    let imap_addr = imap.local_addr().map_err(DaemonError::Bind)?;
    let pop3_addr = pop3.local_addr().map_err(DaemonError::Bind)?;
    let smtp_addr = smtp.local_addr().map_err(DaemonError::Bind)?;

    let (a1, a2, a3) = (make_auth.clone(), make_auth.clone(), make_auth);
    let mut threads = Vec::new();
    threads.push(std::thread::spawn(move || {
        let _ = serve_imap(imap, move || ImapSession::new(MemoryStore::new(), a1(), true));
    }));
    // (POP3 + SMTP-submission started below.)
    threads.push(std::thread::spawn(move || {
        let _ = serve_pop3(pop3, move || Pop3Session::new(MemoryStore::new(), a2(), true));
    }));
    threads.push(std::thread::spawn(move || {
        let _ = serve_smtp(smtp, move || SmtpSession::new(a3(), true));
    }));

    Ok(MailServers { _threads: threads, imap_addr, pop3_addr, smtp_addr })
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

/// Start and run the daemon to completion: load the node, start the §8 servers, and run the steady
/// -state loop until a shutdown signal. The one call `main`'s `run`/`serve` wraps in a runtime.
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

    let _mail = if config.mail_enabled {
        let m = start_mail_servers(&config)?;
        eprintln!(
            "envoir-node: §8 servers — IMAP {} POP3 {} SMTP-submission {}",
            m.imap_addr, m.pop3_addr, m.smtp_addr
        );
        Some(m)
    } else {
        None
    };

    eprintln!(
        "envoir-node: name resolution seam — live DNS `_dmtap` + KT clients not wired; \
         resolve/deliver-by-name available via Node::send_mail_to_name over a dmtap_naming::Resolver"
    );
    eprintln!("envoir-node: running — SIGINT/SIGTERM to stop");

    let stats = if config.send_api_enabled {
        // The Envoir Send HTTP API (spec §13.5.1). Owner identity = this node's identity (reloaded
        // from the same keystore), so a capability-authorized send seals a MOTE authenticated as from
        // this node and enters the node's real §20.1 outbound path. Runs on this same task (a `Node`
        // is not `Send`), interleaved with the delivery/retry tick.
        let owner_ik = {
            let ks = Keystore::load(&config.keystore_path(), config.passphrase.as_deref())?;
            ks.identity_key()
        };
        let mut api = crate::send_api::SendApi::new(owner_ik, config.send_admin_token.clone());
        let listener =
            tokio::net::TcpListener::bind(&config.send_api_bind).await.map_err(DaemonError::Bind)?;
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
        crate::send_api::run_loop_with_send_api(
            &mut node,
            &mut api,
            listener,
            config.tick,
            shutdown_signal(),
        )
        .await
    } else {
        run_loop(&mut node, config.tick, shutdown_signal()).await
    };
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

//! Optional **legacy SMTP-submission access server** (DMTAP spec §7.15.1, RFC 6409): the outbound
//! edge for legacy mail clients. A client authenticates over TLS with an app-password and submits an
//! RFC 5322 message; the gateway converts it to a MOTE for a **native** destination, or hands it to
//! the **legacy** (§7.3) outbound path. It is the submission sibling of [`crate::imap_access`] /
//! [`crate::pop3_access`] and shares their honest scoping:
//!
//! - **TLS-required, app-password auth, off by default.** Runs over the gateway's rustls config
//!   ([`LegacyTls::Implicit`] on 465 / [`LegacyTls::StartTls`]+`STARTTLS` on 587) with
//!   `dmtap-mail`'s [`SmtpSession`], which **requires AUTH before MAIL** (fail-closed) and refuses
//!   `AUTH` on a cleartext channel (`538`). The listener is off unless
//!   [`crate::PersonalConfig::submission_enable`].
//! - **Stateless conversion, node-owned durability (§7.4).** The gateway holds no queue. On a
//!   completed `DATA` it converts the submission to a MOTE draft ([`build_mote_draft`]) and hands the
//!   accepted message to a [`SubmissionSink`] — the seam to the operator's co-located node. In the
//!   personal daemon the sink is a [`SpoolSink`]: it writes the accepted message into a hand-off
//!   directory the operator's authoritative node picks up (the write-side counterpart to the IMAP
//!   maildir the read surfaces project). The node then performs native mesh delivery or drives the
//!   §7.3 legacy SMTP relay; the gateway keeps nothing.
//!
//! ## Native vs legacy classification
//! Per recipient, the server classifies the destination against the operator's configured **native
//! domains** (the gateway's own DMTAP domain(s)): a recipient on a native domain is a
//! [`Destination::Native`] (delivered as a MOTE to the node's mesh), anything else is a
//! [`Destination::Legacy`] (bridged out via §7.3). The classification is passed to the sink so the
//! wiring is explicit and testable.

use std::io;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rustls::ServerConfig;

use dmtap_core::mote::MoteDraft;
use dmtap_mail::auth::Authenticator;
use dmtap_mail::smtp::{build_mote_draft, SmtpSession, Submission};

use crate::legacy_net::{serve_line_session, verb_of, LegacyTls, LineProtocol};

/// Whether a submitted recipient is a **native** DMTAP destination (delivered as a MOTE over the mesh)
/// or a **legacy** email destination (bridged out via the §7.3 SMTP relay).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Destination {
    /// A recipient on one of the gateway's own native domains — converted to a MOTE (§7.15.1).
    Native,
    /// A recipient on any other domain — bridged to legacy SMTP via §7.3.
    Legacy,
}

/// One accepted submission, resolved for a single recipient and classified. The `mote` is the
/// MOTE-draft conversion of the RFC 5322 bytes (the "convert to a MOTE for a native destination"
/// step, §7.15.1); a legacy destination carries the same fields but is bridged out via §7.3 instead.
pub struct RoutedSubmission<'a> {
    /// The authenticated `MAIL FROM` envelope sender.
    pub from: &'a str,
    /// The single `RCPT TO` this routing is for (a submission is split one [`RoutedSubmission`] per
    /// recipient so each can be classified and dispatched independently).
    pub rcpt_to: &'a str,
    /// Native (→ MOTE / mesh) vs legacy (→ §7.3 SMTP relay).
    pub destination: Destination,
    /// The exact submitted RFC 5322 bytes.
    pub rfc5322: &'a [u8],
    /// The MOTE-draft conversion of the message ([`build_mote_draft`]).
    pub mote: &'a MoteDraft,
}

/// The seam a completed submission is handed to — the operator's co-located node (§7.4: the gateway
/// stores nothing; durability and the actual native/legacy dispatch are the node's). Returns whether
/// the message was accepted for delivery (informational; the SMTP `250` was already returned to the
/// client, since a stateless gateway acknowledges receipt and defers durability to the node/edges).
pub trait SubmissionSink: Send + Sync {
    /// Handle one accepted, classified submission for one recipient.
    fn deliver(&self, routed: &RoutedSubmission) -> bool;
}

/// A bound SMTP-submission access listener. Serves one [`SmtpSession`] per accepted connection on its
/// own thread; the authenticator is (re)built per connection via a factory and the [`SubmissionSink`]
/// is shared across connections.
pub struct SubmissionServer {
    listener: TcpListener,
    tls: Arc<ServerConfig>,
    mode: LegacyTls,
    native_domains: Arc<Vec<String>>,
}

impl SubmissionServer {
    /// Bind a submission access listener with the gateway's TLS config, TLS mode, and the operator's
    /// native domains (recipients on these are classified [`Destination::Native`]). Native domains are
    /// lowercased for a case-insensitive match.
    pub fn bind(
        addr: impl std::net::ToSocketAddrs,
        tls: Arc<ServerConfig>,
        mode: LegacyTls,
        native_domains: Vec<String>,
    ) -> io::Result<Self> {
        let native_domains =
            native_domains.iter().map(|d| d.trim().to_ascii_lowercase()).collect::<Vec<_>>();
        Ok(SubmissionServer {
            listener: TcpListener::bind(addr)?,
            tls,
            mode,
            native_domains: Arc::new(native_domains),
        })
    }

    /// The address actually bound (useful with an ephemeral `:0` port in tests).
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// Accept exactly one connection, run its submission session to completion, and return. For tests
    /// and single-shot use; the daemon uses [`Self::serve_until`].
    pub fn serve_once<A, K>(&self, auth: A, sink: Arc<K>) -> io::Result<()>
    where
        A: Authenticator,
        K: SubmissionSink,
    {
        let (stream, _peer) = self.listener.accept()?;
        stream.set_nonblocking(false)?;
        handle_connection(
            stream,
            self.tls.clone(),
            self.mode,
            auth,
            sink,
            self.native_domains.clone(),
        )
    }

    /// Serve connections until `shutdown` flips, then stop accepting and return — the long-running
    /// daemon loop with graceful shutdown, mirroring the IMAP/POP3 access servers. Each connection is
    /// handled on its own detached thread; a per-connection error is logged and never stops the loop.
    pub fn serve_until<A, K, MkAuth>(
        &self,
        make_auth: MkAuth,
        sink: Arc<K>,
        shutdown: &AtomicBool,
    ) -> io::Result<()>
    where
        A: Authenticator + Send + 'static,
        K: SubmissionSink + 'static,
        MkAuth: Fn() -> A + Send + Sync + 'static,
    {
        self.listener.set_nonblocking(true)?;
        let make_auth = Arc::new(make_auth);
        let idle = Duration::from_millis(100);
        loop {
            if shutdown.load(Ordering::SeqCst) {
                return Ok(());
            }
            match self.listener.accept() {
                Ok((stream, peer)) => {
                    if let Err(e) = stream.set_nonblocking(false) {
                        eprintln!("gateway[submission]: {peer}: cannot set blocking: {e}");
                        continue;
                    }
                    let tls = self.tls.clone();
                    let mode = self.mode;
                    let make_auth = make_auth.clone();
                    let sink = sink.clone();
                    let native = self.native_domains.clone();
                    std::thread::spawn(move || {
                        if let Err(e) =
                            handle_connection(stream, tls, mode, make_auth(), sink, native)
                        {
                            if e.kind() != io::ErrorKind::UnexpectedEof {
                                eprintln!("gateway[submission]: session with {peer} ended: {e}");
                            }
                        }
                    });
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(idle);
                }
                Err(e) => {
                    eprintln!("gateway[submission]: accept error: {e}");
                    std::thread::sleep(idle);
                }
            }
        }
    }
}

/// Drive one submission session over `stream`: build the [`SmtpSession`] with the TLS flag matching
/// the transport (implicit TLS lets AUTH proceed immediately; STARTTLS starts cleartext and flips on
/// the command), then hand it to the shared line-protocol loop.
fn handle_connection<A, K>(
    stream: TcpStream,
    tls: Arc<ServerConfig>,
    mode: LegacyTls,
    auth: A,
    sink: Arc<K>,
    native_domains: Arc<Vec<String>>,
) -> io::Result<()>
where
    A: Authenticator,
    K: SubmissionSink,
{
    let session = SmtpSession::new(auth, mode.is_implicit());
    serve_line_session(stream, tls, mode, SmtpLine { session, sink, native_domains })
}

/// Adapts `dmtap-mail`'s [`SmtpSession`] to the shared [`LineProtocol`] loop, routing each accepted
/// submission through the [`SubmissionSink`] as the session yields it.
struct SmtpLine<A: Authenticator, K: SubmissionSink> {
    session: SmtpSession<A>,
    sink: Arc<K>,
    native_domains: Arc<Vec<String>>,
}

impl<A: Authenticator, K: SubmissionSink> SmtpLine<A, K> {
    /// Convert and route every submission the session accepted on the last line, one
    /// [`RoutedSubmission`] per recipient.
    fn route_pending(&mut self) {
        let now = now_ms();
        for sub in self.session.take_submissions() {
            self.route_one(&sub, now);
        }
    }

    fn route_one(&self, sub: &Submission, now: u64) {
        let mote = build_mote_draft(&sub.data, now);
        for rcpt in &sub.rcpt_to {
            let destination =
                if self.is_native(rcpt) { Destination::Native } else { Destination::Legacy };
            let routed = RoutedSubmission {
                from: &sub.mail_from,
                rcpt_to: rcpt,
                destination,
                rfc5322: &sub.data,
                mote: &mote,
            };
            let accepted = self.sink.deliver(&routed);
            if !accepted {
                eprintln!(
                    "gateway[submission]: sink rejected {} → {rcpt} ({destination:?}); message not \
                     handed off (client already got 250)",
                    sub.mail_from
                );
            }
        }
    }

    /// Whether `rcpt`'s domain is one of the operator's native DMTAP domains.
    fn is_native(&self, rcpt: &str) -> bool {
        match domain_of(rcpt) {
            Some(d) => self.native_domains.iter().any(|n| n == &d),
            None => false,
        }
    }
}

impl<A: Authenticator, K: SubmissionSink> LineProtocol for SmtpLine<A, K> {
    fn greeting(&mut self) -> String {
        self.session.greeting()
    }
    // Raw bytes through to `dmtap-mail`'s lossless entry point: a submission DATA line under an
    // 8-bit CTE must be buffered byte-exact (the session's own docs on `feed_line_bytes`).
    fn feed_line_bytes(&mut self, line: &[u8]) -> String {
        let reply = self.session.feed_line_bytes(line);
        // Drain and route any submission the session accepted on this line (a completed `DATA`).
        self.route_pending();
        reply
    }
    fn is_starttls(&self, line: &str) -> bool {
        verb_of(line) == "STARTTLS"
    }
    fn accepts_upgrade(&self, reply: &str) -> bool {
        reply.starts_with("220")
    }
    fn is_quit(&self, line: &str) -> bool {
        verb_of(line) == "QUIT"
    }
}

/// The concrete daemon [`SubmissionSink`]: writes each accepted submission into a hand-off **spool
/// directory** the operator's authoritative node picks up (§7.4 — the gateway holds no queue; this is
/// the operator's own local hand-off, the write-side counterpart to the IMAP maildir the read
/// surfaces project). One `.eml` file per recipient, name-tagged with the destination class so the
/// node knows to deliver it natively (mesh) or bridge it to legacy (§7.3). Fail-closed: a write error
/// is logged and reported as not-accepted.
pub struct SpoolSink {
    dir: std::path::PathBuf,
    seq: AtomicU64,
}

impl SpoolSink {
    /// A spool sink writing into `dir` (which must already exist — a mis-typed path must not silently
    /// swallow outbound mail). Fail-closed: a missing directory is an error at construction.
    pub fn new(dir: impl AsRef<std::path::Path>) -> io::Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        if !dir.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("submission spool {} is not a directory", dir.display()),
            ));
        }
        Ok(SpoolSink { dir, seq: AtomicU64::new(0) })
    }
}

impl SubmissionSink for SpoolSink {
    fn deliver(&self, routed: &RoutedSubmission) -> bool {
        let n = self.seq.fetch_add(1, Ordering::SeqCst);
        let tag = match routed.destination {
            Destination::Native => "native",
            Destination::Legacy => "legacy",
        };
        // Envelope trace headers let the node recover the SMTP envelope (which RFC 5322 alone does not
        // fully carry) without parsing the body; they are namespaced so they never collide with mail
        // headers. Prepended before the submitted message bytes.
        let mut out = format!(
            "X-Envoir-Destination: {tag}\r\nX-Envoir-Mail-From: {}\r\nX-Envoir-Rcpt-To: {}\r\n",
            sanitize(routed.from),
            sanitize(routed.rcpt_to),
        )
        .into_bytes();
        out.extend_from_slice(routed.rfc5322);
        let path = self.dir.join(format!("{now}-{n}-{tag}.eml", now = now_ms()));
        match std::fs::write(&path, &out) {
            Ok(()) => true,
            Err(e) => {
                eprintln!("gateway[submission]: cannot spool to {}: {e}", path.display());
                false
            }
        }
    }
}

/// Strip CR/LF/NUL from an envelope value before it is written into a trace header (header-injection
/// guard: a hostile `MAIL FROM` must not be able to inject extra spool headers).
fn sanitize(v: &str) -> String {
    v.chars().filter(|c| *c != '\r' && *c != '\n' && *c != '\0').collect()
}

/// The domain part of an address like `<a@b.com>` / `a@b.com`, lowercased.
fn domain_of(addr: &str) -> Option<String> {
    let a = addr.trim().trim_start_matches('<').trim_end_matches('>');
    a.rsplit_once('@').map(|(_, d)| d).filter(|d| !d.is_empty()).map(|d| d.to_ascii_lowercase())
}

/// Epoch-milliseconds now (the MOTE-draft timestamp / spool-file ordering key).
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// One captured routed entry: `(from, rcpt, destination, rfc5322)`.
    type Captured = (String, String, Destination, Vec<u8>);

    /// A capturing sink that records every routed submission (for the unit + integration tests).
    #[derive(Default)]
    struct Capturing {
        seen: Mutex<Vec<Captured>>,
    }
    impl SubmissionSink for Capturing {
        fn deliver(&self, r: &RoutedSubmission) -> bool {
            self.seen.lock().unwrap().push((
                r.from.to_string(),
                r.rcpt_to.to_string(),
                r.destination,
                r.rfc5322.to_vec(),
            ));
            true
        }
    }

    #[test]
    fn classifies_native_vs_legacy_and_splits_per_recipient() {
        let sink = Arc::new(Capturing::default());
        let line = SmtpLine {
            session: SmtpSession::new(dmtap_mail::auth::StaticAuthenticator::new(), true),
            sink: sink.clone(),
            native_domains: Arc::new(vec!["example.org".to_string()]),
        };
        // A submission with one native and one legacy recipient is split into two routed entries.
        let sub = Submission {
            mail_from: "me@example.org".into(),
            rcpt_to: vec!["friend@example.org".into(), "someone@gmail.com".into()],
            data: b"Subject: Hi\r\n\r\nhello\r\n".to_vec(),
            envid: None,
            ret: None,
            dsn_notify: vec![None, None],
        };
        line.route_one(&sub, 1_000);

        let seen = sink.seen.lock().unwrap();
        assert_eq!(seen.len(), 2, "one routed entry per recipient");
        assert_eq!(seen[0].1, "friend@example.org");
        assert_eq!(seen[0].2, Destination::Native, "on the native domain → MOTE path");
        assert_eq!(seen[1].1, "someone@gmail.com");
        assert_eq!(seen[1].2, Destination::Legacy, "elsewhere → §7.3 legacy bridge");
    }

    #[test]
    fn domain_and_verb_helpers() {
        assert_eq!(domain_of("<a@B.com>").as_deref(), Some("b.com"));
        assert_eq!(domain_of("bare").as_deref(), None);
        assert_eq!(sanitize("a\r\nb\0c"), "abc");
    }

    #[test]
    fn spool_sink_requires_an_existing_directory() {
        assert!(SpoolSink::new("/definitely/not/here/at/all").is_err());
    }
}

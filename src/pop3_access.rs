//! Optional **legacy POP3 access server** (DMTAP spec §7.15.1, RFC 1939): serves the identity's INBOX
//! as a download-and-delete **maildrop** to authenticated legacy clients, alongside the IMAP access
//! server and the SMTP bridge. It is the POP3 sibling of [`crate::imap_access`] and shares its honest
//! scoping exactly:
//!
//! - **Store-backed, not a stateless proxy.** POP3 LISTs and RETRs messages that must exist somewhere;
//!   the store is the operator's own DMTAP mailbox projection ([`dmtap_mail::store::MailStore`]) — the
//!   same projection the IMAP server serves and the co-located node owns.
//! - **Session-local mutations.** In the personal daemon the operator hands the gateway a mailbox
//!   snapshot (a maildir of `.eml` files via [`crate::imap_access::load_maildir_messages`]) projected
//!   into a fresh per-connection [`MemoryStore`]. A POP3 `DELE`…`QUIT` expunges from *that* session
//!   store; because the gateway is not the mailbox authority, the deletion is **not** persisted back
//!   to the DMTAP MOTE store. That authority is the node. The limitation is documented, not faked.
//! - **TLS-required, app-password auth, off by default.** Every session runs over the gateway's rustls
//!   config ([`LegacyTls::Implicit`] on 995 / [`LegacyTls::StartTls`]+`STLS` on 110), authenticated by
//!   `dmtap-mail`'s app-password path (`USER`/`PASS`, `APOP`, or `AUTH PLAIN`) — the exact scheme the
//!   IMAP and submission surfaces use. The listener is off unless [`crate::PersonalConfig::pop3_enable`].

use std::io;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rustls::ServerConfig;

use dmtap_mail::auth::Authenticator;
use dmtap_mail::pop3::Pop3Session;
use dmtap_mail::store::MailStore;

use crate::legacy_net::{serve_line_session, verb_of, LegacyTls, LineProtocol};

/// A bound POP3 access listener. Serves one [`Pop3Session`] per accepted connection on its own thread.
/// The store and authenticator are (re)built per connection via factories, so each session owns its
/// own snapshot — exactly as [`crate::imap_access::ImapAccessServer`] does.
pub struct Pop3AccessServer {
    listener: TcpListener,
    tls: Arc<ServerConfig>,
    mode: LegacyTls,
}

impl Pop3AccessServer {
    /// Bind a POP3 access listener with the gateway's TLS config and the chosen TLS mode.
    pub fn bind(
        addr: impl std::net::ToSocketAddrs,
        tls: Arc<ServerConfig>,
        mode: LegacyTls,
    ) -> io::Result<Self> {
        Ok(Pop3AccessServer { listener: TcpListener::bind(addr)?, tls, mode })
    }

    /// The address actually bound (useful with an ephemeral `:0` port in tests).
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// Accept exactly one connection, run its POP3 session to completion, and return. For tests and
    /// single-shot use; the daemon uses [`Self::serve_until`].
    pub fn serve_once<S, A>(&self, store: S, auth: A) -> io::Result<()>
    where
        S: MailStore,
        A: Authenticator,
    {
        let (stream, _peer) = self.listener.accept()?;
        stream.set_nonblocking(false)?;
        handle_connection(stream, self.tls.clone(), self.mode, store, auth)
    }

    /// Serve connections until `shutdown` flips to `true`, then stop accepting and return — the
    /// long-running daemon loop with graceful shutdown, mirroring
    /// [`crate::imap_access::ImapAccessServer::serve_until`]. Each accepted connection is handled on
    /// its own detached thread; a per-connection error is logged and never stops the accept loop.
    pub fn serve_until<S, A, MkStore, MkAuth>(
        &self,
        make_store: MkStore,
        make_auth: MkAuth,
        shutdown: &AtomicBool,
    ) -> io::Result<()>
    where
        S: MailStore + Send + 'static,
        A: Authenticator + Send + 'static,
        MkStore: Fn() -> S + Send + Sync + 'static,
        MkAuth: Fn() -> A + Send + Sync + 'static,
    {
        self.listener.set_nonblocking(true)?;
        let make_store = Arc::new(make_store);
        let make_auth = Arc::new(make_auth);
        let idle = Duration::from_millis(100);
        loop {
            if shutdown.load(Ordering::SeqCst) {
                return Ok(());
            }
            match self.listener.accept() {
                Ok((stream, peer)) => {
                    if let Err(e) = stream.set_nonblocking(false) {
                        eprintln!("gateway[pop3]: {peer}: cannot set blocking: {e}");
                        continue;
                    }
                    let tls = self.tls.clone();
                    let mode = self.mode;
                    let make_store = make_store.clone();
                    let make_auth = make_auth.clone();
                    std::thread::spawn(move || {
                        if let Err(e) =
                            handle_connection(stream, tls, mode, make_store(), make_auth())
                        {
                            if e.kind() != io::ErrorKind::UnexpectedEof {
                                eprintln!("gateway[pop3]: session with {peer} ended: {e}");
                            }
                        }
                    });
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(idle);
                }
                Err(e) => {
                    eprintln!("gateway[pop3]: accept error: {e}");
                    std::thread::sleep(idle);
                }
            }
        }
    }
}

/// Drive one POP3 session over `stream`: build the session with the TLS flag matching the transport
/// (implicit TLS starts authenticated-channel-ready; STLS starts cleartext and flips on the command),
/// then hand it to the shared line-protocol loop.
fn handle_connection<S, A>(
    stream: TcpStream,
    tls: Arc<ServerConfig>,
    mode: LegacyTls,
    store: S,
    auth: A,
) -> io::Result<()>
where
    S: MailStore,
    A: Authenticator,
{
    let session = Pop3Session::new(store, auth, mode.is_implicit());
    serve_line_session(stream, tls, mode, Pop3Line { session })
}

/// Adapts `dmtap-mail`'s [`Pop3Session`] to the shared [`LineProtocol`] loop. `STLS` is the in-band
/// upgrade verb (RFC 2595); a `+OK` reply to it triggers the in-place TLS termination.
struct Pop3Line<S: MailStore, A: Authenticator> {
    session: Pop3Session<S, A>,
}

impl<S: MailStore, A: Authenticator> LineProtocol for Pop3Line<S, A> {
    fn greeting(&mut self) -> String {
        self.session.greeting()
    }
    fn feed_line(&mut self, line: &str) -> String {
        self.session.feed_line(line)
    }
    fn is_starttls(&self, line: &str) -> bool {
        verb_of(line) == "STLS"
    }
    fn accepts_upgrade(&self, reply: &str) -> bool {
        reply.starts_with("+OK")
    }
    fn is_quit(&self, line: &str) -> bool {
        verb_of(line) == "QUIT"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dmtap_mail::auth::StaticAuthenticator;
    use dmtap_mail::store::MemoryStore;

    #[test]
    fn recognizes_stls_and_quit_and_ok_reply() {
        let line = Pop3Line {
            session: Pop3Session::new(MemoryStore::new(), StaticAuthenticator::new(), true),
        };
        assert!(line.is_starttls("STLS\r\n"));
        assert!(line.is_starttls("stls"));
        assert!(!line.is_starttls("USER alice"));
        assert!(line.is_quit("QUIT"));
        assert!(line.is_quit("quit\r\n"));
        assert!(!line.is_quit("NOOP"));
        assert!(line.accepts_upgrade("+OK Begin TLS\r\n"));
        assert!(!line.accepts_upgrade("-ERR no\r\n"));
    }
}

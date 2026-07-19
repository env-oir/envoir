//! Mesh delivery (spec §4 / §19.2.3 reachability ladder + §19.3.1 `deliver`): hand a converted,
//! attested MOTE **toward the recipient's node** and report whether durable custody was acked inside
//! the inbound SMTP transaction window (§19.7.1 step 6).
//!
//! [`crate::inbound::MeshDelivery`] is the abstract seam. The gateway must not depend on the DMTAP
//! P2P stack directly: `dmtap-p2p` depends on `envoir-node`, so wiring it in here would invert the
//! layering (and pull the whole libp2p swarm into the *optional*, std-only bridge). Instead this
//! module supplies two named, non-silent implementations, and the node transport is a drop-in behind
//! the same trait:
//!
//! - [`HttpMeshDelivery`] — a **real** HTTP/1.1 `POST` of the MOTE to a node's ingest endpoint. This
//!   is the loopback / sidecar path: the operator runs an `envoir-node` (or a relay-mailbox, §14.5)
//!   alongside the gateway, exposing an ingest URL on `127.0.0.1`; the gateway POSTs the sealed MOTE
//!   there and maps the node's HTTP response onto the durable-ack decision. A `2xx` means the node
//!   took **durable** custody → [`DeliveryOutcome::Acked`] → SMTP `250`; anything else (non-2xx,
//!   refused connection, timeout) → [`DeliveryOutcome::NoAck`] → SMTP `451`, so durability stays
//!   with the legacy sender's retry queue (§7.4). This is the flagship working impl.
//! - [`NullMesh`] — the honest **unconfigured** default: it durably-acks nothing and always returns
//!   [`DeliveryOutcome::NoAck`], so a gateway with no mesh wired refuses inbound mail with `451`
//!   rather than silently accepting and dropping it. It is a *named* safe default, not a stub that
//!   pretends to deliver.
//!
//! ### The `dmtap-p2p` drop-in
//! A production deployment that wants the gateway to inject straight into the swarm (rather than via
//! a co-located node's HTTP ingest) implements [`crate::inbound::MeshDelivery`] over the node's
//! `deliver` path in the crate that already depends on `envoir-node` (e.g. `dmtap-p2p` or the node
//! binary), and passes that `Box<dyn MeshDelivery>` into [`crate::inbound::InboundGateway::new`].
//! The trait is the exact seam; nothing else in the gateway changes. Keeping that impl *above* the
//! gateway (where `envoir-node` is already a dependency) is what avoids the dependency cycle.

use std::io::Write;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use dmtap_core::mote::Envelope;

use crate::attestation::Attestation;
use crate::b64;
use crate::inbound::{DeliveryOutcome, MeshDelivery};
use crate::net::{read_line_str, write_all};

/// The honest **unconfigured** mesh seam: acks nothing, so inbound mail is deferred `451` and the
/// legacy sender retries (§7.4). A gateway wired with this is safe — it never silently accepts and
/// drops a message — but it delivers nothing until a real mesh (e.g. [`HttpMeshDelivery`] or the
/// `dmtap-p2p` node drop-in) is configured.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullMesh;

impl MeshDelivery for NullMesh {
    fn deliver(&self, _env: &Envelope, _att: &Attestation) -> DeliveryOutcome {
        DeliveryOutcome::NoAck
    }
}

/// A **real** mesh-delivery adapter that `POST`s the sealed MOTE to a node's HTTP ingest endpoint
/// (the loopback / co-located-node path — see the module docs).
///
/// The MOTE travels as the request body in its canonical §18 deterministic-CBOR form
/// ([`Envelope::det_cbor`]); the §7.2a gateway attestation travels in `X-Dmtap-*` headers so the
/// ingesting node can bind the message to the gateway that vouched for it. The node's HTTP status
/// **is** the durable-ack signal: `2xx` ⇒ durable custody ([`DeliveryOutcome::Acked`]), everything
/// else ⇒ [`DeliveryOutcome::NoAck`]. Stateless: one connection per delivery, `Connection: close`.
#[derive(Debug, Clone)]
pub struct HttpMeshDelivery {
    host: String,
    port: u16,
    path: String,
    connect_timeout: Duration,
    io_timeout: Duration,
}

impl HttpMeshDelivery {
    /// Build a delivery adapter for a node ingest `endpoint` of the form
    /// `http://host[:port]/path` (plaintext HTTP, the loopback/sidecar transport; the default port
    /// is 80). Returns [`MeshConfigError`] on a malformed or non-`http` URL.
    ///
    /// TLS to a *remote* relay ingest is a documented extension: terminate rustls exactly as
    /// [`crate::mta_sts::HttpsPolicyFetcher`] does and keep the same request/response contract. The
    /// reference impl is plaintext because the intended peer is a node on `127.0.0.1`, where the
    /// hop never leaves the host.
    pub fn new(endpoint: &str) -> Result<Self, MeshConfigError> {
        let rest = endpoint
            .strip_prefix("http://")
            .ok_or_else(|| MeshConfigError::UnsupportedScheme(endpoint.to_string()))?;
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        if authority.is_empty() {
            return Err(MeshConfigError::MissingHost(endpoint.to_string()));
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => {
                let port = p.parse::<u16>().map_err(|_| MeshConfigError::BadPort(p.to_string()))?;
                (h.to_string(), port)
            }
            None => (authority.to_string(), 80),
        };
        if host.is_empty() {
            return Err(MeshConfigError::MissingHost(endpoint.to_string()));
        }
        Ok(HttpMeshDelivery {
            host,
            port,
            path: path.to_string(),
            connect_timeout: Duration::from_secs(10),
            io_timeout: Duration::from_secs(10),
        })
    }

    /// Override the connect / per-read-write timeouts (defaults: 10 s each).
    pub fn with_timeouts(mut self, connect: Duration, io: Duration) -> Self {
        self.connect_timeout = connect;
        self.io_timeout = io;
        self
    }

    /// The `host:port` authority this adapter delivers to (useful for logging).
    pub fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// Perform the POST and return whether the node acked durable custody (`2xx`). Any transport
    /// failure is a `NoAck` (never a false ack): the silent-loss-avoidance rule then yields `451`.
    fn post(&self, env: &Envelope, att: &Attestation) -> std::io::Result<bool> {
        let body = env.det_cbor();
        let addr = (self.host.as_str(), self.port).to_socket_addrs()?.next().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "no address for mesh ingest host")
        })?;
        let mut tcp = TcpStream::connect_timeout(&addr, self.connect_timeout)?;
        tcp.set_read_timeout(Some(self.io_timeout))?;
        tcp.set_write_timeout(Some(self.io_timeout))?;

        // Request head: the MOTE is the body; the §7.2a attestation binds it to the vouching gateway.
        let head = format!(
            "POST {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             User-Agent: envoir-gateway\r\n\
             Content-Type: application/dmtap-mote\r\n\
             Content-Length: {len}\r\n\
             X-Dmtap-Mote-Id: {mote_id}\r\n\
             X-Dmtap-Gateway-Domain: {domain}\r\n\
             X-Dmtap-Gateway-Selector: {selector}\r\n\
             X-Dmtap-Attestation-Sig: {sig}\r\n\
             X-Dmtap-Smtp-From: {mail_from}\r\n\
             X-Dmtap-Smtp-Rcpt: {rcpt_to}\r\n\
             Connection: close\r\n\r\n",
            path = self.path,
            host = self.host,
            len = body.len(),
            mote_id = b64::encode(env.id.as_bytes()),
            domain = att.domain,
            selector = att.selector,
            sig = b64::encode(&att.sig),
            mail_from = header_safe(&att.smtp_mail_from),
            rcpt_to = header_safe(&att.smtp_rcpt_to),
        );
        write_all(&mut tcp, &head)?;
        tcp.write_all(&body)?;
        tcp.flush()?;

        // Only the status line matters for the ack decision.
        let status = read_line_str(&mut tcp)?.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "no HTTP status line")
        })?;
        let code_ok = status.split_whitespace().nth(1).map(|c| c.starts_with('2')).unwrap_or(false);
        Ok(code_ok)
    }
}

impl MeshDelivery for HttpMeshDelivery {
    fn deliver(&self, env: &Envelope, attestation: &Attestation) -> DeliveryOutcome {
        match self.post(env, attestation) {
            Ok(true) => DeliveryOutcome::Acked,
            // A non-2xx status or any transport error is a non-ack: the sender's queue retries.
            Ok(false) | Err(_) => DeliveryOutcome::NoAck,
        }
    }
}

/// Strip CR/LF so an attacker-influenced SMTP address can never inject extra HTTP headers
/// (request-splitting) into the ingest POST.
fn header_safe(v: &str) -> String {
    v.chars().filter(|&c| c != '\r' && c != '\n').collect()
}

/// Why a mesh ingest endpoint string could not be parsed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MeshConfigError {
    #[error("mesh endpoint {0:?} must be an http:// URL (the loopback node-ingest transport)")]
    UnsupportedScheme(String),
    #[error("mesh endpoint {0:?} has no host")]
    MissingHost(String),
    #[error("mesh endpoint port {0:?} is not a valid port number")]
    BadPort(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_endpoints() {
        let d = HttpMeshDelivery::new("http://127.0.0.1:8646/dmtap/ingest").unwrap();
        assert_eq!(d.host, "127.0.0.1");
        assert_eq!(d.port, 8646);
        assert_eq!(d.path, "/dmtap/ingest");
        assert_eq!(d.authority(), "127.0.0.1:8646");

        // Default port + default path.
        let d = HttpMeshDelivery::new("http://node.local").unwrap();
        assert_eq!(d.port, 80);
        assert_eq!(d.path, "/");
    }

    #[test]
    fn rejects_malformed_endpoints() {
        assert!(matches!(
            HttpMeshDelivery::new("https://node/ingest"),
            Err(MeshConfigError::UnsupportedScheme(_))
        ));
        assert!(matches!(
            HttpMeshDelivery::new("http:///ingest"),
            Err(MeshConfigError::MissingHost(_))
        ));
        assert!(matches!(
            HttpMeshDelivery::new("http://host:notaport/ingest"),
            Err(MeshConfigError::BadPort(_))
        ));
    }

    #[test]
    fn header_safe_strips_crlf_injection() {
        assert_eq!(header_safe("a@b.com\r\nX-Evil: 1"), "a@b.comX-Evil: 1");
    }

    #[test]
    fn unreachable_ingest_is_a_noack_never_a_false_ack() {
        // Nothing is listening on this port → connection refused → NoAck (→ 451), never a false 250.
        let d = HttpMeshDelivery::new("http://127.0.0.1:1/ingest")
            .unwrap()
            .with_timeouts(Duration::from_millis(200), Duration::from_millis(200));
        let env = sample_envelope();
        let att = sample_attestation(&env);
        assert_eq!(d.deliver(&env, &att), DeliveryOutcome::NoAck);
    }

    #[test]
    fn null_mesh_never_acks() {
        let env = sample_envelope();
        let att = sample_attestation(&env);
        assert_eq!(NullMesh.deliver(&env, &att), DeliveryOutcome::NoAck);
    }

    // --- helpers -----------------------------------------------------------------------------

    fn sample_envelope() -> Envelope {
        use dmtap_core::identity::IdentityKey;
        use dmtap_core::mote::{build_mote, Hpke, Kind, MoteDraft, SealKeypair};
        let gw = IdentityKey::generate();
        let eph = IdentityKey::generate();
        let recip_ik = IdentityKey::generate();
        let recip_seal = SealKeypair::generate();
        let draft = MoteDraft::new(Kind::Mail, 1_752_600_000_000, b"body".to_vec());
        build_mote(&Hpke, &gw, &eph, &recip_ik.public(), recip_seal.public(), draft).expect("mote")
    }

    fn sample_attestation(env: &Envelope) -> Attestation {
        use crate::attestation::AttestationKey;
        AttestationKey::generate("example.org", "gw1").attest(
            &env.id,
            "sender@gmail.com",
            "alice@example.org",
            1_752_600_000_000,
        )
    }
}

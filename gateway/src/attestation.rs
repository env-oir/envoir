//! Gateway attestation — spec §7.2a (normative key binding).
//!
//! An inbound legacy message is not end-to-end encrypted before the gateway (the legacy leg is
//! plaintext). To let the recipient trust that a MOTE genuinely arrived through a gateway the
//! recipient's own domain authorized — rather than any operator forging a "legitimate legacy
//! origin" — the gateway signs an **attestation** with a **domain-anchored attestation key**, and
//! the domain publishes that key's public half in DNS:
//!
//! ```text
//! <sel>._dmtap-gw.<domain>.  IN  TXT  "v=dmtapgw1; k=<attestation public key>"
//! ```
//!
//! The recipient node MUST verify the attestation against the key published **under its own
//! domain**, MUST reject one that does not verify, and MUST mark accepted MOTEs as *legacy-origin*
//! (§7.2a). This module provides the signable attestation object, the domain-anchored signing
//! key, an abstract `GwKeyResolver` (the DNS TXT lookup), and the recipient-side verify.

use dmtap_core::identity::{verify_domain, IdentityError, IdentityKey};
use dmtap_core::ContentId;
use dmtap_core::TimestampMs;

/// Domain-separation tag for the attestation signature (§18.1.6 style: a distinct label so an
/// attestation signature can never be replayed as any other DMTAP object). ASCII + one NUL.
const ATTESTATION_DS: &[u8] = b"DMTAP-v0/gateway-attestation\x00";

/// The gateway's domain-anchored attestation signing key (§7.2a). This is the private half of the
/// key published at `<selector>._dmtap-gw.<domain>`; it is **not** the operator's arbitrary key —
/// binding is what makes the attestation meaningful.
pub struct AttestationKey {
    domain: String,
    selector: String,
    key: IdentityKey,
}

impl AttestationKey {
    /// Create an attestation key bound to `domain`/`selector`. In production the private key is
    /// operator-held and the public half is published in DNS; here `key` is supplied directly.
    pub fn new(domain: impl Into<String>, selector: impl Into<String>, key: IdentityKey) -> Self {
        AttestationKey { domain: domain.into(), selector: selector.into(), key }
    }

    /// Generate a fresh attestation keypair for `domain`/`selector`.
    pub fn generate(domain: impl Into<String>, selector: impl Into<String>) -> Self {
        Self::new(domain, selector, IdentityKey::generate())
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }
    pub fn selector(&self) -> &str {
        &self.selector
    }

    /// The public key to publish at `<selector>._dmtap-gw.<domain>` (§7.2a).
    pub fn public(&self) -> Vec<u8> {
        self.key.public()
    }

    /// Sign an attestation binding this gateway to a specific inbound MOTE (§7.2a step 4). The
    /// signature covers the gateway id, domain/selector, receive time, the legacy SMTP envelope,
    /// and the MOTE's content address — so an attestation cannot be lifted onto a different MOTE.
    pub fn attest(
        &self,
        mote_id: &ContentId,
        smtp_mail_from: &str,
        smtp_rcpt_to: &str,
        received_at: TimestampMs,
    ) -> Attestation {
        let mut att = Attestation {
            domain: self.domain.clone(),
            selector: self.selector.clone(),
            gateway_key: self.key.public(),
            received_at,
            smtp_mail_from: smtp_mail_from.to_string(),
            smtp_rcpt_to: smtp_rcpt_to.to_string(),
            mote_id: mote_id.clone(),
            sig: Vec::new(),
        };
        att.sig = self.key.sign_domain(ATTESTATION_DS, &att.signing_body());
        att
    }
}

/// A signed statement "received via gateway `G` at `T` from `<SMTP envelope>`", bound to the
/// wrapped MOTE's content address (§7.2a). Travels alongside the MOTE into the mesh; a stateless
/// gateway holds nothing after emitting it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attestation {
    /// The recipient domain this gateway is MX for (the attestation key is anchored here).
    pub domain: String,
    /// The DNS selector under `<selector>._dmtap-gw.<domain>`.
    pub selector: String,
    /// The attestation public key (also the DNS-published value); the recipient MUST still confirm
    /// this equals the key actually published under its own domain — carrying it here is a hint,
    /// never the trust anchor.
    pub gateway_key: Vec<u8>,
    pub received_at: TimestampMs,
    pub smtp_mail_from: String,
    pub smtp_rcpt_to: String,
    /// The content address of the MOTE this attestation vouches for.
    pub mote_id: ContentId,
    pub sig: Vec<u8>,
}

impl Attestation {
    /// The signed preimage body: every field except `sig`, length-prefixed so no field boundary is
    /// ambiguous (a naive concatenation would let `a‖b` collide with `a'‖b'`).
    fn signing_body(&self) -> Vec<u8> {
        let mut m = Vec::new();
        let push = |m: &mut Vec<u8>, b: &[u8]| {
            m.extend_from_slice(&(b.len() as u64).to_be_bytes());
            m.extend_from_slice(b);
        };
        push(&mut m, self.domain.as_bytes());
        push(&mut m, self.selector.as_bytes());
        push(&mut m, &self.gateway_key);
        m.extend_from_slice(&self.received_at.to_be_bytes());
        push(&mut m, self.smtp_mail_from.as_bytes());
        push(&mut m, self.smtp_rcpt_to.as_bytes());
        push(&mut m, self.mote_id.as_bytes());
        m
    }

    /// Recipient-side verification (§7.2a, default-on). `published_key` is the attestation public
    /// key the recipient looked up at `<selector>._dmtap-gw.<own-domain>` (via [`GwKeyResolver`]).
    ///
    /// Rejects (fail-closed) if:
    /// - the attestation names a domain other than the recipient's own (`expected_domain`), or
    /// - no key is published for that domain/selector, or
    /// - the carried `gateway_key` disagrees with the published one (can't self-assert a key), or
    /// - the signature does not verify under the published key.
    pub fn verify(
        &self,
        expected_domain: &str,
        published_key: Option<&[u8]>,
        wrapped_mote_id: &ContentId,
    ) -> Result<(), AttestationError> {
        if self.domain != expected_domain {
            return Err(AttestationError::WrongDomain);
        }
        if &self.mote_id != wrapped_mote_id {
            // The attestation vouches for a different MOTE than the one delivered — reject rather
            // than accept an attestation lifted off another message.
            return Err(AttestationError::MoteMismatch);
        }
        let published = published_key.ok_or(AttestationError::NoPublishedKey)?;
        if published != self.gateway_key.as_slice() {
            return Err(AttestationError::KeyMismatch);
        }
        verify_domain(published, ATTESTATION_DS, &self.signing_body(), &self.sig)
            .map_err(AttestationError::BadSignature)?;
        Ok(())
    }
}

/// Errors from recipient-side attestation verification (§7.2a). Every one is a hard reject — a
/// recipient MUST NOT surface an unverifiable-attestation MOTE as ordinary inbox mail.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AttestationError {
    #[error("attestation domain does not match the recipient's own domain")]
    WrongDomain,
    #[error("no attestation key published under this domain/selector")]
    NoPublishedKey,
    #[error("carried gateway key disagrees with the DNS-published key")]
    KeyMismatch,
    #[error("attestation vouches for a different MOTE than the one delivered")]
    MoteMismatch,
    #[error("attestation signature verification failed: {0}")]
    BadSignature(IdentityError),
}

/// Resolves the attestation public key published at `<selector>._dmtap-gw.<domain>` (§7.2a) —
/// the DNS TXT lookup, abstracted so it is testable in-process (a real impl queries DNS).
pub trait GwKeyResolver {
    /// Return the attestation public key published for `domain`/`selector`, or `None` if the
    /// domain has published no such key (recipient MUST then reject the attestation).
    fn resolve_gw_key(&self, domain: &str, selector: &str) -> Option<Vec<u8>>;
}

/// An in-memory `GwKeyResolver` for tests and single-domain self-host deployments: a static map of
/// `(domain, selector) → attestation public key`, modelling the DNS zone's `_dmtap-gw` records.
#[derive(Debug, Default, Clone)]
pub struct StaticGwKeys {
    entries: Vec<(String, String, Vec<u8>)>,
}

impl StaticGwKeys {
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish `key` at `<selector>._dmtap-gw.<domain>`.
    pub fn publish(mut self, domain: impl Into<String>, selector: impl Into<String>, key: Vec<u8>) -> Self {
        self.entries.push((domain.into(), selector.into(), key));
        self
    }
}

impl GwKeyResolver for StaticGwKeys {
    fn resolve_gw_key(&self, domain: &str, selector: &str) -> Option<Vec<u8>> {
        self.entries
            .iter()
            .find(|(d, s, _)| d == domain && s == selector)
            .map(|(_, _, k)| k.clone())
    }
}

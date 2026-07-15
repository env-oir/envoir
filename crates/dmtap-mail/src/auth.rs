//! Authentication — app-passwords mapped to the identity, and the SASL mechanisms the legacy
//! protocols use (spec §8.2: "Auth = app-passwords … so legacy clients authenticate without
//! touching the keypair").
//!
//! The node issues app-specific passwords, each bound to the owner's identity public key. A
//! legacy IMAP/POP/SMTP login presents `(username, app-password)`; we verify it and hand back the
//! bound identity. SASL PLAIN (RFC 4616) and LOGIN are supported; both carry the same credential.
//! TLS/STARTTLS terminates on the node (spec §8.2) — these mechanisms therefore assume a
//! confidential channel and MUST NOT be offered in cleartext (advertised via LOGINDISABLED until
//! STARTTLS; see the protocol modules).

use crate::util::base64_decode;

/// An issued app-password (spec §8.2), bound to the owner's identity key. The secret is stored
/// verbatim here for the reference; a real node stores a KDF hash and compares in constant time.
#[derive(Debug, Clone)]
pub struct AppPassword {
    pub username: String,
    pub secret: String,
    /// The DMTAP identity public key this credential authenticates as.
    pub identity_pub: Vec<u8>,
    pub label: String,
}

/// Verifies credentials and resolves them to a bound identity. A real node consults its
/// app-password table; [`StaticAuthenticator`] is the reference/testing implementation.
pub trait Authenticator {
    /// Returns the bound identity public key on success, or `None` on any failure (fail closed).
    fn verify(&self, username: &str, password: &str) -> Option<Vec<u8>>;

    /// The shared secret for a user, if the backend can expose it. Required only for POP3 APOP
    /// (RFC 1939 §7), whose digest is computed over the plaintext secret server-side. Defaults to
    /// `None` (APOP unsupported) so most backends need not store recoverable secrets.
    fn secret_for(&self, _username: &str) -> Option<String> {
        None
    }
}

/// A fixed set of app-passwords (reference/testing). Comparison is length-independent-ish; a
/// production node MUST use a constant-time compare over a KDF hash.
#[derive(Debug, Clone, Default)]
pub struct StaticAuthenticator {
    passwords: Vec<AppPassword>,
}

impl StaticAuthenticator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Issue an app-password bound to `identity_pub`.
    pub fn issue(
        &mut self,
        username: impl Into<String>,
        secret: impl Into<String>,
        identity_pub: Vec<u8>,
        label: impl Into<String>,
    ) -> &mut Self {
        self.passwords.push(AppPassword {
            username: username.into(),
            secret: secret.into(),
            identity_pub,
            label: label.into(),
        });
        self
    }
}

impl Authenticator for StaticAuthenticator {
    fn verify(&self, username: &str, password: &str) -> Option<Vec<u8>> {
        self.passwords
            .iter()
            .find(|p| p.username == username && ct_eq(p.secret.as_bytes(), password.as_bytes()))
            .map(|p| p.identity_pub.clone())
    }

    fn secret_for(&self, username: &str) -> Option<String> {
        self.passwords.iter().find(|p| p.username == username).map(|p| p.secret.clone())
    }
}

/// Constant-time-ish byte comparison (length leaks, contents do not).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// A decoded SASL credential: authentication identity (authcid) + password. `authzid` (the
/// authorization identity, RFC 4616) is captured but must equal authcid or be empty here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaslCredential {
    pub authzid: Option<String>,
    pub authcid: String,
    pub password: String,
}

/// The SASL mechanisms this crate implements (advertised in CAPABILITY / EHLO / CAPA).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaslMechanism {
    Plain,
    Login,
}

impl SaslMechanism {
    pub fn parse(name: &str) -> Option<SaslMechanism> {
        match name.to_ascii_uppercase().as_str() {
            "PLAIN" => Some(SaslMechanism::Plain),
            "LOGIN" => Some(SaslMechanism::Login),
            _ => None, // unknown mechanism — reject, do not guess
        }
    }
    pub fn name(&self) -> &'static str {
        match self {
            SaslMechanism::Plain => "PLAIN",
            SaslMechanism::Login => "LOGIN",
        }
    }
}

/// Decode a SASL PLAIN response (RFC 4616): base64 of `authzid NUL authcid NUL passwd`.
pub fn decode_plain(b64: &str) -> Option<SaslCredential> {
    let raw = base64_decode(b64.trim())?;
    let mut parts = raw.split(|&b| b == 0);
    let authzid = parts.next()?;
    let authcid = parts.next()?;
    let passwd = parts.next()?;
    if parts.next().is_some() {
        return None; // too many NUL-separated fields — malformed
    }
    let authzid = String::from_utf8(authzid.to_vec()).ok()?;
    Some(SaslCredential {
        authzid: if authzid.is_empty() { None } else { Some(authzid) },
        authcid: String::from_utf8(authcid.to_vec()).ok()?,
        password: String::from_utf8(passwd.to_vec()).ok()?,
    })
}

/// Decode one base64 field of the SASL LOGIN exchange (username, then password).
pub fn decode_login_field(b64: &str) -> Option<String> {
    String::from_utf8(base64_decode(b64.trim())?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::base64_encode;

    #[test]
    fn plain_decodes() {
        // authzid empty, authcid "alice", passwd "s3cret".
        let payload = b"\0alice\0s3cret";
        let cred = decode_plain(&base64_encode(payload)).unwrap();
        assert_eq!(cred.authcid, "alice");
        assert_eq!(cred.password, "s3cret");
        assert_eq!(cred.authzid, None);
    }

    #[test]
    fn plain_rejects_malformed() {
        assert!(decode_plain(&base64_encode(b"onlyonefield")).is_none());
        assert!(decode_plain(&base64_encode(b"a\0b\0c\0d")).is_none());
    }

    #[test]
    fn login_field_decodes() {
        assert_eq!(decode_login_field(&base64_encode(b"alice")).as_deref(), Some("alice"));
    }

    #[test]
    fn static_authenticator_verifies_and_fails_closed() {
        let mut a = StaticAuthenticator::new();
        a.issue("alice@dmtap.local", "app-pw-1", vec![1, 2, 3], "iphone");
        assert_eq!(a.verify("alice@dmtap.local", "app-pw-1"), Some(vec![1, 2, 3]));
        assert_eq!(a.verify("alice@dmtap.local", "wrong"), None);
        assert_eq!(a.verify("mallory", "app-pw-1"), None);
    }

    #[test]
    fn mechanism_parse() {
        assert_eq!(SaslMechanism::parse("plain"), Some(SaslMechanism::Plain));
        assert_eq!(SaslMechanism::parse("LOGIN"), Some(SaslMechanism::Login));
        assert_eq!(SaslMechanism::parse("SCRAM-SHA-256"), None);
    }
}

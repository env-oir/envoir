//! The recipient directory (spec §3 `resolve` / §19.1.1): map an inbound legacy `RCPT TO`
//! (`user@domain`) to the DMTAP [`RecipientKey`] the MOTE is sealed and routed to.
//!
//! [`crate::inbound::KeyDirectory`] is the abstract seam; this module supplies two concrete,
//! **operator-configurable** implementations so a real deployment is not left with a silent
//! resolve-nobody stub:
//!
//! - [`InMemoryDirectory`] — an explicit `email → key` table built in code (or from an already
//!   parsed source). The unit of composition; a directory-service client would build one of these.
//! - [`FileDirectory`] — the same table loaded from a simple line-oriented config file
//!   (`<email> <ik-b64> <seal-b64>`), the reference file-backed directory a self-hoster points
//!   `GATEWAY_DIRECTORY` at.
//!
//! Both resolve **case-insensitively** on the full address (local-part + domain), which is what the
//! inbound MX session hands in after stripping angle brackets. Neither performs key-transparency
//! verification — that (the KT-log inclusion proof of §19.1.1) is the documented next seam a
//! production directory layers on top of the raw `email → key` mapping resolved here.

use std::collections::HashMap;
use std::path::Path;

use crate::b64;
use crate::inbound::{KeyDirectory, RecipientKey};

/// An explicit in-memory recipient directory: a case-insensitive `email → RecipientKey` table.
///
/// This is the reference [`KeyDirectory`] a deployment builds from whatever authoritative source it
/// has (a config file via [`FileDirectory`], a directory-service response, a database row). Resolves
/// only addresses it was told about; everything else is `None` (→ SMTP `550`, the safe default).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct InMemoryDirectory {
    /// Keyed by the lowercased full address so `resolve` is case-insensitive (RFC 5321 §2.4: the
    /// domain is case-insensitive and virtually all real mailbox local-parts are treated so too).
    entries: HashMap<String, RecipientKey>,
}

impl InMemoryDirectory {
    /// An empty directory (resolves nobody). Add recipients with [`Self::with_recipient`].
    pub fn new() -> Self {
        InMemoryDirectory { entries: HashMap::new() }
    }

    /// Register (or replace) `email`'s DMTAP key. Chainable.
    pub fn with_recipient(mut self, email: impl AsRef<str>, key: RecipientKey) -> Self {
        self.insert(email, key);
        self
    }

    /// Register (or replace) `email`'s DMTAP key.
    pub fn insert(&mut self, email: impl AsRef<str>, key: RecipientKey) {
        self.entries.insert(email.as_ref().trim().to_ascii_lowercase(), key);
    }

    /// Number of configured recipients.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the directory resolves nobody.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate the configured `(lowercased-email, key)` recipients. The personal run-mode uses this
    /// to seed the key-registered admission registry from the operator's own directory, so the same
    /// file that resolves inbound recipients also authorizes those identities to relay outbound.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &RecipientKey)> {
        self.entries.iter().map(|(e, k)| (e.as_str(), k))
    }

    /// Parse the reference directory file format into an [`InMemoryDirectory`].
    ///
    /// One recipient per line, whitespace-separated:
    ///
    /// ```text
    /// # comment lines and blank lines are ignored
    /// alice@example.org  <ik-base64>  <seal-base64>
    /// ```
    ///
    /// `ik` is the recipient's Ed25519 identity key and `seal` their X25519 sealing public key, both
    /// standard Base64 (RFC 4648). A malformed line fails the **whole** parse with its 1-based line
    /// number — a directory that silently dropped a garbled recipient could route that user's mail to
    /// `550` (a silent unreachability), so parsing is fail-closed.
    pub fn parse(text: &str) -> Result<Self, DirectoryError> {
        let mut dir = InMemoryDirectory::new();
        for (idx, raw) in text.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut fields = line.split_whitespace();
            let lineno = idx + 1;
            let email = fields.next().ok_or(DirectoryError::MissingField { line: lineno, field: "email" })?;
            let ik_b64 = fields.next().ok_or(DirectoryError::MissingField { line: lineno, field: "ik" })?;
            let seal_b64 =
                fields.next().ok_or(DirectoryError::MissingField { line: lineno, field: "seal" })?;
            if fields.next().is_some() {
                return Err(DirectoryError::TrailingData { line: lineno });
            }
            if !email.contains('@') {
                return Err(DirectoryError::BadAddress { line: lineno, addr: email.to_string() });
            }
            let ik = b64::decode(ik_b64)
                .map_err(|e| DirectoryError::BadBase64 { line: lineno, field: "ik", reason: e })?;
            let seal_pub = b64::decode(seal_b64)
                .map_err(|e| DirectoryError::BadBase64 { line: lineno, field: "seal", reason: e })?;
            dir.insert(email, RecipientKey { ik, seal_pub });
        }
        Ok(dir)
    }
}

impl KeyDirectory for InMemoryDirectory {
    fn resolve(&self, rcpt: &str) -> Option<RecipientKey> {
        self.entries.get(&rcpt.trim().to_ascii_lowercase()).cloned()
    }
}

/// A [`KeyDirectory`] loaded from the reference directory file at construction time.
///
/// The file is read and parsed once (a stateless gateway does not watch it live; a reload is a
/// restart, which is cheap — the gateway holds no mail state, §7.4). The in-memory table it produces
/// is the resolver. `GATEWAY_DIRECTORY` in the daemon points at this file.
#[derive(Debug, Clone)]
pub struct FileDirectory {
    inner: InMemoryDirectory,
}

impl FileDirectory {
    /// Load and parse the directory file at `path`.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, DirectoryError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)
            .map_err(|e| DirectoryError::Io { path: path.display().to_string(), reason: e.to_string() })?;
        Ok(FileDirectory { inner: InMemoryDirectory::parse(&text)? })
    }

    /// Number of configured recipients.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the directory resolves nobody.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Iterate the loaded `(lowercased-email, key)` recipients (see [`InMemoryDirectory::iter`]).
    pub fn iter(&self) -> impl Iterator<Item = (&str, &RecipientKey)> {
        self.inner.iter()
    }
}

impl KeyDirectory for FileDirectory {
    fn resolve(&self, rcpt: &str) -> Option<RecipientKey> {
        self.inner.resolve(rcpt)
    }
}

/// Why a directory file could not be parsed/loaded. All variants fail the whole load closed rather
/// than silently dropping a recipient (a dropped recipient is a silent `550` unreachability).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DirectoryError {
    #[error("directory file {path}: {reason}")]
    Io { path: String, reason: String },
    #[error("directory line {line}: missing {field} field")]
    MissingField { line: usize, field: &'static str },
    #[error("directory line {line}: unexpected trailing data (expected exactly: email ik seal)")]
    TrailingData { line: usize },
    #[error("directory line {line}: {addr:?} is not an email address (no '@')")]
    BadAddress { line: usize, addr: String },
    #[error("directory line {line}: {field} is not valid base64: {reason}")]
    BadBase64 { line: usize, field: &'static str, reason: &'static str },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(ik: &[u8], seal: &[u8]) -> RecipientKey {
        RecipientKey { ik: ik.to_vec(), seal_pub: seal.to_vec() }
    }

    #[test]
    fn in_memory_resolves_case_insensitively() {
        let dir = InMemoryDirectory::new().with_recipient("Alice@Example.ORG", key(&[1, 2, 3], &[4, 5, 6]));
        assert_eq!(dir.resolve("alice@example.org"), Some(key(&[1, 2, 3], &[4, 5, 6])));
        assert_eq!(dir.resolve("ALICE@EXAMPLE.ORG"), Some(key(&[1, 2, 3], &[4, 5, 6])));
        assert_eq!(dir.resolve(" alice@example.org "), Some(key(&[1, 2, 3], &[4, 5, 6])));
        assert_eq!(dir.resolve("bob@example.org"), None);
        assert_eq!(dir.len(), 1);
        assert!(!dir.is_empty());
    }

    #[test]
    fn parses_the_reference_file_format_with_comments_and_blanks() {
        let ik = b64::encode(&[9u8; 32]);
        let seal = b64::encode(&[7u8; 32]);
        let text = format!(
            "# recipient directory\n\
             \n\
             alice@example.org  {ik}  {seal}   # inline comment\n\
             bob@example.org {ik} {seal}\n"
        );
        let dir = InMemoryDirectory::parse(&text).expect("parse");
        assert_eq!(dir.len(), 2);
        assert_eq!(dir.resolve("alice@example.org").unwrap().ik, vec![9u8; 32]);
        assert_eq!(dir.resolve("bob@example.org").unwrap().seal_pub, vec![7u8; 32]);
    }

    #[test]
    fn parse_fails_closed_on_a_malformed_line() {
        let ik = b64::encode(&[1u8; 32]);
        // Missing the seal field.
        let text = format!("alice@example.org {ik}\n");
        assert_eq!(
            InMemoryDirectory::parse(&text),
            Err(DirectoryError::MissingField { line: 1, field: "seal" })
        );

        // Not an address.
        let seal = b64::encode(&[2u8; 32]);
        let text = format!("notanemail {ik} {seal}\n");
        assert!(matches!(
            InMemoryDirectory::parse(&text),
            Err(DirectoryError::BadAddress { line: 1, .. })
        ));

        // Bad base64.
        let text = "alice@example.org !!!!! @@@@@\n";
        assert!(matches!(
            InMemoryDirectory::parse(text),
            Err(DirectoryError::BadBase64 { line: 1, field: "ik", .. })
        ));

        // Trailing junk.
        let text = format!("alice@example.org {ik} {seal} extra-token\n");
        assert_eq!(
            InMemoryDirectory::parse(&text),
            Err(DirectoryError::TrailingData { line: 1 })
        );
    }

    #[test]
    fn file_directory_round_trips_through_a_temp_file() {
        let ik = b64::encode(&[3u8; 32]);
        let seal = b64::encode(&[4u8; 32]);
        let mut path = std::env::temp_dir();
        path.push(format!("envoir-gw-dir-{}.txt", std::process::id()));
        std::fs::write(&path, format!("carol@example.org {ik} {seal}\n")).expect("write");
        let dir = FileDirectory::load(&path).expect("load");
        assert_eq!(dir.len(), 1);
        assert!(!dir.is_empty());
        assert_eq!(dir.resolve("carol@example.org").unwrap().ik, vec![3u8; 32]);
        assert!(dir.resolve("nobody@example.org").is_none());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_file_is_an_io_error_not_a_panic() {
        assert!(matches!(
            FileDirectory::load("/nonexistent/envoir/gateway/directory.txt"),
            Err(DirectoryError::Io { .. })
        ));
    }
}

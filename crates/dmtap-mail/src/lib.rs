//! # dmtap-mail — mail-protocol server layer for Envoir (DMTAP §8)
//!
//! A **reference implementation, not normative** (the DMTAP spec repo governs, spec §10.4). This
//! crate turns one DMTAP MOTE store into every mail surface a client might speak, so **both**
//! legacy clients (old iPhone Mail, Outlook, Thunderbird, mutt) and modern JMAP clients work
//! against a node unchanged (spec §8.1–§8.2). Every protocol is a *view* of the same
//! [`store::MailStore`] projection of `Kind::Mail` MOTEs.
//!
//! ## Modules
//! - [`store`] — the MOTE→mailbox projection: mailboxes, messages, flags, SPECIAL-USE auto-map.
//! - [`mime`] — RFC 5322/MIME render (MOTE→message) and parse (message→ENVELOPE/BODYSTRUCTURE).
//! - [`auth`] — app-passwords bound to the identity + SASL PLAIN/LOGIN (spec §8.2).
//! - [`imap`] — IMAP4rev2 (RFC 9051) + rev1 (RFC 3501): tokenizer, command AST, response encoder,
//!   and the session state machine.
//! - [`search`] — IMAP SEARCH key parser + evaluator.
//! - [`smtp`] — SMTP submission (RFC 6409): EHLO/AUTH/MAIL/RCPT/DATA → MOTE.
//! - [`pop3`] — POP3 (RFC 1939) incl. APOP.
//! - [`jmap`] — JMAP Core/Mail (RFC 8620/8621): Session, `/get` `/query` `/set` `/changes`, blobs.
//! - [`autodiscover`] — SRV (RFC 6186), Thunderbird autoconfig, Apple `.mobileconfig`, MS Autodiscover.
//!
//! ## Design constraints
//! The protocol core (parsers, encoders, state machines) is **synchronous and std-only**, so it
//! always builds offline and is fully unit/integration tested. Real TCP listeners (thread-per-
//! connection, std only — no async runtime) live behind the optional `net` feature. See
//! `README.md` for the full capability/extension matrix (implemented vs deferred — nothing is
//! silently dropped).
//!
//! ## Decentralization invariant (spec §8.5)
//! These are **edge-compat surfaces on the user's own node**, not a central server: the node
//! terminates TLS and speaks the legacy protocol, the mesh/relay never decrypts, and there is no
//! central IMAP/JMAP store for any data class.

pub mod auth;
pub mod autodiscover;
pub mod imap;
pub mod jmap;
pub mod mime;
pub mod pop3;
pub mod search;
pub mod smtp;
pub mod store;
pub mod util;

#[cfg(feature = "net")]
pub mod net;

pub use auth::{Authenticator, StaticAuthenticator};
pub use store::{Flag, MailStore, Mailbox, MemoryStore, Message, SpecialUse};

/// The set of RFCs this crate profiles, for the capability matrix / conformance notes (spec §15).
pub const IMPLEMENTED_RFCS: &[&str] = &[
    "RFC 9051 (IMAP4rev2)",
    "RFC 3501 (IMAP4rev1)",
    "RFC 4315 (UIDPLUS)",
    "RFC 6851 (MOVE)",
    "RFC 2177 (IDLE)",
    "RFC 7162 (CONDSTORE/QRESYNC)",
    "RFC 4731/9051 (ESEARCH)",
    "RFC 5258 (LIST-EXTENDED)",
    "RFC 6154 (SPECIAL-USE)",
    "RFC 2971 (ID)",
    "RFC 4959 (SASL-IR)",
    "RFC 7888 (LITERAL+)",
    "RFC 5161 (ENABLE)",
    "RFC 2342 (NAMESPACE)",
    "RFC 6409 (Submission)",
    "RFC 3207 (STARTTLS)",
    "RFC 4954 (SMTP AUTH)",
    "RFC 6152 (8BITMIME)",
    "RFC 6531 (SMTPUTF8)",
    "RFC 1870 (SIZE)",
    "RFC 3461 (DSN)",
    "RFC 1939 (POP3)",
    "RFC 2449 (POP3 CAPA)",
    "RFC 5034 (POP3 SASL)",
    "RFC 8620 (JMAP Core)",
    "RFC 8621 (JMAP Mail)",
    "RFC 6186 (SRV autoconfig)",
    "RFC 4616 (SASL PLAIN)",
];

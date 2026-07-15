//! IMAP4rev2 (RFC 9051) + IMAP4rev1 (RFC 3501) server, projecting the MOTE store (spec §8.2).
//!
//! Submodules: [`sequence`] (sequence sets), [`parser`] (tokenizer + command AST), [`response`]
//! (ENVELOPE/BODYSTRUCTURE/section encoding), and [`session`] (the state machine). SEARCH keys
//! live in [`crate::search`]. See the crate README for the full capability/extension matrix.

pub mod parser;
pub mod response;
pub mod sequence;
pub mod session;

pub use session::{Session, State};

/// The advertised CAPABILITY set (RFC 9051 §6.1.1). Before STARTTLS on a cleartext channel we
/// advertise `LOGINDISABLED` and withhold the SASL mechanisms (RFC 9051 §5.1 security note).
pub fn capabilities(tls: bool) -> Vec<&'static str> {
    let mut caps = vec![
        "IMAP4rev2",
        "IMAP4rev1",
        "LITERAL+",
        "SASL-IR",
        "ENABLE",
        "IDLE",
        "NAMESPACE",
        "ID",
        "UIDPLUS",
        "MOVE",
        "CONDSTORE",
        "QRESYNC",
        "ESEARCH",
        "SEARCHRES",
        "LIST-EXTENDED",
        "LIST-STATUS",
        "SPECIAL-USE",
        "UNSELECT",
        "STATUS=SIZE",
    ];
    if tls {
        caps.push("AUTH=PLAIN");
        caps.push("AUTH=LOGIN");
    } else {
        caps.push("STARTTLS");
        caps.push("LOGINDISABLED");
    }
    caps
}

/// The CAPABILITY line body (space-joined), used in the greeting and CAPABILITY responses.
pub fn capability_line(tls: bool) -> String {
    let mut s = String::from("CAPABILITY ");
    s.push_str(&capabilities(tls).join(" "));
    s
}

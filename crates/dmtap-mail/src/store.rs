//! The **MailStore** — the projection of the DMTAP MOTE store as mailboxes/messages/flags that
//! every client protocol (IMAP/POP3/JMAP) is a *view* of (spec §8: "every protocol is a view of
//! the same mailbox").
//!
//! A DMTAP node holds `Kind::Mail` MOTEs (spec §2.3). This module renders a decrypted MOTE
//! [`Payload`](dmtap_core::mote::Payload) into an RFC 5322 message and files it into a mailbox,
//! auto-mapping the SPECIAL-USE folders (`\Sent \Drafts \Trash \Junk \Archive`, RFC 6154). The
//! in-memory [`MemoryStore`] is the reference backing used by the servers and the tests; a real
//! node would back the same trait with its encrypted-at-rest store + device-cluster CRDT (§8.3).

use std::collections::BTreeMap;

use dmtap_core::mote::Payload;
use dmtap_core::TimestampMs;

use crate::mime;

/// A message unique identifier within a mailbox (IMAP UID, RFC 9051 §2.3.1.1).
pub type Uid = u32;
/// The CONDSTORE/QRESYNC modification sequence (RFC 7162).
pub type ModSeq = u64;

/// An IMAP message flag (RFC 9051 §2.3.2). System flags plus arbitrary keywords.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Flag {
    Seen,
    Answered,
    Flagged,
    Deleted,
    Draft,
    /// `\Recent` — session-scoped; RFC 9051 removed it, RFC 3501 keeps it. We track it for rev1.
    Recent,
    /// A custom keyword (atom), e.g. `$Forwarded`, `$MDNSent`, `NonJunk`.
    Keyword(String),
}

impl Flag {
    /// The IMAP wire form, e.g. `\Seen`, `\Answered`, or a bare keyword.
    pub fn imap(&self) -> String {
        match self {
            Flag::Seen => "\\Seen".into(),
            Flag::Answered => "\\Answered".into(),
            Flag::Flagged => "\\Flagged".into(),
            Flag::Deleted => "\\Deleted".into(),
            Flag::Draft => "\\Draft".into(),
            Flag::Recent => "\\Recent".into(),
            Flag::Keyword(k) => k.clone(),
        }
    }

    /// Parse an IMAP flag token (case-insensitive for the system flags).
    pub fn parse(tok: &str) -> Flag {
        match tok.to_ascii_lowercase().as_str() {
            "\\seen" => Flag::Seen,
            "\\answered" => Flag::Answered,
            "\\flagged" => Flag::Flagged,
            "\\deleted" => Flag::Deleted,
            "\\draft" => Flag::Draft,
            "\\recent" => Flag::Recent,
            _ => Flag::Keyword(tok.to_string()),
        }
    }
}

/// A SPECIAL-USE folder role (RFC 6154), auto-mapped from MOTE routing so that Apple Mail /
/// Thunderbird show the right icons and put Sent/Drafts/Trash in the right place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpecialUse {
    Inbox,
    Sent,
    Drafts,
    Trash,
    Junk,
    Archive,
    All,
}

impl SpecialUse {
    /// The LIST SPECIAL-USE attribute, or `None` for INBOX (which is named, not attributed).
    pub fn attribute(&self) -> Option<&'static str> {
        match self {
            SpecialUse::Inbox => None,
            SpecialUse::Sent => Some("\\Sent"),
            SpecialUse::Drafts => Some("\\Drafts"),
            SpecialUse::Trash => Some("\\Trash"),
            SpecialUse::Junk => Some("\\Junk"),
            SpecialUse::Archive => Some("\\Archive"),
            SpecialUse::All => Some("\\All"),
        }
    }

    /// JMAP `role` string (RFC 8621 §2), lowercase.
    pub fn jmap_role(&self) -> &'static str {
        match self {
            SpecialUse::Inbox => "inbox",
            SpecialUse::Sent => "sent",
            SpecialUse::Drafts => "drafts",
            SpecialUse::Trash => "trash",
            SpecialUse::Junk => "junk",
            SpecialUse::Archive => "archive",
            SpecialUse::All => "all",
        }
    }
}

/// A stored message: RFC 5322 bytes plus IMAP metadata. Built either by rendering a MOTE
/// payload ([`MemoryStore::deliver_mote`]) or by a client APPEND / SMTP submission.
#[derive(Debug, Clone)]
pub struct Message {
    pub uid: Uid,
    pub flags: Vec<Flag>,
    pub internal_date: TimestampMs,
    pub modseq: ModSeq,
    pub raw: Vec<u8>,
}

impl Message {
    /// RFC822.SIZE — octet count of the raw message.
    pub fn size(&self) -> usize {
        self.raw.len()
    }

    pub fn has_flag(&self, f: &Flag) -> bool {
        self.flags.contains(f)
    }

    pub fn set_flag(&mut self, f: Flag) {
        if !self.flags.contains(&f) {
            self.flags.push(f);
        }
    }

    pub fn clear_flag(&mut self, f: &Flag) {
        self.flags.retain(|x| x != f);
    }

    /// Parse the message into headers + MIME structure (for ENVELOPE / BODYSTRUCTURE / SEARCH).
    pub fn parsed(&self) -> mime::ParsedMessage {
        mime::ParsedMessage::parse(&self.raw)
    }
}

/// A mailbox (folder) — an ordered list of messages with IMAP bookkeeping.
#[derive(Debug, Clone)]
pub struct Mailbox {
    pub name: String,
    pub special_use: Option<SpecialUse>,
    pub uid_validity: u32,
    pub uid_next: Uid,
    pub highest_modseq: ModSeq,
    pub subscribed: bool,
    pub messages: Vec<Message>,
}

impl Mailbox {
    pub fn new(name: impl Into<String>, special_use: Option<SpecialUse>) -> Self {
        Mailbox {
            name: name.into(),
            special_use,
            uid_validity: 1,
            uid_next: 1,
            highest_modseq: 1,
            subscribed: true,
            messages: Vec::new(),
        }
    }

    pub fn exists(&self) -> usize {
        self.messages.len()
    }

    pub fn recent(&self) -> usize {
        self.messages.iter().filter(|m| m.has_flag(&Flag::Recent)).count()
    }

    pub fn unseen(&self) -> usize {
        self.messages.iter().filter(|m| !m.has_flag(&Flag::Seen)).count()
    }

    /// Sequence number (1-based) of the first unseen message, per SELECT's `[UNSEEN n]`.
    pub fn first_unseen_seq(&self) -> Option<usize> {
        self.messages.iter().position(|m| !m.has_flag(&Flag::Seen)).map(|i| i + 1)
    }

    /// Append a fully-formed message, assigning the next UID and bumping modseq (UIDPLUS data).
    pub fn append(&mut self, raw: Vec<u8>, flags: Vec<Flag>, internal_date: TimestampMs) -> Uid {
        let uid = self.uid_next;
        self.uid_next += 1;
        self.highest_modseq += 1;
        self.messages.push(Message { uid, flags, internal_date, modseq: self.highest_modseq, raw });
        uid
    }

    /// UID → sequence number (1-based).
    pub fn seq_of_uid(&self, uid: Uid) -> Option<usize> {
        self.messages.iter().position(|m| m.uid == uid).map(|i| i + 1)
    }

    pub fn by_uid(&self, uid: Uid) -> Option<&Message> {
        self.messages.iter().find(|m| m.uid == uid)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StoreError {
    #[error("mailbox already exists")]
    AlreadyExists,
    #[error("no such mailbox")]
    NoSuchMailbox,
    #[error("INBOX cannot be deleted or renamed")]
    InboxImmutable,
}

/// The MailStore projection: the set of operations every protocol view needs. A real node backs
/// this with its encrypted store; [`MemoryStore`] is the reference/testing backing.
pub trait MailStore {
    fn mailbox_names(&self) -> Vec<String>;
    fn mailbox(&self, name: &str) -> Option<&Mailbox>;
    fn mailbox_mut(&mut self, name: &str) -> Option<&mut Mailbox>;
    fn create(&mut self, name: &str) -> Result<(), StoreError>;
    fn delete(&mut self, name: &str) -> Result<(), StoreError>;
    fn rename(&mut self, from: &str, to: &str) -> Result<(), StoreError>;
}

/// In-memory reference MailStore. Deterministic UIDVALIDITY, INBOX + the five SPECIAL-USE
/// folders created up front (so a fresh client sees the standard layout).
#[derive(Debug, Clone)]
pub struct MemoryStore {
    mailboxes: BTreeMap<String, Mailbox>,
    order: Vec<String>,
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryStore {
    /// A store pre-populated with INBOX and the SPECIAL-USE folders (spec §8 auto-mapping).
    pub fn new() -> Self {
        let mut s = MemoryStore { mailboxes: BTreeMap::new(), order: Vec::new() };
        s.insert(Mailbox::new("INBOX", Some(SpecialUse::Inbox)));
        s.insert(Mailbox::new("Sent", Some(SpecialUse::Sent)));
        s.insert(Mailbox::new("Drafts", Some(SpecialUse::Drafts)));
        s.insert(Mailbox::new("Trash", Some(SpecialUse::Trash)));
        s.insert(Mailbox::new("Junk", Some(SpecialUse::Junk)));
        s.insert(Mailbox::new("Archive", Some(SpecialUse::Archive)));
        s
    }

    /// An empty store with only INBOX (for tests that want a minimal layout).
    pub fn empty() -> Self {
        let mut s = MemoryStore { mailboxes: BTreeMap::new(), order: Vec::new() };
        s.insert(Mailbox::new("INBOX", Some(SpecialUse::Inbox)));
        s
    }

    fn insert(&mut self, mb: Mailbox) {
        self.order.push(mb.name.clone());
        self.mailboxes.insert(mb.name.clone(), mb);
    }

    /// Project a decrypted MOTE payload (spec §2.4) into the store as an RFC 5322 message.
    ///
    /// The MOTE is rendered to RFC 5322 by [`mime::render_rfc5322`] and filed into `mailbox`
    /// (default INBOX). This is the concrete MOTE-store → mailbox mapping of spec §8.2:
    /// "the node decrypts MOTEs and presents normal RFC 5322/MIME to the authenticated client."
    pub fn deliver_mote(&mut self, payload: &Payload, mailbox: &str, ts: TimestampMs) -> Option<Uid> {
        let raw = mime::render_rfc5322(payload, ts);
        let flags = vec![Flag::Recent];
        let mb = self.mailboxes.get_mut(mailbox)?;
        Some(mb.append(raw, flags, ts))
    }

    /// File raw RFC 5322 bytes (from SMTP submission / IMAP APPEND) into a mailbox.
    pub fn deliver_raw(
        &mut self,
        mailbox: &str,
        raw: Vec<u8>,
        flags: Vec<Flag>,
        internal_date: TimestampMs,
    ) -> Option<Uid> {
        let mb = self.mailboxes.get_mut(mailbox)?;
        Some(mb.append(raw, flags, internal_date))
    }

    /// Look up a mailbox by its SPECIAL-USE role (used by SMTP submission to file into Sent).
    pub fn by_role(&self, role: SpecialUse) -> Option<&str> {
        self.order
            .iter()
            .find(|n| self.mailboxes.get(*n).and_then(|m| m.special_use) == Some(role))
            .map(|s| s.as_str())
    }
}

impl MailStore for MemoryStore {
    fn mailbox_names(&self) -> Vec<String> {
        self.order.clone()
    }
    fn mailbox(&self, name: &str) -> Option<&Mailbox> {
        self.mailboxes.get(name)
    }
    fn mailbox_mut(&mut self, name: &str) -> Option<&mut Mailbox> {
        self.mailboxes.get_mut(name)
    }
    fn create(&mut self, name: &str) -> Result<(), StoreError> {
        if self.mailboxes.contains_key(name) {
            return Err(StoreError::AlreadyExists);
        }
        self.insert(Mailbox::new(name, None));
        Ok(())
    }
    fn delete(&mut self, name: &str) -> Result<(), StoreError> {
        if name.eq_ignore_ascii_case("INBOX") {
            return Err(StoreError::InboxImmutable);
        }
        if self.mailboxes.remove(name).is_none() {
            return Err(StoreError::NoSuchMailbox);
        }
        self.order.retain(|n| n != name);
        Ok(())
    }
    fn rename(&mut self, from: &str, to: &str) -> Result<(), StoreError> {
        if from.eq_ignore_ascii_case("INBOX") {
            return Err(StoreError::InboxImmutable);
        }
        if self.mailboxes.contains_key(to) {
            return Err(StoreError::AlreadyExists);
        }
        let mut mb = self.mailboxes.remove(from).ok_or(StoreError::NoSuchMailbox)?;
        mb.name = to.to_string();
        for n in self.order.iter_mut() {
            if n == from {
                *n = to.to_string();
            }
        }
        self.mailboxes.insert(to.to_string(), mb);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn special_use_folders_exist() {
        let s = MemoryStore::new();
        assert!(s.mailbox("INBOX").is_some());
        assert_eq!(s.by_role(SpecialUse::Sent), Some("Sent"));
        assert_eq!(s.by_role(SpecialUse::Trash), Some("Trash"));
    }

    #[test]
    fn append_assigns_uids_and_modseq() {
        let mut s = MemoryStore::empty();
        let u1 = s.deliver_raw("INBOX", b"a".to_vec(), vec![Flag::Recent], 0).unwrap();
        let u2 = s.deliver_raw("INBOX", b"b".to_vec(), vec![], 0).unwrap();
        assert_eq!((u1, u2), (1, 2));
        let mb = s.mailbox("INBOX").unwrap();
        assert_eq!(mb.exists(), 2);
        assert!(mb.messages[1].modseq > mb.messages[0].modseq);
    }

    #[test]
    fn create_delete_rename() {
        let mut s = MemoryStore::empty();
        assert!(s.create("Work").is_ok());
        assert_eq!(s.create("Work"), Err(StoreError::AlreadyExists));
        assert!(s.rename("Work", "Projects").is_ok());
        assert!(s.mailbox("Projects").is_some());
        assert_eq!(s.delete("INBOX"), Err(StoreError::InboxImmutable));
        assert!(s.delete("Projects").is_ok());
    }

    #[test]
    fn flag_parse_round_trip() {
        for f in [Flag::Seen, Flag::Answered, Flag::Deleted, Flag::Keyword("$Label".into())] {
            assert_eq!(Flag::parse(&f.imap()), f);
        }
        // System flags are case-insensitive.
        assert_eq!(Flag::parse("\\SEEN"), Flag::Seen);
    }
}

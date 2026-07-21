//! The **MailStore** — the projection of the DMTAP MOTE store as mailboxes/messages/flags that
//! every client protocol (IMAP/POP3/JMAP) is a *view* of (spec §8: "every protocol is a view of
//! the same mailbox").
//!
//! A DMTAP node holds `Kind::Mail` MOTEs (spec §2.3). This module renders a decrypted MOTE
//! [`Payload`](dmtap_core::mote::Payload) into an RFC 5322 message and files it into a mailbox,
//! auto-mapping the SPECIAL-USE folders (`\Sent \Drafts \Trash \Junk \Archive`, RFC 6154). The
//! in-memory [`MemoryStore`] is the reference backing used by the servers and the tests; a real
//! node would back the same trait with its encrypted-at-rest store + device-cluster CRDT (§8.3).

use std::cell::OnceCell;
use std::collections::BTreeMap;

use dmtap_core::mote::Payload;
use dmtap_core::TimestampMs;

use crate::mime;
use crate::util::base64_decode;

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
///
/// The MIME parse is **memoized** in `parsed_cache`: the raw bytes never change after a message
/// is stored, so ENVELOPE / BODYSTRUCTURE / SEARCH re-derivations across many FETCH/SEARCH
/// requests parse the message at most once (the IMAP hot path — see [`Message::parsed_cached`]).
#[derive(Debug, Clone)]
pub struct Message {
    pub uid: Uid,
    pub flags: Vec<Flag>,
    pub internal_date: TimestampMs,
    pub modseq: ModSeq,
    /// The modseq at which this message was **created** (appended). Distinguishes JMAP
    /// `created` from `updated` in `/changes` (RFC 8620 §5.2) without a separate log.
    pub created_modseq: ModSeq,
    pub raw: Vec<u8>,
    /// Lazily-populated MIME parse (see the type doc). `OnceCell` keeps `Message: Send` (it is
    /// `!Sync`, which is fine — a session owns its store on one thread).
    parsed_cache: OnceCell<mime::ParsedMessage>,
}

impl Message {
    /// Construct a stored message with an explicit create-modseq (used by [`Mailbox::append`]).
    pub fn new(uid: Uid, flags: Vec<Flag>, internal_date: TimestampMs, modseq: ModSeq, raw: Vec<u8>) -> Message {
        Message {
            uid,
            flags,
            internal_date,
            modseq,
            created_modseq: modseq,
            raw,
            parsed_cache: OnceCell::new(),
        }
    }

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

    /// Parse the message into headers + MIME structure (fresh, uncached).
    pub fn parsed(&self) -> mime::ParsedMessage {
        mime::ParsedMessage::parse(&self.raw)
    }

    /// The memoized MIME parse (parses once, then returns the cached structure). This is what the
    /// IMAP FETCH/SEARCH hot paths use so a 10k-message mailbox is never re-parsed per request.
    pub fn parsed_cached(&self) -> &mime::ParsedMessage {
        self.parsed_cache.get_or_init(|| mime::ParsedMessage::parse(&self.raw))
    }
}

/// A mailbox (folder) — an ordered list of messages with IMAP bookkeeping.
///
/// Messages are held in **ascending UID order** (UIDs are monotonic and expunge preserves order),
/// so UID→index lookups are `O(log n)` binary searches, not linear scans ([`Mailbox::index_of_uid`]).
/// `expunged` is the QRESYNC vanished-UID log: each expunge records `(uid, modseq)` so a client
/// that reconnects after being offline can fast-resync (RFC 7162 §3.2.5.2 VANISHED (EARLIER)) and
/// JMAP `/changes` can report `destroyed` (RFC 8620 §5.2) — both without keeping the message body.
#[derive(Debug, Clone)]
pub struct Mailbox {
    pub name: String,
    pub special_use: Option<SpecialUse>,
    pub uid_validity: u32,
    pub uid_next: Uid,
    pub highest_modseq: ModSeq,
    pub subscribed: bool,
    pub messages: Vec<Message>,
    /// `(expunged-uid, modseq-at-expunge)`, ascending by modseq. The vanished log (RFC 7162).
    pub expunged: Vec<(Uid, ModSeq)>,
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
            expunged: Vec::new(),
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

    /// The highest UID in use (`*` in a UID sequence-set). `O(1)` — messages are UID-sorted.
    pub fn max_uid(&self) -> Uid {
        self.messages.last().map(|m| m.uid).unwrap_or(0)
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
        self.messages.push(Message::new(uid, flags, internal_date, self.highest_modseq, raw));
        uid
    }

    /// Index of a UID via binary search (`O(log n)`; messages are UID-sorted).
    pub fn index_of_uid(&self, uid: Uid) -> Option<usize> {
        self.messages.binary_search_by(|m| m.uid.cmp(&uid)).ok()
    }

    /// UID → sequence number (1-based). `O(log n)`.
    pub fn seq_of_uid(&self, uid: Uid) -> Option<usize> {
        self.index_of_uid(uid).map(|i| i + 1)
    }

    pub fn by_uid(&self, uid: Uid) -> Option<&Message> {
        self.index_of_uid(uid).map(|i| &self.messages[i])
    }

    /// Remove the message at `index`, bumping modseq and recording the vanished UID in the
    /// expunge log (QRESYNC / JMAP change tracking). Returns the removed UID.
    pub fn remove_at(&mut self, index: usize) -> Option<Uid> {
        if index >= self.messages.len() {
            return None;
        }
        let uid = self.messages[index].uid;
        self.highest_modseq += 1;
        self.expunged.push((uid, self.highest_modseq));
        self.messages.remove(index);
        Some(uid)
    }

    /// UIDs expunged since `modseq` (for QRESYNC VANISHED (EARLIER) resync), ascending.
    pub fn vanished_since(&self, modseq: ModSeq) -> Vec<Uid> {
        let mut v: Vec<Uid> =
            self.expunged.iter().filter(|(_, ms)| *ms > modseq).map(|(u, _)| *u).collect();
        v.sort_unstable();
        v
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

/// A JMAP object type for `/changes` (RFC 8620 §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JmapObj {
    Email,
    Mailbox,
    Thread,
}

/// The result of a JMAP `/changes` call: object ids that were created / updated / destroyed since
/// the client's `sinceState`, plus the resulting `newState` (RFC 8620 §5.2).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JmapChanges {
    pub old_state: String,
    pub new_state: String,
    pub created: Vec<String>,
    pub updated: Vec<String>,
    pub destroyed: Vec<String>,
    pub has_more: bool,
}

/// The MailStore projection: the set of operations every protocol view needs. A real node backs
/// this with its encrypted store; [`MemoryStore`] is the reference/testing backing.
///
/// The JMAP change-log methods ([`MailStore::jmap_state`] / [`MailStore::jmap_changes`]) are
/// **default-implemented** purely from per-mailbox modseqs and the per-message create-modseq +
/// [`Mailbox::expunged`] log, so *every* backend gets a real, durable `/changes` — no separate
/// change journal, and no `cannotCalculateChanges` fallback.
pub trait MailStore {
    fn mailbox_names(&self) -> Vec<String>;
    fn mailbox(&self, name: &str) -> Option<&Mailbox>;
    fn mailbox_mut(&mut self, name: &str) -> Option<&mut Mailbox>;
    fn create(&mut self, name: &str) -> Result<(), StoreError>;
    fn delete(&mut self, name: &str) -> Result<(), StoreError>;
    fn rename(&mut self, from: &str, to: &str) -> Result<(), StoreError>;

    /// The opaque JMAP state token (RFC 8620 §1.3): an encoding of every mailbox's
    /// `highest_modseq`, from which [`jmap_changes`](MailStore::jmap_changes) computes a delta.
    fn jmap_state(&self) -> String {
        let map: BTreeMap<String, ModSeq> = self
            .mailbox_names()
            .iter()
            .filter_map(|n| self.mailbox(n).map(|mb| (n.clone(), mb.highest_modseq)))
            .collect();
        encode_state_map(&map)
    }

    /// Compute a JMAP `/changes` delta for `obj` since the `since` state token. Compares the
    /// caller's per-mailbox modseqs against the live store: a message with `modseq > old` is a
    /// change (`created` if `created_modseq > old`, else `updated`); every `expunged` entry with
    /// `modseq > old` is `destroyed`. Returns `None` only if the token is unparseable (the JMAP
    /// layer then reports `cannotCalculateChanges`).
    fn jmap_changes(&self, obj: JmapObj, since: &str) -> Option<JmapChanges> {
        let old = decode_state_map(since)?;
        let new_state = self.jmap_state();
        let mut created = Vec::new();
        let mut updated = Vec::new();
        let mut destroyed = Vec::new();

        match obj {
            JmapObj::Email | JmapObj::Thread => {
                for name in self.mailbox_names() {
                    let mb = match self.mailbox(&name) {
                        Some(mb) => mb,
                        None => continue,
                    };
                    let old_ms = old.get(&name).copied().unwrap_or(0);
                    for m in &mb.messages {
                        if m.modseq > old_ms {
                            let id = format!("{name}|{}", m.uid);
                            if m.created_modseq > old_ms {
                                created.push(id);
                            } else {
                                updated.push(id);
                            }
                        }
                    }
                    for (uid, ms) in &mb.expunged {
                        if *ms > old_ms {
                            destroyed.push(format!("{name}|{uid}"));
                        }
                    }
                }
            }
            JmapObj::Mailbox => {
                let current: BTreeMap<String, ModSeq> = self
                    .mailbox_names()
                    .iter()
                    .filter_map(|n| self.mailbox(n).map(|mb| (n.clone(), mb.highest_modseq)))
                    .collect();
                for (name, ms) in &current {
                    match old.get(name) {
                        None => created.push(name.clone()),
                        Some(old_ms) if ms != old_ms => updated.push(name.clone()),
                        _ => {}
                    }
                }
                for name in old.keys() {
                    if !current.contains_key(name) {
                        destroyed.push(name.clone());
                    }
                }
            }
        }
        Some(JmapChanges { old_state: since.to_string(), new_state, created, updated, destroyed, has_more: false })
    }
}

/// Encode a `{mailbox → modseq}` map as an opaque, order-independent state token. Length-prefixed
/// binary (so mailbox names may contain any byte) then base64 — safe to hand a client verbatim.
fn encode_state_map(map: &BTreeMap<String, ModSeq>) -> String {
    let mut buf = Vec::with_capacity(map.len() * 16);
    for (name, ms) in map {
        buf.extend_from_slice(&(name.len() as u32).to_be_bytes());
        buf.extend_from_slice(name.as_bytes());
        buf.extend_from_slice(&ms.to_be_bytes());
    }
    crate::util::base64_encode(&buf)
}

/// Inverse of [`encode_state_map`]. Returns `None` on any malformed token (fail closed).
fn decode_state_map(token: &str) -> Option<BTreeMap<String, ModSeq>> {
    // The genesis token "0" (or empty) means "before any state" — an empty map.
    if token.is_empty() || token == "0" {
        return Some(BTreeMap::new());
    }
    let bytes = base64_decode(token)?;
    let mut map = BTreeMap::new();
    let mut i = 0;
    while i < bytes.len() {
        let nlen = u32::from_be_bytes(bytes.get(i..i + 4)?.try_into().ok()?) as usize;
        i += 4;
        let name = String::from_utf8(bytes.get(i..i + nlen)?.to_vec()).ok()?;
        i += nlen;
        let ms = u64::from_be_bytes(bytes.get(i..i + 8)?.try_into().ok()?);
        i += 8;
        map.insert(name, ms);
    }
    Some(map)
}

/// The outcome of projecting a decrypted MOTE into the store.
///
/// An enum rather than `Option<Uid>` so that "not persisted, by policy" cannot be confused with
/// "no such mailbox" — and so the compiler makes every caller decide what to do about a §6.7
/// `sensitive` message instead of silently treating it as a failed delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
    /// Filed into the mailbox at this UID.
    Stored(Uid),
    /// §6.7 `sensitive`: rendered for an ephemeral view and deliberately **NOT** persisted. The
    /// caller may show these bytes and MUST NOT write them to a durable store.
    Ephemeral(Vec<u8>),
    /// The named mailbox does not exist.
    NoSuchMailbox,
}

impl Delivery {
    /// The UID if the message was actually persisted. `Ephemeral` deliberately yields `None`.
    pub fn uid(&self) -> Option<Uid> {
        match self {
            Delivery::Stored(u) => Some(*u),
            _ => None,
        }
    }

    /// Whether the message reached the store. False for both `Ephemeral` and `NoSuchMailbox`.
    pub fn is_stored(&self) -> bool {
        matches!(self, Delivery::Stored(_))
    }
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
    ///
    /// **§6.7 `sensitive` is honored here**, and this is the right place for it: every decrypted
    /// payload that becomes a stored message passes through this one funnel, so refusing here means
    /// a `sensitive` MOTE never enters the store at all — rather than being written and deleted,
    /// which is not the same thing on any real medium. The rendered bytes are still returned, as
    /// [`Delivery::Ephemeral`], because §6.7 asks for an ephemeral *view*, not for the message to be
    /// discarded: "held in memory for an ephemeral view and dropped, never written to the durable
    /// MOTE store".
    pub fn deliver_mote(
        &mut self,
        payload: &Payload,
        mailbox: &str,
        ts: TimestampMs,
    ) -> Delivery {
        let raw = mime::render_rfc5322(payload, ts);
        // Check BEFORE touching the mailbox. Honoring the flag is cooperative (§6.6 item 8) — a
        // compromised recipient can still copy what it can read — but a conformant one must not
        // create the durable artifact in the first place.
        if payload.headers.sensitive == Some(true) {
            return Delivery::Ephemeral(raw);
        }
        let flags = vec![Flag::Recent];
        match self.mailboxes.get_mut(mailbox) {
            Some(mb) => Delivery::Stored(mb.append(raw, flags, ts)),
            None => Delivery::NoSuchMailbox,
        }
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

    /// §6.7 (`sensitive`, MAY-send / MUST-honor): a message marked `sensitive` MUST NOT be written
    /// to the durable store. It is rendered for an ephemeral view and dropped.
    ///
    /// Enforced at `deliver_mote` because that is the single funnel every decrypted payload passes
    /// through on its way to becoming a stored message — so refusing here means the message never
    /// enters the store at all, rather than being written and then deleted, which is not the same
    /// thing on any real medium.
    #[test]
    fn a_sensitive_mote_is_rendered_but_never_stored() {
        use dmtap_core::mote::{Headers, Payload};
        let mk = |sensitive: Option<bool>| Payload {
            from: vec![9u8; 32],
            sig: vec![0u8; 64],
            headers: Headers {
                thread: None,
                subject: Some("private".into()),
                mime: None,
                cc: vec![],
                ext: vec![],
                sensitive,
            },
            body: b"burn after reading".to_vec(),
            refs: vec![],
            attach: vec![],
            expires: None,
        };

        let mut s = MemoryStore::empty();

        // Positive control: an ordinary message IS stored, so the assertion below is about the flag
        // and not about a delivery path that never worked.
        let ordinary = s.deliver_mote(&mk(None), "INBOX", 1_700_000_000_000);
        assert!(ordinary.is_stored(), "an unflagged message must be stored");
        assert_eq!(s.mailbox("INBOX").unwrap().exists(), 1);

        // sensitive = Some(false) is an explicit "not sensitive" and must behave like absent.
        assert!(s.deliver_mote(&mk(Some(false)), "INBOX", 1_700_000_000_000).is_stored());
        assert_eq!(s.mailbox("INBOX").unwrap().exists(), 2);

        // The flag itself: rendered, not retained.
        let out = s.deliver_mote(&mk(Some(true)), "INBOX", 1_700_000_000_000);
        match &out {
            Delivery::Ephemeral(raw) => {
                assert!(
                    !raw.is_empty(),
                    "§6.7 asks for an ephemeral VIEW — the bytes must still be produced, not discarded"
                );
            }
            other => panic!("a sensitive message must not be stored, got {other:?}"),
        }
        assert_eq!(out.uid(), None, "an unstored message has no UID to report");
        assert_eq!(
            s.mailbox("INBOX").unwrap().exists(),
            2,
            "the store must be untouched — the sensitive message never entered it"
        );
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

    #[test]
    fn index_of_uid_is_binary_search() {
        let mut s = MemoryStore::empty();
        for i in 0..1000u32 {
            s.deliver_raw("INBOX", vec![(i % 256) as u8], vec![], 0);
        }
        let mb = s.mailbox("INBOX").unwrap();
        assert_eq!(mb.index_of_uid(1), Some(0));
        assert_eq!(mb.index_of_uid(500), Some(499));
        assert_eq!(mb.index_of_uid(1000), Some(999));
        assert_eq!(mb.index_of_uid(1001), None);
        assert_eq!(mb.max_uid(), 1000);
    }

    #[test]
    fn remove_at_records_vanished() {
        let mut s = MemoryStore::empty();
        for _ in 0..4 {
            s.deliver_raw("INBOX", b"x".to_vec(), vec![], 0);
        }
        let mb = s.mailbox_mut("INBOX").unwrap();
        let base = mb.highest_modseq;
        // Remove uid 2 (index 1) then uid 3 (now index 1) — vanished log grows, modseq climbs.
        mb.remove_at(1);
        mb.remove_at(1);
        assert_eq!(mb.exists(), 2);
        let vanished = mb.vanished_since(base);
        assert_eq!(vanished, vec![2, 3]);
        // A later baseline sees nothing.
        assert!(mb.vanished_since(mb.highest_modseq).is_empty());
    }

    #[test]
    fn jmap_state_token_round_trips() {
        let s = MemoryStore::new();
        let token = s.jmap_state();
        let map = decode_state_map(&token).unwrap();
        assert!(map.contains_key("INBOX"));
        // Genesis + empty tokens decode to "before any state".
        assert!(decode_state_map("0").unwrap().is_empty());
        assert!(decode_state_map("").unwrap().is_empty());
        // Garbage fails closed.
        assert!(decode_state_map("@@not base64@@").is_none());
    }

    #[test]
    fn jmap_changes_delta_from_modseq() {
        let mut s = MemoryStore::empty();
        s.deliver_raw("INBOX", b"one".to_vec(), vec![], 0);
        let state0 = s.jmap_state();
        s.deliver_raw("INBOX", b"two".to_vec(), vec![], 0);
        let ch = s.jmap_changes(JmapObj::Email, &state0).unwrap();
        assert_eq!(ch.created, vec!["INBOX|2"]);
        assert!(ch.updated.is_empty());
        assert!(ch.destroyed.is_empty());
        // Mailbox-level changes see INBOX as updated (its modseq advanced).
        let mch = s.jmap_changes(JmapObj::Mailbox, &state0).unwrap();
        assert_eq!(mch.updated, vec!["INBOX"]);
    }
}

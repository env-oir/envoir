//! IMAP session state machine (RFC 9051 §3): NotAuthenticated → Authenticated → Selected →
//! Logout. [`Session::process`] consumes one complete command buffer (literals already read off
//! the wire) and returns the response bytes. It is transport-agnostic and fully synchronous, so
//! it is driven directly by unit/integration tests and by the optional `net` TCP server.

use crate::auth::{self, Authenticator, SaslMechanism};
use crate::mime;
use crate::search::{self, SearchCtx, SearchKey};
use crate::store::{Flag, MailStore, Mailbox, Message};

use super::parser::{self, Command, FetchItem, ParsedCommand, QResyncParams, StoreCommand, StoreOp};
use super::response;
use super::sequence::SequenceSet;
use super::capability_line;

/// IMAP connection state (RFC 9051 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    NotAuthenticated,
    Authenticated,
    Selected,
    Logout,
}

/// A pending multi-step SASL exchange awaiting a client continuation line.
enum Pending {
    Plain { tag: String },
    LoginUser { tag: String },
    LoginPass { tag: String, user: String },
}

/// An IMAP session over an owned [`MailStore`] and [`Authenticator`].
pub struct Session<S: MailStore, A: Authenticator> {
    store: S,
    auth: A,
    tls: bool,
    state: State,
    identity: Option<Vec<u8>>,
    selected: Option<String>,
    read_only: bool,
    condstore: bool,
    qresync: bool,
    idle_tag: Option<String>,
    pending: Option<Pending>,
}

impl<S: MailStore, A: Authenticator> Session<S, A> {
    pub fn new(store: S, auth: A, tls: bool) -> Self {
        Session {
            store,
            auth,
            tls,
            state: State::NotAuthenticated,
            identity: None,
            selected: None,
            read_only: false,
            condstore: false,
            qresync: false,
            idle_tag: None,
            pending: None,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }
    pub fn store(&self) -> &S {
        &self.store
    }
    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }
    pub fn into_store(self) -> S {
        self.store
    }
    /// Whether the session is idling (awaiting `DONE`).
    pub fn is_idling(&self) -> bool {
        self.idle_tag.is_some()
    }

    /// The greeting a server sends on connect (RFC 9051 §7.1.1).
    pub fn greeting(&self) -> Vec<u8> {
        format!("* OK [{}] Envoir DMTAP IMAP ready\r\n", capability_line(self.tls)).into_bytes()
    }

    /// Process one complete command buffer; returns the response bytes.
    pub fn process(&mut self, buf: &[u8]) -> Vec<u8> {
        // IDLE (RFC 2177): while idling, only a `DONE` line terminates.
        if let Some(tag) = self.idle_tag.take() {
            let t = String::from_utf8_lossy(buf);
            if t.trim().eq_ignore_ascii_case("DONE") {
                return ok(&tag, "IDLE terminated");
            }
            self.idle_tag = Some(tag);
            return Vec::new();
        }
        // SASL continuation (AUTHENTICATE multi-step).
        if let Some(p) = self.pending.take() {
            return self.continue_sasl(p, buf);
        }
        match parser::parse_command(buf) {
            Ok(pc) => self.dispatch(pc),
            Err(e) => {
                let tag = extract_tag(buf).unwrap_or_else(|| "*".into());
                bad(&tag, &format!("{e}"))
            }
        }
    }

    fn dispatch(&mut self, pc: ParsedCommand) -> Vec<u8> {
        let tag = pc.tag;
        match pc.command {
            Command::Capability => {
                let mut out = untagged(&capability_line(self.tls));
                out.extend(ok(&tag, "CAPABILITY completed"));
                out
            }
            Command::Noop => ok(&tag, "NOOP completed"),
            Command::Logout => {
                self.state = State::Logout;
                let mut out = untagged("BYE Envoir logging out");
                out.extend(ok(&tag, "LOGOUT completed"));
                out
            }
            Command::StartTls => {
                // The state machine acknowledges; the transport layer performs the handshake.
                self.tls = true;
                ok(&tag, "Begin TLS negotiation now")
            }
            Command::Id(_) => {
                let mut out =
                    untagged("ID (\"name\" \"Envoir\" \"version\" \"0.0.1\" \"vendor\" \"DMTAP\")");
                out.extend(ok(&tag, "ID completed"));
                out
            }
            Command::Enable(caps) => self.cmd_enable(&tag, &caps),
            Command::Login { user, pass } => self.cmd_login(&tag, &user, &pass),
            Command::Authenticate { mechanism, initial } => self.cmd_authenticate(&tag, &mechanism, initial),
            Command::Namespace => {
                let mut out = untagged("NAMESPACE ((\"\" \"/\")) NIL NIL");
                out.extend(ok(&tag, "NAMESPACE completed"));
                out
            }
            _ if self.identity.is_none() => no(&tag, "Not authenticated"),
            Command::Select { mailbox, condstore, qresync } => {
                self.cmd_select(&tag, &mailbox, false, condstore, qresync)
            }
            Command::Examine { mailbox, condstore, qresync } => {
                self.cmd_select(&tag, &mailbox, true, condstore, qresync)
            }
            Command::Create(name) => match self.store.create(&name) {
                Ok(()) => ok(&tag, "CREATE completed"),
                Err(e) => no(&tag, &format!("CREATE failed: {e}")),
            },
            Command::Delete(name) => match self.store.delete(&name) {
                Ok(()) => ok(&tag, "DELETE completed"),
                Err(e) => no(&tag, &format!("DELETE failed: {e}")),
            },
            Command::Rename { from, to } => match self.store.rename(&from, &to) {
                Ok(()) => ok(&tag, "RENAME completed"),
                Err(e) => no(&tag, &format!("RENAME failed: {e}")),
            },
            Command::Subscribe(name) => self.set_subscribed(&tag, &name, true),
            Command::Unsubscribe(name) => self.set_subscribed(&tag, &name, false),
            Command::List { reference, pattern, .. } => self.cmd_list(&tag, &reference, &pattern, false),
            Command::Lsub { reference, pattern } => self.cmd_list(&tag, &reference, &pattern, true),
            Command::Status { mailbox, items } => self.cmd_status(&tag, &mailbox, &items),
            Command::Append { mailbox, flags, date, message } => {
                self.cmd_append(&tag, &mailbox, flags, date, message)
            }
            Command::Idle => {
                self.idle_tag = Some(tag);
                continuation("idling")
            }
            // Selected-state commands.
            Command::Check => self.require_selected(&tag, "CHECK completed"),
            Command::Close => self.cmd_close(&tag, true),
            Command::Unselect => self.cmd_close(&tag, false),
            Command::Expunge => self.cmd_expunge(&tag, None),
            Command::UidExpunge(set) => self.cmd_expunge(&tag, Some(set)),
            Command::Search { key, uid, ret, charset } => self.cmd_search(&tag, key, uid, ret, charset),
            Command::Fetch { set, items, uid, changedsince, vanished } => {
                self.cmd_fetch(&tag, set, items, uid, changedsince, vanished)
            }
            Command::Store(sc) => self.cmd_store(&tag, sc),
            Command::Copy { set, mailbox, uid } => self.cmd_copy(&tag, set, &mailbox, uid),
            Command::Move { set, mailbox, uid } => self.cmd_move(&tag, set, &mailbox, uid),
        }
    }

    // --- auth ------------------------------------------------------------------------------

    fn cmd_login(&mut self, tag: &str, user: &str, pass: &str) -> Vec<u8> {
        if !self.tls {
            return no(tag, "[PRIVACYREQUIRED] LOGIN disabled until STARTTLS");
        }
        match self.auth.verify(user, pass) {
            Some(id) => {
                self.identity = Some(id);
                self.state = State::Authenticated;
                ok(tag, "LOGIN completed")
            }
            None => no(tag, "[AUTHENTICATIONFAILED] invalid credentials"),
        }
    }

    fn cmd_authenticate(&mut self, tag: &str, mechanism: &str, initial: Option<String>) -> Vec<u8> {
        let mech = match SaslMechanism::parse(mechanism) {
            Some(m) => m,
            None => return no(tag, "[CANNOT] unsupported SASL mechanism"),
        };
        if !self.tls {
            return no(tag, "[PRIVACYREQUIRED] AUTHENTICATE disabled until STARTTLS");
        }
        match mech {
            SaslMechanism::Plain => match initial {
                Some(ir) => self.finish_plain(tag, &ir),
                None => {
                    self.pending = Some(Pending::Plain { tag: tag.to_string() });
                    continuation("")
                }
            },
            SaslMechanism::Login => match initial {
                Some(ir) => {
                    // Initial response carries the username; still need the password.
                    let user = auth::decode_login_field(&ir).unwrap_or_default();
                    self.pending = Some(Pending::LoginPass { tag: tag.to_string(), user });
                    continuation(&crate::util::base64_encode(b"Password:"))
                }
                None => {
                    self.pending = Some(Pending::LoginUser { tag: tag.to_string() });
                    continuation(&crate::util::base64_encode(b"Username:"))
                }
            },
        }
    }

    fn continue_sasl(&mut self, pending: Pending, buf: &[u8]) -> Vec<u8> {
        let line = String::from_utf8_lossy(buf);
        let line = line.trim();
        match pending {
            Pending::Plain { tag } => self.finish_plain(&tag, line),
            Pending::LoginUser { tag } => {
                let user = auth::decode_login_field(line).unwrap_or_default();
                self.pending = Some(Pending::LoginPass { tag, user });
                continuation(&crate::util::base64_encode(b"Password:"))
            }
            Pending::LoginPass { tag, user } => {
                let pass = auth::decode_login_field(line).unwrap_or_default();
                self.finish_credentials(&tag, &user, &pass)
            }
        }
    }

    fn finish_plain(&mut self, tag: &str, ir: &str) -> Vec<u8> {
        match auth::decode_plain(ir) {
            Some(cred) => self.finish_credentials(tag, &cred.authcid, &cred.password),
            None => no(tag, "[AUTHENTICATIONFAILED] malformed SASL PLAIN"),
        }
    }

    fn finish_credentials(&mut self, tag: &str, user: &str, pass: &str) -> Vec<u8> {
        match self.auth.verify(user, pass) {
            Some(id) => {
                self.identity = Some(id);
                self.state = State::Authenticated;
                ok(tag, "AUTHENTICATE completed")
            }
            None => no(tag, "[AUTHENTICATIONFAILED] invalid credentials"),
        }
    }

    fn cmd_enable(&mut self, tag: &str, caps: &[String]) -> Vec<u8> {
        let mut enabled = Vec::new();
        for c in caps {
            match c.to_ascii_uppercase().as_str() {
                "CONDSTORE" => {
                    self.condstore = true;
                    enabled.push("CONDSTORE");
                }
                "QRESYNC" => {
                    self.qresync = true;
                    self.condstore = true;
                    enabled.push("QRESYNC");
                }
                "IMAP4REV2" => enabled.push("IMAP4rev2"),
                _ => {}
            }
        }
        let mut out = untagged(&format!("ENABLED {}", enabled.join(" ")));
        out.extend(ok(tag, "ENABLE completed"));
        out
    }

    // --- mailbox management ----------------------------------------------------------------

    fn set_subscribed(&mut self, tag: &str, name: &str, sub: bool) -> Vec<u8> {
        match self.store.mailbox_mut(name) {
            Some(mb) => {
                mb.subscribed = sub;
                ok(tag, if sub { "SUBSCRIBE completed" } else { "UNSUBSCRIBE completed" })
            }
            None => no(tag, "no such mailbox"),
        }
    }

    fn cmd_select(
        &mut self,
        tag: &str,
        name: &str,
        read_only: bool,
        condstore: bool,
        qresync: Option<QResyncParams>,
    ) -> Vec<u8> {
        let mb = match self.store.mailbox(name) {
            Some(mb) => mb,
            None => return no(tag, "[NONEXISTENT] no such mailbox"),
        };
        if condstore || qresync.is_some() {
            self.condstore = true;
        }
        let exists = mb.exists();
        let recent = mb.recent();
        let uidnext = mb.uid_next;
        let uidvalidity = mb.uid_validity;
        let highest = mb.highest_modseq;
        let unseen = mb.first_unseen_seq();

        let mut out = Vec::new();
        out.extend(untagged("FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)"));
        out.extend(untagged(&format!("{exists} EXISTS")));
        out.extend(untagged(&format!("{recent} RECENT")));
        if let Some(u) = unseen {
            out.extend(untagged(&format!("OK [UNSEEN {u}] first unseen")));
        }
        out.extend(untagged(&format!("OK [UIDVALIDITY {uidvalidity}] UIDs valid")));
        out.extend(untagged(&format!("OK [UIDNEXT {uidnext}] predicted next UID")));
        out.extend(untagged(
            "OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft \\*)] limited",
        ));
        if self.condstore {
            out.extend(untagged(&format!("OK [HIGHESTMODSEQ {highest}] highest modseq")));
        }

        // QRESYNC fast-resync (RFC 7162 §3.2.5.2): if the client's UIDVALIDITY still matches, tell
        // it which of the UIDs it knew have VANISHED (EARLIER) and re-FETCH the ones that changed
        // since its last-seen HIGHESTMODSEQ — so an iPhone that was offline catches up in one round
        // trip instead of a full re-sync.
        if let Some(q) = qresync {
            self.qresync = true;
            if q.uid_validity == uidvalidity {
                out.extend(self.qresync_resync(name, q.modseq, q.known_uids.as_ref()));
            }
        }

        self.selected = Some(name.to_string());
        self.read_only = read_only;
        self.state = State::Selected;
        let code = if read_only { "[READ-ONLY]" } else { "[READ-WRITE]" };
        let verb = if read_only { "EXAMINE" } else { "SELECT" };
        out.extend(ok(tag, &format!("{code} {verb} completed")));
        out
    }

    /// Emit the QRESYNC catch-up: a `VANISHED (EARLIER)` list of expunged UIDs and a `FETCH` of
    /// every surviving message changed since `modseq` (RFC 7162 §3.2.5.2), scoped to `known_uids`
    /// when the client supplied its known set.
    fn qresync_resync(
        &self,
        name: &str,
        modseq: u64,
        known_uids: Option<&super::sequence::SequenceSet>,
    ) -> Vec<u8> {
        let mb = match self.store.mailbox(name) {
            Some(mb) => mb,
            None => return Vec::new(),
        };
        let max_uid = mb.max_uid();
        let mut out = Vec::new();

        // VANISHED (EARLIER): UIDs expunged after the client's modseq, intersected with what it knew.
        let mut vanished: Vec<u32> = mb
            .vanished_since(modseq)
            .into_iter()
            .filter(|u| known_uids.map(|k| k.contains(*u, max_uid)).unwrap_or(true))
            .collect();
        vanished.sort_unstable();
        if !vanished.is_empty() {
            out.extend(untagged(&format!("VANISHED (EARLIER) {}", to_sequence_set(&vanished))));
        }

        // Re-FETCH survivors changed since the client's modseq (UID/FLAGS/MODSEQ).
        for (i, m) in mb.messages.iter().enumerate() {
            if m.modseq <= modseq {
                continue;
            }
            if known_uids.map(|k| !k.contains(m.uid, max_uid)).unwrap_or(false) {
                continue;
            }
            let seq = i + 1;
            out.extend(untagged(&format!(
                "{seq} FETCH (UID {} MODSEQ ({}) FLAGS ({}))",
                m.uid,
                m.modseq,
                flags_str(&m.flags)
            )));
        }
        out
    }

    fn cmd_list(&mut self, tag: &str, _reference: &str, pattern: &str, lsub: bool) -> Vec<u8> {
        let verb = if lsub { "LSUB" } else { "LIST" };
        let mut out = Vec::new();
        // `LIST "" ""` is the hierarchy-delimiter probe (RFC 9051 §6.3.9).
        if pattern.is_empty() {
            out.extend(untagged(&format!("{verb} (\\Noselect) \"/\" \"\"")));
            out.extend(ok(tag, &format!("{verb} completed")));
            return out;
        }
        let names = self.store.mailbox_names();
        for name in names {
            if !wildcard_match(pattern, &name) {
                continue;
            }
            let mb = self.store.mailbox(&name).unwrap();
            if lsub && !mb.subscribed {
                continue;
            }
            let mut attrs: Vec<String> = vec!["\\HasNoChildren".into()];
            if let Some(su) = mb.special_use.and_then(|s| s.attribute()) {
                attrs.push(su.to_string());
            }
            out.extend(untagged(&format!(
                "{verb} ({}) \"/\" {}",
                attrs.join(" "),
                response::imap_string(&name)
            )));
        }
        out.extend(ok(tag, &format!("{verb} completed")));
        out
    }

    fn cmd_status(&mut self, tag: &str, name: &str, items: &[String]) -> Vec<u8> {
        let mb = match self.store.mailbox(name) {
            Some(mb) => mb,
            None => return no(tag, "[NONEXISTENT] no such mailbox"),
        };
        let mut parts = Vec::new();
        for item in items {
            let v = match item.as_str() {
                "MESSAGES" => format!("MESSAGES {}", mb.exists()),
                "RECENT" => format!("RECENT {}", mb.recent()),
                "UIDNEXT" => format!("UIDNEXT {}", mb.uid_next),
                "UIDVALIDITY" => format!("UIDVALIDITY {}", mb.uid_validity),
                "UNSEEN" => format!("UNSEEN {}", mb.unseen()),
                "HIGHESTMODSEQ" => format!("HIGHESTMODSEQ {}", mb.highest_modseq),
                "SIZE" => format!("SIZE {}", mb.messages.iter().map(|m| m.size()).sum::<usize>()),
                _ => continue,
            };
            parts.push(v);
        }
        let mut out =
            untagged(&format!("STATUS {} ({})", response::imap_string(name), parts.join(" ")));
        out.extend(ok(tag, "STATUS completed"));
        out
    }

    fn cmd_append(
        &mut self,
        tag: &str,
        name: &str,
        flags: Vec<Flag>,
        date: Option<String>,
        message: Vec<u8>,
    ) -> Vec<u8> {
        let ts = date.as_deref().and_then(parse_internal_date).unwrap_or(0);
        let mb = match self.store.mailbox_mut(name) {
            Some(mb) => mb,
            None => return no(tag, "[TRYCREATE] no such mailbox"),
        };
        let uidvalidity = mb.uid_validity;
        let uid = mb.append(message, flags, ts);
        ok(tag, &format!("[APPENDUID {uidvalidity} {uid}] APPEND completed"))
    }

    // --- selected-state ops ----------------------------------------------------------------

    fn require_selected(&self, tag: &str, done: &str) -> Vec<u8> {
        if self.selected.is_some() {
            ok(tag, done)
        } else {
            bad(tag, "no mailbox selected")
        }
    }

    fn selected_name(&self) -> Option<String> {
        self.selected.clone()
    }

    fn cmd_close(&mut self, tag: &str, expunge: bool) -> Vec<u8> {
        let verb = if expunge { "CLOSE" } else { "UNSELECT" };
        if let (true, Some(name)) = (expunge && !self.read_only, self.selected_name()) {
            if let Some(mb) = self.store.mailbox_mut(&name) {
                // CLOSE expunges silently, but still records the vanished UIDs (QRESYNC / JMAP).
                let to_remove: Vec<usize> = mb
                    .messages
                    .iter()
                    .enumerate()
                    .filter(|(_, m)| m.has_flag(&Flag::Deleted))
                    .map(|(i, _)| i)
                    .collect();
                for &i in to_remove.iter().rev() {
                    mb.remove_at(i);
                }
            }
        }
        self.selected = None;
        self.state = State::Authenticated;
        ok(tag, &format!("{verb} completed"))
    }

    fn cmd_expunge(&mut self, tag: &str, uid_set: Option<SequenceSet>) -> Vec<u8> {
        let name = match self.selected_name() {
            Some(n) => n,
            None => return bad(tag, "no mailbox selected"),
        };
        if self.read_only {
            return no(tag, "mailbox is read-only");
        }
        let qresync = self.qresync;
        let mb = self.store.mailbox_mut(&name).unwrap();
        let max_uid = mb.max_uid();
        // Collect the sequence numbers to expunge (removed descending, so seq numbers stay valid).
        let mut to_remove: Vec<usize> = Vec::new();
        for (i, m) in mb.messages.iter().enumerate() {
            let deleted = m.has_flag(&Flag::Deleted);
            let in_set = uid_set.as_ref().map(|s| s.contains(m.uid, max_uid)).unwrap_or(true);
            if deleted && in_set {
                to_remove.push(i);
            }
        }
        let mut out = Vec::new();
        let mut vanished: Vec<u32> = Vec::new();
        for &i in to_remove.iter().rev() {
            // With QRESYNC enabled the server MUST report VANISHED, not EXPUNGE (RFC 7162 §3.2.10).
            if !qresync {
                out.extend(untagged(&format!("{} EXPUNGE", i + 1)));
            }
            if let Some(uid) = mb.remove_at(i) {
                vanished.push(uid);
            }
        }
        if qresync && !vanished.is_empty() {
            vanished.sort_unstable();
            out.extend(untagged(&format!("VANISHED {}", to_sequence_set(&vanished))));
        }
        out.extend(ok(tag, "EXPUNGE completed"));
        out
    }

    fn cmd_search(
        &mut self,
        tag: &str,
        key: SearchKey,
        uid: bool,
        ret: Vec<String>,
        charset: Option<String>,
    ) -> Vec<u8> {
        // CHARSET handling (RFC 9051 §6.4.4): we match on decoded UTF-8, so US-ASCII and UTF-8 are
        // the only meaningful charsets; anything else is rejected with [BADCHARSET] (never silently
        // treated as ASCII), listing what we support so the client can retry.
        if let Some(cs) = &charset {
            let up = cs.to_ascii_uppercase();
            if up != "UTF-8" && up != "US-ASCII" && up != "ASCII" {
                return no(tag, "[BADCHARSET (US-ASCII UTF-8)] unsupported SEARCH charset");
            }
        }
        let name = match self.selected_name() {
            Some(n) => n,
            None => return bad(tag, "no mailbox selected"),
        };
        let mb = self.store.mailbox(&name).unwrap();
        let max_seq = mb.exists() as u32;
        let max_uid = mb.max_uid();
        let mut hits: Vec<u32> = Vec::new();
        for (i, m) in mb.messages.iter().enumerate() {
            let seq = (i + 1) as u32;
            let ctx = SearchCtx::new(seq, max_seq, m.uid, max_uid, m);
            if search::eval(&key, &ctx) {
                hits.push(if uid { m.uid } else { seq });
            }
        }
        let mut out = Vec::new();
        if ret.is_empty() {
            // Classic SEARCH response.
            let list: Vec<String> = hits.iter().map(|n| n.to_string()).collect();
            out.extend(untagged(format!("SEARCH {}", list.join(" ")).trim_end()));
        } else {
            // ESEARCH (RFC 9051 §6.4.4 / RFC 4731).
            let mut parts = format!("ESEARCH (TAG \"{tag}\")");
            if uid {
                parts.push_str(" UID");
            }
            if ret.iter().any(|r| r == "MIN") {
                if let Some(m) = hits.iter().min() {
                    parts.push_str(&format!(" MIN {m}"));
                }
            }
            if ret.iter().any(|r| r == "MAX") {
                if let Some(m) = hits.iter().max() {
                    parts.push_str(&format!(" MAX {m}"));
                }
            }
            if ret.iter().any(|r| r == "COUNT") {
                parts.push_str(&format!(" COUNT {}", hits.len()));
            }
            if ret.iter().any(|r| r == "ALL") && !hits.is_empty() {
                let list: Vec<String> = hits.iter().map(|n| n.to_string()).collect();
                parts.push_str(&format!(" ALL {}", list.join(",")));
            }
            out.extend(untagged(&parts));
        }
        out.extend(ok(tag, "SEARCH completed"));
        out
    }

    fn cmd_fetch(
        &mut self,
        tag: &str,
        set: SequenceSet,
        items: Vec<FetchItem>,
        uid_mode: bool,
        changedsince: Option<u64>,
        vanished: bool,
    ) -> Vec<u8> {
        let name = match self.selected_name() {
            Some(n) => n,
            None => return bad(tag, "no mailbox selected"),
        };
        let read_only = self.read_only;
        let condstore = self.condstore || changedsince.is_some();
        let mb = self.store.mailbox_mut(&name).unwrap();
        let max_uid = mb.max_uid();

        let mut out = Vec::new();

        // The VANISHED FETCH modifier (RFC 7162 §3.2.5.1): with a CHANGEDSINCE, report the UIDs in
        // the requested set that were expunged since that modseq before the surviving-message data.
        if vanished {
            if let Some(cs) = changedsince {
                let mut v: Vec<u32> = mb
                    .vanished_since(cs)
                    .into_iter()
                    .filter(|u| set.contains(*u, max_uid))
                    .collect();
                v.sort_unstable();
                if !v.is_empty() {
                    out.extend(untagged(&format!("VANISHED (EARLIER) {}", to_sequence_set(&v))));
                }
            }
        }

        // Resolve the requested set to just the matched indices — a targeted UID FETCH is answered
        // with `O(log n)` binary searches, never a full-mailbox scan (see [`resolve_targets`]).
        for i in resolve_targets(mb, &set, uid_mode) {
            let seq = (i + 1) as u32;
            let uid = mb.messages[i].uid;
            if let Some(cs) = changedsince {
                if mb.messages[i].modseq <= cs {
                    continue;
                }
            }
            // Implicit \Seen if a body/text is fetched non-PEEK on a writable mailbox.
            if !read_only && fetch_marks_seen(&items) && !mb.messages[i].has_flag(&Flag::Seen) {
                mb.messages[i].set_flag(Flag::Seen);
                mb.highest_modseq += 1;
                mb.messages[i].modseq = mb.highest_modseq;
            }
            let msg = &mb.messages[i];
            let item_bytes = render_fetch_items(&items, msg, seq, uid, uid_mode, condstore);
            out.extend_from_slice(format!("* {seq} FETCH (").as_bytes());
            out.extend_from_slice(&item_bytes);
            out.extend_from_slice(b")\r\n");
        }
        out.extend(ok(tag, "FETCH completed"));
        out
    }

    fn cmd_store(&mut self, tag: &str, sc: StoreCommand) -> Vec<u8> {
        let name = match self.selected_name() {
            Some(n) => n,
            None => return bad(tag, "no mailbox selected"),
        };
        if self.read_only {
            return no(tag, "mailbox is read-only");
        }
        let condstore = self.condstore || sc.unchangedsince.is_some();
        let mb = self.store.mailbox_mut(&name).unwrap();

        let mut out = Vec::new();
        let mut modified: Vec<u32> = Vec::new();
        for i in resolve_targets(mb, &sc.set, sc.uid) {
            let seq = (i + 1) as u32;
            let uid = mb.messages[i].uid;
            // CONDSTORE UNCHANGEDSINCE guard (RFC 7162 §3.1).
            if let Some(uc) = sc.unchangedsince {
                if mb.messages[i].modseq > uc {
                    modified.push(uid);
                    continue;
                }
            }
            apply_store(&mut mb.messages[i], sc.op, &sc.flags);
            mb.highest_modseq += 1;
            mb.messages[i].modseq = mb.highest_modseq;

            if !sc.silent {
                let msg = &mb.messages[i];
                let mut parts = vec![format!("FLAGS ({})", flags_str(&msg.flags))];
                if sc.uid {
                    parts.push(format!("UID {uid}"));
                }
                if condstore {
                    parts.push(format!("MODSEQ ({})", msg.modseq));
                }
                out.extend(untagged(&format!("{seq} FETCH ({})", parts.join(" "))));
            }
        }
        if modified.is_empty() {
            out.extend(ok(tag, "STORE completed"));
        } else {
            let list: Vec<String> = modified.iter().map(|u| u.to_string()).collect();
            out.extend(ok(tag, &format!("[MODIFIED {}] STORE completed", list.join(","))));
        }
        out
    }

    fn cmd_copy(&mut self, tag: &str, set: SequenceSet, dest: &str, uid_mode: bool) -> Vec<u8> {
        let (copied, src_valid) = match self.collect_for_copy(&set, uid_mode) {
            Some(v) => v,
            None => return bad(tag, "no mailbox selected"),
        };
        let dmb = match self.store.mailbox_mut(dest) {
            Some(mb) => mb,
            None => return no(tag, "[TRYCREATE] no such destination mailbox"),
        };
        let dst_valid = dmb.uid_validity;
        let (mut src_uids, mut dst_uids) = (Vec::new(), Vec::new());
        for (src_uid, msg) in copied {
            let new_uid = dmb.append(msg.raw, msg.flags, msg.internal_date);
            src_uids.push(src_uid.to_string());
            dst_uids.push(new_uid.to_string());
        }
        ok(
            tag,
            &format!(
                "[COPYUID {} {} {}] COPY completed",
                dst_valid,
                compact(&src_uids, src_valid),
                dst_uids.join(",")
            ),
        )
    }

    fn cmd_move(&mut self, tag: &str, set: SequenceSet, dest: &str, uid_mode: bool) -> Vec<u8> {
        let name = match self.selected_name() {
            Some(n) => n,
            None => return bad(tag, "no mailbox selected"),
        };
        let (copied, src_valid) = match self.collect_for_copy(&set, uid_mode) {
            Some(v) => v,
            None => return bad(tag, "no mailbox selected"),
        };
        let dmb = match self.store.mailbox_mut(dest) {
            Some(mb) => mb,
            None => return no(tag, "[TRYCREATE] no such destination mailbox"),
        };
        let dst_valid = dmb.uid_validity;
        let (mut src_uids, mut dst_uids, mut moved_uids) = (Vec::new(), Vec::new(), Vec::new());
        for (src_uid, msg) in copied {
            let new_uid = dmb.append(msg.raw, msg.flags, msg.internal_date);
            src_uids.push(src_uid.to_string());
            dst_uids.push(new_uid.to_string());
            moved_uids.push(src_uid);
        }
        // Remove the moved messages from the source, emitting EXPUNGE (or VANISHED under QRESYNC),
        // descending seq so numbers stay valid.
        let qresync = self.qresync;
        let smb = self.store.mailbox_mut(&name).unwrap();
        let mut out = untagged(&format!(
            "OK [COPYUID {} {} {}] MOVE",
            dst_valid,
            compact(&src_uids, src_valid),
            dst_uids.join(",")
        ));
        let mut indices: Vec<usize> =
            moved_uids.iter().filter_map(|u| smb.index_of_uid(*u)).collect();
        indices.sort_unstable();
        let mut vanished: Vec<u32> = Vec::new();
        for &i in indices.iter().rev() {
            if !qresync {
                out.extend(untagged(&format!("{} EXPUNGE", i + 1)));
            }
            if let Some(uid) = smb.remove_at(i) {
                vanished.push(uid);
            }
        }
        if qresync && !vanished.is_empty() {
            vanished.sort_unstable();
            out.extend(untagged(&format!("VANISHED {}", to_sequence_set(&vanished))));
        }
        out.extend(ok(tag, "MOVE completed"));
        out
    }

    /// Snapshot (src_uid, cloned message) pairs for a COPY/MOVE, plus the source UIDVALIDITY.
    fn collect_for_copy(&self, set: &SequenceSet, uid_mode: bool) -> Option<(Vec<(u32, Message)>, u32)> {
        let name = self.selected.as_ref()?;
        let mb = self.store.mailbox(name)?;
        let out = resolve_targets(mb, set, uid_mode)
            .into_iter()
            .map(|i| (mb.messages[i].uid, mb.messages[i].clone()))
            .collect();
        Some((out, mb.uid_validity))
    }
}

// --- FETCH item rendering ------------------------------------------------------------------

fn fetch_marks_seen(items: &[FetchItem]) -> bool {
    items.iter().any(|i| {
        matches!(
            i,
            FetchItem::Rfc822 | FetchItem::Rfc822Text | FetchItem::BodySection { peek: false, .. }
        )
    })
}

fn render_fetch_items(
    items: &[FetchItem],
    msg: &Message,
    seq: u32,
    uid: u32,
    uid_mode: bool,
    condstore: bool,
) -> Vec<u8> {
    let _ = seq;
    // The MIME parse is fetched lazily and only by the items that need it (ENVELOPE /
    // BODYSTRUCTURE / BODY): a `FETCH (FLAGS UID)` never parses the message body, and the parse is
    // memoized on the message so repeated FETCHes across a session parse it at most once.
    let mut out: Vec<u8> = Vec::new();
    let mut first = true;
    let mut wrote_uid = false;
    let push_sep = |out: &mut Vec<u8>, first: &mut bool| {
        if !*first {
            out.push(b' ');
        }
        *first = false;
    };
    for item in items {
        push_sep(&mut out, &mut first);
        match item {
            FetchItem::Flags => {
                out.extend_from_slice(format!("FLAGS ({})", flags_str(&msg.flags)).as_bytes());
            }
            FetchItem::Uid => {
                out.extend_from_slice(format!("UID {uid}").as_bytes());
                wrote_uid = true;
            }
            FetchItem::InternalDate => {
                out.extend_from_slice(
                    format!("INTERNALDATE \"{}\"", mime::format_internal_date(msg.internal_date))
                        .as_bytes(),
                );
            }
            FetchItem::Rfc822Size => {
                out.extend_from_slice(format!("RFC822.SIZE {}", msg.size()).as_bytes());
            }
            FetchItem::Envelope => {
                out.extend_from_slice(b"ENVELOPE ");
                out.extend_from_slice(response::envelope(msg.parsed_cached()).as_bytes());
            }
            FetchItem::BodyStructure => {
                out.extend_from_slice(b"BODYSTRUCTURE ");
                out.extend_from_slice(
                    response::body_structure(&msg.parsed_cached().structure, true).as_bytes(),
                );
            }
            FetchItem::Body => {
                out.extend_from_slice(b"BODY ");
                out.extend_from_slice(
                    response::body_structure(&msg.parsed_cached().structure, false).as_bytes(),
                );
            }
            FetchItem::ModSeq => {
                out.extend_from_slice(format!("MODSEQ ({})", msg.modseq).as_bytes());
            }
            FetchItem::Rfc822 => literal_item(&mut out, "RFC822", &msg.raw),
            FetchItem::Rfc822Header => {
                literal_item(&mut out, "RFC822.HEADER", &mime::header_and_body(&msg.raw).0)
            }
            FetchItem::Rfc822Text => {
                literal_item(&mut out, "RFC822.TEXT", &mime::header_and_body(&msg.raw).1)
            }
            FetchItem::BodySection { section, partial, .. } => {
                // `extract_section` borrows the raw bytes for `[]`/`[HEADER]`/`[TEXT]`, so a
                // `BODY[]<0.512>` on a 10 MB message never copies more than the requested window.
                let full = response::extract_section(&msg.raw, section);
                let (data, origin) = response::apply_partial(full.as_ref(), *partial);
                let label = response::section_label(section);
                let head = match origin {
                    Some(o) => format!("BODY[{label}]<{o}>"),
                    None => format!("BODY[{label}]"),
                };
                literal_item(&mut out, &head, &data);
            }
        }
    }
    // UID FETCH responses MUST include UID (RFC 9051 §6.4.8).
    if uid_mode && !wrote_uid {
        push_sep(&mut out, &mut first);
        out.extend_from_slice(format!("UID {uid}").as_bytes());
    }
    let _ = condstore;
    out
}

fn literal_item(out: &mut Vec<u8>, label: &str, data: &[u8]) {
    out.extend_from_slice(format!("{label} {{{}}}\r\n", data.len()).as_bytes());
    out.extend_from_slice(data);
}

fn flags_str(flags: &[Flag]) -> String {
    flags.iter().map(|f| f.imap()).collect::<Vec<_>>().join(" ")
}

fn apply_store(msg: &mut Message, op: StoreOp, flags: &[Flag]) {
    match op {
        StoreOp::Replace => {
            // Preserve \Recent across a flag replace (it is session state, not client-settable).
            let recent = msg.has_flag(&Flag::Recent);
            msg.flags = flags.iter().filter(|f| **f != Flag::Recent).cloned().collect();
            if recent {
                msg.set_flag(Flag::Recent);
            }
        }
        StoreOp::Add => {
            for f in flags {
                if *f != Flag::Recent {
                    msg.set_flag(f.clone());
                }
            }
        }
        StoreOp::Remove => {
            for f in flags {
                msg.clear_flag(f);
            }
        }
    }
}

/// Compact a UID list into a sequence-set where possible. Reference: joins with commas (the
/// COPYUID `source-set` accepts any valid sequence set); `_valid` is the source UIDVALIDITY,
/// carried for completeness though the set itself does not encode it.
fn compact(uids: &[String], _valid: u32) -> String {
    uids.join(",")
}

/// Resolve a sequence set to the matched message **indices**, output-proportional. For a UID set
/// this binary-searches the UID-sorted messages for each range boundary (`O(k log n)`), so a
/// targeted `UID FETCH 5` touches ~`log n` messages, not all `n` (the large-mailbox hot path).
fn resolve_targets(mb: &Mailbox, set: &SequenceSet, uid_mode: bool) -> Vec<usize> {
    let mut idx = Vec::new();
    if uid_mode {
        let max = mb.max_uid();
        for (lo, hi) in set.ranges_resolved(max) {
            // messages are UID-sorted → binary-search the window's left edge, then walk it.
            let start = mb.messages.partition_point(|m| m.uid < lo);
            let mut i = start;
            while i < mb.messages.len() && mb.messages[i].uid <= hi {
                idx.push(i);
                i += 1;
            }
        }
    } else {
        let count = mb.exists() as u32;
        for (lo, hi) in set.ranges_resolved(count) {
            let lo = lo.max(1);
            let hi = hi.min(count);
            for s in lo..=hi {
                idx.push((s - 1) as usize);
            }
        }
    }
    idx.sort_unstable();
    idx.dedup();
    idx
}

/// Render a sorted UID list as a compact IMAP sequence-set, collapsing contiguous runs into
/// `lo:hi` (RFC 7162 VANISHED benefits from ranges: an offline mailbox purge is one short token).
fn to_sequence_set(sorted_uids: &[u32]) -> String {
    let mut out = String::new();
    let mut i = 0;
    while i < sorted_uids.len() {
        let start = sorted_uids[i];
        let mut end = start;
        while i + 1 < sorted_uids.len() && sorted_uids[i + 1] == end + 1 {
            end += 1;
            i += 1;
        }
        if !out.is_empty() {
            out.push(',');
        }
        if start == end {
            out.push_str(&start.to_string());
        } else {
            out.push_str(&format!("{start}:{end}"));
        }
        i += 1;
    }
    out
}

// --- response primitives -------------------------------------------------------------------

fn ok(tag: &str, text: &str) -> Vec<u8> {
    format!("{tag} OK {text}\r\n").into_bytes()
}
fn no(tag: &str, text: &str) -> Vec<u8> {
    format!("{tag} NO {text}\r\n").into_bytes()
}
fn bad(tag: &str, text: &str) -> Vec<u8> {
    format!("{tag} BAD {text}\r\n").into_bytes()
}
fn untagged(text: &str) -> Vec<u8> {
    format!("* {text}\r\n").into_bytes()
}
fn continuation(text: &str) -> Vec<u8> {
    format!("+ {text}\r\n").into_bytes()
}

fn extract_tag(buf: &[u8]) -> Option<String> {
    let s = String::from_utf8_lossy(buf);
    s.split_whitespace().next().map(|t| t.to_string())
}

/// Parse an IMAP INTERNALDATE `"dd-Mon-yyyy hh:mm:ss +zzzz"` into Unix-ms (best-effort, UTC).
fn parse_internal_date(s: &str) -> Option<u64> {
    let s = s.trim().trim_matches('"');
    let (date, rest) = s.split_once(' ')?;
    let mut d = date.split('-');
    let day: i64 = d.next()?.parse().ok()?;
    let mon = month_num(d.next()?)?;
    let year: i64 = d.next()?.parse().ok()?;
    let time = rest.split(' ').next().unwrap_or("00:00:00");
    let mut t = time.split(':');
    let h: i64 = t.next().unwrap_or("0").parse().unwrap_or(0);
    let mi: i64 = t.next().unwrap_or("0").parse().unwrap_or(0);
    let sec: i64 = t.next().unwrap_or("0").parse().unwrap_or(0);
    let days = days_from_civil(year, mon, day);
    let total = days * 86400 + h * 3600 + mi * 60 + sec;
    Some((total.max(0) as u64) * 1000)
}

fn month_num(m: &str) -> Option<i64> {
    const MO: [&str; 12] =
        ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
    MO.iter().position(|x| x.eq_ignore_ascii_case(m)).map(|i| i as i64 + 1)
}

/// Days since 1970-01-01 for a civil date (Howard Hinnant's days_from_civil).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// IMAP LIST wildcard match: `*` matches across the hierarchy delimiter, `%` within one level
/// (RFC 9051 §6.3.9). Delimiter is `/`.
fn wildcard_match(pattern: &str, name: &str) -> bool {
    fn rec(p: &[u8], n: &[u8]) -> bool {
        if p.is_empty() {
            return n.is_empty();
        }
        match p[0] {
            b'*' => {
                // Match zero or more of anything.
                (0..=n.len()).any(|k| rec(&p[1..], &n[k..]))
            }
            b'%' => {
                // Match zero or more non-delimiter chars.
                let mut k = 0;
                loop {
                    if rec(&p[1..], &n[k..]) {
                        return true;
                    }
                    if k >= n.len() || n[k] == b'/' {
                        return false;
                    }
                    k += 1;
                }
            }
            c => !n.is_empty() && n[0] == c && rec(&p[1..], &n[1..]),
        }
    }
    rec(pattern.as_bytes(), name.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcards() {
        assert!(wildcard_match("*", "INBOX"));
        assert!(wildcard_match("INB*", "INBOX"));
        assert!(wildcard_match("%", "Sent"));
        assert!(!wildcard_match("%", "a/b"));
        assert!(wildcard_match("*", "a/b"));
    }

    #[test]
    fn internal_date_round_trips() {
        let ms = parse_internal_date("\"15-Jul-2026 12:00:00 +0000\"").unwrap();
        let s = mime::format_internal_date(ms);
        assert!(s.starts_with("15-Jul-2026 12:00:00"), "got {s}");
    }

    #[test]
    fn sequence_set_compaction() {
        assert_eq!(to_sequence_set(&[1, 2, 3]), "1:3");
        assert_eq!(to_sequence_set(&[1, 3, 4, 5, 8]), "1,3:5,8");
        assert_eq!(to_sequence_set(&[7]), "7");
        assert_eq!(to_sequence_set(&[]), "");
    }

    #[test]
    fn resolve_targets_uid_is_windowed() {
        use crate::store::{MailStore, MemoryStore};
        let mut store = MemoryStore::empty();
        for _ in 0..100 {
            store.deliver_raw("INBOX", b"x".to_vec(), vec![], 0);
        }
        let mb = store.mailbox("INBOX").unwrap();
        // A single UID → exactly one index, found by binary search.
        assert_eq!(resolve_targets(mb, &SequenceSet::parse("42").unwrap(), true), vec![41]);
        // A UID range maps to the contiguous index window.
        assert_eq!(resolve_targets(mb, &SequenceSet::parse("10:12").unwrap(), true), vec![9, 10, 11]);
        // Seq mode maps directly to indices.
        assert_eq!(resolve_targets(mb, &SequenceSet::parse("1:3").unwrap(), false), vec![0, 1, 2]);
        // A nonexistent UID yields no targets (not a panic).
        assert!(resolve_targets(mb, &SequenceSet::parse("9999").unwrap(), true).is_empty());
    }
}

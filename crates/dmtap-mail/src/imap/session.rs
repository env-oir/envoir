//! IMAP session state machine (RFC 9051 §3): NotAuthenticated → Authenticated → Selected →
//! Logout. [`Session::process`] consumes one complete command buffer (literals already read off
//! the wire) and returns the response bytes. It is transport-agnostic and fully synchronous, so
//! it is driven directly by unit/integration tests and by the optional `net` TCP server.

use std::borrow::Cow;

use crate::auth::{self, Authenticator, SaslMechanism};
use crate::mime;
use crate::search::{self, SearchCtx, SearchKey};
use crate::store::{Flag, MailStore, Mailbox, Message};

use super::parser::{
    self, CatPart, Command, FetchItem, ParsedCommand, QResyncParams, Section, SortCriterion,
    SortKey, StoreCommand, StoreOp, ThreadAlgorithm,
};
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
    /// SEARCHRES saved result (RFC 5182): the UIDs from the last SEARCH/SORT that used
    /// `RETURN (SAVE)`, referenced by `$` in a later command.
    saved_search: Vec<u32>,
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
            saved_search: Vec::new(),
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
        // A mailbox can be DELETEd or RENAMEd while it is this session's SELECTed mailbox — RFC
        // 9051 does not forbid deleting/renaming the currently selected mailbox (§6.3.4/§6.3.5) —
        // so `self.selected` can go stale mid-session. Self-heal back to Authenticated before
        // running a SELECTED-state command rather than let a `cmd_*` handler assume the name still
        // resolves (see also the defensive fallback at each such lookup, kept as a second layer).
        if let Some(name) = self.selected.clone() {
            if self.store.mailbox(&name).is_none() {
                self.selected = None;
                self.state = State::Authenticated;
            }
        }
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
            Command::Create { name, use_attr } => self.cmd_create(&tag, &name, use_attr.as_deref()),
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
            Command::List { reference, pattern, return_opts, select_opts } => {
                self.cmd_list(&tag, &reference, &pattern, false, &return_opts, &select_opts)
            }
            Command::Lsub { reference, pattern } => {
                self.cmd_list(&tag, &reference, &pattern, true, &[], &[])
            }
            Command::Status { mailbox, items } => self.cmd_status(&tag, &mailbox, &items),
            Command::Append { mailbox, flags, date, message, catenate } => {
                self.cmd_append(&tag, &mailbox, flags, date, message, catenate)
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
            Command::Sort { criteria, charset, key, uid } => {
                self.cmd_sort(&tag, &criteria, charset, key, uid)
            }
            Command::Thread { algorithm, charset, key, uid } => {
                self.cmd_thread(&tag, algorithm, charset, key, uid)
            }
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

    fn cmd_list(
        &mut self,
        tag: &str,
        _reference: &str,
        pattern: &str,
        lsub: bool,
        return_opts: &[String],
        select_opts: &[String],
    ) -> Vec<u8> {
        let verb = if lsub { "LSUB" } else { "LIST" };
        let mut out = Vec::new();
        // `LIST "" ""` is the hierarchy-delimiter probe (RFC 9051 §6.3.9).
        if pattern.is_empty() {
            out.extend(untagged(&format!("{verb} (\\Noselect) \"/\" \"\"")));
            out.extend(ok(tag, &format!("{verb} completed")));
            return out;
        }
        let up: Vec<String> = return_opts.iter().map(|s| s.to_ascii_uppercase()).collect();
        let sel: Vec<String> = select_opts.iter().map(|s| s.to_ascii_uppercase()).collect();
        let want_subscribed = up.iter().any(|s| s == "SUBSCRIBED");
        let want_children = up.iter().any(|s| s == "CHILDREN");
        // LIST-EXTENDED select-options (RFC 5258 §3): filter to SUBSCRIBED / SPECIAL-USE sets.
        let only_subscribed = sel.iter().any(|s| s == "SUBSCRIBED");
        let only_special = sel.iter().any(|s| s == "SPECIAL-USE");
        // LIST-STATUS: RETURN (STATUS (items…)) piggybacks a STATUS reply per match (RFC 5819).
        let status_items = self.list_status_items(&up);

        let names = self.store.mailbox_names();
        let mut status_lines = Vec::new();
        for name in &names {
            if !wildcard_match(pattern, name) {
                continue;
            }
            // `name` came from `mailbox_names()` a moment ago; a defensive `MailStore` impl could
            // still have dropped it (e.g. a concurrent DELETE on a shared backend), so skip rather
            // than trust the invariant and unwrap.
            let mb = match self.store.mailbox(name) {
                Some(m) => m,
                None => continue,
            };
            if (lsub || only_subscribed) && !mb.subscribed {
                continue;
            }
            if only_special && mb.special_use.and_then(|s| s.attribute()).is_none() {
                continue;
            }
            let mut attrs: Vec<String> = Vec::new();
            // \HasChildren / \HasNoChildren (RFC 3348 CHILDREN): a child is any mailbox prefixed
            // with "<name>/". Always reported for LIST; gated on CHILDREN for the wire is optional.
            let _ = want_children;
            if names.iter().any(|n| n.starts_with(&format!("{name}/"))) {
                attrs.push("\\HasChildren".into());
            } else {
                attrs.push("\\HasNoChildren".into());
            }
            if (want_subscribed || lsub) && mb.subscribed {
                attrs.push("\\Subscribed".into());
            }
            if let Some(su) = mb.special_use.and_then(|s| s.attribute()) {
                attrs.push(su.to_string());
            }
            out.extend(untagged(&format!(
                "{verb} ({}) \"/\" {}",
                attrs.join(" "),
                response::imap_string(name)
            )));
            if let Some(items) = &status_items {
                status_lines.push(self.status_reply_line(name, items));
            }
        }
        for line in status_lines {
            out.extend(line);
        }
        out.extend(ok(tag, &format!("{verb} completed")));
        out
    }

    /// Extract the `RETURN (STATUS (…))` item list from LIST return-options (RFC 5819).
    fn list_status_items(&self, return_opts_upper: &[String]) -> Option<Vec<String>> {
        let pos = return_opts_upper.iter().position(|s| s == "STATUS")?;
        // The token after STATUS is the parenthesised item list, already flattened to atoms by the
        // parser's `read_paren_atoms`; everything after STATUS up to the next known opt are items.
        let items: Vec<String> = return_opts_upper[pos + 1..]
            .iter()
            .take_while(|s| {
                matches!(
                    s.as_str(),
                    "MESSAGES" | "RECENT" | "UIDNEXT" | "UIDVALIDITY" | "UNSEEN" | "DELETED"
                        | "SIZE" | "HIGHESTMODSEQ"
                )
            })
            .cloned()
            .collect();
        if items.is_empty() {
            None
        } else {
            Some(items)
        }
    }

    fn cmd_status(&mut self, tag: &str, name: &str, items: &[String]) -> Vec<u8> {
        if self.store.mailbox(name).is_none() {
            return no(tag, "[NONEXISTENT] no such mailbox");
        }
        let mut out = self.status_reply_line(name, items);
        out.extend(ok(tag, "STATUS completed"));
        out
    }

    /// Build a single untagged `* STATUS <name> (…)` response line for the requested items
    /// (shared by STATUS and LIST-STATUS, RFC 9051 §7.3.2 / RFC 5819). `DELETED` counts messages
    /// flagged `\Deleted` awaiting expunge (RFC 9051 STATUS item).
    fn status_reply_line(&self, name: &str, items: &[String]) -> Vec<u8> {
        let mb = match self.store.mailbox(name) {
            Some(mb) => mb,
            None => return Vec::new(),
        };
        let mut parts = Vec::new();
        for item in items {
            let v = match item.to_ascii_uppercase().as_str() {
                "MESSAGES" => format!("MESSAGES {}", mb.exists()),
                "RECENT" => format!("RECENT {}", mb.recent()),
                "UIDNEXT" => format!("UIDNEXT {}", mb.uid_next),
                "UIDVALIDITY" => format!("UIDVALIDITY {}", mb.uid_validity),
                "UNSEEN" => format!("UNSEEN {}", mb.unseen()),
                "DELETED" => format!(
                    "DELETED {}",
                    mb.messages.iter().filter(|m| m.has_flag(&Flag::Deleted)).count()
                ),
                "HIGHESTMODSEQ" => format!("HIGHESTMODSEQ {}", mb.highest_modseq),
                "SIZE" => format!("SIZE {}", mb.messages.iter().map(|m| m.size()).sum::<usize>()),
                _ => continue,
            };
            parts.push(v);
        }
        untagged(&format!("STATUS {} ({})", response::imap_string(name), parts.join(" ")))
    }

    /// CREATE, honoring the SPECIAL-USE `(USE (\Attr))` parameter (RFC 6154 §3): the created
    /// mailbox is tagged with the requested role so clients see the right folder icon.
    fn cmd_create(&mut self, tag: &str, name: &str, use_attr: Option<&str>) -> Vec<u8> {
        match self.store.create(name) {
            Ok(()) => {
                if let Some(su) = use_attr.and_then(special_use_from_attr) {
                    if let Some(mb) = self.store.mailbox_mut(name) {
                        mb.special_use = Some(su);
                    }
                }
                ok(tag, "CREATE completed")
            }
            Err(e) => no(tag, &format!("CREATE failed: {e}")),
        }
    }

    fn cmd_append(
        &mut self,
        tag: &str,
        name: &str,
        flags: Vec<Flag>,
        date: Option<String>,
        message: Vec<u8>,
        catenate: Option<Vec<CatPart>>,
    ) -> Vec<u8> {
        let ts = date.as_deref().and_then(parse_internal_date).unwrap_or(0);
        // Resolve CATENATE parts (RFC 4469) against the store before touching the destination.
        let message = match catenate {
            Some(parts) => match self.build_catenate(&parts) {
                Ok(bytes) => bytes,
                Err(msg) => return no(tag, msg),
            },
            None => message,
        };
        let mb = match self.store.mailbox_mut(name) {
            Some(mb) => mb,
            None => return no(tag, "[TRYCREATE] no such mailbox"),
        };
        let uidvalidity = mb.uid_validity;
        let uid = mb.append(message, flags, ts);
        ok(tag, &format!("[APPENDUID {uidvalidity} {uid}] APPEND completed"))
    }

    /// Assemble a CATENATE message (RFC 4469): concatenate inline `TEXT` parts with the bytes an
    /// IMAP `URL` reference resolves to. URLs are resolved against *this* node's own store (the
    /// common "resent/redirect" case, `imap://…/mailbox;UID=n[/;SECTION=…]`); a URL that names a
    /// message we do not hold is rejected with `[BADURL]` rather than silently dropped.
    fn build_catenate(&self, parts: &[CatPart]) -> Result<Vec<u8>, &'static str> {
        let mut out = Vec::new();
        for part in parts {
            match part {
                CatPart::Text(bytes) => out.extend_from_slice(bytes),
                CatPart::Url(url) => match self.resolve_imap_url(url) {
                    Some(bytes) => out.extend_from_slice(&bytes),
                    None => return Err("[BADURL] CATENATE URL not resolvable on this node"),
                },
            }
        }
        Ok(out)
    }

    /// Resolve an IMAP URL (RFC 5092) of the form `…/<mailbox>;UID=<n>[/;SECTION=<sec>]` against the
    /// local store, returning the referenced bytes (whole message, or a body section).
    fn resolve_imap_url(&self, url: &str) -> Option<Vec<u8>> {
        // Take the path after the authority (everything after the last "//host/…" or a bare path).
        let path = url.rsplit_once('/').map(|(_, _)| url).unwrap_or(url);
        let path = path.split_once("//").map(|(_, rest)| rest.splitn(2, '/').nth(1).unwrap_or(rest)).unwrap_or(path);
        // mailbox;UID=n[/;SECTION=s]
        let (mailbox_part, rest) = path.split_once(";UID=")?;
        let mailbox = mailbox_part.trim_start_matches('/');
        let (uid_str, section_str) = match rest.split_once("/;SECTION=") {
            Some((u, s)) => (u, Some(s)),
            None => (rest, None),
        };
        let uid: u32 = uid_str.trim_end_matches('/').parse().ok()?;
        let msg = self.store.mailbox(mailbox)?.by_uid(uid)?;
        match section_str {
            None => Some(msg.raw.clone()),
            Some(s) => {
                let section = parse_url_section(s);
                Some(response::extract_section(&msg.raw, &section).into_owned())
            }
        }
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
        let uid_set = uid_set.map(|s| self.materialize(&s, true).into_owned());
        // The dispatch preamble already self-heals a vanished selected mailbox back to
        // Authenticated; this is a defensive second layer, never expected to trigger.
        let mb = match self.store.mailbox_mut(&name) {
            Some(m) => m,
            None => return bad(tag, "no mailbox selected"),
        };
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
        let saved_uids = self.saved_search.clone();
        let mb = match self.store.mailbox(&name) {
            Some(m) => m,
            None => return bad(tag, "no mailbox selected"),
        };
        let max_seq = mb.exists() as u32;
        let max_uid = mb.max_uid();
        // Matched (seq, uid) pairs — we keep both so SEARCHRES can SAVE UIDs regardless of mode.
        let mut matched: Vec<(u32, u32)> = Vec::new();
        for (i, m) in mb.messages.iter().enumerate() {
            let seq = (i + 1) as u32;
            let ctx = SearchCtx::new(seq, max_seq, m.uid, max_uid, m);
            if search::eval_saved(&key, &ctx, &saved_uids) {
                matched.push((seq, m.uid));
            }
        }
        let hits: Vec<u32> = matched.iter().map(|&(s, u)| if uid { u } else { s }).collect();

        // SEARCHRES RETURN (SAVE) (RFC 5182): remember the matched UIDs for later `$` reference.
        let up: Vec<String> = ret.iter().map(|r| r.to_ascii_uppercase()).collect();
        if up.iter().any(|r| r == "SAVE") {
            self.saved_search = matched.iter().map(|&(_, u)| u).collect();
        }

        let mut out = Vec::new();
        // A bare `RETURN (SAVE)` (no MIN/MAX/ALL/COUNT) produces no ESEARCH data (RFC 5182 §2.1).
        let only_save = !up.is_empty() && up.iter().all(|r| r == "SAVE");
        if ret.is_empty() {
            // Classic SEARCH response.
            let list: Vec<String> = hits.iter().map(|n| n.to_string()).collect();
            out.extend(untagged(format!("SEARCH {}", list.join(" ")).trim_end()));
        } else if !only_save {
            out.extend(self.esearch_line(tag, uid, &up, &hits));
        }
        out.extend(ok(tag, "SEARCH completed"));
        out
    }

    /// Build an ESEARCH untagged line (RFC 9051 §6.4.4 / RFC 4731) for the requested return items.
    fn esearch_line(&self, tag: &str, uid: bool, up: &[String], hits: &[u32]) -> Vec<u8> {
        let mut parts = format!("ESEARCH (TAG \"{tag}\")");
        if uid {
            parts.push_str(" UID");
        }
        if up.iter().any(|r| r == "MIN") {
            if let Some(m) = hits.iter().min() {
                parts.push_str(&format!(" MIN {m}"));
            }
        }
        if up.iter().any(|r| r == "MAX") {
            if let Some(m) = hits.iter().max() {
                parts.push_str(&format!(" MAX {m}"));
            }
        }
        if up.iter().any(|r| r == "COUNT") {
            parts.push_str(&format!(" COUNT {}", hits.len()));
        }
        // ALL (or, when only SAVE-less returns without MIN/MAX/COUNT were asked, default to ALL).
        let wants_all = up.iter().any(|r| r == "ALL")
            || !up.iter().any(|r| r == "MIN" || r == "MAX" || r == "COUNT");
        if wants_all && !hits.is_empty() {
            parts.push_str(&format!(" ALL {}", to_sequence_set_of(hits)));
        }
        untagged(&parts)
    }

    /// SORT (RFC 5256 §3): evaluate the SEARCH program, order the matches by the criteria, and emit
    /// `* SORT <ids…>` (sequence numbers, or UIDs under UID SORT).
    fn cmd_sort(
        &mut self,
        tag: &str,
        criteria: &[SortCriterion],
        charset: Option<String>,
        key: SearchKey,
        uid: bool,
    ) -> Vec<u8> {
        if let Some(bad) = self.check_charset(tag, &charset) {
            return bad;
        }
        let name = match self.selected_name() {
            Some(n) => n,
            None => return bad(tag, "no mailbox selected"),
        };
        let saved = self.saved_search.clone();
        let mb = match self.store.mailbox(&name) {
            Some(m) => m,
            None => return bad(tag, "no mailbox selected"),
        };
        let max_seq = mb.exists() as u32;
        let max_uid = mb.max_uid();
        let mut matched: Vec<usize> = Vec::new();
        for (i, m) in mb.messages.iter().enumerate() {
            let ctx = SearchCtx::new((i + 1) as u32, max_seq, m.uid, max_uid, m);
            if search::eval_saved(&key, &ctx, &saved) {
                matched.push(i);
            }
        }
        matched.sort_by(|&a, &b| sort_compare(&mb.messages[a], &mb.messages[b], criteria));
        let ids: Vec<String> = matched
            .iter()
            .map(|&i| if uid { mb.messages[i].uid } else { (i + 1) as u32 }.to_string())
            .collect();
        let mut out = untagged(format!("SORT {}", ids.join(" ")).trim_end());
        out.extend(ok(tag, "SORT completed"));
        out
    }

    /// THREAD (RFC 5256 §3): group the SEARCH matches into threads and emit `* THREAD (…)`.
    fn cmd_thread(
        &mut self,
        tag: &str,
        algorithm: ThreadAlgorithm,
        charset: Option<String>,
        key: SearchKey,
        uid: bool,
    ) -> Vec<u8> {
        if let Some(bad) = self.check_charset(tag, &charset) {
            return bad;
        }
        let name = match self.selected_name() {
            Some(n) => n,
            None => return bad(tag, "no mailbox selected"),
        };
        let saved = self.saved_search.clone();
        let mb = match self.store.mailbox(&name) {
            Some(m) => m,
            None => return bad(tag, "no mailbox selected"),
        };
        let max_seq = mb.exists() as u32;
        let max_uid = mb.max_uid();
        let mut matched: Vec<usize> = Vec::new();
        for (i, m) in mb.messages.iter().enumerate() {
            let ctx = SearchCtx::new((i + 1) as u32, max_seq, m.uid, max_uid, m);
            if search::eval_saved(&key, &ctx, &saved) {
                matched.push(i);
            }
        }
        let threads = build_threads(mb, &matched, algorithm);
        let mut body = String::from("THREAD ");
        for group in &threads {
            body.push('(');
            let ids: Vec<String> = group
                .iter()
                .map(|&i| if uid { mb.messages[i].uid } else { (i + 1) as u32 }.to_string())
                .collect();
            body.push_str(&ids.join(" "));
            body.push(')');
        }
        let mut out = untagged(body.trim_end());
        out.extend(ok(tag, "THREAD completed"));
        out
    }

    /// Validate a SEARCH/SORT/THREAD CHARSET argument, returning a ready `NO [BADCHARSET]` reply if
    /// it names a charset we cannot honor (RFC 9051 §6.4.4). `None` = acceptable.
    fn check_charset(&self, tag: &str, charset: &Option<String>) -> Option<Vec<u8>> {
        if let Some(cs) = charset {
            let up = cs.to_ascii_uppercase();
            if up != "UTF-8" && up != "US-ASCII" && up != "ASCII" {
                return Some(no(tag, "[BADCHARSET (US-ASCII UTF-8)] unsupported charset"));
            }
        }
        None
    }

    /// Materialize a sequence set, substituting the SEARCHRES saved result for `$` (RFC 5182). For
    /// a UID command the saved UIDs are used directly; for a message-number command they are mapped
    /// to current sequence numbers in the selected mailbox.
    fn materialize<'a>(&self, set: &'a SequenceSet, uid_mode: bool) -> Cow<'a, SequenceSet> {
        if !set.is_saved() {
            return Cow::Borrowed(set);
        }
        if uid_mode {
            return Cow::Owned(SequenceSet::from_uids(&self.saved_search));
        }
        let seqs: Vec<u32> = match self.selected.as_ref().and_then(|n| self.store.mailbox(n)) {
            Some(mb) => self
                .saved_search
                .iter()
                .filter_map(|&u| mb.seq_of_uid(u).map(|s| s as u32))
                .collect(),
            None => Vec::new(),
        };
        Cow::Owned(SequenceSet::from_uids(&seqs))
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
        let set = self.materialize(&set, uid_mode).into_owned();
        let read_only = self.read_only;
        let condstore = self.condstore || changedsince.is_some();
        let mb = match self.store.mailbox_mut(&name) {
            Some(m) => m,
            None => return bad(tag, "no mailbox selected"),
        };
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
        let set = self.materialize(&sc.set, sc.uid).into_owned();
        let mb = match self.store.mailbox_mut(&name) {
            Some(m) => m,
            None => return bad(tag, "no mailbox selected"),
        };

        let mut out = Vec::new();
        let mut modified: Vec<u32> = Vec::new();
        for i in resolve_targets(mb, &set, sc.uid) {
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
        // MOVE-to-self (dest == name) has already released the mutable borrow above (`dmb`'s scope
        // ended with the loop), so re-resolving the source by name here is safe; a same-name dest
        // just means we already appended the copies into what we're about to expunge from.
        let smb = match self.store.mailbox_mut(&name) {
            Some(m) => m,
            None => return bad(tag, "no mailbox selected"),
        };
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
        let set = self.materialize(set, uid_mode);
        let mb = self.store.mailbox(name)?;
        let out = resolve_targets(mb, &set, uid_mode)
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
            FetchItem::Rfc822
                | FetchItem::Rfc822Text
                | FetchItem::BodySection { peek: false, .. }
                | FetchItem::Binary { peek: false, .. }
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
            FetchItem::Binary { section, partial, .. } => {
                // RFC 3516: CTE-decoded content, emitted as a literal8 (`~{n}`) since it may hold
                // NUL bytes. A `[NIL]` decode failure would use `BODY[…] NIL`; we always decode here.
                let full = response::extract_binary(&msg.raw, section);
                let (data, origin) = response::apply_partial(&full, *partial);
                let label = join_nums(section);
                let head = match origin {
                    Some(o) => format!("BINARY[{label}]<{o}>"),
                    None => format!("BINARY[{label}]"),
                };
                out.extend_from_slice(format!("{head} ~{{{}}}\r\n", data.len()).as_bytes());
                out.extend_from_slice(&data);
            }
            FetchItem::BinarySize { section } => {
                let full = response::extract_binary(&msg.raw, section);
                let label = join_nums(section);
                out.extend_from_slice(format!("BINARY.SIZE[{label}] {}", full.len()).as_bytes());
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

/// Join a numeric MIME part path into its dotted label (`[1.2]`), empty for the whole message.
fn join_nums(nums: &[u32]) -> String {
    nums.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(".")
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

/// Compact an unsorted id list into an IMAP sequence-set (sorts a copy first).
fn to_sequence_set_of(ids: &[u32]) -> String {
    let mut v = ids.to_vec();
    v.sort_unstable();
    v.dedup();
    to_sequence_set(&v)
}

/// Map a SPECIAL-USE `\Attr` (from `CREATE … (USE (\Archive))`) to a [`SpecialUse`] role.
fn special_use_from_attr(attr: &str) -> Option<crate::store::SpecialUse> {
    use crate::store::SpecialUse::*;
    match attr.to_ascii_lowercase().as_str() {
        "\\sent" => Some(Sent),
        "\\drafts" => Some(Drafts),
        "\\trash" => Some(Trash),
        "\\junk" => Some(Junk),
        "\\archive" => Some(Archive),
        "\\all" => Some(All),
        _ => None,
    }
}

/// Parse the `SECTION=` fragment of an IMAP URL (RFC 5092) into a [`Section`] for CATENATE URL.
fn parse_url_section(s: &str) -> Section {
    let s = s.trim_end_matches('/');
    if s.eq_ignore_ascii_case("HEADER") {
        Section::Header
    } else if s.eq_ignore_ascii_case("TEXT") {
        Section::Text
    } else if s.is_empty() {
        Section::Full
    } else {
        let nums: Vec<u32> = s.split('.').filter_map(|p| p.parse().ok()).collect();
        if nums.is_empty() {
            Section::Full
        } else {
            Section::Part(nums)
        }
    }
}

/// Order two messages by a SORT criteria list (RFC 5256 §3), first criterion dominant.
fn sort_compare(a: &Message, b: &Message, criteria: &[SortCriterion]) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    for c in criteria {
        let ord = match c.key {
            SortKey::Arrival => a.internal_date.cmp(&b.internal_date),
            SortKey::Size => a.size().cmp(&b.size()),
            SortKey::Date => sort_date(a).cmp(&sort_date(b)),
            SortKey::Subject => base_subject(a).cmp(&base_subject(b)),
            SortKey::From => addr_sort_key(a, "From", false).cmp(&addr_sort_key(b, "From", false)),
            SortKey::To => addr_sort_key(a, "To", false).cmp(&addr_sort_key(b, "To", false)),
            SortKey::Cc => addr_sort_key(a, "Cc", false).cmp(&addr_sort_key(b, "Cc", false)),
            SortKey::DisplayFrom => {
                addr_sort_key(a, "From", true).cmp(&addr_sort_key(b, "From", true))
            }
            SortKey::DisplayTo => addr_sort_key(a, "To", true).cmp(&addr_sort_key(b, "To", true)),
        };
        let ord = if c.reverse { ord.reverse() } else { ord };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    // Ties break on sequence order — here, ascending UID (RFC 5256 §3, "otherwise by number").
    a.uid.cmp(&b.uid)
}

/// The sort date of a message (RFC 5256): the `Date:` header, falling back to INTERNALDATE.
fn sort_date(m: &Message) -> (i64, i64, i64) {
    m.parsed_cached()
        .header("Date")
        .and_then(parse_date_ymd)
        .unwrap_or_else(|| mime::ymd_from_ms(m.internal_date))
}

fn parse_date_ymd(date: &str) -> Option<(i64, i64, i64)> {
    let cleaned = date.replace(',', " ");
    let mut toks = cleaned.split_whitespace();
    let mut first = toks.next()?;
    let months = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
    let month_of = |m: &str| months.iter().position(|x| x.eq_ignore_ascii_case(m)).map(|i| i as i64 + 1);
    if month_of(first).is_none() && first.parse::<i64>().is_err() {
        first = toks.next()?;
    }
    let day: i64 = first.parse().ok()?;
    let mon = month_of(toks.next()?)?;
    let year: i64 = toks.next()?.parse().ok()?;
    Some((year, mon, day))
}

/// The RFC 5256 "base subject": the subject lowercased with leading `Re:`/`Fwd:` and surrounding
/// whitespace stripped, so a reply threads/sorts next to its parent.
fn base_subject(m: &Message) -> String {
    // Decode RFC 2047 first (an encoded reply must thread next to its plain parent), and lowercase
    // with full Unicode folding — ASCII-only lowercasing sorts every non-English subject wrong.
    let raw = mime::decode_encoded_words(m.parsed_cached().header("Subject").unwrap_or(""))
        .to_lowercase();
    let mut s = raw.trim().to_string();
    loop {
        let t = s.trim_start();
        let stripped = t
            .strip_prefix("re:")
            .or_else(|| t.strip_prefix("fwd:"))
            .or_else(|| t.strip_prefix("fw:"));
        match stripped {
            Some(rest) => s = rest.trim_start().to_string(),
            None => break,
        }
    }
    s
}

/// A sort key for an address header (RFC 5256 §3): the mailbox local-part, or the display name for
/// DISPLAYFROM/DISPLAYTO (RFC 5957), lowercased.
fn addr_sort_key(m: &Message, header: &str, display: bool) -> String {
    let addrs = m.parsed_cached().addresses(header);
    match addrs.first() {
        // DISPLAY sort keys are the *rendered* name: RFC 2047-decode it (RFC 5957 sorts what the
        // user reads, not the wire spelling) and Unicode-lowercase for a language-blind order.
        Some(a) if display => mime::decode_encoded_words(
            a.name.as_deref().or(a.mailbox.as_deref()).unwrap_or_default(),
        )
        .to_lowercase(),
        Some(a) => a.mailbox.clone().unwrap_or_default().to_lowercase(),
        None => String::new(),
    }
}

/// Group matched message indices into threads (RFC 5256 §3). ORDEREDSUBJECT groups by base
/// subject; REFERENCES unions messages linked by Message-ID / In-Reply-To / References. Each thread
/// is returned date-ordered, and threads are ordered by their earliest message's date.
fn build_threads(mb: &Mailbox, matched: &[usize], algo: ThreadAlgorithm) -> Vec<Vec<usize>> {
    let mut groups: Vec<Vec<usize>> = match algo {
        ThreadAlgorithm::OrderedSubject => {
            let mut by_subject: std::collections::BTreeMap<String, Vec<usize>> = Default::default();
            for &i in matched {
                by_subject.entry(base_subject(&mb.messages[i])).or_default().push(i);
            }
            by_subject.into_values().collect()
        }
        ThreadAlgorithm::References => {
            // Union-find over message-id links.
            let mut id_to_pos: std::collections::HashMap<String, usize> = Default::default();
            for (pos, &i) in matched.iter().enumerate() {
                if let Some(mid) = msg_id(&mb.messages[i]) {
                    id_to_pos.entry(mid).or_insert(pos);
                }
            }
            let mut parent: Vec<usize> = (0..matched.len()).collect();
            fn find(parent: &mut [usize], x: usize) -> usize {
                let mut r = x;
                while parent[r] != r {
                    r = parent[r];
                }
                let mut c = x;
                while parent[c] != r {
                    let n = parent[c];
                    parent[c] = r;
                    c = n;
                }
                r
            }
            for (pos, &i) in matched.iter().enumerate() {
                for reff in msg_refs(&mb.messages[i]) {
                    if let Some(&other) = id_to_pos.get(&reff) {
                        let (ra, rb) = (find(&mut parent, pos), find(&mut parent, other));
                        if ra != rb {
                            parent[ra] = rb;
                        }
                    }
                }
            }
            let mut buckets: std::collections::BTreeMap<usize, Vec<usize>> = Default::default();
            for pos in 0..matched.len() {
                let root = find(&mut parent, pos);
                buckets.entry(root).or_default().push(matched[pos]);
            }
            buckets.into_values().collect()
        }
    };
    // Order within each thread by sort date, and threads by their first message's date.
    for g in &mut groups {
        g.sort_by(|&a, &b| sort_date(&mb.messages[a]).cmp(&sort_date(&mb.messages[b])).then(a.cmp(&b)));
    }
    groups.sort_by(|a, b| {
        let da = a.first().map(|&i| sort_date(&mb.messages[i]));
        let db = b.first().map(|&i| sort_date(&mb.messages[i]));
        da.cmp(&db)
    });
    groups
}

/// A message's own Message-ID (angle brackets stripped), for REFERENCES threading.
fn msg_id(m: &Message) -> Option<String> {
    m.parsed_cached()
        .header("Message-ID")
        .or_else(|| m.parsed_cached().header("Message-Id"))
        .map(|s| s.trim().trim_matches(|c| c == '<' || c == '>').to_string())
        .filter(|s| !s.is_empty())
}

/// The message-ids a message references (In-Reply-To + References), for REFERENCES threading.
fn msg_refs(m: &Message) -> Vec<String> {
    let p = m.parsed_cached();
    let mut out = Vec::new();
    for h in ["In-Reply-To", "References"] {
        if let Some(v) = p.header(h) {
            for tok in v.split(|c: char| c == '<' || c == '>' || c.is_whitespace()) {
                let t = tok.trim();
                if !t.is_empty() && t.contains('@') {
                    out.push(t.to_string());
                }
            }
        }
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
    // Bottom-up DP over `(p_idx, n_idx)` — `dp[pi][ni]` is "does `p[pi..]` match `n[ni..]`". This
    // is O(len(p)·len(n)) and allocation-bounded, replacing the old naive recursion whose `*`
    // branch (`(0..=n.len()).any(|k| rec(..))`) backtracked exponentially: a pattern with many
    // `*`s against a long name was a pre-auth ReDoS. Match semantics are preserved exactly —
    // `*` spans the `/` delimiter, `%` matches zero-or-more non-delimiter chars (RFC 9051 §6.3.9).
    let p = pattern.as_bytes();
    let n = name.as_bytes();
    let (pl, nl) = (p.len(), n.len());

    // dp[pi][ni]; row pl is the "pattern exhausted" base row (matches iff name also exhausted).
    let mut dp = vec![vec![false; nl + 1]; pl + 1];
    dp[pl][nl] = true;

    for pi in (0..pl).rev() {
        for ni in (0..=nl).rev() {
            dp[pi][ni] = match p[pi] {
                // `*`: skip it, or consume one arbitrary name byte and stay on `*`.
                b'*' => dp[pi + 1][ni] || (ni < nl && dp[pi][ni + 1]),
                // `%`: skip it, or consume one name byte provided it is not the `/` delimiter.
                b'%' => dp[pi + 1][ni] || (ni < nl && n[ni] != b'/' && dp[pi][ni + 1]),
                // Literal byte: must match exactly and advance both.
                c => ni < nl && n[ni] == c && dp[pi + 1][ni + 1],
            };
        }
    }
    dp[0][0]
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
    fn wildcard_semantics_preserved() {
        // Broaden coverage of the semantics the DP rewrite must keep identical to the old matcher.
        assert!(wildcard_match("", ""));
        assert!(!wildcard_match("", "x"));
        assert!(wildcard_match("*", ""));
        assert!(wildcard_match("a*b", "aXYZb"));
        assert!(wildcard_match("a*b", "ab"));
        assert!(wildcard_match("a/*", "a/b/c")); // `*` crosses the delimiter
        assert!(wildcard_match("a/%", "a/b"));
        assert!(!wildcard_match("a/%", "a/b/c")); // `%` stops at the delimiter
        assert!(wildcard_match("%/%", "a/b"));
        assert!(wildcard_match("INBOX*", "INBOX"));
        assert!(!wildcard_match("INBOX", "INBOXX"));
        assert!(wildcard_match("*a*b*c*", "zazbzcz"));
    }

    #[test]
    fn wildcard_redos_pattern_returns_quickly() {
        // MED-1 regression: the old naive `*` recursion backtracked exponentially. A pattern of
        // many `*a` groups against a long non-matching name would take effectively forever there;
        // the DP matcher is O(len(p)·len(n)) and returns near-instantly. We assert both a wall-clock
        // ceiling AND correctness (this pattern needs 20 `a`s, the name has none → no match).
        let pattern = "*a".repeat(20) + "b"; // 20 `*a` groups then a `b`
        let name = "a".repeat(1); // deliberately cannot satisfy 20 required `a`s + trailing `b`
        let name = format!("{}c", "x".repeat(64)) + &name; // long, wrong tail
        let start = std::time::Instant::now();
        let matched = wildcard_match(&pattern, &name);
        let elapsed = start.elapsed();
        assert!(!matched);
        assert!(elapsed < std::time::Duration::from_secs(1), "wildcard match took {elapsed:?} — ReDoS regression");
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

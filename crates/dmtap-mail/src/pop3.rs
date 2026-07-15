//! POP3 (RFC 1939) server — the download-and-delete legacy surface (spec §8.2). Projects the
//! INBOX as a flat maildrop. Supports USER/PASS, APOP (RFC 1939 §7), STLS (RFC 2595), CAPA
//! (RFC 2449), and the SASL AUTH bridge (RFC 5034). Transaction: STAT/LIST/UIDL/RETR/TOP/DELE/
//! RSET/NOOP/QUIT. Deletes are committed to the store on QUIT (the UPDATE state).

use crate::auth::{self, Authenticator};
use crate::store::{Flag, MailStore};
use crate::util::{hex, md5};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Authorization,
    Transaction,
}

/// One message in the POP3 maildrop snapshot (fixed at login, per RFC 1939).
#[derive(Debug, Clone)]
struct Slot {
    uid: u32,
    raw: Vec<u8>,
    deleted: bool,
}

/// A stateful POP3 session over an owned store + authenticator.
pub struct Pop3Session<S: MailStore, A: Authenticator> {
    store: S,
    auth: A,
    tls: bool,
    state: State,
    user: Option<String>,
    identity: Option<Vec<u8>>,
    slots: Vec<Slot>,
    banner: String,
    pending_sasl: Option<SaslStep>,
}

enum SaslStep {
    Plain,
}

impl<S: MailStore, A: Authenticator> Pop3Session<S, A> {
    pub fn new(store: S, auth: A, tls: bool) -> Self {
        // The APOP banner timestamp — a unique msg-id per RFC 1939 §7.
        let banner = "<envoir.1.1@mail.dmtap.local>".to_string();
        Pop3Session {
            store,
            auth,
            tls,
            state: State::Authorization,
            user: None,
            identity: None,
            slots: Vec::new(),
            banner,
            pending_sasl: None,
        }
    }

    pub fn store(&self) -> &S {
        &self.store
    }
    pub fn into_store(self) -> S {
        self.store
    }
    pub fn is_authenticated(&self) -> bool {
        self.identity.is_some()
    }

    /// The `+OK` greeting including the APOP timestamp banner.
    pub fn greeting(&self) -> String {
        format!("+OK Envoir DMTAP POP3 ready {}\r\n", self.banner)
    }

    /// Feed one command line (without CRLF). Returns the reply (possibly multi-line).
    pub fn feed_line(&mut self, line: &str) -> String {
        if let Some(step) = self.pending_sasl.take() {
            return self.continue_sasl(step, line);
        }
        let (verb, rest) = match line.split_once(' ') {
            Some((v, r)) => (v.to_ascii_uppercase(), r.trim().to_string()),
            None => (line.trim().to_ascii_uppercase(), String::new()),
        };
        match (self.state, verb.as_str()) {
            (_, "CAPA") => self.capa(),
            (_, "QUIT") => self.quit(),
            (_, "NOOP") => "+OK\r\n".into(),
            (State::Authorization, "STLS") => {
                self.tls = true;
                "+OK Begin TLS\r\n".into()
            }
            (State::Authorization, "USER") => {
                self.user = Some(rest);
                "+OK send PASS\r\n".into()
            }
            (State::Authorization, "PASS") => self.pass(&rest),
            (State::Authorization, "APOP") => self.apop(&rest),
            (State::Authorization, "AUTH") => self.auth_cmd(&rest),
            (State::Transaction, "STAT") => self.stat(),
            (State::Transaction, "LIST") => self.list(&rest),
            (State::Transaction, "UIDL") => self.uidl(&rest),
            (State::Transaction, "RETR") => self.retr(&rest),
            (State::Transaction, "TOP") => self.top(&rest),
            (State::Transaction, "DELE") => self.dele(&rest),
            (State::Transaction, "RSET") => self.rset(),
            _ => "-ERR command not permitted in this state\r\n".into(),
        }
    }

    fn capa(&self) -> String {
        let mut s = String::from("+OK Capability list follows\r\n");
        s.push_str("TOP\r\nUIDL\r\nUSER\r\nRESP-CODES\r\nPIPELINING\r\n");
        if self.tls {
            s.push_str("SASL PLAIN\r\n");
        } else {
            s.push_str("STLS\r\n");
        }
        s.push_str(".\r\n");
        s
    }

    fn login_ok(&mut self, identity: Vec<u8>) -> String {
        self.identity = Some(identity);
        self.state = State::Transaction;
        self.load_inbox();
        format!("+OK mailbox ready, {} messages\r\n", self.slots.len())
    }

    fn load_inbox(&mut self) {
        self.slots = self
            .store
            .mailbox("INBOX")
            .map(|mb| mb.messages.iter().map(|m| Slot { uid: m.uid, raw: m.raw.clone(), deleted: false }).collect())
            .unwrap_or_default();
    }

    fn pass(&mut self, pass: &str) -> String {
        let user = match &self.user {
            Some(u) => u.clone(),
            None => return "-ERR USER first\r\n".into(),
        };
        match self.auth.verify(&user, pass) {
            Some(id) => self.login_ok(id),
            None => "-ERR [AUTH] invalid credentials\r\n".into(),
        }
    }

    fn apop(&mut self, rest: &str) -> String {
        let mut it = rest.split_whitespace();
        let (name, digest) = match (it.next(), it.next()) {
            (Some(n), Some(d)) => (n.to_string(), d.to_string()),
            _ => return "-ERR APOP requires name and digest\r\n".into(),
        };
        let secret = match self.auth.secret_for(&name) {
            Some(s) => s,
            None => return "-ERR [AUTH] APOP not available for this user\r\n".into(),
        };
        let expected = hex(&md5(format!("{}{}", self.banner, secret).as_bytes()));
        if expected == digest.to_ascii_lowercase() {
            match self.auth.verify(&name, &secret) {
                Some(id) => self.login_ok(id),
                None => "-ERR [AUTH] APOP failed\r\n".into(),
            }
        } else {
            "-ERR [AUTH] APOP digest mismatch\r\n".into()
        }
    }

    fn auth_cmd(&mut self, rest: &str) -> String {
        let mech = rest.split_whitespace().next().unwrap_or("").to_ascii_uppercase();
        if mech == "PLAIN" {
            if let Some(ir) = rest.split_whitespace().nth(1) {
                return self.finish_plain(ir);
            }
            self.pending_sasl = Some(SaslStep::Plain);
            return "+ \r\n".into();
        }
        "-ERR unsupported SASL mechanism\r\n".into()
    }

    fn continue_sasl(&mut self, step: SaslStep, line: &str) -> String {
        match step {
            SaslStep::Plain => self.finish_plain(line.trim()),
        }
    }

    fn finish_plain(&mut self, ir: &str) -> String {
        match auth::decode_plain(ir) {
            Some(cred) => match self.auth.verify(&cred.authcid, &cred.password) {
                Some(id) => self.login_ok(id),
                None => "-ERR [AUTH] invalid credentials\r\n".into(),
            },
            None => "-ERR malformed SASL PLAIN\r\n".into(),
        }
    }

    fn active(&self) -> impl Iterator<Item = (usize, &Slot)> {
        self.slots.iter().enumerate().filter(|(_, s)| !s.deleted)
    }

    fn stat(&self) -> String {
        let (count, size) = self.active().fold((0usize, 0usize), |(c, s), (_, slot)| (c + 1, s + slot.raw.len()));
        format!("+OK {count} {size}\r\n")
    }

    fn list(&self, rest: &str) -> String {
        if rest.is_empty() {
            let mut out = String::from("+OK scan listing follows\r\n");
            for (i, slot) in self.active() {
                out.push_str(&format!("{} {}\r\n", i + 1, slot.raw.len()));
            }
            out.push_str(".\r\n");
            out
        } else {
            match self.slot_of(rest) {
                Some((i, slot)) => format!("+OK {} {}\r\n", i + 1, slot.raw.len()),
                None => "-ERR no such message\r\n".into(),
            }
        }
    }

    fn uidl(&self, rest: &str) -> String {
        if rest.is_empty() {
            let mut out = String::from("+OK unique-id listing follows\r\n");
            for (i, slot) in self.active() {
                out.push_str(&format!("{} {}\r\n", i + 1, slot.uid));
            }
            out.push_str(".\r\n");
            out
        } else {
            match self.slot_of(rest) {
                Some((i, slot)) => format!("+OK {} {}\r\n", i + 1, slot.uid),
                None => "-ERR no such message\r\n".into(),
            }
        }
    }

    fn retr(&self, rest: &str) -> String {
        match self.slot_of(rest) {
            Some((_, slot)) => {
                let mut out = format!("+OK {} octets\r\n", slot.raw.len());
                out.push_str(&dot_stuff(&slot.raw));
                out.push_str(".\r\n");
                out
            }
            None => "-ERR no such message\r\n".into(),
        }
    }

    fn top(&self, rest: &str) -> String {
        let mut it = rest.split_whitespace();
        let num = it.next().unwrap_or("");
        let lines: usize = it.next().and_then(|n| n.parse().ok()).unwrap_or(0);
        match self.slot_of(num) {
            Some((_, slot)) => {
                let (headers, body) = crate::mime::header_and_body(&slot.raw);
                let mut top = headers;
                for l in String::from_utf8_lossy(&body).split_inclusive('\n').take(lines) {
                    top.extend_from_slice(l.as_bytes());
                }
                let mut out = String::from("+OK\r\n");
                out.push_str(&dot_stuff(&top));
                out.push_str(".\r\n");
                out
            }
            None => "-ERR no such message\r\n".into(),
        }
    }

    fn dele(&mut self, rest: &str) -> String {
        match self.index_of(rest) {
            Some(i) => {
                self.slots[i].deleted = true;
                "+OK message deleted\r\n".into()
            }
            None => "-ERR no such message\r\n".into(),
        }
    }

    fn rset(&mut self) -> String {
        for s in &mut self.slots {
            s.deleted = false;
        }
        "+OK\r\n".into()
    }

    fn quit(&mut self) -> String {
        if self.state == State::Transaction {
            // UPDATE state: commit deletions to the store's INBOX.
            let to_delete: Vec<u32> =
                self.slots.iter().filter(|s| s.deleted).map(|s| s.uid).collect();
            if let Some(mb) = self.store.mailbox_mut("INBOX") {
                for uid in &to_delete {
                    if let Some(pos) = mb.messages.iter().position(|m| m.uid == *uid) {
                        // Mark \Deleted then remove (POP3 delete == expunge).
                        mb.messages[pos].set_flag(Flag::Deleted);
                        mb.messages.remove(pos);
                        mb.highest_modseq += 1;
                    }
                }
            }
        }
        "+OK Envoir POP3 signing off\r\n".into()
    }

    fn slot_of(&self, num: &str) -> Option<(usize, &Slot)> {
        let i = self.index_of(num)?;
        Some((i, &self.slots[i]))
    }

    fn index_of(&self, num: &str) -> Option<usize> {
        let n: usize = num.trim().parse().ok()?;
        if n == 0 || n > self.slots.len() {
            return None;
        }
        let i = n - 1;
        if self.slots[i].deleted {
            None
        } else {
            Some(i)
        }
    }
}

/// RFC 1939 §3 byte-stuffing: lines beginning with `.` get an extra leading `.`.
fn dot_stuff(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    let mut out = String::new();
    for line in text.split_inclusive('\n') {
        if line.starts_with('.') {
            out.push('.');
        }
        out.push_str(line);
    }
    if !out.ends_with('\n') {
        out.push_str("\r\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::StaticAuthenticator;
    use crate::store::MemoryStore;

    fn session() -> Pop3Session<MemoryStore, StaticAuthenticator> {
        let mut store = MemoryStore::empty();
        store.deliver_raw("INBOX", b"Subject: One\r\n\r\nbody one\r\n".to_vec(), vec![], 0);
        store.deliver_raw("INBOX", b"Subject: Two\r\n\r\nbody two\r\n".to_vec(), vec![], 0);
        let mut auth = StaticAuthenticator::new();
        auth.issue("alice", "pw", vec![1], "test");
        Pop3Session::new(store, auth, true)
    }

    #[test]
    fn user_pass_and_stat() {
        let mut s = session();
        assert!(s.feed_line("USER alice").starts_with("+OK"));
        assert!(s.feed_line("PASS pw").starts_with("+OK"));
        let total: usize = s.slots.iter().map(|x| x.raw.len()).sum();
        assert_eq!(s.feed_line("STAT"), format!("+OK 2 {total}\r\n"));
    }

    #[test]
    fn apop_authenticates() {
        let mut s = session();
        let digest = hex(&md5(format!("{}pw", s.banner).as_bytes()));
        assert!(s.feed_line(&format!("APOP alice {digest}")).starts_with("+OK"));
        assert!(s.is_authenticated());
    }

    #[test]
    fn retr_and_dele_commit_on_quit() {
        let mut s = session();
        s.feed_line("USER alice");
        s.feed_line("PASS pw");
        assert!(s.feed_line("RETR 1").contains("body one"));
        assert!(s.feed_line("UIDL").contains("1 1"));
        assert!(s.feed_line("DELE 1").starts_with("+OK"));
        // Deleted message is hidden from LIST immediately.
        assert!(!s.feed_line("LIST").contains("1 "));
        s.feed_line("QUIT");
        let store = s.into_store();
        assert_eq!(store.mailbox("INBOX").unwrap().exists(), 1);
    }

    #[test]
    fn top_returns_headers() {
        let mut s = session();
        s.feed_line("USER alice");
        s.feed_line("PASS pw");
        let top = s.feed_line("TOP 1 0");
        assert!(top.contains("Subject: One"));
        assert!(!top.contains("body one"));
    }
}

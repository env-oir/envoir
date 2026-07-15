//! SMTP message submission (RFC 6409 on port 587, over RFC 5321) — the outbound edge for legacy
//! clients (spec §8.2). On a completed `DATA`, submission converts to a MOTE (native peer) or is
//! handed to the legacy gateway (spec §8.2 / §7); [`SmtpSession::take_submissions`] yields the
//! accepted messages and [`build_mote_draft`] shows the MOTE conversion.
//!
//! Advertised extensions: STARTTLS (RFC 3207), AUTH PLAIN/LOGIN (RFC 4954), PIPELINING (RFC 2920),
//! 8BITMIME (RFC 6152), SIZE (RFC 1870), SMTPUTF8 (RFC 6531), DSN (RFC 3461), ENHANCEDSTATUSCODES.

use dmtap_core::mote::{Headers, Kind, MoteDraft};
use dmtap_core::TimestampMs;

use crate::auth::{self, Authenticator, SaslMechanism};
use crate::mime::ParsedMessage;

/// The maximum message size advertised via the SIZE extension (RFC 1870). 50 MiB.
pub const MAX_SIZE: usize = 50 * 1024 * 1024;

/// An accepted submission (envelope + RFC 5322 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Submission {
    pub mail_from: String,
    pub rcpt_to: Vec<String>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Greeting,
    Command,
    Data,
}

/// A stateful SMTP submission session.
pub struct SmtpSession<A: Authenticator> {
    auth: A,
    tls: bool,
    require_auth: bool,
    phase: Phase,
    authed: Option<Vec<u8>>,
    mail_from: Option<String>,
    rcpt_to: Vec<String>,
    data_buf: Vec<u8>,
    pending_auth: Option<SmtpPendingAuth>,
    submissions: Vec<Submission>,
}

enum SmtpPendingAuth {
    Plain,
    LoginUser,
    LoginPass(String),
}

impl<A: Authenticator> SmtpSession<A> {
    pub fn new(auth: A, tls: bool) -> Self {
        SmtpSession {
            auth,
            tls,
            require_auth: true,
            phase: Phase::Greeting,
            authed: None,
            mail_from: None,
            rcpt_to: Vec::new(),
            data_buf: Vec::new(),
            pending_auth: None,
            submissions: Vec::new(),
        }
    }

    /// The 220 service-ready banner.
    pub fn greeting(&mut self) -> String {
        self.phase = Phase::Command;
        "220 mail.dmtap.local Envoir DMTAP Submission ready\r\n".into()
    }

    /// Accepted submissions collected so far (drains the buffer).
    pub fn take_submissions(&mut self) -> Vec<Submission> {
        std::mem::take(&mut self.submissions)
    }

    pub fn is_authenticated(&self) -> bool {
        self.authed.is_some()
    }

    /// Feed one line (without CRLF). Returns the reply (possibly multi-line).
    pub fn feed_line(&mut self, line: &str) -> String {
        if self.phase == Phase::Data {
            return self.feed_data_line(line);
        }
        if let Some(p) = self.pending_auth.take() {
            return self.continue_auth(p, line);
        }
        let (verb, rest) = match line.split_once(' ') {
            Some((v, r)) => (v.to_ascii_uppercase(), r.trim()),
            None => (line.trim().to_ascii_uppercase(), ""),
        };
        match verb.as_str() {
            "EHLO" => self.ehlo(rest, true),
            "HELO" => self.ehlo(rest, false),
            "STARTTLS" => {
                self.tls = true;
                "220 2.0.0 Ready to start TLS\r\n".into()
            }
            "AUTH" => self.cmd_auth(rest),
            "MAIL" => self.cmd_mail(rest),
            "RCPT" => self.cmd_rcpt(rest),
            "DATA" => self.cmd_data(),
            "RSET" => {
                self.reset_txn();
                "250 2.0.0 OK\r\n".into()
            }
            "NOOP" => "250 2.0.0 OK\r\n".into(),
            "VRFY" => "252 2.1.5 Cannot VRFY, but will accept and attempt delivery\r\n".into(),
            "QUIT" => "221 2.0.0 Bye\r\n".into(),
            "HELP" => "214 2.0.0 Envoir DMTAP submission\r\n".into(),
            _ => "500 5.5.1 Command unrecognized\r\n".into(),
        }
    }

    fn ehlo(&mut self, domain: &str, esmtp: bool) -> String {
        self.reset_txn();
        if !esmtp {
            return format!("250 mail.dmtap.local greets {domain}\r\n");
        }
        let mut lines = vec![format!("250-mail.dmtap.local greets {domain}")];
        lines.push(format!("250-SIZE {MAX_SIZE}"));
        lines.push("250-8BITMIME".into());
        lines.push("250-SMTPUTF8".into());
        lines.push("250-PIPELINING".into());
        lines.push("250-DSN".into());
        lines.push("250-ENHANCEDSTATUSCODES".into());
        if self.tls {
            lines.push("250-AUTH PLAIN LOGIN".into());
        } else {
            lines.push("250-STARTTLS".into());
        }
        lines.push("250 HELP".into());
        lines.join("\r\n") + "\r\n"
    }

    fn cmd_auth(&mut self, rest: &str) -> String {
        if !self.tls {
            return "538 5.7.11 Encryption required for requested authentication mechanism\r\n".into();
        }
        let mut it = rest.split_whitespace();
        let mech = it.next().unwrap_or("");
        let initial = it.next();
        match SaslMechanism::parse(mech) {
            Some(SaslMechanism::Plain) => match initial {
                Some(ir) => self.finish_plain(ir),
                None => {
                    self.pending_auth = Some(SmtpPendingAuth::Plain);
                    "334 \r\n".into()
                }
            },
            Some(SaslMechanism::Login) => {
                self.pending_auth = Some(SmtpPendingAuth::LoginUser);
                format!("334 {}\r\n", crate::util::base64_encode(b"Username:"))
            }
            None => "504 5.5.4 Unrecognized authentication type\r\n".into(),
        }
    }

    fn continue_auth(&mut self, p: SmtpPendingAuth, line: &str) -> String {
        match p {
            SmtpPendingAuth::Plain => self.finish_plain(line.trim()),
            SmtpPendingAuth::LoginUser => {
                let user = auth::decode_login_field(line.trim()).unwrap_or_default();
                self.pending_auth = Some(SmtpPendingAuth::LoginPass(user));
                format!("334 {}\r\n", crate::util::base64_encode(b"Password:"))
            }
            SmtpPendingAuth::LoginPass(user) => {
                let pass = auth::decode_login_field(line.trim()).unwrap_or_default();
                self.finish_credentials(&user, &pass)
            }
        }
    }

    fn finish_plain(&mut self, ir: &str) -> String {
        match auth::decode_plain(ir) {
            Some(cred) => self.finish_credentials(&cred.authcid, &cred.password),
            None => "501 5.5.2 Cannot decode AUTH PLAIN\r\n".into(),
        }
    }

    fn finish_credentials(&mut self, user: &str, pass: &str) -> String {
        match self.auth.verify(user, pass) {
            Some(id) => {
                self.authed = Some(id);
                "235 2.7.0 Authentication successful\r\n".into()
            }
            None => "535 5.7.8 Authentication credentials invalid\r\n".into(),
        }
    }

    fn cmd_mail(&mut self, rest: &str) -> String {
        if self.require_auth && self.authed.is_none() {
            return "530 5.7.0 Authentication required\r\n".into();
        }
        // MAIL FROM:<addr> [ SIZE=n BODY=8BITMIME SMTPUTF8 RET=… ENVID=… ]
        let addr = match parse_path_param(rest, "FROM") {
            Some(a) => a,
            None => return "501 5.5.4 Syntax: MAIL FROM:<address>\r\n".into(),
        };
        // Honor a declared SIZE against our advertised limit (RFC 1870).
        if let Some(sz) = param_value(rest, "SIZE").and_then(|v| v.parse::<usize>().ok()) {
            if sz > MAX_SIZE {
                return "552 5.3.4 Message size exceeds fixed limit\r\n".into();
            }
        }
        self.mail_from = Some(addr);
        self.rcpt_to.clear();
        "250 2.1.0 Sender OK\r\n".into()
    }

    fn cmd_rcpt(&mut self, rest: &str) -> String {
        if self.mail_from.is_none() {
            return "503 5.5.1 Need MAIL before RCPT\r\n".into();
        }
        let addr = match parse_path_param(rest, "TO") {
            Some(a) => a,
            None => return "501 5.5.4 Syntax: RCPT TO:<address>\r\n".into(),
        };
        self.rcpt_to.push(addr);
        "250 2.1.5 Recipient OK\r\n".into()
    }

    fn cmd_data(&mut self) -> String {
        if self.mail_from.is_none() || self.rcpt_to.is_empty() {
            return "503 5.5.1 Need MAIL and RCPT before DATA\r\n".into();
        }
        self.phase = Phase::Data;
        self.data_buf.clear();
        "354 End data with <CR><LF>.<CR><LF>\r\n".into()
    }

    fn feed_data_line(&mut self, line: &str) -> String {
        if line == "." {
            // End of data.
            self.phase = Phase::Command;
            let data = std::mem::take(&mut self.data_buf);
            let sub = Submission {
                mail_from: self.mail_from.take().unwrap_or_default(),
                rcpt_to: std::mem::take(&mut self.rcpt_to),
                data,
            };
            self.submissions.push(sub);
            return "250 2.0.0 OK: queued as MOTE\r\n".into();
        }
        // Dot-unstuffing (RFC 5321 §4.5.2).
        let content = line.strip_prefix('.').unwrap_or(line);
        self.data_buf.extend_from_slice(content.as_bytes());
        self.data_buf.extend_from_slice(b"\r\n");
        String::new()
    }

    fn reset_txn(&mut self) {
        self.mail_from = None;
        self.rcpt_to.clear();
        self.data_buf.clear();
    }
}

/// Extract the `<addr>` after `MAIL FROM:` / `RCPT TO:`.
fn parse_path_param(rest: &str, keyword: &str) -> Option<String> {
    let up = rest.to_ascii_uppercase();
    let kw = format!("{keyword}:");
    let idx = up.find(&kw)?;
    let after = &rest[idx + kw.len()..];
    let after = after.trim_start();
    if let (Some(lt), Some(gt)) = (after.find('<'), after.find('>')) {
        Some(after[lt + 1..gt].to_string())
    } else {
        // Bare address up to first space.
        after.split_whitespace().next().map(str::to_string)
    }
}

fn param_value(rest: &str, key: &str) -> Option<String> {
    for tok in rest.split_whitespace() {
        if let Some((k, v)) = tok.split_once('=') {
            if k.eq_ignore_ascii_case(key) {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// Convert a submitted RFC 5322 message into a native MOTE draft (spec §8.2 outbound path).
/// The Subject/Content-Type map into MOTE [`Headers`]; the message body becomes the MOTE body.
pub fn build_mote_draft(data: &[u8], ts: TimestampMs) -> MoteDraft {
    let parsed = ParsedMessage::parse(data);
    let mut draft = MoteDraft::new(Kind::Mail, ts, parsed.body.clone());
    draft.headers = Headers {
        thread: None,
        subject: parsed.header("Subject").map(str::to_string),
        mime: parsed.header("Content-Type").map(str::to_string),
        cc: Vec::new(),
    };
    draft
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::StaticAuthenticator;
    use crate::util::base64_encode;

    fn authed_session() -> SmtpSession<StaticAuthenticator> {
        let mut a = StaticAuthenticator::new();
        a.issue("alice", "pw", vec![9, 9], "test");
        let mut s = SmtpSession::new(a, true);
        let _ = s.greeting();
        s
    }

    #[test]
    fn ehlo_advertises_extensions() {
        let mut s = authed_session();
        let reply = s.feed_line("EHLO client.example");
        assert!(reply.contains("250-SIZE"));
        assert!(reply.contains("8BITMIME"));
        assert!(reply.contains("SMTPUTF8"));
        assert!(reply.contains("AUTH PLAIN LOGIN"));
    }

    #[test]
    fn full_submission_flow() {
        let mut s = authed_session();
        s.feed_line("EHLO c");
        let cred = base64_encode(b"\0alice\0pw");
        assert!(s.feed_line(&format!("AUTH PLAIN {cred}")).starts_with("235"));
        assert!(s.feed_line("MAIL FROM:<alice@dmtap.local> SIZE=100").starts_with("250"));
        assert!(s.feed_line("RCPT TO:<bob@example.net>").starts_with("250"));
        assert!(s.feed_line("DATA").starts_with("354"));
        s.feed_line("Subject: Hi");
        s.feed_line("");
        s.feed_line("Hello Bob");
        assert!(s.feed_line(".").starts_with("250"));
        let subs = s.take_submissions();
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].rcpt_to, vec!["bob@example.net"]);
        assert!(subs[0].data.windows(9).any(|w| w == b"Hello Bob"));
    }

    #[test]
    fn requires_auth_before_mail() {
        let mut s = authed_session();
        s.feed_line("EHLO c");
        assert!(s.feed_line("MAIL FROM:<x@y>").starts_with("530"));
    }

    #[test]
    fn builds_mote_draft() {
        let draft = build_mote_draft(b"Subject: Test\r\n\r\nbody", 42);
        assert_eq!(draft.headers.subject.as_deref(), Some("Test"));
        assert_eq!(draft.body, b"body");
    }
}

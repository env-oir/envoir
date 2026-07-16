//! IMAP SEARCH keys (RFC 9051 §6.4.4) — parser + evaluator.
//!
//! A search program is a tree of [`SearchKey`]s; multiple keys in sequence are ANDed. The
//! evaluator runs a key against one message's projected metadata ([`SearchCtx`]). Unsupported
//! keys fail **closed** at parse time (a `BAD` response) rather than silently matching nothing.

use crate::imap::parser::{ParseError, Token};
use crate::imap::sequence::SequenceSet;
use crate::mime::{self, ParsedMessage};
use crate::store::{Flag, Message};

/// A SEARCH key (RFC 9051 §6.4.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchKey {
    All,
    And(Vec<SearchKey>),
    Or(Box<SearchKey>, Box<SearchKey>),
    Not(Box<SearchKey>),
    Answered,
    Unanswered,
    Deleted,
    Undeleted,
    Draft,
    Undraft,
    Flagged,
    Unflagged,
    Seen,
    Unseen,
    Recent,
    New,
    Old,
    Keyword(String),
    Unkeyword(String),
    From(String),
    To(String),
    Cc(String),
    Bcc(String),
    Subject(String),
    Body(String),
    Text(String),
    Header(String, String),
    Before(String),
    On(String),
    Since(String),
    SentBefore(String),
    SentOn(String),
    SentSince(String),
    Larger(usize),
    Smaller(usize),
    Uid(SequenceSet),
    Seq(SequenceSet),
    ModSeq(u64),
}

/// Parse a full (top-level) search program; a sequence of keys is ANDed together.
pub fn parse_search_key(toks: &[Token]) -> Result<SearchKey, ParseError> {
    if toks.is_empty() {
        return Ok(SearchKey::All);
    }
    let mut keys = Vec::new();
    let mut rest = toks;
    while !rest.is_empty() {
        let (key, next) = parse_one(rest)?;
        keys.push(key);
        rest = next;
    }
    Ok(if keys.len() == 1 { keys.pop().unwrap() } else { SearchKey::And(keys) })
}

fn s(t: &Token) -> Result<String, ParseError> {
    t.as_str().map(str::to_string).ok_or(ParseError::Syntax("expected search argument"))
}

fn parse_one(toks: &[Token]) -> Result<(SearchKey, &[Token]), ParseError> {
    let head = &toks[0];
    // A parenthesised sub-program.
    if matches!(head, Token::LParen) {
        let end = close_paren(toks)?;
        let inner = parse_search_key(&toks[1..end])?;
        return Ok((inner, &toks[end + 1..]));
    }
    let kw = head.as_str().ok_or(ParseError::Syntax("bad search key"))?.to_ascii_uppercase();
    let rest = &toks[1..];

    // Zero-argument keys.
    let simple = match kw.as_str() {
        "ALL" => Some(SearchKey::All),
        "ANSWERED" => Some(SearchKey::Answered),
        "UNANSWERED" => Some(SearchKey::Unanswered),
        "DELETED" => Some(SearchKey::Deleted),
        "UNDELETED" => Some(SearchKey::Undeleted),
        "DRAFT" => Some(SearchKey::Draft),
        "UNDRAFT" => Some(SearchKey::Undraft),
        "FLAGGED" => Some(SearchKey::Flagged),
        "UNFLAGGED" => Some(SearchKey::Unflagged),
        "SEEN" => Some(SearchKey::Seen),
        "UNSEEN" => Some(SearchKey::Unseen),
        "RECENT" => Some(SearchKey::Recent),
        "NEW" => Some(SearchKey::New),
        "OLD" => Some(SearchKey::Old),
        _ => None,
    };
    if let Some(k) = simple {
        return Ok((k, rest));
    }

    // One-string-argument keys.
    macro_rules! one_str {
        ($ctor:expr) => {{
            let arg = s(rest.first().ok_or(ParseError::Syntax("missing arg"))?)?;
            Ok(($ctor(arg), &rest[1..]))
        }};
    }
    match kw.as_str() {
        "KEYWORD" => return one_str!(SearchKey::Keyword),
        "UNKEYWORD" => return one_str!(SearchKey::Unkeyword),
        "FROM" => return one_str!(SearchKey::From),
        "TO" => return one_str!(SearchKey::To),
        "CC" => return one_str!(SearchKey::Cc),
        "BCC" => return one_str!(SearchKey::Bcc),
        "SUBJECT" => return one_str!(SearchKey::Subject),
        "BODY" => return one_str!(SearchKey::Body),
        "TEXT" => return one_str!(SearchKey::Text),
        "BEFORE" => return one_str!(SearchKey::Before),
        "ON" => return one_str!(SearchKey::On),
        "SINCE" => return one_str!(SearchKey::Since),
        "SENTBEFORE" => return one_str!(SearchKey::SentBefore),
        "SENTON" => return one_str!(SearchKey::SentOn),
        "SENTSINCE" => return one_str!(SearchKey::SentSince),
        _ => {}
    }

    match kw.as_str() {
        "HEADER" => {
            let field = s(rest.first().ok_or(ParseError::Syntax("HEADER field"))?)?;
            let val = s(rest.get(1).ok_or(ParseError::Syntax("HEADER value"))?)?;
            Ok((SearchKey::Header(field, val), &rest[2..]))
        }
        "LARGER" => {
            let n = s(rest.first().ok_or(ParseError::Syntax("LARGER n"))?)?
                .parse()
                .map_err(|_| ParseError::Syntax("LARGER number"))?;
            Ok((SearchKey::Larger(n), &rest[1..]))
        }
        "SMALLER" => {
            let n = s(rest.first().ok_or(ParseError::Syntax("SMALLER n"))?)?
                .parse()
                .map_err(|_| ParseError::Syntax("SMALLER number"))?;
            Ok((SearchKey::Smaller(n), &rest[1..]))
        }
        "MODSEQ" => {
            let n = s(rest.first().ok_or(ParseError::Syntax("MODSEQ n"))?)?
                .parse()
                .map_err(|_| ParseError::Syntax("MODSEQ number"))?;
            Ok((SearchKey::ModSeq(n), &rest[1..]))
        }
        "UID" => {
            let set = SequenceSet::parse(&s(rest.first().ok_or(ParseError::Syntax("UID set"))?)?)
                .ok_or(ParseError::Syntax("UID set"))?;
            Ok((SearchKey::Uid(set), &rest[1..]))
        }
        "NOT" => {
            let (inner, next) = parse_one(rest)?;
            Ok((SearchKey::Not(Box::new(inner)), next))
        }
        "OR" => {
            let (a, next1) = parse_one(rest)?;
            let (b, next2) = parse_one(next1)?;
            Ok((SearchKey::Or(Box::new(a), Box::new(b)), next2))
        }
        _ => {
            // A bare sequence set (e.g. `1:5`), else unknown → fail closed.
            if let Some(set) = SequenceSet::parse(&kw) {
                Ok((SearchKey::Seq(set), rest))
            } else {
                Err(ParseError::Syntax("unknown search key"))
            }
        }
    }
}

fn close_paren(toks: &[Token]) -> Result<usize, ParseError> {
    let mut depth = 0;
    for (i, t) in toks.iter().enumerate() {
        match t {
            Token::LParen => depth += 1,
            Token::RParen => {
                depth -= 1;
                if depth == 0 {
                    return Ok(i);
                }
            }
            _ => {}
        }
    }
    Err(ParseError::Syntax("unbalanced parens in search"))
}

// --- Evaluation ----------------------------------------------------------------------------

/// Per-message context for [`eval`]. The MIME parse is obtained **lazily** through the message's
/// memoized cache ([`Message::parsed_cached`]) — a flag-only SEARCH over a large mailbox never
/// parses a single body, and header/body predicates parse each message at most once, ever.
pub struct SearchCtx<'a> {
    pub seq: u32,
    pub max_seq: u32,
    pub uid: u32,
    pub max_uid: u32,
    pub msg: &'a Message,
}

impl<'a> SearchCtx<'a> {
    /// Build a context for `msg` at sequence/uid coordinates.
    pub fn new(seq: u32, max_seq: u32, uid: u32, max_uid: u32, msg: &'a Message) -> SearchCtx<'a> {
        SearchCtx { seq, max_seq, uid, max_uid, msg }
    }

    /// The memoized MIME parse (only touched by predicates that need headers/body/structure).
    fn parsed(&self) -> &ParsedMessage {
        self.msg.parsed_cached()
    }
}

/// Evaluate a search key against one message.
pub fn eval(key: &SearchKey, c: &SearchCtx) -> bool {
    use SearchKey::*;
    match key {
        All => true,
        And(ks) => ks.iter().all(|k| eval(k, c)),
        Or(a, b) => eval(a, c) || eval(b, c),
        Not(k) => !eval(k, c),
        Answered => has(c, &Flag::Answered),
        Unanswered => !has(c, &Flag::Answered),
        Deleted => has(c, &Flag::Deleted),
        Undeleted => !has(c, &Flag::Deleted),
        Draft => has(c, &Flag::Draft),
        Undraft => !has(c, &Flag::Draft),
        Flagged => has(c, &Flag::Flagged),
        Unflagged => !has(c, &Flag::Flagged),
        Seen => has(c, &Flag::Seen),
        Unseen => !has(c, &Flag::Seen),
        Recent => has(c, &Flag::Recent),
        New => has(c, &Flag::Recent) && !has(c, &Flag::Seen),
        Old => !has(c, &Flag::Recent),
        Keyword(k) => has(c, &Flag::Keyword(k.clone())),
        Unkeyword(k) => !has(c, &Flag::Keyword(k.clone())),
        From(v) => hdr_contains(c, "From", v),
        To(v) => hdr_contains(c, "To", v),
        Cc(v) => hdr_contains(c, "Cc", v),
        Bcc(v) => hdr_contains(c, "Bcc", v),
        Subject(v) => hdr_contains(c, "Subject", v),
        Header(f, v) => c.parsed().header(f).map(|h| icontains(h, v)).unwrap_or(v.is_empty()),
        Body(v) => body_contains(c, v),
        Text(v) => icontains(&String::from_utf8_lossy(&c.msg.raw), v),
        Larger(n) => c.msg.size() > *n,
        Smaller(n) => c.msg.size() < *n,
        Uid(set) => set.contains(c.uid, c.max_uid),
        Seq(set) => set.contains(c.seq, c.max_seq),
        ModSeq(n) => c.msg.modseq >= *n,
        Before(d) => cmp_internal_date(c, d, |a, b| a < b),
        On(d) => cmp_internal_date(c, d, |a, b| a == b),
        Since(d) => cmp_internal_date(c, d, |a, b| a >= b),
        SentBefore(d) => cmp_sent_date(c, d, |a, b| a < b),
        SentOn(d) => cmp_sent_date(c, d, |a, b| a == b),
        SentSince(d) => cmp_sent_date(c, d, |a, b| a >= b),
    }
}

fn has(c: &SearchCtx, f: &Flag) -> bool {
    c.msg.has_flag(f)
}

fn hdr_contains(c: &SearchCtx, name: &str, needle: &str) -> bool {
    c.parsed().header(name).map(|h| icontains(h, needle)).unwrap_or(false)
}

fn body_contains(c: &SearchCtx, needle: &str) -> bool {
    icontains(&String::from_utf8_lossy(&c.parsed().body), needle)
}

fn icontains(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.to_ascii_lowercase().contains(&needle.to_ascii_lowercase())
}

/// Parse an IMAP `date` (`d-Mon-yyyy`, e.g. `15-Jul-2026`) into (year, month, day).
fn parse_imap_date(d: &str) -> Option<(i64, i64, i64)> {
    let d = d.trim().trim_matches('"');
    let mut it = d.split('-');
    let day: i64 = it.next()?.parse().ok()?;
    let mon = month_num(it.next()?)?;
    let year: i64 = it.next()?.parse().ok()?;
    Some((year, mon, day))
}

fn month_num(m: &str) -> Option<i64> {
    const MO: [&str; 12] =
        ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
    MO.iter().position(|x| x.eq_ignore_ascii_case(m)).map(|i| i as i64 + 1)
}

fn cmp_internal_date(c: &SearchCtx, d: &str, f: impl Fn(&(i64, i64, i64), &(i64, i64, i64)) -> bool) -> bool {
    match parse_imap_date(d) {
        Some(target) => f(&mime::ymd_from_ms(c.msg.internal_date), &target),
        None => false,
    }
}

fn cmp_sent_date(c: &SearchCtx, d: &str, f: impl Fn(&(i64, i64, i64), &(i64, i64, i64)) -> bool) -> bool {
    let target = match parse_imap_date(d) {
        Some(t) => t,
        None => return false,
    };
    // Use the message's Date: header day if present; else fall back to internal date.
    let sent = c.parsed().header("Date").and_then(parse_rfc5322_day).unwrap_or(mime::ymd_from_ms(c.msg.internal_date));
    f(&sent, &target)
}

/// Extract (y, m, d) from an RFC 5322 Date header (best-effort; day/month/year tokens).
fn parse_rfc5322_day(date: &str) -> Option<(i64, i64, i64)> {
    // e.g. "Wed, 15 Jul 2026 12:00:00 +0000"
    let cleaned = date.replace(',', " ");
    let mut toks = cleaned.split_whitespace();
    // Skip optional weekday.
    let mut first = toks.next()?;
    if month_num(first).is_none() && first.parse::<i64>().is_err() {
        first = toks.next()?;
    }
    let day: i64 = first.parse().ok()?;
    let mon = month_num(toks.next()?)?;
    let year: i64 = toks.next()?.parse().ok()?;
    Some((year, mon, day))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imap::parser::tokenize;

    fn key(s: &str) -> SearchKey {
        let toks = tokenize(s.as_bytes()).unwrap();
        parse_search_key(&toks).unwrap()
    }

    #[test]
    fn parses_flag_and_text_keys() {
        assert_eq!(key("SEEN"), SearchKey::Seen);
        assert_eq!(key("FROM alice"), SearchKey::From("alice".into()));
        assert!(matches!(key("SUBJECT hello UNSEEN"), SearchKey::And(_)));
    }

    #[test]
    fn parses_or_not() {
        assert!(matches!(key("OR SEEN FLAGGED"), SearchKey::Or(_, _)));
        assert!(matches!(key("NOT DELETED"), SearchKey::Not(_)));
    }

    #[test]
    fn evaluates_against_message() {
        let raw = b"From: Alice <alice@example.com>\r\nSubject: Weekly report\r\n\r\nthe body text\r\n";
        let msg = Message::new(5, vec![Flag::Seen], 1_752_537_600_000, 3, raw.to_vec());
        let ctx = SearchCtx::new(1, 1, 5, 5, &msg);
        assert!(eval(&key("SEEN"), &ctx));
        assert!(!eval(&key("UNSEEN"), &ctx));
        assert!(eval(&key("FROM alice"), &ctx));
        assert!(eval(&key("SUBJECT report"), &ctx));
        assert!(eval(&key("BODY body"), &ctx));
        assert!(eval(&key("UID 5"), &ctx));
        assert!(eval(&key("SINCE 1-Jan-2020"), &ctx));
        assert!(eval(&key("BEFORE 1-Jan-2030"), &ctx));
        assert!(!eval(&key("LARGER 100000"), &ctx));
    }
}

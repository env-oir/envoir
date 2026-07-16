//! IMAP command tokenizer + parser (RFC 9051 §6 / RFC 3501 §6, `command`).
//!
//! The [`tokenize`] pass turns a complete command buffer (with any literals already read off the
//! wire and inlined) into a flat [`Token`] stream, understanding quoted strings, parenthesised
//! lists, bracketed section specs, and `{n}`/`{n+}` literals (LITERAL+ / SASL-IR feed the reader,
//! not the tokenizer). [`parse_command`] then builds a typed [`Command`]. Grammar not yet
//! handled fails **closed** with a `BAD`-worthy [`ParseError`], never a silent guess.

use crate::search::SearchKey;
use crate::store::Flag;

use super::sequence::SequenceSet;

/// A lexical token of an IMAP command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    Atom(String),
    Quoted(String),
    Literal(Vec<u8>),
    LParen,
    RParen,
    LBracket,
    RBracket,
}

impl Token {
    /// The string value of an atom or quoted string (for arguments that accept `astring`).
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Token::Atom(s) | Token::Quoted(s) => Some(s),
            _ => None,
        }
    }
    /// Bytes of a literal, or the UTF-8 bytes of an atom/quoted string.
    pub fn as_bytes(&self) -> Option<Vec<u8>> {
        match self {
            Token::Atom(s) | Token::Quoted(s) => Some(s.clone().into_bytes()),
            Token::Literal(b) => Some(b.clone()),
            _ => None,
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("empty command")]
    Empty,
    #[error("malformed literal")]
    BadLiteral,
    #[error("unterminated quoted string")]
    UnterminatedQuote,
    #[error("unknown command {0}")]
    UnknownCommand(String),
    #[error("syntax error: {0}")]
    Syntax(&'static str),
}

/// Tokenize a complete command buffer. The trailing CRLF is optional.
pub fn tokenize(buf: &[u8]) -> Result<Vec<Token>, ParseError> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < buf.len() {
        match buf[i] {
            b' ' | b'\t' | b'\r' | b'\n' => i += 1,
            b'(' => {
                out.push(Token::LParen);
                i += 1;
            }
            b')' => {
                out.push(Token::RParen);
                i += 1;
            }
            b'[' => {
                out.push(Token::LBracket);
                i += 1;
            }
            b']' => {
                out.push(Token::RBracket);
                i += 1;
            }
            b'"' => {
                let (s, ni) = read_quoted(buf, i + 1)?;
                out.push(Token::Quoted(s));
                i = ni;
            }
            b'{' => {
                let (lit, ni) = read_literal(buf, i + 1)?;
                out.push(Token::Literal(lit));
                i = ni;
            }
            _ => {
                let (s, ni) = read_atom(buf, i);
                out.push(Token::Atom(s));
                i = ni;
            }
        }
    }
    Ok(out)
}

fn read_quoted(buf: &[u8], mut i: usize) -> Result<(String, usize), ParseError> {
    let mut s = String::new();
    while i < buf.len() {
        match buf[i] {
            b'"' => return Ok((s, i + 1)),
            b'\\' if i + 1 < buf.len() => {
                s.push(buf[i + 1] as char);
                i += 2;
            }
            c => {
                s.push(c as char);
                i += 1;
            }
        }
    }
    Err(ParseError::UnterminatedQuote)
}

fn read_literal(buf: &[u8], mut i: usize) -> Result<(Vec<u8>, usize), ParseError> {
    let start = i;
    while i < buf.len() && buf[i].is_ascii_digit() {
        i += 1;
    }
    let n: usize =
        std::str::from_utf8(&buf[start..i]).ok().and_then(|s| s.parse().ok()).ok_or(ParseError::BadLiteral)?;
    // Optional LITERAL+ non-sync marker.
    if i < buf.len() && buf[i] == b'+' {
        i += 1;
    }
    if i >= buf.len() || buf[i] != b'}' {
        return Err(ParseError::BadLiteral);
    }
    i += 1;
    // Skip the CRLF (or bare LF) that terminates the literal header.
    if i < buf.len() && buf[i] == b'\r' {
        i += 1;
    }
    if i < buf.len() && buf[i] == b'\n' {
        i += 1;
    }
    if i + n > buf.len() {
        return Err(ParseError::BadLiteral);
    }
    Ok((buf[i..i + n].to_vec(), i + n))
}

fn read_atom(buf: &[u8], mut i: usize) -> (String, usize) {
    let start = i;
    while i < buf.len() {
        match buf[i] {
            b' ' | b'\t' | b'\r' | b'\n' | b'(' | b')' | b'[' | b']' | b'{' | b'"' => break,
            _ => i += 1,
        }
    }
    (String::from_utf8_lossy(&buf[start..i]).into_owned(), i)
}

// --- Command AST ---------------------------------------------------------------------------

/// A parsed, tagged IMAP command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCommand {
    pub tag: String,
    pub command: Command,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Capability,
    Noop,
    Logout,
    StartTls,
    Enable(Vec<String>),
    Login { user: String, pass: String },
    Authenticate { mechanism: String, initial: Option<String> },
    Select { mailbox: String, qresync: Option<QResyncParams>, condstore: bool },
    Examine { mailbox: String, qresync: Option<QResyncParams>, condstore: bool },
    /// CREATE, optionally with a SPECIAL-USE `(USE (\Archive …))` attribute (RFC 6154 §3).
    Create { name: String, use_attr: Option<String> },
    Delete(String),
    Rename { from: String, to: String },
    Subscribe(String),
    Unsubscribe(String),
    List { reference: String, pattern: String, return_opts: Vec<String>, select_opts: Vec<String> },
    Lsub { reference: String, pattern: String },
    Status { mailbox: String, items: Vec<String> },
    Append {
        mailbox: String,
        flags: Vec<Flag>,
        date: Option<String>,
        message: Vec<u8>,
        /// CATENATE parts (RFC 4469), when the client built the message from `TEXT {n}` literals
        /// and `URL "…"` references instead of a single literal. `None` = ordinary APPEND.
        catenate: Option<Vec<CatPart>>,
    },
    Check,
    Close,
    Unselect,
    Expunge,
    UidExpunge(SequenceSet),
    Idle,
    Namespace,
    Id(Option<Vec<(String, String)>>),
    Search { charset: Option<String>, key: SearchKey, uid: bool, ret: Vec<String> },
    Fetch { set: SequenceSet, items: Vec<FetchItem>, uid: bool, changedsince: Option<u64>, vanished: bool },
    Store(StoreCommand),
    Copy { set: SequenceSet, mailbox: String, uid: bool },
    Move { set: SequenceSet, mailbox: String, uid: bool },
    /// SORT (RFC 5256): `SORT (criteria…) charset search-key`.
    Sort { criteria: Vec<SortCriterion>, charset: Option<String>, key: SearchKey, uid: bool },
    /// THREAD (RFC 5256): `THREAD algorithm charset search-key`.
    Thread { algorithm: ThreadAlgorithm, charset: Option<String>, key: SearchKey, uid: bool },
}

/// A SORT ordering criterion (RFC 5256 §3), optionally reversed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SortCriterion {
    pub reverse: bool,
    pub key: SortKey,
}

/// A SORT key (RFC 5256 §3): the sortable message attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortKey {
    Arrival,
    Cc,
    Date,
    From,
    Size,
    Subject,
    To,
    /// `DISPLAYFROM` / `DISPLAYTO` (RFC 5957) — sort on the display name.
    DisplayFrom,
    DisplayTo,
}

/// A THREAD algorithm (RFC 5256 §3): ORDEREDSUBJECT or REFERENCES.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadAlgorithm {
    OrderedSubject,
    References,
}

/// QRESYNC SELECT/EXAMINE parameters (RFC 7162 §3.2.5): the client's last-seen `UIDVALIDITY` and
/// `HIGHESTMODSEQ`, plus optionally the set of UIDs it still knows about (so the server can scope
/// the VANISHED (EARLIER) report). The optional `(seq-set uid-set)` known-sequence-match is parsed
/// and ignored (a UID-based resync is a strict superset of what it optimizes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QResyncParams {
    pub uid_validity: u32,
    pub modseq: u64,
    pub known_uids: Option<SequenceSet>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreCommand {
    pub set: SequenceSet,
    pub op: StoreOp,
    pub flags: Vec<Flag>,
    pub silent: bool,
    pub uid: bool,
    pub unchangedsince: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreOp {
    Replace,
    Add,
    Remove,
}

/// One CATENATE part (RFC 4469 §2): inline `TEXT` bytes or an IMAP `URL` reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatPart {
    Text(Vec<u8>),
    Url(String),
}

/// A FETCH data item (RFC 9051 §6.4.5, `fetch-att`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchItem {
    Flags,
    Uid,
    InternalDate,
    Rfc822Size,
    Envelope,
    BodyStructure,
    /// `BODY` with no section = the non-extensible BODYSTRUCTURE.
    Body,
    Rfc822,
    Rfc822Header,
    Rfc822Text,
    ModSeq,
    /// `BODY[section]<partial>` / `BODY.PEEK[section]<partial>`.
    BodySection { peek: bool, section: Section, partial: Option<(u32, u32)> },
    /// `BINARY[section]<partial>` / `BINARY.PEEK[…]` (RFC 3516): the CTE-decoded part content.
    Binary { peek: bool, section: Vec<u32>, partial: Option<(u32, u32)> },
    /// `BINARY.SIZE[section]` (RFC 3516): the decoded octet count.
    BinarySize { section: Vec<u32> },
}

/// A body section specifier (RFC 9051 §6.4.5, `section`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Section {
    /// `[]` — the whole message.
    Full,
    /// `[HEADER]`
    Header,
    /// `[HEADER.FIELDS (…)]`
    HeaderFields(Vec<String>),
    /// `[HEADER.FIELDS.NOT (…)]`
    HeaderFieldsNot(Vec<String>),
    /// `[TEXT]`
    Text,
    /// `[n]` / `[n.m]` — a numeric MIME part path.
    Part(Vec<u32>),
    /// `[n.MIME]` — a numeric part's MIME header.
    PartMime(Vec<u32>),
}

/// Parse a complete command buffer into a [`ParsedCommand`].
pub fn parse_command(buf: &[u8]) -> Result<ParsedCommand, ParseError> {
    let tokens = tokenize(buf)?;
    parse_tokens(&tokens)
}

/// Parse an already-tokenized command (shared with the SASL-IR / literal reader path).
pub fn parse_tokens(tokens: &[Token]) -> Result<ParsedCommand, ParseError> {
    let tag = tokens.first().and_then(Token::as_str).ok_or(ParseError::Empty)?.to_string();
    let name = tokens.get(1).and_then(Token::as_str).ok_or(ParseError::Empty)?.to_ascii_uppercase();
    let args = &tokens[2..];
    let command = parse_body(&name, args)?;
    Ok(ParsedCommand { tag, command })
}

fn atom_at(args: &[Token], i: usize) -> Result<String, ParseError> {
    args.get(i).and_then(Token::as_str).map(str::to_string).ok_or(ParseError::Syntax("missing argument"))
}

fn parse_body(name: &str, args: &[Token]) -> Result<Command, ParseError> {
    Ok(match name {
        "CAPABILITY" => Command::Capability,
        "NOOP" => Command::Noop,
        "LOGOUT" => Command::Logout,
        "STARTTLS" => Command::StartTls,
        "CHECK" => Command::Check,
        "CLOSE" => Command::Close,
        "UNSELECT" => Command::Unselect,
        "IDLE" => Command::Idle,
        "NAMESPACE" => Command::Namespace,
        "EXPUNGE" => Command::Expunge,
        "ENABLE" => {
            let caps = args.iter().filter_map(Token::as_str).map(str::to_string).collect();
            Command::Enable(caps)
        }
        "LOGIN" => Command::Login { user: atom_at(args, 0)?, pass: atom_at(args, 1)? },
        "AUTHENTICATE" => {
            let mechanism = atom_at(args, 0)?;
            // SASL-IR (RFC 4959): an optional initial response as the next arg.
            let initial = args.get(1).and_then(Token::as_str).map(str::to_string);
            Command::Authenticate { mechanism, initial }
        }
        "SELECT" | "EXAMINE" => {
            let mailbox = atom_at(args, 0)?;
            let (qresync, condstore) = parse_select_params(&args[1.min(args.len())..])?;
            if name == "SELECT" {
                Command::Select { mailbox, qresync, condstore }
            } else {
                Command::Examine { mailbox, qresync, condstore }
            }
        }
        "CREATE" => parse_create(args)?,
        "DELETE" => Command::Delete(atom_at(args, 0)?),
        "RENAME" => Command::Rename { from: atom_at(args, 0)?, to: atom_at(args, 1)? },
        "SUBSCRIBE" => Command::Subscribe(atom_at(args, 0)?),
        "UNSUBSCRIBE" => Command::Unsubscribe(atom_at(args, 0)?),
        "LIST" => parse_list(args)?,
        "LSUB" => Command::Lsub { reference: atom_at(args, 0)?, pattern: atom_at(args, 1)? },
        "STATUS" => parse_status(args)?,
        "APPEND" => parse_append(args)?,
        "ID" => parse_id(args)?,
        "SEARCH" => parse_search(args, false)?,
        "SORT" => parse_sort(args, false)?,
        "THREAD" => parse_thread(args, false)?,
        "FETCH" => parse_fetch(args, false)?,
        "STORE" => Command::Store(parse_store(args, false)?),
        "COPY" => parse_copy_move(args, false, false)?,
        "MOVE" => parse_copy_move(args, false, true)?,
        "UID" => parse_uid(args)?,
        other => return Err(ParseError::UnknownCommand(other.to_string())),
    })
}

fn parse_select_params(args: &[Token]) -> Result<(Option<QResyncParams>, bool), ParseError> {
    // The optional `(CONDSTORE)` / `(QRESYNC (uidvalidity modseq [known-uids [(seqs uids)]]))`
    // parameter list after the mailbox name (RFC 7162 §3.1 / §3.2.5).
    let mut qresync = None;
    let mut condstore = false;
    if !matches!(args.first(), Some(Token::LParen)) {
        return Ok((None, false));
    }
    let (inner, _next) = read_paren_tokens(args, 0)?;
    let mut i = 0;
    while i < inner.len() {
        match inner[i].as_str().map(|s| s.to_ascii_uppercase()).as_deref() {
            Some("CONDSTORE") => {
                condstore = true;
                i += 1;
            }
            Some("QRESYNC") => {
                // QRESYNC is followed by a parenthesised argument list.
                let (q, ni) = read_paren_tokens(&inner, i + 1)?;
                let uid_validity =
                    q.first().and_then(Token::as_str).and_then(|s| s.parse().ok()).ok_or(
                        ParseError::Syntax("QRESYNC needs UIDVALIDITY"),
                    )?;
                let modseq = q
                    .get(1)
                    .and_then(Token::as_str)
                    .and_then(|s| s.parse().ok())
                    .ok_or(ParseError::Syntax("QRESYNC needs modseq"))?;
                // The third element (if an atom, not the trailing `(seq uid)` match list) is the
                // set of UIDs the client still knows.
                let known_uids = q.get(2).and_then(Token::as_str).and_then(SequenceSet::parse);
                qresync = Some(QResyncParams { uid_validity, modseq, known_uids });
                i = ni;
            }
            _ => i += 1,
        }
    }
    Ok((qresync, condstore))
}

fn parse_list(args: &[Token]) -> Result<Command, ParseError> {
    // LIST [ (select-opts) ] reference pattern [ RETURN (return-opts) ]
    let mut i = 0;
    let mut select_opts = Vec::new();
    if matches!(args.first(), Some(Token::LParen)) {
        let (opts, ni) = read_paren_atoms(args, 0)?;
        select_opts = opts;
        i = ni;
    }
    let reference = atom_at(args, i)?;
    let pattern = atom_at(args, i + 1)?;
    let mut return_opts = Vec::new();
    if let Some(Token::Atom(a)) = args.get(i + 2) {
        if a.eq_ignore_ascii_case("RETURN") {
            let (opts, _ni) = read_paren_atoms(args, i + 3)?;
            return_opts = opts;
        }
    }
    Ok(Command::List { reference, pattern, return_opts, select_opts })
}

fn parse_status(args: &[Token]) -> Result<Command, ParseError> {
    let mailbox = atom_at(args, 0)?;
    let (items, _n) = read_paren_atoms(args, 1)?;
    Ok(Command::Status { mailbox, items: items.into_iter().map(|s| s.to_ascii_uppercase()).collect() })
}

fn parse_append(args: &[Token]) -> Result<Command, ParseError> {
    // APPEND mailbox [ (flags) ] [ "date-time" ] ( message-literal | CATENATE (parts…) )
    let mailbox = atom_at(args, 0)?;
    let mut i = 1;
    let mut flags = Vec::new();
    if matches!(args.get(i), Some(Token::LParen)) {
        let (fs, ni) = read_paren_atoms(args, i)?;
        flags = fs.iter().map(|s| Flag::parse(s)).collect();
        i = ni;
    }
    let mut date = None;
    if let Some(Token::Quoted(d)) = args.get(i) {
        date = Some(d.clone());
        i += 1;
    }
    // CATENATE (RFC 4469): `CATENATE ( TEXT {n} | URL "…" )+`.
    if matches!(args.get(i), Some(Token::Atom(a)) if a.eq_ignore_ascii_case("CATENATE")) {
        let (inner, _n) = read_paren_tokens(args, i + 1)?;
        let mut parts = Vec::new();
        let mut j = 0;
        while j < inner.len() {
            let kw = inner[j].as_str().unwrap_or("").to_ascii_uppercase();
            match kw.as_str() {
                "TEXT" => {
                    let bytes = inner
                        .get(j + 1)
                        .and_then(Token::as_bytes)
                        .ok_or(ParseError::Syntax("CATENATE TEXT needs a literal"))?;
                    parts.push(CatPart::Text(bytes));
                    j += 2;
                }
                "URL" => {
                    let url = inner
                        .get(j + 1)
                        .and_then(Token::as_str)
                        .ok_or(ParseError::Syntax("CATENATE URL needs a string"))?;
                    parts.push(CatPart::Url(url.to_string()));
                    j += 2;
                }
                _ => return Err(ParseError::Syntax("bad CATENATE part")),
            }
        }
        return Ok(Command::Append { mailbox, flags, date, message: Vec::new(), catenate: Some(parts) });
    }
    let message = match args.get(i) {
        Some(Token::Literal(b)) => b.clone(),
        Some(t) => t.as_bytes().ok_or(ParseError::Syntax("APPEND needs a message"))?,
        None => return Err(ParseError::Syntax("APPEND needs a message")),
    };
    Ok(Command::Append { mailbox, flags, date, message, catenate: None })
}

fn parse_create(args: &[Token]) -> Result<Command, ParseError> {
    let name = atom_at(args, 0)?;
    // Optional `(USE (\Attr …))` SPECIAL-USE create parameter (RFC 6154 §3).
    let mut use_attr = None;
    if matches!(args.get(1), Some(Token::LParen)) {
        let (inner, _n) = read_paren_tokens(args, 1)?;
        let mut it = inner.iter();
        while let Some(tok) = it.next() {
            if tok.as_str().map(|s| s.eq_ignore_ascii_case("USE")).unwrap_or(false) {
                if let Some(Token::LParen) = it.next() {
                    // The next atom is the first \Use attribute.
                    use_attr = it.next().and_then(Token::as_str).map(str::to_string);
                }
            }
        }
    }
    Ok(Command::Create { name, use_attr })
}

fn parse_sort(args: &[Token], uid: bool) -> Result<Command, ParseError> {
    // SORT (criteria) charset search-key
    let (crit_atoms, next) = read_paren_atoms(args, 0)?;
    let mut criteria = Vec::new();
    let mut reverse = false;
    for a in &crit_atoms {
        if a.eq_ignore_ascii_case("REVERSE") {
            reverse = true;
            continue;
        }
        let key = match a.to_ascii_uppercase().as_str() {
            "ARRIVAL" => SortKey::Arrival,
            "CC" => SortKey::Cc,
            "DATE" => SortKey::Date,
            "FROM" => SortKey::From,
            "SIZE" => SortKey::Size,
            "SUBJECT" => SortKey::Subject,
            "TO" => SortKey::To,
            "DISPLAYFROM" => SortKey::DisplayFrom,
            "DISPLAYTO" => SortKey::DisplayTo,
            _ => return Err(ParseError::Syntax("unknown SORT key")),
        };
        criteria.push(SortCriterion { reverse, key });
        reverse = false;
    }
    if criteria.is_empty() {
        return Err(ParseError::Syntax("SORT needs at least one criterion"));
    }
    // charset (required by RFC 5256 grammar) then the search program.
    let charset = args.get(next).and_then(Token::as_str).map(str::to_string);
    let key = crate::search::parse_search_key(&args[(next + 1).min(args.len())..])?;
    Ok(Command::Sort { criteria, charset, key, uid })
}

fn parse_thread(args: &[Token], uid: bool) -> Result<Command, ParseError> {
    // THREAD algorithm charset search-key
    let algo = atom_at(args, 0)?.to_ascii_uppercase();
    let algorithm = match algo.as_str() {
        "ORDEREDSUBJECT" => ThreadAlgorithm::OrderedSubject,
        "REFERENCES" => ThreadAlgorithm::References,
        _ => return Err(ParseError::Syntax("unknown THREAD algorithm")),
    };
    let charset = args.get(1).and_then(Token::as_str).map(str::to_string);
    let key = crate::search::parse_search_key(&args[2.min(args.len())..])?;
    Ok(Command::Thread { algorithm, charset, key, uid })
}

fn parse_id(args: &[Token]) -> Result<Command, ParseError> {
    if let Some(Token::Atom(a)) = args.first() {
        if a.eq_ignore_ascii_case("NIL") {
            return Ok(Command::Id(None));
        }
    }
    if matches!(args.first(), Some(Token::LParen)) {
        let inner = read_paren_tokens(args, 0)?.0;
        let mut kv = Vec::new();
        let mut it = inner.into_iter();
        while let (Some(k), Some(v)) = (it.next(), it.next()) {
            if let (Some(k), Some(v)) = (k.as_str(), v.as_str()) {
                kv.push((k.to_string(), v.to_string()));
            }
        }
        return Ok(Command::Id(Some(kv)));
    }
    Ok(Command::Id(None))
}

fn parse_search(args: &[Token], uid: bool) -> Result<Command, ParseError> {
    let mut i = 0;
    let mut ret = Vec::new();
    // ESEARCH: `RETURN (opts)` prefix.
    if let Some(Token::Atom(a)) = args.first() {
        if a.eq_ignore_ascii_case("RETURN") {
            let (opts, ni) = read_paren_atoms(args, 1)?;
            ret = opts.into_iter().map(|s| s.to_ascii_uppercase()).collect();
            i = ni;
        }
    }
    let mut charset = None;
    if let Some(Token::Atom(a)) = args.get(i) {
        if a.eq_ignore_ascii_case("CHARSET") {
            charset = args.get(i + 1).and_then(Token::as_str).map(str::to_string);
            i += 2;
        }
    }
    let key = crate::search::parse_search_key(&args[i.min(args.len())..])?;
    Ok(Command::Search { charset, key, uid, ret })
}

fn parse_fetch(args: &[Token], uid: bool) -> Result<Command, ParseError> {
    let set = SequenceSet::parse(atom_at(args, 0)?.as_str()).ok_or(ParseError::Syntax("bad sequence set"))?;
    let (items, next) = parse_fetch_items(args, 1)?;
    // Optional `(CHANGEDSINCE n [VANISHED])` modifier list (RFC 7162 §3.1.5 / §3.2.5).
    let mut changedsince = None;
    let mut vanished = false;
    if matches!(args.get(next), Some(Token::LParen)) {
        let (mods, _n) = read_paren_atoms(args, next)?;
        let mut it = mods.iter();
        while let Some(m) = it.next() {
            if m.eq_ignore_ascii_case("CHANGEDSINCE") {
                changedsince = it.next().and_then(|v| v.parse().ok());
            } else if m.eq_ignore_ascii_case("VANISHED") {
                vanished = true;
            }
        }
    }
    Ok(Command::Fetch { set, items, uid, changedsince, vanished })
}

fn parse_fetch_items(args: &[Token], start: usize) -> Result<(Vec<FetchItem>, usize), ParseError> {
    // A single macro/atom, or a parenthesised list of fetch-atts.
    if matches!(args.get(start), Some(Token::LParen)) {
        // Consume tokens until the matching RParen, honoring bracket sections.
        let end = matching_paren(args, start)?;
        let inner = &args[start + 1..end];
        let items = parse_fetch_att_list(inner)?;
        Ok((items, end + 1))
    } else {
        let atom = atom_at(args, start)?;
        let items = expand_fetch_macro(&atom).unwrap_or_default();
        if !items.is_empty() {
            Ok((items, start + 1))
        } else {
            // A single fetch-att possibly with a bracket section.
            let (item, consumed) = parse_one_fetch_att(&args[start..])?;
            Ok((vec![item], start + consumed))
        }
    }
}

fn parse_fetch_att_list(inner: &[Token]) -> Result<Vec<FetchItem>, ParseError> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < inner.len() {
        let (item, consumed) = parse_one_fetch_att(&inner[i..])?;
        out.push(item);
        i += consumed;
    }
    Ok(out)
}

fn expand_fetch_macro(atom: &str) -> Option<Vec<FetchItem>> {
    let up = atom.to_ascii_uppercase();
    Some(match up.as_str() {
        "ALL" => vec![FetchItem::Flags, FetchItem::InternalDate, FetchItem::Rfc822Size, FetchItem::Envelope],
        "FAST" => vec![FetchItem::Flags, FetchItem::InternalDate, FetchItem::Rfc822Size],
        "FULL" => vec![
            FetchItem::Flags,
            FetchItem::InternalDate,
            FetchItem::Rfc822Size,
            FetchItem::Envelope,
            FetchItem::Body,
        ],
        _ => return None,
    })
}

/// Parse one fetch-att starting at `toks[0]`, returning (item, tokens-consumed).
fn parse_one_fetch_att(toks: &[Token]) -> Result<(FetchItem, usize), ParseError> {
    let head = toks.first().and_then(Token::as_str).ok_or(ParseError::Syntax("bad fetch item"))?;
    let up = head.to_ascii_uppercase();
    let simple = match up.as_str() {
        "FLAGS" => Some(FetchItem::Flags),
        "UID" => Some(FetchItem::Uid),
        "INTERNALDATE" => Some(FetchItem::InternalDate),
        "RFC822.SIZE" => Some(FetchItem::Rfc822Size),
        "ENVELOPE" => Some(FetchItem::Envelope),
        "BODYSTRUCTURE" => Some(FetchItem::BodyStructure),
        "RFC822" => Some(FetchItem::Rfc822),
        "RFC822.HEADER" => Some(FetchItem::Rfc822Header),
        "RFC822.TEXT" => Some(FetchItem::Rfc822Text),
        "MODSEQ" => Some(FetchItem::ModSeq),
        _ => None,
    };
    if let Some(item) = simple {
        return Ok((item, 1));
    }
    // BINARY / BINARY.PEEK / BINARY.SIZE (RFC 3516): a numeric [section], optional <partial>.
    if up == "BINARY" || up == "BINARY.PEEK" || up == "BINARY.SIZE" {
        if !matches!(toks.get(1), Some(Token::LBracket)) {
            return Err(ParseError::Syntax("BINARY needs a [section]"));
        }
        let end = matching_bracket(toks, 1)?;
        // The section is a numeric part path (or empty for the whole message).
        let section = match parse_section(&toks[2..end])? {
            Section::Part(p) => p,
            Section::Full => Vec::new(),
            _ => return Err(ParseError::Syntax("BINARY section must be a part number")),
        };
        if up == "BINARY.SIZE" {
            return Ok((FetchItem::BinarySize { section }, end + 1));
        }
        let peek = up == "BINARY.PEEK";
        let mut consumed = end + 1;
        let mut partial = None;
        if let Some(Token::Atom(a)) = toks.get(consumed) {
            if let Some(p) = parse_partial(a) {
                partial = Some(p);
                consumed += 1;
            }
        }
        return Ok((FetchItem::Binary { peek, section, partial }, consumed));
    }
    // BODY / BODY.PEEK, optionally with a [section]<partial>.
    if up == "BODY" || up == "BODY.PEEK" {
        let peek = up == "BODY.PEEK";
        if matches!(toks.get(1), Some(Token::LBracket)) {
            let end = matching_bracket(toks, 1)?;
            let section = parse_section(&toks[2..end])?;
            let mut consumed = end + 1;
            // Optional <start.count> partial as a trailing atom like "<0.100>".
            let mut partial = None;
            if let Some(Token::Atom(a)) = toks.get(consumed) {
                if let Some(p) = parse_partial(a) {
                    partial = Some(p);
                    consumed += 1;
                }
            }
            return Ok((FetchItem::BodySection { peek, section, partial }, consumed));
        }
        // Bare BODY = non-extensible bodystructure.
        return Ok((FetchItem::Body, 1));
    }
    Err(ParseError::Syntax("unknown fetch item"))
}

fn parse_section(toks: &[Token]) -> Result<Section, ParseError> {
    if toks.is_empty() {
        return Ok(Section::Full);
    }
    let first = toks[0].as_str().unwrap_or("").to_ascii_uppercase();
    match first.as_str() {
        "HEADER" => Ok(Section::Header),
        "TEXT" => Ok(Section::Text),
        "HEADER.FIELDS" => {
            let fields = section_field_list(&toks[1..])?;
            Ok(Section::HeaderFields(fields))
        }
        "HEADER.FIELDS.NOT" => {
            let fields = section_field_list(&toks[1..])?;
            Ok(Section::HeaderFieldsNot(fields))
        }
        _ => {
            // Numeric part path like `1`, `1.2`, `1.2.MIME`, possibly with trailing HEADER/TEXT.
            let s = first;
            if s.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                let mut mime = false;
                let mut nums = Vec::new();
                for seg in s.split('.') {
                    if seg.eq_ignore_ascii_case("MIME") {
                        mime = true;
                    } else if let Ok(n) = seg.parse::<u32>() {
                        nums.push(n);
                    }
                }
                if mime {
                    Ok(Section::PartMime(nums))
                } else {
                    Ok(Section::Part(nums))
                }
            } else {
                Err(ParseError::Syntax("unknown body section"))
            }
        }
    }
}

fn section_field_list(toks: &[Token]) -> Result<Vec<String>, ParseError> {
    // toks should be `( field field … )`.
    let inner = match toks.first() {
        Some(Token::LParen) => {
            let end = matching_paren(toks, 0)?;
            &toks[1..end]
        }
        _ => toks,
    };
    Ok(inner.iter().filter_map(Token::as_str).map(|s| s.to_string()).collect())
}

fn parse_partial(a: &str) -> Option<(u32, u32)> {
    let inner = a.strip_prefix('<')?.strip_suffix('>')?;
    let (start, count) = inner.split_once('.')?;
    Some((start.parse().ok()?, count.parse().ok()?))
}

fn parse_store(args: &[Token], uid: bool) -> Result<StoreCommand, ParseError> {
    let set = SequenceSet::parse(atom_at(args, 0)?.as_str()).ok_or(ParseError::Syntax("bad sequence set"))?;
    let mut i = 1;
    let mut unchangedsince = None;
    // Optional `(UNCHANGEDSINCE n)` modifier (RFC 7162).
    if matches!(args.get(i), Some(Token::LParen)) {
        let (mods, ni) = read_paren_atoms(args, i)?;
        let mut it = mods.iter();
        while let Some(m) = it.next() {
            if m.eq_ignore_ascii_case("UNCHANGEDSINCE") {
                unchangedsince = it.next().and_then(|v| v.parse().ok());
            }
        }
        i = ni;
    }
    let verb = atom_at(args, i)?.to_ascii_uppercase();
    i += 1;
    let (op, silent) = match verb.as_str() {
        "FLAGS" => (StoreOp::Replace, false),
        "FLAGS.SILENT" => (StoreOp::Replace, true),
        "+FLAGS" => (StoreOp::Add, false),
        "+FLAGS.SILENT" => (StoreOp::Add, true),
        "-FLAGS" => (StoreOp::Remove, false),
        "-FLAGS.SILENT" => (StoreOp::Remove, true),
        _ => return Err(ParseError::Syntax("bad STORE verb")),
    };
    // Flags: a parenthesised list, or a bare space-separated remainder.
    let flags = if matches!(args.get(i), Some(Token::LParen)) {
        let (fs, _n) = read_paren_atoms(args, i)?;
        fs.iter().map(|s| Flag::parse(s)).collect()
    } else {
        args[i..].iter().filter_map(Token::as_str).map(Flag::parse).collect()
    };
    Ok(StoreCommand { set, op, flags, silent, uid, unchangedsince })
}

fn parse_copy_move(args: &[Token], uid: bool, is_move: bool) -> Result<Command, ParseError> {
    let set = SequenceSet::parse(atom_at(args, 0)?.as_str()).ok_or(ParseError::Syntax("bad sequence set"))?;
    let mailbox = atom_at(args, 1)?;
    Ok(if is_move {
        Command::Move { set, mailbox, uid }
    } else {
        Command::Copy { set, mailbox, uid }
    })
}

fn parse_uid(args: &[Token]) -> Result<Command, ParseError> {
    let sub = atom_at(args, 0)?.to_ascii_uppercase();
    let rest = &args[1..];
    Ok(match sub.as_str() {
        "FETCH" => parse_fetch(rest, true)?,
        "STORE" => Command::Store(parse_store(rest, true)?),
        "SEARCH" => parse_search(rest, true)?,
        "SORT" => parse_sort(rest, true)?,
        "THREAD" => parse_thread(rest, true)?,
        "COPY" => parse_copy_move(rest, true, false)?,
        "MOVE" => parse_copy_move(rest, true, true)?,
        "EXPUNGE" => {
            let set = SequenceSet::parse(atom_at(rest, 0)?.as_str())
                .ok_or(ParseError::Syntax("bad sequence set"))?;
            Command::UidExpunge(set)
        }
        _ => return Err(ParseError::Syntax("unknown UID subcommand")),
    })
}

// --- token helpers -------------------------------------------------------------------------

fn read_paren_atoms(args: &[Token], open: usize) -> Result<(Vec<String>, usize), ParseError> {
    let (toks, next) = read_paren_tokens(args, open)?;
    Ok((toks.iter().filter_map(Token::as_str).map(str::to_string).collect(), next))
}

fn read_paren_tokens(args: &[Token], open: usize) -> Result<(Vec<Token>, usize), ParseError> {
    if !matches!(args.get(open), Some(Token::LParen)) {
        return Err(ParseError::Syntax("expected ("));
    }
    let end = matching_paren(args, open)?;
    Ok((args[open + 1..end].to_vec(), end + 1))
}

fn matching_paren(args: &[Token], open: usize) -> Result<usize, ParseError> {
    let mut depth = 0;
    for (idx, t) in args.iter().enumerate().skip(open) {
        match t {
            Token::LParen => depth += 1,
            Token::RParen => {
                depth -= 1;
                if depth == 0 {
                    return Ok(idx);
                }
            }
            _ => {}
        }
    }
    Err(ParseError::Syntax("unbalanced parentheses"))
}

fn matching_bracket(args: &[Token], open: usize) -> Result<usize, ParseError> {
    let mut depth = 0;
    for (idx, t) in args.iter().enumerate().skip(open) {
        match t {
            Token::LBracket => depth += 1,
            Token::RBracket => {
                depth -= 1;
                if depth == 0 {
                    return Ok(idx);
                }
            }
            _ => {}
        }
    }
    Err(ParseError::Syntax("unbalanced brackets"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmd(s: &str) -> Command {
        parse_command(s.as_bytes()).unwrap().command
    }

    #[test]
    fn tokenizes_quoted_and_parens() {
        let toks = tokenize(b"a LOGIN \"user name\" pass\r\n").unwrap();
        assert_eq!(toks[2], Token::Quoted("user name".into()));
    }

    #[test]
    fn parses_login() {
        assert_eq!(cmd("a1 LOGIN alice secret"), Command::Login { user: "alice".into(), pass: "secret".into() });
    }

    #[test]
    fn parses_select_condstore() {
        assert_eq!(
            cmd("a SELECT INBOX (CONDSTORE)"),
            Command::Select { mailbox: "INBOX".into(), qresync: None, condstore: true }
        );
    }

    #[test]
    fn parses_select_qresync() {
        match cmd("a SELECT INBOX (QRESYNC (67890007 90060115 1:29))") {
            Command::Select { qresync: Some(q), .. } => {
                assert_eq!(q.uid_validity, 67890007);
                assert_eq!(q.modseq, 90060115);
                assert!(q.known_uids.is_some());
            }
            other => panic!("expected QRESYNC select, got {other:?}"),
        }
    }

    #[test]
    fn parses_fetch_macro_and_items() {
        match cmd("a FETCH 1:3 FULL") {
            Command::Fetch { items, .. } => assert!(items.contains(&FetchItem::Envelope)),
            _ => panic!(),
        }
        match cmd("a FETCH 1 (UID FLAGS BODY.PEEK[HEADER.FIELDS (FROM TO)]<0.100>)") {
            Command::Fetch { items, .. } => {
                assert!(items.contains(&FetchItem::Uid));
                assert!(items.iter().any(|i| matches!(
                    i,
                    FetchItem::BodySection { peek: true, section: Section::HeaderFields(_), partial: Some((0, 100)) }
                )));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parses_uid_fetch() {
        match cmd("a UID FETCH 100:* (FLAGS)") {
            Command::Fetch { uid, .. } => assert!(uid),
            _ => panic!(),
        }
    }

    #[test]
    fn parses_store() {
        match cmd("a STORE 1:5 +FLAGS.SILENT (\\Seen \\Deleted)") {
            Command::Store(s) => {
                assert_eq!(s.op, StoreOp::Add);
                assert!(s.silent);
                assert!(s.flags.contains(&Flag::Seen));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parses_append_literal() {
        let raw = b"a APPEND INBOX (\\Seen) {11}\r\nHello world\r\n";
        match parse_command(raw).unwrap().command {
            Command::Append { mailbox, flags, message, .. } => {
                assert_eq!(mailbox, "INBOX");
                assert!(flags.contains(&Flag::Seen));
                assert_eq!(message, b"Hello world");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn unknown_command_fails_closed() {
        assert!(matches!(
            parse_command(b"a FROBNICATE x\r\n"),
            Err(ParseError::UnknownCommand(_))
        ));
    }
}

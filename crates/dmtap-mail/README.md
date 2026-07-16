# dmtap-mail — mail-protocol server layer (DMTAP §8)

Reference (non-normative) implementation of the **client-access surface** for the Envoir DMTAP
node: it projects one MOTE store (`Kind::Mail` MOTEs, spec §2) as mailboxes/messages/flags and
serves that projection over **IMAP, POP3, SMTP-submission, and JMAP**, plus **autodiscovery**, so
both legacy clients (old iPhone Mail, Outlook, Thunderbird, mutt) and modern JMAP clients work
against a node unchanged (spec §8.1–§8.2). Every protocol is a *view* of the same
[`store::MailStore`].

These are **edge-compat surfaces on the user's own node** (spec §8.5): the node terminates TLS
and speaks the legacy protocol; the mesh/relay never decrypts; there is no central mail store.

## Design

- The protocol **core** (tokenizers, response encoders, state machines, the MOTE→mailbox
  projection) is **synchronous and std-only**, so it always builds offline and is fully unit +
  integration tested.
- Real **TCP listeners** (thread-per-connection, std only — *no async runtime*) live behind the
  optional `net` feature. `cargo run -p envoir-node -- serve-mail` runs them on localhost.
- Auth is **app-passwords bound to the DMTAP identity** (spec §8.2), verified via the
  `Authenticator` trait; SASL PLAIN/LOGIN carry the credential. A DMTAP peer's identity key is
  projected to an address via the 8-word **key-name** (`<keyname>@dmtap.local`, spec §3.9.1).

## Module layout

| Module | Responsibility |
|--------|----------------|
| `store` | MOTE→mailbox projection: `Mailbox`/`Message`/`Flag`, SPECIAL-USE auto-map, `MemoryStore` |
| `mime` | RFC 5322/MIME render (MOTE→message) + parse (message→ENVELOPE/BODYSTRUCTURE), date formatting |
| `auth` | app-passwords, `Authenticator` trait, SASL PLAIN/LOGIN decode |
| `imap::sequence` | sequence-set parser (`1:3,5,*`) |
| `imap::parser` | tokenizer + typed command AST (FETCH items, sections, STORE ops) |
| `imap::response` | ENVELOPE, BODYSTRUCTURE, section extraction, astring/nstring/literal quoting |
| `imap::session` | the session state machine (dispatch + responses) |
| `search` | SEARCH key parser + evaluator |
| `smtp` | SMTP submission state machine → MOTE draft |
| `pop3` | POP3 state machine incl. APOP |
| `jmap` | JMAP Core/Mail: Session, `/get` `/query` `/set` `/changes`, blobs, push types |
| `autodiscover` | SRV records, Thunderbird autoconfig, Apple `.mobileconfig`, MS Autodiscover |
| `net` (feature) | blocking TCP servers + the IMAP synchronizing-literal reader |

## Capability / extension matrix

### IMAP (RFC 9051 rev2 + RFC 3501 rev1)

| Capability | RFC | Status |
|-----------|-----|--------|
| CAPABILITY, NOOP, LOGOUT | 9051 | ✅ |
| LOGIN, AUTHENTICATE (SASL PLAIN/LOGIN, SASL-IR) | 9051 / 4959 | ✅ |
| STARTTLS (state ack; LOGINDISABLED pre-TLS) | 9051 | ✅ handshake note¹ |
| SELECT / EXAMINE (+ CONDSTORE/QRESYNC select-params) | 9051 / 7162 | ✅ |
| CREATE / DELETE / RENAME / SUBSCRIBE / UNSUBSCRIBE | 9051 | ✅ |
| CREATE with SPECIAL-USE `(USE (\Attr))` | 6154 | ✅ |
| LIST / LSUB, SPECIAL-USE, LIST-EXTENDED (return/select opts: SUBSCRIBED/SPECIAL-USE, `\HasChildren`) | 9051 / 6154 / 5258 / 3348 | ✅ honored |
| LIST-STATUS (`RETURN (STATUS (…))` piggyback) | 5819 | ✅ |
| STATUS (incl. SIZE, DELETED, HIGHESTMODSEQ) | 9051 | ✅ |
| APPEND (+ flags/date/literal, APPENDUID) | 9051 / 4315 | ✅ |
| APPEND CATENATE (inline `TEXT` + `URL` → same-node IMAP-URL resolve, `[BADURL]` on miss) | 4469 | ✅ (cross-server URLFETCH deferred) |
| FETCH: FLAGS, UID, INTERNALDATE, RFC822.SIZE, ENVELOPE, BODY, BODYSTRUCTURE | 9051 | ✅ |
| FETCH BODY[…]/BODY.PEEK[…] sections + `<partial>` (HEADER/HEADER.FIELDS[.NOT]/TEXT/MIME/part) | 9051 | ✅ |
| FETCH BINARY[…]/BINARY.PEEK[…] + BINARY.SIZE[…] (CTE-decoded base64/QP, literal8 `~{n}`) | 3516 | ✅ |
| FETCH RFC822 / RFC822.HEADER / RFC822.TEXT / MODSEQ | 9051 / 7162 | ✅ |
| SEARCH (flags, FROM/TO/CC/SUBJECT/BODY/TEXT/HEADER, dates, LARGER/SMALLER, UID/seq, NOT/OR, MODSEQ) | 9051 | ✅ |
| ESEARCH (RETURN MIN/MAX/COUNT/ALL) | 9051 / 4731 | ✅ |
| SEARCHRES — `RETURN (SAVE)` + `$` reference in SEARCH/SORT/FETCH/STORE/COPY/MOVE/EXPUNGE | 5182 | ✅ |
| SORT / UID SORT (ARRIVAL/CC/DATE/FROM/SIZE/SUBJECT/TO + REVERSE + DISPLAYFROM/DISPLAYTO) | 5256 / 5957 | ✅ |
| THREAD / UID THREAD (ORDEREDSUBJECT + REFERENCES) | 5256 | ✅ |
| STORE / UID STORE (FLAGS ±, .SILENT, UNCHANGEDSINCE→MODIFIED) | 9051 / 7162 | ✅ |
| COPY / UID COPY (COPYUID) | 9051 / 4315 | ✅ |
| MOVE / UID MOVE (COPYUID + EXPUNGE) | 6851 | ✅ |
| EXPUNGE / UID EXPUNGE | 9051 / 4315 | ✅ |
| CLOSE / UNSELECT | 9051 | ✅ |
| IDLE / DONE | 2177 | ✅ |
| ENABLE (CONDSTORE/QRESYNC/IMAP4rev2) | 5161 / 9051 | ✅ |
| NAMESPACE | 2342 | ✅ |
| ID | 2971 | ✅ |
| LITERAL+ / synchronizing literals | 7888 | ✅ (`net` reader) |
| CONDSTORE (HIGHESTMODSEQ, MODSEQ, CHANGEDSINCE) | 7162 | ✅ |
| **QRESYNC full resync** (VANISHED (EARLIER) on `SELECT (QRESYNC …)`, `(UIDVALIDITY modseq known-uids)`, VANISHED on EXPUNGE/MOVE, `FETCH … (CHANGEDSINCE n VANISHED)`) | 7162 | ✅ |
| **CHARSET in SEARCH** — US-ASCII / UTF-8 accepted; others rejected `[BADCHARSET (US-ASCII UTF-8)]` | 9051 | ✅ |
| **Nested multipart part paths** (`BODY[n.m…]`, `.MIME`, partial windows) | 9051 | ✅ top-down walk; exotic `message/rfc822` envelope-in-BODYSTRUCTURE **deferred** (niche; needs recursive envelope embedding) |
| **Real TLS** (STARTTLS crypto) | 9051 | ⛔ **deferred** — transport concern; state machine acks, node terminates TLS¹ |

### SMTP submission (RFC 6409)

| Capability | RFC | Status |
|-----------|-----|--------|
| EHLO/HELO, MAIL/RCPT/DATA, RSET/NOOP/VRFY/QUIT | 5321 / 6409 | ✅ |
| AUTH PLAIN/LOGIN (+ initial response); second AUTH → `503`; pre-TLS → `538` | 4954 | ✅ |
| STARTTLS (state ack) | 3207 | ✅ handshake note¹ |
| 8BITMIME | 6152 | ✅ advertised |
| SMTPUTF8 | 6531 | ✅ advertised |
| PIPELINING | 2920 | ✅ advertised |
| SIZE (advertised + enforced against MAIL `SIZE=` and the actual DATA stream → `552`) | 1870 | ✅ |
| DSN (RET/NOTIFY/ENVID params + RFC 3464 report generation) | 3461 / 3464 | ✅ params captured on the `Submission`; `DsnReport::failure_for` / `.render()` emit a `multipart/report; report-type=delivery-status` honoring RET (full/hdrs), ENVID, and per-recipient NOTIFY |
| ENHANCEDSTATUSCODES | 2034 | ✅ |
| Submit → **MOTE** (`build_mote_draft`) or gateway hand-off | spec §8.2 | ✅ (draft built; mesh send is the node's job) |

### POP3 (RFC 1939)

| Capability | RFC | Status |
|-----------|-----|--------|
| USER/PASS | 1939 | ✅ |
| APOP (MD5 digest over the banner + app-password) | 1939 §7 | ✅ |
| STAT/LIST/UIDL/RETR/TOP/DELE/RSET/NOOP/QUIT | 1939 | ✅ |
| UPDATE state — deletes committed to the store on QUIT | 1939 | ✅ |
| STLS | 2595 | ✅ handshake note¹ |
| CAPA | 2449 | ✅ |
| SASL AUTH (PLAIN) | 5034 | ✅ |

### JMAP (RFC 8620 Core + RFC 8621 Mail)

| Capability | RFC | Status |
|-----------|-----|--------|
| Session resource (`apiUrl`/`downloadUrl`/`uploadUrl`/`eventSourceUrl`, capabilities, accounts) | 8620 | ✅ |
| Request/Response envelope (`using`, `methodCalls`, `methodResponses`, `sessionState`) | 8620 | ✅ |
| Core/echo | 8620 §4 | ✅ |
| Mailbox/get, Mailbox/query, Mailbox/set (create/update-rename-subscribe/destroy) | 8621 | ✅ |
| Email/get (envelope fields, keywords, bodyValues, preview), Email/query (inMailbox filter), Email/queryChanges | 8621 | ✅ |
| Email/set (create/update/destroy) — **create composes** RFC 5322 from `from`/`to`/`cc`/`subject`/`bodyValues`, keyword update (full + patch), destroy | 8621 | ✅ |
| Thread/get, Thread/changes | 8621 | ✅ (reference: single-message threads) |
| SearchSnippet/get (`<mark>` highlight over subject/preview) | 8621 §5 | ✅ |
| Identity/get, Identity/set, Identity/changes | 8621 §6 | ✅ (default identity from account) |
| EmailSubmission/set (create → accepted), EmailSubmission/get (state is the node's outbound machine → `notFound`) | 8621 §7 | ✅ |
| PushSubscription/get, PushSubscription/set (verificationCode) | 8620 §7.2 | ✅ (types + set/get; wire transport deferred) |
| Blob upload / download (blobId = content address, ties to MOTE id) | 8620 §6 | ✅ (functions) |
| Mailbox/changes, Email/changes, Thread/changes | 8620 §5.2 | ✅ real delta from the per-mailbox modseq + create-modseq + vanished-log change tracking (opaque state token); `cannotCalculateChanges` only on an unparseable token |
| back-references (`#` result refs, JSON-pointer `path` incl. `*`) | 8620 §3.7 | ✅ (e.g. `Email/query` → `Email/get` in one request) |
| Push: StateChange / EventSource / WebSocket | 8620 §7 | ⚠️ **types provided** (`StateChange`); HTTP push transport **deferred** (transport concern, like TLS) |

### Autodiscovery

| Document | RFC / schema | Status |
|----------|--------------|--------|
| SRV records `_imaps` / `_submissions` / `_pop3s` / `_jmap` (+ zone lines) | 6186 / 8314 / 8620 | ✅ |
| Thunderbird autoconfig XML (`clientConfig` v1.1) | Mozilla ISPDB | ✅ |
| Apple `.mobileconfig` profile (`com.apple.mail.managed`, deterministic UUIDs) | Apple config-profile | ✅ |
| Microsoft Autodiscover POX XML (Outlook) | MS-OXDSCLI | ✅ |
| Microsoft Autodiscover **v2** JSON (`autodiscover.json?Protocol=…`, incl. `AutodiscoverV1` redirect) | MS-OXDSCLI | ✅ |

¹ **TLS** is intentionally out of scope for this crate: the node terminates TLS (spec §8.2) and
hands the plaintext stream to these state machines, which advertise/ack STARTTLS·STLS and gate
cleartext auth behind it (LOGINDISABLED / `538` / `STLS`). Wiring a TLS library is a transport
concern for the node binary.

## Efficiency properties (hot paths)

The IMAP FETCH/SEARCH/STORE paths are built to stay proportional to the *answer*, not the mailbox:

- **Parse once, ever.** Each `Message` memoizes its MIME parse (`parsed_cached`, a `OnceCell`);
  ENVELOPE/BODYSTRUCTURE/SEARCH re-derivations across many requests never re-parse. A
  `FETCH (FLAGS UID)` or a flag-only SEARCH parses **no** bodies at all (lazy — the parse is only
  touched by items/keys that need it).
- **`O(log n)` UID lookup.** Messages are held UID-sorted; `index_of_uid` is a binary search and
  `resolve_targets` walks only the matched window, so a targeted `UID FETCH 5` over a 10k-message
  mailbox touches ~`log n` messages instead of scanning all `n` (regression-guarded by a timing
  test — see `tests/imap_session.rs::large_mailbox_targeted_fetch_is_sublinear`). `max_uid` is `O(1)`.
- **No needless copies.** `BODY[]` / `BODY[HEADER]` / `BODY[TEXT]` **borrow** the raw bytes
  (`Cow`), so a partial fetch `BODY[]<0.512>` on a 10 MB message copies only the 512-byte window,
  not the whole message. `BODY[HEADER.FIELDS (…)]` parses just the header block, not the MIME tree.
- **VANISHED is compact.** Expunged-UID lists collapse contiguous runs to `lo:hi`.
- **Incremental-friendly store.** The `MailStore` trait exposes references (not clones) and the
  JMAP change-log is derived from modseqs + a small vanished log, so a real indexed/encrypted
  backend can implement it without a second journal.

## Explicitly deferred (never silently dropped)

- IMAP exotic `message/rfc822` **envelope-in-BODYSTRUCTURE** (top-down part walk + `.MIME` are
  done; a nested-message BODYSTRUCTURE does not embed the inner ENVELOPE — niche). (SORT/THREAD,
  BINARY, SEARCHRES, CATENATE, LIST-EXTENDED/LIST-STATUS, QRESYNC VANISHED, SEARCH CHARSET are now
  **done**.)
- IMAP **COMPRESS=DEFLATE** (RFC 4978) — needs a real DEFLATE codec (a dependency); the framing is
  a transport concern, so it is left to the node binary rather than pulled into the std-only core.
- IMAP **CATENATE URL** across *other* servers (RFC 5092 URLFETCH) — same-node `UID=…[/;SECTION=…]`
  URLs resolve; a URL naming a different host is refused `[BADURL]` rather than fetched.
- SMTP **SCRAM/CRAM** SASL — only PLAIN/LOGIN are offered (channel is TLS-terminated on the node,
  so the extra challenge-response mechanisms add no confidentiality here); **BDAT/CHUNKING** (3030).
- JMAP **push transport** (StateChange/PushSubscription types + set/get exist; HTTP
  EventSource/WebSocket wiring is a transport concern like TLS).
- Real **TLS/crypto** (STARTTLS handshake) — see note ¹.
- **CalDAV/CardDAV** (spec §8.4) — a separate surface, not in this crate.

## Test & run

```sh
cargo test -p dmtap-mail                 # synchronous core: unit + integration tests
cargo test -p dmtap-mail --features net  # + the TCP literal-reader tests
cargo run  -p envoir-node -- serve-mail  # demo IMAP:1143 / POP3:1110 / Submission:1587
```

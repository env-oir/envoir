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
| LIST / LSUB, SPECIAL-USE, LIST-EXTENDED (return/select opts) | 9051 / 6154 / 5258 | ✅ (opts parsed) |
| STATUS (incl. SIZE, HIGHESTMODSEQ) | 9051 | ✅ |
| APPEND (+ flags/date/literal, APPENDUID) | 9051 / 4315 | ✅ |
| FETCH: FLAGS, UID, INTERNALDATE, RFC822.SIZE, ENVELOPE, BODY, BODYSTRUCTURE | 9051 | ✅ |
| FETCH BODY[…]/BODY.PEEK[…] sections + `<partial>` (HEADER/HEADER.FIELDS[.NOT]/TEXT/MIME/part) | 9051 | ✅ |
| FETCH RFC822 / RFC822.HEADER / RFC822.TEXT / MODSEQ | 9051 / 7162 | ✅ |
| SEARCH (flags, FROM/TO/CC/SUBJECT/BODY/TEXT/HEADER, dates, LARGER/SMALLER, UID/seq, NOT/OR, MODSEQ) | 9051 | ✅ |
| ESEARCH (RETURN MIN/MAX/COUNT/ALL) | 9051 / 4731 | ✅ |
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
| **QRESYNC full resync** (VANISHED, `(UIDVALIDITY … known-uids)`) | 7162 | ⚠️ **partial** — ENABLE + CHANGEDSINCE work; VANISHED/known-set resync **deferred** |
| **CHARSET conversion in SEARCH** | 9051 | ⚠️ parsed but only ASCII/UTF-8 substring matching |
| **Nested multipart part paths deeper than the MIME tree offsets** | 9051 | ✅ top-down walk; exotic message/rfc822 envelope-in-bodystructure **deferred** |
| **Real TLS** (STARTTLS crypto) | 9051 | ⛔ **deferred** — transport concern; state machine acks, node terminates TLS¹ |

### SMTP submission (RFC 6409)

| Capability | RFC | Status |
|-----------|-----|--------|
| EHLO/HELO, MAIL/RCPT/DATA, RSET/NOOP/VRFY/QUIT | 5321 / 6409 | ✅ |
| AUTH PLAIN/LOGIN (+ initial response) | 4954 | ✅ |
| STARTTLS (state ack) | 3207 | ✅ handshake note¹ |
| 8BITMIME | 6152 | ✅ advertised |
| SMTPUTF8 | 6531 | ✅ advertised |
| PIPELINING | 2920 | ✅ advertised |
| SIZE (advertised + enforced against MAIL SIZE=) | 1870 | ✅ |
| DSN (RET/NOTIFY/ENVID params) | 3461 | ⚠️ advertised + accepted; **no delivery-status generation** (submission-only) |
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
| Mailbox/get, Mailbox/query | 8621 | ✅ |
| Email/get (envelope fields, keywords, bodyValues, preview), Email/query (inMailbox filter) | 8621 | ✅ |
| Email/set (keyword update — full + patch form — and destroy) | 8621 | ✅ |
| Thread/get | 8621 | ✅ (reference: single-message threads) |
| EmailSubmission/set (create → accepted; send is the node's MOTE path) | 8621 | ✅ |
| Blob upload / download (blobId = content address, ties to MOTE id) | 8620 §6 | ✅ (functions) |
| Mailbox/changes, Email/changes | 8620 §5.2 | ⚠️ **stub** — reports `cannotCalculateChanges` (no durable change log yet); clients fall back to full query+get |
| Email/set **create** (compose a new Email object) | 8621 | ⛔ **deferred** (update/destroy done; MIME-compose-from-JMAP not yet) |
| Push: StateChange / EventSource / WebSocket | 8620 §7 | ⚠️ **types provided** (`StateChange`); HTTP push transport **deferred** |
| back-references (`#` result refs), method-level `createdIds` chaining | 8620 §3.7 | ⛔ **deferred** |

### Autodiscovery

| Document | RFC / schema | Status |
|----------|--------------|--------|
| SRV records `_imaps` / `_submissions` / `_pop3s` / `_jmap` (+ zone lines) | 6186 / 8314 / 8620 | ✅ |
| Thunderbird autoconfig XML (`clientConfig` v1.1) | Mozilla ISPDB | ✅ |
| Apple `.mobileconfig` profile (`com.apple.mail.managed`, deterministic UUIDs) | Apple config-profile | ✅ |
| Microsoft Autodiscover POX XML | MS-OXDSCLI | ✅ |

¹ **TLS** is intentionally out of scope for this crate: the node terminates TLS (spec §8.2) and
hands the plaintext stream to these state machines, which advertise/ack STARTTLS·STLS and gate
cleartext auth behind it (LOGINDISABLED / `538` / `STLS`). Wiring a TLS library is a transport
concern for the node binary.

## Explicitly deferred (never silently dropped)

- IMAP **QRESYNC** VANISHED / known-UID resynchronization (CONDSTORE + CHANGEDSINCE are done).
- IMAP **SEARCH CHARSET** transcoding beyond ASCII/UTF-8 substring; server-side threading (THREAD).
- JMAP **/changes** durable change log, **Email/set create** (compose), **push transport**, and
  request **back-references**.
- SMTP **DSN status generation** (submission accepts DSN params but does not emit reports).
- Real **TLS/crypto** (STARTTLS handshake) — see note ¹.
- **CalDAV/CardDAV** (spec §8.4) — a separate surface, not in this crate.

## Test & run

```sh
cargo test -p dmtap-mail                 # synchronous core: unit + integration tests
cargo test -p dmtap-mail --features net  # + the TCP literal-reader tests
cargo run  -p envoir-node -- serve-mail  # demo IMAP:1143 / POP3:1110 / Submission:1587
```

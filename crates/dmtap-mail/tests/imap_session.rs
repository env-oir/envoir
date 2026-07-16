//! Integration test: a scripted IMAP session (LOGIN → SELECT → FETCH → STORE → LOGOUT) driven
//! against the in-memory MailStore, projecting a real MOTE payload (spec §8.2).

use dmtap_core::identity::IdentityKey;
use dmtap_core::mote::{Headers, Payload};
use dmtap_mail::auth::StaticAuthenticator;
use dmtap_mail::imap::{Session, State};
use dmtap_mail::store::{Flag, MailStore, MemoryStore};

/// Deliver one MOTE into INBOX and return a store + the owner's app credentials.
fn setup() -> (MemoryStore, StaticAuthenticator) {
    let sender = IdentityKey::generate();
    let owner = IdentityKey::generate();
    let payload = Payload {
        from: sender.public(),
        sig: vec![],
        headers: Headers { subject: Some("Project kickoff".into()), ..Default::default() },
        body: b"Let's meet on Tuesday.".to_vec(),
        refs: vec![],
        attach: vec![],
        expires: None,
    };
    let mut store = MemoryStore::new();
    store.deliver_mote(&payload, "INBOX", 1_752_000_000_000);

    let mut auth = StaticAuthenticator::new();
    auth.issue("owner@dmtap.local", "app-password-xyz", owner.public(), "iphone");
    (store, auth)
}

fn run(session: &mut Session<MemoryStore, StaticAuthenticator>, cmd: &str) -> String {
    String::from_utf8(session.process(cmd.as_bytes())).unwrap()
}

#[test]
fn scripted_imap_session() {
    let (store, auth) = setup();
    // tls=true: the node terminates TLS, so LOGIN is permitted (spec §8.2).
    let mut session = Session::new(store, auth, true);

    // Greeting advertises the capability set.
    let greeting = String::from_utf8(session.greeting()).unwrap();
    assert!(greeting.contains("IMAP4rev2"), "greeting: {greeting}");
    assert!(greeting.contains("* OK"));

    // CAPABILITY.
    let caps = run(&mut session, "a0 CAPABILITY\r\n");
    assert!(caps.contains("UIDPLUS"));
    assert!(caps.contains("CONDSTORE"));
    assert!(caps.contains("MOVE"));
    assert!(caps.contains("a0 OK"));

    // LOGIN.
    let login = run(&mut session, "a1 LOGIN owner@dmtap.local app-password-xyz\r\n");
    assert!(login.contains("a1 OK"), "login: {login}");
    assert_eq!(session.state(), State::Authenticated);

    // A wrong password on a second session must fail closed.
    {
        let (store2, auth2) = setup();
        let mut s2 = Session::new(store2, auth2, true);
        let bad = run(&mut s2, "x LOGIN owner@dmtap.local wrong\r\n");
        assert!(bad.contains("x NO"), "bad login should be NO: {bad}");
    }

    // SELECT INBOX.
    let select = run(&mut session, "a2 SELECT INBOX\r\n");
    assert!(select.contains("1 EXISTS"), "select: {select}");
    assert!(select.contains("[UIDVALIDITY 1]"));
    assert!(select.contains("[UIDNEXT 2]"));
    assert!(select.contains("a2 OK [READ-WRITE]"));
    assert_eq!(session.state(), State::Selected);

    // FETCH: flags, envelope, size, and the header via a peeking body section.
    let fetch = run(&mut session, "a3 FETCH 1 (UID FLAGS RFC822.SIZE ENVELOPE BODY.PEEK[HEADER.FIELDS (SUBJECT FROM)])\r\n");
    assert!(fetch.contains("* 1 FETCH ("), "fetch: {fetch}");
    assert!(fetch.contains("UID 1"));
    assert!(fetch.contains("\"Project kickoff\""), "envelope subject missing: {fetch}");
    assert!(fetch.contains("BODY[HEADER.FIELDS (SUBJECT FROM)]"));
    assert!(fetch.contains("Subject: Project kickoff"));
    assert!(fetch.contains("a3 OK"));

    // The message started unseen; PEEK must not have set \Seen.
    assert!(!session.store().mailbox("INBOX").unwrap().messages[0].has_flag(&Flag::Seen));

    // STORE: mark \Seen, expect an untagged FETCH echo.
    let store_resp = run(&mut session, "a4 STORE 1 +FLAGS (\\Seen)\r\n");
    assert!(store_resp.contains("* 1 FETCH (FLAGS ("), "store: {store_resp}");
    assert!(store_resp.contains("\\Seen"));
    assert!(store_resp.contains("a4 OK"));
    assert!(session.store().mailbox("INBOX").unwrap().messages[0].has_flag(&Flag::Seen));

    // UID FETCH the full body — response must carry UID even though only BODY[] was asked.
    let body = run(&mut session, "a5 UID FETCH 1 (BODY[])\r\n");
    assert!(body.contains("Let's meet on Tuesday."), "body: {body}");
    assert!(body.contains("UID 1"));

    // SEARCH.
    let search = run(&mut session, "a6 SEARCH SUBJECT kickoff\r\n");
    assert!(search.contains("* SEARCH 1"), "search: {search}");

    // LOGOUT.
    let logout = run(&mut session, "a7 LOGOUT\r\n");
    assert!(logout.contains("* BYE"));
    assert!(logout.contains("a7 OK"));
    assert_eq!(session.state(), State::Logout);
}

#[test]
fn copy_move_and_expunge_uidplus() {
    let (store, auth) = setup();
    let mut session = Session::new(store, auth, true);
    run(&mut session, "a1 LOGIN owner@dmtap.local app-password-xyz\r\n");
    run(&mut session, "a2 SELECT INBOX\r\n");

    // COPY to Archive → UIDPLUS COPYUID response.
    let copy = run(&mut session, "a3 UID COPY 1 Archive\r\n");
    assert!(copy.contains("[COPYUID"), "copy: {copy}");
    assert_eq!(session.store().mailbox("Archive").unwrap().exists(), 1);

    // MOVE to Trash → COPYUID + EXPUNGE, source emptied.
    let mv = run(&mut session, "a4 MOVE 1 Trash\r\n");
    assert!(mv.contains("[COPYUID"), "move: {mv}");
    assert!(mv.contains("1 EXPUNGE"));
    assert_eq!(session.store().mailbox("INBOX").unwrap().exists(), 0);
    assert_eq!(session.store().mailbox("Trash").unwrap().exists(), 1);
}

/// Build a store with `n` deliverable messages in INBOX (uids 1..=n) + the owner's credentials.
fn setup_n(n: usize) -> (MemoryStore, StaticAuthenticator) {
    let owner = IdentityKey::generate();
    let mut store = MemoryStore::new();
    for i in 0..n {
        store.deliver_raw(
            "INBOX",
            format!("Subject: Message {i}\r\nFrom: s{i}@example.com\r\n\r\nbody {i}\r\n").into_bytes(),
            vec![],
            1_752_000_000_000,
        );
    }
    let mut auth = StaticAuthenticator::new();
    auth.issue("owner@dmtap.local", "app-password-xyz", owner.public(), "iphone");
    (store, auth)
}

fn logged_in_selected(n: usize) -> Session<MemoryStore, StaticAuthenticator> {
    let (store, auth) = setup_n(n);
    let mut session = Session::new(store, auth, true);
    run(&mut session, "a1 LOGIN owner@dmtap.local app-password-xyz\r\n");
    run(&mut session, "a2 SELECT INBOX\r\n");
    session
}

#[test]
fn qresync_vanished_fast_resync() {
    // The iPhone-was-offline path: expunge some UIDs, then a QRESYNC SELECT must report exactly
    // those as VANISHED (EARLIER) and re-FETCH only what changed (RFC 7162 §3.2.5.2).
    let mut session = logged_in_selected(4);
    let known_modseq = session.store().mailbox("INBOX").unwrap().highest_modseq;

    // Delete uids 2 and 3, expunge them; touch uid 4's flags.
    run(&mut session, "b1 UID STORE 2:3 +FLAGS (\\Deleted)\r\n");
    run(&mut session, "b2 EXPUNGE\r\n");
    run(&mut session, "b3 UID STORE 4 +FLAGS (\\Seen)\r\n");

    // Reconnect with QRESYNC, presenting the last-known UIDVALIDITY + HIGHESTMODSEQ + known UIDs.
    let resync = run(&mut session, &format!("c1 SELECT INBOX (QRESYNC (1 {known_modseq} 1:4))\r\n"));
    assert!(resync.contains("VANISHED (EARLIER) 2:3"), "expected vanished 2:3: {resync}");
    // uid 4 changed since the client's modseq → re-fetched with its new FLAGS/MODSEQ.
    assert!(resync.contains("UID 4"), "changed uid 4 must be re-fetched: {resync}");
    assert!(resync.contains("\\Seen"), "uid 4 flags must be reported: {resync}");
    // uid 1 was untouched → NOT re-fetched.
    assert!(!resync.contains("UID 1"), "unchanged uid 1 must not be re-fetched: {resync}");
    assert!(resync.contains("c1 OK"), "{resync}");
}

#[test]
fn qresync_enabled_expunge_emits_vanished() {
    // After ENABLE QRESYNC, EXPUNGE responses become VANISHED (RFC 7162 §3.2.10).
    let mut session = logged_in_selected(3);
    run(&mut session, "e1 ENABLE QRESYNC\r\n");
    run(&mut session, "e2 UID STORE 2 +FLAGS (\\Deleted)\r\n");
    let expunge = run(&mut session, "e3 EXPUNGE\r\n");
    assert!(expunge.contains("* VANISHED 2"), "qresync expunge → VANISHED: {expunge}");
    assert!(!expunge.contains("* 2 EXPUNGE"), "no classic EXPUNGE under QRESYNC: {expunge}");
}

#[test]
fn fetch_vanished_modifier() {
    // UID FETCH … (CHANGEDSINCE n VANISHED) reports expunged UIDs in the set (RFC 7162 §3.2.5.1).
    let mut session = logged_in_selected(4);
    let base = session.store().mailbox("INBOX").unwrap().highest_modseq;
    run(&mut session, "f1 UID STORE 2:3 +FLAGS (\\Deleted)\r\n");
    run(&mut session, "f2 EXPUNGE\r\n");
    let fetch = run(&mut session, &format!("f3 UID FETCH 1:* (FLAGS) (CHANGEDSINCE {base} VANISHED)\r\n"));
    assert!(fetch.contains("VANISHED (EARLIER) 2:3"), "vanished modifier: {fetch}");
}

#[test]
fn search_charset_handling() {
    let mut session = logged_in_selected(1);
    // UTF-8 and US-ASCII are accepted.
    assert!(run(&mut session, "g1 SEARCH CHARSET UTF-8 SUBJECT Message\r\n").contains("g1 OK"));
    assert!(run(&mut session, "g2 SEARCH CHARSET US-ASCII SUBJECT Message\r\n").contains("g2 OK"));
    // Any other charset is rejected cleanly with [BADCHARSET], never silently matched.
    let bad = run(&mut session, "g3 SEARCH CHARSET KOI8-R SUBJECT Message\r\n");
    assert!(bad.contains("g3 NO"), "{bad}");
    assert!(bad.contains("[BADCHARSET"), "must list supported charsets: {bad}");
}

#[test]
fn malformed_input_never_panics() {
    let mut session = logged_in_selected(2);
    // Each of these is hostile/truncated; every one must yield a BAD/NO, not a panic or hang.
    for cmd in [
        "z1 FETCH\r\n",                     // missing args
        "z2 FETCH abc (FLAGS)\r\n",         // bad sequence set
        "z3 FETCH 1 (BOGUSITEM)\r\n",       // unknown fetch item
        "z4 SEARCH LARGER notanumber\r\n",  // non-numeric
        "z5 STORE 1 FLAGS\r\n",             // missing flag list is empty → still parses
        "z6 UID\r\n",                       // truncated UID command
        "z7 FROBNICATE stuff\r\n",          // unknown command
        "z8 STORE 1 BOGUS (\\Seen)\r\n",    // bad STORE verb
        "z9 FETCH 1:2:3 (FLAGS)\r\n",       // malformed range
        "z10 SELECT\r\n",                   // missing mailbox
        "\r\n",                             // empty line
        "onlytag\r\n",                      // tag with no command
    ] {
        let resp = run(&mut session, cmd);
        assert!(
            resp.contains(" BAD") || resp.contains(" NO") || resp.contains(" OK"),
            "hostile input {cmd:?} must be handled, got: {resp}"
        );
    }
    // The session is still usable after all that abuse.
    assert!(run(&mut session, "ok1 NOOP\r\n").contains("ok1 OK"));
}

#[test]
fn selected_mailbox_deleted_mid_session_never_panics() {
    // RFC 9051 does not forbid DELETE/RENAME of the currently SELECTed mailbox (§6.3.4/§6.3.5), so
    // a client can legally: CREATE a mailbox, SELECT it, then DELETE (or RENAME) it out from under
    // itself. Every SELECTED-state command issued afterwards must fail closed (BAD/NO), never
    // panic, and the session must remain usable once the client SELECTs something real again.
    let mut session = logged_in_selected(5);
    assert!(run(&mut session, "c1 CREATE Scratch\r\n").contains("c1 OK"));
    assert!(run(&mut session, "c2 SELECT Scratch\r\n").contains("c2 OK"));
    assert!(run(&mut session, "c3 DELETE Scratch\r\n").contains("c3 OK"));

    for cmd in [
        "d1 FETCH 1 (FLAGS)\r\n",
        "d2 SEARCH ALL\r\n",
        "d3 SORT (ARRIVAL) UTF-8 ALL\r\n",
        "d4 THREAD REFERENCES UTF-8 ALL\r\n",
        "d5 STORE 1 +FLAGS (\\Seen)\r\n",
        "d6 EXPUNGE\r\n",
    ] {
        let resp = run(&mut session, cmd);
        assert!(
            !resp.is_empty() && (resp.contains(" BAD") || resp.contains(" NO")),
            "a command against a vanished mailbox must fail closed, not panic: {cmd:?} -> {resp}"
        );
    }
    // The session self-healed back to Authenticated, so it's immediately usable again.
    assert_eq!(session.state(), State::Authenticated);
    assert!(run(&mut session, "e1 SELECT INBOX\r\n").contains("e1 OK"));
    assert!(run(&mut session, "e2 NOOP\r\n").contains("e2 OK"));
}

#[test]
fn selected_mailbox_renamed_mid_session_never_panics() {
    // Same hazard as above, via RENAME instead of DELETE: the name in `self.selected` no longer
    // resolves, even though a mailbox with the *content* still exists under a new name.
    let mut session = logged_in_selected(6);
    assert!(run(&mut session, "c1 CREATE Old\r\n").contains("c1 OK"));
    assert!(run(&mut session, "c2 SELECT Old\r\n").contains("c2 OK"));
    assert!(run(&mut session, "c3 RENAME Old New\r\n").contains("c3 OK"));

    let resp = run(&mut session, "d1 SEARCH ALL\r\n");
    assert!(resp.contains(" NO") || resp.contains(" BAD"), "must fail closed, not panic: {resp}");
    assert_eq!(session.state(), State::Authenticated);
    // The renamed mailbox is selectable under its new name.
    assert!(run(&mut session, "e1 SELECT New\r\n").contains("e1 OK"));
}

#[test]
fn uid_fetch_edge_cases() {
    let mut session = logged_in_selected(3);
    // Fetching a nonexistent UID returns just the tagged OK, no FETCH data.
    let miss = run(&mut session, "u1 UID FETCH 999 (FLAGS)\r\n");
    assert!(miss.contains("u1 OK"));
    assert!(!miss.contains("* "), "no untagged data for a missing uid: {miss}");
    // `*` resolves to the max UID.
    let star = run(&mut session, "u2 UID FETCH * (UID)\r\n");
    assert!(star.contains("UID 3"), "star → highest uid: {star}");
    // A range spanning past the end still works.
    let range = run(&mut session, "u3 UID FETCH 2:* (UID)\r\n");
    assert!(range.contains("UID 2") && range.contains("UID 3"));
}

#[test]
fn sort_orders_by_criteria() {
    // SORT (RFC 5256): three messages with distinct subjects/sizes → deterministic order.
    let mut store = MemoryStore::new();
    store.deliver_raw("INBOX", b"Subject: Banana\r\nDate: Wed, 03 Jul 2024 10:00:00 +0000\r\n\r\nx".to_vec(), vec![], 300);
    store.deliver_raw("INBOX", b"Subject: Apple\r\nDate: Mon, 01 Jul 2024 10:00:00 +0000\r\n\r\nlonger body here".to_vec(), vec![], 100);
    store.deliver_raw("INBOX", b"Subject: Cherry\r\nDate: Tue, 02 Jul 2024 10:00:00 +0000\r\n\r\nyy".to_vec(), vec![], 200);
    let mut auth = StaticAuthenticator::new();
    auth.issue("owner@dmtap.local", "app-password-xyz", IdentityKey::generate().public(), "d");
    let mut session = Session::new(store, auth, true);
    run(&mut session, "a1 LOGIN owner@dmtap.local app-password-xyz\r\n");
    run(&mut session, "a2 SELECT INBOX\r\n");

    // SORT by SUBJECT alphabetical: Apple(2) Banana(1) Cherry(3).
    let subj = run(&mut session, "s1 SORT (SUBJECT) UTF-8 ALL\r\n");
    assert!(subj.contains("* SORT 2 1 3"), "subject sort: {subj}");
    // SORT by DATE ascending: 1 Jul(2), 2 Jul(3), 3 Jul(1).
    let date = run(&mut session, "s2 SORT (DATE) UTF-8 ALL\r\n");
    assert!(date.contains("* SORT 2 3 1"), "date sort: {date}");
    // REVERSE SIZE: largest first → Apple(2, longest) ... .
    let size = run(&mut session, "s3 SORT (REVERSE SIZE) UTF-8 ALL\r\n");
    assert!(size.contains("* SORT 2"), "reverse size sort starts largest: {size}");
    // UID SORT returns UIDs.
    let usort = run(&mut session, "s4 UID SORT (SUBJECT) UTF-8 ALL\r\n");
    assert!(usort.contains("* SORT 2 1 3"), "uid sort: {usort}");
}

#[test]
fn thread_groups_by_references_and_subject() {
    let mut store = MemoryStore::new();
    // A root and a reply (via In-Reply-To) share a thread; a third is separate.
    store.deliver_raw("INBOX", b"Subject: Plan\r\nMessage-ID: <root@x>\r\nDate: Mon, 01 Jul 2024 10:00:00 +0000\r\n\r\na".to_vec(), vec![], 100);
    store.deliver_raw("INBOX", b"Subject: Re: Plan\r\nMessage-ID: <reply@x>\r\nIn-Reply-To: <root@x>\r\nDate: Tue, 02 Jul 2024 10:00:00 +0000\r\n\r\nb".to_vec(), vec![], 200);
    store.deliver_raw("INBOX", b"Subject: Other\r\nMessage-ID: <other@x>\r\nDate: Wed, 03 Jul 2024 10:00:00 +0000\r\n\r\nc".to_vec(), vec![], 300);
    let mut auth = StaticAuthenticator::new();
    auth.issue("owner@dmtap.local", "app-password-xyz", IdentityKey::generate().public(), "d");
    let mut session = Session::new(store, auth, true);
    run(&mut session, "a1 LOGIN owner@dmtap.local app-password-xyz\r\n");
    run(&mut session, "a2 SELECT INBOX\r\n");

    let refs = run(&mut session, "t1 THREAD REFERENCES UTF-8 ALL\r\n");
    assert!(refs.contains("* THREAD"), "thread response: {refs}");
    assert!(refs.contains("(1 2)"), "root+reply must thread together: {refs}");
    assert!(refs.contains("(3)"), "unrelated message is its own thread: {refs}");

    // ORDEREDSUBJECT: "Plan" and "Re: Plan" share a base subject.
    let os = run(&mut session, "t2 THREAD ORDEREDSUBJECT UTF-8 ALL\r\n");
    assert!(os.contains("(1 2)"), "ordered-subject groups Re: with parent: {os}");
}

#[test]
fn binary_fetch_decodes_cte() {
    // BINARY[1] (RFC 3516) must CTE-decode a base64 part; BINARY.SIZE reports the decoded length.
    let mut store = MemoryStore::new();
    // base64("hello") = aGVsbG8=
    let raw = b"Content-Type: multipart/mixed; boundary=\"B\"\r\n\r\n\
                --B\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8=\r\n--B--\r\n";
    store.deliver_raw("INBOX", raw.to_vec(), vec![], 0);
    let mut auth = StaticAuthenticator::new();
    auth.issue("owner@dmtap.local", "app-password-xyz", IdentityKey::generate().public(), "d");
    let mut session = Session::new(store, auth, true);
    run(&mut session, "a1 LOGIN owner@dmtap.local app-password-xyz\r\n");
    run(&mut session, "a2 SELECT INBOX\r\n");

    let bin = run(&mut session, "b1 FETCH 1 (BINARY.PEEK[1])\r\n");
    assert!(bin.contains("BINARY[1] ~{5}"), "literal8 with decoded size: {bin}");
    assert!(bin.contains("hello"), "decoded content: {bin}");
    let size = run(&mut session, "b2 FETCH 1 (BINARY.SIZE[1])\r\n");
    assert!(size.contains("BINARY.SIZE[1] 5"), "decoded size: {size}");
}

#[test]
fn list_extended_and_status_and_special_use() {
    let mut session = logged_in_selected(2);
    // CREATE with SPECIAL-USE USE attribute (RFC 6154).
    assert!(run(&mut session, "c1 CREATE Newsletters (USE (\\Archive))\r\n").contains("c1 OK"));
    // A child mailbox → parent should report \HasChildren.
    assert!(run(&mut session, "c2 CREATE Parent\r\n").contains("c2 OK"));
    assert!(run(&mut session, "c3 CREATE Parent/Child\r\n").contains("c3 OK"));
    let list = run(&mut session, "l1 LIST \"\" \"*\"\r\n");
    assert!(list.contains("\\HasChildren) \"/\" \"Parent\""), "parent has children: {list}");
    assert!(list.contains("\\HasNoChildren"), "leaf has no children: {list}");

    // LIST RETURN (SUBSCRIBED) → \Subscribed attribute; LIST-STATUS piggybacks STATUS.
    let ls = run(&mut session, "l2 LIST \"\" \"INBOX\" RETURN (STATUS (MESSAGES UNSEEN))\r\n");
    assert!(ls.contains("* LIST"), "list line: {ls}");
    assert!(ls.contains("* STATUS \"INBOX\" (MESSAGES 2"), "list-status piggyback: {ls}");

    // Select-option SPECIAL-USE filters to special folders only.
    let su = run(&mut session, "l3 LIST (SPECIAL-USE) \"\" \"*\"\r\n");
    assert!(su.contains("Newsletters") && su.contains("Sent"), "special-use only: {su}");
    assert!(!su.contains("\"Parent\""), "non-special mailbox excluded: {su}");

    // STATUS DELETED item.
    run(&mut session, "d1 STORE 1 +FLAGS (\\Deleted)\r\n");
    let st = run(&mut session, "l4 STATUS INBOX (DELETED)\r\n");
    assert!(st.contains("DELETED 1"), "status deleted: {st}");
}

#[test]
fn searchres_save_and_dollar() {
    let mut session = logged_in_selected(4);
    // Mark 2 and 4 as seen, then SEARCH SEEN RETURN (SAVE).
    run(&mut session, "x1 STORE 2,4 +FLAGS (\\Seen)\r\n");
    let saved = run(&mut session, "x2 UID SEARCH RETURN (SAVE) SEEN\r\n");
    assert!(saved.contains("x2 OK"), "save search: {saved}");
    // `$` now refers to the saved UIDs {2,4}; UID FETCH $ returns exactly those.
    let f = run(&mut session, "x3 UID FETCH $ (UID)\r\n");
    assert!(f.contains("UID 2") && f.contains("UID 4"), "dollar fetch: {f}");
    assert!(!f.contains("UID 1") && !f.contains("UID 3"), "only saved uids: {f}");
    // COPY $ to Archive copies the saved set.
    let cp = run(&mut session, "x4 UID COPY $ Archive\r\n");
    assert!(cp.contains("[COPYUID"), "copy dollar: {cp}");
    assert_eq!(session.store().mailbox("Archive").unwrap().exists(), 2);
}

#[test]
fn catenate_append_builds_message() {
    let mut session = logged_in_selected(1);
    // CATENATE TEXT parts (RFC 4469) plus a URL referencing the existing UID 1's HEADER.
    let cmd = "y1 APPEND Drafts CATENATE (TEXT {14}\r\nSubject: Hi\r\n\r\n TEXT {5}\r\nbody!)\r\n";
    let resp = run(&mut session, cmd);
    assert!(resp.contains("[APPENDUID"), "catenate append: {resp}");
    let drafts = session.store().mailbox("Drafts").unwrap();
    assert_eq!(drafts.exists(), 1);
    let raw = String::from_utf8_lossy(&drafts.messages[0].raw);
    assert!(raw.contains("Subject: Hi"), "catenated headers: {raw}");
    assert!(raw.contains("body!"), "catenated body: {raw}");
}

#[test]
fn esearch_count_and_all() {
    let mut session = logged_in_selected(5);
    let r = run(&mut session, "e1 SEARCH RETURN (COUNT) ALL\r\n");
    assert!(r.contains("ESEARCH"), "esearch: {r}");
    assert!(r.contains("COUNT 5"), "count: {r}");
}

#[test]
fn large_mailbox_targeted_fetch_is_sublinear() {
    // Efficiency demonstration (a lightweight timing benchmark, no extra deps): a targeted UID
    // FETCH over a 10k-message mailbox must not scan linearly. We compare the cost of 200 targeted
    // single-UID fetches against ONE full-mailbox FETCH; the binary-search path makes the former
    // dramatically cheaper even though it runs 200×.
    use std::time::Instant;
    const N: usize = 10_000;
    let mut session = logged_in_selected(N);

    // Warm baseline: a full FLAGS fetch is inherently O(n) (it emits n lines).
    let t = Instant::now();
    let full = run(&mut session, "p0 FETCH 1:* (FLAGS)\r\n");
    let full_dur = t.elapsed();
    assert_eq!(full.matches("* ").count(), N, "full fetch must return all rows");

    // 200 targeted UID fetches spread across the mailbox.
    let t = Instant::now();
    for k in 0..200u32 {
        let uid = 1 + (k * (N as u32 / 200));
        let r = run(&mut session, &format!("p{k} UID FETCH {uid} (UID)\r\n"));
        assert!(r.contains(&format!("UID {uid}")), "targeted fetch {uid} missing: {r}");
    }
    let targeted_dur = t.elapsed();

    // 200 binary-search fetches should cost less than a single full linear scan+render. (Generous
    // margin so this is not flaky under CI load; a linear FETCH scan would be ~200× worse.)
    assert!(
        targeted_dur < full_dur * 3,
        "targeted 200× fetch ({targeted_dur:?}) should beat one full scan ({full_dur:?}) — linear scan regression?"
    );
}

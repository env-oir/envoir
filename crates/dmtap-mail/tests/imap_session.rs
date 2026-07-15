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

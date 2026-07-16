//! KT-verified `name → identity` resolution, wired end-to-end into a real `dmtap-core` capability
//! delegation (spec §3, §3.5, §13.5) — proving the resolved, KT-attested key is not just a passive
//! "this name maps to this bag of bytes" pointer but a **real signing key** other parts of the
//! system can build on.
//!
//! `dmtap-naming`'s own crate tests already cover the resolution algorithm exhaustively (happy
//! path, quorum, staleness, DNS/Identity mismatch, unreachable-KT-blocks). What this integration
//! test adds is the cross-crate composition the resolver exists to serve: resolve a name, verify
//! its KT inclusion proof, reject a log that forges one — and then hand the resolved key straight
//! into `dmtap-core::capability`, minting and verifying a real delegation token issued *by* the
//! identity that resolution just KT-attested.

use dmtap_core::capability::{Capability, CapabilityToken};
use dmtap_core::id::ContentId;
use dmtap_core::identity::{Identity, IdentityKey, KeyPackageBundleRef};
use dmtap_core::TimestampMs;

use dmtap_naming::error::ResolveError;
use dmtap_naming::kt::{InMemoryKtLog, KtLog, KtProof};
use dmtap_naming::{DmtapTxtRecord, InMemoryResolver, Resolver};

const NOW: TimestampMs = 1_752_600_000_000;
const NAME: &str = "alice@example.org";

/// Build a real signed `Identity` for `NAME` plus the `_dmtap` TXT record pointing at it (mirrors
/// `dmtap-naming`'s own `resolver::tests::make_identity` fixture shape).
fn make_identity(seed: u8) -> (IdentityKey, Identity, String) {
    let ik = IdentityKey::from_seed(&[seed; 32]);
    let identity = Identity::create_classical(
        &ik,
        0,
        vec![],
        KeyPackageBundleRef::new("/mesh/kp/alice", ContentId::of(b"kp-alice")),
        ContentId::of(b"recovery-policy"),
        vec![NAME.to_owned()],
        None,
        NOW,
    );
    let txt = DmtapTxtRecord {
        version: "dmtap1".into(),
        suite: 1,
        ik: ik.public(),
        id: identity.content_id(),
        kt: vec!["https://kt.example.org/log".into()],
        keypkgs: "/mesh/kp/alice".into(),
    }
    .to_txt();
    (ik, identity, txt)
}

/// A `KtLog` that wraps a real, honestly-answering [`InMemoryKtLog`] but forges the proof's
/// committed `leaf_hash` — modeling a compromised/malicious log (or a MITM between resolver and
/// log) that tries to attest a binding the tree never actually indexed. The STH itself (and its
/// signature) is left untouched: the forgery must be caught by the **leaf-hash-vs-recomputed**
/// check (§18.4.9), not by an STH-signature failure — the honest, most dangerous forgery shape.
struct ForgingLog {
    inner: InMemoryKtLog,
}

impl KtLog for ForgingLog {
    fn log_id(&self) -> Vec<u8> {
        self.inner.log_id()
    }

    fn prove(&self, leaf: &ContentId) -> Option<KtProof> {
        let mut att = self.inner.prove(leaf)?;
        let mut forged = att.proof.leaf_hash.as_bytes().to_vec();
        let last = forged.len() - 1;
        forged[last] ^= 0xff; // claim a binding the log never actually committed to
        att.proof.leaf_hash = ContentId(forged);
        Some(att)
    }
}

#[test]
fn kt_verified_resolution_mints_a_real_capability_token() {
    let (alice_ik, identity, txt) = make_identity(0x51);

    let mut log = InMemoryKtLog::new(IdentityKey::from_seed(&[0x99; 32]));
    log.append_identity(NAME, &identity).expect("classical ik present");

    let mut resolver = InMemoryResolver::new(NOW);
    resolver.set_txt("alice._dmtap.example.org", &txt);
    resolver.publish_identity(identity.clone());
    resolver.pin_log(log);

    // 1. Resolve: DNS parse → Identity fetch/verify → DNS⇄Identity cross-check → KT inclusion
    //    verified against the pinned log's signed tree head (§3.3, §3.5).
    let resolved = resolver.resolve(NAME).expect("KT-verified resolution succeeds");
    assert_eq!(resolved.name, NAME);
    assert_eq!(resolved.ik, alice_ik.public(), "resolution pins the real identity key");
    assert_eq!(resolved.identity_id, identity.content_id());
    assert_eq!(resolved.attested_by.len(), 1, "one log attested the binding");
    assert!(!resolved.oob_verified, "first contact is a TOFU pin (§3.4), not yet OOB-verified");

    // 2. Cross-crate proof this is a REAL usable key, not just a resolved pointer: mint a real
    //    dmtap-core capability delegation FROM the resolved identity TO a third party, using the
    //    same private key `alice_ik` that resolution just KT-attested the public half of.
    let bob = IdentityKey::from_seed(&[0x52; 32]);
    let token = CapabilityToken::issue(
        &alice_ik,
        bob.public(),
        vec![Capability {
            resource: "mailbox:inbox".into(),
            ability: "read".into(),
            caveats: None,
        }],
        NOW,
        NOW + 3_600_000,
        b"resolved-then-delegated".to_vec(),
        None,
    );
    assert_eq!(token.iss, resolved.ik, "the token's issuer IS the KT-resolved key");
    assert!(token.verify().is_ok(), "a real, independently-verifiable delegation");

    // A tampered token (e.g. a widened `exp`) still fails signature verification — the resolved
    // key's authority doesn't make forged extensions of it valid.
    let mut widened = token.clone();
    widened.exp += 1_000_000;
    assert!(widened.verify().is_err(), "widening a signed field breaks the signature");
}

#[test]
fn forged_inclusion_proof_is_rejected_fail_closed() {
    let (_alice_ik, identity, txt) = make_identity(0x53);

    let mut inner = InMemoryKtLog::new(IdentityKey::from_seed(&[0x9a; 32]));
    inner.append_identity(NAME, &identity).expect("classical ik present");

    let mut resolver = InMemoryResolver::new(NOW);
    resolver.set_txt("alice._dmtap.example.org", &txt);
    resolver.publish_identity(identity);
    resolver.pin_log(ForgingLog { inner });

    // The forged leaf hash no longer matches what §18.4.9 recomputes from the resolved Identity —
    // resolution MUST fail closed, never accept a binding the log didn't actually attest to.
    assert_eq!(
        resolver.resolve(NAME),
        Err(ResolveError::KtLeafHashMismatch),
        "a forged inclusion proof must be rejected, not silently accepted or downgraded"
    );
}

#[test]
fn unreachable_kt_never_falls_back_to_an_unverified_pin() {
    // Same real Identity/DNS setup, but no log is pinned at all — the "network partition at first
    // contact" case (§3.3). There is deliberately no code path here that TOFU-pins instead.
    let (_alice_ik, identity, txt) = make_identity(0x54);
    let mut resolver = InMemoryResolver::new(NOW);
    resolver.set_txt("alice._dmtap.example.org", &txt);
    resolver.publish_identity(identity);

    assert_eq!(resolver.resolve(NAME), Err(ResolveError::KtUnreachable));
}

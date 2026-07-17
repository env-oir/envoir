//! The `name → key` resolver — spec §3.3.
//!
//! Ties the pieces together into the §3.3 resolution algorithm, fail-closed at every step:
//!
//! ```text
//! resolve(name):
//!   1. DNS TXT lookup            → { ik, id, kt, keypkgs }      (dns.rs)
//!   2. fetch full Identity by id → verify sig chain             (dmtap-core::identity)
//!   3. cross-check DNS ⇄ Identity (ik/id must match)            (kt::check_dns_matches_identity)
//!   4. KT-verify the binding (§3.5): single-log (v0) or         (kt::verify_attestation / verify_quorum)
//!      > n/2 quorum (v1); unreachable KT ⇒ BLOCK, never TOFU
//!   5. PIN (name → ik, id) as an unverified (TOFU) pin          (PinnedResolution)
//! ```
//!
//! [`Resolver`] is the abstraction; [`InMemoryResolver`] is a fully in-memory harness (DNS zone +
//! mesh + KT logs as data) so the whole flow is unit-testable offline. A real resolver is a thin
//! layer that swaps the in-memory DNS/mesh/KT for network fetches and implements the same trait —
//! the verification core (`kt`, `merkle`) is identical.

use std::collections::HashMap;

use dmtap_core::id::ContentId;
use dmtap_core::identity::{Identity, KeyPackageBundleRef};
use dmtap_core::TimestampMs;

use crate::dns::DmtapTxtRecord;
use crate::error::ResolveError;
use crate::keypackage::{InMemoryKeyPackages, KeyPackageSource};
use crate::kt::{self, KtLog, KtProof};

/// A parsed DMTAP `name@domain` address (§3.9.1), with the `_dmtap` DNS query names it derives and
/// subaddressing (`you+tag@domain`, §3.9.4) canonicalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmtapName {
    /// The full local part as typed (MAY include a `+tag`).
    pub local: String,
    /// The domain part.
    pub domain: String,
}

impl DmtapName {
    /// Parse `local@domain`, failing closed on a missing/empty part or a domain without a dot.
    pub fn parse(s: &str) -> Result<Self, ResolveError> {
        let (local, domain) = s
            .split_once('@')
            .ok_or(ResolveError::MalformedName("no '@' in name"))?;
        if local.is_empty() || domain.is_empty() {
            return Err(ResolveError::MalformedName("empty local or domain part"));
        }
        if domain.contains('@') || !domain.contains('.') {
            return Err(ResolveError::MalformedName("domain is not a FQDN"));
        }
        Ok(DmtapName { local: local.to_owned(), domain: domain.to_owned() })
    }

    /// The base local part with any `+tag` subaddress stripped (§3.9.4): `you+tag` → `you`.
    pub fn base_local(&self) -> &str {
        self.local.split('+').next().unwrap_or(&self.local)
    }

    /// The canonical `base_local@domain` address — the string a KT leaf and `Identity.names` carry
    /// (subaddressing resolves to the same key, §3.9.4).
    pub fn base_address(&self) -> String {
        format!("{}@{}", self.base_local(), self.domain)
    }

    /// The `_dmtap` TXT query name: `<base_local>._dmtap.<domain>` (§3.2).
    pub fn txt_qname(&self) -> String {
        format!("{}._dmtap.{}", self.base_local(), self.domain)
    }

    /// The `_dmtap` SVCB query name: `_dmtap.<domain>` (§3.2).
    pub fn svcb_qname(&self) -> String {
        format!("_dmtap.{}", self.domain)
    }
}

/// The result of a successful §3.3 resolution: a **pinned** `name → key` binding. `oob_verified`
/// starts `false` — this is a TOFU pin (§3.4); out-of-band safety-number verification (§3.4.1)
/// upgrades it. `attested_by` lists the KT log id(s) that proved the binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedResolution {
    /// The canonical `base_local@domain` address that was resolved.
    pub name: String,
    /// The pinned identity key (classical `IK`).
    pub ik: Vec<u8>,
    /// The pinned `Identity` content address (§18.9.4).
    pub identity_id: ContentId,
    /// The pinned `Identity` version (§1.3).
    pub version: u64,
    /// The KeyPackage bundle locator (§5.3) advertised by the identity, for async join.
    pub keypkgs: KeyPackageBundleRef,
    /// The KT log id(s) that attested the binding with a valid inclusion proof.
    pub attested_by: Vec<Vec<u8>>,
    /// `false` for a first-contact TOFU pin; upgraded to `true` only by OOB verification (§3.4.1).
    pub oob_verified: bool,
}

/// The `name → key` resolver abstraction (§3.3). A real implementation fetches DNS/mesh/KT over the
/// network; the in-memory one serves from data. Either way it returns a KT-verified, pinned binding
/// or a typed fail-closed error.
pub trait Resolver {
    /// Resolve and KT-verify `name` at first contact, returning a pinned binding.
    fn resolve(&self, name: &str) -> Result<PinnedResolution, ResolveError>;
}

/// Which KT profile the resolver enforces (§3.5): the interoperable v0 single-log default, or the
/// v1 federated `> n/2` quorum over the pinned log set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KtMode {
    /// v0-minimal (log-type `0x01`, §3.5.1): one pinned log MUST attest, else fail closed.
    V0Single,
    /// v1-hardening (log-type `0x02`, §3.5.2): a strict majority of the pinned set MUST attest.
    V1Quorum,
}

/// A fully in-memory [`Resolver`] harness: DNS zone (raw TXT strings, so the parser is exercised),
/// a content-addressed mesh of `Identity` objects, a set of pinned KT logs, and an optional
/// freshness window. Drives the §3.3 flow end-to-end with no network.
pub struct InMemoryResolver {
    zone_txt: HashMap<String, String>,
    mesh: HashMap<Vec<u8>, Identity>,
    logs: Vec<Box<dyn KtLog>>,
    pinned_logs: Vec<Vec<u8>>,
    mode: KtMode,
    now: TimestampMs,
    freshness_window: Option<TimestampMs>,
    keypkgs: InMemoryKeyPackages,
}

impl InMemoryResolver {
    /// A new resolver in v0 single-log mode, clock at `now`.
    pub fn new(now: TimestampMs) -> Self {
        InMemoryResolver {
            zone_txt: HashMap::new(),
            mesh: HashMap::new(),
            logs: Vec::new(),
            pinned_logs: Vec::new(),
            mode: KtMode::V0Single,
            now,
            freshness_window: None,
            keypkgs: InMemoryKeyPackages::new(),
        }
    }

    /// Switch KT enforcement to v1 `> n/2` quorum over the pinned set (§3.5.2).
    pub fn with_quorum(mut self) -> Self {
        self.mode = KtMode::V1Quorum;
        self
    }

    /// Require STH freshness within `window` ms (§3.5.2(a)); absent ⇒ no freshness gate.
    pub fn with_freshness(mut self, window: TimestampMs) -> Self {
        self.freshness_window = Some(window);
        self
    }

    /// Install a raw TXT record at a `_dmtap` query name (parsed on resolve, exercising the parser).
    pub fn set_txt(&mut self, qname: impl Into<String>, txt: impl Into<String>) {
        self.zone_txt.insert(qname.into(), txt.into());
    }

    /// Publish an `Identity` into the content-addressed mesh (keyed by its §18.9.4 content id).
    pub fn publish_identity(&mut self, identity: Identity) {
        self.mesh.insert(identity.content_id().as_bytes().to_vec(), identity);
    }

    /// Pin a KT log into the verifier's log set. In v0 the first pinned log is authoritative; in v1
    /// the whole pinned set forms the quorum.
    pub fn pin_log(&mut self, log: impl KtLog + 'static) {
        self.pinned_logs.push(log.log_id());
        self.logs.push(Box::new(log));
    }

    /// Access the KeyPackage store (publish bundles / fetch by ref, §5.3).
    pub fn keypackages(&mut self) -> &mut InMemoryKeyPackages {
        &mut self.keypkgs
    }

    /// Fetch the async-join KeyPackage bundle for a resolved binding (§5.3), content-verified.
    pub fn fetch_keypackages(&self, res: &PinnedResolution) -> Result<Vec<u8>, ResolveError> {
        self.keypkgs.fetch_bundle(&res.keypkgs)
    }

    fn find_log(&self, log_id: &[u8]) -> Option<&dyn KtLog> {
        self.logs
            .iter()
            .find(|l| l.log_id() == log_id)
            .map(|b| b.as_ref())
    }
}

impl Resolver for InMemoryResolver {
    fn resolve(&self, name: &str) -> Result<PinnedResolution, ResolveError> {
        // 1. DNS TXT lookup + parse (§3.2).
        let dmtap_name = DmtapName::parse(name)?;
        let raw = self
            .zone_txt
            .get(&dmtap_name.txt_qname())
            .ok_or(ResolveError::NameResolution("no _dmtap TXT record"))?;
        let txt = DmtapTxtRecord::parse(raw)?;

        // 2. Fetch the full Identity from the mesh by its content address, verify its own
        //    signature + chain (§1.3). First contact ⇒ no pinned predecessor.
        let identity = self
            .mesh
            .get(txt.id.as_bytes())
            .ok_or(ResolveError::NameResolution("Identity not found in mesh"))?;
        identity.verify(None)?;

        // 3. Cross-check the DNS pointer against the signed Identity (§3.3 step 3–4).
        kt::check_dns_matches_identity(&txt.ik, &txt.id, identity)?;

        // The self-asserted name MUST be one the resolved Identity actually lists (§3.9.4 forward
        // check); the KT leaf then binds *that* name → ik. A name the resolved identity does **not**
        // claim is an alias-specific failure, distinct from the plain `ik`/`id` pointer mismatch
        // (`0x0109`) already caught above: it is either a *revoked* alias (once listed, since
        // dropped — `0x011D`) or a *never-verified* self-asserted alias (`0x011C`). Fail closed on
        // either; the two codes only differ in the mandated response (REJECT_NOTIFY vs BLOCK).
        let addr = dmtap_name.base_address();
        if !identity.names.iter().any(|n| n == &addr) {
            if self.alias_was_revoked(&addr, identity) {
                return Err(ResolveError::AliasRevoked(
                    "alias retired in a newer Identity version",
                ));
            }
            return Err(ResolveError::AliasForwardUnverified(
                "alias not claimed by the resolved identity — forward name→ik binding does not resolve back",
            ));
        }
        let leaf = kt::leaf_for(&addr, identity)
            .ok_or(ResolveError::DnsIdentityMismatch("Identity has no classical ik"))?;

        // 4. KT-verify the binding (§3.5). Unreachable KT ⇒ BLOCK (never TOFU, §3.3).
        if self.pinned_logs.is_empty() {
            return Err(ResolveError::KtUnreachable);
        }
        let attested_by = match self.mode {
            KtMode::V0Single => {
                let log_id = &self.pinned_logs[0];
                let log = self
                    .find_log(log_id)
                    .ok_or(ResolveError::KtUnreachable)?;
                let att = log.prove(&leaf).ok_or(ResolveError::KtUnreachable)?;
                self.check_fresh(&att)?;
                kt::verify_attestation(&addr, identity, log_id, &att)?;
                vec![log_id.clone()]
            }
            KtMode::V1Quorum => {
                let mut attestations: Vec<(Vec<u8>, Option<KtProof>)> =
                    Vec::with_capacity(self.pinned_logs.len());
                for log_id in &self.pinned_logs {
                    let att = self
                        .find_log(log_id)
                        .and_then(|l| l.prove(&leaf));
                    // A stale STH is treated as no attestation (fail-closed toward quorum).
                    let att = att.filter(|a| self.check_fresh(a).is_ok());
                    attestations.push((log_id.clone(), att));
                }
                kt::verify_quorum(&addr, identity, &attestations)?
            }
        };

        // 5. PIN (name → ik, id) as a TOFU pin (§3.4).
        let ik = txt.ik.clone();
        Ok(PinnedResolution {
            name: addr,
            ik,
            identity_id: txt.id.clone(),
            version: identity.version,
            keypkgs: identity.keypkgs.clone(),
            attested_by,
            oob_verified: false,
        })
    }
}

/// Bound on the `prev`-chain walk when distinguishing a revoked alias (§1.5). A signed `Identity`
/// chain is monotonic in `version`, so this is only a defence against a malformed/cyclic mesh — it
/// never truncates an honest history within any realistic key-rotation count.
const MAX_ALIAS_CHAIN_WALK: u32 = 1_024;

impl InMemoryResolver {
    fn check_fresh(&self, att: &KtProof) -> Result<(), ResolveError> {
        match self.freshness_window {
            Some(w) => kt::check_freshness(&att.sth, self.now, w),
            None => Ok(()),
        }
    }

    /// Was `addr` a **revoked** alias of `current` (§3.9.4, §3.11.5)? Walk `current`'s `prev` hash
    /// chain (§1.5) looking for a **prior signed `Identity` version** that listed `addr`. A name
    /// present in a prior version but absent from the current one was retired by the owner in a
    /// newer signed version — a revocation (`0x011D`), as opposed to a name this identity *never*
    /// verifiably claimed (`0x011C`).
    ///
    /// Fail-closed: this only ever *upgrades* the diagnosis from the stricter BLOCK (`0x011C`) to
    /// the softer REJECT_NOTIFY (`0x011D`) when it can **prove**, on the content-addressed chain,
    /// that the alias once existed. Any hop we cannot fetch, that fails its own signature/chain
    /// verification, whose content address does not match the `prev` pointer, or that does not
    /// strictly precede its successor in `version`, stops the walk — an unprovable "it was revoked"
    /// claim is never asserted.
    fn alias_was_revoked(&self, addr: &str, current: &Identity) -> bool {
        let mut prev = current.prev.clone();
        let mut successor_version = current.version;
        for _ in 0..MAX_ALIAS_CHAIN_WALK {
            let Some(pid) = prev else { return false };
            let Some(older) = self.mesh.get(pid.as_bytes()) else { return false };
            // Content address must bind the fetched object to the `prev` pointer, the object must
            // verify on its own, and `version` must strictly decrease along the chain (§1.3, §1.5).
            if older.content_id() != pid
                || older.verify(None).is_err()
                || older.version >= successor_version
            {
                return false;
            }
            if older.names.iter().any(|n| n == addr) {
                return true;
            }
            successor_version = older.version;
            prev = older.prev.clone();
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base64url;
    use crate::kt::{InMemoryKtLog, UnreachableLog};
    use dmtap_core::identity::{IdentityKey, KeyPackageBundleRef};

    const NOW: TimestampMs = 1_700_000_000_000;

    /// Build an identity for `name` and the TXT record that points at it.
    fn make_identity(name: &str, seed: u8, keypkgs: KeyPackageBundleRef) -> (Identity, String) {
        let ik = IdentityKey::from_seed(&[seed; 32]);
        let id = Identity::create_classical(
            &ik,
            0,
            vec![],
            keypkgs,
            ContentId::of(b"recovery"),
            vec![name.to_owned()],
            None,
            NOW,
        );
        let txt = DmtapTxtRecord {
            version: "dmtap1".into(),
            suite: 1,
            ik: ik.public(),
            id: id.content_id(),
            kt: vec!["https://kt.example/log".into()],
            keypkgs: "/mesh/kp/it".into(),
        }
        .to_txt();
        (id, txt)
    }

    #[test]
    fn full_happy_path_v0_resolution() {
        let name = "alice@example.com";
        let bundle_ref = KeyPackageBundleRef::new("/mesh/kp/alice", ContentId::of(b"kp"));
        let (id, txt) = make_identity(name, 1, bundle_ref);

        let mut log = InMemoryKtLog::new(IdentityKey::from_seed(&[9; 32]));
        log.append_identity(name, &id).unwrap();

        let mut r = InMemoryResolver::new(NOW);
        r.set_txt("alice._dmtap.example.com", &txt);
        r.publish_identity(id.clone());
        r.pin_log(log);

        let res = r.resolve(name).unwrap();
        assert_eq!(res.name, name);
        assert_eq!(res.ik, IdentityKey::from_seed(&[1; 32]).public());
        assert_eq!(res.identity_id, id.content_id());
        assert!(!res.oob_verified, "first contact is a TOFU pin");
        assert_eq!(res.attested_by.len(), 1);
    }

    #[test]
    fn subaddressing_resolves_to_same_binding() {
        let name = "alice@example.com";
        let (id, txt) = make_identity(name, 1, KeyPackageBundleRef::new("/kp", ContentId::of(b"k")));
        let mut log = InMemoryKtLog::new(IdentityKey::from_seed(&[9; 32]));
        log.append_identity(name, &id).unwrap();
        let mut r = InMemoryResolver::new(NOW);
        r.set_txt("alice._dmtap.example.com", &txt);
        r.publish_identity(id.clone());
        r.pin_log(log);
        // you+tag@domain queries the base name and pins the same key.
        let res = r.resolve("alice+newsletter@example.com").unwrap();
        assert_eq!(res.name, "alice@example.com");
        assert_eq!(res.identity_id, id.content_id());
    }

    #[test]
    fn kt_unreachable_blocks_no_tofu() {
        let name = "bob@example.com";
        let (id, txt) = make_identity(name, 2, KeyPackageBundleRef::new("/kp", ContentId::of(b"k")));
        let mut r = InMemoryResolver::new(NOW);
        r.set_txt("bob._dmtap.example.com", &txt);
        r.publish_identity(id.clone());
        // Pin only an unreachable log — the §3.3 fail-closed condition.
        r.pin_log(UnreachableLog { log_id: IdentityKey::from_seed(&[7; 32]).public() });
        assert_eq!(r.resolve(name), Err(ResolveError::KtUnreachable));
    }

    #[test]
    fn no_pinned_log_blocks() {
        let name = "carol@example.com";
        let (id, txt) = make_identity(name, 3, KeyPackageBundleRef::new("/kp", ContentId::of(b"k")));
        let mut r = InMemoryResolver::new(NOW);
        r.set_txt("carol._dmtap.example.com", &txt);
        r.publish_identity(id);
        assert_eq!(r.resolve(name), Err(ResolveError::KtUnreachable));
    }

    #[test]
    fn missing_dns_record_fails() {
        let r = InMemoryResolver::new(NOW);
        assert!(matches!(
            r.resolve("nobody@example.com"),
            Err(ResolveError::NameResolution(_))
        ));
    }

    #[test]
    fn dns_pointing_at_wrong_identity_fails_closed() {
        // TXT id points at a real identity, but ik= is swapped for an attacker key: the DNS pointer
        // and the signed Identity disagree.
        let name = "dave@example.com";
        let (id, _good) = make_identity(name, 4, KeyPackageBundleRef::new("/kp", ContentId::of(b"k")));
        let evil_ik = IdentityKey::from_seed(&[0xee; 32]).public();
        let tampered = format!(
            "v=dmtap1; suite=1; ik={}; id={}; kt=https://kt/log; keypkgs=/kp",
            base64url::encode(&evil_ik),
            base64url::encode(id.content_id().as_bytes()),
        );
        let mut log = InMemoryKtLog::new(IdentityKey::from_seed(&[9; 32]));
        log.append_identity(name, &id).unwrap();
        let mut r = InMemoryResolver::new(NOW);
        r.set_txt("dave._dmtap.example.com", &tampered);
        r.publish_identity(id);
        r.pin_log(log);
        assert!(matches!(
            r.resolve(name),
            Err(ResolveError::DnsIdentityMismatch(_))
        ));
    }

    #[test]
    fn quorum_happy_and_sub_quorum_paths() {
        let name = "erin@example.com";
        let (id, txt) = make_identity(name, 5, KeyPackageBundleRef::new("/kp", ContentId::of(b"k")));

        // Three honest logs, all attesting.
        let build = || {
            let mut r = InMemoryResolver::new(NOW).with_quorum();
            r.set_txt("erin._dmtap.example.com", &txt);
            r.publish_identity(id.clone());
            r
        };

        let mut r = build();
        for s in 0..3u8 {
            let mut log = InMemoryKtLog::new(IdentityKey::from_seed(&[50 + s; 32]));
            log.append_identity(name, &id).unwrap();
            r.pin_log(log);
        }
        assert_eq!(r.resolve(name).unwrap().attested_by.len(), 3);

        // Pin 3 logs but only 1 is reachable → sub-quorum, fail closed.
        let mut r2 = build();
        let mut good = InMemoryKtLog::new(IdentityKey::from_seed(&[60; 32]));
        good.append_identity(name, &id).unwrap();
        r2.pin_log(good);
        r2.pin_log(UnreachableLog { log_id: IdentityKey::from_seed(&[61; 32]).public() });
        r2.pin_log(UnreachableLog { log_id: IdentityKey::from_seed(&[62; 32]).public() });
        assert_eq!(r2.resolve(name), Err(ResolveError::KtQuorumUnmet));
    }

    #[test]
    fn quorum_treats_a_stale_sth_as_no_attestation_not_an_error() {
        // §3.5.2(a): a stale STH must count as if that log had not attested at all — it should
        // never surface as ERR_KT_STH_STALE from inside a quorum check, only ever fold into
        // ERR_KT_LOG_QUORUM_UNMET if too many logs end up excluded this way.
        let name = "hank@example.com";
        let (id, txt) = make_identity(name, 8, KeyPackageBundleRef::new("/kp", ContentId::of(b"k")));

        let build = || {
            let mut r = InMemoryResolver::new(NOW).with_quorum().with_freshness(3_600_000);
            r.set_txt("hank._dmtap.example.com", &txt);
            r.publish_identity(id.clone());
            r
        };

        // 2 fresh + 1 stale: the stale log is excluded, but 2/3 is still a strict majority.
        let mut r = build();
        for s in 0..2u8 {
            let mut log = InMemoryKtLog::new(IdentityKey::from_seed(&[80 + s; 32]));
            log.append_identity(name, &id).unwrap();
            log.set_issued_at(NOW); // fresh relative to the verifier's NOW
            r.pin_log(log);
        }
        let mut stale = InMemoryKtLog::new(IdentityKey::from_seed(&[82; 32]));
        stale.append_identity(name, &id).unwrap();
        stale.set_issued_at(0); // far in the past — outside the 1h window
        r.pin_log(stale);
        let res = r.resolve(name).expect("2 fresh of 3 is still a strict majority");
        assert_eq!(res.attested_by.len(), 2, "the stale log does not count toward the quorum");

        // All 3 stale: every log is excluded as "no attestation" -> sub-quorum, fail closed. The
        // error is the QUORUM failure, not a per-log staleness error — staleness is folded away.
        let mut r2 = build();
        for s in 0..3u8 {
            let mut log = InMemoryKtLog::new(IdentityKey::from_seed(&[90 + s; 32]));
            log.append_identity(name, &id).unwrap();
            log.set_issued_at(0);
            r2.pin_log(log);
        }
        assert_eq!(r2.resolve(name), Err(ResolveError::KtQuorumUnmet));
    }

    #[test]
    fn stale_sth_rejected_when_freshness_enforced() {
        let name = "fred@example.com";
        let (id, txt) = make_identity(name, 6, KeyPackageBundleRef::new("/kp", ContentId::of(b"k")));
        let mut log = InMemoryKtLog::new(IdentityKey::from_seed(&[9; 32]));
        log.append_identity(name, &id).unwrap();
        log.set_issued_at(NOW); // the log's head is stamped at NOW (a frozen head)
        // Verifier clock is 2h past the STH timestamp; window 1h → stale.
        let mut r = InMemoryResolver::new(NOW + 7_200_000).with_freshness(3_600_000);
        r.set_txt("fred._dmtap.example.com", &txt);
        r.publish_identity(id);
        r.pin_log(log);
        assert_eq!(r.resolve(name), Err(ResolveError::KtSthStale));
    }

    #[test]
    fn keypackage_fetch_after_resolution() {
        let name = "gwen@example.com";
        // Publish a bundle first so the identity can point at its real content address.
        let mut store_probe = InMemoryKeyPackages::new();
        let bref = store_probe.publish("/mesh/kp/gwen", b"gwen bundle".to_vec());
        let (id, txt) = make_identity(name, 7, bref.clone());
        let mut log = InMemoryKtLog::new(IdentityKey::from_seed(&[9; 32]));
        log.append_identity(name, &id).unwrap();

        let mut r = InMemoryResolver::new(NOW);
        r.set_txt("gwen._dmtap.example.com", &txt);
        r.publish_identity(id);
        r.pin_log(log);
        r.keypackages().publish("/mesh/kp/gwen", b"gwen bundle".to_vec());

        let res = r.resolve(name).unwrap();
        assert_eq!(res.keypkgs, bref);
        assert_eq!(r.fetch_keypackages(&res).unwrap(), b"gwen bundle".to_vec());
    }

    /// Build an identity with an explicit name list / version / prev (for alias + chain tests).
    fn make_identity_full(
        seed: u8,
        version: u64,
        names: &[&str],
        prev: Option<ContentId>,
    ) -> (Identity, IdentityKey) {
        let ik = IdentityKey::from_seed(&[seed; 32]);
        let id = Identity::create_classical(
            &ik,
            version,
            vec![],
            KeyPackageBundleRef::new("/kp", ContentId::of(b"k")),
            ContentId::of(b"recovery"),
            names.iter().map(|s| s.to_string()).collect(),
            prev,
            NOW,
        );
        (id, ik)
    }

    /// A TXT record carrying an identity's *own* ik/id (so `check_dns_matches_identity` passes and
    /// the failure, if any, is alias-specific rather than a pointer mismatch).
    fn txt_for(ik: &IdentityKey, id: &Identity) -> String {
        DmtapTxtRecord {
            version: "dmtap1".into(),
            suite: 1,
            ik: ik.public(),
            id: id.content_id(),
            kt: vec!["https://kt.example/log".into()],
            keypkgs: "/mesh/kp/it".into(),
        }
        .to_txt()
    }

    #[test]
    fn alias_not_claimed_is_forward_unverified_0x011c() {
        // DNS points `mallory@example.com` at an identity whose ik/id genuinely match — but that
        // identity only claims `alice@example.com`. The forward name→ik binding does not resolve
        // back, so the alias is UNVERIFIED (ERR_ALIAS_FORWARD_UNVERIFIED, 0x011C), never the plain
        // pointer mismatch (0x0109). DMTAP-ALIAS-01.
        let (id, ik) = make_identity_full(1, 0, &["alice@example.com"], None);
        let txt = txt_for(&ik, &id);
        let mut r = InMemoryResolver::new(NOW);
        r.set_txt("mallory._dmtap.example.com", &txt);
        r.publish_identity(id);
        let err = r.resolve("mallory@example.com").unwrap_err();
        assert!(matches!(err, ResolveError::AliasForwardUnverified(_)));
        assert_eq!(err.code(), 0x011C);
    }

    #[test]
    fn revoked_alias_is_0x011d() {
        // v0 lists `oldbob@example.com`; v1 (same IK, prev→v0) drops it, keeping `bob@example.com`.
        // Resolving the retired alias against v1 must surface ERR_ALIAS_REVOKED (0x011D) — proven by
        // walking the prev chain to the version that listed it — not the never-claimed 0x011C.
        // DMTAP-ALIAS-02.
        let (v0, ik) = make_identity_full(2, 0, &["bob@example.com", "oldbob@example.com"], None);
        let (v1, _) = make_identity_full(2, 1, &["bob@example.com"], Some(v0.content_id()));
        let txt = txt_for(&ik, &v1);
        let mut r = InMemoryResolver::new(NOW);
        r.set_txt("oldbob._dmtap.example.com", &txt);
        r.publish_identity(v0);
        r.publish_identity(v1);
        let err = r.resolve("oldbob@example.com").unwrap_err();
        assert!(matches!(err, ResolveError::AliasRevoked(_)));
        assert_eq!(err.code(), 0x011D);
    }

    #[test]
    fn revocation_unprovable_without_prior_version_falls_to_0x011c() {
        // Same shape as the revoked case, but the prior version that listed the alias is NOT
        // published: the chain walk cannot PROVE the alias ever existed, so it fails closed to the
        // stricter 0x011C (BLOCK), never asserting an unprovable 0x011D (REJECT_NOTIFY).
        let (v0, _) = make_identity_full(3, 0, &["bob@example.com", "oldbob@example.com"], None);
        let (v1, ik) = make_identity_full(3, 1, &["bob@example.com"], Some(v0.content_id()));
        let txt = txt_for(&ik, &v1);
        let mut r = InMemoryResolver::new(NOW);
        r.set_txt("oldbob._dmtap.example.com", &txt);
        r.publish_identity(v1); // v0 withheld — the prior listing is unprovable
        let err = r.resolve("oldbob@example.com").unwrap_err();
        assert!(matches!(err, ResolveError::AliasForwardUnverified(_)));
        assert_eq!(err.code(), 0x011C);
    }

    #[test]
    fn plain_dns_pointer_mismatch_stays_0x0109() {
        // A swapped ik= (the non-alias pointer mismatch) must remain ERR_NAME_RESOLUTION_FAILED
        // (0x0109) — the distinct alias codes MUST NOT capture it.
        let name = "dave@example.com";
        let (id, _good) = make_identity(name, 4, KeyPackageBundleRef::new("/kp", ContentId::of(b"k")));
        let evil_ik = IdentityKey::from_seed(&[0xee; 32]).public();
        let tampered = format!(
            "v=dmtap1; suite=1; ik={}; id={}; kt=https://kt/log; keypkgs=/kp",
            base64url::encode(&evil_ik),
            base64url::encode(id.content_id().as_bytes()),
        );
        let mut log = InMemoryKtLog::new(IdentityKey::from_seed(&[9; 32]));
        log.append_identity(name, &id).unwrap();
        let mut r = InMemoryResolver::new(NOW);
        r.set_txt("dave._dmtap.example.com", &tampered);
        r.publish_identity(id);
        r.pin_log(log);
        let err = r.resolve(name).unwrap_err();
        assert!(matches!(err, ResolveError::DnsIdentityMismatch(_)));
        assert_eq!(err.code(), 0x0109);
    }

    #[test]
    fn name_parsing_rules() {
        assert!(DmtapName::parse("a@b.com").is_ok());
        assert!(DmtapName::parse("no-at-sign").is_err());
        assert!(DmtapName::parse("@b.com").is_err());
        assert!(DmtapName::parse("a@").is_err());
        assert!(DmtapName::parse("a@localhost").is_err()); // no dot
        let n = DmtapName::parse("alice+tag@example.com").unwrap();
        assert_eq!(n.base_address(), "alice@example.com");
        assert_eq!(n.txt_qname(), "alice._dmtap.example.com");
        assert_eq!(n.svcb_qname(), "_dmtap.example.com");
    }
}

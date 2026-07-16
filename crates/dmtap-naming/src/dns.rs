//! DMTAP DNS record parsing — spec §3.2.
//!
//! DNS is **discovery, never proof** (§3.1): these records tell a resolver which key *claims* a
//! name and where to audit that claim (KT), but authenticity is always the key + KT + pinning
//! (§3.3–3.5). This module parses the two §3.2 records into typed, fail-closed structs:
//!
//! - [`DmtapTxtRecord`] — `abc._dmtap.def.com TXT "v=dmtap1; suite=…; ik=…; id=…; kt=…; keypkgs=…"`
//! - [`DmtapSvcbRecord`] — `_dmtap.def.com SVCB 1 . ( … )`, whose params MAY carry extra KT anchors.
//!
//! Parsing is strict: a missing required field, a duplicate key, a bad base64url value, a
//! wrong-length key, or a malformed content-address `id` fails closed with
//! [`ResolveError::MalformedDns`] (`ERR_NAME_RESOLUTION_FAILED`, §21.3) rather than yielding a
//! half-populated record. Unknown *extra* keys are ignored for forward-compatibility (DNS is an
//! extensible pointer, not a signed object), but every field DMTAP defines is validated.

use dmtap_core::id::{ContentId, MH_BLAKE3_256};

use crate::base64url;
use crate::error::ResolveError;

/// The v0 classical Ed25519 identity public key length (bytes) — the `ik` field of a §3.2 TXT
/// record under `suite=1`.
const IK_LEN_CLASSICAL: usize = 32;

/// A parsed `_dmtap` **TXT** record (§3.2): the stable `name → key` pointer plus the KT anchor and
/// KeyPackage locator a resolver needs. Discovery only — never trusted without KT + pinning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmtapTxtRecord {
    /// `v=` — the record version tag. v0 is exactly `"dmtap1"`.
    pub version: String,
    /// `suite=` — the suite governing the `ik` in this record (a discovery hint; the full
    /// multi-suite keyset is in the `Identity`, §1.3). v0 default `0x01` (classical).
    pub suite: u8,
    /// `ik=` — the identity public key, decoded from base64url (§3.2). For `suite=1` this is the
    /// 32-byte Ed25519 `IK`.
    pub ik: Vec<u8>,
    /// `id=` — the content address of the current `Identity` version (§1.3, §18.9.4), decoded from
    /// base64url into a validated [`ContentId`].
    pub id: ContentId,
    /// `kt=` — the KT log anchor(s). One or more log URLs (v1 pins a *set*, §3.5.2(b)); parsed as a
    /// comma-separated list so a single TXT can advertise a quorum set.
    pub kt: Vec<String>,
    /// `keypkgs=` — the KeyPackage bundle locator for async-join (§5.3, §18.4.3).
    pub keypkgs: String,
}

impl DmtapTxtRecord {
    /// Parse a `_dmtap` TXT record body (§3.2), failing closed on any malformed/duplicate/missing
    /// field. Whitespace around `;`-separated `key=value` pairs is tolerated; DNS may split a TXT
    /// into multiple character-strings, so the caller concatenates them before parsing.
    pub fn parse(txt: &str) -> Result<Self, ResolveError> {
        let mut version: Option<String> = None;
        let mut suite: Option<u8> = None;
        let mut ik: Option<Vec<u8>> = None;
        let mut id: Option<ContentId> = None;
        let mut kt: Option<Vec<String>> = None;
        let mut keypkgs: Option<String> = None;

        for field in txt.split(';') {
            let field = field.trim();
            if field.is_empty() {
                continue; // tolerate a trailing "; " and incidental whitespace
            }
            let (key, val) = field
                .split_once('=')
                .ok_or(ResolveError::MalformedDns("field is not key=value"))?;
            let key = key.trim();
            let val = val.trim();

            macro_rules! set_once {
                ($slot:ident, $v:expr) => {{
                    if $slot.is_some() {
                        return Err(ResolveError::MalformedDns("duplicate key in TXT record"));
                    }
                    $slot = Some($v);
                }};
            }

            match key {
                "v" => set_once!(version, val.to_owned()),
                "suite" => {
                    let n = val
                        .parse::<u8>()
                        .map_err(|_| ResolveError::MalformedDns("suite is not a u8"))?;
                    set_once!(suite, n);
                }
                "ik" => {
                    let bytes = base64url::decode(val)
                        .ok_or(ResolveError::MalformedDns("ik is not valid base64url"))?;
                    set_once!(ik, bytes);
                }
                "id" => {
                    let bytes = base64url::decode(val)
                        .ok_or(ResolveError::MalformedDns("id is not valid base64url"))?;
                    // An identity content address is a 1-byte alg prefix + 32-byte BLAKE3 digest
                    // (§2.2). Fail closed on any other shape rather than pinning a bad anchor.
                    if bytes.first() != Some(&MH_BLAKE3_256) || bytes.len() != 33 {
                        return Err(ResolveError::MalformedDns(
                            "id is not a BLAKE3-256 content address",
                        ));
                    }
                    set_once!(id, ContentId(bytes));
                }
                "kt" => {
                    let anchors: Vec<String> = val
                        .split(',')
                        .map(|s| s.trim().to_owned())
                        .filter(|s| !s.is_empty())
                        .collect();
                    if anchors.is_empty() {
                        return Err(ResolveError::MalformedDns("kt anchor list is empty"));
                    }
                    set_once!(kt, anchors);
                }
                "keypkgs" => {
                    if val.is_empty() {
                        return Err(ResolveError::MalformedDns("keypkgs locator is empty"));
                    }
                    set_once!(keypkgs, val.to_owned());
                }
                // Unknown keys are ignored (DNS pointer is extensible; it is not a signed object).
                _ => {}
            }
        }

        let version = version.ok_or(ResolveError::MalformedDns("missing v="))?;
        if version != "dmtap1" {
            return Err(ResolveError::MalformedDns("unsupported record version (want dmtap1)"));
        }
        let suite = suite.ok_or(ResolveError::MalformedDns("missing suite="))?;
        let ik = ik.ok_or(ResolveError::MalformedDns("missing ik="))?;
        // For the classical suite the key length is fixed; reject a truncated/oversized key.
        if suite == 0x01 && ik.len() != IK_LEN_CLASSICAL {
            return Err(ResolveError::MalformedDns("classical ik is not 32 bytes"));
        }
        let id = id.ok_or(ResolveError::MalformedDns("missing id="))?;
        let kt = kt.ok_or(ResolveError::MalformedDns("missing kt="))?;
        let keypkgs = keypkgs.ok_or(ResolveError::MalformedDns("missing keypkgs="))?;

        Ok(DmtapTxtRecord { version, suite, ik, id, kt, keypkgs })
    }

    /// Serialize back to the §3.2 presentation form (round-trips through [`parse`]).
    pub fn to_txt(&self) -> String {
        format!(
            "v={}; suite={}; ik={}; id={}; kt={}; keypkgs={}",
            self.version,
            self.suite,
            base64url::encode(&self.ik),
            base64url::encode(self.id.as_bytes()),
            self.kt.join(","),
            self.keypkgs,
        )
    }
}

/// A parsed `_dmtap` **SVCB** record (§3.2): optional service parameters and extra KT anchors. The
/// presentation form is `<priority> <target> [key=value ...]`; DMTAP reads `kt` params as
/// additional log anchors that extend the TXT `kt=` set (§3.5.2(b) pins a *set*).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmtapSvcbRecord {
    /// SvcPriority (0 = AliasMode; ≥1 = ServiceMode).
    pub priority: u16,
    /// TargetName — `.` means "the owner name itself" (§3.2's `SVCB 1 .`).
    pub target: String,
    /// SvcParams as `(key, value)` pairs, values dequoted.
    pub params: Vec<(String, String)>,
}

impl DmtapSvcbRecord {
    /// Parse an SVCB record from its presentation format, failing closed on a missing
    /// priority/target. Surrounding `( … )` grouping parens are tolerated.
    pub fn parse(svcb: &str) -> Result<Self, ResolveError> {
        // Strip one layer of grouping parens if present: `1 . ( kt="…" )`.
        let s = svcb.trim();
        let s = s.strip_prefix('(').map(str::trim).unwrap_or(s);
        let s = s.strip_suffix(')').map(str::trim).unwrap_or(s);

        let mut toks = split_svcb(s);
        let priority = toks
            .next()
            .and_then(|t| t.parse::<u16>().ok())
            .ok_or(ResolveError::MalformedDns("SVCB priority missing/invalid"))?;
        let target = toks
            .next()
            .ok_or(ResolveError::MalformedDns("SVCB target missing"))?;
        let mut params = Vec::new();
        for tok in toks {
            if let Some((k, v)) = tok.split_once('=') {
                let v = v.trim();
                let v = v.strip_prefix('"').and_then(|x| x.strip_suffix('"')).unwrap_or(v);
                params.push((k.trim().to_owned(), v.to_owned()));
            } else {
                params.push((tok.to_owned(), String::new())); // valueless param key
            }
        }
        Ok(DmtapSvcbRecord { priority, target, params })
    }

    /// The KT log anchors advertised in this SVCB record's `kt` params (comma-lists flattened).
    pub fn kt_anchors(&self) -> Vec<String> {
        self.params
            .iter()
            .filter(|(k, _)| k == "kt")
            .flat_map(|(_, v)| v.split(','))
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect()
    }
}

/// Whitespace-split that keeps `"quoted values with spaces"` together (SVCB param values MAY be
/// quoted). Deliberately small — SVCB presentation is simple here.
fn split_svcb(s: &str) -> impl Iterator<Item = String> + '_ {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    for c in s.chars() {
        match c {
            '"' => {
                in_quotes = !in_quotes;
                cur.push(c);
            }
            c if c.is_whitespace() && !in_quotes => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out.into_iter()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_id() -> ContentId {
        ContentId::of(b"some Identity object")
    }

    fn valid_txt() -> String {
        format!(
            "v=dmtap1; suite=1; ik={}; id={}; kt=https://kt.example/log; keypkgs=/mesh/kp/abc",
            base64url::encode(&[7u8; 32]),
            base64url::encode(sample_id().as_bytes()),
        )
    }

    #[test]
    fn parses_a_valid_txt_record() {
        let r = DmtapTxtRecord::parse(&valid_txt()).unwrap();
        assert_eq!(r.version, "dmtap1");
        assert_eq!(r.suite, 1);
        assert_eq!(r.ik, vec![7u8; 32]);
        assert_eq!(r.id, sample_id());
        assert_eq!(r.kt, vec!["https://kt.example/log".to_owned()]);
        assert_eq!(r.keypkgs, "/mesh/kp/abc");
        // Round-trips through presentation form.
        assert_eq!(DmtapTxtRecord::parse(&r.to_txt()).unwrap(), r);
    }

    #[test]
    fn parses_multi_anchor_kt_and_ignores_unknown_keys() {
        let txt = format!(
            "v=dmtap1; suite=1; ik={}; id={}; kt=https://a/log , https://b/log; keypkgs=/kp; ext=whatever",
            base64url::encode(&[1u8; 32]),
            base64url::encode(sample_id().as_bytes()),
        );
        let r = DmtapTxtRecord::parse(&txt).unwrap();
        assert_eq!(r.kt, vec!["https://a/log".to_owned(), "https://b/log".to_owned()]);
    }

    #[test]
    fn fails_closed_on_missing_required_fields() {
        let base_ik = base64url::encode(&[7u8; 32]);
        let base_id = base64url::encode(sample_id().as_bytes());
        // Drop each required field in turn.
        for missing in ["v", "suite", "ik", "id", "kt", "keypkgs"] {
            let fields = [
                ("v", "dmtap1".to_owned()),
                ("suite", "1".to_owned()),
                ("ik", base_ik.clone()),
                ("id", base_id.clone()),
                ("kt", "https://kt/log".to_owned()),
                ("keypkgs", "/kp".to_owned()),
            ];
            let txt = fields
                .iter()
                .filter(|(k, _)| *k != missing)
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; ");
            assert!(
                matches!(DmtapTxtRecord::parse(&txt), Err(ResolveError::MalformedDns(_))),
                "missing {missing} must fail closed"
            );
        }
    }

    #[test]
    fn fails_closed_on_malformed_values() {
        let good_ik = base64url::encode(&[7u8; 32]);
        let good_id = base64url::encode(sample_id().as_bytes());
        let cases = [
            // wrong version
            format!("v=dmtap0; suite=1; ik={good_ik}; id={good_id}; kt=x; keypkgs=y"),
            // bad base64url ik
            format!("v=dmtap1; suite=1; ik=not+base64url; id={good_id}; kt=x; keypkgs=y"),
            // short ik under classical suite
            format!(
                "v=dmtap1; suite=1; ik={}; id={good_id}; kt=x; keypkgs=y",
                base64url::encode(&[7u8; 16])
            ),
            // id not a content address (wrong length)
            format!(
                "v=dmtap1; suite=1; ik={good_ik}; id={}; kt=x; keypkgs=y",
                base64url::encode(&[9u8; 20])
            ),
            // duplicate key
            format!("v=dmtap1; v=dmtap1; suite=1; ik={good_ik}; id={good_id}; kt=x; keypkgs=y"),
            // suite not a number
            format!("v=dmtap1; suite=xx; ik={good_ik}; id={good_id}; kt=x; keypkgs=y"),
            // field without '='
            format!("v=dmtap1; suite=1; ik={good_ik}; id={good_id}; kt=x; keypkgs=y; junk"),
        ];
        for c in cases {
            assert!(
                matches!(DmtapTxtRecord::parse(&c), Err(ResolveError::MalformedDns(_))),
                "expected fail-closed on: {c}"
            );
        }
    }

    #[test]
    fn parses_svcb_with_kt_anchors() {
        let r = DmtapSvcbRecord::parse(r#"1 . ( kt="https://a/log,https://b/log" alpn=dmtap )"#)
            .unwrap();
        assert_eq!(r.priority, 1);
        assert_eq!(r.target, ".");
        assert_eq!(
            r.kt_anchors(),
            vec!["https://a/log".to_owned(), "https://b/log".to_owned()]
        );
    }

    #[test]
    fn svcb_fails_closed_without_priority() {
        assert!(matches!(
            DmtapSvcbRecord::parse("notanumber ."),
            Err(ResolveError::MalformedDns(_))
        ));
    }

    // ── Adversarial / oversized input — fail closed, never panic (§3.2) ──────────────────────────

    #[test]
    fn oversized_classical_ik_rejected() {
        // A 64-byte "ik" under the classical suite (which requires exactly 32) must fail closed,
        // symmetric with the already-covered truncated-key case.
        let txt = format!(
            "v=dmtap1; suite=1; ik={}; id={}; kt=x; keypkgs=y",
            base64url::encode(&[7u8; 64]),
            base64url::encode(sample_id().as_bytes()),
        );
        assert!(matches!(DmtapTxtRecord::parse(&txt), Err(ResolveError::MalformedDns(_))));
    }

    #[test]
    fn oversized_kt_anchor_list_parses_without_panic() {
        // A TXT record advertising a large multi-log quorum set must not panic or hang — DNS is an
        // attacker-observable input and a resolver must stay fail-closed-but-alive under a
        // pathological (if not protocol-violating) record shape.
        let many_anchors: Vec<String> =
            (0..5_000).map(|i| format!("https://kt-{i}.example/log")).collect();
        let txt = format!(
            "v=dmtap1; suite=1; ik={}; id={}; kt={}; keypkgs=/kp",
            base64url::encode(&[7u8; 32]),
            base64url::encode(sample_id().as_bytes()),
            many_anchors.join(","),
        );
        let r = DmtapTxtRecord::parse(&txt).expect("a large but well-formed record still parses");
        assert_eq!(r.kt.len(), 5_000);
    }

    #[test]
    fn oversized_keypkgs_locator_parses_without_panic() {
        let huge_locator = "/mesh/kp/".to_string() + &"a".repeat(1_000_000);
        let txt = format!(
            "v=dmtap1; suite=1; ik={}; id={}; kt=https://kt/log; keypkgs={huge_locator}",
            base64url::encode(&[7u8; 32]),
            base64url::encode(sample_id().as_bytes()),
        );
        let r = DmtapTxtRecord::parse(&txt).expect("a huge (but syntactically valid) value parses");
        assert_eq!(r.keypkgs, huge_locator);
    }

    #[test]
    fn many_bogus_extra_fields_are_tolerated_without_panic() {
        // Thousands of unknown `key=value` extras (forward-compatible DNS pointer, §3.2) must be
        // ignored, not cause quadratic blowup or a panic.
        let extras: String = (0..2_000).map(|i| format!("x{i}=v{i}; ")).collect();
        let txt = format!(
            "{extras}v=dmtap1; suite=1; ik={}; id={}; kt=https://kt/log; keypkgs=/kp",
            base64url::encode(&[7u8; 32]),
            base64url::encode(sample_id().as_bytes()),
        );
        let r = DmtapTxtRecord::parse(&txt).expect("unknown extras are ignored, not fatal");
        assert_eq!(r.suite, 1);
    }

    #[test]
    fn embedded_control_bytes_fail_closed_or_are_inert_never_panic() {
        // A field value carrying stray control characters / an embedded NUL (still valid UTF-8,
        // and thus a legal Rust &str an attacker-controlled DNS answer could carry) must not panic
        // the parser — it is simply bad base64url and fails closed.
        let txt = "v=dmtap1; suite=1; ik=not\0valid\nbase64; id=x; kt=x; keypkgs=y";
        assert!(matches!(DmtapTxtRecord::parse(txt), Err(ResolveError::MalformedDns(_))));
    }

    #[test]
    fn empty_and_whitespace_only_txt_fail_closed_without_panic() {
        assert!(matches!(DmtapTxtRecord::parse(""), Err(ResolveError::MalformedDns(_))));
        assert!(matches!(DmtapTxtRecord::parse("   ;  ; \t"), Err(ResolveError::MalformedDns(_))));
    }

    #[test]
    fn svcb_oversized_params_parse_without_panic() {
        let many_params: String = (0..5_000).map(|i| format!(" p{i}=v{i}")).collect();
        let svcb = format!("1 .{many_params}");
        let r = DmtapSvcbRecord::parse(&svcb).expect("a large but well-formed SVCB still parses");
        assert_eq!(r.params.len(), 5_000);
    }

    #[test]
    fn svcb_unterminated_quote_and_garbage_do_not_panic() {
        // An unterminated quote, stray parens, and empty/garbage tokens must all fail gracefully
        // (either a clean parse of best-effort tokens, or a typed error) — never panic.
        for garbage in [
            r#"1 . ( kt="unterminated )"#,
            "1 . ((( )))",
            "1 . =====",
            ") ( 1 . kt=x",
            "",
            "   ",
            "1",
        ] {
            let _ = DmtapSvcbRecord::parse(garbage); // must not panic regardless of Ok/Err
        }
    }

    #[test]
    fn svcb_extremely_long_single_token_does_not_panic() {
        let long_target = "a".repeat(500_000);
        let svcb = format!("1 {long_target}");
        let r = DmtapSvcbRecord::parse(&svcb).expect("a long target token still parses");
        assert_eq!(r.target.len(), 500_000);
    }
}

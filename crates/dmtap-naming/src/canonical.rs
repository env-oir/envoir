//! The **canonical name form** + UTS-39-informed confusables defense — spec §3.9.1, §3.12.4
//! (i18n hardening; error codes `0x0121`/`0x0122`, pending §21.3 registration).
//!
//! Names are identity-bearing strings: they key KT leaves (§18.4.9), the `Identity.names`
//! forward-check (§3.9.4), and the pin store (§3.4). Before this module existed they were kept
//! **byte-verbatim**, so `ALICE@Example.COM` ≠ `alice@example.com` (a hard identity-check failure
//! for plain ASCII), and `bücher.example` / `xn--bcher-kva.example` / an NFD spelling were three
//! *different* identities — an aliasing/spoofing surface. This module is the **one chokepoint**
//! every name entry point funnels through:
//!
//! - [`canonical_name`] — the funnel. Called by `DmtapName::parse`, `restype::classify`,
//!   `kt::leaf_for` (so KT leaves are always computed over the canonical string on both the append
//!   and the verify side), the `Identity.names` comparisons in `resolver`/`namechain`, and the
//!   petname book. **The canonical form, precisely:**
//!   - **local part** — Unicode NFC, then lowercased (simple case fold), then NFC again (casing
//!     can denormalize, e.g. `İ` → `i` + combining dot);
//!   - **domain part** — full UTS-46/IDNA processing ([`idna`]); the canonical stored/compared
//!     form is the **A-label (ASCII/punycode)** form, and DNS qnames are always built from
//!     A-labels;
//!   - **chain / bare forms** (`.eth`/`.sol` namespaces, key-names, petnames) — NFC + lowercase
//!     (their namespaces are not DNS, so no IDNA), same mixed-script gate;
//!   - every label MUST be **single-script** (the UTS-39 restriction-level gate below).
//! - [`skeleton`] / [`find_confusable`] — the **pin-time** confusable gate: a new name whose
//!   skeleton collides with a *different* already-pinned name is rejected (`0x0122`) instead of
//!   silently pinned, so `аррӏе.com` (all-Cyrillic, single-script, so it passes the label gate)
//!   cannot sit next to an existing `apple.com` pin.
//!
//! ## The mixed-script rule (fail-closed, `0x0121`)
//! Each label is checked against UTS-39's single-script restriction: characters with script
//! `Common`/`Inherited` (digits, hyphen, `+`, combining marks, …) are exempt, and the conventional
//! East-Asian combinations **Han+Hiragana+Katakana** (Japanese), **Han+Hangul** (Korean) and
//! **Han+Bopomofo** (Chinese) are whitelisted; any other multi-script label is rejected. This one
//! rule already kills the classic single-label homograph (`pаypal.com`, Latin + Cyrillic `а`)
//! *before* resolution — the skeleton below only has to catch whole-label substitutions.
//!
//! ## Honesty: the skeleton is a UTS-39 **subset**, not the full table
//! A faithful `confusables.txt` mapping is ~6k entries of data. The v0 trade here is deliberate:
//! after NFD + case-fold, fold only the **highest-value confusable sets** — the Cyrillic and Greek
//! letters whose lowercase glyphs are near-identical to Latin (`а е о р с у х і ѕ ј ѡ ѵ һ ӏ ԁ ԛ ԝ
//! к м` / `ο ν ι κ ρ τ υ χ ω α ε η γ`), the Latin strays (`ı ɩ ɡ ⅼ`-class compatibility forms are
//! already folded by UTS-46), and the `0`/`O`, `1`/`l` digit homoglyphs. That subset is sufficient
//! for whole-label Cyrillic/Greek↔Latin spoofs because the mixed-script rule above already forbids
//! *mixing* scripts inside a label — an attacker must go all-in on one script, which is exactly
//! what the folded sets cover. Multi-char confusables (`rn`→`m`) and rarer scripts are out of
//! scope for v0 and documented as such.

use icu_properties::{props::Script, CodePointMapDataBorrowed};
use unicode_normalization::UnicodeNormalization;

use crate::error::ResolveError;

/// The compiled Unicode `Script` property map (ICU4X `compiled_data` — embedded tables, no I/O).
const SCRIPTS: CodePointMapDataBorrowed<'static, Script> = CodePointMapDataBorrowed::new();

/// NFC → lowercase → NFC. The trailing NFC matters: Unicode lowercasing can emit decomposed
/// sequences (e.g. `İ` U+0130 → `i` + U+0307), which must not survive into the canonical form.
fn nfc_lower(s: &str) -> String {
    s.nfc().collect::<String>().to_lowercase().nfc().collect()
}

/// UTS-39 single-script-per-label gate. `Common`/`Inherited` never vote; `Unknown` (unassigned
/// code points) counts as a script of its own, so it cannot mix with anything — fail-closed.
fn check_single_script_label(label: &str) -> Result<(), ResolveError> {
    // A label mixes at most a handful of scripts before failing; a tiny Vec beats a HashSet here.
    let mut seen: Vec<Script> = Vec::new();
    for c in label.chars() {
        let s = SCRIPTS.get(c);
        if s == Script::Common || s == Script::Inherited {
            continue;
        }
        if !seen.contains(&s) {
            seen.push(s);
        }
    }
    if seen.len() <= 1 {
        return Ok(());
    }
    // The conventional East-Asian combinations are the ONLY multi-script labels admitted
    // (UTS-39 §5.1 "Highly Restrictive" minus its Latin admixture — stricter, fail-closed).
    let all_in = |allowed: &[Script]| seen.iter().all(|s| allowed.contains(s));
    if all_in(&[Script::Han, Script::Hiragana, Script::Katakana])
        || all_in(&[Script::Han, Script::Hangul])
        || all_in(&[Script::Han, Script::Bopomofo])
    {
        return Ok(());
    }
    Err(ResolveError::MixedScriptLabel(
        "label mixes Unicode scripts outside the Han+kana/Hangul/Bopomofo exemptions",
    ))
}

/// Canonicalize the **local part** of a `local@…` name: NFC + lowercase (simple case fold), one
/// single-script label. The whole local part (subaddress `+tag` included — `+` is script-`Common`)
/// is treated as ONE label: a cross-`.` script mix inside a local part is still a spoofing
/// surface, so the stricter whole-part reading is the fail-closed one.
pub fn canonical_local(local: &str) -> Result<String, ResolveError> {
    if local.is_empty() {
        return Err(ResolveError::MalformedName("empty local part"));
    }
    let folded = nfc_lower(local);
    check_single_script_label(&folded)?;
    Ok(folded)
}

/// Canonicalize a **DNS domain** via UTS-46/IDNA: the canonical stored/compared form is the
/// **A-label** (ASCII/punycode) form, so a U-label, an A-label, and any NFC/NFD/case spelling of
/// one domain all collapse to a single identity — and DNS qnames are always built from A-labels.
/// The mixed-script gate runs per label over the **U-label** (display) form, because that is the
/// form a human is spoofed with. `domain_to_ascii_strict` enforces STD3 + DNS length rules —
/// fail-closed on anything that is not a real hostname.
pub fn canonical_domain(domain: &str) -> Result<String, ResolveError> {
    let (unicode, mapping) = idna::domain_to_unicode(domain);
    mapping.map_err(|_| ResolveError::MalformedName("domain fails UTS-46/IDNA processing"))?;
    for label in unicode.split('.') {
        check_single_script_label(label)?;
    }
    idna::domain_to_ascii_strict(domain)
        .map_err(|_| ResolveError::MalformedName("domain fails UTS-46/IDNA processing"))
}

/// **The funnel**: canonicalize any name form (§3.12.4) — the one function every entry point
/// (parse, classify, KT leaf computation, `Identity.names` comparison, pin/petname keys) routes
/// through, so "two spellings, one identity" holds everywhere or nowhere. Dispatch mirrors
/// [`crate::restype::classify`]'s form rules; it must, or a name could canonicalize under one
/// form and route under another.
pub fn canonical_name(name: &str) -> Result<String, ResolveError> {
    let name = name.trim();

    // `@handle` (§3.9.2): the directory type is not implemented here (classify fails it closed),
    // but the canonical form is still defined so a future directory build inherits the same rules.
    if let Some(handle) = name.strip_prefix('@') {
        let folded = nfc_lower(handle);
        check_single_script_label(&folded)?;
        return Ok(format!("@{folded}"));
    }

    if let Some((local, ns)) = name.split_once('@') {
        let local = canonical_local(local)?;
        let ns_folded = nfc_lower(ns);
        // Chain namespaces (`alice@.eth`, §3.13) and non-domain namespaces are NOT DNS: no IDNA
        // (punycoding `.eth` would invent an identity DNS never serves), but the same NFC +
        // lowercase + single-script rules apply — a chain label is exactly as spoofable.
        if ns_folded.starts_with('.') || !ns_folded.contains('.') {
            for label in ns_folded.split('.') {
                check_single_script_label(label)?;
            }
            return Ok(format!("{local}@{ns_folded}"));
        }
        let domain = canonical_domain(ns)?;
        return Ok(format!("{local}@{domain}"));
    }

    // Bare forms: chain (`vitalik.eth`), key-name (ASCII word-list — a fixed point of this fold),
    // petname. NFC + lowercase + per-label single-script.
    let folded = nfc_lower(name);
    for label in folded.split('.') {
        check_single_script_label(label)?;
    }
    Ok(folded)
}

/// Fold one character onto its Latin/ASCII look-alike — the v0 UTS-39 confusables **subset**
/// (see the module docs for the honest scope statement). Input is already lowercased + NFD.
fn confusable_fold(c: char) -> char {
    match c {
        // Cyrillic → Latin (the IDN-homograph workhorses).
        'а' => 'a', // U+0430
        'е' => 'e', // U+0435
        'о' => 'o', // U+043E
        'р' => 'p', // U+0440
        'с' => 'c', // U+0441
        'у' => 'y', // U+0443
        'х' => 'x', // U+0445
        'і' => 'i', // U+0456
        'ѕ' => 's', // U+0455
        'ј' => 'j', // U+0458
        'һ' => 'h', // U+04BB
        'ӏ' => 'l', // U+04CF palochka — the `аррӏе.com` letter
        'ԁ' => 'd', // U+0501
        'ԛ' => 'q', // U+051B
        'ԝ' => 'w', // U+051D
        'ѡ' => 'w', // U+0461
        'ѵ' => 'v', // U+0475
        'к' => 'k', // U+043A
        'м' => 'm', // U+043C
        // Greek → Latin.
        'ο' => 'o', // U+03BF
        'ν' => 'v', // U+03BD
        'ι' => 'i', // U+03B9
        'κ' => 'k', // U+03BA
        'ρ' => 'p', // U+03C1
        'τ' => 't', // U+03C4
        'υ' => 'u', // U+03C5
        'χ' => 'x', // U+03C7
        'ω' => 'w', // U+03C9
        'α' => 'a', // U+03B1
        'ε' => 'e', // U+03B5
        'η' => 'n', // U+03B7
        'γ' => 'y', // U+03B3
        // Latin strays UTS-46 does not already compatibility-fold.
        'ı' => 'i', // U+0131 dotless i
        'ɩ' => 'i', // U+0269
        'ɡ' => 'g', // U+0261 script g
        // Digit homoglyphs.
        '1' => 'l',
        '0' => 'o',
        other => other,
    }
}

/// The UTS-39-informed **skeleton** of a name: lowercase + NFD, then [`confusable_fold`] per
/// character. Two names with equal skeletons are treated as confusable at pin time. Computed over
/// the **display (U-label)** form — an A-label (`xn--…`) is pure ASCII and would never collide
/// with the Latin name it imitates, so a punycoded domain is decoded back to Unicode first.
pub fn skeleton(name: &str) -> String {
    let display = match name.split_once('@') {
        // Only a DNS-form namespace round-trips through IDNA; chain/bare namespaces are kept.
        Some((local, ns)) if ns.contains('.') && !ns.starts_with('.') => {
            let (unicode, _) = idna::domain_to_unicode(ns);
            format!("{local}@{unicode}")
        }
        _ => name.to_owned(),
    };
    nfc_lower(&display).nfd().map(confusable_fold).collect()
}

/// Pin-time confusables gate: does `candidate` skeleton-collide with a **different** existing
/// pinned/petnamed name? Returns the colliding name (for the caller's alert UI) or `None` when the
/// candidate is safe. An exact re-pin of the same canonical name is never a collision.
pub fn find_confusable<'a, I>(candidate: &str, existing: I) -> Option<&'a str>
where
    I: IntoIterator<Item = &'a str>,
{
    let sk = skeleton(candidate);
    existing
        .into_iter()
        .find(|e| *e != candidate && skeleton(e) == sk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_case_folds_to_one_canonical_form() {
        assert_eq!(
            canonical_name("ALICE@Example.COM").unwrap(),
            canonical_name("alice@example.com").unwrap()
        );
        assert_eq!(canonical_name("ALICE@Example.COM").unwrap(), "alice@example.com");
    }

    #[test]
    fn u_label_and_a_label_are_one_identity() {
        let u = canonical_name("alice@bücher.example").unwrap();
        let a = canonical_name("alice@xn--bcher-kva.example").unwrap();
        assert_eq!(u, a);
        assert_eq!(u, "alice@xn--bcher-kva.example", "canonical domain form is the A-label");
        // Idempotent: canonicalizing a canonical name is a no-op.
        assert_eq!(canonical_name(&u).unwrap(), u);
    }

    #[test]
    fn nfd_and_nfc_spellings_are_one_identity() {
        // ü precomposed (NFC) vs u + combining diaeresis (NFD) — same identity both sides of the @.
        let nfc = canonical_name("j\u{00FC}rgen@b\u{00FC}cher.example").unwrap();
        let nfd = canonical_name("ju\u{0308}rgen@bu\u{0308}cher.example").unwrap();
        assert_eq!(nfc, nfd);
    }

    #[test]
    fn mixed_script_label_rejected_0x0121() {
        // The classic homograph: Latin p-y-p-a-l + Cyrillic а in ONE label.
        let err = canonical_name("alice@p\u{0430}ypal.com").unwrap_err();
        assert!(matches!(err, ResolveError::MixedScriptLabel(_)));
        assert_eq!(err.code(), 0x0121);
        // Also rejected in the local part and in bare (petname/chain) forms.
        assert!(matches!(
            canonical_name("p\u{0430}ypal@example.com"),
            Err(ResolveError::MixedScriptLabel(_))
        ));
        assert!(matches!(
            canonical_name("p\u{0430}ypal"),
            Err(ResolveError::MixedScriptLabel(_))
        ));
    }

    #[test]
    fn cjk_exemptions_pass_the_mixed_script_gate() {
        // Han + Katakana in one label (Japanese) — conventional, allowed.
        assert!(canonical_name("alice@東京テスト.example").is_ok());
        // Han + Hiragana.
        assert!(canonical_name("alice@ほん本.example").is_ok());
        // Han + Hangul (Korean).
        assert!(canonical_name("alice@한국漢.example").is_ok());
        // Han + Bopomofo.
        assert!(canonical_name("alice@ㄅㄆ漢.example").is_ok());
        // …but Han + Cyrillic is NOT a conventional combination.
        assert!(matches!(
            canonical_name("alice@漢д.example"),
            Err(ResolveError::MixedScriptLabel(_))
        ));
    }

    #[test]
    fn single_script_cyrillic_domain_is_accepted() {
        // An honest all-Cyrillic name is not collateral damage: per-label single-script passes,
        // and the canonical form is its A-labels.
        let c = canonical_name("иван@почта.рф").unwrap();
        assert!(c.starts_with("иван@xn--"), "domain must canonicalize to A-labels: {c}");
    }

    #[test]
    fn skeleton_folds_the_cyrillic_apple_spoof_onto_latin() {
        // `аррӏе` = Cyrillic а-р-р-ӏ(palochka)-е — single-script, so it passes the label gate,
        // which is exactly why the pin-time skeleton must catch it.
        assert_eq!(skeleton("аррӏе.com"), skeleton("apple.com"));
        // …including through the canonical (A-label) form of the domain.
        let canonical = canonical_name("alice@аррӏе.com").unwrap();
        assert!(canonical.contains("xn--"));
        assert_eq!(skeleton(&canonical), skeleton("alice@apple.com"));
        // Digit homoglyphs fold too.
        assert_eq!(skeleton("paypa1.com"), skeleton("paypal.com"));
        // Honest distinct names do NOT collide.
        assert_ne!(skeleton("apple.com"), skeleton("orange.com"));
    }

    #[test]
    fn find_confusable_flags_collisions_but_not_self() {
        let pinned = ["alice@apple.com", "bob@example.com"];
        // The Cyrillic spoof of an existing pin is flagged, and the colliding pin is named.
        let spoof = canonical_name("alice@аррӏе.com").unwrap();
        assert_eq!(
            find_confusable(&spoof, pinned.iter().copied()),
            Some("alice@apple.com")
        );
        // Re-pinning the exact same name is never a collision.
        assert_eq!(find_confusable("alice@apple.com", pinned.iter().copied()), None);
        // An unrelated name is safe.
        assert_eq!(find_confusable("carol@other.net", pinned.iter().copied()), None);
    }

    #[test]
    fn keynames_and_chain_forms_are_fixed_points() {
        // A key-name (ASCII lowercase word-list) canonicalizes to itself.
        assert_eq!(canonical_name("bafu-koda-mel-zorv").unwrap(), "bafu-koda-mel-zorv");
        // Chain forms fold case but are never punycoded (`.eth` is not DNS).
        assert_eq!(canonical_name("Vitalik.ETH").unwrap(), "vitalik.eth");
        assert_eq!(canonical_name("Alice@.eth").unwrap(), "alice@.eth");
    }
}

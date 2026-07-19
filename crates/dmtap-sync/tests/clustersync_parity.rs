//! **Parity with the §5.6 reference** (`dmtap-clustersync`).
//!
//! `SYNC.md` §1 is explicit that the substrate's semantics are *grounded in* §5.6, and that where
//! the two agree, §5.6 remains the normative home of the single-owner device-cluster profile. This
//! crate therefore must not quietly re-invent the three CRDTs it inherits: for the same logical
//! inputs, its [`OrSet`](dmtap_sync::OrSet), [`LwwMap`](dmtap_sync::LwwMap) and
//! [`DeathReg`](dmtap_sync::DeathReg) must reach the same decisions as the reference.
//!
//! The types cannot be *shared* — §5.6's HLC is `device`-flavoured and its value type is core's
//! unsigned-integer-only `Cv`, while the substrate's `cv` must also carry negative integers (§4.1)
//! — so the reuse obligation is discharged here, executably: same ops in, same observable answer
//! out, including the exact-tie tiebreaks that are the easiest thing to get subtly wrong.

use dmtap_clustersync as cs;
use dmtap_core::cbor::Cv;
use dmtap_sync as sy;

const WALL: u64 = 1_700_000_100_000;

fn author(seed: u8) -> Vec<u8> {
    vec![seed; 32]
}

fn sy_hlc(counter: u32, a: u8) -> sy::Hlc {
    sy::Hlc { wall: WALL, counter, author: author(a) }
}

fn cs_hlc(counter: u32, a: u8) -> cs::Hlc {
    cs::Hlc { wall: WALL, counter, device: author(a) }
}

fn sy_tag(counter: u32, a: u8) -> sy::AddTag {
    sy::AddTag { author: author(a), hlc: sy_hlc(counter, a) }
}

fn cs_tag(counter: u32, a: u8) -> cs::AddTag {
    cs::AddTag { device: author(a), hlc: cs_hlc(counter, a) }
}

#[test]
fn orset_presence_agrees_with_the_reference() {
    // A remove that observed only the FIRST add: add-wins keeps the element present in both.
    let element = "e1";
    let sv = sy::SVal::Text(element.into());

    let mut a = sy::OrSet::new();
    a.add("tags", &sv, sy_tag(0, 0xcc));
    a.add("tags", &sv, sy_tag(2, 0xcc));
    a.remove("tags", &sv, &[sy_tag(0, 0xcc)]);

    let mut b = cs::OrSet::new();
    b.add(element, cs_tag(0, 0xcc));
    b.add(element, cs_tag(2, 0xcc));
    b.remove(element, &[cs_tag(0, 0xcc)]);

    assert_eq!(a.contains("tags", &sv), b.contains(element));
    assert!(a.contains("tags", &sv));

    // Now tombstone BOTH adds: absent in both.
    a.remove("tags", &sv, &[sy_tag(2, 0xcc)]);
    b.remove(element, &[cs_tag(2, 0xcc)]);
    assert_eq!(a.contains("tags", &sv), b.contains(element));
    assert!(!a.contains("tags", &sv));
}

#[test]
fn lww_winner_agrees_with_the_reference_including_the_exact_tie() {
    for (h1, h2) in [(0u32, 1u32), (5, 5)] {
        let mut a = sy::LwwMap::new();
        a.set("doc1", "title", sy_hlc(h1, 0xcc), sy::SVal::Text("m".into()));
        a.set("doc1", "title", sy_hlc(h2, 0xcc), sy::SVal::Text("n".into()));

        let mut b = cs::LwwMap::new();
        b.set("doc1", "title", cs_hlc(h1, 0xcc), Cv::Text("m".into()));
        b.set("doc1", "title", cs_hlc(h2, 0xcc), Cv::Text("n".into()));

        let got = a.get("doc1", "title").and_then(sy::SVal::as_text).unwrap().to_string();
        let want = match b.get("doc1", "title") {
            Some(Cv::Text(t)) => t.clone(),
            other => panic!("reference produced {other:?}"),
        };
        assert_eq!(got, want, "LWW winner diverged at ({h1}, {h2})");
        // At the exact tie the larger encoded value wins in BOTH: "n" > "m".
        assert_eq!(got, "n");
    }
}

#[test]
fn death_certificate_agrees_with_the_reference_including_the_tie_fail_safe() {
    let mut a = sy::DeathReg::new();
    let mut b = cs::DeathReg::new();

    // Exact-HLC tie between `Deleted` and `Live`: remove-wins in both.
    a.write("rec2", sy_hlc(7, 0xcc), sy::DeathState::Deleted(sy::DeathClass::Redact));
    a.write("rec2", sy_hlc(7, 0xcc), sy::DeathState::Live);
    b.write("rec2", cs_hlc(7, 0xcc), cs::DeathState::Deleted(cs::DeleteClass::Redact));
    b.write("rec2", cs_hlc(7, 0xcc), cs::DeathState::Live);
    assert_eq!(a.is_deleted("rec2"), b.is_deleted("rec2"));
    assert!(a.is_deleted("rec2"));

    // Only a strictly greater HLC revives — in both.
    a.write("rec2", sy_hlc(8, 0xcc), sy::DeathState::Live);
    b.write("rec2", cs_hlc(8, 0xcc), cs::DeathState::Live);
    assert_eq!(a.is_deleted("rec2"), b.is_deleted("rec2"));
    assert!(!a.is_deleted("rec2"));
}

#[test]
fn hlc_total_order_agrees_with_the_reference() {
    let pairs = [((1u32, 0xccu8), (2u32, 0xccu8)), ((3, 0xcc), (3, 0xdd)), ((4, 0xdd), (4, 0xcc))];
    for ((c1, a1), (c2, a2)) in pairs {
        assert_eq!(
            sy_hlc(c1, a1).cmp(&sy_hlc(c2, a2)),
            cs_hlc(c1, a1).cmp(&cs_hlc(c2, a2)),
            "HLC order diverged for ({c1},{a1:#x}) vs ({c2},{a2:#x})"
        );
    }
}

#[test]
fn the_hlc_wire_encoding_is_byte_identical_to_the_reference() {
    // §3's grounding claim in bytes: the substrate HLC map {1: wall, 2: counter, 3: author} is the
    // very same encoding §18.6.3 already specifies (with `device` renamed to `author`).
    let sy_bytes = sy_hlc(3, 0xcc).det_cbor();
    let cs_bytes = dmtap_core::cbor::encode(&cs_hlc(3, 0xcc).to_cv());
    assert_eq!(sy_bytes, cs_bytes);
}

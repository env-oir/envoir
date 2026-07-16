# dmtap-core / dmtap-naming fuzz targets

`cargo-fuzz` (libFuzzer) targets over `dmtap-core`'s canonical-CBOR **decoders** — the real
attack surface: every one of these functions is called with fully attacker-controlled bytes
before any signature is checked. One target per decodable wire object (§18):

| target | decodes |
|---|---|
| `identity` | `dmtap_core::identity::Identity` |
| `device_cert` | `dmtap_core::identity::DeviceCert` |
| `recovery_policy` | `dmtap_core::identity::RecoveryPolicy` |
| `move_record` | `dmtap_core::identity::MoveRecord` |
| `envelope` | `dmtap_core::mote::Envelope` |
| `payload` | `dmtap_core::mote::Payload` |
| `manifest` | `dmtap_core::mote::Manifest` |
| `mix_node_descriptor` | `dmtap_core::mixnet::MixNodeDescriptor` |
| `mix_directory` | `dmtap_core::mixnet::MixDirectory` |
| `domain_directory` | `dmtap_core::directory::DomainDirectory` |
| `deniable_prekey_bundle` | `dmtap_core::deniable::DeniablePrekeyBundle` |
| `deniable_frame` | `dmtap_core::deniable::DeniableFrame` (both `Init`/`Message` discriminators) |
| `deniable_payload` | `dmtap_core::deniable::DeniablePayload` |
| `capability_token` | `dmtap_core::capability::CapabilityToken` (§13.5, §18.7.3) |
| `capability_revocation` | `dmtap_core::capability::CapabilityRevocation` (§18.7.3) |
| `kt_sth` | `dmtap_core::kt::SignedTreeHead` (§18.4.9) |
| `kt_inclusion_proof` | `dmtap_core::kt::InclusionProof` (§18.4.10) |
| `kt_consistency_proof` | `dmtap_core::kt::ConsistencyProof` (§18.4.11) |

Plus two families with a **different** wire shape, each with its own contract (see below):

| target | decodes | wire shape |
|---|---|---|
| `sphinx_cell` | `dmtap_core::sphinx::SphinxCell` (§18.5.4) | fixed-length binary, not CBOR |
| `sphinx_routing_command` | `dmtap_core::sphinx::RoutingCommand` (§18.5.4) | fixed-length binary |
| `sphinx_surb` | `dmtap_core::sphinx::Surb` (§18.5.4) | fixed-length binary |
| `sphinx_fragment_header` | `dmtap_core::sphinx::SphinxFragmentHeader` (§18.5.4) | fixed-length binary |
| `dns_txt` | `dmtap_naming::dns::DmtapTxtRecord` (§3.2) | DNS TXT presentation text |
| `dns_svcb` | `dmtap_naming::dns::DmtapSvcbRecord` (§3.2) | DNS SVCB presentation text |

## Contract each target enforces (`fuzz_targets/common.rs`, `fuzz_targets/naming_common.rs`)

Every target proves, at minimum:

1. **Never panic / never UB** on any input. This is checked simply by calling the decoder inside
   the fuzz harness; a Rust panic or a sanitizer-caught UB *is* the crash libFuzzer reports.

For the canonical-CBOR targets (everything above the "different wire shape" table, checked by
`common::check_roundtrip`), it additionally proves:

2. Any `Ok(_)` decode result **re-encodes to byte-identical input** — canonical-form idempotence
   (§18.1.1). A decoder that accepts a non-canonical encoding of the same semantic object is a
   bug: two implementations (or the same node at two points in time) could disagree about whether
   two different byte-strings are "the same" object.

Property 2 is checked **non-fatally by default** (logged once to stderr) and **fatally** when the
environment variable `DMTAP_FUZZ_STRICT_CANONICAL` is set — see "Known finding" below for why.

The four `sphinx_*` targets reuse the same `common::check_roundtrip` byte-identical check, but for
them it is expected to **always hold** (never trip, even under `DMTAP_FUZZ_STRICT_CANONICAL=1`):
Sphinx is a fixed-length binary layout (§18.5.4), not canonical CBOR, so there is no non-shortest-
int / key-ordering malleability to find — `from_bytes` accepts exactly one byte-length per type and
rejects any input that isn't already in the one valid shape (reserved-must-be-zero, unknown `cmd`,
wrong length), so its own encode necessarily reproduces the input. Verified: `DMTAP_FUZZ_STRICT_CANONICAL=1 cargo +nightly fuzz run sphinx_cell -- -max_total_time=5` finds nothing.

The two `dns_*` targets are **not** canonical-CBOR and use a different helper
(`naming_common::check_decode_encode_decode`) because the DNS `_dmtap` TXT/SVCB presentation format
(§3.2) is explicitly *not* a deterministic wire format — whitespace/field-order/comma-spacing
variation is legitimate for the same semantic record, so "re-encodes to byte-identical input" would
be the wrong (and would falsely flag benign formatting differences as bugs) property here. Instead:
`decode(data) = Ok(v)` implies `decode(encode(v)) = Ok(v2)` with `v2 == v` — literal
decode∘encode∘decode stability. `dns_svcb` has no round-trip check at all: `DmtapSvcbRecord`'s
current API is parse-only (no serializer exists), a real, documented scope limit — see the target's
own doc comment.

## Running

```sh
# one target, short smoke run (what the verification gate uses):
cargo +nightly fuzz run envelope -- -max_total_time=5

# a real campaign (long-running):
cargo +nightly fuzz run envelope

# just prove everything builds, without running:
cargo +nightly fuzz build
```

A small seed corpus (`corpus/<target>/`) is checked in — the exact bytes from
`dmtap-core/vectors.json`'s `cbor_*`/`sphinx_*` vectors (plus two hand-generated seeds for
`recovery_policy`/`move_record`, which have no committed vector today, and hand-written valid
TXT/SVCB presentation strings for `dns_txt`/`dns_svcb`, which aren't in `vectors.json` at all) — so
every target starts from known-valid input rather than an empty corpus.

**Do not commit libFuzzer's discovered corpus growth.** Running any target locally (even a short
`-max_total_time=N` smoke run) has libFuzzer write every new-coverage input it finds back into
`corpus/<target>/` — that's normal fuzzing behavior, but it means a local run can leave thousands of
generated files sitting in a directory meant to hold a small, deliberate seed set. Before
committing, diff `corpus/` against HEAD and drop anything you didn't put there on purpose (e.g.
`git status --porcelain -- fuzz/corpus | ...` then `git clean -fd` the polluted target directories).

## Known finding: canonical-form is not yet enforced at decode time

Running any target for even a few seconds with `DMTAP_FUZZ_STRICT_CANONICAL=1` set reliably finds
a "crash" — this is not a bug in the fuzz harness. `dmtap_core::cbor::decode` (the shared
low-level canonical-CBOR primitive every `from_det_cbor` is built on) currently rejects duplicate
keys, floats, CBOR `null`/tags/undefined — but does **not** reject non-shortest-form integers,
indefinite-length items, or a map whose keys are not in bytewise-ascending order (see
`dmtap-core/src/cbor.rs`'s `decode`/`from_map`). Every object decoder reads fields by key via
`Fields::req`/`take`, which is independent of a map's on-the-wire key order or how long-winded
each integer's encoding is — so re-ordering an object's top-level keys, or re-encoding one of its
integers in a longer-than-minimal form, still decodes to a bit-for-bit-identical semantic object,
whose canonical re-encoding (`det_cbor()`) then differs from the input bytes that were accepted.

This is the same root cause behind three specific, hand-picked gaps the sibling
`crates/conformance-runner` reports against the `../dmtap` spec repo's conformance-suite catalog
(`DMTAP-CBOR-05` non-shortest-int, `DMTAP-CBOR-06` indefinite-length, `DMTAP-CBOR-07`
descending-key-order — all status `self-contained`, all currently FAIL) — fuzzing here shows the
same gap is **systemic**: it reaches every wire object in the crate, not just the low-level `Cv`
primitive those three cases exercise directly.

**Why this isn't fixed here:** this task's scope is limited to `crates/conformance-runner/`,
`fuzz/`, and new test files under `crates/dmtap-core/tests/` — `dmtap-core/src/cbor.rs` itself is
out of bounds. The fix (when someone picks it up) is at the `cbor::decode`/`from_map` layer:
track each integer's *encoded byte length* against `write_head`'s shortest-form rule, and require
`Cv::Map` keys to already be in bytewise-ascending order on input (mirroring the ordering `encode`
already produces), rejecting otherwise with `CborError::Malformed`. Once that lands, flip this
harness back to `DMTAP_FUZZ_STRICT_CANONICAL=1`-by-default (or just remove the toggle) — the
default-mode smoke run will then need to stay green with the stricter check, which is exactly the
regression protection this harness is for.

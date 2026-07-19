# envoir-node

Reference implementation of the DMTAP **node** — the whole client side. One binary, installed
on any always-on box; it *is* the mesh.

See the DMTAP spec repo ([`../dmtap/`](../dmtap/)) for the normative specification. This crate
is a **reference, not normative** (spec §10.4).

## Native-only (spec §8.5)

The node runs the libp2p **mesh**, the **Send API** (§13.5.1), and **JMAP** (§8.1) — JMAP is the
node's native, and only, client surface. It does **not** run any legacy protocol server: the
IMAP/POP3/SMTP-submission surfaces live **only on the separate `envoir-gateway`** (spec §7). There
are therefore no `ENVOIR_IMAP_PORT`/`ENVOIR_POP3_PORT`/`ENVOIR_SMTP_PORT`/`ENVOIR_MAIL_HOST` knobs
on the node.

## DMTAP-PUB serving (spec §22.5/§22.6, opt-in)

The node can optionally serve its own public objects (feed head/range, announce, manifest, chunk)
over plain HTTP to anyone, at the five well-known paths under `crate::pubserve::WELL_KNOWN_BASE`.
This is **off by default** — set `ENVOIR_PUB_SERVE=1` to turn it on, and optionally
`ENVOIR_PUB_BIND` to change its bind address (default `0.0.0.0:4680`, deliberately not loopback:
unlike JMAP this surface is meant to be reached by other peers off-box).

**Security note:** turning this on is a real disclosure decision, not a no-op. Public reads are
unauthenticated by design (§22.5.1) — anyone who can reach the port can read anything the gateway
serves. The daemon only ever enables the listener after presenting itself a genuine, verified
`pub-1` [`CapabilityToken`] through the same fail-closed `enable_with_capability` path a remote
grant would use (self-host: operator == node); it never bypasses that check. A node that never
sets `ENVOIR_PUB_SERVE` advertises no `pub-1` grant and is never expected to serve public objects
at all (§22.6.1) — that remains the safe default.

## Modules (planned)

| Module | Spec | Responsibility |
|--------|------|----------------|
| `identity` | §1 | Keys, device certs, recovery policy + rotation, migration |
| `mote`     | §2 | The MOTE object: build, seal, verify, content-address |
| `naming`   | §3 | name→key resolution, TOFU pinning, key transparency |
| `transport`| §4 | libp2p mesh, mixnet client, reachability ladder, delivery/retry |
| `messaging`| §5 | MLS groups, prekeys/KeyPackages, chat, files (chunked blobs) |
| `privacy`  | §6 | sealed sender, cover traffic, padding, privacy tiers |
| `clients`  | §8.1 | JMAP — the node's native, and only, client surface (native-only, §8.5) |
| `pubserve` | §22 | DMTAP-PUB gateway serving: the five well-known GET endpoints (feed head/range, announce, manifest, chunk) behind the `pub-1` operator opt-in, plus pin storage + author-feed publish/append |
| `abuse`    | §9 | recipient policy, anonymous tokens, PoW, postage |
| `store`    | §2,§5 | encrypted-at-rest mailbox + blob store + device-cluster CRDT |

## Build

```sh
cargo build            # scaffold builds std-only; deps are commented in Cargo.toml
cargo run -- --help
```

## Status

Pre-alpha scaffold. Types mirror the spec; logic is stubbed with `todo!()`/`TODO`. The
dependency stack in `Cargo.toml` is the intended, standards-grounded reference (HPKE/MLS/
libp2p/…); uncomment as each subsystem is implemented.

## Key implementation cautions (from spec grounding)

- **MLS handshake ordering:** Commit/Proposal/Welcome messages require a totally-ordered
  channel per group; they MUST NOT traverse the reordering mixnet. Application messages may.
- **Async join:** use MLS-native KeyPackages + external commits, not a bolted-on PQXDH.
- **Deniability:** MLS is non-repudiable by design; do not claim message deniability without
  engineering it at another layer.
- **Sealed sender** hides the sender from intermediaries but not the IP (the mixnet does that)
  and is metadata-*reduction*, not elimination.

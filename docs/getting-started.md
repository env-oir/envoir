# Getting Started

This walks through building the workspace and running the real, working pieces: the reference
node's delivery engine, its demo mail servers, the legacy gateway, and the web client. Every
command below is copied from the actual CLI entry points (`node/src/main.rs`,
`gateway/src/main.rs`) — nothing aspirational.

## Prerequisites

- Rust 1.75+ (stable toolchain; `cargo build --workspace` builds everything)
- Python 3 — only used to serve the static web apps (`client/`, `console/`, `superadmin/`,
  `status/`, `site/`) with `python3 -m http.server`; no npm, no build step, no CDN

## Build the workspace

```sh
git clone <this repo>
cd envoir
cargo build --workspace
```

The workspace ([`Cargo.toml`](../Cargo.toml)) has four member groups: `node`, `gateway`,
`integration` (cross-component tests), and every crate under `crates/*`.

## Run the node

`envoir-node` is a single CLI binary:

```sh
cargo run -p envoir-node -- <command>
```

| Command | What it does |
|---|---|
| `version` | Print the version and default crypto suite |
| `run` | Run the delivery engine: two in-process nodes exchange a real, end-to-end-encrypted MOTE over an in-memory transport (seal → validate → decrypt → ack) |
| `serve-mail` | Run the client-protocol servers — **real** IMAP (`:1143`), POP3 (`:1110`), and SMTP-submission (`:1587`) listeners against an in-memory mailbox, with a fixed demo app-password (`owner@dmtap.local` / `app-password`) |
| `init` | Not yet implemented — will generate a root identity key + recovery policy |
| `gateway` | Points you at the dedicated `envoir-gateway` binary below |
| `help` | Usage |

Try the delivery demo first — it's the clearest illustration of what's real today:

```sh
cargo run -p envoir-node -- run
```

You'll see Alice seal a MOTE to Bob, Bob validate/decrypt/store/ack it, and Alice's outbound queue
reach `ACKED` — the actual recipient-validation pipeline and sender-retry state machine running,
just over an in-process transport rather than the libp2p mesh (see [Roadmap](roadmap.md) for
what's stubbed).

To point a real mail client (or `curl` / `openssl s_client`) at the demo mail servers:

```sh
cargo run -p envoir-node -- serve-mail
```

## Run the gateway (optional)

`envoir-gateway` is the legacy SMTP bridge — only needed if you want to exchange mail with the
existing email world:

```sh
cargo run -p envoir-gateway -- run
```

Configure it with environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `GATEWAY_LISTEN` | `127.0.0.1:2525` | Bind address for the inbound MX listener |
| `GATEWAY_DOMAIN` | `localhost` | Domain this gateway is MX for |
| `GATEWAY_GW_SELECTOR` | `gw1` | DKIM / attestation selector |
| `GATEWAY_TLS_CERT` / `GATEWAY_TLS_KEY` | unset | PEM cert+key to enable STARTTLS; without them the listener runs in plaintext dev mode |
| `GATEWAY_DNS_SERVER` | `1.1.1.1:53` | DNS server for outbound MX + MTA-STS lookups |

The reference gateway wires up a real inbound MX listener, a real outbound SMTP-over-STARTTLS
transport, real DNS-based MX resolution, and real MTA-STS policy fetching. The recipient directory
and mesh-delivery hookup are left as operator-supplied seams (see
[`gateway/README.md`](../gateway/README.md)) — until wired to a real directory/mesh, inbound mail
is refused (`550`, the safe default) and outbound never durably acks (`451`, so the legacy
sender's own queue retries).

## Open the web client

```sh
cd client
python3 -m http.server 8095
# open http://localhost:8095
```

No build step, no framework, no npm. The client does real Ed25519 identity/signing and a real
deterministic safety-number derivation in the browser; mesh/mixnet delivery is a clearly-labeled
in-browser simulation (`mesh-sim.js`). See [features/identity.md](features/identity.md) and the
client's own [`README.md`](../client/README.md) for the exact real-vs-simulated line.

## Run the other apps

Each of these is the same "static folder, `python3 -m http.server`" pattern — see each one's own
`README.md` for what it does:

```sh
cd console    && python3 -m http.server 8097   # domain admin console
cd superadmin && python3 -m http.server 8098   # fleet operator console
cd status     && python3 -m http.server 8099   # public + personal status page
cd site       && python3 -m http.server 8096   # marketing/landing page
```

## Run the tests

```sh
cargo test --workspace              # everything that builds without extra tooling
cargo test -p dmtap-core            # canonical CBOR, conformance vectors, known-answer tests
cargo test -p dmtap-mail            # IMAP/POP3/SMTP/JMAP protocol core
cargo test -p dmtap-mail --features net   # + the real TCP literal-reader tests
cargo test -p envoir-gateway        # inbound/outbound gateway flows
cargo test -p integration           # cross-component adversarial + end-to-end tests
```

Formal verification and fuzzing need extra tooling and are covered in [security.md](security.md):

```sh
cd formal && ./run.sh               # ProVerif symbolic models (needs proverif or Docker)
cd fuzz   && cargo +nightly fuzz run envelope -- -max_total_time=5
```

## Where to go next

- [Architecture](architecture.md) for how the pieces fit together.
- [Protocol](protocol.md) for what DMTAP actually specifies.
- [Roadmap](roadmap.md) for an honest read on what's implemented vs. stubbed.

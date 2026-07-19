# Getting Started

This walks through building the workspace and running the real, working pieces: the reference
node's delivery engine and daemon, the legacy gateway (including its demo mail servers), and the
web client. Every command below is copied from the actual CLI entry points (`node/src/main.rs`,
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
| `init` | Generate a root Ed25519 identity + X25519 sealing keypair, persist them to a keystore, and print the `_dmtap` DNS record to publish |
| `run` (alias `serve`) | Run the real long-running node daemon — loads the keystore + durable outbound journal, binds the mesh transport, and serves until SIGINT/SIGTERM |
| `demo` | Run the delivery engine as a one-shot demo: two in-process nodes exchange a real, end-to-end-encrypted MOTE over an in-memory transport (seal → validate → decrypt → ack), then exit |
| `record` | Reload the keystore and print just its `_dmtap` DNS record |
| `gateway` | Points you at the dedicated `envoir-gateway` binary below |
| `help` | Usage |

Try the delivery demo first — it's the clearest illustration of what's real today:

```sh
cargo run -p envoir-node -- demo
```

You'll see Alice seal a MOTE to Bob, Bob validate/decrypt/store/ack it, and Alice's outbound queue
reach `ACKED` — the actual recipient-validation pipeline and sender-retry state machine running,
just over an in-process transport rather than the libp2p mesh (see [Roadmap](roadmap.md) for
what's stubbed).

To run the real daemon (persists identity + outbound queue, serves until stopped):

```sh
cargo run -p envoir-node -- init   # once, to create a keystore
cargo run -p envoir-node -- run    # the daemon; Ctrl-C to stop
```

Legacy IMAP/POP3/SMTP-submission clients aren't served by the node — only the separate
`envoir-gateway` binary speaks those protocols (see below). The node's own client-sync surface is
JMAP, opt-in via `ENVOIR_JMAP=1` (see [`node/src/config.rs`](../node/src/config.rs) for the full
`ENVOIR_*` environment reference).

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

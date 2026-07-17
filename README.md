# envoir-gateway

The **optional** legacy bridge between DMTAP and the SMTP world — and it can be **just a gateway for
your own email**. The only component that speaks SMTP and the only one not content-blind (the legacy
leg is unavoidably plaintext).

See the DMTAP spec repo, [`../dmtap/07-gateway.md`](../dmtap/07-gateway.md) (normative). A node with no legacy
correspondents never uses a gateway; at full DMTAP adoption it is unnecessary.

## Quickstart — a personal gateway for your own domain (2 commands)

You are one person bridging **your own** domain. No mesh, cloud, or billing required.

```sh
# 1. Scaffold config + recipient file + a DKIM key, and print the DNS records to publish:
./setup.sh your-domain.example --listen 0.0.0.0:2525

# 2. Run it:
cargo run -p envoir-gateway -- personal ./personal.toml
```

That's it — the daemon binds the inbound MX, wires the outbound/admission/quota seams, and serves
until `Ctrl-C`. Between the two commands you: (a) add your own identity line(s) to
`recipients.directory` (your address + the public keys your envoir node publishes), (b) publish the
DNS records `setup.sh` printed, and (c) point `mesh_endpoint` in `personal.toml` at your node's
ingest URL so delivered mail gets a durable ack (until then inbound returns `451` and the sender
retries — never a silent drop).

Prefer containers?

```sh
cd gateway
mkdir -p config && cp examples/personal.toml examples/recipients.directory config/   # then edit them
docker compose up --build
```

The example config is [`examples/personal.toml`](examples/personal.toml) (every key documented) and
the recipient-file format is [`examples/recipients.directory`](examples/recipients.directory).

### Configuration

`envoir-gateway personal <config.toml>` reads a flat `key = value` file; every key is optional with a
safe default (a fresh gateway resolves nobody and is **not** an open relay). Unknown keys and
malformed values are hard startup errors (fail-closed). `envoir-gateway run` takes the same settings
from `GATEWAY_*` environment variables instead (handy for systemd/containers). See
[`examples/personal.toml`](examples/personal.toml) or `envoir-gateway help` for the full key list:
`domain`, `listen`, `selector`, `dns_server`, `directory`, `mesh_endpoint`, `tls_cert`/`tls_key`,
`authz_mode` (`key-registered` default / `open-public`), `dkim_enforce`/`spf_enforce`/`dmarc_enforce`,
`quota_messages`/`quota_bytes`.

### DNS records you must publish for your domain

The gateway does **not** touch DNS — you publish these at your provider (`setup.sh` prints them filled
in for your domain and DKIM key):

| Record | Name | Value | Why |
| ------ | ---- | ----- | --- |
| MX | `your-domain.example` | `10 mx.your-domain.example` (→ this host's public IP) | route legacy inbound mail here |
| A/AAAA | `mx.your-domain.example` | this gateway's public IP | the MX target |
| SPF | `your-domain.example` TXT | `v=spf1 a:mx.your-domain.example -all` | authorize this IP to send as you |
| DKIM | `gw1._domainkey.your-domain.example` TXT | `v=DKIM1; k=ed25519; p=<pubkey>` | verify your outbound signatures (RFC 8463) |
| DMARC | `_dmarc.your-domain.example` TXT | `v=DMARC1; p=none; rua=mailto:postmaster@…` | alignment policy (start at `p=none`) |
| DMTAP | `<base-local>._dmtap.your-domain.example` TXT | `v=dmtap1; suite=1; ik=…; id=…; kt=…; keypkgs=…` | the DMTAP name→key pointer (spec §3.2) |

The `_dmtap` `ik`/`id`/`kt`/`keypkgs` values are produced by your **envoir node** (this gateway does
not mint identities); publish one per address you host. `selector` (`gw1` by default) is the DKIM
selector label.

### Be honest about what a real public gateway needs

- **A real public IPv4 and inbound TCP port 25.** Inbound legacy mail can only reach you if other
  MTAs can open port 25 to your host. Many residential/home ISPs **block inbound (and outbound) port
  25** — you need a VPS or a business line. For local testing use `listen = "127.0.0.1:2525"`.
- **IP reputation.** A brand-new sending IP has none; warm it up and keep `*_enforce` off until each
  check is trustworthy for your traffic. This is the one irreducible operational cost (below).
- **STARTTLS.** Set `tls_cert`/`tls_key` to a real certificate for your MX hostname (e.g. Let's
  Encrypt) for production; without them the listener is plaintext (dev only).
- **The generated DKIM private key** is for the DNS record you publish; wiring it into the
  node-driven outbound signing leg is a documented roadmap item, not auto-wired by the daemon.
- **Attestation key.** The reference daemon generates its gateway attestation key per boot; a
  persistent, DNS-published attestation selector is a production follow-up.

## What it does

- **Inbound** (legacy → DMTAP): act as MX, reject spam before `DATA` (RBL/SPF/DMARC/greylist),
  wrap the RFC 5322 message into an attested MOTE, encrypt to the recipient key, deliver into
  the mesh — or return SMTP `4xx` so the sending server retries. Stores nothing.
- **Outbound** (DMTAP → legacy): translate a `mail` MOTE to RFC 5322, DKIM-sign as the sender's
  domain via a **delegated selector** (the gateway never holds the user's DMTAP key), send via
  SMTP with MTA-STS/DANE. On failure the user's node retries. Stores nothing.

## Statelessness

Durability is punted to the edges: inbound → the legacy sender's SMTP retry; outbound → the
user's node retry queue. The gateway holds no queue and no mailbox — restart it freely.

## The one irreducible cost

**IP reputation** (warmup, feedback loops, blocklist remediation, abuse handling). This is the
only operationally heavy part of the whole system, and it is quarantined here and only to
legacy traffic. Per-identity accountability + operator stake keep a decentralized gateway pool
safe; postage (spec §9) can fund outbound sending.

## Status

Reference bridge implemented as a library (`envoir_gateway`) plus the `envoir-gateway` daemon,
std-only and synchronous, with all network effects behind traits so the full flows run in-process:

- **Personal run-mode** (`personal`): [`PersonalConfig`](src/personal.rs) composes the existing
  pieces — inbound `InboundGateway` (real DKIM/SPF/DMARC), the file-backed recipient
  [`directory`](src/directory.rs), the HTTP [`mesh`](src/mesh.rs) adapter, the outbound
  `OutboundGateway`, and the `IdentityRegistry` + `QuotaLedger` admission/quota seams — from one
  config file (or `GATEWAY_*` env for `run`). Fail-closed: a bad config never brings up a half-wired
  or accidentally-open gateway. The key-registered admission registry is seeded from the operator's
  own directory identities, so the same file that resolves inbound recipients authorizes them to
  relay outbound.
- **Inbound** (`inbound`): line-fed MX SMTP session with a pre-`DATA` anti-abuse gate, recipient-key
  resolution, real MOTE sealing to the recipient (`dmtap-core` HPKE), a domain-anchored gateway
  **attestation** (`attestation`, §7.2a), and the **ack-before-`250` / `451`-on-no-ack**
  silent-loss-avoidance rule (§19.7.1).
- **Outbound** (`outbound`): MOTE → RFC 5322, verifiable **delegated-selector DKIM** (`dkim`,
  ed25519-sha256 / relaxed-relaxed, RFC 8463 / RFC 6376) with a hard refusal to sign undelegated
  domains, plus **TLS enforcement** (MTA-STS/DANE policy hook) that refuses cleartext fallback.
- **Directory** (`directory`, §3): `FileDirectory` loads a `<email> <ik-b64> <seal-b64>` file
  (`InMemoryDirectory` is the in-code table it parses into); fail-closed parsing.
- **Mesh delivery** (`mesh`, §4): `HttpMeshDelivery` POSTs the converted MOTE to a node's ingest
  endpoint; a `2xx` is the durable-custody ack that permits SMTP `250`. `NullMesh` is the honest
  unconfigured default (never a silent drop).

Both `personal` and `run` are **real long-running daemons** that bind the MX listener and serve until
`SIGINT`/`SIGTERM`, then shut down gracefully (`MxListener::serve_until`). Covered by
`cargo test -p envoir-gateway`.

## Repo split

This component is intended to become its own `envoir-gateway` repository. The precise, mechanical
extraction runbook (and the precondition that must hold first) lives in [`SEPARATION.md`](SEPARATION.md).

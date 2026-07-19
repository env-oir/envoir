# envoir-gateway

The **optional** legacy bridge between DMTAP and the SMTP world — and it can be **just a gateway for
your own email**. The only component that speaks SMTP and the only one not content-blind (the legacy
leg is unavoidably plaintext).

The gateway is a member of the envoir monorepo workspace and builds its own `envoir-gateway`
binary alongside the node's `envoir-node`. The two shared libraries it needs, `dmtap-core` and
`dmtap-mail`, are plain workspace path deps (see [`Cargo.toml`](Cargo.toml)). It briefly lived as a
standalone repository — see [`SEPARATION.md`](SEPARATION.md) for that history and the boundary
discipline that keeps a future re-split cheap.

See the normative DMTAP spec, §7 "Gateway", in the spec repo:
[`env-oir/dmtap` → `07-gateway.md`](https://github.com/env-oir/dmtap/blob/main/07-gateway.md). A node
with no legacy correspondents never uses a gateway; at full DMTAP adoption it is unnecessary.

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
# from this repo root:
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
`quota_messages`/`quota_bytes`; legacy client access (§7.15, all off by default): `gateway_mode`
(`private` default / `registered-clients-only` / `public`), `imap_enable`/`imap_listen`/`imap_tls`,
`imap_credentials`, `imap_maildir`, `pop3_enable`/`pop3_listen`/`pop3_tls`,
`submission_enable`/`submission_listen`/`submission_tls`, `submission_spool`,
`submission_native_domains`.

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
- **EAI / SMTPUTF8 posture (RFC 6531) — deliberately asymmetric.** The inbound MX does **not**
  advertise `SMTPUTF8`: this v0 gateway cannot resolve a non-ASCII local part to a DMTAP recipient,
  and per RFC 6531 §3.1 a conforming EAI sender therefore bounces cleanly at its *own* MTA — an
  honest refusal, never a mangled address or a silent drop. (Everything else about inbound i18n is
  real: 8-bit `DATA` is carried byte-exact end-to-end, so ISO-8859-x/GB18030 bodies survive and
  DKIM verifies over the original bytes.) Outbound, the transport checks what each message actually
  needs against the destination's EHLO capabilities: an IDN recipient *domain* is converted to its
  A-label (punycode) form at the DNS/dial/SNI boundary and needs no extension at all, while a
  non-ASCII *local part* requires the peer to advertise `SMTPUTF8` (and an 8-bit body `8BITMIME`) —
  when the peer doesn't, the send fails with a specific permanent error naming the missing
  extension (`5.6.7` / `5.6.3`), because there is no lossless downgrade for an address, and
  re-encoding an already-DKIM-signed body would break the signature. What is **not** implemented:
  serving mailboxes under non-ASCII local parts, and generating internationalized DSNs (RFC 6533).

## What it does

- **Inbound** (legacy → DMTAP): act as MX, reject spam before `DATA` (RBL/SPF/DMARC/greylist),
  wrap the RFC 5322 message into an attested MOTE, encrypt to the recipient key, deliver into
  the mesh — or return SMTP `4xx` so the sending server retries. Stores nothing.
- **Outbound** (DMTAP → legacy): translate a `mail` MOTE to RFC 5322, DKIM-sign as the sender's
  domain via a **delegated selector** (the gateway never holds the user's DMTAP key), send via
  SMTP with MTA-STS/DANE. On failure the user's node retries. Stores nothing.
- **Legacy client access** (§7.15): serve the operator's own mailbox to old client apps
  (Thunderbird, Apple Mail, Outlook, mutt) over **IMAP**, **POP3**, and **SMTP-submission** —
  all optional, off by default, TLS-required, and app-password authenticated. See below.

## Legacy client access & the reachability ingress (§7.15)

The DMTAP node itself speaks only JMAP over the mesh and runs **no** legacy protocol server. Every
legacy client surface — and the ingress that carries a legacy client to it — is a **gateway** surface
(spec §7.15). This gateway can optionally serve:

| Surface | RFC | Direction | Config |
| ------- | --- | --------- | ------ |
| IMAP | 9051 / 3501 | read (folders/flags) | `imap_enable` |
| POP3 | 1939 | read (maildrop) | `pop3_enable` |
| SMTP-submission | 6409 | outbound (submit) | `submission_enable` |
| CalDAV / CardDAV | 4791 / 6352 | calendar/contacts | **not yet — see "Gaps" below** |

All three implemented surfaces are **OFF by default**, require `tls_cert`/`tls_key` (an app-password
must never travel in cleartext — the submission server additionally refuses `AUTH` on a cleartext
channel, `538`), and authenticate with **app-passwords** issued in `imap_credentials` (shared across
IMAP/POP3/submission). The read surfaces project the operator's own mailbox snapshot (`imap_maildir`)
and are **session-local** (mutations are not persisted back — the node stays the mailbox authority).
The submission server converts each accepted RFC 5322 message to a MOTE and hands it to a hand-off
**spool** directory (`submission_spool`) the operator's node picks up (native recipients → mesh,
legacy recipients → the §7.3 SMTP relay); the classification of *native* vs *legacy* is by
`submission_native_domains` (defaults to your own `domain`).

### The reachability ingress

A legacy client opens a raw protocol/TLS connection (IMAPS 993, POP3S 995, SMTPS 465, or the
STARTTLS/STLS variants on 143/110/587) to a hostname. Because DMTAP nodes have no static IP and
legacy clients cannot speak the mesh, **the gateway is the reachability ingress**: it accepts the
inbound legacy connection (routed by SNI / stream to the right mailbox), **terminates TLS**, and
speaks the legacy protocol against the mailbox. This is a gateway surface and is **distinct from** the
node's native mesh relay (which carries ciphertext-only, content-blind node↔node traffic and never
speaks a legacy protocol). The legacy protocol is spoken in the clear only *after* TLS is terminated
here.

### Honest privacy (§7.15.3) — a non-private gateway can read your mail

To speak IMAP/POP3/SMTP-submission the gateway **MUST decrypt** the mailbox — these protocols have no
notion of DMTAP object encryption. So a legacy client's mail is **visible in the clear to whatever
gateway serves it**: a gateway serving legacy clients is **not** content-blind for those clients.
This is unlike the node's native JMAP + mesh path, which is zero-access / zero-intermediary. Run your
**own** gateway (mode `private`) and no external party ever decrypts your mail; a public / third-party
gateway is a deliberate trust decision, equivalent to choosing a hosted mail provider.

### Operator modes (§7.15.4) — `gateway_mode`

The operator declares, and this gateway **enforces**, which accounts the legacy surfaces will serve:

| `gateway_mode` | Serves | Trust |
| -------------- | ------ | ----- |
| `private` (**default**) | a single operator — you, on your own gateway | zero third party can read the mail (you *are* the operator) |
| `registered-clients-only` | only your registered directory identities | same read-access for those users; not open to strangers |
| `public` | open registration — any provisioned account | the operator can read the mail of every user it serves |

The gate is fail-closed at startup: in `private` mode a credentials file naming more than one distinct
account is refused; in `registered-clients-only` every credential account must be present in
`directory`; `public` is unrestricted. Default is the most restrictive (`private`).

### Gaps (not faked)

**CalDAV (RFC 4791) / CardDAV (RFC 6352) are NOT implemented.** The shared `dmtap-mail` library
provides IMAP/POP3/SMTP/JMAP servers but **no DAV server**, so there is nothing to wire yet — the
gateway does not pretend to serve calendar/contacts. Projecting JSCalendar/JSContact MOTEs as
iCalendar/vCard for DAV clients is a documented follow-up (it needs a DAV server + iCalendar/vCard
projection in `dmtap-mail` first).

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

This is the split-out `envoir-gateway` repository. It was extracted from the `env-oir/envoir`
monorepo; the mechanical extraction runbook and the precondition that had to hold first (a published
monorepo tag for the shared crates) are recorded in [`SEPARATION.md`](SEPARATION.md) for history. The
gateway now depends on `dmtap-core` / `dmtap-mail` via a git tag rather than sibling path deps.

## Build & test

```sh
cargo build            # fetches the git-tag dmtap-core / dmtap-mail deps, then builds
cargo test             # ~240 tests (unit in-process + real-socket TLS legacy-access integration)
```

If your environment restricts anonymous git fetches, set `CARGO_NET_GIT_FETCH_WITH_CLI=true` so cargo
uses the git CLI (the monorepo is public, so plain https works).

## License

Licensed under either of

- Apache License, Version 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE))
- MIT license ([`LICENSE-MIT`](LICENSE-MIT))

at your option. Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in this crate by you, as defined in the Apache-2.0 license, shall be dual licensed as above,
without any additional terms or conditions.

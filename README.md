# envoir-gateway

The **optional** legacy bridge between DMTAP and the SMTP world. The only component that speaks
SMTP and the only one not content-blind (the legacy leg is unavoidably plaintext).

See the DMTAP spec repo, [`../dmtap/07-gateway.md`](../dmtap/07-gateway.md) (normative). A node with no legacy
correspondents never uses a gateway; at full DMTAP adoption it is unnecessary.

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

Reference bridge implemented as a library (`envoir_gateway`), std-only and synchronous, with all
network effects behind traits so the full flows run in-process:

- **Inbound** (`inbound`): line-fed MX SMTP session with a pre-`DATA` anti-abuse gate, recipient-key
  resolution, real MOTE sealing to the recipient (`dmtap-core` HPKE), a domain-anchored gateway
  **attestation** (`attestation`, §7.2a), and the **ack-before-`250` / `451`-on-no-ack**
  silent-loss-avoidance rule (§19.7.1).
- **Outbound** (`outbound`): MOTE → RFC 5322, verifiable **delegated-selector DKIM** (`dkim`,
  ed25519-sha256 / relaxed-relaxed, RFC 8463 / RFC 6376) with a hard refusal to sign undelegated
  domains, plus **TLS enforcement** (MTA-STS/DANE policy hook) that refuses cleartext fallback.

Abstract seams (`KeyDirectory`, `MeshDelivery`, `AntiAbuse`, `TlsPolicy`, `OutboundTransport`,
`GwKeyResolver`) are the only things a production deployment fills in with real sockets/DNS. The
`run` CLI subcommand is still a stub. Covered by `cargo test -p envoir-gateway`.

# The DMTAP Operator Seam — Contract

The seam is the boundary between the **open-source** DMTAP node/gateway and an **operator** —
anyone who runs a node or gateway for other people. It exists so an operator can add quotas,
usage accounting, and legacy-egress authorization **without forking the OSS or gating any
protocol/privacy feature**. Envoir itself is not a business and runs no control plane; this
contract is what lets someone else's operator tooling — including a billing system, if they want
one — attach cleanly.

There are two ways to implement the contract:

1. **In-process (Rust traits)** — a self-host binary embeds `dmtap-seam` (and, for a working
   reference implementation of quotas/usage-tracking/gateway-authz, the sibling `dmtap-operator`
   crate) and uses the default impls or its own.  This is the `Metering`, `Provisioning`,
   `Policy`, `GatewayAuthz`, `BillingSink` traits.
2. **Out-of-process (HTTP + events)** — an operator, possibly in another language, implements the
   same capabilities behind an HTTP API. The OSS ships a thin adapter that turns trait calls into
   HTTP calls.

Both expose the **same capabilities** and obey the **same invariants**.

## Invariants (MUST)

- **Privacy/crypto are never gated.** No seam call can disable encryption, weaken the mixnet,
  reduce metadata privacy, or deny a user access to their own keys/mailbox. The seam meters and
  limits *operations* (gateway egress, storage, relay bandwidth) and *organizational* concerns
  (accounts, quotas) only.
- **Self-host defaults are fully functional.** With no operator, the OSS runs unrestricted:
  `NullMetering` (nothing recorded), `SelfHostProvisioning` (single owner), `UnlimitedPolicy` (no
  limits), `OpenGatewayAuthz` (you are your own gateway), `NullBillingSink` (nothing exported —
  there is no billing system to export to).
- **Fail-open to function, fail-closed on unattributable legacy egress.** If the operator
  endpoint is unreachable, the OSS MUST NOT break user-facing mail/chat/files. Metering events
  queue locally and retry (usage may be under-counted during an outage — an accepted operator
  risk, documented, never a reason to drop a user's message). `Policy` falls back to a
  **configured** default (an operator chooses `allow` for graceful degradation or `deny` for hard
  quota enforcement; the OSS default is `allow` — this is a quota/organizational concern, not a
  security one). `GatewayAuthz` is the one exception: it MUST NOT fail open to a bare "allow" when
  the operator is unreachable (see §12.2 below) — unattributable legacy egress is exactly the
  open-relay failure mode accountability exists to prevent.
- **Sealed sender preserved.** `GatewayAuthz` attributes accountability to an anonymous token /
  postage / account — never requires the sender's identity in clear (spec §6.2, §9).

## Capability 1 — Metering

The OSS emits usage events at cost centers. Out-of-process shape:

```
POST /v1/metering/events
{ "events": [
    { "account": "acct_123", "kind": "gateway_send", "amount": 1, "ts_ms": 1737000000000 },
    { "account": "acct_123", "kind": "storage_bytes", "amount": 5242880, "ts_ms": ... }
] }
→ 202 Accepted   (operator enqueues; OSS retries on non-2xx)
```

`kind` ∈ `gateway_send | inbound_legacy | storage_bytes | relay_bytes | messages_sent |
vanity_domain`. Events are idempotent by `(account, kind, ts_ms, amount)` best-effort; the
operator dedups.

## Capability 2 — Provisioning

```
POST /v1/provision
{ "ik": "<base64url identity key>", "desired_name": "alice", "tier": "gateway_domain" }
→ 200 { "provisioned": { "id": "acct_123", "address": "alice@gw.example",
                          "tier": "gateway_domain", "suspended": false } }
→ 200 { "unavailable": { "reason": "name taken" } }
→ 200 { "pending_domain_setup": { "account": {...},
          "instructions": "Approve DNS via Domain Connect at <url>" } }   // tier C

GET  /v1/account/{id}          → 200 Account | 404
POST /v1/account/{id}/suspend  → 204
POST /v1/account/{id}/resume   → 204
```

`tier` ∈ `key_only | gateway_domain | vanity_domain` (spec §3.8 A/B/C).

## Capability 3 — Policy / entitlements

```
POST /v1/policy/check
{ "account": "acct_123", "quota": { "storage_bytes": 6000000000 } }
→ 200 { "allow": true }
→ 200 { "allow_with_remaining": 1200000000 }
→ 200 { "deny": { "reason": "storage limit reached" } }
```

`quota` is one of `storage_bytes | gateway_sends | domains | send_rate`. There is deliberately
**no** quota for any privacy/crypto capability. `dmtap-operator::policy::StaticQuotas` is a
working, flat-limit reference implementation — one number per dimension, no plans, no accounts
table.

## Capability 4 — Gateway authorization

```
POST /v1/gateway/authorize
{ "cred": { "account": "acct_123", "token": null, "postage": 0, "pow_bits": 0 } }
→ 200 { "allow": true }
→ 200 { "deny": { "reason": "monthly send cap reached" } }
```

For anonymous senders, `account` is null and accountability rides on `token` (ARC),
`postage`, or `pow_bits` (spec §9). The operator rate-limits/blocks per token without learning
identity.

### §12.2 — the safe default when the operator is unreachable

This is the one seam decision that MUST NOT fail open to a bare "allow". If an out-of-process
operator cannot be reached, `GatewayAuthz` falls back to permitting legacy egress **only** to:

1. already-established contacts (a fact the node/gateway can determine from its own history, no
   operator round-trip needed), or
2. senders carrying **self-contained** proof verifiable without the operator — postage or
   sufficient proof-of-work.

A bare ARC `token` is deliberately **not** honored in the fallback — validating/rate-limiting a
token requires the operator's registry, so it cannot authorize offline; that is exactly the
distinction from the online path, where a token IS honored because the operator can check it.
Everything else — cold, unproven, unestablished — is denied for the outage window.
`dmtap-operator::authz` is a tested reference implementation of exactly this rule (ported from an
earlier control-plane prototype, with billing-specific language stripped and the fail-closed
logic preserved bit-for-bit).

## Capability 5 — Billing export (optional; no shape mandated)

Unlike capabilities 1–4, this one has **no prescribed wire shape**, because Envoir does not
define what a billing system needs — Patala, once it exists, defines its own ingestion contract.
The seam only guarantees that `Metering`/usage-tracking hands an operator clean, deduplicated,
per-account/per-dimension totals ([`dmtap_seam::BillingSink`], [`dmtap_seam::UsageTotal`]) to
export however it likes. There is no currency, price, plan, or invoice type anywhere in this
contract, and there never will be — that logic belongs entirely to whatever billing system an
operator chooses to attach, or to none at all.

## Capability 6 — Prepaid postage (optional; provider-agnostic)

Spec §9.5 lets a gateway accept a **postage** stamp as one of three alternative accountability
mechanisms for legacy egress (alongside an ARC rate-limit token and proof-of-work). This
capability is the seam for the *prepaid* form of that: a sender tops up a credit balance once,
through whatever payment provider the operator has chosen, and the gateway draws it down locally
per send — never settling with the provider per message.

```
POST /v1/postage/topup
{ "account": "acct_123", "amount": { "minor_units": 500, "currency": "USD" }, "reference": "ref-1" }
→ 200 { "credited": { "new_balance": { "minor_units": 500, "currency": "USD" }, "reference": "ref-1" } }
→ 200 { "pending": { "reference": "ref-1" } }
→ 200 { "failed": { "reason": "postage is not enabled on this gateway" } }

GET  /v1/postage/balance/{account}
→ 200 { "account": "acct_123", "balance": { "minor_units": 200, "currency": "USD" } }
→ 404   (postage not tracked for this account)
```

`dmtap-seam::postage::PostageProvider` is the in-process trait ([`top_up`]/[`balance`]/[`spend`]);
`PostageGatedAuthz` composes it with any `GatewayAuthz` and is **off by default** — nothing
constructs one unless an operator opts in. **This capability names no payment provider anywhere in
its shape.** `patala` (a separate, already-real, non-custodial payment-rail substrate — see
`../../../patala/PATALA.md`) is exactly ONE way an operator could implement `top_up` (its Stellar
rail suits micropayment top-ups, ~$0.0001/tx); the sibling `dmtap-postage-patala` crate is that one
optional, isolated reference adapter. An operator is equally free to implement `top_up` against
Stripe, M-Pesa, or their own ledger — `dmtap-seam` and this contract are unaffected either way.

Like the other capabilities, postage never gates privacy/crypto: it composes only with
`GatewayAuthz`, the operations-only legacy-egress gate.

## Versioning

The HTTP contract is versioned under `/v1`. Unknown fields are ignored (forward-compatible);
the OSS and operator negotiate capabilities via `GET /v1/capabilities`. The in-process trait
API is versioned by the `dmtap-seam` crate semver.

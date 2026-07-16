# Self-Hosting

Envoir's self-host mode is not a crippled free tier — it is a complete product with every
protocol feature, every client, and every privacy guarantee a hosted operator would offer. A
hosted operator adds *convenience* (someone else runs the box, warms the legacy-mail IPs, manages
the domain), never *capability*. See spec §12.1 and
[architecture.md](../architecture.md#where-an-operators-billing-sits).

## Running your own `@yourdomain`

Any domain owner can run their own node and reach every other DMTAP user **natively over the
mesh, with no gateway and no operator at all** — this is what the spec calls the self-host
backstop, and it's a structural right, not a grant anyone can revoke. Native mesh delivery is
key-based and free, because nothing about it depends on a third party.

Onboarding has three tiers (spec §3.8), so you can start free and grow into full sovereignty:

| Tier | What it looks like | DNS work |
|---|---|---|
| A — no domain | A key plus a directory name; DMTAP-only, no legacy interop | None |
| B — provider domain | `you@gw.example`, a provider-issued address with legacy email already working | None — the provider maintains the shared domain's records for everyone |
| C — your own domain | `you@yourbrand.com`, full sovereignty | The provider auto-publishes records (Domain Connect / registrar API); you approve once |

## Running your own gateway

To exchange mail with the legacy world (`@gmail.com` and the like), you need a gateway — either
your own, self-hosted (`cargo run -p envoir-gateway -- run`, see
[getting-started.md](../getting-started.md#run-the-gateway-optional)), in which case you bear only
the IP-reputation warmup cost and owe nobody a bill, or a third-party operator's.

Switching gateways later costs nothing: DKIM delegation means changing a DNS record, not
migrating data, because the box — not the gateway — is the authority over your identity. If one
operator won't serve you, you can always run your own or switch to another.

## Billing is tied to the gateway only

DMTAP is explicit about who pays for what, and [transport-path provenance](transport-traceability.md)
makes it auditable:

- **Native mesh delivery is always $0.** Nothing about talking to another DMTAP user —
  encryption, the mixnet, key transparency, directory resolution — is ever metered or gated. This
  is an inviolable rule of the protocol's operator seam, not a pricing choice a particular
  operator happens to make.
- **Reaching the legacy world through *someone else's* gateway is the billable event.** Because
  every gateway-touched message carries a verifiable attestation naming the gateway and the time,
  you can independently confirm that a billed legacy send or receive corresponds to a real
  message that actually used the gateway — a pure-mesh message can never legitimately show up on
  a gateway bill.
- **Your own self-hosted gateway has no third-party bill at all** — you only bear the
  IP-reputation cost of running it.

## The operator seam, if you do want a hosted operator

A hosted operator (a private, separate control-plane — never part of this OSS workspace)
implements four capabilities against the [`crates/dmtap-seam`](../../crates/dmtap-seam) contract:
metering, provisioning, policy/quotas, and gateway authorization. Every one of them has a
fully-functional, unlimited self-host default, and none of them is allowed to touch encryption,
the mixnet, metadata privacy, or your access to your own keys and mailbox — that's the inviolable
rule (spec §12.3), and a conformant operator implementation is not permitted to violate it. See
[architecture.md](../architecture.md#where-an-operators-billing-sits).

## Organizations

An organization that controls a domain gets a real admin console ([`console/`](../../console))
without any new trust machinery: provisioning a member is publishing a name→key binding, the
directory is a signed enumeration of those bindings, admin roles are delegated capabilities, and
offboarding is removing a name. Members can be **sovereign** (they hold their own key; the
default) or, for compliance needs, **org-managed** (the org holds/escrows the key, disclosed
honestly as such — never presented as equivalent to a sovereign account). The org controls names
and operations; it never controls a sovereign member's key. See the console's own
[`README.md`](../../console/README.md) for the full model.

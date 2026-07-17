# Gateway — intended for its own repo (`envoir-gateway`)

**Status: lives in the `envoir` monorepo for now, by design — but it is intended to be split
out into its own repository (`envoir-gateway`) once it earns it.** This note records that intent
and the discipline that keeps the future split a clean lift rather than an untangling.

## Why the gateway is the natural thing to separate

The gateway is the **legacy bridge** — the one component that touches the old world (SMTP / IMAP /
POP3 / DNS / DKIM / SPF / DMARC / spam-filtering). It is architecturally the odd one out:

- **Most exposed.** It accepts inbound SMTP from the entire public internet and performs outbound
  DNS/SMTP — by far the largest attack surface in the system (SSRF, spoofing, relay abuse). Keeping
  it in a separate repo lets its security review and release cadence be scoped independently.
- **Legacy-only dependencies.** It pulls in mail/DNS/TLS/anti-spam machinery that the native core
  (`dmtap-core`, `node`, `client`, mesh) does not need.
- **A different audience.** Its operators are mail-relay/infrastructure people, not end users or
  self-hosters — a distinct contributor and ops community.
- **Deprecatable by design.** The whole point of DMTAP is that the gateway is a *bridge you can walk
  away from* as the native mesh grows. Isolating "the bridge" from "the sovereign core" reflects that
  in the repo structure: native identity, delivery, files, chat, and verification never depend on it.

The **node** and **client** stay together (the client is the node's UI); they are the native pair.

## Why it is not split out *yet*

While `dmtap-core`'s public API is still moving fast, a monorepo's **atomic cross-component changes**
are worth more than the boundary. Splitting now would turn every core change that touches the gateway
into a cross-repo dance (edit core → bump the pin → fix the gateway). We split when the friction
flips the other way.

## Boundary discipline to maintain NOW (so the split stays a clean lift)

Keep the gateway loosely coupled so extracting it is a `git filter-repo` plus a dependency line:

- **Depend only on `dmtap-core`'s public API.** No reaching into sibling crates' internals.
- **No dependency on `node` / `dmtap-p2p`.** Mesh delivery is behind the `MeshDelivery` trait
  (`src/mesh.rs`) — the `dmtap-p2p`/node swarm is the drop-in *above* the gateway, never a build
  dependency of it (this also avoids the `dmtap-p2p → node` cycle).
- **Own wire objects via `dmtap-core`.** `GatewayAttestation` / `ProvenanceRecord` come from
  `dmtap-core`; the gateway consumes, it does not redefine.
- **Config/authz/quota/usage-tracking are self-contained** (`GatewayAuthz`, `GatewayMeter`); billing
  is an external concern (the private `envoir-cloud` layer reads the meter — never a build dep here).

If a change would make the gateway depend on `node`, on another crate's internals, or on the billing
layer, treat it as a smell and route it through `dmtap-core`'s public API or a trait seam instead.

## When to actually split it out

Move the gateway to `envoir-gateway` when **any** of these is true:

1. `dmtap-core`'s public API has stabilized (≈ post-1.0), so a git/published-crate dependency is
   low-churn.
2. A distinct gateway-operator community has formed with its own cadence.
3. The gateway's release/security cadence has clearly diverged from the native core.

## Target long-term repository shape

```
dmtap           the protocol specification
envoir          native core: dmtap-core + crates + node + client + mesh + mail-engine
envoir-gateway  the legacy bridge (this component, once split out)
envoir-cloud    private, thin billing layer
```

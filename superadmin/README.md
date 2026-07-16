# Envoir Superadmin

The open-source **operator / platform control plane** for whoever runs Envoir Cloud (or any
fleet of Envoir/DMTAP infrastructure). It is the third admin surface in the suite — where
[`../client`](../client) answers *"I am one sovereign identity"* and [`../console`](../console)
answers *"I administer a domain full of them"*, the superadmin answers *"I operate the fleet that
carries them all"*.

Same discipline as the rest of the suite: **no framework, no build step, no npm, no CDNs**; pure
DOM on the brand **"Aurora Indigo"** design system (see [`../brand`](../brand)); everything
network-facing a clearly-labeled simulation you swap out for the real operator data plane.

It is built to make one guarantee impossible to miss: **content-blind by construction.** Nothing
in this console can read a mailbox, a message, a recipient set, or a user's keys. It meters
*operations* and aggregates *anti-abuse signals* only — the inviolable rule (spec §12.3,
`dmtap-seam` CONTRACT invariants).

## Run

```sh
cd superadmin
python3 -m http.server 8098
# open http://localhost:8098
```

No external assets. On first run a believable fleet is seeded (deterministic, so it is stable
across reloads). "Reseed demo fleet" (top-right ⋯) regenerates it.

## What it does (spec-mapped)

| Screen | Spec | What you see |
|--------|------|--------------|
| **Overview** | §7, §9 | Fleet health at a glance — counts by component kind (nodes · gateways · mix nodes · relays), up / degraded / down, a per-region rollup, aggregate metered operations, and the incident feed. A standing **content-blind** marker. |
| **Fleet** | §7.2a, §4.4.8, §9.6 | A filterable directory of every component with a detail pane: health + load + uptime, version, region, operator, **attestation** (domain-anchored §7.2a for nodes+gateways, operator-diversity §4.4.8 for mix nodes), **reputation** (§9.6 for gateways+mix), per-kind operational metrics, and **enroll / decommission**. |
| **Billing** | `dmtap-seam` | Per-account metered **operations** from the `Metering` + `Provisioning` seam — hosted storage, gateway sends, inbound legacy, relayed bytes, managed domains, native messages — with tier and suspend/resume. Loudly surfaces that **privacy is never metered**. |
| **Abuse ops** | §9, §9.6, §6.2 | Aggregate anti-abuse **signals** (rate ceilings, ARC-token revocations, bounce/complaint spikes, spam-trap hits, PoW clearances) and **operator reputation** for gateways + mix operators. Accountability **without content**: every signal is attributed to an anonymous accountable credential, never a message or a sender identity in clear. |
| **Provisioning** | — | Warm-pool / capacity per region (active · warm · target · claims, provider mix) plus the incident / alert feed with resolve. Mirrors the generic-box warm-pool / claim / attach model. |

## The inviolable rule, made legible

The point of an operator console is that it could be tempted to look inside. This one is built so it
structurally cannot, and says so in three places:

1. A persistent **content-blind** marker on the Overview, Billing and Abuse headers.
2. The **billing** view states plainly that the seam has quotas for storage / sends / domains / rate
   and **deliberately none** for encryption, metadata privacy or key access — no billing state gates
   a protocol capability. Suspending an account stops new metered operations; it never touches the
   account's keys or contents.
3. The **abuse** view attributes every signal to an anonymous **accountable credential** (ARC token /
   postage / PoW), preserving sealed sender (spec §6.2) — you can throttle a credential, never learn
   who is behind it or what they sent.

## What is real vs. simulated

Everything here is a **read model over a simulated operator data plane** — there is no live fleet in
the browser. A production superadmin replaces exactly `js/store.js` with a client to:

- the operator's **node / gateway / mix enrollment registry** (health, versions, attestation),
- the **`dmtap-seam`** endpoints (`crates/dmtap-seam`): `Metering`, `Provisioning`, `Policy`,
  `GatewayAuthz` — the same four capabilities, same invariants,
- the **reputation + anti-abuse** pipeline (spec §9, §9.6), and
- the **alerting bus** and **autoscaler / provider registry**.

The seeded data is deterministic and honestly labeled ("simulated seam" in the topbar). No real
metering, provisioning, attestation or reputation is performed.

## Module layout

```
index.html               mount point + global overlays (modal / toast)
css/superadmin.css        the Aurora Indigo design system — all components, light + dark

js/app.js                 boot: load a persisted fleet snapshot or seed one, then mount the shell
js/shell.js               rail (Overview · Fleet · Billing · Abuse ops · Provisioning), topbar glance, dispatch
js/bus.js                 late-bound rerender/setView dispatch (no import cycle)
js/store.js               THE SIMULATED SEAM: fleet + accounts + signals + incidents + warm-pool; persistence
js/ui.js                  DOM helpers, icon set, health dots/pills, attestation + reputation badges, meters, sparkline, modal, toast, empty/loading/error

js/views/overview.js      fleet health at a glance: kind counts, region rollup, metered ops, incidents
js/views/fleet.js         component directory + detail: health, attestation, reputation, enroll / decommission
js/views/billing.js       dmtap-seam metering per account + tier + suspend/resume
js/views/abuse.js         anti-abuse signals + gateway/mix operator reputation (content-blind)
js/views/provisioning.js  warm-pool / capacity per region + incident feed
```

## Accessibility & responsiveness

Semantic landmarks + ARIA (`dialog`/`aria-modal`, `tablist`/`tab`, `aria-current`, `aria-pressed`,
`aria-live`), a focus-trapped modal that restores focus, an Escape-to-close affordance, a consistent
keyboard focus-visible ring, `prefers-reduced-motion` honored, and a master/detail fleet layout that
collapses to a single pane (with a back affordance) from phone width up. Full light and dark themes.

## Local testing

Every screen and every primary interaction — overview drill-downs, fleet filtering + node/gateway/
mix/relay detail + attestation re-verify + enroll + decommission, billing sorts + account
suspend/resume, abuse throttle, provisioning incident resolve, theme toggle, session menu — was
driven headlessly in Chrome, asserting **zero page-level console errors** (`console.error` /
`pageerror` / `requestfailed` / HTTP ≥ 400 all captured) and **no horizontal overflow** at desktop
(1440px) and phone (390px), across light and dark.

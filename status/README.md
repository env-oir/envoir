# Envoir Status

The public + personal **status page** for Envoir/DMTAP — a polished, statuspage.io-class surface on
the brand **"Aurora Indigo"** design system (see [`../brand`](../brand)). Same discipline as the rest
of the suite: **no framework, no build step, no npm, no CDNs**; pure DOM; everything network-facing a
clearly-labeled simulation.

Two surfaces in one app:

- **System status** (unauthenticated) — the public page: overall status banner
  (operational / degraded / outage), per-component health with 90-day uptime bars + uptime %, the
  active-incident section, and incident history.
- **My status** (authenticated) — the individual user's *own* service health: their mailbox, their
  node's reachability path, any platform degradation currently affecting **them**, and their recent
  delivery outcomes.

## Run

```sh
cd status
python3 -m http.server 8099
# open http://localhost:8099
```

No external assets. A **demo scenario switch** in the header (`Operational · Degraded · Outage`)
regenerates the feed so every state of the page is previewable — it is a demo affordance, clearly
labeled, not a production control. "Sign in" opens the authenticated view (a demo session; no real
credentials).

## Components (spec-mapped)

The public page tracks the six user-facing surfaces of the protocol:

| Component | Spec | What it covers |
|-----------|------|----------------|
| **Mail delivery** | §4 | Native JMAP send + receive across the mesh |
| **Legacy gateway** | §7 | SMTP ↔ DMTAP bridge for legacy correspondents |
| **Mixnet** | §4.4 | Private-tier, metadata-hiding routing |
| **Key Transparency** | §3.5 | Append-only name→key log |
| **Directory** | §3.10 | Name resolution + `DomainDirectory` |
| **Reachability relay** | §4 | Direct-first, relay-fallback delivery path |

The overall banner is derived from component health + open incidents: any component down →
**partial outage**; any degraded → **degraded performance**; otherwise **all systems operational**.
Copy is honest about scope — e.g. an outage banner still notes that *native mail remains durable:
messages are held and retried at the edges until delivery* (DMTAP puts durability at the sender's
outbound queue, not the middle).

## Transparency

A public panel beneath the component list — the honest counterpart to the operator's own KT-log-
health and attestation views: **Key Transparency** (spec §3.5) shows the tree size, how long ago
the checkpoint was last verified, and how many independent witnesses agree; **Gateway attestation**
(spec §7.2a) shows how fresh the legacy bridge's domain-anchored attestation key verification is.
Tracks the active scenario — e.g. the outage scenario shows a stale gateway attestation, since the
bridge itself is down and can't be re-verified until it's back.

## My status (authenticated)

Answers a personal question the public page can't: *is **my** mail working right now, and if not,
why?* It shows:

- **Mailbox** — reachability, storage usage, last sync (on your home node).
- **Reachability** — your delivery path (direct P2P vs relay-fallback) and which relay, with an
  explanation when you've been pushed onto the fallback path.
- **Legacy bridge** — that native mail is unaffected while legacy-bridge sends may be delayed/queued.
- **Affecting you right now** — only the open incidents that touch a surface you actually rely on.
- **Recent delivery status** — your recent sends/receipts (native vs legacy) with outcome
  (delivered / delayed / queued / failed) — **outcomes only, never content**.

## States

All four required states are real code paths, not mockups:

- **Loading** — a short simulated fetch shows a shimmer before the feed renders (and on every
  scenario switch / refresh).
- **Empty** — an all-clear panel when there are no active incidents; an empty-state card when there
  is no past-incident history.
- **Error** — a fetch-failure state with a **Retry** (reachable at `#error`) that recovers; the copy
  reassures that mail is unaffected because DMTAP delivery is edge-durable.
- **Content** — the populated public / user views.

## What is real vs. simulated

Everything is simulated in the browser and labeled as such (header demo switch + footer note). A
production status page replaces exactly `js/store.js` with:

- a poll of the operator's **public component + incident feed** (the same feed the superadmin's
  incident bus publishes), and
- an authenticated call to the user's **home node** for their mailbox / reachability / recent-delivery
  health.

## Module layout

```
index.html            mount point + global overlays (modal / toast)
css/status.css         the Aurora Indigo design system — banner, uptime bars, incidents, user cards; light + dark

js/app.js              boot: load prefs, mount the shell
js/shell.js            header (brand, System-status / My-status tabs, demo scenario switch, theme, sign-in) + loading/error orchestration
js/store.js            THE SIMULATED SEAM: scenarios → components + incidents + transparency (KT + gateway attestation) + per-user health; prefs persistence
js/ui.js               DOM helpers, icon set, status vocabulary, health dot/pill, 90-day uptime bars, modal, toast, empty/loading/error

js/views/public.js     public status page: banner, components + uptime, transparency (KT consistency, gateway attestation freshness), active incidents, history
js/views/user.js       authenticated "My status": mailbox, reachability, legacy bridge, affecting-you, recent deliveries
```

## Accessibility & responsiveness

Semantic landmarks + ARIA (`dialog`/`aria-modal`, `tablist`/`tab`, `role="status"`, `aria-live`,
`aria-pressed`, uptime bars as a labeled `img`), a focus-trapped modal that restores focus,
Escape-to-close, a consistent focus-visible ring, `prefers-reduced-motion` honored, and a layout
that reflows cleanly from wide down to phone width. Full light and dark themes.

## Local testing

Both surfaces and every state were driven headlessly in Chrome: the public page in **each** scenario
(operational / degraded / outage), the authenticated user view across scenarios, sign-in / sign-out,
the loading shimmer, the error state + retry recovery, and the empty/all-clear paths — asserting
**zero page-level console errors** (`console.error` / `pageerror` / `requestfailed` / HTTP ≥ 400 all
captured) and **no horizontal overflow** at desktop (1200px) and phone (390px), across light and dark.

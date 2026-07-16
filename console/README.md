# Envoir Management Console

The open-source **admin console** for an organization that controls a domain (e.g. `@abc.com`)
and wants to run its people on Envoir/DMTAP. It is the counterpart to the end-user app in
[`../client`](../client): same instrument-panel design language, same "no framework, no build
step, no npm, no CDNs" discipline, real browser cryptography where it matters, everything
network-facing a clearly-labeled simulation.

Where the client answers *"I am one sovereign identity"*, the console answers *"I administer a
domain full of them"* — and it is built to make one guarantee impossible to miss: **the org
controls names and operations, never a sovereign member's key.**

## Run

```sh
cd console
python3 -m http.server 8097
# open http://localhost:8097
```

No external assets. On first run you'll connect a domain (any domain, e.g. `abc.com`); a real
Ed25519 **domain-authority** keypair is generated in your browser and a believable organization is
seeded so every admin surface has something to manage. "Reset demo organization" (top-right ⋯)
wipes local state and starts over.

## What it does (spec-mapped)

| Screen | Spec | What you can do |
|--------|------|-----------------|
| **Overview** | §3.10.1 | See the threshold-held domain authority (fingerprint + safety number + holder set), DNS/`kt=` anchor status, org shape, and a **"what you CAN / CANNOT do"** panel. Rotate the directory-signing key (threshold-gated). |
| **Members** | §3.10.2, §3.10.5, §18.4.7 | Add a member as **sovereign** (default) or **org-managed** (opt-in, consent-gated); inspect the per-account **capability matrix**; offboard (with the sovereign-vs-managed divergence shown); on org-managed accounts, *demonstrate* the escrow by really signing as them. |
| **Directory** | §3.10.3, §18.4.7 | Curate the signed, versioned `DomainDirectory` (GAL); set **public / members-only** visibility; see each entry's custody and **forward DNS+KT verification** status; re-verify. |
| **Groups** | §5.8.7 | Create/manage `team@`, `all@`, `support@` distribution lists & channels; roster, posting model, membership visibility, join policy; the group key stays threshold-held. |
| **Admin roles** | §13.5.1 | Delegate/revoke `domain-owner` / `domain-admin` / `user-admin` / `group-admin` **capabilities** (UCAN-style, attenuable, expirable, revocable). Granting `domain-owner` requires the domain **threshold**. |
| **Audit log** | §3.5, §13.5.1 | The append-only, hash-chained, owner-visible trail of every administrative act — nothing an admin does is silent. |

## How the sovereignty distinction is made legible

This is the point of the tool, so it is surfaced in five places, not one:

1. **A custody badge on every member, everywhere** — <kbd>sovereign</kbd> (green key) vs
   <kbd>org-managed</kbd> (amber open-lock). It appears in the list, the detail hero, the
   directory table, and directory entries.
2. **A per-account capability matrix** — "Read their mail / Impersonate / Recover their key" render
   as **NO** (green ✗ = the org cannot) for a sovereign member and **YES** (red ✓) for an
   org-managed one. "Revoke the name" is always YES — the org's real power.
3. **A consent gate on org-managed provisioning** — you cannot create an org-managed account
   without ticking an explicit acknowledgement that the org will hold the key and can read +
   impersonate; it is disclosed to the member as `org-managed` (undisclosed escrow fails closed,
   `ERR_ORG_MANAGED_UNDISCLOSED`).
4. **The escrow made concrete** — an org-managed account can be *actually signed as* from the
   console (real Ed25519 over the retained key); a sovereign account has no such path because its
   private key was **discarded at creation**.
5. **Offboarding divergence** — a sovereign member's **key survives** (name revocation, not mailbox
   seizure); an org-managed mailbox can be retained by the org. The offboard dialog states which.

The overview's "what you CAN / CANNOT do" panel states the whole invariant plainly: as domain
owner you hold power over **names**, not keys.

## No lone super-admin

Domain-authoritative acts — rotating the anchor or the directory-signing key, granting full
`domain-owner` authority — are gated behind a **threshold quorum-collection** step (2-of-3 by
default). A single admin can add/remove ordinary members (bounded, KT-logged, reversible) but
cannot seize the namespace. See `js/session.js` `collectThreshold`.

## What is real vs. simulated

| Area | Real (Web Crypto) | Simulated / stand-in (labeled) |
|------|-------------------|--------------------------------|
| Domain authority key | **Ed25519 keygen + real signing** of the `DomainDirectory` | — |
| Member keys | **Ed25519 keygen**; sovereign private key **discarded**, org-managed private key **retained in escrow** and really used to sign | — |
| Safety numbers | **Deterministic SHA-256 derivation** (words + grid) | SHA-256 stands in for BLAKE3; 256-word list |
| Directory / KT log | signature is real | versioning + hash-chained audit are in-memory; a real console appends to KT and publishes over the mesh |
| Threshold (FROST) | — | a single authority signature stands in for the m-of-n quorum signature once approvals are collected |
| DNS zone / `_dmtap` / node / mesh | — | **entirely simulated** by `js/store.js`; the UI says "simulated node" |

A production console replaces exactly `js/store.js` (+ the escrow/DNS seams in `js/session.js`)
with a client to the domain authority's node — publishing real DNS records, `DomainDirectory`
objects, and KT-log appends. The view layer is unchanged.

## Module layout

```
index.html              mount points + global overlays (modal / toast)
css/console.css          the design system (shared language with ../client) — all components, light+dark

js/app.js                boot: load an admin session or run setup, then mount the shell
js/setup.js              "connect your domain" — generate the authority key + seed the org
js/shell.js              rail (Overview · Members · Directory · Groups · Roles · Audit), topbar, dispatch
js/bus.js                late-bound rerender/setView dispatch (no import cycle)

js/store.js              THE SIMULATED SEAM: domain + members + groups + caps + audit; persistence; directory versioning/signing
js/session.js            domain-authority keypair, org-managed escrow, directory signing, threshold quorum collection
js/crypto.js             REAL Web Crypto: keygen, signing, escrow signing, safety-number derivation

js/ui.js                 DOM helpers, icon set, avatars, custody badge, modal (focus-trapped), toast, empty/loading/error, safety visuals

js/views/overview.js     domain authority, anchor status, sovereignty guarantee panel, recent activity
js/views/members.js      provisioning (both models), capability matrix, offboarding, escrow demonstration
js/views/directory.js    DomainDirectory (GAL) curation, visibility, forward-verification
js/views/groups.js       org groups / distribution lists, rosters, policy
js/views/roles.js        admin capabilities: delegate / attenuate / revoke (threshold for domain-owner)
js/views/audit.js        KT-logged, owner-visible administrative trail
```

## Accessibility & responsiveness

Semantic landmarks + ARIA (`dialog`/`aria-modal`, `radiogroup`, `progressbar`, `aria-current`,
`aria-pressed`), a focus-trapped modal that restores focus, a consistent keyboard focus-visible
ring, `prefers-reduced-motion` honored, and a master/detail layout that collapses to a single pane
from phone width up. Full light and dark themes.

## Local testing

Every screen and every primary action (add sovereign, add org-managed with the consent gate,
offboard, create group + add member, grant + revoke a role, a threshold quorum act, edit directory
visibility, rotate the directory key, demonstrate escrow signing) was driven headlessly in Chrome,
asserting **zero page-level console errors** (`console.error` / `pageerror` / `requestfailed` all
captured), across desktop and phone viewports, plus a persistence-across-reload check.

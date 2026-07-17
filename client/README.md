# Envoir reference web client

A premium, unified communications app for DMTAP — **mail, chat, calendar, contacts, files, and
groups on one sovereign identity**. Plain HTML + CSS + vanilla JS ES modules. **No framework, no
build step, no npm, no CDNs.** Everything is self-contained; the real cryptography runs in the
browser and everything network-facing is a clearly-labeled simulation.

## Run

```sh
cd client
python3 -m http.server 8095
# open http://localhost:8095
```

Or open `index.html` via any static server. No external assets.

## The addressing model (finalized)

The identity is always the **keypair**. What you see and give out is a **primary address**,
`name@domain` (e.g. `you@envoir.org`, or your own domain). An identity may hold **many addresses
at once** — aliases, a kept **legacy address**, an optional `@handle`, and plus-addressing
(`you+tag@domain`) — all resolving to the same key (spec §3.9.4).

The key is verified out-of-band with a **safety number** (spec §3.4): compare the words, scan the
QR-style grid, or read the digits, exactly like Signal. A blue **verified ✓** means you did this,
so a look-alike key would be caught — that's the anti-spoofing win, and why phishing stops working
when identity is a key rather than a display name. (The old client used this 8-word encoding *as
an address*; it is now correctly a verification affordance, never an address.)

## Feature set

- **Unified shell** — left rail (Mail · Chat · Calendar · Contacts · Files · Identity · Groups ·
  Settings),
  a live **global search**, a **command palette** (⌘/Ctrl-K), and full **keyboard shortcuts** with
  a help overlay (`?`).
- **Accessible & responsive** — semantic landmarks + ARIA (dialog/listbox/status/`aria-current`),
  a single consistent **focus-visible** ring on every control, a **focus-trapped** modal that
  restores focus on close, `prefers-reduced-motion` honored throughout, a **master/detail**
  layout that collapses to one pane (with a back affordance) from phone width to wide desktop,
  and — below 680px — the left rail becomes a **bottom tab bar** (safe-area aware, ≥44px tap
  targets) down to ~360px phones. Breakpoints: 1100px (mail rail narrows), 900px (two-pane views
  shed their widest column; the Identity page's label/body rows go single-column), 680px (single
  pane + bottom tab bar), 360px (extra-narrow phones).
- **Installable PWA** — `manifest.webmanifest` (standalone display, themed, maskable 512 icon) +
  a service worker (`sw.js`) that precaches the app shell for offline load (cache-first shell,
  network-first navigation with an offline fallback to `index.html`), plus a subtle **"Install
  app"** affordance (Settings → App) wired to `beforeinstallprompt`.
- **Web Push — content-free wake pings** — Settings → Notifications: request permission,
  `PushManager.subscribe()` against a demo VAPID-shaped key, and a **"Send test wake-ping"** dev
  button that posts straight to the service worker to exercise the real push → sync →
  notification path with no backend. The push payload is *never read* (spec's honest-privacy
  model): a push means only "something changed, go sync" — sender and content stay end-to-end
  and travel later, over the mesh, never in the push transport.
- **Mail** — three-pane, conversation **threading**, folders + color **labels**, star, archive,
  **snooze**, **scheduled send**, **undo send**, drafts, rich compose with **signatures**,
  multi-select **bulk actions**, mark read/unread, per-message **verified badges**, clear
  **legacy-origin** marking, and the MOTE **3-layer inspector** as a "why this is private" drawer.
- **Chat** — DMs + **channels (groups)**, reactions, threaded replies, opt-in typing/presence
  (labeled metadata-sensitive) — the same MOTE substrate (`kind=chat`, fast tier). Every
  conversation header carries an honest protocol badge: DMs are **deniable 1:1** (a pairwise
  X3DH + Double Ratchet channel, MAC-authenticated, spec §5.2.1 — no signature ties a message to
  you), channels are **MLS group · signed** (spec §5.3/§5.8 — scales to any group size, but the
  per-message signature is non-repudiable); click the badge for the tradeoff explained in full.
- **Calendar** — month / week / day views, create event, **recurring** events, peer-to-peer
  **invitations + RSVP** (a message, not a server query), reminders, free/busy.
- **Contacts** — cards with org/title/phone/groups, gradient avatars, and **per-contact key
  verification** (TOFU-pinned vs verified via safety number), import/export affordances.
- **Files** — content-addressed, E2E, any size (drop to chunk + hash client-side), with
  **shared-folder = group**.
- **Groups** — the new concept made tangible: a group **has an address** (`team@envoir.org` /
  `@core`); create one, see its address, manage **members + roles** (owner/admin/member),
  **broadcast** (hidden list) vs **channel** (member-visible), and join policy. Sending to the
  address posts to all members.
- **Settings** — identity + safety number, **aliases** management (incl. kept legacy + @handle +
  make-primary), signatures, **vacation/auto-responder**, filters/rules, default privacy tier,
  presence + gateway toggles, **light/dark theme**, keyboard reference, recovery phrase, sign-out,
  and the **"Sign in with Envoir"** demo.

### Keyboard shortcuts

`⌘K`/`Ctrl K` command palette · `/` search · `c` compose · `g` then `m/c/a/p/f/i/r` go to
Mail/Chat/cAlendar/People/Files/Identity/gRoups · `1`–`8` jump to view · `j`/`k` next/prev
conversation ·
`Enter` open · `e` archive · `#` delete · `r` reply · `s` star · `u` mark unread · `x` select ·
`?` help · `Esc` close overlay.

## What is real vs. simulated

| Area | Real (browser Web Crypto) | Simulated / stand-in (honestly labeled) |
|------|---------------------------|------------------------------------------|
| Identity | **Ed25519 keygen + signing** (ECDSA-P256 fallback, labeled); SHA-256 | Persistence is localStorage (a real node uses an OS keystore) |
| Safety number | **Deterministic derivation** from the public key (words + digits + grid); "recompute & verify" proves it | SHA-256 stands in for BLAKE3; 256-word list (8 bits/word) vs the spec's ~1024-word/10-bit list |
| MOTE | **Real signature** over the payload; content-address id computed | "Encryption" and the mixnet onion are structural, not performed (no real MLS/HPKE session) |
| Sign-in demo | **Real signature** over the origin-bound challenge, same key path as mail | Origin binding is the weaker in-page mode; true phishing-resistance needs WebAuthn (§13.3.1) |
| Files | **Real SHA-256** chunk/manifest hashing of dropped files | Labeled `b3:` to match the spec's BLAKE3 intent; not actually stored/replicated |
| Network | — | **Entirely simulated**: no peers, no mixnet, no gateway; delivery paths + latency + hop animation are in-memory (`mesh-sim.js`). The UI says "simulated network." |
| Web Push | **Real** `PushManager.subscribe()` + service-worker `push`/`notificationclick` handling | No live push backend exists here — the applicationServerKey is a demo placeholder, and "Send test wake-ping" (Settings → Notifications) posts straight to the service worker to exercise the exact push → sync → notification path locally, clearly labeled as a simulation of what the user's own node would send |
| Mail/chat/calendar/contacts/files/groups data | — | Rich in-memory **seed data** (`seed.js`); a real client syncs these as MOTEs over JMAP + libp2p to your node |
| @handle directory | — | In-memory registry with pre-taken names + a fake key-transparency leaf |
| Aliases / plus-addressing / RSVP / group posts | Build **real signed MOTEs** | Their *delivery* is simulated |

A production client replaces `mesh-sim.js` + `seed.js` with a libp2p connection to the user's
node, compiles the Rust MOTE/MLS/identity core to WASM (the libsignal model), and binds the
sign-in origin via WebAuthn — the UI layer stays essentially the same.

## Module layout

```
index.html            shell mount points + overlays (modal / inspector / toast)
css/app.css           the design system — instrument-panel dark/light theme, all components
assets/               brand mark SVGs (copied from ../brand/) + generated favicons/og-image PNGs;
                      assets/make-icons.mjs is the dev-time rasterizer that produced the PNGs

js/app.js             boot: load-or-create identity, mount the shell, register the service worker
js/shell.js           unified shell: rail (bottom tab bar on mobile), global search, command palette, keyboard shortcuts, view dispatch
js/bus.js             tiny late-bound dispatch (rerender/setView) so views and shell don't import in a cycle
js/store.js           central in-memory state + settings persistence + mail helpers
js/onboarding.js      create a sovereign identity (name@domain primary + real keypair)
js/pwa.js             service worker registration, install-prompt capture, Web Push subscribe/permission + local test wake-ping
sw.js                 service worker: app-shell precache (offline load) + content-free push "wake ping" handling
manifest.webmanifest  PWA manifest (standalone display, themed, maskable icon)

js/identity.js        REAL Web Crypto identity: keygen, signing, aliases, plus-addressing, safety number
js/safety.js          deterministic safety-number derivation (words + digits + QR-grid) + key-name — key verification
js/avatar.js          the avatar ladder: user URL → opt-in Gravatar → key-derived identicon → initials
js/resolver.js        pattern-classify a name against the resolver ladder (key-name/DNS/name-chain/@handle/petname) — presentation only
js/provenance.js      transport-path provenance (pure-mesh vs gateway-touched) badges + expandable path graph
js/mote.js            MOTE construction (spec §2), real payload signature; mail/chat/calendar/contact/group kinds
js/mesh-sim.js        SIMULATED mesh/mixnet delivery planning + @handle directory
js/seed.js            rich seed data for every module (people, mail threads, chats, events, files, groups)
js/compose.js         compose modal: signatures, privacy tier, scheduled send, undo send, drafts
js/profileModal.js    shared "Edit profile" modal (self-asserted name + avatar) for Settings + Identity
js/signin.js          "Sign in with Envoir" demo (real signature over an origin-bound challenge)
js/ui.js              DOM helpers, icon set, avatars, MOTE inspector, safety visuals, toast, modal, shimmer

js/views/mail.js      three-pane mail: folders/labels, threading, bulk actions, reading pane, inspector
js/views/chat.js      DMs + channels, reactions, threads, typing/presence, deniable-vs-MLS badge
js/views/calendar.js  month/week/day, recurring events, invitations + RSVP, reminders
js/views/contacts.js  cards + per-contact safety-number verification, import/export
js/views/files.js     content-addressed E2E files, shared-folder = group
js/views/identity.js  identity surface: naming ladder, safety number, devices, sessions, recovery, key lifecycle
js/views/groups.js    groups-as-addresses: members + roles, broadcast vs channel, membership visibility
js/views/settings.js  identity, aliases, signatures, vacation, filters, privacy, theme, shortcuts, sign-in
```

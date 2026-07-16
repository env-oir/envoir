# PWA, offline, and push — the honest privacy model

The web client ([`client/`](../client)) is an installable **Progressive Web App**: it works
offline for the app shell, it can be added to a phone or desktop home screen like a native app, and
it can wake up in the background using **Web Push** — without the push transport ever learning who
messaged you or what they said. This page is the plain-language version of the design and its one
disclosed, unavoidable residual on iOS.

## Installable and responsive

- **`client/manifest.webmanifest`** declares a standalone-display, themed, maskable-icon app —
  "Add to Home Screen" / "Install" turns the client into something that looks and launches like a
  native app, with no app-store review and no separate binary to trust.
- **A subtle install affordance** (Settings → App) wired to the browser's `beforeinstallprompt`
  event, so installing is discoverable without being pushed on anyone.
- **Responsive down to ~360px-wide phones**: a master/detail layout that collapses to one pane
  (with a back affordance) from phone width to wide desktop, and — below 680px — the left rail
  becomes a bottom tab bar (safe-area aware, ≥44px tap targets). See
  [`client/README.md`](../client/README.md#feature-set) for the exact breakpoints.

<p align="center">
  <img src="img/mail-mobile.png" width="300" alt="Envoir on a phone — installed PWA, responsive mail view">
</p>

## Offline app-shell loading

**`client/sw.js`** is a service worker that precaches the app shell (HTML/CSS/JS/assets) so the
app *opens* even with no network: cache-first for the precached, content-hashless shell, and
network-first for navigation with an offline fallback to `index.html` if the network is
unreachable. This makes the app launch instantly and survive a dead connection at open time — it
does not mean your mailbox is available offline (that depends on the node/mesh sync layer this
reference client simulates; see [roadmap.md](roadmap.md)).

## Web Push — a content-free wake ping, by design

The hardest part of "your own sovereign node, not a company's server" is the one thing every
mobile OS makes structurally hard: waking an app in the background when it isn't running. Envoir's
answer keeps that wake-up mechanism from becoming a metadata leak:

- A push event carries **no sender and no content** — the push payload is deliberately never read
  even when the browser's Push API hands the service worker bytes. A push means exactly one thing:
  *"your node has something new — open and sync over the mesh."* Everything else (who, what, when)
  stays end-to-end and travels later, over DMTAP's own transport, never through the push service.
- **Your own node would mint its own VAPID keypair** and hand only the public half to the push
  service — never a shared, provider-wide key — so the "wake me up" relationship is between you
  and your own node, not a fleet-wide push credential a hosted operator controls. (This reference
  client uses a placeholder demo key, clearly labeled, since there is no real node behind it yet.)
- **"Send test wake-ping"** (Settings → Notifications) posts a message straight to the active
  service worker, running the *exact* push → notification → wake-sync code path a real push event
  would — with no backend involved. It's a way to see the real mechanism work, not a simulation of
  a different mechanism.

This is the same honest-privacy posture as the rest of the project: push is a **wake-up plumbing
concern**, and DMTAP is deliberately designed so that plumbing never needs to see who's talking to
whom. See [privacy.md](privacy.md) for the project's broader metadata-privacy model.

## The one disclosed residual: iOS and APNs

Stated plainly, because this project doesn't paper over inconvenient platform realities: **every**
browser's Web Push implementation — Safari/iOS included — is ultimately delivered through that
platform's own push infrastructure. On Apple platforms that means Apple's **APNs** sits in the
delivery path for *any* web app's push notifications, Envoir's included; there is currently no way
for a web app to reach an iOS device in the background without transiting Apple's push service.
Two things are true at once, and neither cancels the other out:

- **Content and sender stay protected even through APNs** — the wake ping is content-free by
  design (see above), so what transits Apple's infrastructure is "something changed for identifier
  X," not a sender, a subject, or a message body. This is the same design that protects you from
  a hosted Envoir operator's own push infrastructure; it isn't weakened for iOS specifically.
- **The residual is the existence of the ping and its timing**, visible to Apple as the platform
  operator, exactly as it would be for any other web or native app using APNs. This is a
  platform-level constraint no web app can opt out of, not an Envoir shortcoming — and it's
  disclosed here rather than glossed over. A future native or WASM-core client could investigate
  platform-specific alternatives (e.g. a persistent local connection while foregrounded, or a
  native app wrapper with its own APNs entitlement), but none of that changes the fact that *some*
  platform push service is unavoidable for background wake-up on iOS today.

Also see [`client/README.md`](../client/README.md#what-is-real-vs-simulated) for exactly which
parts of the push/PWA path are real browser APIs versus this reference client's local-only demo
plumbing, and [security.md](security.md) for how this fits the project's broader
honest-not-absolute privacy posture.

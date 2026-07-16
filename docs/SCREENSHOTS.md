# Screenshotter

`npm run screenshotter` regenerates every screenshot used by the docs and root README, captured
live from the real UIs in this repo — no mockups, no hand-editing.

```
npm run screenshotter                          # capture every app
npm run screenshotter -- --only=client,status  # capture a subset (comma-separated app names)
```

## What it does

For each app (`client/`, `console/`, `superadmin/`, `status/`, `site/`) the script:

1. starts a tiny built-in static file server rooted at that app's directory (plain node
   `http`, no `python3` dependency, nothing to install) on a free localhost port;
2. drives it with real headless Chrome via `puppeteer-core`, reused from the sibling
   `dmtap/build/node_modules` tree — nothing new is installed for this to work;
3. runs the app's actual onboarding/setup flow where one exists (client identity creation,
   console "connect your domain"), then navigates by clicking real nav / theme-toggle / scenario
   controls — never by pixel coordinates or synthetic routing;
4. before every screenshot, asserts the expected screen actually rendered (a view-specific DOM
   node, or matching visible text) and afterwards checks the PNG isn't a suspiciously tiny
   blank/error page;
5. writes deterministic filenames into `docs/img/` (e.g. `mail-dark.png`, `console-overview-light.png`,
   `status-outage.png`, `landing-hero.png`), overwriting in place so doc/README image references
   never need to change.

One broken capture never aborts the rest of the run — failures are recorded and printed in a
summary table at the end. The process exits non-zero iff any *required* shot failed (a couple of
onboarding "bonus" shots are marked non-required, since they document a transient step rather
than a deliverable app view). Servers, browser pages and the browser process are always cleaned
up, including on error or Ctrl-C.

## Images produced

| App | Files |
|---|---|
| client | `onboarding-safety.png`\*, `onboarding-identity.png`\*, `mail-dark.png`, `mail-light.png`, `mail-mobile.png`, `path-graph.png`, `chat-dark.png`, `chat-light.png`, `chat-mobile.png`, `calendar-dark.png`, `calendar-light.png`, `calendar-mobile.png`, `contacts-dark.png`, `contacts-mobile.png`, `files-dark.png`, `files-light.png`, `identity-dark.png`, `identity-light.png`, `identity-mobile.png` |
| console | `console-overview-dark.png`, `console-overview-light.png`, `console-members-dark.png`, `console-directory-dark.png`, `console-billing-dark.png` |
| superadmin | `superadmin-overview-dark.png`, `superadmin-overview-light.png`, `superadmin-fleet-dark.png`, `superadmin-abuse-dark.png`, `superadmin-billing-dark.png` |
| status | `status-operational.png`, `status-light.png`, `status-degraded.png`, `status-outage.png`, `status-user.png` |
| site | `landing-hero.png`, `landing-hero-light.png` |

\* non-required "bonus" shots.

Note: the `-mobile.png` shots (a narrow-viewport capture of the same view) and the `calendar-*` /
`contacts-*` shots document the client's Calendar/Contacts parity and its responsive layout down
to phone width; `docs/screenshotter/apps/client.mjs` is still being extended with the capture
calls for these views, so re-running `npm run screenshotter` today will not yet regenerate them —
until then, treat the images already committed in `docs/img/` as current.

## Environment overrides

Only needed if your machine differs from the reference dev box:

- `CHROME_PATH` — path to a Chrome/Chromium binary
  (default: `/Applications/Google Chrome.app/Contents/MacOS/Google Chrome`)
- `PUPPETEER_CORE_PATH` — path to puppeteer-core's ESM entrypoint
  (default: the sibling `dmtap/build/node_modules/puppeteer-core/lib/esm/puppeteer/puppeteer-core.js`)

## Code layout

- `docs/capture-screenshots.mjs` — orchestrator: starts/stops servers, launches/closes the
  browser, runs each app, prints the summary and sets the exit code.
- `docs/screenshotter/lib.mjs` — shared infra: the static server, the puppeteer-core loader, the
  results ledger, and the `capture()` / `goToView()` / `setTheme()` / `waitForText()` helpers.
- `docs/screenshotter/apps/*.mjs` — one module per app, each exporting `run(page, baseUrl, capture)`.

## Note on the UI redesign in flight

The client/cloud/landing UIs are being redesigned in parallel branches. Screenshots taken now
will look pre-redesign — that's expected. Re-run `npm run screenshotter` after the redesign
merges to regenerate every image against the new UI; the navigation/assertion logic here targets
nav structure, data-view attributes and rendered text rather than exact visual markup, so it
should mostly survive a redesign, but some individual captures may need their `assert` selectors
updated if wrapper class names change.

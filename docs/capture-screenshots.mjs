#!/usr/bin/env node
// docs/capture-screenshots.mjs — run via `npm run screenshotter`. Full usage: docs/SCREENSHOTS.md.
//
// One command that regenerates every screenshot used by the docs/README from the REAL UIs in
// this repo — the client, the three cloud-side apps (console, superadmin, status), and the
// marketing site (site/). For each app it:
//
//   1. spins up a tiny built-in static file server rooted at that app's directory (no python3,
//      no extra installs — just node's http module) on a free localhost port,
//   2. drives it with real headless Chrome via puppeteer-core (reused from the sibling dmtap
//      build's node_modules — nothing new is installed; see PUPPETEER_CORE_PATH below),
//   3. navigates by clicking the app's real nav / theme-toggle / scenario controls (never by
//      pixel coordinates), asserting the expected screen actually rendered (a view-specific DOM
//      node, or matching visible text) before every shot,
//   4. writes deterministic PNG filenames into docs/img/, overwriting in place so doc/README
//      image references never need to change.
//
// Usage:
//   npm run screenshotter                              # capture every app
//   npm run screenshotter -- --only=client,status       # capture a subset (comma-separated)
//
// Environment overrides (only needed if your machine differs from this dev box):
//   CHROME_PATH           path to a Chrome/Chromium binary
//                          (default: /Applications/Google Chrome.app/Contents/MacOS/Google Chrome)
//   PUPPETEER_CORE_PATH    path to puppeteer-core's ESM entrypoint
//                          (default: sibling .../dmtap/build/node_modules/puppeteer-core/lib/esm/puppeteer/puppeteer-core.js)
//
// A per-app run is wrapped so one broken capture never aborts the others; the process exit code
// is non-zero iff any REQUIRED shot failed (a handful of onboarding "bonus" shots are marked
// non-required, since they document a transient step rather than the deliverable app views).
// Servers, pages and the browser are always cleaned up, including on error or Ctrl-C.

import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { mkdirSync } from 'node:fs';
import { launchBrowser, serveStatic, Results, shooter } from './screenshotter/lib.mjs';

import * as clientApp from './screenshotter/apps/client.mjs';
import * as consoleApp from './screenshotter/apps/console.mjs';
import * as superadminApp from './screenshotter/apps/superadmin.mjs';
import * as statusApp from './screenshotter/apps/status.mjs';
import * as siteApp from './screenshotter/apps/site.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, '..');
const OUT = join(__dirname, 'img');
mkdirSync(OUT, { recursive: true });

const APPS = [
  { name: 'client', dir: join(REPO_ROOT, 'client'), run: clientApp.run },
  { name: 'console', dir: join(REPO_ROOT, 'console'), run: consoleApp.run },
  { name: 'superadmin', dir: join(REPO_ROOT, 'superadmin'), run: superadminApp.run },
  { name: 'status', dir: join(REPO_ROOT, 'status'), run: statusApp.run },
  { name: 'site', dir: join(REPO_ROOT, 'site'), run: siteApp.run },
];

function parseOnly() {
  const arg = process.argv.find((a) => a.startsWith('--only='));
  if (!arg) return null;
  return new Set(arg.slice('--only='.length).split(',').map((s) => s.trim()).filter(Boolean));
}

let browser; // module-scope so the SIGINT/SIGTERM handlers below can always reach it

async function shutdown(code) {
  await browser?.close().catch(() => {});
  process.exit(code);
}
process.on('SIGINT', () => shutdown(130));
process.on('SIGTERM', () => shutdown(143));

(async () => {
  const only = parseOnly();
  const targets = only ? APPS.filter((a) => only.has(a.name)) : APPS;
  if (!targets.length) {
    console.error(`No matching apps for --only filter. Known apps: ${APPS.map((a) => a.name).join(', ')}`);
    process.exit(1);
  }

  try {
    browser = await launchBrowser();
  } catch (err) {
    console.error(`Could not launch Chrome:\n${err.message}`);
    process.exit(1);
  }

  const results = new Results();

  for (const app of targets) {
    console.log(`\n--- ${app.name} (${app.dir}) ---`);
    let server;
    let page;
    try {
      server = await serveStatic(app.dir);
      page = await browser.newPage();
      page.on('pageerror', (e) => console.error(`  [${app.name}] pageerror:`, e.message));
      page.on('console', (m) => { if (m.type() === 'error') console.error(`  [${app.name}] console error:`, m.text()); });

      const capture = shooter(page, OUT, app.name, results);
      await app.run(page, server.baseUrl, capture);
    } catch (err) {
      results.fail(app.name, '(app run)', err.stack || err.message);
    } finally {
      await page?.close().catch(() => {});
      await server?.close().catch(() => {});
    }
  }

  await browser.close().catch(() => {});

  const allOk = results.summary();
  process.exit(allOk ? 0 : 1);
})().catch(async (err) => {
  console.error('Fatal:', err.stack || err.message);
  await browser?.close().catch(() => {});
  process.exit(1);
});

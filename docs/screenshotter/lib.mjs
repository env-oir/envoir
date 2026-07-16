// docs/screenshotter/lib.mjs
//
// Shared infrastructure for the Envoir screenshotter (see ../capture-screenshots.mjs and
// ../SCREENSHOTS.md). Everything here is deliberately generic across apps:
//
//   - serveStatic()   a zero-dependency static file server (no python3, no extra installs)
//   - launchBrowser() a puppeteer-core loader that reuses the sibling dmtap build's node_modules
//   - shooter()       a capture() helper that REQUIRES a DOM assertion to pass before it will
//                     trust a screenshot, and never throws — failures are recorded so one broken
//                     view can't abort the rest of the run
//   - goToView / setTheme   drive real nav / theme-toggle controls (never pixel coordinates),
//                     and verify afterwards that the app's own state actually changed
//
// This file has no dependencies beyond node's stdlib + puppeteer-core (loaded dynamically).

import http from 'node:http';
import { createReadStream, existsSync, statSync, mkdirSync } from 'node:fs';
import { extname, join, resolve, sep } from 'node:path';

// ---- Chrome + puppeteer-core discovery ------------------------------------------------------
// Both are overridable via env vars for machines that don't match this dev box's layout.
export const CHROME_PATH =
  process.env.CHROME_PATH || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';

const DEFAULT_PUPPETEER_CORE =
  '/Users/pc/code/envoir/dmtap/build/node_modules/puppeteer-core/lib/esm/puppeteer/puppeteer-core.js';

export async function loadPuppeteer() {
  const path = process.env.PUPPETEER_CORE_PATH || DEFAULT_PUPPETEER_CORE;
  try {
    const mod = await import(path);
    return mod.default ?? mod;
  } catch (err) {
    throw new Error(
      `Could not load puppeteer-core from:\n  ${path}\n` +
      `Set PUPPETEER_CORE_PATH to puppeteer-core's ESM entrypoint (or npm-install puppeteer-core ` +
      `locally and point this at it).\nOriginal error: ${err.message}`,
    );
  }
}

export async function launchBrowser() {
  if (!existsSync(CHROME_PATH)) {
    throw new Error(`Chrome not found at:\n  ${CHROME_PATH}\nSet CHROME_PATH to override.`);
  }
  const puppeteer = await loadPuppeteer();
  return puppeteer.launch({
    executablePath: CHROME_PATH,
    headless: true,
    defaultViewport: { width: 1440, height: 900, deviceScaleFactor: 2 },
  });
}

// ---- tiny static file server ----------------------------------------------------------------
// Serves one app directory (client/, console/, superadmin/, status/, site/) on a free localhost
// port. "/" maps to index.html; everything else is a literal path under the app's root, with
// directory-traversal blocked. No SPA history-mode rewriting is needed — every app here is a
// single index.html with hash-based or in-page view switching.
const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png',
  '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.ico': 'image/x-icon', '.woff': 'font/woff',
  '.woff2': 'font/woff2', '.map': 'application/json', '.webp': 'image/webp', '.txt': 'text/plain',
};

export function serveStatic(rootDir) {
  const root = resolve(rootDir);
  return new Promise((res, rej) => {
    const server = http.createServer((req, resp) => {
      try {
        let urlPath = decodeURIComponent((req.url || '/').split('?')[0]);
        if (urlPath === '/' || urlPath === '') urlPath = '/index.html';
        const filePath = resolve(join(root, urlPath));
        if (filePath !== root && !filePath.startsWith(root + sep)) {
          resp.writeHead(403); resp.end('forbidden'); return;
        }
        if (!existsSync(filePath) || statSync(filePath).isDirectory()) {
          resp.writeHead(404); resp.end(`not found: ${urlPath}`); return;
        }
        resp.writeHead(200, { 'Content-Type': MIME[extname(filePath)] || 'application/octet-stream' });
        createReadStream(filePath).pipe(resp);
      } catch (err) {
        resp.writeHead(500); resp.end(String(err && err.message || err));
      }
    });
    server.on('error', rej);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      res({
        baseUrl: `http://127.0.0.1:${port}/`,
        close: () => new Promise((r) => server.close(() => r())),
      });
    });
  });
}

// ---- results ledger -----------------------------------------------------------------------
export class Results {
  constructor() { this.rows = []; }
  ok(app, name, detail) {
    this.rows.push({ app, name, status: 'ok', detail });
    console.log(`  [ok]   ${app}/${name}  ${detail || ''}`);
  }
  skip(app, name, detail) {
    this.rows.push({ app, name, status: 'skip', detail });
    console.warn(`  [skip] ${app}/${name} — ${detail}`);
  }
  fail(app, name, detail) {
    this.rows.push({ app, name, status: 'fail', detail });
    console.error(`  [FAIL] ${app}/${name} — ${detail}`);
  }
  // Returns true iff there were zero required (non-skip) failures.
  summary() {
    const ok = this.rows.filter((r) => r.status === 'ok').length;
    const skip = this.rows.filter((r) => r.status === 'skip').length;
    const fail = this.rows.filter((r) => r.status === 'fail').length;
    console.log('\n' + '='.repeat(78));
    console.log(`Screenshotter summary: ${ok} captured, ${skip} skipped (non-required), ${fail} FAILED`);
    if (skip || fail) {
      for (const r of this.rows) {
        if (r.status !== 'ok') console.log(`  [${r.status.padEnd(4)}] ${r.app}/${r.name} — ${r.detail}`);
      }
    }
    console.log('='.repeat(78));
    return fail === 0;
  }
}

// ---- per-app shot helper --------------------------------------------------------------------
// capture(name, { assert, required, minBytes }) runs `assert` (must resolve without throwing —
// this is the "the expected screen is really on screen" gate, e.g. a waitForSelector on a
// view-specific element or a waitForFunction checking rendered text), takes the screenshot, then
// sanity-checks the PNG is non-trivially sized. It NEVER throws: failures/skips are recorded on
// `results` so the rest of the run continues regardless. Returns true/false for convenience.
export function shooter(page, outDir, appLabel, results) {
  mkdirSync(outDir, { recursive: true });
  return async function capture(name, { assert, required = true, minBytes = 1200 } = {}) {
    try {
      if (assert) await assert();
      const filePath = join(outDir, name);
      await page.screenshot({ path: filePath });
      const size = statSync(filePath).size;
      if (size < minBytes) throw new Error(`PNG only ${size} bytes — looks blank or broken`);
      results.ok(appLabel, name, `${size.toLocaleString()} bytes`);
      return true;
    } catch (err) {
      if (required) results.fail(appLabel, name, err.message);
      else results.skip(appLabel, name, err.message);
      return false;
    }
  };
}

// ---- generic DOM helpers used across every app's simulated SPA shell -----------------------
export const wait = (ms) => new Promise((r) => setTimeout(r, ms));

// Waits until `selector`'s rendered text contains `text` (case-insensitive) — a markup-agnostic
// "did the right screen render" gate that survives most redesigns better than a brittle class
// name would. Used for views that don't have (or might lose) a dedicated wrapper class.
export async function waitForText(page, selector, text, { timeout = 8000 } = {}) {
  await page.waitForFunction(
    (sel, needle) => {
      const el = document.querySelector(sel);
      return !!el && el.textContent.toLowerCase().includes(String(needle).toLowerCase());
    },
    { timeout },
    selector,
    text,
  );
}

// Clicks a nav button by data-view (rail-btn / head-tab / etc.) and gives the SPA a moment to
// re-render. Callers should still assert the resulting view explicitly in capture(); this just
// performs the navigation via the app's real click handler, never synthetic routing.
export async function goToView(page, viewId, { navSelector = '.rail-btn', settle = 250 } = {}) {
  await page.evaluate(
    (sel, id) => { document.querySelector(`${sel}[data-view="${id}"]`)?.click(); },
    navSelector,
    viewId,
  );
  await wait(settle);
}

// Toggles the app's theme via its REAL toggle button (so persisted settings / icon state stay
// correct, per the pattern in the original capture-screenshots.mjs), then verifies
// documentElement really flipped rather than assuming the click worked.
export async function setTheme(page, theme, { toggleSelector = '#theme-toggle', settle = 220 } = {}) {
  await page.evaluate(
    (sel, t) => {
      const current = document.documentElement.getAttribute('data-theme');
      if (current !== t) document.querySelector(sel)?.click();
    },
    toggleSelector,
    theme,
  );
  await wait(settle);
  const got = await page.evaluate(() => document.documentElement.getAttribute('data-theme'));
  if (got !== theme) throw new Error(`theme toggle did not switch to "${theme}" (still "${got}")`);
}

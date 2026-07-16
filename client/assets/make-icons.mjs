#!/usr/bin/env node
// make-icons.mjs — throwaway-but-kept rasterizer: renders assets/logo-mark.svg (the canonical
// Envoir mark) to every PNG size the client needs (favicons + apple-touch-icon), and renders a
// small standalone HTML card to produce the 1200x630 og-image / twitter-card share image.
//
// Requires a local Chrome/Chromium + puppeteer-core (dev-time only; not shipped/loaded by the
// client at runtime — the client only ever references the generated PNGs + the SVGs directly).
//
// Usage: node assets/make-icons.mjs

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const PUPPETEER_CORE = '/Users/pc/code/envoir/dmtap/build/node_modules/puppeteer-core/lib/esm/puppeteer/puppeteer-core.js';

const { default: puppeteer } = await import(PUPPETEER_CORE);

const markSvg = readFileSync(join(HERE, 'logo-mark.svg'), 'utf8');

const ICON_SIZES = [16, 32, 48, 180, 192, 512];

function iconPageHtml(svg, px) {
  return `<!doctype html><html><head><meta charset="utf-8"><style>
    html,body{margin:0;padding:0;background:transparent;width:${px}px;height:${px}px;overflow:hidden;}
    svg{display:block;width:${px}px;height:${px}px;}
  </style></head><body>${svg}</body></html>`;
}

// og-image: brand tile + wordmark on an Aurora Indigo aurora backdrop, 1200x630.
function ogPageHtml(svg) {
  return `<!doctype html><html><head><meta charset="utf-8"><style>
    html,body{margin:0;padding:0;width:1200px;height:630px;overflow:hidden;background:#0a0912;
      font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;}
    .wrap{position:relative;width:1200px;height:630px;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:36px;}
    .aura1{position:absolute;left:-160px;top:-200px;width:900px;height:900px;border-radius:50%;
      background:radial-gradient(circle, rgba(76,77,255,.55), transparent 62%);filter:blur(4px);}
    .aura2{position:absolute;right:-220px;bottom:-260px;width:900px;height:900px;border-radius:50%;
      background:radial-gradient(circle, rgba(154,77,255,.5), transparent 62%);filter:blur(4px);}
    .aura3{position:absolute;left:50%;top:38%;transform:translate(-50%,-50%);width:700px;height:700px;border-radius:50%;
      background:radial-gradient(circle, rgba(0,224,199,.16), transparent 65%);}
    .mark{position:relative;width:190px;height:190px;filter:drop-shadow(0 30px 70px rgba(76,20,255,.55));}
    .mark svg{width:190px;height:190px;display:block;}
    .word{position:relative;font-size:64px;font-weight:800;letter-spacing:-.03em;color:#ecebf6;}
    .tag{position:relative;font-size:24px;font-weight:500;color:#a8a3c1;letter-spacing:-.005em;}
  </style></head><body>
    <div class="wrap">
      <div class="aura1"></div><div class="aura2"></div><div class="aura3"></div>
      <div class="mark">${svg}</div>
      <div class="word">envoir</div>
      <div class="tag">Sovereign mail, chat, calendar &amp; files &mdash; one key is your identity.</div>
    </div>
  </body></html>`;
}

async function main() {
  if (!existsSync(CHROME)) throw new Error(`Chrome not found at ${CHROME}`);
  const browser = await puppeteer.launch({ executablePath: CHROME, headless: 'new' });
  try {
    const page = await browser.newPage();

    for (const px of ICON_SIZES) {
      await page.setViewport({ width: px, height: px, deviceScaleFactor: 1 });
      await page.setContent(iconPageHtml(markSvg, px), { waitUntil: 'load' });
      const el = await page.$('svg');
      const buf = await el.screenshot({ omitBackground: true });
      const name = `favicon-${px}.png`;
      writeFileSync(join(HERE, name), buf);
      console.log(`wrote ${name} (${buf.length} bytes)`);
    }

    await page.setViewport({ width: 1200, height: 630, deviceScaleFactor: 1 });
    await page.setContent(ogPageHtml(markSvg), { waitUntil: 'load' });
    const ogBuf = await page.screenshot({ clip: { x: 0, y: 0, width: 1200, height: 630 } });
    writeFileSync(join(HERE, 'og-image.png'), ogBuf);
    console.log(`wrote og-image.png (${ogBuf.length} bytes)`);
  } finally {
    await browser.close();
  }
}

main().catch((e) => { console.error(e); process.exit(1); });

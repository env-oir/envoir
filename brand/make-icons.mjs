// Rasterize the Envoir brand SVGs into PNG icons for app favicons / PWA / social cards.
// Usage: node brand/make-icons.mjs   (from the repo root or the brand/ dir)
// Chrome + puppeteer-core are reused from the spec build tree (nothing new installed).
import { readFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import puppeteer from "/Users/pc/code/envoir/dmtap/build/node_modules/puppeteer-core/lib/esm/puppeteer/puppeteer-core.js";

const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, "icons");
mkdirSync(out, { recursive: true });
const chrome = process.env.CHROME_PATH ||
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";

// square app-tile icons (transparent corners; the tile carries its own gradient)
const square = [16, 32, 48, 64, 180, 192, 256, 512];

const browser = await puppeteer.launch({ executablePath: chrome, headless: "new", args: ["--no-sandbox"] });

async function render(svgPath, w, h, outPath, transparent) {
  const svg = readFileSync(join(here, svgPath), "utf8");
  const page = await browser.newPage();
  await page.setViewport({ width: w, height: h, deviceScaleFactor: 1 });
  await page.setContent(
    `<!doctype html><html><head><style>*{margin:0;padding:0}html,body{width:${w}px;height:${h}px;overflow:hidden}svg{display:block;width:${w}px;height:${h}px}</style></head><body>${svg}</body></html>`,
    { waitUntil: "networkidle0" });
  await new Promise((r) => setTimeout(r, 60));
  await page.screenshot({ path: outPath, omitBackground: !!transparent });
  await page.close();
}

for (const s of square) {
  await render("logo-mark.svg", s, s, join(out, `icon-${s}.png`), true);
}
// friendly aliases
await render("logo-mark.svg", 180, 180, join(out, "apple-touch-icon.png"), true);
await render("logo-mark.svg", 32, 32, join(out, "favicon-32.png"), true);
await render("logo-mark.svg", 16, 16, join(out, "favicon-16.png"), true);
// social card
await render("og-image.svg", 1200, 630, join(out, "og-image.png"), false);

await browser.close();
console.log(`wrote icons to ${out}: ${square.map((s) => `icon-${s}`).join(", ")}, apple-touch-icon, favicon-16/32, og-image (1200x630)`);

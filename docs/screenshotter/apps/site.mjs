// docs/screenshotter/apps/site.mjs
//
// Captures the Envoir marketing site (site/): a single static landing page. Just the hero, in
// both themes — the rest of the page is long-form marketing copy that doesn't need to churn
// every time docs/README images regenerate.

import { setTheme, wait } from '../lib.mjs';

export async function run(page, baseUrl, capture) {
  await page.goto(baseUrl, { waitUntil: 'networkidle0' });

  // Let the hero's mesh-canvas animation and scroll-reveal settle before capturing.
  await page.waitForSelector('.hero-copy h1', { timeout: 8000 });
  await wait(500);

  await capture('landing-hero.png', {
    assert: async () => {
      await page.waitForSelector('#mesh-canvas', { timeout: 4000 });
      const hasHeading = await page.evaluate(() => {
        const h1 = document.querySelector('.hero-copy h1');
        return !!h1 && h1.textContent.trim().length > 10;
      });
      if (!hasHeading) throw new Error('hero heading missing or empty');
    },
  });

  await setTheme(page, 'light');
  await wait(300);
  await capture('landing-hero-light.png', {
    assert: async () => {
      const hasHeading = await page.evaluate(() => {
        const h1 = document.querySelector('.hero-copy h1');
        return !!h1 && h1.textContent.trim().length > 10;
      });
      if (!hasHeading) throw new Error('hero heading missing or empty');
    },
  });
  await setTheme(page, 'dark');
}

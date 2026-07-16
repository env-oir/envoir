// docs/screenshotter/apps/status.mjs
//
// Captures Envoir Status (status/): the public system-status page in each demo scenario
// (operational / degraded / outage), a light-theme variant, and the authenticated "My status"
// view reached via the real (demo) sign-in modal.

import { setTheme, waitForText, wait } from '../lib.mjs';

async function setScenario(page, id) {
  await page.evaluate((sc) => { document.querySelector(`[data-sc="${sc}"]`)?.click(); }, id);
  await wait(700); // the shell simulates a brief fetch (shimmer) before the real content mounts
}

export async function run(page, baseUrl, capture) {
  await page.goto(baseUrl, { waitUntil: 'networkidle0' });
  await page.waitForSelector('.status-page', { timeout: 8000 });

  // ---- public status page, each demo scenario -----------------------------------------------
  await setScenario(page, 'operational');
  await capture('status-operational.png', {
    assert: () => waitForText(page, '.status-banner', 'operational'),
  });

  await setTheme(page, 'light', { toggleSelector: '#theme' });
  await capture('status-light.png', {
    assert: () => waitForText(page, '.status-banner', 'operational'),
  });
  await setTheme(page, 'dark', { toggleSelector: '#theme' });

  await setScenario(page, 'degraded');
  await capture('status-degraded.png', {
    assert: () => waitForText(page, '.status-banner', 'degrad'),
  });

  await setScenario(page, 'outage');
  await capture('status-outage.png', {
    assert: () => waitForText(page, '.status-banner', ''), // any banner text — outage copy varies
  });

  await setScenario(page, 'operational'); // leave the demo in a clean state before signing in

  // ---- authenticated "My status" view (demo sign-in) -----------------------------------------
  await page.click('#auth');
  await page.waitForSelector('#sgo', { timeout: 6000 });
  await page.click('#sgo');
  await wait(700);
  await capture('status-user.png', {
    assert: () => page.waitForSelector('.status-page', { timeout: 6000 }),
  });
}

// docs/screenshotter/apps/client.mjs
//
// Captures the Envoir web client (client/): runs the real onboarding flow to create a demo
// sovereign identity, then Mail / Chat / Files / Identity in both themes, plus the reading
// pane's transport-path-graph expansion. Mirrors (and generalizes) the original throwaway
// docs/capture-screenshots.mjs, which only drove this one app.

import { goToView, setTheme, wait } from '../lib.mjs';

export async function run(page, baseUrl, capture) {
  await page.goto(baseUrl, { waitUntil: 'networkidle0' });

  // ---- onboarding: create a demo identity ----------------------------------------------------
  await page.waitForSelector('#disp', { timeout: 8000 });
  await page.type('#disp', 'Ada Okonkwo');
  await page.type('#local', 'ada');
  await page.click('#next');

  // Bonus, non-required shots of the onboarding flow itself — nice for docs, but a UI reshuffle
  // here shouldn't fail the whole run since the views below are the real deliverable.
  await capture('onboarding-safety.png', {
    required: false,
    assert: () => page.waitForSelector('.ob-phrase', { timeout: 6000 }),
  });
  await page.click('#next').catch(() => {});

  await capture('onboarding-identity.png', {
    required: false,
    assert: async () => { await page.waitForSelector('.ob-final', { timeout: 6000 }); await wait(200); },
  });
  await page.click('#go').catch(() => {});

  await page.waitForSelector('.rail-btn', { timeout: 8000 });
  await wait(300);

  // ---- Mail -----------------------------------------------------------------------------------
  await goToView(page, 'mail');
  await capture('mail-dark.png', {
    assert: () => page.waitForSelector('.mail-view', { timeout: 6000 }),
  });

  await setTheme(page, 'light');
  await capture('mail-light.png', {
    assert: () => page.waitForSelector('.mail-view', { timeout: 6000 }),
  });
  await setTheme(page, 'dark');

  // Reading-pane transport-path graph (needs an open message with a path button).
  await goToView(page, 'mail');
  await capture('path-graph.png', {
    assert: async () => {
      const btn = await page.$('[data-pathbtn]');
      if (!btn) throw new Error('no [data-pathbtn] found on the currently-open message');
      await btn.click();
      await wait(300);
    },
  });

  // ---- Chat -----------------------------------------------------------------------------------
  await goToView(page, 'chat');
  await capture('chat-dark.png', {
    assert: () => page.waitForSelector('.chat-view', { timeout: 6000 }),
  });

  await setTheme(page, 'light');
  await capture('chat-light.png', {
    assert: () => page.waitForSelector('.chat-view', { timeout: 6000 }),
  });
  await setTheme(page, 'dark');

  // ---- Files ----------------------------------------------------------------------------------
  await goToView(page, 'files');
  await capture('files-dark.png', {
    assert: () => page.waitForSelector('.files-view', { timeout: 6000 }),
  });

  await setTheme(page, 'light');
  await capture('files-light.png', {
    assert: () => page.waitForSelector('.files-view', { timeout: 6000 }),
  });
  await setTheme(page, 'dark');

  // ---- Identity (safety number view) -----------------------------------------------------------
  await goToView(page, 'identity');
  await capture('identity-dark.png', {
    assert: () => page.waitForSelector('.identity-view', { timeout: 6000 }),
  });

  await setTheme(page, 'light');
  await capture('identity-light.png', {
    assert: () => page.waitForSelector('.identity-view', { timeout: 6000 }),
  });
  await setTheme(page, 'dark');
}

// docs/screenshotter/apps/console.mjs
//
// Captures the Envoir Management Console (console/): runs the real "connect your domain" setup
// (generates a real Ed25519 domain-authority keypair + seeds a believable demo org), then the
// Overview, Members, Directory and Billing views in both themes where useful.

import { goToView, setTheme, waitForText, wait } from '../lib.mjs';

export async function run(page, baseUrl, capture) {
  await page.goto(baseUrl, { waitUntil: 'networkidle0' });

  // ---- setup: "connect your domain" ----------------------------------------------------------
  await page.waitForSelector('#dom', { timeout: 8000 });
  await page.type('#dom', 'abc.com');
  await page.click('#next');

  await page.waitForSelector('#go', { timeout: 8000 });
  await page.click('#go');

  // Seeding generates several real Ed25519 keypairs (members + authority) — give it real headroom.
  await page.waitForSelector('.rail-btn', { timeout: 15000 });
  await wait(400);

  // ---- Overview ---------------------------------------------------------------------------------
  await goToView(page, 'overview');
  await capture('console-overview-dark.png', {
    assert: () => waitForText(page, '#view', 'Overview'),
  });

  await setTheme(page, 'light');
  await capture('console-overview-light.png', {
    assert: () => waitForText(page, '#view', 'Overview'),
  });
  await setTheme(page, 'dark');

  // ---- Members (sovereign vs org-managed custody) ------------------------------------------------
  await goToView(page, 'members');
  await capture('console-members-dark.png', {
    assert: () => waitForText(page, '#view', 'Members'),
  });

  // ---- Directory (GAL) --------------------------------------------------------------------------
  await goToView(page, 'directory');
  await capture('console-directory-dark.png', {
    assert: () => waitForText(page, '#view', 'Directory'),
  });

  // ---- Billing (dmtap-seam) ----------------------------------------------------------------------
  await goToView(page, 'billing');
  await capture('console-billing-dark.png', {
    assert: () => waitForText(page, '#view', 'Billing'),
  });
}

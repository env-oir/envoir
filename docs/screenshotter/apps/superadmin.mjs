// docs/screenshotter/apps/superadmin.mjs
//
// Captures the Envoir Superadmin (superadmin/): it auto-seeds a believable fleet snapshot on
// first load (no setup flow), so this just waits for the shell to mount and walks Overview,
// Fleet, Abuse ops and Billing.

import { goToView, setTheme, waitForText, wait } from '../lib.mjs';

export async function run(page, baseUrl, capture) {
  await page.goto(baseUrl, { waitUntil: 'networkidle0' });
  await page.waitForSelector('.rail-btn', { timeout: 10000 });
  await wait(300);

  // ---- Overview ---------------------------------------------------------------------------------
  await goToView(page, 'overview');
  await capture('superadmin-overview-dark.png', {
    assert: () => waitForText(page, '#view', 'Overview'),
  });

  await setTheme(page, 'light');
  await capture('superadmin-overview-light.png', {
    assert: () => waitForText(page, '#view', 'Overview'),
  });
  await setTheme(page, 'dark');

  // ---- Fleet (nodes / gateways / mix nodes / relays) ---------------------------------------------
  await goToView(page, 'fleet');
  await capture('superadmin-fleet-dark.png', {
    assert: () => waitForText(page, '#view', 'Fleet'),
  });

  // ---- Abuse ops (content-blind by construction) -------------------------------------------------
  await goToView(page, 'abuse');
  await capture('superadmin-abuse-dark.png', {
    assert: () => waitForText(page, '#view', 'Abuse'),
  });

  // ---- Billing (dmtap-seam metering) ---------------------------------------------------------------
  await goToView(page, 'billing');
  await capture('superadmin-billing-dark.png', {
    assert: () => waitForText(page, '#view', 'Billing'),
  });
}

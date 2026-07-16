// app.js — boot controller. Loads (or creates) the sovereign identity, then mounts the
// unified shell. Everything network-facing is simulated (seed.js + mesh-sim.js) and labeled;
// the crypto (keygen, signing, hashing, safety-number derivation) is real Web Crypto.

import { loadIdentity } from './identity.js';
import { renderOnboarding } from './onboarding.js';
import { mountShell } from './shell.js';
import { registerServiceWorker, onWakeSync } from './pwa.js';

(async function main() {
  const id = await loadIdentity();
  if (id) mountShell();
  else renderOnboarding(() => mountShell());

  // PWA: register the service worker (app-shell offline cache + push wake-pings). Guarded and
  // fully optional — a browser/context without serviceWorker support just skips this, and the
  // rest of the app is unaffected either way.
  registerServiceWorker();
  onWakeSync(() => {
    import('./ui.js').then(({ toast, icon }) => toast(`${icon('bell')} Wake ping received — syncing over the mesh…`, { ms: 3600 }));
  });
})();

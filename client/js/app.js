// app.js — boot controller. Loads (or creates) the sovereign identity, then mounts the
// unified shell. Everything network-facing is simulated (seed.js + mesh-sim.js) and labeled;
// the crypto (keygen, signing, hashing, safety-number derivation) is real Web Crypto.

import { loadIdentity } from './identity.js';
import { renderOnboarding } from './onboarding.js';
import { mountShell } from './shell.js';

(async function main() {
  const id = await loadIdentity();
  if (id) mountShell();
  else renderOnboarding(() => mountShell());
})();

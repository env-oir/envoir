// app.js — boot controller for the Envoir Superadmin. Loads a persisted fleet snapshot or seeds a
// believable one, then mounts the shell. Everything network-facing (the enrollment registry, the
// dmtap-seam metering/provisioning endpoints, the alert bus) is SIMULATED by store.js and clearly
// labeled — a production superadmin swaps store.js for a read model over the operator data plane.

import { load, hasSession, seed } from './store.js';
import { mountShell } from './shell.js';

(async function main() {
  if (!(hasSession() && await load())) seed();
  mountShell();
})();

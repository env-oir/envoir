// app.js — boot controller for the Envoir Management Console. Loads an existing admin session
// (domain authority + org state) or runs setup, then mounts the shell. The crypto (authority
// keygen, directory signing, member keypairs, safety numbers) is real Web Crypto; the node /
// DNS / KT log / mesh are simulated by store.js and clearly labeled.

import { load, hasSession } from './store.js';
import { loadAuthority } from './session.js';
import { renderSetup } from './setup.js';
import { mountShell } from './shell.js';

(async function main() {
  if (hasSession() && loadAuthority() && await load()) mountShell();
  else renderSetup(() => mountShell());
})();

// app.js — boot controller for Envoir Status. Loads saved prefs (theme / scenario / signed-in),
// then mounts the shell which orchestrates a brief loading state before rendering the public feed
// or the authenticated user view. The feed + per-user probe are SIMULATED by store.js and labeled.

import { loadPrefs } from './store.js';
import { mountShell } from './shell.js';

loadPrefs();
mountShell();

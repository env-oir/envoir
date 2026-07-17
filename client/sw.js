// sw.js — Envoir service worker: offline app-shell cache + content-free "wake ping" push.
//
// This app has no build step, so the precache list below is maintained by hand next to the
// module list in README.md — bump CACHE_VERSION whenever files are added/removed/renamed.
//
// Push is metadata-minimizing by design (spec §7/§8's honest-privacy model): a push event is a
// sender-blind, content-free signal meaning only "your node has something new — open to sync
// over the mesh." Whatever bytes a push service delivers as event.data (if any) are deliberately
// NEVER read or shown here — the notification copy below is a fixed, generic string. The real
// MOTE (sender, subject, body) is pulled later over the user's own mesh connection, end-to-end,
// once the app is open; it never rides in the push payload.

const CACHE_VERSION = 'envoir-shell-v2';

const PRECACHE_URLS = [
  './',
  './index.html',
  './manifest.webmanifest',
  './css/app.css',
  './js/app.js',
  './js/shell.js',
  './js/bus.js',
  './js/store.js',
  './js/onboarding.js',
  './js/identity.js',
  './js/safety.js',
  './js/mote.js',
  './js/mesh-sim.js',
  './js/resolver.js',
  './js/seed.js',
  './js/compose.js',
  './js/signin.js',
  './js/ui.js',
  './js/avatar.js',
  './js/profileModal.js',
  './js/provenance.js',
  './js/pwa.js',
  './js/views/mail.js',
  './js/views/chat.js',
  './js/views/calendar.js',
  './js/views/contacts.js',
  './js/views/files.js',
  './js/views/identity.js',
  './js/views/groups.js',
  './js/views/settings.js',
  './assets/logo-mark.svg',
  './assets/logo-mono.svg',
  './assets/wordmark.svg',
  './assets/favicon-16.png',
  './assets/favicon-32.png',
  './assets/favicon-48.png',
  './assets/favicon-180.png',
  './assets/favicon-192.png',
  './assets/favicon-512.png',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_VERSION)
      .then((cache) => cache.addAll(PRECACHE_URLS))
      .then(() => self.skipWaiting())
      .catch((err) => console.warn('envoir sw: precache failed', err)),
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE_VERSION).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

// Cache-first for the precached app shell (css/js/assets — content-hashless, so a version bump
// on CACHE_VERSION is what invalidates them); network-first for navigations, falling back to the
// cached shell so a reload while offline still boots the app. Nothing here is "live data" — this
// client's mail/chat/etc. are simulated in-memory (seed.js), not fetched — so there is no
// separate "data" origin to treat network-first the way a real backend-backed client would.
self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return; // this app loads nothing cross-origin

  if (req.mode === 'navigate') {
    event.respondWith(
      fetch(req).catch(() => caches.match('./index.html').then((r) => r || Response.error())),
    );
    return;
  }

  event.respondWith(
    caches.match(req).then((cached) => {
      if (cached) return cached;
      return fetch(req).then((res) => {
        if (res && res.ok) {
          const copy = res.clone();
          caches.open(CACHE_VERSION).then((cache) => cache.put(req, copy)).catch(() => {});
        }
        return res;
      }).catch(() => cached);
    }),
  );
});

// ---- Web Push: content-free wake ping ------------------------------------------------------
function wakePing() {
  return self.registration.showNotification('New activity — open to sync', {
    body: 'Your node has something new. This ping never carries the sender or the content.',
    icon: './assets/favicon-192.png',
    badge: './assets/favicon-192.png',
    tag: 'envoir-wake',
    renotify: true,
  }).then(() => self.clients.matchAll({ type: 'window', includeUncontrolled: true }))
    .then((clients) => clients.forEach((c) => c.postMessage({ type: 'ENVOIR_WAKE_SYNC', at: Date.now() })))
    .catch((err) => console.warn('envoir sw: wake ping failed (likely no notification permission)', err));
}

self.addEventListener('push', (event) => {
  // Deliberately not reading event.data — see file header.
  event.waitUntil(wakePing());
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clients) => {
      const existing = clients.find((c) => 'focus' in c);
      if (existing) return existing.focus();
      return self.clients.openWindow('./index.html');
    }),
  );
});

// Local dev/demo path (no real push backend exists here): the Settings "Send test wake-ping"
// button posts this message to run the exact push -> notification code path above.
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'ENVOIR_TEST_WAKE_PING') {
    event.waitUntil(wakePing());
  }
});

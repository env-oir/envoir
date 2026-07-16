// pwa.js — service worker registration, install-prompt capture, and the Web Push (RFC 8291-style)
// client plumbing for the content-free "wake ping" model implemented in sw.js. Everything here
// degrades silently where unsupported (no serviceWorker, no PushManager, no Notification) — it
// must never block the normal (non-PWA) app path.

export const swSupported = typeof navigator !== 'undefined' && 'serviceWorker' in navigator;
export const pushSupported = swSupported && typeof window !== 'undefined' && 'PushManager' in window;
export const notifSupported = typeof Notification !== 'undefined';

// ---- Install affordance (beforeinstallprompt) ----------------------------------------------
let deferredInstallPrompt = null;
const installListeners = [];
export function onInstallPromptChange(fn) { installListeners.push(fn); }
function fireInstallListeners() { installListeners.forEach((fn) => { try { fn(!!deferredInstallPrompt); } catch { /* ignore */ } }); }

if (typeof window !== 'undefined') {
  window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault();
    deferredInstallPrompt = e;
    fireInstallListeners();
  });
  window.addEventListener('appinstalled', () => {
    deferredInstallPrompt = null;
    fireInstallListeners();
  });
}

export const canInstall = () => !!deferredInstallPrompt;
export function isStandalone() {
  if (typeof window === 'undefined') return false;
  return (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches) || window.navigator.standalone === true;
}
export async function promptInstall() {
  if (!deferredInstallPrompt) return { outcome: 'unavailable' };
  deferredInstallPrompt.prompt();
  const choice = await deferredInstallPrompt.userChoice;
  deferredInstallPrompt = null;
  fireInstallListeners();
  return choice;
}

// ---- Service worker registration -------------------------------------------------------------
let swRegistration = null;
export async function registerServiceWorker() {
  if (!swSupported) return null;
  try {
    swRegistration = await navigator.serviceWorker.register('./sw.js');
    return swRegistration;
  } catch (err) {
    console.warn('Envoir: service worker registration failed (app still works without it)', err);
    return null;
  }
}
export function getRegistration() { return swRegistration; }

// ---- Web Push (client half) -------------------------------------------------------------------
// Placeholder applicationServerKey: a real-format (65-byte uncompressed P-256 point) demo key so
// PushManager.subscribe() exercises the genuine browser API end-to-end. A real Envoir node would
// generate its own VAPID keypair locally and hand only the public half here — never a shared,
// provider-wide key — since the whole point is that YOUR node is the one waking your client.
const DEMO_VAPID_PUBLIC_KEY =
  'BOtR_vkFWfg6GCPT4ZRCmzOI_6rInHB07aNEJii6fYSyFclQISLjb6lTmBE5UTJ9Wb0MZbQhWOLK7U1XBBVf3MM';

function urlB64ToUint8Array(base64String) {
  const padding = '='.repeat((4 - (base64String.length % 4)) % 4);
  const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(base64);
  return Uint8Array.from([...raw].map((c) => c.charCodeAt(0)));
}

export function notificationPermission() { return notifSupported ? Notification.permission : 'unsupported'; }
export async function requestNotificationPermission() {
  if (!notifSupported) return 'unsupported';
  return Notification.requestPermission();
}

export async function getPushSubscription() {
  if (!pushSupported || !swRegistration) return null;
  return swRegistration.pushManager.getSubscription();
}
export async function subscribePush() {
  if (!pushSupported || !swRegistration) throw new Error('Push not supported in this browser/context');
  const existing = await swRegistration.pushManager.getSubscription();
  if (existing) return existing;
  return swRegistration.pushManager.subscribe({
    userVisibleOnly: true,
    applicationServerKey: urlB64ToUint8Array(DEMO_VAPID_PUBLIC_KEY),
  });
}
export async function unsubscribePush() {
  const sub = await getPushSubscription();
  if (sub) await sub.unsubscribe();
}

// Local simulation only: posts straight to the active service worker so it runs the exact same
// push -> notification code path as a real push event — no real push backend or network involved.
export async function sendTestWakePing() {
  if (!swSupported) throw new Error('Service workers are not supported in this browser');
  if (!swRegistration) throw new Error('No service worker registered yet');
  const reg = await navigator.serviceWorker.ready;
  if (!reg.active) throw new Error('Service worker is not active yet');
  reg.active.postMessage({ type: 'ENVOIR_TEST_WAKE_PING' });
}

// Fires when the service worker tells the page a wake-sync happened (real push or the local
// test-ping simulation) — a client can use this to trigger its own "resync" UI affordance.
export function onWakeSync(fn) {
  if (!swSupported) return;
  navigator.serviceWorker.addEventListener('message', (event) => {
    if (event.data && event.data.type === 'ENVOIR_WAKE_SYNC') fn(event.data);
  });
}

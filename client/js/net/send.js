// net/send.js — REAL outbound send over the node's Envoir Send API (POST /v1/send, spec §13.5.1).
//
// WHY NOT JMAP EmailSubmission. The node's JMAP surface (crates/dmtap-mail) *does* answer
// EmailSubmission/set — but only as an ECHO: `jmap::process` is handed the mail STORE, never the
// running Node (node/src/jmap_api.rs), so an EmailSubmission neither seals nor dispatches a MOTE
// onto the wire; it just records intent. An Email/set create likewise only appends bytes to a
// mailbox. The ONLY path that genuinely seals a MOTE and routes it into the node's real §20.1
// outbound retry queue + mesh dispatch is POST /v1/send (node/src/send_api.rs → Node::dispatch_sealed).
// So an honest "real send" uses the Send API; leaning on EmailSubmission would report a delivery
// that never left the node — a fake "sent".
//
// The Send API authenticates with a Bearer CAPABILITY TOKEN — a scoped, rotatable send key issued
// by the node (spec §13.5.1), SEPARATE from the JMAP app-password. Minting that key is an admin
// operation (POST /v1/keys, admin-token-guarded on the node); provisioning it into this client is
// the remaining seam. It is surfaced alongside the app-password in Settings → Node.
//
// The transport (SendClient) is DELIBERATELY DOM-FREE and state-free — it depends only on `fetch` —
// so it smoke-tests under Node against a mock emitting the node's exact wire shapes, exactly like
// net/jmap.js. The app-facing `sendMail()` / `sendMode()` helpers below read the saved node config.

import { state, resolveNodeConfig } from '../store.js';

const DEFAULT_BASE_URL = 'http://127.0.0.1:4700';

export { DEFAULT_BASE_URL };

/** A Send-API error carrying the HTTP status, the node's machine-readable slug, and its detail. */
export class SendApiError extends Error {
  constructor(message, { status = 0, slug = null, detail = null } = {}) {
    super(message);
    this.name = 'SendApiError';
    this.status = status;
    this.slug = slug;
    this.detail = detail;
  }
}

// Map the node's stable error slug (dmtap-send `error_slug`) + our client-side slugs onto a short,
// human sentence. Unknown slugs fall through to the raw detail so nothing is ever silently masked.
const SLUG_MESSAGES = {
  no_token: 'no send token — add one in Settings → Node',
  bad_request: 'the message was rejected as malformed',
  unreachable: 'the node could not be reached',
  malformed: 'the node returned an unexpected response',
  unauthorized: 'the send token was rejected',
  revoked: 'the send token has been revoked',
  expired: 'the send token has expired',
  not_yet_valid: 'the send token is not yet valid',
  wrong_issuer: 'the send token was issued by a different node',
  capability_invalid: 'the send token is invalid',
  out_of_scope: 'this From address is outside the token’s scope',
  rate_limited: 'the send rate limit was hit — try again shortly',
  unresolvable_recipient: 'the recipient could not be resolved',
  delivery_failed: 'the node could not deliver the message',
  build_failed: 'the message could not be sealed',
};

function sendErrorMessage(slug, detail, status) {
  if (slug && SLUG_MESSAGES[slug]) return SLUG_MESSAGES[slug];
  if (detail) return detail;
  return `send failed (HTTP ${status})`;
}

/**
 * A live client for the node's Envoir Send API. DOM-free / state-free: pass it a base URL and a
 * Bearer capability token and it speaks `POST /v1/send` (spec §13.5.1) and nothing else.
 *
 * @param {object} cfg
 * @param {string} cfg.baseUrl    node base URL (default http://127.0.0.1:4700)
 * @param {string} cfg.token      send capability token (Bearer)
 * @param {number} [cfg.timeoutMs] per-request timeout (default 8000)
 */
export class SendClient {
  constructor({ baseUrl, token, timeoutMs = 8000 } = {}) {
    this.baseUrl = (baseUrl || DEFAULT_BASE_URL).replace(/\/+$/, '');
    this.token = token || '';
    this.timeoutMs = timeoutMs;
    this.sendUrl = `${this.baseUrl}/v1/send`;
  }

  /**
   * POST /v1/send. Builds the Resend-shaped body `{ from, to, subject, body, mime? }`, authenticates
   * with the Bearer token, and returns the node's receipt `{ id, native, transport }` on 200. Any
   * non-2xx (or transport failure) throws a {@link SendApiError} carrying the node's error slug +
   * detail — so a failed send can NEVER masquerade as a success.
   */
  async send({ from, to, subject = '', body = '', mime } = {}) {
    if (!this.token) throw new SendApiError(SLUG_MESSAGES.no_token, { slug: 'no_token' });
    if (!to) throw new SendApiError('a recipient is required', { slug: 'bad_request' });

    const payload = { from: from || '', to, subject: subject || '', body: body || '' };
    if (mime) payload.mime = mime;

    const ctrl = typeof AbortController !== 'undefined' ? new AbortController() : null;
    const timer = ctrl ? setTimeout(() => ctrl.abort(), this.timeoutMs) : null;
    let res;
    try {
      res = await fetch(this.sendUrl, {
        method: 'POST',
        signal: ctrl ? ctrl.signal : undefined,
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
          Authorization: `Bearer ${this.token}`,
        },
        body: JSON.stringify(payload),
      });
    } catch (err) {
      throw new SendApiError(SLUG_MESSAGES.unreachable, {
        slug: 'unreachable',
        detail: err && err.message ? err.message : String(err),
      });
    } finally {
      if (timer) clearTimeout(timer);
    }

    let parsed = null;
    try { parsed = await res.json(); } catch { /* non-JSON / empty body */ }

    if (!res.ok) {
      const slug = (parsed && typeof parsed.error === 'string') ? parsed.error : `http_${res.status}`;
      const detail = parsed && parsed.detail != null ? String(parsed.detail) : null;
      throw new SendApiError(sendErrorMessage(slug, detail, res.status), { status: res.status, slug, detail });
    }
    if (!parsed || typeof parsed.id !== 'string') {
      throw new SendApiError(SLUG_MESSAGES.malformed, { status: res.status, slug: 'malformed' });
    }
    return { id: parsed.id, native: !!parsed.native, transport: parsed.transport || null };
  }
}

// ---- App-facing helpers (read the saved / injected node config) -----------------------------

/**
 * The honest send capability of the current session:
 *   'real' → REAL mode (live node) AND a send token is configured → POST /v1/send genuinely sends
 *   'seam' → REAL mode but NO send token → sending is NOT wired; never fake a "sent"
 *   'sim'  → SIMULATION mode → compose uses the labeled mesh-sim animation
 */
export function sendMode() {
  const cfg = resolveNodeConfig();
  if (state.net && state.net.mode === 'real') return cfg.sendToken ? 'real' : 'seam';
  return 'sim';
}

/**
 * Send `msg` for real via the node's Send API. `msg = { to, subject, body, mime?, from? }`.
 * `from` defaults to the connected account id. Throws {@link SendApiError} on any failure.
 * Returns the node's receipt `{ id, native, transport }`.
 */
export async function sendMail(msg = {}) {
  const cfg = resolveNodeConfig();
  if (!cfg.sendToken) throw new SendApiError(SLUG_MESSAGES.no_token, { slug: 'no_token' });
  const from = msg.from || (state.net && state.net.accountId) || cfg.username || '';
  const client = new SendClient({ baseUrl: cfg.baseUrl, token: cfg.sendToken });
  return client.send({ from, to: msg.to, subject: msg.subject, body: msg.body, mime: msg.mime });
}

export default SendClient;

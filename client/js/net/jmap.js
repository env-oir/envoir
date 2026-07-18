// net/jmap.js — a REAL JMAP client (RFC 8620 Core + RFC 8621 Mail) that talks to the user's
// own node's native JMAP listener (spec §8.1). This is the seam that turns the client from a
// simulation into a real product: it speaks the exact wire shapes the node serves at
// `http://127.0.0.1:4700` (default) — Session discovery, batched method calls with
// back-references, incremental /changes, and blob download — authenticated with an HTTP Basic
// app-password (spec §8.2).
//
// DELIBERATELY DOM-FREE. This module depends only on `fetch`, `TextEncoder`, and a base64
// primitive — no `document`, no `localStorage`, no app state — so it runs unchanged in the
// browser, in a Tauri shell, and under Node, where it is smoke-tested against mocks emitting
// the node's exact wire shapes (client/test/net.test.mjs, run via `npm run test:client`).
// Everything app-facing (state, mapping to the UI's thread shape, mode switching) lives
// one layer up in net/sync.js.

const DEFAULT_BASE_URL = 'http://127.0.0.1:4700';
const CAP_CORE = 'urn:ietf:params:jmap:core';
const CAP_MAIL = 'urn:ietf:params:jmap:mail';
const CAP_SUBMISSION = 'urn:ietf:params:jmap:submission';

export { DEFAULT_BASE_URL, CAP_CORE, CAP_MAIL, CAP_SUBMISSION };

// Base64 of arbitrary bytes, in whatever runtime we're in (browser btoa / Node Buffer).
function base64(bytes) {
  if (typeof btoa !== 'undefined') {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }
  // eslint-disable-next-line no-undef
  return Buffer.from(bytes).toString('base64');
}

// The HTTP Basic credential `username:app-password` (RFC 7617). The password may itself contain
// ':' — Basic concatenates on the FIRST colon, so this is unambiguous.
function basicAuth(username, password) {
  const raw = new TextEncoder().encode(`${username}:${password}`);
  return 'Basic ' + base64(raw);
}

/** A JMAP transport error carrying the HTTP status and any parsed problem body. */
export class JmapError extends Error {
  constructor(message, { status = 0, body = null } = {}) {
    super(message);
    this.name = 'JmapError';
    this.status = status;
    this.body = body;
  }
}

/**
 * A live JMAP client bound to one node account.
 *
 * @param {object} cfg
 * @param {string} cfg.baseUrl      node base URL (default http://127.0.0.1:4700)
 * @param {string} cfg.username     account id / login (e.g. you@your-node)
 * @param {string} cfg.appPassword  app-password (spec §8.2)
 * @param {number} [cfg.timeoutMs]  per-request timeout (default 8000)
 */
export class JmapClient {
  constructor({ baseUrl, username, appPassword, timeoutMs = 8000 } = {}) {
    this.baseUrl = (baseUrl || DEFAULT_BASE_URL).replace(/\/+$/, '');
    this.username = username || '';
    this.appPassword = appPassword || '';
    this.timeoutMs = timeoutMs;
    // Filled in by session(): the account id + resource URLs the node advertises.
    this.session = null;
    this.accountId = username || '';
    this.apiUrl = `${this.baseUrl}/jmap/api/`;
    this.downloadUrl = `${this.baseUrl}/jmap/download/{accountId}/{blobId}/{name}`;
  }

  get authHeader() {
    return basicAuth(this.username, this.appPassword);
  }

  // A fetch with a bounded timeout and Basic auth. Never throws on non-2xx here — the caller
  // decides how to treat each route's status codes.
  async _fetch(url, init = {}) {
    const ctrl = typeof AbortController !== 'undefined' ? new AbortController() : null;
    const timer = ctrl ? setTimeout(() => ctrl.abort(), this.timeoutMs) : null;
    try {
      return await fetch(url, {
        ...init,
        signal: ctrl ? ctrl.signal : undefined,
        headers: { Authorization: this.authHeader, ...(init.headers || {}) },
      });
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  /**
   * GET /jmap/session (RFC 8620 §2). Discovers the account id, the `state` token, and the
   * api/download URLs. Caches the result on the client. A 401 means bad/absent app-password.
   */
  async discover() {
    const res = await this._fetch(`${this.baseUrl}/jmap/session`, {
      headers: { Accept: 'application/json' },
    });
    if (res.status === 401) throw new JmapError('unauthorized (app-password rejected)', { status: 401 });
    if (!res.ok) throw new JmapError(`session discovery failed (HTTP ${res.status})`, { status: res.status });
    const s = await res.json();
    this.session = s;
    // primaryAccounts.<mail> is the account to address method calls to.
    this.accountId = (s.primaryAccounts && s.primaryAccounts[CAP_MAIL]) || s.username || this.username;
    if (typeof s.apiUrl === 'string' && s.apiUrl) this.apiUrl = s.apiUrl;
    if (typeof s.downloadUrl === 'string' && s.downloadUrl) this.downloadUrl = s.downloadUrl;
    return s;
  }

  /** The current session `state` token (available after discover()). */
  get sessionState() {
    return (this.session && this.session.state) || null;
  }

  /** A cheap reachability + auth probe: resolves true iff the node answers session with 200. */
  async ping() {
    try {
      await this.discover();
      return true;
    } catch {
      return false;
    }
  }

  /**
   * POST /jmap/api/ (RFC 8620 §3.3): send a batch of method calls in the standard envelope
   * `{ using, methodCalls, createdIds }` and return the parsed Response. `methodCalls` are raw
   * `[name, args, callId]` triples; back-reference args (`"#ids": {...}`) are passed through
   * verbatim and resolved server-side (RFC 8620 §3.7).
   */
  async request(methodCalls, { using, createdIds } = {}) {
    const envelope = {
      using: using || [CAP_CORE, CAP_MAIL, CAP_SUBMISSION],
      methodCalls,
    };
    if (createdIds) envelope.createdIds = createdIds;
    const res = await this._fetch(this.apiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify(envelope),
    });
    if (res.status === 401) throw new JmapError('unauthorized', { status: 401 });
    let body = null;
    try { body = await res.json(); } catch { /* fall through to status error */ }
    if (!res.ok) throw new JmapError(`JMAP request failed (HTTP ${res.status})`, { status: res.status, body });
    if (!body || !Array.isArray(body.methodResponses)) {
      throw new JmapError('malformed JMAP response', { status: res.status, body });
    }
    return new JmapResponse(body);
  }

  // ---- Typed convenience wrappers over request() ------------------------------------------

  /** Mailbox/get (RFC 8621 §2.3). `ids=null` → all mailboxes. */
  async mailboxGet(ids = null) {
    const r = await this.request([
      ['Mailbox/get', { accountId: this.accountId, ids }, 'mb'],
    ]);
    return r.arguments('mb');
  }

  /** Email/query (RFC 8621 §4.4) → the list of matching Email ids. */
  async emailQuery(filter = null, extra = {}) {
    const args = { accountId: this.accountId, ...extra };
    if (filter) args.filter = filter;
    const r = await this.request([['Email/query', args, 'q']]);
    return r.arguments('q');
  }

  /** Email/get (RFC 8621 §4.2). `ids=null` → every email (the node bounds this to the store). */
  async emailGet(ids = null, properties = null) {
    const args = { accountId: this.accountId, ids };
    if (properties) args.properties = properties;
    const r = await this.request([['Email/get', args, 'g']]);
    return r.arguments('g');
  }

  /**
   * Email/query + Email/get chained via a back-reference in ONE round-trip (RFC 8620 §3.7):
   * the get's `#ids` resolves against the query's `/ids`. Returns the Email/get arguments.
   */
  async emailQueryGet(filter = null, properties = null) {
    const qArgs = { accountId: this.accountId };
    if (filter) qArgs.filter = filter;
    const gArgs = {
      accountId: this.accountId,
      '#ids': { resultOf: 'q', name: 'Email/query', path: '/ids' },
    };
    if (properties) gArgs.properties = properties;
    const r = await this.request([
      ['Email/query', qArgs, 'q'],
      ['Email/get', gArgs, 'g'],
    ]);
    return r.arguments('g');
  }

  /** Thread/get (RFC 8621 §3.2) → thread objects with their `emailIds`. */
  async threadGet(ids) {
    const r = await this.request([
      ['Thread/get', { accountId: this.accountId, ids }, 't'],
    ]);
    return r.arguments('t');
  }

  /**
   * Email/changes (RFC 8620 §5.2): the incremental delta since `sinceState`. Returns the
   * changes arguments, or `{ cannotCalculateChanges: true }` when the token is unrecognizable
   * (the caller then falls back to a full re-pull).
   */
  async emailChanges(sinceState) {
    const r = await this.request([
      ['Email/changes', { accountId: this.accountId, sinceState }, 'c'],
    ]);
    const args = r.arguments('c');
    if (args && args.type === 'cannotCalculateChanges') return { cannotCalculateChanges: true };
    return args;
  }

  /**
   * GET /jmap/download/{accountId}/{blobId}/{name} (RFC 8620 §6.2): the raw RFC 5322 bytes of an
   * Email blob. Returns an ArrayBuffer (browser) / Buffer-backed ArrayBuffer (Node).
   */
  async blobDownload(blobId, name = 'message.eml') {
    const url = this.downloadUrl
      .replace('{accountId}', encodeURIComponent(this.accountId))
      .replace('{blobId}', encodeURIComponent(blobId))
      .replace('{name}', encodeURIComponent(name));
    const res = await this._fetch(url);
    if (!res.ok) throw new JmapError(`blob download failed (HTTP ${res.status})`, { status: res.status });
    return res.arrayBuffer();
  }
}

/** A parsed JMAP Response with helpers to pull a method call's result by its callId. */
export class JmapResponse {
  constructor(body) {
    this.methodResponses = body.methodResponses || [];
    this.sessionState = body.sessionState || null;
    this.createdIds = body.createdIds || null;
  }

  /** The full `[name, args, callId]` invocation for a callId (the FIRST match), or null. */
  invocation(callId) {
    return this.methodResponses.find((m) => m[2] === callId) || null;
  }

  /**
   * The arguments object for a callId. Throws JmapError if that call came back as a method-level
   * `error` (RFC 8620 §3.6.1) so a failed method never masquerades as an empty-but-ok result.
   */
  arguments(callId) {
    const inv = this.invocation(callId);
    if (!inv) return null;
    const [name, args] = inv;
    if (name === 'error') {
      throw new JmapError(`method error: ${args && args.type ? args.type : 'unknown'}`, { body: args });
    }
    return args;
  }
}

export default JmapClient;

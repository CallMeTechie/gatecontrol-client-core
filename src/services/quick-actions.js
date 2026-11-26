'use strict';

/**
 * GateControl – plugin quick actions (Core service)
 *
 * The data side of "Schnellaktionen" in the Windows apps (the Pro client pins
 * them to its start page): the actions the plugins offer the device's user
 * (light, shutters, heating, chains …) and running one, over the device token
 * of the existing ApiClient (contract: server src/routes/api/client/actions.js,
 * fields up to 1.317.1; utils/quick-actions.js checks every answer):
 *
 *   GET  /api/v1/client/actions?lang=de|en      → the actions of every plugin
 *   POST /api/v1/client/actions/<plugin>/<id>   { source: 'app', control?, value?, state? }
 *
 * - list(): the actions as checked; a server without the route (404, before
 *   quick actions) answers `supported: false` — no error. While the server
 *   cannot be asked the last answer of this server comes back with
 *   `offline: true` (and the reason); without one { ok: false, reason }.
 * - run(): { ok, message, state, widget, unchanged } of the server — the new
 *   widget (if the plugin sent one) also replaces the copy kept for list() —
 *   or { ok: false, reason, status, message } with reason from
 *   utils/quick-actions.js failureReason (control_disabled, gone, no_user,
 *   busy, timeout, invalid, state_unknown, network, failed, not_configured).
 *   Nothing is retried: a run is something a person did.
 * - The language of titles and texts is the app's (getLocale).
 */

const qa = require('../utils/quick-actions');

const LIST_PATH = '/api/v1/client/actions';
const LIST_TIMEOUT_MS = 15000;
// the server waits up to 10 s for the plugin
const RUN_TIMEOUT_MS = 15000;

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }

/** axios error → { status, code } (code: the server's `error`, 'timeout', 'network'). */
function errorOf(err) {
  const res = err && err.response;
  if (res) {
    const d = res.data && typeof res.data === 'object' ? res.data : null;
    return { status: res.status, code: d && typeof d.error === 'string' && /^[a-z_]{2,40}$/.test(d.error) ? d.error : `http_${res.status}` };
  }
  const c = err && err.code;
  if (c === 'ECONNABORTED' || c === 'ETIMEDOUT' || (err && /timeout/i.test(String(err.message)))) return { status: null, code: 'timeout' };
  return { status: null, code: 'network' };
}

class QuickActionsService {
  /**
   * @param {object} opts
   * @param {object} opts.apiClient - ApiClient / ApiClientPro (its axios `client`, re-read on every call)
   * @param {object} [opts.log]
   * @param {() => string} [opts.getLocale] - 'de' | 'en'
   * @param {() => number} [opts.now]
   */
  constructor({ apiClient, log, getLocale = null, now = Date.now } = {}) {
    this.apiClient = apiClient;
    this.log = log || noopLog();
    this.getLocale = getLocale;
    this.now = now;
    this._cache = null;   // { scope, lang, actions, fetchedAt }
  }

  _lang() {
    const l = typeof this.getLocale === 'function' ? this.getLocale() : null;
    return l === 'en' ? 'en' : 'de';
  }

  _client() {
    const c = this.apiClient && this.apiClient.client;
    return c && typeof c.request === 'function' ? c : null;
  }

  /** The configured server (origin + token): a copy of another one is never shown. */
  _scope() {
    const a = this.apiClient || {};
    return a.serverUrl && a.apiKey ? `${String(a.serverUrl).replace(/\/+$/, '')}\n${a.apiKey}` : '';
  }

  /** server:setup: the old server's actions go. */
  resetForNewServer() {
    this._cache = null;
  }

  /**
   * The actions for this device's user.
   * @returns {Promise<{ ok: true, supported: boolean, actions: object[], fetchedAt: number|null, offline: boolean, reason?: string }
   *   | { ok: false, reason: string }>}
   */
  async list() {
    const client = this._client();
    if (!client) return { ok: false, reason: 'not_configured' };
    const scope = this._scope();
    const lang = this._lang();
    try {
      const res = await client.request({ method: 'GET', url: LIST_PATH, params: { lang }, timeout: LIST_TIMEOUT_MS });
      const data = res && res.data && typeof res.data === 'object' ? res.data : {};
      const actions = qa.sanitizeActions(data.actions);
      this._cache = { scope, lang, actions, fetchedAt: this.now() };
      return { ok: true, supported: true, actions: clone(actions), fetchedAt: this._cache.fetchedAt, offline: false };
    } catch (err) {
      const e = errorOf(err);
      if (e.status === 404) {
        this._cache = null;
        return { ok: true, supported: false, actions: [], fetchedAt: this.now(), offline: false };
      }
      const reason = qa.failureReason(e.status, e.code);
      this.log.debug(`Quick actions: listing failed (${e.code})`);
      const c = this._cache;
      if (c && c.scope === scope) return { ok: true, supported: true, actions: clone(c.actions), fetchedAt: c.fetchedAt, offline: true, reason };
      return { ok: false, reason };
    }
  }

  /**
   * Runs one action (a button, a toggle — `state` the one it should end in —, or a control of its widget:
   * `control` + `value`).
   * @param {string} plugin
   * @param {string} id
   * @param {{ control?: string, value?: number|string, state?: 'on'|'off' }} [opts]
   */
  async run(plugin, id, opts = {}) {
    if (!qa.isPluginId(plugin) || !qa.isActionId(id)) return { ok: false, reason: 'invalid', status: null, message: null };
    const o = opts && typeof opts === 'object' ? opts : {};
    const body = qa.runBody({ source: 'app', control: o.control, value: o.value, state: o.state });
    if (!body) return { ok: false, reason: 'invalid', status: null, message: null };
    const client = this._client();
    if (!client) return { ok: false, reason: 'not_configured', status: null, message: null };
    try {
      const res = await client.request({
        method: 'POST',
        url: `${LIST_PATH}/${encodeURIComponent(plugin)}/${encodeURIComponent(id)}`,
        params: { lang: this._lang() },
        data: body,
        timeout: RUN_TIMEOUT_MS,
      });
      const answer = qa.sanitizeRunAnswer(res && res.data);
      if (answer.ok) this._remember(plugin, id, answer);
      return answer.ok ? answer : { ...answer, reason: 'failed', status: res ? res.status : 200 };
    } catch (err) {
      const e = errorOf(err);
      this.log.debug(`Quick action ${plugin}/${id} failed (${e.code})`);
      const d = err && err.response && err.response.data && typeof err.response.data === 'object' ? err.response.data : {};
      return { ok: false, reason: qa.failureReason(e.status, e.code), status: e.status, message: qa.text(d.message, 120) };
    }
  }

  /** A run's new state / widget into the copy kept for list(). */
  _remember(plugin, id, answer) {
    const c = this._cache;
    if (!c || c.scope !== this._scope()) return;
    const a = c.actions.find((x) => x.plugin === plugin && x.id === id);
    if (!a) return;
    if (answer.state && a.kind === 'toggle') a.state = answer.state;
    if (answer.widget) a.widget = answer.widget;
  }
}

function clone(v) {
  return JSON.parse(JSON.stringify(v));
}

module.exports = QuickActionsService;
module.exports.LIST_PATH = LIST_PATH;

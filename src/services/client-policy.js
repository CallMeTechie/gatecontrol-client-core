/**
 * GateControl – Client-Richtlinien (Core service)
 *
 * Fetches the effective client policy from the server, caches it in the
 * (encrypted) config store and tells the app when it changes.
 *
 *   - Never fetched → unrestricted (uiState().fetched === false).
 *   - Fetched → persisted under `policy` in the store; applies offline and
 *     while the server is unreachable (fail-safe: last known policy).
 *   - Refresh: on start, every `interval` ms (If-None-Match → 304 is cheap),
 *     and immediately when a heartbeat/permissions answer carries a
 *     policyVersion different from the cached one (noteVersion()).
 *   - Changing the server (new URL/token) should call reset(): the policy of
 *     the old server must not stick to the new setup.
 *
 * Not a security boundary — see utils/client-policy.js.
 */

'use strict';

const { normalizePolicy, uiState } = require('../utils/client-policy');

const STORE_KEY = 'policy';
const VERSION_RE = /^[0-9a-f]{1,64}$/i;

class ClientPolicyService {
  /**
   * @param {object} opts
   * @param {object} opts.apiClient - ApiClient (getClientPolicy)
   * @param {object} opts.store - electron-store compatible ({ get, set, delete? })
   * @param {object} opts.log
   * @param {number} [opts.interval=300000] - poll interval in ms (0 = no polling)
   * @param {string} [opts.storeKey='policy']
   */
  constructor({ apiClient, store, log, interval = 300000, storeKey = STORE_KEY } = {}) {
    this.apiClient = apiClient;
    this.store = store;
    this.log = log || { info() {}, warn() {}, debug() {}, error() {} };
    this.interval = interval;
    this.storeKey = storeKey;
    this.timer = null;
    this.listeners = new Set();
    this._inflight = null;
    this.cached = this._load();
  }

  _load() {
    try {
      const raw = this.store && this.store.get(this.storeKey);
      if (!raw || typeof raw !== 'object' || !raw.policy) return null;
      return {
        version: typeof raw.version === 'string' ? raw.version : null,
        fetchedAt: typeof raw.fetchedAt === 'string' ? raw.fetchedAt : null,
        policy: normalizePolicy(raw.policy),
      };
    } catch (err) {
      this.log.warn(`Client policy cache unreadable: ${err.message}`);
      return null;
    }
  }

  _persist() {
    try {
      if (this.cached) this.store.set(this.storeKey, { ...this.cached });
      else if (typeof this.store.delete === 'function') this.store.delete(this.storeKey);
      else this.store.set(this.storeKey, null);
    } catch (err) {
      this.log.warn(`Client policy could not be saved: ${err.message}`);
    }
  }

  /** Effective policy (unrestricted when never fetched). */
  getPolicy() {
    return this.cached ? this.cached.policy : normalizePolicy(null);
  }

  getVersion() {
    return this.cached ? this.cached.version : null;
  }

  /** State for the renderer (see utils/client-policy uiState). */
  getState() {
    return uiState(this.getPolicy(), {
      fetched: !!this.cached,
      version: this.getVersion(),
      fetchedAt: this.cached ? this.cached.fetchedAt : null,
    });
  }

  /** Subscribe to changes: cb(state, previousPolicy). Returns unsubscribe. */
  onChange(cb) {
    this.listeners.add(cb);
    return () => this.listeners.delete(cb);
  }

  _emit(previous) {
    const state = this.getState();
    for (const cb of this.listeners) {
      try {
        cb(state, previous);
      } catch (err) {
        this.log.warn(`Client policy listener failed: ${err.message}`);
      }
    }
  }

  /**
   * Ask the server. Resolves to 'updated' | 'unchanged' | 'unavailable'.
   * Never throws; on any failure the last known policy stays in force.
   */
  refresh() {
    if (this._inflight) return this._inflight;
    this._inflight = this._refresh().finally(() => { this._inflight = null; });
    return this._inflight;
  }

  async _refresh() {
    if (!this.apiClient || typeof this.apiClient.getClientPolicy !== 'function') return 'unavailable';
    let res;
    try {
      res = await this.apiClient.getClientPolicy(this.getVersion());
    } catch (err) {
      this.log.debug(`Client policy fetch failed (keeping last known): ${err.message}`);
      return 'unavailable';
    }
    if (!res) return 'unavailable';
    if (res.notModified) return 'unchanged';
    const data = res.data;
    if (!data || data.ok !== true || !data.policy || typeof data.policy !== 'object') {
      // 404 on an old server, malformed answer: keep what we have.
      return 'unavailable';
    }
    const version = typeof data.version === 'string' && VERSION_RE.test(data.version) ? data.version : null;
    const policy = normalizePolicy(data.policy);
    const previous = this.cached ? this.cached.policy : null;
    const changed = !this.cached
      || this.cached.version !== version
      || JSON.stringify(previous) !== JSON.stringify(policy);
    this.cached = { version, fetchedAt: new Date().toISOString(), policy };
    this._persist();
    if (changed) {
      this.log.info(`Client policy ${previous ? 'updated' : 'loaded'} (version ${version || '-'})`);
      this._emit(previous);
      return 'updated';
    }
    return 'unchanged';
  }

  /**
   * A server answer (heartbeat, permissions) carried a policy version.
   * Refreshes when it differs from the cached one.
   */
  noteVersion(version) {
    if (typeof version !== 'string' || !VERSION_RE.test(version)) return Promise.resolve('unchanged');
    if (version === this.getVersion()) return Promise.resolve('unchanged');
    return this.refresh();
  }

  /** Drop the cached policy (server changed / reset). Emits a change. */
  reset() {
    if (!this.cached) return;
    const previous = this.cached.policy;
    this.cached = null;
    this._persist();
    this._emit(previous);
  }

  start() {
    this.refresh();
    if (this.interval > 0 && !this.timer) {
      this.timer = setInterval(() => this.refresh(), this.interval);
      if (typeof this.timer.unref === 'function') this.timer.unref();
    }
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }
}

ClientPolicyService.STORE_KEY = STORE_KEY;

module.exports = ClientPolicyService;

'use strict';

/**
 * „Videos umwandeln“ (gatecontrol-medien from 1.6.0): the states of the plugin's files as the Medien page needs them,
 * over the device token of MediaServerSources (contract „umwandeln-apps-vertrag“):
 *
 *   GET  …/gatecontrol-medien/api/v1/convert/status?items=<id>,…   up to 100 Jellyfin item ids in one question
 *   POST …/gatecontrol-medien/api/v1/convert/request { itemId }     „Für heute Nacht vormerken“ (only onto the list)
 *
 * - Asked together: what is asked within a moment (`batchMs`, the detail and a season's episodes) goes out as one
 *   question, at most 100 ids each. Kept `ttlMs` (3 min); never asked per line or in a loop.
 * - Without the route (plugin before 1.6.0: 404), without the right „Medien“ or the licence (403): no hint and the
 *   plugin not asked again for `offMs` (30 min). A network error: no hint, asked again the next time.
 * - `enabled()` (MediaServerSources): the plugin is there, visible and at least 1.6.0 — else nothing is asked.
 *
 * Every method resolves; nothing throws.
 */

const MC = require('../utils/media-convert');
const { API_BASE } = require('../utils/media-server');

const DEFAULT_TIMING = Object.freeze({
  ttlMs: 3 * 60 * 1000,
  offMs: 30 * 60 * 1000,
  batchMs: 20,
});
const MAX_KEPT = 500;

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }

class MediaConvert {
  /**
   * @param {object} opts
   * @param {object} opts.api - MessengerApi-compatible transport (_call)
   * @param {() => boolean} [opts.enabled]
   * @param {() => number} [opts.now]
   * @param {object} [opts.log]
   * @param {object} [opts.timing]
   */
  constructor({ api, enabled = () => true, now = Date.now, log = null, timing = {} } = {}) {
    this.api = api;
    this.enabled = enabled;
    this.now = now;
    this.log = log || noopLog();
    this.timing = { ...DEFAULT_TIMING, ...timing };
    this._kept = new Map(); // id → { item | null, available, at }
    this._offUntil = 0;
    this._queue = new Set();
    this._flush = null;
  }

  /** Another server or person: nothing kept. */
  reset() {
    this._kept.clear();
    this._offUntil = 0;
  }

  _fresh(id, t) {
    const k = this._kept.get(id);
    return !!k && t - k.at >= 0 && t - k.at < this.timing.ttlMs;
  }

  /** The ids of `wanted` that are not kept: asked in one question with whatever else comes within batchMs. */
  _ask(ids) {
    for (const id of ids) this._queue.add(id);
    if (!this._flush) {
      this._flush = new Promise((r) => { setTimeout(r, this.timing.batchMs); }).then(() => this._send());
    }
    return this._flush;
  }

  async _send() {
    const ids = [...this._queue];
    this._queue.clear();
    this._flush = null;
    for (let i = 0; i < ids.length; i += MC.MAX_IDS) {
      if (this.now() < this._offUntil) return;
      const chunk = ids.slice(i, i + MC.MAX_IDS);
      let raw;
      try {
        raw = await this.api._call('GET', `${API_BASE}v1/convert/status`, { params: { items: chunk.join(',') }, timeout: 8000 });
      } catch (err) {
        if (MC.switchesOff(err)) {
          this._offUntil = this.now() + this.timing.offMs;
          this._kept.clear();
          this.log.debug(`Medien: Umwandeln not offered (${(err && (err.code || err.status)) || 'refused'})`);
          return;
        }
        this.log.debug(`Medien: Umwandeln state not read (${(err && (err.code || err.status)) || 'failed'})`);
        continue;
      }
      const s = MC.statusOf(raw);
      const t = this.now();
      for (const id of chunk) this._kept.set(id, { item: s.items.get(id) || null, available: s.available, at: t });
    }
    if (this._kept.size > MAX_KEPT) {
      const old = [...this._kept.entries()].sort((a, b) => a[1].at - b[1].at).slice(0, this._kept.size - MAX_KEPT);
      for (const [id] of old) this._kept.delete(id);
    }
  }

  /**
   * The files of `rawIds` (Jellyfin item ids): { available, items: Map <id> → item } (ids as the plugin writes them);
   * null: nothing to show (switched off, not enabled, no answer).
   */
  async states(rawIds) {
    const ids = [...new Set((Array.isArray(rawIds) ? rawIds : []).map(MC.itemId).filter(Boolean))];
    if (!ids.length || !this._on()) return null;
    const missing = ids.filter((id) => !this._fresh(id, this.now()));
    if (missing.length) await this._ask(missing);
    if (!this._on()) return null;
    const known = ids.map((id) => [id, this._kept.get(id)]).filter(([, k]) => !!k);
    if (!known.length) return null;
    const items = new Map();
    for (const [id, k] of known) if (k.item) items.set(id, k.item);
    return { available: known.some(([, k]) => k.available), items };
  }

  _on() {
    if (this.now() < this._offUntil) return false;
    try { return this.enabled() !== false; } catch { return false; }
  }

  /** Asked ahead for a list (a season's episodes) in one question; nothing shown from it yet. */
  async prefetch(rawIds) {
    await this.states(rawIds);
  }

  /** The hint for `rawId` whose picture is converted here (`problem`: MC.videoProblem); null: none. */
  async hint(rawId, problem) {
    if (!problem) return null;
    const id = MC.itemId(rawId);
    if (!id) return null;
    const s = await this.states([id]);
    return s ? MC.hintOf(problem, s.items.get(id) || null, s.available) : null;
  }

  /**
   * „Für heute Nacht vormerken“: `rawId` onto the plugin's list (the admin queues it, question 100 b).
   * → { ok: true, hint } | { ok: false, code } (also `rate_limited`: 30 an hour).
   */
  async request(rawId) {
    const id = MC.itemId(rawId);
    if (!id) return { ok: false, code: 'invalid' };
    if (!this._on()) return { ok: false, code: 'unavailable' };
    let raw;
    try {
      raw = await this.api._call('POST', `${API_BASE}v1/convert/request`, { body: { itemId: id }, timeout: 8000 });
    } catch (err) {
      if (MC.switchesOff(err) && err.code !== 'not_found') {
        this._offUntil = this.now() + this.timing.offMs;
        this._kept.clear();
      }
      return { ok: false, code: (err && err.code) || 'failed' };
    }
    const before = this._kept.get(id);
    const item = MC.requestedOf(id, raw, before && before.item);
    this._kept.set(id, { item, available: before ? before.available : true, at: this.now() });
    return { ok: true, hint: MC.hintOf({ code: 'requested' }, item, true) || { kind: 'requested' } };
  }
}

MediaConvert.DEFAULT_TIMING = DEFAULT_TIMING;

module.exports = MediaConvert;

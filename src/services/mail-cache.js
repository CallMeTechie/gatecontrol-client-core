'use strict';

/**
 * GateControl – Mail offline cache (Core)
 *
 * The lists and mails Mail last loaded, so the page still shows them without
 * a connection: `me` (accounts, features), the folders, every list page
 * loaded (items of at least the last 30 days — the newest 200 always — per
 * query) and every mail opened (at most 500, the oldest opened go first;
 * mails of the last 30 days are kept). Attachments are never cached.
 *
 * On disk only encrypted with Windows' DPAPI (Electron safeStorage, passed in
 * as `protect` like Drive's vault keys): one file for the index
 * (index.bin) and one per mail (m-<id>.bin) in
 * %APPDATA%\…\mail-cache\<hash of server + token>. Without DPAPI the cache
 * lives in memory only. clear() removes everything (new server, the device's
 * token refused, the plugin gone or not allowed any more).
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const KEEP_MS = 30 * 24 * 60 * 60 * 1000;
const MIN_ITEMS = 200;
const MAX_ITEMS = 3000;
const MAX_MESSAGES = 500;
const MAX_LISTS = 100;
const WRITE_DELAY_MS = 800;

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }

class MailCache {
  /**
   * @param {object} opts
   * @param {() => string|null} [opts.dir] - base folder (null: memory only)
   * @param {object} [opts.protect] - { available(), encrypt(buf) → buf, decrypt(buf) → buf }
   * @param {object} [opts.log]
   * @param {() => number} [opts.now]
   */
  constructor({ dir = null, protect = null, log = null, now = Date.now } = {}) {
    this.dir = typeof dir === 'function' ? dir : () => null;
    this.protect = protect;
    this.log = log || noopLog();
    this.now = now;
    this._scope = null;
    this._index = null;     // { me, folders, lists: { key: { at, items, next, counts } }, messages: { id: { at, date } } }
    this._messages = new Map();
    this._loading = null;
    this._timer = null;
    this._dirty = false;
    this._dirtyMessages = new Set();
  }

  _disk() {
    try {
      return !!(this.dir() && this.protect && this.protect.available());
    } catch {
      return false;
    }
  }

  _folder() {
    const base = this.dir();
    return base && this._scope ? path.join(base, crypto.createHash('sha256').update(this._scope).digest('hex').slice(0, 16)) : null;
  }

  /** Server + token: another one starts another cache (the old one stays until clear()). */
  setScope(scope) {
    const s = typeof scope === 'string' && scope ? scope : null;
    if (s === this._scope) return;
    this.flush().catch(() => {});
    this._scope = s;
    this._index = null;
    this._messages.clear();
    this._loading = null;
  }

  async _read(file) {
    const raw = await fs.promises.readFile(file);
    return JSON.parse(this.protect.decrypt(raw).toString('utf8'));
  }

  async _write(file, value) {
    const tmp = `${file}.${crypto.randomBytes(4).toString('hex')}.tmp`;
    await fs.promises.writeFile(tmp, this.protect.encrypt(Buffer.from(JSON.stringify(value), 'utf8')));
    await fs.promises.rename(tmp, file);
  }

  async _load() {
    if (this._index) return this._index;
    if (!this._loading) {
      this._loading = (async () => {
        let idx = null;
        const dir = this._disk() ? this._folder() : null;
        if (dir) {
          try { idx = await this._read(path.join(dir, 'index.bin')); } catch { idx = null; }
        }
        const ok = idx && typeof idx === 'object' && idx.lists && idx.messages;
        this._index = ok ? idx : { me: null, folders: null, lists: {}, messages: {} };
        return this._index;
      })();
    }
    return this._loading;
  }

  _touch(messageId = null) {
    this._dirty = true;
    if (messageId) this._dirtyMessages.add(messageId);
    if (this._timer || !this._disk()) return;
    this._timer = setTimeout(() => { this._timer = null; this.flush().catch(() => {}); }, WRITE_DELAY_MS);
    if (this._timer.unref) this._timer.unref();
  }

  /** Writes what changed (index and new mails). */
  async flush() {
    clearTimeout(this._timer);
    this._timer = null;
    if (!this._dirty || !this._index || !this._disk()) return;
    const dir = this._folder();
    if (!dir) return;
    this._dirty = false;
    const ids = [...this._dirtyMessages];
    this._dirtyMessages.clear();
    try {
      await fs.promises.mkdir(dir, { recursive: true });
      for (const id of ids) {
        const m = this._messages.get(id);
        const file = path.join(dir, `m-${id}.bin`);
        if (m) await this._write(file, m);
        else await fs.promises.rm(file, { force: true });
      }
      await this._write(path.join(dir, 'index.bin'), this._index);
    } catch (err) {
      this.log.warn(`Mail cache not written: ${err.code || err.message}`);
    }
  }

  // ── me / folders ─────────────────────────────────────────

  async getMe() { return (await this._load()).me; }

  async putMe(me) { (await this._load()).me = me; this._touch(); }

  async getFolders() { return (await this._load()).folders; }

  async putFolders(f) { (await this._load()).folders = f; this._touch(); }

  // ── Lists ────────────────────────────────────────────────

  async getList(key) {
    const l = (await this._load()).lists[key];
    return l ? { ...l, items: l.items.slice() } : null;
  }

  /** A page of a list: the first page replaces what was there, a later one (`append`) adds behind. */
  async putList(key, page, { append = false } = {}) {
    const idx = await this._load();
    const old = idx.lists[key];
    let items = page.items || [];
    if (append && old) {
      const seen = new Set(old.items.map((m) => m.id));
      items = old.items.concat(items.filter((m) => !seen.has(m.id)));
    } else if (old && !append) {
      // the newest page replaces the head; older items already cached stay behind it
      const seen = new Set(items.map((m) => m.id));
      const last = items.length ? items[items.length - 1].date || 0 : Infinity;
      items = items.concat(old.items.filter((m) => !seen.has(m.id) && (m.date || 0) <= last));
    }
    const limit = this.now() - KEEP_MS;
    items = items.filter((m, i) => i < MIN_ITEMS || (m.date || 0) >= limit).slice(0, MAX_ITEMS);
    idx.lists[key] = { at: this.now(), items, next: append || !old ? page.next || null : (old.next || page.next || null), counts: page.counts || (old && old.counts) || null };
    const keys = Object.keys(idx.lists);
    if (keys.length > MAX_LISTS) {
      keys.sort((a, b) => idx.lists[a].at - idx.lists[b].at);
      for (const k of keys.slice(0, keys.length - MAX_LISTS)) delete idx.lists[k];
    }
    this._touch();
    return idx.lists[key];
  }

  /** Does the cached list `key` already reach back `ms` (or end)? */
  async reaches(key, ms) {
    const l = (await this._load()).lists[key];
    if (!l || !l.items.length) return false;
    return !l.next || (l.items[l.items.length - 1].date || 0) <= ms;
  }

  /** Changes summaries in every cached list (and cached mails): fn(summary) → new summary | null (drop it). */
  async patch(ids, fn) {
    const idx = await this._load();
    const set = new Set(ids);
    for (const l of Object.values(idx.lists)) {
      l.items = l.items.map((m) => (set.has(m.id) ? fn(m) : m)).filter(Boolean);
    }
    for (const id of set) {
      const m = await this.getMessage(id);
      if (!m) continue;
      const next = fn(m);
      if (next) await this.putMessage({ ...m, ...next });
    }
    this._touch();
  }

  // ── Mails ────────────────────────────────────────────────

  async getMessage(id) {
    if (this._messages.has(id)) return this._messages.get(id);
    const idx = await this._load();
    if (!idx.messages[id] || !this._disk()) return null;
    try {
      const m = await this._read(path.join(this._folder(), `m-${id}.bin`));
      this._messages.set(id, m);
      return m;
    } catch {
      delete idx.messages[id];
      return null;
    }
  }

  async putMessage(m) {
    if (!m || !m.id) return;
    const idx = await this._load();
    this._messages.set(m.id, m);
    idx.messages[m.id] = { at: this.now(), date: m.date || 0 };
    this._touch(m.id);
    // the oldest opened go (mails of the last 30 days stay)
    const all = Object.entries(idx.messages);
    if (all.length > MAX_MESSAGES) {
      const limit = this.now() - KEEP_MS;
      all.sort((a, b) => a[1].at - b[1].at);
      let over = all.length - MAX_MESSAGES;
      for (const [id, meta] of all) {
        if (over <= 0) break;
        if (meta.date >= limit && meta.at >= limit) continue;
        delete idx.messages[id];
        this._messages.delete(Number(id));
        this._dirtyMessages.add(Number(id));
        over -= 1;
      }
    }
  }

  async dropMessages(ids) {
    const idx = await this._load();
    for (const id of ids) {
      if (!idx.messages[id] && !this._messages.has(id)) continue;
      delete idx.messages[id];
      this._messages.delete(id);
      this._touch(id);
    }
  }

  /** Everything of every server goes (memory and disk). */
  async clear() {
    clearTimeout(this._timer);
    this._timer = null;
    this._index = null;
    this._loading = null;
    this._messages.clear();
    this._dirty = false;
    this._dirtyMessages.clear();
    const base = this.dir();
    if (base) await fs.promises.rm(base, { recursive: true, force: true }).catch(() => {});
  }
}

module.exports = MailCache;
module.exports.KEEP_MS = KEEP_MS;

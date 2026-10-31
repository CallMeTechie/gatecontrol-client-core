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
 *
 * Phase 2 (calendar and contacts, read only offline) in its own file
 * (pim.bin): the calendar list, the occurrences of the ranges loaded (−30 …
 * +90 days around today are kept), the events opened (200), the address
 * books, every CardSummary (kept current with `since`), the contacts opened
 * (500) and their photos (500, the least recently used go; one file each,
 * ph-<id>.bin).
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
const PIM_RANGES = 40;
const PIM_EVENTS = 200;
const PIM_CARDS = 500;
const PIM_PHOTOS = 500;
const PIM_KEEP_BEFORE_MS = 30 * 24 * 60 * 60 * 1000;
const PIM_KEEP_AFTER_MS = 90 * 24 * 60 * 60 * 1000;

const emptyPim = () => ({ calendars: null, ranges: {}, events: {}, books: null, cards: null, cardDetails: {}, photos: {}, extra: {} });
const EXTRA_KEYS = 20;

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
    this._pim = null;            // see emptyPim()
    this._pimLoading = null;
    this._pimDirty = false;
    this._photos = new Map();    // card id → { mime, data } (base64) read this session
    this._dirtyPhotos = new Set();
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
    this._pim = null;
    this._pimLoading = null;
    this._photos.clear();
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
    this._schedule();
  }

  _schedule() {
    if (this._timer || !this._disk()) return;
    this._timer = setTimeout(() => { this._timer = null; this.flush().catch(() => {}); }, WRITE_DELAY_MS);
    if (this._timer.unref) this._timer.unref();
  }

  /** Writes what changed (index and new mails). */
  async flush() {
    clearTimeout(this._timer);
    this._timer = null;
    await this._flushPim();
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

  // ── Calendar and contacts (Phase 2) ──────────────────────

  async _loadPim() {
    if (this._pim) return this._pim;
    if (!this._pimLoading) {
      this._pimLoading = (async () => {
        let p = null;
        const dir = this._disk() ? this._folder() : null;
        if (dir) {
          try { p = await this._read(path.join(dir, 'pim.bin')); } catch { p = null; }
        }
        this._pim = p && typeof p === 'object' && p.ranges && p.events && p.cardDetails && p.photos ? p : emptyPim();
        if (!this._pim.extra || typeof this._pim.extra !== 'object') this._pim.extra = {};
        return this._pim;
      })();
    }
    return this._pimLoading;
  }

  _touchPim(photoId = null) {
    this._pimDirty = true;
    if (photoId) this._dirtyPhotos.add(photoId);
    this._schedule();
  }

  async _flushPim() {
    if (!this._pimDirty || !this._pim || !this._disk()) return;
    const dir = this._folder();
    if (!dir) return;
    this._pimDirty = false;
    // taken now: another scope (setScope) may start while this is written
    const pim = this._pim;
    const photos = [...this._dirtyPhotos].map((id) => [id, pim.photos[id] ? this._photos.get(id) : null]);
    this._dirtyPhotos.clear();
    try {
      await fs.promises.mkdir(dir, { recursive: true });
      for (const [id, ph] of photos) {
        const file = path.join(dir, `ph-${id}.bin`);
        if (ph) await this._write(file, ph);
        else await fs.promises.rm(file, { force: true });
      }
      await this._write(path.join(dir, 'pim.bin'), pim);
    } catch (err) {
      this.log.warn(`Mail calendar / contacts cache not written: ${err.code || err.message}`);
    }
  }

  async getCalendars() { return (await this._loadPim()).calendars; }

  async putCalendars(c) { (await this._loadPim()).calendars = c; this._touchPim(); }

  /** The occurrences of an events query (GET events); ranges far from today are not kept. */
  async putRange(key, from, to, data) {
    const p = await this._loadPim();
    const now = this.now();
    if (to < now - PIM_KEEP_BEFORE_MS || from > now + PIM_KEEP_AFTER_MS) return;
    p.ranges[key] = { at: now, from, to, items: data.items || [], overlays: data.overlays || [] };
    const keys = Object.keys(p.ranges);
    for (const k of keys) {
      const r = p.ranges[k];
      if (r.to < now - PIM_KEEP_BEFORE_MS || r.from > now + PIM_KEEP_AFTER_MS) delete p.ranges[k];
    }
    const left = Object.keys(p.ranges);
    if (left.length > PIM_RANGES) {
      left.sort((a, b) => p.ranges[a].at - p.ranges[b].at);
      for (const k of left.slice(0, left.length - PIM_RANGES)) delete p.ranges[k];
    }
    this._touchPim();
  }

  /**
   * The occurrences of [from, to) offline: the query itself when it was loaded, else what the loaded ranges hold of it
   * (newest first, each occurrence once; `calendars`: only these ids / overlay ids) → { items, overlays, at } | null.
   */
  async getRange(key, from, to, calendars = null) {
    const p = await this._loadPim();
    if (p.ranges[key]) { const r = p.ranges[key]; return { items: r.items.slice(), overlays: r.overlays.slice(), at: r.at }; }
    const hits = Object.values(p.ranges).filter((r) => r.from < to && r.to > from).sort((a, b) => b.at - a.at);
    if (!hits.length) return null;
    const want = calendars ? new Set(String(calendars).split(',')) : null;
    const seen = new Set();
    const items = [];
    const overlays = [];
    for (const r of hits) {
      for (const x of r.items) {
        if (seen.has(x.key) || x.start >= to || x.end <= from || (want && !want.has(String(x.calendarId)))) continue;
        seen.add(x.key);
        items.push(x);
      }
      for (const x of r.overlays) {
        if (seen.has(x.key) || x.start >= to || x.end <= from || (want && !want.has(x.overlayId))) continue;
        seen.add(x.key);
        overlays.push(x);
      }
    }
    items.sort((a, b) => a.start - b.start);
    return { items, overlays, at: hits[hits.length - 1].at };
  }

  async getEvent(key) { const e = (await this._loadPim()).events[key]; return e ? e.ev : null; }

  async putEvent(key, ev) {
    const p = await this._loadPim();
    p.events[key] = { at: this.now(), ev };
    const keys = Object.keys(p.events);
    if (keys.length > PIM_EVENTS) {
      keys.sort((a, b) => p.events[a].at - p.events[b].at);
      for (const k of keys.slice(0, keys.length - PIM_EVENTS)) delete p.events[k];
    }
    this._touchPim();
  }

  /** An event changed or went: its cached details go (all of its occurrences). */
  async dropEvent(eventId) {
    const p = await this._loadPim();
    for (const k of Object.keys(p.events)) if (k === String(eventId) || k.startsWith(`${eventId}:`)) delete p.events[k];
    this._touchPim();
  }

  async getBooks() { return (await this._loadPim()).books; }

  async putBooks(b) { (await this._loadPim()).books = b; this._touchPim(); }

  /** Every CardSummary of the person: { version, items, at } | null. */
  async getCards() {
    const c = (await this._loadPim()).cards;
    return c ? { version: c.version, items: c.items.slice(), at: c.at } : null;
  }

  /** All of them (`full`), or the changes since the version kept (items replace, `deleted` go). */
  async putCards({ version, items, deleted = [], full = false }) {
    const p = await this._loadPim();
    let list = full || !p.cards ? items : p.cards.items;
    if (!full && p.cards) {
      const gone = new Set([...deleted, ...items.map((c) => c.id)]);
      list = list.filter((c) => !gone.has(c.id)).concat(items);
      for (const id of deleted) { delete p.cardDetails[id]; this._dropPhoto(p, id); }
    }
    p.cards = { version, items: list, at: this.now() };
    this._touchPim();
  }

  /** The list must be loaded anew (a merge, an address book shown or hidden). */
  async resetCards() {
    const p = await this._loadPim();
    p.cards = null;
    this._touchPim();
  }

  async getCard(id) { const c = (await this._loadPim()).cardDetails[id]; return c ? c.card : null; }

  async putCard(card) {
    if (!card || !card.id) return;
    const p = await this._loadPim();
    p.cardDetails[card.id] = { at: this.now(), card };
    const keys = Object.keys(p.cardDetails);
    if (keys.length > PIM_CARDS) {
      keys.sort((a, b) => p.cardDetails[a].at - p.cardDetails[b].at);
      for (const k of keys.slice(0, keys.length - PIM_CARDS)) delete p.cardDetails[k];
    }
    this._touchPim();
  }

  async dropCard(id) {
    const p = await this._loadPim();
    delete p.cardDetails[id];
    if (p.cards) p.cards.items = p.cards.items.filter((c) => c.id !== id);
    this._dropPhoto(p, id);
    this._touchPim();
  }

  _dropPhoto(p, id) {
    if (!p.photos[id] && !this._photos.has(id)) return;
    delete p.photos[id];
    this._photos.delete(id);
    this._dirtyPhotos.add(id);
  }

  /** A contact's photo kept for its etag → { mime, data } | null. */
  async getPhoto(id, etag) {
    const p = await this._loadPim();
    const meta = p.photos[id];
    if (!meta || (etag && meta.etag !== etag)) return null;
    meta.at = this.now();
    if (this._photos.has(id)) return this._photos.get(id);
    if (!this._disk()) return null;
    try {
      const ph = await this._read(path.join(this._folder(), `ph-${id}.bin`));
      this._photos.set(id, ph);
      return ph;
    } catch {
      delete p.photos[id];
      return null;
    }
  }

  async putPhoto(id, etag, photo) {
    const p = await this._loadPim();
    p.photos[id] = { at: this.now(), etag: etag || null };
    this._photos.set(id, photo);
    this._touchPim(id);
    const keys = Object.keys(p.photos);
    if (keys.length > PIM_PHOTOS) {
      keys.sort((a, b) => p.photos[a].at - p.photos[b].at);
      for (const k of keys.slice(0, keys.length - PIM_PHOTOS)) this._dropPhoto(p, Number(k));
    }
  }

  /** A small answer kept for offline (Mail 1.4.0: the favourites, the calendar widget) → its value | null. */
  async getExtra(key) {
    const x = (await this._loadPim()).extra[key];
    return x ? x.value : null;
  }

  async putExtra(key, value) {
    const p = await this._loadPim();
    p.extra[key] = { at: this.now(), value };
    const keys = Object.keys(p.extra);
    if (keys.length > EXTRA_KEYS) {
      keys.sort((a, b) => p.extra[a].at - p.extra[b].at);
      for (const k of keys.slice(0, keys.length - EXTRA_KEYS)) delete p.extra[k];
    }
    this._touchPim();
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
    this._pim = null;
    this._pimLoading = null;
    this._pimDirty = false;
    this._photos.clear();
    this._dirtyPhotos.clear();
    const base = this.dir();
    if (base) await fs.promises.rm(base, { recursive: true, force: true }).catch(() => {});
  }
}

module.exports = MailCache;
module.exports.KEEP_MS = KEEP_MS;

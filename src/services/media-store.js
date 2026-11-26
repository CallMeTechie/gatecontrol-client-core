'use strict';

/**
 * Medien (Stufe 4e): what Medien keeps on this PC, in electron-store —
 *
 *   - the sources with their access (Jellyfin token, a share's password, a confirmed certificate): one blob encrypted
 *     with safeStorage (Windows: DPAPI, bound to the Windows user), as Mail and Vault — never plain. Without
 *     safeStorage a source with a secret is not kept (code 'no_protect').
 *   - this PC's own device id for Jellyfin (`DeviceId`), made once: every device can be signed out on its own in
 *     Jellyfin's device list.
 *   - the sound and subtitle chosen per series, the progress of share files ("Weiterschauen" of a share lives on the
 *     device, decision 11; the newest 500), the quality setting.
 *
 * The logic of the list (pairing SMB ↔ WebDAV, replacing a source signed in again) is utils/media-sources.js.
 *
 * Medien-Plugin (W1): the sources come from the server (services/media-server-sources.js): `replaceAll` writes the list
 * merged with the server's, `moveProgress` keeps the progress of a share taken over under the server's id, and the
 * last answer of the plugin (rev, the network rule's probes, the offline days, when the server was reached) is kept
 * as a second safeStorage blob (`serverCache`).
 */

const crypto = require('crypto');
const MS = require('../utils/media-sources');
const MQ = require('../utils/media-quality');

const KEY = 'media';
const MAX_PROGRESS = 500;
const MAX_TRACK_CHOICES = 200;
const KEY_RE = /^[^|]{1,64}\|[\s\S]{1,600}$/;
const FORBIDDEN = new Set(['__proto__', 'constructor', 'prototype']);
const safeKey = (k) => typeof k === 'string' && !FORBIDDEN.has(k);

class MediaStore {
  /**
   * @param {object} opts
   * @param {object} opts.store - electron-store (get/set/delete)
   * @param {object} [opts.protect] - { available(), encrypt(buf) → Buffer, decrypt(Buffer) → buf } (safeStorage:
   *   DriveService.safeStorageProtect(safeStorage))
   * @param {() => number} [opts.now]
   */
  constructor({ store, protect = null, now = Date.now }) {
    this.store = store;
    this.protect = protect;
    this.now = now;
    this._sources = null;
  }

  _get(k, def) {
    const v = this.store.get(`${KEY}.${k}`);
    return v === undefined || v === null ? def : v;
  }

  _set(k, v) { this.store.set(`${KEY}.${k}`, v); }

  canProtect() {
    try { return !!(this.protect && this.protect.available()); } catch { return false; }
  }

  /** The id the servers know this PC by (Jellyfin's `DeviceId`), made once. */
  deviceId() {
    const id = this._get('deviceId', null);
    if (typeof id === 'string' && /^[A-Za-z0-9-]{8,64}$/.test(id)) return id;
    const fresh = crypto.randomUUID();
    this._set('deviceId', fresh);
    return fresh;
  }

  sources() {
    if (this._sources) return this._sources;
    let list = [];
    const blob = this._get('sources', null);
    if (typeof blob === 'string' && blob && this.canProtect()) {
      try { list = MS.decode(Buffer.from(this.protect.decrypt(Buffer.from(blob, 'base64'))).toString('utf8')); } catch { list = []; }
    }
    this._sources = list;
    return list;
  }

  source(id) { return this.sources().find((s) => s.id === id) || null; }

  _write(list) {
    if (!this.canProtect()) {
      const err = new Error('no safeStorage on this PC');
      err.code = 'no_protect';
      throw err;
    }
    const enc = this.protect.encrypt(Buffer.from(MS.encode(list), 'utf8'));
    this._set('sources', Buffer.from(enc).toString('base64'));
    this._sources = MS.decode(MS.encode(list));
  }

  /** Adds or replaces (signed in again, the same share) → the source as stored. */
  save(src) {
    const list = this.sources();
    if (list.length >= MS.MAX_SOURCES && !list.some((x) => x.id === src.id || (src.serverId && x.serverId === src.serverId && x.userId === src.userId) || (x.kind === src.kind && x.address === src.address))) {
      const err = new Error('too many sources');
      err.code = 'too_many';
      throw err;
    }
    const { list: next, kept } = MS.save(list, { alwaysOriginal: false, ...src, id: src.id || crypto.randomBytes(9).toString('base64url') });
    this._write(next);
    return this.source(kept.id);
  }

  /** Removes `id`; its partner stays alone, the progress of its files goes. */
  remove(id) {
    this._write(MS.remove(this.sources(), id));
    const p = this._get('progress', {});
    if (p && typeof p === 'object') {
      for (const k of Object.keys(p)) if (k.startsWith(`${id}|`)) delete p[k];
      this._set('progress', p);
    }
  }

  update(id, patch) {
    this._write(this.sources().map((s) => (s.id === id ? { ...s, ...patch, id } : s)));
    return this.source(id);
  }

  setAlwaysOriginal(id, on) { return this.update(id, { alwaysOriginal: on === true }); }

  /** Signed out by the server (401): the access goes, the source stays to sign in again. */
  dropToken(id) { return this.update(id, { token: null }); }

  /** The whole list at once (the server's list merged in: services/media-server-sources.js). */
  replaceAll(list) {
    this._write(Array.isArray(list) ? list : []);
    return this.sources();
  }

  /** Removes several sources (and the progress of their files) at once. */
  removeMany(ids) {
    const gone = new Set(ids);
    if (!gone.size) return;
    let list = this.sources();
    for (const id of gone) list = MS.remove(list, id);
    this._write(list);
    const p = this._get('progress', {});
    if (p && typeof p === 'object') {
      for (const k of Object.keys(p)) if (gone.has(k.split('|')[0])) delete p[k];
      this._set('progress', p);
    }
  }

  /** The progress of the files of share `from` under `to` (a source of this PC taken over by the server's). */
  moveProgress(from, to) {
    if (!safeKey(from) || !safeKey(to) || from === to) return;
    const p = { ...(this._get('progress', {}) || {}) };
    let moved = false;
    for (const k of Object.keys(p)) {
      if (!k.startsWith(`${from}|`)) continue;
      const nk = `${to}|${k.slice(from.length + 1)}`;
      if (!safeKey(nk)) continue;
      p[nk] = p[k];
      delete p[k];
      moved = true;
    }
    if (moved) this._set('progress', p);
  }

  /** The plugin's last answer and its times (no secrets, but addresses: encrypted as the sources). */
  serverCache() {
    const blob = this._get('server', null);
    if (typeof blob !== 'string' || !blob || !this.canProtect()) return null;
    try {
      const o = JSON.parse(Buffer.from(this.protect.decrypt(Buffer.from(blob, 'base64'))).toString('utf8'));
      return o && typeof o === 'object' && !Array.isArray(o) ? o : null;
    } catch { return null; }
  }

  setServerCache(obj) {
    if (!this.canProtect()) return;
    if (!obj) { this.store.delete(`${KEY}.server`); return; }
    this._set('server', Buffer.from(this.protect.encrypt(Buffer.from(JSON.stringify(obj), 'utf8'))).toString('base64'));
  }

  /** This PC's GateControl device id as the plugin's cast signal told it (`to`), null before (services/media-cast.js). */
  castSelf() {
    const id = this._get('castSelf', null);
    return typeof id === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(id) ? id : null;
  }

  setCastSelf(id) {
    if (typeof id === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(id)) this._set('castSelf', id);
  }

  /** Signed out of GateControl / another server: nothing of Medien is left. */
  forgetAll() {
    this.store.delete(KEY);
    this._sources = [];
  }

  // ── the progress of share files (Jellyfin keeps its own) ───

  progress(key) {
    const p = this._get('progress', {});
    const v = p && typeof p === 'object' && Object.prototype.hasOwnProperty.call(p, key) ? p[key] : null;
    return v && Number.isFinite(v.p) ? { positionMs: v.p, durationMs: v.d || 0, played: v.w === true, at: v.t || 0 } : null;
  }

  all(prefix) {
    const p = this._get('progress', {});
    const out = {};
    for (const [k, v] of Object.entries(p && typeof p === 'object' ? p : {})) {
      if (k.startsWith(prefix) && v && Number.isFinite(v.p)) out[k] = { positionMs: v.p, durationMs: v.d || 0, played: v.w === true, at: v.t || 0 };
    }
    return out;
  }

  /** Kept for the newest MAX_PROGRESS files; a file watched to its end is kept as "gesehen". */
  setProgress(key, { positionMs, durationMs = 0, played = false, at = this.now() }) {
    if (!safeKey(key) || !KEY_RE.test(key)) return;
    const p = { ...(this._get('progress', {}) || {}) };
    delete p[key];
    const keys = Object.keys(p);
    if (keys.length >= MAX_PROGRESS) {
      keys.sort((a, b) => (p[a].t || 0) - (p[b].t || 0));
      for (const k of keys.slice(0, keys.length - MAX_PROGRESS + 1)) delete p[k];
    }
    p[key] = { p: Math.max(0, Math.floor(positionMs) || 0), d: Math.max(0, Math.floor(durationMs) || 0), w: played === true, t: at };
    this._set('progress', p);
  }

  // ── sound and subtitle per series ───────────────────────────

  trackChoice(seriesId) {
    const t = this._get('tracks', {});
    const c = t && typeof t === 'object' && Object.prototype.hasOwnProperty.call(t, seriesId) ? t[seriesId] : null;
    return c ? { audioLanguage: c.audio || null, subtitleLanguage: c.subtitle || null, subtitlesOff: c.off === true } : null;
  }

  setTrackChoice(seriesId, choice) {
    if (!safeKey(seriesId) || !/^[A-Za-z0-9:_-]{1,80}$/.test(seriesId)) return;
    const t = { ...(this._get('tracks', {}) || {}) };
    const keys = Object.keys(t);
    if (keys.length >= MAX_TRACK_CHOICES && !Object.prototype.hasOwnProperty.call(t, seriesId)) delete t[keys[0]];
    const lang = (v) => (typeof v === 'string' && /^[A-Za-z-]{2,16}$/.test(v) ? v : undefined);
    t[seriesId] = { audio: lang(choice.audioLanguage), subtitle: lang(choice.subtitleLanguage), off: choice.subtitlesOff === true };
    this._set('tracks', t);
  }

  // ── settings ────────────────────────────────────────────────

  quality() { return MQ.settingOf(this._get('quality', 'auto')); }

  setQuality(v) { this._set('quality', MQ.settingOf(v)); return this.quality(); }
}

MediaStore.MAX_PROGRESS = MAX_PROGRESS;

module.exports = MediaStore;

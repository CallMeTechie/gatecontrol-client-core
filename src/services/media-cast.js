'use strict';

/**
 * "Auf TV/PC abspielen" — this PC as the receiver (cast contract version 1, sections 2 and 3; Android's TvCast is the
 * other receiver of the same contract). A phone of the same person sends the plugin's source id, the title and the
 * place through the plugin „Medien": it comes in as the push stream's event `plugin` (type `media.cast`) and as the
 * silent signal (topic media_signal, `data.kind = 'media.cast'`), for this PC, each once (utils/media-cast.js Inbox).
 *
 * The PC plays it from its own source of the plugin with the same id (its own Jellyfin access or share; not there:
 * `source_missing`) by the network rule of Medien (MediaService.detail: at home directly, away only through the VPN,
 * which it starts itself), the page opens the player at the place ('play') and stays remote-controlled by that phone:
 * its keys come in as 'command', every change goes back as `cast.state` (`POST v1/cast/{session}/message`) — on a
 * change of the phase, a track or the volume, on a jump, else every 5 minutes while it plays. One session at a time: a
 * new start (from any own device) takes over (the one before hears `stopped` / `taken_over`).
 *
 * The page's part (ipc/media-handlers.js media:cast:*): opened(session) once the player shows it, state(session, …)
 * whenever the player changes, closed(session, …) when it closes (by the phone's "Stopp", at the end, on this PC).
 *
 * Events: 'play' { session, sourceId, itemId, item, detail, startMs, audioIndex, subtitleIndex, controllerName },
 *         'command' { session, cmd, positionMs, deltaMs, audioIndex, subtitleIndex, volume, muted },
 *         'session' (status()).
 */

const EventEmitter = require('events');
const MessengerApi = require('./messenger-api');
const MSV = require('../utils/media-server');
const C = require('../utils/media-cast');

const DEFAULT_TIMING = Object.freeze({
  openTimeoutMs: 15000, // the player must have opened by then (else `blocked`)
  retryMs: 61000,       // the plugin counts 60 messages a minute per device: the end of a session once more after it
});

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }

class MediaCastReceiver extends EventEmitter {
  /**
   * @param {object} opts
   * @param {object} opts.media - MediaService (its store: the sources and this PC's id; detail / shareInspect)
   * @param {object} [opts.apiClient] - ApiClient / ApiClientPro
   * @param {object} [opts.api] - MessengerApi-compatible transport (_call) (tests)
   * @param {object} [opts.pushClient] - PushClient: 'event' (event `plugin`, type media.cast)
   * @param {object} [opts.notificationCenter] - NotificationCenter: the silent signal (addPushHandler)
   * @param {() => string} [opts.deviceName] - this PC's name for the phone (default: MediaService's)
   * @param {object} [opts.log]
   * @param {() => number} [opts.now]
   * @param {object} [opts.timing]
   */
  constructor({ media, apiClient = null, api = null, pushClient = null, notificationCenter = null, deviceName = null, log = null, now = Date.now, timing = {} } = {}) {
    super();
    this.media = media;
    this.api = api || new MessengerApi({ apiClient, log });
    this.pushClient = pushClient;
    this.notificationCenter = notificationCenter;
    this.log = log || noopLog();
    this.now = now;
    this.timing = { ...DEFAULT_TIMING, ...timing };
    this.deviceName = deviceName || (() => (media && typeof media.info === 'function' ? media.info().device : 'PC'));
    this._inbox = null;
    this._s = null;          // the session: { session, controller, controllerName, lastSeq, nextSeq }
    this._opened = null;     // the session the player showed
    this._told = null;       // the last snapshot told, and when
    this._toldAt = 0;
    this._sending = Promise.resolve();
    this._timers = new Set();
    this._unsub = [];
    this._started = false;
    if (media && typeof media.setCastReceiver === 'function') media.setCastReceiver(this);
  }

  // ── lifecycle ───────────────────────────────────────────────

  start() {
    if (this._started) return;
    this._started = true;
    const pc = this.pushClient;
    if (pc && typeof pc.on === 'function') {
      const onEvent = (ev) => {
        if (!ev || ev.event !== 'plugin' || !ev.data || ev.data.plugin !== MSV.PLUGIN_ID || ev.data.type !== C.KIND) return;
        this.receive(ev.data.data, { push: false });
      };
      pc.on('event', onEvent);
      this._unsub.push(() => pc.removeListener('event', onEvent));
    }
    const nc = this.notificationCenter;
    if (nc && typeof nc.addPushHandler === 'function') {
      this._unsub.push(nc.addPushHandler({ notification: (n) => this._onPush(n) }));
    }
  }

  stop() {
    this._started = false;
    for (const off of this._unsub.splice(0)) { try { off(); } catch { /* gone */ } }
    for (const t of this._timers) clearTimeout(t);
    this._timers.clear();
  }

  /** Signed out of GateControl / another server (MediaService.forgetAll): nothing of this PC's casts is kept. */
  reset() {
    const s = this._s;
    this._s = null;
    this._opened = null;
    this._told = null;
    this._inbox = null;
    if (s) {
      this.emit('command', { session: s.session, cmd: 'stop' });
      this._emitSession();
    }
  }

  _onPush(n) {
    if (!MSV.isSignal(n) || !n.data || n.data.kind !== C.KIND) return false;
    this.receive(n.data, { push: true });
    return 'consumed';
  }

  _timer(fn, ms) {
    const t = setTimeout(() => { this._timers.delete(t); fn(); }, ms);
    if (t.unref) t.unref();
    this._timers.add(t);
    return t;
  }

  inbox() {
    if (!this._inbox) {
      let self = null;
      try { self = this.media && this.media.store && typeof this.media.store.castSelf === 'function' ? this.media.store.castSelf() : null; } catch { self = null; }
      this._inbox = new C.Inbox(self);
    }
    return this._inbox;
  }

  /** This PC's GateControl id, once a signal told it; null before. */
  get self() { return this.inbox().self; }

  status() {
    const s = this._s;
    return { ok: true, session: s ? { session: s.session, controllerName: s.controllerName || null, opened: this._opened === s.session } : null };
  }

  _emitSession() { this.emit('session', this.status()); }

  // ── in ──────────────────────────────────────────────────────

  /** A delivery of `media.cast` ({ push }: the silent signal, else the event). True when it was taken. */
  receive(data, { push = false } = {}) {
    const e = C.envelopeOf(data);
    if (!e) return false;
    const verdict = this.inbox().take(e, {
      push,
      mine: (session) => !!this._s && this._s.session === session,
      onSelf: (id) => { try { if (this.media && this.media.store && typeof this.media.store.setCastSelf === 'function') this.media.store.setCastSelf(id); } catch { /* kept in memory */ } },
    });
    if (verdict !== 'take') return false;
    const m = e.message;
    if (m.type === C.TYPE_PLAY) {
      // the plugin gives no time of its own: the phone's `at` (a signal that waited while the PC was off is too old)
      if (C.freshPlay(m, this.now())) this._job(this._play(m, e));
    } else if (m.type === C.TYPE_COMMAND) {
      this._command(m, e);
    }
    // a state is for the phone, not for this PC
    return true;
  }

  _job(p) { Promise.resolve(p).catch((err) => this.log.warn(`Cast: ${err && err.message}`)); }

  async _play(m, e) {
    const before = this._s;
    const s = C.begin(m, e.from, e.fromName);
    this._s = s;
    this._opened = null;
    this._told = null;
    this.log.info(`Cast: start from ${s.controllerName || 'a device'} (${m.source.id})`);
    // whoever had this PC before: it is over for them
    if (before && before.session !== s.session) {
      this._send(before, { phase: 'stopped', error: C.ERROR.TAKEN_OVER });
      this.emit('command', { session: before.session, cmd: 'stop', takenOver: true });
    }
    this._emitSession();
    this._tell({ phase: 'loading', positionMs: m.positionMs, durationMs: m.item.runtimeMs || 0, title: m.item.name }, true);

    const store = this.media && this.media.store;
    const ref = C.match(m.source, store ? store.sources() : []);
    if (!ref) return this._fail(s, m, C.ERROR.SOURCE_MISSING);
    const itemId = C.itemIdOf(ref.kind, m.item);
    if (!itemId) return this._fail(s, m, C.ERROR.NOT_FOUND);
    // the network rule of Medien (home directly, away only through the VPN, started here), the sign-in, the title
    let detail;
    try { detail = await this.media.detail(ref.sourceId, itemId); } catch (err) { detail = { ok: false, code: (err && err.code) || 'failed' }; }
    if (!this._is(s)) return undefined;
    if (!detail || !detail.ok) return this._fail(s, m, C.errorOf(detail && detail.code));
    if (ref.kind === 'share') {
      if (!detail.share || !detail.share.path) return this._fail(s, m, C.ERROR.NOT_FOUND);
      let check = null;
      try { check = await this.media.shareInspect({ sourceId: ref.sourceId, itemId }); } catch { check = null; }
      if (!this._is(s)) return undefined;
      // Chromium cannot play it at all (avi, …): the phone hears it, nothing opens here
      if (check && check.ok && check.check && check.check.verdict === 'no') return this._fail(s, m, C.ERROR.UNSUPPORTED);
    }
    const title = detail.title || {};
    const share = ref.kind === 'share';
    const item = { ...title, sourceId: ref.sourceId, id: itemId, name: title.name || m.item.name, fromShare: share || title.fromShare === true };
    this.emit('play', {
      session: s.session,
      sourceId: ref.sourceId,
      itemId,
      item,
      detail,
      startMs: m.positionMs,
      audioIndex: share ? null : m.audio,
      subtitleIndex: share ? null : m.subtitle,
      controllerName: s.controllerName,
    });
    // the page may not show it (no window, Medien not there): then the phone hears it
    this._timer(() => { if (this._is(s) && this._opened !== s.session) this._fail(s, m, C.ERROR.BLOCKED); }, this.timing.openTimeoutMs);
    return undefined;
  }

  _is(s) { return this._s === s; }

  _fail(s, m, error) {
    if (this._s !== s) return;
    this.log.info(`Cast: not played (${error})`);
    this._s = null;
    this._opened = null;
    this._send(s, { phase: 'failed', positionMs: m.positionMs, title: m.item.name, error });
    this.emit('command', { session: s.session, cmd: 'stop', failed: error });
    this._emitSession();
  }

  _command(m, e) {
    const next = C.accept(this._s, m, e.from, this.now());
    if (!next) return;
    this._s.lastSeq = next.lastSeq;
    const out = { session: m.session, cmd: m.cmd };
    if (m.cmd === 'seek') out.positionMs = m.positionMs;
    if (m.cmd === 'seekBy') out.deltaMs = m.deltaMs;
    if (m.cmd === 'audio' || m.cmd === 'subtitle') {
      const index = C.trackIndex(m.cmd, m.track);
      if (index === null) return;
      out[m.cmd === 'audio' ? 'audioIndex' : 'subtitleIndex'] = index;
    }
    if (m.cmd === 'volume') {
      if (m.volume !== null) out.volume = m.volume;
      if (m.muted !== null) out.muted = m.muted;
    }
    if (m.cmd === 'stop' && this._opened !== m.session) {
      // still loading: nothing to close, over at once
      const s = this._s;
      this._s = null;
      this._send(s, { phase: 'stopped' });
      this._emitSession();
    }
    this.emit('command', out);
  }

  // ── the page ────────────────────────────────────────────────

  /** The player shows the session's title. */
  opened(session) {
    if (!this._s || this._s.session !== session) return { ok: false, code: 'not_found' };
    this._opened = session;
    this._emitSession();
    return { ok: true };
  }

  /**
   * How the player plays now: { phase, positionMs, durationMs, title?, audio?, subtitles?, volume?, muted? }
   * (audio / subtitles as utils/media-cast.js tracksOf); told to the phone when it is worth a message (or `force`).
   */
  state(session, st = {}, { force = false } = {}) {
    if (!this._s || this._s.session !== session || !C.PHASES.includes(st.phase)) return { ok: false, code: 'not_found' };
    return { ok: true, sent: this._tell(st, force) };
  }

  /**
   * The player closed: by the phone's "Stopp" (`byRemote`), at the end (`ended`), on this PC, or it cannot play the
   * title (`failed`: the player shows its error and "Erneut versuchen" here, the phone's remote ends).
   */
  closed(session, { positionMs = 0, durationMs = 0, byRemote = false, ended = false, failed = false } = {}) {
    const s = this._s;
    if (!s || s.session !== session) return { ok: false, code: 'not_found' };
    this._s = null;
    this._opened = null;
    const pos = Math.max(0, Math.floor(Number(positionMs) || 0));
    const dur = Math.max(0, Math.floor(Number(durationMs) || 0));
    if (failed) this._send(s, { phase: 'failed', positionMs: pos, durationMs: dur, error: C.ERROR.FAILED });
    else if (ended) this._send(s, { phase: 'ended', positionMs: dur || pos, durationMs: dur });
    else this._send(s, { phase: 'stopped', positionMs: pos, durationMs: dur, error: byRemote ? null : C.ERROR.CLOSED });
    this._emitSession();
    return { ok: true };
  }

  _tell(st, force) {
    const s = this._s;
    if (!s) return false;
    const now = this.now();
    const snap = C.snapshotOf(st);
    if (!force && !C.shouldReport(this._told, this._toldAt, snap, now)) return false;
    this._told = snap;
    this._toldAt = now;
    this._send(s, st);
    return true;
  }

  // ── out ─────────────────────────────────────────────────────

  /** One state after the other, each with the session's next seq. */
  _send(s, st) {
    // the session object is this PC's own (never shared): its seq grows in place, also after it ended
    const seq = s.nextSeq;
    s.nextSeq = seq + 1;
    const msg = {
      type: C.TYPE_STATE, session: s.session, seq, at: this.now(),
      phase: st.phase,
      positionMs: Math.max(0, Math.floor(Number(st.positionMs) || 0)),
      durationMs: Math.max(0, Math.floor(Number(st.durationMs) || 0)),
      title: typeof st.title === 'string' && st.title.trim() ? st.title.trim().slice(0, 300) : null,
      audio: Array.isArray(st.audio) ? st.audio.filter((t) => t && C.validTrack(t.id)) : [],
      subtitles: Array.isArray(st.subtitles) ? st.subtitles.filter((t) => t && C.validTrack(t.id)) : [],
      error: st.error || null,
      device: this._device(),
      volume: Number.isFinite(st.volume) ? Math.round(Math.min(100, Math.max(0, st.volume))) : null,
      muted: typeof st.muted === 'boolean' ? st.muted : null,
    };
    const p = this._sending.then(() => this._post(s, msg));
    this._sending = p.catch(() => {});
    return p;
  }

  _device() {
    try { return String(this.deviceName() || 'PC').slice(0, 80); } catch { return 'PC'; }
  }

  async _post(s, msg) {
    const fitted = C.fit(msg);
    if (!fitted) { this.log.warn('Cast: state too large'); return 'too_large'; }
    try {
      await this.api._call('POST', `${MSV.API_BASE}v1/cast/${encodeURIComponent(s.session)}/message`, { body: { to: s.controller, body: C.toJson(fitted) } });
      return 'ok';
    } catch (err) {
      const code = (err && err.code) || 'failed';
      this.log.debug(`Cast: state not sent (${code})`);
      // told nothing: the next change goes out; the end of a session once more after the plugin's minute
      if (this._s && this._s.session === s.session) this._told = null;
      if (code === 'rate_limited' && C.isFinal(msg.phase)) {
        this._timer(() => {
          this.api._call('POST', `${MSV.API_BASE}v1/cast/${encodeURIComponent(s.session)}/message`, { body: { to: s.controller, body: C.toJson({ ...fitted, at: this.now() }) } })
            .catch(() => {});
        }, this.timing.retryMs);
      }
      return code;
    }
  }
}

MediaCastReceiver.DEFAULT_TIMING = DEFAULT_TIMING;

module.exports = MediaCastReceiver;

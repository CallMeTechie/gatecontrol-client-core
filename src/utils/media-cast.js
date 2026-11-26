'use strict';

/**
 * "Auf TV/PC abspielen" — this PC as the receiver (cast contract version 1, sections 2 and 3, as Android's
 * `:core:media` cast/ — CastWire, CastEnvelopes, CastInbox, CastReceiverRules, CastSources). Pure, unit-tested; the
 * service is services/media-cast.js.
 *
 * A phone of the same person (the controller) sends the plugin's source id, the title and the place through the plugin
 * „Medien" (`POST v1/cast/{session}/message`); it arrives here as the push stream's event `plugin` with
 * `type: 'media.cast'` and/or as the silent signal (topic media_signal) with `data.kind = 'media.cast'`:
 *
 *   data = { kind: 'media.cast', from, fromName, to, session, body }
 *   body = { v: 1, type: 'cast.play' | 'cast.cmd' | 'cast.state', session, seq, at, … }
 *
 * The PC plays from its own source of the plugin with the same id (its own Jellyfin access or share), opens the player
 * at the place and stays remote-controlled by that phone: commands come in, every change goes back as `cast.state`.
 * Only the source, the title and the place travel, never an access.
 *
 *   envelopeOf(data)         a delivery → { from, fromName, to, session, message } | null
 *   parse(body) / toJson(m)  a message of version 1 ↔ its JSON (unknown fields ignored, broken ones refused)
 *   fit(m, max)              a state made small enough for the plugin (tracks dropped from the end)
 *   Inbox                    which deliveries are for this PC and new (each once, the own id learned from a push)
 *   freshPlay / begin / accept / shouldReport / seekTarget   the receiver's rules
 *   match(ref, sources)      the own source with the plugin's id → { sourceId, kind }
 *   itemIdOf(kind, item)     the title's id in that source (Jellyfin's item id, a share's `f:<path>`)
 *   tracksOf(version, play)  sound and subtitles as the controller shows them
 */

const VERSION = 1;
const KIND = 'media.cast';
const TYPE_PLAY = 'cast.play';
const TYPE_COMMAND = 'cast.cmd';
const TYPE_STATE = 'cast.state';

const CMDS = ['play', 'pause', 'seek', 'seekBy', 'audio', 'subtitle', 'stop', 'status', 'volume'];
const PHASES = ['loading', 'playing', 'paused', 'buffering', 'ended', 'stopped', 'failed'];
const FINAL = new Set(['ended', 'stopped', 'failed']);

const TRACK_OFF = 'off';
const SUBTITLE_OFF = -1;

const ERROR = Object.freeze({
  SOURCE_MISSING: 'source_missing',
  SIGNED_OUT: 'signed_out',
  NOT_FOUND: 'not_found',
  OFFLINE: 'offline',
  UNSUPPORTED: 'unsupported',
  TAKEN_OVER: 'taken_over',
  CLOSED: 'closed',
  BLOCKED: 'blocked',
  FAILED: 'failed',
});

const PLAY_MAX_AGE_MS = 120000;
const COMMAND_MAX_AGE_MS = 60000;
const MAX_BYTES = 3000;
const HEARTBEAT_MS = 300000;
const JUMP_MS = 4000;
const FUTURE_MS = 60000;

const MAX_TEXT = 300;
const MAX_ID = 200;
const MAX_PATH = 1000;
const MAX_TRACKS = 40;
const MAX_POSITION = 7 * 24 * 3600000;

const SESSION_RE = /^[A-Za-z0-9_-]{8,40}$/;
const SOURCE_RE = /^[a-z]{1,8}-[A-Za-z0-9_-]{1,40}$/;
const TRACK_RE = /^[A-Za-z0-9:._-]{1,40}$/;
const ERROR_RE = /^[a-z_]{1,32}$/;
const DEVICE_RE = /^[A-Za-z0-9_-]{1,64}$/;
const JF_ITEM_RE = /^[A-Za-z0-9-]{1,64}$/;

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const validSession = (s) => typeof s === 'string' && SESSION_RE.test(s);
const validTrack = (s) => typeof s === 'string' && TRACK_RE.test(s);
const validError = (s) => typeof s === 'string' && ERROR_RE.test(s);
const validSource = (s) => typeof s === 'string' && SOURCE_RE.test(s);
const validDevice = (s) => typeof s === 'string' && DEVICE_RE.test(s);
const isFinal = (phase) => FINAL.has(phase);

/** A line of text: trimmed, no control characters, not empty and at most `max` long — else null. */
function line(v, max) {
  if (typeof v !== 'string') return null;
  // eslint-disable-next-line no-control-regex
  const s = v.trim().replace(/[\u0000-\u001f\u007f-\u009f]/g, '');
  return s && s.length <= max ? s : null;
}

/** A whole number (also 5.0), not NaN / Infinity / beyond 9e15. */
function int(v) {
  if (typeof v !== 'number' || !Number.isFinite(v) || Math.floor(v) !== v || Math.abs(v) > 9e15) return null;
  return v;
}

const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));

/** Ids are text, also when the server sends a number. */
function idOf(v) {
  if (typeof v === 'string') return v;
  if (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0) return String(v);
  return null;
}

/** A share's relative path: no way up, no absolute path, no backslash. */
function safePath(p) {
  if (typeof p !== 'string' || !p || p.startsWith('/') || p.includes('\\')) return false;
  return p.split('/').every((x) => x && x !== '.' && x !== '..');
}

// ── the messages ─────────────────────────────────────────────

function readTracks(v) {
  if (!Array.isArray(v)) return [];
  const out = [];
  for (const t of v) {
    if (out.length >= MAX_TRACKS) break;
    if (!isObj(t) || !validTrack(t.id)) continue;
    out.push({ id: t.id, label: line(t.label, 120) || t.id, selected: t.selected === true });
  }
  return out;
}

function play(o, base) {
  const s = o.source;
  if (!isObj(s) || !validSource(s.id)) return null;
  const i = o.item;
  if (!isObj(i)) return null;
  let path = null;
  if (i.path !== undefined) {
    path = line(i.path, MAX_PATH);
    // a share's file: never a way up or an absolute path
    if (!path || !safePath(path)) return null;
  }
  const id = line(i.id, MAX_PATH);
  const name = line(i.name, MAX_TEXT);
  if (!id || !name) return null;
  const season = int(i.season);
  const episode = int(i.episode);
  const runtime = int(i.runtimeMs);
  const audio = int(o.audio);
  const subtitle = int(o.subtitle);
  return {
    ...base,
    type: TYPE_PLAY,
    source: { id: s.id, kind: line(s.kind, 20), serverId: line(s.serverId, MAX_ID), name: line(s.name, MAX_TEXT) },
    item: {
      id, name,
      kind: ['movie', 'episode', 'video'].includes(i.kind) ? i.kind : 'video',
      path,
      seriesName: line(i.seriesName, MAX_TEXT),
      season: season !== null && season >= 0 && season <= 9999 ? season : null,
      episode: episode !== null && episode >= 0 && episode <= 99999 ? episode : null,
      runtimeMs: runtime !== null && runtime >= 1 && runtime <= MAX_POSITION ? runtime : null,
    },
    positionMs: clamp(int(o.positionMs) || 0, 0, MAX_POSITION),
    audio: audio !== null && audio >= 0 ? audio : null,
    subtitle: subtitle !== null && subtitle >= SUBTITLE_OFF ? subtitle : null,
    from: line(o.from, 80),
  };
}

function command(o, base) {
  if (!CMDS.includes(o.cmd)) return null;
  const pos = int(o.positionMs);
  const delta = int(o.deltaMs);
  const vol = int(o.volume);
  const m = {
    ...base,
    type: TYPE_COMMAND,
    cmd: o.cmd,
    positionMs: pos === null ? null : clamp(pos, 0, MAX_POSITION),
    deltaMs: delta === null ? null : clamp(delta, -MAX_POSITION, MAX_POSITION),
    track: validTrack(o.track) ? o.track : null,
    // "volume" (a proposal beyond version 1: 0–100 and/or muted; the plugin passes only the commands it knows)
    volume: vol === null ? null : clamp(vol, 0, 100),
    muted: typeof o.muted === 'boolean' ? o.muted : null,
  };
  if (m.cmd === 'seek' && m.positionMs === null) return null;
  if (m.cmd === 'seekBy' && m.deltaMs === null) return null;
  if ((m.cmd === 'audio' || m.cmd === 'subtitle') && m.track === null) return null;
  if (m.cmd === 'volume' && m.volume === null && m.muted === null) return null;
  return m;
}

function state(o, base) {
  if (!PHASES.includes(o.state)) return null;
  return {
    ...base,
    type: TYPE_STATE,
    phase: o.state,
    positionMs: clamp(int(o.positionMs) || 0, 0, MAX_POSITION),
    durationMs: clamp(int(o.durationMs) || 0, 0, MAX_POSITION),
    title: line(o.title, MAX_TEXT),
    audio: readTracks(o.audio),
    subtitles: readTracks(o.subtitles),
    error: validError(o.error) ? o.error : null,
    device: line(o.device, 80),
  };
}

/** A message of version 1; null for anything else (another type, a newer version, a broken field). */
function parse(body) {
  let o = body;
  if (typeof o === 'string') {
    if (o.length > 16000) return null;
    try { o = JSON.parse(o); } catch { return null; }
  }
  if (!isObj(o) || o.v !== VERSION || !validSession(o.session)) return null;
  const seq = int(o.seq);
  const at = int(o.at);
  if (seq === null || seq < 0 || at === null || at < 0) return null;
  const base = { session: o.session, seq, at };
  if (o.type === TYPE_PLAY) return play(o, base);
  if (o.type === TYPE_COMMAND) return command(o, base);
  if (o.type === TYPE_STATE) return state(o, base);
  return null;
}

const tracksJson = (list) => (list || []).slice(0, MAX_TRACKS).map((t) => ({ id: t.id, label: t.label, selected: t.selected === true }));

/** The JSON of a message (only the fields that are set). */
function toJson(m) {
  const o = { v: VERSION, type: m.type, session: m.session, seq: m.seq, at: m.at };
  const put = (k, v) => { if (v !== null && v !== undefined) o[k] = v; };
  if (m.type === TYPE_PLAY) {
    const s = {};
    for (const k of ['id', 'kind', 'serverId', 'name']) if (m.source[k] != null) s[k] = m.source[k];
    const i = {};
    for (const k of ['id', 'name', 'kind', 'path', 'seriesName', 'season', 'episode', 'runtimeMs']) if (m.item[k] != null) i[k] = m.item[k];
    o.source = s;
    o.item = i;
    o.positionMs = m.positionMs || 0;
    put('audio', m.audio);
    put('subtitle', m.subtitle);
    put('from', m.from);
  } else if (m.type === TYPE_COMMAND) {
    o.cmd = m.cmd;
    put('positionMs', m.positionMs);
    put('deltaMs', m.deltaMs);
    put('track', m.track);
    put('volume', m.volume);
    put('muted', m.muted);
  } else {
    o.state = m.phase;
    o.positionMs = Math.max(0, Math.floor(m.positionMs || 0));
    o.durationMs = Math.max(0, Math.floor(m.durationMs || 0));
    put('title', m.title);
    o.audio = tracksJson(m.audio);
    o.subtitles = tracksJson(m.subtitles);
    put('error', m.error);
    put('device', m.device);
    put('volume', m.volume);
    put('muted', m.muted);
  }
  return o;
}

/** The size the plugin counts (JSON, UTF-8). */
const bytes = (m) => Buffer.byteLength(JSON.stringify(toJson(m)), 'utf8');

/** The last track that may go (not chosen, not `off`); -1: none. */
function droppable(list) {
  for (let i = list.length - 1; i >= 0; i--) if (!list[i].selected && list[i].id !== TRACK_OFF) return i;
  return -1;
}

/**
 * A state made small enough for the plugin (`max` bytes): tracks go from the end (the chosen ones and `off` stay),
 * then the title. Null when even that is too big (or for another message that is too big).
 */
function fit(m, max = MAX_BYTES) {
  if (bytes(m) <= max) return m;
  if (m.type !== TYPE_STATE) return null;
  let s = m;
  while (bytes(s) > max) {
    const a = droppable(s.audio);
    const t = droppable(s.subtitles);
    if (t >= 0 && (a < 0 || s.subtitles.length >= s.audio.length)) s = { ...s, subtitles: s.subtitles.filter((_, i) => i !== t) };
    else if (a >= 0) s = { ...s, audio: s.audio.filter((_, i) => i !== a) };
    else if (s.title) s = { ...s, title: null };
    else return null;
  }
  return s;
}

// ── the envelope ─────────────────────────────────────────────

/** A delivery of `media.cast` (the event's data or the silent signal's data); null for anything else. */
function envelopeOf(data) {
  if (!isObj(data) || data.kind !== KIND) return null;
  const from = idOf(data.from);
  const to = idOf(data.to);
  if (!validDevice(from) || !validDevice(to) || from === to) return null;
  if (!validSession(data.session)) return null;
  const message = parse(data.body);
  if (!message || message.session !== data.session) return null;
  return { from, fromName: line(data.fromName, 80), to, session: data.session, message };
}

/** The same sender, session and seq is the same message (it may come as the event and as the signal). */
const keyOf = (e) => `${e.from}|${e.session}|${e.message.seq}`;

/**
 * Which deliveries are for this PC and new (Android's CastInbox):
 * - a silent signal goes to exactly the addressed device: it is ours, its `to` tells this PC its own id;
 * - the event goes to every open app of the person: only `to == self` counts. While the own id is not known yet, an
 *   event counts only for a session this PC runs (`mine`) and never as a start (a start always comes as a signal too);
 * - each message once.
 */
class Inbox {
  constructor(self = null, capacity = 400) {
    this.self = validDevice(self) ? self : null;
    this.capacity = capacity;
    this._seen = new Set();
  }

  /** → 'take' | 'not_mine' | 'duplicate'; `onSelf(id)` when this PC learned (or changed) its id. */
  take(e, { push = false, mine = () => false, onSelf = () => {} } = {}) {
    if (push) {
      if (this.self !== e.to) {
        this.self = e.to;
        onSelf(e.to);
      }
    } else {
      const ours = this.self ? e.to === this.self : e.message.type !== TYPE_PLAY && mine(e.session);
      if (!ours) return 'not_mine';
    }
    const k = keyOf(e);
    if (this._seen.has(k)) return 'duplicate';
    this._seen.add(k);
    while (this._seen.size > this.capacity) this._seen.delete(this._seen.values().next().value);
    return 'take';
  }

  clear() {
    this._seen.clear();
    this.self = null;
  }
}

// ── the receiver's rules ─────────────────────────────────────

/** Server and devices disagree a little on the time: up to a minute in the future is still "now". */
function fresh(at, now, max) { return now - at <= max && at - now <= FUTURE_MS; }

/** A start to act on: not older than 120 s (a signal that waited while the PC was off brings an old start). */
function freshPlay(m, now) { return fresh(m.at, now, PLAY_MAX_AGE_MS); }

/** The session a start makes; whoever had this PC before loses it (taken_over). */
function begin(m, fromDevice, fromName = null) {
  return { session: m.session, controller: fromDevice, controllerName: m.from || fromName || null, lastSeq: m.seq, nextSeq: 1 };
}

/** A command to act on: of `s`'s session, from its controller, newer than the last and fresh → the session with its seq; null: drop it. */
function accept(s, m, fromDevice, now) {
  if (!s || m.session !== s.session || fromDevice !== s.controller || m.seq <= s.lastSeq) return null;
  if (!fresh(m.at, now, COMMAND_MAX_AGE_MS)) return null;
  return { ...s, lastSeq: m.seq };
}

/** The part of a state that decides whether it is worth a message. */
function snapshotOf(st) {
  const sel = (list) => { const t = (list || []).find((x) => x.selected); return t ? t.id : null; };
  return {
    phase: st.phase, positionMs: st.positionMs || 0, durationMs: st.durationMs || 0,
    audio: sel(st.audio), subtitle: sel(st.subtitles), tracks: (st.audio || []).length + (st.subtitles || []).length,
    volume: Number.isFinite(st.volume) ? st.volume : null, muted: st.muted === true,
  };
}

/**
 * Whether to tell the controller about `now` after `last` (null: nothing told yet): on every change of the phase, a
 * track or the volume, on a jump, and as a heartbeat every 5 minutes while it plays — each state is a message of the
 * plugin (60 a minute, 600 an hour per device), so nothing more often.
 */
function shouldReport(last, lastAt, now, nowMs) {
  if (!last) return true;
  if (now.phase !== last.phase || now.audio !== last.audio || now.subtitle !== last.subtitle || now.tracks !== last.tracks) return true;
  if (now.volume !== last.volume || now.muted !== last.muted) return true;
  if (now.durationMs > 0 && last.durationMs <= 0) return true;
  const expected = last.phase === 'playing' ? last.positionMs + (nowMs - lastAt) : last.positionMs;
  if (Math.abs(now.positionMs - expected) > JUMP_MS) return true;
  return now.phase === 'playing' && nowMs - lastAt >= HEARTBEAT_MS;
}

/** The place after `seekBy` from `position`, within the video (not past its last second). */
function seekTarget(position, delta, duration) {
  const to = Math.max(0, position + delta);
  return duration > 0 ? Math.min(to, Math.max(0, duration - 1000)) : to;
}

// ── the source and the title ─────────────────────────────────

/**
 * The own source for the plugin's id `ref.id` among MediaStore's entries: a Jellyfin source, or a share (its visible
 * id: the SMB half, the WebDAV half alone when there is no SMB) → { sourceId, kind: 'jellyfin' | 'share' } | null
 * (not there for this PC: source_missing).
 */
function match(ref, sources) {
  if (!ref || !validSource(ref.id)) return null;
  const own = (Array.isArray(sources) ? sources : []).filter((s) => s && s.managed && s.sid === ref.id);
  const jf = own.find((s) => s.kind === 'jellyfin');
  if (jf) return { sourceId: jf.id, kind: 'jellyfin' };
  const smb = own.find((s) => s.kind === 'smb');
  const dav = own.find((s) => s.kind === 'webdav');
  if (smb) return { sourceId: smb.id, kind: 'share' };
  if (dav) return { sourceId: dav.id, kind: 'share' };
  return null;
}

/** The title's id in the own source: Jellyfin's item id (the same server), a share's file by its path. */
function itemIdOf(kind, item) {
  if (!item) return null;
  if (kind === 'share') return item.path && safePath(item.path) ? `f:${item.path}` : null;
  return typeof item.id === 'string' && JF_ITEM_RE.test(item.id) ? item.id : null;
}

/** The core's play / detail refusals → the contract's error codes. */
function errorOf(code) {
  switch (code) {
    case 'not_found': return ERROR.NOT_FOUND;
    case 'signed_out': case 'unauthorized': case 'no_mapping': case 'quick_connect_off': case 'code_invalid': case 'device_mismatch': return ERROR.SIGNED_OUT;
    case 'offline': case 'unreachable': case 'vpn_required': case 'timeout': case 'tunnel_unreachable': return ERROR.OFFLINE;
    case 'unsupported': return ERROR.UNSUPPORTED;
    default: return ERROR.FAILED;
  }
}

/**
 * Sound and subtitles of a Jellyfin version (media:detail's `versions[0]`) as the controller shows them, `audioIndex`
 * / `subtitleIndex` the ones playing (-1 / null: no subtitle). Track ids are Jellyfin's stream index (`a3`, `s5`),
 * the subtitle "Aus" is `off`. A share's file has none.
 */
function tracksOf(version, { audioIndex = null, subtitleIndex = null } = {}) {
  if (!isObj(version)) return { audio: [], subtitles: [] };
  const label = (s, fallback) => line(s.label || s.displayTitle || s.title || s.languageName || s.language, 120) || fallback;
  const audio = (Array.isArray(version.audio) ? version.audio : [])
    .filter((s) => isObj(s) && Number.isInteger(s.index) && s.index >= 0)
    .slice(0, MAX_TRACKS)
    .map((s) => ({ id: `a${s.index}`, label: label(s, `#${s.index}`), selected: s.index === audioIndex }));
  const subs = (Array.isArray(version.subtitles) ? version.subtitles : [])
    .filter((s) => isObj(s) && Number.isInteger(s.index) && s.index >= 0)
    .slice(0, MAX_TRACKS - 1)
    .map((s) => ({ id: `s${s.index}`, label: label(s, `#${s.index}`), selected: s.index === subtitleIndex }));
  const off = !Number.isInteger(subtitleIndex) || subtitleIndex < 0;
  const subtitles = subs.length ? [{ id: TRACK_OFF, label: 'Aus', selected: off }, ...subs] : [];
  return { audio, subtitles };
}

/** A track id of `audio` / `subtitle` → Jellyfin's stream index (-1: subtitle off); null when it is not one of ours. */
function trackIndex(kind, id) {
  if (kind === 'subtitle' && id === TRACK_OFF) return SUBTITLE_OFF;
  const m = /^([as])(\d{1,4})$/.exec(String(id || ''));
  if (!m || (kind === 'audio') !== (m[1] === 'a')) return null;
  return Number(m[2]);
}

module.exports = {
  VERSION, KIND, TYPE_PLAY, TYPE_COMMAND, TYPE_STATE, CMDS, PHASES, TRACK_OFF, SUBTITLE_OFF, ERROR,
  PLAY_MAX_AGE_MS, COMMAND_MAX_AGE_MS, MAX_BYTES, HEARTBEAT_MS, JUMP_MS,
  validSession, validTrack, validSource, validDevice, safePath, isFinal,
  parse, toJson, bytes, fit, envelopeOf, keyOf, Inbox,
  freshPlay, begin, accept, snapshotOf, shouldReport, seekTarget,
  match, itemIdOf, errorOf, tracksOf, trackIndex,
};

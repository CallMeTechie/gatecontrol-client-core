'use strict';

/**
 * Medien (Stufe 4e): the pure parts of the Jellyfin client — the `Authorization: MediaBrowser …` header, URLs under
 * the server's base, Jellyfin's JSON read by hand (unknown or wrong fields left out, never thrown), the device profile
 * of Chromium in Electron, the PlaybackInfo body, how a title is played (the plan), the progress body, the server
 * search's answers. Unit-tested with the cases of Android's :core:media (JellyfinJson, JellyfinProfile,
 * JellyfinLibrary, JellyfinDiscovery).
 *
 * The device profile (decision 24 a: the app's HTML5 video + hls.js): Chromium plays H.264, VP9, AV1 and — with the
 * hardware decoder of Windows — HEVC in mp4/webm, sound AAC, MP3, Opus, FLAC (Vorbis in webm). DTS and TrueHD never,
 * AC3/E-AC3 not in Chromium under Windows (only when the page's canPlayType says so): Jellyfin converts the sound
 * (mostly only the sound, the picture stays). Converting goes to HLS in fMP4 (hls.js), H.264, AAC up to 5.1. Text
 * subtitles come beside the video as WebVTT, picture subtitles (PGS, DVD) are burnt in.
 */

const MA = require('./media-address');

const TICKS_PER_MS = 10000;
const ORIGINAL_BPS = 200000000;
const SUBTITLES_OFF = -1;
const FIELDS = 'PrimaryImageAspectRatio,DateCreated,Genres,OfficialRating';
const IMAGES = 'Primary,Backdrop,Thumb';
const MEASURE_BYTES = 2500000;
const DISCOVERY_PORT = 7359;
const DISCOVERY_MESSAGE = 'who is JellyfinServer?';
const PLAY_METHODS = Object.freeze({ DIRECT_PLAY: 'DirectPlay', DIRECT_STREAM: 'DirectStream', TRANSCODE: 'Transcode' });

// eslint-disable-next-line no-control-regex
const CONTROL_RE = /[\u0000-\u0009\u000b-\u001f\u007f-\u009f]/g;
// eslint-disable-next-line no-control-regex
const ALL_CONTROL_RE = /[\u0000-\u001f\u007f-\u009f]/g;
const ID_RE = /^[A-Za-z0-9-]{1,64}$/;

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);

// ── JSON helpers ─────────────────────────────────────────────

/** A trimmed string without control characters (a line break stays), else null. */
function str(o, key) {
  const v = isObj(o) ? o[key] : undefined;
  if (typeof v !== 'string' && typeof v !== 'number' && typeof v !== 'boolean') return null;
  const s = String(v).replace(CONTROL_RE, '').trim();
  return s || null;
}

function int(o, key) {
  const v = isObj(o) ? o[key] : undefined;
  return typeof v === 'number' && Number.isFinite(v) ? Math.trunc(v) : null;
}

const long = int;

function bool(o, key) {
  const v = isObj(o) ? o[key] : undefined;
  return typeof v === 'boolean' ? v : null;
}

function obj(o, key) {
  const v = isObj(o) ? o[key] : undefined;
  return isObj(v) ? v : null;
}

function objects(o, key) {
  const v = isObj(o) ? o[key] : undefined;
  return Array.isArray(v) ? v.filter(isObj) : [];
}

function strings(o, key) {
  const v = isObj(o) ? o[key] : undefined;
  if (!Array.isArray(v)) return [];
  return v.filter((x) => typeof x === 'string' || typeof x === 'number').map((x) => String(x).trim()).filter(Boolean);
}

function ticksToMs(ticks) {
  return typeof ticks === 'number' && ticks >= 0 ? Math.floor(ticks / TICKS_PER_MS) : null;
}

function msToTicks(ms) {
  return Math.max(0, Math.floor(Number(ms) || 0)) * TICKS_PER_MS;
}

function dateMs(s) {
  if (!s) return null;
  const t = Date.parse(s);
  return Number.isFinite(t) ? t : null;
}

/** "10.10.3" ≥ major.minor. */
function versionAtLeast(version, major, minor) {
  if (typeof version !== 'string' || !version) return false;
  const parts = version.split('.').map((p) => {
    const m = /^\d+/.exec(p);
    return m ? Number(m[0]) : 0;
  });
  const ma = parts[0] || 0;
  const mi = parts[1] || 0;
  return ma > major || (ma === major && mi >= minor);
}

// ── who asks ─────────────────────────────────────────────────

/**
 * The header of every call: who asks (`info`: { client, device, deviceId, version }) and, once signed in, with which
 * access. The token goes here, never in a URL. The values are URL-encoded (encodeURIComponent, as Jellyfin's own
 * clients do; Jellyfin decodes them): a device name such as "GateControl · Büro-PC" sent raw is refused with 400
 * (Medien-Plugin, spike M0).
 */
function authorization(info, token = null) {
  const q = (s) => encodeURIComponent(String(s == null ? '' : s).replace(ALL_CONTROL_RE, '').slice(0, 200));
  const i = info || {};
  const parts = [`Client="${q(i.client)}"`, `Device="${q(i.device)}"`, `DeviceId="${q(i.deviceId)}"`, `Version="${q(i.version)}"`];
  if (token) parts.push(`Token="${q(token)}"`);
  return `MediaBrowser ${parts.join(', ')}`;
}

// ── URLs ─────────────────────────────────────────────────────

/** `path` ("Items/abc/PlaybackInfo") under the server's `base` with `query` (null/undefined values left out). */
function url(base, path, query = {}) {
  const u = new URL(String(base).replace(/\/+$/, '') + '/');
  const segs = String(path || '').split('/').filter(Boolean).map((s) => encodeURIComponent(s));
  u.pathname = u.pathname.replace(/\/+$/, '') + '/' + segs.join('/');
  for (const [k, v] of Object.entries(query || {})) {
    if (v !== null && v !== undefined) u.searchParams.append(k, String(v));
  }
  return u.toString();
}

/**
 * A path the server gave (a converting URL "/videos/…/master.m3u8?…", a subtitle's URL) as an absolute URL under
 * `base`. An absolute URL is taken by its path and query only: the access header never goes to another host.
 */
function absolute(base, relative) {
  const rel = String(relative || '');
  let pathAndQuery;
  if (/^https?:\/\//i.test(rel)) {
    let u = null;
    try { u = new URL(rel); } catch { u = null; }
    pathAndQuery = u ? u.pathname + u.search : '/';
  } else {
    pathAndQuery = rel.startsWith('/') ? rel : `/${rel}`;
  }
  const b = new URL(String(base));
  const root = `${b.protocol}//${b.host}`;
  const basePath = b.pathname.replace(/\/+$/, '');
  const path = basePath && pathAndQuery.startsWith(`${basePath}/`) ? pathAndQuery : basePath + pathAndQuery;
  return root + path;
}

// ── answers ──────────────────────────────────────────────────

/** `GET /System/Info/Public` → { name, version, id, supported } (10.9 or newer: the API this client speaks). */
function serverInfo(o) {
  const id = str(o, 'Id');
  if (!id) return null;
  const version = str(o, 'Version');
  return { name: (str(o, 'ServerName') || 'Jellyfin').slice(0, 64), version, id, supported: versionAtLeast(version, 10, 9) };
}

/** The answer of a sign-in → { token, userId, userName, serverId } or null. */
function auth(o) {
  const token = str(o, 'AccessToken');
  const user = obj(o, 'User');
  const userId = str(user, 'Id');
  if (!token || !userId) return null;
  return { token, userId, userName: str(user, 'Name'), serverId: str(o, 'ServerId') };
}

/** Quick Connect: the code shown here and the secret this device asks with. */
function quickConnect(o) {
  const code = str(o, 'Code');
  const secret = str(o, 'Secret');
  return code && secret ? { code, secret } : null;
}

/** The code of another device (TV, PC) as typed ("482 913") → "482913", else null. */
function quickConnectCode(input) {
  const s = String(input == null ? '' : input).replace(/[\s-]/g, '');
  return /^\d{6}$/.test(s) ? s : null;
}

const KINDS = { Movie: 'movie', Series: 'series', Season: 'season', Episode: 'episode', Video: 'video', MusicVideo: 'video' };

function kind(type) {
  return Object.prototype.hasOwnProperty.call(KINDS, type) ? KINDS[type] : null;
}

/** One item → a title; null for kinds Medien does not show (music, books, folders). */
function title(o, sourceId) {
  const id = str(o, 'Id');
  const k = kind(str(o, 'Type'));
  const name = str(o, 'Name');
  if (!id || !k || !name) return null;
  const user = obj(o, 'UserData');
  const tags = obj(o, 'ImageTags');
  const ownPrimary = str(tags, 'Primary');
  // an episode without its own picture shows its series' poster
  let posterId = null;
  let posterTag = null;
  if (ownPrimary) { posterId = id; posterTag = ownPrimary; } else if (str(o, 'SeriesPrimaryImageTag')) { posterId = str(o, 'SeriesId'); posterTag = str(o, 'SeriesPrimaryImageTag'); }
  const backdrops = strings(o, 'BackdropImageTags');
  const parentBackdrops = strings(o, 'ParentBackdropImageTags');
  let backdropId = null;
  let backdropTag = null;
  if (backdrops.length) { backdropId = id; backdropTag = backdrops[0]; } else if (parentBackdrops.length) { backdropId = str(o, 'ParentBackdropItemId'); backdropTag = parentBackdrops[0]; }
  const overview = str(o, 'Overview');
  return {
    id,
    sourceId,
    kind: k,
    name: name.slice(0, 200),
    year: int(o, 'ProductionYear'),
    runtimeMs: ticksToMs(long(o, 'RunTimeTicks')),
    positionMs: ticksToMs(long(user, 'PlaybackPositionTicks')) || 0,
    played: bool(user, 'Played') === true,
    seriesId: str(o, 'SeriesId'),
    seriesName: str(o, 'SeriesName'),
    seasonId: str(o, 'SeasonId'),
    season: int(o, 'ParentIndexNumber'),
    episode: int(o, 'IndexNumber'),
    overview: overview ? overview.slice(0, 4000) : null,
    genres: strings(o, 'Genres').slice(0, 4),
    rating: str(o, 'OfficialRating'),
    childCount: int(o, 'ChildCount'),
    unplayed: int(user, 'UnplayedItemCount'),
    posterId,
    posterTag,
    backdropId,
    backdropTag,
    addedAt: dateMs(str(o, 'DateCreated')),
    playedAt: dateMs(str(user, 'LastPlayedDate')),
    fromShare: false,
  };
}

/** The items of `{ "Items": [ … ] }` or of a bare array (`/Items/Latest`). */
function items(e, sourceId) {
  const list = Array.isArray(e) ? e.filter(isObj) : isObj(e) ? objects(e, 'Items') : [];
  return list.map((o) => title(o, sourceId)).filter(Boolean);
}

function total(e) {
  return isObj(e) ? int(e, 'TotalRecordCount') : null;
}

/** Started and not finished: "Weiter ab …". */
function resumable(t) { return !!t && t.positionMs > 0 && !t.played; }

/** The time left ("noch 18 Min."); null without a length or position. */
function leftMs(t) {
  return t && t.runtimeMs > 0 && t.positionMs > 0 ? Math.max(0, t.runtimeMs - t.positionMs) : null;
}

/** Watched share 0..1 for the bar of a card. */
function progressOf(t) {
  return t && t.runtimeMs > 0 ? Math.min(1, Math.max(0, t.positionMs / t.runtimeMs)) : 0;
}

function playable(t) { return !!t && (t.kind === 'movie' || t.kind === 'episode' || t.kind === 'video'); }

/** The start of the next page; null: all loaded. */
function nextOf(page) {
  const n = page.start + page.items.length;
  return page.items.length && n < page.total ? n : null;
}

const STREAM_TYPES = { Video: 'video', Audio: 'audio', Subtitle: 'subtitle' };

function stream(o) {
  const index = int(o, 'Index');
  if (index === null) return null;
  const type = STREAM_TYPES[str(o, 'Type')] || 'other';
  const codec = str(o, 'Codec');
  const lang = str(o, 'Language');
  const t = str(o, 'Title');
  const dt = str(o, 'DisplayTitle');
  const textual = bool(o, 'IsTextSubtitleStream') === true;
  return {
    index,
    type,
    codec: codec ? codec.toLowerCase() : null,
    language: lang && lang.length <= 16 ? lang : null,
    title: t ? t.slice(0, 120) : null,
    displayTitle: dt ? dt.slice(0, 160) : null,
    channels: int(o, 'Channels'),
    external: bool(o, 'IsExternal') === true,
    textual,
    isDefault: bool(o, 'IsDefault') === true,
    forced: bool(o, 'IsForced') === true,
    width: int(o, 'Width'),
    height: int(o, 'Height'),
    videoRange: str(o, 'VideoRange'),
    videoRangeType: str(o, 'VideoRangeType'),
    bitrate: long(o, 'BitRate'),
    deliveryMethod: str(o, 'DeliveryMethod'),
    deliveryUrl: str(o, 'DeliveryUrl'),
    picture: type === 'subtitle' && !textual,
  };
}

/** `TranscodeReasons=AudioCodecNotSupported,SubtitleCodecNotSupported` of a converting URL. */
function reasons(u) {
  if (typeof u !== 'string' || !u.includes('?')) return [];
  const q = u.slice(u.indexOf('?') + 1);
  const part = q.split('&').find((p) => /^TranscodeReasons=/i.test(p));
  if (!part) return [];
  let v = part.slice(part.indexOf('=') + 1);
  try { v = decodeURIComponent(v.replace(/\+/g, ' ')); } catch { /* as it is */ }
  return v.split(',').map((s) => s.trim()).filter(Boolean);
}

function version(o) {
  const id = str(o, 'Id');
  if (!id) return null;
  const container = str(o, 'Container');
  const streams = objects(o, 'MediaStreams').map(stream).filter(Boolean);
  const transcodingUrl = str(o, 'TranscodingUrl');
  const proto = str(o, 'TranscodingSubProtocol');
  return {
    id,
    container: container ? container.toLowerCase() : null,
    bitrate: long(o, 'Bitrate'),
    runtimeMs: ticksToMs(long(o, 'RunTimeTicks')),
    streams,
    defaultAudio: int(o, 'DefaultAudioStreamIndex'),
    defaultSubtitle: int(o, 'DefaultSubtitleStreamIndex'),
    supportsDirectPlay: bool(o, 'SupportsDirectPlay') === true,
    supportsDirectStream: bool(o, 'SupportsDirectStream') === true,
    supportsTranscoding: bool(o, 'SupportsTranscoding') === true,
    transcodingUrl,
    transcodingProtocol: proto ? proto.toLowerCase() : null,
    transcodeReasons: reasons(transcodingUrl),
  };
}

function versions(o) {
  return objects(o, 'MediaSources').map(version).filter(Boolean);
}

const videoOf = (v) => (v && v.streams.find((s) => s.type === 'video')) || null;
const audioOf = (v) => (v ? v.streams.filter((s) => s.type === 'audio') : []);
const subtitlesOf = (v) => (v ? v.streams.filter((s) => s.type === 'subtitle') : []);

// ── the device profile ───────────────────────────────────────

/** What Chromium in this app plays itself; filled from the page's canPlayType / MediaCapabilities (capsOf). */
const DEFAULT_CAPS = Object.freeze({
  hevc: false, av1: true, vp9: true, mkv: false, hdr: false, ac3: false, eac3: false, maxAudioChannels: 6, name: 'GateControl Pro',
});

/** Sound Chromium decodes itself (Vorbis only in webm, it is listed for webm/mkv only). */
const DECODED_AUDIO = Object.freeze(['aac', 'mp3', 'opus', 'flac']);

/** Sound Chromium never plays (Jellyfin converts it, a share's file plays without sound). */
const NEVER_AUDIO = Object.freeze(['dts', 'dca', 'truehd', 'mlp']);

const PICTURE_SUBTITLES = ['pgssub', 'pgs', 'dvdsub', 'dvbsub', 'vobsub'];

/**
 * The capabilities from what the page found (renderer: canPlayType / MediaCapabilities.decodingInfo, matchMedia
 * '(dynamic-range: high)'): only `true` counts, anything else is "no".
 */
function capsOf(probe = {}, name = DEFAULT_CAPS.name) {
  const p = isObj(probe) ? probe : {};
  const ch = Number.isInteger(p.maxAudioChannels) ? Math.min(8, Math.max(2, p.maxAudioChannels)) : DEFAULT_CAPS.maxAudioChannels;
  const nm = typeof name === 'string' && name.trim() ? name.trim().replace(ALL_CONTROL_RE, '').slice(0, 64) : DEFAULT_CAPS.name;
  return {
    hevc: p.hevc === true,
    av1: p.av1 !== false,
    vp9: p.vp9 !== false,
    mkv: p.mkv === true,
    hdr: p.hdr === true,
    ac3: p.ac3 === true,
    eac3: p.eac3 === true,
    maxAudioChannels: ch,
    name: nm,
  };
}

/** The sound codecs played directly with `caps`. */
function directAudio(caps = DEFAULT_CAPS) {
  const out = [...DECODED_AUDIO];
  if (caps.ac3) out.push('ac3');
  if (caps.eac3) out.push('eac3');
  return out;
}

/** H.264 always, HEVC only with the hardware decoder (Risiko 4), VP9 and AV1 as Chromium has them. */
function videoCodecs(caps = DEFAULT_CAPS) {
  return ['h264', caps.hevc ? 'hevc' : null, caps.vp9 ? 'vp9' : null, caps.av1 ? 'av1' : null].filter(Boolean);
}

function direct(container, video, audio) {
  return { Container: container, Type: 'Video', VideoCodec: video, AudioCodec: audio };
}

/** `DeviceProfile` of `PlaybackInfo` for `caps` and `maxBitrate`. */
function profile(caps = DEFAULT_CAPS, maxBitrate = ORIGINAL_BPS) {
  const audio = directAudio(caps).join(',');
  const video = videoCodecs(caps);
  const mp4Video = video.join(',');
  const webmVideo = ['vp8', caps.vp9 ? 'vp9' : null, caps.av1 ? 'av1' : null].filter(Boolean).join(',');
  const direct_ = [
    direct('mp4,m4v,mov', mp4Video, audio),
    direct('webm', webmVideo, 'opus,vorbis'),
  ];
  // Matroska only when the page's Chromium says it plays it; else Jellyfin remuxes (cheap: DirectStream)
  if (caps.mkv) direct_.push(direct('mkv', mp4Video, `${audio},vorbis`));
  const codecProfiles = [];
  if (!caps.hdr) {
    // an SDR screen (or Windows' HDR off): HDR video is tone-mapped on the NAS
    codecProfiles.push({ Type: 'Video', Conditions: [{ Condition: 'EqualsAny', Property: 'VideoRangeType', Value: 'SDR', IsRequired: false }] });
  }
  const subtitles = [{ Format: 'vtt', Method: 'External' }];
  for (const f of PICTURE_SUBTITLES) subtitles.push({ Format: f, Method: 'Encode' });
  return {
    Name: caps.name || DEFAULT_CAPS.name,
    MaxStreamingBitrate: maxBitrate,
    MaxStaticBitrate: maxBitrate,
    MusicStreamingTranscodingBitrate: 384000,
    DirectPlayProfiles: direct_,
    TranscodingProfiles: [{
      // hls.js: HLS in fMP4; H.264 first (what the NAS's Quick Sync converts to without effort), the picture copied
      // when it is one Chromium plays
      Container: 'mp4',
      Type: 'Video',
      Protocol: 'hls',
      VideoCodec: mp4Video,
      AudioCodec: 'aac,mp3,opus,flac',
      Context: 'Streaming',
      MaxAudioChannels: String(caps.maxAudioChannels || 6),
      MinSegments: 1,
      BreakOnNonKeyFrames: true,
      CopyTimestamps: false,
    }],
    ContainerProfiles: [],
    CodecProfiles: codecProfiles,
    SubtitleProfiles: subtitles,
  };
}

// ── playing ──────────────────────────────────────────────────

/**
 * What to play: { itemId, versionId?, startMs?, audioIndex?, subtitleIndex? (SUBTITLES_OFF: none), maxBitrate? }.
 * → the `PlaybackInfo` body: the device profile, the cap, the start and the chosen streams.
 */
function playbackBody(play, caps, userId) {
  const max = Number.isFinite(play.maxBitrate) && play.maxBitrate > 0 ? Math.floor(play.maxBitrate) : ORIGINAL_BPS;
  const body = { UserId: userId || '', MaxStreamingBitrate: max, StartTimeTicks: msToTicks(play.startMs || 0) };
  if (Number.isInteger(play.audioIndex)) body.AudioStreamIndex = play.audioIndex;
  if (Number.isInteger(play.subtitleIndex)) body.SubtitleStreamIndex = play.subtitleIndex;
  if (play.versionId) body.MediaSourceId = play.versionId;
  Object.assign(body, {
    EnableDirectPlay: true, EnableDirectStream: true, EnableTranscoding: true,
    AllowVideoStreamCopy: true, AllowAudioStreamCopy: true, AutoOpenLiveStream: true,
    DeviceProfile: profile(caps, max),
  });
  return body;
}

function subtitleMime(s) {
  const path = String(s.deliveryUrl || '').split('?')[0].toLowerCase();
  if (path.endsWith('.vtt')) return 'text/vtt';
  if (path.endsWith('.srt') || s.codec === 'subrip' || s.codec === 'srt') return 'application/x-subrip';
  if (path.endsWith('.ass') || path.endsWith('.ssa')) return 'text/x-ssa';
  if (path.endsWith('.ttml')) return 'application/ttml+xml';
  return 'text/vtt';
}

function staticUrl(base, itemId, v, playSessionId, deviceId) {
  return url(base, `Videos/${itemId}/stream`, { static: true, mediaSourceId: v.id, playSessionId, deviceId });
}

/**
 * How `v` is played: the file itself when the server allows it (direct), else its converting URL; the chosen subtitle
 * beside the video when the server delivers it as a file. Null: neither is offered.
 */
function plan(base, play, v, playSessionId, deviceId) {
  let u;
  let method;
  if (v.supportsDirectPlay) {
    u = staticUrl(base, play.itemId, v, playSessionId, deviceId);
    method = PLAY_METHODS.DIRECT_PLAY;
  } else if (v.transcodingUrl) {
    u = absolute(base, v.transcodingUrl);
    const onlyContainer = v.transcodeReasons.length > 0 && v.transcodeReasons.every((r) => r === 'ContainerNotSupported');
    method = onlyContainer ? PLAY_METHODS.DIRECT_STREAM : PLAY_METHODS.TRANSCODE;
  } else if (v.supportsDirectStream) {
    u = staticUrl(base, play.itemId, v, playSessionId, deviceId);
    method = PLAY_METHODS.DIRECT_STREAM;
  } else {
    return null;
  }
  const subIdx = Number.isInteger(play.subtitleIndex) && play.subtitleIndex >= 0 ? play.subtitleIndex
    : (play.subtitleIndex === undefined || play.subtitleIndex === null ? v.defaultSubtitle : null);
  const side = subtitlesOf(v)
    .filter((s) => s.index === subIdx && s.deliveryMethod === 'External' && s.deliveryUrl)
    .map((s) => ({ index: s.index, url: absolute(base, s.deliveryUrl), mime: subtitleMime(s), language: s.language, label: s.displayTitle || s.title }));
  const hls = v.transcodingProtocol === 'hls' || u.split('?')[0].toLowerCase().endsWith('.m3u8');
  const max = Number.isFinite(play.maxBitrate) && play.maxBitrate > 0 ? play.maxBitrate : ORIGINAL_BPS;
  return {
    itemId: play.itemId,
    url: u,
    method,
    version: v,
    playSessionId: playSessionId || null,
    hls: method !== PLAY_METHODS.DIRECT_PLAY && hls,
    audioIndex: Number.isInteger(play.audioIndex) ? play.audioIndex : v.defaultAudio,
    subtitleIndex: subIdx === undefined ? null : subIdx,
    bitrate: method === PLAY_METHODS.TRANSCODE && max < ORIGINAL_BPS ? max : null,
    converted: method === PLAY_METHODS.TRANSCODE,
    sideSubtitles: side,
  };
}

/** The body of the three progress reports (Sessions/Playing, …/Progress, …/Stopped). */
function progressBody(p, stopped = false) {
  const pl = p.plan;
  const b = { ItemId: pl.itemId, MediaSourceId: pl.version.id };
  if (pl.playSessionId) b.PlaySessionId = pl.playSessionId;
  Object.assign(b, {
    PositionTicks: msToTicks(p.positionMs),
    IsPaused: p.paused === true,
    IsMuted: false,
    CanSeek: true,
    PlayMethod: pl.method,
  });
  if (Number.isInteger(pl.audioIndex)) b.AudioStreamIndex = pl.audioIndex;
  b.SubtitleStreamIndex = Number.isInteger(pl.subtitleIndex) ? pl.subtitleIndex : SUBTITLES_OFF;
  if (stopped) b.Failed = false;
  return b;
}

/** The path and query of a title's picture (backdrop: the wide one), at most maxHeight px high; null: it has none. */
function imagePath(t, backdrop, maxHeight) {
  const id = backdrop ? t.backdropId : t.posterId;
  const tag = backdrop ? t.backdropTag : t.posterTag;
  if (!id || !tag || !ID_RE.test(id)) return null;
  const h = Math.min(2160, Math.max(48, Math.floor(Number(maxHeight) || 300)));
  return `Items/${id}/Images/${backdrop ? 'Backdrop' : 'Primary'}?maxHeight=${h}&quality=85&tag=${encodeURIComponent(tag)}`;
}

// ── the server search ────────────────────────────────────────

/**
 * One answer of the UDP search (`{"Address":"http://192.168.1.20:8096","Id":"…","Name":"DS918+"}`) → { address, id,
 * name } or null. The address must be one of the home network; a server that names another one (its public URL) is
 * taken at the address it answered from (`from`) on Jellyfin's HTTP port.
 */
function parseDiscovery(text, from = null) {
  if (typeof text !== 'string' || text.length > 4096) return null;
  let o;
  try { o = JSON.parse(text); } catch { return null; }
  if (!isObj(o)) return null;
  const s = (k) => {
    const v = o[k];
    if (typeof v !== 'string') return null;
    const t = v.replace(ALL_CONTROL_RE, '').trim();
    return t || null;
  };
  const id = s('Id');
  if (!id || id.length > 64 || !/^[A-Za-z0-9-]+$/.test(id)) return null;
  let named = null;
  try { named = s('Address') ? new URL(s('Address')) : null; } catch { named = null; }
  let base = null;
  if (named && (named.protocol === 'http:' || named.protocol === 'https:') && MA.isHomeHost(named.hostname)) base = MA.normalize(named.toString());
  else if (from && MA.isPrivateIpv4(from)) base = MA.normalize(`http://${from}:${MA.JELLYFIN_HTTP_PORT}`);
  if (!base) return null;
  const name = (s('Name') || MA.host(base) || '').slice(0, 64);
  return name ? { address: base, id, name } : null;
}

/** The directed broadcast of address/prefix ("192.168.1.37"/24 → "192.168.1.255"); null but for private IPv4, 8..30. */
function broadcastOf(address, prefix) {
  if (!MA.isPrivateIpv4(address) || !Number.isInteger(prefix) || prefix < 8 || prefix > 30) return null;
  const v = address.split('.').reduce((acc, p) => acc * 256 + Number(p), 0);
  const hostBits = 2 ** (32 - prefix) - 1;
  const b = (v - (v % (hostBits + 1))) + hostBits;
  return [24, 16, 8, 0].map((sh) => Math.floor(b / 2 ** sh) % 256).join('.');
}

module.exports = {
  TICKS_PER_MS,
  ORIGINAL_BPS,
  SUBTITLES_OFF,
  FIELDS,
  IMAGES,
  MEASURE_BYTES,
  DISCOVERY_PORT,
  DISCOVERY_MESSAGE,
  PLAY_METHODS,
  DEFAULT_CAPS,
  DECODED_AUDIO,
  NEVER_AUDIO,
  ID_RE,
  str, int, long, bool, obj, objects, strings,
  ticksToMs,
  msToTicks,
  versionAtLeast,
  authorization,
  url,
  absolute,
  serverInfo,
  auth,
  quickConnect,
  quickConnectCode,
  kind,
  title,
  items,
  total,
  resumable,
  leftMs,
  progressOf,
  playable,
  nextOf,
  stream,
  version,
  versions,
  reasons,
  videoOf,
  audioOf,
  subtitlesOf,
  capsOf,
  directAudio,
  videoCodecs,
  profile,
  playbackBody,
  plan,
  progressBody,
  imagePath,
  parseDiscovery,
  broadcastOf,
};

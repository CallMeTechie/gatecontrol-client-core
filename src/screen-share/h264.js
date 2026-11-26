/*
 * GateControl – Fernzugriff stage 7: H.264 helpers of "Bildschirm teilen" (the sender of gc-screen.v1).
 *
 * Shared by the capture window (src/screen-share/capture.html loads this file as a script: window.GCH264) and the
 * main process / tests (require). No DOM, no Node API.
 *
 *   nalUnits(u8)                  the NAL units of an Annex B access unit → [{ type, start, end, header }]
 *   codecOf(sps)                  the RFC 6381 string of an SPS NAL (without start code) → 'avc1.PPCCLL' | null
 *   withParamSets(u8, cache)      a key frame without SPS/PPS gets the last ones in front (the relay needs them before
 *                                 every key frame: a new viewer starts at any key frame); the cache learns them
 *   frameHeader(key, tsUs)        the 12-byte head of a binary frame of gc-screen.v1
 *   fitSize(w, h, maxEdge, maxShort)   the encoded size: aspect kept, even, inside 1920×1080
 *   encoderConfigs(w, h, o)       the VideoEncoder configurations to try, hardware first
 */
(function (root, factory) {
  'use strict';
  var lib = factory();
  if (typeof module === 'object' && module.exports) module.exports = lib;
  else root.GCH264 = lib;
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var START = new Uint8Array([0, 0, 0, 1]);

  /** The NAL units of an Annex B stream (start codes 00 00 01 or 00 00 00 01). */
  function nalUnits(u8) {
    var out = [];
    var n = u8.length;
    var i = 0;
    var cur = null;
    while (i + 3 <= n) {
      if (u8[i] === 0 && u8[i + 1] === 0 && (u8[i + 2] === 1 || (u8[i + 2] === 0 && i + 3 < n && u8[i + 3] === 1))) {
        var sc = u8[i + 2] === 1 ? 3 : 4;
        if (cur) { cur.end = i; out.push(cur); }
        var h = i + sc;
        cur = h < n ? { type: u8[h] & 0x1f, start: i, header: h, end: n } : null;
        i = h;
        continue;
      }
      i++;
    }
    if (cur) { cur.end = n; out.push(cur); }
    // trailing zero bytes of a unit belong to the next start code, not to the unit
    return out;
  }

  function hex2(v) { var s = (v & 0xff).toString(16).toUpperCase(); return s.length < 2 ? '0' + s : s; }

  /** 'avc1.PPCCLL' of an SPS NAL (its first byte the NAL header), null when it is none. */
  function codecOf(sps) {
    if (!sps || sps.length < 4 || (sps[0] & 0x1f) !== 7) return null;
    return 'avc1.' + hex2(sps[1]) + hex2(sps[2]) + hex2(sps[3]);
  }

  function concat(parts) {
    var len = 0;
    parts.forEach(function (p) { len += p.length; });
    var out = new Uint8Array(len);
    var o = 0;
    parts.forEach(function (p) { out.set(p, o); o += p.length; });
    return out;
  }

  /**
   * An access unit → { data, codec, key }: SPS/PPS learnt into `cache` ({ sps, pps } with start codes), a key frame (IDR)
   * without them gets the cached ones in front. codec: the string of the SPS of this unit (or of the cache).
   */
  function withParamSets(u8, cache) {
    var units = nalUnits(u8);
    var hasSps = false;
    var hasPps = false;
    var idr = false;
    units.forEach(function (u) {
      if (u.type === 7) { hasSps = true; cache.sps = concat([START, u8.subarray(u.header, u.end)]); cache.codec = codecOf(u8.subarray(u.header, u.end)) || cache.codec; }
      else if (u.type === 8) { hasPps = true; cache.pps = concat([START, u8.subarray(u.header, u.end)]); }
      else if (u.type === 5) idr = true;
    });
    var data = u8;
    if (idr && (!hasSps || !hasPps) && cache.sps && cache.pps) data = concat([hasSps ? new Uint8Array(0) : cache.sps, hasPps ? new Uint8Array(0) : cache.pps, u8]);
    return { data: data, codec: cache.codec || null, key: idr };
  }

  /** The 12-byte head: version 1, flags (bit 0 key frame), 0, 0, timestamp µs as uint64 big endian. */
  function frameHeader(key, tsUs) {
    var h = new Uint8Array(12);
    h[0] = 1;
    h[1] = key ? 1 : 0;
    var ts = Math.max(0, Math.floor(Number(tsUs) || 0));
    var hi = Math.floor(ts / 4294967296);
    var lo = ts - hi * 4294967296;
    var dv = new DataView(h.buffer);
    dv.setUint32(4, hi >>> 0);
    dv.setUint32(8, lo >>> 0);
    return h;
  }

  /** The size to encode: the aspect of the display, even, the long edge ≤ maxEdge and the short one ≤ maxShort. */
  function fitSize(w, h, maxEdge, maxShort) {
    var W = Math.max(16, Math.round(Number(w) || 0));
    var H = Math.max(16, Math.round(Number(h) || 0));
    var me = maxEdge || 1920;
    var ms = maxShort || 1080;
    var s = Math.min(1, me / Math.max(W, H), ms / Math.min(W, H));
    var even = function (v) { var x = Math.floor(v * s); return Math.max(16, x - (x % 2)); };
    return { width: even(W), height: even(H) };
  }

  /** The level of a size in macroblocks: 3.1 up to 1280×720, 4.0 up to 2048×1088 (both 30 fps). */
  function levelOf(w, h) {
    var mbs = Math.ceil(w / 16) * Math.ceil(h / 16);
    return mbs <= 3600 ? '1F' : '28';
  }

  /**
   * The VideoEncoder configurations to try, in order: Constrained Baseline, then Main — each with the GPU first
   * (Media Foundation), then the software encoder, then whatever the browser has. Annex B, realtime.
   */
  function encoderConfigs(w, h, o) {
    var opt = o || {};
    var lvl = levelOf(w, h);
    var out = [];
    ['42E0', '4D40'].forEach(function (p) {
      ['prefer-hardware', 'prefer-software', 'no-preference'].forEach(function (hw) {
        out.push({ codec: 'avc1.' + p + lvl, width: w, height: h, bitrate: opt.bitrate || 2000000, framerate: opt.fps || 15, bitrateMode: 'variable',
          latencyMode: 'realtime', hardwareAcceleration: hw, avc: { format: 'annexb' } });
      });
    });
    return out;
  }

  return { nalUnits: nalUnits, codecOf: codecOf, withParamSets: withParamSets, frameHeader: frameHeader, fitSize: fitSize, levelOf: levelOf,
    encoderConfigs: encoderConfigs };
}));

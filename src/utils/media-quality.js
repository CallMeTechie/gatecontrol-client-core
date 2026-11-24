'use strict';

/**
 * Medien (Stufe 4e): the quality of the player (decision 10) — "Automatisch": at home always the original, away the
 * original only when the measured bandwidth carries it, else the NAS converts to the step that goes through without
 * stalling — or a fixed step up to "immer Original". Pure, unit-tested with the cases of Android's MediaQuality.
 */

const ORIGINAL_BPS = 200000000;
/** Away without a measurement: a careful start. */
const UNMEASURED_BPS = 8000000;
/** The steps the NAS converts to (as the mockup: 1080p · 8 Mbit/s for 18 Mbit/s measured). */
const LADDER = Object.freeze([20000000, 12000000, 8000000, 4000000, 2000000, 1000000]);
/** Of the measured bandwidth this share is used: a hotel's line varies, the sound and the overhead come on top. */
const HEADROOM = 0.6;

/** The settings: wire value → bit/s (null: automatic). */
const SETTINGS = Object.freeze({ auto: null, original: ORIGINAL_BPS, 20: 20000000, 12: 12000000, 8: 8000000, 4: 4000000, 2: 2000000 });

function settingOf(value) {
  const v = String(value == null ? '' : value);
  return Object.prototype.hasOwnProperty.call(SETTINGS, v) ? v : 'auto';
}

/** The highest step of LADDER that fits `measuredBps` with HEADROOM; the lowest when none does. */
function step(measuredBps) {
  const usable = Math.floor(measuredBps * HEADROOM);
  return LADDER.find((s) => s <= usable) || LADDER[LADDER.length - 1];
}

/** The original of `originalBps` goes through `measuredBps` (with HEADROOM); unknown bit rate: assumed not. */
function fits(originalBps, measuredBps) {
  return Number.isFinite(originalBps) && originalBps > 0 && originalBps <= Math.floor(measuredBps * HEADROOM);
}

const known = (v) => Number.isFinite(v) && v > 0;

/**
 * The `MaxStreamingBitrate` to ask for: `setting` fixed, else at home (or alwaysOriginal, or a source that cannot
 * convert) the original; away the original when it fits `measuredBps`, else step(). Away without a measurement:
 * UNMEASURED_BPS unless the original is known to be smaller.
 */
function cap({ setting = 'auto', atHome, measuredBps = null, originalBps = null, alwaysOriginal = false, canConvert = true } = {}) {
  if (!canConvert || alwaysOriginal) return ORIGINAL_BPS;
  const fixed = SETTINGS[settingOf(setting)];
  if (fixed) return fixed;
  if (atHome) return ORIGINAL_BPS;
  if (!known(measuredBps)) return known(originalBps) && originalBps <= UNMEASURED_BPS ? ORIGINAL_BPS : UNMEASURED_BPS;
  return fits(originalBps, measuredBps) ? ORIGINAL_BPS : step(measuredBps);
}

/**
 * What the detail page shows for a title of `originalBps` on this line (mockup 8):
 * { originalBps, originalFits, adaptedBps, suggestAdapted }.
 */
function offer({ atHome, measuredBps = null, originalBps = null, alwaysOriginal = false, canConvert = true } = {}) {
  const o = Number.isFinite(originalBps) ? originalBps : null;
  if (!canConvert || atHome) return { originalBps: o, originalFits: true, adaptedBps: null, suggestAdapted: false };
  if (!known(measuredBps)) {
    const small = known(originalBps) && originalBps <= UNMEASURED_BPS;
    const adapted = small ? null : UNMEASURED_BPS;
    return { originalBps: o, originalFits: small, adaptedBps: adapted, suggestAdapted: adapted !== null && !alwaysOriginal };
  }
  const f = fits(originalBps, measuredBps);
  const adapted = f ? null : step(measuredBps);
  return { originalBps: o, originalFits: f, adaptedBps: adapted, suggestAdapted: adapted !== null && !alwaysOriginal };
}

/** "18 Mbit/s" / "2,5 Mbit/s" / "800 kbit/s" (lang 'en': "2.5 Mbit/s"). */
function label(bps, lang = 'de') {
  if (bps >= 10000000) return `${Math.floor(bps / 1000000)} Mbit/s`;
  if (bps >= 1000000) {
    const tenths = Math.floor(bps / 100000);
    if (tenths % 10 === 0) return `${tenths / 10} Mbit/s`;
    const s = (tenths / 10).toFixed(1);
    return `${lang === 'en' ? s : s.replace('.', ',')} Mbit/s`;
  }
  return `${Math.floor(bps / 1000)} kbit/s`;
}

/** The picture a converting step gives (as the server scales by bit rate): "1080p" from 6 Mbit/s, "720p" from 3. */
function resolution(bps) {
  if (bps >= 6000000) return '1080p';
  if (bps >= 3000000) return '720p';
  return '480p';
}

/** "HDR10", "HDR10+", "Dolby Vision", "HLG", "HDR"; null for SDR. */
function hdrLabel(video) {
  if (!video) return null;
  const type = video.videoRangeType ? String(video.videoRangeType).toUpperCase() : null;
  if (!type || type === 'SDR' || type === 'UNKNOWN') return String(video.videoRange || '').toUpperCase() === 'HDR' ? 'HDR' : null;
  if (type.startsWith('DOVI')) return 'Dolby Vision';
  if (type === 'HDR10PLUS') return 'HDR10+';
  if (type === 'HDR10') return 'HDR10';
  if (type === 'HLG') return 'HLG';
  return 'HDR';
}

/** The picture of a video stream: "4K HDR", "1080p", "720p". */
function videoLabel(video) {
  if (!video || !Number.isFinite(video.height)) return null;
  const h = video.height;
  const w = video.width || 0;
  let res;
  if (h >= 1600 || w >= 3200) res = '4K';
  else if (h >= 1000 || w >= 1800) res = '1080p';
  else if (h >= 700 || w >= 1200) res = '720p';
  else if (h > 0) res = `${h}p`;
  else return null;
  const hdr = hdrLabel(video);
  return hdr ? `${res} ${hdr}` : res;
}

module.exports = {
  ORIGINAL_BPS, UNMEASURED_BPS, LADDER, HEADROOM, SETTINGS,
  settingOf, step, fits, cap, offer, label, resolution, hdrLabel, videoLabel,
};

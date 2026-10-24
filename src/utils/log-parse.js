'use strict';

/**
 * Log file → entries for the "Protokoll" page (logs:get).
 *
 * electron-log writes `[YYYY-MM-DD HH:MM:SS.mmm] [level]{scope} text` and
 * ends every line with os.EOL — "\r\n" on Windows. The renderers used to
 * split the text on "\n" only; the "\r" left at the end of every line made
 * their pattern (`(.*)$`, where `.` does not match "\r") fail, so the whole
 * raw line ended up in the "Meldung" column with empty time and level.
 *
 * Here:
 *   - "\r\n" and "\n" both end a line,
 *   - a line without the timestamp header (stack trace, multi-line message)
 *     belongs to the entry above it,
 *   - the level is normalized (warning → warn, verbose/silly → debug); an
 *     unknown bracket after the timestamp stays part of the message,
 *   - the timestamp is local time (as electron-log writes it).
 *
 * Electron-free (unit-tested in test/log-parse.test.js).
 */

const HEAD_RE = /^\[(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?\][ \t]*(?:\[([^\]\r\n]{0,40})\][ \t]*)?(?:\[([^\]\r\n]{0,40})\][ \t]*)?(.*)$/;

const LEVELS = Object.freeze({
  error: 'error',
  warn: 'warn',
  warning: 'warn',
  info: 'info',
  debug: 'debug',
  verbose: 'debug',
  silly: 'debug',
});

const PERIOD_HOURS = Object.freeze({ '1h': 1, '12h': 12, '24h': 24 });

function levelOf(v) {
  return typeof v === 'string' ? LEVELS[v.trim().toLowerCase()] || null : null;
}

/**
 * Parse one header line → entry, or null when the line has no header.
 * @returns {{ts: number, date: string, time: string, ms: string, level: string|null, msg: string}|null}
 */
function parseHeader(line) {
  const m = HEAD_RE.exec(line);
  if (!m) return null;
  const [, y, mo, d, h, mi, s, frac = '', b1, b2, rest] = m;
  const ms = frac ? frac.padEnd(3, '0').slice(0, 3) : '000';
  const ts = new Date(Number(y), Number(mo) - 1, Number(d), Number(h), Number(mi), Number(s), Number(ms)).getTime();
  // "[level] text" or "[scope] [level] text" (older formats); otherwise the
  // bracket is part of the message.
  let level = null;
  let msg = rest;
  if (b2 !== undefined && levelOf(b2)) {
    level = levelOf(b2);
    msg = `[${b1}] ${rest}`;
  } else if (b1 !== undefined && levelOf(b1)) {
    level = levelOf(b1);
    if (b2 !== undefined) msg = `[${b2}] ${rest}`;
  } else if (b1 !== undefined) {
    msg = `[${b1}]${b2 !== undefined ? ` [${b2}]` : ''} ${rest}`;
  }
  return {
    ts: Number.isFinite(ts) ? ts : null,
    date: `${y}-${mo}-${d}`,
    time: `${h}:${mi}:${s}`,
    ms,
    level,
    msg: msg.trimEnd(),
  };
}

/**
 * @param {string} text - log file content
 * @param {object} [opts]
 * @param {boolean} [opts.raw=false] - keep the original lines (entry.raw)
 * @returns {Array<object>} entries, oldest first
 */
function parseLogText(text, { raw = false } = {}) {
  const entries = [];
  if (typeof text !== 'string' || !text) return entries;
  let cur = null;
  for (const line of text.split(/\r?\n/)) {
    const clean = line.replace(/\r+$/, '');
    if (!clean.trim()) continue;
    const head = parseHeader(clean);
    if (head) {
      cur = head;
      if (raw) cur.raw = clean;
      entries.push(cur);
    } else if (cur) {
      cur.msg += `\n${clean.trimEnd()}`;
      if (raw) cur.raw += `\n${clean}`;
    } else {
      // Continuation of an entry cut off at the start of the read window.
      cur = { ts: null, date: '', time: '', ms: '', level: null, msg: clean.trimEnd() };
      if (raw) cur.raw = clean;
      entries.push(cur);
    }
  }
  return entries;
}

/**
 * Keep entries of the last 1h / 12h / 24h ('all' or unknown: everything).
 * Entries without a timestamp are kept.
 */
function filterByPeriod(entries, period, now = Date.now()) {
  const hours = PERIOD_HOURS[period];
  if (!hours) return entries;
  const cutoff = now - hours * 3600000;
  return entries.filter((e) => e.ts === null || e.ts >= cutoff);
}

module.exports = { parseLogText, parseHeader, filterByPeriod, LEVELS, PERIOD_HOURS };

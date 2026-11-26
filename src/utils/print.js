'use strict';

/**
 * Pure helpers of "Drucken" (plugin `gatecontrol-print`; contract: the
 * plugin's README "API", plugin 1.1.1): paths, the file types and the size
 * the plugin takes (plugin.json `media`), which type a file of this PC or of
 * Drive goes up as, argument checks of `POST print`, cleaned answers of
 * `overview` and `jobs/<id>`, and the context of a print push.
 *
 * Everything that reaches the renderer goes through the normalizers below:
 * known fields only, strings capped and stripped of control characters,
 * ids and codes checked, times as ms timestamps. A field an older plugin
 * does not send counts as "not there" (no paper / tray before 1.1.0, no
 * `expiresAt` / `doneAt` before 1.1.1). The apps show the text with
 * textContent only.
 */

const PLUGIN_ID = 'gatecontrol-print';
const APP_ROUTE = `plg-${PLUGIN_ID}`;
const TOPIC_PREFIX = `plugin:${PLUGIN_ID}:`;
const TOPIC_DONE = `${TOPIC_PREFIX}print_done`;
const TOPIC_FAILED = `${TOPIC_PREFIX}print_failed`;
const API_BASE = `/api/v1/client/plugins/${PLUGIN_ID}/api/`;
const MEDIA_PATH = `/api/v1/client/plugins/${PLUGIN_ID}/media`;

/** plugin.json `media.maxBytes` (50 MB) */
const MAX_BYTES = 50 * 1024 * 1024;
/** Files of one print dialog (each becomes a job; the server allows 20 open jobs a person). */
const MAX_FILES = 20;
const MAX_COPIES = 99;

/** Office files: printed where the printer's gateway turns them into a PDF (`printer.office`). */
const OFFICE_TYPES = Object.freeze([
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  'application/vnd.oasis.opendocument.text',
  'application/vnd.oasis.opendocument.spreadsheet',
  'application/vnd.oasis.opendocument.presentation',
  'application/rtf',
]);
const IMAGE_TYPES = Object.freeze(['image/jpeg', 'image/png', 'image/webp', 'image/heic', 'image/heif']);
/** plugin.json `media.types`: uploads of other types are refused (415). */
const UPLOAD_TYPES = Object.freeze(['application/pdf', ...IMAGE_TYPES, 'text/plain', ...OFFICE_TYPES]);

/** File extension → the type it goes up as. */
const EXTENSIONS = Object.freeze({
  pdf: 'application/pdf',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  png: 'image/png',
  webp: 'image/webp',
  heic: 'image/heic',
  heif: 'image/heif',
  txt: 'text/plain',
  docx: OFFICE_TYPES[0],
  xlsx: OFFICE_TYPES[1],
  pptx: OFFICE_TYPES[2],
  odt: OFFICE_TYPES[3],
  ods: OFFICE_TYPES[4],
  odp: OFFICE_TYPES[5],
  rtf: 'application/rtf',
});

const PRINTER_STATES = ['idle', 'processing', 'stopped', 'offline'];
const JOB_OPEN = ['queued', 'sending', 'printing', 'waiting'];

// Device ids are `u:<uuid>` or `h:<sha1>` (gateway docs/print.md); a little more is allowed, never a path.
const DEVICE_ID_RE = /^[A-Za-z0-9:_.-]{1,120}$/;
const JOB_ID_RE = /^[A-Za-z0-9_-]{1,80}$/;
const CODE_RE = /^[a-z][a-z0-9_]{0,40}$/;
// A job's `message`: a code, or a printer's stop reason with hyphens (`media-empty`).
const MESSAGE_RE = /^[a-z][a-z0-9_-]{0,40}$/;
const PAPER_RE = /^[a-z0-9]+_[a-z0-9.-]+_[0-9.]+x[0-9.]+(mm|in)$/;
const TRAY_RE = /^[a-z][a-z0-9-]{0,39}$/;
const CTRL_RE = /[\u0000-\u001F\u007F]/g;

const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : null);
const flag = (v) => v === true || v === 1;

/** Single-line text without control characters, at most `max` characters; null when empty. */
function line(v, max) {
  if (typeof v !== 'string') return null;
  const s = v.replace(CTRL_RE, ' ').replace(/\s+/g, ' ').trim().slice(0, max);
  return s || null;
}

function count(v, max = 1000000) {
  return Number.isFinite(v) && v >= 0 && v <= max ? Math.floor(v) : null;
}

/** ISO time (or ms) → ms, null when there is none. */
function msOf(v) {
  if (Number.isFinite(v) && v > 0) return Math.floor(v);
  const t = typeof v === 'string' && v.length <= 40 ? Date.parse(v) : NaN;
  return Number.isFinite(t) && t > 0 ? t : null;
}

const isDeviceId = (v) => typeof v === 'string' && DEVICE_ID_RE.test(v);
const isJobId = (v) => typeof v === 'string' && JOB_ID_RE.test(v);
const isPaper = (v) => typeof v === 'string' && v.length <= 64 && PAPER_RE.test(v);
const isTray = (v) => typeof v === 'string' && TRAY_RE.test(v);
const code = (v) => (typeof v === 'string' && CODE_RE.test(v) ? v : null);

// ── File types ───────────────────────────────────────────

/** 'pdf' | 'image' | 'text' | 'office' of an upload type, else null. */
function kindOf(type) {
  if (type === 'application/pdf') return 'pdf';
  if (IMAGE_TYPES.includes(type)) return 'image';
  if (type === 'text/plain') return 'text';
  if (OFFICE_TYPES.includes(type)) return 'office';
  return null;
}

function extOf(name) {
  const m = /\.([A-Za-z0-9]{1,8})$/.exec(String(name || ''));
  return m ? m[1].toLowerCase() : '';
}

function baseMime(m) {
  const s = String(m || '').toLowerCase().split(';')[0].trim();
  if (s === 'image/jpg') return 'image/jpeg';
  if (s === 'text/rtf') return 'application/rtf';
  return s;
}

/**
 * The type of a file by its first bytes: 'application/pdf', a picture type,
 * 'zip' (the container of docx / xlsx / pptx / odt / ods / odp), 'rtf',
 * 'binary' (NUL bytes — not a text) or null (nothing recognised).
 */
function sniff(head) {
  if (!head || head.length < 4) return null;
  const b = Buffer.isBuffer(head) ? head : Buffer.from(head);
  const at = (text, offset = 0) => b.length >= offset + text.length && b.toString('latin1', offset, offset + text.length) === text;
  if (b.subarray(0, 1024).indexOf('%PDF-', 0, 'latin1') >= 0) return 'application/pdf';
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return 'image/jpeg';
  if (b.length >= 8 && b[0] === 0x89 && at('PNG\r\n', 1) && b[6] === 0x1a && b[7] === 0x0a) return 'image/png';
  if (at('RIFF') && at('WEBP', 8)) return 'image/webp';
  if (at('ftyp', 4) && b.length >= 12) {
    const brand = b.toString('latin1', 8, 12);
    if (['heic', 'heix', 'hevc', 'hevx'].includes(brand)) return 'image/heic';
    if (['mif1', 'msf1'].includes(brand)) return 'image/heif';
  }
  if (b[0] === 0x50 && b[1] === 0x4b && (b[2] === 0x03 || b[2] === 0x05 || b[2] === 0x07)) return 'zip';
  if (at('{\\rtf')) return 'rtf';
  if (b.subarray(0, 1024).includes(0)) return 'binary';
  return null;
}

/**
 * The type a file goes up as → one of UPLOAD_TYPES, or null when the plugin
 * does not print it. `name` and `mime` are what the file claims (its
 * extension; Drive's type), `head` its first bytes when they are at hand (a
 * file of this PC): the content must fit the claim — a PDF is a PDF, a
 * picture the picture it is, an office file a ZIP container (RTF: `{\rtf`),
 * a text has no NUL bytes.
 */
function uploadType(name, mime = null, head = null) {
  const byExt = EXTENSIONS[extOf(name)] || null;
  const m = baseMime(mime);
  const claimed = byExt || (UPLOAD_TYPES.includes(m) ? m : null);
  if (!head) return claimed;
  const seen = sniff(head);
  if (seen === 'application/pdf' || IMAGE_TYPES.includes(seen)) {
    // a PDF or picture under another name still is what its content says
    if (!claimed || claimed === 'application/pdf' || IMAGE_TYPES.includes(claimed)) return seen;
    return null;
  }
  if (!claimed) return null;
  if (claimed === 'application/pdf' || IMAGE_TYPES.includes(claimed)) return null;
  if (claimed === 'application/rtf') return seen === 'rtf' ? claimed : null;
  if (claimed === 'text/plain') return seen === null ? claimed : null;
  return seen === 'zip' ? claimed : null;
}

/**
 * The pages of a PDF by its page tree (`/Type /Pages … /Count n`), read
 * from the raw bytes → n, or null when the tree is not readable this way
 * (compressed object streams, encrypted). Only for showing "2 Seiten" and
 * the page limit before sending; the server counts for real.
 */
function pdfPages(buf) {
  if (!buf || !buf.length) return null;
  const s = (Buffer.isBuffer(buf) ? buf : Buffer.from(buf)).toString('latin1');
  let best = null;
  const re = /\/Type\s*\/Pages\b/g;
  let m;
  let seen = 0;
  while ((m = re.exec(s)) && seen++ < 2000) {
    // the dictionary around the hit: back to its "<<", forward to the next "endobj"
    const from = Math.max(0, s.lastIndexOf('obj', m.index));
    const to = s.indexOf('endobj', m.index);
    const dict = s.slice(from, to < 0 ? Math.min(s.length, m.index + 2000) : Math.min(to, m.index + 20000));
    const c = /\/Count\s+(\d{1,7})\b/.exec(dict);
    if (c) best = Math.max(best || 0, Number(c[1]));
  }
  return best && best > 0 && best <= 100000 ? best : null;
}

/** The job's name on the printer and in the history: the file's own name, else "GateControl". */
function jobName(name) {
  return line(name, 120) || 'GateControl';
}

// ── POST print ───────────────────────────────────────────

/**
 * The options of a print call → { deviceId, copies, color, duplex, media?, source? } or null when one is not valid.
 * (What the printer and the person's rights allow is the plugin's decision.)
 */
function printOptions(a) {
  const o = obj(a);
  if (!o || !isDeviceId(o.deviceId)) return null;
  const copies = o.copies === undefined || o.copies === null ? 1 : o.copies;
  if (!Number.isInteger(copies) || copies < 1 || copies > MAX_COPIES) return null;
  const out = { deviceId: o.deviceId, copies, color: o.color === true, duplex: o.duplex === true };
  if (o.media !== undefined && o.media !== null && o.media !== '') {
    if (!isPaper(o.media)) return null;
    out.media = o.media;
  }
  if (o.source !== undefined && o.source !== null && o.source !== '') {
    if (!isTray(o.source)) return null;
    out.source = o.source;
  }
  return out;
}

// ── Answers ──────────────────────────────────────────────

function list(v, max) {
  return Array.isArray(v) ? v.slice(0, max) : [];
}

/** `printer.media` (plugin 1.1.0): PWG paper names and trays, each with the printer's default. */
function normalizeMedia(v) {
  const m = obj(v) || {};
  const sizes = [...new Set(list(m.sizes, 24).filter(isPaper))].slice(0, 12);
  const sources = [...new Set(list(m.sources, 16).filter(isTray))].slice(0, 8);
  return {
    sizes,
    default: sizes.includes(m.default) ? m.default : null,
    sources,
    sourceDefault: sources.includes(m.sourceDefault) ? m.sourceDefault : null,
  };
}

/** A printer of `overview.printers` → cleaned, or null (no id, no name, not a printer). */
function normalizePrinter(v) {
  const o = obj(v);
  const p = o && obj(o.printer);
  if (!o || !p || !isDeviceId(o.id)) return null;
  const name = line(o.name, 120);
  if (!name) return null;
  const copiesMax = count(p.copiesMax, 100000);
  return {
    id: o.id,
    name,
    location: line(o.location, 120),
    online: flag(o.online),
    problem: code(o.problem),
    state: PRINTER_STATES.includes(p.state) ? p.state : 'idle',
    color: flag(p.color),
    duplex: flag(p.duplex),
    copiesMax: Math.min(MAX_COPIES, Math.max(1, copiesMax || MAX_COPIES)),
    office: p.office === true,
    media: normalizeMedia(p.media),
  };
}

/** A job (`overview.jobs[]`, `jobs/<id>`, `print`) → cleaned, or null. */
function normalizeJob(v) {
  const o = obj(v);
  if (!o || !isJobId(o.id)) return null;
  if (o.kind !== undefined && o.kind !== null && o.kind !== 'print') return null;
  const state = code(o.state);
  if (!state) return null;
  return {
    id: o.id,
    name: line(o.name, 200) || 'GateControl',
    device: line(o.device, 120),
    deviceId: isDeviceId(o.deviceId) ? o.deviceId : null,
    state,
    open: JOB_OPEN.includes(state),
    error: code(o.error),
    message: typeof o.message === 'string' && MESSAGE_RE.test(o.message) ? o.message : null,
    pages: Math.max(1, count(o.pages) || 1),
    copies: Math.max(1, count(o.copies) || 1),
    color: flag(o.color),
    duplex: flag(o.duplex),
    media: isPaper(o.media) ? o.media : null,
    source: isTray(o.source) ? o.source : null,
    at: msOf(o.at),
    updatedAt: msOf(o.updatedAt),
    // plugin 1.1.1; an older plugin names neither
    expiresAt: msOf(o.expiresAt),
    doneAt: msOf(o.doneAt),
  };
}

/**
 * `GET overview` → { rights: { print, pagesPerDay, bwOnly }, pagesLeft, printers, jobs } or null (no `rights`:
 * not an answer of the plugin). Printers only with the print right; `pagesLeft` null: no limit.
 */
function normalizeOverview(v) {
  const o = obj(v);
  const r = o && obj(o.rights);
  if (!r) return null;
  const rights = { print: flag(r.print), pagesPerDay: count(r.pagesPerDay) || 0, bwOnly: flag(r.bwOnly) };
  const seen = new Set();
  const printers = [];
  if (rights.print) {
    for (const x of list(o.printers, 64)) {
      const p = normalizePrinter(x);
      if (p && !seen.has(p.id)) { seen.add(p.id); printers.push(p); }
    }
  }
  return {
    rights,
    pagesLeft: rights.print && rights.pagesPerDay > 0 ? count(o.pagesLeft) : null,
    printers,
    jobs: list(o.jobs, 50).map(normalizeJob).filter(Boolean),
  };
}

// ── Push ─────────────────────────────────────────────────

/**
 * A print message of the plugin ("Druck fertig" / "Druck fehlgeschlagen")
 * → { type: 'print', kind: 'done' | 'failed', jobId } or null. The job is
 * in the collapse key (`print-<jobId>`), when the server passes it on.
 */
function pushContext(entry) {
  if (!entry || typeof entry !== 'object') return null;
  const topic = typeof entry.topic === 'string' ? entry.topic : '';
  if (topic !== TOPIC_DONE && topic !== TOPIC_FAILED) return null;
  const m = /(?:^|:)print-([A-Za-z0-9_-]{1,80})$/.exec(typeof entry.collapse_key === 'string' ? entry.collapse_key : '');
  return { type: 'print', kind: topic === TOPIC_DONE ? 'done' : 'failed', jobId: m ? m[1] : null };
}

module.exports = {
  PLUGIN_ID,
  APP_ROUTE,
  TOPIC_PREFIX,
  TOPIC_DONE,
  TOPIC_FAILED,
  API_BASE,
  MEDIA_PATH,
  MAX_BYTES,
  MAX_FILES,
  MAX_COPIES,
  OFFICE_TYPES,
  IMAGE_TYPES,
  UPLOAD_TYPES,
  EXTENSIONS,
  JOB_OPEN,
  isDeviceId,
  isJobId,
  isPaper,
  isTray,
  line,
  msOf,
  kindOf,
  extOf,
  sniff,
  uploadType,
  pdfPages,
  jobName,
  printOptions,
  normalizeMedia,
  normalizePrinter,
  normalizeJob,
  normalizeOverview,
  pushContext,
};

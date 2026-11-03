'use strict';

/**
 * GateControl – the host's virus scan as the plugins pass it on (Drive 1.19, GateDrop 1.4, Mail 1.8,
 * Messenger 1.11; GateControl 1.223.0). Pure, Electron-free, unit-tested.
 *
 *   scan { state, blocked, finding }   on Drive nodes and photos, GateDrop items, Mail attachments (+ removed),
 *                                      Messenger media — only when the host scans and knows a result. No `scan`:
 *                                      nothing to show (older host or plugin, an old file).
 *     state    pending | clean | infected | unscannable | unchecked
 *     blocked  decides (not `state`): true = not opened, downloaded, previewed, shared or handed on
 *     finding  the name of the find (`Eicar-Test-Signature`, …) or, when unscannable, the reason (`encrypted`,
 *              `too_large`, `archive_depth`, `error`); may be null
 *
 * Refusals of the media routes and of the plugins (`{ ok: false, code }` or Mail's `{ error: { code, scan } }`):
 *   423 scan_pending (Retry-After: 5) · 423 quarantined · 423 scan_blocked · 422 infected (upload / send)
 *   503 scan_unavailable (upload: try again later) · 410 attachment_removed · 409 attachment_blocked (Mail send)
 *
 * view(scan) → what a list shows:
 *   'checking'     pending + blocked        „Wird auf Viren geprüft …“
 *   'malware'      infected + blocked       „Gesperrt – Schadsoftware (<finding>)“
 *   'unscannable'  unscannable + blocked    „Gesperrt – konnte nicht geprüft werden“
 *   'blocked'      blocked, other state     „Gesperrt“
 *   'removed'      Mail: the host deleted the attachment   „Anhang entfernt (Schadsoftware)“
 *   'warning'      infected, not blocked (only marked)   warn, ask before opening
 *   'notCheckable' unscannable, not blocked   quiet „Nicht prüfbar“
 *   null           clean, unchecked, pending without block, no scan: nothing
 */

const STATES = Object.freeze(['pending', 'clean', 'infected', 'unscannable', 'unchecked']);
/** The 423 codes of a blocked file (media routes, Drive content / office / links, GateDrop, Mail). */
const REFUSALS = Object.freeze(['scan_pending', 'quarantined', 'scan_blocked']);
/** Every code of the scan an app turns into its own message. */
const CODES = Object.freeze([...REFUSALS, 'infected', 'scan_unavailable', 'attachment_removed', 'attachment_blocked']);
const KINDS = Object.freeze(['checking', 'malware', 'unscannable', 'blocked', 'removed', 'warning', 'notCheckable']);

const FINDING_MAX = 200;
const RETRY_DEFAULT_S = 5;
const RETRY_MAX_S = 60;

const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : null);

/** The finding: one line of printable text (≤ 200), else null. */
function findingOf(v) {
  if (typeof v !== 'string') return null;
  const s = v.replace(/[\u0000-\u001F\u007F]/g, ' ').replace(/\s+/g, ' ').trim();
  return s ? s.slice(0, FINDING_MAX) : null;
}

/**
 * A plugin's `scan` → { state, blocked, finding } (+ removed: true for Mail) or null (nothing known).
 * An unknown state counts as 'unchecked' (only `blocked` decides).
 */
function normalizeScan(v) {
  const o = obj(v);
  if (!o) return null;
  const state = STATES.includes(o.state) ? o.state : 'unchecked';
  const out = { state, blocked: o.blocked === true, finding: findingOf(o.finding) };
  if (o.removed === true) { out.removed = true; out.blocked = true; }
  return out;
}

/** Is it locked (not opened, downloaded, previewed, shared, handed on)? */
function isBlocked(scan) {
  return !!(scan && (scan.blocked === true || scan.removed === true));
}

/** What a list shows for `scan` (see the head of the file) → kind or null. */
function view(scan) {
  const s = obj(scan);
  if (!s) return null;
  if (s.removed === true) return 'removed';
  if (s.blocked === true) {
    if (s.state === 'pending') return 'checking';
    if (s.state === 'infected') return 'malware';
    if (s.state === 'unscannable') return 'unscannable';
    return 'blocked';
  }
  if (s.state === 'infected') return 'warning';
  if (s.state === 'unscannable') return 'notCheckable';
  return null;
}

/** The 423 code that belongs to a blocked `scan` (pending → scan_pending, infected → quarantined, else scan_blocked). */
function refusalOf(scan) {
  const s = obj(scan) || {};
  if (s.state === 'pending') return 'scan_pending';
  if (s.state === 'infected' || s.removed === true) return 'quarantined';
  return 'scan_blocked';
}

const isRefusal = (code) => REFUSALS.includes(code);
const isScanCode = (code) => CODES.includes(code);

/**
 * `Retry-After` → seconds (1…60; an HTTP date counts from `now`), else null. The host sends 5 with scan_pending.
 */
function retryAfterOf(v, now = Date.now()) {
  if (Array.isArray(v)) v = v[0];
  if (typeof v === 'number' && Number.isFinite(v)) return Math.min(RETRY_MAX_S, Math.max(1, Math.ceil(v)));
  if (typeof v !== 'string' || !v.trim() || v.length > 64) return null;
  const t = v.trim();
  if (/^\d{1,6}$/.test(t)) return Math.min(RETRY_MAX_S, Math.max(1, Number(t)));
  const at = Date.parse(t);
  if (!Number.isFinite(at)) return null;
  return Math.min(RETRY_MAX_S, Math.max(1, Math.ceil((at - now) / 1000)));
}

/** The `scan` of a refusal's body ({ scan } or Mail's { error: { scan } }) → normalized or null. */
function scanOfBody(body) {
  const b = obj(body);
  if (!b) return null;
  if (obj(b.scan)) return normalizeScan(b.scan);
  const inner = obj(b.error);
  return inner && obj(inner.scan) ? normalizeScan(inner.scan) : null;
}

/**
 * The extra fields of a scan refusal for the renderer (IPC `fail()`): `scan`, `finding`, `name`, `attachmentId`,
 * `retryAfter` (seconds) — only those that are there; {} for every other failure.
 */
function refusalFields(err) {
  if (!err || !isScanCode(err.code)) return {};
  const out = {};
  const body = obj(err.body);
  const inner = body && obj(body.error);
  const scan = obj(err.scan) ? normalizeScan(err.scan) : scanOfBody(body);
  if (scan) out.scan = scan;
  const finding = findingOf((body && body.finding) || (inner && inner.finding) || (scan && scan.finding));
  if (finding) out.finding = finding;
  const name = findingOf((body && body.name) || (inner && inner.name) || err.fileName);
  if (name) out.name = name;
  const aid = (body && body.attachmentId) ?? (inner && inner.attachmentId);
  if (Number.isSafeInteger(aid) && aid > 0) out.attachmentId = aid;
  else if (typeof aid === 'string' && /^[A-Za-z0-9_.:-]{1,128}$/.test(aid)) out.attachmentId = aid;
  const ra = Number.isSafeInteger(err.retryAfter) && err.retryAfter > 0 ? err.retryAfter : null;
  if (ra) out.retryAfter = ra;
  else if (err.code === 'scan_pending') out.retryAfter = RETRY_DEFAULT_S;
  return out;
}

/**
 * Runs `fn` again while it is refused with 423 scan_pending, after each `Retry-After` (default 5 s), at most
 * `tries` times and `maxWaitMs` in all; then (or for any other failure) the refusal is thrown as it is.
 * @param {() => Promise<any>} fn
 * @param {{ sleep: (ms: number) => Promise<void>, tries?: number, maxWaitMs?: number, onWait?: (err, ms) => void }} opts
 */
async function retryWhilePending(fn, { sleep, tries = 3, maxWaitMs = 30000, onWait = null } = {}) {
  let waited = 0;
  for (let i = 0; ; i++) {
    try {
      return await fn();
    } catch (err) {
      if (!err || err.code !== 'scan_pending' || i + 1 >= tries) throw err;
      const ms = (Number.isSafeInteger(err.retryAfter) && err.retryAfter > 0 ? err.retryAfter : RETRY_DEFAULT_S) * 1000;
      if (waited + ms > maxWaitMs) throw err;
      waited += ms;
      if (typeof onWait === 'function') { try { onWait(err, ms); } catch { /* ignore */ } }
      await sleep(ms);
    }
  }
}

/**
 * The text of a list kind (view()) or of a refusal code (CODES) in the core's i18n `scan.*` (DE/EN; the windows of
 * the apps have the same keys through the shared i18n) → string, or null for anything else.
 * @param {Function} t - i18n t()
 */
function text(t, kind, { finding = null, name = null } = {}) {
  const f = findingOf(finding);
  const n = findingOf(name);
  switch (kind) {
    case 'checking': return t('scan.checking');
    case 'malware': return f ? t('scan.malwareOf', { finding: f }) : t('scan.malware');
    case 'unscannable': return t('scan.unscannable');
    case 'blocked': return t('scan.blocked');
    case 'removed': return t('scan.removed');
    case 'warning': return f ? t('scan.warningOf', { finding: f }) : t('scan.warning');
    case 'notCheckable': return t('scan.notCheckable');
    case 'scan_pending': return t('scan.checkingOpen');
    case 'quarantined': return f ? t('scan.quarantinedOf', { finding: f }) : t('scan.quarantined');
    case 'scan_blocked': return n ? t('scan.scanBlockedOf', { name: n }) : t('scan.scanBlocked');
    case 'infected': return n ? t('scan.rejectedOf', { name: n }) : t('scan.rejected');
    case 'scan_unavailable': return t('scan.unavailable');
    case 'attachment_removed': return t('scan.attachmentRemoved');
    case 'attachment_blocked': return n ? t('scan.attachmentBlockedOf', { name: n }) : t('scan.attachmentBlocked');
    default: return null;
  }
}

module.exports = {
  STATES,
  REFUSALS,
  CODES,
  KINDS,
  RETRY_DEFAULT_S,
  findingOf,
  normalizeScan,
  isBlocked,
  view,
  refusalOf,
  isRefusal,
  isScanCode,
  retryAfterOf,
  scanOfBody,
  refusalFields,
  retryWhilePending,
  text,
};

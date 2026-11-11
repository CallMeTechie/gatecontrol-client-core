'use strict';

/**
 * IPC of "Drucken" (opt-in: registerBaseHandlers(…, { print })).
 * Arguments from the renderer are checked here and again in PrintService.
 * Every handler resolves; failures come back as { ok: false, code, error, status, left, pages }.
 *
 * The renderer never names a file by its path: it gets tokens for files the
 * person picked (print:pick), dropped (print:dropped — paths the preload
 * read from the dropped File objects) or chose in Drive (print:drive), and
 * prints tokens (print:submit).
 *
 *   print:status            () → PrintService.status()
 *   print:check             () → status after asking the server again
 *   print:overview          ({ refresh? }) → { ok, rights, pagesLeft, printers, jobs, fetchedAt, stale }
 *                           (codes: unavailable — the plugin is gone for the apps —, forbidden, network, …)
 *   print:job               ({ id }) → { ok, job | null }
 *   print:cancel            ({ id }) → { ok, canceled }
 *   print:pick              () → { ok, files, rejected } | { ok: false, code: 'cancelled' }
 *   print:dropped           ({ paths }) → { ok, files, rejected }
 *   print:drive             ({ ids, vault? }) → { ok, files, rejected }   (vault: the person's yes for vault files)
 *   print:forget            ({ tokens }) → { ok }
 *   print:submit            ({ tokens, deviceId, copies, color, duplex, media?, source? }) → { ok, transfers }
 *                           (codes: invalid, not_picked)
 *   print:transfers         () → { ok, transfers }
 *   print:transfer:cancel   ({ id }) → { ok }
 *   print:again             ({ jobId } | { transferId }, vault?) → { ok, files, rejected, options } | code 'source_gone'
 *                           | code 'vault_confirm' (a vault file: asked again every time; vault: the person's yes)
 *   print:sources           () → { ok, ids }   (jobs whose file is still known for "Erneut drucken")
 *
 * Events to the main window: print:state (status()), print:push ({ type,
 * kind, jobId, notificationId }), print:transfers (the jobs in the making),
 * print:job ({ job, pagesLeft, transferId }).
 */

const P = require('../utils/print');

const PRINT_EVENTS = {
  state: 'print:state',
  push: 'print:push',
  transfers: 'print:transfers',
  job: 'print:job',
};

const TOKEN_RE = /^[A-Za-z0-9_-]{16,40}$/;
const TRANSFER_ID_RE = /^t[0-9]{1,9}$/;

function fail(err) {
  const b = err && err.body && typeof err.body === 'object' ? err.body : {};
  const n = (v) => (Number.isFinite(v) && v >= 0 ? Math.floor(v) : null);
  return { ok: false, code: (err && err.code) || 'failed', error: (err && err.message) || 'failed', status: (err && err.status) || null, left: n(b.left), pages: n(b.pages) };
}

const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});

/**
 * @param {Function} handle - registerBaseHandlers' handle(channel, fn)
 * @param {object} deps
 * @param {object} deps.print - PrintService
 * @param {Function} deps.getMainWindow
 * @param {object} deps.log
 */
function registerPrintHandlers(handle, { print: s, getMainWindow, log }) {
  const wrap = (fn) => async (_e, arg) => {
    try {
      return await fn(obj(arg));
    } catch (err) {
      return fail(err);
    }
  };
  const invalid = () => ({ ok: false, code: 'invalid', error: 'invalid argument', status: null, left: null, pages: null });
  const tokens = (v) => Array.isArray(v) && v.length > 0 && v.length <= P.MAX_FILES && v.every((x) => typeof x === 'string' && TOKEN_RE.test(x));

  handle('print:status', () => s.status());
  handle('print:check', wrap(async () => s.check()));
  handle('print:overview', wrap(async (a) => s.overview({ refresh: a.refresh === true })));
  handle('print:job', wrap(async (a) => (P.isJobId(a.id) ? s.job(a.id) : invalid())));
  handle('print:cancel', wrap(async (a) => (P.isJobId(a.id) ? s.cancel(a.id) : invalid())));

  handle('print:pick', wrap(async () => s.pick()));
  handle('print:dropped', wrap(async (a) => {
    if (!Array.isArray(a.paths) || !a.paths.length || a.paths.length > 200 || !a.paths.every((p) => typeof p === 'string' && p.length > 0 && p.length <= 4096)) return invalid();
    return s.addPaths(a.paths);
  }));
  handle('print:drive', wrap(async (a) => {
    if (!Array.isArray(a.ids) || !a.ids.length || a.ids.length > 200 || !a.ids.every((x) => Number.isSafeInteger(x) && x > 0)) return invalid();
    return s.addDrive(a.ids, { vault: a.vault === true });
  }));
  handle('print:forget', wrap(async (a) => (Array.isArray(a.tokens) && a.tokens.length <= 200 && a.tokens.every((x) => typeof x === 'string' && TOKEN_RE.test(x)) ? s.forget(a.tokens) : invalid())));

  handle('print:submit', wrap(async (a) => {
    const opts = P.printOptions(a);
    if (!opts || !tokens(a.tokens)) return invalid();
    return s.submit({ ...opts, tokens: a.tokens });
  }));
  handle('print:transfers', wrap(async () => ({ ok: true, transfers: s.transfers() })));
  handle('print:transfer:cancel', wrap(async (a) => (typeof a.id === 'string' && TRANSFER_ID_RE.test(a.id) ? s.cancelTransfer(a.id) : invalid())));
  handle('print:again', wrap(async (a) => {
    if (P.isJobId(a.jobId)) return s.again({ jobId: a.jobId, vault: a.vault === true });
    if (typeof a.transferId === 'string' && TRANSFER_ID_RE.test(a.transferId)) return s.again({ transferId: a.transferId, vault: a.vault === true });
    return invalid();
  }));
  handle('print:sources', wrap(async () => s.sources()));

  const send = (channel, payload) => {
    const win = getMainWindow && getMainWindow();
    if (!win || (typeof win.isDestroyed === 'function' && win.isDestroyed()) || !win.webContents) return;
    try { win.webContents.send(channel, payload); } catch (err) { log.debug(`${channel} not delivered: ${err.message}`); }
  };
  for (const [event, channel] of Object.entries(PRINT_EVENTS)) s.on(event, (payload) => send(channel, payload));
}

module.exports = { registerPrintHandlers, PRINT_EVENTS };

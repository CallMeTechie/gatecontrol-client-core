/**
 * GateControl – Window guard (Core)
 *
 * Electron security checklist for every window of the app: a page may only
 * navigate within the app's own files, never open a new Electron window and
 * never attach a <webview>.
 *
 *   - will-navigate: the app's own file:// pages stay; http(s) links open in
 *     the system browser (same filter as shell:open-external); everything
 *     else (javascript:, data:, file:// outside the app, custom protocols,
 *     ms-settings:, …) is blocked.
 *   - will-redirect: only the app's own pages, nothing is opened.
 *   - setWindowOpenHandler: always deny; http(s) links open in the browser.
 *   - will-attach-webview: always blocked (the apps use no webviews).
 *
 * installWindowGuard() hooks app.on('web-contents-created'), so every window
 * (main window, Vault quick search, future ones) is covered without each one
 * having to remember it. The renderer opens links through shell:open-external
 * (IPC), which this guard does not touch.
 *
 * navigationDecision() is pure (unit-tested); Electron objects are passed in.
 */

'use strict';

const { pathToFileURL } = require('url');
const { isSafeExternalUrl } = require('./external-url');

const ALLOW = 'allow';
const EXTERNAL = 'external';
const DENY = 'deny';

function parse(raw) {
  if (typeof raw !== 'string' || !raw || raw.length > 8192) return null;
  try {
    return new URL(raw);
  } catch {
    return null;
  }
}

/** Directory (absolute path or file:// URL) → normalised file URL prefix ending in "/". */
function rootPrefix(root) {
  let url;
  if (root instanceof URL) url = root;
  else if (typeof root === 'string' && /^file:/i.test(root)) url = parse(root);
  else if (typeof root === 'string' && root) url = pathToFileURL(root);
  if (!url || url.protocol !== 'file:') return null;
  let p = safeDecode(url.pathname);
  if (p === null) return null;
  if (!p.endsWith('/')) p += '/';
  return { host: url.host.toLowerCase(), path: p.toLowerCase() };
}

function safeDecode(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return null;
  }
}

/**
 * true if `raw` is a file:// URL inside one of the app's directories.
 * Case-insensitive (Windows paths); "..", "%2e%2e" and the like are
 * resolved before the comparison.
 *
 * @param {string} raw
 * @param {Array<string|URL>} appRoots - directories of the app's pages
 */
function isAppUrl(raw, appRoots) {
  const url = parse(raw);
  if (!url || url.protocol !== 'file:') return false;
  const p = safeDecode(url.pathname);
  if (p === null || p.includes('\\') || /(^|\/)\.\.?(\/|$)/.test(p)) return false;
  const host = url.host.toLowerCase();
  const path = p.toLowerCase();
  return (Array.isArray(appRoots) ? appRoots : [appRoots])
    .map(rootPrefix)
    .some((r) => r && r.host === host && path.startsWith(r.path) && path.length > r.path.length);
}

/**
 * What to do with a navigation or a window.open() of a page.
 *
 * @param {string} raw - target URL
 * @param {object} o
 * @param {Array<string|URL>} o.appRoots
 * @param {'navigate'|'redirect'|'open'} [o.kind]
 * @returns {'allow'|'external'|'deny'}
 *   allow    – let it happen (own page; never for 'open')
 *   external – prevent it and open the URL in the system browser
 *   deny     – prevent it
 */
function navigationDecision(raw, o = {}) {
  const kind = o.kind || 'navigate';
  if (kind !== 'open' && isAppUrl(raw, o.appRoots)) return ALLOW;
  if (kind !== 'redirect' && isSafeExternalUrl(raw)) return EXTERNAL;
  return DENY;
}

/** Scheme and host only: URLs can carry tickets or tokens that must not reach the log. */
function describeUrl(raw) {
  const url = parse(raw);
  if (!url) return '(invalid URL)';
  if (url.protocol === 'http:' || url.protocol === 'https:') return `${url.protocol}//${url.host}`;
  return url.protocol;
}

/**
 * Apply the guard to one webContents.
 *
 * @param {Electron.WebContents} contents
 * @param {object} o
 * @param {Array<string|URL>} o.appRoots
 * @param {() => { openExternal: (url: string) => Promise<void> }} o.getShell
 * @param {object} [o.log]
 * @param {(e: { kind: string, decision: string, url: string }) => void} [o.onDecision] - tests
 */
function guardWebContents(contents, o) {
  if (!contents || contents.__gcWindowGuard) return;
  const log = o.log || null;
  const openExternal = (url) => {
    try {
      const shell = o.getShell();
      Promise.resolve(shell.openExternal(url.trim())).catch((err) => log?.warn(`Window guard: opening ${describeUrl(url)} failed: ${err && err.message}`));
    } catch (err) {
      log?.warn(`Window guard: opening ${describeUrl(url)} failed: ${err && err.message}`);
    }
  };
  const handle = (kind, e, url) => {
    const decision = navigationDecision(url, { appRoots: o.appRoots, kind });
    try { o.onDecision?.({ kind, decision, url }); } catch { /* test hook */ }
    if (decision === ALLOW) return;
    if (e && typeof e.preventDefault === 'function') e.preventDefault();
    if (decision === EXTERNAL) {
      log?.info(`Window guard: ${kind} to ${describeUrl(url)} opened in the browser`);
      openExternal(url);
    } else {
      log?.warn(`Window guard: ${kind} to ${describeUrl(url)} blocked`);
    }
  };

  try { Object.defineProperty(contents, '__gcWindowGuard', { value: true }); } catch { /* frozen test double */ }

  // Electron ≥ 25 passes a details object as the event; older ones (event, url).
  contents.on('will-navigate', (e, url) => handle('navigate', e, typeof url === 'string' ? url : e && e.url));
  contents.on('will-redirect', (e, url) => handle('redirect', e, typeof url === 'string' ? url : e && e.url));
  if (typeof contents.setWindowOpenHandler === 'function') {
    contents.setWindowOpenHandler((details) => {
      handle('open', null, details && details.url);
      return { action: 'deny' };
    });
  }
  contents.on('will-attach-webview', (e, webPreferences, params) => {
    if (e && typeof e.preventDefault === 'function') e.preventDefault();
    log?.warn(`Window guard: <webview> blocked (${describeUrl(params && params.src)})`);
  });
}

/**
 * Guard every webContents the app creates (call once, before the first window).
 *
 * @param {Electron.App} app
 * @param {object} o - see guardWebContents
 */
function installWindowGuard(app, o) {
  if (!o || !o.appRoots || typeof o.getShell !== 'function') throw new Error('window guard: appRoots and getShell required');
  app.on('web-contents-created', (_event, contents) => guardWebContents(contents, o));
}

module.exports = {
  ALLOW,
  EXTERNAL,
  DENY,
  isAppUrl,
  navigationDecision,
  describeUrl,
  guardWebContents,
  installWindowGuard,
};

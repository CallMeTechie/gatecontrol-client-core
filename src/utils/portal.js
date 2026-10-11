'use strict';

/**
 * Opening the GateControl portal (shared by Pro and Community).
 *
 * Every open asks the server for a fresh one-time login link
 * (ApiClient.getPortalLink) right before opening it, so the user lands in the
 * portal already signed in. Without a valid link the plain portal URL is
 * opened, exactly as before. Links are never cached, logged or stored.
 *
 * Electron-free: the shell is injected, so it is unit-testable.
 */

const { isSafeExternalUrl } = require('./external-url');

// Only https portals are opened (unchanged from the former openPortalSafe).
function isOpenablePortalUrl(url) {
  return isSafeExternalUrl(url) && /^https:\/\//i.test(url.trim());
}

// ─── Target inside the portal (`next`) ──────────────────────────────────
// Same rule as the server (gatecontrol src/services/portalTickets.js
// portalNext): '/portal', '/portal#<tab>' or '/#<tab>' with a known tab or a
// plugin tab plg-<id>, at most 100 characters. Anything else → null.
const NEXT_MAX = 100;
const PORTAL_TABS = Object.freeze(['start', 'dienste', 'zuhause', 'fahrzeug', 'netzwerk', 'geraete', 'mitteilungen', 'benachrichtigungen']);
const PLUGIN_TAB_RE = /^plg-[a-z0-9]+(?:-[a-z0-9]+)*$/;
const NEXT_RE = /^\/(?:portal\/?)?(?:#([a-z0-9-]{1,60}))?$/;

/** Validated portal target → '/portal' | '/portal#<tab>' | null. */
function portalNext(raw) {
  if (typeof raw !== 'string' || !raw || raw.length > NEXT_MAX) return null;
  const m = NEXT_RE.exec(raw);
  if (!m) return null;
  const tab = m[1];
  if (!tab) return raw === '/' ? null : '/portal';
  if (!PORTAL_TABS.includes(tab) && !PLUGIN_TAB_RE.test(tab)) return null;
  return `/portal#${tab}`;
}

/**
 * The login link with the target: servers with `next` support put it into
 * the link already; otherwise it is appended (the contract allows it, the
 * server checks it again when the link is opened, older servers ignore it).
 */
function withNext(link, next) {
  if (!next) return link;
  try {
    const url = new URL(link);
    if (!url.searchParams.has('next')) url.searchParams.set('next', next);
    return url.href;
  } catch {
    return link;
  }
}

/**
 * URL to open for the portal: the one-time login link when the server
 * hands out a valid one, otherwise the configured portal URL.
 *
 * @param {{ apiClient: { getPortalLink?: Function }, portalUrl: ?string, next?: ?string }} opts
 *   next: validated portal target (portalNext), sent to the server and kept in the link
 * @returns {Promise<?string>}
 */
async function resolvePortalUrl({ apiClient, portalUrl, next = null }) {
  if (!portalUrl) return null;
  const link = await fetchLink(apiClient, portalUrl, next);
  return link ? withNext(link, next) : portalUrl;
}

async function fetchLink(apiClient, portalUrl, next) {
  if (!apiClient || typeof apiClient.getPortalLink !== 'function') return null;
  try {
    return (next ? await apiClient.getPortalLink(portalUrl, { next }) : await apiClient.getPortalLink(portalUrl)) || null;
  } catch {
    return null;
  }
}

// Same rule as the server's notify sanitize.portalPath: '/…', never '//host'.
const PORTAL_PATH_RE = /^\/(?!\/)[A-Za-z0-9._~!$&'()*+,;=:@%/?#-]{0,300}$/;

/** https URL of a portal page (same origin as the portal URL) or null. */
function portalPageUrl(portalUrl, path) {
  if (typeof path !== 'string' || !PORTAL_PATH_RE.test(path) || path.includes('\\')) return null;
  try {
    const base = new URL(portalUrl);
    const url = new URL(path, base.origin);
    return url.origin === base.origin && isOpenablePortalUrl(url.href) ? url.href : null;
  } catch {
    return null;
  }
}

/**
 * Build the portal opener used for the auto-open after connect, the tray
 * entry, the "Portal öffnen" button and push actions (open_portal).
 *
 * @param {object} opts
 * @param {object} opts.apiClient - ApiClient (getPortalLink)
 * @param {() => ?string} opts.getPortalUrl - current portal URL (null when none)
 * @param {() => object} [opts.getShell] - returns Electron's shell (openExternal)
 * @param {object} [opts.log]
 * @returns {{ open: (opts?: { path?: string, next?: string }) => Promise<boolean> }} open() resolves true when a URL was opened
 */
function createPortalOpener({ apiClient, getPortalUrl, getShell, log }) {
  const shellOf = typeof getShell === 'function' ? getShell : () => require('electron').shell;

  /**
   * @param {object} [opts]
   * @param {string} [opts.next] - portal tab to land on ('/portal#benachrichtigungen').
   * @param {string} [opts.path] - same as next (push action open_portal: its
   *   `target`). A portal tab (portalNext) goes through the one-time login
   *   link as `next`, so the user lands there signed in. Any other portal
   *   path, and every target when the server hands out no link, is opened
   *   directly on the portal origin (the browser's portal session applies).
   */
  async function open({ path, next } = {}) {
    const portalUrl = getPortalUrl();
    if (!isOpenablePortalUrl(portalUrl)) return false;
    const target = next != null ? next : path;
    let url;
    if (target == null) {
      url = await resolvePortalUrl({ apiClient, portalUrl });
      if (!isOpenablePortalUrl(url)) url = portalUrl;
    } else {
      const page = portalPageUrl(portalUrl, target);
      if (!page) return false;
      const tab = portalNext(target);
      const link = tab ? await fetchLink(apiClient, portalUrl, tab) : null;
      url = link ? withNext(link, tab) : (tab ? portalPageUrl(portalUrl, tab) : page);
      if (!isOpenablePortalUrl(url)) url = page;
    }
    try {
      await shellOf().openExternal(url.trim());
      return true;
    } catch (err) {
      if (log) log.warn('Opening the portal failed:', err && err.message);
      return false;
    }
  }

  return { open };
}

module.exports = { createPortalOpener, resolvePortalUrl, isOpenablePortalUrl, portalPageUrl, portalNext, PORTAL_TABS };

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

/**
 * URL to open for the portal: the one-time login link when the server
 * hands out a valid one, otherwise the configured portal URL.
 *
 * @param {{ apiClient: { getPortalLink?: Function }, portalUrl: ?string }} opts
 * @returns {Promise<?string>}
 */
async function resolvePortalUrl({ apiClient, portalUrl }) {
  if (!portalUrl) return null;
  let link = null;
  if (apiClient && typeof apiClient.getPortalLink === 'function') {
    try {
      link = await apiClient.getPortalLink(portalUrl);
    } catch {
      link = null;
    }
  }
  return link || portalUrl;
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
 * entry and the "Portal öffnen" button.
 *
 * @param {object} opts
 * @param {object} opts.apiClient - ApiClient (getPortalLink)
 * @param {() => ?string} opts.getPortalUrl - current portal URL (null when none)
 * @param {() => object} [opts.getShell] - returns Electron's shell (openExternal)
 * @param {object} [opts.log]
 * @returns {{ open: (opts?: { path?: string }) => Promise<boolean> }} open() resolves true when a URL was opened
 */
function createPortalOpener({ apiClient, getPortalUrl, getShell, log }) {
  const shellOf = typeof getShell === 'function' ? getShell : () => require('electron').shell;

  /**
   * @param {object} [opts]
   * @param {string} [opts.path] - a page of the portal ('/…', push action
   *   open_portal). The one-time login link has no target page (the server
   *   always lands on the portal home), so a path is opened directly on the
   *   portal origin — the browser's portal session applies, otherwise the
   *   portal asks for the login.
   */
  async function open({ path } = {}) {
    const portalUrl = getPortalUrl();
    if (!isOpenablePortalUrl(portalUrl)) return false;
    let target;
    const page = typeof path === 'string' ? portalPageUrl(portalUrl, path) : null;
    if (path != null && !page) return false;
    if (page) {
      target = page;
    } else {
      target = await resolvePortalUrl({ apiClient, portalUrl });
      if (!isOpenablePortalUrl(target)) target = portalUrl;
    }
    try {
      await shellOf().openExternal(target.trim());
      return true;
    } catch (err) {
      if (log) log.warn('Opening the portal failed:', err && err.message);
      return false;
    }
  }

  return { open };
}

module.exports = { createPortalOpener, resolvePortalUrl, isOpenablePortalUrl, portalPageUrl };

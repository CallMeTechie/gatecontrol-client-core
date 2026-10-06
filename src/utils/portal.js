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

/**
 * Build the portal opener used for the auto-open after connect, the tray
 * entry and the "Portal öffnen" button.
 *
 * @param {object} opts
 * @param {object} opts.apiClient - ApiClient (getPortalLink)
 * @param {() => ?string} opts.getPortalUrl - current portal URL (null when none)
 * @param {() => object} [opts.getShell] - returns Electron's shell (openExternal)
 * @param {object} [opts.log]
 * @returns {{ open: () => Promise<boolean> }} open() resolves true when a URL was opened
 */
function createPortalOpener({ apiClient, getPortalUrl, getShell, log }) {
  const shellOf = typeof getShell === 'function' ? getShell : () => require('electron').shell;

  async function open() {
    const portalUrl = getPortalUrl();
    if (!isOpenablePortalUrl(portalUrl)) return false;
    let target = await resolvePortalUrl({ apiClient, portalUrl });
    if (!isOpenablePortalUrl(target)) target = portalUrl;
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

module.exports = { createPortalOpener, resolvePortalUrl, isOpenablePortalUrl };

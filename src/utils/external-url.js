/**
 * GateControl – External URL filter (Core)
 *
 * Only http(s) links may be handed to shell.openExternal: file://, smb://,
 * ms-*:, javascript: and custom protocol handlers could start programs or
 * reach local files. Service URLs come from the server, so the renderer
 * must not be trusted with the scheme.
 *
 * shell:open-external additionally opens a short list of Windows settings
 * pages, matched exactly (isAllowedSettingsUri): the location privacy page
 * that Vault's Wi-Fi scan points to when Windows denies scan results, and
 * the sign-in options (set up Windows Hello for Vault's Hello unlock).
 *
 * openExternalSafely() is the one way main hands a URL to the browser
 * (shell:open-external, the company sign-in): the filter above, then
 * shell.openExternal. The shell is passed in, so it stays unit-testable.
 */

'use strict';

/** true for a well-formed http:// or https:// URL with a host. */
function isSafeExternalUrl(raw) {
  if (typeof raw !== 'string' || !raw.trim() || raw.length > 4096) return false;
  let url;
  try {
    url = new URL(raw.trim());
  } catch {
    return false;
  }
  return (url.protocol === 'https:' || url.protocol === 'http:') && !!url.hostname;
}

/** Windows settings pages the renderer may open, exact URIs only (no other ms-settings: page, no arguments). */
const SETTINGS_URIS = Object.freeze(['ms-settings:privacy-location', 'ms-settings:signinoptions']);

/** true for exactly one of SETTINGS_URIS. */
function isAllowedSettingsUri(raw) {
  return typeof raw === 'string' && SETTINGS_URIS.includes(raw.trim());
}

/**
 * Opens an http(s) URL (with allowSettings also one of SETTINGS_URIS) in the
 * system's default handler. Anything else is refused. Never throws.
 *
 * @param {{ openExternal: (url: string) => Promise<void> }} shell - Electron shell
 * @param {unknown} raw
 * @param {{ log?: object, allowSettings?: boolean, label?: string }} [opts]
 * @returns {Promise<boolean>} true when handed to the shell
 */
async function openExternalSafely(shell, raw, { log = null, allowSettings = false, label = 'openExternal' } = {}) {
  if (!isSafeExternalUrl(raw) && !(allowSettings && isAllowedSettingsUri(raw))) {
    if (log) log.warn(`${label} rejected a non-http(s) URL`);
    return false;
  }
  try {
    await shell.openExternal(raw.trim());
    return true;
  } catch (err) {
    if (log) log.warn(`${label} failed:`, err && err.message);
    return false;
  }
}

module.exports = { isSafeExternalUrl, isAllowedSettingsUri, openExternalSafely, SETTINGS_URIS };

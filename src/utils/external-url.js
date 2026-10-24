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
 * Pure — no Electron — so it is unit-testable.
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

module.exports = { isSafeExternalUrl, isAllowedSettingsUri, SETTINGS_URIS };

/**
 * GateControl – External URL filter (Core)
 *
 * Only http(s) links may be handed to shell.openExternal: file://, smb://,
 * ms-*:, javascript: and custom protocol handlers could start programs or
 * reach local files. Service URLs come from the server, so the renderer
 * must not be trusted with the scheme.
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

module.exports = { isSafeExternalUrl };

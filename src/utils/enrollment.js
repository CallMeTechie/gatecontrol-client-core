/**
 * GateControl – Setup codes (Core)
 *
 * The server issues one-shot setup codes instead of showing the raw API
 * token: "XXXX-XXXX-XXXX-XXXX", or as QR code
 *   gatecontrol://enroll?url=https://gate.example.com&code=XXXX-XXXX-XXXX-XXXX
 * The client redeems the code at POST /api/v1/client/enroll and receives the
 * token (plus the WireGuard config when the code is bound to a peer).
 *
 * Pure parsing only — no Electron, no network — so it is unit-testable.
 */

'use strict';

const HEX16 = /^[A-F0-9]{16}$/;

/**
 * Canonical XXXX-XXXX-XXXX-XXXX form of a typed code (any case, spaces,
 * dashes or none), or null. API tokens (gc_…) are never taken for a code.
 */
function normalizeCode(raw) {
  if (typeof raw !== 'string') return null;
  const trimmed = raw.trim();
  if (!trimmed || /^gc_/i.test(trimmed)) return null;
  const hex = trimmed.toUpperCase().replace(/[\s-]/g, '');
  if (!HEX16.test(hex)) return null;
  return `${hex.slice(0, 4)}-${hex.slice(4, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}`;
}

/** Only https servers; returns "https://host[:port]" without path, or null. */
function normalizeServerUrl(raw) {
  if (typeof raw !== 'string' || !raw.trim()) return null;
  let url;
  try {
    url = new URL(raw.trim());
  } catch {
    return null;
  }
  if (url.protocol !== 'https:' || !url.hostname) return null;
  return url.origin;
}

/** Parses a scanned setup link; null if it is anything else (e.g. a WG config). */
function parseEnrollmentLink(raw) {
  if (typeof raw !== 'string') return null;
  let url;
  try {
    url = new URL(raw.trim());
  } catch {
    return null;
  }
  if (url.protocol !== 'gatecontrol:' || url.hostname.toLowerCase() !== 'enroll') return null;
  const serverUrl = normalizeServerUrl(url.searchParams.get('url') || '');
  const code = normalizeCode(url.searchParams.get('code') || '');
  if (!serverUrl || !code) return null;
  return { serverUrl, code };
}

module.exports = { normalizeCode, normalizeServerUrl, parseEnrollmentLink };

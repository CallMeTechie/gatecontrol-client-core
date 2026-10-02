/**
 * GateControl – Client-Richtlinien (Core, pure helpers)
 *
 * The server delivers an effective policy per peer
 * (GET /api/v1/client/policy, see the server's docs/feature-client-policies.md):
 *
 *   killSwitch         'user' | 'required'
 *   autoConnect        'user' | 'required' | 'always_on'
 *   autostart          'user' | 'required' | 'forbidden'
 *   splitTunnelModes   subset of ['off', 'exclude', 'include']
 *   splitTunnelLocked  boolean (a locked split-tunnel preset applies)
 *   lockSettings       boolean
 *   lockServer         boolean
 *
 * Semantics on the client:
 *   - never fetched → UNRESTRICTED (no restriction at all)
 *   - fetched once  → persisted, applies offline and while the server is
 *                     unreachable (last known policy)
 *   - unknown / broken field values fall back to the unrestricted value of
 *     that field (a damaged answer must not lock the user out)
 *
 * This is a management convenience, not a security boundary: a user with
 * local admin rights can stop the client or edit its store.
 *
 * Windows split tunneling knows two modes: 'off' (all traffic) and
 * 'include' (only the listed targets go through the tunnel).
 */

'use strict';

const SPLIT_MODES = Object.freeze(['off', 'exclude', 'include']);
const WINDOWS_SPLIT_MODES = Object.freeze(['off', 'include']);

const ENUMS = Object.freeze({
  killSwitch: Object.freeze(['user', 'required']),
  autoConnect: Object.freeze(['user', 'required', 'always_on']),
  autostart: Object.freeze(['user', 'required', 'forbidden']),
});

const UNRESTRICTED = Object.freeze({
  killSwitch: 'user',
  autoConnect: 'user',
  autostart: 'user',
  splitTunnelModes: Object.freeze([...SPLIT_MODES]),
  splitTunnelLocked: false,
  lockSettings: false,
  lockServer: false,
});

// Config keys (electron-store) that stay writable under lockSettings:
// display preferences only.
const ALWAYS_WRITABLE_KEYS = Object.freeze(['app.theme', 'app.locale']);

/** Policy object with every field valid (unknown/invalid → unrestricted). */
function normalizePolicy(raw) {
  const src = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
  const out = {};
  for (const [field, values] of Object.entries(ENUMS)) {
    out[field] = values.includes(src[field]) ? src[field] : UNRESTRICTED[field];
  }
  const modes = Array.isArray(src.splitTunnelModes)
    ? SPLIT_MODES.filter((m) => src.splitTunnelModes.includes(m))
    : [];
  out.splitTunnelModes = modes.length ? modes : [...SPLIT_MODES];
  out.splitTunnelLocked = src.splitTunnelLocked === true;
  out.lockSettings = src.lockSettings === true;
  out.lockServer = src.lockServer === true;
  return out;
}

function unrestricted() {
  return normalizePolicy(UNRESTRICTED);
}

/** true when anything is restricted compared to UNRESTRICTED. */
function isManaged(policy) {
  const p = normalizePolicy(policy);
  return JSON.stringify(p) !== JSON.stringify(unrestricted());
}

/**
 * Split modes the Windows client may offer: the policy's modes that Windows
 * implements. When none is left (e.g. only 'exclude' allowed), full tunnel
 * ('off') is the safe fallback.
 */
function windowsSplitModes(policy) {
  const p = normalizePolicy(policy);
  const modes = WINDOWS_SPLIT_MODES.filter((m) => p.splitTunnelModes.includes(m));
  return modes.length ? modes : ['off'];
}

/** The user may disconnect the tunnel manually. */
function canDisconnect(policy) {
  return normalizePolicy(policy).autoConnect !== 'always_on';
}

/**
 * Forced values for the Windows store keys (key → value). Keys that are not
 * forced are absent.
 *   splitTunnelEnabled — current store value of tunnel.splitTunnel
 */
function forcedValues(policy, { splitTunnelEnabled = false } = {}) {
  const p = normalizePolicy(policy);
  const forced = {};
  if (p.killSwitch === 'required') forced['tunnel.killSwitch'] = true;
  if (p.autoConnect !== 'user') forced['tunnel.autoConnect'] = true;
  if (p.autostart === 'required') forced['app.startWithWindows'] = true;
  if (p.autostart === 'forbidden') forced['app.startWithWindows'] = false;
  const modes = windowsSplitModes(p);
  const current = splitTunnelEnabled ? 'include' : 'off';
  if (!modes.includes(current)) forced['tunnel.splitTunnel'] = modes[0] === 'include';
  return forced;
}

/**
 * Lock state per Windows setting — what the UI disables with the hint
 * "Vom Administrator festgelegt". lockSettings locks everything except the
 * display preferences.
 */
function locks(policy) {
  const p = normalizePolicy(policy);
  const all = p.lockSettings;
  const modes = windowsSplitModes(p);
  return {
    killSwitch: all || p.killSwitch === 'required',
    autoConnect: all || p.autoConnect !== 'user',
    autostart: all || p.autostart !== 'user',
    splitMode: all || p.splitTunnelLocked || modes.length < 2,
    splitRoutes: all || p.splitTunnelLocked,
    // everything else in the settings (intervals, minimized start, RDP allow …)
    settings: all,
    server: p.lockServer,
    disconnect: !canDisconnect(p),
  };
}

/**
 * May the renderer write `key` = `value` (config:set)? Forced values may be
 * written as long as they equal the forced value (idempotent UI saves).
 */
function canWriteConfig(policy, key, value, { splitTunnelEnabled = false } = {}) {
  const p = normalizePolicy(policy);
  if (ALWAYS_WRITABLE_KEYS.includes(key)) return true;
  const l = locks(p);
  const forced = forcedValues(p, { splitTunnelEnabled });
  if (Object.prototype.hasOwnProperty.call(forced, key) && forced[key] !== value) return false;
  if (key === 'tunnel.killSwitch' && l.killSwitch) return value === true && p.killSwitch === 'required';
  if (key === 'tunnel.autoConnect' && l.autoConnect) return p.autoConnect !== 'user' && value === true;
  if (key === 'app.startWithWindows' && l.autostart) {
    return (p.autostart === 'required' && value === true) || (p.autostart === 'forbidden' && value === false);
  }
  if (key === 'tunnel.splitTunnel') {
    if (p.lockSettings || p.splitTunnelLocked) return false;
    return windowsSplitModes(p).includes(value ? 'include' : 'off');
  }
  if (key === 'tunnel.splitRoutes') return !l.splitRoutes;
  return !l.settings;
}

/** Everything the renderer needs to show the policy. */
function uiState(policy, { fetched = false, version = null, fetchedAt = null } = {}) {
  const p = normalizePolicy(policy);
  return {
    fetched,
    version,
    fetchedAt,
    managed: isManaged(p),
    policy: p,
    locks: locks(p),
    splitModes: windowsSplitModes(p),
  };
}

module.exports = {
  SPLIT_MODES,
  WINDOWS_SPLIT_MODES,
  ENUMS,
  UNRESTRICTED,
  ALWAYS_WRITABLE_KEYS,
  normalizePolicy,
  unrestricted,
  isManaged,
  windowsSplitModes,
  canDisconnect,
  forcedValues,
  locks,
  canWriteConfig,
  uiState,
};

'use strict';

/**
 * Store schema fragment of the notification center (push client and
 * notification-center service). Both apps merge it into their electron-store
 * schema — the core createStores() does it already, Pro has its own schema:
 *
 *   const { notificationsSchema } = require('@gatecontrol/client-core');
 *   new Store({ schema: { ...ownSchema, ...notificationsSchema } });
 *
 * Electron-free (no electron-store import), so it is unit-testable.
 *
 * Keys under `notifications`:
 *   enabled         receive push notifications at all
 *   direct          also without VPN (server mode 'always'); false = 'vpn_only'
 *   toasts          show Windows toasts (otherwise tray badge + inbox only)
 *   criticalBypass  critical messages are shown during "Nicht stören"
 *   mutedTopics     topics switched off on this PC (sent to the server)
 *   dndUntil        "Nicht stören bis" as epoch ms, null = off
 *   muteUntil       { topic: epoch ms } — local "1 h stumm" from a toast
 *   lastSeq         last processed push seq (SSE Last-Event-ID)
 *   seqScope        server/token the lastSeq belongs to (reset on change)
 */

const NOTIFICATION_DEFAULTS = Object.freeze({
  enabled: true,
  direct: true,
  toasts: true,
  criticalBypass: true,
  mutedTopics: Object.freeze([]),
  dndUntil: null,
  muteUntil: Object.freeze({}),
  lastSeq: 0,
  seqScope: '',
});

const notificationsSchema = {
  notifications: {
    type: 'object',
    properties: {
      enabled:        { type: 'boolean', default: true },
      direct:         { type: 'boolean', default: true },
      toasts:         { type: 'boolean', default: true },
      criticalBypass: { type: 'boolean', default: true },
      mutedTopics:    { type: 'array', items: { type: 'string', maxLength: 120 }, maxItems: 100, default: [] },
      dndUntil:       { type: ['number', 'null'], default: null },
      muteUntil:      { type: 'object', additionalProperties: { type: 'number' }, default: {} },
      lastSeq:        { type: 'number', minimum: 0, default: 0 },
      seqScope:       { type: 'string', default: '' },
    },
    default: {},
  },
};

// Keys the renderer may write via config:set (validated by the schema above).
// lastSeq / seqScope / muteUntil are owned by the main process.
const NOTIFICATION_WRITABLE_KEYS = Object.freeze([
  'notifications.enabled',
  'notifications.direct',
  'notifications.toasts',
  'notifications.criticalBypass',
  'notifications.mutedTopics',
  'notifications.dndUntil',
]);

/** Settings with defaults applied (tolerates a store without the schema). */
function readNotificationSettings(store, key = 'notifications') {
  let raw = null;
  try { raw = store && store.get(key); } catch { raw = null; }
  const o = raw && typeof raw === 'object' ? raw : {};
  const bool = (v, d) => (typeof v === 'boolean' ? v : d);
  return {
    enabled: bool(o.enabled, true),
    direct: bool(o.direct, true),
    toasts: bool(o.toasts, true),
    criticalBypass: bool(o.criticalBypass, true),
    mutedTopics: Array.isArray(o.mutedTopics) ? o.mutedTopics.filter((t) => typeof t === 'string') : [],
    dndUntil: Number.isFinite(o.dndUntil) ? o.dndUntil : null,
    muteUntil: o.muteUntil && typeof o.muteUntil === 'object' && !Array.isArray(o.muteUntil) ? { ...o.muteUntil } : {},
    lastSeq: Number.isSafeInteger(o.lastSeq) && o.lastSeq > 0 ? o.lastSeq : 0,
    seqScope: typeof o.seqScope === 'string' ? o.seqScope : '',
  };
}

module.exports = {
  NOTIFICATION_DEFAULTS,
  NOTIFICATION_WRITABLE_KEYS,
  notificationsSchema,
  readNotificationSettings,
};

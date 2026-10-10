/**
 * @gatecontrol/client-core — Public API
 *
 * Shared business logic for all GateControl Windows Clients.
 * Import from this module to get services, utils, IPC handlers, and lifecycle helpers.
 */

'use strict';

// ── Services ────────────────────────────────────────────────
const WireGuardService = require('./services/wireguard-native');
const ApiClient = require('./services/api-client');
const KillSwitch = require('./services/killswitch');
const editions = require('./services/editions');
const RdpAllow = require('./services/rdp-allow');
const ConnectionMonitor = require('./services/connection-monitor');
const Updater = require('./services/updater');
const DnsPolicy = require('./services/dns-policy');
const ClientPolicyService = require('./services/client-policy');
const PushClient = require('./services/push-client');
const NotificationCenter = require('./services/notification-center');

// ── Utils ───────────────────────────────────────────────────
const validation = require('./utils/validation');
const { getMachineFingerprint } = require('./utils/machine-id');
const { createLogger } = require('./utils/logger');
const { createStores } = require('./utils/store');
const notifySchema = require('./utils/notify-schema');
const { checkPushPath, isTunnelOnly } = require('./utils/push-path');
const { notifyMenuItems } = require('./utils/notify-menu');
const { SseParser } = require('./utils/sse-parser');
const E2EEHandler = require('./utils/e2ee');
const enrollment = require('./utils/enrollment');
const { isSafeExternalUrl } = require('./utils/external-url');
const { reconnectDelay, shouldOpenPortal } = require('./utils/tunnel-logic');
const { createPortalOpener, resolvePortalUrl } = require('./utils/portal');
const { loadUpdatePublicKey, updatePublicKeyPaths } = require('./utils/update-public-key');
const { renderTrayIcon, createTrayIcon, formatBytesShort } = require('./utils/tray-icon');
const { updateMenuItems, mandatoryNotice } = require('./utils/update-notice');
const clientPolicy = require('./utils/client-policy');

// ── Shared validators ───────────────────────────────────────
const { validateWgConfig } = require('@callmetechie/gatecontrol-config-hash');

// ── Support bundle ──────────────────────────────────────────
const { collectSupportBundle } = require('./support/collector');
const { createSupportBundleSender } = require('./support/sender');
const supportRedact = require('./support/redact');

// ── i18n ──────────────────────────────────────────────────
const i18n = require('./i18n');

// ── IPC ─────────────────────────────────────────────────────
const { registerBaseHandlers, applyPolicyToStore } = require('./ipc/base-handlers');

// ── Lifecycle ───────────────────────────────────────────────
const { setupAppLifecycle } = require('./lifecycle/app-events');
const { recoverKillSwitch } = require('./lifecycle/killswitch-startup');

// ── Preload ─────────────────────────────────────────────────
const { createBridgeApi, createSubscriber } = require('./preload/bridge');

module.exports = {
  // Services
  WireGuardService,
  ApiClient,
  KillSwitch,
  editions,
  RdpAllow,
  ConnectionMonitor,
  Updater,
  DnsPolicy,
  ClientPolicyService,
  PushClient,
  NotificationCenter,

  // Utils
  validation,
  validateWgConfig,
  getMachineFingerprint,
  createLogger,
  createStores,
  notificationsSchema: notifySchema.notificationsSchema,
  NOTIFICATION_DEFAULTS: notifySchema.NOTIFICATION_DEFAULTS,
  NOTIFICATION_WRITABLE_KEYS: notifySchema.NOTIFICATION_WRITABLE_KEYS,
  readNotificationSettings: notifySchema.readNotificationSettings,
  checkPushPath,
  isTunnelOnly,
  notifyMenuItems,
  SseParser,
  E2EEHandler,
  enrollment,
  isSafeExternalUrl,
  reconnectDelay,
  shouldOpenPortal,
  createPortalOpener,
  resolvePortalUrl,
  loadUpdatePublicKey,
  updatePublicKeyPaths,
  renderTrayIcon,
  createTrayIcon,
  formatBytesShort,
  updateMenuItems,
  mandatoryNotice,
  clientPolicy,

  // Support bundle
  collectSupportBundle,
  createSupportBundleSender,
  supportRedact,

  // IPC
  registerBaseHandlers,
  applyPolicyToStore,

  // Lifecycle
  setupAppLifecycle,
  recoverKillSwitch,

  // Preload
  createBridgeApi,
  createSubscriber,

  // i18n
  i18n,
};

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
const PushControl = require('./services/push-control');
const MessengerService = require('./services/messenger');
const MessengerApi = require('./services/messenger-api');
const MessengerOutbox = require('./services/messenger-outbox');
const ChatNotifier = require('./services/chat-notifier');
const MapService = require('./services/map-service');
const SchoolService = require('./services/school');
const GateDropService = require('./services/gatedrop');
const GateDropApi = require('./services/gatedrop-api');
const GateDropListener = require('./services/gatedrop-listener');

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
const { createPortalOpener, resolvePortalUrl, portalNext } = require('./utils/portal');
const { loadUpdatePublicKey, updatePublicKeyPaths } = require('./utils/update-public-key');
const { renderTrayIcon, createTrayIcon, formatBytesShort } = require('./utils/tray-icon');
const { updateMenuItems, mandatoryNotice } = require('./utils/update-notice');
const clientPolicy = require('./utils/client-policy');
const messengerUtil = require('./utils/messenger');
const schoolUtil = require('./utils/school');
const notifyRoutes = require('./utils/notify-routes');
const gatedropUtil = require('./utils/gatedrop');
const gatedropShell = require('./utils/gatedrop-shell');
const vaultUtil = require('./utils/vault');

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
  PushControl,
  MessengerService,
  MessengerApi,
  MessengerOutbox,
  ChatNotifier,
  MapService,
  SchoolService,
  GateDropService,
  GateDropApi,
  GateDropListener,

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
  portalNext,
  loadUpdatePublicKey,
  updatePublicKeyPaths,
  renderTrayIcon,
  createTrayIcon,
  formatBytesShort,
  updateMenuItems,
  mandatoryNotice,
  clientPolicy,
  messengerUtil,
  schoolUtil,
  notifyRoutes,
  gatedropUtil,
  gatedropShell,
  vaultUtil,

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

// Vault loads libsodium (WASM): only when used, not in every process that requires the core (renderer preloads).
Object.defineProperties(module.exports, {
  VaultService: { enumerable: true, get: () => require('./services/vault') },
  vaultCrypto: { enumerable: true, get: () => require('./utils/vault-crypto') },
  // Wi-Fi networks nearby (Windows Native Wifi API via koffi, loaded on the first scan)
  wifiScan: { enumerable: true, get: () => require('./services/wifi-scan') },
  // 2FA keys from QR codes (screen / clipboard / image file; jsQR in a worker thread)
  totpQr: { enumerable: true, get: () => require('./services/totp-qr') },
  totpQrUtil: { enumerable: true, get: () => require('./utils/totp-qr') },
});

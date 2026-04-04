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
const ConnectionMonitor = require('./services/connection-monitor');
const Updater = require('./services/updater');

// ── Utils ───────────────────────────────────────────────────
const validation = require('./utils/validation');
const { getMachineFingerprint } = require('./utils/machine-id');
const { createLogger } = require('./utils/logger');
const { createStores } = require('./utils/store');
const E2EEHandler = require('./utils/e2ee');

// ── i18n ──────────────────────────────────────────────────
const i18n = require('./i18n');

// ── IPC ─────────────────────────────────────────────────────
const { registerBaseHandlers } = require('./ipc/base-handlers');

// ── Lifecycle ───────────────────────────────────────────────
const { setupAppLifecycle } = require('./lifecycle/app-events');

module.exports = {
  // Services
  WireGuardService,
  ApiClient,
  KillSwitch,
  ConnectionMonitor,
  Updater,

  // Utils
  validation,
  getMachineFingerprint,
  createLogger,
  createStores,
  E2EEHandler,

  // IPC
  registerBaseHandlers,

  // Lifecycle
  setupAppLifecycle,

  // i18n
  i18n,
};

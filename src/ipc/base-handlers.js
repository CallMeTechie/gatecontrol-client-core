/**
 * GateControl – IPC Base Handlers (Core)
 *
 * Provides registerBaseHandlers(ipcMain, ctx) that registers all common
 * IPC handlers shared between Community and Pro clients.
 *
 * The context object `ctx` provides all dependencies so this module
 * has zero module-level coupling.
 */

'use strict';

const { t, getLocale } = require('../i18n');
const { validateWgConfig } = require('@callmetechie/gatecontrol-config-hash');
const ApiClient = require('../services/api-client');
const { normalizeCode, toServerOrigin, parseEnrollmentLink } = require('../utils/enrollment');
const { openExternalSafely } = require('../utils/external-url');
const { AppSignin } = require('../services/app-signin');
const { signinErrorMessage, isDirectoryId } = require('../utils/app-signin');
const { portalNext } = require('../utils/portal');
const clientPolicyUtil = require('../utils/client-policy');
const { createSupportBundleSender } = require('../support/sender');
const { NOTIFICATION_WRITABLE_KEYS } = require('../utils/notify-schema');
const { parseLogText, filterByPeriod } = require('../utils/log-parse');
const { registerMessengerHandlers } = require('./messenger-handlers');
const { registerSchoolHandlers } = require('./school-handlers');
const { registerGateDropHandlers } = require('./gatedrop-handlers');
const { registerVaultHandlers } = require('./vault-handlers');
const { registerDriveHandlers } = require('./drive-handlers');
const { registerMailHandlers } = require('./mail-handlers');
const MapService = require('../services/map-service');

// Server error codes of POST /api/v1/client/enroll → i18n keys
const ENROLL_ERRORS = {
  invalid_or_expired: 'server.enrollInvalid',
  user_disabled: 'server.enrollForbidden',
  user_not_found: 'server.enrollForbidden',
  no_valid_scopes: 'server.enrollForbidden',
  limit_reached: 'server.enrollLimit',
  fingerprint_required: 'server.enrollFingerprint',
};

function enrollErrorMessage(err) {
  const status = err && err.response && err.response.status;
  if (status === 429) return t('server.enrollRateLimited');
  const code = (err && err.response && err.response.data && err.response.data.error) || (err && err.code);
  const key = ENROLL_ERRORS[code];
  return key ? t(key) : t('server.enrollFailed', { error: (err && err.message) || String(code) });
}

// ── Company sign-in: renderer input ─────────────────────────
// Everything from the renderer is checked here before it reaches the network.

const SIGNIN_MAX_URL = 2048;
const SIGNIN_MAX_USER = 256;
const SIGNIN_MAX_PASSWORD = 1024;

/** https origin of opts.url, or null. */
function signinServer(opts) {
  if (!opts || typeof opts !== 'object' || typeof opts.url !== 'string' || opts.url.length > SIGNIN_MAX_URL) return null;
  return toServerOrigin(opts.url);
}

/**
 * { username, password, totp? } from the renderer, or null when anything is
 * missing, too long or of the wrong type. The password is passed on as typed.
 */
function readSigninCredentials(opts) {
  if (!opts || typeof opts !== 'object') return null;
  const { username, password, totp } = opts;
  if (typeof username !== 'string' || typeof password !== 'string') return null;
  const user = username.trim();
  // eslint-disable-next-line no-control-regex
  if (!user || user.length > SIGNIN_MAX_USER || /[\u0000-\u001f\u007f]/.test(user)) return null;
  if (!password || password.length > SIGNIN_MAX_PASSWORD) return null;
  const creds = { username: user, password };
  if (totp !== undefined && totp !== null && totp !== '') {
    if (typeof totp !== 'string') return null;
    const digits = totp.replace(/\s/g, '');
    if (!/^\d{6}$/.test(digits)) return null;
    creds.totp = digits;
  }
  return creds;
}

// Config keys the renderer is allowed to write
const CONFIG_WRITABLE_KEYS = new Set([
  'app.startMinimized', 'app.startWithWindows', 'app.theme',
  'app.checkInterval', 'app.configPollInterval',
  'tunnel.autoConnect', 'tunnel.killSwitch', 'tunnel.rdpAllow',
  'tunnel.splitTunnel', 'tunnel.splitRoutes',
  // Notification center (schema-validated; changes reach the push client
  // through NotificationCenter's store watcher)
  ...NOTIFICATION_WRITABLE_KEYS,
]);

// main → renderer events of the notification center
const NOTIFY_EVENTS = {
  new: 'notify:new',
  update: 'notify:update',
  status: 'notify:status',
  navigate: 'notify:navigate',
};

/**
 * Register base IPC handlers shared by all GateControl clients.
 *
 * @param {Electron.IpcMain} ipcMain
 * @param {object} ctx - Dependency context
 * @param {Electron.App} ctx.app
 * @param {Electron.Dialog} ctx.dialog
 * @param {Function} ctx.getMainWindow - Returns the BrowserWindow or null
 * @param {object} ctx.store - electron-store instance
 * @param {object} ctx.wgService - WireGuardNative instance
 * @param {object} ctx.apiClient - ApiClient instance
 * @param {object} ctx.killSwitch - KillSwitch instance
 * @param {object} [ctx.updater] - Updater instance (or null)
 * @param {Function} [ctx.getUpdater] - () => Updater|null; preferred over
 *   ctx.updater when the updater is created after the handlers are registered
 * @param {Function} [ctx.ApiClientClass] - class whose static
 *   redeemSetupCode() is used (default: core ApiClient; subclasses inherit it)
 * @param {object} ctx.log - electron-log instance
 * @param {Function} ctx.connectTunnel - async () => void
 * @param {Function} ctx.disconnectTunnel - async () => void
 * @param {Function} ctx.toggleKillSwitch - async (enabled) => void
 * @param {Function} [ctx.toggleRdpAllow] - async (enabled) => void
 * @param {Function} [ctx.openPortal] - async (opts?: { next }) => boolean; opens the portal
 *   (with `next`: on that portal tab, already validated by portalNext)
 *   (fresh one-time login link, falling back to the portal URL — see
 *   utils/portal.js). Registers portal:open when given.
 * @param {Function} ctx.installUpdate - async () => { ok, code?, message? } (update:install;
 *   ok:false with code not_ready | busy | verify_failed | launch_failed | exited)
 * @param {Function} ctx.getTunnelState - () => tunnelState object
 * @param {string} ctx.wgConfigFile - Path to the WireGuard config file
 * @param {Iterable<string>} [ctx.extraWritableKeys] - additional config keys
 *   the renderer may write via config:set
 * @param {Object<string, Function>} [ctx.overrides] - ipcMain.handle handlers
 *   that replace the core handler of the same channel (e.g. a client-specific
 *   autostart implementation) or add client-only channels. Each channel is
 *   registered exactly once.
 * @param {Iterable<string>} [ctx.skip] - core channels not to register at all
 * @param {object} [ctx.shell] - Electron shell (injectable for tests)
 * @param {object} [ctx.appSignin] - AppSignin (services/app-signin.js) for
 *   signin:methods / signin:password / signin:microsoft / signin:cancel
 *   ("Mit Firmenkonto anmelden"); created here when missing
 * @param {object} [ctx.clientPolicy] - ClientPolicyService; when given, the
 *   policy guards below apply to the core handler AND to client overrides of
 *   the same channel (config:set, killswitch:toggle, autostart:set,
 *   tunnel:disconnect, server:setup, signin:methods, signin:password,
 *   signin:microsoft, config:import-file, config:import-qr);
 *   policy:get / policy:refresh answer with its state (unrestricted without).
 * @param {object} [ctx.supportBundle] - sender from createSupportBundleSender
 *   (shared with the connection monitor for admin requests); created here
 *   when missing
 * @param {string} [ctx.edition] - 'pro' | 'community' (support bundle)
 * @param {object} [ctx.notificationCenter] - NotificationCenter (opt-in).
 *   When given: registers notify:list, notify:read, notify:action,
 *   notify:prefs:get, notify:prefs:set, notify:test, notify:status,
 *   notify:dnd, notify:quiet, notify:quiet:open, notify:routes, notify:routes:set,
 *   notify:open; forwards its events to the main window as notify:new,
 *   notify:update, notify:status, notify:navigate; and resets it (cache,
 *   resume position, reconnect) after a successful server:setup.
 *   Keep one instance for the app's lifetime.
 * @param {object} [ctx.messenger] - MessengerService (opt-in, "Chats"):
 *   registers the chat:* channels (ipc/messenger-handlers.js), forwards its
 *   events to the main window and resets it after a successful server:setup.
 * @param {object} [ctx.chatNotifier] - ChatNotifier; its 'navigate' (toast
 *   click) reaches the renderer as chat:navigate
 * @param {object} [ctx.maps] - MapService for chat:map:* and drive:map:tile (default: one with
 *   the app's name and version as User-Agent, OpenStreetMap / Nominatim)
 * @param {object} [ctx.school] - SchoolService (opt-in, "Schule"): registers
 *   the school:* channels (ipc/school-handlers.js), forwards its events to the
 *   main window and resets it after a successful server:setup.
 * @param {object} [ctx.gatedrop] - GateDropService (opt-in, "GateDrop"): registers
 *   the gatedrop:* channels (ipc/gatedrop-handlers.js), forwards its events to
 *   the main window and resets it after a successful server:setup.
 * @param {object} [ctx.vault] - VaultService (opt-in, "Vault"): registers the
 *   vault:* channels (ipc/vault-handlers.js), forwards its events to the
 *   main window and resets it after a successful server:setup.
 * @param {object} [ctx.drive] - DriveService (opt-in, "Drive"): registers the
 *   drive:* channels (ipc/drive-handlers.js), forwards its events to the
 *   main window and resets it after a successful server:setup.
 * @param {object} [ctx.driveSync] - DriveSync (opt-in with ctx.drive, "Ordner sichern"):
 *   registers drive:sync:*, forwards its events, resets it after server:setup.
 * @param {object} [ctx.mail] - MailService (opt-in, "Mail"): registers the
 *   mail:* channels (ipc/mail-handlers.js), forwards its events to the
 *   main window and resets it (and its offline cache) after a successful server:setup.
 * @param {object} [ctx.gatedropExplorer] - { get(), set(enabled) } of the
 *   "Senden an → GateDrop" shortcut (gatedrop:explorer)
 * @returns {string[]} the channels registered via ipcMain.handle
 */
function registerBaseHandlers(ipcMain, ctx) {
  const {
    app, dialog, getMainWindow, store, wgService, apiClient,
    log, connectTunnel, disconnectTunnel,
    toggleKillSwitch, installUpdate, getTunnelState, wgConfigFile,
  } = ctx;
  const getUpdater = typeof ctx.getUpdater === 'function' ? ctx.getUpdater : () => ctx.updater || null;
  const ApiClientClass = ctx.ApiClientClass || ApiClient;
  const getShell = () => ctx.shell || require('electron').shell;
  const writableKeys = new Set([...CONFIG_WRITABLE_KEYS, ...(ctx.extraWritableKeys || [])]);
  const overrides = ctx.overrides || {};
  const skip = new Set(ctx.skip || []);
  const registered = [];
  const clientPolicy = ctx.clientPolicy || null;
  const notificationCenter = ctx.notificationCenter || null;
  const messenger = ctx.messenger || null;
  const schoolSvc = ctx.school || null;
  const gatedropSvc = ctx.gatedrop || null;
  const vaultSvc = ctx.vault || null;
  const driveSvc = ctx.drive || null;
  const driveSync = (driveSvc && ctx.driveSync) || null;
  const mailSvc = ctx.mail || null;
  const policyGuards = clientPolicy ? createPolicyGuards({ clientPolicy, store, log }) : {};

  // Registers a core handler unless the client skips or overrides the channel.
  // Policy guards wrap whichever implementation is used.
  function handle(channel, fn) {
    if (skip.has(channel)) return;
    let impl = Object.prototype.hasOwnProperty.call(overrides, channel) ? overrides[channel] : fn;
    if (policyGuards[channel]) impl = policyGuards[channel](impl);
    ipcMain.handle(channel, impl);
    registered.push(channel);
  }

  // A new server / token: the old server's policy and push state must not
  // stick. Drop them and ask the new server (best-effort, the policy answer
  // arrives via onChange, push reconnects on its own).
  function resetForNewServer() {
    if (clientPolicy) {
      clientPolicy.reset();
      Promise.resolve(clientPolicy.refresh()).catch(() => {});
    }
    // Push: new server / token → drop the old inbox, reconnect from scratch.
    if (notificationCenter) {
      try { notificationCenter.resetForNewServer(); } catch (err) { log.warn(`Notification reset failed: ${err.message}`); }
    }
    // Chats: cache, outbox and availability belong to the old server.
    if (messenger) {
      Promise.resolve().then(() => messenger.resetForNewServer()).catch((err) => log.warn(`Messenger reset failed: ${err.message}`));
    }
    // Schule: availability and answers belong to the old server.
    if (schoolSvc) {
      Promise.resolve().then(() => schoolSvc.resetForNewServer()).catch((err) => log.warn(`Schule reset failed: ${err.message}`));
    }
    // GateDrop: availability, targets and lists belong to the old server.
    if (gatedropSvc) {
      Promise.resolve().then(() => gatedropSvc.resetForNewServer()).catch((err) => log.warn(`GateDrop reset failed: ${err.message}`));
    }
    // Vault: lock; the copy, availability and account belong to the old server / login.
    if (vaultSvc) {
      Promise.resolve().then(() => vaultSvc.resetForNewServer()).catch((err) => log.warn(`Vault reset failed: ${err.message}`));
    }
    // Drive: availability, previews and queued uploads belong to the old server.
    if (driveSvc) {
      Promise.resolve().then(() => driveSvc.resetForNewServer()).catch((err) => log.warn(`Drive reset failed: ${err.message}`));
    }
    // "Ordner sichern": the runs of the old server stop; its folders wait ("anderer Server").
    if (driveSync) {
      Promise.resolve().then(() => driveSync.resetForNewServer()).catch((err) => log.warn(`Drive sync reset failed: ${err.message}`));
    }
    // Mail: availability, accounts and the offline cache belong to the old server.
    if (mailSvc) {
      Promise.resolve().then(() => mailSvc.resetForNewServer()).catch((err) => log.warn(`Mail reset failed: ${err.message}`));
    }
  }

  // Writes a (validated) WireGuard config and remembers where it lives.
  async function writeTunnelConfig(content) {
    await wgService.writeConfig(wgConfigFile, content);
    try { store.set('tunnel.configPath', wgConfigFile); } catch { /* schema without configPath */ }
  }

  // ── App ─────────────────────────────────────────────────
  handle('app:version', () => app.getVersion());

  // ── Tunnel ──────────────────────────────────────────────
  handle('tunnel:connect', () => connectTunnel());
  handle('tunnel:disconnect', () => disconnectTunnel());
  // Re-establish the tunnel (e.g. after a split-tunnel change). Not blocked
  // by an always-on policy: the tunnel comes straight back up.
  handle('tunnel:reconnect', async () => {
    await disconnectTunnel();
    return connectTunnel();
  });
  handle('tunnel:status', () => {
    const tunnelState = getTunnelState();
    return {
      ...tunnelState,
      endpoint: store.get('server.url', '') || tunnelState.endpoint,
      killSwitch: store.get('tunnel.killSwitch', false),
      rdpAllow: store.get('tunnel.rdpAllow', false),
    };
  });

  // ── Update ──────────────────────────────────────────────
  handle('update:check', () => getUpdater()?.getUpdateInfo() ?? null);
  handle('update:install', () => installUpdate());
  // Kanal / Mindestversion / Pflicht-Status (vom Server zugewiesen, nur Anzeige)
  handle('update:policy', () => getUpdater()?.getUpdatePolicy?.() ?? null);

  // ── Services & DNS ──────────────────────────────────────
  handle('permissions:get', () => apiClient?.getPermissions());
  handle('services:list', () => apiClient?.getServices());
  handle('traffic:stats', () => apiClient?.getTraffic());
  handle('dns:leak-test', async () => {
    const dns = require('dns').promises;
    const results = { passed: false, dnsServers: [], vpnCheck: null };

    try {
      const resolvers = dns.getServers();
      results.dnsServers = resolvers;

      const serverCheck = await apiClient?.dnsCheck();
      results.vpnCheck = serverCheck;

      if (serverCheck?.vpnSubnet && serverCheck?.serverIp) {
        const subnet = serverCheck.vpnSubnet.split('/')[0].split('.').slice(0, 3).join('.');
        const clientIp = serverCheck.serverIp;
        results.passed = clientIp.startsWith(subnet) || clientIp.startsWith('10.') || clientIp === '127.0.0.1';
      }
    } catch (err) {
      log.debug('DNS leak test failed:', err.message);
    }

    return results;
  });

  // ── Config ──────────────────────────────────────────────
  handle('config:get', (_, key) => store.get(key));
  handle('config:set', (_, key, value) => {
    if (!writableKeys.has(key)) {
      log.warn(`config:set rejected for key: ${key}`);
      return;
    }
    store.set(key, value);
  });
  handle('config:getAll', () => store.store);

  // ── Server Setup ────────────────────────────────────────
  /**
   * Redeem a one-shot setup code: store the minted token, adopt the peer (or
   * register a new one when the code is not bound to a peer) and write the
   * WireGuard config when the server sent one. The existing setup stays
   * untouched until the redeem succeeded.
   */
  async function enrollWithCode(rawUrl, code) {
    const serverUrl = toServerOrigin(rawUrl);
    if (!serverUrl) return { success: false, error: t('server.enrollHttps') };
    let data;
    try {
      data = await ApiClientClass.redeemSetupCode(serverUrl, code, {
        clientVersion: apiClient.clientVersion,
        clientPlatform: apiClient.clientPlatform,
      });
    } catch (err) {
      log.warn(`Setup code redeem failed: ${err.message}`);
      return { success: false, error: enrollErrorMessage(err) };
    }

    store.set('server.url', serverUrl);
    store.set('server.apiKey', data.token);
    apiClient.configure(serverUrl, data.token);
    getUpdater()?.configure(serverUrl, data.token);

    try {
      let peerId = data.peerId;
      if (!peerId) {
        const info = await apiClient.register();
        peerId = info.peerId;
      }
      store.set('server.peerId', String(peerId));
      apiClient.setPeerId(peerId);

      if (data.config) {
        const validation = validateWgConfig(data.config);
        if (validation.ok) {
          await writeTunnelConfig(data.config);
        } else {
          log.warn('Setup code config rejected: ' + validation.errors.join(', '));
        }
      }
      log.info(`Set up via setup code (peer ${peerId})`);
      resetForNewServer();
      return { success: true, peerId, enrolled: true };
    } catch (err) {
      return { success: false, error: err.message };
    }
  }

  handle('server:setup', async (_, { url, apiKey } = {}) => {
    // The API key field also takes a setup code (XXXX-XXXX-XXXX-XXXX).
    const code = normalizeCode(apiKey);
    if (code) return enrollWithCode(url, code);

    // The API token travels in a header — never over plain http.
    const serverUrl = toServerOrigin(url);
    if (!serverUrl) return { success: false, error: t('server.httpsRequired') };
    if (typeof apiKey !== 'string' || !apiKey.trim()) return { success: false, error: t('server.urlAndKeyRequired') };
    apiKey = apiKey.trim();

    store.set('server.url', serverUrl);
    store.set('server.apiKey', apiKey);
    apiClient.configure(serverUrl, apiKey);
    getUpdater()?.configure(serverUrl, apiKey);

    try {
      await apiClient.ping();

      const info = await apiClient.register();
      store.set('server.peerId', String(info.peerId));
      apiClient.setPeerId(info.peerId);
      resetForNewServer();
      return { success: true, peerId: info.peerId };
    } catch (err) {
      return { success: false, error: err.message };
    }
  });

  handle('server:test', async (_, { url, apiKey } = {}) => {
    try {
      if (url) {
        url = toServerOrigin(url);
        if (!url) return { success: false, error: t('server.httpsRequired') };
      }
      if (url && normalizeCode(apiKey)) {
        // A setup code cannot be tested without spending it — only check
        // that the server answers (401 without a token is the expected reply).
        const axios = require('axios');
        try {
          await axios.get(`${url}/api/v1/client/ping`, { timeout: 10000 });
        } catch (err) {
          if (!err.response) throw err;
        }
        return { success: true };
      }
      if (url && apiKey) {
        const axios = require('axios');
        const res = await axios.get(`${url}/api/v1/client/ping`, {
          headers: { 'X-API-Token': apiKey },
          timeout: 10000,
        });
        return { success: res.data?.ok === true };
      }
      await apiClient.ping();
      return { success: true };
    } catch (err) {
      return { success: false, error: err.message };
    }
  });

  // ── Company sign-in ("Mit Firmenkonto anmelden") ────────
  // GateControl ≥ 1.201.0 (services/app-signin.js). Password or Microsoft
  // sign-in answers with a one-shot setup code that goes through
  // enrollWithCode() above, unchanged. The renderer never sees the code,
  // the handoff or the PKCE verifier; the password is only passed on.
  const appSignin = ctx.appSignin || new AppSignin({
    log,
    openExternal: (url) => openExternalSafely(getShell(), url, { log, label: 'Company sign-in' }),
    clientPlatform: () => (apiClient && apiClient.clientPlatform) || 'windows',
  });

  handle('signin:methods', async (_, opts) => {
    const serverUrl = signinServer(opts);
    if (!serverUrl) return { available: false, password: { enabled: false, hint: null }, microsoft: [] };
    return appSignin.methods(serverUrl);
  });

  handle('signin:password', async (_, opts) => {
    const serverUrl = signinServer(opts);
    if (!serverUrl) return { success: false, error: t('server.enrollHttps') };
    const creds = readSigninCredentials(opts);
    if (!creds) return { success: false, error: t('server.signin.invalidInput') };
    let result;
    try {
      result = await appSignin.password(serverUrl, creds);
    } catch (err) {
      return signinFailure(err, 'password');
    }
    log.info('Company sign-in (password) succeeded, redeeming the setup code');
    return enrollWithCode(serverUrl, result.code);
  });

  handle('signin:microsoft', async (_, opts) => {
    const serverUrl = signinServer(opts);
    if (!serverUrl) return { success: false, error: t('server.enrollHttps') };
    const id = opts && typeof opts === 'object' ? opts.id : undefined;
    if (!isDirectoryId(id)) return { success: false, error: t('server.signin.invalidInput') };
    let result;
    try {
      result = await appSignin.microsoft(serverUrl, id);
    } catch (err) {
      return signinFailure(err, 'microsoft');
    }
    log.info('Company sign-in (Microsoft) succeeded, redeeming the setup code');
    return enrollWithCode(serverUrl, result.code);
  });

  handle('signin:cancel', () => appSignin.cancel());

  function signinFailure(err, kind) {
    const code = (err && err.code) || 'failed';
    if (code === 'cancelled') return { success: false, cancelled: true, code };
    // Only the code (and HTTP status): never credentials or one-time values.
    log.warn(`Company sign-in (${kind}) failed: ${code}${err && err.status ? ` (HTTP ${err.status})` : ''}`);
    return {
      success: false,
      code,
      totpRequired: code === 'totp_required' || code === 'totp_invalid',
      error: signinErrorMessage(t, err),
    };
  }

  // ── Config Import ───────────────────────────────────────
  handle('config:import-file', async () => {
    const mainWindow = getMainWindow();
    const result = await dialog.showOpenDialog(mainWindow, {
      title: t('dialog.importTitle'),
      filters: [
        { name: t('dialog.filterConfig'), extensions: ['conf'] },
        { name: t('dialog.filterAll'), extensions: ['*'] },
      ],
      properties: ['openFile'],
    });

    if (result.canceled) return { success: false };

    try {
      const fs = require('fs').promises;
      const content = await fs.readFile(result.filePaths[0], 'utf-8');
      // Fail-closed: validate untrusted imported config before writing.
      const validation = validateWgConfig(content);
      if (!validation.ok) {
        return { success: false, error: 'Invalid WireGuard config: ' + validation.errors.join(', ') };
      }
      if (validation.warnings && validation.warnings.length > 0) {
        log.warn('Imported config warnings: ' + validation.warnings.join(', '));
      }
      await writeTunnelConfig(content);
      return { success: true, path: result.filePaths[0] };
    } catch (err) {
      return { success: false, error: err.message };
    }
  });

  handle('config:import-qr', async (_, imageData) => {
    try {
      const jsQR = require('jsqr');
      const { data, width, height } = imageData;
      const code = jsQR(new Uint8ClampedArray(data), width, height);

      if (!code) return { success: false, error: t('server.qrTimeout') };

      // Setup QR from the server ("App einrichten"): redeem after the user
      // confirmed the server — a foreign QR must not repoint the client.
      const link = parseEnrollmentLink(code.data);
      if (link) {
        const { response } = await dialog.showMessageBox(getMainWindow(), {
          type: 'question',
          buttons: [t('enroll.connect'), t('enroll.cancel')],
          defaultId: 0,
          cancelId: 1,
          message: t('enroll.confirmTitle'),
          detail: t('enroll.confirmBody', { host: new URL(link.serverUrl).host }),
        });
        // enrollment:true tells the renderer's scan loop to stop — otherwise
        // the next camera frame would detect the same QR and ask again.
        if (response !== 0) return { success: false, cancelled: true, enrollment: true };
        return { ...(await enrollWithCode(link.serverUrl, link.code)), enrollment: true };
      }

      // Fail-closed: validate untrusted scanned config before writing.
      const validation = validateWgConfig(code.data);
      if (!validation.ok) {
        return { success: false, error: 'Invalid WireGuard config: ' + validation.errors.join(', ') };
      }
      if (validation.warnings && validation.warnings.length > 0) {
        log.warn('Imported QR config warnings: ' + validation.warnings.join(', '));
      }
      await writeTunnelConfig(code.data);
      return { success: true };
    } catch (err) {
      return { success: false, error: err.message };
    }
  });

  // ── WireGuard Check ─────────────────────────────────────
  handle('wireguard:check', async () => {
    return { installed: true, version: 'wireguard-nt (embedded)' };
  });

  // ── Kill-Switch ─────────────────────────────────────────
  handle('killswitch:toggle', (_, enabled) => toggleKillSwitch(enabled));

  // ── RDP Allow ──────────────────────────────────────────
  if (ctx.toggleRdpAllow) {
    handle('rdp-allow:toggle', (_, enabled) => ctx.toggleRdpAllow(enabled));
  }

  // ── Client-Richtlinie ───────────────────────────────────
  // Without a ClientPolicyService the client is unmanaged (no restriction).
  handle('policy:get', () => (clientPolicy ? clientPolicy.getState() : clientPolicyUtil.uiState(null)));
  handle('policy:refresh', async () => {
    if (!clientPolicy) return clientPolicyUtil.uiState(null);
    await clientPolicy.refresh();
    return clientPolicy.getState();
  });

  // ── Window Controls ─────────────────────────────────────
  ipcMain.on('window:minimize', () => getMainWindow()?.minimize());
  ipcMain.on('window:close', () => getMainWindow()?.hide());

  // ── Autostart ───────────────────────────────────────────
  handle('autostart:set', (_, enabled) => {
    store.set('app.startWithWindows', enabled);
    app.setLoginItemSettings({
      openAtLogin: enabled,
      path: process.execPath,
      args: ['--minimized'],
    });
    return enabled;
  });

  // ── Portal ──────────────────────────────────────────────
  // The renderer never sees the login link: main fetches and opens it.
  // Optional { next }: a portal tab ('/portal#mitteilungen'); anything else
  // is dropped here (utils/portal.js portalNext) and the portal home opens.
  if (ctx.openPortal) {
    handle('portal:open', async (_, opts) => {
      try {
        const next = opts && typeof opts === 'object' ? portalNext(opts.next) : null;
        return (await (next ? ctx.openPortal({ next }) : ctx.openPortal())) === true;
      } catch (err) {
        log.warn('portal:open failed:', err && err.message);
        return false;
      }
    });
  }

  // ── Shell ───────────────────────────────────────────────
  // http(s) links, or exactly one of the allowed Windows settings pages (ms-settings:privacy-location)
  handle('shell:open-external', (_, url) => openExternalSafely(getShell(), url, { log, allowSettings: true, label: 'shell:open-external' }));

  // ── Logs ────────────────────────────────────────────────
  // opts.period: 'all' | '1h' | '12h' | '24h'.
  // opts.format: 'entries' → [{ ts, date, time, ms, level, msg }] newest
  //   first (utils/log-parse.js: "\r\n" line ends, multi-line entries kept
  //   together); otherwise the text, newest entry first (older renderers).
  handle('logs:get', async (_, opts = {}) => {
    const fs = require('fs').promises;
    const entriesWanted = !!opts && opts.format === 'entries';
    try {
      const logPath = log.transports.file.getFile().path;
      const stat = await fs.stat(logPath);

      // Read max 1 MB from end of file
      const MAX_READ = 1024 * 1024;
      let content;
      if (stat.size > MAX_READ) {
        const fh = await fs.open(logPath, 'r');
        const buf = Buffer.alloc(MAX_READ);
        await fh.read(buf, 0, MAX_READ, stat.size - MAX_READ);
        await fh.close();
        content = buf.toString('utf-8');
        // Drop first partial line
        const firstNewline = content.indexOf('\n');
        if (firstNewline > 0) content = content.slice(firstNewline + 1);
      } else {
        content = await fs.readFile(logPath, 'utf-8');
      }

      const period = opts && typeof opts.period === 'string' ? opts.period : 'all';
      const entries = filterByPeriod(parseLogText(content, { raw: !entriesWanted }), period);
      // Newest first
      entries.reverse();

      if (entriesWanted) return entries;
      return entries.map((e) => e.raw).join('\n');
    } catch {
      return entriesWanted ? [] : t('logs.empty');
    }
  });

  handle('logs:export', async () => {
    try {
      const logPath = log.transports.file.getFile().path;
      return logPath;
    } catch {
      return null;
    }
  });

  // Shows the log file in Explorer. Takes no path from the renderer, so it
  // cannot be used to reveal (or, via openExternal, open) arbitrary files.
  handle('logs:show', async () => {
    try {
      const logPath = log.transports.file.getFile().path;
      if (!logPath) return false;
      getShell().showItemInFolder(logPath);
      return true;
    } catch (err) {
      log.warn('logs:show failed:', err && err.message);
      return false;
    }
  });

  // ── Benachrichtigungen (notification center, opt-in) ────
  if (notificationCenter) registerNotifyHandlers(handle, { notificationCenter, getMainWindow, log });

  // OpenStreetMap tiles / addresses for the chats' maps and Drive's photo map (one service: one queue, one cache)
  const maps = ctx.maps || (messenger || driveSvc ? new MapService({
    log,
    userAgent: MapService.userAgentFor(app && typeof app.getName === 'function' ? app.getName() : null, app && typeof app.getVersion === 'function' ? app.getVersion() : null),
    getLang: () => getLocale(),
  }) : null);

  // ── Chats (messenger, opt-in) ───────────────────────────
  if (messenger) {
    registerMessengerHandlers(handle, {
      messenger,
      chatNotifier: ctx.chatNotifier || null,
      maps,
      getMainWindow,
      log,
      dialog,
      shell: ctx.shell || (() => { try { return require('electron').shell; } catch { return null; } })(),
      getTempDir: () => {
        try { return require('path').join(app.getPath('temp'), 'gatecontrol-chat'); } catch { return require('path').join(require('os').tmpdir(), 'gatecontrol-chat'); }
      },
    });
  }

  // ── Schule (WebUntis timetable, opt-in) ────────────────
  if (schoolSvc) registerSchoolHandlers(handle, { school: schoolSvc, getMainWindow, log });

  // ── GateDrop (plugin gatecontrol-gatedrop, opt-in) ──────
  if (gatedropSvc) {
    registerGateDropHandlers(handle, { gatedrop: gatedropSvc, getMainWindow, log, dialog, explorer: ctx.gatedropExplorer || null });
  }

  // ── Vault (plugin gatecontrol-vault, opt-in) ────────────
  if (vaultSvc) registerVaultHandlers(handle, { vault: vaultSvc, getMainWindow, log });

  // ── Drive (plugin gatecontrol-drive, opt-in) ────────────
  if (driveSvc) registerDriveHandlers(handle, { drive: driveSvc, sync: driveSync, maps, getMainWindow, log });

  // ── Mail (plugin gatecontrol-mail, opt-in) ──────────────
  if (mailSvc) registerMailHandlers(handle, { mail: mailSvc, getMainWindow, log });

  // ── Support bundle ("Support-Paket senden") ─────────────
  // Confirmation dialog → redacted bundle → upload (src/support/).
  const supportBundle = ctx.supportBundle || createSupportBundleSender(ctx);
  handle('support:send', () => supportBundle.send({ reason: 'user' }));

  // Client handlers for channels core does not know
  for (const [channel, fn] of Object.entries(overrides)) {
    if (!registered.includes(channel) && !skip.has(channel)) {
      ipcMain.handle(channel, policyGuards[channel] ? policyGuards[channel](fn) : fn);
      registered.push(channel);
    }
  }

  return registered;
}

/**
 * IPC of the notification center. Arguments from the renderer are checked
 * here and again in NotificationCenter.
 *
 *   notify:list        ({ filter?, limit?, before?, refresh? }) → { items, unread, topics }
 *   notify:read        ({ ids: number[] } | { all: true } | number[]) → { ok, updated, unread }
 *   notify:action      ({ id, action }) → { ok, error? }
 *   notify:prefs:get   () → { enabled, direct, toasts, criticalBypass, mutedTopics, dndUntil, topics }
 *   notify:prefs:set   (partial prefs) → { ok, prefs } | { ok: false, error }
 *   notify:test        () → { ok, seq } | { ok: false, error }
 *   notify:status      () → NotificationCenter.status()
 *   notify:dnd         ({ minutes } | { until } | null = off | undefined = query) → { ok, active, until }
 *   notify:quiet       ({ refresh? }) → { ok, known, quiet: { from, to, tz, criticalBypass } | null, source, at }
 *   notify:quiet:open  () → boolean (portal tab "Meine Benachrichtigungen", auto-login)
 *   notify:routes      () → { ok, routes: { sink, canFamily, groups } } | { ok: false, error }
 *                      (where each kind of notification appears, core 1.191; 'unsupported' = older server)
 *   notify:routes:set  ({ topic, dest: 'inbox'|'own'|'family' }) → { ok, routes, chat } | { ok: false, error }
 *                      (chat: on 'own' the source's own chat { source, label, conversationId, created }, else null)
 *   notify:open        ({ route, topic?, data? }) → { ok, route? } — a notice card's link opens what a
 *                      click on that notification would (notify:navigate); ok false: nothing claimed it
 */
function registerNotifyHandlers(handle, { notificationCenter: nc, getMainWindow, log }) {
  handle('notify:list', async (_, opts = {}) => {
    const o = opts && typeof opts === 'object' ? opts : {};
    if (o.refresh === true) await nc.refresh().catch(() => null);
    return nc.list({
      filter: typeof o.filter === 'string' ? o.filter.slice(0, 120) : 'all',
      limit: Number.isSafeInteger(o.limit) ? o.limit : undefined,
      before: Number.isSafeInteger(o.before) ? o.before : null,
    });
  });
  handle('notify:read', (_, arg) => {
    if (arg && typeof arg === 'object' && !Array.isArray(arg) && arg.all === true) return nc.markRead('all');
    const ids = Array.isArray(arg) ? arg : (arg && Array.isArray(arg.ids) ? arg.ids : null);
    if (!ids || ids.length > 500 || !ids.every((x) => Number.isSafeInteger(x) && x > 0)) {
      return { ok: false, error: 'invalid_ids', updated: 0, unread: nc.unreadCount() };
    }
    return nc.markRead(ids);
  });
  handle('notify:action', (_, arg = {}) => {
    const id = arg && Number(arg.id);
    const action = arg && typeof arg.action === 'string' ? arg.action : '';
    if (!Number.isSafeInteger(id) || id <= 0 || !/^[A-Za-z0-9_.:-]{1,40}$/.test(action)) return { ok: false, error: 'invalid' };
    return nc.performAction(id, action);
  });
  handle('notify:prefs:get', () => nc.getPrefs());
  handle('notify:prefs:set', (_, patch) => nc.setPrefs(patch));
  handle('notify:test', () => (nc.pushClient ? nc.pushClient.requestTest() : { ok: false, error: 'not_configured' }));
  handle('notify:status', () => nc.status());
  handle('notify:dnd', (_, arg) => (arg === undefined ? { ok: true, ...nc.dndState() } : nc.setDnd(arg)));
  handle('notify:quiet', async (_, opts) => {
    if (opts && typeof opts === 'object' && opts.refresh === true) return nc.refreshQuiet();
    return { ok: true, ...nc.quietState() };
  });
  handle('notify:routes', () => nc.routes());
  handle('notify:routes:set', (_, arg) => {
    const a = arg && typeof arg === 'object' && !Array.isArray(arg) ? arg : {};
    if (typeof a.topic !== 'string' || a.topic.length > 120 || typeof a.dest !== 'string' || a.dest.length > 20) return { ok: false, error: 'invalid' };
    return nc.setRoute(a.topic, a.dest);
  });
  handle('notify:open', (_, arg) => {
    const a = arg && typeof arg === 'object' && !Array.isArray(arg) ? arg : {};
    const route = typeof a.route === 'string' && a.route.length <= 200 ? a.route : null;
    const topic = typeof a.topic === 'string' && a.topic.length <= 120 ? a.topic : null;
    let data = null;
    if (a.data && typeof a.data === 'object' && !Array.isArray(a.data)) {
      // Untrusted (from a chat message): only a small plain object is passed on.
      try { if (JSON.stringify(a.data).length <= 16384) data = a.data; } catch { data = null; }
    }
    return nc.openTarget({ route, topic, data });
  });
  handle('notify:quiet:open', async () => {
    try {
      return (await nc.openQuietHoursInPortal()) === true;
    } catch (err) {
      log.warn('notify:quiet:open failed:', err && err.message);
      return false;
    }
  });

  for (const [event, channel] of Object.entries(NOTIFY_EVENTS)) {
    nc.on(event, (payload) => {
      const win = getMainWindow && getMainWindow();
      if (!win || (typeof win.isDestroyed === 'function' && win.isDestroyed()) || !win.webContents) return;
      try { win.webContents.send(channel, payload); } catch (err) { log.debug(`${channel} not delivered: ${err.message}`); }
    });
  }
}

/**
 * Wrappers that refuse renderer requests the client policy does not allow.
 * The main process still decides — a manipulated renderer cannot bypass a
 * lock through IPC. (Local admins can bypass the client altogether; the
 * policy is a management convenience, not a security boundary.)
 */
function createPolicyGuards({ clientPolicy, store, log }) {
  const policy = () => clientPolicy.getPolicy();
  const locks = () => clientPolicyUtil.locks(policy());
  const refuse = (channel, detail) => {
    log.warn(`${channel} refused by client policy${detail ? `: ${detail}` : ''}`);
  };
  const serverLocked = (channel, impl) => async (...args) => {
    if (locks().server) {
      refuse(channel);
      return { success: false, error: t('policy.serverLocked'), policyLocked: true };
    }
    return impl(...args);
  };

  return {
    'config:set': (impl) => (event, key, value) => {
      const ok = clientPolicyUtil.canWriteConfig(policy(), key, value, {
        splitTunnelEnabled: store.get('tunnel.splitTunnel', false) === true,
      });
      if (!ok) {
        refuse('config:set', key);
        return false;
      }
      return impl(event, key, value);
    },
    'killswitch:toggle': (impl) => (event, enabled) => {
      const l = locks();
      if (l.killSwitch) {
        const forcedOn = policy().killSwitch === 'required';
        if ((enabled === true) !== forcedOn) {
          refuse('killswitch:toggle');
          return { blocked: true, policyLocked: true };
        }
      }
      return impl(event, enabled);
    },
    'autostart:set': (impl) => (event, enabled) => {
      const p = policy();
      if (locks().autostart) {
        const want = p.autostart === 'required' ? true : p.autostart === 'forbidden' ? false : null;
        if (want === null || (enabled === true) !== want) {
          refuse('autostart:set');
          return store.get('app.startWithWindows', want === true);
        }
      }
      return impl(event, enabled);
    },
    'tunnel:disconnect': (impl) => (...args) => {
      if (locks().disconnect) {
        refuse('tunnel:disconnect');
        return { blocked: true, policyLocked: true };
      }
      return impl(...args);
    },
    'server:setup': (impl) => serverLocked('server:setup', impl),
    // Company sign-in sets the device up like server:setup.
    'signin:methods': (impl) => async (...args) => {
      if (locks().server) return { available: false, password: { enabled: false, hint: null }, microsoft: [], policyLocked: true };
      return impl(...args);
    },
    'signin:password': (impl) => serverLocked('signin:password', impl),
    'signin:microsoft': (impl) => serverLocked('signin:microsoft', impl),
    'config:import-file': (impl) => serverLocked('config:import-file', impl),
    'config:import-qr': (impl) => serverLocked('config:import-qr', impl),
  };
}

/**
 * Apply the forced values of a client policy to the store (kill switch on,
 * auto-connect on, autostart on/off, allowed split mode). Returns the keys
 * that changed so the app can act on them (e.g. enable the kill switch,
 * (un)register autostart). Never throws.
 */
function applyPolicyToStore(store, policy, log) {
  const changed = {};
  try {
    const forced = clientPolicyUtil.forcedValues(policy, {
      splitTunnelEnabled: store.get('tunnel.splitTunnel', false) === true,
    });
    for (const [key, value] of Object.entries(forced)) {
      if (store.get(key) !== value) {
        store.set(key, value);
        changed[key] = value;
      }
    }
  } catch (err) {
    if (log) log.warn(`Applying client policy failed: ${err.message}`);
  }
  return changed;
}

module.exports = { registerBaseHandlers, createPolicyGuards, applyPolicyToStore, readSigninCredentials, CONFIG_WRITABLE_KEYS, NOTIFY_EVENTS };

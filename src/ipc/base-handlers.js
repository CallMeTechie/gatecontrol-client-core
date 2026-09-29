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

const { t } = require('../i18n');
const { validateWgConfig } = require('@callmetechie/gatecontrol-config-hash');
const ApiClient = require('../services/api-client');
const { normalizeCode, toServerOrigin, parseEnrollmentLink } = require('../utils/enrollment');
const { isSafeExternalUrl } = require('../utils/external-url');

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

// Config keys the renderer is allowed to write
const CONFIG_WRITABLE_KEYS = new Set([
  'app.startMinimized', 'app.startWithWindows', 'app.theme',
  'app.checkInterval', 'app.configPollInterval',
  'tunnel.autoConnect', 'tunnel.killSwitch', 'tunnel.rdpAllow',
  'tunnel.splitTunnel', 'tunnel.splitRoutes',
]);

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
 * @param {Function} ctx.installUpdate - async () => boolean
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

  // Registers a core handler unless the client skips or overrides the channel.
  function handle(channel, fn) {
    if (skip.has(channel)) return;
    const impl = Object.prototype.hasOwnProperty.call(overrides, channel) ? overrides[channel] : fn;
    ipcMain.handle(channel, impl);
    registered.push(channel);
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

  // ── Shell ───────────────────────────────────────────────
  handle('shell:open-external', async (_, url) => {
    if (!isSafeExternalUrl(url)) {
      log.warn('shell:open-external rejected a non-http(s) URL');
      return false;
    }
    try {
      await getShell().openExternal(url.trim());
      return true;
    } catch (err) {
      log.warn('shell:open-external failed:', err.message);
      return false;
    }
  });

  // ── Logs ────────────────────────────────────────────────
  handle('logs:get', async (_, opts = {}) => {
    const fs = require('fs').promises;
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

      let lines = content.split('\n').filter(l => l.trim());

      // Time filter
      if (opts.period && opts.period !== 'all') {
        const hours = opts.period === '24h' ? 24 : opts.period === '12h' ? 12 : opts.period === '1h' ? 1 : 0;
        if (hours > 0) {
          const cutoff = new Date(Date.now() - hours * 3600000);
          lines = lines.filter(line => {
            // electron-log format: [YYYY-MM-DD HH:MM:SS.mmm] or [HH:MM:SS.mmm]
            const m = line.match(/\[(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})/);
            if (!m) return true; // keep lines without timestamp
            return new Date(m[1]) >= cutoff;
          });
        }
      }

      // Reverse: newest first
      lines.reverse();

      return lines.join('\n');
    } catch {
      return t('logs.empty');
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

  // Client handlers for channels core does not know
  for (const [channel, fn] of Object.entries(overrides)) {
    if (!registered.includes(channel) && !skip.has(channel)) {
      ipcMain.handle(channel, fn);
      registered.push(channel);
    }
  }

  return registered;
}

module.exports = { registerBaseHandlers };

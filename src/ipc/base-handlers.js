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

// Config keys the renderer is allowed to write
const CONFIG_WRITABLE_KEYS = new Set([
  'app.startMinimized', 'app.startWithWindows', 'app.theme',
  'app.checkInterval', 'app.configPollInterval',
  'tunnel.autoConnect', 'tunnel.killSwitch',
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
 * @param {object} ctx.updater - Updater instance (or null)
 * @param {object} ctx.log - electron-log instance
 * @param {Function} ctx.connectTunnel - async () => void
 * @param {Function} ctx.disconnectTunnel - async () => void
 * @param {Function} ctx.toggleKillSwitch - async (enabled) => void
 * @param {Function} ctx.installUpdate - async () => boolean
 * @param {Function} ctx.getTunnelState - () => tunnelState object
 * @param {string} ctx.wgConfigFile - Path to the WireGuard config file
 */
function registerBaseHandlers(ipcMain, ctx) {
  const {
    app, dialog, getMainWindow, store, wgService, apiClient,
    killSwitch, updater, log, connectTunnel, disconnectTunnel,
    toggleKillSwitch, installUpdate, getTunnelState, wgConfigFile,
  } = ctx;

  // ── App ─────────────────────────────────────────────────
  ipcMain.handle('app:version', () => app.getVersion());

  // ── Tunnel ──────────────────────────────────────────────
  ipcMain.handle('tunnel:connect', () => connectTunnel());
  ipcMain.handle('tunnel:disconnect', () => disconnectTunnel());
  ipcMain.handle('tunnel:status', () => {
    const tunnelState = getTunnelState();
    return {
      ...tunnelState,
      endpoint: store.get('server.url', '') || tunnelState.endpoint,
      killSwitch: store.get('tunnel.killSwitch', false),
    };
  });

  // ── Update ──────────────────────────────────────────────
  ipcMain.handle('update:check', () => updater?.getUpdateInfo());
  ipcMain.handle('update:install', () => installUpdate());

  // ── Services & DNS ──────────────────────────────────────
  ipcMain.handle('permissions:get', () => apiClient?.getPermissions());
  ipcMain.handle('services:list', () => apiClient?.getServices());
  ipcMain.handle('traffic:stats', () => apiClient?.getTraffic());
  ipcMain.handle('dns:leak-test', async () => {
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
      log.debug('DNS-Leak-Test fehlgeschlagen:', err.message);
    }

    return results;
  });

  // ── Config ──────────────────────────────────────────────
  ipcMain.handle('config:get', (_, key) => store.get(key));
  ipcMain.handle('config:set', (_, key, value) => {
    if (!CONFIG_WRITABLE_KEYS.has(key)) {
      log.warn(`config:set verweigert für Key: ${key}`);
      return;
    }
    store.set(key, value);
  });
  ipcMain.handle('config:getAll', () => store.store);

  // ── Server Setup ────────────────────────────────────────
  ipcMain.handle('server:setup', async (_, { url, apiKey }) => {
    store.set('server.url', url);
    store.set('server.apiKey', apiKey);
    apiClient.configure(url, apiKey);
    updater?.configure(url, apiKey);

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

  ipcMain.handle('server:test', async (_, { url, apiKey } = {}) => {
    try {
      if (url && apiKey) {
        const axios = require('axios');
        const res = await axios.get(`${url.replace(/\/+$/, '')}/api/v1/client/ping`, {
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
  ipcMain.handle('config:import-file', async () => {
    const mainWindow = getMainWindow();
    const result = await dialog.showOpenDialog(mainWindow, {
      title: 'WireGuard-Konfiguration importieren',
      filters: [
        { name: 'WireGuard Config', extensions: ['conf'] },
        { name: 'Alle Dateien', extensions: ['*'] },
      ],
      properties: ['openFile'],
    });

    if (result.canceled) return { success: false };

    try {
      const fs = require('fs').promises;
      const content = await fs.readFile(result.filePaths[0], 'utf-8');
      await wgService.writeConfig(wgConfigFile, content);
      return { success: true, path: result.filePaths[0] };
    } catch (err) {
      return { success: false, error: err.message };
    }
  });

  ipcMain.handle('config:import-qr', async (_, imageData) => {
    try {
      const jsQR = require('jsqr');
      const { data, width, height } = imageData;
      const code = jsQR(new Uint8ClampedArray(data), width, height);

      if (!code) return { success: false, error: 'Kein QR-Code erkannt' };

      await wgService.writeConfig(wgConfigFile, code.data);
      return { success: true, config: code.data };
    } catch (err) {
      return { success: false, error: err.message };
    }
  });

  // ── WireGuard Check ─────────────────────────────────────
  ipcMain.handle('wireguard:check', async () => {
    return { installed: true, version: 'wireguard-nt (embedded)' };
  });

  // ── Kill-Switch ─────────────────────────────────────────
  ipcMain.handle('killswitch:toggle', (_, enabled) => toggleKillSwitch(enabled));

  // ── Window Controls ─────────────────────────────────────
  ipcMain.on('window:minimize', () => getMainWindow()?.minimize());
  ipcMain.on('window:close', () => getMainWindow()?.hide());

  // ── Autostart ───────────────────────────────────────────
  ipcMain.handle('autostart:set', (_, enabled) => {
    store.set('app.startWithWindows', enabled);
    app.setLoginItemSettings({
      openAtLogin: enabled,
      path: process.execPath,
      args: ['--minimized'],
    });
    return enabled;
  });

  // ── Shell ───────────────────────────────────────────────
  ipcMain.handle('shell:open-external', (_, url) => {
    const { shell } = require('electron');
    if (typeof url === 'string' && /^https?:\/\//i.test(url)) {
      shell.openExternal(url);
    }
  });

  // ── Logs ────────────────────────────────────────────────
  ipcMain.handle('logs:get', async () => {
    const fs = require('fs').promises;
    try {
      const logPath = log.transports.file.getFile().path;
      const content = await fs.readFile(logPath, 'utf-8');
      const lines = content.split('\n').slice(-200);
      return lines.join('\n');
    } catch {
      return 'Keine Logs verfügbar';
    }
  });
}

module.exports = { registerBaseHandlers };

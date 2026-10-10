'use strict';

/**
 * Renderer bridge shared by the Pro and Community preload scripts.
 *
 * createBridgeApi() builds the `window.gatecontrol` object with every channel
 * both editions expose; the app preload adds its edition-specific parts
 * (e.g. Pro: rdp.*, dns.checkSystem; Community: window.toggleMaximize) and
 * hands the result to contextBridge.exposeInMainWorld('gatecontrol', api).
 *
 * Electron-free: ipcRenderer and the i18n module are passed in, so the
 * channel list can be unit-tested with a fake ipcRenderer.
 *
 * @param {Electron.IpcRenderer} ipcRenderer
 * @param {object} i18n - core i18n module (t, setLocale, getLocale, …)
 * @param {object} [opts]
 * @param {string} [opts.updateReadyChannel='update-ready'] - event channel the
 *   main process uses to announce a downloaded update (Pro: 'update:ready')
 * @returns {object} bridge API
 */
function createBridgeApi(ipcRenderer, i18n, { updateReadyChannel = 'update-ready' } = {}) {
  const { t, setLocale, getLocale, onLocaleChange, getSupportedLocales } = i18n;

  // Subscribe to a main → renderer event; returns an unsubscribe function.
  const subscribe = createSubscriber(ipcRenderer);

  return {
    // ── App ──────────────────────────────────────────────
    getVersion: () => ipcRenderer.invoke('app:version'),

    // ── Tunnel ───────────────────────────────────────────
    tunnel: {
      connect:    () => ipcRenderer.invoke('tunnel:connect'),
      disconnect: () => ipcRenderer.invoke('tunnel:disconnect'),
      reconnect:  () => ipcRenderer.invoke('tunnel:reconnect'),
      getStatus:  () => ipcRenderer.invoke('tunnel:status'),
      onState:    (cb) => subscribe('tunnel-state', cb),
    },

    // ── Server ───────────────────────────────────────────
    server: {
      setup: (opts) => ipcRenderer.invoke('server:setup', opts),
      test:  (opts) => ipcRenderer.invoke('server:test', opts),
    },

    // ── Config ───────────────────────────────────────────
    config: {
      get:        (key)        => ipcRenderer.invoke('config:get', key),
      set:        (key, value) => ipcRenderer.invoke('config:set', key, value),
      getAll:     ()           => ipcRenderer.invoke('config:getAll'),
      importFile: ()           => ipcRenderer.invoke('config:import-file'),
      importQR:   (imageData)  => ipcRenderer.invoke('config:import-qr', imageData),
    },

    // ── WireGuard ────────────────────────────────────────
    wireguard: {
      check: () => ipcRenderer.invoke('wireguard:check'),
    },

    // ── Kill-Switch ──────────────────────────────────────
    killSwitch: {
      toggle: (enabled) => ipcRenderer.invoke('killswitch:toggle', enabled),
    },

    // ── RDP Allow ────────────────────────────────────────
    rdpAllow: {
      toggle: (enabled) => ipcRenderer.invoke('rdp-allow:toggle', enabled),
    },

    // ── Autostart ────────────────────────────────────────
    autostart: {
      set: (enabled) => ipcRenderer.invoke('autostart:set', enabled),
    },

    // ── Logs ─────────────────────────────────────────────
    logs: {
      get: (opts) => ipcRenderer.invoke('logs:get', opts),
      export: () => ipcRenderer.invoke('logs:export'),
      show: () => ipcRenderer.invoke('logs:show'),
    },

    // ── Support bundle ───────────────────────────────────
    // → { success, id } | { success: false, cancelled } | { success: false, error }
    support: {
      send: () => ipcRenderer.invoke('support:send'),
    },

    // ── Peer ─────────────────────────────────────────────
    peer: {
      onExpiry: (cb) => subscribe('peer-expiry', cb),
    },

    // ── Permissions ──────────────────────────────────────
    permissions: {
      get: () => ipcRenderer.invoke('permissions:get'),
    },

    // ── Traffic ──────────────────────────────────────────
    traffic: {
      stats: () => ipcRenderer.invoke('traffic:stats'),
    },

    // ── Services ─────────────────────────────────────────
    services: {
      list: () => ipcRenderer.invoke('services:list'),
    },

    // ── DNS ──────────────────────────────────────────────
    dns: {
      leakTest: () => ipcRenderer.invoke('dns:leak-test'),
    },

    // ── Update ───────────────────────────────────────────
    update: {
      check:   () => ipcRenderer.invoke('update:check'),
      install: () => ipcRenderer.invoke('update:install'),
      onReady: (cb) => subscribe(updateReadyChannel, cb),
      // { channel, minVersion, belowMinimum, mandatory, updateReady, version }
      policy:   () => ipcRenderer.invoke('update:policy'),
      onPolicy: (cb) => subscribe('update:policy', cb),
    },

    // ── Client-Richtlinie (vom Server) ───────────────────
    // State: { fetched, version, managed, policy, locks, splitModes }
    policy: {
      get:      () => ipcRenderer.invoke('policy:get'),
      refresh:  () => ipcRenderer.invoke('policy:refresh'),
      onChange: (cb) => subscribe('policy:changed', cb),
    },

    // ── Shell ────────────────────────────────────────────
    shell: {
      openExternal: (url) => ipcRenderer.invoke('shell:open-external', url),
    },

    // ── Portal ───────────────────────────────────────────
    onPortalUrl: (cb) => ipcRenderer.on('portal-url', (_e, url) => cb(url)),
    // Opens the portal with a fresh one-time login link (fallback: portal URL).
    portal: {
      open: () => ipcRenderer.invoke('portal:open'),
    },

    // ── Fenster ──────────────────────────────────────────
    window: {
      minimize: () => ipcRenderer.send('window:minimize'),
      close:    () => ipcRenderer.send('window:close'),
    },

    // ── Navigation ───────────────────────────────────────
    onNavigate: (cb) => subscribe('navigate', cb),

    // ── i18n ─────────────────────────────────────────────
    i18n: {
      t: (key, params) => t(key, params),
      getLocale: () => getLocale(),
      getSupportedLocales: () => getSupportedLocales(),
    },

    // ── Locale ───────────────────────────────────────────
    locale: {
      set: (locale) => {
        setLocale(locale);
        ipcRenderer.invoke('locale:set', locale);
      },
      get: () => ipcRenderer.invoke('locale:get'),
      onChange: (cb) => {
        const ipcHandler = (_, loc) => {
          setLocale(loc);
          cb(loc);
        };
        ipcRenderer.on('locale:changed', ipcHandler);
        const unsub = onLocaleChange((loc) => cb(loc));
        return () => {
          ipcRenderer.removeListener('locale:changed', ipcHandler);
          unsub();
        };
      },
    },
  };
}

/**
 * Helper for edition-specific event subscriptions in the app preload.
 * @returns {(channel: string, cb: Function) => Function} subscribe(channel, cb) → unsubscribe
 */
function createSubscriber(ipcRenderer) {
  return (channel, cb) => {
    const handler = (_, data) => cb(data);
    ipcRenderer.on(channel, handler);
    return () => ipcRenderer.removeListener(channel, handler);
  };
}

module.exports = { createBridgeApi, createSubscriber };

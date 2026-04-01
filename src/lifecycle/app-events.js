/**
 * GateControl – App Lifecycle Events (Core)
 *
 * Provides setupAppLifecycle(app, ctx) that configures:
 * - Single instance lock
 * - second-instance handler (show window)
 * - window-all-closed prevention
 * - before-quit flag
 * - Quit cleanup (tunnel disconnect, kill-switch disable, tray destroy)
 * - Autostart configuration
 */

'use strict';

/**
 * Enforce single-instance lock. Returns false if this is a duplicate instance
 * (the app should quit immediately).
 *
 * @param {Electron.App} app
 * @returns {boolean} true if this is the primary instance
 */
function enforceSingleInstance(app) {
  const gotLock = app.requestSingleInstanceLock();
  if (!gotLock) {
    app.quit();
    return false;
  }
  return true;
}

/**
 * Configure autostart (login item settings).
 *
 * @param {Electron.App} app
 * @param {boolean} enabled
 */
function configureAutostart(app, enabled) {
  app.setLoginItemSettings({
    openAtLogin: enabled,
    path: process.execPath,
    args: ['--minimized'],
  });
}

/**
 * Setup app lifecycle event handlers.
 *
 * @param {Electron.App} app
 * @param {object} ctx
 * @param {Function} ctx.showWindow - () => void
 * @param {Function} ctx.quitApp - async () => void
 */
function setupAppLifecycle(app, ctx) {
  const { showWindow } = ctx;

  // Show window when a second instance is launched
  app.on('second-instance', () => {
    showWindow();
  });

  // Prevent app from quitting when all windows are closed (tray app)
  app.on('window-all-closed', (e) => {
    e.preventDefault();
  });

  // Set quitting flag
  app.on('before-quit', () => {
    app.isQuitting = true;
  });
}

/**
 * Perform clean shutdown: disconnect tunnel, disable kill-switch, destroy tray.
 *
 * @param {Electron.App} app
 * @param {object} ctx
 * @param {object} ctx.store - electron-store instance
 * @param {object} ctx.tunnelState - { connected: boolean }
 * @param {object} ctx.killSwitch - KillSwitch instance
 * @param {object} ctx.updater - Updater instance (or null)
 * @param {Electron.Tray|null} ctx.tray
 * @param {Function} ctx.disconnectTunnel - async () => void
 */
async function performCleanShutdown(app, ctx) {
  const { store, tunnelState, killSwitch, updater, tray, disconnectTunnel } = ctx;

  app.isQuitting = true;

  // Stop updater
  updater?.stop();

  // Disconnect tunnel
  if (tunnelState.connected) {
    await disconnectTunnel();
  }

  // Disable kill-switch if active
  if (killSwitch?.enabled) {
    try {
      await killSwitch.disable();
      store.set('tunnel.killSwitch', false);
    } catch {}
  }

  tray?.destroy();
  app.quit();
}

module.exports = {
  enforceSingleInstance,
  configureAutostart,
  setupAppLifecycle,
  performCleanShutdown,
};

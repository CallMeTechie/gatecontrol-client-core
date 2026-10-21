'use strict';

/**
 * GateDrop in the Windows Explorer: "Senden an → GateDrop".
 *
 * The app keeps a shortcut `GateDrop.lnk` in the user's SendTo folder
 * (%APPDATA%\Microsoft\Windows\SendTo) while GateDrop is available and the
 * setting is on. Explorer starts the target with the chosen files appended:
 *
 *   "<app>.exe" [<app path> in development] --gatedrop-send "C:\a.pdf" "D:\b.jpg"
 *
 * The single-instance lock hands that argv to the running app
 * ('second-instance'), which opens the send dialog (GateDropService.handleArgv).
 *
 * Electron-free: shell (writeShortcutLink / readShortcutLink) and fs are passed in.
 */

const path = require('path');

const SEND_FLAG = '--gatedrop-send';
const SHORTCUT_NAME = 'GateDrop.lnk';
const MAX_ARGS = 40;

/**
 * Files of a "Senden an" start (everything after --gatedrop-send that is an
 * absolute path), or null when argv is no such start.
 */
function parseSendArgs(argv) {
  if (!Array.isArray(argv)) return null;
  const at = argv.findIndex((a) => typeof a === 'string' && a.toLowerCase() === SEND_FLAG);
  if (at < 0) return null;
  const out = [];
  for (const a of argv.slice(at + 1)) {
    if (typeof a !== 'string' || !a || a.startsWith('--')) continue;
    if (!(path.win32.isAbsolute(a) || path.isAbsolute(a))) continue;
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(a)) continue; // protocol URLs (toast buttons)
    out.push(a);
    if (out.length >= MAX_ARGS) break;
  }
  return out;
}

/** %APPDATA%\Microsoft\Windows\SendTo\GateDrop.lnk */
function sendToShortcutPath(appData) {
  return path.win32.join(appData, 'Microsoft', 'Windows', 'SendTo', SHORTCUT_NAME);
}

/**
 * Arguments of the shortcut: packaged builds start the exe, development
 * (`electron .`) needs the app path in front.
 */
function shortcutArgs({ isPackaged = true, appPath = null } = {}) {
  const parts = [];
  if (!isPackaged && appPath) parts.push(`"${appPath}"`);
  parts.push(SEND_FLAG);
  return parts.join(' ');
}

/**
 * Create, update or remove the SendTo shortcut.
 * @param {object} o
 * @param {boolean} o.enabled
 * @param {object} o.shell - Electron shell
 * @param {object} o.fs - node fs
 * @param {string} o.appData - app.getPath('appData')
 * @param {string} o.exePath - process.execPath
 * @param {string} o.args - shortcutArgs()
 * @param {string} [o.description]
 * @param {string} [o.icon]
 * @param {object} [o.log]
 * @returns {'created'|'updated'|'unchanged'|'removed'|'absent'|'failed'}
 */
function syncSendToShortcut({ enabled, shell, fs, appData, exePath, args, description = 'GateDrop', icon = null, log = null }) {
  if (!shell || typeof shell.writeShortcutLink !== 'function' || !appData || !exePath) return 'failed';
  const file = sendToShortcutPath(appData);
  let current = null;
  try { if (fs.existsSync(file)) current = shell.readShortcutLink(file); } catch { current = { target: null }; }
  try {
    if (!enabled) {
      if (!current) return 'absent';
      // Only our own shortcut (the other edition may own one with the same name).
      if (current.target && path.win32.normalize(current.target).toLowerCase() !== path.win32.normalize(exePath).toLowerCase()) return 'unchanged';
      fs.unlinkSync(file);
      return 'removed';
    }
    const want = { target: exePath, args, description, icon: icon || exePath, iconIndex: 0 };
    if (current && current.target === want.target && (current.args || '') === want.args) return 'unchanged';
    fs.mkdirSync(path.win32.dirname(file), { recursive: true });
    const ok = shell.writeShortcutLink(file, current ? 'replace' : 'create', want);
    return ok === false ? 'failed' : current ? 'updated' : 'created';
  } catch (err) {
    if (log) log.warn(`GateDrop SendTo shortcut: ${err.message}`);
    return 'failed';
  }
}

module.exports = { SEND_FLAG, SHORTCUT_NAME, parseSendArgs, sendToShortcutPath, shortcutArgs, syncSendToShortcut };

'use strict';

/**
 * "Im Ordner anzeigen" on Windows through `explorer.exe /select,<file>`.
 *
 * Electron's shell.showItemInFolder() asks the running Explorer over COM
 * (SHOpenFolderAndSelectItems) and reports nothing back. The apps run with
 * requireAdministrator: from the elevated process that call can do
 * nothing at all (the Explorer of the signed-in user runs without admin
 * rights, or as another Windows user) — the log export, Drive's transfer list and GateDrop's "Anzeigen"
 * showed no window. A started explorer.exe hands the folder over to the
 * running Explorer itself and selects the file; only when it cannot be
 * started, showItemInFolder() is tried.
 *
 *   const shell = explorerShell(require('electron').shell, { log });
 *   shell.showItemInFolder(file)   // explorer.exe /select,"file" on Windows
 *   shell.openPath(dir)            // everything else as before
 */

const path = require('path');

/**
 * Shows `file` selected in its folder → true when it was handed on.
 * @param {object} shell - Electron's shell (showItemInFolder as the fallback)
 * @param {string} file - absolute path
 * @param {object} [o]
 * @param {string} [o.platform=process.platform]
 * @param {Function} [o.spawn] - child_process.spawn (tests)
 * @param {object} [o.log]
 */
function revealItem(shell, file, { platform = process.platform, spawn = null, log = null } = {}) {
  if (typeof file !== 'string' || !file) return false;
  const fallback = () => {
    if (shell && typeof shell.showItemInFolder === 'function') shell.showItemInFolder(file);
  };
  if (platform !== 'win32' || !path.win32.isAbsolute(file)) {
    fallback();
    return true;
  }
  const target = path.win32.normalize(file);
  try {
    const run = spawn || require('child_process').spawn;
    // two arguments: Node quotes the path (spaces); explorer.exe takes `/select, "C:\…\file"`
    const child = run('explorer.exe', ['/select,', target], { detached: true, stdio: 'ignore', windowsHide: false });
    if (child && typeof child.on === 'function') {
      child.on('error', (err) => {
        if (log) log.warn(`explorer.exe could not be started (${err.code || err.message}) – showItemInFolder instead`);
        fallback();
      });
    }
    if (child && typeof child.unref === 'function') child.unref();
    return true;
  } catch (err) {
    if (log) log.warn(`explorer.exe could not be started (${err.code || err.message}) – showItemInFolder instead`);
    fallback();
    return true;
  }
}

/**
 * Electron's shell with showItemInFolder() through revealItem(); every other
 * member is Electron's own (bound to it).
 */
function explorerShell(shell, opts = {}) {
  if (!shell) return shell;
  const reveal = (file) => { revealItem(shell, file, opts); };
  return new Proxy(shell, {
    get(target, prop) {
      if (prop === 'showItemInFolder') return reveal;
      const v = target[prop];
      return typeof v === 'function' ? v.bind(target) : v;
    },
  });
}

module.exports = { revealItem, explorerShell };

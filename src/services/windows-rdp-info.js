'use strict';

/**
 * GateControl – Fernzugriff: what Windows offers for Remote Desktop (Core service)
 *
 * detect() reads the edition (HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion EditionID) and
 * whether Remote Desktop is on (HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server
 * fDenyTSConnections = 0). Windows Home ("Core…") cannot offer Remote Desktop at all; the app then
 * points to "Bildschirm teilen" instead of registering the PC.
 *
 * enable() switches Remote Desktop on in Windows (fDenyTSConnections = 0) — the apps run elevated
 * (requireAdministrator). It never enables the built-in firewall rules: 3389 opens only per
 * session (rdp-session-firewall.js).
 */

const os = require('os');
const { execFile } = require('child_process');
const { promisify } = require('util');

const execFileAsync = promisify(execFile);

const VERSION_KEY = 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion';
const TS_KEY = 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server';

function defaultReg(args) {
  return execFileAsync('reg', args, { windowsHide: true, timeout: 10000 });
}

/** "    EditionID    REG_SZ    Professional" → 'Professional' */
function regValue(stdout, name) {
  for (const line of String(stdout || '').split(/\r?\n/)) {
    const m = line.trim().match(/^(\S+)\s+(REG_\w+)\s+(.*)$/);
    if (m && m[1].toLowerCase() === name.toLowerCase()) return { type: m[2], value: m[3].trim() };
  }
  return null;
}

/** EditionID → 'pro' | 'enterprise' | 'education' | 'home' | null */
function editionOf(id) {
  const s = String(id || '');
  if (!s) return null;
  if (/^Core/i.test(s)) return 'home';
  if (/^Education/i.test(s)) return 'education';
  if (/^(Enterprise|Server|IoTEnterprise)/i.test(s)) return 'enterprise';
  if (/^Professional/i.test(s)) return 'pro';
  return 'pro';
}

class WindowsRdpInfo {
  /**
   * @param {object} [opts]
   * @param {Function} [opts.reg] - async (args[]) => { stdout } (tests)
   * @param {string} [opts.platform]
   */
  constructor({ reg, platform = process.platform, log } = {}) {
    this._reg = reg || defaultReg;
    this.platform = platform;
    this.log = log || { info() {}, warn() {}, debug() {}, error() {} };
  }

  /** → { edition, editionId, rdpAvailable, rdpEnabled, osUser } (null fields when unknown) */
  async detect() {
    let editionId = null;
    let rdpEnabled = null;
    if (this.platform === 'win32') {
      try { const r = regValue((await this._reg(['query', VERSION_KEY, '/v', 'EditionID'])).stdout, 'EditionID'); editionId = r ? r.value : null; } catch { editionId = null; }
      try {
        const r = regValue((await this._reg(['query', TS_KEY, '/v', 'fDenyTSConnections'])).stdout, 'fDenyTSConnections');
        if (r) rdpEnabled = parseInt(r.value, 16) === 0;
      } catch { rdpEnabled = null; }
    }
    const edition = editionOf(editionId);
    let osUser = null;
    try { osUser = os.userInfo().username || null; } catch { osUser = null; }
    return { edition, editionId, rdpAvailable: edition === null ? null : edition !== 'home', rdpEnabled, osUser };
  }

  /** "In Windows einschalten": Remote Desktop on (fDenyTSConnections = 0). */
  async enable() {
    if (this.platform !== 'win32') throw new Error('Windows only');
    await this._reg(['add', TS_KEY, '/v', 'fDenyTSConnections', '/t', 'REG_DWORD', '/d', '0', '/f']);
    this.log.info('Remote Desktop switched on in Windows');
  }
}

WindowsRdpInfo.editionOf = editionOf;
WindowsRdpInfo.regValue = regValue;

module.exports = WindowsRdpInfo;

'use strict';

/**
 * GateControl – Fernzugriff: Windows Firewall per session (Core service)
 *
 * Stage 2 of "Fernzugriff": while the PC is registered with the plugin, port 3389 is not opened
 * for the whole VPN (rdp-allow.js) but per session for exactly one remote address — the hub
 * address of the server for a session in the browser (guacd connects from there) or the VPN
 * address of the helper's app. Each rule is called "GateControl RDP <sessionKey>"
 * (sessionKey = fw_<random> from the plugin); the app removes every such rule when it starts
 * and when the switch goes off.
 *
 * Only literal IPv4 addresses and session keys of the plugin's form get into a netsh call; the
 * cleanup runs a fixed PowerShell script (no input in it).
 *
 * builtInOpen(): are the built-in Windows rules of the group "Remote Desktop" enabled? Then
 * Windows itself lets 3389 in from every network of the active profile, and the per-session rule
 * cannot narrow it — the app says so (null: unknown).
 */

const { execFile } = require('child_process');
const { promisify } = require('util');
const { IPV4_RE } = require('../utils/validation');

const execFileAsync = promisify(execFile);

const RULE_PREFIX = 'GateControl RDP ';
const SESSION_KEY_RE = /^fw_[A-Za-z0-9_-]{8,40}$/;
const RDP_PORT = 3389;

const CLEANUP_PS = String.raw`
$ErrorActionPreference = 'SilentlyContinue'
$n = 0
foreach ($r in @(Get-NetFirewallRule -DisplayName 'GateControl RDP fw_*' -PolicyStore PersistentStore)) { Remove-NetFirewallRule -Name $r.Name; $n++ }
"$n"
`;

// the group "Remote Desktop" (indirect string, the same on every display language)
const BUILTIN_PS = String.raw`
$ErrorActionPreference = 'SilentlyContinue'
$r = @(Get-NetFirewallRule -Group '@FirewallAPI.dll,-28752' -Direction Inbound -PolicyStore ActiveStore | Where-Object { $_.Enabled -eq 'True' -and $_.Action -eq 'Allow' })
"$($r.Count)"
`;

function defaultNetsh(args) {
  return execFileAsync('netsh', args, { windowsHide: true, timeout: 15000 });
}

function defaultPowerShell(script) {
  return execFileAsync('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script], { windowsHide: true, timeout: 20000 });
}

class RdpSessionFirewall {
  /**
   * @param {object} opts
   * @param {object} [opts.log]
   * @param {Function} [opts.netsh] - async (args[]) => { stdout } (tests)
   * @param {Function} [opts.powershell] - async (script) => { stdout } (tests)
   */
  constructor({ log, netsh, powershell } = {}) {
    this.log = log || { info() {}, warn() {}, debug() {}, error() {} };
    this._netsh = netsh || defaultNetsh;
    this._ps = powershell || defaultPowerShell;
  }

  static ruleName(sessionKey) {
    if (!SESSION_KEY_RE.test(String(sessionKey || ''))) throw new Error('invalid session key');
    return RULE_PREFIX + sessionKey;
  }

  /** Allow TCP 3389 from exactly `ip` for this session. */
  async open(sessionKey, ip, port = RDP_PORT) {
    const name = RdpSessionFirewall.ruleName(sessionKey);
    if (typeof ip !== 'string' || !IPV4_RE.test(ip)) throw new Error('invalid remote address');
    if (port !== RDP_PORT) throw new Error('invalid port');
    // a rule of the same key from an earlier attempt goes first
    await this._netsh(['advfirewall', 'firewall', 'delete', 'rule', `name=${name}`]).catch(() => {});
    await this._netsh(['advfirewall', 'firewall', 'add', 'rule', `name=${name}`, 'dir=in', 'action=allow', 'protocol=tcp',
      `localport=${RDP_PORT}`, `remoteip=${ip}`, 'profile=any', 'enable=yes']);
    this.log.info(`RDP session rule opened for ${ip}`);
  }

  /** Remove the rule of this session (no error when it is gone). */
  async close(sessionKey) {
    const name = RdpSessionFirewall.ruleName(sessionKey);
    await this._netsh(['advfirewall', 'firewall', 'delete', 'rule', `name=${name}`]).catch(() => {});
  }

  /** Remove every "GateControl RDP fw_*" rule → how many (null when unknown). */
  async closeAll() {
    try {
      const { stdout } = await this._ps(CLEANUP_PS);
      const n = parseInt(String(stdout || '').trim(), 10);
      return Number.isFinite(n) ? n : null;
    } catch (err) {
      this.log.warn('RDP session rules could not be cleaned up:', err && err.message);
      return null;
    }
  }

  /** true / false: the built-in "Remote Desktop" rules let 3389 in; null: unknown. */
  async builtInOpen() {
    try {
      const { stdout } = await this._ps(BUILTIN_PS);
      const n = parseInt(String(stdout || '').trim(), 10);
      return Number.isFinite(n) ? n > 0 : null;
    } catch {
      return null;
    }
  }
}

RdpSessionFirewall.RULE_PREFIX = RULE_PREFIX;
RdpSessionFirewall.SESSION_KEY_RE = SESSION_KEY_RE;

module.exports = RdpSessionFirewall;

'use strict';

/**
 * GateControl – GateDrop firewall check (Windows, Core)
 *
 * The LAN listener (gatedrop-listener.js) can bind and still be unreachable:
 * the phone's connection to TCP 47731 never arrives when the Windows
 * Firewall drops it. Typical causes, all seen in the field:
 *
 *   - Block rules for the app's exe. Up to Pro 1.38 / Community 1.39 the
 *     installer allowed the port only for the "Private" profile. On a home
 *     WLAN that Windows rates "Public", the first listen() showed the
 *     "Windows-Sicherheitswarnung"; "Abbrechen" (or allowing only private
 *     networks) makes Windows create inbound BLOCK rules for the exe. Block
 *     rules beat every allow rule, so the newer installer rule (all profiles,
 *     local subnet) never took effect.
 *   - The allow rule is missing (portable version: no installer; deleted by
 *     a cleanup tool) or points to another exe path.
 *   - "Alle eingehenden Verbindungen blockieren, einschließlich der in der
 *     Liste zugelassenen Apps" (AllowInboundRules = False) for the profile
 *     of the WLAN — only the user can change that.
 *
 * ensure() reads the rules of the own exe with PowerShell (NetSecurity
 * cmdlets: enum values are not localized, unlike netsh output), removes
 * local inbound block rules of the own exe that cover the port, (re)creates
 * the allow rule under the edition's name (same name as the installer's
 * GC_GATEDROP_RULE) and reads again. The apps run elevated
 * (requireAdministrator), so the repair works there; without rights it
 * reports what is wrong. Rules of group policies are never touched.
 *
 * Result: { checked, issues: [{ code, detail }], repaired: [] } with code
 *   firewall_shields_up – the active profile blocks every inbound connection
 *   firewall_blocked    – a block rule for the exe is left (group policy, or removal failed)
 *   firewall_rule       – no allow rule for the port / exe and the profile blocks by default
 *   firewall_unknown    – could not be checked (no PowerShell, timeout)
 */

const { execFile } = require('child_process');
const gd = require('../utils/gatedrop');
const editions = require('./editions');

const INSPECT_PS = String.raw`
$ErrorActionPreference = 'SilentlyContinue'
if (-not (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue)) { '{"ok":false,"error":"no_netsecurity"}'; exit 0 }
$exe = $env:GC_GD_EXE
$name = $env:GC_GD_RULE
function N([string]$p) {
  if (-not $p) { return '' }
  $x = [Environment]::ExpandEnvironmentVariables($p)
  try { $x = [IO.Path]::GetFullPath($x) } catch {}
  return $x.ToLowerInvariant()
}
$me = N $exe
$rules = @()
foreach ($f in @(Get-NetFirewallApplicationFilter -PolicyStore ActiveStore | Where-Object { $_.Program -and $_.Program -ne 'Any' -and (N $_.Program) -eq $me })) {
  foreach ($r in @($f | Get-NetFirewallRule)) {
    $pf = $r | Get-NetFirewallPortFilter
    $rules += [pscustomobject]@{
      id = [string]$r.Name; name = [string]$r.DisplayName; enabled = [string]$r.Enabled
      action = [string]$r.Action; direction = [string]$r.Direction; profile = [string]$r.Profile
      store = [string]$r.PolicyStoreSourceType; protocol = [string]$pf.Protocol
      localPort = [string](@($pf.LocalPort) -join ',')
    }
  }
}
$named = @(Get-NetFirewallRule -DisplayName $name -PolicyStore ActiveStore | ForEach-Object { [string]$_.Name })
$profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {
  [pscustomobject]@{ name = [string]$_.Name; enabled = [string]$_.Enabled; allowInboundRules = [string]$_.AllowInboundRules; defaultInbound = [string]$_.DefaultInboundAction }
})
$nets = @(Get-NetConnectionProfile | ForEach-Object { [pscustomobject]@{ alias = [string]$_.InterfaceAlias; category = [string]$_.NetworkCategory } })
[pscustomobject]@{ ok = $true; rules = $rules; named = $named; profiles = $profiles; nets = $nets } | ConvertTo-Json -Depth 4 -Compress
`;

const REPAIR_PS = String.raw`
$ErrorActionPreference = 'Stop'
$exe = $env:GC_GD_EXE
$name = $env:GC_GD_RULE
$port = [int]$env:GC_GD_PORT
$res = @()
foreach ($id in @(([string]$env:GC_GD_REMOVE) -split "\n" | Where-Object { $_ })) {
  try { Remove-NetFirewallRule -Name $id -PolicyStore PersistentStore -ErrorAction Stop; $res += "removed" }
  catch { $res += ("remove_failed: " + $_.Exception.Message) }
}
if ($env:GC_GD_ADD -eq '1') {
  try { Remove-NetFirewallRule -DisplayName $name -PolicyStore PersistentStore -ErrorAction SilentlyContinue } catch {}
  try {
    New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Allow -Protocol TCP -LocalPort $port -RemoteAddress LocalSubnet -Profile Any -Program $exe -Enabled True -PolicyStore PersistentStore -ErrorAction Stop | Out-Null
    $res += "added"
  } catch { $res += ("add_failed: " + $_.Exception.Message) }
}
ConvertTo-Json -InputObject @($res) -Compress
`;

const CATEGORY_PROFILE = { public: 'Public', private: 'Private', domainauthenticated: 'Domain' };

function runPowerShell(script, env, timeoutMs) {
  return new Promise((resolve) => {
    execFile('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
      '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64'),
    ], { timeout: timeoutMs, windowsHide: true, maxBuffer: 4 * 1024 * 1024, env: { ...process.env, ...env } }, (err, stdout, stderr) => {
      resolve({ err, stdout: String(stdout || '').trim(), stderr: String(stderr || '').trim() });
    });
  });
}

// Windows PowerShell 5.1 sometimes writes an array as { value: [...], Count: n }
// and a single element without brackets: accept all three.
const list = (v) => {
  if (Array.isArray(v)) return v;
  if (v && typeof v === 'object') return Array.isArray(v.value) ? v.value : [v];
  return [];
};
const s = (v) => (typeof v === 'string' ? v : (v === null || v === undefined ? '' : String(v)));

/** Profile list of a rule ("Any", "Private, Public", "Domain,Private") → names, null = all. */
function profilesOf(profile) {
  const p = s(profile).trim();
  if (!p || /^any$/i.test(p) || p === '0') return null;
  return p.split(/[\s,]+/).filter(Boolean).map((x) => x.toLowerCase());
}

function portCovered(rule, port) {
  const proto = s(rule.protocol).toLowerCase();
  if (proto && proto !== 'tcp' && proto !== 'any' && proto !== '6') return false;
  const lp = s(rule.localPort).trim();
  if (!lp || /^any$/i.test(lp)) return true;
  return lp.split(',').some((part) => {
    const m = /^\s*(\d+)\s*(?:-\s*(\d+))?\s*$/.exec(part);
    if (!m) return false;
    const lo = Number(m[1]);
    const hi = m[2] ? Number(m[2]) : lo;
    return port >= lo && port <= hi;
  });
}

/**
 * What is wrong and what to repair, from the inspect answer (pure, tested).
 * @returns {{ issues: Array<{code, detail}>, addRule: boolean, removeIds: string[] }}
 */
function planFirewall(inspect, { ruleName, port = gd.PORT } = {}) {
  const r = inspect && typeof inspect === 'object' ? inspect : null;
  if (!r || r.ok !== true) {
    return { issues: [{ code: 'firewall_unknown', detail: s(r && r.error) || null }], addRule: false, removeIds: [] };
  }
  const enabled = list(r.profiles).filter((p) => /^true$/i.test(s(p.enabled)));
  if (!enabled.length) return { issues: [], addRule: false, removeIds: [] }; // Windows Firewall off
  // Profiles of the connected networks (Public / Private / Domain); unknown → all enabled ones.
  const active = new Set(list(r.nets).map((n) => CATEGORY_PROFILE[s(n.category).toLowerCase()]).filter(Boolean).map((x) => x.toLowerCase()));
  const relevant = enabled.filter((p) => !active.size || active.has(s(p.name).toLowerCase()));
  if (!relevant.length) return { issues: [], addRule: false, removeIds: [] };
  const names = relevant.map((p) => s(p.name).toLowerCase());
  const applies = (rule) => { const ps = profilesOf(rule.profile); return !ps || ps.some((x) => names.includes(x)); };
  const coversAll = (rule) => { const ps = profilesOf(rule.profile); return !ps || names.every((x) => ps.includes(x)); };

  const inbound = list(r.rules).filter((x) => /^inbound$/i.test(s(x.direction)) && /^true$/i.test(s(x.enabled)) && portCovered(x, port));
  const blocks = inbound.filter((x) => /^block$/i.test(s(x.action)) && applies(x));
  const allowOk = inbound.some((x) => /^allow$/i.test(s(x.action)) && coversAll(x))
    || relevant.every((p) => /^allow$/i.test(s(p.defaultInbound)));
  const removeIds = blocks.filter((x) => /^local$/i.test(s(x.store)) && s(x.id)).map((x) => s(x.id));

  const issues = [];
  const shields = relevant.filter((p) => /^false$/i.test(s(p.allowInboundRules)));
  if (shields.length) issues.push({ code: 'firewall_shields_up', detail: shields.map((p) => s(p.name)).join(', ') });
  if (blocks.length) issues.push({ code: 'firewall_blocked', detail: [...new Set(blocks.map((x) => s(x.name)))].join(', ') });
  if (!allowOk) issues.push({ code: 'firewall_rule', detail: ruleName || null });
  return { issues, addRule: !allowOk, removeIds };
}

function parseJson(text) {
  try { return JSON.parse(text); } catch { return null; }
}

class GateDropFirewall {
  /**
   * @param {object} opts
   * @param {object} [opts.log]
   * @param {'pro'|'community'} [opts.edition] - rule name (editions.gatedropRuleName)
   * @param {string} [opts.ruleName] - instead of edition (tests)
   * @param {string} [opts.exePath=process.execPath]
   * @param {number} [opts.port=47731]
   * @param {string} [opts.platform=process.platform]
   * @param {(script: string, env: object, timeoutMs: number) => Promise<{ err, stdout, stderr }>} [opts.run]
   * @param {number} [opts.timeoutMs=30000]
   */
  constructor({ log, edition = null, ruleName = null, exePath = process.execPath, port = gd.PORT, platform = process.platform, run = runPowerShell, timeoutMs = 30000 } = {}) {
    this.log = log || { info() {}, warn() {}, debug() {} };
    this.ruleName = ruleName || editions.gatedropRuleName(edition || 'pro');
    this.exePath = exePath;
    this.port = port;
    this.platform = platform;
    this.run = run;
    this.timeoutMs = timeoutMs;
    this._running = null;
  }

  get supported() {
    return this.platform === 'win32';
  }

  async inspect() {
    const env = { GC_GD_EXE: this.exePath, GC_GD_RULE: this.ruleName };
    const res = await this.run(INSPECT_PS, env, this.timeoutMs);
    const data = parseJson(res.stdout);
    if (!data) {
      const why = (res.err && (res.err.killed ? 'timeout' : (res.err.code || res.err.message))) || res.stderr || 'no answer';
      return { ok: false, error: String(why).slice(0, 200) };
    }
    return data;
  }

  /** Check and repair once at a time → { checked, issues, repaired } */
  ensure() {
    if (!this._running) this._running = this._ensure().finally(() => { this._running = null; });
    return this._running;
  }

  async _ensure() {
    if (!this.supported) return { checked: false, issues: [], repaired: [] };
    let plan = planFirewall(await this.inspect(), { ruleName: this.ruleName, port: this.port });
    const repaired = [];
    if (plan.addRule || plan.removeIds.length) {
      const env = {
        GC_GD_EXE: this.exePath, GC_GD_RULE: this.ruleName, GC_GD_PORT: String(this.port),
        GC_GD_REMOVE: plan.removeIds.join('\n'), GC_GD_ADD: plan.addRule ? '1' : '0',
      };
      const res = await this.run(REPAIR_PS, env, this.timeoutMs);
      const out = parseJson(res.stdout);
      const lines = Array.isArray(out) ? out.map(String) : [String(res.stderr || (res.err && res.err.message) || 'no answer')];
      for (const line of lines) {
        if (line === 'removed' || line === 'added') repaired.push(line);
        else this.log.warn(`GateDrop firewall repair: ${line.slice(0, 300)}`);
      }
      if (plan.removeIds.length) this.log.info(`GateDrop firewall: ${plan.removeIds.length} block rule(s) for ${this.exePath} found (Windows security prompt) – removing`);
      if (plan.addRule) this.log.info(`GateDrop firewall: allow rule "${this.ruleName}" for TCP ${this.port} missing or wrong – creating`);
      plan = planFirewall(await this.inspect(), { ruleName: this.ruleName, port: this.port });
    }
    for (const i of plan.issues) this.log.warn(`GateDrop firewall: ${i.code}${i.detail ? ` (${i.detail})` : ''}`);
    if (!plan.issues.length) this.log.info(`GateDrop firewall: TCP ${this.port} open for the local network`);
    return { checked: true, issues: plan.issues, repaired };
  }
}

GateDropFirewall.planFirewall = planFirewall;
GateDropFirewall.INSPECT_PS = INSPECT_PS;
GateDropFirewall.REPAIR_PS = REPAIR_PS;

module.exports = GateDropFirewall;

'use strict';

// Medien (Stufe 4e) against the real Windows — the spike of Risiko 6 and the SMB way of Risiko 5. Runs in the CI job
// "Medien (Windows: VPN-Route, SMB)" (GC_MEDIA_SPIKE=1, elevated runner); elsewhere skipped (Windows only, it creates
// a network adapter, routes, a local user and a share).
//
//   1. GetBestRoute2 through koffi: the layout of MIB_IPFORWARD_ROW2 / SOCKADDR_INET (loopback, the default route).
//   2. The spike: a real wireguard-nt adapter (the driver of the app) gets the route of a network — as when the tunnel
//      carries the home network. Unbound, a connection to that network goes into the tunnel (and nowhere); bound to the
//      LAN address (localAddress) it goes through the LAN adapter (strong host model). Plan B: the host route of
//      MediaLanRoute (/32 through the LAN) brings the unbound way (SMB, the Explorer) back to the LAN; removed again.
//   3. SMB through Windows: a local share and user, WNetAddConnection2W without a drive letter, the folder and a range
//      through the UNC path, error 1219 for a second user on the same server, the connection cancelled.

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const dns = require('node:dns').promises;
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');

const MediaLanRoute = require('../src/services/media-lan-route');
const MediaNet = require('../src/services/media-net');
const { SmbShare, loadWnet } = require('../src/services/media-share');

const run = promisify(execFile);
const win = process.platform === 'win32';
const spike = win && process.env.GC_MEDIA_SPIKE === '1';
const skip = !win ? 'Windows only' : !spike ? 'set GC_MEDIA_SPIKE=1 (elevated: adapter, routes, a user and a share)' : false;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function connects(host, port, localAddress = null, timeoutMs = 3000) {
  return new Promise((resolve) => {
    const s = net.connect({ host, port, ...(localAddress ? { localAddress } : {}) });
    const done = (ok) => { clearTimeout(t); s.destroy(); resolve(ok); };
    const t = setTimeout(() => done(false), timeoutMs);
    s.once('connect', () => done(true));
    s.once('error', () => done(false));
  });
}

describe('Medien on Windows: GetBestRoute2 (koffi layout)', { skip: win ? false : 'Windows only' }, () => {
  it('loopback and the default way answer with their interface and source', () => {
    const api = MediaLanRoute.loadIphlp();
    assert.ok(api, 'iphlpapi through koffi');
    const lo = api.bestRoute('127.0.0.1');
    assert.equal(lo.error, 0);
    assert.equal(lo.source, '127.0.0.1');
    const out = api.bestRoute('8.8.8.8');
    assert.equal(out.error, 0);
    assert.ok(out.ifIndex > 0);
    const own = Object.values(os.networkInterfaces()).flat().filter((a) => a && !a.internal && a.family === 'IPv4').map((a) => a.address);
    assert.ok(own.includes(out.source), `${out.source} is one of ${own}`);
    console.log(`default way: interface ${out.ifIndex}, source ${out.source}, next hop ${out.nextHop}, metric ${out.metric}`);
  });
});

describe('Medien on Windows: the spike — LAN binding while the tunnel carries the network', { skip }, () => {
  const NAME = 'gcmediaspike';
  const TUN_IP = '10.99.77.2';
  let wg = null;
  let adapter = null;
  let tunIndex = null;
  let target = null;
  let network = null;
  let lan = null;

  before(async () => {
    const { address } = await dns.lookup('example.com', { family: 4 });
    target = address;
    network = `${target.split('.').slice(0, 3).join('.')}.0/24`;
    lan = MediaLanRoute.loadIphlp().bestRoute(target).source;
    const WireGuardNative = require('../src/services/wireguard-native');
    wg = new WireGuardNative({ info() {}, warn() {}, error() {}, debug() {} }, { resourcesPath: path.join(__dirname, '..', 'resources') });
    adapter = wg._createAdapter(Buffer.from(`${NAME}\0`, 'utf16le'), Buffer.from('GateControl\0', 'utf16le'), null);
    assert.ok(adapter, 'wireguard-nt adapter (elevated runner)');
    assert.ok(wg._setAdapterState(adapter, 1), 'adapter up');
    await run('netsh', ['interface', 'ip', 'set', 'address', NAME, 'static', TUN_IP, '255.255.255.0']);
    for (let i = 0; i < 60 && !tunIndex; i++) {
      const { stdout } = await run('powershell', ['-NoProfile', '-Command', `(Get-NetIPAddress -IPAddress ${TUN_IP} -ErrorAction SilentlyContinue).InterfaceIndex`]).catch(() => ({ stdout: '' }));
      const n = Number(String(stdout).trim());
      if (Number.isInteger(n) && n > 0) tunIndex = n;
      else await sleep(500);
    }
    assert.ok(tunIndex, 'the tunnel adapter has its address');
    // the tunnel carries the network of the target (as split routes with the home network), as the app sets routes
    await run('netsh', ['interface', 'ip', 'add', 'route', network, `interface=${tunIndex}`, `nexthop=${TUN_IP}`, 'metric=5', 'store=active']);
    await sleep(1500);
    console.log(`spike: target ${target} (${network} into the tunnel, interface ${tunIndex}), LAN address ${lan}`);
  });

  after(async () => {
    await run('netsh', ['interface', 'ip', 'delete', 'route', network, `interface=${tunIndex}`]).catch(() => {});
    if (adapter && wg) { try { wg._setAdapterState(adapter, 0); } catch { /* down */ } try { wg._closeAdapter(adapter); } catch { /* gone */ } }
  });

  it('unbound the way is the tunnel; bound to the LAN address the LAN adapter (diagnosis)', () => {
    // diagnose() takes home addresses only: for the public target GetBestRoute2 is asked directly
    const api = MediaLanRoute.loadIphlp();
    const free = api.bestRoute(target);
    const bound = api.bestRoute(target, lan);
    console.log(`free: ${JSON.stringify(free)} bound: ${JSON.stringify(bound)}`);
    assert.equal(free.ifIndex, tunIndex, 'unbound through the tunnel');
    assert.equal(free.source, TUN_IP);
    assert.notEqual(bound.ifIndex, tunIndex, 'bound: not the tunnel');
    assert.equal(bound.source, lan);
  });

  it('a real connection: unbound it dies in the tunnel, bound to the LAN address it arrives (HTTP too)', async () => {
    assert.equal(await connects(target, 80), false, 'unbound: into the tunnel');
    assert.equal(await connects(target, 80, lan), true, 'bound to the LAN address: through the LAN');
    const m = new MediaNet();
    try {
      const r = await m.request({ url: `http://${target}/`, headers: { Host: 'example.com' }, responseType: 'text', localAddress: lan, timeout: 8000 });
      assert.ok(r.status >= 200 && r.status < 500, `HTTP ${r.status}`);
    } finally { m.reset(); }
  });

  it('Plan B: the host route brings the unbound way (SMB, the Explorer) back to the LAN, and goes again', async () => {
    const api = MediaLanRoute.loadIphlp();
    const free = api.bestRoute(target);
    const bound = api.bestRoute(target, lan);
    assert.equal(free.ifIndex, tunIndex);
    const nextHop = bound.nextHop && bound.nextHop !== '0.0.0.0' ? bound.nextHop : '0.0.0.0';
    // the same netsh call as ensureHostRoute (which takes home addresses only)
    await run('netsh', ['interface', 'ipv4', 'add', 'route', `${target}/32`, `interface=${bound.ifIndex}`, `nexthop=${nextHop}`, 'metric=1', 'store=active']);
    try {
      await sleep(1000);
      const after1 = api.bestRoute(target);
      console.log(`with the host route: ${JSON.stringify(after1)}`);
      assert.equal(after1.ifIndex, bound.ifIndex, 'the /32 through the LAN wins over the tunnel\'s /24');
      assert.equal(await connects(target, 80), true, 'unbound: through the LAN again');
    } finally {
      await run('netsh', ['interface', 'ipv4', 'delete', 'route', `${target}/32`, `interface=${bound.ifIndex}`, `nexthop=${nextHop}`, 'store=active']).catch(() => {});
    }
    await sleep(1000);
    assert.equal(api.bestRoute(target).ifIndex, tunIndex, 'removed: the tunnel again');
  });

  it('MediaLanRoute with a home address in the tunnel: ensureHostRoute / removeHostRoutes', async () => {
    // 192.168.250.0/24 into the tunnel; the LAN has no such network: the bound way is the LAN's default gateway
    const nas = '192.168.250.20';
    await run('netsh', ['interface', 'ip', 'add', 'route', '192.168.250.0/24', `interface=${tunIndex}`, `nexthop=${TUN_IP}`, 'metric=5', 'store=active']);
    const route = new MediaLanRoute();
    try {
      await sleep(1000);
      const d = route.diagnose(nas, lan);
      console.log(`home address in the tunnel: ${JSON.stringify(d)}`);
      assert.equal(d.tunnel, true);
      assert.equal(d.bindingHolds, true);
      const r = await route.ensureHostRoute(nas, lan);
      assert.equal(r.ok, true, JSON.stringify(r));
      assert.equal(r.added, true);
      assert.equal(route.diagnose(nas, lan).tunnel, false);
    } finally {
      await route.removeHostRoutes();
      await run('netsh', ['interface', 'ip', 'delete', 'route', '192.168.250.0/24', `interface=${tunIndex}`]).catch(() => {});
    }
    await sleep(500);
    assert.equal(route.diagnose(nas, lan).tunnel, false, 'tunnel route gone as well');
  });
});

describe('Medien on Windows: SMB through Windows (UNC, WNetAddConnection2W, 1219)', { skip }, () => {
  const dir = path.join(os.tmpdir(), 'gcmedia-share');
  // at most 14 characters: net user asks a question for longer passwords
  const users = [['gcmedia1', 'Gc-Med1a#26xA'], ['gcmedia2', 'Gc-Med1a#26xB']];

  before(async () => {
    fs.mkdirSync(path.join(dir, 'Neu'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'Neu', 'Kobaltnacht (2025).mkv'), '0123456789');
    for (const [u] of users) await run('net', ['user', u, '/delete']).catch(() => {});
    for (const [u, pw] of users) await run('net', ['user', u, pw, '/add', '/Y']);
    await run('icacls', [dir, '/grant', 'gcmedia1:(OI)(CI)R', 'gcmedia2:(OI)(CI)R']);
    await run('net', ['share', `gcmedia=${dir}`, '/GRANT:gcmedia1,READ', '/GRANT:gcmedia2,READ']);
  });

  after(async () => {
    await run('net', ['use', '\\\\localhost\\gcmedia', '/delete', '/y']).catch(() => {});
    await run('net', ['share', 'gcmedia', '/delete', '/y']).catch(() => {});
    for (const [u] of users) await run('net', ['user', u, '/delete']).catch(() => {});
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('connects without a drive letter, lists, reads a range, 1219 for another user, cancels', async () => {
    const wnet = loadWnet();
    assert.ok(wnet, 'mpr.dll through koffi');
    const smb = new SmbShare({ source: { address: 'smb://localhost/gcmedia', userName: users[0][0], password: users[0][1] } });
    const c = await smb.connect();
    assert.equal(c.ok, true, JSON.stringify(c));
    const { stdout } = await run('net', ['use']);
    console.log(stdout);
    assert.ok(!/^\w*\s+[A-Z]:\s+\\\\localhost\\gcmedia/im.test(stdout), 'no drive letter');
    const list = await smb.list('Neu');
    assert.deepEqual(list.value.map((e) => e.name), ['Kobaltnacht (2025).mkv']);
    assert.equal((await smb.read('Neu/Kobaltnacht (2025).mkv', 3, 4)).value.toString(), '3456');
    const o = (await smb.open('Neu/Kobaltnacht (2025).mkv', { start: 6, end: 8 })).value;
    let text = '';
    for await (const ch of o.stream) text += ch.toString();
    assert.equal(text, '678');
    const other = new SmbShare({ source: { address: 'smb://localhost/gcmedia', userName: users[1][0], password: users[1][1] } });
    const conflict = await other.connect();
    console.log(`second user on the same server: ${JSON.stringify(conflict)}`);
    assert.equal(conflict.code, 'smb_conflict');
    assert.equal(conflict.winError, 1219);
    const explorer = new SmbShare({ source: { address: 'smb://localhost/gcmedia', userName: users[1][0], password: users[1][1], useExisting: true } });
    assert.equal((await explorer.list('Neu')).ok, true, 'with the existing connection');
    const wrong = new SmbShare({ source: { address: 'smb://localhost/gcmedia-gibtsnicht', userName: users[0][0], password: users[0][1] } });
    console.log(`missing share: ${JSON.stringify(await wrong.connect())}`);
    await smb.close();
    const after1 = await run('net', ['use']);
    assert.ok(!after1.stdout.toLowerCase().includes('\\\\localhost\\gcmedia'), 'cancelled again');
  });
});

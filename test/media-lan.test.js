'use strict';

// Medien (Stufe 4e, spike): which way a connection to the NAS takes — the LAN adapter to bind to (never the VPN),
// the tunnel's own address away, the verdict of the route diagnosis and the host route of Plan B (netsh faked;
// against the real Windows in media.win.test.js).

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const L = require('../src/utils/media-lan');
const MediaLanRoute = require('../src/services/media-lan-route');

const ifaces = {
  Ethernet: [{ address: '192.168.1.37', netmask: '255.255.255.0', family: 'IPv4', internal: false, cidr: '192.168.1.37/24' }],
  'WLAN': [{ address: '10.0.3.4', netmask: '255.255.0.0', family: 'IPv4', internal: false }],
  gatecontrol0: [{ address: '10.8.0.2', family: 'IPv4', internal: false, cidr: '10.8.0.2/24' }],
  'vEthernet (WSL)': [{ address: '172.20.0.1', family: 'IPv4', internal: false, cidr: '172.20.0.1/20' }],
  'Loopback Pseudo-Interface 1': [{ address: '127.0.0.1', family: 'IPv4', internal: true, cidr: '127.0.0.1/8' }],
};

describe('media-lan', () => {
  it('the LAN adapter whose subnet has the NAS; never the VPN or a virtual switch', () => {
    assert.deepEqual(L.lanBinding('192.168.1.20', ifaces), { localAddress: '192.168.1.37', iface: 'Ethernet', prefix: 24, network: '192.168.1.0/24' });
    assert.deepEqual(L.lanBinding('10.0.200.9', ifaces), { localAddress: '10.0.3.4', iface: 'WLAN', prefix: 16, network: '10.0.0.0/16' }, 'netmask without cidr');
    assert.equal(L.lanBinding('10.8.0.1', ifaces), null, 'the tunnel network is no LAN');
    assert.equal(L.lanBinding('172.20.0.5', ifaces), null, 'nor a virtual switch');
    assert.equal(L.lanBinding('192.168.2.20', ifaces), null, 'another subnet: not here');
    assert.equal(L.lanBinding('nas', ifaces), null);
    assert.equal(L.lanBinding('192.168.1.37', ifaces), null, 'not this PC itself');
    assert.deepEqual(L.lanLinks(ifaces).map((l) => l.iface), ['Ethernet', 'WLAN']);
  });

  it('away: the own address in the tunnel', () => {
    assert.equal(L.tunnelAddress(ifaces), '10.8.0.2');
    assert.equal(L.tunnelAddress({ Ethernet: ifaces.Ethernet }), null);
  });

  it('the verdict of the route diagnosis', () => {
    // on its own through the LAN: nothing to do
    assert.deepEqual(L.routeVerdict('192.168.1.37', { ifIndex: 12, source: '192.168.1.37' }, { ifIndex: 12, source: '192.168.1.37' }), { tunnel: false, bindingHolds: true, hostRoute: false });
    // the tunnel carries the home network, bound to the LAN address it takes the LAN adapter: HTTP fine, SMB needs the route
    assert.deepEqual(L.routeVerdict('192.168.1.37', { ifIndex: 40, source: '10.8.0.2' }, { ifIndex: 12, source: '192.168.1.37' }), { tunnel: true, bindingHolds: true, hostRoute: true });
    // weak host send: the binding does not hold
    assert.deepEqual(L.routeVerdict('192.168.1.37', { ifIndex: 40, source: '10.8.0.2' }, { ifIndex: 40, source: '192.168.1.37' }), { tunnel: true, bindingHolds: false, hostRoute: true });
  });
});

describe('MediaLanRoute (Plan B: a host route for the NAS through the LAN)', () => {
  function fake() {
    const state = { route: false, calls: [] };
    const api = {
      bestRoute(dest, source) {
        if (source === '192.168.1.37' || state.route) return { error: 0, ifIndex: 12, nextHop: '0.0.0.0', metric: 25, source: '192.168.1.37' };
        return { error: 0, ifIndex: 40, nextHop: '0.0.0.0', metric: 5, source: '10.8.0.2' };
      },
    };
    const run = async (file, args) => {
      state.calls.push([file, ...args]);
      if (args[2] === 'add') state.route = true;
      if (args[2] === 'delete') state.route = false;
      return { stdout: 'Ok.' };
    };
    return { state, route: new MediaLanRoute({ api, run }) };
  }

  it('the tunnel would carry the NAS: the route for its address alone, in memory only, removed again', async () => {
    const { state, route } = fake();
    const d = route.diagnose('192.168.1.20', '192.168.1.37');
    assert.equal(d.tunnel, true);
    assert.equal(d.bindingHolds, true);
    const r = await route.ensureHostRoute('192.168.1.20', '192.168.1.37');
    assert.equal(r.ok, true);
    assert.equal(r.added, true);
    assert.deepEqual(state.calls[0], ['netsh', 'interface', 'ipv4', 'add', 'route', '192.168.1.20/32', 'interface=12', 'nexthop=0.0.0.0', 'metric=1', 'store=active']);
    assert.equal(r.diagnosis.tunnel, false);
    assert.deepEqual(route.routes(), ['192.168.1.20']);
    await route.removeHostRoutes();
    assert.deepEqual(state.calls[1].slice(0, 6), ['netsh', 'interface', 'ipv4', 'delete', 'route', '192.168.1.20/32']);
    assert.deepEqual(route.routes(), []);
  });

  it('no route when the way is the LAN already; nothing but private IPv4; not on other systems', async () => {
    const api = { bestRoute: () => ({ error: 0, ifIndex: 12, nextHop: '0.0.0.0', metric: 25, source: '192.168.1.37' }) };
    const calls = [];
    const route = new MediaLanRoute({ api, run: async (...a) => { calls.push(a); } });
    assert.deepEqual((await route.ensureHostRoute('192.168.1.20', '192.168.1.37')).added, false);
    assert.equal(calls.length, 0);
    assert.equal((await route.ensureHostRoute('8.8.8.8', '192.168.1.37')).code, 'invalid');
    assert.equal((await new MediaLanRoute({ api: null }).ensureHostRoute('192.168.1.20', '192.168.1.37')).code, 'unsupported');
  });

  it('SOCKADDR_INET of an IPv4 address', () => {
    const b = MediaLanRoute.sockaddr('192.168.1.20');
    assert.equal(b.length, 28);
    assert.equal(b.readUInt16LE(0), 2);
    assert.equal(MediaLanRoute.ipOf(b), '192.168.1.20');
  });
});

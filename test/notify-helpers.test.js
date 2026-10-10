'use strict';

// Small helpers of the notification center: kill-switch path check, tray
// badge, tray menu entries, portal pages for open_portal.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { parseWgEndpoint, checkPushPath, isTunnelOnly } = require('../src/utils/push-path');
const { renderTrayIcon, TRAY_ICON_SIZE } = require('../src/utils/tray-icon');
const { notifyMenuItems } = require('../src/utils/notify-menu');
const { createPortalOpener, portalPageUrl } = require('../src/utils/portal');
const i18n = require('../src/i18n');

const lookup = (map) => async (host) => {
  if (!map[host]) throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' });
  return map[host].map((address) => ({ address, family: 4 }));
};

describe('push path (kill switch)', () => {
  it('parses the WireGuard endpoint', () => {
    assert.deepEqual(parseWgEndpoint('[Peer]\nPublicKey = x\nEndpoint = vpn.example.com:51820\n'), { host: 'vpn.example.com', port: 51820 });
    assert.deepEqual(parseWgEndpoint('Endpoint=203.0.113.4:443'), { host: '203.0.113.4', port: 443 });
    assert.deepEqual(parseWgEndpoint('Endpoint = [2001:db8::1]:51820'), { host: '2001:db8::1', port: 51820 });
    assert.equal(parseWgEndpoint('Endpoint = bad host:1'), null);
    assert.equal(parseWgEndpoint(null), null);
  });

  it('covered when the server URL resolves to the endpoint IPs on 443', async () => {
    const p = await checkPushPath({ serverUrl: 'https://gc.example.com', wgConfig: 'Endpoint = vpn.example.com:51820', lookup: lookup({ 'gc.example.com': ['203.0.113.4'], 'vpn.example.com': ['203.0.113.4', '203.0.113.5'] }) });
    assert.deepEqual([p.sameHost, p.port443, p.coveredByKillSwitch], [false, true, true]);
    assert.equal(isTunnelOnly(p, true), false);
  });

  it('not covered for other IPs or another port → tunnel only with the kill switch on', async () => {
    const other = await checkPushPath({ serverUrl: 'https://gc.example.com', wgConfig: 'Endpoint = vpn.example.com:51820', lookup: lookup({ 'gc.example.com': ['198.51.100.1'], 'vpn.example.com': ['203.0.113.4'] }) });
    assert.equal(other.coveredByKillSwitch, false);
    assert.equal(isTunnelOnly(other, true), true);
    assert.equal(isTunnelOnly(other, false), false);
    const port = await checkPushPath({ serverUrl: 'https://203.0.113.4:8443', wgConfig: 'Endpoint = 203.0.113.4:51820', lookup: lookup({}) });
    assert.deepEqual([port.sameHost, port.port443, port.coveredByKillSwitch], [true, false, false]);
  });

  it('unknown without config or DNS (no warning)', async () => {
    const none = await checkPushPath({ serverUrl: 'https://gc.example.com', wgConfig: null, lookup: lookup({}) });
    assert.equal(none.coveredByKillSwitch, null);
    assert.equal(isTunnelOnly(none, true), false);
    const nodns = await checkPushPath({ serverUrl: 'https://gc.example.com', wgConfig: 'Endpoint = vpn.example.com:51820', lookup: lookup({}) });
    assert.equal(nodns.coveredByKillSwitch, null);
    const same = await checkPushPath({ serverUrl: 'https://gc.example.com', wgConfig: 'Endpoint = GC.example.com:51820', lookup: lookup({}) });
    assert.equal(same.coveredByKillSwitch, true, 'same host name, port 443, DNS down');
    assert.equal((await checkPushPath({ serverUrl: 'not a url' })).serverHost, null);
  });
});

describe('tray badge', () => {
  it('adds a blue dot top right, leaves the plain icon unchanged', () => {
    const plain = renderTrayIcon('connected');
    assert.deepEqual(renderTrayIcon('connected', {}).buffer, plain.buffer);
    const badge = renderTrayIcon('connected', { badge: true });
    const px = (buf, x, y) => [...buf.subarray((y * TRAY_ICON_SIZE + x) * 4, (y * TRAY_ICON_SIZE + x) * 4 + 4)];
    assert.deepEqual(px(badge.buffer, 25, 7), [0x3B, 0x82, 0xF6, 255]);
    assert.deepEqual(px(badge.buffer, 4, 28), px(plain.buffer, 4, 28));
    assert.notDeepEqual(badge.buffer, plain.buffer);
  });
});

describe('notifyMenuItems', () => {
  const t = i18n.t;
  it('shows unread count and the DND toggle', () => {
    const calls = [];
    const items = notifyMenuItems({ unread: 2, dnd: { active: false }, t, openInbox: () => calls.push('inbox'), setDnd: (a) => calls.push(a) });
    assert.deepEqual(items.map((i) => i.label), ['Mitteilungen · 2 neu', 'Nicht stören für 1 Stunde']);
    items.forEach((i) => i.click());
    assert.deepEqual(calls, ['inbox', { minutes: 60 }]);
    const on = notifyMenuItems({ unread: 0, dnd: { active: true }, t, openInbox() {}, setDnd: (a) => calls.push(a) });
    assert.deepEqual(on.map((i) => i.label), ['Mitteilungen', 'Nicht stören beenden']);
    on[1].click();
    assert.equal(calls[2], null);
    assert.deepEqual(notifyMenuItems({ enabled: false, t, openInbox() {}, setDnd() {} }), []);
  });

  it('has English strings', () => {
    i18n.setLocale('en');
    try {
      assert.equal(notifyMenuItems({ unread: 3, dnd: { active: false }, t, openInbox() {}, setDnd() {} })[0].label, 'Notifications · 3 new');
      assert.equal(t('push.priority.critical'), 'Critical');
    } finally {
      i18n.setLocale('de');
    }
  });
});

describe('portal pages (open_portal)', () => {
  it('portalPageUrl keeps the portal origin', () => {
    assert.equal(portalPageUrl('https://gc.example.com/portal', '/portal/notify?x=1'), 'https://gc.example.com/portal/notify?x=1');
    assert.equal(portalPageUrl('https://gc.example.com/portal', '//evil.example/x'), null);
    assert.equal(portalPageUrl('https://gc.example.com/portal', 'https://evil.example'), null);
    assert.equal(portalPageUrl('https://gc.example.com/portal', '/\\evil'), null);
  });

  it('open({ path }) opens the page; open() still uses the login link', async () => {
    const opened = [];
    const opener = createPortalOpener({
      apiClient: { getPortalLink: async () => 'https://gc.example.com/auto?t=secret' },
      getPortalUrl: () => 'https://gc.example.com/portal',
      getShell: () => ({ openExternal: async (u) => opened.push(u) }),
    });
    assert.equal(await opener.open({ path: '/portal/notify' }), true);
    assert.equal(await opener.open(), true);
    assert.equal(await opener.open({ path: '//evil.example' }), false);
    assert.deepEqual(opened, ['https://gc.example.com/portal/notify', 'https://gc.example.com/auto?t=secret']);
  });
});

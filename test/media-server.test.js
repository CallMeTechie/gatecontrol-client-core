'use strict';

// Medien-Plugin (W1): the pure parts of the server's sources (utils/media-server.js) — the list of GET v1/sources as
// the contract gives it, the entries a share takes (SMB and WebDAV half), merging with what this PC keeps (the access
// kept, another linked user signs in again, sources of this PC taken over by serverId / address, the rest dropped),
// the 30 / 90 days, the network rule, the silent revoke, the plugin list, the refusals.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const MSV = require('../src/utils/media-server');

const PIN = '9c41'.padEnd(64, '0');
const list = (over = {}) => ({
  ok: true, v: 1, rev: 'rVdEa3gRkVX1W', at: '2026-11-25T19:02:11.000Z', media: true, maxOfflineDays: 90, offlineHintDays: 30,
  network: {
    rule: 'home_direct_away_vpn', vpnRequiredAway: true,
    home: { probes: [
      { kind: 'jellyfin', url: 'http://192.168.1.20:8096/System/Info/Public', serverId: '4F1CA9' },
      { kind: 'tls', url: 'https://192.168.1.20:5006/filme', certSha256: PIN },
      { kind: 'jellyfin', url: 'http://jellyfin.example.test/System/Info/Public', serverId: 'x' },
    ] },
  },
  cast: { enabled: true },
  sources: [
    {
      id: 'jf-1', kind: 'jellyfin', name: 'DS918+', serverId: '4f1ca9', version: '10.10.7', address: 'http://192.168.1.20:8096',
      home: { address: 'http://192.168.1.20:8096' }, away: { mode: 'vpn' }, user: { id: 'a71e', name: 'mila' }, problem: null,
      device: { id: 'gc-7Hq2mXk4Rb9tLp0sVw3N', name: 'GateControl · Büro-PC' }, paired: false, quickConnect: true, downloads: true, alwaysOriginal: false,
      future: { ignored: true },
    },
    {
      id: 'sh-1', kind: 'share', name: 'Filme', folder: 'filme', smb: { address: 'smb://192.168.1.20/filme' },
      webdav: { address: 'https://192.168.1.20:5006/filme', certSha256: PIN }, user: 'medien-lesen', secretRev: 3, away: { mode: 'vpn' },
    },
    { id: '../x', kind: 'jellyfin', name: 'bad', address: 'http://192.168.1.20:8096' },
    { id: 'jf-2', kind: 'jellyfin', name: 'no address', address: 'ftp://x' },
    { id: 'sh-9', kind: 'printer' },
  ],
  ...over,
});

describe('normalizeList', () => {
  it('the contract\'s answer: sources, probes, days, unknown fields left out, broken sources skipped', () => {
    const l = MSV.normalizeList(list());
    assert.equal(l.rev, 'rVdEa3gRkVX1W');
    assert.equal(l.maxOfflineDays, 90);
    assert.equal(l.offlineHintDays, 30);
    assert.deepEqual(l.sources.map((s) => s.id), ['jf-1', 'sh-1']);
    const jf = l.sources[0];
    assert.deepEqual(jf.away, { mode: 'vpn', address: null });
    assert.deepEqual(jf.device, { id: 'gc-7Hq2mXk4Rb9tLp0sVw3N', name: 'GateControl · Büro-PC' });
    assert.equal(jf.future, undefined);
    assert.equal(l.network.vpnRequiredAway, true);
    assert.deepEqual(l.network.probes.map((p) => p.kind), ['jellyfin', 'tls'], 'a probe that is not in a private network is none');
    assert.equal(l.network.probes[0].serverId, '4f1ca9', 'compared in lower case');
    assert.equal(l.cast.enabled, true);
  });

  it('away without VPN only with an https:// address (fail closed); no user → no_mapping; unchanged; no v1', () => {
    const l = MSV.normalizeList(list({
      sources: [
        { id: 'jf-1', kind: 'jellyfin', name: 'a', address: 'http://192.168.1.20:8096', away: { mode: 'direct', address: 'http://jellyfin.example.test' }, user: null },
        { id: 'jf-2', kind: 'jellyfin', name: 'b', address: 'http://192.168.1.21:8096', away: { mode: 'direct', address: 'https://jellyfin.example.test/' }, user: { id: 'u', name: 'n' } },
      ],
    }));
    assert.deepEqual(l.sources[0].away, { mode: 'vpn', address: null });
    assert.equal(l.sources[0].problem, 'no_mapping');
    assert.deepEqual(l.sources[1].away, { mode: 'direct', address: 'https://jellyfin.example.test' });
    assert.deepEqual(MSV.normalizeList({ ok: true, v: 1, rev: 'r1', unchanged: true, at: 'x' }), { unchanged: true, rev: 'r1', at: 'x' });
    assert.equal(MSV.normalizeList({ ok: true, v: 2, sources: [] }), null);
    assert.equal(MSV.normalizeList({ ok: false, v: 1, code: 'x' }), null);
    assert.deepEqual(MSV.normalizeList(list({ media: false })).sources, [], 'without the right "Medien" no source');
  });
});

describe('entriesOf / merge', () => {
  const sources = () => MSV.normalizeList(list()).sources;

  it('a share is a pair: SMB under its id, WebDAV beside it; only WebDAV takes the id', () => {
    const [jf, sh] = sources();
    const [j] = MSV.entriesOf(jf);
    assert.equal(j.jfDeviceId, 'gc-7Hq2mXk4Rb9tLp0sVw3N');
    assert.equal(j.mapUserId, 'a71e');
    assert.equal(j.managed, true);
    const e = MSV.entriesOf(sh);
    assert.deepEqual(e.map((x) => [x.id, x.kind, x.pairWith]), [['sh-1', 'smb', 'sh-1_w'], ['sh-1_w', 'webdav', 'sh-1']]);
    assert.equal(e[1].tlsPin, PIN, 'the admin\'s pin');
    assert.equal(MSV.visibleId('sh-1_w'), 'sh-1');
    const only = MSV.entriesOf({ ...sh, smb: null });
    assert.deepEqual(only.map((x) => [x.id, x.kind]), [['sh-1', 'webdav']]);
    assert.ok(!JSON.stringify(e).includes('password'));
  });

  it('kept: the access of this PC, the password, "Immer Original"; another linked user signs in again', () => {
    const first = MSV.merge([], sources());
    const withAccess = first.list.map((x) => (x.kind === 'jellyfin' ? { ...x, token: 'tok', userId: 'a71e', pairedUserId: 'a71e', alwaysOriginal: true }
      : { ...x, password: 'pw', pwRev: 3 }));
    const again = MSV.merge(withAccess, sources());
    assert.equal(again.list[0].token, 'tok');
    assert.equal(again.list[0].alwaysOriginal, true);
    assert.equal(again.list[1].password, 'pw');
    assert.deepEqual(again.repair, []);
    const other = sources();
    other[0].user = { id: 'b22f', name: 'jonas' };
    const m = MSV.merge(withAccess, other);
    assert.equal(m.list[0].token, null);
    assert.deepEqual(m.repair, ['jf-1']);
    const gone = MSV.merge(withAccess, [other[0]]);
    assert.deepEqual(gone.removed.map((x) => x.id), ['sh-1', 'sh-1_w']);
  });

  it('taken over once (33 a): the same Jellyfin server, the same share address; the rest dropped, old access signed out', () => {
    const local = [
      { id: 'loc1', kind: 'jellyfin', name: 'DS918+', address: 'http://192.168.1.20:8096', serverId: '4F1CA9', token: 'old-tok', alwaysOriginal: true },
      { id: 'loc2', kind: 'smb', name: 'nas', address: 'smb://192.168.1.20/filme' },
      { id: 'loc3', kind: 'webdav', name: 'other', address: 'https://192.168.1.30/x' },
      { id: 'loc4', kind: 'jellyfin', name: 'Alt', address: 'http://192.168.1.40:8096', serverId: 'zz', token: 'tok4' },
    ];
    const m = MSV.merge(local, sources());
    assert.deepEqual(m.adopted.map((a) => [a.from, a.to]), [['loc1', 'jf-1'], ['loc2', 'sh-1']]);
    assert.equal(m.list[0].alwaysOriginal, true);
    assert.equal(m.list[0].token, undefined, 'the old access is not taken: the plugin\'s device replaces it');
    assert.deepEqual(m.dropped.map((x) => x.id), ['loc3', 'loc4']);
    assert.deepEqual(m.logout.map((x) => x.id), ['loc1', 'loc4']);
    assert.ok(m.list.every((x) => x.managed));
  });
});

describe('times, the network rule, signals', () => {
  it('30 days a note, 90 days the passwords go', () => {
    const day = MSV.DAY_MS;
    assert.deepEqual(MSV.offline(100 * day, 71 * day, 30, 90), { days: 29, hint: false, expired: false });
    assert.deepEqual(MSV.offline(100 * day, 70 * day, 30, 90), { days: 30, hint: true, expired: false });
    assert.equal(MSV.offline(100 * day, 10 * day, 30, 90).expired, true);
    assert.equal(MSV.offline(100 * day, null).hint, false, 'never reached: nothing to count');
  });

  it('home direct; away only through the VPN, else blocked; the admin\'s exception direct', () => {
    assert.equal(MSV.wayOf({ atHome: true, awayMode: 'vpn', tunnelUp: true }), 'home', 'at home never through the tunnel');
    assert.equal(MSV.wayOf({ atHome: false, awayMode: 'vpn', tunnelUp: true }), 'vpn');
    assert.equal(MSV.wayOf({ atHome: false, awayMode: 'vpn', tunnelUp: false }), 'blocked');
    assert.equal(MSV.wayOf({ atHome: false, awayMode: 'direct', tunnelUp: false }), 'direct');
  });

  it('at home only by GateControl\'s home network: same_lan with a site; directly only a gateway site; probes never', () => {
    const own = { ok: true, same_lan: true, via: 'tunnel', site: { type: 'server' } };
    const gw = { ok: true, same_lan: true, via: 'direct', site: { type: 'gateway', gatewayId: 3, name: 'NAS' } };
    assert.equal(MSV.homeNetworkOf(own, { tunnelUp: true }), true);
    assert.equal(MSV.homeNetworkOf(own, { tunnelUp: false }), false, 'asked without the tunnel');
    assert.equal(MSV.homeNetworkOf({ ...own, via: 'direct' }, { tunnelUp: true }), false, 'a direct "own LAN"');
    assert.equal(MSV.homeNetworkOf(gw, { tunnelUp: false }), true);
    assert.equal(MSV.homeNetworkOf({ ...gw, via: 'tunnel' }, { tunnelUp: true }), true);
    assert.equal(MSV.homeNetworkOf({ ...own, same_lan: false }, { tunnelUp: true }), false);
    assert.equal(MSV.homeNetworkOf({ ...own, site: null }, { tunnelUp: true }), false);
    assert.equal(MSV.homeNetworkOf({ ...own, site: { type: 'other' } }, { tunnelUp: true }), false);
    assert.equal(MSV.homeNetworkOf({ ...own, ok: false }, { tunnelUp: true }), false);
    assert.equal(MSV.homeNetworkOf({ ...own, same_lan: 'true' }, { tunnelUp: true }), false);
    assert.equal(MSV.homeNetworkOf(null), false);
    // a tcp probe of the plugin (1.0.1) is no proof of anything: dropped from the list
    assert.equal(MSV.probeOf({ kind: 'tcp', host: '192.168.1.30', port: 445, sourceId: 'sh-2', unique: false }), null);
    assert.equal(MSV.probeOf({ kind: 'tcp', url: 'http://192.168.1.30:445/', unique: false }), null);
  });

  it('media.revoke, the plugin list, the refusals', () => {
    assert.deepEqual(MSV.revokeOf({ kind: 'media.revoke', sourceIds: null, reason: 'device_removed' }), { sourceIds: null, reason: 'device_removed' });
    assert.deepEqual(MSV.revokeOf({ kind: 'media.revoke', sourceIds: ['jf-1', 'x'], reason: 'odd' }), { sourceIds: ['jf-1'], reason: 'admin' });
    assert.equal(MSV.revokeOf({ kind: 'media.revoke', sourceIds: ['x'] }), null);
    assert.equal(MSV.revokeOf({ kind: 'media.cast' }), null);
    assert.equal(MSV.isSignal({ topic: MSV.SIGNAL_TOPIC }), true);
    assert.deepEqual(MSV.pluginOf({ plugins: [{ id: MSV.PLUGIN_ID, version: '1.0.0', tab: { label: 'Medien' } }] }), { installed: true, tab: { label: 'Medien' }, version: '1.0.0' });
    assert.equal(MSV.pluginOf({ plugins: [{ id: MSV.PLUGIN_ID, tab: null }] }).tab, null);
    assert.equal(MSV.refusalOf({ code: 'not_found', body: { reason: 'plugin_unavailable' } }), 'unavailable');
    assert.equal(MSV.refusalOf({ code: 'license_required' }), 'unavailable');
    assert.equal(MSV.refusalOf({ code: 'no_access' }), 'no_access');
    assert.equal(MSV.refusalOf({ code: 'no_mapping' }), 'problem');
    assert.equal(MSV.refusalOf({ code: 'network' }), 'retry');
  });
});

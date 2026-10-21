'use strict';

// GateDrop pure helpers (utils/gatedrop.js, utils/gatedrop-shell.js): names,
// LAN addresses, tolerant parsing of the plugin's answers and pushes,
// "Senden an" arguments and shortcut, and the gatedrop.* texts.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const gd = require('../src/utils/gatedrop');
const shellUtil = require('../src/utils/gatedrop-shell');
const de = require('../src/i18n/locales/de.json');
const en = require('../src/i18n/locales/en.json');

const KEY_B64 = crypto.randomBytes(32).toString('base64');

describe('GateDrop names', () => {
  it('X-GD-Name is base64url of UTF-8', () => {
    const name = 'Angebot Küche – März 📄.pdf';
    const enc = gd.encodeName(name);
    assert.match(enc, /^[A-Za-z0-9_-]+$/);
    assert.equal(gd.decodeName(enc), name);
    assert.equal(gd.decodeName('not base64!'), null);
    assert.equal(gd.decodeName(Buffer.from([0xff, 0xfe]).toString('base64url')), null);
  });

  it('path traversal names are recognised', () => {
    for (const n of ['../evil.exe', '..\\evil.exe', 'a/b.txt', 'C:\\Windows\\x.dll', 'C:x', '..', '.', '', 'x\u0000.txt']) assert.equal(gd.isTraversalName(n), true, n);
    for (const n of ['bericht.pdf', '..hidden', 'a..b.txt']) assert.equal(gd.isTraversalName(n), false, n);
  });

  it('safe file names for Windows', () => {
    assert.equal(gd.safeFileName('../../etc/passwd'), 'passwd');
    assert.equal(gd.safeFileName('a<b>c:d"e|f?g*h.txt'), 'a_b_c_d_e_f_g_h.txt');
    assert.equal(gd.safeFileName('CON.txt'), '_CON.txt');
    assert.equal(gd.safeFileName('nul'), '_nul');
    assert.equal(gd.safeFileName('report.pdf. . '), 'report.pdf');
    assert.equal(gd.safeFileName('\u0007\u0001'), null);
    assert.equal(gd.safeFileName('..', 'datei'), 'datei');
    const long = gd.safeFileName(`${'x'.repeat(300)}.jpeg`);
    assert.equal(long.length, 180);
    assert.ok(long.endsWith('.jpeg'));
    assert.equal(gd.numberedName('Bericht.pdf', 2), 'Bericht (2).pdf');
    assert.equal(gd.numberedName('README', 3), 'README (3)');
  });

  it('encrypted size adds one tag per started MiB', () => {
    assert.equal(gd.encryptedSize(0), 0);
    assert.equal(gd.encryptedSize(1), 17);
    assert.equal(gd.encryptedSize(gd.BLOCK_SIZE), gd.BLOCK_SIZE + 16);
    assert.equal(gd.encryptedSize(gd.BLOCK_SIZE + 1), gd.BLOCK_SIZE + 1 + 32);
  });
});

describe('GateDrop LAN', () => {
  it('private IPv4 only', () => {
    for (const ip of ['10.0.0.1', '172.16.5.4', '172.31.255.1', '192.168.178.20']) assert.equal(gd.isPrivateIPv4(ip), true, ip);
    for (const ip of ['8.8.8.8', '172.32.0.1', '127.0.0.1', '169.254.1.1', '100.64.0.1', '192.169.0.1', '::1', 'x']) assert.equal(gd.isPrivateIPv4(ip), false, ip);
  });

  it('LAN addresses skip tunnels, loopback and public addresses', () => {
    const list = gd.lanAddresses({
      Ethernet: [{ family: 'IPv4', address: '192.168.178.20', netmask: '255.255.255.0', internal: false, cidr: '192.168.178.20/24' }, { family: 'IPv6', address: 'fe80::1', internal: false }],
      'WLAN': [{ family: 'IPv4', address: '10.1.2.3', netmask: '255.255.0.0', internal: false }],
      gatecontrol0: [{ family: 'IPv4', address: '10.8.0.5', netmask: '255.255.255.0', internal: false }],
      'Loopback Pseudo-Interface 1': [{ family: 'IPv4', address: '127.0.0.1', netmask: '255.0.0.0', internal: true }],
      Mobile: [{ family: 'IPv4', address: '80.1.2.3', netmask: '255.255.255.0', internal: false }],
    });
    assert.deepEqual(list.map((a) => [a.ip, a.prefix]), [['10.1.2.3', 16], ['192.168.178.20', 24]]);
    assert.equal(gd.sameSubnet('192.168.178.20', '192.168.178.99', 24), true);
    assert.equal(gd.sameSubnet('192.168.178.20', '192.168.1.99', 24), false);
  });

  it('candidates: private ip:port only', () => {
    assert.deepEqual(gd.parseCandidate('192.168.1.5:47731'), { host: '192.168.1.5', port: 47731 });
    assert.equal(gd.parseCandidate('8.8.8.8:47731'), null);
    assert.equal(gd.parseCandidate('192.168.1.5:0'), null);
    assert.equal(gd.parseCandidate('evil.example:80'), null);
    assert.equal(gd.parseCandidate('192.168.1.5'), null);
  });
});

describe('GateDrop answers', () => {
  it('targets: cleaned, unknown entries dropped', () => {
    const t = gd.normalizeTargets({
      me: { canLink: true, canNas: 'yes' },
      people: [{ id: 8, name: 'Anna', avatar: '/avatars/annaAvatarFile0001.webp', kind: 'user' }, { id: 'family', name: 'Familie', kind: 'family' }, { id: { x: 1 } }, { id: 9, avatar: 'https://evil/x.png' }],
      devices: [{ id: 'tok_12', name: 'Pixel', platform: 'android', online: true, direct: true }, { name: 'no id' }],
      nas: [{ id: 'n1', label: 'Fotos', path: '/Familie/Fotos' }],
      links: { enabled: true },
      future: 1,
    });
    assert.deepEqual(t.me, { canLink: true, canNas: false });
    assert.deepEqual(t.people.map((p) => [p.id, p.kind, p.avatar]), [['8', 'user', '/avatars/annaAvatarFile0001.webp'], ['family', 'family', null], ['9', 'user', null]]);
    assert.deepEqual(t.devices, [{ id: 'tok_12', name: 'Pixel', platform: 'android', online: true, direct: true, self: false }]);
    assert.deepEqual(t.nas, [{ id: 'n1', label: 'Fotos', path: '/Familie/Fotos' }]);
    assert.equal(t.links.enabled, true);
    assert.deepEqual(gd.normalizeTargets(null).people, []);
  });

  it('send result with direct entries and a link', () => {
    const r = gd.normalizeSendResult({
      id: 41,
      deliveries: [{ kind: 'device', target: 'tok_12', status: 'direct', via: 'direct' }, { kind: 'alien' }],
      link: { url: 'https://gc.example/s/abcdefghijklmnopqrstuv', pin: '4711' },
      direct: [
        { deviceId: 'tok_12', transferId: 'tr_1', mode: 'push', candidates: ['192.168.1.5:47731', 'bad', 'x:1'], key: KEY_B64, ticket: 'tkt_abcdefghijkl' },
        { deviceId: 'tok_13', transferId: 'tr_2', mode: 'sideways', key: KEY_B64, ticket: 'tkt_abcdefghijkl' },
        { deviceId: 'tok_14', transferId: 'tr_3', mode: 'pull', key: 'short', ticket: 'tkt_abcdefghijkl' },
      ],
    });
    assert.equal(r.id, '41');
    assert.equal(r.deliveries.length, 1);
    assert.deepEqual(r.link, { url: 'https://gc.example/s/abcdefghijklmnopqrstuv', pin: '4711' });
    assert.equal(r.direct.length, 1);
    assert.deepEqual(r.direct[0].candidates, ['192.168.1.5:47731']);
    assert.equal(r.direct[0].key.length, 32);
  });

  it('push data: direct transfer and server send', () => {
    const d = gd.parsePushData({ gatedrop: { transfer: 'tr_9', mode: 'pull', from: { name: 'Pixel', deviceId: 'tok_1' }, items: [{ name: '../a.jpg', bytes: 12, mime: 'image/jpeg' }], candidates: ['192.168.1.9:47731'], key: KEY_B64, ticket: 'tkt_abcdefghijkl' } });
    assert.equal(d.kind, 'direct');
    assert.equal(d.items[0].name, 'a.jpg');
    assert.equal(d.items[0].index, 0);
    assert.equal(d.from.name, 'Pixel');
    const s = gd.parsePushData({ gatedrop: { send: 77 } });
    assert.deepEqual([s.kind, s.sendId, s.send], ['send', '77', null]);
    const s2 = gd.parsePushData({ gatedrop: { send: { id: 'x1', items: [{ mediaId: 'a'.repeat(32), name: 'b.pdf', bytes: 3 }] } } });
    assert.equal(s2.send.items[0].mediaId, 'a'.repeat(32));
    assert.equal(gd.parsePushData({ gatedrop: { transfer: 'tr_9', mode: 'pull', key: 'x', ticket: 'y' } }), null);
    assert.equal(gd.parsePushData({ other: 1 }), null);
    assert.equal(gd.isGateDropPush({ topic: 'plugin:gatecontrol-gatedrop:received' }), true);
    assert.equal(gd.isGateDropPush({ topic: 'security', data: {} }), false);
  });

  it('inbox: sends and links in any wrapper', () => {
    const sends = gd.normalizeInbox({ items: [{ id: 5, created_at: '2026-10-20 10:00:00', from: { name: 'Anna' }, items: [{ mediaId: 'b'.repeat(32), name: 'x.pdf', bytes: 9 }], text: 'hi' }, { nope: 1 }] }, 'received');
    assert.equal(sends.length, 1);
    assert.equal(sends[0].at, Date.parse('2026-10-20T10:00:00Z'));
    assert.equal(sends[0].from.name, 'Anna');
    const links = gd.normalizeInbox([{ token: 'abcdefghijklmnopqrstuv', url: 'https://gc/s/abcdefghijklmnopqrstuv', expiresAt: 1760000000000, downloads: 2, pin: true }, { token: 'short' }], 'links');
    assert.deepEqual(links.map((l) => [l.token, l.downloads, l.pin]), [['abcdefghijklmnopqrstuv', 2, true]]);
  });

  it('send targets: checked, link expiry fixed list', () => {
    assert.deepEqual(gd.sendTargets({ people: [8, 'family', 8], devices: ['tok_1'], nas: [{ id: 'n1', path: '/Fotos' }, { id: 'n2', path: '/../x' }], link: { expires: '1d', pin: true } }),
      { people: ['8', 'family'], devices: ['tok_1'], nas: [{ id: 'n1', path: '/Fotos' }, { id: 'n2' }], link: { expires: '1d', pin: true } });
    assert.equal(gd.sendTargets({ link: { expires: '30d' } }), null);
    assert.equal(gd.sendTargets({}), null);
    assert.equal(gd.linkArg('javascript:alert(1)'), null);
    assert.equal(gd.linkArg(' https://example.org/x '), 'https://example.org/x');
  });
});

describe('GateDrop "Senden an"', () => {
  it('parses the files after --gatedrop-send', () => {
    assert.equal(shellUtil.parseSendArgs(['C:\\GC\\GateControl.exe']), null);
    assert.deepEqual(shellUtil.parseSendArgs(['C:\\GC\\GateControl.exe', '--allow-file-access-from-files', '--gatedrop-send', 'C:\\Users\\a\\x.pdf', 'relative.txt', '--foo', '\\\\nas\\share\\y.jpg', 'gatecontrol-pro://notify/action?t=x']),
      ['C:\\Users\\a\\x.pdf', '\\\\nas\\share\\y.jpg']);
  });

  it('creates, keeps and removes only its own shortcut', () => {
    const files = new Map();
    const fsFake = { existsSync: (p) => files.has(p), unlinkSync: (p) => files.delete(p), mkdirSync() {} };
    const shell = {
      writeShortcutLink: (p, op, o) => { files.set(p, { ...o }); return true; },
      readShortcutLink: (p) => files.get(p),
    };
    const base = { shell, fs: fsFake, appData: 'C:\\Users\\a\\AppData\\Roaming', exePath: 'C:\\GC\\GateControl.exe', args: shellUtil.shortcutArgs({ isPackaged: true }) };
    assert.equal(base.args, '--gatedrop-send');
    assert.equal(shellUtil.syncSendToShortcut({ ...base, enabled: true }), 'created');
    assert.equal(shellUtil.syncSendToShortcut({ ...base, enabled: true }), 'unchanged');
    const lnk = shellUtil.sendToShortcutPath(base.appData);
    assert.equal(lnk, 'C:\\Users\\a\\AppData\\Roaming\\Microsoft\\Windows\\SendTo\\GateDrop.lnk');
    assert.equal(files.get(lnk).target, base.exePath);
    assert.equal(shellUtil.syncSendToShortcut({ ...base, enabled: false, exePath: 'C:\\Other\\Other.exe' }), 'unchanged');
    assert.equal(shellUtil.syncSendToShortcut({ ...base, enabled: false }), 'removed');
    assert.equal(shellUtil.syncSendToShortcut({ ...base, enabled: false }), 'absent');
    assert.equal(shellUtil.shortcutArgs({ isPackaged: false, appPath: 'C:\\dev\\app' }), '"C:\\dev\\app" --gatedrop-send');
  });
});

describe('i18n gatedrop.* (de / en)', () => {
  function flatten(obj, prefix = '', out = {}) {
    for (const [k, v] of Object.entries(obj)) {
      const key = prefix ? `${prefix}.${k}` : k;
      if (v && typeof v === 'object') flatten(v, key, out);
      else out[key] = String(v);
    }
    return out;
  }
  const ph = (s) => [...String(s).matchAll(/\{\{\s*(\w+)\s*\}\}/g)].map((m) => m[1]).sort();
  it('same keys and placeholders', () => {
    const d = flatten(de.gatedrop);
    const e = flatten(en.gatedrop);
    assert.deepEqual(Object.keys(d).sort(), Object.keys(e).sort());
    for (const k of Object.keys(d)) assert.deepEqual(ph(d[k]), ph(e[k]), k);
    assert.equal(d['toast.openFolder'], 'Ordner öffnen');
    assert.equal(d['toast.show'], 'Anzeigen');
  });
});

'use strict';

// GateDropService against a stub GateControl server with the GateDrop
// plugin: availability and presence, sending through the server (resumable
// upload), receiving a send (download to Downloads\GateControl with unique
// names, toast with "Ordner öffnen" / "Anzeigen"), direct transfers between
// two PCs (push, pull, fallback to the server) and the IPC channels.

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const EventEmitter = require('node:events');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const ApiClient = require('../src/services/api-client');
const GateDropService = require('../src/services/gatedrop');
const GateDropApi = require('../src/services/gatedrop-api');
const GateDropListener = require('../src/services/gatedrop-listener');
const NotificationCenter = require('../src/services/notification-center');
const { registerGateDropHandlers } = require('../src/ipc/gatedrop-handlers');
const { createMemoryStore } = require('./fixtures/memory-store');
const { gatedropServer } = require('./fixtures/gatedrop-server');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const loopback = (v) => { const m = /^(127\.0\.0\.1):(\d+)$/.exec(v); return m ? { host: m[1], port: Number(m[2]) } : null; };
const KEY_B64 = () => crypto.randomBytes(32).toString('base64');
const TICKET = () => `tkt_${crypto.randomBytes(12).toString('base64url')}`;

class FakeNotification extends EventEmitter {
  constructor(opts) { super(); this.opts = opts; FakeNotification.shown.push(this); }
  static isSupported() { return true; }
  show() { this.visible = true; }
  close() { this.visible = false; }
}
FakeNotification.shown = [];

const cleanup = [];
afterEach(async () => {
  for (const fn of cleanup.splice(0).reverse()) { try { await fn(); } catch { /* ignore */ } }
  FakeNotification.shown = [];
});

function tmpDir(prefix) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  cleanup.push(() => fs.rmSync(d, { recursive: true, force: true }));
  return d;
}

async function setup(srv, { withListener = true, nc = false, shell = null, resumableFrom } = {}) {
  const apiClient = new ApiClient(srv.url, 'gc_token', log);
  const store = createMemoryStore();
  const downloads = tmpDir('gd-dl-');
  const listener = withListener ? new GateDropListener({ log, port: 0, bindAddresses: ['127.0.0.1'], isAllowedPeer: () => true }) : false;
  const center = nc ? new NotificationCenter({ store, log, Notification: FakeNotification, platform: 'win32', protocol: 'gatecontrol-pro' }) : null;
  const api = new GateDropApi({ apiClient, log, sleep: async () => {}, resumableFrom });
  const svc = new GateDropService({
    apiClient, api, log, store, listener, notificationCenter: center, downloadsDir: () => downloads,
    Notification: FakeNotification, platform: 'win32', protocol: 'gatecontrol-pro', shell, resolveCandidate: loopback,
    getInterfaces: () => ({}),
  });
  svc.start();
  cleanup.push(async () => { svc.stop(); await svc.idle(); });
  await svc.check();
  return { svc, store, downloads, center, listener, apiClient };
}

function writeFile(dir, name, data) {
  const p = path.join(dir, name);
  fs.writeFileSync(p, data);
  return p;
}

describe('GateDropService', () => {
  it('available with the plugin: listener on, presence with LAN, port and listening', async () => {
    const srv = await gatedropServer();
    cleanup.push(() => srv.close());
    const { svc } = await setup(srv);
    const st = svc.status();
    assert.equal(st.state, 'available');
    assert.equal(st.version, '1.0.0');
    assert.equal(st.listening, true);
    assert.deepEqual(srv.state.presence[0], { lan: [{ ip: '127.0.0.1', prefix: 24 }], port: 47731, listening: true });
  });

  it('unavailable without the plugin (no listener, no presence)', async () => {
    const srv = await gatedropServer({ plugin: false });
    cleanup.push(() => srv.close());
    const { svc } = await setup(srv);
    assert.equal(svc.status().state, 'unavailable');
    assert.equal(svc.status().reason, 'not_installed');
    assert.equal(svc.status().listening, false);
    assert.equal(srv.state.presence.length, 0);
    await assert.rejects(svc.send({ text: 'x', to: { people: [8] } }), (e) => e.code === 'unavailable');
  });

  it('sends through the server: upload (resumable after a cut), then POST sends', async () => {
    const srv = await gatedropServer();
    cleanup.push(() => srv.close());
    const { svc } = await setup(srv, { resumableFrom: 1000 });
    const dir = tmpDir('gd-src-');
    const big = crypto.randomBytes(300000);
    const small = Buffer.from('kleine Datei');
    const prep = await svc.prepareFiles([writeFile(dir, 'gross.bin', big), writeFile(dir, 'klein.txt', small), dir, path.join(dir, 'fehlt.pdf'), 'relativ.txt']);
    assert.deepEqual(prep.files.map((f) => [f.name, f.size]), [['gross.bin', big.length], ['klein.txt', small.length]]);
    assert.deepEqual(prep.rejected.map((r) => r.reason), ['directory', 'missing', 'invalid']);
    assert.ok(!('path' in prep.files[0]), 'no paths to the renderer');

    srv.cutUploadAfter = 100000;
    const r = await svc.send({ files: prep.files.map((f) => f.id), text: 'Für dich', note: 'Angebot', to: { people: [8] } });
    assert.equal(r.ok, true);
    const sent = srv.state.sends.get(r.id);
    assert.equal(sent.text, 'Für dich');
    assert.deepEqual(sent.to, { people: ['8'], devices: [], nas: [] });
    assert.equal(sent.items.length, 2);
    assert.deepEqual(srv.state.media.get(sent.items[0].mediaId).data, big);
    assert.deepEqual(srv.state.media.get(sent.items[1].mediaId).data, small);
    const resumed = srv.state.uploadCalls.filter((u) => u.uploadId);
    assert.equal(resumed.length, 2);
    assert.equal(resumed[1].offset, 100000);
    assert.equal(resumed[1].range, `bytes 100000-${big.length - 1}/${big.length}`);
    await assert.rejects(svc.send({ files: ['unknown'], to: { people: [8] } }), (e) => e.code === 'invalid');
    await assert.rejects(svc.send({ text: 'x', to: {} }), (e) => e.code === 'no_target');
  });

  it('a public link answer is passed on (url + PIN)', async () => {
    const srv = await gatedropServer();
    cleanup.push(() => srv.close());
    const { svc } = await setup(srv);
    const dir = tmpDir('gd-src-');
    const prep = await svc.prepareFiles([writeFile(dir, 'steuer.zip', 'zip')]);
    const r = await svc.send({ files: [prep.files[0].id], to: { link: { expires: 'once', pin: true } } });
    assert.match(r.link.url, /^https:\/\/gc\.example\/s\//);
    assert.equal(r.link.pin, '4711');
  });

  it('receives a send: download to Downloads\\GateControl with unique names, toast with buttons', async () => {
    const srv = await gatedropServer();
    cleanup.push(() => srv.close());
    const shellCalls = [];
    const shell = { showItemInFolder: (p) => shellCalls.push(['show', p]), openPath: async (p) => { shellCalls.push(['open', p]); return ''; } };
    const { svc, downloads, center } = await setup(srv, { nc: true, shell });
    fs.writeFileSync(path.join(downloads, 'angebot.pdf'), 'old');
    const send = srv.addSend({ from: { name: 'Büro-PC' }, items: [{ name: 'angebot.pdf', data: Buffer.from('%PDF-neu') }, { name: '../../boese.exe', data: Buffer.from('MZ') }] });

    const received = new Promise((r) => svc.once('received', r));
    const entry = center.handleNotification({ seq: 5, id: 50, topic: 'plugin:gatecontrol-gatedrop:received', title: 'Büro-PC hat dir 2 Dateien geschickt', body: '', data: { gatedrop: { send: send.id } } });
    const rec = await received;
    await svc.idle();

    assert.ok(entry, 'kept in the inbox');
    assert.deepEqual(rec.files.map((f) => path.basename(f.path)), ['angebot (2).pdf', 'boese.exe']);
    assert.equal(fs.readFileSync(path.join(downloads, 'angebot (2).pdf'), 'utf8'), '%PDF-neu');
    assert.equal(fs.readFileSync(path.join(downloads, 'angebot.pdf'), 'utf8'), 'old');
    assert.deepEqual(fs.readdirSync(downloads).filter((f) => f.endsWith('.gdpart')), []);
    assert.equal(fs.readdirSync(path.dirname(downloads)).includes('boese.exe'), false);

    // One toast — ours, not the center's — with both buttons.
    assert.equal(FakeNotification.shown.length, 1);
    const xml = FakeNotification.shown[0].opts.toastXml;
    assert.match(xml, /Büro-PC hat dir 2 Dateien geschickt/);
    assert.match(xml, /Ordner öffnen/);
    assert.match(xml, /Anzeigen/);
    const nonces = [...xml.matchAll(/gatecontrol-pro:\/\/notify\/action\?t=([A-Za-z0-9_-]+)/g)].map((m) => m[1]);
    assert.equal(nonces.length, 2);
    assert.equal(center.handleProtocolUrl(`gatecontrol-pro://notify/action?t=${nonces[1]}`), true);
    await new Promise((r) => setTimeout(r, 30));
    assert.deepEqual(shellCalls[0], ['show', path.join(downloads, 'angebot (2).pdf')]);
    assert.deepEqual(srv.state.opened, [send.id]);

    // The page: the received entry knows its saved files; only those may be shown.
    srv.state.inbox.received = [{ id: send.id, from: { name: 'Büro-PC' }, items: send.items }];
    const inbox = await svc.inbox({ kind: 'received', refresh: true });
    assert.equal(inbox.items[0].local.length, 2);
    assert.equal(svc.isSavedPath(inbox.items[0].local[0].path), true);
    assert.throws(() => svc.showItem('C:\\Windows\\system32\\cmd.exe'), (e) => e.code === 'invalid');

    // A replay of the same push is ignored.
    center.handleNotification({ seq: 6, id: 51, topic: 'plugin:gatecontrol-gatedrop:received', title: 'x', data: { gatedrop: { send: send.id } } });
    await svc.idle();
    assert.equal(fs.readdirSync(downloads).length, 3);
  });

  it('a text send: toast with "Kopieren", silent pushes are not stored', async () => {
    const srv = await gatedropServer();
    cleanup.push(() => srv.close());
    const copied = [];
    const { svc, center } = await setup(srv, { nc: true });
    svc.clipboard = { writeText: (t) => copied.push(t) };
    const send = srv.addSend({ from: { name: 'Anna' }, text: 'Code: 4711' });
    const entry = center.handleNotification({ seq: 9, id: 90, topic: 'plugin:gatecontrol-gatedrop:received', title: 'x', silent: true, data: { gatedrop: { send: send.id } } });
    await svc.idle();
    assert.equal(entry, null);
    const xml = FakeNotification.shown[0].opts.toastXml;
    assert.match(xml, /Anna hat dir einen Text geschickt/);
    const nonce = /t=([A-Za-z0-9_-]+)/.exec(xml)[1];
    center.handleProtocolUrl(`gatecontrol-pro://notify/action?t=${nonce}`);
    await new Promise((r) => setTimeout(r, 20));
    assert.deepEqual(copied, ['Code: 4711']);
  });

  it('direct push between two PCs: local items, listener learns the ticket from GET transfers/<id>', async () => {
    const srv = await gatedropServer();
    cleanup.push(() => srv.close());
    const receiver = await setup(srv);
    const rPort = receiver.listener.status().addresses[0].port;
    srv.state.targets.devices = [{ id: 'tok_buero', name: 'Büro-PC', platform: 'windows', online: true, direct: true }];
    srv.state.direct = (body) => {
      const transferId = `tr_${crypto.randomBytes(6).toString('hex')}`;
      const entry = { deviceId: 'tok_buero', transferId, mode: 'push', candidates: [`127.0.0.1:${rPort}`], key: KEY_B64(), ticket: TICKET() };
      srv.state.transfers.set(transferId, { mode: 'push', key: entry.key, ticket: entry.ticket, from: { name: 'Laptop' }, items: body.items.map((it) => ({ name: it.name, bytes: it.bytes })) });
      return [entry];
    };
    const sender = await setup(srv);
    const dir = tmpDir('gd-src-');
    const data = crypto.randomBytes(2 * 1024 * 1024 + 99);
    const prep = await sender.svc.prepareFiles([writeFile(dir, 'video.mp4', data)]);
    const received = new Promise((r) => receiver.svc.once('received', r));
    const r = await sender.svc.send({ files: [prep.files[0].id], to: { devices: ['tok_buero'] } });
    assert.equal(r.direct.length, 1);
    const sent = srv.state.sends.get(r.id);
    assert.deepEqual(sent.items, [{ name: 'video.mp4', bytes: data.length, mime: 'video/mp4', local: true }]);
    const rec = await received;
    await sender.svc.idle();
    await receiver.svc.idle();
    assert.deepEqual(fs.readFileSync(rec.files[0].path), data);
    assert.equal(rec.via, 'direct');
    assert.equal(srv.state.results.length, 2);
    assert.ok(srv.state.results.every((x) => x.ok === true && x.bytes === data.length));
    assert.equal(srv.state.uploadCalls.length, 0, 'nothing went through the server');
  });

  it('direct push fails (nobody listening): result ok:false, upload and POST sends/<id>/items', async () => {
    const srv = await gatedropServer();
    cleanup.push(() => srv.close());
    srv.state.targets.devices = [{ id: 'tok_buero', name: 'Büro-PC', platform: 'windows', online: true, direct: true }];
    srv.state.direct = () => [{ deviceId: 'tok_buero', transferId: 'tr_dead', mode: 'push', candidates: ['127.0.0.1:1'], key: KEY_B64(), ticket: TICKET() }];
    const sender = await setup(srv);
    const dir = tmpDir('gd-src-');
    const prep = await sender.svc.prepareFiles([writeFile(dir, 'a.txt', 'hallo')]);
    const r = await sender.svc.send({ files: [prep.files[0].id], to: { devices: ['tok_buero'] } });
    await sender.svc.idle();
    assert.equal(srv.state.results[0].ok, false);
    assert.equal(srv.state.addItems.length, 1);
    assert.equal(srv.state.addItems[0].sendId, r.id);
    const mediaId = srv.state.addItems[0].items[0].mediaId;
    assert.equal(srv.state.media.get(mediaId).data.toString(), 'hallo');
  });

  it('direct pull: the receiving PC fetches from the sending PC', async () => {
    const srv = await gatedropServer();
    cleanup.push(() => srv.close());
    srv.state.targets.devices = [{ id: 'tok_b', name: 'B', platform: 'windows', online: true, direct: true }];
    let pushToB = null;
    const sender = await setup(srv);
    const sPort = sender.listener.status().addresses[0].port;
    srv.state.direct = (body) => {
      const entry = { deviceId: 'tok_b', transferId: 'tr_pull1', mode: 'pull', candidates: [`127.0.0.1:${sPort}`], key: KEY_B64(), ticket: TICKET() };
      pushToB = { gatedrop: { transfer: entry.transferId, mode: 'pull', from: { name: 'A' }, items: body.items.map((it) => ({ name: it.name, bytes: it.bytes })), candidates: entry.candidates, key: entry.key, ticket: entry.ticket } };
      return [entry];
    };
    const receiver = await setup(srv, { nc: true });
    const dir = tmpDir('gd-src-');
    const data = crypto.randomBytes(1500000);
    const prep = await sender.svc.prepareFiles([writeFile(dir, 'foto.jpg', data)]);
    await sender.svc.send({ files: [prep.files[0].id], to: { devices: ['tok_b'] } });
    const received = new Promise((r) => receiver.svc.once('received', r));
    assert.equal(receiver.center.handleNotification({ seq: 1, id: 1, topic: 'plugin:gatecontrol-gatedrop:received', silent: true, title: '', data: pushToB }), null);
    const rec = await received;
    await sender.svc.idle();
    assert.deepEqual(fs.readFileSync(rec.files[0].path), data);
    assert.deepEqual(srv.state.results.map((x) => x.ok), [true, true]);
    assert.match(FakeNotification.shown.at(-1).opts.toastXml, /A hat dir foto\.jpg geschickt/);
  });
});

describe('GateDrop IPC', () => {
  it('checks arguments and forwards events', async () => {
    const handlers = {};
    const sent = [];
    const svc = new EventEmitter();
    const calls = [];
    Object.assign(svc, {
      status: () => ({ state: 'available' }),
      prepareFiles: async (paths) => { calls.push(['prepare', paths]); return { ok: true, files: [], rejected: [] }; },
      send: async (m) => { calls.push(['send', m]); return { ok: true, id: '1' }; },
      showItem: () => { throw Object.assign(new Error('unknown file'), { code: 'invalid' }); },
      inbox: async (o) => ({ ok: true, ...o, items: [] }),
    });
    registerGateDropHandlers((ch, fn) => { handlers[ch] = fn; }, {
      gatedrop: svc, log, getMainWindow: () => ({ webContents: { send: (ch, p) => sent.push([ch, p]) } }),
      dialog: { showOpenDialog: async () => ({ canceled: true, filePaths: [] }) },
    });
    assert.equal((await handlers['gatedrop:prepare']({}, { paths: 'C:\\x' })).code, 'invalid');
    assert.equal((await handlers['gatedrop:send']({}, { files: [], text: 'x'.repeat(20001), to: {} })).code, 'invalid');
    assert.equal((await handlers['gatedrop:send']({}, { files: ['a'], to: { people: [8] } })).ok, true);
    assert.equal((await handlers['gatedrop:show']({}, { path: 'C:\\x' })).code, 'invalid');
    assert.equal((await handlers['gatedrop:pick']({})).code, 'cancelled');
    assert.deepEqual(await handlers['gatedrop:explorer']({}, { enabled: true }), { ok: true, enabled: false, supported: false });
    svc.emit('compose', { files: [1] });
    svc.emit('progress', { id: 'x' });
    assert.deepEqual(sent.map((s) => s[0]), ['gatedrop:compose', 'gatedrop:progress']);
  });
});

describe('NotificationCenter push handlers', () => {
  it('consumed → not stored; quiet → stored without toast; protocol buttons', () => {
    const store = createMemoryStore();
    const nc = new NotificationCenter({ store, log, Notification: FakeNotification, platform: 'linux' });
    const protocolSeen = [];
    const off = nc.addPushHandler({
      notification: (n) => (n.data && n.data.mode) || false,
      protocol: (nonce) => { protocolSeen.push(nonce); return nonce === 'mine1234'; },
    });
    assert.equal(nc.handleNotification({ seq: 1, id: 1, title: 'a', data: { mode: 'consumed' } }), null);
    assert.ok(nc.handleNotification({ seq: 2, id: 2, title: 'b', data: { mode: 'quiet' } }));
    assert.equal(FakeNotification.shown.length, 0);
    assert.ok(nc.handleNotification({ seq: 3, id: 3, title: 'c' }));
    assert.equal(FakeNotification.shown.length, 1);
    nc.protocol = 'gatecontrol-pro';
    assert.equal(nc.handleProtocolUrl('gatecontrol-pro://notify/action?t=mine1234'), true);
    assert.deepEqual(protocolSeen, ['mine1234']);
    off();
    assert.equal(nc.handleNotification({ seq: 4, id: 4, title: 'd', data: { mode: 'consumed' } }).id, 4);
  });
});

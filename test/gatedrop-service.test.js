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

async function setup(srv, { withListener = true, nc = false, shell = null, resumableFrom, partSize } = {}) {
  const apiClient = new ApiClient(srv.url, 'gc_token', log);
  const store = createMemoryStore();
  const downloads = tmpDir('gd-dl-');
  const listener = withListener ? new GateDropListener({ log, port: 0, bindAddresses: ['127.0.0.1'], isAllowedPeer: () => true }) : false;
  const center = nc ? new NotificationCenter({ store, log, Notification: FakeNotification, platform: 'win32', protocol: 'gatecontrol-pro' }) : null;
  const api = new GateDropApi({ apiClient, log, sleep: async () => {}, resumableFrom, partSize });
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
    const { svc } = await setup(srv, { resumableFrom: 1000, partSize: 128 * 1024 });
    const dir = tmpDir('gd-src-');
    const big = crypto.randomBytes(300000);
    const small = Buffer.from('kleine Datei');
    const prep = await svc.prepareFiles([writeFile(dir, 'gross.bin', big), writeFile(dir, 'klein.txt', small), dir, path.join(dir, 'fehlt.pdf'), 'relativ.txt']);
    assert.deepEqual(prep.files.map((f) => [f.name, f.size]), [['gross.bin', big.length], ['klein.txt', small.length]]);
    assert.deepEqual(prep.rejected.map((r) => r.reason), ['directory', 'missing', 'invalid']);
    assert.ok(!('path' in prep.files[0]), 'no paths to the renderer');

    srv.cutUploadAfter = 100000; // first part breaks off; the server kept 65536 bytes
    const events = [];
    svc.on('progress', (p) => events.push(p));
    const r = await svc.send({ files: prep.files.map((f) => f.id), text: 'Für dich', note: 'Angebot', to: { people: [8] }, job: 'job-1' });
    assert.equal(r.ok, true);
    // the caller's job id from the first upload byte to the end
    assert.equal(r.job, 'job-1');
    assert.ok(events.every((e) => e.id === 'job-1' && e.dir === 'out'));
    assert.equal(events[0].phase, 'upload');
    assert.deepEqual(events.slice(-2).map((e) => e.phase), ['sent', 'done']);
    assert.deepEqual([events.at(-1).via, events.at(-1).sendId, events.at(-1).sent], ['server', r.id, big.length + small.length]);
    const sent = srv.state.sends.get(r.id);
    assert.equal(sent.text, 'Für dich');
    assert.deepEqual(sent.to, { people: ['8'], devices: [], nas: [] });
    assert.equal(sent.items.length, 2);
    assert.deepEqual(srv.state.media.get(sent.items[0].mediaId).data, big);
    assert.deepEqual(srv.state.media.get(sent.items[1].mediaId).data, small);
    const parts = srv.state.uploadCalls.filter((u) => u.uploadId);
    assert.deepEqual(parts.map((u) => u.offset), [0, 65536, 65536 + 131072]);
    assert.equal(parts[0].range, `bytes 0-131071/${big.length}`);
    assert.equal(parts[1].range, `bytes 65536-196607/${big.length}`);
    assert.equal(parts[2].range, `bytes 196608-${big.length - 1}/${big.length}`);
    assert.ok(parts.every((u) => u.offset % 65536 === 0));
    assert.equal(new Set(parts.map((u) => u.uploadId)).size, 1);
    assert.match(parts[0].uploadId, /^[A-Za-z0-9_-]{8,64}$/);
    await assert.rejects(svc.send({ files: ['unknown'], to: { people: [8] } }), (e) => e.code === 'invalid');
    await assert.rejects(svc.send({ text: 'x', to: {} }), (e) => e.code === 'no_target');
    // the server refuses the send → the job ends with 'error'; an unusable job id → an own one
    srv.state.failCreate = { status: 403, code: 'forbidden' };
    events.length = 0;
    await assert.rejects(svc.send({ text: 'x', to: { people: [8] }, job: 'bad id!' }));
    assert.equal(events.length, 1);
    assert.equal(events[0].phase, 'error');
    assert.match(events[0].id, /^[0-9a-f]{16}$/);
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

  it('a text send: toast with "Kopieren"; data pushes are not stored, quiet hours stay silent', async () => {
    const srv = await gatedropServer();
    cleanup.push(() => srv.close());
    const copied = [];
    const { svc, center } = await setup(srv, { nc: true });
    svc.clipboard = { writeText: (t) => copied.push(t) };
    const send = srv.addSend({ from: { name: 'Anna' }, text: 'Code: 4711' });
    const entry = center.handleNotification({ seq: 9, id: 90, kind: 'data', topic: 'plugin:gatecontrol-gatedrop:received', title: '', silent: true, data: { gatedrop: { send: send.id } } });
    await svc.idle();
    assert.equal(entry, null);
    assert.equal(center.list({ filter: 'all' }).items.length, 0);
    const xml = FakeNotification.shown[0].opts.toastXml;
    assert.match(xml, /Anna hat dir einen Text geschickt/);
    const nonce = /t=([A-Za-z0-9_-]+)/.exec(xml)[1];
    center.handleProtocolUrl(`gatecontrol-pro://notify/action?t=${nonce}`);
    await new Promise((r) => setTimeout(r, 20));
    assert.deepEqual(copied, ['Code: 4711']);

    // A visible push during quiet hours (`silent`): kept in the inbox, no toast at all.
    const quiet = srv.addSend({ from: { name: 'Lena' }, text: 'psst' });
    const e2 = center.handleNotification({ seq: 10, id: 91, topic: 'plugin:gatecontrol-gatedrop:received', title: 'Lena hat dir einen Text geschickt', silent: true, data: { gatedrop: { send: quiet.id } } });
    await svc.idle();
    assert.ok(e2);
    assert.equal(FakeNotification.shown.length, 1);

    // Other data pushes nobody takes: never shown, never stored, 'data' event.
    const seen = [];
    center.on('data', (d) => seen.push(d));
    assert.equal(center.handleNotification({ seq: 11, id: 92, kind: 'data', topic: 'plugin:x:y', title: '', data: { x: 1 } }), null);
    assert.deepEqual(seen, [{ topic: 'plugin:x:y', data: { x: 1 } }]);
    assert.equal(FakeNotification.shown.length, 1);
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
    assert.deepEqual(sent.items, [{ idx: 0, mediaId: null, name: 'video.mp4', mime: 'video/mp4', bytes: data.length, local: true }]);
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
    const events = [];
    sender.svc.on('progress', (p) => events.push(p.phase));
    const r = await sender.svc.send({ files: [prep.files[0].id], to: { devices: ['tok_buero'] } });
    await sender.svc.idle();
    assert.equal(srv.state.results[0].ok, false);
    // direct failed → over the server → done
    assert.equal(events.at(-1), 'done');
    assert.ok(events.includes('failed'));
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
    const outcome = new Promise((r) => sender.svc.on('progress', (p) => { if (p.phase === 'done' || p.phase === 'error') r(p); }));
    await sender.svc.send({ files: [prep.files[0].id], to: { devices: ['tok_b'] } });
    const received = new Promise((r) => receiver.svc.once('received', r));
    assert.equal(receiver.center.handleNotification({ seq: 1, id: 1, kind: 'data', topic: 'plugin:gatecontrol-gatedrop:received', silent: true, title: '', data: pushToB }), null);
    const rec = await received;
    await sender.svc.idle();
    assert.deepEqual(fs.readFileSync(rec.files[0].path), data);
    assert.deepEqual(srv.state.results.map((x) => x.ok), [true, true]);
    assert.deepEqual([(await outcome).phase, (await outcome).via], ['done', 'direct']);
    assert.match(FakeNotification.shown.at(-1).opts.toastXml, /A hat dir foto\.jpg geschickt/);
  });
});

describe('GateDropService – plugin shapes', () => {
  it('fallback "server" uploads nothing; "upload" only the missing indexes as { index, mediaId }', async () => {
    const srv = await gatedropServer();
    cleanup.push(() => srv.close());
    srv.state.targets.devices = [{ id: '43', name: 'Büro-PC', platform: 'windows', online: true, direct: true, mode: 'push' }];
    // Files uploaded first (a person is a target too), the direct transfer to the PC fails → the server delivers.
    srv.state.direct = () => [{ deviceId: '43', transferId: 'a'.repeat(24), mode: 'push', candidates: ['127.0.0.1:1'], key: KEY_B64(), ticket: TICKET(), expiresAt: new Date(Date.now() + 600000).toISOString() }];
    const sender = await setup(srv);
    const dir = tmpDir('gd-src-');
    const prep = await sender.svc.prepareFiles([writeFile(dir, 'a.txt', 'eins'), writeFile(dir, 'b.txt', 'zwei')]);
    await sender.svc.send({ files: prep.files.map((f) => f.id), to: { devices: ['43'], people: [8] } });
    await sender.svc.idle();
    assert.equal(srv.state.results.at(-1).ok, false);
    assert.equal(srv.state.addItems.length, 0, 'fallback server: nothing to upload');
    assert.equal(srv.state.uploadCalls.length, 2);

    // Local items; the plugin asks for index 1 only (0 got there another way).
    srv.state.direct = (body, sendId) => {
      setImmediate(() => { const st = srv.state.sends.get(sendId); st.items[0].mediaId = 'f'.repeat(32); });
      return [{ deviceId: '43', transferId: 'b'.repeat(24), mode: 'push', candidates: ['127.0.0.1:1'], key: KEY_B64(), ticket: TICKET() }];
    };
    const prep2 = await sender.svc.prepareFiles([writeFile(dir, 'c.txt', 'drei'), writeFile(dir, 'd.txt', 'vier')]);
    const r = await sender.svc.send({ files: prep2.files.map((f) => f.id), to: { devices: ['43'] } });
    await sender.svc.idle();
    const last = srv.state.addItems.at(-1);
    assert.equal(last.sendId, r.id);
    assert.equal(last.items.length, 1);
    assert.equal(last.items[0].index, 1);
    assert.deepEqual(Object.keys(last.items[0]).sort(), ['index', 'mediaId']);
    assert.equal(srv.state.media.get(last.items[0].mediaId).data.toString(), 'vier');
  });

  it('a direct push without items asks GET transfers/<id>; transfer wins over send', async () => {
    const srv = await gatedropServer();
    cleanup.push(() => srv.close());
    const receiver = await setup(srv, { nc: true });
    const sender = await setup(srv);
    const sPort = sender.listener.status().addresses[0].port;
    const dir = tmpDir('gd-src-');
    const data = crypto.randomBytes(70000);
    const src = writeFile(dir, 'scan.pdf', data);
    const key = crypto.randomBytes(32);
    const ticket = TICKET();
    const tid = 'c'.repeat(24);
    const send = srv.addSend({ from: { name: 'Marc', deviceName: 'Laptop' }, items: [{ name: 'scan.pdf', bytes: data.length, local: true }] });
    srv.state.transfers.set(tid, { id: tid, sendId: send.id, side: 'receiver', mode: 'pull', status: 'open', fromDevice: '42', toDevice: '43', from: { userId: 2, deviceId: '42', deviceName: 'Laptop' }, candidates: [`127.0.0.1:${sPort}`], key: key.toString('base64'), ticket, expiresAt: new Date(Date.now() + 600000).toISOString(), items: [{ index: 0, name: 'scan.pdf', bytes: data.length, mime: 'application/pdf' }] });
    const offer = sender.listener.offerOutgoing({ transferId: tid, ticket, key, items: [{ path: src, name: 'scan.pdf', size: data.length }] });
    const received = new Promise((res) => receiver.svc.once('received', res));
    const entry = receiver.center.handleNotification({ seq: 3, id: 3, kind: 'data', silent: true, topic: 'plugin:gatecontrol-gatedrop:received', title: '', data: {
      route: 'plg-gatecontrol-gatedrop',
      gatedrop: { transfer: tid, send: send.id, mode: 'pull', from: { userId: 2, name: 'Marc', deviceId: '42', deviceName: 'Laptop' }, items: null, itemCount: 1, candidates: [`127.0.0.1:${sPort}`], key: key.toString('base64'), ticket, expiresAt: new Date(Date.now() + 600000).toISOString() },
    } });
    assert.equal(entry, null);
    const rec = await received;
    await offer.done;
    assert.deepEqual(fs.readFileSync(rec.files[0].path), data);
    assert.equal(rec.sendId, send.id);
    assert.ok(srv.state.requests.some((q) => q.method === 'GET' && q.path.endsWith(`/transfers/${tid}`)));
    // Own device: the toast names the device.
    assert.match(FakeNotification.shown.at(-1).opts.toastXml, /Laptop hat dir scan\.pdf geschickt/);
  });

  it('downloads through items/<id> → url, skips items not on the server, leaves link pushes alone', async () => {
    const srv = await gatedropServer();
    cleanup.push(() => srv.close());
    const { svc, center } = await setup(srv, { nc: true });
    const send = srv.addSend({ from: { name: 'Anna' }, items: [{ name: 'da.txt', data: Buffer.from('da') }, { name: 'lokal.txt', bytes: 5, local: true }] });
    const received = new Promise((r) => svc.once('received', r));
    center.handleNotification({ seq: 4, id: 4, topic: 'plugin:gatecontrol-gatedrop:received', title: 'Anna hat dir 2 Dateien geschickt', data: { route: 'plg-gatecontrol-gatedrop', gatedrop: { send: send.id } } });
    const rec = await received;
    await svc.idle();
    assert.deepEqual(rec.files.map((f) => path.basename(f.path)), ['da.txt']);
    const paths = srv.state.requests.map((q) => q.path);
    assert.ok(paths.some((x) => x.endsWith(`/api/items/${send.items[0].mediaId}`)));
    assert.ok(paths.some((x) => x === `/api/v1/client/plugins/gatecontrol-gatedrop/media/${send.items[0].mediaId}`));

    const shown = FakeNotification.shown.length;
    const e = center.handleNotification({ seq: 5, id: 5, topic: 'plugin:gatecontrol-gatedrop:link', title: 'Link geladen: steuer.zip', body: '1× heruntergeladen', data: { route: 'plg-gatecontrol-gatedrop', gatedrop: { link: 'abcdefghijklmnopqrstuv', send: send.id } } });
    assert.ok(e, 'a normal inbox entry');
    assert.equal(FakeNotification.shown.length, shown + 1, "the center's own toast");
    assert.deepEqual(svc.clickContext(e), { tab: 'links', sendId: send.id });
  });

  it('targets with limits, link only when allowed', async () => {
    const srv = await gatedropServer();
    cleanup.push(() => srv.close());
    const { svc } = await setup(srv);
    const tg = await svc.targets();
    assert.equal(tg.me.deviceId, '42');
    assert.deepEqual(tg.limits.linkExpires, ['1h', '1d', '7d', 'once']);
    assert.equal(tg.limits.directPort, 47731);
    assert.equal(tg.people[1].colorHex, '#84CC16');
    assert.equal(tg.devices[0].mode, null);
  });
});

describe('GateDropService – who may send to this PC (GateDrop 1.2.0)', () => {
  it('reads and sets the setting; older plugins and unknown devices: not supported', async () => {
    const srv = await gatedropServer({ version: '1.2.0' });
    cleanup.push(() => srv.close());
    const { svc } = await setup(srv);
    assert.deepEqual(await svc.deviceAccess(), { ok: true, supported: true, receiveFrom: 'self' });
    await svc.targets();
    assert.deepEqual(await svc.setDeviceAccess('everyone'), { ok: true, supported: true, receiveFrom: 'everyone' });
    assert.deepEqual(srv.state.deviceCalls.at(-1), { method: 'PUT', body: { receiveFrom: 'everyone' } });
    assert.equal((await svc.targets()).me.receiveFrom, 'everyone', 'the cached targets follow');
    await assert.rejects(svc.setDeviceAccess('friends'), (e) => e.code === 'invalid');
    assert.equal(srv.state.deviceCalls.length, 2);
    srv.state.deviceMode = 404;
    assert.deepEqual(await svc.deviceAccess(), { ok: true, supported: false, receiveFrom: null });
    srv.state.deviceMode = 'no_device';
    assert.deepEqual(await svc.deviceAccess(), { ok: true, supported: false, receiveFrom: null });
  });

  it('sends to another person\'s open device like to an own one; local items when it is direct', async () => {
    const srv = await gatedropServer({ version: '1.2.0' });
    cleanup.push(() => srv.close());
    srv.state.targets.peopleDevices = [
      { id: '51', name: 'Surface', platform: 'windows', online: true, direct: false, owner: { id: 3, name: 'Lena' } },
      { id: '52', name: 'Laptop', platform: 'windows', online: true, direct: true, mode: 'push', owner: { id: 3, name: 'Lena' } },
    ];
    const { svc } = await setup(srv);
    const tg = await svc.targets();
    assert.deepEqual(tg.peopleDevices.map((d) => [d.id, d.owner.name]), [['51', 'Lena'], ['52', 'Lena']]);
    const dir = tmpDir('gd-src-');
    const prep = await svc.prepareFiles([writeFile(dir, 'a.txt', 'hallo'), writeFile(dir, 'b.txt', 'welt')]);

    // through the server: the files go up, the delivery is labelled "Surface (Lena)"
    const r = await svc.send({ files: [prep.files[0].id], to: { devices: ['51'] } });
    assert.deepEqual(srv.state.sends.get(r.id).to.devices, ['51']);
    assert.equal(srv.state.sends.get(r.id).items[0].local, false);
    assert.equal(r.deliveries[0].targetName, 'Surface (Lena)');

    // in the same Wi-Fi: the items stay local (direct transfer)
    const r2 = await svc.send({ files: [prep.files[1].id], to: { devices: ['52'] } });
    assert.equal(srv.state.sends.get(r2.id).items[0].local, true);

    // closed for others meanwhile: 409 unavailable → target_unavailable, the targets are asked again
    srv.state.closed.add('51');
    srv.state.targets.peopleDevices = srv.state.targets.peopleDevices.filter((d) => d.id !== '51');
    const events = [];
    svc.on('progress', (p) => events.push(p));
    await assert.rejects(svc.send({ text: 'hi', to: { devices: ['51'] }, job: 'j9' }), (e) => e.code === 'target_unavailable');
    assert.equal(events.at(-1).phase, 'error');
    assert.equal(events.at(-1).code, 'target_unavailable');
    assert.deepEqual((await svc.targets()).peopleDevices.map((d) => d.id), ['52']);
  });

  it('a send from another person names the person, one from an own device the device', async () => {
    const srv = await gatedropServer({ version: '1.2.0' });
    cleanup.push(() => srv.close());
    const { svc, center } = await setup(srv, { nc: true });
    const other = srv.addSend({ from: { userId: 3, name: 'Lena', deviceId: '51', deviceName: 'Surface', own: false }, text: 'Hallo' });
    center.handleNotification({ seq: 1, id: 1, kind: 'data', topic: 'plugin:gatecontrol-gatedrop:received', title: '', silent: true, data: { gatedrop: { send: other.id } } });
    await svc.idle();
    assert.match(FakeNotification.shown.at(-1).opts.toastXml, /Lena hat dir einen Text geschickt/);
    const own = srv.addSend({ from: { userId: 2, name: 'Marc', deviceId: '43', deviceName: 'Pixel', own: true }, text: 'Notiz' });
    center.handleNotification({ seq: 2, id: 2, kind: 'data', topic: 'plugin:gatecontrol-gatedrop:received', title: '', silent: true, data: { gatedrop: { send: own.id } } });
    await svc.idle();
    assert.match(FakeNotification.shown.at(-1).opts.toastXml, /Pixel hat dir einen Text geschickt/);
    // direct transfers: own unless `own: false`; without `own` (older plugins) as before
    assert.equal(svc._fromName({ id: '3', name: 'Lena', deviceName: 'Surface', own: false }, { device: true }), 'Lena');
    assert.equal(svc._fromName({ id: '2', name: 'Marc', deviceName: 'Pixel', own: true }, { device: true }), 'Pixel');
    assert.equal(svc._fromName({ id: '3', name: 'Lena', deviceName: 'Surface', own: null }, { device: true }), 'Surface');
    assert.equal(svc._fromName({ id: '3', name: 'Lena', deviceName: 'Surface', own: null }), 'Lena');
  });

  it('a direct transfer from another person\'s device: the toast names the person', async () => {
    const srv = await gatedropServer({ version: '1.2.0' });
    cleanup.push(() => srv.close());
    srv.state.targets.peopleDevices = [{ id: 'tok_lena', name: 'Lenas PC', platform: 'windows', online: true, direct: true, mode: 'pull', owner: { id: 3, name: 'Lena' } }];
    let pushToB = null;
    const sender = await setup(srv);
    const sPort = sender.listener.status().addresses[0].port;
    srv.state.direct = (body) => {
      const entry = { deviceId: 'tok_lena', transferId: 'tr_pull_other', mode: 'pull', candidates: [`127.0.0.1:${sPort}`], key: KEY_B64(), ticket: TICKET() };
      pushToB = { gatedrop: { transfer: entry.transferId, mode: 'pull', from: { userId: 2, name: 'Marc', deviceId: '42', deviceName: 'Laptop', own: false }, items: body.items.map((it) => ({ name: it.name, bytes: it.bytes })), candidates: entry.candidates, key: entry.key, ticket: entry.ticket } };
      return [entry];
    };
    const receiver = await setup(srv, { nc: true });
    const dir = tmpDir('gd-src-');
    const prep = await sender.svc.prepareFiles([writeFile(dir, 'foto.jpg', crypto.randomBytes(5000))]);
    await sender.svc.send({ files: [prep.files[0].id], to: { devices: ['tok_lena'] } });
    assert.equal(srv.state.sends.size, 1);
    assert.equal([...srv.state.sends.values()][0].items[0].local, true);
    const received = new Promise((r) => receiver.svc.once('received', r));
    receiver.center.handleNotification({ seq: 1, id: 1, kind: 'data', topic: 'plugin:gatecontrol-gatedrop:received', silent: true, title: '', data: pushToB });
    const rec = await received;
    await sender.svc.idle();
    assert.equal(rec.from.own, false);
    assert.match(FakeNotification.shown.at(-1).opts.toastXml, /Marc hat dir foto\.jpg geschickt/);
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
      deviceAccess: async () => ({ ok: true, supported: true, receiveFrom: 'self' }),
      setDeviceAccess: async (m) => { calls.push(['access', m]); return { ok: true, supported: true, receiveFrom: m }; },
    });
    registerGateDropHandlers((ch, fn) => { handlers[ch] = fn; }, {
      gatedrop: svc, log, getMainWindow: () => ({ webContents: { send: (ch, p) => sent.push([ch, p]) } }),
      dialog: { showOpenDialog: async () => ({ canceled: true, filePaths: [] }) },
    });
    assert.equal((await handlers['gatedrop:prepare']({}, { paths: 'C:\\x' })).code, 'invalid');
    assert.equal((await handlers['gatedrop:send']({}, { files: [], text: 'x'.repeat(20001), to: {} })).code, 'invalid');
    assert.equal((await handlers['gatedrop:send']({}, { files: ['a'], to: { people: [8] }, job: 'j1' })).ok, true);
    assert.equal(calls.find((c) => c[0] === 'send')[1].job, 'j1');
    assert.equal((await handlers['gatedrop:show']({}, { path: 'C:\\x' })).code, 'invalid');
    assert.equal((await handlers['gatedrop:pick']({})).code, 'cancelled');
    assert.deepEqual(await handlers['gatedrop:explorer']({}, { enabled: true }), { ok: true, enabled: false, supported: false });
    assert.deepEqual(await handlers['gatedrop:access']({}), { ok: true, supported: true, receiveFrom: 'self' });
    assert.equal((await handlers['gatedrop:access:set']({}, { receiveFrom: 'all' })).code, 'invalid');
    assert.equal((await handlers['gatedrop:access:set']({}, null)).code, 'invalid');
    assert.deepEqual(await handlers['gatedrop:access:set']({}, { receiveFrom: 'everyone' }), { ok: true, supported: true, receiveFrom: 'everyone' });
    assert.deepEqual(calls.filter((c) => c[0] === 'access'), [['access', 'everyone']]);
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

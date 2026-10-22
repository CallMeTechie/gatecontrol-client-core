'use strict';

// GateDrop 1.1.0: files sent to this PC while it was offline. GET pending
// lists the sends waiting for this device; the service saves them like a
// `{ send }` push and acknowledges them (POST sends/<id>/opened). Polled at
// start, on push hello, after resume / network change and with the presence
// tick — debounced, one at a time, deduplicated with live pushes (handled
// send ids persisted in the store). Also: offline own devices as targets
// (upload, delivery status `waiting`).

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const EventEmitter = require('node:events');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const ApiClient = require('../src/services/api-client');
const GateDropService = require('../src/services/gatedrop');
const GateDropApi = require('../src/services/gatedrop-api');
const NotificationCenter = require('../src/services/notification-center');
const { createMemoryStore } = require('./fixtures/memory-store');
const { gatedropServer, MEDIA } = require('./fixtures/gatedrop-server');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const OWN_PIXEL = { userId: 2, name: 'Marc', deviceId: '43', deviceName: 'Pixel' };

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

const wait = (ms) => new Promise((r) => setTimeout(r, ms));

async function until(fn, ms = 3000) {
  const end = Date.now() + ms;
  while (!fn()) {
    if (Date.now() > end) throw new Error('timed out');
    await wait(5);
  }
}

async function setup(srv, { store = createMemoryStore(), downloads = null, timing = {}, pushClient = null, powerMonitor = null, nc = true } = {}) {
  const apiClient = new ApiClient(srv.url, 'gc_token', log);
  const dir = downloads || tmpDir('gd-dl-');
  const center = nc ? new NotificationCenter({ store, log, Notification: FakeNotification, platform: 'win32', protocol: 'gatecontrol-pro' }) : null;
  const api = new GateDropApi({ apiClient, log, sleep: async () => {} });
  const svc = new GateDropService({
    apiClient, api, log, store, listener: false, notificationCenter: center, pushClient, powerMonitor,
    downloadsDir: () => dir, Notification: FakeNotification, platform: 'win32', protocol: 'gatecontrol-pro',
    getInterfaces: () => ({}), timing: { pendingDebounceMs: 60000, ...timing },
  });
  svc.start();
  cleanup.push(async () => { svc.stop(); await svc.idle(); });
  await svc.check();
  return { svc, store, downloads: dir, center };
}

const mediaGets = (srv, mediaId) => srv.state.requests.filter((q) => q.method === 'GET' && q.path === `${MEDIA}/${mediaId}`).length;
const files = (dir) => fs.readdirSync(dir).sort();
const sendPush = (id, seq) => ({ seq, id: seq, topic: 'plugin:gatecontrol-gatedrop:received', title: 'Pixel hat dir 3 Dateien geschickt', body: '', data: { gatedrop: { send: id } } });

function threeFiles(srv) {
  return srv.addSend({
    from: OWN_PIXEL,
    items: [
      { name: 'IMG_1.jpg', data: Buffer.from('eins') },
      { name: 'IMG_2.jpg', data: Buffer.from('zwei') },
      { name: 'IMG_3.jpg', data: Buffer.from('drei') },
    ],
  }, { pending: true });
}

describe('GateDrop pending (sent while offline)', () => {
  it('a poll at start downloads, toasts like a push and acknowledges', async () => {
    const srv = await gatedropServer({ version: '1.1.0' });
    cleanup.push(() => srv.close());
    const older = srv.addSend({ from: { userId: 8, name: 'Anna' }, text: 'Bin gleich da', createdAt: Date.now() - 60000 }, { pending: true });
    const send = threeFiles(srv);

    const store = createMemoryStore();
    const received = [];
    const { svc, downloads } = await setup(srv, { store, timing: { pendingDebounceMs: 5 } });
    svc.on('received', (r) => received.push(r));
    await until(() => srv.state.opened.length === 2);
    await svc.idle();

    // Oldest first: the text, then the files.
    assert.deepEqual(received.map((r) => r.sendId), [older.id, send.id]);
    assert.deepEqual(files(downloads), ['IMG_1.jpg', 'IMG_2.jpg', 'IMG_3.jpg']);
    assert.equal(fs.readFileSync(path.join(downloads, 'IMG_2.jpg'), 'utf8'), 'zwei');
    assert.deepEqual(srv.state.opened, [older.id, send.id]);

    // The same toast as a `{ send }` push: own device named, both buttons.
    assert.equal(FakeNotification.shown.length, 2);
    assert.match(FakeNotification.shown[0].opts.toastXml, /Anna hat dir einen Text geschickt/);
    const xml = FakeNotification.shown[1].opts.toastXml;
    assert.match(xml, /Pixel hat dir 3 Dateien geschickt/);
    assert.match(xml, /Ordner öffnen/);
    assert.match(xml, /Anzeigen/);

    // Persisted; acknowledged sends leave the list, the next poll finds nothing.
    assert.deepEqual(store.get('gatedropHandled').ids, [older.id, send.id]);
    const r = await svc.pollPending();
    assert.deepEqual(r, { ok: true, supported: true, received: 0, failed: 0 });
    assert.equal(FakeNotification.shown.length, 2);
  });

  it('a push and a poll racing for the same send download it once', async () => {
    const srv = await gatedropServer({ version: '1.1.0' });
    cleanup.push(() => srv.close());
    const send = threeFiles(srv);
    const store = createMemoryStore();
    const { svc, downloads, center } = await setup(srv, { store });

    const entry = center.handleNotification(sendPush(send.id, 7));
    const polls = [svc.pollPending(), svc.pollPending()];
    center.handleNotification(sendPush(send.id, 7)); // replay while it runs
    await Promise.all(polls);
    await svc.idle();

    assert.ok(entry, 'the visible push stays in the inbox');
    assert.deepEqual(files(downloads), ['IMG_1.jpg', 'IMG_2.jpg', 'IMG_3.jpg']);
    for (const it of send.items) assert.equal(mediaGets(srv, it.mediaId), 1);
    assert.equal(FakeNotification.shown.length, 1, 'one toast, ours');
    assert.deepEqual(srv.state.opened, [send.id]);

    // App restart: the queued push arrives again → nothing new.
    svc.stop();
    srv.state.sends.get(send.id).deliveries[0].status = 'delivered'; // even if the plugin still lists it
    const again = await setup(srv, { store, downloads });
    again.center.handleNotification(sendPush(send.id, 8));
    await again.svc.pollPending();
    await again.svc.idle();
    assert.deepEqual(files(downloads), ['IMG_1.jpg', 'IMG_2.jpg', 'IMG_3.jpg']);
    for (const it of send.items) assert.equal(mediaGets(srv, it.mediaId), 1);
    assert.equal(FakeNotification.shown.length, 1);
    assert.deepEqual(srv.state.opened, [send.id, send.id], 'still listed → acknowledged again');
  });

  it('404 (plugin older than 1.1.0) and 409 no_device are ignored silently', async () => {
    const srv = await gatedropServer({ version: '1.0.0' });
    cleanup.push(() => srv.close());
    threeFiles(srv);
    srv.state.pendingMode = 404;
    const { svc, downloads } = await setup(srv);
    assert.deepEqual(await svc.pollPending(), { ok: true, supported: false });
    assert.deepEqual(await svc.pollPending(), { ok: true, supported: false });
    assert.equal(srv.state.pendingCalls, 1, 'not asked again for the same plugin version');
    assert.equal(svc.status().state, 'available');

    srv.state.pendingMode = 'no_device';
    svc._pendingOff = undefined;
    assert.deepEqual(await svc.pollPending(), { ok: true, supported: true, received: 0, failed: 0 });
    assert.deepEqual(files(downloads), []);
    assert.equal(FakeNotification.shown.length, 0);
    assert.deepEqual(srv.state.opened, []);
  });

  it('a failed download stays unhandled and the next poll fetches what is missing', async () => {
    const srv = await gatedropServer({ version: '1.1.0' });
    cleanup.push(() => srv.close());
    const send = threeFiles(srv);
    const broken = srv.addSend({ from: { userId: 8, name: 'Anna' }, items: [{ name: 'kaputt.pdf', data: Buffer.from('%PDF') }] }, { pending: true });
    srv.state.mediaFail.add(send.items[2].mediaId);
    srv.state.mediaFail.add(broken.items[0].mediaId);
    const store = createMemoryStore();
    const { svc, downloads } = await setup(srv, { store });

    const r1 = await svc.pollPending();
    await svc.idle();
    assert.deepEqual(r1, { ok: true, supported: true, received: 0, failed: 2 });
    assert.deepEqual(files(downloads), ['IMG_1.jpg', 'IMG_2.jpg']);
    assert.deepEqual(srv.state.opened, [], 'not acknowledged');
    assert.equal(store.get('gatedropHandled'), undefined);
    assert.equal(FakeNotification.shown.length, 2);
    assert.match(FakeNotification.shown[0].opts.toastXml, /Pixel hat dir 2 Dateien geschickt/);
    assert.match(FakeNotification.shown[1].opts.toastXml, /Empfang fehlgeschlagen/);

    // Still broken: tried again quietly (no second failure toast).
    const r2 = await svc.pollPending();
    assert.equal(r2.failed, 2);
    assert.equal(FakeNotification.shown.length, 2);

    srv.state.mediaFail.clear();
    const r3 = await svc.pollPending();
    await svc.idle();
    assert.deepEqual(r3, { ok: true, supported: true, received: 2, failed: 0 });
    assert.deepEqual(files(downloads), ['IMG_1.jpg', 'IMG_2.jpg', 'IMG_3.jpg', 'kaputt.pdf']);
    assert.equal(mediaGets(srv, send.items[0].mediaId), 1, 'saved items are not fetched again');
    assert.equal(mediaGets(srv, send.items[1].mediaId), 1);
    assert.deepEqual(srv.state.opened, [send.id, broken.id]);
    assert.match(FakeNotification.shown[2].opts.toastXml, /Pixel hat dir IMG_3\.jpg geschickt/);
    // The saved list knows all three files of the send.
    const rec = store.get('gatedropSaved').items.find((x) => x.sendId === send.id);
    assert.deepEqual(rec.files.map((f) => f.name), ['IMG_1.jpg', 'IMG_2.jpg', 'IMG_3.jpg']);
  });

  it('polls on hello, presence tick and resume — debounced, never two at once', async () => {
    const srv = await gatedropServer({ version: '1.1.0' });
    cleanup.push(() => srv.close());
    const pushClient = new EventEmitter();
    const powerMonitor = new EventEmitter();
    const { svc } = await setup(srv, { pushClient, powerMonitor, timing: { pendingDebounceMs: 20, resumeDelayMs: 20, presenceMs: 60000 } });
    await until(() => srv.state.pendingCalls === 1); // available at start
    await svc.idle();

    for (let i = 0; i < 3; i++) pushClient.emit('hello', {});
    await wait(60);
    await svc.idle();
    assert.equal(srv.state.pendingCalls, 2, 'three hellos → one poll');

    powerMonitor.emit('resume');
    await until(() => srv.state.pendingCalls === 3);
    await svc.idle();

    // Calls while a poll runs: one more round afterwards, not a second parallel poll.
    let inFlight = 0;
    let maxInFlight = 0;
    const orig = svc.api.pending.bind(svc.api);
    svc.api.pending = async () => { inFlight++; maxInFlight = Math.max(maxInFlight, inFlight); try { await wait(20); return await orig(); } finally { inFlight--; } };
    await Promise.all([svc.pollPending(), svc.pollPending(), svc.pollPending()]);
    assert.equal(maxInFlight, 1);
    assert.equal(srv.state.pendingCalls, 5, 'one poll + one more round');

    svc.stop();
    powerMonitor.emit('resume');
    pushClient.emit('hello', {});
    await wait(50);
    assert.equal(srv.state.pendingCalls, 5, 'stopped: no more polls');
    assert.equal(powerMonitor.listenerCount('resume'), 0);
  });
});

describe('GateDrop to an offline own device', () => {
  it('is a target and goes through the server (upload, delivery `waiting`)', async () => {
    const srv = await gatedropServer({ version: '1.1.0' });
    cleanup.push(() => srv.close());
    srv.state.targets.devices = [
      { id: '43', name: 'Pixel', platform: 'android', online: false, direct: false, mode: null },
      { id: '44', name: 'Büro-PC', platform: 'windows', online: true, direct: true, mode: 'push' },
    ];
    const { svc } = await setup(srv, { nc: false });
    const tg = await svc.targets();
    assert.deepEqual(tg.devices.map((d) => [d.id, d.online]), [['43', false], ['44', true]]);

    const dir = tmpDir('gd-src-');
    const src = path.join(dir, 'urlaub.jpg');
    fs.writeFileSync(src, 'jpeg-bytes');
    for (const devices of [['43'], ['43', '44']]) {
      const prep = await svc.prepareFiles([src]);
      const before = srv.state.uploadCalls.length;
      const r = await svc.send({ files: [prep.files[0].id], to: { devices } });
      assert.equal(srv.state.uploadCalls.length, before + 1, 'uploaded, not local');
      const st = srv.state.sends.get(r.id);
      assert.equal(st.items[0].local, false);
      assert.equal(srv.state.media.get(st.items[0].mediaId).data.toString(), 'jpeg-bytes');
      const pixel = r.deliveries.find((d) => d.target === '43');
      assert.equal(pixel.status, 'waiting');
      assert.equal(pixel.targetName, 'Pixel');
    }
    assert.deepEqual(srv.state.requests.filter((q) => q.path.includes('/transfers/')), [], 'no direct transfer');

    // The sent list keeps `waiting`.
    srv.state.inbox.sent = [srv.view(srv.state.sends.values().next().value, 'sent')];
    const sent = await svc.inbox({ kind: 'sent', refresh: true });
    assert.equal(sent.items[0].deliveries[0].status, 'waiting');
  });
});

describe('GateDrop pending – entries', () => {
  it('own sends (role "sent") are fetched; one already opened on this device is skipped', async () => {
    const srv = await gatedropServer({ version: '1.1.0' });
    cleanup.push(() => srv.close());
    const send = threeFiles(srv);
    const done = srv.addSend({ from: OWN_PIXEL, items: [{ name: 'alt.jpg', data: Buffer.from('alt') }] }, { pending: true });
    const { svc, downloads } = await setup(srv);
    const orig = svc.api.pending.bind(svc.api);
    svc.api.pending = async () => {
      const list = await orig();
      assert.ok(list.every((s) => s.role === 'sent'));
      // The plugin lists it once more although this device opened it already.
      const v = JSON.parse(JSON.stringify(srv.view(srv.state.sends.get(done.id), 'sent')));
      v.deliveries[0].status = 'opened';
      return list.map((s) => (s.id === done.id ? require('../src/utils/gatedrop').normalizeSend(v) : s));
    };
    const r = await svc.pollPending();
    await svc.idle();
    assert.deepEqual(r, { ok: true, supported: true, received: 1, failed: 0 });
    assert.deepEqual(files(downloads), ['IMG_1.jpg', 'IMG_2.jpg', 'IMG_3.jpg']);
    assert.deepEqual(srv.state.opened, [send.id]);
    // Calling pending flipped this device's `waiting` to `delivered` on the server.
    assert.equal(srv.state.sends.get(done.id).deliveries[0].status, 'delivered');
  });

  it('a link-only send: toast with "Öffnen" / "Kopieren", then opened', async () => {
    const srv = await gatedropServer({ version: '1.1.0' });
    cleanup.push(() => srv.close());
    const send = srv.addSend({ from: OWN_PIXEL, link: 'https://example.org/rezept' }, { pending: true });
    const { svc, downloads } = await setup(srv);
    await svc.pollPending();
    await svc.idle();
    const xml = FakeNotification.shown[0].opts.toastXml;
    assert.match(xml, /Pixel hat dir einen Link geschickt/);
    assert.match(xml, /Öffnen/);
    assert.match(xml, /Kopieren/);
    assert.deepEqual(files(downloads), []);
    assert.deepEqual(srv.state.opened, [send.id]);
  });
});

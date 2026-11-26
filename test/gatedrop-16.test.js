'use strict';

// GateDrop 1.6 in the Windows client: the sender's ok leaves a direct delivery 'direct'; only the receiving device's
// confirmation makes it 'delivered' / 'opened' (pickedAt). Without one 20 s after the sender's ok the plugin takes the
// server way (files only on the sender → pending + direct_failed). This PC as the sender therefore asks GET sends/<id>
// ~30 s after its own ok — meanwhile phase 'sent' ("Wird übertragen …"), no early "direkt gesendet" — and uploads the
// files (POST sends/<id>/items) when the delivery waits for them. Older plugins (delivered at once) are done at once.

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const ApiClient = require('../src/services/api-client');
const GateDropService = require('../src/services/gatedrop');
const GateDropApi = require('../src/services/gatedrop-api');
const { createMemoryStore } = require('./fixtures/memory-store');
const { gatedropServer } = require('./fixtures/gatedrop-server');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const KEY_B64 = () => crypto.randomBytes(32).toString('base64');
const TICKET = () => `tkt_${crypto.randomBytes(12).toString('base64url')}`;

const cleanup = [];
afterEach(async () => {
  for (const fn of cleanup.splice(0).reverse()) { try { await fn(); } catch { /* ignore */ } }
});

function tmpDir(prefix) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  cleanup.push(() => fs.rmSync(d, { recursive: true, force: true }));
  return d;
}

async function server(opts = {}) {
  const srv = await gatedropServer({ version: '1.6.0', ...opts });
  cleanup.push(() => srv.close());
  return srv;
}

/** This PC sends one local file directly to device 43 (push); the fake pushTo "delivers" everything. */
async function sendDirect(srv, { timing = {} } = {}) {
  srv.state.targets.devices = [{ id: '43', name: 'Pixel', platform: 'android', online: true, direct: true }];
  srv.state.direct = () => [{ deviceId: '43', transferId: `tr_${crypto.randomBytes(6).toString('hex')}`, mode: 'push', candidates: ['127.0.0.1:9'], key: KEY_B64(), ticket: TICKET() }];
  const direct = {
    pushTo: async ({ files }) => ({ bytes: files.reduce((s, f) => s + f.size, 0) }),
    pullFrom: async () => { throw new Error('unused'); },
  };
  const apiClient = new ApiClient(srv.url, 'gc_token', log);
  const api = new GateDropApi({ apiClient, log, sleep: async () => {} });
  const downloads = tmpDir('gd16-dl-');
  const svc = new GateDropService({
    apiClient, api, log, store: createMemoryStore(), listener: false, downloadsDir: () => downloads, platform: 'linux', direct,
    timing: { directVerifyMs: [0, 20, 20, 20, 20, 20], ...timing }, powerMonitor: null,
  });
  svc.start();
  cleanup.push(async () => { svc.stop(); await svc.idle(); });
  await svc.check();
  const dir = tmpDir('gd16-src-');
  const file = path.join(dir, 'video.mp4');
  fs.writeFileSync(file, Buffer.from('mp4-data'));
  const prep = await svc.prepareFiles([file]);
  const events = [];
  svc.on('progress', (e) => events.push(e));
  const r = await svc.send({ files: [prep.files[0].id], to: { devices: ['43'] } });
  await svc.idle();
  return { r, events, svc };
}

const gets = (srv, id) => srv.state.requests.filter((q) => q.method === 'GET' && q.path.endsWith(`/sends/${id}`)).length;

describe('GateDrop 1.6 – the sender waits for the receiver\'s confirmation', () => {
  it('our ok leaves the delivery direct; the receiver confirms → delivered, done directly, nothing goes up', async () => {
    const srv = await server();
    srv.state.receiverAfterOk = { ok: true, bytes: 8 };
    srv.state.receiverDelayMs = 50;
    const { r, events } = await sendDirect(srv);
    assert.equal(srv.state.addItems.length, 0);
    assert.equal(srv.state.uploadCalls.length, 0);
    assert.deepEqual([events.at(-1).phase, events.at(-1).via], ['done', 'direct']);
    const dl = srv.state.sends.get(r.id).deliveries[0];
    assert.deepEqual([dl.status, dl.via, !!dl.pickedAt], ['delivered', 'direct', true]);
    assert.ok(gets(srv, r.id) >= 2, 'asked until the receiver confirmed');
    // while waiting: "Wird übertragen …" (phase 'sent') once — not "direkt gesendet" before the confirmation
    const handover = events.filter((e) => e.phase === 'sent' && e.handover);
    assert.equal(handover.length, 1);
    assert.equal(handover[0].sendId, r.id);
    assert.ok(events.indexOf(handover[0]) < events.length - 1);
  });

  it('the receiver opened it (opened): done directly', async () => {
    const srv = await server();
    // play the receiving device: POST sends/<id>/opened of device 43 → opened with pickedAt
    const timer = setInterval(() => {
      for (const st of srv.state.sends.values()) {
        const dl = st.deliveries.find((d) => d.kind === 'device' && d.target === '43' && d.status === 'direct');
        if (dl && srv.state.results.length) Object.assign(dl, { status: 'opened', via: 'direct', pickedAt: Date.now() });
      }
    }, 10);
    cleanup.push(() => clearInterval(timer));
    const { r, events } = await sendDirect(srv);
    assert.equal(srv.state.addItems.length, 0);
    assert.deepEqual([events.at(-1).phase, events.at(-1).via], ['done', 'direct']);
    assert.equal(srv.state.sends.get(r.id).deliveries[0].status, 'opened');
  });

  it('no confirmation: the plugin falls back (pending + direct_failed) → the files go up, POST sends/<id>/items', async () => {
    const srv = await server();
    srv.state.confirmMs = 60; // the plugin's 20 s, shortened
    const { r, events } = await sendDirect(srv);
    assert.equal(srv.state.addItems.length, 1);
    assert.equal(srv.state.addItems[0].sendId, r.id);
    assert.deepEqual(srv.state.addItems[0].items.map((x) => x.index), [0]);
    assert.equal(srv.state.media.get(srv.state.addItems[0].items[0].mediaId).data.toString(), 'mp4-data');
    assert.ok(events.some((e) => e.phase === 'sent' && e.handover));
    assert.ok(events.some((e) => e.phase === 'failed'));
    assert.deepEqual([events.at(-1).phase, events.at(-1).via], ['done', 'server']);
    const dl = srv.state.sends.get(r.id).deliveries[0];
    assert.deepEqual([dl.status, dl.via], ['delivered', 'server']);
  });

  it('the receiver reports incomplete: the files go up as well', async () => {
    const srv = await server();
    srv.state.receiverAfterOk = { ok: false, error: 'incomplete' };
    srv.state.receiverDelayMs = 30;
    const { r, events } = await sendDirect(srv);
    assert.equal(srv.state.addItems.length, 1);
    assert.equal(srv.state.addItems[0].sendId, r.id);
    assert.deepEqual([events.at(-1).phase, events.at(-1).via], ['done', 'server']);
  });

  it('timeout: no decision within the wait (still direct) → done as sent, nothing goes up, no endless asking', async () => {
    const srv = await server();
    srv.state.confirmMs = 60 * 60 * 1000; // the plugin never falls back within the wait
    const { r, events } = await sendDirect(srv, { timing: { directVerifyMs: [0, 10, 10, 10] } });
    assert.equal(srv.state.addItems.length, 0);
    assert.equal(srv.state.uploadCalls.length, 0);
    assert.equal(gets(srv, r.id), 4, 'asked once per wait, then stopped');
    assert.deepEqual([events.at(-1).phase, events.at(-1).via], ['done', 'direct']);
    assert.equal(srv.state.sends.get(r.id).deliveries[0].status, 'direct');
  });

  it('an older plugin (1.4: delivered at once, no pickedAt): one look, no waiting, no "Wird übertragen", nothing goes up', async () => {
    const srv = await server({ version: '1.4.1' });
    const { r, events } = await sendDirect(srv, { timing: { directVerifyMs: [0, 5000, 5000] } });
    assert.equal(srv.state.addItems.length, 0);
    assert.deepEqual([events.at(-1).phase, events.at(-1).via], ['done', 'direct']);
    assert.equal(gets(srv, r.id), 1);
    assert.equal(events.filter((e) => e.handover).length, 0);
  });
});

describe('GateDropService._pickup', () => {
  const send = (dl, extra = {}) => ({ removed: false, items: [], deliveries: [{ kind: 'device', target: '43', ...dl }], ...extra });
  it('decides from the delivery of the device', () => {
    assert.equal(GateDropService._pickup(send({ status: 'direct', via: null, pickedAt: null }), '43'), 'wait');
    assert.equal(GateDropService._pickup(send({ status: 'delivered', via: 'direct', pickedAt: null }), '43'), 'wait');
    assert.equal(GateDropService._pickup(send({ status: 'delivered', via: 'direct', pickedAt: '2026-11-19T10:00:00.000Z' }), '43'), 'direct');
    assert.equal(GateDropService._pickup(send({ status: 'opened', via: 'direct', pickedAt: null }), '43'), 'direct');
    assert.equal(GateDropService._pickup(send({ status: 'pending', error: 'direct_failed', pickedAt: null }), '43'), 'upload');
    assert.equal(GateDropService._pickup(send({ status: 'delivered', via: 'server', error: 'direct_failed', pickedAt: null }), '43'), 'server');
    assert.equal(GateDropService._pickup(send({ status: 'delivered', via: 'direct' }), '43'), 'direct'); // no pickedAt key: older plugin
    assert.equal(GateDropService._pickup(send({ status: 'failed', pickedAt: null }), '43'), 'direct');
    assert.equal(GateDropService._pickup(send({ status: 'direct', pickedAt: null }, { removed: true }), '43'), 'direct');
    assert.equal(GateDropService._pickup(send({ status: 'direct', pickedAt: null }), '44'), 'direct');
    assert.equal(GateDropService._pickup(null, '43'), 'direct');
  });
});

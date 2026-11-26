'use strict';

// GateDrop 1.5 in the Windows client (the plugin's report "was die Apps nachziehen"):
//   - a send received through a push is acknowledged (POST sends/<id>/opened — the pick-up) right after it was saved,
//     not only by the next GET pending;
//   - a direct transfer to this PC reports ok only with every file and always with `bytes` (the plaintext size);
//     a part of it is 'incomplete' (the files that came are removed, the server way brings everything);
//   - after this PC's own ok as the sender it asks GET sends/<id> until the receiving end decided: confirmed (pickedAt)
//     → done; not everything arrived (pending + direct_failed, the plugin's `fallback: 'upload'`) → the files go up and
//     POST sends/<id>/items; an older plugin (no pickedAt) is not waited for.

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const ApiClient = require('../src/services/api-client');
const GateDropService = require('../src/services/gatedrop');
const GateDropApi = require('../src/services/gatedrop-api');
const gd = require('../src/utils/gatedrop');
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
  const srv = await gatedropServer({ version: '1.5.0', ...opts });
  cleanup.push(() => srv.close());
  return srv;
}

async function setup(srv, { direct = null, timing = {} } = {}) {
  const apiClient = new ApiClient(srv.url, 'gc_token', log);
  const downloads = tmpDir('gd15-dl-');
  const api = new GateDropApi({ apiClient, log, sleep: async () => {} });
  const svc = new GateDropService({
    apiClient, api, log, store: createMemoryStore(), listener: false, downloadsDir: () => downloads, platform: 'linux', direct,
    timing: { directVerifyMs: [0, 20, 20, 20, 20, 20], ...timing }, powerMonitor: null,
  });
  svc.start();
  cleanup.push(async () => { svc.stop(); await svc.idle(); });
  await svc.check();
  return { svc, downloads };
}

const pushOf = (sendId) => ({ topic: 'plugin:gatecontrol-gatedrop:received', kind: 'data', data: { gatedrop: { send: sendId } } });

describe('GateDrop 1.5 – the receipt of a pushed send', () => {
  it('saved → POST sends/<id>/opened at once (no GET pending needed); the next poll does not send it again', async () => {
    const srv = await server();
    const { svc, downloads } = await setup(srv);
    const send = srv.addSend({ from: { name: 'Anna' }, items: [{ name: 'plan.pdf', data: Buffer.from('%PDF') }] }, { pending: true });
    const before = srv.state.pendingCalls;
    assert.equal(svc._onPush(pushOf(send.id)), 'consumed');
    await svc.idle();
    assert.equal(fs.readFileSync(path.join(downloads, 'plan.pdf'), 'utf8'), '%PDF');
    assert.deepEqual(srv.state.opened, [send.id]);
    assert.equal(srv.state.pendingCalls, before, 'acknowledged without waiting for GET pending');
    // the plugin marks this device's delivery picked up (pickedAt) — the sender sees "empfangen"
    const own = srv.view(srv.state.sends.get(send.id), 'sent').deliveries[0];
    assert.equal(own.status, 'opened');
    assert.ok(own.pickedAt);
    await svc.pollPending();
    assert.deepEqual(srv.state.opened, [send.id], 'acknowledged once');
  });

  it('a failed download is not acknowledged (the next poll tries again and acknowledges then)', async () => {
    const srv = await server();
    const { svc } = await setup(srv);
    const send = srv.addSend({ from: { name: 'Anna' }, items: [{ name: 'a.txt', data: Buffer.from('a'), mediaId: 'm'.repeat(32) }] }, { pending: true });
    srv.state.mediaFail.add('m'.repeat(32));
    svc._onPush(pushOf(send.id));
    await svc.idle();
    assert.deepEqual(srv.state.opened, []);
    srv.state.mediaFail.clear();
    const r = await svc.pollPending();
    assert.equal(r.received, 1);
    assert.deepEqual(srv.state.opened, [send.id]);
  });
});

describe('GateDrop 1.5 – a direct transfer to this PC: ok only with every file, always with bytes', () => {
  /** A direct push of a send with local items (the PC pulls them); `pullFrom` decides what arrives. */
  function pullSetup(srv, items) {
    const send = srv.addSend({ from: { name: 'Pixel', own: true }, items: items.map((it) => ({ ...it, local: true })) });
    const transferId = `tr_${crypto.randomBytes(6).toString('hex')}`;
    srv.state.transfers.set(transferId, { id: transferId, sendId: send.id, side: 'receiver', mode: 'pull', status: 'open', fromDevice: '43', toDevice: '42', candidates: ['127.0.0.1:9'], key: KEY_B64(), ticket: TICKET(), items: items.map((it, i) => ({ index: i, name: it.name, bytes: it.bytes })) });
    const tr = srv.state.transfers.get(transferId);
    return gd.parsePushData({ gatedrop: { transfer: transferId, send: send.id, mode: 'pull', from: { name: 'Pixel' }, items: tr.items, candidates: tr.candidates, key: tr.key, ticket: tr.ticket } });
  }
  const fakePull = (take) => ({
    pushTo: async () => { throw new Error('unused'); },
    pullFrom: async ({ items, sink }) => {
      const saved = [];
      for (const it of items.slice(0, take)) {
        const t = await sink({ index: it.index, name: it.name, bytes: it.bytes });
        t.stream.end(Buffer.alloc(it.bytes, 1));
        saved.push({ index: it.index, name: it.name, path: await t.commit(), bytes: it.bytes });
      }
      return { items: saved, bytes: saved.reduce((s, x) => s + x.bytes, 0) };
    },
  });

  it('every file: ok with bytes = the sum of the plaintext sizes', async () => {
    const srv = await server();
    const { svc } = await setup(srv, { direct: fakePull(2) });
    const p = pullSetup(srv, [{ name: 'a.jpg', bytes: 300 }, { name: 'b.jpg', bytes: 700 }]);
    const r = await svc.receiveDirect(p);
    assert.equal(r.ok, true);
    assert.deepEqual(srv.state.results.map((x) => [x.ok, x.bytes]), [[true, 1000]]);
  });

  it('a part of the files: no ok — incomplete, what came is removed, nothing recorded', async () => {
    const srv = await server();
    const { svc, downloads } = await setup(srv, { direct: fakePull(1) });
    const p = pullSetup(srv, [{ name: 'a.jpg', bytes: 300 }, { name: 'b.jpg', bytes: 700 }]);
    const received = [];
    svc.on('received', (x) => received.push(x));
    const r = await svc.receiveDirect(p);
    assert.deepEqual(r, { ok: false, error: 'incomplete' });
    assert.deepEqual(srv.state.results.map((x) => [x.ok, x.error]), [[false, 'incomplete']]);
    assert.deepEqual(fs.readdirSync(downloads), []);
    assert.equal(received.length, 0);
  });

  it('the count unknown (the push left the items out and GET transfers/<id> does not say): no ok with what came', async () => {
    const srv = await server();
    const { svc } = await setup(srv, { direct: fakePull(1) });
    const p = pullSetup(srv, [{ name: 'a.jpg', bytes: 300 }]);
    srv.state.transfers.get(p.transferId).items = [];
    // pullFrom needs the items; the service only knows them from the push here — the check then has nothing to compare with
    const r = await svc._missingOf({ ...p, items: [], itemCount: 0 }, [{ index: 0, bytes: 300 }]);
    assert.equal(r, 'unknown');
    assert.equal(await svc._missingOf({ ...p, items: [], itemCount: 1 }, [{ index: 0, bytes: 300 }]), null);
    assert.equal(await svc._missingOf(p, [{ index: 0, bytes: 299 }]), 'size');
  });
});

describe('GateDrop 1.5 – the sender after its own ok', () => {
  /** This PC sends one local file directly to device 43 (push); the fake pushTo "delivers" everything. */
  async function sendDirect(srv, { timing, pushed } = {}) {
    srv.state.targets.devices = [{ id: '43', name: 'Pixel', platform: 'android', online: true, direct: true }];
    srv.state.direct = () => [{ deviceId: '43', transferId: `tr_${crypto.randomBytes(6).toString('hex')}`, mode: 'push', candidates: ['127.0.0.1:9'], key: KEY_B64(), ticket: TICKET() }];
    const direct = {
      pushTo: async ({ files, transferId }) => {
        if (pushed) pushed(transferId);
        return { bytes: files.reduce((s, f) => s + f.size, 0) };
      },
      pullFrom: async () => { throw new Error('unused'); },
    };
    const { svc } = await setup(srv, { direct, timing });
    const dir = tmpDir('gd15-src-');
    const file = path.join(dir, 'video.mp4');
    fs.writeFileSync(file, Buffer.from('mp4-data'));
    const prep = await svc.prepareFiles([file]);
    const events = [];
    svc.on('progress', (e) => events.push(e));
    const r = await svc.send({ files: [prep.files[0].id], to: { devices: ['43'] } });
    await svc.idle();
    return { r, events, svc };
  }

  it('the receiver reports that not everything arrived (after our ok): the files go up, POST sends/<id>/items', async () => {
    const srv = await server();
    srv.state.receiverAfterOk = { ok: false, error: 'incomplete' };
    srv.state.receiverDelayMs = 30;
    const { r, events } = await sendDirect(srv);
    assert.equal(srv.state.addItems.length, 1);
    assert.equal(srv.state.addItems[0].sendId, r.id);
    assert.deepEqual(srv.state.addItems[0].items.map((x) => x.index), [0]);
    assert.equal(srv.state.media.get(srv.state.addItems[0].items[0].mediaId).data.toString(), 'mp4-data');
    assert.ok(events.some((e) => e.phase === 'failed'));
    assert.deepEqual([events.at(-1).phase, events.at(-1).via], ['done', 'server']);
    const dl = srv.state.sends.get(r.id).deliveries[0];
    assert.deepEqual([dl.status, dl.via], ['delivered', 'server']);
  });

  it('the receiver failed before our ok (our answer: pending + direct_failed): the files go up right away', async () => {
    const srv = await server();
    let calls = 0;
    const { r, events } = await sendDirect(srv, {
      pushed: (transferId) => {
        const tr = srv.state.transfers.get(transferId);
        const dl = srv.state.sends.get(tr.sendId).deliveries[0];
        Object.assign(dl, { status: 'pending', via: null, error: 'direct_failed' });
        calls++;
      },
    });
    assert.equal(calls, 1);
    assert.equal(srv.state.addItems.length, 1);
    assert.equal(srv.state.addItems[0].sendId, r.id);
    assert.equal(events.at(-1).via, 'server');
  });

  it('the receiver confirms (pickedAt): done directly, nothing goes up', async () => {
    const srv = await server();
    srv.state.receiverAfterOk = { ok: true, bytes: 8 };
    srv.state.receiverDelayMs = 30;
    const { r, events } = await sendDirect(srv);
    assert.equal(srv.state.addItems.length, 0);
    assert.equal(srv.state.uploadCalls.length, 0);
    assert.deepEqual([events.at(-1).phase, events.at(-1).via], ['done', 'direct']);
    assert.ok(srv.state.sends.get(r.id).deliveries[0].pickedAt);
    assert.ok(srv.state.requests.filter((q) => q.method === 'GET' && q.path.endsWith(`/sends/${r.id}`)).length >= 2, 'asked until the receiver decided');
  });

  it('an older plugin (no pickedAt): one look, no waiting, nothing goes up', async () => {
    const srv = await server({ version: '1.4.1' });
    const { r, events } = await sendDirect(srv, { timing: { directVerifyMs: [0, 5000, 5000] } });
    assert.equal(srv.state.addItems.length, 0);
    assert.deepEqual([events.at(-1).phase, events.at(-1).via], ['done', 'direct']);
    assert.equal(srv.state.requests.filter((q) => q.method === 'GET' && q.path.endsWith(`/sends/${r.id}`)).length, 1);
  });
});

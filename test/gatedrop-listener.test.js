'use strict';

// GateDrop LAN listener (protocol C): only announced transfers with the
// right ticket, names with path parts refused, size limits, wrong body
// lengths, tampered data, private peers only, pull of offered items.

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');

const GateDropListener = require('../src/services/gatedrop-listener');
const gd = require('../src/utils/gatedrop');
const c = require('../src/utils/gatedrop-crypto');
const direct = require('../src/services/gatedrop-direct');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const KEY = crypto.randomBytes(32);
const TICKET = 'tkt_' + crypto.randomBytes(12).toString('base64url');
const loopback = (v) => { const m = /^(127\.0\.0\.1):(\d+)$/.exec(v); return m ? { host: m[1], port: Number(m[2]) } : null; };

function post(port, transferId, { ticket = TICKET, item = 0, name = 'bild.jpg', size, body, contentLength } = {}) {
  return new Promise((resolve, reject) => {
    const headers = { 'X-GD-Ticket': ticket, 'X-GD-Item': String(item), 'X-GD-Name': gd.encodeName(name), 'X-GD-Size': String(size) };
    headers['Content-Length'] = String(contentLength !== undefined ? contentLength : body.length);
    const req = http.request({ host: '127.0.0.1', port, method: 'POST', path: `/gatedrop/v1/transfer/${transferId}`, headers, agent: false }, (res) => {
      const parts = [];
      res.on('data', (d) => parts.push(d));
      res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(parts).toString() || '{}') }));
    });
    req.on('error', (e) => (e.code === 'ECONNRESET' || e.code === 'EPIPE' ? resolve({ status: 'reset' }) : reject(e)));
    req.end(body);
  });
}

function sinkTo(dir) {
  return async ({ name }) => {
    const final = path.join(dir, name);
    const tmp = `${final}.part`;
    const stream = fs.createWriteStream(tmp);
    return {
      stream,
      commit: async () => { await fs.promises.rename(tmp, final); return final; },
      abort: async () => { await fs.promises.unlink(tmp).catch(() => {}); },
    };
  };
}

describe('GateDrop listener', () => {
  let dir;
  let l;
  let port;
  beforeEach(async () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gd-listener-'));
    l = new GateDropListener({ log, port: 0, bindAddresses: ['127.0.0.1'], isAllowedPeer: () => true, maxBytes: 64 * 1024 });
    await l.start();
    port = l.status().addresses[0].port;
  });
  afterEach(async () => {
    await l.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('binds only the given LAN addresses and reports them', () => {
    const st = l.status();
    assert.equal(st.listening, true);
    assert.deepEqual(st.addresses.map((a) => a.ip), ['127.0.0.1']);
  });

  it('receives an announced item and decrypts it', async () => {
    const plain = crypto.randomBytes(5000);
    const done = l.expectIncoming({ transferId: 'tr_ok', ticket: TICKET, key: KEY, items: [{ index: 0, name: 'urlaub.jpg', bytes: plain.length }], sink: sinkTo(dir) });
    const r = await post(port, 'tr_ok', { size: plain.length, body: c.encryptBuffer(KEY, 'tr_ok', plain), name: 'urlaub.jpg' });
    assert.equal(r.status, 200);
    const items = await done;
    assert.deepEqual(fs.readFileSync(items[0].path), plain);
    assert.equal(path.basename(items[0].path), 'urlaub.jpg');
    // The ticket ended with the transfer.
    const again = await post(port, 'tr_ok', { size: plain.length, body: c.encryptBuffer(KEY, 'tr_ok', plain) });
    assert.equal(again.status, 403);
  });

  it('refuses unknown transfers and wrong tickets alike', async () => {
    const body = c.encryptBuffer(KEY, 'tr_x', Buffer.from('hi'));
    assert.equal((await post(port, 'tr_unknown', { size: 2, body })).status, 403);
    l.expectIncoming({ transferId: 'tr_x', ticket: TICKET, key: KEY, items: [{ index: 0, name: 'a.txt', bytes: 2 }], sink: sinkTo(dir) });
    const r = await post(port, 'tr_x', { size: 2, body, ticket: 'tkt_wrongwrongwrong' });
    assert.equal(r.status, 403);
    assert.deepEqual(r.body, { error: 'forbidden' });
    assert.deepEqual(fs.readdirSync(dir), []);
  });

  it('asks the plugin for a transfer it does not know yet', async () => {
    const plain = Buffer.from('from the sender before the push');
    l.resolveIncoming = async (id) => {
      l.expectIncoming({ transferId: id, ticket: TICKET, key: KEY, items: [{ index: 0, name: 'n.txt', bytes: plain.length }], sink: sinkTo(dir) });
    };
    const r = await post(port, 'tr_late', { size: plain.length, body: c.encryptBuffer(KEY, 'tr_late', plain), name: 'n.txt' });
    assert.equal(r.status, 200);
  });

  it('refuses names with path parts', async () => {
    l.expectIncoming({ transferId: 'tr_n', ticket: TICKET, key: KEY, items: [], sink: sinkTo(dir) });
    for (const name of ['../../evil.exe', '..\\boot.ini', 'C:\\Windows\\win.ini', 'sub/dir.txt', '..']) {
      const r = await post(port, 'tr_n', { size: 1, body: c.encryptBuffer(KEY, 'tr_n', Buffer.from('x')), name });
      assert.equal(r.status, 400, name);
      assert.equal(r.body.error, 'bad_name');
    }
    assert.deepEqual(fs.readdirSync(dir), []);
  });

  it('refuses oversized items and wrong body lengths', async () => {
    l.expectIncoming({ transferId: 'tr_big', ticket: TICKET, key: KEY, items: [], sink: sinkTo(dir) });
    const big = await post(port, 'tr_big', { size: 64 * 1024 + 1, body: Buffer.alloc(10), contentLength: 10 });
    assert.equal(big.status, 413);
    const wrong = await post(port, 'tr_big', { size: 100, body: c.encryptBuffer(KEY, 'tr_big', Buffer.alloc(50)) });
    assert.equal(wrong.status, 400);
    assert.equal(wrong.body.error, 'bad_length');
    assert.deepEqual(fs.readdirSync(dir), []);
  });

  it('refuses a size other than announced by the plugin', async () => {
    l.expectIncoming({ transferId: 'tr_sz', ticket: TICKET, key: KEY, items: [{ index: 0, name: 'a', bytes: 10 }], sink: sinkTo(dir) });
    const r = await post(port, 'tr_sz', { size: 20, body: c.encryptBuffer(KEY, 'tr_sz', Buffer.alloc(20)) });
    assert.equal(r.status, 400);
    assert.equal(r.body.error, 'size_mismatch');
  });

  it('tampered data is refused and nothing is kept', async () => {
    l.expectIncoming({ transferId: 'tr_t', ticket: TICKET, key: KEY, items: [{ index: 0, name: 'a.bin', bytes: 3000 }], sink: sinkTo(dir) });
    const body = c.encryptBuffer(KEY, 'tr_t', crypto.randomBytes(3000));
    body[100] ^= 0xff;
    const r = await post(port, 'tr_t', { size: 3000, body, name: 'a.bin' });
    assert.equal(r.status, 400);
    assert.equal(r.body.error, 'auth_failed');
    assert.deepEqual(fs.readdirSync(dir), []);
    assert.equal(l.hasIncoming('tr_t'), true); // the sender may try again within the ticket time
  });

  it('expired tickets are refused', async () => {
    let now = 1000;
    l.now = () => now;
    l.expectIncoming({ transferId: 'tr_e', ticket: TICKET, key: KEY, items: [{ index: 0, name: 'a', bytes: 1 }], sink: sinkTo(dir) }).catch(() => {});
    now += gd.TICKET_TTL_MS + 1;
    const r = await post(port, 'tr_e', { size: 1, body: c.encryptBuffer(KEY, 'tr_e', Buffer.from('a')) });
    assert.equal(r.status, 403);
  });

  it('a pull that started and broke off ends with the ticket (the sender does not wait for ever)', async () => {
    let now = 1000;
    l.now = () => now;
    const src = path.join(dir, 'two.bin');
    fs.writeFileSync(src, Buffer.alloc(10, 1));
    const offer = l.offerOutgoing({ transferId: 'tr_half', ticket: TICKET, key: KEY, items: [{ path: src, name: 'a', size: 10 }, { path: src, name: 'b', size: 10 }] });
    const out = fs.mkdtempSync(path.join(os.tmpdir(), 'gd-half-'));
    // the device fetches item 0, never item 1
    await direct.pullFrom({ candidates: [`127.0.0.1:${port}`], transferId: 'tr_half', ticket: TICKET, key: KEY, items: [{ index: 0, name: 'a', bytes: 10 }], sink: sinkTo(out), resolveCandidate: loopback });
    assert.equal(offer.started(), true);
    l.sweep();
    now += gd.TICKET_TTL_MS + 1;
    l.sweep();
    await assert.rejects(offer.done, (e) => e.code === 'broken_off');
    fs.rmSync(out, { recursive: true, force: true });
  });

  it('logs who reached it and why a request was refused (diagnosis)', async () => {
    const lines = [];
    l.log = { ...log, info: (m) => lines.push(m) };
    l.expectIncoming({ transferId: 'tr_log', ticket: TICKET, key: KEY, items: [{ index: 0, name: 'a', bytes: 1 }], sink: sinkTo(dir) }).catch(() => {});
    assert.equal((await post(port, 'tr_log', { ticket: 'tkt_wrongwrongwrong', size: 1, body: Buffer.alloc(17) })).status, 403);
    assert.ok(lines.some((m) => /POST from 127\.0\.0\.1 refused \(403 forbidden\)/.test(m)), lines.join('\n'));
    assert.equal((await post(port, 'tr_log', { size: 1, body: c.encryptBuffer(KEY, 'tr_log', Buffer.from('a')) })).status, 200);
    assert.ok(lines.some((m) => /127\.0\.0\.1 sends transfer tr_log/.test(m)), lines.join('\n'));
  });

  it('only private IPv4 peers by default', async () => {
    const strict = new GateDropListener({ log, port: 0, bindAddresses: ['127.0.0.1'] });
    await strict.start();
    try {
      const r = await post(strict.status().addresses[0].port, 'tr_any', { size: 1, body: Buffer.alloc(17) });
      assert.equal(r.status, 403);
    } finally {
      await strict.stop();
    }
  });

  it('unknown routes and methods', async () => {
    const get = (p, method = 'GET') => new Promise((resolve) => {
      http.request({ host: '127.0.0.1', port, path: p, method, agent: false }, (res) => { res.resume(); resolve(res.statusCode); }).end();
    });
    assert.equal(await get('/'), 404);
    assert.equal(await get('/gatedrop/v1/transfer/../../x'), 404);
    assert.equal(await get('/gatedrop/v1/transfer/tr_1', 'PUT'), 405);
  });

  it('serves offered items to a device that pulls (pullFrom round trip)', async () => {
    const plain = crypto.randomBytes(70000);
    const src = path.join(dir, 'src.bin');
    fs.writeFileSync(src, plain);
    const out = fs.mkdtempSync(path.join(os.tmpdir(), 'gd-pull-'));
    const offer = l.offerOutgoing({ transferId: 'tr_pull', ticket: TICKET, key: KEY, items: [{ path: src, name: 'Ü ber.bin', size: plain.length }] });
    const r = await direct.pullFrom({
      candidates: [`127.0.0.1:${port}`], transferId: 'tr_pull', ticket: TICKET, key: KEY,
      items: [{ index: 0, name: 'Ü ber.bin', bytes: plain.length }], sink: sinkTo(out), resolveCandidate: loopback,
    });
    assert.deepEqual(fs.readFileSync(r.items[0].path), plain);
    assert.deepEqual(await offer.done, { bytes: plain.length });
    // Wrong ticket for a pull: 403 (and the transfer is gone after it was fetched anyway).
    await assert.rejects(direct.pullFrom({
      candidates: [`127.0.0.1:${port}`], transferId: 'tr_pull', ticket: 'tkt_wrongwrongwrong', key: KEY,
      items: [{ index: 0, name: 'x', bytes: 1 }], sink: sinkTo(out), resolveCandidate: loopback,
    }), (e) => e.status === 403);
    fs.rmSync(out, { recursive: true, force: true });
  });

  it('pushTo round trip into the listener', async () => {
    const plain = crypto.randomBytes(12345);
    const src = path.join(dir, 'p.bin');
    fs.writeFileSync(src, plain);
    const out = fs.mkdtempSync(path.join(os.tmpdir(), 'gd-push-'));
    const done = l.expectIncoming({ transferId: 'tr_push', ticket: TICKET, key: KEY, items: [{ index: 0, name: 'p.bin', bytes: plain.length }], sink: sinkTo(out) });
    const r = await direct.pushTo({ candidates: [`127.0.0.1:${port}`], transferId: 'tr_push', ticket: TICKET, key: KEY, files: [{ path: src, name: 'p.bin', size: plain.length }], resolveCandidate: loopback });
    assert.equal(r.bytes, plain.length);
    const items = await done;
    assert.deepEqual(fs.readFileSync(items[0].path), plain);
    fs.rmSync(out, { recursive: true, force: true });
  });

  it('pushTo gives up on an unreachable candidate within the connect timeout', async () => {
    const t0 = Date.now();
    // 10.255.255.1 is not routed in test environments; a blackhole costs the full timeout.
    await assert.rejects(direct.pushTo({
      candidates: ['10.255.255.1:47731'], transferId: 'tr_none', ticket: TICKET, key: KEY,
      files: [{ path: __filename, name: 'x.js', size: fs.statSync(__filename).size }], connectTimeoutMs: 300,
    }), (e) => ['connect_timeout', 'unreachable'].includes(e.code) && e.connected === false);
    assert.ok(Date.now() - t0 < 3000);
  });
});

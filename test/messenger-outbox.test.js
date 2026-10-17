'use strict';

// Messenger outbox (services/messenger-outbox.js): order, idempotent
// retries with the same clientId, backoff on transient errors, refusals,
// uploads before sending, persistence across restarts, server changes.

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const ApiClient = require('../src/services/api-client');
const MessengerApi = require('../src/services/messenger-api');
const MessengerOutbox = require('../src/services/messenger-outbox');
const { messengerServer, API } = require('./fixtures/messenger-server');
const { createMemoryStore } = require('./fixtures/memory-store');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const cleanups = [];
afterEach(async () => { while (cleanups.length) await cleanups.pop()(); });

async function waitFor(fn, ms = 3000, what = 'condition') {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > end) throw new Error(`timeout waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 5));
  }
}

async function setup({ store = createMemoryStore(), dataDir = null, backoffMs = [20, 40, 80] } = {}) {
  const srv = await messengerServer();
  cleanups.push(() => srv.close());
  const apiClient = new ApiClient(srv.url, 'gc_token', log);
  const api = new MessengerApi({ apiClient, log });
  const box = new MessengerOutbox({ api, store, dataDir, log, backoffMs });
  cleanups.push(() => box.stop());
  const conv = srv.addConv();
  return { srv, api, apiClient, box, store, conv };
}

const posts = (srv, conv) => srv.state.requests.filter((r) => r.method === 'POST' && r.path === `${API}conversations/${conv}/messages`);

describe('MessengerOutbox', () => {
  it('sends queued messages in order with their clientId', async () => {
    const { srv, box, conv } = await setup();
    const sent = [];
    box.on('sent', (e) => sent.push(e));
    box.start();
    const a = await box.add({ conversationId: conv, body: { kind: 'text', text: 'eins' } });
    await box.add({ conversationId: conv, body: { kind: 'text', text: 'zwei' } });
    await waitFor(() => sent.length === 2, 3000, 'two sent');
    assert.deepEqual(sent.map((s) => s.message.text), ['eins', 'zwei']);
    assert.equal(posts(srv, conv)[0].body.clientId, a.clientId);
    assert.equal(box.size(), 0);
  });

  it('keeps messages while offline and retries with the same clientId', async () => {
    const { srv, box, conv } = await setup();
    srv.fail(`POST ${API}conversations/${conv}/messages`, 0, 'drop', 2);
    const sent = [];
    box.on('sent', (e) => sent.push(e));
    box.start();
    const e = await box.add({ conversationId: conv, body: { kind: 'text', text: 'später' } });
    await waitFor(() => sent.length === 1, 4000, 'sent after retries');
    const ids = posts(srv, conv).map((r) => r.body && r.body.clientId);
    assert.ok(ids.length >= 3);
    assert.ok(ids.every((x) => x === e.clientId), 'every attempt carries the same clientId');
    assert.equal(srv.state.msgs.get(conv).length, 1, 'stored once');
  });

  it('a retry after a lost answer is a duplicate, not a second message', async () => {
    const { srv, api, box, conv } = await setup();
    await api.send(conv, { clientId: 'client-dup-1', kind: 'text', text: 'x' });
    const sent = [];
    box.on('sent', (e) => sent.push(e));
    box.start();
    await box.add({ conversationId: conv, clientId: 'client-dup-1', body: { kind: 'text', text: 'x' } });
    await waitFor(() => sent.length === 1);
    assert.equal(sent[0].duplicate, true);
    assert.equal(srv.state.msgs.get(conv).length, 1);
  });

  it('marks refusals failed; retry and discard', async () => {
    const { srv, box, conv } = await setup();
    srv.fail(`POST ${API}conversations/${conv}/messages`, 403, 'readonly');
    const failed = [];
    box.on('failed', (e) => failed.push(e));
    box.start();
    const e = await box.add({ conversationId: conv, body: { kind: 'text', text: 'nope' } });
    await waitFor(() => failed.length === 1);
    assert.equal(failed[0].error, 'readonly');
    assert.equal(box.get(e.clientId).state, 'failed');
    srv.heal();
    const sent = [];
    box.on('sent', (x) => sent.push(x));
    assert.equal(box.retry(e.clientId), true);
    await waitFor(() => sent.length === 1);
    const f = await box.add({ conversationId: conv, body: { kind: 'text', text: 'weg' } });
    box.stop();
    assert.equal(await box.discard(f.clientId), true);
    assert.equal(box.size(), 0);
  });

  it('uploads files first, then sends with the media ids; keeps files on disk until sent', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gc-outbox-'));
    cleanups.push(() => fs.rmSync(dir, { recursive: true, force: true }));
    const { srv, box, conv } = await setup({ dataDir: dir });
    const sent = [];
    box.on('sent', (e) => sent.push(e));
    const e = await box.add({
      conversationId: conv,
      body: { kind: 'image', meta: { w: 10, h: 10 } },
      files: { main: { data: Buffer.from('main-image'), mime: 'image/webp', name: 'a.webp' }, thumb: { data: new Uint8Array([1, 2, 3]), mime: 'image/webp' } },
    });
    const files = fs.readdirSync(path.join(dir, 'messenger-outbox'));
    assert.deepEqual(files.sort(), [`${e.clientId}-main.bin`, `${e.clientId}-thumb.bin`]);
    box.start();
    await waitFor(() => sent.length === 1);
    const post = posts(srv, conv)[0].body;
    assert.match(post.mediaId, /^[0-9a-f]{32}$/);
    assert.match(post.thumbMediaId, /^[0-9a-f]{32}$/);
    assert.deepEqual(srv.state.media.get(post.mediaId).data, Buffer.from('main-image'));
    assert.deepEqual(fs.readdirSync(path.join(dir, 'messenger-outbox')), []);
  });

  it('uploads again once when the server no longer knows the upload', async () => {
    const { srv, box, conv } = await setup();
    const sent = [];
    box.on('sent', (e) => sent.push(e));
    await box.add({ conversationId: conv, body: { kind: 'file', meta: { fileName: 'a.pdf' } }, files: { main: { data: Buffer.from('%PDF'), mime: 'application/pdf' } } });
    // The first upload "expires" before the message is sent.
    const origUpload = box.api.upload.bind(box.api);
    let n = 0;
    box.api.upload = async (f) => { const r = await origUpload(f); n += 1; if (n === 1) srv.state.media.delete(r.mediaId); return r; };
    box.start();
    await waitFor(() => sent.length === 1);
    assert.equal(n, 2);
  });

  it('survives a restart (store + files) and drops entries of another server', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gc-outbox-'));
    cleanups.push(() => fs.rmSync(dir, { recursive: true, force: true }));
    const store = createMemoryStore();
    const { srv, api, box, conv, apiClient } = await setup({ store, dataDir: dir });
    box.start();
    srv.fail(`POST ${API}conversations/${conv}/messages`, 503, 'not_running');
    await box.add({ conversationId: conv, body: { kind: 'file', meta: { fileName: 'b.pdf' } }, files: { main: { data: Buffer.from('%PDF-b'), mime: 'application/pdf' } } });
    await waitFor(() => box.list()[0].attempts >= 1 && box.list()[0].state === 'queued');
    box.stop();
    srv.heal();

    const again = new MessengerOutbox({ api, store, dataDir: dir, log, backoffMs: [20] });
    cleanups.push(() => again.stop());
    assert.equal(again.size(), 1);
    const sent = [];
    again.on('sent', (e) => sent.push(e));
    again.start();
    await waitFor(() => sent.length === 1);
    assert.equal(sent[0].message.kind, 'file');

    const third = new MessengerOutbox({ api, store, dataDir: dir, log, backoffMs: [20] });
    cleanups.push(() => third.stop());
    srv.fail(`POST ${API}conversations/${conv}/messages`, 503, 'not_running');
    third.start();
    await third.add({ conversationId: conv, body: { kind: 'text', text: 'alter Server' } });
    third.stop();
    apiClient.configure(apiClient.serverUrl, 'another-token');
    const fourth = new MessengerOutbox({ api, store, dataDir: dir, log, backoffMs: [20] });
    cleanups.push(() => fourth.stop());
    assert.equal(fourth.size(), 1);
    fourth.start();
    await waitFor(() => fourth.size() === 0, 2000, 'dropped on scope change');
  });

  it('refuses malformed entries', async () => {
    const { box } = await setup();
    await assert.rejects(box.add({ conversationId: 'x', body: { kind: 'text', text: 'a' } }), (e) => e.code === 'invalid');
    await assert.rejects(box.add({ conversationId: 1, body: { kind: 'image' }, files: { main: { data: 'nope', mime: 'image/png' } } }), (e) => e.code === 'invalid');
  });
});

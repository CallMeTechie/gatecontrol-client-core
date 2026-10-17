'use strict';

// MessengerApi (services/messenger-api.js) with the real ApiClient against
// the in-memory messenger server: routes, bodies, raw uploads, downloads,
// error mapping, availability on old servers.

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const ApiClient = require('../src/services/api-client');
const MessengerApi = require('../src/services/messenger-api');
const { messengerServer, API, MEDIA } = require('./fixtures/messenger-server');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const cleanups = [];
afterEach(async () => { while (cleanups.length) await cleanups.pop()(); });

async function setup(opts) {
  const srv = await messengerServer(opts);
  cleanups.push(() => srv.close());
  const apiClient = new ApiClient(srv.url, 'gc_token', log, null, { clientType: 'pro' });
  return { srv, api: new MessengerApi({ apiClient, log }), apiClient };
}

describe('MessengerApi', () => {
  it('finds the plugin with its app tab', async () => {
    const { api, srv } = await setup();
    assert.deepEqual(await api.availability(), { available: true, reason: null, tab: { label: 'Chats' }, version: '1.0.0' });
    srv.state.tab = false;
    assert.equal((await api.availability()).reason, 'hidden');
    srv.state.plugin = false;
    assert.equal((await api.availability()).reason, 'not_installed');
  });

  it('treats a server without the plugin list (404) as unsupported', async () => {
    const server = http.createServer((req, res) => { res.writeHead(404, { 'Content-Type': 'application/json' }); res.end('{"error":"Not found"}'); });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    cleanups.push(() => new Promise((r) => server.close(r)));
    const api = new MessengerApi({ apiClient: new ApiClient(`http://127.0.0.1:${server.address().port}`, 't', log), log });
    assert.deepEqual(await api.availability(), { available: false, reason: 'unsupported', tab: null, version: null });
  });

  it('sends the device headers and JSON bodies to the plugin routes', async () => {
    const { api, srv } = await setup();
    const id = srv.addConv();
    const me = await api.me();
    assert.equal(me.user.id, 7);
    const r = await api.send(id, { clientId: 'client-0001', kind: 'text', text: 'Hallo' });
    assert.equal(r.duplicate, false);
    const again = await api.send(id, { clientId: 'client-0001', kind: 'text', text: 'Hallo' });
    assert.equal(again.duplicate, true);
    assert.equal(again.message.id, r.message.id);
    const req = srv.state.requests.find((x) => x.method === 'POST' && x.path === `${API}conversations/${id}/messages`);
    assert.equal(req.headers['x-api-token'], 'gc_token');
    assert.equal(req.headers['x-client-type'], 'pro');
    assert.deepEqual(req.body, { clientId: 'client-0001', kind: 'text', text: 'Hallo' });
    await api.read(id, r.message.id);
    await api.typing(id);
    await api.typing(id, true);
    await api.active(id, false);
    assert.deepEqual(srv.state.typings.map((x) => x.body), [{}, { stop: true }]);
    assert.deepEqual(srv.state.actives.map((x) => x.body), [{ active: false }]);
    const page = await api.messages(id, { after: 1, limit: 500 });
    assert.equal(srv.state.requests.at(-1).query.limit, '100');
    assert.equal(page.messages.length, 1);
    await api.remove(r.message.id, 'all');
    assert.equal(srv.state.requests.at(-1).query.for, 'all');
  });

  it('maps errors to codes (plugin code, network, invalid ids)', async () => {
    const { api, srv } = await setup();
    await assert.rejects(api.conversation(999), (e) => e.code === 'not_found' && e.status === 404 && !e.transient);
    srv.fail('GET /api/v1/client/plugins/gatecontrol-messenger/api/me', 503, 'not_running');
    await assert.rejects(api.me(), (e) => e.status === 503 && e.transient);
    await assert.rejects(api.conversation('1/../../x'), (e) => e.code === 'invalid');
    await assert.rejects(api.postPath('../push/ack', {}), (e) => e.code === 'invalid');
    const dead = new MessengerApi({ apiClient: new ApiClient('http://127.0.0.1:1', 't', log), log });
    await assert.rejects(dead.me(), (e) => e.code === 'network' && e.transient);
    const none = new MessengerApi({ apiClient: { client: null }, log });
    await assert.rejects(none.me(), (e) => e.code === 'not_configured');
  });

  it('uploads files raw with type and length, downloads them back', async () => {
    const { api, srv } = await setup();
    const data = Buffer.from('%PDF-1.7 fake pdf');
    const progress = [];
    const up = await api.upload({ data: new Uint8Array(data), mime: 'application/pdf', onProgress: (p) => progress.push(p) });
    assert.match(up.mediaId, /^[0-9a-f]{32}$/);
    assert.equal(up.bytes, data.length);
    const req = srv.state.requests.find((x) => x.method === 'PUT' && x.path === MEDIA);
    assert.equal(req.headers['content-type'], 'application/pdf');
    assert.equal(req.headers['content-length'], String(data.length));
    assert.equal(req.bytes, data.length);
    const down = await api.download(up.mediaId);
    assert.equal(down.mime, 'application/pdf');
    assert.deepEqual(down.data, data);
    await assert.rejects(api.upload({ data: Buffer.from('x'), mime: 'application/x-msdownload' }), (e) => e.code === 'unsupported_type' && e.status === 415);
    await assert.rejects(api.upload({ data: Buffer.alloc(0), mime: 'image/png' }), (e) => e.code === 'length_required');
    await assert.rejects(api.download('nope'), (e) => e.code === 'invalid');
  });

  it('loads account pictures only from /avatars/ paths', async () => {
    const { api } = await setup();
    const a = await api.avatar('/avatars/annaAvatarFile0001.webp');
    assert.equal(a.mime, 'image/webp');
    await assert.rejects(api.avatar('/api/v1/client/config'), (e) => e.code === 'invalid');
  });

  it('scope() changes with server and token', async () => {
    const { api, apiClient } = await setup();
    const s1 = api.scope();
    apiClient.configure(apiClient.serverUrl, 'other');
    assert.notEqual(api.scope(), s1);
  });
});

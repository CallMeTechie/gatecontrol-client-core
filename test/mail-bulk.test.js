'use strict';

// Mail 1.13 "Mehrfachauswahl + Wischaktionen": the selection's bulk calls in parts of 500 (count, ids, undo, purged
// together), copy, undo tokens, GET messages/ids ("Alle N auswählen"), threads: true, settings.swipe with seven
// actions + confirmDelete (and the old swipeLeft / swipeRight as fallback), the features that switch it all on —
// and the same app against an older plugin (≤ 1.12: no copy, no undo, no ids, the old four swipe actions).

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Module = require('node:module');

const realResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === '@callmetechie/gatecontrol-config-hash') return require.resolve('./fixtures/config-hash-stub');
  return realResolve.call(this, request, ...rest);
};

const mail = require('../src/utils/mail');
const MailService = require('../src/services/mail');
const MailApi = require('../src/services/mail-api');
const ApiClient = require('../src/services/api-client');
const { MessengerError } = require('../src/services/messenger-api');
const { registerMailHandlers } = require('../src/ipc/mail-handlers');
const { mailServer, MAIL13_FEATURES } = require('./fixtures/mail-server');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const BASE_FEATURES = ['mail', 'ai', 'microsoft', 'drive', 'familyCalendar', 'images', 'calendar', 'contacts', 'dav', 'familyOverlay'];

const cleanup = [];
afterEach(async () => {
  for (const fn of cleanup.splice(0).reverse()) { try { await fn(); } catch { /* ignore */ } }
});

async function setup(opts = {}) {
  const srv = await mailServer(opts);
  cleanup.push(() => srv.close());
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'mail-bulk-'));
  cleanup.push(() => fs.rmSync(temp, { recursive: true, force: true }));
  const svc = new MailService({ apiClient: new ApiClient(srv.url, 'gc_token', log), log, tempDir: () => temp, getLang: () => 'de', timing: { retryMinMs: 10, retryMaxMs: 20 } });
  svc.start();
  cleanup.push(() => svc.stop());
  await svc.check();
  return { srv, svc };
}

const setup13 = () => setup({ features: [...BASE_FEATURES, ...MAIL13_FEATURES] });

/** A MessengerApi stand-in that records the calls and answers with [answer](method, path, body, n). */
function stubHttp(answer) {
  const calls = [];
  return {
    calls,
    async _call(method, p, { body, params } = {}) {
      calls.push({ method, path: p, body, params });
      return answer(method, p, body, calls.length);
    },
  };
}

describe('utils/mail 1.13', () => {
  it('features: copy, swipeV2, undo, bulkAll, threadScope are kept', () => {
    const me = mail.normalizeMe({ features: ['mail', 'copy', 'swipeV2', 'undo', 'bulkAll', 'threadScope', 'teleport'] });
    assert.deepEqual(me.features, ['mail', 'copy', 'swipeV2', 'undo', 'bulkAll', 'threadScope']);
  });

  it('settings: swipe { left, right } wins over the old fields, unknown values do nothing, confirmDelete', () => {
    assert.deepEqual(mail.normalizeSettings({}), { threads: true, swipeLeft: 'archive', swipeRight: 'read', confirmDelete: false });
    // an older plugin: only the old fields
    assert.deepEqual(mail.normalizeSettings({ swipeLeft: 'delete', swipeRight: 'none' }), { threads: true, swipeLeft: 'delete', swipeRight: 'none', confirmDelete: false });
    // Mail 1.13: the old fields say "none" for move / junk, the new ones the action
    assert.deepEqual(mail.normalizeSettings({ swipeLeft: 'none', swipeRight: 'none', swipe: { left: 'move', right: 'junk' }, confirmDelete: true }),
      { threads: true, swipeLeft: 'move', swipeRight: 'junk', confirmDelete: true });
    assert.deepEqual(mail.normalizeSettings({ swipe: { left: 'teleport' }, swipeRight: 'flag' }), { threads: true, swipeLeft: 'none', swipeRight: 'none', confirmDelete: false });
    assert.equal(mail.normalizeSettings({ confirmDelete: 'yes' }).confirmDelete, false);
  });

  it('settingsPatch: swipe { … } + confirmDelete with v2, the old four without', () => {
    assert.deepEqual(mail.settingsPatch({ swipeLeft: 'move', swipeRight: 'flag', confirmDelete: true }, { v2: true }), { swipe: { left: 'move', right: 'flag' }, confirmDelete: true });
    assert.deepEqual(mail.settingsPatch({ swipeRight: 'junk' }, { v2: true }), { swipe: { right: 'junk' } });
    assert.deepEqual(mail.settingsPatch({ threads: false, confirmDelete: false }, { v2: true }), { threads: false, confirmDelete: false });
    assert.equal(mail.settingsPatch({ swipeLeft: 'teleport' }, { v2: true }), null);
    assert.equal(mail.settingsPatch({ confirmDelete: 'ja' }, { v2: true }), null);
    // an older plugin: the old fields with the old four, no confirmDelete
    assert.deepEqual(mail.settingsPatch({ swipeLeft: 'delete', confirmDelete: true }), { swipeLeft: 'delete' });
    assert.equal(mail.settingsPatch({ swipeLeft: 'move' }), null);
    assert.equal(mail.settingsPatch({ confirmDelete: true }), null, 'nothing an older plugin knows');
  });

  it('chunks, bulk answers and their merge, undo tokens, ids', () => {
    assert.deepEqual(mail.chunks([1, 2, 3, 4, 5], 2), [[1, 2], [3, 4], [5]]);
    assert.equal(mail.idList(Array.from({ length: 501 }, (_, i) => i + 1)), null);
    assert.equal(mail.idList(Array.from({ length: 2000 }, (_, i) => i + 1), mail.BULK_MAX).length, 2000);
    // an older plugin's answer
    assert.deepEqual(mail.normalizeBulk({ ok: true }), { ok: true, items: null, count: null, ids: null, undo: null, purged: [] });
    const a = mail.normalizeBulk({
      ok: true, items: [], count: 2, ids: [1, 2, 'x'], purged: [2],
      undo: { token: 'Ab_-1', kind: 'delete', count: 1, expiresAt: 5000, items: [{ id: 1, newId: null, accountId: 3, fromFolderId: 10, toFolderId: 13 }, { id: 0 }] },
    });
    assert.deepEqual(a.ids, [1, 2]);
    assert.deepEqual(a.undo.items, [{ id: 1, newId: null, accountId: 3, fromFolderId: 10, toFolderId: 13 }]);
    assert.equal(mail.normalizeBulk({ undo: { token: 'a b', kind: 'delete' } }).undo, null, 'a token of other characters');
    assert.equal(mail.normalizeBulk({ undo: { token: 'abc', kind: 'flags' } }).undo, null, 'flags cannot be taken back by token');
    const b = mail.normalizeBulk({ ok: true, items: [], count: 1, ids: [3], undo: { token: 'Cd', kind: 'delete', count: 1, expiresAt: 4000, items: [{ id: 3 }] } });
    const m = mail.mergeBulk([a, b]);
    assert.deepEqual([m.count, m.ids, m.purged, m.undo.tokens, m.undo.count, m.undo.expiresAt, m.undo.kind], [3, [1, 2, 3], [2], ['Ab_-1', 'Cd'], 2, 4000, 'delete']);
    assert.equal(mail.mergeBulk([mail.normalizeBulk({}), b]).count, null, 'an older plugin does not count');
    assert.deepEqual(mail.undoTokens('abc'), ['abc']);
    assert.equal(mail.undoTokens(['a', 'b', 'c', 'd', 'e']), null);
    assert.equal(mail.undoTokens(['../x']), null);
    assert.equal(mail.undoTokens([]), null);
    assert.deepEqual(mail.idsQuery({ box: 3, folder: 14, tab: 'other', unread: true, before: '1.2', limit: 9 }), { box: '3', folder: 14, tab: 'other', unread: 1 });
    assert.equal(mail.idsQuery({ box: '../x' }), null);
    assert.deepEqual(mail.normalizeIds({ ids: [5, 4, 4, 'x'], total: 7, max: 2000, truncated: false }), { ids: [5, 4], total: 7, max: 2000, truncated: true });
    assert.deepEqual(mail.normalizeUndone({ kind: 'move', restored: 2, failed: 'x', items: [] }), { kind: 'move', restored: 2, failed: 0, items: [] });
  });
});

describe('MailApi 1.13', () => {
  it('a selection of 1200 goes in parts of 500 with the same fields; the answers come together', async () => {
    const http = stubHttp((method, p, body, n) => ({
      ok: true, items: [], count: body.ids.length, ids: body.ids,
      undo: { token: `tok${n}`, kind: 'move', count: body.ids.length, expiresAt: 1000 * n, items: [] },
    }));
    const api = new MailApi({ http, log });
    const ids = Array.from({ length: 1200 }, (_, i) => i + 1);
    const r = await api.move(ids, 14, { threads: true });
    assert.deepEqual(http.calls.map((c) => [c.method, c.path.split('/api/')[2] || c.path.split('/').slice(-2).join('/'), c.body.ids.length, c.body.folderId, c.body.threads]),
      [['POST', 'messages/move', 500, 14, true], ['POST', 'messages/move', 500, 14, true], ['POST', 'messages/move', 200, 14, true]]);
    assert.equal(r.count, 1200);
    assert.deepEqual(r.undo.tokens, ['tok1', 'tok2', 'tok3']);
    assert.equal(r.undo.expiresAt, 1000);
    // no threads unless asked
    await api.act('archive', [1, 2]);
    assert.equal('threads' in http.calls.at(-1).body, false);
    await assert.rejects(api.move(Array.from({ length: 2001 }, (_, i) => i + 1), 14), { code: 'invalid' });
    await assert.rejects(api.copy([1], 'x'), { code: 'invalid' });
  });

  it('a part refused after another went through: the answer says which ids are not done', async () => {
    const http = stubHttp((method, p, body, n) => {
      if (n === 2) throw new MessengerError('busy', { code: 'busy' });
      return { ok: true, items: [], count: body.ids.length, ids: body.ids, undo: null };
    });
    const api = new MailApi({ http, log });
    const r = await api.act('junk', Array.from({ length: 700 }, (_, i) => i + 1));
    assert.equal(r.count, 500);
    assert.equal(r.partial.ids.length, 200);
    assert.equal(r.partial.ids[0], 501);
    assert.equal(r.partial.code, 'busy');
    // the first part refused: the call fails
    const http2 = stubHttp(() => { throw new MessengerError('x', { code: 'unreachable' }); });
    await assert.rejects(new MailApi({ http: http2, log }).act('junk', [1]), { code: 'unreachable' });
  });
});

describe('MailService 1.13', () => {
  it('copy, move with undo, delete in the trash (purged), threads, ids for "Alle auswählen"', async () => {
    const { srv, svc } = await setup13();
    // copy into "Rechnungen" of the same account; a folder of another account is refused
    const c = await svc.act('copy', [101, 104], { folderId: 15 });
    assert.equal(c.count, 2);
    assert.equal(c.undo.kind, 'copy');
    const copies = [...srv.state.messages.values()].filter((m) => m.folderId === 15);
    assert.equal(copies.length, 2);
    assert.ok(srv.state.messages.get(101), 'the original stays');
    await assert.rejects(svc.act('copy', [101], { folderId: 24 }), (e) => e.code === 'invalid' && e.detail.reason === 'account');
    const u = await svc.undo(c.undo.tokens);
    assert.deepEqual([u.kind, u.restored], ['copy', 2]);
    assert.equal([...srv.state.messages.values()].filter((m) => m.folderId === 15).length, 0);
    await assert.rejects(svc.undo(c.undo.tokens), { code: 'not_found' }, 'a token once only');

    // move with the whole conversation (102 and 103 share thread 900 in the inbox of account 2)
    const mv = await svc.act('move', [102], { folderId: 24, threads: true });
    assert.deepEqual(mv.ids.sort(), [102, 103]);
    assert.equal(srv.state.bulkCalls.at(-1).body.threads, true);
    assert.equal(srv.state.messages.get(103).folderId, 24);
    const back = await svc.undo(mv.undo.tokens);
    assert.equal(back.restored, 2);
    assert.equal(srv.state.messages.get(103).folderId, 21);

    // delete twice: first into the trash (undo), then for good (purged, no undo)
    const d1 = await svc.act('delete', [104]);
    assert.equal(d1.undo.kind, 'delete');
    const d2 = await svc.act('delete', [104]);
    assert.deepEqual([d2.purged, d2.undo], [[104], null]);
    assert.equal(srv.state.messages.has(104), false);

    // every id of account 1's inbox (Relevant), newest first
    const all = await svc.ids({ box: 1, tab: 'relevant' });
    assert.equal(all.ok, true);
    assert.equal(all.ids[0], 101);
    assert.equal(all.total, all.ids.length);
    assert.ok(all.ids.length > 60);
    srv.state.idsMax = 10;
    const cut = await svc.ids({ box: 1 });
    assert.deepEqual([cut.ids.length, cut.truncated], [10, true]);

    // flags for many at once
    const f = await svc.flags(all.ids, { unread: true, threads: true });
    assert.equal(f.count, all.ids.length);
    assert.ok(all.ids.every((id) => srv.state.messages.get(id).unread));
  });

  it('settings: seven actions as swipe { … } and confirmDelete with swipeV2', async () => {
    const { srv, svc } = await setup13();
    const r = await svc.settings({ swipeLeft: 'move', swipeRight: 'junk', confirmDelete: true });
    assert.deepEqual(srv.state.lastSettingsBody, { swipe: { left: 'move', right: 'junk' }, confirmDelete: true });
    assert.deepEqual(r.settings, { threads: true, swipeLeft: 'move', swipeRight: 'junk', confirmDelete: true });
    const me = await svc.me();
    assert.deepEqual([me.settings.swipeLeft, me.settings.swipeRight, me.settings.confirmDelete], ['move', 'junk', true]);
  });

  it('an older plugin (≤ 1.12): old swipe fields, no copy / undo / ids, no threads sent', async () => {
    const { srv, svc } = await setup();
    await svc.settings({ swipeLeft: 'delete', confirmDelete: true });
    assert.deepEqual(srv.state.lastSettingsBody, { swipeLeft: 'delete' });
    await assert.rejects(svc.settings({ swipeLeft: 'move' }), { code: 'invalid' });
    await assert.rejects(svc.act('copy', [101], { folderId: 15 }), { code: 'unsupported' });
    await assert.rejects(svc.ids({ box: 1 }), { code: 'unsupported' });
    await assert.rejects(svc.undo(['abc']), { code: 'unsupported' });
    const before = srv.state.requests.length;
    const r = await svc.act('archive', [102], { threads: true });
    assert.deepEqual([r.ok, r.count, r.undo], [true, null, null]);
    const req = srv.state.requests.slice(before).find((x) => x.path.endsWith('/messages/archive'));
    assert.ok(req, 'archive was called');
    assert.equal(srv.state.messages.get(103).folderId, 21, 'the conversation stays: no threads for an older plugin');
  });
});

describe('mail IPC 1.13', () => {
  it('mail:act copy, mail:undo, mail:ids, ≤ 2000 ids', async () => {
    const { svc } = await setup13();
    const handlers = {};
    registerMailHandlers((ch, fn) => { handlers[ch] = fn; }, { mail: svc, getMainWindow: () => null, log });
    const call = (ch, arg) => handlers[ch]({}, arg);
    assert.equal((await call('mail:act', { action: 'copy', ids: [101] })).code, 'invalid', 'copy needs a folder');
    assert.equal((await call('mail:act', { action: 'move', ids: Array.from({ length: 2001 }, (_, i) => i + 1), folderId: 14 })).code, 'invalid');
    const c = await call('mail:act', { action: 'copy', ids: [101], folderId: 15 });
    assert.equal(c.ok, true);
    assert.equal((await call('mail:undo', { tokens: 'abc' })).code, 'invalid');
    assert.equal((await call('mail:undo', { tokens: ['a', 'b', 'c', 'd', 'e'] })).code, 'invalid');
    const u = await call('mail:undo', { tokens: c.undo.tokens });
    assert.deepEqual([u.ok, u.kind], [true, 'copy']);
    const ids = await call('mail:ids', { box: 2 });
    assert.deepEqual([ids.ok, ids.ids.slice().sort()], [true, [102, 103, 105]]);
    const st = await call('mail:settings', { confirmDelete: true });
    assert.equal(st.settings.confirmDelete, true);
  });
});

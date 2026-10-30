'use strict';

// Mail (plugin gatecontrol-mail, Phase 1): the pure helpers (utils/mail.js — cleaned answers, queries, request
// bodies, the HTML of the reading frame, the gcmail: URLs, PKCE), the API (services/mail-api.js — the plugin's
// refusals { error: { code } }), the service (services/mail.js — availability, lists with the offline cache,
// mails marked read, pictures through the protocol, the Microsoft sign-in through the loopback receiver, drafts,
// send / undo, attachments, AI, Drive, live events, push clicks) and its IPC (mail:*).

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const EventEmitter = require('node:events');
const fs = require('node:fs');
const http = require('node:http');
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
const MailCache = require('../src/services/mail-cache');
const ApiClient = require('../src/services/api-client');
const { startCodeListener } = require('../src/services/mail-loopback');
const { registerMailHandlers } = require('../src/ipc/mail-handlers');
const { mailServer, PNG } = require('./fixtures/mail-server');

const log = { info() {}, warn() {}, debug() {}, error() {} };

const cleanup = [];
afterEach(async () => {
  for (const fn of cleanup.splice(0).reverse()) { try { await fn(); } catch { /* ignore */ } }
});

function tmpDir(prefix) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  cleanup.push(() => fs.rmSync(d, { recursive: true, force: true }));
  return d;
}

async function until(fn, ms = 5000) {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > end) throw new Error('timed out');
    await new Promise((r) => setTimeout(r, 10));
  }
}

/** DPAPI stand-in: reversible, never plain text on disk. */
const fakeProtect = () => ({
  available: () => true,
  encrypt: (b) => Buffer.concat([Buffer.from('ENC1'), Buffer.from(b).map((x) => x ^ 0x5a)]),
  decrypt: (b) => {
    if (b.subarray(0, 4).toString() !== 'ENC1') throw new Error('not ours');
    return Buffer.from(b.subarray(4)).map((x) => x ^ 0x5a);
  },
});

async function setup(opts = {}, { shell = null, dialog = null, cacheDir = null, protect = null, openExternal = null, pushClient = null, notificationCenter = null } = {}) {
  const srv = await mailServer(opts);
  cleanup.push(() => srv.close());
  const apiClient = new ApiClient(srv.url, 'gc_token', log);
  const temp = tmpDir('mail-tmp-');
  const svc = new MailService({
    apiClient, log, shell, dialog, tempDir: () => temp, getLang: () => 'de', cacheDir: cacheDir ? () => cacheDir : null, protect,
    openExternal, pushClient, notificationCenter, timing: { retryMinMs: 10, retryMaxMs: 20 },
  });
  svc.start();
  cleanup.push(() => svc.stop());
  await svc.check();
  return { srv, svc, apiClient, temp };
}

describe('utils/mail', () => {
  it('normalizeMe: known features, Microsoft only on its host, unread per account, settings', () => {
    const me = mail.normalizeMe({
      features: ['ai', 'drive', 'teleport'],
      limits: { accountsMax: 5, quotaBytes: 100, usedBytes: '40', retentionMonths: 12 },
      microsoft: { clientId: 'abcd-1234-efgh', authority: 'https://evil.example.com/common', scopes: ['openid', 'bad scope'] },
      accounts: [{ id: 1, email: 'a@b.de', color: 'red', provider: 'x', state: 'weird' }, { id: 0, email: 'x@y.de' }, { id: 2, email: 'nope' }],
      unread: { all: 3, byAccount: { 1: 2, x: 4 } },
      settings: { threads: false, swipeLeft: 'delete', swipeRight: 'explode' },
    });
    assert.deepEqual(me.features, ['mail', 'ai', 'drive']);
    assert.equal(me.limits.usedBytes, 40);
    assert.equal(me.microsoft.authority, mail.MS_AUTHORITY, 'a foreign authority is never used');
    assert.deepEqual(me.microsoft.scopes, ['openid']);
    assert.equal(me.accounts.length, 1);
    assert.deepEqual([me.accounts[0].color, me.accounts[0].provider, me.accounts[0].state, me.accounts[0].name], ['#79B8FF', 'imap', 'ok', 'a@b.de']);
    assert.deepEqual(me.unread, { all: 3, byAccount: { 1: 2 } });
    assert.deepEqual(me.settings, { threads: false, swipeLeft: 'delete', swipeRight: 'read' });
  });

  it('summaries, messages, drafts, AI and filing are cleaned', () => {
    const s = mail.normalizeSummary({ id: '7', accountId: 2, from: { name: 'Tim\u0007', address: 'tim@firma.de' }, to: [{ address: 'a@b.de' }, {}, { address: 'c@d.de' }, { address: 'e@f.de' }, { address: 'g@h.de' }], subject: 'Hi', date: '2026-11-03T08:15:00Z', unread: true, tab: 'spam' });
    assert.equal(s.id, 7);
    assert.deepEqual(s.from, { name: 'Tim', email: 'tim@firma.de' });
    assert.equal(s.to.length, 3);
    assert.equal(s.tab, 'relevant');
    assert.equal(s.date, Date.parse('2026-11-03T08:15:00Z'));
    const m = mail.normalizeMessage({ id: 1, accountId: 1, html: '<p>x</p>', attachments: [{ id: 3, name: 'a.pdf', suggestion: { folderId: 9, confidence: 7, reason: 'magic' } }, { id: 0 }], listUnsubscribe: { url: 'javascript:alert(1)', mail: 'mailto:stop@x.de?subject=a' } });
    assert.equal(m.attachments.length, 1);
    assert.deepEqual([m.attachments[0].suggestion.confidence, m.attachments[0].suggestion.reason], [1, null]);
    assert.deepEqual(m.listUnsubscribe, { url: null, mail: 'stop@x.de' });
    const d = mail.normalizeDraft({ draft: { id: 4, attachments: [{ id: 1, as: 'link', url: 'http://insecure' }], warnings: [{ kind: 'too_large', text: 'zu groß' }, { kind: 'x' }] } });
    assert.deepEqual(d.attachments[0], { id: 1, name: 'Anhang', size: 0, mime: null, as: 'link', url: null });
    assert.deepEqual(d.warnings, [{ kind: 'too_large', text: 'zu groß' }]);
    assert.deepEqual(mail.normalizeAi({ status: 'pending' }), { status: 'none' });
    const ai = mail.normalizeAi({ status: 'done', todos: [{ kind: 'deadline', text: 'x', date: '2026-11-28', time: '25:99x' }, { kind: 'nope', text: 'y' }], replies: [{ label: 'A', text: 'B' }, { label: 'C' }] });
    assert.deepEqual(ai.todos, [{ kind: 'deadline', text: 'x', date: '2026-11-28', time: null, amount: null, currency: null }]);
    assert.equal(ai.replies.length, 1);
    assert.equal(mail.normalizeFiling({ items: [{ id: 1, from: 'Verein', suggestion: null }] }).items[0].from.name, 'Verein');
  });

  it('list and search queries are checked', () => {
    assert.deepEqual(mail.listQuery({}), { box: 'all', limit: 50 });
    assert.deepEqual(mail.listQuery({ box: 2, folder: 11, tab: 'other', unread: true, before: '123.4', limit: 20 }), { box: '2', folder: 11, tab: 'other', unread: 1, before: '123.4', limit: 20 });
    assert.equal(mail.listQuery({ box: 'all', folder: 3 }), null, 'a folder needs an account');
    assert.equal(mail.listQuery({ box: '../x' }), null);
    assert.equal(mail.listQuery({ tab: 'spam' }), null);
    assert.equal(mail.listQuery({ before: 'a b' }), null);
    assert.equal(mail.listQuery({ limit: 1000 }), null);
    assert.deepEqual(mail.searchQuery({ q: ' Rechnung ', box: 'all', after: 5, unread: true }), { q: 'Rechnung', box: 'all', after: 5, unread: 1 });
    assert.equal(mail.searchQuery({ q: '' }), null);
    assert.equal(mail.listKey(mail.listQuery({ box: 1, tab: 'relevant' })), '1||relevant|||');
    assert.equal(mail.isInboxKey(mail.listQuery({ box: 1, folder: 12 })), false);
  });

  it('recipients and draft bodies', () => {
    assert.deepEqual(mail.recipients('Tim Brandt <tim@firma.de>, "Keller, Sabine" <sabine@firma.de>; max@gmx.de, TIM@firma.de'), [
      { name: 'Tim Brandt', email: 'tim@firma.de' }, { name: 'Keller, Sabine', email: 'sabine@firma.de' }, { name: null, email: 'max@gmx.de' },
    ]);
    assert.equal(mail.recipients('tim@'), null);
    assert.deepEqual(mail.draftBody({ replyTo: 5, mode: 'reply' }), { replyTo: 5, mode: 'reply', attachments: [] });
    assert.equal(mail.draftBody({ mode: 'reply' }), null, 'a reply needs its mail');
    const b = mail.draftBody({
      accountId: 1, to: [{ email: 'a@b.de' }], subject: 'Hi\n', html: '<p><img src="gcmail://img/tok"></p>',
      attachments: [{ id: 3 }, { mediaId: 'm123456', name: 'A.pdf' }, { messageId: 1, attachmentId: 2 }, { driveNodeId: 9, as: 'link', expiresDays: 14, password: 'pw' }, { driveNodeId: 8 }],
    });
    assert.equal(b.subject, 'Hi ');
    assert.equal(b.html, '<p><img src="img/tok"></p>', 'gcmail pictures go back as the plugin\'s img/<token>');
    assert.deepEqual(b.attachments, [{ id: 3 }, { mediaId: 'm123456', name: 'A.pdf' }, { messageId: 1, attachmentId: 2 }, { driveNodeId: 9, as: 'link', expiresDays: 14, password: 'pw' }, { driveNodeId: 8, as: 'copy' }]);
    assert.equal(mail.draftBody({ attachments: [{ driveNodeId: 9, as: 'link', expiresDays: 120 }] }), null);
    assert.equal(mail.draftBody({ attachments: [{ path: 'C:\\x' }] }), null);
    assert.equal(mail.accountBody({ provider: 'gmx', email: 'a@gmx.de', password: 'x', imap: { host: '127.0.0.1;rm', port: 993, security: 'tls' } }), null);
    assert.deepEqual(mail.accountBody({ provider: 'imap', email: 'a@x.de', password: 'p', name: 'Privat', color: '#f5b544', imap: { host: 'IMAP.x.de', port: 993, security: 'tls' } }), {
      provider: 'imap', email: 'a@x.de', password: 'p', name: 'Privat', color: '#F5B544', imap: { host: 'imap.x.de', port: 993, security: 'tls' },
    });
    assert.deepEqual(mail.accountPatch({ push: 'all', ai: false, signature: 'Gruß\r\nMax' }), { push: 'all', ai: false, signature: 'Gruß\nMax' });
    assert.equal(mail.accountPatch({ push: 'sometimes' }), null);
    assert.equal(mail.settingsPatch({ swipeLeft: 'explode' }), null);
  });

  it('the frame document: pictures only through gcmail:, cid to the attachment, blocked ones held back, own CSP', () => {
    const msg = {
      id: 5,
      imagesBlocked: false,
      html: '<p title="a src=x">src="y"</p><img src="img/tok_1" srcset="https://t.example/x 2x"><img src=\'cid:Logo@X\'><img src="https://tracker.example/p.gif">'
        + '<img src="/api/v1/client/plugins/gatecontrol-mail/api/img/tok_2"><img src="data:image/png;base64,AAAA"><img src="data:image/svg+xml;base64,PHN2Zz4=">'
        + '<img alt="a>b" src="https://quoted.example/x.png"><img src="file:///C:/x.png"><img src="gcmail://cid/9/9"><table background="https://t.example/bg.png"><tr><td>x</td></tr></table>',
      attachments: [{ id: 9, cid: '<logo@x>' }],
    };
    const doc = mail.mailDocument(msg, { lang: 'de' });
    assert.ok(doc.includes(`content="${mail.FRAME_CSP}"`));
    assert.ok(doc.includes('<base target="_blank">'));
    assert.ok(doc.includes('src="gcmail://img/tok_1"'));
    assert.ok(doc.includes('src="gcmail://img/tok_2"'));
    assert.ok(doc.includes('src="gcmail://cid/5/9"'));
    assert.ok(doc.includes('src="data:image/png;base64,AAAA"'));
    assert.ok(!/https:\/\/(t|tracker|quoted)\.example/.test(doc), 'no remote source left');
    assert.ok(!doc.includes('file:///') && !doc.includes('svg+xml') && !doc.includes('gcmail://cid/9/9'));
    assert.ok(doc.includes('<p title="a src=x">src="y"</p>'), 'text is not touched');
    const blocked = mail.mailDocument({ ...msg, imagesBlocked: true });
    assert.ok(!blocked.includes('gcmail://img/'), 'blocked pictures are not requested');
    assert.ok(blocked.includes('gcmail://cid/5/9'), 'embedded pictures are no tracking');
    const t = mail.mailDocument({ id: 1, text: 'Hallo <b>\nhttps://x.de/a?b=1. javascript:alert(1)' });
    assert.ok(t.includes('Hallo &lt;b&gt;'));
    assert.ok(t.includes('<a href="https://x.de/a?b=1">https://x.de/a?b=1</a>.'));
    assert.ok(!t.includes('href="javascript'));
    const ed = mail.editorDocument('<p><img src="img/tok"></p>', { placeholder: 'Nachricht "x"' });
    assert.ok(ed.includes('contenteditable="true"') && ed.includes('src="gcmail://img/tok"') && ed.includes('data-placeholder="Nachricht &quot;x&quot;"'));
  });

  it('gcmail URLs, PKCE and the authorize URL', () => {
    assert.deepEqual(mail.parseSchemeUrl('gcmail://img/tok_1'), { kind: 'img', token: 'tok_1' });
    assert.deepEqual(mail.parseSchemeUrl('gcmail://cid/5/9'), { kind: 'cid', messageId: 5, attachmentId: 9 });
    for (const bad of ['gcmail://img/a/b', 'gcmail://cid/0/1', 'gcmail://img/tok?x=1', 'https://img/tok', 'gcmail://file/x', 'gcmail://img/%2e%2e']) assert.equal(mail.parseSchemeUrl(bad), null, bad);
    const p = mail.pkcePair(() => Buffer.alloc(32, 7));
    assert.equal(p.verifier.length, 43);
    assert.match(p.challenge, /^[A-Za-z0-9_-]{43}$/);
    const u = new URL(mail.msAuthorizeUrl({ authority: 'https://login.microsoftonline.com/common/', clientId: 'abcd-1234-efgh', redirectUri: 'http://localhost:4711', scopes: mail.MS_SCOPES, state: 'state-state-state-1', challenge: p.challenge }));
    assert.equal(u.origin + u.pathname, 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize');
    assert.equal(u.searchParams.get('code_challenge_method'), 'S256');
    assert.equal(u.searchParams.get('redirect_uri'), 'http://localhost:4711');
    assert.equal(u.searchParams.get('scope'), 'openid profile email offline_access User.Read Mail.ReadWrite Mail.Send');
    assert.equal(mail.msAuthorizeUrl({ authority: 'https://login.microsoftonline.com.evil.de/common', clientId: 'x', redirectUri: 'r', state: 's', challenge: 'c' }), null);
    assert.equal(mail.msAuthority('https://login.microsoftonline.com:8443/common'), null);
  });

  it('push targets', () => {
    assert.deepEqual(mail.pushTarget(mail.MAIL_TOPIC, { mail: { messageId: 5, accountId: '2' } }), { kind: 'message', messageId: 5, accountId: 2 });
    assert.deepEqual(mail.pushTarget(mail.FAILED_TOPIC, { mail: { outboxId: 9 } }), { kind: 'outbox', outboxId: 9 });
    assert.equal(mail.pushTarget('plugin:gatecontrol-drive:deadline', { mail: { messageId: 5 } }), null);
  });
});

describe('MailApi', () => {
  it('a refusal { error: { code, hint } } gives code and detail', async () => {
    const srv = await mailServer();
    cleanup.push(() => srv.close());
    const api = new MailApi({ apiClient: new ApiClient(srv.url, 'gc_token', log), log });
    await assert.rejects(api.addAccount({ provider: 'gmx', email: 'a@gmx.de', password: 'falsch' }), (err) => {
      assert.equal(err.status, 409);
      assert.equal(err.code, 'auth_failed');
      assert.deepEqual(err.detail.hint, { de: 'Passwort prüfen.', en: 'Check the password.' });
      assert.ok(!JSON.stringify(err).includes('falsch'), 'no password in the error');
      return true;
    });
    await assert.rejects(api.addAccount({ provider: 'gmx', email: 'kaputt', password: 'x' }), { code: 'invalid' });
    const prov = await api.providers();
    assert.deepEqual(prov.map((p) => p.id), ['m365', 'gmx', 'gmail', 'imap']);
    assert.equal(prov[2].help, null, 'no javascript: help link');
    assert.equal(srv.state.requests.find((r) => r.path.endsWith('/providers')).query.lang, undefined);
  });
});

describe('MailService', () => {
  it('available only with the plugin and for people let in; the cache goes otherwise', async () => {
    const cacheDir = tmpDir('mail-cache-');
    const { svc, srv } = await setup({}, { cacheDir, protect: fakeProtect() });
    assert.equal(svc.status().state, 'available');
    assert.equal(svc.status().version, '1.0.0');
    await svc.list({ box: 'all', tab: 'relevant' });
    await svc.cache.flush();
    assert.ok(fs.readdirSync(cacheDir).length > 0);
    srv.state.allowed = false;
    await svc.check();
    assert.deepEqual([svc.status().state, svc.status().reason], ['unavailable', 'not_allowed']);
    await until(() => !fs.existsSync(cacheDir));
    await assert.rejects(svc.list({}), { code: 'mail_unavailable' });
    const none = await setup({ plugin: false });
    assert.deepEqual([none.svc.status().state, none.svc.status().reason], ['unavailable', 'not_installed']);
  });

  it('lists: Alle Posteingänge with Relevant / Sonstige, pages by cursor, a folder', async () => {
    const { svc } = await setup();
    const rel = await svc.list({ box: 'all', tab: 'relevant', limit: 10 });
    assert.equal(rel.ok, true);
    assert.deepEqual(rel.items.slice(0, 2).map((m) => m.id), [101, 102]);
    assert.ok(rel.next);
    assert.ok(rel.counts.other >= 1);
    const more = await svc.list({ box: 'all', tab: 'relevant', limit: 10, before: rel.next });
    assert.ok(more.items.every((m) => !rel.items.some((x) => x.id === m.id)));
    const other = await svc.list({ box: 1, tab: 'other' });
    assert.deepEqual(other.items.map((m) => m.id), [104]);
    const sent = await svc.list({ box: 1, folder: 12 });
    assert.deepEqual(sent.items, []);
    const f = await svc.folders();
    assert.deepEqual(f.accounts[0].folders.find((x) => x.id === 15), { id: 15, name: 'Rechnungen', path: 'Archive/Rechnungen', role: null, parentId: 14, unread: 0, total: 0 });
    const s = await svc.search({ q: 'rechnung' });
    assert.deepEqual(s.items.map((m) => m.id), [101]);
  });

  it('offline: the last lists and opened mails come from the encrypted cache (30 days of the inbox filled)', async () => {
    const cacheDir = tmpDir('mail-cache-');
    const protect = fakeProtect();
    const { svc, srv, apiClient } = await setup({}, { cacheDir, protect });
    await svc.list({ box: 1, tab: 'relevant', limit: 20 });
    // the inbox is filled back 30 days in the background
    await until(async () => {
      const l = await svc.cache.getList(mail.listKey(mail.listQuery({ box: 1, tab: 'relevant', limit: 20 })));
      return l && l.items.some((m) => m.date <= Date.now() - 30 * 24 * 3600e3);
    });
    const opened = await svc.message(101);
    assert.equal(opened.message.subject, 'Ihre Rechnung November');
    await svc.cache.flush();
    for (const f of fs.readdirSync(cacheDir, { recursive: true })) {
      const p = path.join(cacheDir, f);
      if (fs.statSync(p).isFile()) assert.ok(!fs.readFileSync(p).toString('latin1').includes('Rechnung'), `plain text in ${f}`);
    }
    // a new app start without the server
    srv.down = true;
    const svc2 = new MailService({ apiClient, log, cacheDir: () => cacheDir, protect, getLang: () => 'de' });
    svc2._setState({ state: 'available' });
    const l = await svc2.list({ box: 1, tab: 'relevant', limit: 20 });
    assert.equal(l.offline, true);
    assert.ok(l.items.length > 20);
    assert.equal(l.next, null);
    const m = await svc2.message(101);
    assert.equal(m.offline, true);
    assert.ok(m.doc.includes('Sehr geehrte Kundin'));
    await assert.rejects(svc2.message(102), { code: 'network' });
    const me = await svc2.me();
    assert.equal(me.offline, true);
    // without DPAPI nothing is written
    const plain = new MailCache({ dir: () => cacheDir + '-x', protect: { available: () => false } });
    plain.setScope('s');
    await plain.putMessage({ id: 1, date: 1 });
    await plain.flush();
    assert.equal(fs.existsSync(cacheDir + '-x'), false);
  });

  it('a mail: marked read, its frame document, pictures through the protocol, "Bilder laden"', async () => {
    const { svc, srv } = await setup();
    const r = await svc.message(101);
    assert.equal(r.message.unread, false);
    assert.equal(srv.state.messages.get(101).unread, false, 'marked read on the server');
    assert.equal(r.message.imagesBlocked, true);
    assert.ok(!r.doc.includes('gcmail://img/'), 'blocked pictures are held back');
    assert.ok(r.doc.includes('gcmail://cid/101/2'));
    const cid = await svc.handleProtocol({ url: 'gcmail://cid/101/2', method: 'GET' });
    assert.equal(cid.status, 200);
    assert.equal(cid.headers.get('content-type'), 'image/png');
    assert.deepEqual(Buffer.from(await cid.arrayBuffer()), PNG);
    const shown = await svc.allowImages(101, 'once');
    assert.ok(shown.doc.includes('src="gcmail://img/tok_logo"'));
    const img = await svc.handleProtocol({ url: 'gcmail://img/tok_logo', method: 'GET' });
    assert.equal(img.status, 200);
    const n = srv.state.requests.filter((x) => x.path.endsWith('/img/tok_logo')).length;
    await svc.handleProtocol({ url: 'gcmail://img/tok_logo', method: 'GET' });
    assert.equal(srv.state.requests.filter((x) => x.path.endsWith('/img/tok_logo')).length, n, 'kept in memory');
    assert.ok(srv.state.requests.filter((x) => x.path.includes('/img/')).every((x) => x.auth === 'gc_token'), 'with the client sign-in');
    assert.equal((await svc.handleProtocol({ url: 'gcmail://img/tok_svg', method: 'GET' })).status, 404, 'never SVG');
    assert.equal((await svc.handleProtocol({ url: 'gcmail://img/tok_big', method: 'GET' })).status, 404, 'too large (413)');
    // cid: the answer names the media, its bytes come from the plugin's media route
    assert.ok(srv.state.requests.some((x) => x.path.endsWith('/media/cid101x2')));
    // a body not in the server's copy
    const missing = await svc.message(105);
    assert.equal(missing.message.bodyMissing, true);
    assert.equal(missing.message.html, null);
    assert.equal((await svc.handleProtocol({ url: 'gcmail://evil/x', method: 'GET' })).status, 404);
    assert.equal((await svc.handleProtocol({ url: 'gcmail://img/tok_logo', method: 'POST' })).status, 405);
    const thread = await svc.thread(900);
    assert.deepEqual(thread.items.map((m) => m.id), [103, 102]);
    assert.ok(thread.items[0].doc.startsWith('<!doctype html>'));
  });

  it('acting on mails: flags, archive, delete, Relevant / Sonstige — the cache follows', async () => {
    const { svc, srv } = await setup();
    const key = mail.listKey(mail.listQuery({ box: 'all', tab: 'relevant' }));
    await svc.list({ box: 'all', tab: 'relevant' });
    await svc.flags([102], { flagged: true });
    assert.equal(srv.state.messages.get(102).flagged, true);
    assert.equal((await svc.cache.getList(key)).items.find((m) => m.id === 102).flagged, true);
    await svc.act('archive', [102]);
    assert.equal(srv.state.messages.get(102).folderId, 24);
    assert.ok(!(await svc.cache.getList(key)).items.some((m) => m.id === 102));
    await svc.act('tab', [104], { tab: 'relevant' });
    assert.equal(srv.state.messages.get(104).tab, 'relevant');
    await svc.act('delete', [101]);
    assert.equal(srv.state.messages.get(101).folderId, 13);
    await svc.act('move', [103], { folderId: 21 });
    await assert.rejects(svc.act('archive', []), { code: 'invalid' });
  });

  it('accounts: providers, add (errors with hint), change, remove, settings', async () => {
    const { svc, srv } = await setup();
    const p = await svc.providers();
    assert.equal(p.providers[0].auth, 'microsoft');
    const d = await svc.discover('max@example.org');
    assert.deepEqual(d.imap, { host: 'imap.example.org', port: 993, security: 'tls' });
    await assert.rejects(svc.addAccount({ provider: 'gmx', email: 'neu@gmx.de', password: 'falsch' }), (e) => e.code === 'auth_failed' && e.detail.hint.de === 'Passwort prüfen.');
    const changed = [];
    svc.on('changed', (c) => changed.push(c));
    const a = await svc.addAccount({ provider: 'imap', email: 'neu@example.org', password: 'pw', name: 'Verein', color: '#46E0A0', imap: d.imap, smtp: d.smtp });
    assert.equal(a.account.name, 'Verein');
    assert.deepEqual(srv.state.lastAccountBody.smtp, { host: 'smtp.example.org', port: 587, security: 'starttls' });
    assert.equal(changed.length, 1);
    const u = await svc.updateAccount(a.account.id, { push: 'off', signature: 'Gruß' });
    assert.deepEqual([u.account.push, u.account.signature], ['off', 'Gruß']);
    await svc.deleteAccount(a.account.id);
    assert.ok(!srv.state.accounts.some((x) => x.id === a.account.id));
    const st = await svc.settings({ swipeLeft: 'delete' });
    assert.equal(st.settings.swipeLeft, 'delete');
  });

  it('Microsoft: PKCE in the browser, loopback http://localhost:<port>, then POST accounts/microsoft', async () => {
    let srvRef = null;
    const opened = [];
    const browser = async (url) => {
      opened.push(url);
      const u = new URL(url);
      const code = srvRef.issueCode(u.searchParams.get('code_challenge'));
      const back = `${u.searchParams.get('redirect_uri')}/?code=${encodeURIComponent(code)}&state=${encodeURIComponent(u.searchParams.get('state'))}`;
      setTimeout(() => http.get(back, (res) => res.resume()), 5);
      return true;
    };
    const { svc, srv } = await setup({}, { openExternal: browser });
    srvRef = srv;
    const r = await svc.signInMicrosoft({ name: 'Firma', color: '#79B8FF' });
    assert.equal(r.account.provider, 'm365');
    assert.equal(r.account.name, 'Firma');
    const sent = srv.state.microsoft[0];
    assert.match(sent.redirectUri, /^http:\/\/localhost:\d+$/);
    assert.match(sent.codeVerifier, /^[A-Za-z0-9_-]{43}$/);
    assert.ok(opened[0].startsWith('https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=abcd-1234-efgh-5678'));
    // sign in again
    const again = await svc.signInMicrosoft({ accountId: 2 });
    assert.equal(again.account.id, 2);
    // the browser says no
    const deny = await setup({}, { openExternal: async (url) => {
      const u = new URL(url);
      setTimeout(() => http.get(`${u.searchParams.get('redirect_uri')}/?error=access_denied&state=${u.searchParams.get('state')}`, (res) => res.resume()), 5);
      return true;
    } });
    await assert.rejects(deny.svc.signInMicrosoft({}), { code: 'access_denied' });
    // without a client id on the server
    const off = await setup({ features: ['mail'] }, { openExternal: async () => true });
    await assert.rejects(off.svc.signInMicrosoft({}), { code: 'ms_unavailable' });
    // cancelled while waiting
    const wait = await setup({}, { openExternal: async () => true });
    const p = wait.svc.signInMicrosoft({});
    await until(() => wait.svc._signin);
    wait.svc.cancelSignIn();
    await assert.rejects(p, { code: 'cancelled' });
  });

  it('writing: reply filled by the server, attachments from this PC and Drive, send with undo, send later, outbox', async () => {
    const { svc, srv, temp } = await setup();
    const reply = await svc.createDraft({ replyTo: 102, mode: 'reply' });
    assert.equal(reply.draft.accountId, 2, 'answered from the account the mail came to');
    assert.equal(reply.draft.subject, 'AW: Projektbesprechung Dienstag');
    assert.deepEqual(reply.draft.to, [{ name: 'Sabine Keller', email: 'sabine@firma.de' }]);
    const file = path.join(temp, 'Angebot.pdf');
    fs.writeFileSync(file, 'PDF-Inhalt');
    const big = path.join(temp, 'gross.bin');
    fs.writeFileSync(big, '');
    fs.truncateSync(big, 60 * 1024 * 1024);
    const up = await svc.uploadFiles([file, big, path.join(temp, 'fehlt.txt')]);
    assert.equal(up.items.length, 1);
    assert.deepEqual(up.items[0].name, 'Angebot.pdf');
    assert.deepEqual(up.rejected.map((x) => x.code).sort(), ['missing', 'too_large']);
    assert.equal(srv.state.uploads.length, 1, 'the big file never went up');
    const upd = await svc.updateDraft(reply.draft.id, {
      to: 'Sabine Keller <sabine@firma.de>', subject: 'AW: Projektbesprechung', html: '<p>Passt!</p>',
      attachments: [{ mediaId: up.items[0].mediaId }, { driveNodeId: 9999, as: 'copy' }],
    });
    assert.deepEqual(upd.draft.attachments.map((a) => a.as), ['copy', 'link']);
    assert.equal(upd.draft.warnings[0].kind, 'too_large');
    // PUT drafts: the whole list, { id } keeps one (the Drive link; a file of this PC cannot go out of a Microsoft account)
    const keep = await svc.updateDraft(reply.draft.id, { attachments: [{ id: upd.draft.attachments[1].id }] });
    assert.deepEqual(keep.draft.attachments.map((a) => a.as), ['link'], 'kept attachments are named by their id');
    assert.deepEqual(keep.draft.warnings, []);
    const outbox = [];
    svc.on('outbox', () => outbox.push(1));
    const sent = await svc.send(reply.draft.id);
    assert.ok(sent.undoUntil > Date.now());
    const back = await svc.cancelSend(sent.outboxId);
    assert.equal(back.draftId, reply.draft.id);
    assert.equal(back.draft.subject, 'AW: Projektbesprechung');
    const at = Date.now() + 24 * 3600e3;
    const later = await svc.send(reply.draft.id, at);
    assert.equal(later.sendAt, at);
    const ob = await svc.outbox();
    assert.deepEqual(ob.items.map((x) => [x.id, x.state]), [[later.outboxId, 'waiting']]);
    assert.equal(outbox.length, 3);
    // forwarding: the client names the attachments to take along ({ messageId, attachmentId })
    // Microsoft accounts cannot send files of this PC: a warning on the draft, send refused
    const ms = await svc.createDraft({ accountId: 2, to: [{ email: 'tim@firma.de' }], subject: 'MS', attachments: [{ mediaId: up.items[0].mediaId, name: 'Angebot.pdf' }] });
    assert.equal(ms.draft.attachments[0].name, 'Angebot.pdf');
    const msu = await svc.updateDraft(ms.draft.id, { subject: 'MS 2', attachments: [{ id: ms.draft.attachments[0].id }] });
    assert.equal(msu.draft.warnings[0].kind, 'too_large');
    await assert.rejects(svc.send(ms.draft.id), (e) => e.code === 'attachments_unsupported' && e.status === 409);
    const fw = await svc.createDraft({ replyTo: 101, mode: 'forward', attachments: [{ messageId: 101, attachmentId: 1 }] });
    assert.deepEqual(fw.draft.attachments.map((a) => a.name), ['Rechnung_2026_11.pdf']);
    const c = await svc.contacts('tim');
    assert.deepEqual(c.items, [{ name: 'Tim Brandt', email: 'tim@firma.de', source: 'person' }]);
    await svc.deleteDraft(fw.draft.id);
    assert.ok(!srv.state.drafts.has(fw.draft.id));
    assert.ok(svc.editorDoc('<p>x</p>').doc.includes('Nachricht schreiben'));
  });

  it('attachments: open (never executables directly), save as', async () => {
    const openedPaths = [];
    const shell = { openPath: async (p) => { openedPaths.push(p); return ''; } };
    const saveTo = path.join(tmpDir('mail-save-'), 'r.pdf');
    const dialog = { showSaveDialog: async () => ({ canceled: false, filePath: saveTo }) };
    const { svc, temp } = await setup({}, { shell, dialog });
    const r = await svc.openAttachment(101, 1, { name: 'Rechnung_2026_11.pdf', mime: 'application/pdf' });
    assert.equal(r.ok, true);
    assert.ok(r.path.startsWith(temp));
    assert.ok(fs.readFileSync(r.path, 'utf8').includes('Rechnung_2026_11.pdf'));
    assert.deepEqual(openedPaths, [r.path]);
    const exe = await svc.openAttachment(101, 1, { name: 'rechnung.pdf.exe' });
    assert.deepEqual([exe.ok, exe.code], [false, 'unsafe']);
    const s = await svc.saveAttachment(101, 1, { name: 'Rechnung.pdf' });
    assert.equal(s.path, saveTo);
    assert.ok(fs.existsSync(saveTo));
  });

  it('AI, family calendar, Drive and "Zum Ablegen"', async () => {
    const { svc, srv } = await setup();
    assert.equal(mail.normalizeMessage({ id: 1, accountId: 1, bodyMissing: true }).bodyMissing, true);
    const ai = await svc.ai(101);
    assert.equal(ai.ai.summary, 'Rechnung über 84,20 € für Strom im Oktober, wird am 28.11. abgebucht.');
    assert.equal(ai.ai.todos[0].kind, 'deadline');
    assert.deepEqual((await svc.ai(102)).ai, { status: 'none' });
    const run = await svc.runAi(102);
    assert.equal(run.ai.replies[0].text, 'Passt, danke!');
    await svc.runAi(102);
    assert.equal(srv.state.aiRuns, 1, 'an existing result is answered as it is');
    await svc.runAi(102, { again: true });
    assert.equal(srv.state.aiRuns, 2, '"Neu erstellen" asks anew');
    const todo = await svc.todo(101, 0);
    assert.equal(todo.where, 'Familienkalender · 28.11.');
    assert.deepEqual(srv.state.todos[0].body, { action: 'family_calendar' });
    const sug = await svc.suggest(101, 1);
    assert.equal(sug.suggestion.path, 'Finanzen › Strom');
    const saved = await svc.saveToDrive(101, 1, { remember: true });
    assert.equal(saved.savedTo.where, 'Meine Dateien › Finanzen › Strom');
    assert.deepEqual(srv.state.lastSave, { remember: true });
    const all = await svc.saveAll(101);
    assert.deepEqual(all.failed, [{ attachmentId: 99, code: 'too_large' }]);
    const f = await svc.filing();
    assert.equal(f.items[0].suggestion.confidence, 0.72);
    const c = await svc.confirmFiling(501, { folderId: 88 });
    assert.equal(c.savedTo.where, 'Meine Dateien › Gewählt');
    srv.state.features = ['mail'];
    await assert.rejects(svc.runAi(101), { code: 'ai_off' });
  });

  it('live events and push clicks', async () => {
    const pushClient = new EventEmitter();
    const routes = new Map();
    const nc = new EventEmitter();
    nc.addClickRoute = (route, fn) => { routes.set(route, fn); return () => routes.delete(route); };
    const { svc } = await setup({}, { pushClient, notificationCenter: nc });
    const changed = [];
    const outbox = [];
    svc.on('changed', (c) => changed.push(c));
    svc.on('outbox', () => outbox.push(1));
    pushClient.emit('event', { event: 'plugin', data: { plugin: 'gatecontrol-mail', type: 'mail', data: { kind: 'changed', accountId: 2, folderId: 21 } } });
    pushClient.emit('event', { event: 'plugin', data: { plugin: 'gatecontrol-drive', type: 'mail', data: { kind: 'changed' } } });
    assert.deepEqual(changed, [{ accountId: 2, folderId: 21 }]);
    nc.emit('new', { topic: mail.FAILED_TOPIC, data: { mail: { outboxId: 3 } } });
    assert.equal(outbox.length, 1);
    const click = routes.get('plg-gatecontrol-mail');
    assert.deepEqual(click({ topic: 'plugin:gatecontrol-mail:mail', data: { mail: { messageId: 101, accountId: 1 } } }), { kind: 'message', messageId: 101, accountId: 1 });
    svc.stop();
    assert.equal(routes.size, 0);
    assert.equal(pushClient.listenerCount('event'), 0);
  });
});

describe('mail loopback receiver', () => {
  const get = (url, headers = {}) => new Promise((resolve, reject) => {
    const req = http.get(url, { headers }, (res) => { let b = ''; res.on('data', (c) => { b += c; }); res.on('end', () => resolve({ status: res.statusCode, body: b })); });
    req.on('error', reject);
  });

  it('one answer with the right state; foreign hosts and paths do not count', async () => {
    const l = await startCodeListener({ state: 'abcdefghijklmnopqrstuvwx', getLang: () => 'en' });
    cleanup.push(() => l.close());
    assert.equal(l.redirectUri, `http://localhost:${l.port}`);
    assert.equal((await get(`http://127.0.0.1:${l.port}/favicon.ico`)).status, 404);
    assert.equal((await get(`http://127.0.0.1:${l.port}/?code=abcdefghijkl&state=x`, { Host: 'evil.example:80' })).status, 404);
    const ok = await get(`http://127.0.0.1:${l.port}/?code=M.C123_abc-DEF&state=abcdefghijklmnopqrstuvwx`);
    assert.equal(ok.status, 200);
    assert.ok(ok.body.includes('Signed in'));
    assert.deepEqual(await l.result, { code: 'M.C123_abc-DEF' });
  });

  it('a wrong state, Microsoft errors and the timeout', async () => {
    const a = await startCodeListener({ state: 'abcdefghijklmnopqrstuvwx' });
    await get(`http://127.0.0.1:${a.port}/?code=M.C123_abc-DEF&state=other-state-value-xx`);
    assert.deepEqual(await a.result, { error: 'state_mismatch' });
    const b = await startCodeListener({ state: 'abcdefghijklmnopqrstuvwx' });
    const page = await get(`http://127.0.0.1:${b.port}/?error=invalid_client&state=abcdefghijklmnopqrstuvwx`);
    assert.ok(page.body.includes('nicht abgeschlossen'));
    assert.deepEqual(await b.result, { error: 'ms_not_configured' });
    const c = await startCodeListener({ state: 'abcdefghijklmnopqrstuvwx', timeoutMs: 20 });
    assert.deepEqual(await c.result, { error: 'timeout' });
    await assert.rejects(startCodeListener({ state: 'short' }));
  });
});

describe('mail IPC', () => {
  it('checks arguments, passes the plugin\'s detail, forwards events', async () => {
    const { svc } = await setup();
    const handlers = {};
    const sent = [];
    const win = { isDestroyed: () => false, webContents: { send: (ch, p) => sent.push([ch, p]) } };
    registerMailHandlers((ch, fn) => { handlers[ch] = fn; }, { mail: svc, getMainWindow: () => win, log });
    const call = (ch, arg) => handlers[ch]({}, arg);
    assert.equal((await call('mail:status')).state, 'available');
    assert.equal((await call('mail:me')).accounts.length, 2);
    assert.equal((await call('mail:message', { id: 'x' })).code, 'invalid');
    assert.equal((await call('mail:act', { action: 'burn', ids: [1] })).code, 'invalid');
    assert.equal((await call('mail:act', { action: 'move', ids: [1] })).code, 'invalid');
    assert.equal((await call('mail:list', { box: '../../x' })).code, 'invalid');
    assert.equal((await call('mail:send', { id: 1, sendAt: 'morgen' })).code, 'invalid');
    assert.equal((await call('mail:upload', { paths: ['a', 1] })).code, 'invalid');
    const r = await call('mail:account:add', { provider: 'gmx', email: 'a@gmx.de', password: 'falsch' });
    assert.deepEqual([r.ok, r.code, r.status, r.detail.hint.en], [false, 'auth_failed', 409, 'Check the password.']);
    const l = await call('mail:list', { box: 'all', tab: 'relevant' });
    assert.ok(l.items.length > 0);
    const d = await call('mail:draft:create', { replyTo: 102, mode: 'replyAll', bogus: 1 });
    assert.equal(d.ok, true);
    const u = await call('mail:draft:update', { id: d.draft.id, subject: 'Neu' });
    assert.equal(u.draft.subject, 'Neu');
    svc.emit('changed', { accountId: 1, folderId: null });
    assert.deepEqual(sent.at(-1), ['mail:changed', { accountId: 1, folderId: null }]);
  });
});

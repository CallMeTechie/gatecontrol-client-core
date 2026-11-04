'use strict';

// The host's virus scan in the Windows apps (Drive 1.19, GateDrop 1.4, Mail 1.8, Messenger 1.11; GateControl 1.223.0):
// `scan { state, blocked, finding }` cleaned and passed on, the refusals 423 scan_pending / quarantined / scan_blocked,
// 422 infected, 503 scan_unavailable, 410 attachment_removed, 409 attachment_blocked as codes with their fields for the
// window, Retry-After, blocked files never opened / loaded / synced, the texts DE / EN — and nothing new without `scan`.

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { Readable } = require('node:stream');
const Module = require('node:module');

const realResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === '@callmetechie/gatecontrol-config-hash') return require.resolve('./fixtures/config-hash-stub');
  return realResolve.call(this, request, ...rest);
};

const SC = require('../src/utils/scan');
const drive = require('../src/utils/drive');
const S = require('../src/utils/drive-sync');
const gd = require('../src/utils/gatedrop');
const mail = require('../src/utils/mail');
const msgr = require('../src/utils/messenger');
const i18n = require('../src/i18n');
const ApiClient = require('../src/services/api-client');
const MessengerApi = require('../src/services/messenger-api');
const MessengerOutbox = require('../src/services/messenger-outbox');
const MessengerService = require('../src/services/messenger');
const PushClient = require('../src/services/push-client');
const DriveService = require('../src/services/drive');
const DriveApi = require('../src/services/drive-api');
const DriveSync = require('../src/services/drive-sync');
const GateDropService = require('../src/services/gatedrop');
const GateDropApi = require('../src/services/gatedrop-api');
const MailService = require('../src/services/mail');
const { registerDriveHandlers } = require('../src/ipc/drive-handlers');
const { registerGateDropHandlers } = require('../src/ipc/gatedrop-handlers');
const { registerMailHandlers } = require('../src/ipc/mail-handlers');
const { createMemoryStore } = require('./fixtures/memory-store');
const { driveServer } = require('./fixtures/drive-server');
const { gatedropServer } = require('./fixtures/gatedrop-server');
const { mailServer } = require('./fixtures/mail-server');
const { messengerServer, API: MSG_API } = require('./fixtures/messenger-server');

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

async function waitFor(fn, ms = 3000, what = 'condition') {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > end) throw new Error(`timeout waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 5));
  }
}

const INFECTED = { state: 'infected', blocked: true, finding: 'Eicar-Test-Signature' };

describe('utils/scan', () => {
  it('cleans scan: states, blocked decides, finding one line, Mail removed', () => {
    assert.equal(SC.normalizeScan(null), null);
    assert.equal(SC.normalizeScan('infected'), null);
    assert.deepEqual(SC.normalizeScan({ state: 'pending', blocked: true, finding: null }), { state: 'pending', blocked: true, finding: null });
    assert.deepEqual(SC.normalizeScan({ state: 'weird', blocked: 'yes', finding: ' Win.Trojan\u0000Agent \n x ' }), { state: 'unchecked', blocked: false, finding: 'Win.Trojan Agent x' });
    assert.equal(SC.normalizeScan({ state: 'infected', finding: 'x'.repeat(500) }).finding.length, 200);
    assert.deepEqual(SC.normalizeScan({ state: 'infected', blocked: false, removed: true }), { state: 'infected', blocked: true, finding: null, removed: true });
    assert.equal(SC.isBlocked(null), false);
    assert.equal(SC.isBlocked({ state: 'infected', blocked: false }), false);
    assert.equal(SC.isBlocked({ state: 'clean', blocked: true }), true);
  });

  it('what a list shows, and the refusal of a blocked file', () => {
    const v = (state, blocked, extra = {}) => SC.view({ state, blocked, finding: null, ...extra });
    assert.equal(v('pending', true), 'checking');
    assert.equal(v('infected', true), 'malware');
    assert.equal(v('unscannable', true), 'unscannable');
    assert.equal(v('unchecked', true), 'blocked');
    assert.equal(v('infected', true, { removed: true }), 'removed');
    assert.equal(v('infected', false), 'warning');
    assert.equal(v('unscannable', false), 'notCheckable');
    for (const s of ['clean', 'unchecked', 'pending']) assert.equal(v(s, false), null);
    assert.equal(SC.view(null), null);
    assert.equal(SC.refusalOf({ state: 'pending' }), 'scan_pending');
    assert.equal(SC.refusalOf({ state: 'infected' }), 'quarantined');
    assert.equal(SC.refusalOf({ state: 'unscannable' }), 'scan_blocked');
    assert.equal(SC.isRefusal('quarantined'), true);
    assert.equal(SC.isRefusal('infected'), false);
    assert.equal(SC.isScanCode('attachment_blocked'), true);
    assert.equal(SC.isScanCode('busy'), false);
  });

  it('Retry-After: seconds (1 … 60), an HTTP date, nothing else', () => {
    assert.equal(SC.retryAfterOf('5'), 5);
    assert.equal(SC.retryAfterOf(['7']), 7);
    assert.equal(SC.retryAfterOf('0'), 1);
    assert.equal(SC.retryAfterOf('3600'), 60);
    assert.equal(SC.retryAfterOf(new Date(1000 + 10000).toUTCString(), 1000), 10);
    assert.equal(SC.retryAfterOf('soon'), null);
    assert.equal(SC.retryAfterOf(undefined), null);
  });

  it('the fields of a refusal for the window (only scan codes)', () => {
    const e = new MessengerApi.MessengerError('x', { status: 423, code: 'quarantined', body: { ok: false, code: 'quarantined', scan: INFECTED } });
    assert.deepEqual(SC.refusalFields(e), { scan: INFECTED, finding: 'Eicar-Test-Signature' });
    const p = new MessengerApi.MessengerError('x', { status: 423, code: 'scan_pending', body: { code: 'scan_pending' } });
    assert.deepEqual(SC.refusalFields(p), { retryAfter: 5 });
    p.retryAfter = 8;
    assert.deepEqual(SC.refusalFields(p), { retryAfter: 8 });
    const up = new MessengerApi.MessengerError('x', { status: 422, code: 'infected', body: { code: 'infected', finding: 'GC.Office.Macro', name: 'Rechnung.docm' } });
    assert.deepEqual(SC.refusalFields(up), { finding: 'GC.Office.Macro', name: 'Rechnung.docm' });
    // Mail's form { error: { code, attachmentId, name, scan } }
    const m = new MessengerApi.MessengerError('x', { status: 409, code: 'attachment_blocked', body: { error: { code: 'attachment_blocked', attachmentId: 9, name: 'a.exe', scan: INFECTED } } });
    assert.deepEqual(SC.refusalFields(m), { scan: INFECTED, finding: 'Eicar-Test-Signature', name: 'a.exe', attachmentId: 9 });
    assert.deepEqual(SC.refusalFields(new MessengerApi.MessengerError('x', { status: 409, code: 'busy' })), {});
    assert.deepEqual(SC.refusalFields(null), {});
  });

  it('tries again while scan_pending (Retry-After), within its limits', async () => {
    const waits = [];
    const sleep = async (ms) => { waits.push(ms); };
    const pending = () => Object.assign(new Error('p'), { code: 'scan_pending', retryAfter: 2 });
    let n = 0;
    assert.equal(await SC.retryWhilePending(async () => { if (++n < 3) throw pending(); return 'ok'; }, { sleep, tries: 5 }), 'ok');
    assert.deepEqual(waits, [2000, 2000]);
    n = 0;
    await assert.rejects(SC.retryWhilePending(async () => { n++; throw pending(); }, { sleep, tries: 3 }), (e) => e.code === 'scan_pending');
    assert.equal(n, 3);
    n = 0;
    await assert.rejects(SC.retryWhilePending(async () => { n++; throw pending(); }, { sleep, tries: 10, maxWaitMs: 3000 }), (e) => e.code === 'scan_pending');
    assert.equal(n, 2, 'stops before waiting past maxWaitMs');
    n = 0;
    await assert.rejects(SC.retryWhilePending(async () => { n++; throw Object.assign(new Error('i'), { code: 'infected' }); }, { sleep }), (e) => e.code === 'infected');
    assert.equal(n, 1, 'other refusals are not tried again');
  });

  it('texts DE and EN for every kind and code', () => {
    const before = i18n.getLocale();
    try {
      i18n.setLocale('de');
      assert.equal(SC.text(i18n.t, 'checking'), 'Wird auf Viren geprüft …');
      assert.equal(SC.text(i18n.t, 'malware', { finding: 'Eicar' }), 'Gesperrt – Schadsoftware (Eicar)');
      assert.equal(SC.text(i18n.t, 'unscannable'), 'Gesperrt – konnte nicht geprüft werden');
      assert.equal(SC.text(i18n.t, 'notCheckable'), 'Nicht prüfbar');
      assert.equal(SC.text(i18n.t, 'removed'), 'Anhang entfernt (Schadsoftware)');
      assert.equal(SC.text(i18n.t, 'infected', { name: 'Foto.jpg' }), 'Foto.jpg abgelehnt – Schadsoftware gefunden.');
      assert.equal(SC.text(i18n.t, 'attachment_blocked', { name: 'a.exe' }), 'Der Anhang a.exe ist gesperrt (Schadsoftware) – entfernen?');
      assert.equal(SC.text(i18n.t, 'something'), null);
      i18n.setLocale('en');
      assert.equal(SC.text(i18n.t, 'warning', { finding: 'Eicar' }), 'Malware found (Eicar) – only open it if you trust it');
      assert.equal(SC.text(i18n.t, 'scan_unavailable'), 'Virus scan not reachable right now – please try again later.');
      // every kind and code has a text in both languages, the keys are the same
      for (const loc of ['de', 'en']) {
        i18n.setLocale(loc);
        for (const k of [...SC.KINDS, ...SC.CODES]) {
          const s = SC.text(i18n.t, k, { finding: 'F', name: 'N' });
          assert.ok(s && !s.startsWith('scan.'), `${loc} ${k}`);
        }
      }
      const de = require('../src/i18n/locales/de.json').scan;
      const en = require('../src/i18n/locales/en.json').scan;
      assert.deepEqual(Object.keys(en), Object.keys(de));
    } finally {
      i18n.setLocale(before);
    }
  });
});

describe('MessengerApi: refusals of the scan', () => {
  it('keeps Retry-After of a 423 and reads the body of a streamed refusal', async () => {
    const e = MessengerApi.toMessengerError({ response: { status: 423, headers: { 'retry-after': '5' }, data: { ok: false, code: 'scan_pending' } } });
    assert.deepEqual([e.status, e.code, e.retryAfter], [423, 'scan_pending', 5]);
    assert.equal(Object.keys(e).includes('retryAfter'), false, 'not enumerable');
    assert.equal(MessengerApi.toMessengerError({ response: { status: 400, headers: { 'retry-after': '5' }, data: {} } }).retryAfter, undefined);
    const streamed = { response: { status: 423, headers: {}, data: Readable.from([Buffer.from('{"ok":false,"code":"quarantined",'), Buffer.from('"finding":"Eicar"}')]) } };
    const s = MessengerApi.toMessengerError(await MessengerApi.bufferErrorBody(streamed));
    assert.deepEqual([s.code, s.body.finding], ['quarantined', 'Eicar']);
    const plain = { message: 'x' };
    assert.equal(await MessengerApi.bufferErrorBody(plain), plain);
  });
});

describe('Drive 1.19 (scan)', () => {
  it('nodes and photos carry scan only when known; a blocked one has no preview or media', () => {
    const base = { id: 5, areaId: 'mine:2', name: 'a.jpg', mime: 'image/jpeg', mediaId: 'abcdef12', preview: { url: '/x' } };
    const plain = drive.normalizeNode(base);
    assert.equal('scan' in plain, false, 'an older Drive: nothing new');
    assert.equal(plain.preview, true);
    const marked = drive.normalizeNode({ ...base, scan: { state: 'infected', blocked: false, finding: 'Eicar' } });
    assert.deepEqual(marked.scan, { state: 'infected', blocked: false, finding: 'Eicar' });
    assert.equal(marked.preview, true);
    const blocked = drive.normalizeNode({ ...base, scan: INFECTED });
    assert.equal(blocked.preview, false);
    assert.equal(drive.normalizeNode({ ...base, isDir: true, scan: INFECTED }).scan, undefined);
    const photo = drive.normalizePhoto({ id: 7, name: 'b.jpg', mime: 'image/jpeg', mediaId: 'abcdef12', preview: true, scan: { state: 'pending', blocked: true } });
    assert.deepEqual([photo.preview, photo.mediaId, photo.scan.state], [false, null, 'pending']);
    assert.equal('scan' in drive.normalizePhoto({ id: 7, name: 'b.jpg', mediaId: 'abcdef12', preview: true }), false);
  });

  it('the change op scan is taken; in the sync tree the rev stays and a blocked file is marked', () => {
    const node = { id: 12, areaId: 'mine:2', parentId: 10, name: 'Brief.pdf', rev: 3, size: 14, sha256: 'a'.repeat(64) };
    const r = drive.normalizeChanges({ changes: [{ seq: 4, op: 'scan', nodeId: 12, areaId: 'mine:2', node: { ...node, scan: INFECTED } }, { seq: 5, op: 'teleport', nodeId: 12 }] });
    assert.deepEqual(r.changes.map((c) => c.op), ['scan']);
    const tree = { 12: S.slimNode(drive.normalizeNode(node)) };
    assert.equal('blocked' in tree[12], false);
    S.applyChanges(tree, 10, r.changes);
    assert.deepEqual([tree[12].rev, tree[12].blocked], [3, 'quarantined']);
    S.applyChanges(tree, 10, [{ seq: 6, op: 'scan', nodeId: 12, node: drive.normalizeNode({ ...node, scan: { state: 'clean', blocked: false } }) }]);
    assert.equal('blocked' in tree[12], false);
  });

  async function setup(features = [], { shell = null, dialog = null } = {}) {
    const srv = await driveServer({ features });
    cleanup.push(() => srv.close());
    const apiClient = new ApiClient(srv.url, 'gc_token', log);
    const api = new DriveApi({ apiClient, log, getLang: () => 'de', sleep: async () => {} });
    const temp = tmpDir('drive-scan-');
    const svc = new DriveService({ apiClient, api, log, store: createMemoryStore(), shell, dialog, tempDir: () => temp, timing: { progressMs: 0 } });
    svc.start();
    cleanup.push(() => svc.stop());
    await svc.check();
    return { srv, svc, temp };
  }

  it('a blocked file is not opened (not even a copy loaded before), saved or previewed; the window gets the refusal', async () => {
    const opened = [];
    const shell = { openPath: async (p) => { opened.push(p); return ''; } };
    const dialog = { showSaveDialog: async () => { throw new Error('no dialog for a blocked file'); } };
    const { srv, svc, temp } = await setup(['scan'], { shell, dialog });
    const first = await svc.open(12);
    assert.equal(first.ok, true);
    // the nightly check blocks it
    srv.state.nodes.get(12).scan = INFECTED;
    const listed = await svc.folder(10);
    assert.deepEqual(listed.items.find((n) => n.id === 12).scan, INFECTED);
    const contentCalls = () => srv.state.requests.filter((r) => r.path.endsWith('/nodes/12/content')).length;
    const before = contentCalls();
    const err = await svc.open(12).catch((e) => e);
    assert.deepEqual([err.status, err.code], [423, 'quarantined']);
    assert.equal(contentCalls(), before, 'no bytes asked for');
    assert.equal(fs.existsSync(path.join(temp, '12-1')), false, 'the copy loaded before is gone');
    assert.deepEqual(opened, [first.path]);
    await assert.rejects(svc.saveAs(12), (e) => e.code === 'quarantined');
    srv.state.nodes.get(11).scan = { state: 'pending', blocked: true, finding: null };
    await assert.rejects(svc.previewOf(11), (e) => e.code === 'scan_pending');

    const handlers = {};
    registerDriveHandlers((ch, fn) => { handlers[ch] = fn; }, { drive: svc });
    const r = await handlers['drive:open'](null, { id: 12 });
    assert.deepEqual([r.ok, r.code, r.status, r.finding], [false, 'quarantined', 423, 'Eicar-Test-Signature']);
    assert.deepEqual(r.scan, INFECTED);
    const p = await handlers['drive:preview:node'](null, { id: 11 });
    assert.deepEqual([p.code, p.retryAfter], ['scan_pending', 5]);
    // marked, not blocked: opens (the window warns first)
    srv.state.nodes.get(12).scan = { state: 'infected', blocked: false, finding: 'Eicar' };
    assert.equal((await svc.open(12)).ok, true);
  });

  it('the plugin\'s 423 reaches the window with its code', async () => {
    const { srv, svc } = await setup(['scan'], { shell: { openPath: async () => '' } });
    srv.state.fail['GET nodes/12/content'] = { status: 423, code: 'scan_blocked' };
    const handlers = {};
    registerDriveHandlers((ch, fn) => { handlers[ch] = fn; }, { drive: svc, getMainWindow: () => null, log });
    const r = await handlers['drive:open'](null, { id: 12 });
    assert.equal(r.code, 'scan_blocked');
    assert.equal(r.status, 423);
  });

  it('folder sync: a blocked file does not come down and is no failure; freed (op scan) it comes', async () => {
    const srv = await driveServer();
    cleanup.push(() => srv.close());
    const apiClient = new ApiClient(srv.url, 'gc_token', log);
    const api = new DriveApi({ apiClient, log, getLang: () => 'de', sleep: async () => {} });
    const svc = new DriveService({ apiClient, api, log, store: createMemoryStore(), timing: { progressMs: 0 } });
    await svc.check();
    const sync = new DriveSync({
      drive: svc, api, store: createMemoryStore(), dir: tmpDir('drive-scan-state-'), log, hostname: () => 'Desktop-PC', getDeviceKey: () => 'ab12cd34',
      getInterfaces: () => ({}), isVpnUp: () => true, trashItem: async () => {}, timing: { watch: false, settleMs: 0, emitMs: 0 },
    });
    cleanup.push(() => sync.stop());
    srv.state.nodes.get(12).scan = INFECTED;
    const root = tmpDir('pc-scan-');
    const { folder } = await sync.addFolder({ path: root, mode: 'sync', targetId: 10 });
    await sync.idle();
    let f = sync.status().folders[0];
    assert.equal(fs.existsSync(path.join(root, 'Brief.pdf')), false);
    assert.deepEqual([f.failed, f.blocked, f.blockedName, f.state], [0, 1, 'Brief.pdf', 'idle']);
    // an administrator frees it: the change log says op 'scan'
    srv.state.nodes.get(12).scan = { state: 'clean', blocked: false, finding: null };
    srv.state.log.push({ seq: ++srv.state.seq, op: 'scan', areaId: 'mine:2', nodeId: 12, at: Date.now(), device: 'nas' });
    sync.sync(folder.id, { full: false, remote: true });
    await sync.idle();
    f = sync.status().folders[0];
    assert.equal(fs.readFileSync(path.join(root, 'Brief.pdf'), 'utf8'), '%PDF-1.4 brief');
    assert.deepEqual([f.failed, f.blocked], [0, 0]);
  });
});

describe('GateDrop 1.4 (scan)', () => {
  it('items: a blocked one is not available and has no mediaId; scan only when known', () => {
    const [a, b, c] = gd.normalizeItems([
      { index: 0, mediaId: 'abcdef1234567890', name: 'a.pdf', available: true },
      { index: 1, mediaId: 'abcdef1234567891', name: 'b.exe', available: true, scan: INFECTED },
      { index: 2, mediaId: 'abcdef1234567892', name: 'c.zip', available: true, scan: { state: 'unscannable', blocked: false, finding: 'encrypted' } },
    ]);
    assert.equal('scan' in a, false);
    assert.deepEqual([b.available, b.mediaId, b.scan.state], [false, null, 'infected']);
    assert.deepEqual([c.available, c.scan.finding], [true, 'encrypted']);
  });

  async function setup(srv, timing = {}) {
    const apiClient = new ApiClient(srv.url, 'gc_token', log);
    const api = new GateDropApi({ apiClient, log, sleep: async () => {} });
    const downloads = tmpDir('gd-scan-dl-');
    const svc = new GateDropService({
      apiClient, api, log, store: createMemoryStore(), listener: false, downloadsDir: () => downloads, platform: 'win32', getInterfaces: () => ({}), timing,
    });
    const waits = [];
    svc._sleep = async (ms) => { waits.push(ms); };
    svc.start();
    cleanup.push(async () => { svc.stop(); await svc.idle(); });
    await svc.check();
    return { svc, downloads, waits };
  }

  it('a send waits while the host checks a file (423 scan_pending), a refused one names the file', async () => {
    const srv = await gatedropServer();
    cleanup.push(() => srv.close());
    const { svc, waits } = await setup(srv);
    const dir = tmpDir('gd-scan-src-');
    fs.writeFileSync(path.join(dir, 'Rechnung.pdf'), '%PDF');
    const prep = await svc.prepareFiles([path.join(dir, 'Rechnung.pdf')]);
    const events = [];
    svc.on('progress', (p) => events.push(p));
    srv.state.failCreate = { status: 423, code: 'scan_pending', retryAfter: 2, times: 2 };
    const r = await svc.send({ files: prep.files.map((f) => f.id), to: { people: [8] }, job: 'job-s' });
    assert.equal(r.ok, true);
    assert.deepEqual(waits, [2000, 2000]);
    assert.equal(events.filter((e) => e.phase === 'scanning').length, 2);
    assert.equal(events.at(-1).phase, 'done');

    const prep2 = await svc.prepareFiles([path.join(dir, 'Rechnung.pdf')]);
    srv.state.failCreate = { status: 422, code: 'infected', name: 'Rechnung.pdf' };
    const handlers = {};
    registerGateDropHandlers((ch, fn) => { handlers[ch] = fn; }, { gatedrop: svc, getMainWindow: () => null, log });
    events.length = 0;
    const res = await handlers['gatedrop:send'](null, { files: prep2.files.map((f) => f.id), to: { people: [8] }, job: 'job-i' });
    assert.deepEqual([res.ok, res.code, res.status, res.name], [false, 'infected', 422, 'Rechnung.pdf']);
    assert.deepEqual(events.filter((e) => e.phase === 'error').map((e) => [e.code, e.name]), [['infected', 'Rechnung.pdf']]);
  });

  it('receiving: blocked files stay on the server (record.blocked); one being checked is loaded once it is clean', async () => {
    const srv = await gatedropServer();
    cleanup.push(() => srv.close());
    const { svc, downloads } = await setup(srv, { scanRecheckMs: [10, 10] });
    const send = srv.addSend({
      from: { name: 'Anna' },
      items: [
        { name: 'ok.txt', data: Buffer.from('ok') },
        { name: 'virus.exe', data: Buffer.from('MZ'), scan: INFECTED },
        { name: 'gross.zip', data: Buffer.from('zip'), scan: { state: 'pending', blocked: true, finding: null } },
      ],
    });
    const first = await svc.receiveSend({ sendId: send.id, from: { name: 'Anna' } }, { failToast: false });
    assert.equal(first.ok, true);
    assert.deepEqual(first.record.files.map((f) => f.name), ['ok.txt']);
    assert.deepEqual(first.record.blocked.map((b) => [b.name, b.scan.state]), [['virus.exe', 'infected'], ['gross.zip', 'pending']]);
    assert.deepEqual(fs.readdirSync(downloads).sort(), ['ok.txt']);
    // the check of the big file ends: clean
    srv.state.sends.get(send.id).items[2].scan = { state: 'clean', blocked: false, finding: null };
    await waitFor(() => fs.readdirSync(downloads).includes('gross.zip'), 3000, 'the checked file');
    assert.equal(fs.existsSync(path.join(downloads, 'virus.exe')), false);

    // only blocked files: nothing saved, done with it
    const bad = srv.addSend({ from: { name: 'Anna' }, items: [{ name: 'virus2.exe', data: Buffer.from('MZ'), scan: INFECTED }] });
    const r = await svc.receiveSend({ sendId: bad.id }, { failToast: false });
    assert.deepEqual([r.ok, r.skipped, r.blocked.length], [true, 'blocked', 1]);
  });

  it('a check that takes long: the send stays pending (not acknowledged) and its file still comes', async () => {
    const srv = await gatedropServer();
    cleanup.push(() => srv.close());
    const { svc, downloads } = await setup(srv, { scanRecheckMs: [10, 10], scanRecheckLateMs: 20, scanRecheckMax: 6 });
    const send = srv.addSend({
      from: { name: 'Pixel' },
      items: [
        { name: 'IMG_1.jpg', data: Buffer.from('jpg1') },
        { name: 'IMG_2.jpg', data: Buffer.from('jpg2'), scan: { state: 'pending', blocked: true, finding: null } },
      ],
    }, { pending: true });
    const r = await svc.pollPending();
    assert.deepEqual([r.ok, r.failed], [true, 0]);
    assert.deepEqual(fs.readdirSync(downloads), ['IMG_1.jpg']);
    assert.equal(srv.state.opened.includes(send.id), false, 'not acknowledged while a file is still checked');
    // longer than the first steps (10 + 10 ms), then every 20 ms
    await new Promise((res) => setTimeout(res, 80));
    srv.state.sends.get(send.id).items[1].scan = { state: 'clean', blocked: false, finding: null };
    await waitFor(() => fs.readdirSync(downloads).includes('IMG_2.jpg'), 3000, 'the file checked late');
    await waitFor(() => svc._isHandled(send.id), 3000, 'done with the send');
  });

  it('a send whose download failed: the page learns why (receiveError) until it worked', async () => {
    const srv = await gatedropServer();
    cleanup.push(() => srv.close());
    const { svc, downloads } = await setup(srv);
    const send = srv.addSend({ from: { name: 'Pixel' }, items: [{ name: 'IMG_3.jpg', data: Buffer.from('jpg3') }] }, { pending: true });
    const mediaId = srv.state.sends.get(send.id).items[0].mediaId;
    srv.state.mediaFail.add(mediaId);
    await svc.pollPending();
    srv.state.mediaFail.delete(mediaId);
    srv.state.inbox.received = [srv.view(srv.state.sends.get(send.id))];
    let list = await svc.inbox({ kind: 'received', refresh: true });
    const row = list.items.find((x) => x.id === send.id);
    assert.ok(row, 'the send is listed');
    assert.equal(typeof row.receiveError, 'string');
    assert.deepEqual(row.local, []);
    const saved = await svc.saveSend(send.id);
    assert.equal(saved.ok, true);
    assert.deepEqual(fs.readdirSync(downloads), ['IMG_3.jpg']);
    list = await svc.inbox({ kind: 'received', refresh: true });
    assert.equal('receiveError' in list.items.find((x) => x.id === send.id), false);
  });

  it('a download of a file blocked later: the refusal, not "gone"', async () => {
    const srv = await gatedropServer();
    cleanup.push(() => srv.close());
    const apiClient = new ApiClient(srv.url, 'gc_token', log);
    const api = new GateDropApi({ apiClient, log, sleep: async () => {} });
    const send = srv.addSend({ items: [{ name: 'x.bin', data: Buffer.from('x') }] });
    const mediaId = send.items[0].mediaId;
    srv.state.sends.get(send.id).items[0].scan = INFECTED;
    const sink = fs.createWriteStream(path.join(tmpDir('gd-scan-x-'), 'x.bin'));
    const err = await api.download(mediaId, sink).catch((e) => e);
    sink.destroy();
    assert.deepEqual([err.status, err.code], [423, 'quarantined']);
    assert.equal(srv.state.requests.some((r) => r.path.includes('/media/')), false, 'the bytes are not asked for');
    // the media route itself: the JSON refusal of a streamed download, with Retry-After
    srv.state.sends.get(send.id).items[0].scan = { state: 'pending', blocked: true, finding: null };
    const sink2 = fs.createWriteStream(path.join(tmpDir('gd-scan-y-'), 'y.bin'));
    const pending = await api.streamTo(`/api/v1/client/plugins/gatecontrol-gatedrop/media/${mediaId}`, sink2).catch((e) => e);
    sink2.destroy();
    assert.deepEqual([pending.status, pending.code, pending.retryAfter], [423, 'scan_pending', 5]);
    assert.deepEqual(SC.refusalFields(pending), { scan: { state: 'pending', blocked: true, finding: null }, retryAfter: 5 });
  });
});

describe('Mail 1.8 (scan)', () => {
  it('attachments, drafts, filing and the media answer carry scan; removed; warnings name the attachment', () => {
    const m = mail.normalizeMessage({
      id: 5, accountId: 1, folderId: 2, from: { email: 'a@b.de' }, subject: 'x', date: 1,
      attachments: [
        { id: 1, name: 'a.pdf' },
        { id: 2, name: 'b.exe', scan: INFECTED, suggestion: { folderId: 7, where: 'x', name: 'b.exe' } },
        { id: 3, name: 'c.doc', mediaError: 'ERR_MEDIA_INFECTED' },
        { id: 4, name: 'd.doc', removed: true, scan: { state: 'infected', blocked: true, finding: 'GC.Office.Macro' } },
      ],
    });
    const [a, b, c, d] = m.attachments;
    assert.equal('scan' in a, false);
    assert.deepEqual([b.scan, b.suggestion], [INFECTED, null]);
    assert.deepEqual(c.scan, { state: 'infected', finding: null, blocked: true, removed: true });
    assert.deepEqual(d.scan, { state: 'infected', blocked: true, finding: 'GC.Office.Macro', removed: true });
    assert.equal(SC.view(c.scan), 'removed');
    const draft = mail.normalizeDraft({ id: 3, attachments: [{ id: 9, name: 'b.exe', scan: INFECTED }], warnings: [{ kind: 'attachment_blocked', text: 'gesperrt', attachmentId: 9 }, { kind: 'password', attachmentId: 9 }] });
    assert.deepEqual(draft.attachments[0].scan, INFECTED);
    assert.deepEqual(draft.warnings, [{ kind: 'attachment_blocked', text: 'gesperrt', attachmentId: 9 }, { kind: 'password', text: null }]);
    const filing = mail.normalizeFiling({ items: [{ id: 1, messageId: 5, attachmentId: 1, name: 'a.pdf' }, { id: 2, messageId: 5, attachmentId: 2, name: 'b.exe', scan: INFECTED }] });
    assert.deepEqual(filing.items.map((x) => x.id), [1]);
    assert.deepEqual(mail.normalizeMedia({ mediaId: 'abcdef1234567890', name: 'a.pdf', scan: { state: 'infected', blocked: false, finding: 'Eicar' } }).scan, { state: 'infected', blocked: false, finding: 'Eicar' });
    assert.equal('scan' in mail.normalizeMedia({ mediaId: 'abcdef1234567890', name: 'a.pdf' }), false);
    assert.deepEqual(mail.normalizeChanged({ accountId: 1, draftId: 4 }).draftId, 4);
    assert.equal('draftId' in mail.normalizeChanged({ accountId: 1 }), false);
    assert.ok(mail.normalizeMe({ features: ['scan'] }).features.includes('scan'));
  });

  async function setup({ shell = null } = {}) {
    const srv = await mailServer({});
    cleanup.push(() => srv.close());
    const apiClient = new ApiClient(srv.url, 'gc_token', log);
    const temp = tmpDir('mail-scan-');
    const svc = new MailService({ apiClient, log, shell, tempDir: () => temp, getLang: () => 'de', timing: { retryMinMs: 10, retryMaxMs: 20 } });
    svc.start();
    cleanup.push(() => svc.stop());
    await svc.check();
    const handlers = {};
    registerMailHandlers((ch, fn) => { handlers[ch] = fn; }, { mail: svc, getMainWindow: () => null, log });
    return { srv, svc, temp, call: (ch, arg) => handlers[ch]({}, arg) };
  }

  it('an attachment blocked or removed later is not opened again; send refused for a blocked attachment', async () => {
    const opened = [];
    const { srv, temp, call } = await setup({ shell: { openPath: async (p) => { opened.push(p); return ''; } } });
    const ok = await call('mail:attachment:open', { id: 101, attachmentId: 1, name: 'Rechnung_2026_11.pdf', mime: 'application/pdf' });
    assert.equal(ok.ok, true);
    srv.state.fail['GET messages/:id/attachments/:id'] = { status: 423, code: 'quarantined', extra: { scan: INFECTED } };
    const r = await call('mail:attachment:open', { id: 101, attachmentId: 1, name: 'Rechnung_2026_11.pdf', mime: 'application/pdf' });
    assert.deepEqual([r.ok, r.code, r.status, r.finding], [false, 'quarantined', 423, 'Eicar-Test-Signature']);
    assert.deepEqual(r.scan, INFECTED);
    assert.equal(fs.existsSync(path.join(temp, '101-1')), false, 'the copy loaded before is gone');
    assert.equal(opened.length, 1);
    srv.state.fail['GET messages/:id/attachments/:id'] = { status: 410, code: 'attachment_removed' };
    assert.equal((await call('mail:attachment:open', { id: 101, attachmentId: 1, name: 'Rechnung_2026_11.pdf' })).code, 'attachment_removed');

    srv.state.fail['POST drafts/:id/send'] = { status: 409, code: 'attachment_blocked', extra: { attachmentId: 9, name: 'b.exe', scan: INFECTED } };
    const s = await call('mail:send', { id: 3 });
    assert.deepEqual([s.ok, s.code, s.attachmentId, s.name], [false, 'attachment_blocked', 9, 'b.exe']);
    assert.deepEqual(s.scan, INFECTED);
  });
});

describe('Messenger 1.11 (scan)', () => {
  it('the feature scan is known (no update hint)', () => {
    assert.deepEqual(msgr.unknownFeatures({ scan: true, files: true }), []);
  });

  it('a file the host refuses: the message is not sent again, with its finding', async () => {
    const srv = await messengerServer();
    cleanup.push(() => srv.close());
    const api = new MessengerApi({ apiClient: new ApiClient(srv.url, 'gc_token', log), log });
    const box = new MessengerOutbox({ api, store: createMemoryStore(), dataDir: null, log, backoffMs: [20, 40] });
    cleanup.push(() => box.stop());
    const conv = srv.addConv();
    srv.fail(`POST ${MSG_API}conversations/${conv}/messages`, 422, 'infected', null, { finding: 'Eicar-Test-Signature' });
    const failed = [];
    box.on('failed', (e) => failed.push(e));
    box.start();
    const e = await box.add({ conversationId: conv, body: { kind: 'text', text: 'mit Datei' } });
    await waitFor(() => failed.length === 1);
    assert.deepEqual([failed[0].error, box.get(e.clientId).state, box.get(e.clientId).finding], ['infected', 'failed', 'Eicar-Test-Signature']);
    srv.heal();
    srv.fail(`POST ${MSG_API}conversations/${conv}/messages`, 423, 'scan_blocked');
    assert.equal(box.retry(e.clientId), true);
    await waitFor(() => failed.length === 2);
    assert.deepEqual([failed[1].error, box.get(e.clientId).finding], ['scan_blocked', undefined]);
  });

  it('message.update with scan: loaded from editedAt − 1 s, the file\'s bytes loaded before are dropped', async () => {
    const srv = await messengerServer();
    cleanup.push(() => srv.close());
    const store = createMemoryStore();
    const apiClient = new ApiClient(srv.url, 'gc_token', log);
    const pushClient = new PushClient({ apiClient, store, log, allowHttp: true, timing: { initialDelayMs: 20, maxDelayMs: 100, ackDelayMs: 5, networkDebounceMs: 5, connectTimeoutMs: 1000 } });
    cleanup.push(() => pushClient.stop());
    const m = new MessengerService({
      apiClient, pushClient, store, log, isWindowVisible: () => true,
      timing: { recheckMs: 60000, errorRetryMs: [30, 60], pollOpenMs: 80, pollIdleMs: 80, activeEveryMs: 40, convDebounceMs: 5, persistDelayMs: 5, typingEveryMs: 3000, typingValidMs: 6000 },
    });
    cleanup.push(() => m.stop());
    const id = srv.addConv();
    const up = await new MessengerApi({ apiClient, log }).upload({ data: Buffer.from('%PDF-scan'), mime: 'application/pdf' });
    const msg = srv.addMsg(id, { kind: 'file', text: null, mediaId: up.mediaId });
    pushClient.start();
    m.start();
    await waitFor(() => m.listConversations().length === 1 && pushClient.status().state === 'connected');
    await m.getMessages(id);
    await m.media(up.mediaId);
    const gets = () => srv.state.requests.filter((r) => r.method === 'GET' && r.path.endsWith(`/media/${up.mediaId}`)).length;
    assert.equal(gets(), 1);
    await m.media(up.mediaId);
    assert.equal(gets(), 1, 'cached');

    // the nightly check: blocked; the plugin's change time is half a second before the event's editedAt
    const at = Date.now();
    const stored = srv.state.msgs.get(id).find((x) => x.id === msg.id);
    stored.scan = INFECTED;
    stored.changedAt = at - 500;
    srv.event('message.update', { conversationId: id, messageId: msg.id, editedAt: new Date(at).toISOString(), scan: INFECTED });
    await waitFor(() => {
      const x = m.messagesView(id).messages.find((y) => y.id === msg.id);
      return x && x.media && x.media.scan && x.media.scan.blocked;
    }, 3000, 'the blocked state');
    const q = srv.state.requests.filter((r) => r.query && r.query.changedSince).at(-1).query.changedSince;
    assert.equal(Date.parse(q), at - 1000);
    const view = m.messagesView(id).messages.find((y) => y.id === msg.id);
    assert.equal(view.editedAt, null, 'not shown as edited');
    await m.media(up.mediaId);
    assert.equal(gets(), 2, 'the bytes loaded before are gone');
  });
});

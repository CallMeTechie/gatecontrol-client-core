'use strict';

// Window guard: which navigations / window.open() calls a page may make
// (navigationDecision, pure) and the Electron wiring (guardWebContents,
// installWindowGuard) against a webContents double.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const { EventEmitter } = require('node:events');

const {
  ALLOW, EXTERNAL, DENY, isAppUrl, navigationDecision, describeUrl, guardWebContents, installWindowGuard,
} = require('../src/utils/window-guard');

const ROOT = path.resolve('/opt/GateControl Pro Client/resources/app.asar/src/renderer');
const ROOTS = [ROOT];
const page = (rel) => pathToFileURL(path.join(ROOT, rel)).href;

describe('isAppUrl', () => {
  it('accepts the app pages (also with query / hash, other case)', () => {
    assert.equal(isAppUrl(page('index.html'), ROOTS), true);
    assert.equal(isAppUrl(page('vault-quick.html'), ROOTS), true);
    assert.equal(isAppUrl(`${page('index.html')}?x=1#settings`, ROOTS), true);
    assert.equal(isAppUrl(page('index.html').toUpperCase().replace('FILE:', 'file:'), ROOTS), true);
    assert.equal(isAppUrl(page('styles/app.css'), ROOTS), true);
    // root given as file URL
    assert.equal(isAppUrl(page('index.html'), [pathToFileURL(ROOT).href]), true);
    assert.equal(isAppUrl(page('index.html'), ROOT), true);
  });

  it('rejects files outside the app directory', () => {
    assert.equal(isAppUrl(pathToFileURL('/etc/passwd').href, ROOTS), false);
    assert.equal(isAppUrl(pathToFileURL(path.join(ROOT, '..', 'main', 'main.js')).href, ROOTS), false);
    assert.equal(isAppUrl(`${pathToFileURL(ROOT).href}/../main/main.js`, ROOTS), false);
    assert.equal(isAppUrl(`${pathToFileURL(ROOT).href}/%2e%2e/main/main.js`, ROOTS), false);
    assert.equal(isAppUrl(`${pathToFileURL(ROOT).href}/..%2fmain/main.js`, ROOTS), false);
    assert.equal(isAppUrl(`${pathToFileURL(ROOT).href}/..%5cmain/main.js`, ROOTS), false);
    // sibling directory with the same prefix
    assert.equal(isAppUrl(`${pathToFileURL(ROOT).href}-evil/index.html`, ROOTS), false);
    // the directory itself
    assert.equal(isAppUrl(pathToFileURL(ROOT).href, ROOTS), false);
    assert.equal(isAppUrl(`${pathToFileURL(ROOT).href}/`, ROOTS), false);
  });

  it('rejects other hosts and schemes', () => {
    assert.equal(isAppUrl(`file://evil-server${pathToFileURL(path.join(ROOT, 'index.html')).pathname}`, ROOTS), false);
    assert.equal(isAppUrl('https://example.com/index.html', ROOTS), false);
    assert.equal(isAppUrl('data:text/html,<p>x</p>', ROOTS), false);
    assert.equal(isAppUrl('', ROOTS), false);
    assert.equal(isAppUrl(null, ROOTS), false);
    assert.equal(isAppUrl(page('index.html'), []), false);
    assert.equal(isAppUrl(page('index.html'), [null, 42]), false);
  });
});

describe('navigationDecision', () => {
  const nav = (url, kind) => navigationDecision(url, { appRoots: ROOTS, kind });

  it('navigate: own pages stay, http(s) goes to the browser, everything else is blocked', () => {
    assert.equal(nav(page('index.html')), ALLOW);
    assert.equal(nav('https://portal.example.com/login?ticket=abc'), EXTERNAL);
    assert.equal(nav('http://example.com/'), EXTERNAL);
    for (const url of [
      'javascript:alert(1)',
      'data:text/html,<script>1</script>',
      'blob:file:///0b6c3f1e',
      pathToFileURL('/etc/passwd').href,
      'file://server/share/x.exe',
      'ms-settings:privacy-location',
      'smb://server/share',
      'gatecontrol-pro://notify/x',
      'https://',
      'about:blank',
      'not a url',
      '',
      undefined,
    ]) {
      assert.equal(nav(url), DENY, String(url));
    }
  });

  it('redirect: only own pages, nothing is opened', () => {
    assert.equal(nav(page('index.html'), 'redirect'), ALLOW);
    assert.equal(nav('https://example.com/', 'redirect'), DENY);
    assert.equal(nav('javascript:1', 'redirect'), DENY);
  });

  it('open (window.open / target=_blank): never a new window; http(s) to the browser', () => {
    assert.equal(nav(page('index.html'), 'open'), DENY);
    assert.equal(nav('https://example.com/release-notes', 'open'), EXTERNAL);
    assert.equal(nav('file:///C:/Windows/System32/calc.exe', 'open'), DENY);
    assert.equal(nav('ms-settings:signinoptions', 'open'), DENY);
  });
});

describe('describeUrl', () => {
  it('logs scheme and host only (no path, query or ticket)', () => {
    assert.equal(describeUrl('https://portal.example.com/x?ticket=SECRET'), 'https://portal.example.com');
    assert.equal(describeUrl('file:///C:/Users/me/secret.txt'), 'file:');
    assert.equal(describeUrl('javascript:alert(document.cookie)'), 'javascript:');
    assert.equal(describeUrl('nope'), '(invalid URL)');
  });
});

function fakeContents() {
  const wc = new EventEmitter();
  wc.openHandler = null;
  wc.setWindowOpenHandler = (fn) => { wc.openHandler = fn; };
  return wc;
}
function fakeEvent(extra = {}) {
  return { defaultPrevented: false, preventDefault() { this.defaultPrevented = true; }, ...extra };
}
function recordingLog() {
  const lines = [];
  const rec = (level) => (msg) => lines.push(`${level} ${msg}`);
  return { lines, info: rec('info'), warn: rec('warn'), error: rec('error'), debug: rec('debug') };
}
const tick = () => new Promise((r) => setImmediate(r));

describe('guardWebContents', () => {
  function setup() {
    const opened = [];
    const log = recordingLog();
    const shell = { openExternal: async (url) => { opened.push(url); } };
    const wc = fakeContents();
    guardWebContents(wc, { appRoots: ROOTS, getShell: () => shell, log });
    return { wc, opened, log, shell };
  }

  it('will-navigate: own page passes, http(s) opens in the browser, the rest is blocked', async () => {
    const { wc, opened, log } = setup();

    const own = fakeEvent();
    wc.emit('will-navigate', own, page('index.html'));
    assert.equal(own.defaultPrevented, false);

    const ext = fakeEvent();
    wc.emit('will-navigate', ext, 'https://portal.example.com/?ticket=SECRET');
    assert.equal(ext.defaultPrevented, true);

    const bad = fakeEvent();
    wc.emit('will-navigate', bad, 'file:///C:/Windows/win.ini');
    assert.equal(bad.defaultPrevented, true);

    await tick();
    assert.deepEqual(opened, ['https://portal.example.com/?ticket=SECRET']);
    assert.ok(log.lines.some((l) => /^warn .*navigate to file: blocked/.test(l)), log.lines.join('\n'));
    assert.ok(!log.lines.some((l) => l.includes('SECRET')), 'ticket must not reach the log');
  });

  it('will-navigate with the Electron ≥ 25 details event (url on the event)', async () => {
    const { wc, opened } = setup();
    const e = fakeEvent({ url: 'https://example.com/a' });
    wc.emit('will-navigate', e);
    assert.equal(e.defaultPrevented, true);
    await tick();
    assert.deepEqual(opened, ['https://example.com/a']);
  });

  it('will-redirect: away from the app is blocked and not opened', async () => {
    const { wc, opened } = setup();
    const e = fakeEvent();
    wc.emit('will-redirect', e, 'https://example.com/');
    assert.equal(e.defaultPrevented, true);
    const own = fakeEvent();
    wc.emit('will-redirect', own, page('index.html'));
    assert.equal(own.defaultPrevented, false);
    await tick();
    assert.deepEqual(opened, []);
  });

  it('setWindowOpenHandler: always deny, http(s) to the browser', async () => {
    const { wc, opened } = setup();
    assert.deepEqual(wc.openHandler({ url: 'https://example.com/help' }), { action: 'deny' });
    assert.deepEqual(wc.openHandler({ url: 'javascript:alert(1)' }), { action: 'deny' });
    assert.deepEqual(wc.openHandler({ url: page('index.html') }), { action: 'deny' });
    assert.deepEqual(wc.openHandler({}), { action: 'deny' });
    await tick();
    assert.deepEqual(opened, ['https://example.com/help']);
  });

  it('will-attach-webview is blocked', () => {
    const { wc, log } = setup();
    const e = fakeEvent();
    wc.emit('will-attach-webview', e, {}, { src: 'https://example.com/x?token=1' });
    assert.equal(e.defaultPrevented, true);
    assert.ok(log.lines.some((l) => l.includes('<webview> blocked (https://example.com)')));
  });

  it('a failing openExternal only logs', async () => {
    const log = recordingLog();
    const wc = fakeContents();
    guardWebContents(wc, { appRoots: ROOTS, getShell: () => ({ openExternal: async () => { throw new Error('no browser'); } }), log });
    const e = fakeEvent();
    wc.emit('will-navigate', e, 'https://example.com/');
    await tick();
    assert.equal(e.defaultPrevented, true);
    assert.ok(log.lines.some((l) => l.includes('no browser')));
  });

  it('uses the shell of the moment (e2e hooks replace shell.openExternal)', async () => {
    const opened = [];
    const shell = { openExternal: async () => { throw new Error('real browser'); } };
    const wc = fakeContents();
    guardWebContents(wc, { appRoots: ROOTS, getShell: () => shell });
    shell.openExternal = async (url) => { opened.push(url); };
    wc.openHandler({ url: 'https://example.com/' });
    await tick();
    assert.deepEqual(opened, ['https://example.com/']);
  });

  it('guards a webContents only once', () => {
    const wc = fakeContents();
    const opts = { appRoots: ROOTS, getShell: () => ({ openExternal: async () => {} }) };
    guardWebContents(wc, opts);
    guardWebContents(wc, opts);
    assert.equal(wc.listenerCount('will-navigate'), 1);
    assert.equal(wc.listenerCount('will-attach-webview'), 1);
  });
});

describe('installWindowGuard', () => {
  it('guards every webContents the app creates', () => {
    const app = new EventEmitter();
    installWindowGuard(app, { appRoots: ROOTS, getShell: () => ({ openExternal: async () => {} }) });
    const a = fakeContents();
    const b = fakeContents();
    app.emit('web-contents-created', {}, a);
    app.emit('web-contents-created', {}, b);
    for (const wc of [a, b]) {
      assert.equal(wc.listenerCount('will-navigate'), 1);
      assert.equal(wc.listenerCount('will-redirect'), 1);
      assert.equal(typeof wc.openHandler, 'function');
    }
  });

  it('needs appRoots and getShell', () => {
    assert.throws(() => installWindowGuard(new EventEmitter(), {}), /appRoots and getShell/);
    assert.throws(() => installWindowGuard(new EventEmitter(), { appRoots: ROOTS }), /appRoots and getShell/);
  });
});

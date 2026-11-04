'use strict';

// "Im Ordner anzeigen" (utils/reveal.js): on Windows explorer.exe /select,<file> — the elevated app's
// shell.showItemInFolder() can do nothing —, showItemInFolder only as the fallback; runAs (utils/session-user.js):
// does the app run as another Windows user than the one signed in?

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const EventEmitter = require('node:events');
const { revealItem, explorerShell } = require('../src/utils/reveal');
const { runAs } = require('../src/utils/session-user');

function fakeSpawn({ fail = false } = {}) {
  const calls = [];
  const spawn = (cmd, args, opts) => {
    const child = new EventEmitter();
    child.unref = () => { child.unrefed = true; };
    calls.push({ cmd, args, opts, child });
    if (fail) setImmediate(() => child.emit('error', Object.assign(new Error('nope'), { code: 'ENOENT' })));
    return child;
  };
  spawn.calls = calls;
  return spawn;
}

describe('revealItem / explorerShell', () => {
  it('Windows: explorer.exe /select, with the path (spaces kept for Node to quote), detached', () => {
    const shown = [];
    const spawn = fakeSpawn();
    const ok = revealItem({ showItemInFolder: (p) => shown.push(p) }, 'C:\\Users\\Max Muster\\Downloads\\GateControl\\IMG 1.jpg', { platform: 'win32', spawn });
    assert.equal(ok, true);
    assert.equal(spawn.calls.length, 1);
    assert.equal(spawn.calls[0].cmd, 'explorer.exe');
    assert.deepEqual(spawn.calls[0].args, ['/select,', 'C:\\Users\\Max Muster\\Downloads\\GateControl\\IMG 1.jpg']);
    assert.equal(spawn.calls[0].opts.detached, true);
    assert.equal(spawn.calls[0].child.unrefed, true);
    assert.deepEqual(shown, []);
  });

  it('explorer.exe cannot be started: showItemInFolder; other systems and relative paths: showItemInFolder', async () => {
    const shown = [];
    const shell = { showItemInFolder: (p) => shown.push(p) };
    const spawn = fakeSpawn({ fail: true });
    revealItem(shell, 'C:\\logs\\main.log', { platform: 'win32', spawn, log: { warn() {} } });
    await new Promise((r) => setImmediate(r));
    assert.deepEqual(shown, ['C:\\logs\\main.log']);
    const spawn2 = fakeSpawn();
    revealItem(shell, '/home/x/main.log', { platform: 'linux', spawn: spawn2 });
    revealItem(shell, 'main.log', { platform: 'win32', spawn: spawn2 });
    assert.equal(spawn2.calls.length, 0);
    assert.deepEqual(shown.slice(1), ['/home/x/main.log', 'main.log']);
    assert.equal(revealItem(shell, '', { platform: 'win32', spawn: spawn2 }), false);
  });

  it('explorerShell: showItemInFolder goes through revealItem, the rest is Electron\'s own', async () => {
    const shown = [];
    const opened = [];
    const electronShell = { showItemInFolder: (p) => shown.push(p), openPath: async function (p) { opened.push([this === electronShell, p]); return ''; }, beepCount: 3 };
    const spawn = fakeSpawn();
    const s = explorerShell(electronShell, { platform: 'win32', spawn });
    s.showItemInFolder('C:\\a\\b.txt');
    assert.deepEqual(spawn.calls[0].args, ['/select,', 'C:\\a\\b.txt']);
    assert.deepEqual(shown, []);
    assert.equal(await s.openPath('C:\\a'), '');
    assert.deepEqual(opened, [[true, 'C:\\a']]);
    assert.equal(s.beepCount, 3);
    assert.equal(explorerShell(null), null);
  });
});

describe('runAs', () => {
  it('another Windows user than the one signed in (case does not matter); unknown session user → no claim', () => {
    const info = () => ({ username: 'Admin', homedir: 'C:\\Users\\Admin' });
    assert.deepEqual(runAs({ platform: 'win32', userInfo: info, getSessionUser: () => 'max' }), { processUser: 'Admin', sessionUser: 'max', differs: true, profile: 'C:\\Users\\Admin' });
    assert.equal(runAs({ platform: 'win32', userInfo: info, getSessionUser: () => 'admin' }).differs, false);
    assert.deepEqual(runAs({ platform: 'win32', userInfo: info, getSessionUser: () => null }), { processUser: 'Admin', sessionUser: null, differs: false, profile: 'C:\\Users\\Admin' });
    assert.equal(runAs({ platform: 'linux', userInfo: info }).sessionUser, null);
    assert.equal(runAs({ platform: 'win32', userInfo: info, getSessionUser: () => { throw new Error('x'); } }).differs, false);
  });
});

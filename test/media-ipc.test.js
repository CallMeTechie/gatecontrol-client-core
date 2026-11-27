'use strict';

// Medien (Stufe 4e): the media:* channels — arguments checked before the service sees them, every handler resolves,
// events reach the main window; the Pro preload's createMediaBridge invokes
// only channels the core serves. Medien-Plugin (W1): the sources come from the server — no channel sets one up.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');
const EventEmitter = require('node:events');

const realResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === '@callmetechie/gatecontrol-config-hash') return require.resolve('./fixtures/config-hash-stub');
  return realResolve.call(this, request, ...rest);
};

const { registerMediaHandlers, MEDIA_EVENTS } = require('../src/ipc/media-handlers');
const { registerBaseHandlers } = require('../src/ipc/base-handlers');
const { createMediaBridge } = require('../src/preload/bridge');

function fakeMedia() {
  const m = new EventEmitter();
  m.calls = [];
  const rec = (name) => (...args) => { m.calls.push([name, ...args]); return { ok: true, name }; };
  for (const n of ['status', 'setCaps', 'setQuality', 'check', 'networkChanged', 'discover', 'server', 'trust', 'quickConnectStart', 'quickConnectPoll',
    'quickConnectCancel', 'signIn', 'authorizeDevice', 'addShare', 'removeSource', 'setAlwaysOriginal', 'resume', 'latest', 'movies', 'series', 'seasons',
    'episodes', 'search', 'detail', 'play', 'report', 'setPlayed', 'shareList', 'shareOpen', 'trackChoice', 'setTrackChoice', 'forgetAll',
    'serverStatus', 'serverRefresh', 'convertHint', 'convertPrefetch', 'convertRequest']) m[n] = rec(n);
  m.stream = { revoke: rec('revoke') };
  m.boom = () => { throw Object.assign(new Error('bad'), { code: 'offline' }); };
  return m;
}

function fakeCast() {
  const c = new EventEmitter();
  c.calls = [];
  const rec = (name) => (...args) => { c.calls.push([name, ...args]); return { ok: true, name }; };
  for (const n of ['status', 'opened', 'state', 'closed']) c[n] = rec(n);
  return c;
}

function register(media, cast = fakeCast()) {
  const handlers = {};
  const sent = [];
  registerMediaHandlers((c, fn) => { handlers[c] = fn; }, {
    media,
    cast,
    getMainWindow: () => ({ isDestroyed: () => false, webContents: { send: (ch, p) => sent.push([ch, p]) } }),
    log: { debug() {} },
  });
  return { handlers, sent };
}

describe('media-handlers', () => {
  it('arguments are checked before the service sees them', async () => {
    const m = fakeMedia();
    const { handlers: h } = register(m);
    const call = (ch, arg) => h[ch]({}, arg);
    assert.equal((await call('media:check', { id: '../x' })).code, 'invalid');
    assert.equal((await call('media:detail', { id: 's1', itemId: 'Items/../Users' })).code, 'invalid');
    assert.equal((await call('media:play', { id: 's1', itemId: 'm1', versionId: 'a b' })).code, 'invalid');
    assert.equal((await call('media:report', { playId: 'p', event: 'pause' })).code, 'invalid');
    assert.equal((await call('media:source:original', { id: 's1', on: 'yes' })).code, 'invalid');
    assert.equal((await call('media:share:open', { id: 's1', path: '' })).code, 'invalid');
    assert.equal((await call('media:stream:end', {})).code, 'invalid');
    assert.equal((await call('media:convert:hint', { id: 's1', itemId: '../Users' })).code, 'invalid');
    assert.equal((await call('media:convert:prefetch', { id: 's1', itemIds: 'x' })).code, 'invalid');
    assert.equal((await call('media:convert:prefetch', { id: 's1', itemIds: Array(101).fill('m1') })).code, 'invalid');
    assert.equal((await call('media:convert:request', { id: '../x', itemId: 'm1' })).code, 'invalid');
    assert.equal(m.calls.length, 0);
    assert.equal((await call('media:convert:hint', { id: 's1', itemId: 'm1' })).name, 'convertHint');
    assert.deepEqual(m.calls[0].slice(1), ['s1', 'm1', null]);
    assert.equal((await call('media:convert:prefetch', { id: 's1', itemIds: ['m1', 'm2'] })).name, 'convertPrefetch');
    assert.equal((await call('media:convert:request', { id: 's1', itemId: 'm1' })).name, 'convertRequest');
    m.calls.length = 0;
    assert.equal((await call('media:play', { id: 's1', itemId: 'm1', audioIndex: 2, subtitleIndex: -1, quality: '8', seriesId: 's9' })).name, 'play');
    assert.deepEqual(m.calls[0][1], { sourceId: 's1', itemId: 'm1', versionId: null, startMs: undefined, audioIndex: 2, subtitleIndex: -1, quality: '8', originalBps: undefined, seriesId: 's9' });
    assert.equal((await call('media:sources:refresh')).name, 'serverRefresh');
    assert.equal((await call('media:sources:status')).name, 'serverStatus');
  });

  it('read only: no channel sets a source up, signs in, removes one or confirms a code', () => {
    const { handlers: h } = register(fakeMedia());
    for (const ch of ['media:discover', 'media:server', 'media:trust', 'media:qc:start', 'media:qc:poll', 'media:qc:cancel', 'media:signin',
      'media:authorize', 'media:share:add', 'media:source:remove']) assert.equal(h[ch], undefined, ch);
    assert.ok(h['media:source:original'], '"Immer Original" stays a setting of this PC');
  });

  it('every handler resolves; events go to the main window', async () => {
    const m = fakeMedia();
    m.status = () => { throw Object.assign(new Error('x'), { code: 'offline' }); };
    const { handlers: h, sent } = register(m);
    assert.deepEqual(await h['media:status']({}, null), { ok: false, code: 'offline', error: 'x' });
    m.emit('state', { ok: true });
    m.emit('link', { sourceId: 's1', link: { atHome: true } });
    m.emit('vpn', { state: 'connecting' });
    m.emit('server', { visible: true });
    assert.deepEqual(sent, [[MEDIA_EVENTS.state, { ok: true }], [MEDIA_EVENTS.link, { sourceId: 's1', link: { atHome: true } }],
      ['media:vpn', { state: 'connecting' }], ['media:sources:state', { visible: true }]]);
  });

  it('the bridge of the Pro preload invokes only channels the core serves', () => {
    const invoked = [];
    const ipc = { invoke: (ch, ...a) => { invoked.push([ch, ...a]); return Promise.resolve(); }, on() {}, removeListener() {} };
    const bridge = createMediaBridge(ipc);
    const walk = (o) => { for (const v of Object.values(o)) { if (typeof v === 'function') { const r = v(() => {}); if (typeof r === 'function') r(); } else if (v && typeof v === 'object') walk(v); } };
    walk(bridge);
    const { handlers } = register(fakeMedia());
    for (const [ch] of invoked) assert.ok(handlers[ch], `no core handler for ${ch}`);
    assert.equal(new Set(invoked.map((c) => c[0])).size, Object.keys(handlers).length, 'and every channel has a bridge function');
    bridge.endStream('gcmedia://media/x/y');
    assert.deepEqual(invoked[invoked.length - 1], ['media:stream:end', { url: 'gcmedia://media/x/y' }]);
  });

  it('cast (this PC as the receiver): arguments checked, events to the main window, none without a receiver', async () => {
    const c = fakeCast();
    const { handlers: h, sent } = register(fakeMedia(), c);
    const call = (ch, arg) => h[ch]({}, arg);
    assert.equal((await call('media:cast:opened', { session: 'x' })).code, 'invalid');
    assert.equal((await call('media:cast:state', { session: 'abcdefgh12', phase: 7 })).code, 'invalid');
    assert.equal((await call('media:cast:closed', {})).code, 'invalid');
    assert.equal(c.calls.length, 0);
    await call('media:cast:state', { session: 'abcdefgh12', phase: 'playing', positionMs: 5000, durationMs: 'x', title: 'Kobaltnacht',
      audio: [{ id: 'a1', label: 'Deutsch', selected: true }, { id: 2, label: 'kaputt' }], volume: 40, force: true });
    assert.deepEqual(c.calls[0], ['state', 'abcdefgh12', { phase: 'playing', positionMs: 5000, durationMs: 0, title: 'Kobaltnacht',
      audio: [{ id: 'a1', label: 'Deutsch', selected: true }], subtitles: [], volume: 40, muted: null }, { force: true }]);
    await call('media:cast:closed', { session: 'abcdefgh12', positionMs: 9000, byRemote: true });
    assert.deepEqual(c.calls[1], ['closed', 'abcdefgh12', { positionMs: 9000, durationMs: 0, byRemote: true, ended: false, failed: false }]);
    c.emit('play', { session: 'abcdefgh12' });
    c.emit('command', { session: 'abcdefgh12', cmd: 'pause' });
    c.emit('session', { ok: true, session: null });
    assert.deepEqual(sent, [['media:cast:play', { session: 'abcdefgh12' }], ['media:cast:command', { session: 'abcdefgh12', cmd: 'pause' }],
      ['media:cast:session', { ok: true, session: null }]]);
    const { handlers: none } = register(fakeMedia(), null);
    assert.equal(none['media:cast:status'], undefined);
  });

  it('registerBaseHandlers: Medien only when the app passes a MediaService', async () => {
    const m = fakeMedia();
    const handlers = {};
    registerBaseHandlers({ handle: (c, fn) => { handlers[c] = fn; }, on() {} }, {
      app: { getVersion: () => '1.0.0', setLoginItemSettings() {} },
      dialog: {}, getMainWindow: () => null, store: { get() {}, set() {}, store: {} },
      wgService: {}, apiClient: {}, log: { info() {}, warn() {}, error() {}, debug() {} },
      connectTunnel() {}, disconnectTunnel() {}, toggleKillSwitch() {}, installUpdate() {}, getTunnelState: () => ({}),
      wgConfigFile: 'wg.conf', media: m,
    });
    assert.ok(handlers['media:status']);
    const without = {};
    registerBaseHandlers({ handle: (c, fn) => { without[c] = fn; }, on() {} }, {
      app: { getVersion: () => '1.0.0', setLoginItemSettings() {} }, dialog: {}, getMainWindow: () => null,
      store: { get() {}, set() {}, store: {} }, wgService: {}, apiClient: {}, log: { info() {}, warn() {}, error() {}, debug() {} },
      connectTunnel() {}, disconnectTunnel() {}, toggleKillSwitch() {}, installUpdate() {}, getTunnelState: () => ({}), wgConfigFile: 'wg.conf',
    });
    assert.equal(without['media:status'], undefined, 'the Community client has no Medien (decision 26 a)');
  });
});

'use strict';

// The renderer bridge shared by the Pro and Community preloads: channel names
// must stay exactly as before, and every invoked channel must be served by
// the core IPC handlers (locale:* is registered by the apps themselves).

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');

const realResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === '@callmetechie/gatecontrol-config-hash') return require.resolve('./fixtures/config-hash-stub');
  return realResolve.call(this, request, ...rest);
};

const { createBridgeApi, createSubscriber } = require('../src/preload/bridge');
const { registerBaseHandlers } = require('../src/ipc/base-handlers');
const i18n = require('../src/i18n');

function fakeIpcRenderer() {
  const calls = { invoke: [], send: [], on: [], off: [] };
  return {
    calls,
    invoke: (ch, ...args) => { calls.invoke.push([ch, ...args]); return Promise.resolve(); },
    send: (ch, ...args) => { calls.send.push([ch, ...args]); },
    on: (ch, fn) => { calls.on.push([ch, fn]); },
    removeListener: (ch, fn) => { calls.off.push([ch, fn]); },
  };
}

// Call every function of the bridge once (callbacks get a no-op).
function exercise(api) {
  const walk = (obj) => {
    for (const v of Object.values(obj)) {
      if (typeof v === 'function') {
        const r = v(() => {});
        if (typeof r === 'function') r();
      } else if (v && typeof v === 'object') walk(v);
    }
  };
  walk(api);
}

describe('createBridgeApi', () => {
  it('uses the same channels as the former app preloads', () => {
    const ipc = fakeIpcRenderer();
    exercise(createBridgeApi(ipc, i18n));
    const invoked = [...new Set(ipc.calls.invoke.map((c) => c[0]))].sort();
    assert.deepEqual(invoked, [
      'app:version', 'autostart:set',
      'cameras:check', 'cameras:clips', 'cameras:list', 'cameras:live', 'cameras:push:set', 'cameras:status', 'cameras:still:save',
      'chat:action', 'chat:actions', 'chat:archive', 'chat:arrival:stop', 'chat:avatar', 'chat:block', 'chat:blocks',
      'chat:cache:clear', 'chat:card:image', 'chat:check', 'chat:conversation', 'chat:conversations', 'chat:create',
      'chat:delete', 'chat:edit', 'chat:event', 'chat:export', 'chat:lists', 'chat:lists:save',
      'chat:map:reverse', 'chat:map:search', 'chat:map:tile',
      'chat:media', 'chat:media:list', 'chat:media:open', 'chat:media:save', 'chat:messages', 'chat:notice:image', 'chat:open',
      'chat:outbox:discard', 'chat:outbox:retry', 'chat:people', 'chat:pin', 'chat:places', 'chat:poll', 'chat:prefs',
      'chat:react', 'chat:read', 'chat:remind', 'chat:reminder:delete', 'chat:reminders', 'chat:search',
      'chat:send', 'chat:status', 'chat:status:clear', 'chat:status:feed', 'chat:status:set', 'chat:storage',
      'chat:story:create', 'chat:story:delete', 'chat:story:react', 'chat:story:seen', 'chat:story:viewers',
      'chat:suggest', 'chat:to-calendar', 'chat:to-drive', 'chat:to-list', 'chat:typing', 'chat:update', 'chat:update-hint:dismiss', 'chat:view',
      'config:get', 'config:getAll', 'config:import-file',
      'config:import-qr', 'config:set', 'dns:leak-test',
      'drive:album', 'drive:album:create', 'drive:album:delete', 'drive:album:items', 'drive:album:update', 'drive:albums',
      'drive:area:calendar', 'drive:area:docai', 'drive:areas', 'drive:ask', 'drive:cache', 'drive:cache:clear', 'drive:check', 'drive:deadline:calendar', 'drive:deadline:calendars', 'drive:deadline:remind', 'drive:deadline:target', 'drive:deadline:targets', 'drive:deadlines', 'drive:doc-view', 'drive:face:move', 'drive:folder', 'drive:guard', 'drive:guard:decide', 'drive:hello-settings', 'drive:import', 'drive:insight', 'drive:insight:apply', 'drive:insight:run', 'drive:last-folder', 'drive:last-folder:set', 'drive:link:create', 'drive:link:end',
      'drive:links', 'drive:map:tile', 'drive:me', 'drive:memories', 'drive:memories:photos', 'drive:mkdir', 'drive:move', 'drive:office', 'drive:offline', 'drive:offline:set', 'drive:open', 'drive:ops:cancel', 'drive:ops:check', 'drive:ops:start', 'drive:ops:undo', 'drive:overview',
      'drive:people', 'drive:person', 'drive:person:confirm', 'drive:person:merge', 'drive:person:similar', 'drive:person:uncertain', 'drive:person:update',
      'drive:photos', 'drive:photos:geo:delete', 'drive:photos:map', 'drive:photos:memories', 'drive:photos:months', 'drive:photos:places', 'drive:photos:settings', 'drive:photos:settings:set', 'drive:photos:suggest',
      'drive:pick', 'drive:pick-folders', 'drive:portal', 'drive:preview', 'drive:preview:node', 'drive:purge',
      'drive:remove', 'drive:rename', 'drive:restore', 'drive:save-as', 'drive:scan:discard', 'drive:scan:prepare', 'drive:scan:save', 'drive:scan:status', 'drive:search', 'drive:show', 'drive:status', 'drive:storage', 'drive:storage:prune', 'drive:stream', 'drive:stream:end',
      'drive:sync:add', 'drive:sync:deletes', 'drive:sync:home', 'drive:sync:open', 'drive:sync:pause', 'drive:sync:pick',
      'drive:sync:remove', 'drive:sync:run', 'drive:sync:settings', 'drive:sync:status', 'drive:sync:suspect',
      'drive:timetravel', 'drive:timetravel:preview',
      'drive:transfers', 'drive:transfers:clear', 'drive:trash', 'drive:tree', 'drive:upload', 'drive:upload:resolve',
      'drive:vault:approve', 'drive:vault:create', 'drive:vault:decline', 'drive:vault:devices', 'drive:vault:lock', 'drive:vault:lock-settings',
      'drive:vault:lock-status', 'drive:vault:open', 'drive:vault:protect', 'drive:vault:recover',
      'drive:vault:request', 'drive:vault:rotate', 'drive:vault:status', 'drive:vault:touch', 'drive:vault:unlock', 'drive:vault:view', 'drive:vault:view:close', 'drive:vaults', 'drive:version:restore',
      'drive:versions', 'drive:zip',
      'familie:avatar', 'familie:check', 'familie:internet', 'familie:internet:extend', 'familie:internet:pause', 'familie:internet:resume',
      'familie:presence', 'familie:presence:share', 'familie:rules', 'familie:rules:actions', 'familie:rules:active', 'familie:rules:options',
      'familie:status', 'familie:wifi', 'familie:wifi:device', 'familie:wifi:set',
      'gatedrop:access', 'gatedrop:access:set', 'gatedrop:check', 'gatedrop:compose:take', 'gatedrop:copy', 'gatedrop:explorer', 'gatedrop:folder', 'gatedrop:folder:pick', 'gatedrop:folder:reset', 'gatedrop:inbox',
      'gatedrop:link:end', 'gatedrop:open', 'gatedrop:open-link', 'gatedrop:pick', 'gatedrop:prepare', 'gatedrop:send',
      'gatedrop:send:get', 'gatedrop:send:save', 'gatedrop:show', 'gatedrop:status', 'gatedrop:targets',
      'killswitch:toggle', 'locale:get',
      'locale:set', 'logs:export', 'logs:get', 'logs:save', 'logs:show',
      'mail:account:add', 'mail:account:delete', 'mail:account:microsoft', 'mail:account:update', 'mail:act', 'mail:ai', 'mail:ai:run',
      'mail:ai:todo', 'mail:attachment:open', 'mail:attachment:save', 'mail:avatar', 'mail:book:update', 'mail:booking:cancel', 'mail:booking:decide',
      'mail:booking:get', 'mail:bookings', 'mail:books', 'mail:cal:create',
      'mail:cal:delete', 'mail:cal:list', 'mail:cal:settings', 'mail:cal:subscribe', 'mail:cal:update', 'mail:call', 'mail:card:activity',
      'mail:card:conflict:accept', 'mail:card:conflict:dismiss', 'mail:card:conflicts',
      'mail:card:create', 'mail:card:delete', 'mail:card:draft', 'mail:card:duplicates', 'mail:card:export', 'mail:card:favorite', 'mail:card:get',
      'mail:card:ignore', 'mail:card:import', 'mail:card:lookup', 'mail:card:main-phone', 'mail:card:merge', 'mail:card:merge:auto', 'mail:card:merge:undo',
      'mail:card:merges', 'mail:card:photo', 'mail:card:photo:delete',
      'mail:card:photo:set', 'mail:card:preview', 'mail:card:settings', 'mail:card:unmerge', 'mail:card:update', 'mail:cards', 'mail:check', 'mail:contacts', 'mail:discover',
      'mail:draft:create', 'mail:draft:delete', 'mail:draft:get', 'mail:draft:update', 'mail:drive:save', 'mail:drive:save-all',
      'mail:drive:suggest', 'mail:editor', 'mail:event:create', 'mail:event:delete', 'mail:event:get', 'mail:event:respond',
      'mail:event:update', 'mail:events', 'mail:favorites', 'mail:favorites:set', 'mail:filing', 'mail:filing:confirm', 'mail:filing:dismiss', 'mail:flags', 'mail:folders',
      'mail:freebusy', 'mail:freebusy:suggest',
      'mail:group:create', 'mail:group:delete', 'mail:group:get', 'mail:group:members', 'mail:group:update', 'mail:ids', 'mail:images',
      'mail:invitation:apply', 'mail:invitation:dismiss', 'mail:invitation:get', 'mail:invitation:respond', 'mail:invitations', 'mail:list',
      'mail:me', 'mail:message', 'mail:outbox', 'mail:overlay:update', 'mail:pick', 'mail:principals', 'mail:providers', 'mail:resource:book', 'mail:resources', 'mail:search', 'mail:send',
      'mail:send:cancel', 'mail:settings', 'mail:share:add', 'mail:share:delete', 'mail:share:update', 'mail:shared', 'mail:shared:update', 'mail:shares',
      'mail:signin:cancel', 'mail:status', 'mail:thread', 'mail:undo', 'mail:upcoming', 'mail:upload',
      'notes:attach', 'notes:attachment:delete', 'notes:attachment:image', 'notes:attachment:open', 'notes:attachment:save', 'notes:check', 'notes:dsnote:cancel', 'notes:dsnote:import', 'notes:dsnote:pick', 'notes:group:create', 'notes:group:delete', 'notes:group:update', 'notes:item', 'notes:item:carry', 'notes:item:complete', 'notes:job', 'notes:list:create', 'notes:list:delete', 'notes:list:members', 'notes:list:update', 'notes:lists', 'notes:me', 'notes:mstodo:accounts', 'notes:mstodo:consent', 'notes:mstodo:links', 'notes:mstodo:open', 'notes:mstodo:poll', 'notes:mstodo:preview', 'notes:mstodo:start', 'notes:mstodo:unlink', 'notes:nav', 'notes:note', 'notes:note:check', 'notes:note:create', 'notes:note:delete', 'notes:note:task', 'notes:note:update', 'notes:notebook:create', 'notes:notebook:delete', 'notes:notebook:members', 'notes:notebook:update', 'notes:notebooks', 'notes:notes', 'notes:parse', 'notes:people', 'notes:prefs', 'notes:prefs:set', 'notes:search', 'notes:sources', 'notes:sources:sync', 'notes:status', 'notes:task', 'notes:task:complete', 'notes:task:create', 'notes:task:delete', 'notes:task:update', 'notes:vault:approve', 'notes:vault:decline', 'notes:vault:devices', 'notes:vault:info', 'notes:vault:lock', 'notes:vault:open', 'notes:vault:recover', 'notes:vault:request', 'notes:vault:rotate', 'notes:vault:settings', 'notes:vault:status', 'notes:vault:unlock', 'notes:view',
      'notify:action', 'notify:dnd', 'notify:email', 'notify:email:set', 'notify:list', 'notify:open', 'notify:prefs:get', 'notify:prefs:set', 'notify:quiet', 'notify:quiet:open',
      'notify:read', 'notify:routes', 'notify:routes:set', 'notify:status', 'notify:test',
      'permissions:get', 'policy:get', 'policy:refresh', 'portal:open',
      'print:again', 'print:cancel', 'print:check', 'print:drive', 'print:dropped', 'print:forget', 'print:job', 'print:overview', 'print:pick', 'print:sources',
      'print:status', 'print:submit', 'print:transfer:cancel', 'print:transfers',
      'rdp-allow:toggle',
      'school:absences', 'school:attachment:drive', 'school:avatar', 'school:changes', 'school:check', 'school:messages', 'school:status', 'school:timetable',
      'server:setup', 'server:test', 'services:list', 'shell:open-external',
      'signin:cancel', 'signin:methods', 'signin:microsoft', 'signin:password', 'support:send', 'system:run-as', 'traffic:stats',
      'tunnel:connect', 'tunnel:disconnect', 'tunnel:reconnect', 'tunnel:status', 'update:check', 'update:install',
      'update:policy',
      'vault:addMember', 'vault:changePassword', 'vault:check', 'vault:completeRecovery', 'vault:copy', 'vault:createVault',
      'vault:deleteAccount', 'vault:deleteVault', 'vault:emergency', 'vault:emergencyAdd', 'vault:emergencyOpen',
      'vault:emergencyRemove', 'vault:emergencyStep', 'vault:entries', 'vault:entry', 'vault:generate', 'vault:hello:check',
      'vault:hello:set', 'vault:history', 'vault:import:parse', 'vault:import:save', 'vault:lock', 'vault:match', 'vault:notices:clear', 'vault:people', 'vault:purge',
      'vault:recover', 'vault:removeMember', 'vault:renameVault', 'vault:restore', 'vault:save', 'vault:setRole',
      'vault:settings:get', 'vault:settings:set', 'vault:setup', 'vault:setup:cancel', 'vault:setup:confirm', 'vault:status',
      'vault:strength', 'vault:sync', 'vault:totp', 'vault:totp-qr', 'vault:touch', 'vault:trash', 'vault:unlock', 'vault:unlockHello',
      'vault:unlockRemembered', 'vault:vaults', 'vault:wifi-qr', 'vault:wifi-scan', 'vault:wifi-share', 'vault:wifi-share-end', 'vault:wifi-shares',
      'wireguard:check',
    ]);
    assert.deepEqual(ipc.calls.send.map((c) => c[0]).sort(), ['window:close', 'window:minimize']);
    const events = [...new Set(ipc.calls.on.map((c) => c[0]))].sort();
    assert.deepEqual(events, [
      'cameras:push', 'cameras:state',
      'chat:conversations', 'chat:feed', 'chat:lists', 'chat:messages', 'chat:navigate', 'chat:outbox', 'chat:reminders',
      'chat:state', 'chat:typing', 'chat:unread',
      'drive:changed', 'drive:guard', 'drive:op', 'drive:remote', 'drive:state', 'drive:sync', 'drive:transfers', 'drive:vault', 'drive:vault-lock', 'drive:vault-move',
      'familie:push', 'familie:state',
      'gatedrop:changed', 'gatedrop:compose', 'gatedrop:navigate', 'gatedrop:progress', 'gatedrop:received', 'gatedrop:state',
      'locale:changed', 'mail:calendar', 'mail:changed', 'mail:contacts', 'mail:loading', 'mail:outbox', 'mail:resources', 'mail:state', 'navigate', 'notes:changed', 'notes:import', 'notes:state', 'notes:vault', 'notes:vault-lock', 'notify:fallback', 'notify:navigate', 'notify:new', 'notify:status', 'notify:update',
      'peer-expiry', 'policy:changed', 'portal-url', 'print:job', 'print:push', 'print:state', 'print:transfers', 'school:push', 'school:state', 'tunnel-state', 'update-ready', 'update:policy',
      'vault:push', 'vault:state',
    ]);
  });

  it('print.addDropped: the path of a dropped file comes from webUtils only, never from the object', async () => {
    const ipc = fakeIpcRenderer();
    const real = { name: 'Brief.pdf' };
    const webUtils = { getPathForFile: (f) => { if (f !== real) throw new TypeError('not a File'); return 'C:\\Users\\anna\\Brief.pdf'; } };
    createBridgeApi(ipc, i18n, { webUtils }).print.addDropped([real, { name: 'x', path: 'C:\\Windows\\win.ini' }, null]);
    assert.deepEqual(ipc.calls.invoke.at(-1), ['print:dropped', { paths: ['C:\\Users\\anna\\Brief.pdf'] }]);
    // without webUtils nothing is read from the objects
    createBridgeApi(ipc, i18n).print.addDropped([{ name: 'x', path: 'C:\\Windows\\win.ini' }]);
    assert.deepEqual(ipc.calls.invoke.at(-1), ['print:dropped', { paths: [] }]);
  });

  it('subscriptions pass the payload and unsubscribe the same handler', () => {
    const ipc = fakeIpcRenderer();
    const api = createBridgeApi(ipc, i18n);
    let got;
    const off = api.tunnel.onState((s) => { got = s; });
    const [ch, handler] = ipc.calls.on[0];
    assert.equal(ch, 'tunnel-state');
    handler({}, { connected: true });
    assert.deepEqual(got, { connected: true });
    off();
    assert.deepEqual(ipc.calls.off[0], ['tunnel-state', handler]);
  });

  it('notify.read sends ids or all', () => {
    const ipc = fakeIpcRenderer();
    const api = createBridgeApi(ipc, i18n);
    api.notify.read([4, 5]);
    api.notify.read('all');
    api.notify.read(7);
    api.notify.action(4, 'details');
    api.notify.dnd();
    api.notify.dnd(null);
    assert.deepEqual(ipc.calls.invoke, [
      ['notify:read', { ids: [4, 5] }], ['notify:read', { all: true }], ['notify:read', { ids: [7] }],
      ['notify:action', { id: 4, action: 'details' }], ['notify:dnd'], ['notify:dnd', null],
    ]);
  });

  it('signin passes only its known fields', () => {
    const ipc = fakeIpcRenderer();
    const api = createBridgeApi(ipc, i18n);
    api.signin.methods('https://gate.example.com');
    api.signin.password({ url: 'u', username: 'a', password: 'p', totp: '123456', extra: 'x' });
    api.signin.microsoft({ url: 'u', id: 3, extra: 'x' });
    api.signin.cancel();
    assert.deepEqual(ipc.calls.invoke, [
      ['signin:methods', { url: 'https://gate.example.com' }],
      ['signin:password', { url: 'u', username: 'a', password: 'p', totp: '123456' }],
      ['signin:microsoft', { url: 'u', id: 3 }],
      ['signin:cancel'],
    ]);
  });

  it('announces updates on the edition-specific channel', () => {
    const ipc = fakeIpcRenderer();
    createBridgeApi(ipc, i18n, { updateReadyChannel: 'update:ready' }).update.onReady(() => {});
    assert.equal(ipc.calls.on[0][0], 'update:ready');
  });

  it('createSubscriber returns an unsubscribe for edition-specific events', () => {
    const ipc = fakeIpcRenderer();
    const seen = [];
    const off = createSubscriber(ipc)('rdp:progress', (d) => seen.push(d));
    ipc.calls.on[0][1]({}, 42);
    off();
    assert.deepEqual(seen, [42]);
    assert.equal(ipc.calls.off[0][0], 'rdp:progress');
  });

  it('every invoked channel is served by the core handlers (locale:* by the apps)', () => {
    const ipc = fakeIpcRenderer();
    exercise(createBridgeApi(ipc, i18n));
    const handlers = {};
    registerBaseHandlers({ handle: (c, fn) => { handlers[c] = fn; }, on() {} }, {
      app: { getVersion: () => '1.0.0', setLoginItemSettings() {} },
      dialog: {},
      getMainWindow: () => null,
      store: { get() {}, set() {}, store: {} },
      wgService: {}, apiClient: {}, killSwitch: {},
      log: { info() {}, warn() {}, error() {}, debug() {} },
      connectTunnel() {}, disconnectTunnel() {}, toggleKillSwitch() {}, toggleRdpAllow() {},
      openPortal() {},
      notificationCenter: { on() {} },
      messenger: { on() {} },
      school: { on() {} },
      familie: { on() {} },
      print: { on() {} },
      cameras: { on() {} },
      gatedrop: { on() {} },
      vault: { on() {} },
      drive: { on() {} },
      driveSync: { on() {} },
      mail: { on() {} },
      notes: { on() {} },
      installUpdate() {}, getTunnelState: () => ({}),
      wgConfigFile: 'wg.conf',
    });
    for (const [ch] of ipc.calls.invoke) {
      if (ch.startsWith('locale:')) continue;
      assert.ok(handlers[ch], `no core handler for ${ch}`);
    }
  });
});

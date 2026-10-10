'use strict';

// Store schema fragment `notifications{}` (utils/notify-schema.js), checked
// with conf — the engine under electron-store — so defaults and validation
// are exactly what both apps get after merging the fragment.

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Conf = require('conf');
const {
  notificationsSchema, NOTIFICATION_DEFAULTS, NOTIFICATION_WRITABLE_KEYS, readNotificationSettings,
} = require('../src/utils/notify-schema');

const dirs = [];
after(() => { for (const d of dirs) fs.rmSync(d, { recursive: true, force: true }); });

function conf(schema) {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'gc-notify-schema-'));
  dirs.push(cwd);
  return new Conf({ cwd, projectName: 'gc-test', schema });
}

describe('notifications schema fragment', () => {
  it('fills the defaults of the contract', () => {
    const c = conf(notificationsSchema);
    assert.deepEqual(c.get('notifications'), {
      enabled: true, direct: true, toasts: true, criticalBypass: true,
      mutedTopics: [], dndUntil: null, muteUntil: {}, lastSeq: 0, seqScope: '',
    });
    assert.deepEqual(readNotificationSettings(c), { ...NOTIFICATION_DEFAULTS, mutedTopics: [], muteUntil: {} });
  });

  it('merges with another app schema (Pro has its own)', () => {
    const c = conf({ app: { type: 'object', properties: { theme: { type: 'string', default: 'dark' } }, default: {} }, ...notificationsSchema });
    assert.equal(c.get('app.theme'), 'dark');
    assert.equal(c.get('notifications.toasts'), true);
  });

  it('validates the writable keys', () => {
    const c = conf(notificationsSchema);
    c.set('notifications.dndUntil', Date.parse('2026-10-10T23:00:00Z'));
    c.set('notifications.dndUntil', null);
    c.set('notifications.mutedTopics', ['plugin:skoda:charging']);
    assert.throws(() => c.set('notifications.toasts', 'yes'), /schema violation/);
    assert.throws(() => c.set('notifications.mutedTopics', 'devices'), /schema violation/);
    assert.throws(() => c.set('notifications.dndUntil', 'tomorrow'), /schema violation/);
    assert.throws(() => c.set('notifications.lastSeq', -1), /schema violation/);
    assert.deepEqual([...NOTIFICATION_WRITABLE_KEYS].every((k) => k.startsWith('notifications.')), true);
    assert.ok(!NOTIFICATION_WRITABLE_KEYS.includes('notifications.lastSeq'));
  });

  it('readNotificationSettings tolerates a store without the schema', () => {
    const s = readNotificationSettings({ get: () => ({ enabled: 'no', mutedTopics: ['devices', 3], dndUntil: 'x', lastSeq: 4.5 }) });
    assert.deepEqual([s.enabled, s.mutedTopics, s.dndUntil, s.lastSeq], [true, ['devices'], null, 0]);
    assert.equal(readNotificationSettings({ get: () => { throw new Error('locked'); } }).enabled, true);
    assert.equal(readNotificationSettings(null).toasts, true);
  });

  it('createStores merges the fragment (source check, electron-store needs Electron)', () => {
    const src = fs.readFileSync(path.join(__dirname, '../src/utils/store.js'), 'utf8');
    assert.match(src, /\.\.\.notificationsSchema/);
  });
});

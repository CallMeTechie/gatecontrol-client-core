'use strict';

// utils/user-folders.js: the folders of the person signed in when the app runs as another Windows user
// (UAC prompt answered with a local admin account). Registry and SID through a fake API — no Windows needed.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  createUserFolders, resolveFolders, expandVars, sidToString, FOLDERS, HKEY_LOCAL_MACHINE, HKEY_USERS,
} = require('../src/utils/user-folders');

const SID = 'S-1-5-21-111-222-333-1001';
const ADMIN_SID = 'S-1-5-21-111-222-333-1002';
const USF = 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders';
const SF = 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders';
const PROFILES = 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList';

/** A registry: { 'HKLM\\…': { value: data } } (names without case like Windows). */
function fakeApi({ reg = {}, sids = {}, loaded = [] } = {}) {
  const calls = { regGet: 0, lookupSid: 0 };
  const hive = (h) => (h === HKEY_LOCAL_MACHINE ? 'HKLM' : h === HKEY_USERS ? 'HKU' : '?');
  const find = (obj, name) => {
    if (!obj) return null;
    const k = Object.keys(obj).find((x) => x.toLowerCase() === String(name).toLowerCase());
    return k === undefined ? null : obj[k];
  };
  return {
    calls,
    lookupSid(domain, user) { calls.lookupSid++; return sids[`${domain}\\${user}`] || null; },
    regGet(h, key, name) { calls.regGet++; return find(find(reg, `${hive(h)}\\${key}`), name); },
    subKeys(h) { return h === HKEY_USERS ? loaded : []; },
  };
}

/** The usual PC: max signed in (profile with an umlaut-free and a redirected folder), the admin runs the app. */
function maxRegistry(extra = {}) {
  return {
    [`HKLM\\${PROFILES}\\${SID}`]: { ProfileImagePath: '%SystemDrive%\\Users\\Jürgen' },
    [`HKU\\${SID}\\${USF}`]: {
      '{374DE290-123F-4565-9164-39C4925E467B}': '%USERPROFILE%\\Downloads',
      Personal: '%OneDrive%\\Dokumente',
      'My Pictures': '%USERPROFILE%\\Pictures',
      Desktop: '%USERPROFILE%\\Desktop',
      AppData: '%USERPROFILE%\\AppData\\Roaming',
    },
    [`HKU\\${SID}\\Environment`]: { OneDrive: '%USERPROFILE%\\OneDrive - Firma' },
    [`HKU\\${SID}\\Volatile Environment`]: { USERNAME: 'Jürgen', USERDOMAIN: 'FIRMA' },
    ...extra,
  };
}

const ENV = { SystemDrive: 'C:', USERPROFILE: 'C:\\Users\\Admin', OneDrive: 'C:\\Users\\Admin\\OneDrive', APPDATA: 'C:\\Users\\Admin\\AppData\\Roaming' };
const ACCOUNT = { user: 'Jürgen', domain: 'FIRMA' };

function quietLog() {
  const lines = { info: [], warn: [] };
  return { lines, info: (m) => lines.info.push(m), warn: (m) => lines.warn.push(m), debug() {}, error() {} };
}

describe('user-folders: helpers', () => {
  it('sidToString reads a binary SID', () => {
    const b = Buffer.from([1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 111, 0, 0, 0, 222, 0, 0, 0, 77, 1, 0, 0, 0xe9, 3, 0, 0]);
    assert.equal(sidToString(b), 'S-1-5-21-111-222-333-1001');
    assert.equal(sidToString(Buffer.from([2, 0, 0, 0, 0, 0, 0, 5])), null);
    assert.equal(sidToString(Buffer.from([1, 3, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0])), null); // cut off
    assert.equal(sidToString(null), null);
  });

  it('expandVars fills in the given variables only (no case, nested, unknown → null)', () => {
    const vars = { USERPROFILE: 'C:\\Users\\max', ONEDRIVE: '%USERPROFILE%\\OneDrive' };
    const lookup = (n) => vars[n] || null;
    assert.equal(expandVars('%userprofile%\\Downloads', lookup), 'C:\\Users\\max\\Downloads');
    assert.equal(expandVars('%OneDrive%\\Dokumente', lookup), 'C:\\Users\\max\\OneDrive\\Dokumente');
    assert.equal(expandVars('%NOPE%\\Downloads', lookup), null);
    assert.equal(expandVars('D:\\Daten', lookup), 'D:\\Daten');
    assert.equal(expandVars('%A%', (n) => (n === 'A' ? '%A%' : null)), null); // endless: refused
    assert.equal(expandVars(null, lookup), null);
  });
});

describe('user-folders: resolveFolders (registry)', () => {
  it('profile from ProfileList, folders from User Shell Folders with the person’s variables, not the admin’s', () => {
    const api = fakeApi({ reg: maxRegistry(), sids: { 'FIRMA\\Jürgen': SID } });
    const r = resolveFolders({ account: ACCOUNT, api, env: ENV });
    assert.equal(r.sid, SID);
    assert.equal(r.profile, 'C:\\Users\\Jürgen');
    assert.deepEqual(r.folders.downloads, { path: 'C:\\Users\\Jürgen\\Downloads', source: 'registry' });
    // OneDrive of HKU\<SID>\Environment, never the admin's %OneDrive%
    assert.deepEqual(r.folders.documents, { path: 'C:\\Users\\Jürgen\\OneDrive - Firma\\Dokumente', source: 'registry' });
    assert.equal(r.folders.appData.path, 'C:\\Users\\Jürgen\\AppData\\Roaming');
    // no value: <profile>\<folder>
    assert.deepEqual(r.folders.videos, { path: 'C:\\Users\\Jürgen\\Videos', source: 'profile' });
    assert.deepEqual(Object.keys(r.folders).sort(), Object.keys(FOLDERS).sort());
  });

  it('Downloads on a network share or another drive stays as it is (checked later)', () => {
    const reg = maxRegistry();
    reg[`HKU\\${SID}\\${USF}`]['{374DE290-123F-4565-9164-39C4925E467B}'] = '\\\\fs01\\home$\\%USERNAME%\\Downloads';
    reg[`HKU\\${SID}\\${USF}`].Desktop = 'H:\\Desktop';
    const r = resolveFolders({ account: ACCOUNT, api: fakeApi({ reg, sids: { 'FIRMA\\Jürgen': SID } }), env: ENV });
    assert.deepEqual(r.folders.downloads, { path: '\\\\fs01\\home$\\Jürgen\\Downloads', source: 'registry' });
    assert.equal(r.folders.desktop.path, 'H:\\Desktop');
  });

  it('a variable that cannot be filled in: Explorer’s copy (Shell Folders), else the profile', () => {
    const reg = maxRegistry({ [`HKU\\${SID}\\${SF}`]: { '{374DE290-123F-4565-9164-39C4925E467B}': 'E:\\Ablage\\Downloads' } });
    reg[`HKU\\${SID}\\${USF}`]['{374DE290-123F-4565-9164-39C4925E467B}'] = '%GC_UNKNOWN%\\Downloads';
    reg[`HKU\\${SID}\\${USF}`].Personal = '%GC_UNKNOWN%\\Dokumente';
    const log = quietLog();
    const r = resolveFolders({ account: ACCOUNT, api: fakeApi({ reg, sids: { 'FIRMA\\Jürgen': SID } }), env: ENV, log });
    assert.deepEqual(r.folders.downloads, { path: 'E:\\Ablage\\Downloads', source: 'shell-folders' });
    assert.deepEqual(r.folders.documents, { path: 'C:\\Users\\Jürgen\\Documents', source: 'profile' });
    assert.equal(log.lines.warn.length, 2);
  });

  it('no SID from LookupAccountName: the loaded hive whose Volatile Environment names the account', () => {
    const reg = maxRegistry({ [`HKU\\${ADMIN_SID}\\Volatile Environment`]: { USERNAME: 'Admin', USERDOMAIN: 'PC01' } });
    const api = fakeApi({ reg, loaded: ['.DEFAULT', 'S-1-5-18', ADMIN_SID, SID, `${SID}_Classes`] });
    const r = resolveFolders({ account: { user: 'jürgen', domain: 'firma' }, api, env: ENV });
    assert.equal(r.sid, SID);
    assert.equal(r.folders.downloads.path, 'C:\\Users\\Jürgen\\Downloads');
  });

  it('profile: Volatile Environment when ProfileList has none; nothing at all → null', () => {
    const reg = maxRegistry();
    delete reg[`HKLM\\${PROFILES}\\${SID}`];
    reg[`HKU\\${SID}\\Volatile Environment`].USERPROFILE = 'C:\\Users\\Jürgen';
    const r = resolveFolders({ account: ACCOUNT, api: fakeApi({ reg, sids: { 'FIRMA\\Jürgen': SID } }), env: ENV });
    assert.equal(r.profile, 'C:\\Users\\Jürgen');
    const log = quietLog();
    assert.equal(resolveFolders({ account: ACCOUNT, api: fakeApi({ sids: { 'FIRMA\\Jürgen': SID } }), env: ENV, log }), null);
    assert.equal(resolveFolders({ account: ACCOUNT, api: fakeApi(), env: ENV, log }), null);
    assert.equal(resolveFolders({ account: null, api: fakeApi(), env: ENV }), null);
    assert.equal(resolveFolders({ account: ACCOUNT, api: null, env: ENV }), null);
    assert.equal(log.lines.warn.length, 2);
  });

  it('a throwing API is no crash', () => {
    const api = { lookupSid() { throw new Error('x'); }, regGet() { throw new Error('y'); }, subKeys() { throw new Error('z'); } };
    assert.equal(resolveFolders({ account: ACCOUNT, api, env: ENV }), null);
  });
});

describe('user-folders: createUserFolders', () => {
  const differs = () => ({ processUser: 'Admin', sessionUser: 'Jürgen', differs: true, profile: 'C:\\Users\\Admin' });
  const same = () => ({ processUser: 'max', sessionUser: 'max', differs: false, profile: 'C:\\Users\\max' });
  const getPath = (k) => `C:\\Users\\Admin\\${k}`;
  const isDir = async () => ({ isDirectory: () => true });

  it('the app runs as the person signed in: app.getPath, dialogs as before', () => {
    const api = fakeApi({ reg: maxRegistry(), sids: { 'FIRMA\\Jürgen': SID } });
    const f = createUserFolders({ getPath: (k) => `C:\\Users\\max\\${k}`, runAs: same, account: () => ACCOUNT, api, env: ENV, log: quietLog() });
    assert.equal(f.userPath('downloads'), 'C:\\Users\\max\\downloads');
    assert.equal(f.dialogPath('downloads', 'Liste.zip'), 'Liste.zip');
    assert.equal(f.dialogPath('documents'), undefined);
    assert.equal(api.calls.regGet, 0);
    assert.equal(f.info().downloadsSource, 'app');
  });

  it('another user: the folders of the person signed in, resolved once', async () => {
    const api = fakeApi({ reg: maxRegistry(), sids: { 'FIRMA\\Jürgen': SID } });
    const log = quietLog();
    const f = createUserFolders({ getPath, runAs: differs, account: () => ACCOUNT, api, env: ENV, log, stat: isDir });
    assert.equal(f.userPath('downloads'), 'C:\\Users\\Jürgen\\Downloads');
    assert.equal(f.userPath('home'), 'C:\\Users\\Jürgen');
    assert.equal(f.userPath('documents'), 'C:\\Users\\Jürgen\\OneDrive - Firma\\Dokumente');
    assert.equal(f.userPath('temp'), 'C:\\Users\\Admin\\temp'); // not a folder of the person: as before
    assert.equal(f.dialogPath('downloads', 'Liste.zip'), 'C:\\Users\\Jürgen\\Downloads\\Liste.zip');
    assert.equal(f.dialogPath('pictures'), 'C:\\Users\\Jürgen\\Pictures');
    const n = api.calls.regGet;
    f.userPath('downloads');
    f.userPath('desktop');
    assert.equal(api.calls.regGet, n, 'cached');
    await f.checked();
    assert.deepEqual(f.info(), {
      processUser: 'Admin', sessionUser: 'Jürgen', differs: true, profile: 'C:\\Users\\Admin',
      sessionProfile: 'C:\\Users\\Jürgen', downloads: 'C:\\Users\\Jürgen\\Downloads', downloadsSource: 'registry', unreachable: null,
    });
    assert.equal(log.lines.info.length, 1);
  });

  it('a redirected folder this process cannot reach: <profile>\\Downloads, said in the log', async () => {
    const reg = maxRegistry();
    reg[`HKU\\${SID}\\${USF}`]['{374DE290-123F-4565-9164-39C4925E467B}'] = '\\\\fs01\\home$\\Jürgen\\Downloads';
    const log = quietLog();
    const stat = async (p) => { if (p.startsWith('\\\\fs01')) throw Object.assign(new Error('denied'), { code: 'EPERM' }); return { isDirectory: () => true }; };
    const f = createUserFolders({ getPath, runAs: differs, account: () => ACCOUNT, api: fakeApi({ reg, sids: { 'FIRMA\\Jürgen': SID } }), env: ENV, log, stat });
    assert.equal(f.userPath('downloads'), '\\\\fs01\\home$\\Jürgen\\Downloads'); // until the check is done
    await f.checked();
    assert.equal(f.userPath('downloads'), 'C:\\Users\\Jürgen\\Downloads');
    assert.equal(f.info().unreachable, '\\\\fs01\\home$\\Jürgen\\Downloads');
    assert.equal(f.info().downloadsSource, 'profile');
    assert.ok(log.lines.warn.some((l) => l.includes('not reachable')));
  });

  it('a share that does not answer counts as unreachable after the timeout', async () => {
    const reg = maxRegistry();
    reg[`HKU\\${SID}\\${USF}`]['{374DE290-123F-4565-9164-39C4925E467B}'] = '\\\\slow\\share\\Downloads';
    const stat = (p) => (p.startsWith('\\\\slow') ? new Promise(() => {}) : Promise.resolve({ isDirectory: () => true }));
    const f = createUserFolders({ getPath, runAs: differs, account: () => ACCOUNT, api: fakeApi({ reg, sids: { 'FIRMA\\Jürgen': SID } }), env: ENV, log: quietLog(), stat, checkTimeoutMs: 20 });
    const keep = setTimeout(() => {}, 1000); // the check's own timer does not hold the process
    await f.checked();
    clearTimeout(keep);
    assert.equal(f.userPath('downloads'), 'C:\\Users\\Jürgen\\Downloads');
  });

  it('another user whose folders are unknown: as before (app.getPath) plus one log line', () => {
    const log = quietLog();
    const f = createUserFolders({ getPath, runAs: differs, account: () => null, api: fakeApi(), env: ENV, log });
    assert.equal(f.userPath('downloads'), 'C:\\Users\\Admin\\downloads');
    assert.equal(f.userPath('downloads'), 'C:\\Users\\Admin\\downloads');
    assert.equal(f.dialogPath('downloads', 'a.log'), 'a.log');
    assert.equal(f.info().sessionProfile, null);
    assert.equal(log.lines.warn.filter((l) => l.includes('unknown')).length, 1);
  });

  it('no Windows API (other platforms): as before', () => {
    const f = createUserFolders({ getPath, runAs: differs, account: () => ACCOUNT, api: null, env: ENV, log: quietLog() });
    assert.equal(f.userPath('pictures'), 'C:\\Users\\Admin\\pictures');
  });

  it('getPath failing: the folder below this process’s home', () => {
    const f = createUserFolders({ getPath: () => { throw new Error('no app'); }, runAs: same, api: null, log: quietLog() });
    assert.match(f.userPath('downloads'), /Downloads$/);
  });
});

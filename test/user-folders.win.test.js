'use strict';

// utils/user-folders.js against the real Windows API (Windows only; skipped elsewhere): the koffi layout of
// LookupAccountNameW / RegGetValueW / RegEnumKeyExW, checked with the runner's own account — its SID, its
// profile in ProfileList, its loaded hive and its User Shell Folders give the folders this process has itself.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const os = require('node:os');

const { loadWinApi, resolveFolders, HKEY_LOCAL_MACHINE, HKEY_USERS } = require('../src/utils/user-folders');
const { sessionAccount } = require('../src/utils/session-user');

const win = process.platform === 'win32';
const same = (a, b) => String(a).toLowerCase() === String(b).toLowerCase();

describe('user-folders on Windows (own account)', { skip: win ? false : 'Windows only' }, () => {
  const user = os.userInfo().username;
  const domain = process.env.USERDOMAIN || os.hostname();

  it('LookupAccountNameW, ProfileList and the loaded hive agree with this process', () => {
    const api = loadWinApi();
    assert.ok(api, 'advapi32 through koffi');
    const sid = api.lookupSid(domain, user);
    assert.match(sid || '', /^S-1-5-21(-\d+)+$/, `SID of ${domain}\\${user}`);
    const profile = api.regGet(HKEY_LOCAL_MACHINE, `SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\${sid}`, 'ProfileImagePath');
    assert.ok(profile, 'ProfileImagePath');
    assert.equal(api.regGet(HKEY_LOCAL_MACHINE, 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion', 'GC_DOES_NOT_EXIST'), null);
    assert.ok(api.subKeys(HKEY_USERS).includes(sid), 'own hive loaded');
    console.log(`own SID ${sid}, profile ${profile}, session ${JSON.stringify(sessionAccount())}`);
  });

  it('resolveFolders gives this process its own profile and folders', () => {
    const r = resolveFolders({ account: { user, domain }, api: loadWinApi() });
    assert.ok(r, 'resolved');
    assert.ok(same(r.profile, os.homedir()), `${r.profile} = ${os.homedir()}`);
    assert.ok(same(r.folders.appData.path, process.env.APPDATA), `${r.folders.appData.path} = ${process.env.APPDATA}`);
    assert.match(r.folders.downloads.path, /^(?:[A-Za-z]:\\|\\\\)/);
    console.log(`own folders: ${JSON.stringify(r.folders)}`);
  });
});

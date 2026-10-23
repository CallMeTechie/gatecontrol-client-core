'use strict';

// Vault's pure parts (utils/vault.js): the entry JSON, 2FA codes (RFC 6238 vectors), the generator, matching by
// web address, import of other password managers' exports, the server's JSON, the device's copy (merge, outbox,
// JSON) and the push context. The same cases as the Android app's VaultLogicTest.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const v = require('../src/utils/vault');

const VID = 'Vt9bJm0n2QwErTyUiOpAsD';
const A = 'Aa1111111111111111111a';
const B = 'Bb2222222222222222222b';

// base32 of ASCII text (RFC 4648, no padding)
function b32(ascii) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const bits = [...Buffer.from(ascii)].map((x) => x.toString(2).padStart(8, '0')).join('');
  return bits.match(/.{1,5}/g).map((g) => alphabet[parseInt(g.padEnd(5, '0'), 2)]).join('');
}

describe('utils/vault: entry JSON v1', () => {
  it('round trip keeps unknown keys, rejects other versions and types', () => {
    const json = { v: 1, type: 'login', title: 'X', fields: { username: 'u', future: 'f', empty: '', n: 5 }, urls: ['a.de', ' ', 3], later: { x: 1 } };
    const e = v.normalizeEntry(json);
    assert.equal(v.entryUsername(e), 'u');
    assert.deepEqual(e.fields, { future: 'f', username: 'u' });
    assert.deepEqual(e.urls, ['a.de']);
    assert.deepEqual(e.apps, []);
    assert.deepEqual(e.custom, []);
    assert.equal(e.fav, undefined);
    const again = v.normalizeEntry(JSON.parse(JSON.stringify(v.normalizeEntry(e))));
    assert.deepEqual(again.later, { x: 1 });
    assert.equal(again.fields.future, 'f');
    assert.equal(v.normalizeEntry({ v: 2, type: 'login' }), null);
    assert.equal(v.normalizeEntry({ v: 1, type: 'spaceship' }), null);
    assert.equal(v.normalizeEntry({ type: 'note', title: 'neu' }).v, 1, 'a new entry from the page may leave v out');
    const c = v.normalizeEntry({ type: 'login', title: 'C', fav: true, notes: 'n', custom: [{ name: 'PIN', value: '1', secret: true }, { name: ' ', value: '' }, 'x'] });
    assert.deepEqual(c.custom, [{ name: 'PIN', value: '1', secret: true }]);
    assert.equal(c.fav, true);
  });

  it('list rows carry no secrets; values for the clipboard', () => {
    const d = v.normalizeEntry({ type: 'login', title: 'Bank', urls: ['https://www.bank.de/login'], fields: { username: 'anna', password: 'geheim', totp: b32('12345678901234567890') }, custom: [{ name: 'PIN', value: '1234', secret: true }] });
    const row = v.entrySummary({ id: A, vaultId: VID, rev: 2, trashed: false, data: d });
    assert.equal(row.username, 'anna');
    assert.equal(row.host, 'bank.de');
    assert.equal(row.hasPassword, true);
    assert.equal(row.hasTotp, true);
    assert.ok(!JSON.stringify(row).includes('geheim'));
    assert.ok(!JSON.stringify(row).includes('1234'));
    assert.equal(v.entryValue(d, 'password'), 'geheim');
    assert.equal(v.entryValue(d, 'custom:0'), '1234');
    assert.equal(v.entryValue(d, 'custom:5'), '');
    assert.equal(v.entryValue(d, 'url'), 'https://www.bank.de/login');
    assert.equal(v.entryValue(d, 'totp', 59000), '287082');
    const card = v.normalizeEntry({ type: 'card', title: 'Visa', fields: { number: '4111 1111 1111 1234', cvc: '123' } });
    assert.equal(v.entrySubtitle(card), '•••• 1234');
  });
});

describe('utils/vault: TOTP', () => {
  it('RFC 6238 appendix B vectors for SHA1, SHA256, SHA512', () => {
    const s1 = b32('12345678901234567890');
    const s256 = b32('12345678901234567890123456789012');
    const s512 = b32('1234567890123456789012345678901234567890123456789012345678901234');
    const cases = [
      [59, ['94287082', '46119246', '90693936']],
      [1111111109, ['07081804', '68084774', '25091201']],
      [1111111111, ['14050471', '67062674', '99943326']],
      [1234567890, ['89005924', '91819424', '93441116']],
      [2000000000, ['69279037', '90698825', '38618901']],
      [20000000000, ['65353130', '77737706', '47863826']],
    ];
    for (const [t, want] of cases) {
      assert.equal(v.totpCode(v.parseTotp(`otpauth://totp/x?secret=${s1}&digits=8`), t * 1000).code, want[0], `SHA1 ${t}`);
      assert.equal(v.totpCode(v.parseTotp(`otpauth://totp/x?secret=${s256}&digits=8&algorithm=SHA256`), t * 1000).code, want[1], `SHA256 ${t}`);
      assert.equal(v.totpCode(v.parseTotp(`otpauth://totp/x?secret=${s512}&digits=8&algorithm=sha512`), t * 1000).code, want[2], `SHA512 ${t}`);
    }
  });

  it('bare secrets, seconds left, labels, invalid input', () => {
    const s1 = b32('12345678901234567890');
    const plain = v.parseTotp(s1.toLowerCase().match(/.{1,4}/g).join(' '));
    assert.equal(plain.digits, 6);
    assert.equal(plain.algorithm, 'SHA1');
    const c = v.totpCode(plain, 59000);
    assert.equal(c.code, '287082');
    assert.equal(c.secondsLeft, 1);
    assert.equal(v.prettyCode('482913'), '482 913');
    assert.equal(v.prettyCode('12345678'), '1234 5678');
    assert.equal(v.parseTotp(`otpauth://hotp/x?secret=${s1}`), null);
    assert.equal(v.parseTotp('not base32 !'), null);
    assert.equal(v.parseTotp(`otpauth://totp/x?secret=${s1}&algorithm=MD5`), null);
    const p = v.parseTotp(`otpauth://totp/x?secret=${s1}&digits=9&period=5`);
    assert.deepEqual([p.digits, p.period], [6, 30], 'out of range → defaults');
    assert.equal(v.parseTotp(`otpauth://totp/x?secret=${s1}&period=60`).period, 60);
    assert.equal(v.totpLabel(`otpauth://totp/Sparkasse:marc?secret=${s1}&issuer=Sparkasse`), 'Sparkasse');
    assert.equal(v.totpLabel(`otpauth://totp/GitHub%3Amarc?secret=${s1}`), 'GitHub');
    assert.equal(v.totpLabel(s1), null);
  });
});

describe('utils/vault: generator', () => {
  it('length, classes, look-alikes, words, strength', () => {
    for (let i = 0; i < 50; i++) {
      const p = v.generatePassword({ length: 20 });
      assert.equal(p.length, 20);
      assert.ok(/[A-Z]/.test(p) && /[a-z]/.test(p) && /\d/.test(p) && /[^A-Za-z0-9]/.test(p), p);
      const q = v.generatePassword({ length: 12, symbols: false, avoidAmbiguous: true });
      assert.ok(!/[l1IO0]/.test(q) && /^[A-Za-z0-9]{12}$/.test(q), q);
    }
    assert.equal(v.generatePassword({ length: 200 }).length, 64);
    assert.equal(v.generatePassword({ length: 2 }).length, 8);
    const w = v.generatePassword({ words: true, wordCount: 4 });
    assert.equal(w.split('-').length, 4);
    assert.ok(/\d/.test(w));
    assert.equal(v.wordCount('Sonnenblume-Kanu-Turm-47'), 4);
    assert.equal(v.passwordStrength('aaaaaaaaaaaaaaaa'), 'weak');
    assert.equal(v.passwordStrength('Passw0rd!'), 'weak');
    assert.equal(v.passwordStrength('Sonnenblume-Kanu-Turm-47'), 'very_strong');
    assert.ok(v.goodMasterPassword('Sonnenblume-Kanu-Turm-47'));
    assert.ok(!v.goodMasterPassword('kurz'));
    assert.ok(!v.goodMasterPassword(null));
  });
});

describe('utils/vault: matching', () => {
  const login = (title, { urls = [], apps = [], fav = false, trashed = false } = {}) =>
    ({ trashed, data: v.normalizeEntry({ type: 'login', title, fav, urls, apps, fields: { username: 'u' } }) });

  it('same site by domain, apps by name, favourites first', () => {
    assert.equal(v.urlHost('https://www.Login.Example.co.uk:8443/x?y'), 'login.example.co.uk');
    assert.equal(v.urlHost('user:pw@host.de/x'), 'host.de');
    assert.equal(v.urlHost('not a host!'), null);
    assert.equal(v.urlHost('  '), null);
    assert.equal(v.siteOf('login.example.co.uk'), 'example.co.uk');
    assert.equal(v.siteOf('banking.sparkasse.de'), 'sparkasse.de');
    assert.equal(v.siteOf('192.168.1.1'), '192.168.1.1');
    const list = [
      login('Sparkasse', { urls: ['sparkasse.de'] }),
      login('Sparkasse Fav', { urls: ['https://www.sparkasse.de'], fav: true }),
      login('Stadtwerke', { apps: ['stadtwerke.exe'] }),
      login('Alt', { urls: ['sparkasse.de'], trashed: true }),
      login('Evil', { urls: ['sparkasse.de.evil.com'] }),
    ];
    assert.deepEqual(v.matchEntries(list, { domain: 'banking.sparkasse.de' }).map((e) => e.data.title), ['Sparkasse Fav', 'Sparkasse']);
    assert.deepEqual(v.matchEntries(list, { app: 'Stadtwerke.EXE' }).map((e) => e.data.title), ['Stadtwerke']);
    assert.deepEqual(v.matchEntries(list, {}), []);
  });
});

describe('utils/vault: import', () => {
  it('Bitwarden JSON', () => {
    const json = JSON.stringify({ encrypted: false, items: [
      { type: 1, name: 'GitHub', favorite: true, notes: 'n', login: { username: 'me', password: 'pw', totp: 'JBSWY3DPEHPK3PXP', uris: [{ uri: 'https://github.com' }, { uri: 'androidapp://com.github.android' }] }, fields: [{ name: 'PIN', value: '1234', type: 1 }] },
      { type: 2, name: 'Notiz', notes: 'Text' },
      { type: 3, name: 'Visa', card: { cardholderName: 'M B', number: '4111', expMonth: '3', expYear: '2029', code: '123' } },
      { type: 4, name: 'Ich', identity: { firstName: 'Marc', lastName: 'B', email: 'm@b.de', address1: 'Weg 1', postalCode: '12345', city: 'Ort' } },
      { type: 5, name: 'SSH' },
      { type: 1, name: '', login: { uris: [{ uri: 'https://shop.example.com/x' }] } },
    ] });
    const r = v.parseImport(`﻿${json}`);
    assert.equal(r.ok, true);
    assert.equal(r.source, 'Bitwarden');
    assert.equal(r.entries.length, 5);
    const gh = r.entries[0];
    assert.deepEqual(gh.apps, ['com.github.android']);
    assert.equal(gh.fields.totp, 'JBSWY3DPEHPK3PXP');
    assert.ok(gh.fav && gh.custom[0].secret);
    assert.equal(r.entries[2].fields.expiry, '03/29');
    assert.equal(r.entries[3].fields.address, 'Weg 1, 12345 Ort');
    assert.equal(r.entries[4].title, 'shop.example.com');
    assert.deepEqual(v.importCounts(r.entries), { total: 5, logins: 2, withTotp: 1, notes: 1, cards: 1 });
    assert.deepEqual(v.parseImport('{"encrypted":true,"data":"x"}'), { ok: false, code: 'encrypted' });
    assert.deepEqual(v.parseImport('{broken'), { ok: false, code: 'unknown' });
  });

  it('CSV of Chrome, quoted cells, duplicates', () => {
    const csv = 'name,url,username,password,note\r\n'
      + 'Bank,https://bank.de,anna,"p,w""x","zwei\nZeilen"\r\n'
      + ',https://shop.example.com/login,bob,secret,\n';
    const r = v.parseImport(csv);
    assert.equal(r.source, 'Chrome / Edge');
    assert.equal(r.entries.length, 2);
    assert.equal(r.entries[0].fields.password, 'p,w"x');
    assert.equal(r.entries[0].notes, 'zwei\nZeilen');
    assert.equal(r.entries[1].title, 'shop.example.com');
    const { keep, duplicates } = v.withoutDuplicates(r.entries, [{ ...r.entries[0], fav: true }]);
    assert.equal(duplicates, 1);
    assert.deepEqual(keep.map((e) => e.title), ['shop.example.com']);
    assert.deepEqual(v.duplicateFlags([...r.entries, r.entries[1]], [r.entries[0]]), [true, false, true]);
    assert.deepEqual(v.parseImport('just,some\ncsv,file'), { ok: false, code: 'unknown' });
  });

  it('CSV of Bitwarden, Firefox, KeePass, 1Password; semicolons; notes', () => {
    assert.equal(v.parseImport('folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n,1,login,Mail,,,0,https://mail.de,me,pw,JBSWY3DPEHPK3PXP\n,,note,Zettel,Inhalt,,0,,,,\n').source, 'Bitwarden');
    const bw = v.parseImport('folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n,1,login,Mail,,,0,https://mail.de,me,pw,JBSWY3DPEHPK3PXP\n,,note,Zettel,Inhalt,,0,,,,\n');
    assert.deepEqual(bw.entries.map((e) => [e.type, e.title, e.fav === true]), [['login', 'Mail', true], ['note', 'Zettel', false]]);
    assert.equal(bw.entries[0].fields.totp, 'JBSWY3DPEHPK3PXP');
    assert.equal(v.parseImport('url,username,password,httpRealm,formActionOrigin,guid\nhttps://a.de,u,p,,,{x}\n').source, 'Firefox');
    assert.equal(v.parseImport('"Group","Title","Username","Password","URL","Notes"\n"Root","A","u","p","https://a.de",""\n').source, 'KeePass');
    assert.equal(v.parseImport('Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\nA,https://a.de,u,p,,,,,\n').source, '1Password');
    const semi = v.parseImport('Title;Username;Password;URL\nA;u;p;https://a.de\n');
    assert.equal(semi.source, 'CSV');
    assert.equal(semi.entries[0].fields.username, 'u');
  });
});

describe('utils/vault: server JSON', () => {
  const vaultJson = (id = VID, extra = {}) => ({ id, kind: 'shared', ownerId: 2, nameEnc: 'AAAA', role: 'write', keyRev: 1, sealedKey: 'BBBB', pending: null, needsRekey: false, members: [{ userId: 2, name: 'Anna', role: 'manage' }, { name: 'x' }], ...extra });
  const itemJson = (id, seq, state = 'live', vid = VID, rev = 2) => ({ id, vaultId: vid, rev, keyRev: 1, blob: state === 'purged' ? null : 'CCCC', state, seq });

  it('invalid shapes are rejected', () => {
    assert.equal(v.parseVault({ id: 'short', kind: 'shared' }), null);
    assert.equal(v.parseVault(vaultJson(VID, { pending: { sealedKey: 'x' } })), null, 'pending without keyRev');
    assert.equal(v.parseVault(vaultJson()).members.length, 1);
    assert.deepEqual(v.parseVault(vaultJson(VID, { pending: { keyRev: 2, sealedKey: 'DDDD' } })).pending, { keyRev: 2, sealedKey: 'DDDD' });
    assert.equal(v.parseItem({ id: A, vaultId: VID, rev: 1, keyRev: 1, state: 'live', seq: 1 }), null, 'a live entry needs a blob');
    assert.ok(v.parseItem(itemJson(A, 1, 'purged')));
    assert.deepEqual(v.parseAccountAnswer({ ok: true, account: null }), { account: null });
    assert.equal(v.parseAccountAnswer({ ok: true }), null);
    const results = v.parseSaveResults({ ok: true, results: [{ id: 'x', ok: true, rev: 3, seq: 10 }, { id: 'y', ok: false, code: 'conflict', current: itemJson(A, 4) }] });
    assert.equal(results[0].rev, 3);
    assert.equal(results[1].code, 'conflict');
    assert.equal(results[1].current.seq, 4);
    assert.equal(v.parseSync({ seq: 1, next: 1, vaults: [], account: { kdf: {} } }), null, 'a damaged account makes the page invalid');
    assert.equal(v.parseEmergency({ id: 'nothex', grantor: { id: 2 }, grantee: { id: 3 }, waitHours: 1, status: 'ready' }), null);
    assert.ok(v.parseEmergency({ id: 'a'.repeat(24), grantor: { id: 2, name: 'A' }, grantee: { id: 3, name: 'M' }, waitHours: 1, status: 'ready' }));
  });

  const page = (items, vaults = [vaultJson()], extra = {}) => v.parseSync({ ok: true, seq: 9, account: null, vaults, items, more: false, next: 9, ...extra });

  it('sync pages merge; tombstones drop entries and unsent changes; gone vaults go; older copies never win', () => {
    let s = v.mergePage(v.emptyState(), page([itemJson(A, 3), itemJson(B, 4)]), 1);
    assert.deepEqual([...s.items.keys()].sort(), [A, B]);
    assert.equal(s.known, true);
    s = v.mergePage(s, page([itemJson(A, 2, 'live', VID, 1)]), 2);
    assert.equal(s.items.get(A).seq, 3, 'an older copy (lower seq / rev) does not replace a newer one');
    s = v.queueSave(s, { id: B, vaultId: VID, blob: 'DDDD', keyRev: 1, baseRev: 2 });
    s = v.mergePage(s, page([itemJson(B, 7, 'purged')]), 3);
    assert.deepEqual([...s.items.keys()], [A]);
    assert.deepEqual(s.outbox, []);
    s = v.queueSave(s, { id: B, vaultId: VID, blob: 'DDDD', keyRev: 1, baseRev: 0 });
    s = v.mergePage(s, page([], [vaultJson('Other0000000000000000x')]), 4);
    assert.equal(s.items.size, 0, 'a vault missing from the list is gone with its entries');
    assert.deepEqual(s.outbox, [], '… and its unsent saves');
  });

  it('outbox keeps the first base revision when an entry changes twice offline; batches', () => {
    const s = v.queueSave(v.queueSave(v.emptyState(), { id: A, vaultId: VID, blob: 'AAAA', keyRev: 1, baseRev: 2 }), { id: A, vaultId: VID, blob: 'BBBB', keyRev: 1, baseRev: 3 });
    assert.equal(s.outbox.length, 1);
    assert.equal(s.outbox[0].baseRev, 2);
    assert.equal(s.outbox[0].blob, 'BBBB');
    const many = Array.from({ length: 250 }, (_, i) => ({ id: `${A.slice(0, 18)}${String(i).padStart(4, '0')}`, vaultId: VID, blob: 'x'.repeat(100), keyRev: 1, baseRev: 0 }));
    assert.deepEqual(v.batches(many).map((b) => b.length), [100, 100, 50]);
    const big = Array.from({ length: 10 }, (_, i) => ({ id: `${A.slice(0, 18)}${String(i).padStart(4, '0')}`, vaultId: VID, blob: 'x'.repeat(20000), keyRev: 1, baseRev: 0 }));
    const bb = v.batches(big);
    assert.deepEqual(bb.map((b) => b.length), [2, 2, 2, 2, 2]);
    for (const b of bb) assert.ok(b.reduce((n, x) => n + v.saveItemBytes(x), 0) <= v.BATCH_BYTES);
  });

  it('the copy round-trips through JSON and belongs to one login', () => {
    const s = v.queueSave(v.mergePage({ ...v.emptyState(), known: true, seq: 9 }, page([itemJson(A, 3)]), 5), { id: B, vaultId: VID, blob: 'EEEE', keyRev: 1, baseRev: 0 });
    const json = JSON.parse(JSON.stringify(v.stateToJson(s, 'owner1')));
    const back = v.stateFromJson(json, 'owner1');
    assert.deepEqual([...back.items.entries()], [...s.items.entries()]);
    assert.deepEqual(back.vaults, s.vaults);
    assert.deepEqual(back.outbox, s.outbox);
    assert.equal(v.stateFromJson(json, 'owner2'), null);
    assert.equal(v.ownerKey(''), '');
    assert.match(v.ownerKey('https://gc\nkey'), /^[0-9a-f]{32}$/);
  });
});

describe('utils/vault: push context', () => {
  it('topics share / emergency; other senders → null', () => {
    const e = { id: 5, topic: 'plugin:gatecontrol-vault:emergency', data: { vault: { topic: 'emergency', event: 'requested', emergency: 'ab'.repeat(12) } } };
    assert.deepEqual(v.pushContext(e), { topic: 'emergency', event: 'requested', vaultId: null, emergencyId: 'ab'.repeat(12), page: 'emergency' });
    assert.deepEqual(v.pushContext({ topic: 'plugin:gatecontrol-vault:share', data: { vault: { topic: 'share', event: 'shared', vault: VID } } }),
      { topic: 'share', event: 'shared', vaultId: VID, emergencyId: null, page: 'home' });
    assert.equal(v.pushContext({ topic: 'devices', data: {} }), null);
    assert.equal(v.pushContext({ topic: 'plugin:gatecontrol-schule:changes', data: {} }), null);
    assert.equal(v.pushContext({ topic: 'x', data: { route: 'plg-gatecontrol-vault', vault: { event: 'evil', vault: '../x' } } }).vaultId, null);
  });
});

'use strict';

// Medien (Stufe 4e): the NAS shares — WebDAV against a fake server (the cases of Android's WebDavFsTest: PROPFIND,
// Basic, Digest, Range, no DTD, the access never to another server, a self-signed certificate only once confirmed),
// SMB through Windows (WNetAddConnection2W faked, error 1219; the files of a folder standing in for the UNC path),
// and the pure parts (paths, UNC, Range).

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const S = require('../src/utils/media-share');
const MediaNet = require('../src/services/media-net');
const { SmbShare, WebDavShare, wnetCode } = require('../src/services/media-share');
const { createMediaServer } = require('./fixtures/media-server');
const { makeSelfSigned } = require('./fixtures/self-signed');

const multistatus = (...responses) => `<?xml version="1.0" encoding="utf-8"?>\n<D:multistatus xmlns:D="DAV:">${responses.join('')}</D:multistatus>`;
const entry = (href, dir, size = 0, modified = null) => `
<D:response><D:href>${href}</D:href><D:propstat><D:prop>
<D:resourcetype>${dir ? '<D:collection/>' : ''}</D:resourcetype>
${!dir ? `<D:getcontentlength>${size}</D:getcontentlength>` : ''}
${modified ? `<D:getlastmodified>${modified}</D:getlastmodified>` : ''}
</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>
<D:propstat><D:prop><D:displayname/></D:prop><D:status>HTTP/1.1 404 Not Found</D:status></D:propstat></D:response>`;

describe('WebDavShare against a fake server', () => {
  let srv;
  let net;
  const share = (user = null, password = null, extra = {}) => new WebDavShare({ source: { address: `${srv.homeBase}/filme`, userName: user, password, ...extra }, net });
  beforeEach(async () => { srv = await createMediaServer().start(); net = new MediaNet(); });
  afterEach(async () => { net.reset(); await srv.close(); });

  it('a folder by PROPFIND - the folder itself left out, names decoded', async () => {
    srv.enqueue({ status: 207, body: multistatus(
      entry('/filme/Neu/', true),
      entry('/filme/Neu/Kobaltnacht%20(2025).mkv', false, 4000000000, 'Mon, 23 Nov 2026 20:15:00 GMT'),
      entry(`${srv.homeBase}/filme/Neu/Serien/`, true),
      entry('/filme/Neu/.DS_Store', false, 6),
      // not in this folder: left out
      entry('/anderes/geheim.mkv', false, 1),
    ) });
    const list = (await share().list('Neu')).value;
    assert.deepEqual(list.map((e) => e.name), ['Kobaltnacht (2025).mkv', 'Serien']);
    assert.deepEqual(list[0], { name: 'Kobaltnacht (2025).mkv', path: 'Neu/Kobaltnacht (2025).mkv', directory: false, size: 4000000000, modifiedAt: 1795464900000, kind: 'video' });
    assert.ok(list[1].directory);
    const req = srv.take();
    assert.equal(req.method, 'PROPFIND');
    assert.equal(req.path, '/filme/Neu/');
    assert.equal(req.headers.depth, '1');
  });

  it('refused, missing, not reachable, no DTD', async () => {
    const fsx = share('kino', 'pw');
    srv.enqueue({ status: 401 });
    assert.equal((await fsx.list('')).code, 'unauthorized');
    srv.enqueue({ status: 404 });
    assert.equal((await fsx.list('weg')).code, 'not_found');
    // an entity of the network is never read
    srv.enqueue({ status: 207, body: '<?xml version="1.0"?><!DOCTYPE m [<!ENTITY x SYSTEM "file:///etc/passwd">]><D:multistatus xmlns:D="DAV:"><D:response><D:href>/filme/&x;</D:href></D:response></D:multistatus>' });
    assert.equal((await fsx.list('')).code, 'failed');
    assert.equal((await fsx.list('../etc')).code, 'not_found');
    await srv.close();
    assert.equal((await share().list('')).code, 'offline');
  });

  it('Basic - after the first 401 at once on every request', async () => {
    const fsx = share('kino', 'geheim');
    srv.enqueue({ status: 401, headers: { 'WWW-Authenticate': 'Basic realm="NAS"' } });
    srv.enqueue({ status: 207, body: multistatus(entry('/filme/', true)) });
    srv.enqueue({ status: 207, body: multistatus(entry('/filme/', true)) });
    assert.deepEqual((await fsx.list('')).value, []);
    assert.equal(srv.take().headers.authorization, undefined);
    const basic = `Basic ${Buffer.from('kino:geheim').toString('base64')}`;
    assert.equal(srv.take().headers.authorization, basic);
    await fsx.list('');
    assert.equal(srv.take().headers.authorization, basic);
  });

  it('Digest - the answer of RFC 7616, a wrong password stays 401', async () => {
    const fsx = share('kino', 'geheim');
    const challenge = 'Digest realm="NAS", qop="auth", nonce="abc123", opaque="op", algorithm=MD5';
    srv.enqueue({ status: 401, headers: { 'WWW-Authenticate': challenge } });
    srv.enqueue({ status: 207, body: multistatus(entry('/filme/', true)) });
    assert.ok((await fsx.list('')).ok);
    srv.take();
    const auth = srv.take().headers.authorization;
    assert.ok(auth.startsWith('Digest '));
    const p = S.parseChallenges([auth])[0].params;
    const md5 = (s) => crypto.createHash('md5').update(s).digest('hex');
    assert.equal(p.response, md5(`${md5('kino:NAS:geheim')}:abc123:${p.nc}:${p.cnonce}:auth:${md5('PROPFIND:/filme/')}`));
    assert.equal(p.uri, '/filme/');
    assert.equal(p.opaque, 'op');
    assert.equal(p.nc, '00000001');
    // the same challenge again after the answer: the password is wrong
    srv.enqueue({ status: 401, headers: { 'WWW-Authenticate': challenge } });
    assert.equal((await fsx.list('')).code, 'unauthorized');
  });

  it('the access never goes to another server; Basic over plain HTTP only in the home network', async () => {
    const fsx = share('kino', 'geheim');
    const other = await createMediaServer().start();
    try {
      other.enqueue({ status: 401, headers: { 'WWW-Authenticate': 'Basic realm="x"' } });
      const r = await fsx.send('GET', `${other.base}/`, {});
      assert.equal(r.status, 401);
      assert.equal(other.requests.length, 1);
      assert.equal(other.take().headers.authorization, undefined);
    } finally {
      await other.close();
    }
    assert.equal(S.chooseChallenge([{ scheme: 'basic', params: { realm: 'x' } }], false), null);
    assert.equal(S.chooseChallenge(S.parseChallenges(['Basic realm="x", Digest realm="y", nonce="n", algorithm=SHA-256']), false).scheme, 'digest');
    const away = new WebDavShare({ source: { address: 'http://dav.example.test/filme', userName: 'kino', password: 'x' }, net });
    assert.equal(away._basicAllowed, false);
  });

  it('a file from a place by Range, the whole length from Content-Range; a server without ranges skipped', async () => {
    const fsx = share();
    srv.enqueue({ status: 206, headers: { 'Content-Range': 'bytes 500-999/1000' }, body: 'x'.repeat(500) });
    const r = (await fsx.open('Neu/Kobaltnacht (2025).mkv', { start: 500 })).value;
    assert.equal(r.size, 1000);
    const chunks = [];
    for await (const c of r.stream) chunks.push(c);
    assert.equal(Buffer.concat(chunks).length, 500);
    const req = srv.take();
    assert.equal(req.headers.range, 'bytes=500-');
    assert.equal(req.path, '/filme/Neu/Kobaltnacht%20(2025).mkv');
    srv.enqueue({ status: 200, body: '0123456789' });
    const all = (await fsx.open('a.mkv', { start: 4 })).value;
    let text = '';
    for await (const c of all.stream) text += c.toString();
    assert.equal(text, '456789');
    srv.enqueue({ status: 200, body: '0123456789' });
    assert.equal((await fsx.read('a.mkv', 2, 3)).value.toString(), '234');
    srv.enqueue({ status: 403 });
    assert.equal((await fsx.open('a.mkv', { start: 0 })).ok, false);
  });

  it('challenges as servers write them', () => {
    const list = S.parseChallenges(['Digest realm="a, b", nonce="n\\"1", qop="auth,auth-int", Basic realm="c"', 'Negotiate']);
    assert.deepEqual(list.map((c) => c.scheme), ['digest', 'basic', 'negotiate']);
    assert.equal(list[0].params.realm, 'a, b');
    assert.equal(list[0].params.nonce, 'n"1');
    assert.equal(list[0].params.qop, 'auth,auth-int');
  });
});

describe('WebDAV over HTTPS with a self-signed certificate (Synology)', () => {
  it('refused until confirmed; then pinned; another certificate is refused', async () => {
    const cert = makeSelfSigned();
    const srv = await createMediaServer({ tls: cert }).start();
    const net = new MediaNet();
    try {
      const fsx = new WebDavShare({ source: { address: `${srv.base}/filme` }, net });
      assert.equal((await fsx.list('')).code, 'cert_untrusted');
      assert.equal(srv.requests.length, 0, 'not a byte of the request before the certificate is trusted');
      const seen = await net.certificate(`${srv.base}/filme`);
      assert.equal(seen.fingerprint, cert.sha256);
      assert.equal(seen.trusted, false);
      srv.enqueue({ status: 207, body: multistatus(entry('/filme/', true)) });
      const pinned = new WebDavShare({ source: { address: `${srv.base}/filme`, tlsPin: seen.fingerprint }, net });
      assert.ok((await pinned.list('')).ok);
      const wrong = new WebDavShare({ source: { address: `${srv.base}/filme`, tlsPin: 'ab'.repeat(32) }, net });
      assert.equal((await wrong.list('')).code, 'cert_changed');
      assert.equal(srv.requests.length, 1);
    } finally {
      net.reset();
      await srv.close();
    }
  });
});

describe('SmbShare (Windows connects, the files are read through the UNC path)', () => {
  let dir;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gc-media-smb-'));
    fs.mkdirSync(path.join(dir, 'filme', 'Neu'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'filme', 'Neu', 'Kobaltnacht (2025).mkv'), '0123456789');
    fs.writeFileSync(path.join(dir, 'filme', 'Neu', 'Thumbs.db'), 'x');
    fs.mkdirSync(path.join(dir, 'filme', 'Neu', 'Serien'));
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  const fakeWnet = (answer = 0) => {
    const calls = [];
    return { calls, add: (remote, user, pw) => { calls.push(['add', remote, user, pw]); return answer; }, cancel: (remote) => { calls.push(['cancel', remote]); return 0; } };
  };

  it('connects once without a drive letter, lists, reads from a place, disconnects', async () => {
    const wnet = fakeWnet(0);
    const smb = new SmbShare({ source: { address: 'smb://nas/filme', userName: 'kino', password: 'geheim' }, wnet });
    assert.equal(smb.remote, '\\\\nas\\filme');
    assert.ok((await smb.connect()).ok);
    assert.ok((await smb.connect()).ok);
    assert.deepEqual(wnet.calls, [['add', '\\\\nas\\filme', 'kino', 'geheim']]);
    await smb.close();
    assert.deepEqual(wnet.calls[1], ['cancel', '\\\\nas\\filme']);

    const local = new SmbShare({ source: { address: 'smb://nas/filme' }, wnet: null, localRoot: path.join(dir, 'filme') });
    const list = (await local.list('Neu')).value;
    assert.deepEqual(list.map((e) => [e.name, e.directory, e.kind]).sort(), [['Kobaltnacht (2025).mkv', false, 'video'], ['Serien', true, 'folder']]);
    assert.equal(list.find((e) => !e.directory).size, 10);
    assert.equal((await local.read('Neu/Kobaltnacht (2025).mkv', 3, 4)).value.toString(), '3456');
    const o = (await local.open('Neu/Kobaltnacht (2025).mkv', { start: 6, end: 8 })).value;
    let text = '';
    for await (const c of o.stream) text += c.toString();
    assert.equal(text, '678');
    assert.equal((await local.list('../..')).code, 'not_found');
    assert.equal((await local.stat('Neu/weg.mkv')).code, 'not_found');
  });

  it('Windows error 1219 (the Explorer is connected with another user): smb_conflict; the Explorer\'s access instead', async () => {
    const wnet = fakeWnet(1219);
    const smb = new SmbShare({ source: { address: 'smb://192.168.1.20/filme', userName: 'medien-lesen', password: 'pw' }, wnet });
    assert.deepEqual(await smb.connect(), { ok: false, code: 'smb_conflict', winError: 1219 });
    const existing = new SmbShare({ source: { address: 'smb://192.168.1.20/filme', userName: 'medien-lesen', password: 'pw', useExisting: true }, wnet });
    assert.ok((await existing.connect()).ok);
    assert.equal(wnet.calls.length, 1, 'no second WNetAddConnection2W');
    assert.equal(wnetCode(1326), 'unauthorized');
    assert.equal(wnetCode(53), 'offline');
    assert.equal(wnetCode(67), 'not_found');
    assert.equal(wnetCode(85), null);
    assert.equal(wnetCode(9999), 'failed');
    const port = new SmbShare({ source: { address: 'smb://nas:4450/filme', userName: 'x', password: 'y' }, wnet });
    assert.equal((await port.connect()).code, 'unsupported', 'Windows connects SMB on 445 only');
  });
});

describe('media-share: paths, UNC, Range', () => {
  it('paths stay below the root', () => {
    assert.equal(S.clean('a//b/'), 'a/b');
    assert.equal(S.clean('a\\b'), 'a/b');
    assert.equal(S.clean('../x'), null);
    assert.equal(S.clean('a/./b'), null);
    assert.equal(S.clean('a\u0000b'), null);
    assert.equal(S.join('', 'x'), 'x');
    assert.equal(S.parent('a/b/c.mkv'), 'a/b');
    assert.equal(S.baseName('a/b/c.mkv'), 'c.mkv');
  });

  it('the UNC path of a file, nothing Windows reads as something else', () => {
    assert.equal(S.uncPath('\\\\nas\\filme', 'Neu/Kobaltnacht (2025).mkv'), '\\\\nas\\filme\\Neu\\Kobaltnacht (2025).mkv');
    assert.equal(S.uncPath('\\\\nas\\filme', ''), '\\\\nas\\filme');
    assert.equal(S.uncPath('\\\\nas\\filme', 'a.mkv:stream'), null, 'no alternate data stream');
    assert.equal(S.uncPath('\\\\nas\\filme', 'CON'), null);
    assert.equal(S.uncPath('\\\\nas\\filme', 'a/../../x'), null);
    assert.equal(S.uncPath('C:\\x', 'a'), null);
  });

  it('Range of a file', () => {
    assert.deepEqual(S.byteRange('bytes=0-', 1000), { start: 0, end: 999 });
    assert.deepEqual(S.byteRange('bytes=500-1499', 1000), { start: 500, end: 999 });
    assert.deepEqual(S.byteRange('bytes=-100', 1000), { start: 900, end: 999 });
    assert.equal(S.byteRange('bytes=1000-', 1000), 'unsatisfiable');
    assert.equal(S.byteRange('bytes=0-1,5-6', 1000), null);
    assert.equal(S.byteRange(null, 1000), null);
    assert.deepEqual(S.contentRange('bytes 500-999/1000'), { start: 500, end: 999, total: 1000 });
    assert.equal(S.kindOf('Film.sample.mkv'), null);
    assert.equal(S.kindOf('poster.jpg'), 'image');
    assert.equal(S.mimeOf('a.mp4'), 'video/mp4');
  });

  it('the XML reader: namespaces by any prefix, entities only the five', () => {
    const x = S.parseXml('<?xml version="1.0"?><m:multistatus xmlns:m="DAV:"><m:response a="1 &amp; 2"><m:href>/a&amp;b</m:href></m:response></m:multistatus>');
    assert.equal(x.ns, 'DAV:');
    assert.equal(x.children[0].children[0].text, '/a&b');
    assert.equal(S.parseXml('<a xmlns="DAV:"><b>&unknown;</b></a>'), null);
    assert.equal(S.parseXml('<a><b></a>'), null);
    assert.equal(S.parseXml('<a/><b/>'), null);
    assert.equal(S.parseXml(`${'<a>'.repeat(100)}${'</a>'.repeat(100)}`), null, 'too deep');
    const def = S.parseMultistatus(`<multistatus xmlns="DAV:"><response><href>/filme/x.mkv</href><propstat><prop><resourcetype/><getcontentlength>5</getcontentlength></prop><status>HTTP/1.1 200 OK</status></propstat></response></multistatus>`, 'http://192.168.1.20/filme', '');
    assert.deepEqual(def.map((e) => [e.name, e.size]), [['x.mkv', 5]]);
  });
});

'use strict';

// Support bundle redaction (src/support/redact.js). Nothing that can unlock
// the tunnel, the API or a session may leave the machine.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { redactText, redactValue, isSecretKey, MASK } = require('../src/support/redact');

const WG_KEY = 'yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=';
const PSK = 'FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE=';

describe('redactText', () => {
  it('masks PrivateKey / PresharedKey in a WireGuard config, keeps the rest', () => {
    const conf = `[Interface]\nPrivateKey = ${WG_KEY}\nAddress = 10.8.0.2/32\nDNS = 10.8.0.1\n\n[Peer]\nPublicKey = ${WG_KEY.replace('y', 'z')}\nPresharedKey=${PSK}\nEndpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0`;
    const out = redactText(conf);
    assert.ok(!out.includes(WG_KEY));
    assert.ok(!out.includes(PSK));
    assert.match(out, /^PrivateKey = \[REDACTED\]$/m);
    assert.match(out, /^PresharedKey=\[REDACTED\]$/m);
    for (const keep of ['Address = 10.8.0.2/32', 'DNS = 10.8.0.1', 'Endpoint = vpn.example.com:51820', 'AllowedIPs = 0.0.0.0/0']) {
      assert.ok(out.includes(keep), keep);
    }
  });

  it('masks Authorization, X-API-Token/Key, Cookie headers and gc_ tokens', () => {
    const cases = [
      ['Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl', /c2lnbmF0dXJl|eyJzdWIi/],
      ['authorization=Basic dXNlcjpwYXNz', /dXNlcjpwYXNz/],
      ["headers: { 'X-API-Token': 'gc_live_0123456789abcdef' }", /0123456789abcdef/],
      ['X-API-Key: secretvalue123', /secretvalue123/],
      ['Cookie: gc.sid=s%3Aabc; other=1', /gc\.sid|other=1/],
      ['Set-Cookie: session=xyz; Path=/; HttpOnly', /session=xyz/],
      ['API 401: /api/v1/client/ping token gc_0123456789abcdef0123', /gc_0123456789abcdef0123/],
    ];
    for (const [line, leak] of cases) {
      const out = redactText(line);
      assert.ok(out.includes(MASK), `not masked: ${line}`);
      assert.ok(!leak.test(out), `leak in: ${out}`);
    }
  });

  it('masks key=value / JSON pairs with secret-like names', () => {
    const out = redactText('password=hunter2&user=bob {"apiKey": "k-123", "client_secret":"s3", "refresh_token": "r1", "rdpPassword":"pw!"} setupCode: AB12-CD34-EF56-7890');
    for (const s of ['hunter2', 'k-123', '"s3"', '"r1"', 'pw!', 'AB12-CD34-EF56-7890']) assert.ok(!out.includes(s), `leak ${s}: ${out}`);
    assert.match(out, /user=bob/);
  });

  it('masks key-like values: WG keys, long hex, PEM private keys, setup codes, JWTs', () => {
    const pem = '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk=\nAAAAB3NzaC1yc2EAAAADAQABAAABAQ\n-----END OPENSSH PRIVATE KEY-----';
    const out = redactText(`peer ${WG_KEY} fp ${'ab'.repeat(32)} code 1a2b-3c4d-5e6f-7a8b jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig_nature\n${pem}`);
    for (const s of [WG_KEY, 'ab'.repeat(32), '1a2b-3c4d-5e6f-7a8b', 'b3BlbnNzaC1rZXk=', 'AAAAB3NzaC1yc2E', 'eyJzdWIiOiIxIn0']) {
      assert.ok(!out.includes(s), `leak ${s}: ${out}`);
    }
  });

  it('keeps ordinary log lines intact', () => {
    for (const line of [
      '[2026-10-02 10:00:00.123] [info] Tunnel connected to 203.0.113.5:51820 after 2 attempts',
      '[2026-10-02 10:00:01.000] [warn] Connection check failed (1/3): Handshake too old: 200s',
      'interface fe80::1c2b:3cff:fe4d:5e6f%12 up',
      'uuid 123e4567-e89b-12d3-a456-426614174000',
    ]) assert.equal(redactText(line), line);
  });

  it('runs in linear time on hostile input', () => {
    for (const s of ['-a'.repeat(50000), '-----BEGIN RSA PRIVATE KEY-----'.repeat(3000), 'Authorization: '.repeat(9000), 'password'.repeat(20000)]) {
      const t0 = Date.now();
      redactText(s);
      assert.ok(Date.now() - t0 < 1500, `slow on ${s.slice(0, 20)}…`);
    }
  });
});

describe('redactValue', () => {
  it('masks secret-named keys at any depth and redacts every string', () => {
    const out = redactValue({
      server: { url: 'https://gate.example.com', apiKey: 'gc_abcdefgh', peerId: '7' },
      list: [{ password: 'p' }, `PrivateKey = ${WG_KEY}`],
      tunnel: { killSwitch: true, presharedKey: { nested: 1 } },
      rdp: { credentials: { user: 'a', pass: 'b' } },
      hasToken: false,
      emptySecret: '',
    });
    assert.equal(out.server.apiKey, MASK);
    assert.equal(out.server.url, 'https://gate.example.com');
    assert.equal(out.server.peerId, '7');
    assert.equal(out.list[0].password, MASK);
    assert.equal(out.list[1], `PrivateKey = ${MASK}`);
    assert.equal(out.tunnel.killSwitch, true);
    assert.equal(out.tunnel.presharedKey, MASK);
    assert.equal(out.rdp.credentials, MASK);
    assert.equal(out.hasToken, false);
    assert.equal(out.emptySecret, '');
  });

  it('drops prototype-related keys and never writes through the prototype', () => {
    const input = JSON.parse('{"__proto__":{"polluted":"yes"},"a":{"constructor":{"prototype":{"x":1}},"prototype":2,"b":"c"}}');
    const out = redactValue(input);
    assert.equal({}.polluted, undefined);
    assert.ok(!Object.prototype.hasOwnProperty.call(out, '__proto__'));
    assert.deepEqual(Object.keys(out.a), ['b']);
  });

  it('isSecretKey covers the secret names and nothing harmless', () => {
    for (const k of ['apiKey', 'api_key', 'privateKey', 'PresharedKey', 'password', 'token', 'X-API-Token', 'cookie', 'Authorization', 'enrollmentCode', 'setup_code', 'machineKey', 'clientSecret']) {
      assert.equal(isSecretKey(k), true, k);
    }
    for (const k of ['url', 'peerId', 'killSwitch', 'endpoint', 'version', 'dnsServers', 'splitRoutes']) {
      assert.equal(isSecretKey(k), false, k);
    }
  });
});

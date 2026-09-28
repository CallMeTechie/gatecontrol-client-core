'use strict';

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { normalizeCode, normalizeServerUrl, parseEnrollmentLink } = require('../src/utils/enrollment');
const ApiClient = require('../src/services/api-client');

describe('setup codes — parsing', () => {
  it('normalizes typed codes', () => {
    assert.equal(normalizeCode(' ab12 cd34 ef56 7890 '), 'AB12-CD34-EF56-7890');
    assert.equal(normalizeCode('AB12-CD34-EF56-7890'), 'AB12-CD34-EF56-7890');
  });

  it('never takes an API token or garbage for a code', () => {
    assert.equal(normalizeCode('gc_b71185344ccf348e47abc55a3203f125'), null);
    assert.equal(normalizeCode('AB12-CD34-EF56'), null);
    assert.equal(normalizeCode('XY12-CD34-EF56-7890'), null);
    assert.equal(normalizeCode(''), null);
    assert.equal(normalizeCode(undefined), null);
  });

  it('accepts only https server URLs and drops the path', () => {
    assert.equal(normalizeServerUrl('https://gate.example.com/admin'), 'https://gate.example.com');
    assert.equal(normalizeServerUrl('https://gate.example.com:8443'), 'https://gate.example.com:8443');
    assert.equal(normalizeServerUrl('http://gate.example.com'), null);
    assert.equal(normalizeServerUrl('gate.example.com'), null);
  });

  it('parses the setup QR link of the server', () => {
    assert.deepEqual(
      parseEnrollmentLink('gatecontrol://enroll?url=https%3A%2F%2Fgate.example.com&code=ab12cd34ef567890'),
      { serverUrl: 'https://gate.example.com', code: 'AB12-CD34-EF56-7890' },
    );
  });

  it('rejects WireGuard configs, other links and plain http servers', () => {
    assert.equal(parseEnrollmentLink('[Interface]\nPrivateKey = x'), null);
    assert.equal(parseEnrollmentLink('gatecontrol://setup?url=https%3A%2F%2Fa.b&token=gc_x'), null);
    assert.equal(parseEnrollmentLink('gatecontrol://enroll?url=http%3A%2F%2Fa.b&code=AB12CD34EF567890'), null);
    assert.equal(parseEnrollmentLink('gatecontrol://enroll?url=https%3A%2F%2Fa.b'), null);
  });
});

describe('ApiClient.redeemSetupCode', () => {
  let server, base, lastRequest;
  before(async () => {
    server = http.createServer((req, res) => {
      let body = '';
      req.on('data', (c) => { body += c; });
      req.on('end', () => {
        lastRequest = { url: req.url, headers: req.headers, body: JSON.parse(body || '{}') };
        res.setHeader('Content-Type', 'application/json');
        if (lastRequest.body.code === 'AB12-CD34-EF56-7890') {
          res.end(JSON.stringify({ ok: true, kind: 'device', token: 'gc_new', peerId: 7, config: '[Interface]', hash: 'h' }));
        } else {
          res.statusCode = 400;
          res.end(JSON.stringify({ ok: false, error: 'invalid_or_expired' }));
        }
      });
    });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    base = `http://127.0.0.1:${server.address().port}`;
  });
  after(() => server.close());

  it('posts the code with hostname, platform and fingerprint and returns the token', async () => {
    const data = await ApiClient.redeemSetupCode(base, 'AB12-CD34-EF56-7890', { clientVersion: '9.9.9' });
    assert.equal(data.token, 'gc_new');
    assert.equal(data.peerId, 7);
    assert.equal(lastRequest.url, '/api/v1/client/enroll');
    assert.equal(lastRequest.body.clientVersion, '9.9.9');
    assert.ok(lastRequest.body.hostname);
    assert.match(lastRequest.headers['x-machine-fingerprint'], /^[a-f0-9]{64}$/);
    assert.equal(lastRequest.headers['x-api-token'], undefined, 'no token is sent before one exists');
  });

  it('surfaces the server error code', async () => {
    await assert.rejects(ApiClient.redeemSetupCode(base, '0000-0000-0000-0000'),
      (err) => err.response && err.response.data.error === 'invalid_or_expired');
  });
});

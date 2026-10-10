'use strict';

// ApiClient default headers: X-Client-Type tells the server which product
// (pro/community) the reported X-Client-Version belongs to (version overview
// and minimum-version check on the server). Only known editions are sent.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const ApiClient = require('../src/services/api-client');

const log = { info() {}, warn() {}, error() {}, debug() {} };
const headersOf = (client) => client.client.defaults.headers;

describe('ApiClient headers', () => {
  it('sends version, platform and edition', () => {
    const c = new ApiClient('https://gate.example.com', 'gc_x', log, 1, { clientVersion: '1.22.3', clientType: 'pro' });
    const h = headersOf(c);
    assert.equal(h['X-Client-Version'], '1.22.3');
    assert.equal(h['X-Client-Platform'], 'windows');
    assert.equal(h['X-Client-Type'], 'pro');
  });

  it('omits an unknown or missing edition', () => {
    assert.equal(headersOf(new ApiClient('https://gate.example.com', 'gc_x', log, 1, {}))['X-Client-Type'], undefined);
    assert.equal(headersOf(new ApiClient('https://gate.example.com', 'gc_x', log, 1, { clientType: 'evil\r\nX: y' }))['X-Client-Type'], undefined);
  });
});

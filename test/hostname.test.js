'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const ApiClient = require('../src/services/api-client');

describe('ApiClient.sanitizeHostnameForDns', () => {
  const s = ApiClient.sanitizeHostnameForDns;

  it('passes a clean RFC-1123 label through', () => {
    assert.equal(s('desktop-8f36qk8'), 'desktop-8f36qk8');
    assert.equal(s('laptop42'), 'laptop42');
  });

  it('lowercases', () => {
    assert.equal(s('DESKTOP-8F36QK8'), 'desktop-8f36qk8');
  });

  it('strips dotted suffix (mac .local, .lan, domain-joined)', () => {
    assert.equal(s('Marcs-MBP.local'), 'marcs-mbp');
    assert.equal(s('machine.corp.example.com'), 'machine');
  });

  it('replaces underscores and other invalid chars with hyphens', () => {
    assert.equal(s('MY_PC'), 'my-pc');
    assert.equal(s('user$machine'), 'user-machine');
  });

  it('collapses repeated hyphens', () => {
    assert.equal(s('foo---bar'), 'foo-bar');
    assert.equal(s('a__b__c'), 'a-b-c');
  });

  it('strips leading and trailing hyphens', () => {
    assert.equal(s('-foo-'), 'foo');
    assert.equal(s('___bar___'), 'bar');
  });

  it('truncates to 63 chars and trims trailing hyphen', () => {
    const long = 'a'.repeat(80);
    const out = s(long);
    assert.equal(out.length, 63);
    assert.ok(!out.endsWith('-'));
  });

  it('returns null for empty / unusable input', () => {
    assert.equal(s(''), null);
    assert.equal(s(null), null);
    assert.equal(s(undefined), null);
    assert.equal(s('---'), null);
    assert.equal(s('...'), null);
    // all-invalid collapses to single hyphen, which gets stripped
    assert.equal(s('@@@'), null);
  });

  it('handles unicode by stripping to hyphens', () => {
    assert.equal(s('münchen'), 'm-nchen');
    assert.equal(s('пример'), null);
  });
});

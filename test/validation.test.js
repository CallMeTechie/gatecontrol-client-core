'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { validateIp, validateCidr, validatePort, validateInt, validateIfaceName } = require('../src/utils/validation');

describe('Validation', () => {
  describe('validateIp', () => {
    it('accepts valid IPv4', () => { assert.equal(validateIp('192.168.1.1'), '192.168.1.1'); });
    it('accepts 0.0.0.0', () => { assert.equal(validateIp('0.0.0.0'), '0.0.0.0'); });
    it('accepts 255.255.255.255', () => { assert.equal(validateIp('255.255.255.255'), '255.255.255.255'); });
    it('rejects invalid format', () => { assert.throws(() => validateIp('abc')); });
    it('rejects out of range', () => { assert.throws(() => validateIp('256.1.1.1')); });
    it('rejects empty', () => { assert.throws(() => validateIp('')); });
  });

  describe('validateCidr', () => {
    it('accepts valid CIDR', () => { assert.equal(validateCidr('10.0.0.0/8'), '10.0.0.0/8'); });
    it('accepts /32', () => { assert.equal(validateCidr('192.168.1.1/32'), '192.168.1.1/32'); });
    it('accepts /0', () => { assert.equal(validateCidr('0.0.0.0/0'), '0.0.0.0/0'); });
    it('rejects invalid prefix', () => { assert.throws(() => validateCidr('10.0.0.0/33')); });
    it('rejects no prefix', () => { assert.throws(() => validateCidr('10.0.0.0')); });
  });

  describe('validatePort', () => {
    it('accepts valid port', () => { assert.equal(validatePort('8080'), '8080'); });
    it('accepts port 1', () => { assert.equal(validatePort('1'), '1'); });
    it('accepts port 65535', () => { assert.equal(validatePort('65535'), '65535'); });
    it('rejects non-numeric', () => { assert.throws(() => validatePort('abc')); });
  });

  describe('validateInt', () => {
    it('accepts integers', () => { assert.equal(validateInt('42'), '42'); });
    it('accepts zero', () => { assert.equal(validateInt('0'), '0'); });
    it('rejects float', () => { assert.throws(() => validateInt('3.14')); });
    it('rejects text', () => { assert.throws(() => validateInt('hello')); });
  });

  describe('validateIfaceName', () => {
    it('accepts alphanumeric', () => { assert.equal(validateIfaceName('wg0'), 'wg0'); });
    it('accepts hyphens and underscores', () => { assert.equal(validateIfaceName('gate-control_0'), 'gate-control_0'); });
    it('rejects special chars', () => { assert.throws(() => validateIfaceName('wg;rm -rf')); });
  });
});

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { renderTrayIcon, createTrayIcon, formatBytesShort, TRAY_ICON_SIZE } = require('../src/utils/tray-icon');

const sha = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

describe('renderTrayIcon', () => {
  // Hashes of the icons the Pro and Community main.js drew before the code
  // moved to core — the tray must look exactly the same.
  const GOLDEN = {
    connected: 'd88b401f27c83302eafbb37e1131fae55fb93ddc0d639a0535c912a7ba11e8b8',
    connecting: '88bec41c5c8c1b5f3c68130f4905950f43f3444baa69fd879558d0d4726672ec',
    disconnected: '557f67463b45bc0f273ba80b69e95cf886697af8614a18adf1a6d488417f9bcf',
  };

  for (const [state, hash] of Object.entries(GOLDEN)) {
    it(`draws the unchanged ${state} icon`, () => {
      const { buffer, width, height } = renderTrayIcon(state);
      assert.equal(width, TRAY_ICON_SIZE);
      assert.equal(height, TRAY_ICON_SIZE);
      assert.equal(buffer.length, TRAY_ICON_SIZE * TRAY_ICON_SIZE * 4);
      assert.equal(sha(buffer), hash);
    });
  }

  it('uses the red icon for every other state', () => {
    assert.equal(sha(renderTrayIcon('error').buffer), GOLDEN.disconnected);
    assert.equal(sha(renderTrayIcon(undefined).buffer), GOLDEN.disconnected);
  });

  it('createTrayIcon hands the RGBA buffer to nativeImage', () => {
    const calls = [];
    const nativeImage = { createFromBuffer: (buf, opts) => { calls.push([buf, opts]); return 'img'; } };
    assert.equal(createTrayIcon(nativeImage, 'connected'), 'img');
    assert.equal(sha(calls[0][0]), GOLDEN.connected);
    assert.deepEqual(calls[0][1], { width: 32, height: 32 });
  });
});

describe('formatBytesShort', () => {
  it('formats byte counts compactly', () => {
    assert.equal(formatBytesShort(0), '0 B');
    assert.equal(formatBytesShort(-5), '0 B');
    assert.equal(formatBytesShort(undefined), '0 B');
    assert.equal(formatBytesShort(512), '512 B');
    assert.equal(formatBytesShort(1536), '1.5 KB');
    assert.equal(formatBytesShort(5 * 1024 * 1024), '5.0 MB');
    assert.equal(formatBytesShort(3 * 1024 ** 4), '3.0 TB');
  });
});

'use strict';

// The chat texts (chat.*) of the core locales: German and English have the
// same keys and the same {{placeholders}} (the Windows apps draw the Chats
// page from them).

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const de = require('../src/i18n/locales/de.json');
const en = require('../src/i18n/locales/en.json');

function flatten(obj, prefix = '', out = {}) {
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === 'object' && !Array.isArray(v)) flatten(v, key, out);
    else out[key] = String(v);
  }
  return out;
}
const placeholders = (s) => [...String(s).matchAll(/\{\{\s*(\w+)\s*\}\}/g)].map((m) => m[1]).sort();

describe('i18n chat.* (de / en)', () => {
  const d = flatten(de.chat, 'chat');
  const e = flatten(en.chat, 'chat');

  it('same keys in both languages', () => {
    assert.deepEqual(Object.keys(d).filter((k) => !(k in e)), [], 'missing in en.json');
    assert.deepEqual(Object.keys(e).filter((k) => !(k in d)), [], 'missing in de.json');
  });

  it('same placeholders', () => {
    for (const k of Object.keys(d)) assert.deepEqual(placeholders(e[k]), placeholders(d[k]), k);
  });

  it('Messenger 1.4.0 texts are there', () => {
    for (const k of ['chat.msg.unsupported', 'chat.st.yours', 'chat.poll.create', 'chat.event.create', 'chat.action.approve', 'chat.set.title', 'chat.error.blocked', 'chat.card.doorbell']) {
      assert.ok(d[k] && e[k], k);
    }
    assert.equal(d['chat.msg.unsupported'], 'Diese Nachricht braucht eine neuere App-Version');
  });
});

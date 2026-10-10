'use strict';

// SSE parsing of the push stream (utils/sse-parser.js): chunk boundaries
// anywhere (even inside a UTF-8 character or a CRLF), multi-line data,
// comments, ids, retry and the WHATWG edge cases.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { SseParser } = require('../src/utils/sse-parser');

function collect(opts = {}) {
  const out = { events: [], comments: [], retries: [] };
  const p = new SseParser({
    onEvent: (e) => out.events.push(e),
    onComment: (c) => out.comments.push(c),
    onRetry: (ms) => out.retries.push(ms),
    ...opts,
  });
  return { p, out };
}

const STREAM = [
  'event: hello',
  'data: {"keepalive_s":25,"via":"direct","topics":[{"id":"devices","label":"Geräte & Gateways"}]}',
  '',
  'id: 123',
  'event: notification',
  'data: {"seq":123,"id":45,"title":"Gateway „Zuhause“ ist offline 🚨"}',
  '',
  ': ping',
  '',
  'event: read',
  'data: {"ids":[45]}',
  '',
].join('\n') + '\n';

function expectStream(out) {
  assert.equal(out.events.length, 3);
  assert.deepEqual(out.events.map((e) => e.event), ['hello', 'notification', 'read']);
  assert.equal(JSON.parse(out.events[0].data).topics[0].label, 'Geräte & Gateways');
  assert.equal(out.events[0].id, '');
  assert.equal(out.events[1].id, '123');
  assert.equal(JSON.parse(out.events[1].data).title, 'Gateway „Zuhause“ ist offline 🚨');
  // the id persists for later events (per spec)
  assert.equal(out.events[2].id, '123');
  assert.deepEqual(out.comments, ['ping']);
}

describe('SseParser', () => {
  it('parses a whole stream in one chunk', () => {
    const { p, out } = collect();
    p.push(Buffer.from(STREAM, 'utf8'));
    expectStream(out);
  });

  it('gives the same result for every possible split into two chunks (bytes)', () => {
    const buf = Buffer.from(STREAM, 'utf8');
    for (let i = 1; i < buf.length; i++) {
      const { p, out } = collect();
      p.push(buf.subarray(0, i));
      p.push(buf.subarray(i));
      expectStream(out);
    }
  });

  it('handles byte-by-byte delivery, including multi-byte characters', () => {
    const { p, out } = collect();
    for (const b of Buffer.from(STREAM, 'utf8')) p.push(Buffer.from([b]));
    expectStream(out);
  });

  it('accepts CRLF and CR line endings, also when CRLF is split across chunks', () => {
    const crlf = STREAM.replace(/\n/g, '\r\n');
    const buf = Buffer.from(crlf, 'utf8');
    for (let i = 1; i < buf.length; i += 7) {
      const { p, out } = collect();
      p.push(buf.subarray(0, i));
      p.push(buf.subarray(i));
      expectStream(out);
    }
    const { p, out } = collect();
    p.push(STREAM.replace(/\n/g, '\r'));
    expectStream(out);
  });

  it('joins multi-line data with \\n and strips only one leading space', () => {
    const { p, out } = collect();
    p.push('data: line one\ndata:line two\ndata:  indented\n\n');
    assert.equal(out.events[0].data, 'line one\nline two\n indented');
    assert.equal(out.events[0].event, 'message');
  });

  it('drops events without data and incomplete trailing events', () => {
    const { p, out } = collect();
    p.push('event: hello\n\nid: 7\n\ndata: x');
    p.end();
    assert.equal(out.events.length, 0);
    assert.equal(p.lastEventId, '7'); // an id without data still counts
  });

  it('dispatches "data" without colon as an empty data line', () => {
    const { p, out } = collect();
    p.push('data\n\n');
    assert.deepEqual(out.events, [{ event: 'message', data: '', id: '' }]);
  });

  it('ignores ids with NUL, unknown fields and non-numeric retry', () => {
    const { p, out } = collect();
    p.push('id: 5\n\nid: 6\u00007\nfoo: bar\nretry: soon\nretry: 3000\ndata: x\n\n');
    assert.equal(out.events[0].id, '5');
    assert.deepEqual(out.retries, [3000]);
  });

  it('removes a leading BOM and keeps comment text', () => {
    const { p, out } = collect();
    p.push(Buffer.from([0xef, 0xbb]));
    p.push(Buffer.concat([Buffer.from([0xbf]), Buffer.from(':keepalive\ndata: a\n\n')]));
    assert.deepEqual(out.comments, ['keepalive']);
    assert.equal(out.events[0].data, 'a');
  });

  it('reset() forgets a half-received event but keeps the last id', () => {
    const { p, out } = collect();
    p.push('id: 9\ndata: one\n\ndata: half');
    p.reset();
    p.push('data: two\n\n');
    assert.deepEqual(out.events.map((e) => e.data), ['one', 'two']);
    assert.equal(out.events[1].id, '9');
  });

  it('throws on an endless line (memory guard)', () => {
    const { p } = collect({ maxLineBytes: 64 });
    assert.throws(() => p.push('data: ' + 'x'.repeat(100)), /sse_line_too_long/);
  });
});

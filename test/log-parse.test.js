'use strict';

// "Protokoll" page: electron-log lines → entries (time, level, message).
// Windows log files end every line with "\r\n"; stack traces belong to the
// entry above them.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { parseLogText, parseHeader, filterByPeriod } = require('../src/utils/log-parse');

const CRLF_LOG = [
  '[2026-10-24 20:58:32.553] [info]  Push connected (tunnel, control events)',
  '[2026-10-24 20:58:33.001] [warn]  Update-Check fehlgeschlagen: timeout',
  '[2026-10-24 20:58:34.250] [error] Update-Download fehlgeschlagen: ENOENT',
  'Error: ENOENT: no such file or directory',
  '    at Object.renameSync (node:fs:1032:11)',
  '',
  '[2026-10-24 20:58:35.000] [debug] details',
  '',
].join('\r\n');

describe('parseLogText', () => {
  it('splits "\\r\\n" lines into time, level and message', () => {
    const entries = parseLogText(CRLF_LOG);
    assert.equal(entries.length, 4);
    const [first, warn, err, dbg] = entries;
    assert.deepEqual(
      { date: first.date, time: first.time, ms: first.ms, level: first.level, msg: first.msg },
      { date: '2026-10-24', time: '20:58:32', ms: '553', level: 'info', msg: 'Push connected (tunnel, control events)' },
    );
    assert.equal(first.ts, new Date(2026, 9, 24, 20, 58, 32, 553).getTime());
    assert.equal(warn.level, 'warn');
    assert.equal(warn.msg, 'Update-Check fehlgeschlagen: timeout');
    assert.equal(dbg.level, 'debug');
    for (const e of entries) assert.ok(!/\r/.test(e.msg), 'no carriage return left');
    // the stack trace stays with its entry
    assert.equal(err.level, 'error');
    assert.equal(err.msg, 'Update-Download fehlgeschlagen: ENOENT\nError: ENOENT: no such file or directory\n    at Object.renameSync (node:fs:1032:11)');
  });

  it('works the same with "\\n" line ends', () => {
    const lf = parseLogText(CRLF_LOG.replace(/\r\n/g, '\n'));
    assert.deepEqual(lf, parseLogText(CRLF_LOG));
  });

  it('keeps the raw lines when asked (text output for older renderers)', () => {
    const entries = parseLogText(CRLF_LOG, { raw: true });
    assert.equal(entries[2].raw, '[2026-10-24 20:58:34.250] [error] Update-Download fehlgeschlagen: ENOENT\nError: ENOENT: no such file or directory\n    at Object.renameSync (node:fs:1032:11)');
    assert.equal(parseLogText(CRLF_LOG)[0].raw, undefined);
  });

  it('a continuation at the start (cut read window) is its own entry without time', () => {
    const entries = parseLogText('    at foo (bar.js:1:1)\r\n[2026-10-24 20:00:00.000] [info]  ok\r\n');
    assert.equal(entries.length, 2);
    assert.deepEqual({ ts: entries[0].ts, level: entries[0].level, msg: entries[0].msg }, { ts: null, level: null, msg: '    at foo (bar.js:1:1)' });
    assert.equal(entries[1].msg, 'ok');
  });

  it('empty or no text → no entries', () => {
    assert.deepEqual(parseLogText(''), []);
    assert.deepEqual(parseLogText(null), []);
    assert.deepEqual(parseLogText('\r\n\r\n'), []);
  });
});

describe('parseHeader', () => {
  it('normalizes levels and keeps unknown brackets in the message', () => {
    assert.equal(parseHeader('[2026-10-24 20:58:32.553] [WARNING] x').level, 'warn');
    assert.equal(parseHeader('[2026-10-24 20:58:32.553] [verbose] x').level, 'debug');
    const scoped = parseHeader('[2026-10-24 20:58:32.553] [main] [error] boom');
    assert.deepEqual([scoped.level, scoped.msg], ['error', '[main] boom']);
    const tagged = parseHeader('[2026-10-24 20:58:32.553] [info]  [GateDrop] sent');
    assert.deepEqual([tagged.level, tagged.msg], ['info', '[GateDrop] sent']);
    const unknown = parseHeader('[2026-10-24 20:58:32.553] [main] hello');
    assert.deepEqual([unknown.level, unknown.msg], [null, '[main] hello']);
    const bare = parseHeader('[2026-10-24T20:58:32] hello');
    assert.deepEqual([bare.level, bare.msg, bare.ms], [null, 'hello', '000']);
  });

  it('no header → null', () => {
    assert.equal(parseHeader('Error: boom'), null);
    assert.equal(parseHeader('[20:58:32] x'), null);
  });
});

describe('filterByPeriod', () => {
  it('keeps the last 1h / 12h / 24h and entries without time', () => {
    const now = new Date(2026, 9, 24, 21, 0, 0).getTime();
    const text = [
      '    at cut-off',
      '[2026-10-23 20:00:00.000] [info]  two days',
      '[2026-10-24 08:30:00.000] [info]  morning',
      '[2026-10-24 20:30:00.000] [info]  recent',
    ].join('\r\n');
    const entries = parseLogText(text);
    const msgs = (p) => filterByPeriod(entries, p, now).map((e) => e.msg);
    assert.deepEqual(msgs('1h'), ['    at cut-off', 'recent']);
    assert.deepEqual(msgs('12h'), ['    at cut-off', 'recent']);
    assert.deepEqual(msgs('24h'), ['    at cut-off', 'morning', 'recent']);
    assert.deepEqual(msgs('all'), ['    at cut-off', 'two days', 'morning', 'recent']);
    assert.deepEqual(msgs(undefined).length, 4);
  });
});

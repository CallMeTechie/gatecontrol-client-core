'use strict';

/**
 * Incremental parser for a text/event-stream (Server-Sent Events) body,
 * following the WHATWG "event stream interpretation" rules:
 *
 *   - lines end in CRLF, LF or CR (a CR at the end of one chunk and the LF at
 *     the start of the next are one line break);
 *   - UTF-8 is decoded across chunk boundaries, a leading BOM is dropped;
 *   - `data:` lines are joined with "\n", `event:` sets the type (default
 *     "message"), `id:` sets the last event id (ignored when it contains NUL;
 *     it persists across events), `retry:` (digits only) sets the reconnect
 *     time, lines starting with ":" are comments;
 *   - one space after the colon is removed, a line without a colon is a field
 *     with an empty value, unknown fields are ignored;
 *   - an empty line dispatches the event; an event without data is dropped
 *     (but its id still counts).
 *
 * Electron-free and synchronous: push(chunk) calls the callbacks before it
 * returns. A line longer than `maxLineBytes` throws (protects memory against
 * a misbehaving server); the caller drops the connection.
 */

const { StringDecoder } = require('string_decoder');

const DEFAULT_MAX_LINE = 256 * 1024;

class SseParser {
  /**
   * @param {object} [opts]
   * @param {(ev: { event: string, data: string, id: string }) => void} [opts.onEvent]
   * @param {(text: string) => void} [opts.onComment]
   * @param {(ms: number) => void} [opts.onRetry]
   * @param {number} [opts.maxLineBytes]
   */
  constructor({ onEvent, onComment, onRetry, maxLineBytes = DEFAULT_MAX_LINE } = {}) {
    this.onEvent = onEvent || (() => {});
    this.onComment = onComment || (() => {});
    this.onRetry = onRetry || (() => {});
    this.maxLineBytes = maxLineBytes;
    this.lastEventId = '';
    this.reset();
  }

  /** Forget the partial state of a stream (new connection). Keeps lastEventId. */
  reset() {
    this._decoder = new StringDecoder('utf8');
    this._buf = '';
    this._started = false;
    this._skipLf = false;
    this._type = '';
    this._data = [];
  }

  /** Feed a chunk (Buffer or string). */
  push(chunk) {
    let text = typeof chunk === 'string' ? chunk : this._decoder.write(chunk);
    if (!text) return;
    if (!this._started) {
      this._started = true;
      if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
    }
    if (this._skipLf) {
      this._skipLf = false;
      if (text[0] === '\n') text = text.slice(1);
    }
    let buf = this._buf + text;
    let start = 0;
    for (;;) {
      const cr = buf.indexOf('\r', start);
      const lf = buf.indexOf('\n', start);
      let end;
      if (cr === -1 && lf === -1) break;
      if (cr === -1) end = lf;
      else if (lf === -1) end = cr;
      else end = Math.min(cr, lf);
      const line = buf.slice(start, end);
      if (buf[end] === '\r') {
        if (end + 1 < buf.length) {
          start = buf[end + 1] === '\n' ? end + 2 : end + 1;
        } else {
          start = end + 1;
          this._skipLf = true; // CRLF split across chunks
        }
      } else {
        start = end + 1;
      }
      this._line(line);
    }
    buf = buf.slice(start);
    if (Buffer.byteLength(buf, 'utf8') > this.maxLineBytes) {
      this._buf = '';
      throw new Error('sse_line_too_long');
    }
    this._buf = buf;
  }

  /** End of stream: an incomplete event is discarded (per spec). */
  end() {
    this._decoder.end();
    this._buf = '';
    this._type = '';
    this._data = [];
  }

  _line(line) {
    if (line === '') { this._dispatch(); return; }
    if (line[0] === ':') { this.onComment(line.slice(1).replace(/^ /, '')); return; }
    const colon = line.indexOf(':');
    let field;
    let value;
    if (colon === -1) {
      field = line;
      value = '';
    } else {
      field = line.slice(0, colon);
      value = line.slice(colon + 1);
      if (value[0] === ' ') value = value.slice(1);
    }
    switch (field) {
      case 'event': this._type = value; break;
      case 'data': this._data.push(value); break;
      case 'id': if (!value.includes('\0')) this.lastEventId = value; break;
      case 'retry': if (/^\d+$/.test(value)) this.onRetry(Number(value)); break;
      default: break; // unknown field: ignored
    }
  }

  _dispatch() {
    const type = this._type || 'message';
    const data = this._data;
    this._type = '';
    this._data = [];
    if (!data.length) return;
    this.onEvent({ event: type, data: data.join('\n'), id: this.lastEventId });
  }
}

module.exports = { SseParser };

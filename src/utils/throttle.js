'use strict';

/**
 * Bandwidth limit for uploads / downloads ("Upload-/Download-Begrenzung"
 * of Drive's folder backup): one token bucket per direction, shared by every
 * stream of that direction, so two files at once together stay below the
 * limit. The rate is read on every chunk (KB/s, 0 = unlimited): a changed
 * setting applies to transfers already running.
 *
 *   const up = createLimiter(() => settings.upKBs);
 *   readStream.pipe(up.stream()).pipe(…)
 *
 * Electron-free; `now` / `sleep` are injectable for tests.
 */

const { Transform } = require('stream');

const BURST_SECONDS = 1;       // the bucket holds at most one second of bytes
const SLICE = 16 * 1024;       // chunks are passed on in pieces of ≤ 16 KiB while limited

function bytesPerSecond(kbs) {
  const n = Number(kbs);
  return Number.isFinite(n) && n > 0 ? Math.round(n * 1024) : 0;
}

/**
 * @param {() => number} getKBs - the limit in KB/s (0 / invalid = unlimited)
 * @param {object} [opts]
 * @param {() => number} [opts.now]
 * @param {(ms: number) => Promise<void>} [opts.sleep]
 */
function createLimiter(getKBs, { now = Date.now, sleep = (ms) => new Promise((r) => setTimeout(r, ms)) } = {}) {
  let tokens = 0;
  let last = now();
  let lastRate = 0;
  let queue = Promise.resolve();

  const rate = () => {
    let r = 0;
    try { r = bytesPerSecond(getKBs()); } catch { r = 0; }
    return r;
  };

  function refill(r) {
    const t = now();
    if (r !== lastRate) {
      // a new limit starts with an empty bucket (no burst of the old one)
      tokens = 0;
      lastRate = r;
      last = t;
      return;
    }
    tokens = Math.min(r * BURST_SECONDS, tokens + ((t - last) / 1000) * r);
    last = t;
  }

  /** Waits until `n` bytes may pass (more than the bucket holds: in steps). */
  async function take(n) {
    let left = n;
    while (left > 0) {
      const r = rate();
      if (!r) { lastRate = 0; return; }
      refill(r);
      const want = Math.min(left, r * BURST_SECONDS);
      if (tokens >= want) { tokens -= want; left -= want; continue; }
      await sleep(Math.max(5, Math.ceil(((want - tokens) / r) * 1000)));
    }
  }

  /** Bytes go through one after the other (fair across streams). */
  function acquire(n) {
    const run = queue.then(() => take(n));
    queue = run.catch(() => {});
    return run;
  }

  return {
    /** The limit now in bytes per second (0 = unlimited). */
    bytesPerSecond: rate,
    acquire,
    /** A pass-through stream that keeps to the limit. */
    stream() {
      return new Transform({
        transform(chunk, _enc, cb) {
          if (!rate()) { cb(null, chunk); return; }
          (async () => {
            for (let o = 0; o < chunk.length; o += SLICE) {
              const part = chunk.subarray(o, Math.min(chunk.length, o + SLICE));
              await acquire(part.length);
              this.push(part);
            }
          })().then(() => cb(), cb);
        },
      });
    },
  };
}

module.exports = { createLimiter, bytesPerSecond };

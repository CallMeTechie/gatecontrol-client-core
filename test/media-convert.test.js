'use strict';

// „Videos umwandeln“ (gatecontrol-medien 1.6.0, contract „umwandeln-apps-vertrag“): the plugin's JSON, the picture
// rule of this PC's Chromium (H.264 10-bit plays directly), the hint per state, and MediaConvert — asked together,
// kept 3 minutes, switched off for 30 minutes without the route / right / licence, „Für heute Nacht vormerken“.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const MC = require('../src/utils/media-convert');
const J = require('../src/utils/media-jellyfin');
const MediaConvert = require('../src/services/media-convert');
const { MessengerError } = require('../src/services/messenger-api');

const A = '0123456789abcdef0123456789abcdef';
const B = 'fedcba9876543210fedcba9876543210';
const C = 'aaaaaaaabbbbbbbbccccccccdddddddd';
const STATUS = '/api/v1/client/plugins/gatecontrol-medien/api/v1/convert/status';
const REQUEST = '/api/v1/client/plugins/gatecontrol-medien/api/v1/convert/request';

const refusal = (status, code) => new MessengerError(code, { status, code, body: { ok: false, code } });

describe('media-convert (pure)', () => {
  it('item ids: 32 hex digits, dashes and capitals allowed, anything else not', () => {
    assert.equal(MC.itemId('01234567-89AB-CDEF-0123-456789ABCDEF'), A);
    assert.equal(MC.itemId(` ${A} `), A);
    assert.equal(MC.itemId('m1'), null);
    assert.equal(MC.itemId(`${A}0`), null);
    assert.equal(MC.itemId(null), null);
    assert.equal(MC.itemId('../Users'), null);
  });

  it('the answer of v1/convert/status as the contract writes it; states over items; unknown fields left out', () => {
    const s = MC.statusOf({
      ok: true, v: 1, available: true,
      items: [
        { id: A, sourceId: 'jf-1', level: 'convert', reasons: ['h264_10bit'], requested: false, state: 'queued', position: 2, startsAt: '2026-11-28T00:08:00.000Z', percent: null, extra: 'x' },
        { id: B, level: 'hint', state: 'running', percent: 47.6 },
        { id: 'kaputt', state: 'done' },
        'nonsense',
      ],
      states: { [C.toUpperCase()]: { state: 'done' }, [B]: { state: 'running', percent: 48 } },
    });
    assert.equal(s.available, true);
    assert.deepEqual([...s.items.keys()].sort(), [A, C, B].sort());
    assert.deepEqual(s.items.get(A), { id: A, state: 'queued', position: 2, startsAt: Date.parse('2026-11-28T00:08:00.000Z'), percent: null, requested: false, level: 'convert' });
    assert.deepEqual(s.items.get(B), { id: B, state: 'running', position: null, startsAt: null, percent: 48, requested: false, level: 'hint' });
    assert.equal(s.items.get(C).state, 'done');
    assert.equal(s.items.get(C).level, null);
    // only states (an older form): enough
    assert.equal(MC.statusOf({ states: { [A]: { state: 'queued', position: 1 } } }).items.get(A).position, 1);
    // broken: nothing, never thrown
    assert.deepEqual(MC.statusOf(null), { available: false, items: new Map() });
    assert.deepEqual(MC.statusOf({ items: 'x', states: [] }), { available: false, items: new Map() });
    // fields only where the state has them; an unknown state counts as none
    const w = MC.statusOf({ items: [{ id: A, state: 'paused', position: 3, percent: 20, level: 'weird' }] }).items.get(A);
    assert.deepEqual(w, { id: A, state: 'none', position: null, startsAt: null, percent: null, requested: false, level: null });
    assert.equal(MC.statusOf({ items: [{ id: A, state: 'running', percent: 140 }] }).items.get(A).percent, 100);
  });

  it('the picture on this PC: H.264 plays in every bit depth; HEVC / AV1 by the decoder; old codecs, Dolby Vision and HDR on SDR not', () => {
    const caps = J.capsOf({});
    assert.equal(MC.videoProblem({ codec: 'h264', videoRangeType: 'SDR' }, caps), null, 'H.264 High 10 too: Chromium decodes it itself');
    assert.equal(MC.videoProblem({ codec: 'vp9' }, caps), null);
    assert.deepEqual(MC.videoProblem({ codec: 'hevc', videoRangeType: 'SDR' }, caps), { code: 'hevc', codec: 'hevc' });
    assert.equal(MC.videoProblem({ codec: 'hevc', videoRangeType: 'SDR' }, J.capsOf({ hevc: true })), null);
    assert.deepEqual(MC.videoProblem({ codec: 'av1' }, J.capsOf({ av1: false })), { code: 'av1', codec: 'av1' });
    assert.equal(MC.videoProblem({ codec: 'av1' }, caps), null);
    assert.deepEqual(MC.videoProblem({ codec: 'mpeg2video' }, caps), { code: 'video_codec', codec: 'mpeg2video' });
    assert.deepEqual(MC.videoProblem({ codec: 'vc1' }, caps), { code: 'video_codec', codec: 'vc1' });
    assert.deepEqual(MC.videoProblem({ codec: 'hevc', videoRangeType: 'DOVI' }, J.capsOf({ hevc: true, hdr: true })), { code: 'dovi', codec: 'hevc' });
    assert.deepEqual(MC.videoProblem({ codec: 'hevc', videoRangeType: 'HDR10', videoRange: 'HDR' }, J.capsOf({ hevc: true })), { code: 'hdr', codec: 'hevc' });
    assert.equal(MC.videoProblem({ codec: 'hevc', videoRangeType: 'HDR10' }, J.capsOf({ hevc: true, hdr: true })), null);
    assert.equal(MC.videoProblem({ codec: 'hevc', videoRangeType: 'DOVIWithHDR10' }, J.capsOf({ hevc: true, hdr: true })), null, 'the HDR10 fallback plays');
    assert.equal(MC.videoProblem(null, caps), null);
    assert.equal(MC.videoProblem({ codec: null }, caps), null);
  });

  it('the hint per state: queued, running, requested, the offer only for „convert“ with a gateway; done and unknown nothing', () => {
    const p = { code: 'dovi', codec: 'hevc' };
    const it_ = (o) => ({ id: A, state: 'none', position: null, startsAt: null, percent: null, requested: false, level: 'convert', ...o });
    assert.deepEqual(MC.hintOf(p, it_({ state: 'queued', position: 2, startsAt: 5 }), true), { kind: 'queued', position: 2, startsAt: 5 });
    assert.deepEqual(MC.hintOf(p, it_({ state: 'queued' }), false), { kind: 'queued', position: null, startsAt: null }, 'queued: shown without a gateway too');
    assert.deepEqual(MC.hintOf(p, it_({ state: 'running', percent: 47 }), true), { kind: 'running', percent: 47 });
    assert.equal(MC.hintOf(p, it_({ state: 'done' }), true), null);
    assert.deepEqual(MC.hintOf(p, it_({}), true), { kind: 'offer' });
    assert.equal(MC.hintOf(p, it_({}), false), null, 'no gateway: no button');
    assert.equal(MC.hintOf(p, it_({ level: 'hint' }), true), null, 'the NAS converts it live without trouble');
    assert.equal(MC.hintOf(p, it_({ level: 'info' }), true), null);
    assert.equal(MC.hintOf(p, it_({ level: null }), true), null);
    assert.deepEqual(MC.hintOf(p, it_({ requested: true, level: 'hint' }), false), { kind: 'requested' });
    assert.equal(MC.hintOf(null, it_({ state: 'queued' }), true), null, 'plays here directly: no hint');
    assert.equal(MC.hintOf(p, null, true), null, 'not known to the plugin');
  });

  it('switched off by 404 / 403 / the codes; a network error or 500 not; the plugin version', () => {
    assert.equal(MC.switchesOff(refusal(404, 'not_found')), true);
    assert.equal(MC.switchesOff(refusal(403, 'no_access')), true);
    assert.equal(MC.switchesOff(refusal(403, 'license_required')), true);
    assert.equal(MC.switchesOff({ code: 'plugin_unavailable' }), true);
    assert.equal(MC.switchesOff({ code: 'network' }), false);
    assert.equal(MC.switchesOff(refusal(500, 'failed')), false);
    assert.equal(MC.switchesOff(null), false);
    assert.equal(MC.versionOk('1.6.0'), true);
    assert.equal(MC.versionOk('1.12.3'), true);
    assert.equal(MC.versionOk('2.0.0'), true);
    assert.equal(MC.versionOk('1.5.9'), false);
    assert.equal(MC.versionOk('0.9.0'), false);
    assert.equal(MC.versionOk(null), true, 'not known: the route decides');
  });
});

function fakeApi(handlers) {
  const calls = [];
  return {
    calls,
    async _call(method, path, opts = {}) {
      calls.push({ method, path, opts });
      const h = handlers[`${method} ${path}`];
      if (!h) throw refusal(404, 'not_found');
      const r = await h(opts);
      if (r instanceof Error) throw r;
      return r;
    },
  };
}

const answer = (opts, by = {}) => {
  const ids = String(opts.params.items).split(',');
  return { ok: true, v: 1, available: true, items: ids.filter((id) => by[id]).map((id) => ({ id, ...by[id] })) };
};

describe('MediaConvert', () => {
  it('asked together (the detail and a season in one question), kept 3 minutes, then asked again', async () => {
    const clock = { t: 1000 };
    const by = { [A]: { level: 'convert', state: 'queued', position: 1, startsAt: '2026-11-28T00:00:00.000Z' }, [B]: { level: 'hint', state: 'running', percent: 12 } };
    const api = fakeApi({ [`GET ${STATUS}`]: (o) => answer(o, by) });
    const c = new MediaConvert({ api, now: () => clock.t, timing: { batchMs: 5 } });
    const [h, , s] = await Promise.all([c.hint(A, { code: 'dovi' }), c.prefetch([B, C]), c.states([A, B])]);
    assert.equal(api.calls.length, 1, 'one question');
    assert.deepEqual(api.calls[0].opts.params.items.split(',').sort(), [A, B, C].sort());
    assert.deepEqual(h, { kind: 'queued', position: 1, startsAt: Date.parse('2026-11-28T00:00:00.000Z') });
    assert.equal(s.available, true);
    assert.equal(s.items.get(B).percent, 12);
    // kept
    clock.t += 2 * 60 * 1000;
    await c.states([A, B, C]);
    assert.equal(api.calls.length, 1, 'C (not known to the plugin) is kept as well');
    clock.t += 61 * 1000;
    by[A] = { level: 'convert', state: 'running', percent: 3 };
    assert.deepEqual(await c.hint(A, { code: 'dovi' }), { kind: 'running', percent: 3 });
    assert.equal(api.calls.length, 2);
  });

  it('more than 100 ids: in questions of 100', async () => {
    const api = fakeApi({ [`GET ${STATUS}`]: (o) => answer(o) });
    const c = new MediaConvert({ api, timing: { batchMs: 1 } });
    const ids = Array.from({ length: 130 }, (_, i) => i.toString(16).padStart(32, '0'));
    await c.states(ids);
    assert.deepEqual(api.calls.map((x) => x.opts.params.items.split(',').length), [100, 30]);
  });

  it('no route (plugin before 1.6.0), no right, no licence: no hint and not asked again for 30 minutes', async () => {
    for (const err of [refusal(404, 'not_found'), refusal(403, 'no_access'), refusal(403, 'license_required')]) {
      const clock = { t: 0 };
      const api = fakeApi({ [`GET ${STATUS}`]: () => err });
      const c = new MediaConvert({ api, now: () => clock.t, timing: { batchMs: 1 } });
      assert.equal(await c.hint(A, { code: 'dovi' }), null);
      assert.equal(await c.hint(A, { code: 'dovi' }), null);
      assert.equal((await c.request(A)).ok, false);
      assert.equal(api.calls.length, 1, `${err.code}: asked once`);
      clock.t += 30 * 60 * 1000;
      await c.states([A]);
      assert.equal(api.calls.length, 2, 'after 30 minutes again');
    }
  });

  it('a network error: no hint, asked again next time; not enabled (plugin hidden or older): nothing asked', async () => {
    let fail = true;
    const api = fakeApi({ [`GET ${STATUS}`]: (o) => (fail ? new MessengerError('down', { code: 'network' }) : answer(o, { [A]: { level: 'convert', state: 'none' } })) });
    const c = new MediaConvert({ api, timing: { batchMs: 1 } });
    assert.equal(await c.hint(A, { code: 'dovi' }), null);
    fail = false;
    assert.deepEqual(await c.hint(A, { code: 'dovi' }), { kind: 'offer' });
    assert.equal(api.calls.length, 2);

    const off = fakeApi({ [`GET ${STATUS}`]: (o) => answer(o) });
    let on = false;
    const d = new MediaConvert({ api: off, enabled: () => on, timing: { batchMs: 1 } });
    assert.equal(await d.states([A]), null);
    assert.equal((await d.request(A)).code, 'unavailable');
    assert.equal(off.calls.length, 0);
    on = true;
    assert.notEqual(await d.states([A]), null);
    assert.equal(await d.states(['m1']), null, 'no Jellyfin item id: nothing asked');
    assert.equal(off.calls.length, 1);
  });

  it('„Für heute Nacht vormerken“: POST { itemId }, then „vorgemerkt“ (kept); a refusal comes back as its code', async () => {
    let refuse = null;
    const api = fakeApi({
      [`GET ${STATUS}`]: (o) => answer(o, { [A]: { level: 'convert', state: 'none' } }),
      [`POST ${REQUEST}`]: () => refuse || { ok: true, v: 1, requested: true, requestedAt: '2026-11-27T20:00:00.000Z', state: 'none', position: null, startsAt: null, percent: null },
    });
    const c = new MediaConvert({ api, timing: { batchMs: 1 } });
    assert.deepEqual(await c.hint(A, { code: 'dovi' }), { kind: 'offer' });
    assert.deepEqual(await c.request(A.toUpperCase()), { ok: true, hint: { kind: 'requested' } });
    assert.deepEqual(api.calls[1].opts.body, { itemId: A });
    assert.deepEqual(await c.hint(A, { code: 'dovi' }), { kind: 'requested' }, 'kept, not asked again');
    assert.equal(api.calls.length, 2);
    refuse = refusal(429, 'rate_limited');
    assert.deepEqual(await c.request(B), { ok: false, code: 'rate_limited' });
    refuse = refusal(404, 'not_found');
    assert.deepEqual(await c.request(B), { ok: false, code: 'not_found' });
    assert.deepEqual(await c.hint(A, { code: 'dovi' }), { kind: 'requested' }, 'a file without a finding does not switch it off');
    assert.deepEqual(await c.request('m1'), { ok: false, code: 'invalid' });
    c.reset();
    await c.states([A]);
    assert.equal(api.calls.filter((x) => x.method === 'GET').length, 2, 'reset: asked again');
  });
});

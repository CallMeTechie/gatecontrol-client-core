/*
 * GateControl – Fernzugriff stage 7: the capture of "Bildschirm teilen" (the hidden window, capture.html).
 *
 * One display (a source id of desktopCapturer, chosen by the main process) → getUserMedia (chromeMediaSource desktop)
 * → MediaStreamTrackProcessor → WebCodecs VideoEncoder, H.264 Annex B, realtime: the GPU first (Media Foundation),
 * then the software encoder (GCH264.encoderConfigs). Every key frame carries SPS/PPS (GCH264.withParamSets). A key frame
 * every 2 s and on request; when the picture stands still, the last frame is encoded again after 1 s so a viewer
 * that comes later gets a picture. Nothing leaves this window but the encoded chunks — to the main process, which
 * sends them to GateControl's relay.
 */
(function () {
  'use strict';
  var H = window.GCH264;
  var api = window.gcCapture;
  var KEY_EVERY_MS = 2000;
  var STILL_MS = 1000;

  var run = null; // { stream, track, reader, encoder, config, opts, lastKey, lastEnc, last, wantKey, cache, sentConfig, stopped }

  function post(m) { try { api.post(m); } catch (e) { /* the window goes */ } }
  function fail(code) { post({ t: 'error', code: code }); stop(); }

  function pick(width, height, opts) {
    var list = H.encoderConfigs(width, height, opts);
    var i = 0;
    function next() {
      if (i >= list.length) return Promise.resolve(null);
      var c = list[i++];
      return window.VideoEncoder.isConfigSupported(c).then(function (r) { return r && r.supported ? c : next(); }, next);
    }
    return next();
  }

  function onChunk(chunk) {
    if (!run || run.stopped) return;
    var u8 = new Uint8Array(chunk.byteLength);
    chunk.copyTo(u8);
    var x = H.withParamSets(u8, run.cache);
    var key = chunk.type === 'key' || x.key;
    if (!run.sentConfig && x.codec) {
      run.sentConfig = true;
      post({ t: 'config', codec: x.codec, width: run.config.width, height: run.config.height });
    }
    if (!run.sentConfig) return; // nothing a viewer could decode yet
    post({ t: 'chunk', key: key, ts: chunk.timestamp, data: x.data });
  }

  function makeEncoder(config) {
    var enc = new window.VideoEncoder({ output: onChunk, error: function () { fail('encoder_failed'); } });
    enc.configure(config);
    return enc;
  }

  function encode(frame, now) {
    var r = run;
    if (!r || r.stopped || !r.encoder || r.encoder.state !== 'configured') return;
    // the encoder cannot keep up: drop this frame (the next one comes soon)
    if (r.encoder.encodeQueueSize > 2) return;
    var key = r.wantKey || now - r.lastKey >= KEY_EVERY_MS;
    try {
      r.encoder.encode(frame, { keyFrame: key });
      r.lastEnc = now;
      if (key) { r.lastKey = now; r.wantKey = false; }
    } catch (e) { fail('encoder_failed'); }
  }

  /** The picture size changed (another resolution of the display): a new encoder, a new config. */
  function resize(w, h) {
    var r = run;
    var s = H.fitSize(w, h);
    if (s.width === r.config.width && s.height === r.config.height) return Promise.resolve(true);
    return pick(s.width, s.height, r.opts).then(function (c) {
      if (!c || !run || run !== r) { if (!c) fail('encoder_unavailable'); return false; }
      try { r.encoder.close(); } catch (e) { /* closed */ }
      r.config = c;
      r.cache = {};
      r.sentConfig = false;
      r.wantKey = true;
      r.encoder = makeEncoder(c);
      return true;
    });
  }

  function loop(r) {
    r.reader.read().then(function (res) {
      if (res.done || r.stopped || run !== r) { if (res.value) res.value.close(); return; }
      var frame = res.value;
      var now = performance.now();
      var w = frame.displayWidth;
      var h = frame.displayHeight;
      var next = function () {
        if (now - r.lastEnc >= 1000 / r.opts.fps - 2 || r.wantKey) encode(frame, now);
        if (r.last) r.last.close();
        r.last = frame;
        loop(r);
      };
      var s = H.fitSize(w, h);
      if (s.width !== r.config.width || s.height !== r.config.height) resize(w, h).then(next, function () { frame.close(); });
      else next();
    }, function () { if (!r.stopped) fail('capture_failed'); });
  }

  function start(m) {
    stop();
    var opts = { fps: Math.min(30, Math.max(5, m.fps || 15)), bitrate: Math.min(4000000, Math.max(300000, m.bitrate || 2000000)) };
    if (typeof window.VideoEncoder !== 'function' || typeof window.MediaStreamTrackProcessor !== 'function') { fail('encoder_unavailable'); return; }
    var r = { stopped: false, opts: opts, lastKey: 0, lastEnc: 0, last: null, wantKey: true, cache: {}, sentConfig: false, still: null };
    run = r;
    pick(m.width, m.height, opts).then(function (c) {
      if (r.stopped) return null;
      if (!c) { fail('encoder_unavailable'); return null; }
      r.config = c;
      r.encoder = makeEncoder(c);
      return navigator.mediaDevices.getUserMedia({ audio: false, video: { mandatory: {
        chromeMediaSource: 'desktop', chromeMediaSourceId: m.sourceId, maxWidth: m.width, maxHeight: m.height, maxFrameRate: opts.fps,
      } } }).then(function (stream) {
        if (r.stopped) { stream.getTracks().forEach(function (t) { t.stop(); }); return; }
        r.stream = stream;
        r.track = stream.getVideoTracks()[0];
        r.track.addEventListener('ended', function () { if (!r.stopped) fail('capture_failed'); });
        r.reader = new window.MediaStreamTrackProcessor({ track: r.track }).readable.getReader();
        // the picture stands still: encode the last frame again (a key frame every 2 s)
        r.still = setInterval(function () {
          var now = performance.now();
          if (r.last && now - r.lastEnc >= STILL_MS) encode(r.last, now);
        }, 500);
        post({ t: 'started', width: c.width, height: c.height, codec: c.codec, hardware: c.hardwareAcceleration });
        loop(r);
      });
    }).catch(function () { if (!r.stopped) fail('capture_failed'); });
  }

  function stop() {
    var r = run;
    run = null;
    if (!r) return;
    r.stopped = true;
    clearInterval(r.still);
    try { if (r.reader) r.reader.cancel(); } catch (e) { /* gone */ }
    try { if (r.stream) r.stream.getTracks().forEach(function (t) { t.stop(); }); } catch (e) { /* gone */ }
    try { if (r.encoder && r.encoder.state !== 'closed') r.encoder.close(); } catch (e) { /* closed */ }
    try { if (r.last) r.last.close(); } catch (e) { /* closed */ }
    post({ t: 'stopped' });
  }

  api.onCommand(function (m) {
    if (!m || typeof m !== 'object') return;
    if (m.t === 'start') start(m);
    else if (m.t === 'stop') stop();
    else if (m.t === 'keyframe') { if (run) run.wantKey = true; }
    else if (m.t === 'bitrate' && run && run.encoder && run.config) {
      var b = Math.min(run.opts.bitrate, Math.max(300000, Number(m.bitrate) || 0));
      if (b === run.config.bitrate) return;
      run.config = Object.assign({}, run.config, { bitrate: b });
      try { run.encoder.configure(run.config); run.wantKey = true; } catch (e) { fail('encoder_failed'); }
    }
  });
  post({ t: 'ready' });
})();

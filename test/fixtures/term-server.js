'use strict';

// A small GateControl server for the SSH terminal (app contract „Fernzugriff Stufe 3 – Apps“): the plugin's app API
// (GET devices, GET devices/<id>/tmux, POST devices/<id>/connect), the core's term-token and the WebSocket
// /api/v1/remote/ssh-tunnel speaking gc-term.v1 — the handshake and frames of RFC 6455 written out (no ws package).
//
//   const srv = await termServer();
//   srv.url, srv.connects (bodies), srv.tokens (count), srv.sockets (open ones: { send(obj|Buffer), close(), drop() }),
//   srv.onHello = (sock, hello) => …  (default: ready with tmux and recording false), srv.received (frames),
//   srv.fail(path, status, code, times), srv.close()

const http = require('node:http');
const crypto = require('node:crypto');

const PLUGIN = '/api/v1/client/plugins/gatecontrol-remote/api/';
const REF = 'R'.repeat(43);

function frame(op, payload) {
  const len = payload.length;
  const head = len < 126 ? Buffer.from([0x80 | op, len]) : len < 65536 ? Buffer.from([0x80 | op, 126, len >> 8, len & 255]) : null;
  if (!head) throw new Error('too long for the test server');
  return Buffer.concat([head, payload]);
}

async function termServer() {
  const state = {
    connects: [], tokens: 0, sockets: [], received: [], failures: new Map(), protocols: [], urls: [],
    onHello: (sock) => sock.send({ t: 'ready', hostKey: { alg: 'ssh-ed25519', sha256: 'x'.repeat(43) }, hostKeyNew: false, tmux: { available: true, session: 'tmux' }, recording: false, mode: 'control' }),
  };
  const json = (res, status, body) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); };
  const failed = (p, res) => {
    const f = state.failures.get(p);
    if (!f || f.times <= 0) return false;
    f.times -= 1;
    json(res, f.status, { ok: false, error: f.code });
    return true;
  };

  const server = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (c) => { raw += c; });
    req.on('end', () => {
      const body = raw ? JSON.parse(raw) : {};
      const p = req.url.split('?')[0];
      if (failed(p, res)) return;
      if (p === PLUGIN + 'devices' && req.method === 'GET') {
        return json(res, 200, { devices: [
          { id: 1, name: 'Büro-PC', protocol: 'rdp', online: true },
          { id: 2, name: 'pi-werkstatt', protocol: 'ssh', online: true, engine: 'term', tmux: 'tmux', recording: 'optional', tags: ['Werkstatt'] },
          { id: 3, name: 'nas-keller', protocol: 'ssh', online: true, engine: 'guac' },
        ], rights: { ssh: true } });
      }
      if (p === PLUGIN + 'devices/2/tmux') {
        return json(res, 200, { sessions: [
          { name: 'build', windows: 1, attached: 1, activity: '2026-11-16T09:00:00Z', attachable: true },
          { name: 'tmux', windows: 3, attached: 0, activity: '2026-11-16T09:58:00Z', attachable: true },
          { name: 'backup.alt', windows: 1, attached: 0, attachable: false },
        ], tmux: 'tmux', hostKey: 'pinned' });
      }
      if (p === PLUGIN + 'devices/2/connect' && req.method === 'POST') {
        state.connects.push(body);
        const tm = body.tmux || { create: 'tmux' };
        return json(res, 200, { session: { ref: REF, expiresAt: new Date(Date.now() + 120000).toISOString(), engine: 'term', recording: body.record === true, tmux: tm, device: { id: 2, name: 'pi-werkstatt' } } });
      }
      if (p === '/api/v1/client/remote/term-token' && req.method === 'POST') {
        if (body.ref !== REF) return json(res, 404, { ok: false, error: 'not_found' });
        state.tokens += 1;
        return json(res, 200, { ok: true, token: ('T' + state.tokens).padEnd(43, 'x'), wsPath: '/api/v1/remote/ssh-tunnel', ttl: 60 });
      }
      json(res, 404, { ok: false, error: 'not_found' });
    });
  });

  server.on('upgrade', (req, socket) => {
    state.urls.push(req.url);
    const offered = String(req.headers['sec-websocket-protocol'] || '').split(',').map((x) => x.trim());
    state.protocols.push(offered);
    const tok = offered.find((x) => x.startsWith('token.'));
    if (req.url !== '/api/v1/remote/ssh-tunnel' || !offered.includes('gc-term.v1') || !tok) {
      socket.end('HTTP/1.1 401 Unauthorized\r\n\r\n');
      return;
    }
    const accept = crypto.createHash('sha1').update(req.headers['sec-websocket-key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\nSec-WebSocket-Protocol: gc-term.v1\r\n\r\n`);
    const sock = {
      send(o) { try { socket.write(Buffer.isBuffer(o) ? frame(2, o) : frame(1, Buffer.from(JSON.stringify(o)))); } catch { /* gone */ } },
      close() { try { socket.write(frame(8, Buffer.from([0x03, 0xe8]))); socket.end(); } catch { /* gone */ } },
      /** Gone without a close frame (a dead spot). */
      drop() { socket.destroy(); },
      token: tok.slice(6),
    };
    state.sockets.push(sock);
    let buf = Buffer.alloc(0);
    socket.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      while (buf.length >= 2) {
        const op = buf[0] & 15;
        let len = buf[1] & 127;
        let off = 2;
        if (len === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); off = 4; }
        if (len === 127) { if (buf.length < 10) return; len = Number(buf.readBigUInt64BE(2)); off = 10; }
        if (buf.length < off + 4 + len) return;
        const mask = buf.subarray(off, off + 4);
        const data = Buffer.from(buf.subarray(off + 4, off + 4 + len));
        for (let i = 0; i < data.length; i++) data[i] ^= mask[i % 4];
        buf = buf.subarray(off + 4 + len);
        if (op === 8) { try { socket.write(frame(8, data.subarray(0, 2))); socket.end(); } catch { /* gone */ } return; }
        if (op === 9) { socket.write(frame(10, data)); continue; }
        if (op === 1) {
          const m = JSON.parse(data.toString('utf8'));
          state.received.push(m);
          if (m.t === 'hello') state.onHello(sock, m);
          if (m.t === 'ping') sock.send({ t: 'pong' });
          if (m.t === 'bye') { sock.send({ t: 'exit', code: null, reason: 'client' }); sock.close(); }
        } else if (op === 2) state.received.push({ bin: data.toString('utf8') });
      }
    });
    socket.on('error', () => {});
  });

  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return Object.assign(state, {
    url: `http://127.0.0.1:${server.address().port}`,
    REF,
    fail(p, status, code, times = 1) { state.failures.set(p, { status, code, times }); },
    close() {
      for (const s of state.sockets) s.drop();
      return new Promise((r) => server.close(() => r()));
    },
  });
}

module.exports = { termServer, PLUGIN, REF };

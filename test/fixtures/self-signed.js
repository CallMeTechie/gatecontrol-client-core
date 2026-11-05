'use strict';

// A self-signed certificate exactly as the home gateway makes one for its cache endpoint
// (gatecontrol-gateway src/cache/selfsigned.js: EC P-256, no CA, keyUsage digitalSignature, serverAuth, no name):
// the tests of the home cache pin it like the apps do.

const crypto = require('node:crypto');

function derLength(n) {
  if (n < 0x80) return Buffer.from([n]);
  const bytes = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v % 256);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
const tlv = (tag, content) => Buffer.concat([Buffer.from([tag]), derLength(content.length), content]);
const seq = (...items) => tlv(0x30, Buffer.concat(items));
const derSet = (...items) => tlv(0x31, Buffer.concat(items));
const derInt = (buf) => tlv(0x02, buf);
const bitString = (buf) => tlv(0x03, Buffer.concat([Buffer.from([0x00]), buf]));
const octetString = (buf) => tlv(0x04, buf);
const utf8 = (s) => tlv(0x0c, Buffer.from(s, 'utf8'));

function time(d) {
  const p = (n) => String(n).padStart(2, '0');
  const body = `${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
  const y = d.getUTCFullYear();
  // RFC 5280: bis 2049 UTCTime, danach GeneralizedTime
  return y < 2050 ? tlv(0x17, Buffer.from(`${p(y % 100)}${body}`, 'ascii')) : tlv(0x18, Buffer.from(`${y}${body}`, 'ascii'));
}

function oid(dotted) {
  const parts = dotted.split('.').map(Number);
  const out = [40 * parts[0] + parts[1]];
  for (const part of parts.slice(2)) {
    const stack = [];
    for (let v = part; ; v = Math.floor(v / 128)) {
      stack.unshift(v % 128);
      if (v < 128) break;
    }
    out.push(...stack.map((b, i) => (i === stack.length - 1 ? b : b | 0x80)));
  }
  return tlv(0x06, Buffer.from(out));
}

const ECDSA_SHA256 = seq(oid('1.2.840.10045.4.3.2'));

function ipBytes(ip) {
  if (ip.includes(':')) {
    const [head, tail = ''] = ip.split('::');
    const h = head ? head.split(':') : [];
    const t = tail ? tail.split(':') : [];
    const groups = ip.includes('::') ? [...h, ...Array(8 - h.length - t.length).fill('0'), ...t] : h;
    return Buffer.from(groups.flatMap((g) => { const v = parseInt(g, 16); return [v >> 8, v & 255]; }));
  }
  return Buffer.from(ip.split('.').map(Number));
}

/**
 * → { cert (PEM), key (PEM), sha256 (hex, klein, über DER) }
 * altNames: [{ dns }|{ ip }] (optional; Tests, Diagnose)
 */
function makeSelfSigned({ commonName = 'GateControl Gateway', days = 3650, altNames = [] } = {}) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const name = seq(derSet(seq(oid('2.5.4.3'), utf8(commonName))));
  const notBefore = new Date(Date.now() - 86_400_000);
  const notAfter = new Date(Date.now() + days * 86_400_000);
  const exts = [
    seq(oid('2.5.29.19'), octetString(seq())), // basicConstraints: kein CA
    seq(oid('2.5.29.15'), tlv(0x01, Buffer.from([0xff])), octetString(tlv(0x03, Buffer.from([0x07, 0x80])))), // keyUsage digitalSignature (kritisch)
    seq(oid('2.5.29.37'), octetString(seq(oid('1.3.6.1.5.5.7.3.1')))), // extKeyUsage serverAuth
  ];
  if (altNames.length) {
    const gn = altNames.map((a) => (a.ip ? tlv(0x87, ipBytes(a.ip)) : tlv(0x82, Buffer.from(a.dns, 'ascii'))));
    exts.push(seq(oid('2.5.29.17'), octetString(seq(...gn))));
  }
  const tbs = seq(
    tlv(0xa0, derInt(Buffer.from([0x02]))),
    derInt(Buffer.concat([Buffer.from([crypto.randomBytes(1)[0] & 0x7f | 0x01]), crypto.randomBytes(15)])),
    ECDSA_SHA256,
    name,
    seq(time(notBefore), time(notAfter)),
    name,
    spki,
    tlv(0xa3, seq(...exts)),
  );
  const der = seq(tbs, ECDSA_SHA256, bitString(crypto.sign('sha256', tbs, privateKey)));
  const cert = '-----BEGIN CERTIFICATE-----\n' + der.toString('base64').match(/.{1,64}/g).join('\n') + '\n-----END CERTIFICATE-----\n';
  return {
    cert,
    key: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    sha256: crypto.createHash('sha256').update(der).digest('hex'),
  };
}

module.exports = { makeSelfSigned };

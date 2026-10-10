'use strict';

/**
 * GateControl – Support bundle redaction (Core)
 *
 * Every string that goes into a support bundle passes through here before it
 * leaves the machine. The server repeats the same rules once more
 * (gatecontrol src/utils/supportRedact.js), the Android client has a port
 * (SupportRedactor). Keep the three in sync.
 *
 *   - object keys that name a secret (password, token, apiKey, privateKey,
 *     presharedKey, secret, cookie, authorization, setup/enrollment code,
 *     credential, machine key) → value "[REDACTED]"
 *   - WireGuard "PrivateKey = …" / "PresharedKey = …" lines
 *   - Authorization / Proxy-Authorization / Cookie / Set-Cookie /
 *     X-API-Token / X-API-Key header values
 *   - key=value / "key": "value" pairs with a secret-like key name
 *   - GateControl API tokens (gc_…), JWTs, PEM private key blocks,
 *     WireGuard-style base64 keys (44 chars, "=" padded), hex strings of
 *     32+ chars, setup codes XXXX-XXXX-XXXX-XXXX
 *
 * All patterns are linear-time (no nested or unbounded lazy quantifiers).
 */

const MASK = '[REDACTED]';
const UNSAFE_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

const SECRET_KEY_RE = /(pass(word|wd|phrase)?|pwd|secret|token|api[-_]?key|apikey|private[-_]?key|preshared[-_]?key|psk|cookie|authori[sz]ation|credential|enrol(l)?ment[-_]?code|setup[-_]?code|machine[-_]?key|session[-_]?id)/i;

// Order matters: specific structures first, generic patterns last.
const TEXT_RULES = [
  // PEM private keys: everything base64 after the BEGIN line (linear, no
  // lazy scan to the END line), plus long base64 lines (encrypted PEM bodies)
  [/(-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----)[A-Za-z0-9+/=\s]*/g, `$1${MASK}\n`],
  [/^[A-Za-z0-9+/]{60,}={0,2}$/gm, MASK],
  // WireGuard config secrets
  [/^(\s*(?:PrivateKey|PresharedKey)\s*=\s*).*$/gim, `$1${MASK}`],
  // HTTP auth / cookie headers (log lines, dumped requests)
  [/((?:proxy-)?authorization["']?\s*[:=]\s*["']?)(?:(?:bearer|basic|digest|token)\s+)?[^\s"',;]+/gi, `$1${MASK}`],
  [/((?:set-)?cookie["']?\s*[:=]\s*["']?)[^\r\n"']+/gi, `$1${MASK}`],
  [/(x-api-(?:token|key)["']?\s*[:=]\s*["']?)[^\s"',;]+/gi, `$1${MASK}`],
  // key=value and "key": "value" with a secret-like key name
  [/\b([A-Za-z0-9_-]{0,40}?(?:password|passwd|pwd|secret|token|api[-_]?key|apikey|private[-_]?key|preshared[-_]?key|psk|enrol(?:l)?ment[-_]?code|setup[-_]?code|credential)s?["']?\s*[:=]\s*["']?)(?!\[REDACTED\])[^\s"'&,;}]+/gi, `$1${MASK}`],
  // Free-standing secrets
  [/\bgc_[A-Za-z0-9_-]{6,}/g, `gc_${MASK}`],
  [/\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}/g, MASK],
  [/(^|[^A-Za-z0-9+/])[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=(?![A-Za-z0-9+/=])/g, `$1${MASK}`],
  [/\b[A-Fa-f0-9]{32,}\b/g, MASK],
  [/\b[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}\b/g, MASK],
];

function redactText(input) {
  if (typeof input !== 'string' || input === '') return input;
  let out = input;
  for (const [re, replacement] of TEXT_RULES) out = out.replace(re, replacement);
  return out;
}

function isSecretKey(key) {
  return typeof key === 'string' && SECRET_KEY_RE.test(key);
}

/**
 * Deep copy of `value` with every secret masked. Object keys naming a
 * secret lose their value (non-empty strings/numbers → "[REDACTED]",
 * nested objects are dropped to "[REDACTED]" as well); all other strings
 * go through redactText.
 */
function redactValue(value, depth = 0) {
  if (depth > 32) return MASK;
  if (typeof value === 'string') return redactText(value);
  if (Array.isArray(value)) return value.map((v) => redactValue(v, depth + 1));
  if (value && typeof value === 'object') {
    // Built with Object.fromEntries (own data properties, no assignment
    // through the prototype chain); prototype-related keys are dropped.
    return Object.fromEntries(Object.entries(value)
      .filter(([k]) => !UNSAFE_KEYS.has(k))
      .map(([k, v]) => [k, isSecretKey(k) && v !== null && v !== '' && typeof v !== 'boolean'
        ? MASK
        : redactValue(v, depth + 1)]));
  }
  return value;
}

module.exports = { redactText, redactValue, isSecretKey, MASK };

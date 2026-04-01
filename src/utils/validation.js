'use strict';

const IPV4_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
const CIDR_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/;
const INT_RE = /^\d+$/;
const PORT_RE = /^\d{1,5}$/;
const IFACE_NAME_RE = /^[a-zA-Z0-9_\- ]+$/;

function validateIp(val) {
  if (!IPV4_RE.test(val)) throw new Error(`Ungültige IP-Adresse: ${val}`);
  const parts = val.split('.').map(Number);
  if (parts.some(p => p < 0 || p > 255)) throw new Error(`IP-Adresse außerhalb des Bereichs: ${val}`);
  return val;
}

function validateCidr(val) {
  if (!CIDR_RE.test(val)) throw new Error(`Ungültige CIDR-Notation: ${val}`);
  const [ip, prefix] = val.split('/');
  validateIp(ip);
  const p = parseInt(prefix, 10);
  if (p < 0 || p > 32) throw new Error(`Ungültige CIDR-Prefix-Länge: ${val}`);
  return val;
}

function validateInt(val) {
  const s = String(val);
  if (!INT_RE.test(s)) throw new Error(`Ungültiger Integer: ${val}`);
  return s;
}

function validatePort(val) {
  if (!PORT_RE.test(String(val))) throw new Error(`Ungültiger Port: ${val}`);
  return String(val);
}

function validateIfaceName(val) {
  if (!IFACE_NAME_RE.test(val)) throw new Error(`Ungültiger Interface-Name: ${val}`);
  return val;
}

module.exports = {
  IPV4_RE, CIDR_RE, INT_RE, PORT_RE, IFACE_NAME_RE,
  validateIp, validateCidr, validateInt, validatePort, validateIfaceName,
};

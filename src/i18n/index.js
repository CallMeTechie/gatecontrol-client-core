'use strict';

/**
 * i18n translation engine for @gatecontrol/client-core
 *
 * Supports dot-notation keys, {{ variable }} interpolation, and runtime locale switching.
 * Fallback chain: current locale → German → key itself
 */

const fs   = require('fs');
const path = require('path');

// ── Constants ────────────────────────────────────────────────
const SUPPORTED_LOCALES = ['de', 'en'];
const DEFAULT_LOCALE    = 'de';

// ── Internal state ───────────────────────────────────────────
let currentLocale = DEFAULT_LOCALE;
const translations = {};    // { locale: { 'dot.key': 'value' } }
const listeners    = new Set();

// ── Helpers ──────────────────────────────────────────────────

/**
 * Flatten a nested object to dot-notation keys.
 * { status: { connected: 'X' } } → { 'status.connected': 'X' }
 */
function flatten(obj, prefix, result) {
  prefix = prefix || '';
  result = result || {};
  for (const key of Object.keys(obj)) {
    const fullKey = prefix ? prefix + '.' + key : key;
    const val     = obj[key];
    if (val !== null && typeof val === 'object' && !Array.isArray(val)) {
      flatten(val, fullKey, result);
    } else {
      result[fullKey] = String(val);
    }
  }
  return result;
}

/**
 * Interpolate {{ variable }} placeholders in a string.
 */
function interpolate(str, params) {
  if (!params || typeof params !== 'object') return str;
  return str.replace(/\{\{\s*(\w+)\s*\}\}/g, function (_, key) {
    return Object.prototype.hasOwnProperty.call(params, key) ? String(params[key]) : '{{ ' + key + ' }}';
  });
}

// ── Load built-in locale files at module load ────────────────
(function loadSharedLocales() {
  for (const locale of SUPPORTED_LOCALES) {
    const filePath = path.join(__dirname, 'locales', locale + '.json');
    try {
      const raw  = fs.readFileSync(filePath, 'utf8');
      const data = JSON.parse(raw);
      translations[locale] = flatten(data);
    } catch (err) {
      translations[locale] = {};
    }
  }
})();

// ── Public API ───────────────────────────────────────────────

/**
 * Translate a dot-notation key with optional interpolation params.
 * Fallback chain: current locale → 'de' → key itself
 */
function t(key, params) {
  const locale  = currentLocale;
  const strings = translations[locale] || {};
  let   value   = strings[key];

  if (value === undefined && locale !== DEFAULT_LOCALE) {
    const fallback = translations[DEFAULT_LOCALE] || {};
    value = fallback[key];
  }

  if (value === undefined) {
    value = key;
  }

  return interpolate(value, params);
}

/**
 * Switch the active locale and notify all listeners.
 */
function setLocale(locale) {
  if (!SUPPORTED_LOCALES.includes(locale)) {
    locale = DEFAULT_LOCALE;
  }
  currentLocale = locale;
  for (const cb of listeners) {
    try { cb(locale); } catch (_) { /* ignore listener errors */ }
  }
}

/**
 * Return the current locale string.
 */
function getLocale() {
  return currentLocale;
}

/**
 * Register a listener that fires whenever the locale changes.
 * Returns an unsubscribe function.
 */
function onLocaleChange(callback) {
  listeners.add(callback);
  return function unsubscribe() {
    listeners.delete(callback);
  };
}

/**
 * Merge additional translation strings for a locale.
 * Useful for client-specific keys on top of the shared base.
 * Accepts both flat and nested objects.
 */
function registerTranslations(locale, strings) {
  if (!translations[locale]) {
    translations[locale] = {};
  }
  const flat = flatten(strings);
  Object.assign(translations[locale], flat);
}

/**
 * Map a system locale string (e.g. 'de-DE', 'en-US') to a supported locale.
 * Falls back to 'en' for unknown locales.
 */
function resolveLocale(systemLocale) {
  if (!systemLocale || typeof systemLocale !== 'string') return 'en';
  const base = systemLocale.split('-')[0].toLowerCase();
  return SUPPORTED_LOCALES.includes(base) ? base : 'en';
}

/**
 * Return the list of supported locale codes.
 */
function getSupportedLocales() {
  return SUPPORTED_LOCALES.slice();
}

// ── Exports ──────────────────────────────────────────────────
module.exports = {
  t,
  setLocale,
  getLocale,
  onLocaleChange,
  registerTranslations,
  resolveLocale,
  getSupportedLocales,
};

'use strict';

/**
 * Mails in the dark (as the Outlook app shows them while it is dark): the colours of a mail's HTML — already
 * cleaned by the server — are changed before it is shown, never by a script in the frame. The Android app does
 * the same with the same rule (mail/MailDark.kt; both have the same test cases).
 *
 * The rule:
 *  1. A colour is taken into OKLab (L the lightness 0…1, a/b its hue and chroma).
 *  2. Backgrounds (background*, bgcolor, borders, outlines, shadows): lighter than the middle between the dark
 *     page and white (P_BG = (1 + L_BG) / 2) their lightness is mirrored, L' = L_BG + (1 − L), a/b stay and get the
 *     tint of the page (white → exactly the page #161B22, light grey → a little lighter, light yellow → dark yellow).
 *     Darker backgrounds stay as they are.
 *  3. Text (color, <font color>, body text/link): darker than the middle (P_TX = 0.5) it turns light,
 *     L' = L_TX − (L_TX − P_TX) · (L / P_TX)³ — black → exactly the app's text #E6EAF0 (a/b get its tint), the usual
 *     dark greys of newsletters (#333) nearly as light, a grey near the middle stays about as it is. Lighter text
 *     stays.
 *  4. A colour outside sRGB loses chroma until it fits (lightness and hue stay).
 *  5. Contrast (WCAG): text keeps at least 4.5 : 1 against its background — the background of the same element
 *     or CSS rule (then at most the contrast it had before), else the page. Missing contrast: the lightness moves
 *     in steps of 0.01 away from the background (hue stays) until it is reached.
 *  6. Alpha stays; transparent, currentColor, inherit and pictures (url(…)) stay; <img> is never touched.
 *  7. What has no colour of its own gets the page's colours by CSS (page #161B22, text #E6EAF0, links #79B8FF).
 */

/** The dark page: the app's panel, text and link colours (Pro: --panel, --text, --info). */
const DARK = Object.freeze({ bg: '#161b22', text: '#e6eaf0', link: '#79b8ff', muted: '#a6afbc', line: '#353e4b', placeholder: '#1e242d' });
const MIN_CONTRAST = 4.5;
const STEP = 0.01;

// ── Colours ─────────────────────────────────────────────────

const NAMED = (() => {
  const raw = 'aliceblue:f0f8ff antiquewhite:faebd7 aqua:00ffff aquamarine:7fffd4 azure:f0ffff beige:f5f5dc bisque:ffe4c4 black:000000 '
    + 'blanchedalmond:ffebcd blue:0000ff blueviolet:8a2be2 brown:a52a2a burlywood:deb887 cadetblue:5f9ea0 chartreuse:7fff00 '
    + 'chocolate:d2691e coral:ff7f50 cornflowerblue:6495ed cornsilk:fff8dc crimson:dc143c cyan:00ffff darkblue:00008b '
    + 'darkcyan:008b8b darkgoldenrod:b8860b darkgray:a9a9a9 darkgreen:006400 darkgrey:a9a9a9 darkkhaki:bdb76b darkmagenta:8b008b '
    + 'darkolivegreen:556b2f darkorange:ff8c00 darkorchid:9932cc darkred:8b0000 darksalmon:e9967a darkseagreen:8fbc8f '
    + 'darkslateblue:483d8b darkslategray:2f4f4f darkslategrey:2f4f4f darkturquoise:00ced1 darkviolet:9400d3 deeppink:ff1493 '
    + 'deepskyblue:00bfff dimgray:696969 dimgrey:696969 dodgerblue:1e90ff firebrick:b22222 floralwhite:fffaf0 forestgreen:228b22 '
    + 'fuchsia:ff00ff gainsboro:dcdcdc ghostwhite:f8f8ff gold:ffd700 goldenrod:daa520 gray:808080 green:008000 greenyellow:adff2f '
    + 'grey:808080 honeydew:f0fff0 hotpink:ff69b4 indianred:cd5c5c indigo:4b0082 ivory:fffff0 khaki:f0e68c lavender:e6e6fa '
    + 'lavenderblush:fff0f5 lawngreen:7cfc00 lemonchiffon:fffacd lightblue:add8e6 lightcoral:f08080 lightcyan:e0ffff '
    + 'lightgoldenrodyellow:fafad2 lightgray:d3d3d3 lightgreen:90ee90 lightgrey:d3d3d3 lightpink:ffb6c1 lightsalmon:ffa07a '
    + 'lightseagreen:20b2aa lightskyblue:87cefa lightslategray:778899 lightslategrey:778899 lightsteelblue:b0c4de '
    + 'lightyellow:ffffe0 lime:00ff00 limegreen:32cd32 linen:faf0e6 magenta:ff00ff maroon:800000 mediumaquamarine:66cdaa '
    + 'mediumblue:0000cd mediumorchid:ba55d3 mediumpurple:9370db mediumseagreen:3cb371 mediumslateblue:7b68ee '
    + 'mediumspringgreen:00fa9a mediumturquoise:48d1cc mediumvioletred:c71585 midnightblue:191970 mintcream:f5fffa '
    + 'mistyrose:ffe4e1 moccasin:ffe4b5 navajowhite:ffdead navy:000080 oldlace:fdf5e6 olive:808000 olivedrab:6b8e23 '
    + 'orange:ffa500 orangered:ff4500 orchid:da70d6 palegoldenrod:eee8aa palegreen:98fb98 paleturquoise:afeeee '
    + 'palevioletred:db7093 papayawhip:ffefd5 peachpuff:ffdab9 peru:cd853f pink:ffc0cb plum:dda0dd powderblue:b0e0e6 '
    + 'purple:800080 rebeccapurple:663399 red:ff0000 rosybrown:bc8f8f royalblue:4169e1 saddlebrown:8b4513 salmon:fa8072 '
    + 'sandybrown:f4a460 seagreen:2e8b57 seashell:fff5ee sienna:a0522d silver:c0c0c0 skyblue:87ceeb slateblue:6a5acd '
    + 'slategray:708090 slategrey:708090 snow:fffafa springgreen:00ff7f steelblue:4682b4 tan:d2b48c teal:008080 '
    + 'thistle:d8bfd8 tomato:ff6347 turquoise:40e0d0 violet:ee82ee wheat:f5deb3 white:ffffff whitesmoke:f5f5f5 yellow:ffff00 '
    + 'yellowgreen:9acd32';
  const m = new Map();
  for (const p of raw.split(' ')) { const [k, v] = p.split(':'); m.set(k, v); }
  return m;
})();

/** A colour of CSS or an HTML attribute → { r, g, b (0…255), a (0…1) }, null when it is none (or transparent). */
function parseColor(raw) {
  const s = String(raw == null ? '' : raw).trim().toLowerCase();
  let m = /^#?([0-9a-f]{3,4}|[0-9a-f]{6}|[0-9a-f]{8})$/.exec(s);
  if (m && (s[0] === '#' || /^[0-9a-f]{6}$/.test(s))) {
    let h = m[1];
    if (h.length <= 4) h = h.split('').map((c) => c + c).join('');
    return { r: parseInt(h.slice(0, 2), 16), g: parseInt(h.slice(2, 4), 16), b: parseInt(h.slice(4, 6), 16), a: h.length === 8 ? parseInt(h.slice(6, 8), 16) / 255 : 1 };
  }
  if (NAMED.has(s)) return parseColor(`#${NAMED.get(s)}`);
  m = /^(rgba?|hsla?)\(\s*([^)]*)\)$/.exec(s);
  if (!m) return null;
  const parts = m[2].split(/\s*[,/]\s*|\s+/).filter(Boolean);
  if (parts.length < 3 || parts.length > 4) return null;
  const num = (x) => (/^[-+]?(\d+\.?\d*|\.\d+)(e[-+]?\d+)?%?$/.test(x) ? parseFloat(x) : NaN);
  const alpha = parts.length === 4 ? (parts[3].endsWith('%') ? num(parts[3]) / 100 : num(parts[3])) : 1;
  if (Number.isNaN(alpha)) return null;
  const a = Math.min(1, Math.max(0, alpha));
  if (m[1].startsWith('rgb')) {
    const ch = parts.slice(0, 3).map((x) => (x.endsWith('%') ? num(x) * 2.55 : num(x)));
    if (ch.some((x) => Number.isNaN(x))) return null;
    const [r, g, b] = ch.map((x) => Math.round(Math.min(255, Math.max(0, x))));
    return { r, g, b, a };
  }
  const hue = parseFloat(parts[0]);
  const sat = num(parts[1]) / 100;
  const lig = num(parts[2]) / 100;
  if ([hue, sat, lig].some((x) => Number.isNaN(x)) || !parts[1].endsWith('%') || !parts[2].endsWith('%')) return null;
  const hh = (((hue % 360) + 360) % 360) / 360;
  const sl = Math.min(1, Math.max(0, sat));
  const ll = Math.min(1, Math.max(0, lig));
  const q = ll < 0.5 ? ll * (1 + sl) : ll + sl - ll * sl;
  const p = 2 * ll - q;
  const f = (t0) => {
    let t = t0;
    if (t < 0) t += 1;
    if (t > 1) t -= 1;
    if (t < 1 / 6) return p + (q - p) * 6 * t;
    if (t < 1 / 2) return q;
    if (t < 2 / 3) return p + (q - p) * (2 / 3 - t) * 6;
    return p;
  };
  return { r: Math.round(f(hh + 1 / 3) * 255), g: Math.round(f(hh) * 255), b: Math.round(f(hh - 1 / 3) * 255), a };
}

const toLinear = (c8) => { const c = c8 / 255; return c <= 0.04045 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4); };
const fromLinear = (c) => (c <= 0.0031308 ? 12.92 * c : 1.055 * Math.pow(c, 1 / 2.4) - 0.055);

/** sRGB (0…255) → OKLab { L, a, b }. */
function toLab({ r, g, b }) {
  const R = toLinear(r);
  const G = toLinear(g);
  const B = toLinear(b);
  const l = Math.cbrt(0.4122214708 * R + 0.5363325363 * G + 0.0514459929 * B);
  const m = Math.cbrt(0.2119034982 * R + 0.6806995451 * G + 0.1073969566 * B);
  const s = Math.cbrt(0.0883024619 * R + 0.2817188376 * G + 0.6299787005 * B);
  return {
    L: 0.2104542553 * l + 0.7936177850 * m - 0.0040720468 * s,
    a: 1.9779984951 * l - 2.4285922050 * m + 0.4505937099 * s,
    b: 0.0259040371 * l + 0.7827717662 * m - 0.8086757660 * s,
  };
}

/** OKLab → linear sRGB (may lie outside 0…1). */
function labToLinear(L, a, b) {
  const l = (L + 0.3963377774 * a + 0.2158037573 * b) ** 3;
  const m = (L - 0.1055613458 * a - 0.0638541728 * b) ** 3;
  const s = (L - 0.0894841775 * a - 1.2914855480 * b) ** 3;
  return [
    4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s,
    -1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s,
    -0.0041960863 * l - 0.7034186147 * m + 1.7076147010 * s,
  ];
}

const inGamut = (rgb) => rgb.every((c) => c >= -1e-7 && c <= 1 + 1e-7);

/** OKLab → sRGB (0…255): outside sRGB the chroma shrinks until it fits (lightness and hue stay). */
function fromLab(L, a, b) {
  const l = Math.min(1, Math.max(0, L));
  let lin = labToLinear(l, a, b);
  if (!inGamut(lin)) {
    let lo = 0;
    let hi = 1;
    for (let i = 0; i < 20; i += 1) {
      const mid = (lo + hi) / 2;
      if (inGamut(labToLinear(l, a * mid, b * mid))) lo = mid; else hi = mid;
    }
    lin = labToLinear(l, a * lo, b * lo);
  }
  const [r, g, bl] = lin.map((c) => Math.round(fromLinear(Math.min(1, Math.max(0, c))) * 255));
  return { r, g, b: bl };
}

/** WCAG relative luminance (0…1). */
function luminance({ r, g, b }) {
  return 0.2126 * toLinear(r) + 0.7152 * toLinear(g) + 0.0722 * toLinear(b);
}

/** WCAG contrast of two colours (1…21). */
function contrast(x, y) {
  const a = luminance(x);
  const b = luminance(y);
  return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
}

const BG = parseColor(DARK.bg);
const TEXT = parseColor(DARK.text);
const LAB_BG = toLab(BG);
const LAB_TX = toLab(TEXT);
const P_BG = (1 + LAB_BG.L) / 2;
const P_TX = 0.5;

/** A background in the dark (rule 2); the same object when it stays. */
function darkBackground(c) {
  const lab = toLab(c);
  if (lab.L <= P_BG) return c;
  return { ...fromLab(LAB_BG.L + (1 - lab.L), lab.a + LAB_BG.a, lab.b + LAB_BG.b), a: c.a };
}

/**
 * A text colour in the dark (rules 3 and 5): [bg] the background it stands on in the dark (null: the page),
 * [bgBefore] that background before (the contrast to keep is at most the one it had there).
 */
function darkText(c, bg = null, bgBefore = null) {
  const lab = toLab(c);
  let L = lab.L;
  let A = lab.a;
  let B = lab.b;
  if (L < P_TX) {
    L = LAB_TX.L - (LAB_TX.L - P_TX) * (L / P_TX) ** 3;
    A += LAB_TX.a;
    B += LAB_TX.b;
  }
  const under = bg || BG;
  const need = bg && bgBefore ? Math.min(MIN_CONTRAST, contrast(c, bgBefore)) : MIN_CONTRAST;
  let out = L === lab.L ? { r: c.r, g: c.g, b: c.b } : fromLab(L, A, B);
  if (contrast(out, under) >= need) return L === lab.L ? c : { ...out, a: c.a };
  const up = toLab(under).L < 0.5;
  for (let i = 0; i < 100; i += 1) {
    L = up ? L + STEP : L - STEP;
    if (L > 1 || L < 0) break;
    out = fromLab(L, A, B);
    if (contrast(out, under) >= need) break;
  }
  if (contrast(out, under) < need) out = up ? { r: 255, g: 255, b: 255 } : { r: 0, g: 0, b: 0 };
  return { ...out, a: c.a };
}

const hex2 = (n) => n.toString(16).padStart(2, '0');

/** A colour as CSS: #rrggbb, or rgba(r,g,b,a) with alpha (no spaces: fits an unquoted attribute too). */
function cssColor(c) {
  if (c.a < 1) return `rgba(${c.r},${c.g},${c.b},${Math.round(c.a * 1000) / 1000})`;
  return `#${hex2(c.r)}${hex2(c.g)}${hex2(c.b)}`;
}

/** One colour as text in the dark: 'bg' or 'text' (a text colour: [bg] / [bgBefore] as in darkText). */
function darkColor(raw, kind, bg = null, bgBefore = null) {
  const c = parseColor(raw);
  if (!c || c.a === 0) return raw;
  const d = kind === 'bg' ? darkBackground(c) : darkText(c, bg, bgBefore);
  return d === c ? raw : cssColor(d);
}

// ── CSS values and declarations ─────────────────────────────

const NAMED_ALT = [...NAMED.keys()].sort((x, y) => y.length - x.length).join('|');
/** Colour tokens in a CSS value (url(…) and quoted strings are skipped by the caller). */
const TOKEN_RE = new RegExp(`#[0-9a-fA-F]{3,8}\\b|\\b(?:rgba?|hsla?)\\([^()]*\\)|(?<![\\w-])(?:${NAMED_ALT})(?![\\w-])`, 'gi');
const SKIP_RE = /url\([^)]*\)|"[^"]*"|'[^']*'/gi;

/** Every colour of a CSS value changed by [fn] (pictures url(…) and strings stay). */
function mapValue(value, fn) {
  let out = '';
  let last = 0;
  const plain = (s) => s.replace(TOKEN_RE, (tok) => fn(tok));
  SKIP_RE.lastIndex = 0;
  let m;
  while ((m = SKIP_RE.exec(value)) !== null) {
    out += plain(value.slice(last, m.index)) + m[0];
    last = m.index + m[0].length;
  }
  return out + plain(value.slice(last));
}

/** The first colour of a CSS value (for the background a text stands on), null without one. */
function firstColor(value) {
  let found = null;
  mapValue(value, (tok) => { if (!found) found = parseColor(tok); return tok; });
  return found && found.a > 0 ? found : null;
}

const BG_PROP_RE = /^(background|border|outline|column-rule|box-shadow)(-|$)/;
const TEXT_PROP_RE = /^(color|text-decoration|text-decoration-color|-webkit-text-fill-color|caret-color|text-emphasis-color)$/;

/** Splits a declaration list on ';' outside brackets and strings: [{ text, prop, colon }]. */
function splitDeclarations(css) {
  const parts = [];
  let depth = 0;
  let quote = null;
  let start = 0;
  for (let i = 0; i < css.length; i += 1) {
    const ch = css[i];
    if (quote) { if (ch === quote) quote = null; continue; }
    if (ch === '"' || ch === "'") quote = ch;
    else if (ch === '(') depth += 1;
    else if (ch === ')') depth = Math.max(0, depth - 1);
    else if (ch === ';' && depth === 0) { parts.push(css.slice(start, i)); start = i + 1; }
  }
  parts.push(css.slice(start));
  return parts;
}

/**
 * A declaration list (a style attribute or a CSS rule) in the dark. [outerBg] the background of the element from
 * an attribute (bgcolor), used when the list sets none: { before, after }.
 */
function darkDeclarations(css, outerBg = null) {
  const parts = splitDeclarations(css);
  const prop = (p) => { const i = p.indexOf(':'); return i < 0 ? null : p.slice(0, i).trim().toLowerCase(); };
  let before = null;
  for (const p of parts) {
    const n = prop(p);
    if (n === 'background' || n === 'background-color') before = firstColor(p.slice(p.indexOf(':') + 1)) || before;
  }
  const own = before ? { before, after: darkBackground(before) } : outerBg;
  return parts.map((p) => {
    const n = prop(p);
    if (!n) return p;
    const i = p.indexOf(':');
    const value = p.slice(i + 1);
    if (BG_PROP_RE.test(n)) return p.slice(0, i + 1) + mapValue(value, (tok) => darkColor(tok, 'bg'));
    if (TEXT_PROP_RE.test(n)) return p.slice(0, i + 1) + mapValue(value, (tok) => darkColor(tok, 'text', own ? own.after : null, own ? own.before : null));
    return p;
  }).join(';');
}

/** A <style> block's rules in the dark (each { … } without inner braces is one declaration list). */
function darkStyleSheet(css) {
  return String(css).replace(/\{([^{}]*)\}/g, (_m, body) => `{${darkDeclarations(body)}}`);
}

// ── HTML ────────────────────────────────────────────────────

const TAG_RE = /<!--[\s\S]*?-->|<(style)\b[^>]*>[\s\S]*?<\/style\s*>|<[A-Za-z](?:[^>"']|"[^"]*"|'[^']*')*>/gi;
const ATTR_RE = /(\s+)([^\s"'=<>/`]+)(?:(\s*=\s*)("[^"]*"|'[^']*'|[^\s"'=<>`]+))?/g;
const BG_ATTRS = new Set(['bgcolor', 'bordercolor']);
const TEXT_ATTRS = new Set(['color', 'text', 'link', 'vlink', 'alink']);

const unquote = (v) => (v[0] === '"' || v[0] === "'" ? v.slice(1, -1) : v);
const requote = (v, inner) => (v[0] === '"' || v[0] === "'" ? `${v[0]}${inner}${v[0]}` : inner);
const decodeColorAttr = (v) => v.replace(/&#35;|&#x23;|&num;/gi, '#');

/** One start tag in the dark: style, bgcolor / bordercolor, color / text / link (pictures are never touched). */
function darkTag(tag) {
  const head = /^<[A-Za-z][A-Za-z0-9-]*/.exec(tag);
  if (!head || /^<img$/i.test(head[0])) return tag;
  const close = /\/?>$/.exec(tag);
  const inner = tag.slice(head[0].length, close ? tag.length - close[0].length : tag.length);
  const attrs = [];
  ATTR_RE.lastIndex = 0;
  let a;
  while ((a = ATTR_RE.exec(inner)) !== null) attrs.push({ ws: a[1], name: a[2], eq: a[3], value: a[4] });
  if (!attrs.some((x) => x.value !== undefined && (x.name.toLowerCase() === 'style' || BG_ATTRS.has(x.name.toLowerCase()) || TEXT_ATTRS.has(x.name.toLowerCase())))) return tag;
  const bgAttr = attrs.find((x) => x.name.toLowerCase() === 'bgcolor' && x.value !== undefined);
  const bgBefore = bgAttr ? parseColor(decodeColorAttr(unquote(bgAttr.value))) : null;
  const outer = bgBefore && bgBefore.a > 0 ? { before: bgBefore, after: darkBackground(bgBefore) } : null;
  // the style's own background wins over bgcolor for the text of this element
  const styleAttr = attrs.find((x) => x.name.toLowerCase() === 'style' && x.value !== undefined);
  let own = outer;
  if (styleAttr) {
    for (const p of splitDeclarations(unquote(styleAttr.value).replace(/&quot;/g, '"').replace(/&#39;/g, "'"))) {
      const i = p.indexOf(':');
      const n = i < 0 ? '' : p.slice(0, i).trim().toLowerCase();
      if (n === 'background' || n === 'background-color') {
        const c = firstColor(p.slice(i + 1));
        if (c) own = { before: c, after: darkBackground(c) };
      }
    }
  }
  const out = attrs.map((x) => {
    if (x.value === undefined) return x.ws + x.name;
    const n = x.name.toLowerCase();
    const v = unquote(x.value);
    let nv = v;
    if (n === 'style') nv = darkDeclarations(v, outer);
    else if (BG_ATTRS.has(n)) nv = darkColor(decodeColorAttr(v), 'bg');
    else if (TEXT_ATTRS.has(n)) nv = darkColor(decodeColorAttr(v), 'text', own ? own.after : null, own ? own.before : null);
    if (nv === v || (nv === decodeColorAttr(v) && n !== 'style')) return x.ws + x.name + x.eq + x.value;
    return x.ws + x.name + x.eq + requote(x.value, nv);
  });
  return head[0] + out.join('') + (close ? close[0] : '');
}

/** A mail's (cleaned) HTML in the dark: its <style> blocks, style attributes and colour attributes (rules 1–6). */
function darkHtml(html) {
  return String(html || '').replace(TAG_RE, (tag, style) => {
    if (tag.startsWith('<!--')) return tag;
    if (style) {
      const open = /^<style\b[^>]*>/i.exec(tag)[0];
      const end = /<\/style\s*>$/i.exec(tag)[0];
      return open + darkStyleSheet(tag.slice(open.length, tag.length - end.length)) + end;
    }
    return darkTag(tag);
  });
}

/** The page's own CSS in the dark (rule 7): what has no colour of its own. */
function darkPageCss() {
  return `:root{color-scheme:dark}html,body{background:${DARK.bg};color:${DARK.text}}a{color:${DARK.link}}`;
}

module.exports = {
  DARK,
  MIN_CONTRAST,
  parseColor,
  toLab,
  fromLab,
  luminance,
  contrast,
  darkBackground,
  darkText,
  darkColor,
  cssColor,
  darkDeclarations,
  darkStyleSheet,
  darkHtml,
  darkPageCss,
};

'use strict';

// Mails in the dark (utils/mail-dark.js): the colour rule — light backgrounds dark, dark text light, the hue kept,
// at least 4.5 : 1 for text — and the mail's HTML (style attributes, bgcolor / color / <font color>, <style> blocks;
// pictures never). The Android app has the same cases (MailDarkTest.kt): both follow the same rule.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const dark = require('../src/utils/mail-dark');
const mail = require('../src/utils/mail');

const c = dark.parseColor;
const hue = (x) => { const l = dark.toLab(c(x)); return Math.atan2(l.b, l.a) * 180 / Math.PI; };
const chroma = (x) => { const l = dark.toLab(c(x)); return Math.hypot(l.a, l.b); };
const hueDiff = (x, y) => { const d = Math.abs(hue(x) - hue(y)) % 360; return d > 180 ? 360 - d : d; };

describe('mail in the dark: the colour rule (same cases as the Android app)', () => {
  it('white → dark: white is the page, light greys a little lighter, darker backgrounds stay', () => {
    assert.equal(dark.darkColor('#ffffff', 'bg'), '#161b22');
    assert.equal(dark.darkColor('#FFF', 'bg'), '#161b22');
    assert.equal(dark.darkColor('white', 'bg'), '#161b22');
    assert.equal(dark.darkColor('rgb(255, 255, 255)', 'bg'), '#161b22');
    assert.equal(dark.darkColor('#f2f2f2', 'bg'), '#1f242b');
    assert.equal(dark.darkColor('#d9e8f5', 'bg'), '#1d2f40');
    assert.equal(dark.darkColor('#000000', 'bg'), '#000000');
    assert.equal(dark.darkColor('rgba(255,255,255,0.5)', 'bg'), 'rgba(22,27,34,0.5)');
  });

  it('black → light: black is the app text, dark greys nearly as light, light text stays', () => {
    assert.equal(dark.darkColor('#000000', 'text'), '#e6eaf0');
    assert.equal(dark.darkColor('black', 'text'), '#e6eaf0');
    assert.equal(dark.darkColor('#333333', 'text'), '#c1c4ca');
    assert.equal(dark.darkColor('#ffffff', 'text'), '#ffffff');
  });

  it('a brand colour stays recognisable: same hue, still coloured', () => {
    assert.equal(dark.darkColor('#e30613', 'bg'), '#e30613', 'a strong colour stays as it is');
    assert.equal(dark.darkColor('#ffe600', 'bg'), '#343000');
    assert.ok(hueDiff('#ffe600', '#343000') < 10 && chroma('#343000') > 0.05, 'yellow stays yellow');
    assert.equal(dark.darkColor('#0078d4', 'text'), '#1c85e2');
    assert.ok(hueDiff('#0078d4', '#1c85e2') < 3 && chroma('#1c85e2') > 0.15, 'the blue stays the blue');
    assert.equal(dark.darkColor('#e30613', 'text'), '#f9312c');
    assert.ok(hueDiff('#e30613', '#f9312c') < 3);
  });

  it('minimum contrast: every text colour reaches 4.5 : 1 on the page', () => {
    assert.equal(dark.darkColor('#777777', 'text'), '#838383');
    for (const x of ['#000000', '#333333', '#555555', '#666666', '#777777', '#7f7f7f', '#999999', '#0078d4', '#0563c1', '#e30613', '#00a650', '#ff9900', '#6a3fd6', 'navy', 'hsl(210, 100%, 30%)']) {
      const out = dark.darkColor(x, 'text');
      assert.ok(dark.contrast(c(out), c(dark.DARK.bg)) >= dark.MIN_CONTRAST, `${x} → ${out}`);
    }
    // on its own background: at least what it had (white on a red button stays white)
    assert.equal(dark.cssColor(dark.darkText(c('#ffffff'), c('#e30613'), c('#e30613'))), '#ffffff');
    const grey = dark.darkText(c('#999999'), dark.darkBackground(c('#ffffff')), c('#ffffff'));
    assert.ok(dark.contrast(grey, dark.darkBackground(c('#ffffff'))) >= Math.min(4.5, dark.contrast(c('#999999'), c('#ffffff'))));
  });

  it('what is no colour stays', () => {
    for (const x of ['transparent', 'currentColor', 'inherit', 'initial', 'none', '#12', 'rgb(1,2)', 'url(x)']) {
      assert.equal(dark.darkColor(x, 'bg'), x);
      assert.equal(dark.darkColor(x, 'text'), x);
    }
  });
});

describe('mail in the dark: the HTML', () => {
  it('style attributes, bgcolor, color, <font color> and <style> blocks; pictures and comments stay', () => {
    const html = '<style>.x{background-color:#fff;color:#333}@media (max-width:600px){.y{background:#FFF url(gcmail://img/a) no-repeat;border:1px solid #ddd}}</style>'
      + '<!-- <td bgcolor="#fff"> --><table bgcolor="#FFFFFF" width=600><tr>'
      + '<td style="background:#FFE600;color:#000;font-family:&quot;Arial&quot;"><font color="#000000" face=Arial>Hi</font><img src="gcmail://img/x" style="background:white"></td>'
      + '<td bgcolor=#ffffff style="color:#999">x</td>'
      + '<td style="background-color:transparent;color:inherit;border-color:currentColor;background-image:url(&quot;gcmail://img/b&quot;)">y</td>'
      + '<td bgcolor="#e30613"><font color=white>Btn</font></td></tr></table><p style=color:black>t</p><body text="#000000" link="#0563c1">';
    const out = dark.darkHtml(html);
    assert.ok(out.includes('<style>.x{background-color:#161b22;color:#c1c4ca}@media (max-width:600px){.y{background:#161b22 url(gcmail://img/a) no-repeat;border:1px solid #2e343c}}</style>'));
    assert.ok(out.includes('<!-- <td bgcolor="#fff"> -->'), 'comments are not touched');
    assert.ok(out.includes('<table bgcolor="#161b22" width=600>'));
    assert.ok(out.includes('<td style="background:#343000;color:#e6eaf0;font-family:&quot;Arial&quot;">'));
    assert.ok(out.includes('<font color="#e6eaf0" face=Arial>Hi</font>'));
    assert.ok(out.includes('<img src="gcmail://img/x" style="background:white">'), 'pictures are never touched');
    assert.ok(out.includes('<td bgcolor=#161b22 style="color:#999">'));
    assert.ok(out.includes('style="background-color:transparent;color:inherit;border-color:currentColor;background-image:url(&quot;gcmail://img/b&quot;)"'), 'background pictures stay');
    assert.ok(out.includes('<td bgcolor="#e30613"><font color=white>Btn</font>'));
    assert.ok(out.includes('<p style=color:#e6eaf0>'));
    assert.ok(out.includes('<body text="#e6eaf0" link="#3585e6">'));
    assert.equal(dark.darkHtml('<p>Hallo</p>'), '<p>Hallo</p>');
    // a long style attribute is no problem for the pattern
    const long = `<td style="${'color:#000;'.repeat(5000)}">x</td>`;
    assert.ok(dark.darkHtml(long).startsWith('<td style="color:#e6eaf0;color:#e6eaf0;'));
  });

  it('the frame document: dark page, the same CSP without scripts, #gc-fit; the original stays light', () => {
    const msg = { id: 3, html: '<table bgcolor="#ffffff"><tr><td><font color="#000">Hi</font><img src="img/tok"></td></tr></table>' };
    const light = mail.mailDocument(msg, { lang: 'de' });
    const night = mail.mailDocument(msg, { lang: 'de', dark: true });
    assert.ok(light.includes('<table bgcolor="#ffffff">') && light.includes('<meta name="color-scheme" content="light">') && light.includes(':root{color-scheme:light}'));
    assert.ok(night.includes('<table bgcolor="#161b22">') && night.includes('<font color="#e6eaf0">'));
    assert.ok(night.includes('<meta name="color-scheme" content="dark">') && night.includes(':root{color-scheme:dark}html,body{background:#161b22;color:#e6eaf0}a{color:#79b8ff}'));
    assert.ok(night.includes('src="gcmail://img/tok"'));
    for (const d of [light, night]) {
      assert.ok(d.includes(`content="${mail.FRAME_CSP}"`) && !/<script/i.test(d) && !mail.FRAME_CSP.includes('script-src'));
      assert.ok(d.includes(`<body><div id="${mail.FIT_ID}">`) && d.endsWith('</div></body></html>'));
    }
    // a text mail: the dark page's colours only
    const t = mail.mailDocument({ id: 1, text: 'Hallo' }, { dark: true });
    assert.ok(t.includes('<div class="gc-text">Hallo</div>') && t.includes('background:#161b22'));
  });
});

// Visual regression harness: full-page screenshots + layout assertions over
// the local build in public/ (never the live site; every non-local request is
// blocked).
//
//   node tests/visual.mjs                       # check, screenshots to docs/screenshots/current/
//   node tests/visual.mjs --out docs/screenshots/after
//   node tests/visual.mjs --no-shots --langs en --viewports 390x844 --pages home,tools
//
// Assertions, per page and viewport (main document and same-origin iframes):
//   overflow   document.scrollWidth <= innerWidth
//   overlap    nothing is painted on top of the H1 or the tool iframe
//              (sampled while each is scrolled through the viewport; the area
//              under a sticky/fixed header is not part of the viewport), and no
//              positioned element (badge, floating button) covers h1-h3 text
//   js         no uncaught exceptions, no console errors
//   pre        every <pre> fits, or scrolls horizontally, and isn't clipped
//   tap        every interactive element is >= 24x24 px, or has the WCAG 2.5.8
//              spacing (24 px circles don't touch other targets); links inside
//              running text are exempt (WCAG inline exception)
// Exit code 1 when any assertion fails. results.json goes next to the shots.
import { chromium } from 'playwright';
import fs from 'node:fs';
import path from 'node:path';
import { serve, blockExternal, BLOCKED_NOISE } from './lib/server.mjs';

const args = process.argv.slice(2);
const opt = (name, def) => { const i = args.indexOf('--' + name); return i >= 0 ? args[i + 1] : def; };
const OUT = opt('out', 'docs/screenshots/current');
const SHOTS = !args.includes('--no-shots');
const LANGS = opt('langs', 'en,it').split(',');
const VIEWPORTS = opt('viewports', '360x740,390x844,768x1024,1440x900').split(',').map((v) => v.split('x').map(Number));
const PAGES = {
  home: '',
  tools: 'tools/',
  'pass-fort': 'tools/pass-fort/',
  'pixel-shrink': 'tools/pixel-shrink/',
  'qr-generator': 'tools/qr-generator/',
  'phishing-quiz': 'tools/phishing-quiz/',
  'screenshot-redactor': 'tools/screenshot-redactor/',
  'email-header-analyzer': 'tools/email-header-analyzer/',
  'spf-dmarc-checker': 'tools/spf-dmarc-checker/',
  'encrypted-message': 'tools/encrypted-message/',
  'cvss-calculator': 'tools/cvss-calculator/',
  'hash-generator': 'tools/hash-generator/',
  'password-generator': 'tools/password-generator/',
  learn: 'learn/',
  guide: 'learn/guides/osint-privacy-exif-data/',
  cheatsheet: 'learn/cheatsheets/nmap-network-scanning/',
  about: 'about/',
  games: 'tools/games/',
  404: 'this-page-does-not-exist/',
};
const ONLY = opt('pages', null)?.split(',');
const CONCURRENCY = Number(opt('concurrency', 4));

// Runs inside the page. Returns { overflow, pre, tap } problems for one document.
// `expected` is the emulated screen width for the top document: on mobile
// emulation Chrome widens the layout viewport (innerWidth) to fit content that
// overflows, so innerWidth alone would hide the overflow.
function documentChecks(expected) {
  const problems = [];
  const vw = expected || window.innerWidth;
  const sw = Math.max(document.documentElement.scrollWidth, window.innerWidth);
  if (sw > vw) {
    const clipped = (el) => { for (let e = el.parentElement; e && e !== document.body; e = e.parentElement) { if (/auto|scroll|hidden|clip/.test(getComputedStyle(e).overflowX)) return true; } return false; };
    const wide = [...document.querySelectorAll('body *')].filter((el) => el.getBoundingClientRect().right > vw + 1 && getComputedStyle(el).position !== 'fixed' && !clipped(el))
      .filter((el) => !el.parentElement || el.parentElement.getBoundingClientRect().right <= vw + 1).slice(0, 3)
      .map((el) => el.tagName.toLowerCase() + (el.id ? '#' + el.id : '') + (el.className && typeof el.className === 'string' ? '.' + el.className.trim().split(/\s+/).join('.') : ''));
    problems.push({ kind: 'overflow', detail: `scrollWidth ${sw} > ${vw}`, culprits: wide });
  }
  const visible = (el) => {
    const r = el.getBoundingClientRect();
    if (r.width < 1 || r.height < 1) return false;
    for (let e = el; e; e = e.parentElement) { const cs = getComputedStyle(e); if (cs.visibility === 'hidden' || cs.display === 'none' || cs.opacity === '0') return false; }
    return true;
  };
  for (const pre of document.querySelectorAll('pre')) {
    if (!visible(pre)) continue;
    const ox = getComputedStyle(pre).overflowX;
    const fits = pre.scrollWidth <= pre.clientWidth + 1;
    const r = pre.getBoundingClientRect();
    if (!fits && !['auto', 'scroll'].includes(ox)) problems.push({ kind: 'pre', detail: `clipped <pre> (overflow-x:${ox}, ${pre.scrollWidth}>${pre.clientWidth})`, text: pre.textContent.slice(0, 40) });
    else if (r.right > vw + 1) problems.push({ kind: 'pre', detail: `<pre> extends past viewport (${Math.round(r.right)} > ${vw})`, text: pre.textContent.slice(0, 40) });
  }
  const SEL = 'a[href], button, input:not([type=hidden]), select, textarea, summary, [role=button], [role=tab], [tabindex]:not([tabindex="-1"])';
  const targets = [...document.querySelectorAll(SEL)].filter((el) => visible(el) && !el.closest('.ad-slot, [aria-hidden=true]') && !el.disabled);
  const inlineText = (el) => {
    if (el.tagName !== 'A' || getComputedStyle(el).display !== 'inline') return false;
    const block = el.closest('p, li, td, th, dd, dt, figcaption, blockquote, label, small, span.byline, .post-meta');
    return block && block.textContent.trim().length > el.textContent.trim().length + 3;
  };
  const rectOf = (el) => {
    let r = el.getBoundingClientRect();
    if (el.tagName === 'INPUT' && /checkbox|radio/.test(el.type)) {
      const lab = el.closest('label') || (el.id && document.querySelector(`label[for="${CSS.escape(el.id)}"]`));
      if (lab) { const l = lab.getBoundingClientRect(); r = { left: Math.min(r.left, l.left), top: Math.min(r.top, l.top), right: Math.max(r.right, l.right), bottom: Math.max(r.bottom, l.bottom) }; r.width = r.right - r.left; r.height = r.bottom - r.top; }
    }
    return r;
  };
  const sized = targets.filter((el) => !inlineText(el)).map((el) => ({ el, r: rectOf(el) }));
  const small = sized.filter(({ r }) => r.width < 23.5 || r.height < 23.5);
  for (const s of small) {
    const cx = s.r.left + s.r.width / 2, cy = s.r.top + s.r.height / 2;
    const clash = sized.find((o) => {
      if (o === s || o.el.contains(s.el) || s.el.contains(o.el)) return false;
      if (small.includes(o)) return Math.hypot(cx - (o.r.left + o.r.width / 2), cy - (o.r.top + o.r.height / 2)) < 24;
      const dx = Math.max(o.r.left - cx, 0, cx - o.r.right), dy = Math.max(o.r.top - cy, 0, cy - o.r.bottom);
      return Math.hypot(dx, dy) < 12;
    });
    if (clash) problems.push({ kind: 'tap', detail: `${Math.round(s.r.width)}x${Math.round(s.r.height)} target too close to another`, el: s.el.outerHTML.slice(0, 120) });
  }
  return problems;
}

// Runs inside the page: is anything painted over `selector` while it scrolls through?
async function overlapCheck(selector) {
  const el = document.querySelector(selector);
  if (!el) return [];
  const found = new Map();
  const headerBottom = () => {
    let b = 0;
    for (const h of document.querySelectorAll('body *')) {
      const cs = getComputedStyle(h);
      if ((cs.position === 'sticky' || cs.position === 'fixed') && h.matches('header, header *, .header, [data-sticky-header]') && h.getBoundingClientRect().top <= 0.5) b = Math.max(b, h.getBoundingClientRect().bottom);
    }
    return b;
  };
  const docTop = el.getBoundingClientRect().top + scrollY;
  const height = el.getBoundingClientRect().height;
  const stops = [];
  if (height < innerHeight * 0.6) stops.push(docTop - (innerHeight - height) / 2);
  else for (let y = docTop - 80; y < docTop + height; y += innerHeight * 0.6) stops.push(y);
  for (const y of stops) {
    window.scrollTo({ top: Math.max(0, y), behavior: 'instant' });
    await new Promise((r) => setTimeout(r, 350));
    const r = el.getBoundingClientRect();
    // inset past rounded corners, where hit-testing falls through to the parent
    const inset = Math.min(14, r.height / 4, r.width / 4);
    const top = Math.max(r.top + inset, headerBottom() + 2), bottom = Math.min(r.bottom - inset, innerHeight - 2);
    const left = Math.max(r.left + inset, 2), right = Math.min(r.right - inset, innerWidth - 2);
    for (let py = top; py <= bottom; py += Math.max(8, (bottom - top) / 12)) {
      for (let px = left; px <= right; px += Math.max(8, (right - left) / 10)) {
        const hit = document.elementFromPoint(px, py);
        if (!hit || hit === el || el.contains(hit)) continue;
        const key = hit.tagName.toLowerCase() + (hit.id ? '#' + hit.id : '') + (typeof hit.className === 'string' && hit.className ? '.' + hit.className.trim().split(/\s+/).join('.') : '');
        if (!found.has(key)) found.set(key, `at ${Math.round(px)},${Math.round(py)} (scrollY ${Math.round(scrollY)})`);
      }
    }
  }
  window.scrollTo({ top: 0, behavior: 'instant' });
  return [...found].map(([k, where]) => ({ kind: 'overlap', detail: `${k} covers ${selector} ${where}` }));
}

// Runs inside the page: positioned elements (badges, floating buttons, sticky
// bars other than the site header) painted over heading text, swept through
// the whole page one viewport at a time.
async function positionedOverHeadings() {
  const found = new Map();
  const textRects = (h) => { const rg = document.createRange(); rg.selectNodeContents(h); return [...rg.getClientRects()].filter((r) => r.width > 2 && r.height > 2); };
  const hits = (a, b) => a.left < b.right - 1 && b.left < a.right - 1 && a.top < b.bottom - 1 && b.top < a.bottom - 1;
  const visible = (el) => { for (let e = el; e; e = e.parentElement) { const cs = getComputedStyle(e); if (cs.visibility === 'hidden' || cs.display === 'none' || cs.opacity === '0') return false; } return true; };
  // a transparent, empty layer (the "stretched link" over a whole card) paints nothing
  const paints = (el) => {
    const cs = getComputedStyle(el);
    if (el.textContent.trim() || /^(IMG|SVG|svg|IFRAME|CANVAS|VIDEO|BUTTON)$/.test(el.tagName)) return true;
    return !/rgba\(.*,\s*0\)|transparent/.test(cs.backgroundColor) || cs.backgroundImage !== 'none' || parseFloat(cs.borderTopWidth) > 0 || cs.boxShadow !== 'none';
  };
  const total = document.documentElement.scrollHeight;
  for (let y = 0; y < total; y += innerHeight * 0.8) {
    window.scrollTo({ top: y, behavior: 'instant' });
    await new Promise((r) => setTimeout(r, 250));
    const layers = [...document.querySelectorAll('body *')].filter((el) => {
      const pos = getComputedStyle(el).position;
      if (!['absolute', 'fixed', 'sticky'].includes(pos) || el.closest('header, .header, [data-sticky-header], .visually-hidden, .ad-slot')) return false;
      const r = el.getBoundingClientRect();
      return r.width > 4 && r.height > 4 && r.bottom > 0 && r.top < innerHeight && visible(el) && paints(el);
    });
    for (const h of document.querySelectorAll('h1, h2, h3')) {
      const hr = h.getBoundingClientRect();
      if (hr.bottom < 0 || hr.top > innerHeight || !visible(h)) continue;
      for (const el of layers) {
        if (el.contains(h) || h.contains(el)) continue;
        const er = el.getBoundingClientRect();
        if (!hits(er, hr) || !textRects(h).some((tr) => hits(er, tr))) continue;
        const key = el.tagName.toLowerCase() + (el.id ? '#' + el.id : '') + (typeof el.className === 'string' && el.className ? '.' + el.className.trim().split(/\s+/).join('.') : '') + ' over «' + h.textContent.trim().slice(0, 40) + '»';
        if (!found.has(key)) found.set(key, Math.round(scrollY));
      }
    }
  }
  window.scrollTo({ top: 0, behavior: 'instant' });
  return [...found].map(([k, y]) => ({ kind: 'overlap', detail: `${k} (scrollY ${y})` }));
}

async function checkPage(browser, origin, lang, name, rel, [w, h]) {
  const mobile = w < 1024;
  const context = await browser.newContext({ viewport: { width: w, height: h }, isMobile: mobile, hasTouch: mobile, deviceScaleFactor: 1, reducedMotion: 'reduce' });
  await blockExternal(context, origin);
  const page = await context.newPage();
  const problems = [];
  page.on('pageerror', (e) => problems.push({ kind: 'js', detail: String(e).slice(0, 200) }));
  page.on('console', (m) => { if (m.type() === 'error' && !BLOCKED_NOISE.test(m.text())) problems.push({ kind: 'js', detail: 'console: ' + m.text().slice(0, 200) }); });
  const url = `${origin}/${lang}/${rel}`;
  const res = await page.goto(url, { waitUntil: 'load' });
  if (!res || (res.status() !== 200 && name !== '404')) problems.push({ kind: 'http', detail: `HTTP ${res && res.status()}` });
  await page.waitForTimeout(1200); // iframe auto-resize, lazy images
  for (const frame of page.frames()) {
    if (!frame.url().startsWith(origin)) continue;
    const inFrame = frame !== page.mainFrame();
    try {
      for (const p of await frame.evaluate(documentChecks, inFrame ? 0 : w)) problems.push(inFrame ? { ...p, frame: new URL(frame.url()).pathname } : p);
    } catch (e) { problems.push({ kind: 'harness', detail: 'frame check failed: ' + e.message.split('\n')[0] }); }
  }
  for (const sel of ['h1', 'iframe.tool-iframe']) problems.push(...await page.evaluate(overlapCheck, sel));
  problems.push(...await page.evaluate(positionedOverHeadings));
  if (SHOTS) {
    const file = path.join(OUT, `${lang}-${name}-${w}x${h}.png`);
    await page.screenshot({ path: file, fullPage: true, animations: 'disabled' });
  }
  await context.close();
  return { url: `/${lang}/${rel}`, viewport: `${w}x${h}`, problems };
}

const { origin, close } = await serve('public');
if (SHOTS) fs.mkdirSync(OUT, { recursive: true });
const browser = await chromium.launch();
const jobs = [];
for (const vp of VIEWPORTS) for (const lang of LANGS) for (const [name, rel] of Object.entries(PAGES)) if (!ONLY || ONLY.includes(name)) jobs.push([lang, name, rel, vp]);
const results = [];
let next = 0;
await Promise.all(Array.from({ length: CONCURRENCY }, async () => {
  while (next < jobs.length) {
    const [lang, name, rel, vp] = jobs[next++];
    try { results.push(await checkPage(browser, origin, lang, name, rel, vp)); }
    catch (e) { results.push({ url: `/${lang}/${rel}`, viewport: vp.join('x'), problems: [{ kind: 'harness', detail: e.message.split('\n')[0] }] }); }
  }
}));
await browser.close();
await close();

results.sort((a, b) => a.url.localeCompare(b.url) || a.viewport.localeCompare(b.viewport, undefined, { numeric: true }));
const failed = results.filter((r) => r.problems.length);
for (const r of failed) {
  console.log(`FAIL ${r.url} @ ${r.viewport}`);
  for (const p of r.problems.slice(0, 12)) console.log(`   [${p.kind}]${p.frame ? ' (' + p.frame + ')' : ''} ${p.detail}${p.el ? ' ' + p.el : ''}${p.culprits ? ' ' + p.culprits.join(', ') : ''}${p.text ? ' «' + p.text.replace(/\s+/g, ' ') + '»' : ''}`);
  if (r.problems.length > 12) console.log(`   … ${r.problems.length - 12} more`);
}
const byKind = {};
for (const r of results) for (const p of r.problems) byKind[p.kind] = (byKind[p.kind] || 0) + 1;
console.log(`\n${results.length} page/viewport combinations, ${failed.length} with problems`, byKind);
if (SHOTS) fs.writeFileSync(path.join(OUT, 'results.json'), JSON.stringify(results, null, 1));
process.exitCode = failed.length ? 1 : 0;

// Functional suite: one or more real actions per tool, run on the embedded
// apps of the local build (public/). Every external request is blocked; the
// few tools that call an API on purpose get a mocked response.
//
//   node tests/functional.mjs                 # all tests
//   node tests/functional.mjs qr-generator,netguard
import { chromium } from 'playwright';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import jsQR from 'jsqr';
import { PNG } from 'pngjs';
import { serve, blockExternal, BLOCKED_NOISE } from './lib/server.mjs';

const FIXTURES = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures');
const PHOTO = path.join(FIXTURES, 'photo-gps.jpg');
const only = process.argv[2]?.split(',');

const blobHref = (page, sel) => page.waitForFunction((s) => { const a = document.querySelector(s); return a && /^blob:|^data:/.test(a.href); }, sel, { timeout: 30000 });
const decodeQR = (buf) => { const png = PNG.sync.read(buf); const r = jsQR(new Uint8ClampedArray(png.data), png.width, png.height); return r && r.data; };
const assert = (cond, msg) => { if (!cond) throw new Error(msg); };
const innerHeightGuess = () => 844 * 1.5 + 50;

// name -> { url, run(page, ctx) => summary string }. New tools add an entry here.
export const TESTS = {
  'pixel-shrink': { url: '/tools/pixel-shrink/', async run(p) {
    await p.setInputFiles('#fileInput', PHOTO); await p.waitForSelector('#compressBtn:not([disabled])'); await p.click('#compressBtn');
    await blobHref(p, '#downloadBtn'); return 'compressed (Web Worker, self-hosted lib)'; } },
  'exif-cleaner': { url: '/tools/exif-cleaner/', async run(p) {
    await p.setInputFiles('#fileInput', PHOTO); await p.waitForFunction(() => /GPS|Canon/i.test(document.body.innerText));
    await p.click('#purgeBtn'); await blobHref(p, '#downloadBtn');
    const hasExif = await p.evaluate(async () => { const b = await (await fetch(document.querySelector('#downloadBtn').href)).arrayBuffer(); return new TextDecoder('latin1').decode(new Uint8Array(b).slice(0, 4096)).includes('Exif'); });
    assert(!hasExif, 'clean image still has an Exif block'); return 'GPS shown, purged image has no Exif'; } },
  'qr-generator': { url: '/tools/qr-generator/', async run(p) {
    const out = [];
    for (const text of ['https://federicosella.com/it/tools/', 'Città: Zürich, España, Ação, €5 ✓']) {
      await p.fill('#qr-input', text); await p.evaluate(() => window.generateQR());
      const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#download-btn')]);
      const got = decodeQR(fs.readFileSync(await dl.path()));
      assert(got === text, `QR decodes to ${JSON.stringify(got)}, expected ${JSON.stringify(text)}`); out.push('ok');
    }
    return `URL + UTF-8 text decode back exactly (${out.length})`; } },
  'freelance-calculator': { url: '/tools/freelance-calculator/', async run(p) {
    await p.fill('#salary', '72000'); await p.dispatchEvent('#salary', 'input');
    await p.waitForFunction(() => typeof Chart !== 'undefined' && Object.keys(Chart.instances || {}).length > 0); return 'rate computed, chart drawn'; } },
  'pass-fort': { url: '/tools/pass-fort/', async run(p) {
    await p.waitForTimeout(500);
    const v = await p.evaluate(() => [...document.querySelectorAll('input,output,code,div')].map((e) => e.value || e.textContent).find((t) => t && /^[\x21-\x7e]{16,}$/.test(t.trim())));
    assert(v, 'no generated password found'); return `password generated (${v.trim().length} chars)`; } },
  'jwt-inspector': { url: '/tools/jwt-inspector/', async run(p) {
    const tok = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    const ta = await p.$('textarea'); await ta.fill(tok); await ta.dispatchEvent('input');
    await p.waitForFunction(() => document.body.innerText.includes('John Doe')); return 'sample JWT decoded'; } },
  'secrets-scanner': { url: '/tools/secrets-scanner/', async run(p) {
    const ta = await p.$('textarea'); await ta.fill('const k = "AKIAIOSFODNN7EXAMPLE";\npassword = "hunter2hunter2"'); await ta.dispatchEvent('input');
    const btn = await p.$('button:has-text("Scan")'); if (btn) await btn.click();
    await p.waitForFunction(() => /AWS|AKIA/i.test(document.body.innerText)); return 'AWS key pattern detected'; } },
  ghostprint: { url: '/tools/ghostprint/', async run(p) {
    await p.waitForTimeout(1000); const b = await p.$('button'); if (b) await b.click().catch(() => {});
    await p.waitForFunction(() => /\d+\s*(bits|%)/i.test(document.body.innerText), null, { timeout: 30000 }); return 'fingerprint scan produced a score'; } },
  netguard: { url: '/tools/netguard/', mock: { 'https://ipwho.is/': { ip: '203.0.113.7', city: 'Testville', country: 'Nowhere', latitude: 1.5, longitude: 2.5, connection: { isp: 'Example ISP' } } }, async run(p) {
    await p.click('#scanBtn');
    await p.waitForFunction(() => /Scan Again/.test(document.getElementById('scanBtn').textContent), null, { timeout: 30000 });
    const ip = (await p.textContent('#valIp')).trim(); assert(ip === '203.0.113.7', 'IP card shows ' + ip); return 'scan complete with mocked ipwho.is'; } },
  steganography: { url: '/tools/steganography/', async run(p, { tmp }) {
    const png = await p.evaluate(() => {
      const c = document.createElement('canvas'); c.width = 300; c.height = 200; const x = c.getContext('2d'); const d = x.createImageData(300, 200);
      for (let y = 0; y < 200; y++) for (let i = 0; i < 300; i++) { const o = (y * 300 + i) * 4; d.data[o] = (i * 7 + y) & 255; d.data[o + 1] = (y * 3) & 255; d.data[o + 2] = (i ^ y) & 255; d.data[o + 3] = i < 150 ? 255 : (i < 280 ? 128 + ((i + y) % 100) : 0); }
      x.putImageData(d, 0, 0); return c.toDataURL('image/png').split(',')[1];
    });
    const src = path.join(tmp, 'stego-src.png'); fs.writeFileSync(src, Buffer.from(png, 'base64'));
    await p.setInputFiles('#hideFileInput', src); await p.waitForTimeout(400);
    const msg = 'Ciao — 秘密のメッセージ 🔐 line1\nline2  ';
    await p.fill('#secretText', msg);
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#encodeBtn')]);
    const out = path.join(tmp, 'stego-out.png'); await dl.saveAs(out);
    await p.click('#tabReveal'); await p.setInputFiles('#revealFileInput', out); await p.waitForTimeout(400);
    await p.click('#decodeBtn'); await p.waitForTimeout(200);
    const got = await p.textContent('#revealedText');
    assert(got === msg, 'round-trip mismatch: ' + JSON.stringify(got)); return 'encode → download → decode round-trip exact'; } },
  'string-master': { url: '/tools/string-master/?lang=en', async run(p) {
    await p.fill('#text-input', 'Hello 👋🏽 world\nsecond line'); await p.dispatchEvent('#text-input', 'input');
    await p.waitForFunction(() => document.getElementById('stat-words').textContent === '5');
    const chars = (await p.textContent('#stat-chars')).trim(); assert(chars === '25', 'chars ' + chars); return 'words 5, graphemes 25 (emoji + skin tone = 1)'; } },
  search: { url: '/en/', async run(p) {
    await p.keyboard.press('Control+k'); await p.fill('#search-input', 'password');
    await p.waitForSelector('#search-results li', { timeout: 10000 }); return 'palette returns results for "password"'; } },
  'header-mobile': { url: '/it/learn/', viewport: { width: 390, height: 844 }, async run(p) {
    const h = await p.evaluate(() => document.getElementById('site-header').getBoundingClientRect().height);
    assert(h <= 56, 'header is ' + h + 'px tall');
    assert(!(await p.isVisible('#site-nav')), 'nav visible before opening the menu');
    await p.click('.nav-toggle'); assert(await p.isVisible('#site-nav a[aria-current]'), 'menu did not open / no current item');
    await p.keyboard.press('Escape'); assert(!(await p.isVisible('#site-nav')), 'Escape did not close the menu');
    await p.click('.lang-menu summary'); await p.click('.lang-list a[hreflang=de]');
    await p.waitForURL(/\/de\/learn\/$/); return `header ${h}px, menu opens/closes, language switch → /de/learn/`; } },
  'header-search': { url: '/en/tools/', async run(p) {
    await p.click('.site-header [data-search-trigger]'); await p.fill('#search-input', 'exif');
    await p.waitForSelector('#search-results li'); const label = await p.textContent('#search-results .search-result-section');
    assert(['Tool', 'Guide'].includes(label.trim()), 'result label ' + label); return 'header search button opens the palette; results labelled by type'; } },
  'code-copy': { url: '/it/learn/cheatsheets/nmap-network-scanning/', async run(p, { context }) {
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    const btn = p.locator('.code-copy').first(); await btn.click();
    await p.waitForFunction(() => document.querySelector('.code-copy').textContent.includes('Copiato'), null, { timeout: 3000 });
    const clip = await p.evaluate(() => navigator.clipboard.readText());
    assert(clip.startsWith('# ') && !clip.includes('Copia'), 'clipboard: ' + clip.slice(0, 40)); return 'localized Copy → Copiato, code on the clipboard'; } },
  'back-to-top': { url: '/en/learn/guides/osint-privacy-exif-data/', viewport: { width: 390, height: 844 }, async run(p) {
    assert(!(await p.isVisible('#top-link')), 'visible at the top of the page');
    await p.evaluate(() => window.scrollTo(0, innerHeight * 0.5)); await p.waitForTimeout(300);
    assert(!(await p.isVisible('#top-link')), 'visible before 1.5 viewports');
    let seen = false;
    for (let y = innerHeightGuess(); y < 9000 && !seen; y += 300) { await p.evaluate((yy) => window.scrollTo(0, yy), y); await p.waitForTimeout(150); seen = await p.isVisible('#top-link'); }
    assert(seen, 'never shown'); await p.click('#top-link'); await p.waitForFunction(() => scrollY === 0);
    return 'appears after 1.5 viewports, scrolls back to the top'; } },
  'search-deeplink': { url: '/it/?q=password', async run(p) {
    await p.waitForSelector('#search-results li', { timeout: 10000 }); return '?q= opens the palette with results'; } },
};

const { origin, close } = await serve('public');
const tmp = fs.mkdtempSync(path.join(fs.realpathSync(process.env.TEMP || process.env.TMPDIR || '/tmp'), 'fs-functional-'));
const browser = await chromium.launch();
let fails = 0;
for (const [name, t] of Object.entries(TESTS)) {
  if (only && !only.includes(name)) continue;
  const context = await browser.newContext({ acceptDownloads: true, viewport: t.viewport || { width: 1280, height: 900 }, isMobile: !!t.viewport, hasTouch: !!t.viewport });
  await blockExternal(context, origin);
  // registered after the block-all route, so these win (Playwright tries the newest route first)
  for (const [url, body] of Object.entries(t.mock || {})) await context.route(url, (r) => r.fulfill({ json: body, headers: { 'access-control-allow-origin': '*' } }));
  const page = await context.newPage();
  const errs = [];
  page.on('pageerror', (e) => errs.push(String(e).slice(0, 160)));
  page.on('console', (m) => { if (m.type() === 'error' && !BLOCKED_NOISE.test(m.text())) errs.push('console: ' + m.text().slice(0, 160)); });
  let res;
  try { await page.goto(origin + t.url, { waitUntil: 'load' }); res = await t.run(page, { origin, tmp, context }); }
  catch (e) { res = 'FAIL ' + e.message.split('\n')[0].slice(0, 200); }
  const bad = res.startsWith('FAIL') || errs.length;
  if (bad) fails++;
  console.log(`${bad ? 'X ' : 'OK'} ${name}: ${res}${errs.length ? ' | JS errors: ' + JSON.stringify(errs) : ''}`);
  await context.close();
}
await browser.close();
await close();
fs.rmSync(tmp, { recursive: true, force: true });
console.log(fails ? `FAILURES: ${fails}` : 'all functional checks passed');
process.exitCode = fails ? 1 : 0;

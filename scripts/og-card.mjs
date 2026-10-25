// Renders the default social / Open Graph card (static/images/og-card.png, 1200×630)
// from the design tokens, the small raven mark and the self-hosted JetBrains Mono.
// Screenshots from headless Chromium carry no EXIF/XMP/text chunks.
//   node scripts/og-card.mjs
import { chromium } from 'playwright';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (p) => fs.readFileSync(path.join(root, p));
const tokens = read('assets/css/extended/tokens.css').toString();
const tok = (name) => tokens.match(new RegExp(`--${name}:\\s*([^;]+);`))[1].trim();
const mark = `data:image/svg+xml;base64,${read('static/images/logo-mark.svg').toString('base64')}`;
const font = `data:font/woff2;base64,${read('static/fonts/jetbrains-mono/jetbrains-mono-latin.woff2').toString('base64')}`;

const html = `<!doctype html><meta charset="utf-8"><style>
@font-face { font-family: 'JetBrains Mono'; font-weight: 400 700; src: url(${font}) format('woff2'); }
html, body { margin: 0; }
.card { box-sizing: border-box; width: 1200px; height: 630px; padding: 72px 88px; display: flex; align-items: center; gap: 64px;
  background: radial-gradient(900px 520px at 85% 110%, ${tok('accent-soft')}, transparent 70%), ${tok('bg')};
  color: ${tok('text')}; font-family: 'JetBrains Mono', ui-monospace, monospace; position: relative; overflow: hidden; }
.card::before { content: ''; position: absolute; inset: 0; border-top: 8px solid ${tok('accent')}; }
.mark { width: 280px; height: 280px; flex: none; border-radius: 56px; box-shadow: 0 0 0 2px ${tok('border-strong')}; }
h1 { margin: 0; font-size: 68px; line-height: 1.08; font-weight: 700; letter-spacing: -0.02em; }
.name { margin: 0 0 22px; font-size: 30px; color: ${tok('text-2')}; }
.domain { margin: 34px 0 0; font-size: 34px; color: ${tok('accent')}; font-weight: 700; }
</style><div class="card"><img class="mark" src="${mark}" alt="">
<div><p class="name">Federico Sella</p><h1>Free, privacy&#8209;first<br>web tools</h1><p class="domain">federicosella.com</p></div></div>`;

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1200, height: 630 }, deviceScaleFactor: 1 });
await page.setContent(html);
await page.evaluate(() => document.fonts.ready);
const out = path.join(root, 'static/images/og-card.png');
await page.screenshot({ path: out, clip: { x: 0, y: 0, width: 1200, height: 630 } });
await browser.close();
console.log('wrote', path.relative(root, out));

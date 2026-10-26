// Renders the static layers of the per-page share cards into assets/og/:
//   bg.png          1200×630 background (flat --bg, accent bar, raven mark, domain)
//   icons/<n>.png   160×160 icon tile for every icon in data/tool_icons.yaml
// Hugo composes the localized category and title over them at build time
// (layouts/partials/og/card.html), so CI needs no browser. Rerun after adding
// an icon or changing the design tokens:   node scripts/og-assets.mjs
// Headless-Chromium screenshots carry no EXIF/XMP/text chunks.
import { chromium } from 'playwright';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (p) => fs.readFileSync(path.join(root, p));
const tokens = read('assets/css/extended/tokens.css').toString();
const tok = (name) => tokens.match(new RegExp(`--${name}:\\s*([^;]+);`))[1].trim();
const yamlCtx = {};
vm.runInNewContext(read('static/vendor/js-yaml@4.1.0/js-yaml.min.js').toString(), yamlCtx);
const icons = yamlCtx.jsyaml.load(read('data/tool_icons.yaml').toString()).icons;
const b64 = (p, type) => `data:${type};base64,${read(p).toString('base64')}`;
const font = b64('static/fonts/jetbrains-mono/jetbrains-mono-latin.woff2', 'font/woff2');
const mark = b64('static/images/logo-mark.svg', 'image/svg+xml');
const out = path.join(root, 'assets/og');
fs.mkdirSync(path.join(out, 'icons'), { recursive: true });

const browser = await chromium.launch();
const page = await browser.newPage({ deviceScaleFactor: 1 });

/* background */
await page.setViewportSize({ width: 1200, height: 630 });
await page.setContent(`<!doctype html><meta charset="utf-8"><style>
@font-face { font-family: 'JetBrains Mono'; font-weight: 400 700; src: url(${font}) format('woff2'); }
html, body { margin: 0; }
.c { position: relative; width: 1200px; height: 630px; background: ${tok('bg')}; font-family: 'JetBrains Mono', monospace; overflow: hidden; }
.bar { position: absolute; inset: 0 0 auto; height: 8px; background: ${tok('accent')}; }
.rule { position: absolute; left: 80px; right: 80px; top: 500px; height: 2px; background: ${tok('border')}; }
.foot { position: absolute; left: 80px; top: 528px; display: flex; align-items: center; gap: 20px; }
.foot img { width: 56px; height: 56px; border-radius: 12px; }
.foot span { font-size: 30px; font-weight: 700; color: ${tok('text-2')}; }
</style><div class="c"><div class="bar"></div><div class="rule"></div>
<div class="foot"><img src="${mark}" alt=""><span>federicosella.com</span></div></div>`);
await page.evaluate(() => document.fonts.ready);
await page.screenshot({ path: path.join(out, 'bg.png'), clip: { x: 0, y: 0, width: 1200, height: 630 } });

/* icon tiles (transparent outside the rounded tile, overlaid by Hugo) */
await page.setViewportSize({ width: 160, height: 160 });
for (const [name, svg] of Object.entries(icons)) {
  await page.setContent(`<!doctype html><style>html,body{margin:0;background:transparent}
  .t{width:160px;height:160px;box-sizing:border-box;border-radius:32px;background:${tok('surface-2')};border:2px solid ${tok('border-strong')};display:grid;place-items:center;color:${tok('accent')}}</style>
  <div class="t"><svg width="96" height="96" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">${svg}</svg></div>`);
  await page.screenshot({ path: path.join(out, 'icons', `${name}.png`), omitBackground: true, clip: { x: 0, y: 0, width: 160, height: 160 } });
}
await browser.close();
console.log(`wrote assets/og/bg.png and ${Object.keys(icons).length} icon tiles`);

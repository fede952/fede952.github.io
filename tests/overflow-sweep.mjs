// Every real page of the build (alias redirect stubs skipped) at a phone
// width: no horizontal overflow, no uncaught JS errors. Complements
// visual.mjs, which checks a fixed sample in depth.
//
//   node tests/overflow-sweep.mjs [width=360] [langs=en,it,es,de,fr,pt]
import { chromium } from 'playwright';
import fs from 'node:fs';
import path from 'node:path';
import { serve, blockExternal } from './lib/server.mjs';

const W = Number(process.argv[2] || 360);
const LANGS = (process.argv[3] || 'en,it,es,de,fr,pt').split(',');
const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)]);
const pages = LANGS.flatMap((l) => walk(path.join('public', l)))
  .filter((f) => f.endsWith('index.html') && !/http-equiv=refresh/i.test(fs.readFileSync(f, 'utf8').slice(0, 400)))
  .map((f) => '/' + path.relative('public', path.dirname(f)).split(path.sep).join('/') + '/');

const { origin, close } = await serve('public');
const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: W, height: 800 }, isMobile: true, hasTouch: true });
await blockExternal(context, origin);
const fails = []; let next = 0;
await Promise.all(Array.from({ length: 6 }, async () => {
  const page = await context.newPage();
  let errors = [];
  page.on('pageerror', (e) => errors.push(String(e).slice(0, 120)));
  while (next < pages.length) {
    const url = pages[next++]; errors = [];
    try {
      await page.goto(origin + url, { waitUntil: 'load' });
      await page.waitForTimeout(250);
      const r = await page.evaluate((w) => {
        const sw = Math.max(document.documentElement.scrollWidth, innerWidth);
        if (sw <= w) return null;
        const clipped = (el) => { for (let e = el.parentElement; e && e !== document.body; e = e.parentElement) if (/auto|scroll|hidden|clip/.test(getComputedStyle(e).overflowX)) return true; return false; };
        const el = [...document.querySelectorAll('body *')].find((e) => e.getBoundingClientRect().right > w + 1 && getComputedStyle(e).position !== 'fixed' && !clipped(e));
        return `scrollWidth ${sw}` + (el ? ` (${el.tagName.toLowerCase()}.${String(el.className).trim().split(/\s+/).join('.')})` : '');
      }, W);
      if (r || errors.length) fails.push(`${url} ${r || ''} ${errors.join(' | ')}`);
    } catch (e) { fails.push(`${url} ${e.message.split('\n')[0]}`); }
  }
}));
await browser.close();
await close();
console.log(fails.sort().join('\n'));
console.log(`${pages.length} pages at ${W}px, ${fails.length} with overflow or JS errors`);
process.exitCode = fails.length ? 1 : 0;

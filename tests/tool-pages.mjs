// Audit of every tool page in every language (local build): H1, JSON-LD
// (WebApplication + BreadcrumbList + FAQPage, FAQ in DOM = FAQ in schema),
// iframe ?lang matches the page, the iframe got auto-resized and its height
// settles, no JS errors.
//
//   node tests/tool-pages.mjs [tool,tool]
import { chromium } from 'playwright';
import fs from 'node:fs';
import path from 'node:path';
import { serve, blockExternal, BLOCKED_NOISE } from './lib/server.mjs';

const LANGS = ['en', 'it', 'es', 'de', 'fr', 'pt'];
const only = process.argv[2]?.split(',');
const tools = fs.readdirSync('public/en/tools').filter((d) => d !== 'games' && fs.existsSync(path.join('public/en/tools', d, 'index.html')) && (!only || only.includes(d)));

const { origin, close } = await serve('public');
const browser = await chromium.launch();
const jobs = tools.flatMap((t) => LANGS.map((l) => [t, l]));
const rows = []; let fails = 0; let next = 0;
await Promise.all(Array.from({ length: 4 }, async () => {
  while (next < jobs.length) {
    const [tool, lang] = jobs[next++];
    const url = `/${lang}/tools/${tool}/`;
    const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
    await blockExternal(context, origin);
    const page = await context.newPage();
    const problems = [];
    page.on('pageerror', (e) => problems.push('pageerror: ' + String(e).slice(0, 160)));
    page.on('console', (m) => { if (m.type() === 'error' && !BLOCKED_NOISE.test(m.text())) problems.push('console: ' + m.text().slice(0, 160)); });
    try {
      await page.goto(origin + url, { waitUntil: 'load' });
      await page.waitForTimeout(1500);
      // The auto-resized frame must settle. Growing while an app fills in
      // results is fine; shrinking step after step is the resize feedback
      // loop (frame border not accounted for), and so is never settling.
      const frameH = () => page.evaluate(() => { const f = document.querySelector('iframe.tool-iframe'); return f ? Math.round(f.getBoundingClientRect().height) : 0; });
      let prev = await frameH(), settled = false, shrinks = 0;
      for (let i = 0; i < 10 && !settled; i++) {
        await page.waitForTimeout(600);
        const h = await frameH();
        if (h < prev - 4) shrinks++;
        settled = Math.abs(h - prev) <= 4;
        prev = h;
      }
      if (shrinks > 1 || !settled) problems.push(`iframe height ${settled ? 'kept shrinking' : 'never settled'} (last ${prev} px)`);
      const info = await page.evaluate(() => {
        const ld = [...document.querySelectorAll('script[type="application/ld+json"]')].flatMap((s) => { try { const j = JSON.parse(s.textContent); return Array.isArray(j) ? j : (j['@graph'] || [j]); } catch { return [{ '@type': 'PARSE_ERROR' }]; } });
        const faq = ld.find((x) => x['@type'] === 'FAQPage');
        const ifr = document.querySelector('iframe.tool-iframe');
        return {
          h1: document.querySelectorAll('h1').length, types: ld.map((x) => x['@type']).flat(), faqLd: faq ? faq.mainEntity.length : 0,
          faqDom: document.querySelectorAll('.tool-faq h3').length,
          iframe: ifr && { src: ifr.getAttribute('src'), scrolling: ifr.getAttribute('scrolling') },
        };
      });
      if (info.h1 !== 1) problems.push(`${info.h1} h1 elements`);
      for (const t of ['WebApplication', 'BreadcrumbList', 'FAQPage']) if (!info.types.includes(t)) problems.push('missing ' + t);
      if (info.types.includes('PARSE_ERROR')) problems.push('ld+json parse error');
      if (info.faqDom !== info.faqLd) problems.push(`faq dom ${info.faqDom} != ld ${info.faqLd}`);
      if (info.iframe) {
        if (!info.iframe.src.endsWith('?lang=' + lang)) problems.push('iframe src ' + info.iframe.src);
        if (info.iframe.scrolling !== 'no') problems.push('iframe not auto-resized');
      }
    } catch (e) { problems.push(String(e).split('\n')[0].slice(0, 200)); }
    if (problems.length) { fails++; rows.push(`FAIL ${url} ${problems.join(' | ')}`); }
    await context.close();
  }
}));
await browser.close();
await close();
console.log(rows.sort().join('\n'));
console.log(`${jobs.length} tool pages, ${fails} with problems`);
process.exitCode = fails ? 1 : 0;

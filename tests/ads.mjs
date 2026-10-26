// Ad layout v2 checks on every tool and learn page (local build; AdSense is
// blocked, so every slot keeps its reserved, CLS-safe height):
//   one-ad    at no scroll position are two ad slots on screen together
//              (in-content units and the desktop sidebar unit)
//   fold      tool pages: the tool's first interactive control is visible
//              without scrolling — at least 48 px of it, or all of a smaller
//              one (390×844 and 1440×900)
//   button    no ad slot within 150 px of any control of the tool
//   cls       cumulative layout shift while loading and scrolling < 0.05
// Also reports where the sidebar unit was placed (>= 1100 px).
//
//   node tests/ads.mjs [--langs en,it] [--viewports 390x844,1440x900] [--only tools|learn]
import { chromium } from 'playwright';
import fs from 'node:fs';
import path from 'node:path';
import { serve, blockExternal, BLOCKED_NOISE } from './lib/server.mjs';

const args = process.argv.slice(2);
const opt = (n, d) => { const i = args.indexOf('--' + n); return i >= 0 ? args[i + 1] : d; };
const LANGS = opt('langs', 'en,it').split(',');
const VIEWPORTS = opt('viewports', '390x844,768x1024,1440x900').split(',').map((v) => v.split('x').map(Number));
const ONLY = opt('only', null);
const FOLD_VIEWPORTS = ['390x844', '1440x900'];

const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)]);
const pages = [];
for (const l of LANGS) {
  for (const sec of ['tools', 'learn']) {
    if (ONLY && ONLY !== sec) continue;
    for (const f of walk(path.join('public', l, sec))) {
      if (!f.endsWith('index.html')) continue;
      const html = fs.readFileSync(f, 'utf8');
      if (/http-equiv=refresh/i.test(html.slice(0, 400)) || !/class="?[^">]*page-main/.test(html)) continue;
      pages.push({ url: '/' + path.relative('public', path.dirname(f)).split(path.sep).join('/') + '/', kind: sec, tool: /class="?tool-frame/.test(html) });
    }
  }
}

async function inspect(page, vp, isTool) {
  return page.evaluate(async ({ vp, isTool }) => {
    const out = { problems: [], sidebar: null };
    const vh = innerHeight;
    const slots = () => [...document.querySelectorAll('.ad-slot')].filter((s) => s.offsetParent !== null && s.getBoundingClientRect().height > 0);
    // controls of the tool, in page coordinates (also inside a same-origin iframe)
    const controls = [];
    const frame = document.querySelector('iframe.tool-iframe');
    const SEL = 'button, input:not([type=hidden]), select, textarea, [role=button], label[for], .dropzone, .drop-zone, [class*=drop]';
    // content of a closed <details> still has layout boxes in Chromium, but is not on screen
    const vis = (el, win) => { if (el.closest('details:not([open])') && !el.closest('summary')) return false; const r = el.getBoundingClientRect(); if (r.width < 2 || r.height < 2) return false; const cs = win.getComputedStyle(el); return cs.visibility !== 'hidden' && cs.display !== 'none' && cs.opacity !== '0'; };
    if (frame && frame.contentDocument) {
      const fr = frame.getBoundingClientRect();
      for (const el of frame.contentDocument.querySelectorAll(SEL)) {
        if (!vis(el, frame.contentWindow)) continue;
        const r = el.getBoundingClientRect();
        controls.push({ top: fr.top + scrollY + r.top, bottom: fr.top + scrollY + r.bottom, left: fr.left + r.left, right: fr.left + r.right });
      }
    } else {
      for (const el of document.querySelectorAll('.tool-inline ' + SEL.split(', ').join(', .tool-inline '))) {
        if (!vis(el, window)) continue;
        const r = el.getBoundingClientRect();
        controls.push({ top: r.top + scrollY, bottom: r.bottom + scrollY, left: r.left, right: r.right });
      }
    }
    // fold: first control visible without scrolling
    if (isTool && vp.fold) {
      // Apps that start working on their own (GhostPrint's scan) have no
      // control at first: then the tool itself must start on screen.
      const first = controls.sort((a, b) => a.top - b.top)[0];
      const toolTop = (frame || document.querySelector('.tool-inline')).getBoundingClientRect().top + scrollY;
      if (!first && toolTop + 120 > vh) out.problems.push({ kind: 'fold', detail: `tool starts at ${Math.round(toolTop)} px, viewport is ${vh} px` });
      // "visible" = tappable: 48 px of it on screen (all of it when smaller; a
      // 220 px textarea or drop zone is usable once its top part shows)
      else if (first && Math.min(first.bottom, vh) - first.top < Math.min(48, first.bottom - first.top)) out.problems.push({ kind: 'fold', detail: `first control at ${Math.round(first.top)}–${Math.round(first.bottom)} px, viewport is ${vh} px` });
    }
    // 150 px rule
    for (const s of slots()) {
      const r = s.getBoundingClientRect();
      const a = { top: r.top + scrollY, bottom: r.bottom + scrollY, left: r.left, right: r.right };
      for (const c of controls) {
        const dx = Math.max(a.left - c.right, 0, c.left - a.right), dy = Math.max(a.top - c.bottom, 0, c.top - a.bottom);
        const d = Math.hypot(dx, dy);
        if (d < 150) { out.problems.push({ kind: 'button', detail: `${s.className} is ${Math.round(d)} px from a tool control` }); break; }
      }
    }
    // one ad per screen, swept through the page
    const total = document.documentElement.scrollHeight;
    for (let y = 0; y <= total - vh + vh / 4; y += vh / 4) {
      window.scrollTo(0, y);
      await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
      const onScreen = slots().filter((s) => { const r = s.getBoundingClientRect(); return r.bottom > 0 && r.top < vh; });
      if (onScreen.length > 1) {
        out.problems.push({ kind: 'one-ad', detail: `${onScreen.length} ads on screen at scrollY ${Math.round(scrollY)}: ${onScreen.map((s) => s.className.replace('ad-slot ', '')).join(', ')}` });
        break;
      }
    }
    const side = document.querySelector('[data-sidebar-ad] .ad-slot');
    out.sidebar = side ? Math.round(document.querySelector('[data-sidebar-ad]').getBoundingClientRect().top + scrollY) : null;
    out.slots = slots().length;
    window.scrollTo(0, 0);
    return out;
  }, { vp, isTool });
}

const { origin, close } = await serve('public');
const browser = await chromium.launch();
const jobs = VIEWPORTS.flatMap((vp) => pages.map((p) => [p, vp]));
const fails = []; const stats = { sidebar: 0, desktopPages: 0, maxCls: 0 }; let next = 0;
await Promise.all(Array.from({ length: 5 }, async () => {
  while (next < jobs.length) {
    const [p, [w, h]] = jobs[next++];
    const mobile = w < 1024;
    const context = await browser.newContext({ viewport: { width: w, height: h }, isMobile: mobile, hasTouch: mobile, deviceScaleFactor: 1 });
    await blockExternal(context, origin);
    const page = await context.newPage();
    const errs = [];
    page.on('pageerror', (e) => errs.push(String(e).slice(0, 150)));
    page.on('console', (m) => { if (m.type() === 'error' && !BLOCKED_NOISE.test(m.text())) errs.push(m.text().slice(0, 150)); });
    await page.addInitScript(() => {
      window.__cls = 0;
      new PerformanceObserver((list) => { for (const e of list.getEntries()) if (!e.hadRecentInput) window.__cls += e.value; }).observe({ type: 'layout-shift', buffered: true });
    });
    try {
      await page.goto(origin + p.url, { waitUntil: 'load' });
      await page.waitForTimeout(1800);
      const r = await inspect(page, { w, h, fold: FOLD_VIEWPORTS.includes(`${w}x${h}`) }, p.tool);
      const cls = await page.evaluate(() => window.__cls);
      stats.maxCls = Math.max(stats.maxCls, cls);
      if (cls >= 0.05) r.problems.push({ kind: 'cls', detail: `CLS ${cls.toFixed(3)}` });
      if (errs.length) r.problems.push({ kind: 'js', detail: errs.join(' | ') });
      if (w >= 1100) { stats.desktopPages++; if (r.sidebar !== null) stats.sidebar++; }
      if (r.problems.length) fails.push(`FAIL ${p.url} @ ${w}x${h}\n` + r.problems.map((x) => `   [${x.kind}] ${x.detail}`).join('\n'));
    } catch (e) { fails.push(`FAIL ${p.url} @ ${w}x${h}\n   [harness] ${e.message.split('\n')[0]}`); }
    await context.close();
  }
}));
await browser.close();
await close();
console.log(fails.sort().join('\n'));
console.log(`\n${jobs.length} page/viewport runs (${pages.length} pages), ${fails.length} with problems; ` +
  `sidebar unit placed on ${stats.sidebar}/${stats.desktopPages} desktop runs; max CLS ${stats.maxCls.toFixed(3)}`);
process.exitCode = fails.length ? 1 : 0;

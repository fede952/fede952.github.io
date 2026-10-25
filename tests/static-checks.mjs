// Build-output checks that need no browser, over public/:
//   links    every internal href/src/srcset in every HTML file resolves to a file
//   jsonld   every <script type=application/ld+json> parses
//   sitemap  every URL in the per-language sitemaps exists; --expect tools/x,tools/y
//            asserts those tool URLs are listed in all 6 languages
//   og       Open Graph / Twitter tags, like a share-card validator: every page has an
//            og:image that resolves; tool and learn pages point at their own card in
//            /og/<lang>/, a 1200×630 PNG under 120 KB without metadata chunks, with
//            matching og:image:width/height and twitter:card summary_large_image
//
//   node tests/static-checks.mjs [--expect tools/subnet-calculator,...]
import fs from 'node:fs';
import path from 'node:path';

const PUB = path.resolve('public');
const HOST = 'https://federicosella.com';
const LANGS = ['en', 'it', 'es', 'de', 'fr', 'pt'];
const args = process.argv.slice(2);
const expect = args.includes('--expect') ? args[args.indexOf('--expect') + 1].split(',') : [];

const exists = (p) => {
  p = decodeURIComponent(p.split('#')[0].split('?')[0]);
  if (!p || p === '/') return true;
  const f = path.join(PUB, p);
  return (fs.existsSync(f) && fs.statSync(f).isFile()) || fs.existsSync(path.join(f, 'index.html'));
};
const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)]);

const html = walk(PUB).filter((f) => f.endsWith('.html'));
const broken = new Map(); let refs = 0; let ldBlocks = 0; const ldErrors = [];
const ogErrors = []; let ogCards = 0; let ogPages = 0;
const meta = (raw, key) => {
  const re = new RegExp(`<meta (?:property|name)=["']?${key.replace(/:/g, ':')}["']? content=(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`);
  const m = raw.match(re); return m ? (m[1] ?? m[2] ?? m[3]) : null;
};
/** PNG facts from the file itself: size from IHDR, and any text/EXIF/time chunk. */
function pngInfo(file) {
  const b = fs.readFileSync(file);
  if (b.toString('latin1', 1, 4) !== 'PNG') return { error: 'not a PNG' };
  const chunks = []; let i = 8;
  while (i + 8 <= b.length) { const n = b.readUInt32BE(i); chunks.push(b.toString('latin1', i + 4, i + 8)); i += 12 + n; }
  return { width: b.readUInt32BE(16), height: b.readUInt32BE(20), bytes: b.length,
    metadata: chunks.filter((c) => ['tEXt', 'zTXt', 'iTXt', 'eXIf', 'tIME'].includes(c)) };
}
const ATTR = /(href|src|srcset|poster|data-src)=(?:"([^"]*)"|'([^']*)'|([^\s>]+))/g;
for (const f of html) {
  const rel = '/' + path.relative(PUB, f).split(path.sep).join('/');
  const raw = fs.readFileSync(f, 'utf8');
  for (const m of raw.matchAll(/<script type=["']?application\/ld\+json["']?>([\s\S]*?)<\/script>/g)) {
    ldBlocks++;
    try { JSON.parse(m[1]); } catch (e) { ldErrors.push(`${rel}: ${e.message.slice(0, 80)}`); }
  }
  // Open Graph (pages that redirect have no head to check)
  if (!/http-equiv=["']?refresh/i.test(raw) && /<meta (property|name)=["']?og:/.test(raw)) {
    ogPages++;
    const img = meta(raw, 'og:image');
    const isCard = /^\/(en|it|es|de|fr|pt)\/(tools|learn)\/.+/.test(rel) && !/\/index\.xml$/.test(rel) && !/\/page\/\d+\//.test(rel);
    if (!img) ogErrors.push(`${rel}: no og:image`);
    else {
      const local = img.startsWith(HOST) ? img.slice(HOST.length) : null;
      if (!local || !exists(local)) ogErrors.push(`${rel}: og:image does not resolve (${img})`);
      const card = local && /^\/og\//.test(local);
      if (card) {
        ogCards++;
        const info = pngInfo(path.join(PUB, decodeURIComponent(local)));
        const w = meta(raw, 'og:image:width'), h = meta(raw, 'og:image:height');
        if (info.error) ogErrors.push(`${rel}: ${info.error}`);
        else {
          if (info.width !== 1200 || info.height !== 630) ogErrors.push(`${rel}: card is ${info.width}×${info.height}`);
          if (String(info.width) !== w || String(info.height) !== h) ogErrors.push(`${rel}: og:image:width/height ${w}×${h} ≠ file ${info.width}×${info.height}`);
          if (info.bytes >= 120 * 1024) ogErrors.push(`${rel}: card is ${Math.round(info.bytes / 1024)} KB`);
          if (info.metadata.length) ogErrors.push(`${rel}: card has metadata chunks ${info.metadata.join(',')}`);
        }
        if (meta(raw, 'twitter:card') !== 'summary_large_image') ogErrors.push(`${rel}: twitter:card is ${meta(raw, 'twitter:card')}`);
        if (meta(raw, 'twitter:image') !== img) ogErrors.push(`${rel}: twitter:image differs from og:image`);
        const lang = rel.split('/')[1];
        if (!local.startsWith(`/og/${lang}/`)) ogErrors.push(`${rel}: card from another language (${local})`);
      } else if (isCard && /<article|tool-page|post-content/.test(raw) && /<meta property=["']?og:type["']? content=["']?article/.test(raw)) {
        ogErrors.push(`${rel}: tool/learn page without its own card (${img})`);
      }
    }
  }
  // inline scripts hold template strings, not links
  const s = raw.replace(/<script\b[^>]*>[\s\S]*?<\/script>/g, '');
  for (const m of s.matchAll(ATTR)) {
    const v = (m[2] ?? m[3] ?? m[4] ?? '').trim();
    const urls = m[1] === 'srcset' ? v.split(',').map((x) => x.trim().split(' ')[0]) : [v];
    for (let u of urls) {
      if (!u || /^(#|mailto:|tel:|javascript:|data:|blob:)/.test(u)) continue;
      if (u.startsWith(HOST)) u = u.slice(HOST.length) || '/';
      else if (/^(https?:)?\/\//.test(u)) continue;
      else if (!u.startsWith('/')) u = new URL(u, 'http://x' + rel).pathname;
      refs++;
      if (!exists(u)) { if (!broken.has(u)) broken.set(u, []); broken.get(u).push(rel); }
    }
  }
}

const sitemapMissing = []; let sitemapUrls = 0; const listed = new Set();
for (const l of LANGS) {
  const xml = fs.readFileSync(path.join(PUB, l, 'sitemap.xml'), 'utf8');
  for (const [, loc] of xml.matchAll(/<loc>([^<]+)<\/loc>/g)) {
    sitemapUrls++; const p = loc.replace(HOST, ''); listed.add(p);
    if (!exists(p)) sitemapMissing.push(p);
  }
}
const notListed = expect.flatMap((t) => LANGS.map((l) => `/${l}/${t.replace(/^\/|\/$/g, '')}/`)).filter((u) => !listed.has(u));

console.log(`links:   ${html.length} HTML files, ${refs} internal references, ${broken.size} broken targets`);
for (const [u, srcs] of [...broken].slice(0, 30)) console.log(`   ${u}  <- ${srcs.length} page(s), e.g. ${srcs[0]}`);
console.log(`jsonld:  ${ldBlocks} blocks, ${ldErrors.length} parse errors`);
for (const e of ldErrors.slice(0, 20)) console.log('   ' + e);
console.log(`sitemap: ${sitemapUrls} URLs, ${sitemapMissing.length} pointing nowhere${expect.length ? `, ${notListed.length} expected tool URLs missing` : ''}`);
for (const u of [...sitemapMissing, ...notListed].slice(0, 30)) console.log('   ' + u);
console.log(`og:      ${ogPages} pages with Open Graph tags, ${ogCards} per-page cards, ${ogErrors.length} problems`);
for (const e of ogErrors.slice(0, 30)) console.log('   ' + e);
const ok = !broken.size && !ldErrors.length && !sitemapMissing.length && !notListed.length && !ogErrors.length;
console.log(ok ? 'all static checks passed' : 'STATIC CHECKS FAILED');
process.exitCode = ok ? 0 : 1;

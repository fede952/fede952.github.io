// Build-output checks that need no browser, over public/:
//   links    every internal href/src/srcset in every HTML file resolves to a file
//   jsonld   every <script type=application/ld+json> parses
//   sitemap  every URL in the per-language sitemaps exists; --expect tools/x,tools/y
//            asserts those tool URLs are listed in all 6 languages
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
const ATTR = /(href|src|srcset|poster|data-src)=(?:"([^"]*)"|'([^']*)'|([^\s>]+))/g;
for (const f of html) {
  const rel = '/' + path.relative(PUB, f).split(path.sep).join('/');
  const raw = fs.readFileSync(f, 'utf8');
  for (const m of raw.matchAll(/<script type=["']?application\/ld\+json["']?>([\s\S]*?)<\/script>/g)) {
    ldBlocks++;
    try { JSON.parse(m[1]); } catch (e) { ldErrors.push(`${rel}: ${e.message.slice(0, 80)}`); }
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
const ok = !broken.size && !ldErrors.length && !sitemapMissing.length && !notListed.length;
console.log(ok ? 'all static checks passed' : 'STATIC CHECKS FAILED');
process.exitCode = ok ? 0 : 1;

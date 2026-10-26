// Unit tests for the SPF/DKIM/DMARC checker against offline DNS fixtures (fictional domains).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { generateKeyPairSync } from 'node:crypto';
import { txtValue, dohResolver, mapResolver, normalizeDomain, parseSpf, checkSpf, checkDmarc, checkDkim, rsaKeyBits, parseDkimKey, checkMx, checkDomain, SPF_LOOKUP_LIMIT } from '../../static/js/tools/mail-auth.mjs';

const Z = JSON.parse(fs.readFileSync(new URL('../fixtures/mail-auth/zones.json', import.meta.url), 'utf8'));
// public keys generated at test time, so no key material lives in the repo
const spki = (bits) => generateKeyPairSync('rsa', { modulusLength: bits }).publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
const KEYS = { RSA1024: spki(1024), RSA2048: spki(2048) };
const zone = (n) => { const m = {}; for (const [k, v] of Object.entries(Z[n])) m[k] = v.map((s) => s.replace(/\{\{(\w+)\}\}/g, (_, x) => KEYS[x])); return mapResolver(m); };
const ids = (r) => r.findings.map((f) => f.id);

test('TXT chunks are joined and unescaped; DoH resolver filters by type and sends the JSON accept header', async () => {
  assert.equal(txtValue('"v=spf1 a " "-all"'), 'v=spf1 a -all');
  assert.equal(txtValue('"quote \\" and \\059 semicolon"'), 'quote " and ; semicolon');
  let seen;
  const fetchFn = async (url, opts) => { seen = { url, opts }; return { ok: true, json: async () => Z['doh-sample'] } };
  const r = await dohResolver(fetchFn)('goodmail.example', 'TXT');
  assert.equal(seen.url, 'https://cloudflare-dns.com/dns-query?name=goodmail.example&type=TXT');
  assert.equal(seen.opts.headers.accept, 'application/dns-json');
  assert.deepEqual(r.answers, ['v=spf1 include:_spf.mailhost.example -all', 'quote " and ; semicolon']);
});

test('domain input normalisation', () => {
  assert.equal(normalizeDomain('Alex@GoodMail.Example'), 'goodmail.example');
  assert.equal(normalizeDomain('https://www.goodmail.example/path?q=1'), 'www.goodmail.example');
  assert.equal(normalizeDomain('goodmail.example.'), 'goodmail.example');
  assert.equal(normalizeDomain('bücher.example'), 'xn--bcher-kva.example');
  assert.equal(normalizeDomain('not a domain'), null);
  assert.equal(normalizeDomain('localhost'), null);
});

test('SPF parsing', () => {
  const t = parseSpf('v=spf1 -ip4:192.0.2.0/24 ~include:x.test mx/24 redirect=y.test');
  assert.deepEqual(t.map((x) => [x.kind, x.qualifier, x.name]), [['mechanism', '-', 'ip4'], ['mechanism', '~', 'include'], ['mechanism', '+', 'mx'], ['modifier', undefined, 'redirect']]);
  assert.equal(t[2].cidr, '/24');
});

test('SPF lookups are counted recursively, including repeated includes', async () => {
  const s = await checkSpf('badmail.test', zone('bad'));
  assert.equal(s.lookups, 24); // 6 + a.spf 7 + b 3 + e 1 + a.spf again 7
  assert(s.lookups > SPF_LOOKUP_LIMIT);
  assert.equal(s.ptr, true); assert.equal(s.macros, true); assert.equal(s.all, '+');
  assert.deepEqual(s.missing, ['gone.spf.test']);
  assert(s.voids > 2);
  const g = await checkSpf('goodmail.example', zone('good'));
  assert.equal(g.lookups, 1); assert.equal(g.all, '-'); assert.equal(g.tree.children[0].record, 'v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 -all');
});

test('SPF redirect, loops and multiple records', async () => {
  const s = await checkSpf('eu.brand.example', zone('inherit'));
  assert.equal(s.all, '-', 'all taken from the redirect target');
  assert.equal(s.tree.children[0].redirect, true);
  assert.equal(s.tree.children[0].children[0].error, 'loop');
  assert.equal((await checkSpf('news.shop.example', zone('sub'))).error, 'multiple');
});

test('DMARC: policy, pct, reports, external authorization and org-domain fallback', async () => {
  const b = await checkDmarc('badmail.test', zone('bad'));
  assert.equal(b.policy, 'quarantine'); assert.equal(b.pct, 25);
  assert.deepEqual(b.unauthorized, ['dmarc-vendor.test']);
  assert.equal(b.ruf.length, 1);
  const i = await checkDmarc('eu.brand.example', zone('inherit'));
  assert.equal(i.inherited, true); assert.equal(i.at, 'brand.example');
  assert.equal(i.policy, 'none', 'subdomain policy sp= applies');
  assert.deepEqual(i.unauthorized, []);
  assert.equal((await checkDmarc('news.shop.example', zone('sub'))).error, 'multiple');
  assert.equal((await checkDmarc('bare.invalid', zone('none'))).record, null);
});

test('DKIM key length from the public key, revoked and testing keys', async () => {
  assert.equal(rsaKeyBits(KEYS.RSA1024), 1024);
  assert.equal(rsaKeyBits(KEYS.RSA2048), 2048);
  assert.equal(rsaKeyBits('not base64!'), null);
  assert.equal(parseDkimKey('v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=').bits, 256);
  const d = await checkDkim('badmail.test', zone('bad'), ['s1', 'old', 'nope']);
  assert.deepEqual(d.found.map((k) => [k.selector, k.bits, k.revoked, !!k.testing]), [['s1', 1024, false, true], ['old', null, true, false]]);
  const g = await checkDkim('goodmail.example', zone('good'));
  assert.equal(g.guessed, true); assert.deepEqual(g.found.map((k) => [k.selector, k.bits]), [['selector1', 2048]]);
});

test('MX and null MX', async () => {
  assert.deepEqual((await checkMx('goodmail.example', zone('good'))).mx.map((m) => m.host), ['mx1.mailhost.example', 'mx2.mailhost.example']);
  assert.equal((await checkMx('parked.example', zone('nullmx'))).nullMx, true);
});

test('grading: a well-configured domain gets an A', async () => {
  const r = await checkDomain('goodmail.example', zone('good'));
  assert.equal(r.letter, 'A', ids(r).join());
  for (const id of ['spf-fail-all', 'spf-lookups-ok', 'dmarc-reject', 'dmarc-rua', 'dmarc-strict', 'dkim-ok', 'mx-ok', 'bimi-ok']) assert(ids(r).includes(id), id);
  assert.equal(r.fixes.length, 0);
});

test('grading: a broken domain gets an F with fixes', async () => {
  const r = await checkDomain('badmail.test', zone('bad'), ['s1', 'old']);
  assert.equal(r.letter, 'F');
  for (const id of ['spf-too-many', 'spf-plus-all', 'spf-ptr', 'spf-include-missing', 'spf-voids', 'spf-macros', 'dmarc-pct', 'dmarc-rua-unauthorized', 'dmarc-ruf', 'dkim-1024', 'dkim-testing', 'dkim-revoked', 'mx-missing', 'bimi-missing']) assert(ids(r).includes(id), id + ' in ' + ids(r));
  assert.equal(r.findings[0].sev, 'high');
  const fx = Object.fromEntries(r.fixes.map((f) => [f.id, f]));
  assert.equal(fx['fix-spf-all'].value, 'v=spf1 ptr include:a.spf.test include:b.spf.test include:gone.spf.test mx a ~all');
  assert(!/ptr/.test(fx['fix-spf-ptr'].value));
  assert.equal(fx['fix-dmarc-enforce'].value, 'v=DMARC1; p=quarantine; pct=100; rua=mailto:reports@dmarc-vendor.test');
  assert.equal(fx['fix-dmarc-auth'].host, 'badmail.test._report._dmarc.dmarc-vendor.test');
  assert(fx['fix-dkim-2048']);
});

test('grading: missing records, null MX, inherited DMARC, merged duplicate SPF', async () => {
  const n = await checkDomain('bare.invalid', zone('none'));
  assert(['spf-missing', 'dmarc-missing', 'dkim-not-found-guess', 'mx-missing'].every((id) => ids(n).includes(id)), ids(n));
  assert.equal(n.letter, 'F');
  assert.equal(n.fixes.find((f) => f.id === 'fix-dmarc-missing').value, 'v=DMARC1; p=none; rua=mailto:dmarc-reports@bare.invalid');
  const p = await checkDomain('parked.example', zone('nullmx'));
  assert(ids(p).includes('mx-null')); assert.equal(p.letter, 'A', ids(p).join());
  const s = await checkDomain('news.shop.example', zone('sub'));
  assert.equal(s.fixes.find((f) => f.id === 'fix-spf-multiple').value, 'v=spf1 include:_spf.shop.example ip4:192.0.2.9 ~all');
  const i = await checkDomain('eu.brand.example', zone('inherit'));
  assert(ids(i).includes('dmarc-inherited') && ids(i).includes('dmarc-none') && ids(i).includes('spf-loop'), ids(i));
});

test('every finding and fix has a string in all 6 languages', async () => {
  const src = fs.readFileSync(new URL('../../static/js/tools/mail-auth.mjs', import.meta.url), 'utf8');
  const fids = [...new Set([...src.matchAll(/add\('\w+', (?:[^,]*\? )?'([a-z0-9-]+)'(?: : '([a-z0-9-]+)')?/g)].flatMap((m) => [m[1], m[2]]).filter(Boolean))];
  const xids = [...new Set([...src.matchAll(/id: '(fix-[a-z0-9-]+)'/g)].map((m) => m[1]))];
  assert(fids.length > 40 && xids.length === 11, `${fids.length} findings, ${xids.length} fixes`);
  const en = (await import('../../static/js/tools/mail-auth/en.mjs')).default;
  for (const l of ['en', 'it', 'es', 'de', 'fr', 'pt']) {
    const s = (await import(`../../static/js/tools/mail-auth/${l}.mjs`)).default;
    for (const id of fids) assert(Array.isArray(s.f[id]) && s.f[id].length === 2, `${l}: finding ${id}`);
    for (const id of xids) assert(typeof s.fix[id] === 'string', `${l}: fix ${id}`);
    assert.deepEqual(Object.keys(s.ui).sort(), Object.keys(en.ui).sort(), `${l}: ui keys`);
    // placeholders must match English, or the UI shows raw {x}
    for (const id of fids) assert.deepEqual(s.f[id].join().match(/\{\w+\}/g)?.sort() || null, en.f[id].join().match(/\{\w+\}/g)?.sort() || null, `${l}: placeholders of ${id}`);
  }
});

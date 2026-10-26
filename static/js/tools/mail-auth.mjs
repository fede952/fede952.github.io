/* SPF / DKIM / DMARC / MX / BIMI checker logic, DOM-free.
   DNS goes through a resolver function (name, type) → { status, answers }.
   In the browser that is DNS-over-HTTPS (dohResolver); unit tests in
   tests/unit/mail-auth.test.mjs pass an offline fixture map instead.

   References: RFC 7208 (SPF; 10-lookup limit §4.6.4, void lookups §4.6.4,
   ptr "SHOULD NOT" §5.5), RFC 7489 (DMARC; tags §6.3, external report
   authorization §7.1, org-domain fallback §6.6.3), RFC 6376 (DKIM key
   record §3.6.1), RFC 8301 (RSA keys < 1024 bits must not be accepted),
   RFC 7505 (null MX), BIMI draft (default._bimi). */

export const DOH_URL = 'https://cloudflare-dns.com/dns-query';
export const TYPE = { A: 1, CNAME: 5, MX: 15, TXT: 16, AAAA: 28 };
export const SPF_LOOKUP_LIMIT = 10;
export const SPF_VOID_LIMIT = 2;
/* Selector names tried when the user gives none. Only names, no
   provider-specific claims: they are simply frequent in the wild. */
export const COMMON_SELECTORS = ['default', 'selector1', 'selector2', 'google', 'k1', 'k2', 's1', 's2', 'dkim', 'mail', 'smtp', 'mx'];

/* TXT data from DNS JSON arrives as one or more quoted chunks: "a" "b". */
export function txtValue(data) {
  const s = String(data).trim();
  if (!s.startsWith('"')) return s;
  let out = '', i = 0;
  while (i < s.length) {
    if (s[i] !== '"') { i++; continue; }
    i++;
    while (i < s.length && s[i] !== '"') {
      if (s[i] === '\\' && i + 1 < s.length) {
        const d = s.slice(i + 1, i + 4);
        if (/^\d{3}$/.test(d)) { out += String.fromCharCode(+d); i += 4; continue; }
        out += s[i + 1]; i += 2; continue;
      }
      out += s[i++];
    }
    i++;
  }
  return out;
}

/** DoH resolver for application/dns-json. Caches per name+type. */
export function dohResolver(fetchFn = globalThis.fetch, url = DOH_URL) {
  const cache = new Map();
  const resolver = async (name, type) => {
    const key = name.toLowerCase() + '|' + type;
    if (!cache.has(key)) {
      cache.set(key, (async () => {
        const res = await fetchFn(`${url}?name=${encodeURIComponent(name)}&type=${type}`, { headers: { accept: 'application/dns-json' } });
        if (!res.ok) throw new Error('DoH HTTP ' + res.status);
        const j = await res.json();
        const want = TYPE[type];
        return { status: j.Status, answers: (j.Answer || []).filter((a) => a.type === want).map((a) => (type === 'TXT' ? txtValue(a.data) : a.data)) };
      })());
    }
    const r = cache.get(key);
    r.catch(() => cache.delete(key));
    resolver.queries = cache.size;
    return r;
  };
  resolver.queries = 0;
  return resolver;
}

/** Fixture resolver for tests: { 'name|TXT': ['…'], 'name|MX': ['10 mx.x.'] }; missing → NXDOMAIN. */
export function mapResolver(map) {
  const r = async (name, type) => {
    r.log.push(name.toLowerCase() + '|' + type);
    const v = map[name.toLowerCase() + '|' + type];
    if (v === 'SERVFAIL') return { status: 2, answers: [] };
    if (v) return { status: 0, answers: v };
    const exists = Object.keys(map).some((k) => k.split('|')[0] === name.toLowerCase());
    return { status: exists ? 0 : 3, answers: [] };
  };
  r.log = [];
  return r;
}

/** Normalise user input (email, URL or domain) to an ASCII domain, or null. */
export function normalizeDomain(input) {
  let s = String(input || '').trim().toLowerCase();
  if (!s) return null;
  if (s.includes('@') && !s.includes('/')) s = s.slice(s.lastIndexOf('@') + 1);
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, '').replace(/[/?#:].*$/, '').replace(/\.$/, '');
  try { s = new URL('http://' + s).hostname; } catch { return null; }
  if (!/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/.test(s)) return null;
  return s;
}

/* Two-label public suffixes common in mail domains (same idea as the email header analyzer). */
const TWO_LABEL = new Set(['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'co.nz', 'co.jp', 'ne.jp', 'or.jp', 'com.br', 'com.mx', 'com.ar', 'co.za', 'co.in', 'co.kr', 'com.cn', 'com.tr', 'com.sg', 'com.hk']);
export function orgDomain(d) {
  const p = d.split('.');
  if (p.length <= 2) return d;
  return p.slice(TWO_LABEL.has(p.slice(-2).join('.')) ? -3 : -2).join('.');
}

/* ---------- SPF ---------- */

const DNS_TERMS = new Set(['include', 'a', 'mx', 'ptr', 'exists']);

/** Parse an SPF record into terms. */
export function parseSpf(record) {
  const parts = record.trim().split(/\s+/);
  const terms = [];
  for (const raw of parts.slice(1)) {
    const mod = raw.match(/^([a-z][a-z0-9_.-]*)=(.*)$/i);
    if (mod) { terms.push({ raw, kind: 'modifier', name: mod[1].toLowerCase(), value: mod[2] }); continue; }
    const m = raw.match(/^([+\-~?]?)([a-z0-9]+)(?::([^/]*))?(\/.*)?$/i);
    if (!m) { terms.push({ raw, kind: 'invalid' }); continue; }
    terms.push({ raw, kind: 'mechanism', qualifier: m[1] || '+', name: m[2].toLowerCase(), value: m[3] || '', cidr: m[4] || '' });
  }
  return terms;
}

const isSpf = (t) => /^v=spf1(\s|$)/i.test(t);

/**
 * Evaluate the SPF tree of a domain: lookups counted recursively per RFC 7208
 * §4.6.4 (include, a, mx, ptr, exists, redirect), void lookups, loops, ptr.
 */
export async function checkSpf(domain, resolve) {
  // `path` holds the includes being evaluated: a repeat on the path is a loop,
  // a repeat elsewhere (diamond) is evaluated, and counted, again as receivers do.
  const state = { lookups: 0, voids: 0, ptr: false, macros: false, missing: [], path: new Set() };
  async function walk(d, depth) {
    if (state.path.has(d)) return { domain: d, record: null, lookups: 0, children: [], error: 'loop', all: null };
    state.path.add(d);
    try { return await evaluate(d, depth); } finally { state.path.delete(d); }
  }
  async function evaluate(d, depth) {
    const node = { domain: d, record: null, lookups: 0, children: [], error: null, all: null };
    if (state.lookups > 60) { node.error = 'depth'; return node; }
    let r;
    try { r = await resolve(d, 'TXT'); } catch (e) { node.error = 'dns'; return node; }
    if (r.status === 2) { node.error = 'servfail'; return node; }
    const recs = r.answers.filter(isSpf);
    if (!recs.length) { node.error = 'none'; return node; }
    if (recs.length > 1) { node.error = 'multiple'; node.record = recs.join(' | '); return node; }
    node.record = recs[0];
    const terms = parseSpf(node.record);
    node.terms = terms;
    const hasAll = terms.some((t) => t.kind === 'mechanism' && t.name === 'all');
    for (const t of terms) {
      if (t.kind === 'invalid') { node.invalid = (node.invalid || []).concat(t.raw); continue; }
      if (t.kind === 'mechanism') {
        if (t.name === 'all') node.all = t.qualifier;
        if (!DNS_TERMS.has(t.name)) continue;
        state.lookups++; node.lookups++;
        if (t.name === 'ptr') state.ptr = true;
        if (t.value.includes('%')) { state.macros = true; continue; }
        if (t.name === 'include') {
          if (depth > 12) { node.error = 'depth'; continue; }
          const child = await walk(t.value.toLowerCase(), depth + 1);
          if (child.error === 'none') { state.voids++; state.missing.push(child.domain); }
          node.children.push(child);
        } else if (t.name === 'mx') {
          const target = (t.value || d).toLowerCase();
          try {
            const mx = await resolve(target, 'MX');
            if (!mx.answers.length) state.voids++;
            if (mx.answers.length > 10) node.error = 'mx-over-10';
          } catch { /* counted anyway */ }
        }
      } else if (t.name === 'redirect' && !hasAll) {
        state.lookups++; node.lookups++;
        if (t.value.includes('%')) { state.macros = true; continue; }
        const child = await walk(t.value.toLowerCase(), depth + 1);
        child.redirect = true;
        if (child.error === 'none') { state.voids++; state.missing.push(child.domain); }
        node.children.push(child);
        if (child.all) node.all = child.all;
      }
    }
    return node;
  }
  const tree = await walk(domain, 0);
  return { tree, record: tree.record, all: tree.all, lookups: state.lookups, voids: state.voids, ptr: state.ptr, macros: state.macros, missing: state.missing, error: tree.error };
}

/* ---------- DMARC ---------- */

export function parseTags(record) {
  const tags = {};
  for (const part of record.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    const k = part.slice(0, i).trim().toLowerCase();
    if (k && !(k in tags)) tags[k] = part.slice(i + 1).trim();
  }
  return tags;
}

const uriDomain = (u) => { const m = u.trim().match(/^mailto:[^@]+@([^!\s]+)/i); return m ? m[1].toLowerCase().replace(/\.$/, '') : null; };

export async function checkDmarc(domain, resolve) {
  const lookup = async (d) => {
    const r = await resolve('_dmarc.' + d, 'TXT');
    return r.answers.filter((t) => /^v=DMARC1\s*(;|$)/i.test(t));
  };
  let at = domain, recs = await lookup(domain), inherited = false;
  const org = orgDomain(domain);
  if (!recs.length && org !== domain) { recs = await lookup(org); at = org; inherited = true; }
  if (!recs.length) return { record: null };
  if (recs.length > 1) return { record: recs.join(' | '), error: 'multiple' };
  const tags = parseTags(recs[0]);
  const policy = (inherited && tags.sp ? tags.sp : tags.p || '').toLowerCase();
  const res = {
    record: recs[0], at, inherited, tags,
    policy: ['none', 'quarantine', 'reject'].includes(policy) ? policy : null,
    pct: tags.pct === undefined ? 100 : Math.max(0, Math.min(100, parseInt(tags.pct, 10))),
    rua: (tags.rua || '').split(',').map((s) => s.trim()).filter(Boolean),
    ruf: (tags.ruf || '').split(',').map((s) => s.trim()).filter(Boolean),
    adkim: (tags.adkim || 'r').toLowerCase(), aspf: (tags.aspf || 'r').toLowerCase(),
    sp: tags.sp ? tags.sp.toLowerCase() : null, unauthorized: [],
  };
  if (Number.isNaN(res.pct)) res.pct = 100;
  // RFC 7489 §7.1: report addresses in another org domain must be authorized there
  for (const u of [...res.rua, ...res.ruf]) {
    const rd = uriDomain(u);
    if (!rd || orgDomain(rd) === orgDomain(at)) continue;
    const r = await resolve(`${at}._report._dmarc.${rd}`, 'TXT');
    if (!r.answers.some((t) => /^v=DMARC1/i.test(t))) res.unauthorized.push(rd);
  }
  return res;
}

/* ---------- DKIM ---------- */

/** Read DER length at offset; returns [length, headerBytes]. */
function derLen(b, i) {
  const f = b[i];
  if (f < 0x80) return [f, 1];
  const n = f & 0x7f; let len = 0;
  for (let k = 1; k <= n; k++) len = len * 256 + b[i + k];
  return [len, 1 + n];
}
/** Bit length of the RSA modulus in a DKIM p= value (SPKI or bare RSAPublicKey). */
export function rsaKeyBits(b64) {
  let bin;
  try { bin = atob(b64.replace(/\s+/g, '')); } catch { return null; }
  const b = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  const seq = (i) => { if (b[i] !== 0x30) return null; const [l, h] = derLen(b, i + 1); return { start: i + 1 + h, end: i + 1 + h + l }; };
  const modulusAt = (i) => {
    const s = seq(i); if (!s || b[s.start] !== 0x02) return null;
    let [l, h] = derLen(b, s.start + 1); let p = s.start + 1 + h;
    while (l > 0 && b[p] === 0) { p++; l--; }
    if (!l) return null;
    let bits = l * 8, top = b[p];
    while (top < 0x80) { bits--; top <<= 1; }
    return bits;
  };
  const outer = seq(0);
  if (!outer) return null;
  if (b[outer.start] === 0x30) { // SPKI: SEQ { SEQ algId, BIT STRING { RSAPublicKey } }
    const alg = seq(outer.start);
    if (!alg) return null;
    const [al, ah] = derLen(b, outer.start + 1);
    const bs = outer.start + 1 + ah + al;
    if (b[bs] !== 0x03) return null;
    const [, bh] = derLen(b, bs + 1);
    return modulusAt(bs + 1 + bh + 1);
  }
  return modulusAt(0);
}

export function parseDkimKey(record) {
  const tags = parseTags(record);
  const k = (tags.k || 'rsa').toLowerCase();
  const p = (tags.p || '').replace(/\s+/g, '');
  if (!p) return { tags, k, revoked: true, bits: null };
  return { tags, k, revoked: false, bits: k === 'ed25519' ? 256 : rsaKeyBits(p), testing: /(^|:)y(:|$)/.test(tags.t || '') };
}

export async function checkDkim(domain, resolve, selectors) {
  const guessed = !selectors || !selectors.length;
  const list = guessed ? COMMON_SELECTORS : selectors;
  const found = [];
  await Promise.all(list.map(async (s) => {
    const r = await resolve(`${s}._domainkey.${domain}`, 'TXT');
    const rec = r.answers.find((t) => /(^|;)\s*p=/i.test(t) || /^v=DKIM1/i.test(t));
    if (rec) found.push({ selector: s, record: rec, ...parseDkimKey(rec) });
  }));
  found.sort((a, b) => list.indexOf(a.selector) - list.indexOf(b.selector));
  return { guessed, tried: list, found };
}

/* ---------- MX / BIMI ---------- */

export async function checkMx(domain, resolve) {
  const r = await resolve(domain, 'MX');
  const mx = r.answers.map((a) => { const [pr, ...h] = String(a).trim().split(/\s+/); return { pref: +pr, host: h.join(' ').replace(/\.$/, '') || '.' }; }).sort((a, b) => a.pref - b.pref);
  const nullMx = mx.length === 1 && (mx[0].host === '.' || mx[0].host === '');
  return { mx, nullMx };
}

export async function checkBimi(domain, resolve) {
  const r = await resolve('default._bimi.' + domain, 'TXT');
  const rec = r.answers.find((t) => /^v=BIMI1/i.test(t));
  if (!rec) return { record: null };
  const tags = parseTags(rec);
  return { record: rec, logo: tags.l || '', vmc: tags.a || '' };
}

/* ---------- grading ---------- */

/**
 * Turn the raw results into findings { id, sev, area, p } and a letter grade.
 * sev: high | medium | low | info | good. Scores start at 100 and lose points.
 */
export function grade(domain, { spf, dmarc, dkim, mx, bimi }) {
  const f = [];
  const add = (area, id, sev, p = {}) => f.push({ area, id, sev, p });
  const PEN = { high: 30, medium: 12, low: 4, info: 0, good: 0 };
  const noMail = mx && mx.nullMx;

  // SPF
  if (spf.error === 'none') add('spf', 'spf-missing', noMail ? 'medium' : 'high');
  else if (spf.error === 'multiple') add('spf', 'spf-multiple', 'high');
  else if (spf.error === 'servfail' || spf.error === 'dns') add('spf', 'spf-dns', 'medium');
  else {
    if (spf.lookups > SPF_LOOKUP_LIMIT) add('spf', 'spf-too-many', 'high', { n: spf.lookups });
    else if (spf.lookups >= 8) add('spf', 'spf-near-limit', 'low', { n: spf.lookups });
    else add('spf', 'spf-lookups-ok', 'good', { n: spf.lookups });
    // RFC 7208 §5.2: an include (or redirect) target without an SPF record is a permerror
    if (spf.missing.length) add('spf', 'spf-include-missing', 'high', { domains: spf.missing.join(', ') });
    if (spf.voids > SPF_VOID_LIMIT) add('spf', 'spf-voids', 'medium', { n: spf.voids });
    if (spf.ptr) add('spf', 'spf-ptr', 'medium');
    if (spf.macros) add('spf', 'spf-macros', 'info');
    if (hasLoop(spf.tree)) add('spf', 'spf-loop', 'high');
    if (hasInvalid(spf.tree)) add('spf', 'spf-invalid', 'high');
    const all = spf.all;
    if (all === '+') add('spf', 'spf-plus-all', 'high');
    else if (all === '?' ) add('spf', 'spf-neutral-all', 'medium');
    else if (all === null) add('spf', 'spf-no-all', 'medium');
    else if (all === '~') add('spf', 'spf-softfail-all', 'info');
    else if (all === '-') add('spf', 'spf-fail-all', 'good');
  }

  // DMARC
  if (!dmarc.record) add('dmarc', 'dmarc-missing', 'high');
  else if (dmarc.error === 'multiple') add('dmarc', 'dmarc-multiple', 'high');
  else {
    if (dmarc.inherited) add('dmarc', 'dmarc-inherited', 'info', { at: dmarc.at });
    if (!dmarc.policy) add('dmarc', 'dmarc-bad-policy', 'high');
    else if (dmarc.policy === 'none') add('dmarc', 'dmarc-none', 'medium');
    else if (dmarc.policy === 'quarantine') add('dmarc', 'dmarc-quarantine', 'good');
    else add('dmarc', 'dmarc-reject', 'good');
    if (dmarc.policy && dmarc.policy !== 'none' && dmarc.pct < 100) add('dmarc', 'dmarc-pct', 'low', { pct: dmarc.pct });
    if (!dmarc.inherited && dmarc.sp === 'none' && dmarc.policy && dmarc.policy !== 'none') add('dmarc', 'dmarc-sp-none', 'low');
    if (!dmarc.rua.length) add('dmarc', 'dmarc-no-rua', 'low');
    else add('dmarc', 'dmarc-rua', 'good', { n: dmarc.rua.length });
    if (dmarc.unauthorized.length) add('dmarc', 'dmarc-rua-unauthorized', 'low', { domains: dmarc.unauthorized.join(', ') });
    if (dmarc.ruf.length) add('dmarc', 'dmarc-ruf', 'info');
    if (dmarc.adkim === 's' || dmarc.aspf === 's') add('dmarc', 'dmarc-strict', 'info', { which: [dmarc.adkim === 's' && 'DKIM', dmarc.aspf === 's' && 'SPF'].filter(Boolean).join(' + ') });
  }

  // DKIM
  if (!dkim.found.length) add('dkim', dkim.guessed ? 'dkim-not-found-guess' : 'dkim-not-found', dkim.guessed ? 'info' : 'medium', { selectors: dkim.tried.join(', ') });
  for (const k of dkim.found) {
    const p = { selector: k.selector, bits: k.bits };
    if (k.revoked) add('dkim', 'dkim-revoked', 'info', p);
    else if (k.k === 'ed25519') add('dkim', 'dkim-ed25519', 'good', p);
    else if (!k.bits) add('dkim', 'dkim-unreadable', 'medium', p);
    else if (k.bits < 1024) add('dkim', 'dkim-weak', 'high', p);
    else if (k.bits < 2048) add('dkim', 'dkim-1024', 'low', p);
    else add('dkim', 'dkim-ok', 'good', p);
    if (k.testing) add('dkim', 'dkim-testing', 'low', p);
  }

  // MX
  if (mx) {
    if (mx.nullMx) add('mx', 'mx-null', 'info');
    else if (!mx.mx.length) add('mx', 'mx-missing', 'low');
    else add('mx', 'mx-ok', 'good', { n: mx.mx.length });
  }

  // BIMI
  if (bimi) {
    if (!bimi.record) add('bimi', 'bimi-missing', 'info');
    else {
      const enforced = dmarc.policy && dmarc.policy !== 'none' && dmarc.pct === 100;
      add('bimi', enforced ? 'bimi-ok' : 'bimi-needs-enforcement', enforced ? 'good' : 'low');
    }
  }

  const score = Math.max(0, 100 - f.reduce((s, x) => s + PEN[x.sev], 0));
  const letter = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
  const order = { high: 0, medium: 1, low: 2, info: 3, good: 4 };
  f.sort((a, b) => order[a.sev] - order[b.sev]);
  return { findings: f, score, letter };
}
function hasLoop(n) { return n.error === 'loop' || n.children.some(hasLoop); }
function hasInvalid(n) { return !!(n.invalid && n.invalid.length) || n.children.some(hasInvalid); }

/* ---------- fix suggestions ---------- */

/** Example records for the problems found. Placeholders are marked with angle brackets. */
export function suggestions(domain, res, findings) {
  const ids = new Set(findings.map((x) => x.id));
  const out = [];
  if (ids.has('spf-missing')) out.push({ id: 'fix-spf-missing', host: domain, type: 'TXT', value: res.mx && res.mx.nullMx ? 'v=spf1 -all' : 'v=spf1 mx include:<your-mail-provider> -all' });
  if (ids.has('spf-multiple')) out.push({ id: 'fix-spf-multiple', host: domain, type: 'TXT', value: mergeSpf(res.spf.record) });
  const base = res.spf.record && !res.spf.error ? res.spf.record : null;
  if (base && (ids.has('spf-plus-all') || ids.has('spf-neutral-all') || ids.has('spf-no-all'))) {
    out.push({ id: 'fix-spf-all', host: domain, type: 'TXT', value: ids.has('spf-no-all') ? base.trim() + ' ~all' : base.replace(/\s[+?]?all\b/i, ' ~all') });
  }
  if (base && ids.has('spf-ptr')) out.push({ id: 'fix-spf-ptr', host: domain, type: 'TXT', value: base.replace(/\s[+?~-]?ptr(:\S+)?/gi, '').trim() });
  if (ids.has('spf-too-many')) out.push({ id: 'fix-spf-too-many', host: domain, type: 'TXT', value: null });
  if (ids.has('dmarc-missing')) out.push({ id: 'fix-dmarc-missing', host: '_dmarc.' + domain, type: 'TXT', value: `v=DMARC1; p=none; rua=mailto:dmarc-reports@${domain}` });
  if (ids.has('dmarc-none') || ids.has('dmarc-pct') || ids.has('dmarc-bad-policy')) {
    const rua = res.dmarc.rua && res.dmarc.rua.length ? res.dmarc.rua.join(',') : `mailto:dmarc-reports@${domain}`;
    out.push({ id: 'fix-dmarc-enforce', host: '_dmarc.' + res.dmarc.at, type: 'TXT', value: `v=DMARC1; p=quarantine; pct=100; rua=${rua}` });
  }
  if (ids.has('dmarc-no-rua') && !ids.has('dmarc-none') && !ids.has('dmarc-pct')) out.push({ id: 'fix-dmarc-rua', host: '_dmarc.' + res.dmarc.at, type: 'TXT', value: res.dmarc.record.replace(/;?\s*$/, '') + `; rua=mailto:dmarc-reports@${res.dmarc.at}` });
  if (ids.has('dmarc-rua-unauthorized')) for (const d of res.dmarc.unauthorized) out.push({ id: 'fix-dmarc-auth', host: `${res.dmarc.at}._report._dmarc.${d}`, type: 'TXT', value: 'v=DMARC1' });
  if (ids.has('dkim-weak') || ids.has('dkim-1024')) out.push({ id: 'fix-dkim-2048', host: `<new-selector>._domainkey.${domain}`, type: 'TXT', value: 'v=DKIM1; k=rsa; p=<2048-bit public key from your mail provider>' });
  if (ids.has('dkim-not-found')) out.push({ id: 'fix-dkim-missing', host: `<selector>._domainkey.${domain}`, type: 'TXT', value: 'v=DKIM1; k=rsa; p=<public key from your mail provider>' });
  return out;
}
function mergeSpf(joined) {
  const recs = joined.split(' | ');
  const seen = new Set(), terms = [];
  let all = null;
  for (const r of recs) for (const t of r.trim().split(/\s+/).slice(1)) {
    if (/^[+?~-]?all$/i.test(t)) { all = all || t; continue; }
    if (!seen.has(t.toLowerCase())) { seen.add(t.toLowerCase()); terms.push(t); }
  }
  return ['v=spf1', ...terms, all || '~all'].join(' ');
}

/** Run every check. `selectors` is optional (comma list). */
export async function checkDomain(domain, resolve, selectors) {
  const [spf, dmarc, dkim, mx, bimi] = await Promise.all([
    checkSpf(domain, resolve), checkDmarc(domain, resolve), checkDkim(domain, resolve, selectors), checkMx(domain, resolve), checkBimi(domain, resolve),
  ]);
  const res = { domain, spf, dmarc, dkim, mx, bimi };
  const g = grade(domain, res);
  return { ...res, ...g, fixes: suggestions(domain, res, g.findings) };
}

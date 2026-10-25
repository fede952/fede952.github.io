/* HTTP security header and Content-Security-Policy analysis for
   tools/security-headers. Pure functions, no network, no DOM: the input is
   text the user pasted. Findings are { id, sev, header, p } where `id` is a
   message key the app translates, `sev` is high|medium|low|info|good and `p`
   holds the values the message refers to. */

export const SEV_WEIGHT = { high: 20, medium: 10, low: 4, info: 0, good: 0 };

const DIRECTIVES = new Set([
  'default-src', 'script-src', 'script-src-elem', 'script-src-attr', 'style-src', 'style-src-elem', 'style-src-attr',
  'img-src', 'font-src', 'connect-src', 'media-src', 'object-src', 'frame-src', 'child-src', 'worker-src', 'manifest-src',
  'fenced-frame-src', 'base-uri', 'form-action', 'frame-ancestors', 'sandbox', 'report-uri', 'report-to',
  'upgrade-insecure-requests', 'require-trusted-types-for', 'trusted-types', 'webrtc',
  // deprecated or removed, still recognised so they are reported as such and not as typos
  'block-all-mixed-content', 'plugin-types', 'prefetch-src', 'navigate-to', 'referrer', 'reflected-xss', 'require-sri-for', 'disown-opener',
]);
const DEPRECATED = new Set(['block-all-mixed-content', 'plugin-types', 'prefetch-src', 'navigate-to', 'referrer', 'reflected-xss', 'require-sri-for', 'disown-opener']);
const KEYWORDS = new Set(['self', 'none', 'unsafe-inline', 'unsafe-eval', 'strict-dynamic', 'unsafe-hashes', 'report-sample', 'wasm-unsafe-eval', 'inline-speculation-rules', 'unsafe-allow-redirects']);
/* Hosts that serve JSONP endpoints or arbitrary versions of libraries such as old
   AngularJS, so allow-listing them for scripts lets an attacker run their own code
   (the cases Google's CSP Evaluator flags). */
const BYPASS_HOSTS = [
  'www.google.com', 'accounts.google.com', 'ajax.googleapis.com', 'www.googleapis.com', 'storage.googleapis.com',
  'cdnjs.cloudflare.com', 'cdn.jsdelivr.net', 'unpkg.com', 'raw.githubusercontent.com', 'gist.githubusercontent.com',
  'www.gstatic.com', 'api.twitter.com', 'connect.facebook.net', 'www.youtube.com', 'code.jquery.com',
];
const SCRIPT_DIRS = ['script-src', 'script-src-elem', 'script-src-attr'];

/* ── parsing ─────────────────────────────────────────────────────────── */

/** Pulls the policy out of a pasted <meta http-equiv="Content-Security-Policy" content="…">. */
function fromMeta(text) {
  const m = text.match(/<meta[^>]+http-equiv\s*=\s*["']?content-security-policy["']?[^>]*>/i);
  if (!m) return null;
  const c = m[0].match(/content\s*=\s*(["'])([\s\S]*?)\1/i);
  return c ? c[2].replace(/&#39;|&apos;/g, "'").replace(/&quot;/g, '"').replace(/&amp;/g, '&') : null;
}

/**
 * Parses pasted response headers (curl -I, browser DevTools, raw HTTP) or a bare CSP.
 * Returns { mode: 'headers'|'csp'|'empty', headers: Map<lowercase name, string[]>, csp?: string }.
 */
export function parseInput(text) {
  const src = String(text || '').replace(/\r\n?/g, '\n').trim();
  if (!src) return { mode: 'empty', headers: new Map() };
  const meta = fromMeta(src);
  if (meta !== null) return { mode: 'csp', headers: new Map(), csp: meta };
  const first = src.split(/[\s;]/)[0].toLowerCase();
  if (DIRECTIVES.has(first)) return { mode: 'csp', headers: new Map(), csp: src.replace(/\n+/g, ' ') };
  const headers = new Map();
  let last = null;
  for (const raw of src.split('\n')) {
    if (/^\s*$/.test(raw)) continue;
    if (/^HTTP\/\d/i.test(raw.trim())) { headers.clear(); last = null; continue; } // a redirect chain: keep the last response
    if (/^[ \t]/.test(raw) && last) { last.arr[last.arr.length - 1] += ' ' + raw.trim(); continue; } // folded line
    const m = raw.match(/^\s*(:?[A-Za-z0-9!#$%&'*+.^_`|~-]+)\s*:\s?(.*)$/);
    if (!m) continue;
    const name = m[1].toLowerCase();
    if (name.startsWith(':')) continue; // HTTP/2 pseudo-headers such as :status
    if (!headers.has(name)) headers.set(name, []);
    headers.get(name).push(m[2].trim());
    last = { arr: headers.get(name) };
  }
  return { mode: headers.size ? 'headers' : 'empty', headers };
}

/** Splits a policy into directives: [{ name, sources: [token], dup }]. */
export function parseCsp(policy) {
  const out = [], seen = new Set();
  for (const part of String(policy).split(';')) {
    const toks = part.trim().split(/\s+/).filter(Boolean);
    if (!toks.length) continue;
    const name = toks[0].toLowerCase();
    out.push({ name, sources: toks.slice(1), dup: seen.has(name) });
    seen.add(name);
  }
  return out;
}

/* ── CSP analysis ─────────────────────────────────────────────────────── */

const lc = (s) => s.toLowerCase();
const isNonce = (s) => /^'nonce-[^']+'$/i.test(s);
const isHash = (s) => /^'sha(256|384|512)-[^']+'$/i.test(s);
function hostOf(source) {
  const m = source.match(/^(?:[a-z][a-z0-9+.-]*:\/\/)?([^/:'"]+)(?::\d+|:\*)?(?:\/.*)?$/i);
  return m ? m[1].toLowerCase() : '';
}
/** Is this allow-listed source one of the known script-gadget hosts (or a wildcard covering one)? */
export function bypassHost(source) {
  if (source.startsWith("'") || /^[a-z]+:$/i.test(source)) return null;
  const host = hostOf(source);
  if (!host) return null;
  if (host.startsWith('*.')) { const base = host.slice(1); return BYPASS_HOSTS.find((h) => h.endsWith(base)) || null; }
  return BYPASS_HOSTS.includes(host) ? host : null;
}

/** Risk label for one source token in a script context, used to colour it in the UI. */
export function sourceRisk(source, directive) {
  const s = lc(source);
  const script = SCRIPT_DIRS.includes(directive) || directive === 'default-src' || directive === 'object-src';
  if (s === "'unsafe-inline'" || s === "'unsafe-eval'") return script ? 'high' : 'low';
  if (s === "'none'" || s === "'self'" || isNonce(source) || isHash(source) || s === "'strict-dynamic'") return 'good';
  if (!script) return s === '*' || s === 'http:' ? 'low' : null;
  if (s === '*' || s === 'https:' || s === 'http:' || s === 'data:') return 'high';
  if (s === 'blob:' || s.startsWith('http://') || bypassHost(source)) return 'medium';
  return null;
}

/**
 * Analyses one policy. `ctx` = { headers: true when other headers are known, hasXfo }.
 * Returns findings (header: 'content-security-policy').
 */
export function analyzeCsp(policy, ctx = {}) {
  const H = 'content-security-policy';
  const f = [];
  const add = (id, sev, p = {}) => f.push({ id, sev, header: H, p });
  const dirs = parseCsp(policy);
  const get = (n) => dirs.find((d) => d.name === n && !d.dup);

  for (const d of dirs) {
    if (!DIRECTIVES.has(d.name)) { add('csp-unknown-directive', 'medium', { directive: d.name }); continue; }
    if (d.dup) add('csp-duplicate-directive', 'low', { directive: d.name });
    if (DEPRECATED.has(d.name)) add('csp-deprecated-directive', 'info', { directive: d.name });
    for (const s of d.sources) {
      const bare = lc(s).replace(/^'|'$/g, '');
      if (!s.startsWith("'") && (KEYWORDS.has(bare) || /^(nonce|sha256|sha384|sha512)-/.test(bare))) add('csp-unquoted-keyword', 'medium', { directive: d.name, source: s });
      else if (DIRECTIVES.has(lc(s)) && d.name !== 'report-to' && d.name !== 'trusted-types') add('csp-missing-semicolon', 'medium', { directive: d.name, source: s });
    }
    if (d.sources.length > 1 && d.sources.some((s) => lc(s) === "'none'")) add('csp-none-combined', 'low', { directive: d.name });
  }

  // Scripts: the first of script-src / default-src that exists governs them.
  const script = get('script-src') || get('default-src');
  if (!script) add('csp-no-script-restriction', 'high');
  else {
    const S = script.sources, L = S.map(lc);
    const nonce = S.find(isNonce), hash = S.some(isHash), dynamic = L.includes("'strict-dynamic'");
    if (L.includes("'unsafe-inline'")) {
      if (nonce || hash) add('csp-unsafe-inline-ignored', 'info', { directive: script.name });
      else add('csp-unsafe-inline', 'high', { directive: script.name });
    }
    if (L.includes("'unsafe-eval'")) add('csp-unsafe-eval', 'medium', { directive: script.name });
    // With 'strict-dynamic', browsers ignore host and scheme allow-lists, so they are not a risk then.
    if (!dynamic) {
      for (const s of S) {
        const l = lc(s);
        if (l === '*') add('csp-wildcard', 'high', { directive: script.name, source: s });
        else if (l === 'https:' || l === 'http:' || l === 'data:') add('csp-scheme-source', 'high', { directive: script.name, source: s });
        else if (l === 'blob:') add('csp-scheme-source', 'medium', { directive: script.name, source: s });
        else if (l.startsWith('http://')) add('csp-http-source', 'medium', { directive: script.name, source: s });
        else { const h = bypassHost(s); if (h) add('csp-bypass-host', 'medium', { directive: script.name, source: s, host: h }); }
      }
    }
    if (dynamic && !nonce && !hash) add('csp-strict-dynamic-no-nonce', 'medium', { directive: script.name });
    if (nonce) {
      const value = nonce.slice(7, -1);
      // 128 bits is the minimum the CSP spec recommends: about 22 base64 characters.
      if (value.length < 22) add('csp-short-nonce', 'medium', { directive: script.name, length: value.length });
    }
    if ((nonce || hash) && dynamic) add('csp-strict-ok', 'good', { directive: script.name });
    else if ((nonce || hash) && !L.includes("'unsafe-inline'")) add('csp-nonce-ok', 'good', { directive: script.name });
  }
  for (const n of ['script-src-elem', 'script-src-attr']) {
    const d = get(n);
    if (d && d.sources.map(lc).includes("'unsafe-inline'") && !d.sources.some((s) => isNonce(s) || isHash(s))) add('csp-unsafe-inline', 'high', { directive: n });
  }

  // Plugins: object-src falls back to default-src.
  const obj = get('object-src') || get('default-src');
  const objSrc = obj ? obj.sources.map(lc) : [];
  if (!obj || !(objSrc.length === 1 && objSrc[0] === "'none'")) {
    add('csp-object-src', objSrc.length === 1 && objSrc[0] === "'self'" ? 'low' : 'medium', { directive: obj ? obj.name : 'object-src' });
  }
  // base-uri and form-action do not fall back to default-src.
  if (!get('base-uri')) add('csp-base-uri-missing', script && script.sources.some((s) => isNonce(s) || isHash(s)) ? 'medium' : 'low');
  if (!get('form-action')) add('csp-form-action-missing', 'low');
  if (!get('frame-ancestors') && ctx.headers && !ctx.hasXfo) add('csp-frame-ancestors-missing', 'medium');
  if (get('report-uri') && !get('report-to')) add('csp-report-uri-only', 'info');
  if (get('upgrade-insecure-requests')) add('csp-upgrade-ok', 'good');
  const style = get('style-src') || get('default-src');
  if (style && style.name === 'style-src' && style.sources.map(lc).includes("'unsafe-inline'")) add('csp-style-inline', 'info');
  return f;
}

/* ── header analysis ──────────────────────────────────────────────────── */

const DISCLOSURE = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator', 'x-drupal-cache', 'x-runtime', 'x-version'];

function cookieFindings(values, add) {
  for (const v of values) {
    const [pair, ...attrs] = v.split(';');
    const name = pair.split('=')[0].trim();
    if (!name) continue;
    const a = new Map(attrs.map((x) => { const [k, ...r] = x.split('='); return [k.trim().toLowerCase(), r.join('=').trim()]; }));
    const secure = a.has('secure'), same = (a.get('samesite') || '').toLowerCase();
    if (same === 'none' && !secure) add('cookie-samesite-none-insecure', 'high', { name });
    else if (!secure) add('cookie-no-secure', 'medium', { name });
    if (!a.has('httponly')) add('cookie-no-httponly', 'low', { name });
    if (!a.has('samesite')) add('cookie-no-samesite', 'low', { name });
    if (name.startsWith('__Host-') && (!secure || a.has('domain') || a.get('path') !== '/')) add('cookie-host-prefix', 'medium', { name });
    if (name.startsWith('__Secure-') && !secure) add('cookie-secure-prefix', 'medium', { name });
  }
}

/** Full analysis. Returns { mode, findings, policies: [{ kind, policy, directives }], score, grade, headers }. */
export function analyze(text) {
  const input = parseInput(text);
  const { headers } = input;
  const findings = [];
  const add = (id, sev, p = {}, header = '') => findings.push({ id, sev, header, p });
  const one = (n) => (headers.get(n) || [])[0];
  const policies = [];

  if (input.mode === 'empty') return { mode: 'empty', findings, policies, score: null, grade: null, headers };

  if (input.mode === 'csp') {
    policies.push({ kind: 'enforce', policy: input.csp, directives: parseCsp(input.csp) });
    findings.push(...analyzeCsp(input.csp, { headers: false }));
    return finish({ mode: 'csp', findings, policies, headers });
  }

  // Strict-Transport-Security
  const hsts = one('strict-transport-security');
  if (!hsts) add('hsts-missing', 'high', {}, 'strict-transport-security');
  else {
    const m = hsts.match(/max-age\s*=\s*"?(\d+)"?/i);
    const age = m ? Number(m[1]) : null, sub = /includesubdomains/i.test(hsts), pre = /preload/i.test(hsts);
    const H = 'strict-transport-security';
    if (age === null) add('hsts-invalid', 'medium', {}, H);
    else if (age === 0) add('hsts-zero', 'high', {}, H);
    else if (age < 15552000) add('hsts-short', 'medium', { age }, H);
    else add('hsts-ok', 'good', { days: Math.floor(age / 86400) }, H);
    if (age && !sub) add('hsts-no-subdomains', 'low', {}, H);
    if (pre && (!sub || age < 31536000)) add('hsts-preload-ineligible', 'low', {}, H);
  }

  // Content-Security-Policy (several headers are all enforced: the result is their intersection)
  const xfo = one('x-frame-options');
  const xfoOk = !!xfo && /^(deny|sameorigin)$/i.test(xfo.trim());
  const csps = (headers.get('content-security-policy') || []).flatMap((v) => v.split(/,(?=\s*[a-z-]+-(?:src|uri|action|ancestors)\b)/i));
  const ro = headers.get('content-security-policy-report-only') || [];
  for (const p of csps) {
    policies.push({ kind: 'enforce', policy: p, directives: parseCsp(p) });
    findings.push(...analyzeCsp(p, { headers: true, hasXfo: xfoOk || csps.some((q) => /frame-ancestors/i.test(q)) }));
  }
  if (csps.length > 1) add('csp-multiple', 'info', { n: csps.length }, 'content-security-policy');
  for (const p of ro) policies.push({ kind: 'report-only', policy: p, directives: parseCsp(p) });
  if (!csps.length) add(ro.length ? 'csp-report-only' : 'csp-missing', 'high', {}, 'content-security-policy');
  const frameAncestors = csps.some((p) => parseCsp(p).some((d) => d.name === 'frame-ancestors'));

  // X-Content-Type-Options
  const xcto = one('x-content-type-options');
  if (!xcto) add('xcto-missing', 'medium', {}, 'x-content-type-options');
  else if (xcto.trim().toLowerCase() !== 'nosniff') add('xcto-invalid', 'medium', { value: xcto }, 'x-content-type-options');
  else add('xcto-ok', 'good', {}, 'x-content-type-options');

  // Framing: CSP frame-ancestors or X-Frame-Options
  if (xfo && /^allow-from/i.test(xfo.trim())) add('xfo-allow-from', frameAncestors ? 'info' : 'medium', {}, 'x-frame-options');
  else if (xfo && !xfoOk) add('xfo-invalid', frameAncestors ? 'info' : 'medium', { value: xfo }, 'x-frame-options');
  if (frameAncestors || xfoOk) add('framing-ok', 'good', { via: frameAncestors ? 'frame-ancestors' : 'X-Frame-Options' }, 'x-frame-options');
  else if (!csps.length) add('xfo-missing', 'medium', {}, 'x-frame-options'); // with a CSP, csp-frame-ancestors-missing covers it

  // Referrer-Policy (the last valid token wins)
  const rp = one('referrer-policy');
  if (!rp) add('referrer-missing', 'low', {}, 'referrer-policy');
  else {
    const tok = rp.split(',').map((s) => s.trim().toLowerCase()).filter(Boolean).pop();
    if (tok === 'unsafe-url' || tok === 'no-referrer-when-downgrade') add('referrer-unsafe', 'medium', { value: tok }, 'referrer-policy');
    else if (['no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin', 'origin', 'origin-when-cross-origin'].includes(tok)) add('referrer-ok', 'good', { value: tok }, 'referrer-policy');
    else add('referrer-invalid', 'low', { value: rp }, 'referrer-policy');
  }

  // Permissions-Policy
  if (one('permissions-policy')) add('permissions-ok', 'good', {}, 'permissions-policy');
  else add('permissions-missing', 'low', {}, 'permissions-policy');
  if (one('feature-policy')) add('feature-policy-deprecated', 'info', {}, 'feature-policy');

  // Cross-Origin-Opener-Policy
  const coop = one('cross-origin-opener-policy');
  if (!coop) add('coop-missing', 'low', {}, 'cross-origin-opener-policy');
  else if (/^same-origin/i.test(coop.trim())) add('coop-ok', 'good', { value: coop.trim() }, 'cross-origin-opener-policy');

  // CORS
  const acao = one('access-control-allow-origin');
  if (acao && acao.trim() === '*') {
    if ((one('access-control-allow-credentials') || '').trim().toLowerCase() === 'true') add('cors-wildcard-credentials', 'high', {}, 'access-control-allow-origin');
    else add('cors-wildcard', 'info', {}, 'access-control-allow-origin');
  }

  // Cookies
  cookieFindings(headers.get('set-cookie') || [], (id, sev, p) => add(id, sev, p, 'set-cookie'));

  // Legacy and information disclosure
  const xxss = one('x-xss-protection');
  if (xxss && !/^0\b/.test(xxss.trim())) add('xxss-enabled', 'low', { value: xxss }, 'x-xss-protection');
  if (one('expect-ct')) add('expect-ct-deprecated', 'info', {}, 'expect-ct');
  if (one('public-key-pins')) add('hpkp-deprecated', 'low', {}, 'public-key-pins');
  for (const n of DISCLOSURE) {
    const v = one(n);
    if (v && (n !== 'server' || /\d/.test(v))) add('disclosure', 'low', { name: n, value: v }, n);
  }
  return finish({ mode: 'headers', findings, policies, headers });
}

function finish(r) {
  const order = { high: 0, medium: 1, low: 2, info: 3, good: 4 };
  r.findings.sort((a, b) => order[a.sev] - order[b.sev]);
  r.score = Math.max(0, 100 - r.findings.reduce((s, x) => s + SEV_WEIGHT[x.sev], 0));
  const worst = r.findings.find((x) => x.sev !== 'info' && x.sev !== 'good');
  r.grade = gradeFor(r.score, worst ? worst.sev : null);
  return r;
}

/** A–F from the score; A+ needs no high or medium findings, A no high ones. */
export function gradeFor(score, worst) {
  let g = score >= 95 ? 'A+' : score >= 85 ? 'A' : score >= 70 ? 'B' : score >= 55 ? 'C' : score >= 40 ? 'D' : 'F';
  if (g === 'A+' && (worst === 'high' || worst === 'medium')) g = 'A';
  if (g === 'A' && worst === 'high') g = 'B';
  return g;
}

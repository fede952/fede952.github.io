// Unit tests for the security headers / CSP analyzer.
import test from 'node:test';
import assert from 'node:assert/strict';
import { parseInput, parseCsp, analyzeCsp, analyze, bypassHost, sourceRisk, gradeFor } from '../../static/js/tools/headers-kit.mjs';

const ids = (findings) => findings.map((f) => f.id);
const byId = (findings, id) => findings.filter((f) => f.id === id);

test('parseInput: curl output, folded lines, repeated headers, redirects, HTTP/2 pseudo-headers', () => {
  const r = parseInput('HTTP/1.1 301 Moved\r\nLocation: https://x/\r\n\r\nHTTP/2 200\r\n:status: 200\r\nSet-Cookie: a=1\r\nset-cookie: b=2\r\nContent-Security-Policy: default-src \'self\';\r\n  img-src *\r\nX-Empty:\r\n');
  assert.equal(r.mode, 'headers');
  assert.equal(r.headers.has('location'), false, 'only the last response of a redirect chain');
  assert.deepEqual(r.headers.get('set-cookie'), ['a=1', 'b=2']);
  assert.equal(r.headers.get('content-security-policy')[0], "default-src 'self'; img-src *");
  assert.equal(r.headers.has(':status'), false);
  assert.deepEqual(r.headers.get('x-empty'), ['']);
});

test('parseInput: bare CSP and <meta> tag', () => {
  assert.equal(parseInput("default-src 'self'; script-src 'self'").mode, 'csp');
  assert.equal(parseInput("script-src https:\nobject-src 'none'").csp, "script-src https: object-src 'none'");
  const m = parseInput('<meta http-equiv="Content-Security-Policy" content="default-src &#39;self&#39;; img-src https:">');
  assert.equal(m.mode, 'csp');
  assert.equal(m.csp, "default-src 'self'; img-src https:");
  assert.equal(parseInput('').mode, 'empty');
  assert.equal(parseInput('hello world').mode, 'empty');
});

test('parseCsp marks duplicate directives', () => {
  const d = parseCsp("Script-Src 'self'; ; script-src *; img-src data: https:");
  assert.deepEqual(d.map((x) => [x.name, x.dup]), [['script-src', false], ['script-src', true], ['img-src', false]]);
  assert.deepEqual(d[2].sources, ['data:', 'https:']);
});

test('weak CSP sample: every classic mistake is reported', () => {
  const weak = "default-src *; script-src 'self' 'unsafe-inline' 'unsafe-eval' https: http://cdn.example.com ajax.googleapis.com self; style-src 'unsafe-inline' *; img-src * data: script-src 'self'; reflected-xss block; scirpt-src 'none'";
  const f = analyzeCsp(weak, { headers: true, hasXfo: false });
  const got = ids(f);
  for (const id of ['csp-unsafe-inline', 'csp-unsafe-eval', 'csp-scheme-source', 'csp-http-source', 'csp-bypass-host', 'csp-unquoted-keyword',
    'csp-missing-semicolon', 'csp-deprecated-directive', 'csp-unknown-directive', 'csp-object-src', 'csp-base-uri-missing', 'csp-form-action-missing',
    'csp-frame-ancestors-missing', 'csp-style-inline']) assert(got.includes(id), 'missing ' + id + ' in ' + got.join(','));
  assert.equal(byId(f, 'csp-unsafe-inline')[0].sev, 'high');
  assert.equal(byId(f, 'csp-bypass-host')[0].p.host, 'ajax.googleapis.com');
  assert.equal(byId(f, 'csp-unquoted-keyword')[0].p.source, 'self');
  assert.equal(byId(f, 'csp-missing-semicolon')[0].p.source, 'script-src');
  assert.equal(byId(f, 'csp-unknown-directive')[0].p.directive, 'scirpt-src');
  assert.equal(byId(f, 'csp-object-src')[0].sev, 'medium', 'object-src falls back to default-src *');
  assert(!got.includes('csp-nonce-ok') && !got.includes('csp-strict-ok'));
});

test('strict nonce-based CSP passes', () => {
  const strict = "script-src 'nonce-rAnd0m4nd5ecur3N0nceV4lue' 'strict-dynamic' https: 'unsafe-inline'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests";
  const f = analyzeCsp(strict, { headers: true });
  assert.deepEqual(f.filter((x) => !['good', 'info'].includes(x.sev)), [], JSON.stringify(f));
  assert.deepEqual(ids(f).sort(), ['csp-strict-ok', 'csp-unsafe-inline-ignored', 'csp-upgrade-ok']);
});

test('strict-dynamic without nonce, short nonce, script-src-attr', () => {
  assert(ids(analyzeCsp("script-src 'strict-dynamic'; object-src 'none'")).includes('csp-strict-dynamic-no-nonce'));
  const s = byId(analyzeCsp("script-src 'nonce-abc123'; object-src 'none'"), 'csp-short-nonce')[0];
  assert.equal(s.p.length, 6);
  assert(ids(analyzeCsp("script-src 'self'; script-src-attr 'unsafe-inline'; object-src 'none'")).includes('csp-unsafe-inline'));
  assert(ids(analyzeCsp("img-src 'self'")).includes('csp-no-script-restriction'));
  assert(ids(analyzeCsp("script-src 'none' 'self'")).includes('csp-none-combined'));
});

test('bypass hosts and source risk', () => {
  assert.equal(bypassHost('https://cdnjs.cloudflare.com/ajax/libs/'), 'cdnjs.cloudflare.com');
  assert.equal(bypassHost('*.googleapis.com'), 'ajax.googleapis.com');
  assert.equal(bypassHost('cdn.example.com'), null);
  assert.equal(bypassHost("'self'"), null);
  assert.equal(sourceRisk("'unsafe-inline'", 'script-src'), 'high');
  assert.equal(sourceRisk("'unsafe-inline'", 'style-src'), 'low');
  assert.equal(sourceRisk('https:', 'script-src'), 'high');
  assert.equal(sourceRisk('https:', 'img-src'), null);
  assert.equal(sourceRisk("'nonce-x'", 'script-src'), 'good');
});

test('missing headers on a bare response', () => {
  const r = analyze('HTTP/1.1 200 OK\nContent-Type: text/html\nServer: Apache/2.4.41 (Ubuntu)\nX-Powered-By: PHP/7.4.3\n');
  const got = ids(r.findings);
  for (const id of ['hsts-missing', 'csp-missing', 'xcto-missing', 'xfo-missing', 'referrer-missing', 'permissions-missing', 'coop-missing'])
    assert(got.includes(id), 'missing ' + id);
  assert.deepEqual(byId(r.findings, 'disclosure').map((x) => x.p.name), ['server', 'x-powered-by']);
  assert.equal(r.grade, 'F');
  assert.equal(r.findings[0].sev, 'high', 'sorted by severity');
});

test('a well-configured response gets A+', () => {
  const good = [
    'HTTP/2 200',
    'strict-transport-security: max-age=63072000; includeSubDomains; preload',
    "content-security-policy: script-src 'nonce-4AEemGb0xJptoIGFP3Nd5Q==' 'strict-dynamic'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'self'",
    'x-content-type-options: nosniff',
    'referrer-policy: strict-origin-when-cross-origin',
    'permissions-policy: camera=(), microphone=(), geolocation=()',
    'cross-origin-opener-policy: same-origin',
    'set-cookie: __Host-sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax',
    'server: nginx',
  ].join('\n');
  const r = analyze(good);
  assert.deepEqual(r.findings.filter((x) => !['good', 'info'].includes(x.sev)), [], JSON.stringify(r.findings.filter((x) => x.sev !== 'good')));
  assert.equal(r.grade, 'A+');
  assert.equal(r.score, 100);
  assert(ids(r.findings).includes('framing-ok'));
});

test('HSTS variants', () => {
  assert.equal(byId(analyze('Strict-Transport-Security: max-age=86400').findings, 'hsts-short')[0].p.age, 86400);
  assert(ids(analyze('Strict-Transport-Security: max-age=0').findings).includes('hsts-zero'));
  assert(ids(analyze('Strict-Transport-Security: includeSubDomains').findings).includes('hsts-invalid'));
  assert(ids(analyze('Strict-Transport-Security: max-age=31536000; preload').findings).includes('hsts-preload-ineligible'));
});

test('cookies, CORS, framing, referrer, legacy headers', () => {
  const r = analyze([
    'Set-Cookie: sid=1; SameSite=None', 'Set-Cookie: pref=dark; Secure; SameSite=Lax; HttpOnly', 'Set-Cookie: __Host-x=1; Secure; Path=/app',
    'Access-Control-Allow-Origin: *', 'Access-Control-Allow-Credentials: true',
    'X-Frame-Options: ALLOW-FROM https://a.example', 'Referrer-Policy: no-referrer, unsafe-url',
    'X-XSS-Protection: 1; mode=block', 'Expect-CT: max-age=0', 'Feature-Policy: camera none',
  ].join('\n'));
  const f = r.findings;
  assert.deepEqual(byId(f, 'cookie-samesite-none-insecure').map((x) => x.p.name), ['sid']);
  assert.deepEqual(byId(f, 'cookie-no-httponly').map((x) => x.p.name), ['sid', '__Host-x']);
  assert.deepEqual(byId(f, 'cookie-host-prefix').map((x) => x.p.name), ['__Host-x']);
  for (const id of ['cors-wildcard-credentials', 'xfo-allow-from', 'referrer-unsafe', 'xxss-enabled', 'expect-ct-deprecated', 'feature-policy-deprecated'])
    assert(ids(f).includes(id), 'missing ' + id);
  assert.equal(byId(f, 'referrer-unsafe')[0].p.value, 'unsafe-url', 'the last token wins');
});

test('report-only CSP is not enforcement; multiple CSP headers are each analysed', () => {
  const ro = analyze("Content-Security-Policy-Report-Only: default-src 'self'");
  assert(ids(ro.findings).includes('csp-report-only'));
  assert.equal(ro.policies[0].kind, 'report-only');
  const two = analyze("Content-Security-Policy: default-src 'self'\nContent-Security-Policy: script-src 'unsafe-inline'");
  assert.equal(two.policies.length, 2);
  assert(ids(two.findings).includes('csp-multiple'));
  assert(ids(two.findings).includes('csp-unsafe-inline'));
});

test('grades', () => {
  assert.equal(gradeFor(100, null), 'A+');
  assert.equal(gradeFor(96, 'medium'), 'A');
  assert.equal(gradeFor(90, 'high'), 'B');
  assert.equal(gradeFor(30, 'high'), 'F');
});

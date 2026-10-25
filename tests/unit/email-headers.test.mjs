// Unit tests for the Email Header Analyzer, against fixtures with fictional domains.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { parseHeaders, parseAddress, orgDomain, parseReceived, hopChain, parseAuthResults, messageIdDomain, analyze, verdict, formatDelay } from '../../static/js/tools/email-headers.mjs';

const fx = (n) => fs.readFileSync(new URL(`../fixtures/email-headers/${n}.txt`, import.meta.url), 'utf8');
const ids = (r) => r.signals.map((s) => s.id);
const NOW = new Date('2025-10-25T00:00:00Z');

test('parseHeaders unfolds continuation lines and stops at the body', () => {
  const h = parseHeaders('Subject: one\r\n two\r\nFrom: a@b.example\r\n\r\nX-Not-A-Header: body');
  assert.deepEqual(h, [{ name: 'Subject', value: 'one two' }, { name: 'From', value: 'a@b.example' }]);
  assert.equal(parseHeaders(fx('legit-esp')).filter((x) => x.name === 'Received').length, 3);
});

test('addresses and organisational domains', () => {
  assert.deepEqual(parseAddress('"Velorabank Support" <help@velorabank.example>'), { name: 'Velorabank Support', address: 'help@velorabank.example', domain: 'velorabank.example' });
  assert.deepEqual(parseAddress('<bounces+812@em.streamora.example>'), { name: '', address: 'bounces+812@em.streamora.example', domain: 'em.streamora.example' });
  assert.equal(parseAddress('plain@host.test (comment)').address, 'plain@host.test');
  assert.equal(orgDomain('em.streamora.example'), 'streamora.example');
  assert.equal(orgDomain('mail.shop.co.uk'), 'shop.co.uk');
  assert.equal(orgDomain('example'), 'example');
  assert.equal(messageIdDomain('<20251021.4F3A@em.streamora.example>'), 'em.streamora.example');
});

test('Received chain: oldest first, hosts, IPs, protocols and delays', () => {
  const hops = hopChain(parseHeaders(fx('legit-esp')));
  assert.equal(hops.length, 3);
  assert.equal(hops[0].from, 'app-03.internal.streamora.example');
  assert.equal(hops[0].fromIp, '10.20.30.40');
  assert.equal(hops[1].fromIp, '198.51.100.17');
  assert.equal(hops[1].with, 'ESMTPS');
  assert.deepEqual(hops.map((h) => h.delay), [null, 2, 1]);
  const r = parseReceived('from x.test (unknown [203.0.113.66]) by mx.mail.example with ESMTP id 9f; Mon, 20 Oct 2025 03:02:11 +0000');
  assert.equal(r.by, 'mx.mail.example'); assert.equal(r.date.toISOString(), '2025-10-20T03:02:11.000Z');
});

test('Authentication-Results parsing', () => {
  const a = parseAuthResults('mx.mail.example; spf=softfail smtp.mailfrom=x@y.test; dkim=pass header.d=a.example header.s=s1; dkim=fail header.d=b.example; dmarc=fail (p=QUARANTINE) header.from=a.example');
  assert.equal(a.authserv, 'mx.mail.example');
  assert.equal(a.spf.result, 'softfail'); assert.equal(a.spf.props['smtp.mailfrom'], 'x@y.test');
  assert.deepEqual(a.dkim.map((d) => [d.result, d.props['header.d']]), [['pass', 'a.example'], ['fail', 'b.example']]);
  assert.equal(a.dmarc.result, 'fail'); assert.equal(a.dmarc.policy, 'quarantine');
});

test('legitimate ESP mail: aligned DKIM and DMARC pass, only a benign Return-Path note', () => {
  const r = analyze(fx('legit-esp'), NOW);
  assert.equal(verdict(r.signals), 'ok');
  assert.deepEqual(ids(r).sort(), ['dkim-aligned', 'dmarc-pass', 'spf-pass'].sort());
  assert.equal(r.from.domain, 'streamora.example');
});

test('spoofed phishing mail: every signal fires', () => {
  const r = analyze(fx('phish-spoof'), NOW);
  assert.equal(verdict(r.signals), 'danger');
  for (const id of ['display-name-address', 'reply-to-mismatch', 'spf-fail', 'dkim-none', 'dmarc-fail', 'message-id-mismatch', 'bulk-mailer', 'return-path-mismatch'])
    assert(ids(r).includes(id), 'missing ' + id + ' in ' + ids(r));
  assert.equal(r.signals[0].sev, 'high', 'sorted by severity');
  assert.equal(r.signals.find((s) => s.id === 'dmarc-fail').p.policy, 'reject');
});

test('forwarded list mail: ARC noted, DKIM by the list not aligned but DMARC passes', () => {
  const r = analyze(fx('forwarded-arc'), NOW);
  assert(ids(r).includes('arc-present'));
  assert(ids(r).includes('dkim-not-aligned'));
  assert(ids(r).includes('spf-not-aligned'));
  assert(ids(r).includes('dmarc-pass'));
  assert.equal(verdict(r.signals), 'ok');
});

test('no authentication results, clock skew and a slow hop', () => {
  const r = analyze(fx('no-auth'), NOW);
  for (const id of ['no-auth-results', 'clock-skew']) assert(ids(r).includes(id), id);
  assert.equal(verdict(r.signals), 'caution');
  assert.deepEqual(ids(analyze('', NOW)), ['empty']);
  assert(ids(analyze('From: a@b.example\nDate: Mon, 1 Jan 2035 00:00:00 +0000\n', NOW)).includes('date-future'));
});

test('formatDelay', () => {
  assert.equal(formatDelay(45), '45 s');
  assert.equal(formatDelay(125), '2 min 5 s');
  assert.equal(formatDelay(3725), '1 h 2 min');
  assert.equal(formatDelay(-9000), '−2 h 30 min');
  assert.equal(formatDelay(null), '');
});

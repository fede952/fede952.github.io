// Unit tests for the Phishing Quiz pool and logic.
import test from 'node:test';
import assert from 'node:assert/strict';
import { SCENARIOS, TOPICS, RESERVED_HOST } from '../../static/js/tools/phish/scenarios.mjs';
import { pickRound, rankFor, topicsToReview, hostsOf, shareData, shuffle } from '../../static/js/tools/phish/quiz.mjs';

const LANGS = ['en', 'it', 'es', 'de', 'fr', 'pt'];
const TEXTS = Object.fromEntries(await Promise.all(LANGS.map(async (l) => [l, (await import(`../../static/js/tools/phish/${l}.mjs`)).default])));
const REQUIRED = { email: ['ctx', 'fromName', 'subject', 'greeting', 'body', 'verdict'], sms: ['ctx', 'body', 'verdict'],
  login: ['ctx', 'title', 'verdict'], qr: ['ctx', 'posterTitle', 'posterText', 'verdict'], url: ['ctx', 'verdict'] };
const seeded = (seed) => () => ((seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648);

test('pool: at least 30 scenarios, unique ids, both verdicts, every type', () => {
  assert(SCENARIOS.length >= 30, `${SCENARIOS.length} scenarios`);
  assert.equal(new Set(SCENARIOS.map((s) => s.id)).size, SCENARIOS.length, 'duplicate id');
  assert(SCENARIOS.filter((s) => !s.phish).length >= 10, 'need enough legitimate scenarios');
  assert.deepEqual([...new Set(SCENARIOS.map((s) => s.type))].sort(), ['email', 'login', 'qr', 'sms', 'url']);
  for (const s of SCENARIOS) {
    assert(s.topics.length && s.topics.every((t) => TOPICS[t]), `${s.id}: unknown topic`);
    assert(s.flags.length, `${s.id}: no flags`);
    assert(s.flags.every(([, k]) => k === (s.phish ? 'bad' : 'good')), `${s.id}: flag kind must match the verdict`);
  }
});

test('pool: only reserved documentation domains and IPs', () => {
  for (const s of SCENARIOS) for (const h of hostsOf(s)) assert.match(h, RESERVED_HOST, `${s.id}: ${h} is not reserved`);
});

test('texts: every scenario is fully written in all 6 languages', () => {
  for (const l of LANGS) {
    const T = TEXTS[l];
    assert.deepEqual(Object.keys(T).sort(), SCENARIOS.map((s) => s.id).sort(), `${l}: scenario set differs`);
    for (const s of SCENARIOS) {
      const t = T[s.id];
      for (const k of REQUIRED[s.type]) assert(t[k] && String(t[k]).trim(), `${l}/${s.id}: missing ${k}`);
      for (const [el] of s.flags) assert(t.f && t.f[el], `${l}/${s.id}: no explanation for ${el}`);
      if (s.type === 'email' && s.m.href) assert(t.cta, `${l}/${s.id}: missing cta`);
      if (s.type === 'sms' && s.m.href) assert(t.body.includes('{link}'), `${l}/${s.id}: SMS body needs {link}`);
      // a translated text must not mention a real-looking domain that is not in the scenario
      for (const d of JSON.stringify(t).match(/[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:example|test|invalid)\b/g) || [])
        assert(JSON.stringify(s.m).includes(d) || RESERVED_HOST.test(d), `${l}/${s.id}: ${d}`);
    }
  }
});

test('pickRound: 10 scenarios, 3–4 legitimate, at least 3 types, no repeats', () => {
  for (let seed = 1; seed < 200; seed++) {
    const r = pickRound(SCENARIOS, 10, seeded(seed));
    assert.equal(r.length, 10);
    assert.equal(new Set(r.map((s) => s.id)).size, 10);
    const legit = r.filter((s) => !s.phish).length;
    assert(legit >= 3 && legit <= 4, `seed ${seed}: ${legit} legitimate`);
    assert(new Set(r.map((s) => s.type)).size >= 3);
  }
});

test('ranks, topics to review, share data', () => {
  assert.deepEqual([0, 3, 4, 6, 7, 8, 9, 10].map((n) => rankFor(n)), ['rank1', 'rank1', 'rank2', 'rank2', 'rank3', 'rank3', 'rank4', 'rank4']);
  const round = [SCENARIOS.find((s) => s.id === 'url-lookalike'), SCENARIOS.find((s) => s.id === 'sms-family'), SCENARIOS.find((s) => s.id === 'qr-parking')];
  // both misses involve payments, so it ranks first; ties keep first-seen order
  assert.deepEqual(topicsToReview(round, [true, false, false]), ['payments', 'urgency', 'qr']);
  assert.deepEqual(topicsToReview(round, [true, true, true]), []);
  assert.deepEqual(shareData(7, 10, 'it', 'Ho fatto {score}/{total}'), { text: 'Ho fatto 7/10', url: 'https://federicosella.com/it/tools/phishing-quiz/score/7/' });
  assert.deepEqual(shuffle([1, 2, 3], () => 0).sort(), [1, 2, 3]);
});

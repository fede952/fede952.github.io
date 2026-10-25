// CVSS v4.0 / v3.1 against FIRST's published examples and FIRST's own calculators.
//  - tests/fixtures/cvss-first-examples.json: every "score + vector" cell of the tables on
//    https://www.first.org/cvss/v4.0/examples (fetched 2026-10-25): 19 v4.0 and 10 v3.1 vectors.
//  - static/vendor/cvss-v4-calculator@c5b0d40/cvss_score.js: FIRST's official v4.0 scoring code.
//  - tests/reference/first-cvsscalc31.js: FIRST's official v3.1 calculator (first.org/cvss/calculator/cvsscalc31.js).
// The official scripts define globals, so they run in an empty vm context.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { parseV4, scoreV4, v4Vector, v4Nomenclature, macroVector, parseV31, scoreV31, v31Vector, roundup, severity, V4_ORDER, V31_ORDER, V4_BASE } from '../../static/js/tools/cvss.mjs';
import V4DATA from '../../static/js/tools/cvss/v4-data.mjs';
import { loadOfficial } from '../../scripts/cvss-v4-data.mjs';

const EX = JSON.parse(fs.readFileSync(new URL('../fixtures/cvss-first-examples.json', import.meta.url), 'utf8'));
const OFF = loadOfficial();
const ctx31 = vm.createContext({});
vm.runInContext(fs.readFileSync(new URL('../reference/first-cvsscalc31.js', import.meta.url), 'utf8'), ctx31);
const CVSS31 = vm.runInContext('CVSS31', ctx31);

// a seeded PRNG so failures are reproducible
let seed = 20261025;
const rnd = () => ((seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648);
const pick = (a) => a[Math.floor(rnd() * a.length)];

test('the generated data module equals the vendored official files', () => {
  assert.deepEqual(V4DATA.lookup, { ...OFF.cvssLookup_global });
  assert.equal(JSON.stringify(V4DATA.maxComposed), JSON.stringify(OFF.maxComposed));
  assert.equal(JSON.stringify(V4DATA.maxSeverity), JSON.stringify(OFF.maxSeverity));
  assert.equal(Object.keys(V4DATA.lookup).length, 270);
});

test(`v4.0: all ${EX.v4.length} FIRST examples`, () => {
  assert(EX.v4.length >= 19);
  for (const [vec, expected] of EX.v4) {
    const p = parseV4(vec);
    assert(p.metrics, vec + ' ' + p.errors);
    assert.equal(scoreV4(p.metrics).score, expected, vec);
  }
});

test('v4.0: identical to the official cvss_score.js on 20,000 random vectors', () => {
  for (let n = 0; n < 20000; n++) {
    const m = {};
    for (const [k, vals] of Object.entries(V4_ORDER)) m[k] = V4_BASE.includes(k) ? pick(vals) : (rnd() < 0.5 ? 'X' : pick(vals));
    // the official code reads E/CR/IR/AR and M* keys from a full selection object
    const mv = OFF.macroVector(m);
    assert.equal(macroVector(m), mv, v4Vector(m));
    const official = OFF.cvss_score(m, OFF.cvssLookup_global, OFF.maxSeverity, mv);
    assert.equal(scoreV4(m).score, official, v4Vector(m));
  }
});

test('v4.0: parsing, canonical order, nomenclature and severity', () => {
  const p = parseV4('CVSS:4.0/E:P/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H');
  assert.equal(v4Vector(p.metrics), 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P/CR:H');
  assert.equal(v4Nomenclature(p.metrics), 'CVSS-BTE');
  assert.equal(v4Nomenclature(parseV4('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N').metrics), 'CVSS-B');
  assert.deepEqual(parseV4('CVSS:4.0/AV:N/AC:L').errors.filter((e) => e.startsWith('missing')).length, 9);
  assert.deepEqual(parseV4('CVSS:4.0/AV:Q/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N').errors, ['value:AV:Q', 'missing:AV']);
  assert.deepEqual(parseV4('CVSS:3.1/AV:N').errors, ['prefix']);
  assert(parseV4('CVSS:4.0/AV:N/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N').errors.includes('duplicate:AV'));
  // supplemental metrics do not change the score
  const a = scoreV4(parseV4('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N').metrics).score;
  const b = scoreV4(parseV4('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/S:P/AU:Y/R:U/V:C/RE:H/U:Red').metrics).score;
  assert.equal(a, b);
  assert.deepEqual([0, 0.1, 3.9, 4, 6.9, 7, 8.9, 9, 10].map(severity), ['None', 'Low', 'Low', 'Medium', 'Medium', 'High', 'High', 'Critical', 'Critical']);
});

test(`v3.1: all ${EX.v31.length} FIRST example vectors`, () => {
  assert(EX.v31.length >= 10);
  for (const [vec, expected] of EX.v31) assert.equal(scoreV31(parseV31(vec).metrics).base, expected, vec);
});

test('v3.1: identical to FIRST cvsscalc31.js (base, temporal, environmental) on 20,000 random vectors', () => {
  for (let n = 0; n < 20000; n++) {
    const m = {};
    for (const [k, vals] of Object.entries(V31_ORDER)) m[k] = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'].includes(k) ? pick(vals) : (rnd() < 0.5 ? 'X' : pick(vals));
    const vec = v31Vector(m);
    const ref = CVSS31.calculateCVSSFromVector(vec);
    assert(ref.success, vec);
    const s = scoreV31(m);
    assert.deepEqual([s.base, s.temporal, s.environmental], [+ref.baseMetricScore, +ref.temporalMetricScore, +ref.environmentalMetricScore], vec);
  }
});

test('v3.1: Roundup (Appendix A) and parsing', () => {
  assert.equal(roundup(4.02), 4.1);
  assert.equal(roundup(4.0), 4.0);
  assert.equal(roundup(4.000001), 4.0, 'tiny float errors do not round up');
  assert.deepEqual(parseV31('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H').errors, ['missing:A']);
  assert.equal(v31Vector(parseV31('CVSS:3.1/E:P/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').metrics), 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P');
});

test('UI metric definitions match the scoring metric values and are translated', async () => {
  const { V4_METRICS, V31_METRICS, V4_GROUPS, V31_GROUPS, T, phrases } = await import('../../static/js/tools/cvss/metrics.mjs');
  for (const [k, vals] of Object.entries(V4_ORDER)) assert.deepEqual(V4_METRICS[k][1].map((v) => v[0]).sort(), [...vals].sort(), 'v4 ' + k);
  for (const [k, vals] of Object.entries(V31_ORDER)) assert.deepEqual(V31_METRICS[k][1].map((v) => v[0]).sort(), [...vals].sort(), 'v3.1 ' + k);
  assert.deepEqual(V4_GROUPS.flatMap((g) => g.sub.flatMap((s) => s[1])).sort(), Object.keys(V4_ORDER).sort());
  assert.deepEqual(V31_GROUPS.flatMap((g) => g.sub.flatMap((s) => s[1])).sort(), Object.keys(V31_ORDER).sort());
  for (const l of ['it', 'es', 'de', 'fr', 'pt']) for (const p of phrases()) assert(T[l][p], `${l}: ${p}`);
});

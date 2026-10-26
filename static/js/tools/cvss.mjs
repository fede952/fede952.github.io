/* CVSS v4.0 and v3.1 scoring, DOM-free.

   v4.0: a line-by-line port of cvss_score.js / macroVector() from FIRST's
   official calculator (github.com/FIRSTdotorg/cvss-v4-calculator, commit
   c5b0d40, BSD-2-Clause, © FIRST.ORG, Inc., Red Hat, and contributors), using
   its MacroVector lookup table unmodified (cvss/v4-data.mjs, generated from
   the vendored files). Spec: https://www.first.org/cvss/v4.0/specification-document
   tests/unit/cvss.test.mjs checks it against FIRST's published examples and
   against the official cvss_score.js itself on random vectors.

   v3.1: the equations of the CVSS v3.1 specification, section 7, with the
   integer-arithmetic Roundup of Appendix A; checked against FIRST's examples
   and FIRST's cvsscalc31.js on random vectors. */

import V4 from './cvss/v4-data.mjs';

export const severity = (s) => (s === 0 ? 'None' : s < 4 ? 'Low' : s < 7 ? 'Medium' : s < 9 ? 'High' : 'Critical');

/* ---------- v4.0 ---------- */

export const V4_ORDER = V4.metricOrder; // metric → allowed values, in vector order
export const V4_BASE = ['AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA'];
export const V4_ENV = ['CR', 'IR', 'AR', 'MAV', 'MAC', 'MAT', 'MPR', 'MUI', 'MVC', 'MVI', 'MVA', 'MSC', 'MSI', 'MSA'];
export const V4_SUPP = ['S', 'AU', 'R', 'V', 'RE', 'U'];

/** Defaults: every non-base metric is X (Not Defined). */
export function v4Defaults() {
  const m = {};
  for (const k of Object.keys(V4_ORDER)) m[k] = V4_BASE.includes(k) ? null : 'X';
  return m;
}

/**
 * Parse a v4.0 vector. Metrics may come in any order (output is canonical);
 * unknown metrics, invalid values, duplicates and missing base metrics are errors.
 */
export function parseV4(vector) {
  const errors = [];
  const s = String(vector || '').trim().replace(/^#/, '');
  const parts = s.split('/');
  if (parts[0] !== 'CVSS:4.0') return { metrics: null, errors: ['prefix'] };
  const m = v4Defaults(), seen = new Set();
  for (const p of parts.slice(1)) {
    const [k, v, extra] = p.split(':');
    if (!(k in V4_ORDER) || v === undefined || extra !== undefined) { errors.push('unknown:' + p); continue; }
    if (seen.has(k)) { errors.push('duplicate:' + k); continue; }
    if (!V4_ORDER[k].includes(v)) { errors.push('value:' + p); continue; }
    seen.add(k); m[k] = v;
  }
  for (const k of V4_BASE) if (!seen.has(k)) errors.push('missing:' + k);
  return { metrics: errors.length ? null : m, errors };
}

export function v4Vector(m) {
  let out = 'CVSS:4.0';
  for (const k of Object.keys(V4_ORDER)) if (m[k] && m[k] !== 'X') out += `/${k}:${m[k]}`;
  return out;
}

/* m(): effective value, as in the official calculator. */
function eff(c, metric) {
  const sel = c[metric];
  if (metric === 'E' && sel === 'X') return 'A';
  if ((metric === 'CR' || metric === 'IR' || metric === 'AR') && sel === 'X') return 'H';
  const mod = c['M' + metric];
  if (mod !== undefined && mod !== 'X') return mod;
  return sel;
}

export function macroVector(c) {
  const m = (k) => eff(c, k);
  let eq1, eq2, eq3, eq4, eq5, eq6;
  if (m('AV') === 'N' && m('PR') === 'N' && m('UI') === 'N') eq1 = '0';
  else if ((m('AV') === 'N' || m('PR') === 'N' || m('UI') === 'N') && !(m('AV') === 'N' && m('PR') === 'N' && m('UI') === 'N') && m('AV') !== 'P') eq1 = '1';
  else eq1 = '2';
  eq2 = m('AC') === 'L' && m('AT') === 'N' ? '0' : '1';
  if (m('VC') === 'H' && m('VI') === 'H') eq3 = '0';
  else if (m('VC') === 'H' || m('VI') === 'H' || m('VA') === 'H') eq3 = '1';
  else eq3 = '2';
  if (m('MSI') === 'S' || m('MSA') === 'S') eq4 = '0';
  else if (m('SC') === 'H' || m('SI') === 'H' || m('SA') === 'H') eq4 = '1';
  else eq4 = '2';
  eq5 = { A: '0', P: '1', U: '2' }[m('E')];
  eq6 = (m('CR') === 'H' && m('VC') === 'H') || (m('IR') === 'H' && m('VI') === 'H') || (m('AR') === 'H' && m('VA') === 'H') ? '0' : '1';
  return eq1 + eq2 + eq3 + eq4 + eq5 + eq6;
}

const LV = {
  AV: { N: 0.0, A: 0.1, L: 0.2, P: 0.3 }, PR: { N: 0.0, L: 0.1, H: 0.2 }, UI: { N: 0.0, P: 0.1, A: 0.2 },
  AC: { L: 0.0, H: 0.1 }, AT: { N: 0.0, P: 0.1 },
  VC: { H: 0.0, L: 0.1, N: 0.2 }, VI: { H: 0.0, L: 0.1, N: 0.2 }, VA: { H: 0.0, L: 0.1, N: 0.2 },
  SC: { H: 0.1, L: 0.2, N: 0.3 }, SI: { S: 0.0, H: 0.1, L: 0.2, N: 0.3 }, SA: { S: 0.0, H: 0.1, L: 0.2, N: 0.3 },
  CR: { H: 0.0, M: 0.1, L: 0.2 }, IR: { H: 0.0, M: 0.1, L: 0.2 }, AR: { H: 0.0, M: 0.1, L: 0.2 },
};
const DIST_METRICS = ['AV', 'PR', 'UI', 'AC', 'AT', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA', 'CR', 'IR', 'AR'];
const valueIn = (metric, str) => { const x = str.slice(str.indexOf(metric) + metric.length + 1); const i = x.indexOf('/'); return i > 0 ? x.substring(0, i) : x; };

/** Score of parsed v4.0 metrics. Returns { score, macroVector }. */
export function scoreV4(c) {
  const mv = macroVector(c);
  if (['VC', 'VI', 'VA', 'SC', 'SI', 'SA'].every((k) => eff(c, k) === 'N')) return { score: 0, macroVector: mv };
  const L = V4.lookup, MS = V4.maxSeverity, MC = V4.maxComposed;
  let value = L[mv];
  const [eq1, eq2, eq3, eq4, eq5, eq6] = [...mv].map(Number);
  const key = (a, b, c3, d, e, f) => '' + a + b + c3 + d + e + f;
  const s1 = L[key(eq1 + 1, eq2, eq3, eq4, eq5, eq6)], s2 = L[key(eq1, eq2 + 1, eq3, eq4, eq5, eq6)];
  let s36;
  if (eq3 === 1 && eq6 === 1) s36 = L[key(eq1, eq2, eq3 + 1, eq4, eq5, eq6)];
  else if (eq3 === 0 && eq6 === 1) s36 = L[key(eq1, eq2, eq3 + 1, eq4, eq5, eq6)];
  else if (eq3 === 1 && eq6 === 0) s36 = L[key(eq1, eq2, eq3, eq4, eq5, eq6 + 1)];
  else if (eq3 === 0 && eq6 === 0) {
    const left = L[key(eq1, eq2, eq3, eq4, eq5, eq6 + 1)], right = L[key(eq1, eq2, eq3 + 1, eq4, eq5, eq6)];
    s36 = left > right ? left : right;
  } else s36 = L[key(eq1, eq2, eq3 + 1, eq4, eq5, eq6 + 1)];
  const s4 = L[key(eq1, eq2, eq3, eq4 + 1, eq5, eq6)], s5 = L[key(eq1, eq2, eq3, eq4, eq5 + 1, eq6)];

  const maxes = [];
  for (const a of MC.eq1[mv[0]]) for (const b of MC.eq2[mv[1]]) for (const c3 of MC.eq3[mv[2]][mv[5]]) for (const d of MC.eq4[mv[3]]) for (const e of MC.eq5[mv[4]]) maxes.push(a + b + c3 + d + e);
  let dist = {};
  for (const mx of maxes) {
    dist = {};
    for (const k of DIST_METRICS) dist[k] = LV[k][eff(c, k)] - LV[k][valueIn(k, mx)];
    if (Object.values(dist).some((x) => x < 0)) continue;
    break; // the first max vector that the scored vector does not exceed (official behaviour keeps the last one otherwise)
  }
  const cur1 = dist.AV + dist.PR + dist.UI, cur2 = dist.AC + dist.AT;
  const cur36 = dist.VC + dist.VI + dist.VA + dist.CR + dist.IR + dist.AR, cur4 = dist.SC + dist.SI + dist.SA;
  const step = 0.1;
  const avail = [value - s1, value - s2, value - s36, value - s4, value - s5];
  const maxSev = [MS.eq1[eq1] * step, MS.eq2[eq2] * step, MS.eq3eq6[eq3][eq6] * step, MS.eq4[eq4] * step];
  const cur = [cur1, cur2, cur36, cur4];
  let n = 0, sum = 0;
  for (let i = 0; i < 5; i++) {
    if (Number.isNaN(avail[i])) continue;
    n++;
    if (i < 4) sum += avail[i] * (cur[i] / maxSev[i]); // EQ5 contributes 0
  }
  value -= n === 0 ? 0 : sum / n;
  value = Math.min(10, Math.max(0, value));
  return { score: Math.round(value * 10) / 10, macroVector: mv };
}

/** Nomenclature (spec §1.3): CVSS-B, CVSS-BT, CVSS-BE or CVSS-BTE. */
export function v4Nomenclature(m) {
  const t = m.E && m.E !== 'X';
  const e = V4_ENV.some((k) => m[k] && m[k] !== 'X');
  return 'CVSS-B' + (t ? 'T' : '') + (e ? 'E' : '');
}

/* ---------- v3.1 ---------- */

export const V31_ORDER = {
  AV: ['N', 'A', 'L', 'P'], AC: ['L', 'H'], PR: ['N', 'L', 'H'], UI: ['N', 'R'], S: ['U', 'C'], C: ['H', 'L', 'N'], I: ['H', 'L', 'N'], A: ['H', 'L', 'N'],
  E: ['X', 'H', 'F', 'P', 'U'], RL: ['X', 'U', 'W', 'T', 'O'], RC: ['X', 'C', 'R', 'U'],
  CR: ['X', 'H', 'M', 'L'], IR: ['X', 'H', 'M', 'L'], AR: ['X', 'H', 'M', 'L'],
  MAV: ['X', 'N', 'A', 'L', 'P'], MAC: ['X', 'L', 'H'], MPR: ['X', 'N', 'L', 'H'], MUI: ['X', 'N', 'R'], MS: ['X', 'U', 'C'], MC: ['X', 'H', 'L', 'N'], MI: ['X', 'H', 'L', 'N'], MA: ['X', 'H', 'L', 'N'],
};
export const V31_BASE = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];

export function parseV31(vector) {
  const errors = [];
  const parts = String(vector || '').trim().replace(/^#/, '').split('/');
  if (parts[0] !== 'CVSS:3.1') return { metrics: null, errors: ['prefix'] };
  const m = {}, seen = new Set();
  for (const k of Object.keys(V31_ORDER)) m[k] = V31_BASE.includes(k) ? null : 'X';
  for (const p of parts.slice(1)) {
    const [k, v, extra] = p.split(':');
    if (!(k in V31_ORDER) || v === undefined || extra !== undefined) { errors.push('unknown:' + p); continue; }
    if (seen.has(k)) { errors.push('duplicate:' + k); continue; }
    if (!V31_ORDER[k].includes(v)) { errors.push('value:' + p); continue; }
    seen.add(k); m[k] = v;
  }
  for (const k of V31_BASE) if (!seen.has(k)) errors.push('missing:' + k);
  return { metrics: errors.length ? null : m, errors };
}
export function v31Vector(m) {
  let out = 'CVSS:3.1';
  for (const k of Object.keys(V31_ORDER)) if (m[k] && m[k] !== 'X') out += `/${k}:${m[k]}`;
  return out;
}

/** Appendix A Roundup: smallest one-decimal number ≥ x, in integer arithmetic. */
export function roundup(x) {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}

const W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }, AC: { L: 0.77, H: 0.44 }, UI: { N: 0.85, R: 0.62 },
  PR: { U: { N: 0.85, L: 0.62, H: 0.27 }, C: { N: 0.85, L: 0.68, H: 0.5 } },
  CIA: { H: 0.56, L: 0.22, N: 0 },
  E: { X: 1, H: 1, F: 0.97, P: 0.94, U: 0.91 }, RL: { X: 1, U: 1, W: 0.97, T: 0.96, O: 0.95 }, RC: { X: 1, C: 1, R: 0.96, U: 0.92 },
  REQ: { X: 1, H: 1.5, M: 1, L: 0.5 },
};

/** Base, temporal and environmental scores for parsed v3.1 metrics. */
export function scoreV31(m) {
  const iss = 1 - (1 - W.CIA[m.C]) * (1 - W.CIA[m.I]) * (1 - W.CIA[m.A]);
  const impact = m.S === 'U' ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  const expl = 8.22 * W.AV[m.AV] * W.AC[m.AC] * W.PR[m.S][m.PR] * W.UI[m.UI];
  const base = impact <= 0 ? 0 : m.S === 'U' ? roundup(Math.min(impact + expl, 10)) : roundup(Math.min(1.08 * (impact + expl), 10));
  const tm = W.E[m.E] * W.RL[m.RL] * W.RC[m.RC];
  const temporal = roundup(base * tm);
  const mod = (k) => (m['M' + k] && m['M' + k] !== 'X' ? m['M' + k] : m[k]);
  const ms = mod('S');
  const miss = Math.min(1 - (1 - W.REQ[m.CR] * W.CIA[mod('C')]) * (1 - W.REQ[m.IR] * W.CIA[mod('I')]) * (1 - W.REQ[m.AR] * W.CIA[mod('A')]), 0.915);
  const mImpact = ms === 'U' ? 6.42 * miss : 7.52 * (miss - 0.029) - 3.25 * Math.pow(miss * 0.9731 - 0.02, 13);
  const mExpl = 8.22 * W.AV[mod('AV')] * W.AC[mod('AC')] * W.PR[ms][mod('PR')] * W.UI[mod('UI')];
  const env = mImpact <= 0 ? 0 : ms === 'U' ? roundup(roundup(Math.min(mImpact + mExpl, 10)) * tm) : roundup(roundup(Math.min(1.08 * (mImpact + mExpl), 10)) * tm);
  return { base, temporal, environmental: env, impact: impact <= 0 ? 0 : Math.round(impact * 10) / 10, exploitability: Math.round(expl * 10) / 10 };
}

// JSON helpers for /tools/json-formatter/ — pure functions, used by the app,
// by its Web Worker (json-worker.mjs, for large inputs) and by
// tests/unit/json.test.mjs.

/**
 * Finds the first syntax error in `text` with a small strict JSON scanner
 * (RFC 8259). Returns null if the text is valid JSON, otherwise
 * { index, line, column, code, found } where code names what was expected.
 * JSON.parse is used for the real parsing; this only explains its failures
 * the same way in every browser (their messages differ).
 */
export function locateError(text) {
  let i = 0;
  const n = text.length;
  const fail = (code) => { throw { index: i, code }; };
  const ws = () => { while (i < n && (text[i] === ' ' || text[i] === '\t' || text[i] === '\n' || text[i] === '\r')) i++; };
  function value() {
    ws();
    if (i >= n) fail('value');
    const c = text[i];
    if (c === '{') return object();
    if (c === '[') return array();
    if (c === '"') return string();
    if (c === '-' || (c >= '0' && c <= '9')) return number();
    for (const lit of ['true', 'false', 'null']) if (text.startsWith(lit, i)) { i += lit.length; return; }
    fail(c === "'" ? 'single-quote' : 'value');
  }
  function object() {
    i++; ws();
    if (text[i] === '}') { i++; return; }
    for (;;) {
      ws();
      if (text[i] !== '"') fail(text[i] === '}' ? 'trailing-comma' : text[i] === "'" ? 'single-quote' : 'key');
      string(); ws();
      if (text[i] !== ':') fail('colon');
      i++; value(); ws();
      if (text[i] === ',') { i++; continue; }
      if (text[i] === '}') { i++; return; }
      fail('comma-or-brace');
    }
  }
  function array() {
    i++; ws();
    if (text[i] === ']') { i++; return; }
    for (;;) {
      ws();
      if (text[i] === ']') fail('trailing-comma');
      value(); ws();
      if (text[i] === ',') { i++; continue; }
      if (text[i] === ']') { i++; return; }
      fail('comma-or-bracket');
    }
  }
  function string() {
    i++;
    while (i < n) {
      const c = text[i];
      if (c === '"') { i++; return; }
      if (c === '\\') {
        const e = text[i + 1];
        if (e === 'u') { if (!/^[0-9a-fA-F]{4}$/.test(text.slice(i + 2, i + 6))) { i++; fail('escape'); } i += 6; continue; }
        if (!'"\\/bfnrt'.includes(e)) { i++; fail('escape'); }
        i += 2; continue;
      }
      if (c < ' ') fail('control-char');
      i++;
    }
    fail('unterminated-string');
  }
  function number() {
    const m = text.slice(i, i + 400).match(/^-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?/);
    if (!m) fail('number');
    i += m[0].length;
  }
  try {
    value(); ws();
    if (i < n) fail('end');
    return null;
  } catch (e) {
    if (!('index' in e)) throw e;
    const before = text.slice(0, e.index);
    const line = (before.match(/\n/g) || []).length + 1;
    const column = e.index - before.lastIndexOf('\n');
    return { index: e.index, line, column, code: e.code, found: e.index < n ? text[e.index] : '' };
  }
}

/** Deep copy with object keys sorted (Unicode code point order); arrays keep their order. */
export function sortKeys(v) {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v && typeof v === 'object') {
    const out = {};
    for (const k of Object.keys(v).sort()) out[k] = sortKeys(v[k]);
    return out;
  }
  return v;
}

export function format(value, indent = 2, sorted = false) {
  return JSON.stringify(sorted ? sortKeys(value) : value, null, indent === 'tab' ? '\t' : Number(indent));
}

export const minify = (value, sorted = false) => JSON.stringify(sorted ? sortKeys(value) : value);

/** Counts objects, arrays, keys and max depth (for the status line). */
export function stats(v) {
  const s = { objects: 0, arrays: 0, keys: 0, depth: 0 };
  (function walk(x, d) {
    if (d > s.depth) s.depth = d;
    if (Array.isArray(x)) { s.arrays++; for (const y of x) walk(y, d + 1); }
    else if (x && typeof x === 'object') { s.objects++; const ks = Object.keys(x); s.keys += ks.length; for (const k of ks) walk(x[k], d + 1); }
  })(v, 0);
  return s;
}

/** {a:{b:1}, c:[1,2]} → {"a.b": 1, "c": "[1,2]"}: nested objects become dotted columns, arrays JSON text. */
function flatten(obj, prefix = '', out = {}) {
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === 'object' && !Array.isArray(v)) flatten(v, key, out);
    else out[key] = Array.isArray(v) ? JSON.stringify(v) : v;
  }
  return out;
}

const csvCell = (v, delim) => {
  if (v === null || v === undefined) return '';
  const s = typeof v === 'string' ? v : String(v);
  return /["\r\n]/.test(s) || s.includes(delim) || /^\s|\s$/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};

/**
 * JSON → CSV (RFC 4180). Accepts an array of objects (columns = union of
 * the flattened keys, in order of first appearance), an array of arrays
 * (rows as they are), or a single object (one row).
 */
export function toCsv(value, delim = ',') {
  let rows = Array.isArray(value) ? value : value && typeof value === 'object' ? [value] : null;
  if (!rows || !rows.length) return { error: 'csv-shape' };
  if (rows.every(Array.isArray)) return { csv: rows.map((r) => r.map((c) => csvCell(c !== null && typeof c === 'object' ? JSON.stringify(c) : c, delim)).join(delim)).join('\r\n') };
  if (!rows.every((r) => r && typeof r === 'object' && !Array.isArray(r))) return { error: 'csv-shape' };
  rows = rows.map((r) => flatten(r));
  const cols = [];
  const seen = new Set();
  for (const r of rows) for (const k of Object.keys(r)) if (!seen.has(k)) { seen.add(k); cols.push(k); }
  const lines = [cols.map((c) => csvCell(c, delim)).join(delim)];
  for (const r of rows) lines.push(cols.map((c) => csvCell(r[c], delim)).join(delim));
  return { csv: lines.join('\r\n'), columns: cols.length, rows: rows.length };
}

/** Bytes of a string in UTF-8 (status line, 2 MB worker threshold). */
export const utf8Length = (s) => { let b = 0; for (let i = 0; i < s.length; i++) { const c = s.charCodeAt(i); b += c < 0x80 ? 1 : c < 0x800 ? 2 : c >= 0xd800 && c < 0xdc00 ? (i++, 4) : 3; } return b; };

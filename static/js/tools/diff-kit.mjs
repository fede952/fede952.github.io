/* Text diff logic for tools/text-diff, independent of the DOM so it can be
   unit-tested in Node. Every function takes the jsdiff namespace `D`
   (window.Diff in the browser, the vendored UMD build in tests). */

/** Splits text into lines (CRLF and CR normalised); a final newline does not add an empty line. */
export function splitLines(text) {
  const s = String(text).replace(/\r\n?/g, '\n');
  if (s === '') return [];
  const lines = s.split('\n');
  if (lines[lines.length - 1] === '') lines.pop();
  return lines;
}

/** The comparison key for a line under the ignore options. */
export function keyFn({ ignoreWs = false, ignoreCase = false } = {}) {
  return (s) => {
    let k = s;
    if (ignoreWs) k = k.replace(/\s+/g, ' ').trim();
    if (ignoreCase) k = k.toLowerCase();
    return k;
  };
}

/** Splits a line into tokens: runs of whitespace, words (letters, digits, _) and single punctuation marks; or characters. */
export function tokens(s, granularity = 'word') {
  if (granularity === 'char') return Array.from(s);
  return s.match(/\s+|[\p{L}\p{N}_]+|[^\s\p{L}\p{N}_]/gu) || [];
}

/**
 * Highlights the changes inside one modified line.
 * Returns { left: [{text, mark}], right: [{text, mark}] } where mark is true on changed spans,
 * or null when the lines share too little for highlighting to help (they are shown as replaced).
 */
export function inlineParts(D, a, b, { granularity = 'word', ignoreWs = false, ignoreCase = false } = {}) {
  const A = tokens(a, granularity), B = tokens(b, granularity);
  const ws = /^\s+$/;
  const norm = (x) => (ignoreCase ? x.toLowerCase() : x);
  const comparator = (x, y) => (ignoreWs && ws.test(x) && ws.test(y)) || norm(x) === norm(y);
  const parts = D.diffArrays(A, B, { comparator, timeout: 1000 });
  if (!parts) return null;
  const left = [], right = [];
  const push = (list, text, mark) => {
    const last = list[list.length - 1];
    if (last && last.mark === mark) last.text += text; else list.push({ text, mark });
  };
  let i = 0, j = 0, same = 0;
  for (const p of parts) {
    if (p.added) { push(right, B.slice(j, j + p.count).join(''), true); j += p.count; continue; }
    if (p.removed) { push(left, A.slice(i, i + p.count).join(''), true); i += p.count; continue; }
    const ta = A.slice(i, i + p.count).join(''), tb = B.slice(j, j + p.count).join('');
    // Under the ignore options "equal" tokens can still differ (case, amount of
    // whitespace): show them unmarked, since the user asked to ignore exactly that.
    push(left, ta, false); push(right, tb, false);
    same += ta.length + tb.length;
    i += p.count; j += p.count;
  }
  if (a.length + b.length && same / (a.length + b.length) < 0.3) return null;
  return { left, right };
}

/**
 * Line diff of two texts.
 * rows: [{ type: 'eq'|'mod'|'del'|'add', l: lineNo|null, r: lineNo|null, a: text|null, b: text|null }]
 * stats: { added, removed, changed, same } in lines (a modified pair counts as one removed + one added).
 * Returns { tooBig: true } when the texts are too different to diff within the time limit.
 */
export function diffTexts(D, oldText, newText, opts = {}) {
  const A = splitLines(oldText), B = splitLines(newText);
  const key = keyFn(opts);
  const parts = D.diffArrays(A, B, { comparator: (x, y) => key(x) === key(y), timeout: opts.timeout ?? 8000 });
  if (!parts) return { tooBig: true };
  const rows = [];
  let i = 0, j = 0, added = 0, removed = 0, same = 0, changed = 0;
  for (let n = 0; n < parts.length; n++) {
    const p = parts[n];
    if (!p.added && !p.removed) {
      for (let k = 0; k < p.count; k++) rows.push({ type: 'eq', l: i + 1, r: j + 1, a: A[i++], b: B[j++] });
      same += p.count;
      continue;
    }
    // A removed run followed by an added run is a modification: pair the lines one to one.
    let del = 0, add = 0;
    if (p.removed) { del = p.count; if (parts[n + 1] && parts[n + 1].added) { add = parts[n + 1].count; n++; } }
    else add = p.count;
    const pairs = Math.min(del, add);
    for (let k = 0; k < pairs; k++) rows.push({ type: 'mod', l: i + 1, r: j + 1, a: A[i++], b: B[j++] });
    for (let k = pairs; k < del; k++) rows.push({ type: 'del', l: i + 1, r: null, a: A[i++], b: null });
    for (let k = pairs; k < add; k++) rows.push({ type: 'add', l: null, r: j + 1, a: null, b: B[j++] });
    removed += del; added += add; changed += pairs;
  }
  return { rows, stats: { added, removed, changed, same } };
}

/**
 * Groups rows for display, folding unchanged runs that would hide more than 3 lines
 * (a fold marker for fewer lines saves almost no space).
 * Returns a list of rows and { type: 'fold', count, from } markers (from = index of the first hidden row).
 */
export function foldRows(rows, context = 3) {
  const out = [];
  let n = 0;
  while (n < rows.length) {
    if (rows[n].type !== 'eq') { out.push(rows[n++]); continue; }
    let end = n;
    while (end < rows.length && rows[end].type === 'eq') end++;
    const lead = n === 0 ? 0 : context, tail = end === rows.length ? 0 : context;
    const hidden = end - n - lead - tail;
    if (hidden > 3) {
      for (let k = n; k < n + lead; k++) out.push(rows[k]);
      out.push({ type: 'fold', count: hidden, from: n + lead });
      for (let k = end - tail; k < end; k++) out.push(rows[k]);
    } else for (let k = n; k < end; k++) out.push(rows[k]);
    n = end;
  }
  return out;
}

/** A unified diff (git apply / patch compatible) of the two texts. */
export function unifiedDiff(D, oldText, newText, { oldName = 'original.txt', newName = 'changed.txt', context = 3, ignoreWs = false, ignoreCase = false } = {}) {
  const norm = (s) => String(s).replace(/\r\n?/g, '\n');
  const key = keyFn({ ignoreWs, ignoreCase });
  const opts = { context, headerOptions: D.FILE_HEADERS_ONLY };
  if (ignoreWs || ignoreCase) opts.comparator = (x, y) => key(x.replace(/\n$/, '')) === key(y.replace(/\n$/, ''));
  return D.createTwoFilesPatch(oldName, newName, norm(oldText), norm(newText), '', '', opts);
}

// Unit tests for the text diff tool's logic, run against the vendored jsdiff build.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import { splitLines, tokens, inlineParts, diffTexts, foldRows, unifiedDiff } from '../../static/js/tools/diff-kit.mjs';

// The UMD build attaches `Diff` to the global object; give it a fresh one.
const ctx = {};
vm.runInNewContext(readFileSync(new URL('../../static/vendor/diff@9.0.0/diff.min.js', import.meta.url), 'utf8'), ctx);
const D = ctx.Diff;
const joined = (spans) => spans.map((s) => s.text).join('');
const marked = (spans) => spans.filter((s) => s.mark).map((s) => s.text);

test('splitLines normalises line endings and ignores the final newline', () => {
  assert.deepEqual(splitLines('a\r\nb\rc\n'), ['a', 'b', 'c']);
  assert.deepEqual(splitLines(''), []);
  assert.deepEqual(splitLines('\n'), ['']);
  assert.deepEqual(splitLines('a\n\nb'), ['a', '', 'b']);
});

test('tokens: words, whitespace runs, punctuation, characters', () => {
  assert.deepEqual(tokens('foo(bar,  2)'), ['foo', '(', 'bar', ',', '  ', '2', ')']);
  assert.deepEqual(tokens('café über'), ['café', ' ', 'über']);
  assert.deepEqual(tokens('ab😀', 'char'), ['a', 'b', '😀']);
});

test('diffTexts pairs replaced lines and counts', () => {
  const r = diffTexts(D, 'one\ntwo\nthree\nfour\n', 'one\nTWO 2\nthree\nfive\nsix\n');
  assert.deepEqual(r.rows.map((x) => x.type), ['eq', 'mod', 'eq', 'mod', 'add']);
  assert.deepEqual(r.stats, { added: 3, removed: 2, changed: 2, same: 2 });
  const last = r.rows[4];
  assert.equal(last.l, null); assert.equal(last.r, 5); assert.equal(last.b, 'six');
  assert.deepEqual([r.rows[3].l, r.rows[3].r], [4, 4]);
});

test('ignore whitespace and case keep both sides\' original text', () => {
  const a = 'if (x  ==  1) {\n  Return y;\n}\n', b = 'if (x == 1) {\n    return y;\n}\n';
  assert.equal(diffTexts(D, a, b).stats.same, 1);
  assert.equal(diffTexts(D, a, b, { ignoreWs: true }).stats.same, 2);
  const r = diffTexts(D, a, b, { ignoreWs: true, ignoreCase: true });
  assert.equal(r.stats.same, 3);
  assert.equal(r.rows[1].a, '  Return y;');
  assert.equal(r.rows[1].b, '    return y;');
});

test('inlineParts: word granularity marks whole words, sides rebuild exactly', () => {
  const p = inlineParts(D, 'The quick brown fox', 'The slow brown fox!');
  assert.equal(joined(p.left), 'The quick brown fox');
  assert.equal(joined(p.right), 'The slow brown fox!');
  assert.deepEqual(marked(p.left), ['quick']);
  assert.deepEqual(marked(p.right), ['slow', '!']);
});

test('inlineParts: character granularity', () => {
  const p = inlineParts(D, 'colour', 'color', { granularity: 'char' });
  assert.deepEqual(marked(p.left), ['u']);
  assert.deepEqual(marked(p.right), []);
});

test('inlineParts: ignore options do not mark ignored differences', () => {
  const p = inlineParts(D, 'Hello   World', 'hello World', { ignoreWs: true, ignoreCase: true });
  assert.deepEqual(marked(p.left), []);
  assert.equal(joined(p.left), 'Hello   World');
  assert.equal(joined(p.right), 'hello World');
});

test('inlineParts returns null for unrelated lines', () => {
  assert.equal(inlineParts(D, 'alpha beta gamma', 'zzz 123 !!!'), null);
});

test('foldRows hides long unchanged runs but keeps context', () => {
  const a = Array.from({ length: 20 }, (_, i) => 'line ' + i).join('\n');
  const b = a.replace('line 10', 'line ten');
  const f = foldRows(diffTexts(D, a, b).rows, 3);
  assert.deepEqual(f.map((x) => x.type), ['fold', 'eq', 'eq', 'eq', 'mod', 'eq', 'eq', 'eq', 'fold']);
  assert.deepEqual([f[0].count, f[0].from], [7, 0]);
  assert.deepEqual([f[8].count, f[8].from], [6, 14]);
  // short runs stay visible
  assert.equal(foldRows(diffTexts(D, 'a\nb\nc', 'a\nB\nc').rows).filter((x) => x.type === 'fold').length, 0);
});

test('unifiedDiff produces a patch jsdiff can apply back', () => {
  const a = 'alpha\nbeta\ngamma\ndelta\n', b = 'alpha\nBETA\ngamma\ndelta\nepsilon\n';
  const patch = unifiedDiff(D, a, b);
  assert.match(patch, /^--- original\.txt\n\+\+\+ changed\.txt\n@@ -1,4 \+1,5 @@\n/);
  assert.match(patch, /\n-beta\n\+BETA\n/);
  assert.equal(D.applyPatch(a, patch), b);
  assert.equal(unifiedDiff(D, 'x\r\ny\r\n', 'x\ny\n'), '--- original.txt\n+++ changed.txt\n');
});

test('git apply accepts the unified diff', (t) => {
  const git = spawnSync('git', ['--version']);
  if (git.status !== 0) return t.skip('git not installed');
  const dir = mkdtempSync(path.join(tmpdir(), 'diff-'));
  try {
    const a = 'alpha\nbeta\ngamma\n', b = 'alpha\nBETA\ngamma\nend';
    writeFileSync(path.join(dir, 'file.txt'), a);
    writeFileSync(path.join(dir, 'change.diff'), unifiedDiff(D, a, b, { oldName: 'file.txt', newName: 'file.txt' }));
    // -p0: the headers carry bare file names, as `patch -p0` expects
    const r = spawnSync('git', ['-c', 'core.autocrlf=false', 'apply', '-p0', 'change.diff'], { cwd: dir, encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    assert.equal(readFileSync(path.join(dir, 'file.txt'), 'utf8'), b);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('unifiedDiff honours ignore options', () => {
  const patch = unifiedDiff(D, 'A\nb\n', 'a\nc\n', { ignoreCase: true });
  assert.doesNotMatch(patch, /\n-A\n/);
  assert.match(patch, /\n-b\n\+c\n/);
});

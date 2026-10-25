// Unit tests for the PDF tools' page-range parser.
import test from 'node:test';
import assert from 'node:assert/strict';
import { parseRanges, partName } from '../../static/js/tools/pdf-kit.mjs';

test('ranges, single pages, open ends', () => {
  assert.deepEqual(parseRanges('1-3, 5, 8-', 10).groups, [[0, 1, 2], [4], [7, 8, 9]]);
  assert.deepEqual(parseRanges('-2', 5).groups, [[0, 1]]);
  assert.deepEqual(parseRanges('4 – 5', 5).groups, [[3, 4]]);
  assert.deepEqual(parseRanges('2;3', 3).groups, [[1], [2]]);
});

test('errors', () => {
  assert.equal(parseRanges('', 5).error, 'syntax');
  assert.equal(parseRanges('a-b', 5).error, 'syntax');
  assert.equal(parseRanges('-', 5).error, 'syntax');
  assert.deepEqual(parseRanges('3-1', 5), { error: 'range', part: '3-1' });
  assert.equal(parseRanges('6', 5).error, 'range');
  assert.equal(parseRanges('0', 5).error, 'range');
});

test('part names', () => {
  assert.equal(partName('Report.PDF', 2), 'Report-part-2.pdf');
  assert.equal(partName('.pdf', 1), 'document-part-1.pdf');
});

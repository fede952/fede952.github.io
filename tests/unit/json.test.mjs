// Unit tests for the JSON formatter helpers.
import test from 'node:test';
import assert from 'node:assert/strict';
import * as J from '../../static/js/tools/json-kit.mjs';

test('valid JSON has no error', () => {
  for (const ok of ['{}', '[]', '0', '-1.5e3', String.raw`"aé\n"`, '{"a":[1,{"b":null}],"c":true}', ' \n {"x": "y"} \n ']) assert.equal(J.locateError(ok), null, ok);
});

test('errors are located by line and column', () => {
  const e = J.locateError('{\n  "a": 1,\n  "b": 2,\n}');
  assert.deepEqual([e.line, e.column, e.code], [4, 1, 'trailing-comma']);
  assert.equal(J.locateError('{"a" 1}').code, 'colon');
  assert.equal(J.locateError("{'a': 1}").code, 'single-quote');
  assert.equal(J.locateError('[1 2]').code, 'comma-or-bracket');
  assert.equal(J.locateError('{"a": 01}').code, 'comma-or-brace'); // a leading zero ends the number at "0"
  assert.equal(J.locateError('"abc').code, 'unterminated-string');
  assert.equal(J.locateError(String.raw`{"a":"\x"}`).code, 'escape');
  assert.equal(J.locateError('[1] x').code, 'end');
  assert.equal(J.locateError('').code, 'value');
  assert.equal(J.locateError('{"a": NaN}').code, 'value');
  // every input JSON.parse rejects, the scanner rejects too
  for (const bad of ['{"a":1,}', '[,1]', '{a:1}', '1.', '.5', '+1', '"\t"', 'tru']) {
    assert.throws(() => JSON.parse(bad));
    assert.ok(J.locateError(bad), bad);
  }
});

test('sort keys deeply, keep array order', () => {
  assert.equal(J.minify({ b: 1, a: { d: 1, c: [3, 1] } }, true), '{"a":{"c":[3,1],"d":1},"b":1}');
  assert.equal(J.format({ a: 1 }, 'tab'), '{\n\t"a": 1\n}');
});

test('CSV from objects, arrays and nested values', () => {
  const r = J.toCsv([{ id: 1, name: 'Ada, L.', tags: ['x'], addr: { city: 'Rome' } }, { id: 2, note: 'say "hi"' }]);
  assert.equal(r.csv, 'id,name,tags,addr.city,note\r\n1,"Ada, L.","[""x""]",Rome,\r\n2,,,,"say ""hi"""');
  assert.equal(J.toCsv([[1, 2], [3, null]], ';').csv, '1;2\r\n3;');
  assert.equal(J.toCsv(5).error, 'csv-shape');
  assert.equal(J.toCsv([1, 2]).error, 'csv-shape');
});

test('stats and UTF-8 size', () => {
  assert.deepEqual(J.stats({ a: [1, { b: 2 }] }), { objects: 2, arrays: 1, keys: 2, depth: 3 });
  assert.equal(J.utf8Length('aé€😀'), 1 + 2 + 3 + 4);
});

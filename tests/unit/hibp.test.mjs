// Unit tests for the k-anonymity breach check used by PassFort.
import test from 'node:test';
import assert from 'node:assert/strict';
import { sha1Hex, splitHash, countInRange, pwnedCount, RANGE_URL } from '../../static/js/tools/hibp.mjs';

test('SHA-1 of "password" and its split', async () => {
  const h = await sha1Hex('password');
  assert.equal(h, '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8');
  assert.deepEqual(splitHash(h), { prefix: '5BAA6', suffix: '1E4C9B93F3F0682250B6CF8331B7EE68FD8' });
  assert.equal(await sha1Hex('pässwörd'), (await sha1Hex('pässwörd')), 'UTF-8 input');
});

test('countInRange: match, absence, padding rows, CRLF, case', () => {
  const body = '003D68EB55068C33ACE09247EE4C639306B:3\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0\r\n';
  assert.equal(countInRange(body, '1E4C9B93F3F0682250B6CF8331B7EE68FD8'), 9545824);
  assert.equal(countInRange(body, '1e4c9b93f3f0682250b6cf8331b7ee68fd8'), 9545824);
  assert.equal(countInRange(body, 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'), 0, 'padding entry');
  assert.equal(countInRange(body, '0000000000000000000000000000000000A'), 0);
  assert.equal(countInRange('', 'X'), 0);
});

test('pwnedCount sends only the prefix, with Add-Padding', async () => {
  const calls = [];
  const fake = async (url, opts) => { calls.push({ url, opts }); return { ok: true, text: async () => '1E4C9B93F3F0682250B6CF8331B7EE68FD8:42\n' }; };
  assert.equal(await pwnedCount('password', fake), 42);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, RANGE_URL + '5BAA6');
  assert.equal(calls[0].opts.headers['Add-Padding'], 'true');
  assert(!JSON.stringify(calls[0].opts).includes('1E4C9B'), 'the hash suffix is never sent');
  await assert.rejects(pwnedCount('x', async () => ({ ok: false, status: 503 })), /HTTP 503/);
});

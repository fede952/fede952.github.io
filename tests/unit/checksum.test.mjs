// File checksum verifier: expected-hash parsing and streaming hashing,
// cross-checked against node:crypto (an independent implementation).
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import vm from 'node:vm';
import { parseExpected, sameDigest, algoForHex, hashStream, formatBytes } from '../../static/js/tools/checksum.mjs';

// the vendored UMD builds run as classic scripts and fill globalThis.hashwasm, as in the worker
for (const a of ['md5', 'sha1', 'sha256', 'sha512']) vm.runInThisContext(fs.readFileSync(new URL(`../../static/vendor/hash-wasm@4.12.0/${a}.umd.min.js`, import.meta.url), 'utf8'));
const H = globalThis.hashwasm;
const create = async () => ({ md5: await H.createMD5(), sha1: await H.createSHA1(), sha256: await H.createSHA256(), sha512: await H.createSHA512() });
const streamOf = (buf, chunk) => new ReadableStream({ start(c) { for (let i = 0; i < buf.length; i += chunk) c.enqueue(new Uint8Array(buf.subarray(i, i + chunk))); c.close(); } });
const node = (alg, buf) => crypto.createHash(alg).update(buf).digest('hex');
const S256 = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'; // SHA-256("abc"), FIPS 180-2 example

test('streaming digests equal node:crypto for every algorithm, whatever the chunk size', async () => {
  const buf = crypto.randomBytes(3 * 1024 * 1024 + 17);
  for (const chunk of [1, 63, 64, 65536, 1 << 20]) {
    const data = chunk === 1 ? buf.subarray(0, 4096) : buf;
    let last = 0;
    const d = await hashStream(streamOf(data, chunk), await create(), (b) => { last = b; });
    assert.equal(last, data.length, 'progress reaches the file size');
    for (const [a, n] of [['md5', 'md5'], ['sha1', 'sha1'], ['sha256', 'sha256'], ['sha512', 'sha512']]) assert.equal(d[a], node(n, data), `${a} chunk ${chunk}`);
  }
  const abc = await hashStream(streamOf(Buffer.from('abc'), 2), await create());
  assert.equal(abc.sha256, S256);
  const empty = await hashStream(streamOf(Buffer.alloc(0), 8), await create());
  assert.equal(empty.md5, 'd41d8cd98f00b204e9800998ecf8427e', 'MD5 of the empty file (RFC 1321 test suite)');
});

test('cancel stops the stream', async () => {
  let n = 0;
  await assert.rejects(hashStream(streamOf(Buffer.alloc(1 << 20), 1024), await create(), () => {}, () => ++n > 3), { message: 'cancelled' });
});

test('expected-hash formats: bare, GNU, BSD, PowerShell', () => {
  assert.deepEqual(parseExpected(`  ${S256.toUpperCase()}  `), { hex: S256, algo: 'sha256', name: '' });
  assert.equal(parseExpected(`${S256}  ubuntu.iso`).name, 'ubuntu.iso');
  assert.equal(parseExpected(`${S256} *ubuntu.iso`).name, 'ubuntu.iso', 'binary-mode asterisk');
  assert.deepEqual(parseExpected(`SHA256 (app-1.2.dmg) = ${S256}`), { hex: S256, algo: 'sha256', name: 'app-1.2.dmg' });
  assert.equal(parseExpected(`Hash : ${S256.toUpperCase()}`).hex, S256);
  assert.equal(parseExpected(`SHA256          ${S256.toUpperCase()}       C:\\Users\\alex\\Downloads\\setup.exe`).name, 'setup.exe');
  assert.equal(parseExpected('900150983cd24fb0d6963f7d28e17f72').algo, 'md5');
  assert.equal(parseExpected('a9993e364706816aba3e25717850c26c9cd0d89d').algo, 'sha1');
  assert.equal(parseExpected('x'.repeat(10)).error, 'format');
  assert.equal(parseExpected('abc123').error, 'format', 'hex of no known length');
  assert.equal(parseExpected('   ').error, 'empty');
});

test('SHA256SUMS listing: pick the line for the chosen file', () => {
  const other = 'f'.repeat(64);
  const sums = `# release checksums\n${other}  tool-linux.tar.gz\n${S256}  tool-windows.zip\n`;
  assert.equal(parseExpected(sums, 'tool-windows.zip').hex, S256);
  assert.equal(parseExpected(sums, 'TOOL-WINDOWS.ZIP').hex, S256, 'case-insensitive file name');
  assert.deepEqual(parseExpected(sums, 'missing.bin'), { error: 'ambiguous', count: 2 });
  assert.deepEqual(parseExpected(sums), { error: 'ambiguous', count: 2 });
});

test('comparison and helpers', () => {
  assert(sameDigest(S256, ` ${S256.toUpperCase()} `));
  assert(!sameDigest(S256, S256.slice(0, -1) + '0'));
  assert(!sameDigest('', ''));
  assert.equal(algoForHex('0'.repeat(128)), 'sha512');
  assert.equal(formatBytes(1536, 'en'), '1.5 KB');
  assert.equal(formatBytes(5 * 1024 ** 3, 'en'), '5 GB');
});

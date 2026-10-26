// Test vectors for the encrypted message link (AES-256-GCM + PBKDF2-SHA-256).
import test from 'node:test';
import assert from 'node:assert/strict';
import nodeCrypto from 'node:crypto';
import { encrypt, decrypt, buildLink, randomPassphrase, b64urlDecode, b64urlEncode, ITERATIONS, SALT_BYTES, IV_BYTES } from '../../static/js/tools/secret-link.mjs';

const FAST = { iterations: 1000 }; // speed for the bulk of the tests; the real count is tested once
const hex = (h) => Uint8Array.from(h.match(/../g), (x) => parseInt(x, 16));

test('round trip with the real iteration count, random salt and IV each time', async () => {
  assert(ITERATIONS >= 600000);
  const a = await encrypt('meet at 10', 'correct horse');
  const b = await encrypt('meet at 10', 'correct horse');
  assert.notEqual(a, b, 'fresh salt/IV → different tokens');
  assert.match(a, /^v1\.[A-Za-z0-9_-]+$/);
  assert.equal(await decrypt(a, 'correct horse'), 'meet at 10');
  const ra = b64urlDecode(a.slice(3)), rb = b64urlDecode(b.slice(3));
  assert.notDeepEqual(ra.subarray(0, SALT_BYTES), rb.subarray(0, SALT_BYTES));
  assert.notDeepEqual(ra.subarray(SALT_BYTES, SALT_BYTES + IV_BYTES), rb.subarray(SALT_BYTES, SALT_BYTES + IV_BYTES));
});

test('wrong passphrase fails authentication', async () => {
  const tok = await encrypt('secret', 'right', FAST);
  await assert.rejects(decrypt(tok, 'wrong', FAST), { message: 'auth' });
  await assert.rejects(decrypt(tok, 'Right', FAST), { message: 'auth' });
});

test('tampered ciphertext, tag, IV or version fails on the GCM tag', async () => {
  const tok = await encrypt('pay 100 to Alex', 'pw', FAST);
  const raw = b64urlDecode(tok.slice(3));
  for (const i of [SALT_BYTES + IV_BYTES, raw.length - 1, SALT_BYTES]) { // first ciphertext byte, last tag byte, first IV byte
    const t = raw.slice(); t[i] ^= 0x01;
    await assert.rejects(decrypt('v1.' + b64urlEncode(t), 'pw', FAST), { message: 'auth' }, 'byte ' + i);
  }
  await assert.rejects(decrypt('v1.' + b64urlEncode(raw.slice(0, -1)), 'pw', FAST), { message: 'auth' }, 'truncated tag');
  await assert.rejects(decrypt('v2.' + tok.slice(3), 'pw', FAST), { message: 'format' });
  await assert.rejects(decrypt('v1.@@@', 'pw', FAST), { message: 'format' });
  await assert.rejects(decrypt('v1.AAAA', 'pw', FAST), { message: 'format' });
});

test('Unicode and emoji in message and passphrase; NFC-normalised passphrase', async () => {
  const msg = 'Ciao 👋 — façade, Straße, 日本語, ½ 🇮🇹\nline 2';
  const tok = await encrypt(msg, 'pässwörd 🔑', FAST);
  assert.equal(await decrypt(tok, 'pässwörd 🔑', FAST), msg);
  // "ä" typed as a + combining diaeresis is the same passphrase
  assert.equal(await decrypt(tok, 'pässwörd 🔑', FAST), msg);
  assert.equal(await decrypt(await encrypt('', 'x', FAST), 'x', FAST), '');
});

test('known-answer vector matches an independent node:crypto implementation', async () => {
  const salt = hex('000102030405060708090a0b0c0d0e0f'), iv = hex('a0a1a2a3a4a5a6a7a8a9aaab');
  const tok = await encrypt('hello 🌍', 'test vector', { salt, iv, iterations: ITERATIONS });
  // independent encryption with node:crypto
  const key = nodeCrypto.pbkdf2Sync('test vector', salt, ITERATIONS, 32, 'sha256');
  const c = nodeCrypto.createCipheriv('aes-256-gcm', key, iv); c.setAAD(Buffer.from('v1'));
  const expected = 'v1.' + Buffer.concat([salt, iv, c.update('hello 🌍', 'utf8'), c.final(), c.getAuthTag()]).toString('base64url');
  assert.equal(tok, expected);
  // and node:crypto decrypts what the module produced
  const raw = Buffer.from(tok.slice(3), 'base64url');
  const d = nodeCrypto.createDecipheriv('aes-256-gcm', key, raw.subarray(16, 28)); d.setAAD(Buffer.from('v1'));
  d.setAuthTag(raw.subarray(raw.length - 16));
  assert.equal(Buffer.concat([d.update(raw.subarray(28, raw.length - 16)), d.final()]).toString('utf8'), 'hello 🌍');
});

test('link format and random passphrases', () => {
  assert.equal(buildLink('https://federicosella.com', 'en', 'v1.abc'), 'https://federicosella.com/tools/encrypted-message/#v1.abc');
  assert.equal(buildLink('https://federicosella.com', 'it', 'v1.abc'), 'https://federicosella.com/tools/encrypted-message/?lang=it#v1.abc');
  const p = randomPassphrase();
  assert.match(p, /^([a-km-zA-HJ-NP-Z2-9]{4}-){4}[a-km-zA-HJ-NP-Z2-9]{4}$/);
  assert.notEqual(randomPassphrase(), p);
});

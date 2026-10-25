/* Encrypted message links: AES-256-GCM with a key from PBKDF2-HMAC-SHA-256.
   Web Crypto only, so it runs the same in the browser and in Node (tests in
   tests/unit/secret-link.test.mjs, cross-checked against node:crypto).

   Token format "v1.<base64url>" where the payload is
     salt (16 random bytes) | iv (12 random bytes) | ciphertext | GCM tag (16 bytes)
   The key is PBKDF2-SHA-256(passphrase, salt, 600 000 iterations, 256 bits);
   the version string "v1" is bound to the ciphertext as additional data, so
   changing it breaks the tag. Everything lives in the URL #fragment, which
   browsers never send to the server. */

export const VERSION = 'v1';
export const ITERATIONS = 600000; // OWASP's 2023 minimum for PBKDF2-HMAC-SHA256
export const SALT_BYTES = 16, IV_BYTES = 12, TAG_BYTES = 16;
export const LINK_WARN_CHARS = 2000;

const enc = new TextEncoder(), dec = new TextDecoder('utf-8', { fatal: true });
const subtle = () => globalThis.crypto.subtle;

export function b64urlEncode(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function b64urlDecode(str) {
  if (!/^[A-Za-z0-9_-]*$/.test(str)) throw new Error('format');
  const s = str.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(s + '='.repeat((4 - (s.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

async function deriveKey(passphrase, salt, iterations) {
  const base = await subtle().importKey('raw', enc.encode(passphrase.normalize('NFC')), 'PBKDF2', false, ['deriveKey']);
  return subtle().deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

/**
 * Encrypt a message. `opts.salt` / `opts.iv` exist only for known-answer
 * tests; normal use takes fresh random values from crypto.getRandomValues.
 */
export async function encrypt(message, passphrase, opts = {}) {
  if (!passphrase) throw new Error('passphrase');
  const salt = opts.salt || globalThis.crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const iv = opts.iv || globalThis.crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const key = await deriveKey(passphrase, salt, opts.iterations || ITERATIONS);
  const ct = new Uint8Array(await subtle().encrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(VERSION), tagLength: 128 }, key, enc.encode(message)));
  const out = new Uint8Array(salt.length + iv.length + ct.length);
  out.set(salt, 0); out.set(iv, salt.length); out.set(ct, salt.length + iv.length);
  return `${VERSION}.${b64urlEncode(out)}`;
}

/**
 * Decrypt a token. Throws Error('format') for a malformed token and
 * Error('auth') when the GCM tag does not verify — a wrong passphrase and a
 * modified link are indistinguishable, by design of authenticated encryption.
 */
export async function decrypt(token, passphrase, opts = {}) {
  const m = /^v1\.([A-Za-z0-9_-]+)$/.exec(String(token).trim().replace(/^#/, ''));
  if (!m) throw new Error('format');
  const raw = b64urlDecode(m[1]);
  if (raw.length < SALT_BYTES + IV_BYTES + TAG_BYTES) throw new Error('format');
  const salt = raw.subarray(0, SALT_BYTES), iv = raw.subarray(SALT_BYTES, SALT_BYTES + IV_BYTES), ct = raw.subarray(SALT_BYTES + IV_BYTES);
  const key = await deriveKey(passphrase, salt, opts.iterations || ITERATIONS);
  let pt;
  try { pt = await subtle().decrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(VERSION), tagLength: 128 }, key, ct); } catch { throw new Error('auth'); }
  return dec.decode(pt);
}

/** The shareable link: the standalone tool page (no ads, no analytics) + the token as #fragment. */
export function buildLink(origin, lang, token) {
  return `${origin}/tools/encrypted-message/${lang && lang !== 'en' ? `?lang=${lang}` : ''}#${token}`;
}

/** Random passphrase from an unambiguous alphabet: 5 groups of 4 (about 113 bits). */
export function randomPassphrase(groups = 5) {
  const A = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // 56 symbols, no 0/O/1/l/I
  const out = [];
  const buf = new Uint8Array(1);
  for (let g = 0; g < groups; g++) {
    let s = '';
    while (s.length < 4) { globalThis.crypto.getRandomValues(buf); if (buf[0] < 224) s += A[buf[0] % 56]; } // 224 = 4·56, no modulo bias
    out.push(s);
  }
  return out.join('-');
}

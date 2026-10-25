/* File checksum helpers, DOM-free (tests: tests/unit/checksum.test.mjs).
   Hashing itself streams through hash-wasm (MIT, vendored in
   /vendor/hash-wasm@4.12.0/) inside js/tools/hash-worker.mjs. */

export const ALGOS = { md5: 32, sha1: 40, sha256: 64, sha512: 128 }; // hex length
export const ALGO_NAMES = { md5: 'MD5', sha1: 'SHA-1', sha256: 'SHA-256', sha512: 'SHA-512' };
const BY_LEN = Object.fromEntries(Object.entries(ALGOS).map(([a, n]) => [n, a]));

/** Algorithm a hex digest of this length belongs to, or null. */
export const algoForHex = (hex) => BY_LEN[hex.length] || null;

/* One line of a checksum listing:
     <hex>                                  bare digest
     <hex>  name / <hex> *name              GNU sha256sum, md5sum (text / binary mode)
     SHA256 (name) = <hex>                  BSD, shasum --tag, openssl
     Hash : <HEX>                           PowerShell Get-FileHash (list format)
     SHA256  <HEX>  C:\path\name            PowerShell Get-FileHash (table format) */
function parseLine(line) {
  const l = line.trim();
  if (!l || l.startsWith('#')) return null;
  let m = /^(?:MD5|SHA-?1|SHA-?256|SHA-?512)\s*\((.*)\)\s*=\s*([0-9a-f]+)$/i.exec(l);
  if (m) return { hex: m[2].toLowerCase(), name: m[1] };
  m = /^Hash\s*:\s*([0-9a-f]+)$/i.exec(l);
  if (m) return { hex: m[1].toLowerCase(), name: '' };
  m = /^(?:MD5|SHA1|SHA256|SHA512)\s+([0-9a-f]+)\s+(.+)$/i.exec(l);
  if (m) return { hex: m[1].toLowerCase(), name: m[2].split(/[\\/]/).pop() };
  m = /^([0-9a-f]+)(?:\s+\*?(.*))?$/i.exec(l);
  if (m) return { hex: m[1].toLowerCase(), name: (m[2] || '').trim() };
  return null;
}

/**
 * Find the expected digest in pasted text (a bare hash or a whole SHA256SUMS
 * file). With several lines, the one naming `fileName` wins.
 * Returns { hex, algo } or { error: 'empty' | 'format' | 'ambiguous' }.
 */
export function parseExpected(text, fileName = '') {
  const rows = String(text || '').split(/\r?\n/).map(parseLine).filter((r) => r && algoForHex(r.hex));
  if (!String(text || '').trim()) return { error: 'empty' };
  if (!rows.length) return { error: 'format' };
  let row = rows.length === 1 ? rows[0] : null;
  if (!row && fileName) row = rows.find((r) => r.name === fileName) || rows.find((r) => r.name.toLowerCase() === fileName.toLowerCase()) || null;
  if (!row) return { error: 'ambiguous', count: rows.length };
  return { hex: row.hex, algo: algoForHex(row.hex), name: row.name };
}

/** Compare two hex digests, ignoring case and surrounding spaces. */
export const sameDigest = (a, b) => !!a && !!b && a.trim().toLowerCase() === b.trim().toLowerCase();

export const toHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

/**
 * Hash a ReadableStream of Uint8Array chunks with several incremental hashers
 * at once (each { init(), update(u8), digest('hex') }). `onProgress(bytes)`
 * is called after each chunk; `isCancelled()` stops early with Error('cancelled').
 */
export async function hashStream(stream, hashers, onProgress = () => {}, isCancelled = () => false) {
  for (const h of Object.values(hashers)) h.init();
  const reader = stream.getReader();
  let done = 0;
  for (;;) {
    const { value, done: end } = await reader.read();
    if (end) break;
    if (isCancelled()) { await reader.cancel(); throw new Error('cancelled'); }
    for (const h of Object.values(hashers)) h.update(value);
    done += value.byteLength;
    onProgress(done);
  }
  return Object.fromEntries(Object.entries(hashers).map(([a, h]) => [a, h.digest('hex')]));
}

export function formatBytes(n, locale) {
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0, v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toLocaleString(locale, { maximumFractionDigits: i ? 1 : 0 })} ${u[i]}`;
}

/* Module worker: streams a File through incremental MD5 / SHA-1 / SHA-256 /
   SHA-512 (hash-wasm, MIT, self-hosted) so files of any size hash without
   being loaded into memory and without blocking the page.
   in:  { type: 'hash', file, algos: ['sha256', …] } | { type: 'cancel' }
   out: { type: 'progress', bytes } | { type: 'done', digests, ms } | { type: 'error', message } */
import '/vendor/hash-wasm@4.12.0/md5.umd.min.js';
import '/vendor/hash-wasm@4.12.0/sha1.umd.min.js';
import '/vendor/hash-wasm@4.12.0/sha256.umd.min.js';
import '/vendor/hash-wasm@4.12.0/sha512.umd.min.js';
import { hashStream } from '/js/tools/checksum.mjs';

const H = globalThis.hashwasm;
const CREATE = { md5: H.createMD5, sha1: H.createSHA1, sha256: H.createSHA256, sha512: H.createSHA512 };
let cancelled = false;

self.onmessage = async (e) => {
  const msg = e.data;
  if (msg.type === 'cancel') { cancelled = true; return; }
  if (msg.type !== 'hash') return;
  cancelled = false;
  const t0 = performance.now();
  try {
    const hashers = {};
    for (const a of msg.algos) hashers[a] = await CREATE[a]();
    let last = 0;
    const digests = await hashStream(msg.file.stream(), hashers, (bytes) => {
      const now = performance.now();
      if (now - last > 80) { last = now; self.postMessage({ type: 'progress', bytes }); }
    }, () => cancelled);
    self.postMessage({ type: 'done', digests, ms: Math.round(performance.now() - t0) });
  } catch (err) {
    self.postMessage({ type: 'error', message: err.message });
  }
};
self.postMessage({ type: 'ready' });

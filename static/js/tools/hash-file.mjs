/* File checksum verifier on the Hash Generator page (partials/tools/hash-generator.html).
   The file is streamed through js/tools/hash-worker.mjs; nothing is uploaded. */
import { parseExpected, sameDigest, formatBytes, ALGO_NAMES } from '/js/tools/checksum.mjs';

const S = window.HASH_FILE_STRINGS || {};
const $ = (id) => document.getElementById(id);
const fill = (s, p) => String(s || '').replace(/\{(\w+)\}/g, (m, k) => (p[k] !== undefined ? p[k] : m));
const el = { drop: $('hash-drop'), input: $('hash-file-input'), expected: $('hash-file-expected'), algo: $('hash-file-algo'), auto: $('hash-file-auto'),
  progress: $('hash-file-progress'), bar: $('hash-file-bar'), status: $('hash-file-status'), cancel: $('hash-file-cancel'),
  out: $('hash-file-out'), label: $('hash-file-label'), digest: $('hash-file-digest'), copy: $('hash-file-copy'), meta: $('hash-file-meta'), verdict: $('hash-file-verdict') };

let file = null, worker = null, result = null; // result: { algo, hex, name, size }

function verdict(kind, text) {
  el.verdict.className = 'tool-message ' + kind;
  el.verdict.textContent = text;
  el.verdict.hidden = !text;
}

/** The expected checksum, if any, decides the algorithm. */
function expectedInfo() {
  const raw = el.expected.value;
  if (!raw.trim()) { el.auto.hidden = true; el.algo.disabled = false; return null; }
  const p = parseExpected(raw, file ? file.name : '');
  if (p.error) { el.auto.hidden = true; el.algo.disabled = false; return p; }
  el.algo.value = p.algo; el.algo.disabled = true;
  el.auto.textContent = fill(S.auto, { algo: ALGO_NAMES[p.algo] }); el.auto.hidden = false;
  return p;
}

function compare() {
  const exp = expectedInfo();
  if (!result) { if (exp && exp.error && exp.error !== 'empty' && exp.error !== 'ambiguous') verdict('error', S.badExpected); else verdict('', ''); return; }
  if (!exp) { verdict('', ''); return; }
  if (exp.error === 'format') return verdict('error', S.badExpected);
  if (exp.error === 'ambiguous') return verdict('error', fill(S.ambiguous, { n: exp.count, name: result.name }));
  if (exp.algo !== result.algo) return start(); // a different algorithm: hash again
  const weak = exp.algo === 'md5' || exp.algo === 'sha1' ? ' ' + S.weak : '';
  if (sameDigest(exp.hex, result.hex)) verdict('success', S.match + weak);
  else verdict('error', S.mismatch);
  window.__hashFileVerdict = sameDigest(exp.hex, result.hex) ? 'match' : 'mismatch';
}

function start() {
  if (!file) return;
  if (worker) worker.terminate();
  result = null;
  const algo = el.algo.value;
  const f = file;
  el.out.hidden = true; verdict('', '');
  el.progress.hidden = false; el.bar.value = 0; el.bar.max = Math.max(1, f.size);
  el.status.textContent = fill(S.hashing, { done: formatBytes(0, S.lang), total: formatBytes(f.size, S.lang) });
  worker = new Worker('/js/tools/hash-worker.mjs', { type: 'module' });
  worker.onmessage = (e) => {
    const m = e.data;
    if (m.type === 'ready') worker.postMessage({ type: 'hash', file: f, algos: [algo] });
    else if (m.type === 'progress') {
      el.bar.value = m.bytes;
      el.status.textContent = fill(S.hashing, { done: formatBytes(m.bytes, S.lang), total: formatBytes(f.size, S.lang) });
    } else if (m.type === 'done') {
      worker.terminate(); worker = null;
      result = { algo, hex: m.digests[algo], name: f.name, size: f.size };
      el.progress.hidden = true;
      el.label.textContent = ALGO_NAMES[algo];
      el.digest.value = result.hex;
      el.meta.textContent = fill(S.meta, { name: f.name, size: formatBytes(f.size, S.lang), s: (m.ms / 1000).toLocaleString(S.lang, { maximumFractionDigits: 1 }) });
      el.out.hidden = false;
      window.__hashFileResult = result;
      compare();
    } else if (m.type === 'error') {
      worker.terminate(); worker = null;
      el.progress.hidden = true;
      if (m.message !== 'cancelled') verdict('error', fill(S.failed, { e: m.message }));
    }
  };
}

function pick(f) { if (!f) return; file = f; expectedInfo(); start(); }

el.input.addEventListener('change', () => pick(el.input.files[0]));
el.drop.addEventListener('dragover', (e) => { e.preventDefault(); el.drop.classList.add('is-over'); });
el.drop.addEventListener('dragleave', () => el.drop.classList.remove('is-over'));
el.drop.addEventListener('drop', (e) => { e.preventDefault(); el.drop.classList.remove('is-over'); pick(e.dataTransfer.files[0]); });
el.expected.addEventListener('input', compare);
el.algo.addEventListener('change', () => { if (file) start(); });
el.cancel.addEventListener('click', () => { if (worker) { worker.terminate(); worker = null; } el.progress.hidden = true; });
el.copy.addEventListener('click', async () => {
  try { await navigator.clipboard.writeText(el.digest.value); el.copy.textContent = '✓'; setTimeout(() => { el.copy.textContent = el.copy.dataset.label; }, 1200); } catch { el.digest.select(); }
});
el.copy.dataset.label = el.copy.textContent;
window.__hashFileReady = true;

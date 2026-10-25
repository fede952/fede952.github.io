// Web Worker of /tools/json-formatter/: parses and serialises inputs larger
// than 2 MB off the main thread so the page stays responsive.
// Message in:  { op: 'format' | 'minify' | 'validate', text, indent, sorted }
// Message out: { ok: true, output, stats } or { ok: false, error }
import { locateError, format, minify, stats } from './json-kit.mjs';

self.onmessage = (e) => {
  const { op, text, indent, sorted } = e.data;
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    self.postMessage({ ok: false, error: locateError(text) || { code: 'unknown', line: 1, column: 1, index: 0 } });
    return;
  }
  const output = op === 'minify' ? minify(value, sorted) : op === 'format' ? format(value, indent, sorted) : null;
  self.postMessage({ ok: true, output, stats: stats(value) });
};

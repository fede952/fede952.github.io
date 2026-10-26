/* Screenshot Redactor — pure logic (no DOM): sensitive-text detection over OCR
   output, validators, redaction geometry and the undo/redo history.
   Unit-tested in tests/unit/redact.test.mjs. */

/** ISO 13616 IBAN check: length 15–34, country letters, mod-97 of the rearranged digits = 1. */
export function ibanValid(raw) {
  const s = String(raw).replace(/\s+/g, '').toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(s)) return false;
  const moved = s.slice(4) + s.slice(0, 4);
  let rem = 0;
  for (const ch of moved) {
    const v = /\d/.test(ch) ? ch : String(ch.charCodeAt(0) - 55);
    for (const d of v) rem = (rem * 10 + Number(d)) % 97;
  }
  return rem === 1;
}

/** Luhn checksum for payment card numbers (13–19 digits). */
export function luhnValid(raw) {
  const d = String(raw).replace(/\D/g, '');
  if (d.length < 13 || d.length > 19) return false;
  let sum = 0;
  for (let i = 0; i < d.length; i++) {
    let n = Number(d[d.length - 1 - i]);
    if (i % 2) { n *= 2; if (n > 9) n -= 9; }
    sum += n;
  }
  return sum % 10 === 0;
}

const ipv4Valid = (s) => s.split('.').every((o) => Number(o) <= 255 && !(o.length > 1 && o[0] === '0'));
const digits = (s) => s.replace(/\D/g, '').length;

/* Detectors in priority order: a later one never claims characters an earlier one took. */
export const DETECTORS = [
  { type: 'email', re: /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/g },
  { type: 'iban', re: /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}\b/g, ok: ibanValid },
  { type: 'card', re: /\b\d(?:[ -]?\d){12,18}\b/g, ok: luhnValid },
  { type: 'ip', re: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, ok: ipv4Valid },
  { type: 'ip', re: /(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}(?![\w:])|(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){1,6}(?::[0-9A-Fa-f]{1,4}){1,6}(?![\w:])/g,
    ok: (s) => /[0-9a-f]/i.test(s) && s.length >= 6 && !/^\d+:\d+(:\d+)?$/.test(s) },   // not a time like 12:30:45
  { type: 'phone', re: /(?:\+\d{1,3}[ .-]?)?(?:\(\d{1,4}\)[ .-]?)?\d{2,4}(?:[ .-]?\d{2,4}){1,4}/g,
    ok: (s) => { const n = digits(s); return s.trim().startsWith('+') ? n >= 8 && n <= 15 : n >= 9 && n <= 13; } },
];

const union = (boxes, pad) => ({
  x0: Math.min(...boxes.map((b) => b.x0)) - pad, y0: Math.min(...boxes.map((b) => b.y0)) - pad,
  x1: Math.max(...boxes.map((b) => b.x1)) + pad, y1: Math.max(...boxes.map((b) => b.y1)) + pad,
});

/**
 * Sensitive values in one OCR line. `words` = [{ text, bbox: {x0,y0,x1,y1} }] in reading order.
 * Returns [{ type, text, bbox }] where bbox covers every word the match touches (+ pad px).
 */
export function findInLine(words, pad = 2) {
  let line = '';
  const spans = words.map((w) => {
    const start = line.length ? line.length + 1 : 0;
    line += (line.length ? ' ' : '') + w.text;
    return { start, end: start + w.text.length, bbox: w.bbox };
  });
  const taken = [];
  const out = [];
  for (const d of DETECTORS) {
    for (const m of line.matchAll(d.re)) {
      const s = m.index, e = s + m[0].length, text = m[0].trim();
      if (!text || taken.some(([a, b]) => s < b && e > a)) continue;
      if (d.ok && !d.ok(text)) continue;
      const hit = spans.filter((w) => w.start < e && w.end > s);
      if (!hit.length) continue;
      taken.push([s, e]);
      out.push({ type: d.type, text, bbox: union(hit.map((w) => w.bbox), pad) });
    }
  }
  return out;
}

/** All suggestions for a Tesseract result: lines = [{ words: [...] }]. */
export const findSensitive = (lines, pad = 2) => lines.flatMap((l) => findInLine(l.words || [], pad));

/** Normalizes a drag (any direction) into a rectangle clamped to the image; null if too small. */
export function rectFrom(a, b, w, h, min = 3) {
  const x = Math.max(0, Math.min(a.x, b.x)), y = Math.max(0, Math.min(a.y, b.y));
  const x2 = Math.min(w, Math.max(a.x, b.x)), y2 = Math.min(h, Math.max(a.y, b.y));
  return x2 - x >= min && y2 - y >= min ? { x: Math.round(x), y: Math.round(y), w: Math.round(x2 - x), h: Math.round(y2 - y) } : null;
}

/** Pixelation block size for a region: about 1/8 of its short side, at least 8 px. */
export const pixelBlock = (r) => Math.max(8, Math.round(Math.min(r.w, r.h) / 8));

/** Undo/redo over immutable snapshots (arrays of redactions). */
export class History {
  constructor(initial = []) { this.stack = [initial]; this.at = 0; }
  get current() { return this.stack[this.at]; }
  push(next) { this.stack = this.stack.slice(0, this.at + 1); this.stack.push(next); this.at++; return next; }
  undo() { if (this.at > 0) this.at--; return this.current; }
  redo() { if (this.at < this.stack.length - 1) this.at++; return this.current; }
  get canUndo() { return this.at > 0; }
  get canRedo() { return this.at < this.stack.length - 1; }
}

/** Output file name: "<original>-redacted.<ext>". */
export function outputName(name, ext) {
  const base = String(name || 'screenshot').replace(/\.[^.]+$/, '') || 'screenshot';
  return `${base}-redacted.${ext}`;
}

// Shared code of the PDF tools (/tools/pdf-merge-split/, /tools/images-to-pdf/).
// parseRanges is pure and unit-tested (tests/unit/pdf.test.mjs); the rest
// runs in the browser and loads pdf.js / pdf-lib / JSZip only on demand.

const PDFJS = '/vendor/pdfjs-dist@6.4.299/';

/**
 * "1-3, 5, 8-" → [[0,1,2],[4],[7,…,count-1]] (0-based page indices; one
 * group per comma-separated part). "-3" means 1-3, "8-" means 8 to the end.
 * Returns { groups } or { error: 'syntax' | 'range', part }.
 */
export function parseRanges(text, count) {
  const parts = String(text).split(/[,;]/).map((p) => p.trim()).filter(Boolean);
  if (!parts.length) return { error: 'syntax', part: '' };
  const groups = [];
  for (const part of parts) {
    const m = part.match(/^(\d*)\s*(?:[-–]\s*(\d*))?$/);
    if (!m || (m[1] === '' && (m[2] === undefined || m[2] === ''))) return { error: 'syntax', part };
    const a = m[1] === '' ? 1 : Number(m[1]);
    const b = m[2] === undefined ? a : m[2] === '' ? count : Number(m[2]);
    if (a < 1 || b < a || b > count) return { error: 'range', part };
    groups.push(Array.from({ length: b - a + 1 }, (_, i) => a - 1 + i));
  }
  return { groups };
}

/** "Report.pdf" + 2 → "Report-part-2.pdf". */
export const partName = (name, n) => `${name.replace(/\.pdf$/i, '') || 'document'}-part-${n}.pdf`;

/* ── browser helpers ── */

const loadScript = (src) => new Promise((ok, fail) => {
  const s = document.createElement('script');
  s.src = src; s.onload = ok; s.onerror = () => fail(new Error('load ' + src));
  document.head.appendChild(s);
});

let pdfLibP, pdfJsP, zipP;
export const pdfLib = () => (pdfLibP ||= loadScript('/vendor/pdf-lib@1.17.1/pdf-lib.min.js').then(() => window.PDFLib));
export const jsZip = () => (zipP ||= loadScript('/vendor/jszip@3.10.2/jszip.min.js').then(() => window.JSZip));
export function pdfJs() {
  return (pdfJsP ||= import(PDFJS + 'pdf.min.mjs').then((lib) => {
    lib.GlobalWorkerOptions.workerSrc = PDFJS + 'pdf.worker.min.mjs';
    return lib;
  }));
}

/** Opens a PDF with pdf.js for thumbnails (a copy of the bytes: pdf.js transfers its buffer to the worker). */
export async function openForPreview(bytes) {
  const lib = await pdfJs();
  return lib.getDocument({
    data: bytes.slice(), cMapUrl: PDFJS + 'cmaps/', cMapPacked: true,
    standardFontDataUrl: PDFJS + 'standard_fonts/', wasmUrl: PDFJS + 'wasm/', isEvalSupported: false,
  }).promise;
}

/** Renders page `index` (0-based) of a pdf.js document into a canvas at most `max` px on its longer side. */
export async function renderThumb(doc, index, max = 180) {
  const page = await doc.getPage(index + 1);
  const base = page.getViewport({ scale: 1 });
  const scale = Math.min(max / Math.max(base.width, base.height), 2);
  const vp = page.getViewport({ scale });
  const canvas = document.createElement('canvas');
  canvas.width = Math.round(vp.width); canvas.height = Math.round(vp.height);
  await page.render({ canvasContext: canvas.getContext('2d'), viewport: vp, canvas }).promise;
  page.cleanup();
  return canvas;
}

/**
 * A reorderable grid of tiles. items: array of objects, each with .el (the
 * tile's content element). Drag and drop with a mouse; on touch screens
 * and from the keyboard, every tile has ← / → buttons. onChange() runs after
 * every move or removal; the array itself is reordered in place.
 */
export function sortableGrid(list, items, { labels, onChange, onRemove, onRotate }) {
  let dragFrom = -1;
  function render() {
    list.replaceChildren(...items.map((it, i) => {
      const li = document.createElement('li');
      li.className = 'tile';
      li.draggable = true;
      li.dataset.index = i;
      const tools = document.createElement('div');
      tools.className = 'tile-tools';
      const btn = (txt, label, fn, disabled) => {
        const b = document.createElement('button');
        b.type = 'button'; b.className = 'tile-btn'; b.textContent = txt; b.title = label; b.setAttribute('aria-label', label);
        b.disabled = !!disabled; b.addEventListener('click', fn);
        return b;
      };
      tools.append(
        btn('←', labels.left, () => move(i, i - 1), i === 0),
        ...(onRotate ? [btn('⟳', labels.rotate, () => { onRotate(it); render(); onChange(); })] : []),
        btn('✕', labels.remove, () => { items.splice(i, 1); onRemove && onRemove(it); render(); onChange(); }),
        btn('→', labels.right, () => move(i, i + 1), i === items.length - 1),
      );
      const num = document.createElement('span');
      num.className = 'tile-num';
      num.textContent = i + 1;
      li.append(it.el, num, tools);
      li.addEventListener('dragstart', (e) => { dragFrom = i; li.classList.add('is-dragging'); e.dataTransfer.effectAllowed = 'move'; e.dataTransfer.setData('text/plain', String(i)); });
      li.addEventListener('dragend', () => li.classList.remove('is-dragging'));
      li.addEventListener('dragover', (e) => { e.preventDefault(); li.classList.add('is-target'); });
      li.addEventListener('dragleave', () => li.classList.remove('is-target'));
      li.addEventListener('drop', (e) => { e.preventDefault(); li.classList.remove('is-target'); if (dragFrom >= 0) move(dragFrom, i); dragFrom = -1; });
      return li;
    }));
  }
  function move(from, to) {
    if (to < 0 || to >= items.length || from === to) return;
    const [x] = items.splice(from, 1);
    items.splice(to, 0, x);
    render(); onChange();
    const target = list.children[to] && list.children[to].querySelector(to > from ? '.tile-btn:last-child' : '.tile-btn');
    if (target && !target.disabled) target.focus();
  }
  render();
  return { render };
}

/** Shared tile styles, injected once by each PDF app. */
export const TILE_CSS = `
.tiles { display: grid; grid-template-columns: repeat(auto-fill, minmax(124px, 1fr)); gap: var(--s-3); margin: 0; padding: 0; list-style: none; }
.tile { position: relative; display: grid; gap: var(--s-1); justify-items: center; padding: var(--s-2); background: var(--bg-raised); border: 1px solid var(--border); border-radius: var(--r); cursor: grab; }
.tile.is-dragging { opacity: .4; }
.tile.is-target { border-color: var(--accent); }
.tile canvas, .tile img { max-width: 100%; height: auto; max-height: 160px; border-radius: 4px; background: #fff; box-shadow: var(--shadow-1); }
.tile-cap { width: 100%; overflow: hidden; color: var(--text-2); font-size: var(--fs-xs); text-align: center; text-overflow: ellipsis; white-space: nowrap; }
.tile-num { position: absolute; top: 6px; left: 6px; min-width: 22px; padding: 0 6px; border-radius: var(--r-pill); background: var(--surface-3); color: var(--text); font-size: var(--fs-xs); font-weight: 600; text-align: center; }
.tile-tools { display: flex; gap: 4px; }
.tile-btn { min-width: 32px; min-height: 32px; border: 1px solid var(--border-strong); border-radius: var(--r-sm); background: var(--surface-2); color: var(--text); cursor: pointer; }
.tile-btn:hover:not(:disabled) { border-color: var(--accent); color: var(--accent); }
.tile-btn:disabled { opacity: .35; cursor: default; }
`;

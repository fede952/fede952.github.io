# Vendored third-party libraries

Self-hosted copies of the browser libraries the site and its tools use, so no
page loads code from a third-party CDN (privacy: no visitor IP is sent to the
CDN; reliability: no external dependency). Fetched from jsDelivr or npm at the exact
pinned version in the folder name. Update by re-downloading the same path
with a new version and changing the `src` that points here.

| Library | Version | Licence | Used by |
|---|---|---|---|
| medium-zoom | 1.1.0 | MIT | image zoom on article pages (extend_footer.html) |
| fuse.js | 7.0.0 | Apache-2.0 | site search palette (extend_footer.html) |
| exif-js | 2.3.0 | MIT | tools/exif-cleaner |
| chart.js | 4.4.7 | MIT | tools/freelance-calculator |
| browser-image-compression | 2.0.2 | MIT | tools/pixel-shrink (also loaded by its Web Worker via `libURL`) |
| qrcode-generator | 1.4.4 | MIT | tools/qr-generator |
| libheif-js | 1.23.5 | LGPL-3.0 (libheif) | tools/heic-converter — `libheif.js` + `libheif.wasm`, the unmodified WebAssembly build from npm, loaded only when a file is dropped. LGPL: the library is a separate, replaceable file; its source is at github.com/strukturag/libheif and github.com/catdad-experiments/libheif-js; `LICENSE` is next to it |
| jszip | 3.10.2 | MIT (dual MIT / GPL-3.0, used under MIT) | tools/heic-converter, tools/pdf-merge-split (via `js/tools/pdf-kit.mjs`) — ZIP download, loaded on demand |
| pdf-lib | 1.17.1 | MIT | tools/pdf-merge-split, tools/images-to-pdf (via `js/tools/pdf-kit.mjs`) — builds the output PDFs, loaded on demand |
| pdfjs-dist | 6.4.299 | Apache-2.0 | tools/pdf-merge-split (via `js/tools/pdf-kit.mjs`) — page thumbnails only; `pdf.min.mjs` + its worker, plus `cmaps/`, `standard_fonts/` and `wasm/` so CJK and non-embedded fonts render without a CDN |
| js-yaml | 4.1.0 | MIT | tools/json-formatter — YAML ⇄ JSON, loaded the first time YAML is used |
| diff (jsdiff) | 9.0.0 | BSD-3-Clause | tools/text-diff — `dist/diff.min.js` (UMD, global `Diff`) |
| tesseract.js | 5.1.1 | Apache-2.0 | tools/screenshot-redactor — optional text detection, loaded only when the user asks for suggestions; `tesseract.min.js` + `worker.min.js` (source-map comments removed) |
| tesseract.js-core | 5.1.1 | Apache-2.0 | tools/screenshot-redactor — the LSTM WebAssembly builds only (`tesseract-core-simd-lstm.wasm.js` and the non-SIMD fallback) |
| @tesseract.js-data/eng | 1.0.0 | MIT (package) / Apache-2.0 (Tesseract `tessdata_best` model) | tools/screenshot-redactor — `eng.traineddata.gz` from `4.0.0_best_int` (2.9 MB) |

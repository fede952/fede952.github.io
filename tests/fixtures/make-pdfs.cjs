// Regenerates the small sample PDFs used by tests/functional.mjs:
//   node tests/fixtures/make-pdfs.cjs
const fs = require('fs');
const path = require('path');
const os = require('os');
// the vendored UMD build, loaded as CommonJS (the repo's package.json is "type": "module")
const tmp = path.join(os.tmpdir(), 'pdf-lib-1.17.1.cjs');
fs.copyFileSync(path.join(__dirname, '../../static/vendor/pdf-lib@1.17.1/pdf-lib.min.js'), tmp);
const { PDFDocument, StandardFonts } = require(tmp);
(async () => {
  for (const [name, n] of [['sample-a.pdf', 2], ['sample-b.pdf', 3]]) {
    const doc = await PDFDocument.create();
    const font = await doc.embedFont(StandardFonts.Helvetica);
    for (let i = 1; i <= n; i++) {
      const page = doc.addPage([300, 400]);
      page.drawText(`${name[7].toUpperCase()}${i}`, { x: 100, y: 200, size: 60, font });
    }
    doc.setTitle(name); doc.setProducer('tests/fixtures/make-pdfs.cjs'); doc.setCreationDate(new Date(0)); doc.setModificationDate(new Date(0));
    fs.writeFileSync(path.join(__dirname, name), await doc.save({ useObjectStreams: false }));
  }
})();

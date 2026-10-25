// Functional suite: one or more real actions per tool, run on the embedded
// apps of the local build (public/). Every external request is blocked; the
// few tools that call an API on purpose get a mocked response.
//
//   node tests/functional.mjs                 # all tests
//   node tests/functional.mjs qr-generator,netguard
import { chromium } from 'playwright';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import jsQR from 'jsqr';
import { PNG } from 'pngjs';
import { serve, blockExternal, BLOCKED_NOISE } from './lib/server.mjs';

const FIXTURES = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures');
const PHOTO = path.join(FIXTURES, 'photo-gps.jpg');
const HEIC = path.join(FIXTURES, 'photo-gps.heic');
const only = process.argv[2]?.split(',');

const blobHref = (page, sel) => page.waitForFunction((s) => { const a = document.querySelector(s); return a && /^blob:|^data:/.test(a.href); }, sel, { timeout: 30000 });
const decodeQR = (buf) => { const png = PNG.sync.read(buf); const r = jsQR(new Uint8ClampedArray(png.data), png.width, png.height); return r && r.data; };
const assert = (cond, msg) => { if (!cond) throw new Error(msg); };
const innerHeightGuess = () => 844 * 1.5 + 50;

// name -> { url, run(page, ctx) => summary string }. New tools add an entry here.
export const TESTS = {
  'pixel-shrink': { url: '/tools/pixel-shrink/', async run(p) {
    await p.setInputFiles('#fileInput', PHOTO); await p.waitForSelector('#compressBtn:not([disabled])'); await p.click('#compressBtn');
    await blobHref(p, '#downloadBtn'); return 'compressed (Web Worker, self-hosted lib)'; } },
  'exif-cleaner': { url: '/tools/exif-cleaner/', async run(p) {
    await p.setInputFiles('#fileInput', PHOTO); await p.waitForFunction(() => /GPS|FixtureCam/i.test(document.body.innerText));
    await p.click('#purgeBtn'); await blobHref(p, '#downloadBtn');
    const hasExif = await p.evaluate(async () => { const b = await (await fetch(document.querySelector('#downloadBtn').href)).arrayBuffer(); return new TextDecoder('latin1').decode(new Uint8Array(b).slice(0, 4096)).includes('Exif'); });
    assert(!hasExif, 'clean image still has an Exif block'); return 'GPS shown, purged image has no Exif'; } },
  'qr-generator': { url: '/tools/qr-generator/', async run(p) {
    const out = [];
    for (const text of ['https://federicosella.com/it/tools/', 'Città: Zürich, España, Ação, €5 ✓']) {
      await p.fill('#qr-input', text); await p.evaluate(() => window.generateQR());
      const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#download-btn')]);
      const got = decodeQR(fs.readFileSync(await dl.path()));
      assert(got === text, `QR decodes to ${JSON.stringify(got)}, expected ${JSON.stringify(text)}`); out.push('ok');
    }
    return `URL + UTF-8 text decode back exactly (${out.length})`; } },
  'qr-wifi-vcard': { url: '/tools/qr-generator/?lang=en', async run(p) {
    await p.waitForFunction(() => window.QRP);
    const grab = async () => { const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#download-btn')]); return { name: dl.suggestedFilename(), text: decodeQR(fs.readFileSync(await dl.path())) }; };
    // Wi-Fi with every character that needs escaping
    await p.click('.mode-tab[data-mode=wifi]');
    await p.click('button.btn-primary');
    assert((await p.textContent('#status')).includes('network name'), 'empty SSID error');
    await p.fill('#wf-ssid', 'Café;Net,work:"5G"\\'); await p.fill('#wf-pass', 'p@ss;w,o:r"d\\ end'); await p.check('#wf-hidden');
    await p.click('button.btn-primary');
    const wifi = await grab();
    const expected = 'WIFI:T:WPA;S:Café\\;Net\\,work\\:\\"5G\\"\\\\;P:p@ss\\;w\\,o\\:r\\"d\\\\ end;H:true;;';
    assert(wifi.text === expected, 'Wi-Fi QR decodes to ' + JSON.stringify(wifi.text));
    assert(wifi.name === 'wifi-qrcode.png', 'file name ' + wifi.name);
    const back = await p.evaluate((s) => window.QRP.parseWifi(s), wifi.text);
    assert(back.S === 'Café;Net,work:"5G"\\' && back.P === 'p@ss;w,o:r"d\\ end' && back.H === 'true', 'Wi-Fi fields ' + JSON.stringify(back));
    // open network: no P field
    await p.selectOption('#wf-auth', 'nopass'); await p.click('button.btn-primary');
    assert((await grab()).text === 'WIFI:T:nopass;S:Café\\;Net\\,work\\:\\"5G\\"\\\\;H:true;;', 'open network payload');
    // vCard
    await p.click('.mode-tab[data-mode=vcard]');
    await p.fill('#vc-first', 'Ada'); await p.fill('#vc-last', 'Lovelace'); await p.fill('#vc-org', 'Engines, Ltd; R&D');
    await p.fill('#vc-phone', '+44 20 7946 0000'); await p.fill('#vc-email', 'ada@example.com'); await p.fill('#vc-city', 'London');
    await p.fill('#vc-note', 'Line 1\nLine 2');
    await p.click('button.btn-primary');
    const vc = await grab();
    assert(vc.text === await p.inputValue('#payload').then((s) => s.replace(/\r?\n/g, '\r\n')), 'vCard QR matches the shown payload');
    const card = vc.text.split('\r\n');
    for (const line of ['BEGIN:VCARD', 'VERSION:3.0', 'N:Lovelace;Ada;;;', 'FN:Ada Lovelace', 'ORG:Engines\\, Ltd\\; R&D', 'TEL;TYPE=CELL:+44 20 7946 0000',
      'EMAIL;TYPE=INTERNET:ada@example.com', 'ADR;TYPE=WORK:;;;London;;;', 'NOTE:Line 1\\nLine 2', 'END:VCARD'])
      assert(card.includes(line), 'vCard misses ' + JSON.stringify(line) + ' in ' + JSON.stringify(vc.text));
    assert(vc.name === 'contact-qrcode.png', 'file name ' + vc.name);
    // the text mode still works after switching back
    await p.click('.mode-tab[data-mode=text]'); await p.fill('#qr-input', 'hello'); await p.click('button.btn-primary');
    assert((await grab()).text === 'hello', 'text mode');
    return 'Wi-Fi (escaped ; , : " \\, hidden, open) and vCard 3.0 decode back exactly with jsQR'; } },
  'freelance-calculator': { url: '/tools/freelance-calculator/', async run(p) {
    await p.fill('#salary', '72000'); await p.dispatchEvent('#salary', 'input');
    await p.waitForFunction(() => typeof Chart !== 'undefined' && Object.keys(Chart.instances || {}).length > 0); return 'rate computed, chart drawn'; } },
  'pass-fort': { url: '/tools/pass-fort/', async run(p) {
    await p.waitForTimeout(500);
    const v = await p.evaluate(() => [...document.querySelectorAll('input,output,code,div')].map((e) => e.value || e.textContent).find((t) => t && /^[\x21-\x7e]{16,}$/.test(t.trim())));
    assert(v, 'no generated password found'); return `password generated (${v.trim().length} chars)`; } },
  'pass-fort-hibp': { url: '/tools/pass-fort/', async run(p, { context }) {
    // Mocked Pwned Passwords range API: never the real service. "password" hashes to 5BAA6 + 1E4C9B…
    const seen = [];
    await context.route('https://api.pwnedpasswords.com/range/*', (r) => {
      seen.push({ url: r.request().url(), padding: r.request().headers()['add-padding'] });
      const body = r.request().url().endsWith('/5BAA6')
        ? '003D68EB55068C33ACE09247EE4C639306B:3\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0'
        : '0000000000000000000000000000000000A:0';
      return r.fulfill({ status: 200, contentType: 'text/plain', body, headers: { 'access-control-allow-origin': '*' } });
    });
    const requests = [];
    p.on('request', (r) => { if (r.url().includes('pwnedpasswords')) requests.push(r.url()); });
    await p.click('.tab-btn[data-tab=auditor]');
    await p.fill('#auditInput', 'password');
    await p.waitForTimeout(300);
    assert(requests.length === 0, 'the breach check must be opt-in: requests before click ' + requests.join(','));
    await p.click('#breachBtn');
    await p.waitForSelector('#breachResult.bad');
    assert(/^Found 9,545,824 times/.test(await p.textContent('#breachResult')), 'result: ' + await p.textContent('#breachResult'));
    assert(seen.length === 1 && seen[0].url === 'https://api.pwnedpasswords.com/range/5BAA6' && seen[0].padding === 'true', 'request: ' + JSON.stringify(seen));
    // typing again clears the old result; a strong unknown password is reported as not found
    await p.fill('#auditInput', 'correct-Horse-battery-staple-91');
    assert((await p.textContent('#breachResult')) === '', 'stale result kept');
    await p.click('#breachBtn'); await p.waitForSelector('#breachResult.ok');
    // service unreachable
    await context.unroute('https://api.pwnedpasswords.com/range/*');
    await p.fill('#auditInput', 'another one'); await p.click('#breachBtn'); await p.waitForSelector('#breachResult.err');
    return 'opt-in only, 5-char prefix + Add-Padding, found / not found / offline (mocked API)'; } },
  'pass-fort-page': { url: '/it/tools/pass-fort/', async run(p) {
    // embedded on the Italian page: the checker opens first and the generator tab links to the generator tool
    const f = p.frameLocator('iframe.tool-iframe');
    await f.locator('#panel-auditor').waitFor({ state: 'visible' });
    assert(!(await f.locator('#panel-generator').isVisible()), 'generator panel visible by default');
    assert((await p.textContent('h1')).trim() === 'Verifica Password: Sicurezza e Violazioni', 'H1: ' + await p.textContent('h1'));
    await f.locator('.tab-btn[data-tab=generator]').click();
    const link = f.locator('#pgLink');
    assert(await link.getAttribute('href') === '/it/tools/password-generator/', 'generator link ' + await link.getAttribute('href'));
    await Promise.all([p.waitForURL(/\/it\/tools\/password-generator\/$/), link.click()]);
    assert(/pass-fort/.test(await p.locator('main a[href="/it/tools/pass-fort/"]').first().getAttribute('href')), 'generator page links back to PassFort');
    return 'checker first, H1 refocused, generator link navigates the top window to /it/tools/password-generator/ and back-links'; } },
  'jwt-inspector': { url: '/tools/jwt-inspector/', async run(p) {
    const tok = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    const ta = await p.$('textarea'); await ta.fill(tok); await ta.dispatchEvent('input');
    await p.waitForFunction(() => document.body.innerText.includes('John Doe')); return 'sample JWT decoded'; } },
  'secrets-scanner': { url: '/tools/secrets-scanner/', async run(p) {
    // the key is assembled so no complete AWS key pattern appears in this file
    const ta = await p.$('textarea'); await ta.fill('const k = "' + 'AKIA' + 'IOSFODNN7EXAMPLE";\npassword = "hunter2hunter2"'); await ta.dispatchEvent('input');
    const btn = await p.$('button:has-text("Scan")'); if (btn) await btn.click();
    await p.waitForFunction(() => /AWS|AKIA/i.test(document.body.innerText)); return 'AWS key pattern detected'; } },
  'secrets-scanner-sample': { url: '/tools/secrets-scanner/?lang=en', async run(p) {
    // "Load sample": every fake secret (built at runtime in the app) is still found
    await p.click('#btn-sample');
    await p.waitForFunction(() => /Findings/.test(document.getElementById('results-card').innerText));
    const out = await p.evaluate(() => document.getElementById('results-card').innerText);
    assert(/4 critical\s+3 high\s+2 medium\s+1 info/.test(out), 'severity counts: ' + out.slice(0, 160));
    const expected = [
      ['AWS Access Key ID', 3, 'AKIA…'], ['AWS Secret Access Key', 4, 'wJal…'], ['GitHub token', 5, 'ghp_…'], ['Stripe live secret key', 6, 'sk_l…'],
      ['Credentials in connection URI', 2, 'post…'], ['Google API key', 7, 'AIza…'], ['High-entropy value (secret-like key)', 9, 'q7Zp…'],
      ['JSON Web Token', 8, 'eyJh…'], ['Hardcoded password', 10, 'hunt…'],
    ];
    for (const [name, line, preview] of expected) {
      const re = new RegExp(name.replace(/[()]/g, '\\$&') + '\\s+line ' + line + '\\s+' + preview.replace('…', '…'));
      assert(re.test(out), `missing ${name} on line ${line}`);
    }
    return '10 findings from the sample (4 critical, 3 high, 2 medium, 1 info), each on its line'; } },
  ghostprint: { url: '/tools/ghostprint/', async run(p) {
    await p.waitForTimeout(1000); const b = await p.$('button'); if (b) await b.click().catch(() => {});
    await p.waitForFunction(() => /\d+\s*(bits|%)/i.test(document.body.innerText), null, { timeout: 30000 }); return 'fingerprint scan produced a score'; } },
  netguard: { url: '/tools/netguard/', mock: { 'https://ipwho.is/': { ip: '203.0.113.7', city: 'Testville', country: 'Nowhere', latitude: 1.5, longitude: 2.5, connection: { isp: 'Example ISP' } } }, async run(p) {
    await p.click('#scanBtn');
    await p.waitForFunction(() => /Scan Again/.test(document.getElementById('scanBtn').textContent), null, { timeout: 30000 });
    const ip = (await p.textContent('#valIp')).trim(); assert(ip === '203.0.113.7', 'IP card shows ' + ip); return 'scan complete with mocked ipwho.is'; } },
  steganography: { url: '/tools/steganography/', async run(p, { tmp }) {
    const png = await p.evaluate(() => {
      const c = document.createElement('canvas'); c.width = 300; c.height = 200; const x = c.getContext('2d'); const d = x.createImageData(300, 200);
      for (let y = 0; y < 200; y++) for (let i = 0; i < 300; i++) { const o = (y * 300 + i) * 4; d.data[o] = (i * 7 + y) & 255; d.data[o + 1] = (y * 3) & 255; d.data[o + 2] = (i ^ y) & 255; d.data[o + 3] = i < 150 ? 255 : (i < 280 ? 128 + ((i + y) % 100) : 0); }
      x.putImageData(d, 0, 0); return c.toDataURL('image/png').split(',')[1];
    });
    const src = path.join(tmp, 'stego-src.png'); fs.writeFileSync(src, Buffer.from(png, 'base64'));
    await p.setInputFiles('#hideFileInput', src); await p.waitForTimeout(400);
    const msg = 'Ciao — 秘密のメッセージ 🔐 line1\nline2  ';
    await p.fill('#secretText', msg);
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#encodeBtn')]);
    const out = path.join(tmp, 'stego-out.png'); await dl.saveAs(out);
    await p.click('#tabReveal'); await p.setInputFiles('#revealFileInput', out); await p.waitForTimeout(400);
    await p.click('#decodeBtn'); await p.waitForTimeout(200);
    const got = await p.textContent('#revealedText');
    assert(got === msg, 'round-trip mismatch: ' + JSON.stringify(got)); return 'encode → download → decode round-trip exact'; } },
  'string-master': { url: '/tools/string-master/?lang=en', async run(p) {
    await p.fill('#text-input', 'Hello 👋🏽 world\nsecond line'); await p.dispatchEvent('#text-input', 'input');
    await p.waitForFunction(() => document.getElementById('stat-words').textContent === '5');
    const chars = (await p.textContent('#stat-chars')).trim(); assert(chars === '25', 'chars ' + chars); return 'words 5, graphemes 25 (emoji + skin tone = 1)'; } },
  'hash-generator': { url: '/en/tools/hash-generator/', async run(p) {
    await p.fill('#hash-input', 'abc'); await p.dispatchEvent('#hash-input', 'input');
    await p.waitForFunction(() => document.getElementById('hash-sha256').value.startsWith('ba7816bf'));
    const md5 = await p.inputValue('#hash-md5'); assert(md5 === '900150983cd24fb0d6963f7d28e17f72', 'md5 ' + md5);
    return 'MD5 + SHA-256 of "abc" match the test vectors'; } },
  'base64-converter': { url: '/it/tools/base64-converter/', async run(p) {
    await p.fill('#base64-input', 'Città ✓'); await p.click('button.tool-btn:not(.secondary)');
    const enc = await p.inputValue('#base64-output'); assert(enc === 'Q2l0dMOgIOKckw==', 'encoded ' + enc);
    await p.fill('#base64-input', 'Q2l0dMOgIOKckw'); await p.click('button.tool-btn.secondary >> nth=0');
    assert(await p.inputValue('#base64-output') === 'Città ✓', 'decode without padding'); return 'UTF-8 encode, decode without padding'; } },
  'caesar-cipher': { url: '/en/tools/caesar-cipher/', async run(p) {
    await p.fill('#caesar-input', 'Hello, World!'); await p.click('button.tool-btn:not(.secondary)');
    const out = await p.inputValue('#caesar-output'); assert(out === 'Khoor, Zruog!', 'shift 3 → ' + out); return 'shift 3: Hello, World! → Khoor, Zruog!'; } },
  'subnet-calculator': { url: '/tools/subnet-calculator/?lang=en', async run(p) {
    await p.waitForFunction(() => window.__subnetReady);
    const val = async (label) => p.evaluate((l) => { const dt = [...document.querySelectorAll('#v4out dt, #v6out dt')].find((d) => d.textContent === l); return dt && dt.nextElementSibling.textContent.trim(); }, label);
    await p.fill('#v4', '10.0.0.1/31'); assert((await val('Usable hosts')).startsWith('2'), '/31 usable'); assert((await val('Broadcast')) === 'none', '/31 broadcast');
    await p.fill('#v4', '172.16.5.4 0.0.15.255'); assert((await val('Network')) === '172.16.0.0', 'wildcard → /20 network');
    await p.click('#tab-v6'); await p.fill('#v6', '2001:0db8:0000:0000:0000:ff00:0042:8329/64');
    assert((await val('Compressed')).startsWith('2001:db8::ff00:42:8329'), 'RFC 5952');
    await p.click('#tab-split'); await p.check('input[name=smode][value=hosts]'); await p.fill('#sbase', '192.168.10.0/24'); await p.fill('#shosts', '20, 100, 2, 50');
    const nets = await p.$$eval('#sout tbody tr', (rs) => rs.map((r) => r.children[2].textContent));
    assert(nets.join(' ') === '192.168.10.192/27 192.168.10.0/25 192.168.10.224/31 192.168.10.128/26', 'VLSM ' + nets.join(' '));
    return '/31, wildcard input, IPv6 compression, VLSM plan'; } },
  'heic-converter': { url: '/tools/heic-converter/?lang=en', async run(p) {
    const grab = async () => { const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#files .file button')]); return fs.readFileSync(await dl.path()); };
    await p.setInputFiles('#file', HEIC);
    await p.waitForFunction(() => window.__heicDone >= 1, null, { timeout: 30000 });
    assert(!(await p.textContent('#files .meta')).match(/fail|Could not/i), 'decode failed: ' + (await p.textContent('#files .meta')));
    let jpg = await grab();
    assert(jpg[0] === 0xff && jpg[1] === 0xd8, 'not a JPEG');
    assert(!jpg.includes(Buffer.from('Exif\0\0')), 'stripped JPEG still has EXIF');
    await p.uncheck('#strip'); await p.waitForFunction(() => /kept/.test(document.querySelector('#files .meta').textContent));
    jpg = await grab();
    assert(jpg.includes(Buffer.from('Exif\0\0')), 'kept JPEG has no EXIF');
    await p.selectOption('#fmt', 'png'); await p.waitForFunction(() => /\.png$/.test(document.querySelector('#files .name').textContent));
    const png = await grab(); assert(png.subarray(1, 4).toString() === 'PNG', 'not a PNG');
    return 'HEIC → JPG without EXIF, with EXIF kept, and → PNG'; } },
  'pdf-merge-split': { url: '/tools/pdf-merge-split/?lang=en', async run(p) {
    await p.setInputFiles('#file', [path.join(FIXTURES, 'sample-a.pdf'), path.join(FIXTURES, 'sample-b.pdf')]);
    await p.waitForFunction(() => window.__pdfLoaded >= 1 && document.querySelectorAll('#tiles .tile').length === 5, null, { timeout: 30000 });
    await p.click('#tiles .tile:first-child .tile-btn:last-child'); // A1 one step right
    await p.click('#tiles .tile:nth-child(5) .tile-btn[title="Remove page"]'); // drop B3
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#merge')]);
    const merged = [...fs.readFileSync(await dl.path())];
    const texts = await p.evaluate(async (bytes) => {
      const { openForPreview } = await import('/js/tools/pdf-kit.mjs');
      const doc = await openForPreview(new Uint8Array(bytes));
      const out = [];
      for (let i = 1; i <= doc.numPages; i++) out.push((await (await doc.getPage(i)).getTextContent()).items.map((x) => x.str).join(''));
      return out;
    }, merged);
    assert(texts.join(',') === 'A2,A1,B1,B2', 'merged order ' + texts.join(','));
    await p.check('input[name=smode][value=ranges]'); await p.fill('#ranges', '1-2, 3-');
    const [z] = await Promise.all([p.waitForEvent('download'), p.click('#split')]);
    const parts = await p.evaluate(async (bytes) => {
      const { jsZip } = await import('/js/tools/pdf-kit.mjs'); const JSZip = await jsZip();
      const zip = await JSZip.loadAsync(new Uint8Array(bytes));
      return Object.keys(zip.files).sort();
    }, [...fs.readFileSync(await z.path())]);
    assert(parts.join(',') === 'sample-a-part-1.pdf,sample-a-part-2.pdf', 'zip ' + parts.join(','));
    return 'reorder + remove + merge (A2,A1,B1,B2), split by ranges into a ZIP of 2'; } },
  'images-to-pdf': { url: '/tools/images-to-pdf/?lang=en', async run(p, { tmp }) {
    const png = await p.evaluate(() => { const c = document.createElement('canvas'); c.width = 400; c.height = 200; const x = c.getContext('2d'); x.fillStyle = '#c00'; x.fillRect(0, 0, 400, 200); return c.toDataURL('image/png').split(',')[1]; });
    const pngPath = path.join(tmp, 'wide.png'); fs.writeFileSync(pngPath, Buffer.from(png, 'base64'));
    await p.setInputFiles('#file', [PHOTO, pngPath]);
    await p.waitForFunction(() => window.__imgLoaded === 2);
    await p.click('#tiles .tile:first-child .tile-btn[title="Rotate 90°"]');
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#make')]);
    const sizes = await p.evaluate(async (bytes) => {
      const { openForPreview } = await import('/js/tools/pdf-kit.mjs');
      const doc = await openForPreview(new Uint8Array(bytes)); const out = [];
      for (let i = 1; i <= doc.numPages; i++) { const v = (await doc.getPage(i)).getViewport({ scale: 1 }); out.push(Math.round(v.width) + 'x' + Math.round(v.height)); }
      return out;
    }, [...fs.readFileSync(await dl.path())]);
    // photo 480x360 rotated → portrait A4; 400x200 PNG → landscape A4
    assert(sizes.join(',') === '595x842,842x595', 'page sizes ' + sizes.join(','));
    const pdfBytes = fs.readFileSync(await dl.path());
    assert(!pdfBytes.includes(Buffer.from('FixtureCam')), 'EXIF camera make leaked into the PDF');
    return 'JPG + PNG → 2-page A4 PDF, rotation and auto orientation, no EXIF'; } },
  'json-formatter': { url: '/tools/json-formatter/?lang=en', async run(p) {
    await p.waitForFunction(() => window.__jsonReady);
    await p.fill('#in', '{\n  "b": 1,\n  "a": [1, 2,],\n}'); await p.click('#fmt');
    const err = await p.textContent('#status');
    assert(/^Line 3, column 14: trailing comma/.test(err), 'error message: ' + err);
    await p.fill('#in', '{"b":1,"a":{"d":[3,1],"c":"x"}}'); await p.check('#sort'); await p.click('#min');
    assert(await p.inputValue('#out') === '{"a":{"c":"x","d":[3,1]},"b":1}', 'sorted minify');
    await p.click('#toyaml'); await p.waitForFunction(() => document.getElementById('out').value.startsWith('a:'));
    await p.fill('#in', '[{"id":1,"tags":["x"]},{"id":2,"name":"Ada, L."}]'); await p.click('#tocsv');
    // a textarea reports CRLF as LF; the downloaded file keeps CRLF
    assert((await p.inputValue('#out')).replace(/\r\n/g, '\n') === 'id,tags,name\n1,"[""x""]",\n2,,"Ada, L."', 'csv ' + JSON.stringify(await p.inputValue('#out')));
    await p.click('#in-yaml'); await p.fill('#in', 'a: 1\nlist: [x, y]\n'); await p.uncheck('#sort'); await p.click('#fmt');
    assert(JSON.parse(await p.inputValue('#out')).list[1] === 'y', 'YAML → JSON');
    await p.click('#in-json');
    await p.evaluate(() => { document.getElementById('in').value = JSON.stringify(Array.from({ length: 60000 }, (_, i) => ({ id: i, name: 'item ' + i, tags: ['a', 'b'] }))); });
    await p.click('#fmt');
    await p.waitForFunction(() => document.getElementById('out').value.length > 2e6, null, { timeout: 30000 });
    assert(/^Valid JSON .*background worker/.test(await p.textContent('#status')), 'worker status: ' + await p.textContent('#status'));
    await p.click('#v-tree'); await p.waitForSelector('#tree details');
    return 'error at line:col, sorted minify, YAML both ways, CSV, 2+ MB via worker, tree view'; } },
  'text-diff': { url: '/tools/text-diff/?lang=en', viewport: { width: 1200, height: 900 }, async run(p) {
    await p.waitForFunction(() => window.__diffReady);
    const done = async (fn) => { const n = await p.evaluate(() => window.__diffDone || 0); await fn(); await p.waitForFunction((k) => (window.__diffDone || 0) > k, n); };
    await done(() => p.click('#sample'));
    assert(/^\+4 added · −3 removed · 14 unchanged lines$/.test((await p.textContent('#stats')).trim()), 'stats: ' + await p.textContent('#stats'));
    // word highlight inside the modified proxy_pass line, both sides
    const marks = await p.evaluate(() => [...document.querySelectorAll('.dt del, .dt ins')].map((e) => e.tagName + ':' + e.textContent));
    assert(marks.includes('DEL:3000') && marks.includes('INS:8080'), 'word marks: ' + marks.join(' | '));
    await p.selectOption('#gran', 'char');
    const cm = await p.evaluate(() => [...document.querySelectorAll('.dt del')].map((e) => e.textContent));
    assert(cm.length && !cm.includes('3000') && cm.includes('3'), 'char granularity: ' + cm.join(' | '));
    await p.click('#v-inline');
    assert(await p.locator('.dt.inline tr.add').count() === 4 && await p.locator('.dt.inline tr.del').count() === 3, 'inline rows');
    // ignore case / whitespace
    await p.fill('#a', 'Hello   World\nsame\n'); await done(() => p.fill('#b', 'hello World\nsame\n'));
    assert(/1 added · −1 removed/.test(await p.textContent('#stats')), 'before ignore');
    await p.check('#ws'); await done(() => p.check('#case'));
    assert((await p.textContent('#out')).includes('No differences with the current options'), 'ignored: ' + await p.textContent('#out'));
    // folding of long unchanged runs, then expanding
    await p.uncheck('#ws'); await p.uncheck('#case');
    const long = Array.from({ length: 60 }, (_, i) => 'row ' + i).join('\n');
    await p.fill('#a', long); await done(() => p.fill('#b', long.replace('row 30', 'row thirty')));
    const fold = p.locator('.fold button').first();
    assert(/^⋯ 27 unchanged lines — show$/.test(await fold.textContent()), 'fold label: ' + await fold.textContent());
    await fold.click();
    assert(await p.locator('.fold button').count() === 1, 'one fold left after expanding');
    // unified diff download applies back to the original
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#save-diff')]);
    const patch = fs.readFileSync(await dl.path(), 'utf8');
    assert(/^--- original\.txt\n\+\+\+ changed\.txt\n@@ -28,7 \+28,7 @@\n/.test(patch), 'patch header: ' + patch.slice(0, 80));
    const applied = await p.evaluate(([a, d]) => window.Diff.applyPatch(a, d), [long, patch]);
    assert(applied === long.replace('row 30', 'row thirty'), 'patch does not apply back');
    await p.click('#swap');
    assert(/^\+1 added · −1 removed/.test(await p.textContent('#stats')), 'swap');
    return 'sample stats, word/char marks, inline view, ignore ws+case, folding, .diff download applies, swap'; } },
  'security-headers': { url: '/tools/security-headers/?lang=en', async run(p, { origin }) {
    const external = [];
    p.on('request', (r) => { if (!r.url().startsWith(origin) && !r.url().startsWith('data:')) external.push(r.url()); });
    await p.waitForFunction(() => window.__headersReady);
    const done = async (fn) => { const n = await p.evaluate(() => window.__headersDone || 0); await fn(); await p.waitForFunction((k) => (window.__headersDone || 0) > k, n); };
    const ids = () => p.evaluate(() => [...document.querySelectorAll('.fd')].map((li) => li.dataset.id));
    // weak sample: grade F with the classic CSP mistakes, rendered with severities
    await done(() => p.click('#weak'));
    assert((await p.textContent('.grade')).trim() === 'F', 'weak grade ' + await p.textContent('.grade'));
    const weak = await ids();
    for (const id of ['csp-unsafe-inline', 'csp-scheme-source', 'csp-unsafe-eval', 'csp-bypass-host', 'hsts-short', 'cookie-no-secure', 'disclosure', 'xxss-enabled'])
      assert(weak.includes(id), 'weak sample misses ' + id + ': ' + weak.join(','));
    assert(await p.locator('.fd.s-high').first().locator('.pill').textContent() === 'High', 'severity pill');
    assert(await p.locator('.chip.r-high', { hasText: "'unsafe-inline'" }).count() === 1, 'risky source chip');
    // a weak CSP pasted on its own (typed, so the debounced input path runs)
    await p.fill('#in', '');
    await done(() => p.locator('#in').pressSequentially("script-src 'self' 'unsafe-inline' http://cdn.example.com self; img-src * data:", { delay: 2 }));
    assert((await p.textContent('#out')).includes('Analysing a Content-Security-Policy on its own'), 'CSP-only mode note');
    const csp = await ids();
    for (const id of ['csp-unsafe-inline', 'csp-http-source', 'csp-unquoted-keyword', 'csp-object-src', 'csp-base-uri-missing'])
      assert(csp.includes(id), 'CSP-only misses ' + id + ': ' + csp.join(','));
    assert(!csp.includes('hsts-missing'), 'header checks must not run in CSP-only mode');
    // strong sample: A+
    await done(() => p.click('#strong'));
    assert((await p.textContent('.grade')).trim() === 'A+', 'strong grade ' + await p.textContent('.grade'));
    assert(await p.locator('.fd.s-high, .fd.s-medium, .fd.s-low').count() === 0, 'strong sample has problems');
    // the report a user can paste into a ticket
    const report = await p.evaluate(async () => { let txt = ''; navigator.clipboard.writeText = async (s) => { txt = s; }; document.getElementById('copy-report').click(); await new Promise((r) => setTimeout(r, 50)); return txt; });
    assert(/^Security Headers & CSP Analyzer — Grade A\+ · Score 100\/100\n\n\[PASS\] /.test(report), 'report: ' + report.slice(0, 120));
    // localized messages
    await p.goto(origin + '/tools/security-headers/?lang=it'); await p.waitForFunction(() => window.__headersReady);
    await done(() => p.click('#weak'));
    assert((await p.textContent('.fd.s-high strong')).includes('in script-src') && (await p.textContent('#out')).includes('Manca Referrer-Policy'), 'Italian findings');
    assert(external.length === 0, 'external requests: ' + external.join(', '));
    return 'weak sample → F with CSP issues, CSP-only paste, strong sample → A+, copy report, Italian, no network'; } },
  'phishing-quiz': { url: '/tools/phishing-quiz/?lang=en', async run(p, { origin }) {
    const external = [];
    p.on('request', (r) => { if (!r.url().startsWith(origin) && !r.url().startsWith('data:')) external.push(r.url()); });
    await p.waitForFunction(() => window.__quizReady);
    let copied = '';
    await p.exposeFunction('__captureCopy', (s) => { copied = s; });
    await p.evaluate(() => { Object.defineProperty(navigator, 'share', { value: undefined }); navigator.clipboard.writeText = (s) => { window.__captureCopy(s); return Promise.resolve(); }; });
    await p.click('#start');
    const round = await p.evaluate(() => window.__quizRound());
    assert(round.length === 10 && new Set(round.map((s) => s.id)).size === 10, 'round of 10 distinct scenarios');
    // question 1 with the keyboard only: from the focused heading, Tab to the right answer button and press Enter
    assert(await p.evaluate(() => document.activeElement.id) === 'q-heading', 'focus starts on the question heading');
    const target = round[0].phish ? 'a-phish' : 'a-legit';
    for (let i = 0; i < 12 && (await p.evaluate(() => document.activeElement.id)) !== target; i++) await p.keyboard.press('Tab');
    assert(await p.evaluate(() => document.activeElement.id) === target, 'answer button reachable with Tab');
    await p.keyboard.press('Enter');
    assert(await p.evaluate(() => document.activeElement.id) === 'verdict', 'focus moves to the verdict');
    assert((await p.textContent('#verdict')).trim() === 'Correct!', 'keyboard answer counted');
    const hl = await p.locator('#mockup .hl').count();
    assert(hl > 0 && hl === await p.locator('#flags li').count(), `red flags highlighted (${hl}) and explained`);
    await p.keyboard.press('Tab'); assert(await p.evaluate(() => document.activeElement.id) === 'next', 'Tab reaches Next');
    await p.keyboard.press('Enter');
    // the rest with the mouse: all right except question 6
    for (let i = 1; i < 10; i++) {
      const right = round[i].phish ? '#a-phish' : '#a-legit', wrong = round[i].phish ? '#a-legit' : '#a-phish';
      await p.click(i === 5 ? wrong : right);
      assert(await p.locator('#mockup .hl').count() > 0, `highlights on question ${i + 1}`);
      await p.click('#next');
    }
    assert((await p.textContent('#score')).trim() === '9/10', 'score ' + await p.textContent('#score'));
    assert(/Phish hunter/.test(await p.textContent('#rank')), 'rank for 9/10');
    const review = await p.locator('#review li').count();
    assert(review >= 1, 'topics to review for the missed question');
    assert(await p.locator('#review a[target=_top]').first().getAttribute('href').then((h) => /^\/en\/tools\/[a-z-]+\/$/.test(h)), 'review links to a tool');
    await p.click('#share');
    await p.waitForFunction(() => !document.getElementById('share-status').hidden);
    assert(copied === 'I scored 9/10 on the Phishing Quiz. Can you spot the phish? https://federicosella.com/en/tools/phishing-quiz/score/9/', 'share text: ' + copied);
    // the share page: own card, noindex, forwards to the quiz with ?score=
    const share = await (await fetch(origin + '/en/tools/phishing-quiz/score/9/')).text();
    const img = share.match(/og:image" content="https:\/\/federicosella\.com([^"]+)"/)[1];
    assert(img === '/og/en/tools/phishing-quiz-score-9.png' && (await fetch(origin + img)).ok, 'score card ' + img);
    assert(/noindex/.test(share) && /url=\/en\/tools\/phishing-quiz\/\?score=9/.test(share), 'share page meta');
    // the quiz app itself makes no request (the host page loaded next has the site's ad and analytics scripts)
    assert(external.length === 0, 'external requests from the quiz: ' + external.join(', '));
    await p.goto(origin + '/en/tools/phishing-quiz/?score=9');
    const f = p.frameLocator('iframe.tool-iframe');
    await f.locator('#challenge').waitFor({ state: 'visible' });
    assert(/scored 9\/10/.test(await f.locator('#challenge').textContent()), 'challenge banner');
    return 'keyboard-only answer, highlights + explanations, 9/10 scoring and rank, topics to review, share text, score page card + challenge banner, no network'; } },
  'phishing-quiz-it': { url: '/tools/phishing-quiz/?lang=it', async run(p) {
    await p.waitForFunction(() => window.__quizReady);
    await p.click('#start');
    assert(/Domanda 1 di 10/.test(await p.textContent('#q-heading')), 'Italian UI');
    const id = (await p.evaluate(() => window.__quizRound()))[0].id;
    const ctx = await p.textContent('#ctx');
    const it = (await p.evaluate(async (k) => (await import('/js/tools/phish/it.mjs')).default[k].ctx, id));
    assert(ctx === it, 'scenario text is Italian');
    return 'scenarios localized (Italian)'; } },
  'screenshot-redactor': { url: '/tools/screenshot-redactor/?lang=en', async run(p, { tmp }) {
    await p.waitForFunction(() => window.__redactReady);
    // a synthetic screenshot with sensitive text (reserved domain, ISO example IBAN, documentation IP)
    const png = await p.evaluate(() => {
      const c = Object.assign(document.createElement('canvas'), { width: 900, height: 300 });
      const x = c.getContext('2d'); x.fillStyle = '#fff'; x.fillRect(0, 0, 900, 300); x.fillStyle = '#111'; x.font = '28px Arial, sans-serif';
      x.fillText('Contact: alex.rivera@example.com', 30, 60);
      x.fillText('IBAN: GB82 WEST 1234 5698 7654 32', 30, 130);
      x.fillText('Server IP: 192.0.2.44', 30, 200);
      x.fillText('Nothing secret on this line', 30, 270);
      return c.toDataURL('image/png').split(',')[1];
    });
    const file = path.join(tmp, 'shot.png'); fs.writeFileSync(file, Buffer.from(png, 'base64'));
    await p.setInputFiles('#file', file);
    await p.waitForFunction(() => window.__redactLoaded === 1);
    // draw one box with the mouse (top-left corner of the image)
    const box = await p.locator('#canvas').boundingBox();
    const zoom = await p.evaluate(() => document.getElementById('canvas').width / 900);
    await p.mouse.move(box.x + 5 * zoom, box.y + 5 * zoom); await p.mouse.down();
    await p.mouse.move(box.x + 120 * zoom, box.y + 40 * zoom, { steps: 4 }); await p.mouse.up();
    assert(await p.evaluate(() => window.__redactCount()) === 1, 'box drawn');
    // a touch drag (pointer events with pointerType touch) draws a second box
    const pe = (type, x, y) => p.locator('#canvas').dispatchEvent(type, { pointerId: 7, pointerType: 'touch', isPrimary: true, clientX: box.x + x * zoom, clientY: box.y + y * zoom });
    await pe('pointerdown', 700, 200); await pe('pointermove', 850, 280); await pe('pointerup', 850, 280);
    assert(await p.evaluate(() => window.__redactCount()) === 2, 'touch drag draws a box');
    await p.click('#undo'); assert(await p.evaluate(() => window.__redactCount()) === 1, 'undo touch box');
    await p.click('#undo'); assert(await p.evaluate(() => window.__redactCount()) === 0, 'undo');
    await p.click('#redo'); assert(await p.evaluate(() => window.__redactCount()) === 1, 'redo');
    // soft modes show the warning
    await p.click('[data-mode=pixelate]'); assert(await p.isVisible('#warn'), 'warning for pixelate');
    await p.click('[data-mode=box]'); assert(!(await p.isVisible('#warn')), 'no warning for solid box');
    // real OCR (self-hosted Tesseract, opt-in) suggests the email, IBAN and IP
    await p.click('#ocr');
    await p.waitForFunction(() => window.__redactSuggestions, null, { timeout: 120000 });
    const sugg = await p.evaluate(() => window.__redactSuggestions);
    assert(JSON.stringify(sugg.map((s) => s.type)) === '["email","iban","ip"]', 'OCR suggestions ' + JSON.stringify(sugg));
    await p.click('#apply-all');
    assert(await p.evaluate(() => window.__redactCount()) === 4, 'suggestions applied as solid boxes');
    // PNG export: redactions burned in (black where the email was), no metadata chunks
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#download')]);
    assert(dl.suggestedFilename() === 'shot-redacted.png', 'file name ' + dl.suggestedFilename());
    const out = PNG.sync.read(fs.readFileSync(await dl.path()));
    const at = (x, y) => [...out.data.slice((y * out.width + x) * 4, (y * out.width + x) * 4 + 3)];
    assert(at(300, 50).join() === '0,0,0' && at(60, 20).join() === '0,0,0', 'redacted pixels are black: ' + at(300, 50));
    assert(at(600, 280).join() === '255,255,255', 'untouched area unchanged');
    const raw = fs.readFileSync(await dl.path()).toString('latin1');
    assert(!/tEXt|iTXt|zTXt|eXIf/.test(raw), 'PNG has metadata chunks');
    // JPEG export of a photo with EXIF + GPS: the output has no EXIF at all
    await p.click('#new');
    await p.setInputFiles('#file', PHOTO);
    await p.waitForFunction(() => window.__redactLoaded === 2);
    await p.selectOption('#fmt', 'jpeg');
    const [dj] = await Promise.all([p.waitForEvent('download'), p.click('#download')]);
    const jpg = fs.readFileSync(await dj.path());
    assert(jpg[0] === 0xff && jpg[1] === 0xd8, 'not a JPEG');
    assert(!jpg.includes(Buffer.from('Exif')) && !jpg.includes(Buffer.from('FixtureCam')), 'JPEG still has EXIF');
    return 'draw + undo/redo, blur/pixelate warning, real OCR suggests email/IBAN/IP, burned-in PNG without metadata, EXIF/GPS dropped from JPEG'; } },
  'email-header-analyzer': { url: '/tools/email-header-analyzer/?lang=en', async run(p, { origin }) {
    const external = [];
    p.on('request', (r) => { if (!r.url().startsWith(origin) && !r.url().startsWith('data:')) external.push(r.url()); });
    await p.waitForFunction(() => window.__emailReady);
    await p.click('#s-phish');
    await p.waitForSelector('.verdict-box');
    assert(await p.locator('.verdict-box.v-danger').count() === 1, 'phishing sample → danger verdict');
    const sigs = await p.$$eval('.sig', (els) => els.map((e) => e.dataset.id));
    for (const id of ['display-name-address', 'reply-to-mismatch', 'spf-fail', 'dmarc-fail']) assert(sigs.includes(id), 'signal ' + id + ' in ' + sigs);
    assert(await p.locator('.sig.s-high').first().isVisible(), 'high-severity signal shown');
    assert(!/\{\w+\}/.test(await p.textContent('#out')), 'no unfilled placeholders');
    const hops = await p.locator('.hop').count();
    assert(hops >= 2, 'hop timeline rendered: ' + hops);
    assert(/after /.test(await p.locator('.hop').nth(1).textContent()), 'delay shown on the second hop');
    // paste a fixture by typing into the box: the input handler re-analyses
    const legit = fs.readFileSync(path.join('tests/fixtures/email-headers/legit-esp.txt'), 'utf8');
    await p.fill('#in', legit);
    await p.waitForSelector('.verdict-box.v-ok');
    assert(await p.locator('.hop').count() === 3, 'three hops for the legit fixture');
    await p.click('#clear');
    assert(await p.locator('.verdict-box').count() === 0, 'cleared');
    await p.goto(origin + '/tools/email-header-analyzer/?lang=de');
    await p.waitForFunction(() => window.__emailReady);
    await p.click('#s-phish');
    await p.waitForSelector('.verdict-box');
    assert(/Wahrscheinlich gefälscht/.test(await p.textContent('.verdict-box')), 'German verdict');
    assert(/Weg \(/.test(await p.textContent('#out')), 'German route heading');
    assert(external.length === 0, 'external requests: ' + external.join(', '));
    return 'phishing sample → danger with spoofing signals + hop delays, pasted fixture → ok with 3 hops, clear, German UI, no network'; } },
  'spf-dmarc-checker': { url: '/tools/spf-dmarc-checker/?lang=en&domain=badmail.test', async run(p, { origin, context }) {
    // DNS-over-HTTPS is mocked from the offline fixtures used by the unit tests
    const Z = JSON.parse(fs.readFileSync('tests/fixtures/mail-auth/zones.json', 'utf8'));
    const { generateKeyPairSync } = await import('node:crypto');
    const key = generateKeyPairSync('rsa', { modulusLength: 1024 }).publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
    const zone = Object.assign({}, Z.good, Z.bad);
    const TYPES = { TXT: 16, MX: 15 };
    const doh = [], external = [];
    p.on('request', (r) => { const u = r.url(); if (!u.startsWith(origin) && !u.startsWith('data:') && !u.startsWith('https://cloudflare-dns.com/dns-query')) external.push(u); });
    await context.route('https://cloudflare-dns.com/dns-query*', (r) => {
      const u = new URL(r.request().url());
      doh.push({ name: u.searchParams.get('name'), type: u.searchParams.get('type'), accept: r.request().headers().accept });
      const v = zone[u.searchParams.get('name') + '|' + u.searchParams.get('type')];
      const Answer = (v || []).map((s) => ({ name: u.searchParams.get('name'), type: TYPES[u.searchParams.get('type')], TTL: 300, data: u.searchParams.get('type') === 'TXT' ? '"' + s.replace(/\{\{RSA\d+\}\}/g, key).replace(/"/g, '\\"') + '"' : s }));
      return r.fulfill({ json: { Status: v ? 0 : 3, Answer }, headers: { 'access-control-allow-origin': '*' } });
    });
    await p.waitForFunction(() => window.__mailReady);
    assert(await p.inputValue('#domain') === 'badmail.test', '?domain= pre-fills the box');
    await p.waitForTimeout(400);
    assert(doh.length === 0, 'no DNS query before Check: ' + doh.length);
    assert(/cloudflare-dns\.com/.test(await p.textContent('#privacy')), 'resolver disclosed on the tool');
    await p.fill('#sel', 's1, old');
    await p.click('#go');
    await p.waitForSelector('.summary');
    assert((await p.textContent('.letter')).trim() === 'F', 'broken domain → F');
    assert(doh.every((d) => d.accept === 'application/dns-json'), 'dns-json accept header');
    const ids = await p.$$eval('.sig', (els) => els.map((e) => e.dataset.id));
    for (const id of ['spf-too-many', 'spf-plus-all', 'spf-ptr', 'spf-include-missing', 'dmarc-pct', 'dkim-1024', 'dkim-revoked']) assert(ids.includes(id), id + ' in ' + ids);
    assert(/24 of 10/.test(await p.textContent('[data-area="spf"]')), 'lookup count shown');
    assert(await p.locator('.tree li').count() > 5, 'include tree');
    assert(!/\{\w+\}/.test(await p.textContent('#out')), 'no unfilled placeholders');
    assert(await p.locator('.fix').count() >= 4, 'fixes listed');
    const clip = await p.evaluate(async () => { let txt = ''; navigator.clipboard.writeText = async (s) => { txt = s; }; document.querySelector('.fix [data-copy]').click(); await new Promise((r) => setTimeout(r, 50)); return txt; });
    assert(/^(v=spf1 |v=DMARC1)/.test(clip), 'copy example record: ' + JSON.stringify(clip.slice(0, 60)));
    assert((await p.textContent('.fix [data-copy]')) === 'Copied', 'copy button feedback');
    // a good domain, auto-selectors
    await p.fill('#domain', 'alex@GoodMail.example'); await p.fill('#sel', '');
    await p.click('#go');
    await p.waitForFunction(() => document.querySelector('.summary h2')?.textContent.includes('goodmail.example'));
    assert((await p.textContent('.letter')).trim() === 'A', 'good domain → A');
    assert(doh.some((d) => d.name === 'selector1._domainkey.goodmail.example'), 'common selectors tried');
    await p.fill('#domain', 'not a domain'); await p.click('#go');
    assert(await p.locator('.tb-note--warn').count() === 1, 'invalid input message');
    await p.goto(origin + '/tools/spf-dmarc-checker/?lang=it');
    await p.waitForFunction(() => window.__mailReady);
    await p.fill('#domain', 'goodmail.example'); await p.click('#go');
    await p.waitForSelector('.summary');
    assert(/Risultati per goodmail\.example/.test(await p.textContent('.summary')), 'Italian UI');
    await context.unroute('https://cloudflare-dns.com/dns-query*');
    assert(external.length === 0, 'other external requests: ' + external.join(', '));
    return `no query before Check, ${doh.length} mocked DoH queries with dns-json, broken domain → F (24/10 lookups, tree, fixes, copy), good domain → A with guessed selectors, invalid input, Italian`; } },
  'encrypted-message': { url: '/tools/encrypted-message/?lang=en', async run(p, { origin }) {
    const requests = [];
    p.on('request', (r) => requests.push(r.url()));
    await p.waitForFunction(() => window.__msgReady);
    const MSG = 'Door code 4711 🔑 — façade ½';
    await p.fill('#message', MSG);
    await p.click('#encrypt');
    assert(/Enter or generate/.test(await p.textContent('#c-err')), 'passphrase required');
    await p.click('#gen');
    const pass = await p.inputValue('#pass');
    assert(/^([A-Za-z2-9]{4}-){4}[A-Za-z2-9]{4}$/.test(pass), 'generated passphrase ' + pass);
    await p.click('#encrypt');
    await p.waitForSelector('#result:not([hidden])');
    const link = await p.inputValue('#link');
    assert(link.startsWith(origin + '/tools/encrypted-message/#v1.'), 'link targets the standalone page with a #fragment: ' + link.slice(0, 80));
    assert(!link.includes('4711') && !link.includes(encodeURIComponent('🔑')), 'plaintext not in the link');
    assert(await p.isHidden('#long'), 'no length warning for a short message');
    const token = link.split('#')[1];
    // open the link: the fragment must never appear in any request URL
    await p.goto(link);
    await p.waitForFunction(() => window.__msgReady);
    assert(await p.isVisible('#open') && await p.isHidden('#compose'), 'open mode');
    assert(!p.url().includes('#'), 'fragment removed from the address bar: ' + p.url());
    await p.fill('#opass', pass + 'x');
    await p.click('#decrypt');
    await p.waitForSelector('#o-err:not([hidden])');
    assert(/passphrase is wrong/.test(await p.textContent('#o-err')), 'wrong passphrase message');
    await p.fill('#opass', pass);
    await p.click('#decrypt');
    await p.waitForSelector('#plain:not([hidden])');
    assert((await p.textContent('#msg')) === MSG, 'decrypted message round-trips Unicode');
    // a tampered link (one character of the ciphertext changed) fails on the tag
    const i = token.length - 30;
    const bad = token.slice(0, i) + (token[i] === 'A' ? 'B' : 'A') + token.slice(i + 1);
    await p.goto(origin + '/tools/encrypted-message/#' + bad);
    await p.waitForFunction(() => window.__msgReady);
    await p.fill('#opass', pass); await p.click('#decrypt');
    await p.waitForSelector('#o-err:not([hidden])');
    assert(/changed or cut off/.test(await p.textContent('#o-err')), 'tampered link rejected');
    await p.goto(origin + '/tools/encrypted-message/#v1.abc');
    await p.waitForFunction(() => window.__msgReady);
    await p.fill('#opass', 'whatever'); await p.click('#decrypt');
    await p.waitForSelector('#o-err:not([hidden])');
    assert(/incomplete/.test(await p.textContent('#o-err')), 'truncated link message');
    // a long message warns about link length
    await p.goto(origin + '/tools/encrypted-message/?lang=it');
    await p.waitForFunction(() => window.__msgReady);
    await p.fill('#message', 'x'.repeat(1600)); await p.fill('#pass', 'una passphrase lunga');
    await p.click('#encrypt');
    await p.waitForSelector('#result:not([hidden])');
    assert(await p.isVisible('#long') && /circa 2\.000 caratteri/.test(await p.textContent('#long')), 'Italian long-link warning');
    assert(requests.every((u) => u.startsWith(origin) && !u.includes('#') && !u.includes(token.slice(3, 40))), 'no external request and no token in any request: ' + requests.filter((u) => !u.startsWith(origin)).join(', '));
    return 'passphrase required + generator, link to standalone page with #fragment only, fragment stripped and never requested, wrong passphrase / tampered / truncated rejected, Unicode round trip, long-link warning (Italian), no network'; } },
  search: { url: '/en/', async run(p) {
    await p.keyboard.press('Control+k'); await p.fill('#search-input', 'password');
    await p.waitForSelector('#search-results li', { timeout: 10000 }); return 'palette returns results for "password"'; } },
  'header-mobile': { url: '/it/learn/', viewport: { width: 390, height: 844 }, async run(p) {
    const h = await p.evaluate(() => document.getElementById('site-header').getBoundingClientRect().height);
    assert(h <= 56, 'header is ' + h + 'px tall');
    assert(!(await p.isVisible('#site-nav')), 'nav visible before opening the menu');
    await p.click('.nav-toggle'); assert(await p.isVisible('#site-nav a[aria-current]'), 'menu did not open / no current item');
    await p.keyboard.press('Escape'); assert(!(await p.isVisible('#site-nav')), 'Escape did not close the menu');
    await p.click('.lang-menu summary'); await p.click('.lang-list a[hreflang=de]');
    await p.waitForURL(/\/de\/learn\/$/); return `header ${h}px, menu opens/closes, language switch → /de/learn/`; } },
  'header-search': { url: '/en/tools/', async run(p) {
    await p.click('.site-header [data-search-trigger]'); await p.fill('#search-input', 'exif');
    await p.waitForSelector('#search-results li'); const label = await p.textContent('#search-results .search-result-section');
    assert(['Tool', 'Guide'].includes(label.trim()), 'result label ' + label); return 'header search button opens the palette; results labelled by type'; } },
  'code-copy': { url: '/it/learn/cheatsheets/nmap-network-scanning/', async run(p, { context }) {
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    const btn = p.locator('.code-copy').first(); await btn.click();
    await p.waitForFunction(() => document.querySelector('.code-copy').textContent.includes('Copiato'), null, { timeout: 3000 });
    const clip = await p.evaluate(() => navigator.clipboard.readText());
    assert(clip.startsWith('# ') && !clip.includes('Copia'), 'clipboard: ' + clip.slice(0, 40)); return 'localized Copy → Copiato, code on the clipboard'; } },
  'back-to-top': { url: '/en/learn/guides/osint-privacy-exif-data/', viewport: { width: 390, height: 844 }, async run(p) {
    assert(!(await p.isVisible('#top-link')), 'visible at the top of the page');
    await p.evaluate(() => window.scrollTo(0, innerHeight * 0.5)); await p.waitForTimeout(300);
    assert(!(await p.isVisible('#top-link')), 'visible before 1.5 viewports');
    let seen = false;
    for (let y = innerHeightGuess(); y < 9000 && !seen; y += 300) { await p.evaluate((yy) => window.scrollTo(0, yy), y); await p.waitForTimeout(150); seen = await p.isVisible('#top-link'); }
    assert(seen, 'never shown'); await p.click('#top-link'); await p.waitForFunction(() => scrollY === 0);
    return 'appears after 1.5 viewports, scrolls back to the top'; } },
  'search-deeplink': { url: '/it/?q=password', async run(p) {
    await p.waitForSelector('#search-results li', { timeout: 10000 }); return '?q= opens the palette with results'; } },
};

const { origin, close } = await serve('public');
const tmp = fs.mkdtempSync(path.join(fs.realpathSync(process.env.TEMP || process.env.TMPDIR || '/tmp'), 'fs-functional-'));
const browser = await chromium.launch();
let fails = 0;
for (const [name, t] of Object.entries(TESTS)) {
  if (only && !only.includes(name)) continue;
  const context = await browser.newContext({ acceptDownloads: true, viewport: t.viewport || { width: 1280, height: 900 }, isMobile: !!t.viewport, hasTouch: !!t.viewport });
  await blockExternal(context, origin);
  // registered after the block-all route, so these win (Playwright tries the newest route first)
  for (const [url, body] of Object.entries(t.mock || {})) await context.route(url, (r) => r.fulfill({ json: body, headers: { 'access-control-allow-origin': '*' } }));
  const page = await context.newPage();
  const errs = [];
  page.on('pageerror', (e) => errs.push(String(e).slice(0, 160)));
  page.on('console', (m) => { if (m.type() === 'error' && !BLOCKED_NOISE.test(m.text())) errs.push('console: ' + m.text().slice(0, 160)); });
  let res;
  try { await page.goto(origin + t.url, { waitUntil: 'load' }); res = await t.run(page, { origin, tmp, context }); }
  catch (e) { res = 'FAIL ' + e.message.split('\n')[0].slice(0, 200); }
  const bad = res.startsWith('FAIL') || errs.length;
  if (bad) fails++;
  console.log(`${bad ? 'X ' : 'OK'} ${name}: ${res}${errs.length ? ' | JS errors: ' + JSON.stringify(errs) : ''}`);
  await context.close();
}
await browser.close();
await close();
fs.rmSync(tmp, { recursive: true, force: true });
console.log(fails ? `FAILURES: ${fails}` : 'all functional checks passed');
process.exitCode = fails ? 1 : 0;

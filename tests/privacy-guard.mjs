// Source-tree privacy guard, run before `hugo` (CI) and in `npm test`. Fails when
//   1. a tracked (or new, not ignored) file outside static/vendor/ contains the owner's old home town or
//      personal mailbox (patterns assembled from fragments so this file never matches), or
//   2. an image under static/, assets/ or content/ carries EXIF GPS data
//      (a GPS IFD pointer in its EXIF block, or GPS fields in an XMP packet).
// No dependencies: needs only Node and git.
//   node tests/privacy-guard.mjs
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';

const FORBIDDEN = new RegExp([['sui', 'sio'], ['fedesella', '95@', 'gmail']].map((p) => p.join('')).join('|'), 'i');
const IMAGE_ROOTS = ['static/', 'assets/', 'content/'];
const IMAGE_EXT = /\.(jpe?g|png|webp|gif|avif|heic|heif|tiff?)$/i;

const files = execFileSync('git', ['ls-files', '-z', '--cached', '--others', '--exclude-standard'], { encoding: 'utf8', maxBuffer: 64 << 20 }).split('\0').filter(Boolean);
const problems = [];

/* ── 1. forbidden personal strings ── */
for (const f of files) {
  if (f.startsWith('static/vendor/')) continue;
  let buf;
  try { buf = fs.readFileSync(f); } catch { continue; } // deleted in the working tree
  // latin1 keeps a 1:1 byte mapping, so binary files are searched too
  const m = buf.toString('latin1').match(FORBIDDEN);
  if (m) {
    const line = buf.toString('latin1').slice(0, m.index).split('\n').length;
    problems.push(`${f}:${line}: personal string`);
  }
}

/* ── 2. EXIF GPS in published images ── */

/** Does this TIFF (EXIF payload) have a GPS IFD pointer in IFD0? */
function tiffHasGps(b, o) {
  if (o + 8 > b.length) return false;
  const le = b[o] === 0x49 && b[o + 1] === 0x49;
  if (!le && !(b[o] === 0x4d && b[o + 1] === 0x4d)) return false;
  const u16 = (p) => (le ? b.readUInt16LE(p) : b.readUInt16BE(p));
  const u32 = (p) => (le ? b.readUInt32LE(p) : b.readUInt32BE(p));
  const ifd = o + u32(o + 4);
  if (ifd + 2 > b.length) return false;
  const n = u16(ifd);
  for (let i = 0; i < n; i++) {
    const e = ifd + 2 + i * 12;
    if (e + 12 > b.length) break;
    if (u16(e) === 0x8825) return true; // GPSInfo
  }
  return false;
}

/** Offsets of every EXIF/TIFF payload in the file, whatever the container. */
function exifPayloads(b) {
  const out = [];
  if (b[0] === 0xff && b[1] === 0xd8) {                                   // JPEG: APP1 "Exif\0\0"
    let i = 2;
    while (i + 4 <= b.length && b[i] === 0xff) {
      const m = b[i + 1]; if (m === 0xda || m === 0xd9) break;
      const len = b.readUInt16BE(i + 2);
      if (m === 0xe1 && b.toString('latin1', i + 4, i + 10) === 'Exif\0\0') out.push(i + 10);
      i += 2 + len;
    }
  } else if (b.toString('latin1', 1, 4) === 'PNG') {                       // PNG: eXIf chunk
    let i = 8;
    while (i + 8 <= b.length) {
      const len = b.readUInt32BE(i), type = b.toString('latin1', i + 4, i + 8);
      if (type === 'eXIf') out.push(i + 8);
      i += 12 + len;
    }
  } else if (b.toString('latin1', 0, 4) === 'RIFF' && b.toString('latin1', 8, 12) === 'WEBP') { // WebP: EXIF chunk
    let i = 12;
    while (i + 8 <= b.length) {
      const type = b.toString('latin1', i, i + 4), len = b.readUInt32LE(i + 4);
      if (type === 'EXIF') out.push(b.toString('latin1', i + 8, i + 14) === 'Exif\0\0' ? i + 14 : i + 8);
      i += 8 + len + (len & 1);
    }
  } else {                                                                  // HEIF/AVIF/TIFF/other: look for the marker
    if ((b[0] === 0x49 && b[1] === 0x49) || (b[0] === 0x4d && b[1] === 0x4d)) out.push(0);
    for (let i = b.indexOf('Exif\0\0', 0, 'latin1'); i >= 0; i = b.indexOf('Exif\0\0', i + 6, 'latin1')) out.push(i + 6);
  }
  return out;
}

let images = 0;
for (const f of files) {
  if (!IMAGE_ROOTS.some((r) => f.startsWith(r)) || f.startsWith('static/vendor/') || !IMAGE_EXT.test(f)) continue;
  let b;
  try { b = fs.readFileSync(f); } catch { continue; }
  images++;
  if (exifPayloads(b).some((o) => tiffHasGps(b, o))) problems.push(`${f}: EXIF GPS data`);
  if (/exif:GPS(Latitude|Longitude)|<exif:GPS/i.test(b.toString('latin1'))) problems.push(`${f}: GPS in XMP`);
}

console.log(`privacy guard: ${files.length} tracked files, ${images} images checked, ${problems.length} problems`);
for (const p of problems) console.log('  ' + p);
process.exit(problems.length ? 1 : 0);

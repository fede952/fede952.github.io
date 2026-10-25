// Metadata helpers for /tools/heic-converter/ (no dependencies; unit-tested
// in tests/unit/heic.test.mjs). The pixels are decoded by libheif; these
// functions only move the EXIF block when the user chooses to keep it.

const u32 = (b, o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
const u16 = (b, o) => (b[o] << 8) | b[o + 1];
const readN = (b, o, n) => { let v = 0; for (let i = 0; i < n; i++) v = v * 256 + b[o + i]; return v; };
const fourcc = (b, o) => String.fromCharCode(b[o], b[o + 1], b[o + 2], b[o + 3]);

/** ISOBMFF boxes in [start, end): [{ type, start, header, end }]. */
function boxes(b, start, end) {
  const out = [];
  let o = start;
  while (o + 8 <= end) {
    let size = u32(b, o);
    const type = fourcc(b, o + 4);
    let header = 8;
    if (size === 1) { size = readN(b, o + 8, 8); header = 16; }
    else if (size === 0) size = end - o;
    if (size < header || o + size > end) break;
    out.push({ type, start: o, header, end: o + size });
    o += size;
  }
  return out;
}

/** True when the file starts like a HEIF/HEIC/AVIF container (ftyp box). */
export function isHeif(b) {
  if (b.length < 12 || fourcc(b, 4) !== 'ftyp') return false;
  const brand = fourcc(b, 8);
  return ['heic', 'heix', 'hevc', 'hevx', 'heim', 'heis', 'mif1', 'msf1'].includes(brand);
}

/**
 * The EXIF payload of a HEIF file as a TIFF block ("II*\0" / "MM\0*" …),
 * or null. Follows meta → iinf (item of type "Exif") → iloc (its extents).
 */
export function extractExif(b) {
  const meta = boxes(b, 0, b.length).find((x) => x.type === 'meta');
  if (!meta) return null;
  const kids = boxes(b, meta.start + meta.header + 4, meta.end); // meta is a FullBox
  const iinf = kids.find((x) => x.type === 'iinf');
  const iloc = kids.find((x) => x.type === 'iloc');
  const idat = kids.find((x) => x.type === 'idat');
  if (!iinf || !iloc) return null;

  // iinf: find the item_ID of the Exif item
  let o = iinf.start + iinf.header;
  const iinfVer = b[o];
  o += 4 + (iinfVer === 0 ? 2 : 4);
  let exifId = null;
  for (const infe of boxes(b, o, iinf.end)) {
    if (infe.type !== 'infe') continue;
    const p = infe.start + infe.header;
    const v = b[p];
    if (v < 2) continue;
    const id = v === 2 ? u16(b, p + 4) : u32(b, p + 4);
    const typeAt = p + 4 + (v === 2 ? 2 : 4) + 2;
    if (fourcc(b, typeAt) === 'Exif') { exifId = id; break; }
  }
  if (exifId === null) return null;

  // iloc: extents of that item
  o = iloc.start + iloc.header;
  const v = b[o]; o += 4;
  const offSize = b[o] >> 4, lenSize = b[o] & 15, baseSize = b[o + 1] >> 4, idxSize = v >= 1 ? b[o + 1] & 15 : 0;
  o += 2;
  const count = v < 2 ? u16(b, o) : u32(b, o); o += v < 2 ? 2 : 4;
  for (let i = 0; i < count; i++) {
    const id = v < 2 ? u16(b, o) : u32(b, o); o += v < 2 ? 2 : 4;
    let method = 0;
    if (v >= 1) { method = u16(b, o) & 15; o += 2; }
    o += 2; // data_reference_index
    const base = readN(b, o, baseSize); o += baseSize;
    const extents = u16(b, o); o += 2;
    const parts = [];
    for (let e = 0; e < extents; e++) {
      o += idxSize;
      const eo = readN(b, o, offSize); o += offSize;
      const el = readN(b, o, lenSize); o += lenSize;
      parts.push([base + eo, el]);
    }
    if (id !== exifId) continue;
    const origin = method === 1 && idat ? idat.start + idat.header : 0;
    const chunks = parts.map(([off, len]) => b.subarray(origin + off, origin + off + len));
    const data = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
    let at = 0; for (const c of chunks) { data.set(c, at); at += c.length; }
    if (data.length < 8) return null;
    const tiff = data.subarray(4 + u32(data, 0)); // exif_tiff_header_offset
    const bo = String.fromCharCode(tiff[0], tiff[1]);
    return bo === 'II' || bo === 'MM' ? new Uint8Array(tiff) : null;
  }
  return null;
}

/**
 * Sets the IFD0 Orientation tag (0x0112) to 1 in place. The decoder has
 * already applied the HEIF rotation to the pixels; keeping the old value
 * would make viewers rotate the picture a second time.
 */
export function resetOrientation(tiff) {
  const le = tiff[0] === 0x49;
  const r16 = (o) => (le ? tiff[o] | (tiff[o + 1] << 8) : (tiff[o] << 8) | tiff[o + 1]);
  const r32 = (o) => (le ? (tiff[o] | (tiff[o + 1] << 8) | (tiff[o + 2] << 16) | (tiff[o + 3] << 24)) >>> 0 : u32(tiff, o));
  const ifd = r32(4);
  if (ifd + 2 > tiff.length) return tiff;
  const n = r16(ifd);
  for (let i = 0; i < n; i++) {
    const e = ifd + 2 + i * 12;
    if (e + 12 > tiff.length) break;
    if (r16(e) === 0x0112) {
      if (le) { tiff[e + 8] = 1; tiff[e + 9] = 0; } else { tiff[e + 8] = 0; tiff[e + 9] = 1; }
    }
  }
  return tiff;
}

/** Does the TIFF block hold a GPS IFD pointer (tag 0x8825)? */
export function hasGps(tiff) {
  const le = tiff[0] === 0x49;
  const r16 = (o) => (le ? tiff[o] | (tiff[o + 1] << 8) : (tiff[o] << 8) | tiff[o + 1]);
  const r32 = (o) => (le ? (tiff[o] | (tiff[o + 1] << 8) | (tiff[o + 2] << 16) | (tiff[o + 3] << 24)) >>> 0 : u32(tiff, o));
  const ifd = r32(4);
  const n = r16(ifd);
  for (let i = 0; i < n; i++) if (r16(ifd + 2 + i * 12) === 0x8825) return true;
  return false;
}

/** JPEG bytes with an APP1 "Exif" segment holding `tiff` right after SOI. */
export function insertExif(jpeg, tiff) {
  if (jpeg[0] !== 0xff || jpeg[1] !== 0xd8) throw new Error('not a JPEG');
  const len = 2 + 6 + tiff.length;
  if (len > 0xffff) return jpeg; // too big for one segment (embedded thumbnails): keep the JPEG clean
  const seg = new Uint8Array(2 + len);
  seg.set([0xff, 0xe1, len >> 8, len & 255, 0x45, 0x78, 0x69, 0x66, 0, 0]);
  seg.set(tiff, 10);
  const out = new Uint8Array(jpeg.length + seg.length);
  out.set(jpeg.subarray(0, 2));
  out.set(seg, 2);
  out.set(jpeg.subarray(2), 2 + seg.length);
  return out;
}

/** "IMG_1234.HEIC" → "IMG_1234.jpg", unique within `taken`. */
export function outputName(name, ext, taken) {
  const base = name.replace(/\.(heic|heif|hif)$/i, '') || 'image';
  let n = `${base}.${ext}`, i = 2;
  while (taken.has(n.toLowerCase())) n = `${base}-${i++}.${ext}`;
  taken.add(n.toLowerCase());
  return n;
}

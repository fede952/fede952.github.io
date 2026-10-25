// Unit tests for the HEIC converter's metadata helpers.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import * as H from '../../static/js/tools/heic.mjs';

const heic = new Uint8Array(fs.readFileSync(new URL('../fixtures/photo-gps.heic', import.meta.url)));
const jpeg = new Uint8Array(fs.readFileSync(new URL('../fixtures/photo-gps.jpg', import.meta.url)));

test('recognises a HEIF container', () => {
  assert.equal(H.isHeif(heic), true);
  assert.equal(H.isHeif(jpeg), false);
});

test('extracts the EXIF block with its GPS pointer', () => {
  const tiff = H.extractExif(heic);
  assert.ok(tiff, 'no EXIF found');
  assert.ok(['II', 'MM'].includes(String.fromCharCode(tiff[0], tiff[1])));
  assert.equal(H.hasGps(tiff), true);
});

test('inserts EXIF into a JPEG after SOI and resets orientation', () => {
  const tiff = H.resetOrientation(H.extractExif(heic));
  const clean = new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 0, 4, 0, 0, 0xff, 0xd9]);
  const out = H.insertExif(clean, tiff);
  assert.deepEqual([...out.subarray(0, 4)], [0xff, 0xd8, 0xff, 0xe1]);
  assert.equal(String.fromCharCode(...out.subarray(6, 10)), 'Exif');
  assert.equal(out.length, clean.length + 10 + tiff.length);
  assert.deepEqual([...out.subarray(out.length - 2)], [0xff, 0xd9]);
});

test('output names are unique', () => {
  const taken = new Set();
  assert.equal(H.outputName('IMG_1.HEIC', 'jpg', taken), 'IMG_1.jpg');
  assert.equal(H.outputName('IMG_1.heic', 'jpg', taken), 'IMG_1-2.jpg');
  assert.equal(H.outputName('photo.heif', 'png', taken), 'photo.png');
});

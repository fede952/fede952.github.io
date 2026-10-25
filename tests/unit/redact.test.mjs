// Unit tests for the Screenshot Redactor's detection and history.
import test from 'node:test';
import assert from 'node:assert/strict';
import { ibanValid, luhnValid, findInLine, findSensitive, rectFrom, pixelBlock, History, outputName } from '../../static/js/tools/redact-kit.mjs';

/** Fake OCR line: words laid out left to right, 10 px per character + 6 px gaps. */
function line(text, y = 100) {
  let x = 20;
  return text.split(' ').map((t) => { const w = { text: t, bbox: { x0: x, y0: y, x1: x + t.length * 10, y1: y + 18 } }; x += t.length * 10 + 6; return w; });
}
const types = (r) => r.map((m) => m.type);

test('IBAN and Luhn validators', () => {
  // the ISO 13616 / ECBS documentation examples
  assert.equal(ibanValid('GB82 WEST 1234 5698 7654 32'), true);
  assert.equal(ibanValid('DE89370400440532013000'), true);
  assert.equal(ibanValid('GB82 WEST 1234 5698 7654 33'), false);
  assert.equal(ibanValid('HELLO1234567890'), false);
  assert.equal(luhnValid('4111 1111 1111 1111'), true);     // standard test card number
  assert.equal(luhnValid('4111 1111 1111 1112'), false);
  assert.equal(luhnValid('1234'), false);
});

test('finds emails, IBANs, cards, IPs and phones, each once', () => {
  const r = findInLine(line('Contact alex.rivera@example.com or +44 20 7946 0958 from 192.0.2.44'));
  assert.deepEqual(types(r), ['email', 'ip', 'phone']);
  assert.equal(r[0].text, 'alex.rivera@example.com');
  assert.equal(r[2].text, '+44 20 7946 0958');
  const iban = findInLine(line('IBAN: GB82 WEST 1234 5698 7654 32 thanks'));
  assert.deepEqual(types(iban), ['iban']);
  assert.equal(iban[0].text.replace(/ /g, ''), 'GB82WEST12345698765432');
  assert.deepEqual(types(findInLine(line('Card 4111 1111 1111 1111 exp 12/29'))), ['card']);
  assert.deepEqual(types(findInLine(line('host 2001:db8::8a2e:370:7334 up'))), ['ip']);
});

test('a match spanning several words gets the union of their boxes', () => {
  const ws = line('Call +44 20 7946 0958 now');
  const [m] = findInLine(ws, 0);
  const covered = ws.slice(1, 5);
  assert.deepEqual(m.bbox, { x0: covered[0].bbox.x0, y0: 100, x1: covered[3].bbox.x1, y1: 118 });
});

test('no false positives on ordinary text, times, dates, versions and invalid numbers', () => {
  for (const s of ['Meeting at 12:30:45 on 2026-10-26', 'Version 1.2.3 released', 'Order 4111 1111 1111 1112 failed',
    'GB82 WEST 1234 5698 7654 33', 'Total 1,299.00 EUR', 'Room 101 floor 3', 'IP 300.1.2.3 is invalid'])
    assert.deepEqual(findInLine(line(s)), [], s);
});

test('findSensitive walks every line', () => {
  const r = findSensitive([{ words: line('mail bob@example.org', 10) }, { words: line('nothing here', 40) }, { words: line('ip 198.51.100.7', 70) }]);
  assert.deepEqual(types(r), ['email', 'ip']);
});

test('geometry, pixel blocks, history, names', () => {
  assert.deepEqual(rectFrom({ x: 50, y: 40 }, { x: 10, y: 5 }, 100, 100), { x: 10, y: 5, w: 40, h: 35 });
  assert.deepEqual(rectFrom({ x: -5, y: 90 }, { x: 30, y: 130 }, 100, 100), { x: 0, y: 90, w: 30, h: 10 });
  assert.equal(rectFrom({ x: 1, y: 1 }, { x: 2, y: 2 }, 100, 100), null);
  assert.equal(pixelBlock({ w: 400, h: 40 }), 8);
  assert.equal(pixelBlock({ w: 400, h: 200 }), 25);
  const h = new History();
  h.push([1]); h.push([1, 2]);
  assert.deepEqual(h.undo(), [1]); assert.deepEqual(h.undo(), []); assert.deepEqual(h.undo(), []);
  assert.deepEqual(h.redo(), [1]); h.push([1, 3]);
  assert.equal(h.canRedo, false); assert.deepEqual(h.current, [1, 3]);
  assert.equal(outputName('Screen Shot 2026.png', 'jpg'), 'Screen Shot 2026-redacted.jpg');
  assert.equal(outputName('', 'png'), 'screenshot-redacted.png');
});

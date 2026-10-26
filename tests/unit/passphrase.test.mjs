// Multilingual diceware passphrases: vendored lists, entropy and generation.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { LISTS, parseList, prepare, stripAccents, randomIndex, bitsPerWord, generate } from '../../static/js/tools/passphrase.mjs';

const load = (l) => parseList(fs.readFileSync(new URL('../../static' + LISTS[l].url, import.meta.url), 'utf8'));

test('every vendored list has the documented size, no duplicates, no empty words, and a licence file', () => {
  for (const l of Object.keys(LISTS)) {
    const w = load(l);
    assert.equal(w.length, LISTS[l].size, l);
    assert.equal(new Set(w).size, w.length, l + ' duplicates');
    // letters only; the EFF list also has four hyphenated words (drop-down, felt-tip, t-shirt, yo-yo)
    assert(w.every((x) => /^\p{L}+(-\p{L}+)?$/u.test(x)), l + ' letters only');
    if (l === 'en') assert.deepEqual(w.filter((x) => x.includes('-')), ['drop-down', 'felt-tip', 't-shirt', 'yo-yo']);
    const dir = new URL('../../static' + LISTS[l].url.replace(/[^/]+$/, ''), import.meta.url);
    assert(fs.existsSync(new URL('LICENSE', dir)), l + ' LICENSE');
  }
  assert.equal(load('en')[0], 'abacus', 'EFF dice prefix removed');
});

test('accents: NFC on load, stripping keeps every BIP-39 word distinct', () => {
  const fr = load('fr'), es = load('es');
  assert(fr.some((w) => /é/.test(w)) && fr.every((w) => w === w.normalize('NFC')));
  assert.equal(stripAccents('élève'), 'eleve');
  assert.equal(stripAccents('año'), 'ano');
  for (const w of [fr, es]) {
    const s = prepare(w, { strip: true });
    assert.equal(s.length, w.length);
    assert(s.every((x) => /^[a-z]+$/.test(x)));
  }
  // a list that collapses when stripped reports the smaller size
  assert.equal(prepare(['été', 'ete', 'eté'], { strip: true }).length, 1);
});

test('entropy per word', () => {
  assert.equal(bitsPerWord(7776).toFixed(3), '12.925');
  assert.equal(bitsPerWord(2048), 11);
  const { bits } = generate(load('en'), 6, {});
  assert.equal(bits.toFixed(1), '77.5');
  const n = generate(load('it'), 5, { number: true });
  assert.equal(n.bits.toFixed(2), (55 + Math.log2(50)).toFixed(2));
});

test('generation: count, separator, capitalisation, digit', () => {
  const list = load('de');
  const a = generate(list, 7, { separator: ' ' });
  assert.equal(a.text.split(' ').length, 7);
  assert(a.text.split(' ').every((w) => list.includes(w)));
  const b = generate(list, 4, { separator: '.', capitalize: true, number: true });
  const parts = b.text.split('.');
  assert.equal(parts.length, 4);
  assert(parts.every((w) => /^\p{Lu}/u.test(w)));
  assert.equal(parts.filter((w) => /\d$/.test(w)).length, 1);
  assert.notEqual(generate(list, 6).text, generate(list, 6).text);
});

test('rejection sampling is unbiased at the edge of the 32-bit range', () => {
  // a fake RNG that first returns values in the rejected top bucket
  const seq = [0xffffffff, 0xfffffffe, 5];
  const rng = (a) => { a[0] = seq.shift(); };
  assert.equal(randomIndex(7776, rng), 5);
  // rough uniformity over a small list
  const counts = new Array(6).fill(0);
  for (let i = 0; i < 60000; i++) counts[randomIndex(6)]++;
  assert(counts.every((c) => Math.abs(c - 10000) < 600), counts.join());
});

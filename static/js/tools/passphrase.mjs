/* Diceware-style passphrases, DOM-free (tests: tests/unit/passphrase.test.mjs).
   Word lists are vendored unmodified, each with its licence:
     en  EFF Large Wordlist, 7,776 words, CC BY 4.0 (Electronic Frontier Foundation)
     de  dys2p/wordlists-de de-7776-v1, 7,776 words, Unlicense / CC0 / BSD-3
     it es fr pt  BIP-39 word lists, 2,048 words each, from trezor/python-mnemonic (MIT) */

export const LISTS = {
  en: { label: 'English (EFF)', url: '/vendor/eff-wordlists@2016-07-18/eff_large_wordlist.txt', size: 7776, source: 'EFF Large Wordlist, CC BY 4.0' },
  de: { label: 'Deutsch', url: '/vendor/dys2p-wordlists-de@6ef31b9/de-7776-v1.txt', size: 7776, source: 'dys2p/wordlists-de, CC0' },
  it: { label: 'Italiano (BIP-39)', url: '/vendor/python-mnemonic-wordlists@b57a5ad/italian.txt', size: 2048, source: 'BIP-39, MIT' },
  es: { label: 'Español (BIP-39)', url: '/vendor/python-mnemonic-wordlists@b57a5ad/spanish.txt', size: 2048, source: 'BIP-39, MIT' },
  fr: { label: 'Français (BIP-39)', url: '/vendor/python-mnemonic-wordlists@b57a5ad/french.txt', size: 2048, source: 'BIP-39, MIT' },
  pt: { label: 'Português (BIP-39)', url: '/vendor/python-mnemonic-wordlists@b57a5ad/portuguese.txt', size: 2048, source: 'BIP-39, MIT' },
};

/** Words of a list file: one per line, optional EFF dice prefix ("11111<TAB>"), NFC-normalised. */
export function parseList(text) {
  return text.split(/\r?\n/).map((l) => l.replace(/^[1-6]{5}\s+/, '').trim().normalize('NFC')).filter(Boolean);
}

export const stripAccents = (w) => w.normalize('NFD').replace(/\p{M}/gu, '').normalize('NFC');

/** The list actually drawn from: accents stripped on request, duplicates removed (so the entropy stays honest). */
export function prepare(words, { strip = false } = {}) {
  return [...new Set(strip ? words.map(stripAccents) : words)];
}

/** Uniform integer in [0, max) from crypto.getRandomValues, by rejection sampling (no modulo bias). */
export function randomIndex(max, rng = (a) => globalThis.crypto.getRandomValues(a)) {
  const a = new Uint32Array(1), limit = Math.floor(0x100000000 / max) * max;
  do { rng(a); } while (a[0] >= limit);
  return a[0] % max;
}

export const bitsPerWord = (n) => Math.log2(n);

/**
 * A passphrase of `count` words. Options: separator, capitalize (first
 * letter of each word: no entropy added, it is deterministic), number (one
 * random digit appended to a random word: + log2(10 × count) bits).
 * Returns { text, bits }.
 */
export function generate(list, count, { separator = '-', capitalize = false, number = false } = {}, rng) {
  const words = [];
  for (let i = 0; i < count; i++) {
    let w = list[randomIndex(list.length, rng)];
    if (capitalize) w = w.charAt(0).toLocaleUpperCase() + w.slice(1);
    words.push(w);
  }
  let bits = count * bitsPerWord(list.length);
  if (number && count) {
    const at = randomIndex(count, rng), d = randomIndex(10, rng);
    words[at] += String(d);
    bits += Math.log2(10 * count);
  }
  return { text: words.join(separator), bits };
}

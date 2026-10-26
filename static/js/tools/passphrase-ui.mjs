/* Passphrase mode of the Password Generator (partials/tools/password-generator.html).
   Word lists are same-site files, fetched the first time a list is used. */
import { LISTS, parseList, prepare, generate, bitsPerWord } from '/js/tools/passphrase.mjs';

const S = window.PG_STRINGS || {};
const $ = (id) => document.getElementById(id);
const fill = (s, p) => String(s || '').replace(/\{(\w+)\}/g, (m, k) => (p[k] !== undefined ? p[k] : m));
const cache = {};

const list = $('pg-list');
list.value = LISTS[list.dataset.default] ? list.dataset.default : 'en'; // default list follows the page language

async function words(lang) {
  if (!cache[lang]) cache[lang] = fetch(LISTS[lang].url).then((r) => { if (!r.ok) throw new Error(r.status); return r.text(); }).then(parseList);
  try { return await cache[lang]; } catch (e) { delete cache[lang]; throw e; }
}

let run = 0;
async function phrase() {
  const id = ++run, lang = list.value;
  const info = $('pg-list-info');
  let w;
  try { w = await words(lang); } catch { info.textContent = S.failed; return; }
  if (id !== run) return; // a newer request superseded this one
  const hasAccents = w.some((x) => /[^\x00-\x7f]/.test(x));
  $('pg-strip-wrap').hidden = !hasAccents;
  const pool = prepare(w, { strip: hasAccents && $('pg-strip').checked });
  const n = parseInt($('pg-words').value, 10);
  const r = generate(pool, n, { separator: $('pg-sep').value, capitalize: $('pg-cap').checked, number: $('pg-digit').checked });
  $('pg-password').value = r.text;
  window.pgShowStrength(r.bits);
  info.textContent = fill(S.perWord, { bits: bitsPerWord(pool.length).toLocaleString(S.lang, { maximumFractionDigits: 2 }), n: pool.length.toLocaleString(S.lang), source: LISTS[lang].source });
  window.__pgPhrase = { text: r.text, bits: r.bits, list: lang, size: pool.length };
}
window.pgPassphrase = phrase;

$('pg-words').addEventListener('input', (e) => { $('pg-words-val').textContent = e.target.value; phrase(); });
for (const id of ['pg-list', 'pg-sep', 'pg-cap', 'pg-digit', 'pg-strip']) $(id).addEventListener('change', phrase);
if ($('pg-mode-phrase').checked) phrase();
window.__pgPhraseReady = true;

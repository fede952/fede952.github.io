/* Have I Been Pwned "Pwned Passwords" range check with k-anonymity:
   only the first 5 hex characters of the password's SHA-1 are sent; the API
   answers with every hash suffix in that range and the match happens here.
   `Add-Padding: true` makes every response roughly the same size (padding
   entries have a count of 0), so the reply does not hint at the result. */

export const RANGE_URL = 'https://api.pwnedpasswords.com/range/';

/** Uppercase hex SHA-1 of a UTF-8 string (Web Crypto). */
export async function sha1Hex(text) {
  const buf = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

/** Splits a hash into the 5-character prefix that is sent and the 35-character suffix that is not. */
export function splitHash(hash) {
  return { prefix: hash.slice(0, 5), suffix: hash.slice(5) };
}

/** Finds `suffix` in a range response ("SUFFIX:COUNT" lines). Returns the breach count, 0 when absent. */
export function countInRange(body, suffix) {
  const want = suffix.toUpperCase();
  for (const line of String(body).split(/\r?\n/)) {
    const i = line.indexOf(':');
    if (i < 0) continue;
    if (line.slice(0, i).trim().toUpperCase() === want) return parseInt(line.slice(i + 1), 10) || 0; // padding rows are 0
  }
  return 0;
}

/** Full check. Resolves to the number of times the password appears in breaches. */
export async function pwnedCount(password, fetchImpl = fetch) {
  const { prefix, suffix } = splitHash(await sha1Hex(password));
  const res = await fetchImpl(RANGE_URL + prefix, { headers: { 'Add-Padding': 'true' }, cache: 'no-store', referrerPolicy: 'no-referrer' });
  if (!res.ok) throw new Error('HTTP ' + res.status);
  return countInRange(await res.text(), suffix);
}

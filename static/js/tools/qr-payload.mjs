/* Payload builders for tools/qr-generator's Wi-Fi and contact modes.
   Wi-Fi follows the ZXing "WIFI:" format that Android and iOS cameras read;
   contacts are vCard 3.0 (RFC 2426), the version phone cameras import most
   reliably. */

/** Wi-Fi field escaping: backslash, semicolon, comma, colon and double quote get a backslash. */
export const escWifi = (s) => String(s).replace(/([\\;,:"])/g, '\\$1');

/**
 * WIFI:T:<WPA|WEP|nopass>;S:<ssid>;P:<password>;H:true;;
 * WPA covers WPA, WPA2 and WPA3-Personal; scanners negotiate the exact version.
 * Returns { payload } or { error: 'ssid' | 'password' }.
 */
export function wifiPayload({ ssid = '', password = '', auth = 'WPA', hidden = false } = {}) {
  if (!ssid) return { error: 'ssid' };
  const T = auth === 'WEP' ? 'WEP' : auth === 'nopass' ? 'nopass' : 'WPA';
  if (T !== 'nopass' && !password) return { error: 'password' };
  let s = `WIFI:T:${T};S:${escWifi(ssid)};`;
  if (T !== 'nopass') s += `P:${escWifi(password)};`;
  if (hidden) s += 'H:true;';
  return { payload: s + ';' };
}

/** vCard 3.0 text value escaping: backslash, semicolon and comma get a backslash; line breaks become \n. */
export const escVcard = (s) => String(s).replace(/([\\;,])/g, '\\$1').replace(/\r\n|\r|\n/g, '\\n');

/**
 * A vCard 3.0 with the fields that are filled in (CRLF line endings, as the RFC requires).
 * Fields: first, last, org, title, phone, email, url, street, city, zip, country, note.
 * Returns { payload } or { error: 'name' } when there is no name or organisation.
 */
export function vcardPayload(f = {}) {
  const v = (k) => String(f[k] ?? '').trim();
  const first = v('first'), last = v('last'), org = v('org');
  if (!first && !last && !org) return { error: 'name' };
  const fn = [first, last].filter(Boolean).join(' ') || org;
  const lines = ['BEGIN:VCARD', 'VERSION:3.0', `N:${escVcard(last)};${escVcard(first)};;;`, `FN:${escVcard(fn)}`];
  if (org) lines.push(`ORG:${escVcard(org)}`);
  if (v('title')) lines.push(`TITLE:${escVcard(v('title'))}`);
  if (v('phone')) lines.push(`TEL;TYPE=CELL:${escVcard(v('phone'))}`);
  if (v('email')) lines.push(`EMAIL;TYPE=INTERNET:${escVcard(v('email'))}`);
  if (v('url')) lines.push(`URL:${escVcard(v('url'))}`);
  if (v('street') || v('city') || v('zip') || v('country')) {
    // ADR: post office box; extended address; street; locality; region; postal code; country
    lines.push(`ADR;TYPE=WORK:;;${escVcard(v('street'))};${escVcard(v('city'))};;${escVcard(v('zip'))};${escVcard(v('country'))}`);
  }
  if (v('note')) lines.push(`NOTE:${escVcard(v('note'))}`);
  lines.push('END:VCARD');
  return { payload: lines.join('\r\n') };
}

/* ── decoders, used by the tests to check a payload round-trips ── */

/** Parses a WIFI: payload back into { T, S, P, H }. */
export function parseWifi(s) {
  if (!s.startsWith('WIFI:')) return null;
  const out = {};
  let i = 5;
  while (i < s.length && s[i] !== ';') {
    const k = s.slice(i, s.indexOf(':', i)); i += k.length + 1;
    let val = '';
    while (i < s.length && s[i] !== ';') { if (s[i] === '\\') i++; val += s[i++]; }
    out[k] = val; i++;
  }
  return out;
}

/** Splits a vCard into { NAME: value } with the 3.0 escapes undone (first occurrence of each property). */
export function parseVcard(s) {
  const out = {};
  for (const line of s.split(/\r\n/)) {
    const c = line.indexOf(':');
    if (c < 0) continue;
    const name = line.slice(0, c).split(';')[0];
    if (name in out) continue;
    out[name] = line.slice(c + 1);
  }
  return out;
}
/** Splits one structured vCard value on unescaped semicolons and unescapes each part. */
export function vcardParts(value) {
  const parts = [''];
  for (let i = 0; i < value.length; i++) {
    const ch = value[i];
    if (ch === '\\') { const n = value[++i]; parts[parts.length - 1] += n === 'n' || n === 'N' ? '\n' : n; }
    else if (ch === ';') parts.push('');
    else parts[parts.length - 1] += ch;
  }
  return parts;
}

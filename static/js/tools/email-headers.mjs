/* Email Header Analyzer — pure parsing and checks (no DOM, no network).
   Unit-tested in tests/unit/email-headers.test.mjs with the fixtures in
   tests/fixtures/email-headers/ (fictional domains only). */

/** Splits raw headers into [{ name, value }] in order: unfolds continuation lines, stops at the body. */
export function parseHeaders(raw) {
  const lines = String(raw).replace(/\r\n?/g, '\n').split('\n');
  const out = [];
  for (const line of lines) {
    if (line === '' && out.length) break;                 // blank line = end of the header block
    if (/^[ \t]/.test(line) && out.length) { out[out.length - 1].value += ' ' + line.trim(); continue; }
    const m = line.match(/^([!-9;-~]+):\s?(.*)$/);           // field-name: printable ASCII except ":"
    if (m) out.push({ name: m[1], value: m[2].trim() });
  }
  return out;
}
const all = (hs, name) => hs.filter((h) => h.name.toLowerCase() === name).map((h) => h.value);
const first = (hs, name) => all(hs, name)[0];

/** Parses a mailbox header: { name, address, domain }, or null. */
export function parseAddress(v) {
  if (!v) return null;
  let s = String(v).trim();
  let name = '', address = '';
  const angle = s.match(/^(.*?)<([^<>]+)>\s*$/);
  if (angle) { name = angle[1].trim().replace(/^"|"$/g, '').trim(); address = angle[2].trim(); }
  else address = s.replace(/^"|"$/g, '').split(/[\s,(]/)[0];
  const at = address.lastIndexOf('@');
  return { name, address, domain: at > 0 ? address.slice(at + 1).toLowerCase().replace(/[>\s]+$/, '') : '' };
}

/* Public suffixes with two labels that are common in mail domains (enough for a
   same-organisation comparison; not a full Public Suffix List). */
const TWO_LABEL = new Set(['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'co.nz', 'co.jp', 'ne.jp', 'or.jp', 'com.br', 'com.mx', 'com.ar', 'co.za', 'co.in', 'co.kr', 'com.cn', 'com.tr', 'com.sg', 'com.hk']);
/** Organisational domain: the registrable part (mail.example.co.uk → example.co.uk). */
export function orgDomain(d) {
  const parts = String(d || '').toLowerCase().replace(/\.$/, '').split('.').filter(Boolean);
  if (parts.length <= 2) return parts.join('.');
  const last2 = parts.slice(-2).join('.');
  return TWO_LABEL.has(last2) ? parts.slice(-3).join('.') : last2;
}

/** One Received header → { from, fromIp, by, with, id, for, date, raw }. */
export function parseReceived(v) {
  const semi = v.lastIndexOf(';');
  const body = semi >= 0 ? v.slice(0, semi) : v;
  const dateStr = semi >= 0 ? v.slice(semi + 1).trim() : '';
  const date = dateStr ? new Date(dateStr.replace(/\s*\([^)]*\)\s*$/, '')) : null;
  const grab = (kw) => { const m = body.match(new RegExp(`(?:^|\\s)${kw}\\s+([^\\s;()]+)`, 'i')); return m ? m[1] : ''; };
  const ip = (body.match(/\[(?:IPv6:)?([0-9a-fA-F:.]+)\]/) || body.match(/\(([0-9]{1,3}(?:\.[0-9]{1,3}){3})\)/) || [])[1] || '';
  return { from: grab('from'), fromIp: ip, by: grab('by'), with: grab('with'), id: grab('id'), for: grab('for').replace(/[<>]/g, ''),
    date: date && !isNaN(date) ? date : null, raw: v };
}

/** Hops oldest first, each with the delay since the previous hop in seconds. */
export function hopChain(headers) {
  const hops = all(headers, 'received').map(parseReceived).reverse();
  hops.forEach((h, i) => { h.delay = i && h.date && hops[i - 1].date ? Math.round((h.date - hops[i - 1].date) / 1000) : null; });
  return hops;
}

/** Authentication-Results → { authserv, spf, dkim[], dmarc, arc, ... } with the method properties. */
export function parseAuthResults(v) {
  const parts = String(v).split(';').map((s) => s.trim()).filter(Boolean);
  const out = { authserv: (parts.shift() || '').split(/\s/)[0], spf: null, dkim: [], dmarc: null, arc: null };
  for (const p of parts) {
    const m = p.match(/^(spf|dkim|dmarc|arc|bimi|compauth)\s*=\s*([a-z]+)/i);
    if (!m) continue;
    const props = {};
    for (const kv of p.matchAll(/([a-z]+\.[a-z0-9-]+)=("?)([^\s";]+)\2/gi)) props[kv[1].toLowerCase()] = kv[3];
    const pol = p.match(/\bp=([a-z]+)/i);
    const r = { result: m[2].toLowerCase(), props, policy: pol ? pol[1].toLowerCase() : '' };
    const k = m[1].toLowerCase();
    if (k === 'dkim') out.dkim.push(r); else out[k] = r;
  }
  return out;
}

/** Message-ID → domain part. */
export const messageIdDomain = (v) => { const m = String(v || '').match(/@([^>\s]+)>?\s*$/); return m ? m[1].toLowerCase() : ''; };

/**
 * Full analysis. Returns { headers, from, replyTo, returnPath, sender, messageIdDomain, mailer, auth, arcCount, hops, signals }.
 * signals: [{ id, sev: 'high'|'medium'|'low'|'info'|'good', p }] — ids are message keys in the app.
 */
export function analyze(raw, now = new Date()) {
  const headers = parseHeaders(raw);
  const from = parseAddress(first(headers, 'from'));
  const replyTo = parseAddress(first(headers, 'reply-to'));
  const returnPath = parseAddress(first(headers, 'return-path'));
  const sender = parseAddress(first(headers, 'sender'));
  const msgDomain = messageIdDomain(first(headers, 'message-id'));
  const mailer = first(headers, 'x-mailer') || first(headers, 'user-agent') || '';
  const authHeaders = all(headers, 'authentication-results');
  const auth = authHeaders.length ? parseAuthResults(authHeaders[0]) : null;   // the topmost is added by the receiving server
  const arcCount = all(headers, 'arc-seal').length;
  const hops = hopChain(headers);
  const signals = [];
  const add = (id, sev, p = {}) => signals.push({ id, sev, p });
  const fromOrg = from ? orgDomain(from.domain) : '';

  if (!headers.length) return { headers, signals: [{ id: 'empty', sev: 'info', p: {} }] };
  if (!from || !from.domain) add('no-from', 'high');
  if (from && /@/.test(from.name)) {
    const shown = parseAddress(from.name);
    if (shown && shown.domain && orgDomain(shown.domain) !== fromOrg) add('display-name-address', 'high', { shown: shown.address, real: from.address });
  }
  if (replyTo && from && replyTo.domain && orgDomain(replyTo.domain) !== fromOrg) add('reply-to-mismatch', 'medium', { replyTo: replyTo.address, from: from.domain });
  if (returnPath && from && returnPath.domain && orgDomain(returnPath.domain) !== fromOrg) add('return-path-mismatch', 'low', { returnPath: returnPath.domain, from: from.domain });
  if (msgDomain && from && orgDomain(msgDomain) !== fromOrg) add('message-id-mismatch', 'info', { domain: msgDomain });

  if (!auth) add('no-auth-results', 'medium');
  else {
    const spf = auth.spf, dmarc = auth.dmarc;
    if (spf) {
      if (spf.result === 'pass') {
        const mf = (spf.props['smtp.mailfrom'] || '').split('@').pop().toLowerCase();
        if (mf && fromOrg && orgDomain(mf) !== fromOrg) add('spf-not-aligned', 'info', { domain: mf });
        else add('spf-pass', 'good');
      } else if (spf.result === 'fail') add('spf-fail', 'high');
      else if (spf.result === 'softfail') add('spf-softfail', 'medium');
      else add('spf-other', 'low', { result: spf.result });
    } else add('spf-missing', 'low');
    const dk = auth.dkim;
    const aligned = dk.filter((d) => d.result === 'pass' && fromOrg && orgDomain(d.props['header.d'] || d.props['header.i']?.split('@').pop() || '') === fromOrg);
    if (aligned.length) add('dkim-aligned', 'good', { domain: aligned[0].props['header.d'] || '' });
    else if (dk.some((d) => d.result === 'pass')) add('dkim-not-aligned', 'low', { domain: dk.find((d) => d.result === 'pass').props['header.d'] || '' });
    else if (dk.some((d) => d.result === 'fail')) add('dkim-fail', 'medium');
    else add('dkim-none', 'low');
    if (dmarc) {
      if (dmarc.result === 'pass') add('dmarc-pass', 'good');
      else if (dmarc.result === 'fail') add('dmarc-fail', 'high', { policy: dmarc.policy || '?' });
      else add('dmarc-other', 'low', { result: dmarc.result });
    } else add('dmarc-missing', 'low');
  }
  if (arcCount) add('arc-present', 'info', { n: arcCount });
  if (/phpmailer|swiftmailer|mass ?mail|bulk/i.test(mailer)) add('bulk-mailer', 'info', { mailer });

  const date = first(headers, 'date') ? new Date(first(headers, 'date')) : null;
  if (date && !isNaN(date) && date - now > 3600e3) add('date-future', 'medium');
  if (hops.some((h) => h.delay !== null && h.delay < -300)) add('clock-skew', 'info');
  const slow = hops.filter((h) => h.delay !== null && h.delay > 3600);
  if (slow.length) add('slow-hop', 'info', { n: slow.length });
  if (!hops.length) add('no-received', 'low');

  const order = { high: 0, medium: 1, low: 2, info: 3, good: 4 };
  signals.sort((a, b) => order[a.sev] - order[b.sev]);
  return { headers, from, replyTo, returnPath, sender, messageIdDomain: msgDomain, mailer, auth, arcCount, hops, signals };
}

/** Overall verdict from the signals. */
export function verdict(signals) {
  if (signals.some((s) => s.sev === 'high')) return 'danger';
  if (signals.some((s) => s.sev === 'medium')) return 'caution';
  return 'ok';
}

/** "1 h 2 min", "45 s" style delay, unit labels from the caller. */
export function formatDelay(sec, u = { s: 's', min: 'min', h: 'h' }) {
  if (sec === null || sec === undefined) return '';
  const neg = sec < 0 ? '−' : ''; sec = Math.abs(sec);
  if (sec < 60) return `${neg}${sec} ${u.s}`;
  if (sec < 3600) return `${neg}${Math.floor(sec / 60)} ${u.min} ${sec % 60 ? `${sec % 60} ${u.s}` : ''}`.trim();
  return `${neg}${Math.floor(sec / 3600)} ${u.h} ${Math.floor((sec % 3600) / 60)} ${u.min}`;
}

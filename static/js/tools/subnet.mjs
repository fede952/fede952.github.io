// Subnet math for /tools/subnet-calculator/ (IPv4 + IPv6), no dependencies.
// Pure functions: imported by the app and by tests/unit/subnet.test.mjs.
// IPv4 addresses are unsigned 32-bit Numbers, IPv6 addresses BigInts.

/* ── IPv4 ── */

export function parseIPv4(s) {
  const m = String(s).trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  const o = m.slice(1).map(Number);
  if (o.some((x, i) => x > 255 || (m[i + 1].length > 1 && m[i + 1][0] === '0'))) return null;
  return ((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]) >>> 0;
}

export const formatIPv4 = (n) => [24, 16, 8, 0].map((s) => (n >>> s) & 255).join('.');
export const maskFromPrefix = (p) => (p === 0 ? 0 : (0xffffffff << (32 - p)) >>> 0);
export const toBinary32 = (n) => [24, 16, 8, 0].map((s) => ((n >>> s) & 255).toString(2).padStart(8, '0')).join('.');

/** Prefix length of a contiguous netmask (255.255.254.0 → 23), or null. */
export function prefixFromMask(mask) {
  const inv = (~mask) >>> 0;
  if ((inv & (inv + 1)) !== 0) return null; // ones must be contiguous from the left
  let p = 0;
  for (let b = 31; b >= 0 && (mask >>> b) & 1; b--) p++;
  return p;
}

/**
 * "10.0.0.5/8", "10.0.0.5 255.0.0.0", "10.0.0.5 0.255.255.255" (wildcard)
 * or a bare address (/32) → { ip, prefix } or { error }.
 */
export function parseIPv4Cidr(input) {
  const s = String(input).trim();
  const m = s.match(/^([\d.]+)\s*(?:\/\s*(\d{1,2})|\s+([\d.]+))?$/);
  if (!m) return { error: 'syntax' };
  const ip = parseIPv4(m[1]);
  if (ip === null) return { error: 'address' };
  if (m[2] !== undefined) {
    const prefix = Number(m[2]);
    return prefix > 32 ? { error: 'prefix' } : { ip, prefix };
  }
  if (m[3] !== undefined) {
    const mask = parseIPv4(m[3]);
    if (mask === null) return { error: 'mask' };
    let prefix = prefixFromMask(mask);
    if (prefix === null) prefix = prefixFromMask((~mask) >>> 0); // a wildcard mask
    return prefix === null ? { error: 'mask' } : { ip, prefix };
  }
  return { ip, prefix: 32 };
}

/** What kind of address this is (first matching block wins). */
export function ipv4Scope(ip) {
  const inBlock = (net, p) => ((ip & maskFromPrefix(p)) >>> 0) === parseIPv4(net);
  if (inBlock('0.0.0.0', 8)) return 'this-network';
  if (inBlock('127.0.0.0', 8)) return 'loopback';
  if (inBlock('10.0.0.0', 8) || inBlock('172.16.0.0', 12) || inBlock('192.168.0.0', 16)) return 'private';
  if (inBlock('100.64.0.0', 10)) return 'cgnat';
  if (inBlock('169.254.0.0', 16)) return 'link-local';
  if (inBlock('192.0.2.0', 24) || inBlock('198.51.100.0', 24) || inBlock('203.0.113.0', 24)) return 'documentation';
  if (inBlock('224.0.0.0', 4)) return 'multicast';
  if (ip === 0xffffffff) return 'broadcast';
  if (inBlock('240.0.0.0', 4)) return 'reserved';
  return 'public';
}

/**
 * Everything about one IPv4 network. RFC 3021: a /31 has two usable
 * addresses (point-to-point, no network/broadcast); a /32 is one host.
 */
export function ipv4Info(ip, prefix) {
  const mask = maskFromPrefix(prefix);
  const wildcard = (~mask) >>> 0;
  const network = (ip & mask) >>> 0;
  const broadcast = (network | wildcard) >>> 0;
  const total = 2 ** (32 - prefix);
  let first, last, usable;
  if (prefix === 32) { first = last = network; usable = 1; }
  else if (prefix === 31) { first = network; last = broadcast; usable = 2; }
  else { first = network + 1; last = broadcast - 1; usable = total - 2; }
  return {
    ip, prefix, mask, wildcard, network, broadcast, first, last, total, usable,
    hasBroadcast: prefix <= 30, scope: ipv4Scope(ip),
  };
}

/** Split a block into `count` equal subnets (rounded up to a power of two). */
export function splitEqual(network, prefix, count) {
  if (!(count >= 1)) return { error: 'count' };
  const extra = Math.ceil(Math.log2(count));
  const p = prefix + extra;
  if (p > 32) return { error: 'too-many' };
  const size = 2 ** (32 - p);
  const out = [];
  for (let i = 0; i < 2 ** extra; i++) out.push(ipv4Info((network + i * size) >>> 0, p));
  return { prefix: p, subnets: out };
}

/** Smallest prefix that holds `hosts` usable addresses. */
export function prefixForHosts(hosts) {
  if (hosts <= 1) return 32;
  if (hosts === 2) return 31;
  for (let p = 30; p >= 0; p--) if (2 ** (32 - p) - 2 >= hosts) return p;
  return null;
}

/**
 * VLSM: allocate one subnet per requested host count inside network/prefix,
 * largest first so every subnet stays aligned. Returns the allocations in
 * the order requested plus the free space left.
 */
export function vlsm(network, prefix, hostCounts) {
  const reqs = hostCounts.map((h, i) => ({ i, hosts: h, p: prefixForHosts(h) }));
  if (reqs.some((r) => r.p === null || !(r.hosts >= 1))) return { error: 'hosts' };
  const sorted = [...reqs].sort((a, b) => a.p - b.p || a.i - b.i);
  const end = network + 2 ** (32 - prefix);
  let cursor = network;
  const out = [];
  for (const r of sorted) {
    if (r.p < prefix) return { error: 'too-big', hosts: r.hosts };
    const size = 2 ** (32 - r.p);
    cursor = Math.ceil(cursor / size) * size; // align
    if (cursor + size > end) return { error: 'no-space', hosts: r.hosts };
    out.push({ ...r, info: ipv4Info(cursor >>> 0, r.p) });
    cursor += size;
  }
  out.sort((a, b) => a.i - b.i);
  return { subnets: out, used: cursor - network, free: end - cursor };
}

/* ── IPv6 ── */

const MAX128 = (1n << 128n) - 1n;

/** Parses full, compressed (::) and IPv4-suffixed (::ffff:1.2.3.4) forms. */
export function parseIPv6(s) {
  let str = String(s).trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/%.*$/, '');
  if (!/^[0-9a-f:.]+$/.test(str) || str.includes(':::')) return null;
  const v4 = str.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/);
  if (v4) {
    const n = parseIPv4(v4[2]);
    if (n === null) return null;
    str = v4[1] + ((n >>> 16).toString(16)) + ':' + ((n & 0xffff).toString(16));
  }
  const halves = str.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - left.length - right.length;
  if (halves.length === 1 ? missing !== 0 : missing < 1) return null;
  const groups = [...left, ...Array(halves.length === 2 ? missing : 0).fill('0'), ...right];
  if (groups.length !== 8 || groups.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return null;
  return groups.reduce((acc, g) => (acc << 16n) | BigInt(parseInt(g, 16)), 0n);
}

const groupsOf = (n) => Array.from({ length: 8 }, (_, i) => Number((n >> BigInt(112 - i * 16)) & 0xffffn));

export const expandIPv6 = (n) => groupsOf(n).map((g) => g.toString(16).padStart(4, '0')).join(':');

/** RFC 5952: lowercase, no leading zeros, the longest run (≥ 2) of zero groups as "::" (leftmost on ties). */
export function compressIPv6(n) {
  const g = groupsOf(n);
  let best = -1, bestLen = 0;
  for (let i = 0; i < 8;) {
    if (g[i] !== 0) { i++; continue; }
    let j = i;
    while (j < 8 && g[j] === 0) j++;
    if (j - i > bestLen && j - i >= 2) { best = i; bestLen = j - i; }
    i = j;
  }
  const hex = g.map((x) => x.toString(16));
  if (best < 0) return hex.join(':');
  return hex.slice(0, best).join(':') + '::' + hex.slice(best + bestLen).join(':');
}

export const maskFromPrefix6 = (p) => (p === 0 ? 0n : (MAX128 << BigInt(128 - p)) & MAX128);

export function parseIPv6Cidr(input) {
  const m = String(input).trim().match(/^([^/\s]+)\s*(?:\/\s*(\d{1,3}))?$/);
  if (!m) return { error: 'syntax' };
  const ip = parseIPv6(m[1]);
  if (ip === null) return { error: 'address' };
  const prefix = m[2] === undefined ? 128 : Number(m[2]);
  return prefix > 128 ? { error: 'prefix' } : { ip, prefix };
}

export function ipv6Scope(ip) {
  const inBlock = (net, p) => (ip & maskFromPrefix6(p)) === parseIPv6(net);
  if (ip === 0n) return 'unspecified';
  if (ip === 1n) return 'loopback';
  if (inBlock('::ffff:0:0', 96)) return 'ipv4-mapped';
  if (inBlock('2001:db8::', 32)) return 'documentation';
  if (inBlock('fe80::', 10)) return 'link-local';
  if (inBlock('fc00::', 7)) return 'unique-local';
  if (inBlock('ff00::', 8)) return 'multicast';
  if (inBlock('2000::', 3)) return 'global';
  return 'reserved';
}

export function ipv6Info(ip, prefix) {
  const mask = maskFromPrefix6(prefix);
  const network = ip & mask;
  const last = network | (~mask & MAX128);
  return {
    ip, prefix, network, last, total: 1n << BigInt(128 - prefix),
    subnets64: prefix <= 64 ? 1n << BigInt(64 - prefix) : 0n, scope: ipv6Scope(ip),
  };
}

/** 340282366920938463463374607431768211456 → "3.4 × 10^38" style string for huge counts. */
export function humanBig(n) {
  const s = n.toString();
  if (s.length <= 15) return Number(n).toLocaleString('en-US');
  return `${s[0]}.${s.slice(1, 3)} × 10^${s.length - 1}`;
}

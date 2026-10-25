// Unit tests for the subnet calculator engine (node --test tests/unit/).
import test from 'node:test';
import assert from 'node:assert/strict';
import * as S from '../../static/js/tools/subnet.mjs';

const info = (cidr) => { const r = S.parseIPv4Cidr(cidr); assert.ok(!r.error, cidr + ' ' + r.error); return S.ipv4Info(r.ip, r.prefix); };
const f = S.formatIPv4;

test('IPv4 /24 basics', () => {
  const i = info('192.168.1.130/24');
  assert.equal(f(i.network), '192.168.1.0');
  assert.equal(f(i.broadcast), '192.168.1.255');
  assert.equal(f(i.first), '192.168.1.1');
  assert.equal(f(i.last), '192.168.1.254');
  assert.equal(f(i.mask), '255.255.255.0');
  assert.equal(f(i.wildcard), '0.0.0.255');
  assert.equal(i.usable, 254);
  assert.equal(i.scope, 'private');
});

test('IPv4 /31 is point-to-point (RFC 3021)', () => {
  const i = info('10.0.0.1/31');
  assert.equal(f(i.network), '10.0.0.0');
  assert.equal(f(i.first), '10.0.0.0');
  assert.equal(f(i.last), '10.0.0.1');
  assert.equal(i.usable, 2);
  assert.equal(i.hasBroadcast, false);
});

test('IPv4 /32 is a single host', () => {
  const i = info('8.8.8.8');
  assert.equal(i.prefix, 32);
  assert.equal(f(i.first), '8.8.8.8');
  assert.equal(f(i.last), '8.8.8.8');
  assert.equal(i.usable, 1);
  assert.equal(i.scope, 'public');
});

test('IPv4 /0 is the whole address space', () => {
  const i = info('203.0.113.9/0');
  assert.equal(f(i.network), '0.0.0.0');
  assert.equal(f(i.broadcast), '255.255.255.255');
  assert.equal(f(i.mask), '0.0.0.0');
  assert.equal(i.total, 2 ** 32);
  assert.equal(i.usable, 2 ** 32 - 2);
});

test('IPv4 input forms: dotted mask, wildcard, errors', () => {
  assert.deepEqual(S.parseIPv4Cidr('172.16.5.4 255.255.240.0'), { ip: S.parseIPv4('172.16.5.4'), prefix: 20 });
  assert.equal(S.parseIPv4Cidr('172.16.5.4 0.0.15.255').prefix, 20);
  assert.equal(S.parseIPv4Cidr('10.0.0.1 255.0.255.0').error, 'mask');
  assert.equal(S.parseIPv4Cidr('256.1.1.1/8').error, 'address');
  assert.equal(S.parseIPv4Cidr('10.01.1.1').error, 'address'); // no ambiguous leading zeros
  assert.equal(S.parseIPv4Cidr('10.0.0.0/33').error, 'prefix');
  assert.equal(S.toBinary32(S.parseIPv4('192.168.1.1')), '11000000.10101000.00000001.00000001');
});

test('IPv4 scopes', () => {
  assert.equal(info('100.72.1.1/10').scope, 'cgnat');
  assert.equal(info('169.254.10.1/16').scope, 'link-local');
  assert.equal(info('127.0.0.1/8').scope, 'loopback');
  assert.equal(info('239.1.1.1/8').scope, 'multicast');
  assert.equal(info('172.32.0.1/16').scope, 'public'); // just outside 172.16/12
});

test('split into equal subnets', () => {
  const r = S.splitEqual(S.parseIPv4('192.168.0.0'), 24, 3);
  assert.equal(r.prefix, 26);
  assert.deepEqual(r.subnets.map((s) => f(s.network)), ['192.168.0.0', '192.168.0.64', '192.168.0.128', '192.168.0.192']);
  assert.equal(S.splitEqual(S.parseIPv4('10.0.0.0'), 31, 4).error, 'too-many');
});

test('VLSM allocation, largest first, aligned', () => {
  const r = S.vlsm(S.parseIPv4('192.168.10.0'), 24, [20, 100, 2, 50]);
  assert.ok(!r.error);
  const byHosts = Object.fromEntries(r.subnets.map((s) => [s.hosts, `${f(s.info.network)}/${s.info.prefix}`]));
  assert.equal(byHosts[100], '192.168.10.0/25');
  assert.equal(byHosts[50], '192.168.10.128/26');
  assert.equal(byHosts[20], '192.168.10.192/27');
  assert.equal(byHosts[2], '192.168.10.224/31');
  assert.equal(r.free, 256 - 226);
  assert.equal(S.vlsm(S.parseIPv4('10.0.0.0'), 28, [10, 10]).error, 'no-space');
  assert.equal(S.prefixForHosts(254), 24);
  assert.equal(S.prefixForHosts(255), 23);
});

test('IPv6 parsing and RFC 5952 compression', () => {
  const n = S.parseIPv6('2001:0db8:0000:0000:0000:ff00:0042:8329');
  assert.equal(S.compressIPv6(n), '2001:db8::ff00:42:8329');
  assert.equal(S.expandIPv6(S.parseIPv6('::1')), '0000:0000:0000:0000:0000:0000:0000:0001');
  assert.equal(S.compressIPv6(S.parseIPv6('::')), '::');
  assert.equal(S.compressIPv6(S.parseIPv6('2001:db8:0:1:1:1:1:1')), '2001:db8:0:1:1:1:1:1'); // a single 0 group is not compressed
  assert.equal(S.compressIPv6(S.parseIPv6('2001:0:0:1:0:0:0:1')), '2001:0:0:1::1'); // longest run wins
  assert.equal(S.compressIPv6(S.parseIPv6('2001:db8:0:0:1:0:0:1')), '2001:db8::1:0:0:1'); // leftmost on ties
  assert.equal(S.compressIPv6(S.parseIPv6('::ffff:192.0.2.1')), '::ffff:c000:201');
  for (const bad of ['2001:db8:::1', '1::2::3', '12345::', 'g::1', '1:2:3:4:5:6:7', '1:2:3:4:5:6:7:8:9']) assert.equal(S.parseIPv6(bad), null, bad);
});

test('IPv6 prefix info', () => {
  const r = S.parseIPv6Cidr('2001:db8:abcd:12::1/48');
  const i = S.ipv6Info(r.ip, r.prefix);
  assert.equal(S.compressIPv6(i.network), '2001:db8:abcd::');
  assert.equal(S.compressIPv6(i.last), '2001:db8:abcd:ffff:ffff:ffff:ffff:ffff');
  assert.equal(i.subnets64, 65536n);
  assert.equal(i.scope, 'documentation');
  assert.equal(S.ipv6Info(S.parseIPv6('fe80::1'), 64).scope, 'link-local');
  assert.equal(S.ipv6Info(S.parseIPv6('fd12:3456::1'), 64).scope, 'unique-local');
  assert.equal(S.ipv6Info(0n, 0).total, 1n << 128n);
  assert.equal(S.parseIPv6Cidr('::1/129').error, 'prefix');
});

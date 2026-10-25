// Unit tests for the QR generator's Wi-Fi and vCard payloads.
import test from 'node:test';
import assert from 'node:assert/strict';
import { escWifi, wifiPayload, escVcard, vcardPayload, parseWifi, parseVcard, vcardParts } from '../../static/js/tools/qr-payload.mjs';

test('Wi-Fi escaping of \\ ; , : "', () => {
  assert.equal(escWifi('a\\b;c,d:e"f'), 'a\\\\b\\;c\\,d\\:e\\"f');
  assert.equal(escWifi('plain'), 'plain');
});

test('Wi-Fi payloads', () => {
  assert.deepEqual(wifiPayload({ ssid: 'Home', password: 'secret' }), { payload: 'WIFI:T:WPA;S:Home;P:secret;;' });
  assert.deepEqual(wifiPayload({ ssid: 'Cafe', auth: 'nopass', password: 'ignored' }), { payload: 'WIFI:T:nopass;S:Cafe;;' });
  assert.deepEqual(wifiPayload({ ssid: 'Old', password: '12345', auth: 'WEP', hidden: true }), { payload: 'WIFI:T:WEP;S:Old;P:12345;H:true;;' });
  assert.deepEqual(wifiPayload({ ssid: '' }), { error: 'ssid' });
  assert.deepEqual(wifiPayload({ ssid: 'x', auth: 'WPA' }), { error: 'password' });
});

test('Wi-Fi round-trip with every special character', () => {
  const ssid = 'My;Net,work:"5G"\\', password = 'p@ss;w,o:r"d\\ end';
  const { payload } = wifiPayload({ ssid, password, hidden: true });
  assert.deepEqual(parseWifi(payload), { T: 'WPA', S: ssid, P: password, H: 'true' });
});

test('vCard escaping and structure', () => {
  assert.equal(escVcard('a;b,c\\d\ne'), 'a\\;b\\,c\\\\d\\ne');
  const { payload } = vcardPayload({ first: 'Ada', last: 'Lovelace', org: 'Analytical Engines, Ltd.', phone: '+44 20 7946 0000', email: 'ada@example.com', city: 'London', note: 'Line 1\nLine 2; more' });
  assert.equal(payload.split('\r\n')[0], 'BEGIN:VCARD');
  assert(payload.endsWith('\r\nEND:VCARD'));
  assert(!/[^\r]\n/.test(payload), 'CRLF line endings only');
  const v = parseVcard(payload);
  assert.equal(v.VERSION, '3.0');
  assert.deepEqual(vcardParts(v.N), ['Lovelace', 'Ada', '', '', '']);
  assert.equal(v.FN, 'Ada Lovelace');
  assert.deepEqual(vcardParts(v.ORG), ['Analytical Engines, Ltd.']);
  assert.equal(v.TEL, '+44 20 7946 0000');
  assert.deepEqual(vcardParts(v.ADR), ['', '', '', 'London', '', '', '']);
  assert.deepEqual(vcardParts(v.NOTE), ['Line 1\nLine 2; more']);
  assert.equal('TITLE' in v, false, 'empty fields are left out');
});

test('vCard needs a name or an organisation', () => {
  assert.deepEqual(vcardPayload({ phone: '1' }), { error: 'name' });
  assert.equal(parseVcard(vcardPayload({ org: 'ACME' }).payload).FN, 'ACME');
});

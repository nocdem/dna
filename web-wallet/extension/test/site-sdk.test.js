// Node >=22.14, Playwright Chromium, the freshly built site SDK WASM and
// native vector (build-nodus-send-native-vector.sh). No external service;
// browser parity uses an ephemeral loopback server, closed on completion.
// Native signatures are positive controls: JS never signs or hashes here.
// Missing artifacts fail explicitly; no skip can masquerade as parity.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { chromium } from 'playwright';
import { addressOf, connect, createNodusConnector, signMessage, verify } from '../site-sdk/index.mjs';

const origin = 'https://iyi.com', message = 'Sign in: public test challenge \u00e9';
function native(seed = '01'.repeat(32), text = message, site = origin) {
  return Object.fromEntries(execFileSync(process.env.NODUS_SEND_VECTOR_BIN || '/tmp/nodus-send-native-vector',
    ['site-message', '--seed', seed, '--origin', site, '--message', Buffer.from(text).toString('hex'),
      '--sign-random', '02'.repeat(32)], { encoding: 'utf8' }).trim().split('\n').map(row => row.split('=')));
}
function cases() {
  const signed = native(), other = native('03'.repeat(32));
  const valid = { origin, message, publicKey: `0x${signed.public_key}`, signature: `0x${signed.signature}` };
  return [[valid, true], [{ ...valid, origin: 'https://other.example' }, false],
    [{ ...valid, message: message + '!' }, false], [{ ...valid, publicKey: other.public_key }, false],
    [{ ...valid, signature: '0x00' }, false], [{ ...valid, origin: '' }, false]];
}

test('site SDK verifier accepts native C signatures only for the matching origin, message and key in Node', async () => {
  for (const [input, expected] of cases()) assert.equal(await verify(input), expected);
  const signed = native();
  assert.equal(await verify({ origin, message: new TextEncoder().encode(message),
    publicKey: Uint8Array.from(Buffer.from(signed.public_key, 'hex')),
    signature: Uint8Array.from(Buffer.from(signed.signature, 'hex')) }), true);
  for (const text of ['', 'abc', '0x1234']) {
    const fixture = native(undefined, text);
    assert.equal(await verify({ origin, message: text, publicKey: fixture.public_key, signature: fixture.signature }), true);
  }
});

test('addressOf matches the native vector address for hex and byte public keys', async () => {
  for (const seed of ['01'.repeat(32), '03'.repeat(32)]) {
    const signed = native(seed);
    assert.match(signed.address, /^[0-9a-f]{128}$/);
    for (const publicKey of [signed.public_key, `0x${signed.public_key.toUpperCase()}`,
      Uint8Array.from(Buffer.from(signed.public_key, 'hex'))]) {
      assert.equal(await addressOf(publicKey), signed.address);
    }
  }
  for (const publicKey of [undefined, null, '0x', 'gg'.repeat(2592), new Uint8Array(2591)]) {
    await assert.rejects(addressOf(publicKey), TypeError);
  }
});

test('the shipped verifier exposes verification, address hashing and allocation, with no signing or secret-key entry points', () => {
  const wasm = new WebAssembly.Module(readFileSync(new URL('../site-sdk/nodus-site-verify.wasm', import.meta.url)));
  const names = WebAssembly.Module.exports(wasm).map(entry => entry.name);
  assert.ok(names.includes('nsv_verify'));
  assert.ok(names.includes('nsv_address_of'));
  assert.ok(!names.some(name => /sign|keypair|seed|random/.test(name)), names.join(', '));
});

test('the same native C signature cases and address derivation work in a browser', async t => {
  const inputs = cases(), signed = native(), files = new Set(['index.mjs', 'nodus-site-verify.mjs', 'nodus-site-verify.wasm']);
  const server = createServer((req, res) => {
    const name = req.url.slice(1);
    if (name === '') { res.setHeader('Content-Type', 'text/html'); res.end('<!doctype html>'); return; }
    if (!files.has(name)) { res.writeHead(404); res.end(); return; }
    try {
      const bytes = readFileSync(new URL(`../site-sdk/${name}`, import.meta.url));
      res.setHeader('Content-Type', name.endsWith('.wasm') ? 'application/wasm' : 'text/javascript');
      res.end(bytes);
    } catch { res.writeHead(500); res.end(); }
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  const browser = await chromium.launch({ headless: true, executablePath: process.env.CHROMIUM_PATH || undefined }); t.after(() => browser.close());
  const page = await browser.newPage();
  await page.goto(`http://127.0.0.1:${server.address().port}/`);
  const results = await page.evaluate(async inputs => {
    const { verify } = await import('/index.mjs');
    return Promise.all(inputs.map(([input]) => verify(input)));
  }, inputs);
  assert.deepEqual(results, inputs.map(([, expected]) => expected));
  assert.equal(await page.evaluate(async publicKey => {
    const { addressOf } = await import('/index.mjs');
    return addressOf(publicKey);
  }, signed.public_key), signed.address);
});

test('provider discovery uses the Nodus EIP-6963 identity; connect and sign send the exact methods and bytes', async () => {
  const window = Object.assign(new EventTarget(), { Event, CustomEvent });
  const account = { address: 'ab'.repeat(64), publicKey: '0x' + '12'.repeat(2592) }, calls = [];
  const beforeConnectCalls = [], otherRdnsCalls = [], otherNameCalls = [];
  const makeProvider = requests => ({ async request(args) {
    requests.push(args);
    if (args.method === 'nodus_requestAccounts') return [account];
    assert.equal(args.method, 'nodus_signMessage'); return '0x' + '34'.repeat(4627);
  } });
  const announcements = [
    { info: { name: 'Nodus Wallet', rdns: 'other.wallet' }, provider: makeProvider(otherRdnsCalls) },
    { info: { name: 'Other Wallet', rdns: 'io.nodusnetwork.wallet' }, provider: makeProvider(otherNameCalls) },
    { info: { name: 'Nodus Wallet', rdns: 'io.nodusnetwork.wallet' }, provider: makeProvider(calls) },
  ];
  const announce = detail => window.dispatchEvent(new CustomEvent('eip6963:announceProvider', { detail }));
  const flushMicrotasks = async () => { await Promise.resolve(); await Promise.resolve(); };
  const connector = createNodusConnector({ window });
  announce({ info: { name: 'Nodus Wallet', rdns: 'io.nodusnetwork.wallet' }, provider: makeProvider(beforeConnectCalls) });
  await flushMicrotasks();
  assert.deepEqual([beforeConnectCalls, otherRdnsCalls, otherNameCalls, calls], [[], [], [], []], 'no request before connect()');
  const pending = connector.connect();
  for (const detail of announcements.slice(0, 2)) {
    announce(detail);
    await flushMicrotasks();
    assert.deepEqual([otherRdnsCalls, otherNameCalls, calls], [[], [], []], 'another provider must never be called');
  }
  announce(announcements[2]);
  assert.deepEqual(await pending, account);
  assert.equal(await connector.signMessage('abc'), '0x' + '34'.repeat(4627));
  await connector.signMessage('0x1234');
  await connector.signMessage(new Uint8Array([0, 255, 128]));
  for (const message of ['', new Uint8Array(0)]) {
    await assert.rejects(connector.signMessage(message), /Invalid message "data"/);
  }
  assert.deepEqual(beforeConnectCalls, []); assert.deepEqual(otherRdnsCalls, []); assert.deepEqual(otherNameCalls, []);
  assert.deepEqual(calls, [{ method: 'nodus_requestAccounts' },
    { method: 'nodus_signMessage', params: ['0x616263', account.address] },
    { method: 'nodus_signMessage', params: ['0x307831323334', account.address] },
    { method: 'nodus_signMessage', params: ['0x00ff80', account.address] }]);
  assert.equal(typeof connect, 'function'); assert.equal(typeof signMessage, 'function');
});

test('discovery requests reannouncement and the optional plain button connects on click', async () => {
  const window = Object.assign(new EventTarget(), { Event, CustomEvent });
  const account = { address: 'ab'.repeat(64), publicKey: '0x' + '12'.repeat(2592) }, calls = [];
  window.addEventListener('eip6963:requestProvider', () => {
    calls.push('announce');
    window.dispatchEvent(new CustomEvent('eip6963:announceProvider', {
      detail: { info: { name: 'Nodus Wallet', rdns: 'io.nodusnetwork.wallet' },
        provider: { async request(args) { calls.push(args); return [account]; } } },
    }));
  });
  const connector = createNodusConnector({ window });
  const document = { createElement: tag => ({ tagName: tag }) };
  let connected;
  const button = connector.createConnectButton({ document, onConnect: value => { connected = value; } });
  assert.equal(button.tagName, 'button'); assert.equal(button.type, 'button');
  assert.equal(button.textContent, 'Connect with Nodus'); assert.deepEqual(calls, []);
  await button.onclick(); assert.deepEqual(connected, account);
  assert.deepEqual(calls, ['announce', { method: 'nodus_requestAccounts' }]);
});

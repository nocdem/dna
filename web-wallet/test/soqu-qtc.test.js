import test from 'node:test';
import assert from 'node:assert/strict';
import { bech32m } from '@scure/base';
import { readSoquBalances } from '../src/pq/soqucoin.js';
import { portfolioReaders } from '../extension/src/ui/wallet-page.js';
import { capabilitiesFor } from '../src/capabilities.js';
const address = (prefix, v) => bech32m.encode(prefix, [v, ...bech32m.toWords(new Uint8Array(32).fill(3))]);
const S = address('sq', 1);
function mock(...bodies) { const calls = []; return { calls, fetcher: async (url, options) => { calls.push(url); assert.equal(options.credentials, 'omit'); assert.equal(options.redirect, 'error'); const body = bodies.shift(); return body instanceof Response ? body : new Response(body); } }; }
const soqu = value => `{"address":"${S}","soq":{"confirmed":${value},"confirmed_soq":0.1},"usdsoq":{"confirmed":999}}`;
test('Soqu native confirmed integer precision, zero, and isolation', async () => {
  for (const [raw, expected] of [['0','0'], ['9007199254740993','90071992.54740993'], ['9223372036854775807','92233720368.54775807'], ['"100000001"','1.00000001']]) {
    const m = mock(soqu(raw)); assert.deepEqual(await readSoquBalances(S, m), [{ symbol: 'SOQ', balance: expected }]);
    assert.equal(m.calls[0], `https://mainnet-api.soqu.org/api/v2/multi-balance/${S}`);
  }
});
test('Soqu rejects ambiguous, malformed, wrong-account and noncanonical values', async () => {
  for (const value of ['null', '-1', '1.0', '1e2', '9223372036854775808', '"01"', '"-1"']) await assert.rejects(readSoquBalances(S, mock(soqu(value))));
  for (const body of [soqu('0').replace(S, address('sq', 1).replace(/.$/, 'a')), `{"address":"${S}","soq":{"confirmed":0,"confir\\u006ded":1}}`, `{"address":"${S}","soq":{"confirmed":0},"soq":{"confirmed":1}}`, '{bad', '{}']) await assert.rejects(readSoquBalances(S, mock(body)));
  for (const status of [404, 503]) await assert.rejects(readSoquBalances(S, mock(new Response('', { status }))), new RegExp(`HTTP ${status}`));
  await assert.rejects(readSoquBalances(S, { ...mock(), networkId: 'testnet' }));
  await assert.rejects(readSoquBalances(address('sq', 2), mock()));
  const c = new AbortController(); c.abort(); const m = mock(); await assert.rejects(readSoquBalances(S, { ...m, signal: c.signal })); assert.equal(m.calls.length, 0);
  const c2 = new AbortController(); await assert.rejects(readSoquBalances(S, { signal: c2.signal, fetcher: async () => { c2.abort(); return new Response(soqu('0')); } }));
});
test('Soqu extension public route honors explicit network and avoids secret access', async () => {
  const state = { networks: { soqucoin: 'testnet' } }; for (const key of ['wallet','phrase','keys','client']) Object.defineProperty(state, key, { get() { throw Error('secret'); } });
  const reader = portfolioReaders({ state, request() { throw Error('background'); } });
  assert.deepEqual(await reader.readBalances('soqucoin', S, '', { ...mock(soqu('0')), networkId: 'mainnet' }), [{ symbol: 'SOQ', balance: '0' }]);
  assert.equal(capabilitiesFor('soqucoin').balance, true); assert.equal(capabilitiesFor('soqucoin').history, false);
});
const { readQtcBalances } = await import('../src/pq/qtc.js');
const gen = { mainnet: 'd5f04a8a320b4e7bb454c7c564ca9cf191f70d7521d2486b62274df776f4eb24', testnet: 'efcba50d2de7cb16fd92423df899eba29e750b2271ef0ea64efe8cfeb4382ddf' };
const qa = n => address(n === 'mainnet' ? 'qtc' : 'tqtc', 2);
const chain = n => JSON.stringify({ chain: n === 'mainnet' ? 'main' : 'test' });
const block = n => `{"block":{"height":0,"hash":"${gen[n]}"}}`;
const record = (n, balance = '9007199254740993') => `{"address":{"address":"${qa(n)}","script":"5220${'03'.repeat(32)}","type":"witness","first_height":1,"tx_count":1,"received":${balance},"sent":0,"utxo_count":1},"balance":${balance}}`;
const empty = n => `{"address":{"address":"${qa(n)}","script":"","type":"","first_height":-1,"tx_count":0,"received":0,"sent":0,"utxo_count":0},"balance":0}`;
test('QTC exact confirmed indexed balances and validated empty sentinel', async () => {
  for (const n of ['mainnet', 'testnet']) {
    const m = mock(chain(n), block(n), record(n));
    assert.deepEqual(await readQtcBalances(qa(n), { ...m, networkId: n }), [{ symbol: 'QTC', balance: '90071992.54740993' }]);
    assert.ok(m.calls.every(url => url.startsWith(n === 'mainnet' ? 'https://qtc.events/' : 'https://testnet.qtc.events/')));
    assert.equal((await readQtcBalances(qa(n), { ...mock(chain(n), block(n), empty(n)), networkId: n }))[0].balance, '0');
    assert.equal((await readQtcBalances(qa(n), { ...mock(chain(n), block(n), record(n, '9223372036854775807')), networkId: n }))[0].balance, '92233720368.54775807');
  }
});
test('QTC rejects wrong identity, account, duplicates, malformed amounts, HTTP and cancellation', async () => {
  const n = 'mainnet';
  await assert.rejects(readQtcBalances(qa(n), mock(chain('testnet'))));
  await assert.rejects(readQtcBalances(qa(n), mock(chain(n), block('testnet'))));
  for (const bad of [record(n).replace(qa(n), qa('testnet')), record(n).replace('5220', '5221'), empty(n).replace('"tx_count":0', '"tx_count":1'), record(n, '9223372036854775808'), record(n, '1e2'), record(n).replace('"balance":', '"balance":0,"bal\\u0061nce":'), '{}', '{bad']) await assert.rejects(readQtcBalances(qa(n), mock(chain(n), block(n), bad)));
  for (const status of [404, 503]) await assert.rejects(readQtcBalances(qa(n), mock(chain(n), block(n), new Response('', { status }))), new RegExp(`HTTP ${status}`));
  await assert.rejects(readQtcBalances(qa('testnet'), mock()));
  const c = new AbortController(); c.abort(); const m = mock(); await assert.rejects(readQtcBalances(qa(n), { ...m, signal: c.signal })); assert.equal(m.calls.length, 0);
  const c2 = new AbortController(); let calls = 0; await assert.rejects(readQtcBalances(qa(n), { signal: c2.signal, fetcher: async () => { calls++; c2.abort(); return new Response(chain(n)); } })); assert.equal(calls, 1);
});
test('QTC extension honors explicit network without secret access', async () => {
  const state = { networks: { qtc: 'mainnet' } }; for (const key of ['wallet','phrase','keys','client']) Object.defineProperty(state, key, { get() { throw Error('secret'); } });
  const readers = portfolioReaders({ state, request() { throw Error('background'); } });
  assert.deepEqual(await readers.readBalances('qtc', qa('testnet'), '', { ...mock(chain('testnet'), block('testnet'), empty('testnet')), networkId: 'testnet' }), [{ symbol: 'QTC', balance: '0' }]);
  assert.equal(capabilitiesFor('qtc').balance, true); assert.equal(capabilitiesFor('qtc').history, false);
});

test('HTTP status is retained for sanitized UI error details', async () => {
  await assert.rejects(readSoquBalances(S, mock(new Response('', { status: 503 }))), error => error.status === 503);
});

test('provider error envelopes cannot masquerade as zero Soqu balances', async () => {
  for (const field of ['"error":"unavailable"', '"Error":"unavailable"', '"success":false']) {
    await assert.rejects(readSoquBalances(S, mock(soqu('0').replace('{', `{${field},`))));
  }
});

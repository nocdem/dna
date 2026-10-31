import test from 'node:test';
import assert from 'node:assert/strict';
import { bech32 } from '@scure/base';
import { readAsentumBalances } from '../src/pq/asentum.js';
import { portfolioReaders } from '../extension/src/ui/wallet-page.js';
import { capabilitiesFor } from '../src/capabilities.js';
import { PQ_NETWORKS } from '../src/pq/networks.js';
const bytes = new Uint8Array(20).fill(3);
const A = bech32.encode('ase', bech32.toWords(bytes));
const B = bech32.encode('ase', bech32.toWords(new Uint8Array(20).fill(4)));
const HEX = '0x' + '03'.repeat(20);
const genesisHash = '0xc12243eee53d0a642c34845575687144802b79eabb07b213815ee907f0451aa3';
const chain = { chainId: '1423' }, genesis = { chainId: '1423', genesisHash };
function mock(responses) {
  const calls = [];
  return { calls, fetcher: async (url, options) => {
    calls.push(url); assert.equal(options.method, 'GET'); assert.equal(options.credentials, 'omit'); assert.equal(options.redirect, 'error');
    return new Response(JSON.stringify(responses.shift()));
  } };
}
const data = (balance = '0', address = A) => [chain, genesis, { address, balance }];
test('testnet balances retain uint256 precision and explicitly read zero', async () => {
  const max = (2n ** 256n - 1n).toString(), m = mock(data(max, HEX));
  assert.deepEqual(await readAsentumBalances(A, m), [{ symbol: 'ASE', balance: '115792089237316195423570985008687907853269984665640564039457.584007913129639935' }]);
  assert.deepEqual(m.calls, ['https://testnet.asentum.com/chain', 'https://testnet.asentum.com/genesis', `https://testnet.asentum.com/balance/${A}`]);
  assert.equal((await readAsentumBalances(A, mock(data())))[0].balance, '0');
  assert.equal((await readAsentumBalances(A, mock(data('1000000000000000000'))))[0].balance, '1');
});
test('identity, account and decimal strings are mandatory on each read', async () => {
  for (const first of [{}, [], { chainId: 1423 }, { chainId: '1' }]) await assert.rejects(readAsentumBalances(A, mock([first])));
  for (const second of [{}, [], { chainId: '1423', genesisHash: 'wrong' }, { chainId: '1', genesisHash }]) await assert.rejects(readAsentumBalances(A, mock([chain, second])));
  for (const value of [undefined, null, 0, -1, '01', '1e6', '-1', (2n ** 256n).toString()]) await assert.rejects(readAsentumBalances(A, mock([chain, genesis, { address: A, balance: value }])));
  for (const wrong of [B, '0x' + '04'.repeat(20), HEX.toUpperCase(), undefined]) await assert.rejects(readAsentumBalances(A, mock([chain, genesis, { address: wrong, balance: '0' }])));
  const m = mock([...data(), { chainId: '1' }]); await readAsentumBalances(A, m); await assert.rejects(readAsentumBalances(A, m)); assert.equal(m.calls.length, 4);
});
test('invalid inputs, cancellation and provider errors fail closed', async () => {
  let calls = 0; const fetcher = async () => { calls++; return new Response('{}', { status: 503 }); };
  for (const value of ['invalid', A.toUpperCase(), bech32.encode('ase', bech32.toWords(new Uint8Array(19)))]) await assert.rejects(readAsentumBalances(value, { fetcher }));
  await assert.rejects(readAsentumBalances(A, { fetcher, networkId: 'mainnet' }));
  const c = new AbortController(); c.abort(); await assert.rejects(readAsentumBalances(A, { fetcher, signal: c.signal })); assert.equal(calls, 0);
  await assert.rejects(readAsentumBalances(A, { fetcher }), /HTTP 503/);
  const c2 = new AbortController(); let n = 0;
  await assert.rejects(readAsentumBalances(A, { signal: c2.signal, fetcher: async () => { n++; c2.abort(); return new Response(JSON.stringify(chain)); } })); assert.equal(n, 1);
});
test('extension routes public testnet reads and rejects other environments', async () => {
  const state = { networks: { asentum: 'testnet' } };
  for (const key of ['wallet', 'phrase', 'keys', 'client']) Object.defineProperty(state, key, { get() { throw Error('Secret accessed'); } });
  const readers = portfolioReaders({ state, request: () => { throw Error('Background accessed'); } });
  assert.deepEqual(await readers.readBalances('asentum', A, '', mock(data('1000000000000000001'))), [{ symbol: 'ASE', balance: '1.000000000000000001' }]);
  const m = mock([]); await assert.rejects(readers.readBalances('asentum', A, '', { ...m, networkId: 'mainnet' })); assert.equal(m.calls.length, 0);
  assert.equal(capabilitiesFor('asentum').balance, true); assert.equal(capabilitiesFor('asentum').history, false); assert.equal(PQ_NETWORKS.asentum.balanceUnavailable, false);
});

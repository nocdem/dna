import test from 'node:test';
import assert from 'node:assert/strict';
import { bech32 } from '@scure/base';
import { readXionBalances } from '../src/pq/xion.js';
import { readSplendorBalances } from '../src/pq/splendor.js';
import { portfolioReaders } from '../extension/src/ui/wallet-page.js';
import { capabilitiesFor } from '../src/capabilities.js';
const X = bech32.encode('xion', bech32.toWords(new Uint8Array(20).fill(3)));
const S = 'SQ:' + 'ab'.repeat(32);
const xi = n => ({ default_node_info: { network: n === 'mainnet' ? 'xion-mainnet-1' : 'xion-testnet-2' } });
const si = n => ({ chain_id: n === 'mainnet' ? 'splendor-quantum-1' : 'splendor-quantum-testnet-1', decimals: 18, fee_unit: 'smallest_spld' });
const account = balance => ({ address: S, balance, nonce: 0, has_public_key: false, state_root: '00'.repeat(32), block_height: 0 });
function mock(responses) { const calls = []; return { calls, fetcher: async (url, opts) => { calls.push(url); assert.equal(opts.credentials, 'omit'); assert.equal(opts.redirect, 'error'); const value = responses.shift(); return value instanceof Response ? value : new Response(JSON.stringify(value)); } }; }
for (const [name, read, address, identity, result, symbol, unit, expected] of [
  ['xion', readXionBalances, X, xi, n => ({ balance: { denom: 'uxion', amount: n } }), 'XION', '1000001', '1.000001'],
  ['splendor', readSplendorBalances, S, si, account, 'SPLD', '1000000000000000001', '1.000000000000000001']
]) {
  test(`${name} reads precise values and explicit zero on both networks`, async () => {
    for (const networkId of ['mainnet', 'testnet']) {
      const m = mock([identity(networkId), result(unit)]);
      assert.deepEqual(await read(address, { ...m, networkId }), [{ symbol, balance: expected }]);
      if (networkId === 'testnet') assert.ok(m.calls.every(url => url.includes('testnet')));
      assert.equal((await read(address, { ...mock([identity(networkId), result('0')]), networkId }))[0].balance, '0');
    }
  });
  test(`${name} rejects identity, shape, HTTP errors and abort`, async () => {
    await assert.rejects(read(address, mock([{}])));
    for (const value of [undefined, null, 0, '01', '-1', '1e3', (2n ** 256n).toString()]) await assert.rejects(read(address, mock([identity('mainnet'), result(value)])));
    for (const status of [404, 503]) await assert.rejects(read(address, mock([identity('mainnet'), new Response('', { status })])), new RegExp(`HTTP ${status}`));
    const c = new AbortController(); c.abort(); const m = mock([]); await assert.rejects(read(address, { ...m, signal: c.signal })); assert.equal(m.calls.length, 0);
    const c2 = new AbortController(); let calls = 0; await assert.rejects(read(address, { signal: c2.signal, fetcher: async () => { calls++; c2.abort(); return new Response(JSON.stringify(identity('mainnet'))); } })); assert.equal(calls, 1);
    await assert.rejects(read('bad', mock([])));
  });
  test(`${name} extension honors explicit environment without secret access`, async () => {
    const state = { networks: { [name]: 'mainnet' } };
    for (const key of ['wallet', 'phrase', 'keys', 'client']) Object.defineProperty(state, key, { get() { throw Error('Secret accessed'); } });
    const readers = portfolioReaders({ state, request() { throw Error('Background accessed'); } });
    assert.deepEqual(await readers.readBalances(name, address, '', { ...mock([identity('testnet'), result('0')]), networkId: 'testnet' }), [{ symbol, balance: '0' }]);
    assert.equal(capabilitiesFor(name).balance, true); assert.equal(capabilitiesFor(name).history, ['xion', 'splendor'].includes(name));
  });
}
test('Splendor rejects wrong account and incomplete committed view', async () => {
  for (const data of [{ ...account('0'), address: 'SQ:' + 'cd'.repeat(32) }, { ...account('0'), state_root: 'bad' }, { ...account('0'), nonce: -1 }]) await assert.rejects(readSplendorBalances(S, mock([si('mainnet'), data])));
});
test('XION rejects missing balance and wrong denomination', async () => {
  for (const data of [{}, { balance: null }, { balance: { denom: 'other', amount: '0' } }]) await assert.rejects(readXionBalances(X, mock([xi('mainnet'), data])));
});
test('CKB extension routes explicit testnet without secret access', async () => {
  const { bech32m } = await import('@scure/base');
  const { ckbNetwork } = await import('../src/pq/ckb.js');
  const network = ckbNetwork('testnet'), hash = '0x' + 'ab'.repeat(32);
  const payload = Uint8Array.from([0, ...Buffer.from(network.codeHash.slice(2), 'hex'), network.hashTypeByte, ...new Uint8Array(32)]);
  const address = bech32m.encode(network.prefix, bech32m.toWords(payload), 1023);
  const state = { networks: { ckb: 'mainnet' } };
  for (const key of ['wallet', 'phrase', 'keys', 'client']) Object.defineProperty(state, key, { get() { throw Error('Secret accessed'); } });
  const readers = portfolioReaders({ state, request() { throw Error('Background accessed'); } });
  const urls = [];
  const fetcher = async (url, options) => {
    urls.push(url); const req = JSON.parse(options.body);
    const result = req.method === 'get_cells_capacity' ? { capacity: '0x0', block_number: '0x1', block_hash: hash } : req.method === 'get_tip_block_number' ? '0x1' : req.params[0] === '0x0' ? network.genesisHash : hash;
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result }));
  };
  assert.deepEqual(await readers.readBalances('ckb', address, '', { networkId: 'testnet', fetcher }), [{ symbol: 'CKB', balance: '0' }]);
  assert.equal(urls.length, 4); assert.ok(urls.every(url => url === new URL(network.rpc).href));
  assert.equal(capabilitiesFor('ckb').balance, true); assert.equal(capabilitiesFor('ckb').history, false);
});

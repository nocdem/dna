import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { readIxiosBalance, IXIOS_GENESIS_HASH } from '../src/ixios/balance.js';
import { IXIOS_NETWORK } from '../src/ixios/network.js';
// Public fixture address (the checksummed Ixios address of the public test phrase).
const address = JSON.parse(readFileSync(new URL('./fixtures/ixios-checksum.json', import.meta.url))).vectors[0].Checksummed;
const endpoint = IXIOS_NETWORK.endpoint;
// ixiosSpark params/config.go:27, Ixios mainnet genesis.
const MAINNET_GENESIS = '0xa19acef59b3b84f192a69407981c50695fd105988d9311dd2e1c60332b629f2f';

// Replaces the global fetch (the one the wallet's readBalances path uses: it
// passes no fetcher) for one call, and records every JSON-RPC call made.
async function withFetch(results, run) {
  const calls = [], original = globalThis.fetch;
  globalThis.fetch = async (url, options) => {
    const body = JSON.parse(options.body);
    calls.push({ url, method: body.method, params: body.params });
    if (!Object.hasOwn(results, body.method)) throw new Error(`Unexpected RPC method ${body.method}`);
    return Response.json({ jsonrpc: '2.0', id: body.id, result: results[body.method] });
  };
  try { return { value: await run(), calls }; }
  catch (error) { error.calls = calls; throw error; }
  finally { globalThis.fetch = original; }
}
async function rejectsWith(results, pattern) {
  let calls;
  await assert.rejects(withFetch(results, () => readIxiosBalance(address, endpoint, {})).catch(error => { calls = error.calls; throw error; }), pattern);
  return calls;
}

test('the pinned genesis hash is Ixios mainnet', () => {
  assert.equal(IXIOS_GENESIS_HASH, MAINNET_GENESIS);
});

test('right genesis: the identity check runs first, then eth_getBalance; the balance is formatted with 18 decimals', async () => {
  const { value, calls } = await withFetch({
    eth_getBlockByNumber: { number: '0x1', parentHash: MAINNET_GENESIS },
    eth_getBalance: '0x' + (1234567n * 10n ** 15n).toString(16),
  }, () => readIxiosBalance(address, endpoint, {}));
  assert.deepEqual(value, [{ symbol: 'IXIOS', balance: '1234.567' }]);
  assert.deepEqual(calls.map(c => c.method), ['eth_getBlockByNumber', 'eth_getBalance']);
  // Block 1, never block 0: the real Ixios genesis block exceeds the transport's string cap.
  assert.deepEqual(calls[0].params, ['0x1', false]);
  assert.deepEqual(calls[1].params, [address, 'latest']);
  assert.ok(calls.every(c => c.url === endpoint + '/' || c.url === endpoint), calls.map(c => c.url).join());
});

test('a 0x0 balance formats as 0.0 without throwing', async () => {
  const { value } = await withFetch({ eth_getBlockByNumber: { number: '0x1', parentHash: MAINNET_GENESIS }, eth_getBalance: '0x0' }, () => readIxiosBalance(address, endpoint, {}));
  assert.deepEqual(value, [{ symbol: 'IXIOS', balance: '0.0' }]);
});

test('wrong genesis (for example an Ethereum RPC, whose chain id is also 1) throws before eth_getBalance', async () => {
  const ethereumGenesis = '0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3';
  for (const block of [{ number: '0x1', parentHash: ethereumGenesis }, { number: '0x1', parentHash: MAINNET_GENESIS.toUpperCase() },
    { number: '0x2', parentHash: MAINNET_GENESIS }, { number: '0x0', hash: MAINNET_GENESIS }, {}, null]) {
    const calls = await rejectsWith({ eth_getBlockByNumber: block, eth_getBalance: '0x1' }, /RPC is connected to the wrong network\./);
    assert.deepEqual(calls.map(c => c.method), ['eth_getBlockByNumber']);
  }
});

test('a malformed balance throws instead of becoming a number', async () => {
  for (const balance of ['abc', '-1', -1, 1.5, null, {}, '0x' + 'f'.repeat(65)]) {
    await rejectsWith({ eth_getBlockByNumber: { number: '0x1', parentHash: MAINNET_GENESIS }, eth_getBalance: balance }, /RPC returned (an invalid|an unsafe numeric) balance\./);
  }
});

test('an invalid Ixios address is refused before any request', async () => {
  for (const bad of ['0x' + '11'.repeat(20), address.slice(0, -2), address.toLowerCase().replace('0x', '')]) {
    let fetched = false;
    const original = globalThis.fetch;
    globalThis.fetch = async () => { fetched = true; throw new Error('Must not fetch'); };
    try { await assert.rejects(readIxiosBalance(bad, endpoint, {}), /Ixios address/); }
    finally { globalThis.fetch = original; }
    assert.equal(fetched, false);
  }
});

test('cancellation makes no request', async () => {
  const controller = new AbortController(); controller.abort();
  let fetched = false;
  const original = globalThis.fetch;
  globalThis.fetch = async () => { fetched = true; throw new Error('Must not fetch'); };
  try { await assert.rejects(readIxiosBalance(address, endpoint, { signal: controller.signal }), /cancelled/); }
  finally { globalThis.fetch = original; }
  assert.equal(fetched, false);
});

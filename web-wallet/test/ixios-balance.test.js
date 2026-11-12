import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { readIxiosBalance, IXIOS_GENESIS_HASH } from '../src/pq/ixios/balance.js';
import { IXIOS_NETWORK } from '../src/pq/ixios/network.js';
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

// ---- Ixios test network: added with the test-network entry ----
// What this proves: with {networkId:'testnet'} the balance read asks the test node (URL checked on every call) with
// ixios_ method names only, after identity by the TEST genesis; each entry refuses the other's genesis and makes no
// balance call afterwards; a main read, a test read and a main read in one process keep their own names (no cached entry);
// an unknown id makes no request. The main sequence is today's: eth_getBlockByNumber, eth_getBalance.
// Compile flags / environment: none (global fetch replaced for each call, restored in finally). Leaves nothing behind.
// Falsely passes if: a mock answered by method name without the URL (every call's URL is asserted), or the genesis
// literal came from the code (it is copied from docs/research-evidence/2026-11-12-ixios-testnet-rpc/probes.txt:52).
const TEST_ENDPOINT = 'https://nx-rpc.ixoflow.io';
const TEST_GENESIS = '0x33177fd0b2fb50907e5f6e17af05b3812881ab2d3effbf0a3493d9b665dfa5fe';
const sameUrl = (call, url) => call.url === url || call.url === url + '/';
test('test entry: identity by the test genesis first, then ixios_getBalance, both at the test URL', async () => {
  const { value, calls } = await withFetch({
    ixios_getBlockByNumber: { number: '0x1', parentHash: TEST_GENESIS },
    ixios_getBalance: '0x' + (5n * 10n ** 18n).toString(16),
  }, () => readIxiosBalance(address, TEST_ENDPOINT, { networkId: 'testnet' }));
  assert.deepEqual(value, [{ symbol: 'IXIOS', balance: '5.0' }]);
  assert.deepEqual(calls.map(c => c.method), ['ixios_getBlockByNumber', 'ixios_getBalance']);
  assert.deepEqual(calls[0].params, ['0x1', false]);
  assert.deepEqual(calls[1].params, [address, 'latest']);
  assert.ok(calls.every(c => sameUrl(c, TEST_ENDPOINT)), calls.map(c => c.url).join());
});
test('each entry refuses the other entry\'s genesis and makes no balance call after it', async () => {
  const wrongOnTest = await rejectsWithNet({ ixios_getBlockByNumber: { number: '0x1', parentHash: MAINNET_GENESIS }, ixios_getBalance: '0x1' }, TEST_ENDPOINT, 'testnet', /RPC is connected to the wrong network\./);
  assert.deepEqual(wrongOnTest.map(c => c.method), ['ixios_getBlockByNumber']);
  const wrongOnMain = await rejectsWithNet({ eth_getBlockByNumber: { number: '0x1', parentHash: TEST_GENESIS }, eth_getBalance: '0x1' }, endpoint, 'mainnet', /RPC is connected to the wrong network\./);
  assert.deepEqual(wrongOnMain.map(c => c.method), ['eth_getBlockByNumber']);
  const defaultIsMain = await rejectsWithNet({ eth_getBlockByNumber: { number: '0x1', parentHash: TEST_GENESIS }, eth_getBalance: '0x1' }, endpoint, undefined, /RPC is connected to the wrong network\./);
  assert.deepEqual(defaultIsMain.map(c => c.method), ['eth_getBlockByNumber']);
  for (const block of [{ number: '0x1', parentHash: TEST_GENESIS.toUpperCase() }, { number: '0x2', parentHash: TEST_GENESIS }, {}, null]) {
    const calls = await rejectsWithNet({ ixios_getBlockByNumber: block, ixios_getBalance: '0x1' }, TEST_ENDPOINT, 'testnet', /RPC is connected to the wrong network\./);
    assert.deepEqual(calls.map(c => c.method), ['ixios_getBlockByNumber']);
  }
});
test('main, test, main in one process: every entry keeps its own URL, names and genesis', async () => {
  const main = { eth_getBlockByNumber: { number: '0x1', parentHash: MAINNET_GENESIS }, eth_getBalance: '0x' + (1234567n * 10n ** 15n).toString(16) };
  const test_ = { ixios_getBlockByNumber: { number: '0x1', parentHash: TEST_GENESIS }, ixios_getBalance: '0x' + (7n * 10n ** 18n).toString(16) };
  const first = await withFetch(main, () => readIxiosBalance(address, endpoint, {}));
  const second = await withFetch(test_, () => readIxiosBalance(address, TEST_ENDPOINT, { networkId: 'testnet' }));
  const third = await withFetch(main, () => readIxiosBalance(address, endpoint, { networkId: 'mainnet' }));
  assert.deepEqual(first.value, [{ symbol: 'IXIOS', balance: '1234.567' }]);
  assert.deepEqual(second.value, [{ symbol: 'IXIOS', balance: '7.0' }]);
  assert.deepEqual(third.value, first.value);
  assert.deepEqual(first.calls.map(c => c.method), ['eth_getBlockByNumber', 'eth_getBalance']);
  assert.deepEqual(second.calls.map(c => c.method), ['ixios_getBlockByNumber', 'ixios_getBalance']);
  assert.deepEqual(third.calls.map(c => c.method), ['eth_getBlockByNumber', 'eth_getBalance']);
  assert.ok(first.calls.every(c => sameUrl(c, endpoint)) && third.calls.every(c => sameUrl(c, endpoint)));
  assert.ok(second.calls.every(c => sameUrl(c, TEST_ENDPOINT)));
});
test('an unknown network id throws before any request', async () => {
  for (const networkId of ['regtest', '', null, 3]) {
    let fetched = false;
    const original = globalThis.fetch;
    globalThis.fetch = async () => { fetched = true; throw new Error('Must not fetch'); };
    try { await assert.rejects(readIxiosBalance(address, TEST_ENDPOINT, { networkId }), /^Error: Unknown Ixios network\.$/); }
    finally { globalThis.fetch = original; }
    assert.equal(fetched, false, String(networkId));
  }
});
async function rejectsWithNet(results, url, networkId, pattern) {
  let calls;
  await assert.rejects(withFetch(results, () => readIxiosBalance(address, url, { networkId })).catch(error => { calls = error.calls; throw error; }), pattern);
  return calls;
}

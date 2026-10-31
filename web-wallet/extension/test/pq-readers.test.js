import test from 'node:test';
import assert from 'node:assert/strict';
import { base32 } from '@scure/base';
import { sha512_256 } from '@noble/hashes/sha512';
import { portfolioReaders } from '../src/ui/wallet-page.js';
import { algorandNetwork } from '../../src/pq/algorand.js';
const key = new Uint8Array(32).fill(3);
const ALGO = base32.encode(Uint8Array.from([...key, ...sha512_256(key).slice(-4)])).replace(/=+$/, '');
function fixture(chain, networkId) {
  const calls = [];
  return { calls, fetcher: async (url, options) => {
    calls.push({ url, options }); assert.equal(options.credentials, 'omit');
    let result;
    assert.equal(options.method, 'GET');
    result = url.includes('/params') ? { 'genesis-hash': algorandNetwork(networkId).genesisHash } : { address: ALGO, amount: '1234567' };
    return new Response(JSON.stringify(result));
  } };
}
function ui(networkId) {
  return { state: { networks: { algorand: networkId } }, request: () => { throw Error('Public PQ reads must not use background bridge'); } };
}
test('extension PQ public readers honor selected networks without background or key access', async () => {
  for (const chain of ['algorand']) for (const networkId of ['mainnet', 'testnet']) {
    const state = ui(networkId);
    for (const name of ['wallet', 'phrase', 'keys', 'client']) Object.defineProperty(state.state, name, { get() { throw Error('Secret state accessed'); } });
    const f = fixture(chain, networkId);
    const rows = await portfolioReaders(state).readBalances(chain, ALGO, 'https://ignored.invalid', f);
    assert.deepEqual(rows, [{ symbol: 'ALGO', balance: '1.234567' }]);
    const provider = algorandNetwork(networkId).algod;
    assert(f.calls.every(call => call.url.startsWith(new URL(provider).href)));
  }
});
test('extension PQ pending network selection overrides stored selection', async () => {
  const state = ui('mainnet'), readers = portfolioReaders(state);
  for (const chain of ['algorand']) {
    const f = fixture(chain, 'testnet');
    await readers.readBalances(chain, ALGO, '', { ...f, networkId: 'testnet' });
    assert(f.calls.every(call => call.url.includes('testnet')));
  }
});
test('extension PQ provider failures and invalid addresses propagate without fake zero', async () => {
  const readers = portfolioReaders(ui('mainnet'));
  for (const chain of ['algorand']) {
    let calls = 0;
    const fetcher = async () => { calls++; return new Response('', { status: 503 }); };
    await assert.rejects(readers.readBalances(chain, 'invalid', '', { fetcher })); assert.equal(calls, 0);
    await assert.rejects(readers.readBalances(chain, ALGO, '', { fetcher }), /HTTP 503/);
    const c = new AbortController(); c.abort();
    await assert.rejects(readers.readBalances(chain, ALGO, '', { fetcher, signal: c.signal }));
    assert.equal(calls, 1);
  }
});

test('extension CKB remains receive-only without invoking a provider', async () => {
  let calls = 0;
  await assert.rejects(portfolioReaders(ui('mainnet')).readBalances('ckb', 'unused', '', {
    fetcher: async () => { calls++; throw Error('Unexpected provider call'); }
  }), /Unsupported balance network/);
  assert.equal(calls, 0);
});

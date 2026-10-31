import test from 'node:test';
import assert from 'node:assert/strict';
import { base32 } from '@scure/base';
import { sha512_256 } from '@noble/hashes/sha512';
import { algorandNetwork, readAlgorandBalances, readAlgorandHistory } from '../src/pq/algorand.js';
function addr(n) {
  const key = new Uint8Array(32).fill(n);
  return base32.encode(new Uint8Array([...key, ...sha512_256(key).slice(-4)])).replace(/=+$/, '');
}
const A = addr(1), B = addr(2), C = addr(3), ID = 'A'.repeat(52);
function mock(responses) {
  const calls = [];
  return { calls, fetcher: async (url, options) => { calls.push(url); assert.equal(options.method, 'GET'); assert.equal(options.credentials, 'omit'); return new Response(JSON.stringify(responses.shift()), { status: 200 }); } };
}
const identity = (network = 'mainnet') => ({ 'genesis-hash': algorandNetwork(network).genesisHash });
function history(txs, network = 'mainnet') { return mock([{ ...identity(network), round: 0 }, { 'current-round': 10, transactions: txs }]); }
function tx(extra = {}) { return { id: ID, sender: A, 'tx-type': 'pay', 'confirmed-round': 2, 'round-time': 100, 'payment-transaction': { receiver: B, amount: 1234567 }, ...extra }; }

test('native balances retain exact uint64 precision and select pinned network', async () => {
  const m = mock([identity('testnet'), { address: A, amount: '18446744073709551615' }]);
  assert.deepEqual(await readAlgorandBalances(A, { ...m, networkId: 'testnet' }), [{ symbol: 'ALGO', balance: '18446744073709.551615' }]);
  assert(m.calls.every(url => url.startsWith('https://testnet-api.algonode.cloud/')));
  const zero = mock([identity(), { address: A, amount: 0 }]);
  assert.equal((await readAlgorandBalances(A, zero))[0].balance, '0');
});
test('wrong/missing genesis and malformed amounts never become zero', async () => {
  for (const response of [{}, { 'genesis-hash': 'wrong' }]) {
    const m = mock([response]);
    await assert.rejects(readAlgorandBalances(A, m), /wrong network/);
    assert.equal(m.calls.length, 1);
  }
  for (const amount of [undefined, null, -1, 1.5, Number.MAX_SAFE_INTEGER + 1, '18446744073709551616', '01', '1e6']) {
    await assert.rejects(readAlgorandBalances(A, mock([identity(), { address: A, amount }])));
  }
  await assert.rejects(readAlgorandBalances(A, mock([identity(), { address: B, amount: 0 }])), /different account/);
});
test('invalid checksum/network rejected before network access; abort prevents work', async () => {
  let calls = 0;
  const fetcher = async () => { calls++; throw new Error('must not fetch'); };
  await assert.rejects(readAlgorandBalances('A'.repeat(58), { fetcher }));
  await assert.rejects(readAlgorandBalances(A, { fetcher, networkId: 'devnet' }));
  const controller = new AbortController(); controller.abort();
  await assert.rejects(readAlgorandBalances(A, { fetcher, signal: controller.signal }));
  assert.equal(calls, 0);
});
test('cancellation between identity and data prevents second read', async () => {
  const controller = new AbortController(); let calls = 0;
  const fetcher = async () => { calls++; controller.abort(); return new Response(JSON.stringify(identity())); };
  await assert.rejects(readAlgorandBalances(A, { signal: controller.signal, fetcher }));
  assert.equal(calls, 1);
});
test('history verifies indexer genesis, bounds request, deduplicates payments', async () => {
  const m = history([tx(), tx()], 'testnet');
  const rows = await readAlgorandHistory(A, { ...m, networkId: 'testnet' });
  assert.deepEqual(rows, [{ chain: 'algorand', hash: ID, time: 100000, dir: 'out', symbol: 'ALGO', amount: '1.234567', peer: B, status: 'confirmed' }]);
  assert(m.calls[1].endsWith('/transactions?tx-type=pay&limit=50'));
  await assert.rejects(readAlgorandHistory(A, mock([{ ...identity('testnet'), round: 0 }])), /wrong network/);
  await assert.rejects(readAlgorandHistory(A, history([tx(), tx({ sender: B })])), /Conflicting/);
  await assert.rejects(readAlgorandHistory(A, history(Array(51).fill(tx()))), /Invalid Algorand history/);
});
test('payment closes aggregate external legs, retain incoming closes and omit fees', async () => {
  const close = { receiver: B, amount: 2000000, 'close-remainder-to': C, 'close-amount': 3000000 };
  let rows = await readAlgorandHistory(A, history([tx({ 'payment-transaction': close, fee: 1000 })]));
  assert.equal(rows[0].amount, '5'); assert.equal(rows[0].peer, '');
  rows = await readAlgorandHistory(C, history([tx({ 'payment-transaction': close })]));
  assert.equal(rows[0].amount, '3'); assert.equal(rows[0].dir, 'in'); assert.equal(rows[0].peer, A);
  rows = await readAlgorandHistory(A, history([tx({ 'payment-transaction': { receiver: A, amount: 10 } })]));
  assert.equal(rows[0].dir, 'self'); assert.equal(rows[0].amount, '0');
  await assert.rejects(readAlgorandHistory(A, history([tx({ 'payment-transaction': { receiver: B, amount: 0, 'close-remainder-to': C } })])));
});
test('malformed history and remote errors fail explicitly', async () => {
  for (const transactions of [undefined, {}, null]) await assert.rejects(readAlgorandHistory(A, mock([{ ...identity(), round: 0 }, { 'current-round': 10, transactions }])));
  for (const item of [tx({ 'round-time': Number.MAX_SAFE_INTEGER }), tx({ 'confirmed-round': 0 }), tx({ sender: C }), tx({ 'tx-type': 'axfer' })]) await assert.rejects(readAlgorandHistory(A, history([item])));
  await assert.rejects(readAlgorandBalances(A, { fetcher: async () => new Response('{}', { status: 503 }) }), /HTTP 503/);
  await assert.rejects(readAlgorandBalances(A, { fetcher: async () => new Response('{') }), /invalid JSON/);
  await assert.rejects(readAlgorandBalances(A, { fetcher: async () => new Response(' '.repeat(262145)) }), /too large/);
});

 test('zero payments preserve direction and peer, and invalid metadata is rejected', async () => {
  const zero = tx({ 'payment-transaction': { receiver: B, amount: 0 } });
  const outgoing = (await readAlgorandHistory(A, history([zero])))[0];
  assert.equal(outgoing.dir, 'out'); assert.equal(outgoing.amount, '0'); assert.equal(outgoing.peer, B);
  const incoming = (await readAlgorandHistory(B, history([zero])))[0];
  assert.equal(incoming.dir, 'in'); assert.equal(incoming.peer, A);
  const self = (await readAlgorandHistory(A, history([tx({ 'payment-transaction': { receiver: A, amount: 0 } })])))[0];
  assert.equal(self.dir, 'self'); assert.equal(self.amount, '0');
  for (const extra of [{ id: 2 }, { 'round-time': 0 }, { 'confirmed-round': 11 }]) await assert.rejects(readAlgorandHistory(A, history([tx(extra)])));
});
 test('every read rechecks identity and an explicit empty history is valid', async () => {
  const m = mock([identity(), { address: A, amount: 10 }, { 'genesis-hash': 'wrong' }]);
  await readAlgorandBalances(A, m);
  await assert.rejects(readAlgorandBalances(A, m), /wrong network/);
  assert.equal(m.calls.length, 3);
  assert.deepEqual(await readAlgorandHistory(A, history([])), []);
});

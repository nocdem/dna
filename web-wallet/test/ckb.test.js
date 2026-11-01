import test from 'node:test';
import assert from 'node:assert/strict';
import { bech32, bech32m } from '@scure/base';
import { ckbNetwork, readCkbBalances } from '../src/pq/ckb.js';
const H = '0x' + 'ab'.repeat(32);
function address(networkId = 'mainnet', mutate = x => x, codec = bech32m) {
  const n = ckbNetwork(networkId);
  const payload = Uint8Array.from([0, ...Buffer.from(n.codeHash.slice(2), 'hex'), n.hashTypeByte, ...new Uint8Array(32).fill(7)]);
  return codec.encode(n.prefix, codec.toWords(mutate(payload)), 1023);
}
function fixture({ networkId = 'mainnet', capacity = '0x1', indexed = '0x64', tip = '0x64', blockHash = H, genesis, snapshotHash = H, response } = {}) {
  const n = ckbNetwork(networkId), calls = [];
  return { calls, networkId, fetcher: async (url, options) => {
    const req = JSON.parse(options.body); calls.push({ url, ...req });
    assert.equal(options.method, 'POST'); assert.equal(options.credentials, 'omit');
    const result = req.method === 'get_cells_capacity' ? { capacity, block_number: indexed, block_hash: blockHash }
      : req.method === 'get_tip_block_number' ? tip : req.params[0] === '0x0' ? (genesis ?? n.genesisHash) : snapshotHash;
    return new Response(JSON.stringify(response ?? { jsonrpc: '2.0', id: 1, result }));
  } };
}
test('CKB fixed networks and exact-lock total capacity retain uint64 precision', async () => {
  for (const networkId of ['mainnet', 'testnet']) {
    const f = fixture({ networkId, capacity: '0xffffffffffffffff' });
    assert.deepEqual(await readCkbBalances(address(networkId), f), [{ symbol: 'CKB', balance: '184467440737.09551615' }]);
    assert.equal(f.calls.length, 4);
    assert(f.calls.every(c => c.url === new URL(ckbNetwork(networkId).rpc).href));
    assert.deepEqual(f.calls[1].params, [{ script: { code_hash: ckbNetwork(networkId).codeHash, hash_type: ckbNetwork(networkId).hashType, args: '0x' + '07'.repeat(32) }, script_type: 'lock', script_search_mode: 'exact' }]);
  }
  for (const [capacity, balance] of [['0x0', '0'], ['0x1', '0.00000001'], ['0x5f5e100', '1'], ['0x5f5e101', '1.00000001']]) {
    assert.equal((await readCkbBalances(address(), fixture({ capacity })))[0].balance, balance);
  }
});
test('CKB validates checksum, full payload, profile, prefix and network before reads', async () => {
  let count = 0; const fetcher = async () => { count++; throw Error('unexpected'); };
  const a = address();
  for (const value of [null, '', a.toUpperCase(), a.slice(0, -1) + (a.endsWith('q') ? 'p' : 'q'), address('testnet'), address('mainnet', x => x, bech32), address('mainnet', x => x.slice(0, -1)), address('mainnet', x => { x[0] = 1; return x; }), address('mainnet', x => { x[1] ^= 1; return x; }), address('mainnet', x => { x[33] = 2; return x; })]) await assert.rejects(readCkbBalances(value, { fetcher }));
  await assert.rejects(readCkbBalances(a, { networkId: 'devnet', fetcher }));
  assert.equal(count, 0);
});
test('CKB verifies genesis on every read, including repeated reads', async () => {
  const f = fixture(); await readCkbBalances(address(), f); await readCkbBalances(address(), f);
  assert.equal(f.calls.filter(c => c.method === 'get_block_hash' && c.params[0] === '0x0').length, 2);
  const wrong = fixture({ genesis: H }); await assert.rejects(readCkbBalances(address(), wrong), /wrong network/); assert.equal(wrong.calls.length, 1);
});
test('CKB rejects malformed and overflowing capacity/height without returning zero', async () => {
  for (const value of [undefined, null, 0, -1, '0', '0x', '0x00', '0x01', '0xA', '0x10000000000000000']) {
    await assert.rejects(readCkbBalances(address(), fixture({ capacity: value === undefined ? null : value })));
    await assert.rejects(readCkbBalances(address(), fixture({ indexed: value === undefined ? null : value })));
    await assert.rejects(readCkbBalances(address(), fixture({ tip: value === undefined ? null : value })));
  }
});
test('CKB rejects inconsistent snapshots and bounds indexer lag to 24 blocks', async () => {
  await assert.rejects(readCkbBalances(address(), fixture({ snapshotHash: '0x' + 'cd'.repeat(32) })), /does not match/);
  for (const blockHash of [null, '0x1', H.toUpperCase()]) await assert.rejects(readCkbBalances(address(), fixture({ blockHash })));
  await assert.rejects(readCkbBalances(address(), fixture({ tip: '0x63' })), /synchronized/);
  await assert.rejects(readCkbBalances(address(), fixture({ tip: '0x7d' })), /synchronized/);
  assert.equal((await readCkbBalances(address(), fixture({ tip: '0x7c' })))[0].balance, '0.00000001');
});
test('CKB missing, error, oversized and mismatched RPC replies fail closed', async () => {
  for (const response of [{}, { error: { code: -1 } }, { id: 2, result: H }, { jsonrpc: '1.0', result: H }]) await assert.rejects(readCkbBalances(address(), fixture({ response })));
  for (const result of [null, [], {}, { capacity: '0x0' }]) {
    const f = fixture(), fetcher = f.fetcher;
    f.fetcher = async (u, o) => JSON.parse(o.body).method === 'get_cells_capacity' ? new Response(JSON.stringify({ result })) : fetcher(u, o);
    await assert.rejects(readCkbBalances(address(), f));
  }
  await assert.rejects(readCkbBalances(address(), { fetcher: async () => new Response('x'.repeat(262145)) }), /too large/);
  await assert.rejects(readCkbBalances(address(), { fetcher: async () => new Response('', { status: 503 }) }), /HTTP 503/);
});
test('CKB cancellation prevents reads and stops between requests', async () => {
  const c = new AbortController(); c.abort(); const f = fixture();
  await assert.rejects(readCkbBalances(address(), { ...f, signal: c.signal })); assert.equal(f.calls.length, 0);
  const c2 = new AbortController(), f2 = fixture(), fetcher = f2.fetcher;
  await assert.rejects(readCkbBalances(address(), { signal: c2.signal, fetcher: async (u, o) => { const r = await fetcher(u, o); c2.abort(); return r; } }));
  assert.equal(f2.calls.length, 1);
});

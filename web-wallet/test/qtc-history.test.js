import test from 'node:test';
import assert from 'node:assert/strict';
import { bech32m } from '@scure/base';
import { readQtcHistory } from '../src/pq/qtc.js';
const address = bech32m.encode('qtc', [2, ...bech32m.toWords(new Uint8Array(32).fill(3))]);
const script = '5220' + '03'.repeat(32);
const chain = '{"chain":"main"}';
const block = '{"block":{"height":0,"hash":"d5f04a8a320b4e7bb454c7c564ca9cf191f70d7521d2486b62274df776f4eb24"}}';
function mock(data) { const responses = [chain, block, JSON.stringify(data)]; return { fetcher: async () => new Response(responses.shift()) }; }
const tx = { txid: 'ab'.repeat(32), height: '1', blocktime: '100', shielded: false, coinbase: false, vin: [{ txid: 'cd'.repeat(32), address, script, value: '300000000' }], vout: [{ address, script, value: '100000000' }] };
test('QTC indexed history gives exact net outgoing flow including fee', async () => {
  const rows = await readQtcHistory(address, mock({ total: '1', txs: [tx] }));
  assert.deepEqual(rows, [{ chain: 'qtc', hash: tx.txid, time: 100000, dir: 'out', symbol: 'QTC', amount: '2', peer: '', status: 'confirmed' }]);
});
test('QTC history rejects wrong script, shielded and malformed rows', async () => {
  for (const bad of [{ ...tx, vin: [{ ...tx.vin[0], script: '00' }] }, { ...tx, shielded: true }, { ...tx, blocktime: '-1' }]) assert.deepEqual(await readQtcHistory(address, mock({ total: '1', txs: [bad] })), []);
  await assert.rejects(readQtcHistory(address, mock({ total: '0', txs: {} })));
});

test('duplicates fail closed, including conflicting or malformed records', async () => {
  await assert.rejects(readQtcHistory(address, mock({ total: '2', txs: [tx, { ...tx, height: '0' }] })), /Duplicate/);
});
test('ambiguous address-script ownership and genesis rows are omitted', async () => {
  for (const bad of [
    { ...tx, height: '0' },
    { ...tx, vin: [{ ...tx.vin[0], address: undefined }] },
    { ...tx, vout: [{ ...tx.vout[0], address: 'other' }] },
    { ...tx, vout: [{ ...tx.vout[0], script: '00' }] },
  ]) assert.deepEqual(await readQtcHistory(address, mock({ total: '1', txs: [bad] })), []);
});
test('coinbase index schema and exact high precision receipt', async () => {
  const coinbase = { ...tx, coinbase: true, vin: [{ coinbase: '0102', value: '0', vout: '0', sequence: '0' }], vout: [{ address, script, value: '9007199254740993' }] };
  const rows = await readQtcHistory(address, mock({ total: '1', txs: [coinbase] }));
  assert.equal(rows[0].amount, '90071992.54740993'); assert.equal(rows[0].dir, 'in');
  assert.deepEqual(await readQtcHistory(address, mock({ total: '1', txs: [{ ...coinbase, vin: [{ ...coinbase.vin[0], value: '1' }] }] })), []);
});
test('network identity and cancellation fail closed', async () => {
  const badNetwork = { fetcher: async () => new Response('{"chain":"test"}') };
  await assert.rejects(readQtcHistory(address, badNetwork), /wrong network/);
  await assert.rejects(readQtcHistory(address, { networkId: 'testnet' }), /witness address/);
  const controller = new AbortController(); controller.abort(); let called = false;
  await assert.rejects(readQtcHistory(address, { signal: controller.signal, fetcher: async () => { called = true; } }));
  assert.equal(called, false);
  const during = new AbortController(); let calls = 0;
  await assert.rejects(readQtcHistory(address, { signal: during.signal, fetcher: async () => { calls++; during.abort(); return new Response(chain); } }));
  assert.equal(calls, 1);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { checkActivity, watchActivity } from '../src/activity.js';
const hash = '0x' + 'a'.repeat(64), blockHash = '0x' + 'b'.repeat(64);
const row = { chain: 'ethereum', hash, endpoint: 'https://rpc.example', status: 'pending' };
test('EVM waits for canonical finality, distinguishes execution failure and reorg', async () => {
  let receipt = null, final = '0x9', canonical = blockHash;
  const call = async (_, method, params) => ({ eth_chainId: '0x1', eth_getTransactionReceipt: receipt, eth_getBlockByNumber: params[0] === 'finalized' ? { number: final } : { hash: canonical } })[method];
  assert.equal((await checkActivity(row, { call })).status, 'pending');
  receipt = { transactionHash: hash, blockHash, blockNumber: '0xa', status: '0x1' };
  assert.equal((await checkActivity(row, { call })).status, 'included');
  canonical = '0x' + 'c'.repeat(64); assert.equal((await checkActivity(row, { call })).status, 'pending');
  canonical = blockHash; final = '0xb'; assert.equal((await checkActivity(row, { call })).status, 'confirmed');
  receipt.status = '0x0'; assert.equal((await checkActivity(row, { call })).status, 'failed');
  receipt = null; assert.equal((await checkActivity(row, { call })).status, 'pending');
  await assert.rejects(checkActivity(row, { call: async () => '0x38' }), /Wrong network/);
});
test('Solana requires finalized status, preserves error, and checks expiry only after history lookup', async () => {
  const sol = { ...row, chain: 'solana', hash: '1'.repeat(88), lastValidBlockHeight: 100 };
  let status = null, height = 99;
  const call = async (_, method) => ({ getGenesisHash: '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d', getSignatureStatuses: { value: [status] }, getBlockHeight: height })[method];
  assert.equal((await checkActivity(sol, { call })).status, 'pending');
  height = 101; assert.equal((await checkActivity(sol, { call })).status, 'expired');
  status = { err: null, confirmationStatus: 'confirmed' }; assert.equal((await checkActivity(sol, { call })).status, 'included');
  status.confirmationStatus = 'finalized'; assert.equal((await checkActivity(sol, { call })).status, 'confirmed');
  status.err = { InstructionError: [0, 'failed'] }; assert.equal((await checkActivity(sol, { call })).status, 'failed');
});
test('TRON uses solidified transaction execution result, never infers failure from absence', async () => {
  const tron = { ...row, chain: 'tron', hash: 'a'.repeat(64), endpoint: 'https://api.trongrid.io' }; let tx = {};
  const post = async path => path.endsWith('getblockbynum') ? { blockID: '00000000000000001ebf88508a03865c71d452e25f4d51194196a1d22b6653dc' } : tx;
  assert.equal((await checkActivity(tron, { post })).status, 'pending');
  tx = { txID: tron.hash, ret: [{ contractRet: 'SUCCESS' }] }; assert.equal((await checkActivity(tron, { post })).status, 'confirmed');
  tx.ret[0].contractRet = 'REVERT'; assert.equal((await checkActivity(tron, { post })).status, 'failed');
});
test('tracking preserves state on transient failure and ignores results after cancellation', async () => {
  let updates = 0, finish;
  const item = { ...row, status: 'included' };
  const stop = watchActivity(() => [item], () => updates++, { interval: 999999, check: () => new Promise(resolve => { finish = resolve; }) });
  stop(); finish({ status: 'confirmed' }); await new Promise(resolve => setImmediate(resolve));
  assert.equal(updates, 0); assert.equal(item.status, 'included');
  const stop2 = watchActivity(() => [item], () => updates++, { interval: 999999, check: async () => { throw Error('offline'); } });
  await new Promise(resolve => setImmediate(resolve)); stop2();
  assert.equal(item.status, 'included'); assert.match(item.readError, /offline/);
});

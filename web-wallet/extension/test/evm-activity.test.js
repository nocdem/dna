import test from 'node:test';
import assert from 'node:assert/strict';
import { Messenger } from '@metamask/messenger';
import { createEvm } from '../src/background/evm.js';
import { createLockCoordinator } from '../src/background/lock.js';
import { deriveWallet, disposeWallet } from '../../src/keys.js';
import { recordActivity } from '../../src/activity.js';
import { keccak256 } from 'ethers';
import { walletSession } from './fixtures/wallet-session.js';
import { chainNetwork } from '../src/constants/networks.js';

// Package B1: real adapter, real signer; HTTPS fixture only. No flags or
// artifacts. Merely checking rows after send misses pre-broadcast durability.
test('EVM records before broadcast, rejects another pending send and cancels on lock', async t => {
  const wallet = deriveWallet('abandon '.repeat(23) + 'art'), rows = [], writes = [];
  const lockCoordinator = createLockCoordinator(); await lockCoordinator.unlock(async () => {});
  const activity = { rows: () => rows, assertSendable() {}, client: null,
    append(transfer, details) { const row = recordActivity(transfer, details); rows.push(row); return row; },
    async persist() { writes.push(rows.map(row => ({ ...row }))); } };
  t.mock.method(globalThis, 'fetch', async (_url, options) => {
    const req = JSON.parse(typeof options.body === 'string' ? options.body : new TextDecoder().decode(options.body));
    const values = { eth_chainId: '0x1', eth_getBalance: '0x8ac7230489e80000', eth_estimateGas: '0x5208',
      eth_gasPrice: '0x3b9aca00', eth_maxPriorityFeePerGas: '0x3b9aca00', eth_getTransactionCount: '0x7', eth_getTransactionReceipt: null,
      eth_getBlockByNumber: { number: '0x10', hash: '0x' + '11'.repeat(32), parentHash: '0x' + '22'.repeat(32), timestamp: '0x1', nonce: '0x0000000000000000',
        difficulty: '0x0', gasLimit: '0x1c9c380', gasUsed: '0x0', miner: '0x0000000000000000000000000000000000000001', extraData: '0x', transactions: [] } };
    let result = values[req.method];
    if (req.method === 'eth_sendRawTransaction') { assert.equal(writes[0][0].hash, keccak256(req.params[0])); result = keccak256(req.params[0]); }
    else assert.ok(Object.hasOwn(values, req.method), req.method);
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: req.id, result }));
  });
  const evm = createEvm({ messenger: new Messenger({ namespace: 'B1Test' }),
    store: { getInitialState: () => ({}), flush: async () => {} }, approvals: {}, permissions: {}, lockCoordinator,
    getWallet: () => wallet, getActivity: () => activity, onNetworkChanged() {} });
  t.after(() => { evm.destroy(); disposeWallet(wallet); });
  const fields = { chain: 'ethereum', symbol: 'ETH', to: '0x0000000000000000000000000000000000000001', amount: '0.01' };
  const review = await evm.prepareSend(fields);
  assert.deepEqual(review.review.map(row => row[0]), ['Network', 'From', 'To', 'Address check', 'Asset', 'Amount', 'Network fee', 'Transaction number (nonce)', 'Review expires']);
  await evm.confirmSend(review.id);
  await assert.rejects(evm.prepareSend(fields), /previous send/);
  await lockCoordinator.lock();
  await assert.rejects(evm.confirmSend(review.id), /closed|locked/);
});

// B1: both shared mainnet records and a populated testnet bucket are eligible;
// Nodus/final/missing rows are not. No flags/network/artifacts. Testing only
// Ethereum would miss the separate testnet encrypted writer.
test('abandon is restricted to non-terminal non-Nodus activity in the selected network', async t => {
  const { nodus, addresses } = await walletSession(t);
  for (const [chain, networkId, hash] of [['ethereum', 'mainnet', '0x' + '11'.repeat(32)], ['bsc', 'mainnet', '0x' + '22'.repeat(32)],
    ['solana', 'mainnet', '1'.repeat(88)], ['tron', 'mainnet', '33'.repeat(32)], ['solana', 'devnet', '2'.repeat(88)]]) {
    const network = chainNetwork(chain, networkId), activity = nodus.chainActivity(chain, networkId); await activity.ready;
    activity.append({ chain, from: addresses[chain], to: addresses[chain], symbol: { ethereum: 'ETH', bsc: 'BNB', solana: 'SOL', tron: 'TRX' }[chain], amount: '1', endpoint: network.endpoint }, { hash, nonce: 7 });
    await activity.persist(); await nodus.abandonActivity(chain, hash, networkId);
    assert.equal(activity.rows().find(row => row.hash === hash).status, 'abandoned');
    await assert.rejects(nodus.abandonActivity(chain, hash, networkId), /cannot be abandoned/);
  }
  await assert.rejects(nodus.abandonActivity('nodus', 'ab'.repeat(64)), /cannot be abandoned/);
  await assert.rejects(nodus.abandonActivity('ethereum', '0x' + '44'.repeat(32)), /cannot be abandoned/);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { setup } from './solana-tron-fixture.js';
import { extensionCapabilitiesFor, extensionNetworkConfig, extensionPageSupported } from '../src/constants/capabilities.js';
import { chainNetwork } from '../src/constants/networks.js';
import { PQ_NETWORKS } from '../../src/pq/networks.js';
import { ckbNetwork } from '../../src/pq/ckb.js';
import { createWalletUi } from '../src/ui/wallet-ui.js';

test('CKB trusted send is mainnet-only and inaccessible to websites', async t => {
  const { background, client } = await setup(t);
  for (const network of ['mainnet', 'testnet']) {
    assert.equal(extensionCapabilitiesFor('ckb', network).send, network === 'mainnet');
    assert.equal(extensionNetworkConfig('ckb', PQ_NETWORKS.ckb, network).receiveOnly, network !== 'mainnet');
    assert.equal(extensionCapabilitiesFor('ckb', network).history, true);
    assert.equal(extensionPageSupported('ckb', 'wallet-activity', network), true);
    assert.equal(extensionPageSupported('ckb', 'send', network), network === 'mainnet');
    assert.equal(chainNetwork('ckb', network).endpoint, ckbNetwork(network).rpc);
    await client.request('setChainNetwork', ['ckb', network]);
    if (network !== 'mainnet') for (const [method, arg] of [['prepareCkbSend', {}], ['prepareCkbResubmit', '0x' + 'ff'.repeat(32)], ['confirmCkbSend', '1']])
      await assert.rejects(client.request(method, [arg]), /not enabled/);
  }
  assert.equal(extensionCapabilitiesFor('ckb', 'unknown').send, false);
  const { engine } = background.engine.setupProviderEngineEip1193({ origin: 'https://site.example', subjectType: 'website' });
  try { for (const method of ['prepareCkbSend', 'prepareCkbResubmit', 'confirmCkbSend']) assert.ok((await engine.handle({ id: 1, jsonrpc: '2.0', method, params: [] })).error); }
  finally { engine.destroy(); }
});

test('CKB UI adapter preserves fields across trusted boundary', async () => {
  const calls = [], ui = createWalletUi({ async request(method, args) { calls.push([method, args]); if (method === 'getState') return { isUnlocked: true, addresses: {}, pqAddresses: { ckb: { mainnet: 'synthetic' } }, networks: { ckb: 'mainnet' } }; return {}; } });
  await ui.refresh();
  await ui.prepareSolanaTronSend({ chain: 'ckb', symbol: 'CKB', to: 'recipient', amount: '73' });
  assert.deepEqual(calls.at(-1), ['prepareCkbSend', [{ symbol: 'CKB', to: 'recipient', amount: '73' }]]);
});

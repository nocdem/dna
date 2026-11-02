import test from 'node:test';
import assert from 'node:assert/strict';
import { setup } from './solana-tron-fixture.js';
import { extensionCapabilitiesFor, extensionNetworkConfig } from '../src/constants/capabilities.js';
import { chainNetwork } from '../src/constants/networks.js';
import { PQ_NETWORKS } from '../../src/pq/networks.js';
import { createWalletUi } from '../src/ui/wallet-ui.js';

test('QTC trusted send and recovery are mainnet-only and inaccessible to websites', async t => {
  const { background, client } = await setup(t);
  for (const network of ['mainnet', 'testnet']) {
    assert.equal(extensionCapabilitiesFor('qtc', network).send, network === 'mainnet');
    assert.equal(extensionNetworkConfig('qtc', PQ_NETWORKS.qtc, network).receiveOnly, network !== 'mainnet');
    assert.equal(chainNetwork('qtc', network).endpoint, network==='mainnet'?'https://qtc.events':'https://testnet.qtc.events');
    await client.request('setChainNetwork', ['qtc', network]);
    if (network !== 'mainnet') for (const [method, arg] of [['prepareQtcSend', {}], ['prepareQtcResubmit', 'ff'.repeat(32)], ['confirmQtcSend', '1']])
      await assert.rejects(client.request(method, [arg]), /not enabled/);
  }
  assert.equal(extensionCapabilitiesFor('qtc', 'unsupported').send, false);
  const { engine } = background.engine.setupProviderEngineEip1193({ origin: 'https://site.example', subjectType: 'website' });
  try { for (const method of ['prepareQtcSend', 'prepareQtcResubmit', 'confirmQtcSend']) assert.ok((await engine.handle({ id: 1, jsonrpc: '2.0', method, params: [] })).error); }
  finally { engine.destroy(); }
});

test('QTC UI adapter preserves fields across trusted boundary', async () => {
  const calls = [], ui = createWalletUi({ async request(method, args) { calls.push([method, args]); if (method === 'getState') return { isUnlocked: true, addresses: {}, pqAddresses: { qtc: { mainnet: 'synthetic' } }, networks: { qtc: 'mainnet' } }; return {}; } });
  await ui.refresh();
  await ui.prepareSolanaTronSend({ chain: 'qtc', symbol: 'QTC', to: 'recipient', amount: '1' });
  assert.deepEqual(calls.at(-1), ['prepareQtcSend', [{ symbol: 'QTC', to: 'recipient', amount: '1' }]]);
});
test('QTC full background creates separate authenticated network buckets and exposes recovery only on enabled mainnet',async t=>{const {readFileSync}=await import('node:fs'),{ACTIVITY_KEY,VAULT_KEY,parseVault}=await import('../../src/vault.js'),{activityKeyFor,parseActivity}=await import('../../src/activity-storage.js'),{phrase}=await import('./solana-tron-fixture.js');const {background,client,values}=await setup(t),addresses=JSON.parse(readFileSync(new URL('../../test/fixtures/pq-receive.json',import.meta.url))).vectors[0].addresses.qtc;t.mock.method(background.walletKeys,'getPqAddresses',()=>({qtc:addresses}));for(const [index,networkId]of ['mainnet','testnet'].entries()){const a=background.nodus.chainActivity('qtc',networkId);await a.ready;const review={from:addresses[networkId],to:addresses[networkId],amount:'100000000',fee:'1000',outpoints:[`${'ab'.repeat(32)}:${index}`]};await a.appendQtcPendingWithProof(review,{...review,networkId,state:'signed-exposure-pending',txid:String(index+1).repeat(64)});await a.persist();}const id=parseVault(values[VAULT_KEY]).id,key=await activityKeyFor(phrase,id);for(const networkId of ['mainnet','testnet']){const rows=await parseActivity(values[`${ACTIVITY_KEY}.qtc.${networkId}`],id,{qtc:addresses[networkId]},key);assert.equal(rows.length,1);assert.equal(rows[0].networkId,networkId);}t.mock.method(background.qtc,'getHistory',()=>({rows:[],local:[{hash:'aa'.repeat(32),canResubmit:true}]}));const h=await client.request('getQtcHistory');assert.equal(h.local[0].canResubmit,true);await client.request('setChainNetwork',['qtc','testnet']);assert.equal((await client.request('getQtcHistory')).local[0].canResubmit,false);});

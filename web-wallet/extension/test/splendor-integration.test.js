import test from 'node:test';import assert from 'node:assert/strict';
import {setup} from './solana-tron-fixture.js';
import {chainNetwork} from '../src/constants/networks.js';
import {extensionCapabilitiesFor,extensionNetworkConfig} from '../src/constants/capabilities.js';
import {PQ_NETWORKS} from '../../src/pq/networks.js';
import {ACTIVITY_KEY,VAULT_KEY,parseVault} from '../../src/vault.js';
import {activityKeyFor,parseActivity} from '../../src/activity-storage.js';
import {phrase} from './solana-tron-fixture.js';
import {createWalletUi} from '../src/ui/wallet-ui.js';

test('Splendor trusted RPC composition routes wallet operations only; selected endpoint is fixed',async t=>{
 const {background,client}=await setup(t),calls=[];
 for(const [method,result] of [['getBalances',[]],['getHistory',{rows:[],local:[]}],['prepareSend',{id:'send'}],['prepareResubmit',{id:'recovery'}],['confirmOperation','hash'],['cancelOperation',undefined]])t.mock.method(background.splendor,method,(...args)=>{calls.push([method,args]);return result;});
 assert.deepEqual(await client.request('getSplendorBalances'),[]);await client.request('getSplendorHistory',[{manual:true}]);
 assert.deepEqual(await client.request('prepareSplendorSend',[{symbol:'SPLD',to:'recipient',amount:'1'}]),{id:'send'});
 assert.deepEqual(await client.request('prepareSplendorResubmit',['oldhash']),{id:'recovery'});
 assert.equal(await client.request('confirmSplendorSend',['recovery']),'hash');await client.request('cancelSplendorSend',['send']);
 assert.deepEqual(calls.map(c=>c[0]),['getBalances','getHistory','prepareSend','prepareResubmit','confirmOperation','cancelOperation']);
 assert.equal(chainNetwork('splendor','mainnet').endpoint,'https://quantum-rpc.splendor.org');assert.equal(chainNetwork('splendor','testnet').endpoint,'https://quantum-rpc-testnet.splendor.org');assert.throws(()=>chainNetwork('splendor','devnet'));
 await client.request('setChainNetwork',['splendor','testnet']);await assert.rejects(client.request('prepareSplendorSend',[{symbol:'SPLD',to:'recipient',amount:'1'}]),/mainnet/);await assert.rejects(client.request('prepareSplendorResubmit',['oldhash']),/mainnet/);
});
test('real Nodus activity composition separates Splendor main/test encrypted nonce reservations',async t=>{
 const {background,values}=await setup(t),address='SQ:'+'11'.repeat(32),to='SQ:'+'22'.repeat(32);
 t.mock.method(background.walletKeys,'getPqAddresses',()=>({splendor:{mainnet:address,testnet:address}}));
 for(const [index,networkId]of ['mainnet','testnet'].entries()){
  const activity=background.nodus.chainActivity('splendor',networkId);await activity.ready;
  const review={from:address,to,amountAtoms:'100',feeAtoms:'1000',nonce:String(index)};
  await activity.appendSplendorPendingWithProof(review,{networkId,from:address,to,amount:'100',fee:'1000',nonce:String(index),hash:String(index+1).repeat(64)});await activity.persist();
 }
 const id=parseVault(values[VAULT_KEY]).id,key=await activityKeyFor(phrase,id);
 for(const [index,networkId]of ['mainnet','testnet'].entries()){
  const rows=await parseActivity(values[`${ACTIVITY_KEY}.splendor.${networkId}`],id,{splendor:address},key);assert.equal(rows.length,1);assert.equal(rows[0].networkId,networkId);assert.equal(rows[0].nonce,String(index));
 }
});
test('Splendor native send is mainnet-only and UI drops old-network history',async()=>{
 for(const id of ['testnet',undefined]){assert.equal(extensionCapabilitiesFor('splendor',id).send,false);assert.equal(extensionNetworkConfig('splendor',PQ_NETWORKS.splendor,id).receiveOnly,true);}
 assert.equal(extensionCapabilitiesFor('splendor','mainnet').send,true);assert.equal(extensionNetworkConfig('splendor',PQ_NETWORKS.splendor,'mainnet').receiveOnly,false);
 let resolve,network='mainnet';const pending=new Promise(r=>resolve=r),calls=[];
 const ui=createWalletUi({async request(method,args){calls.push([method,args]);if(method==='getState')return {isUnlocked:true,addresses:{},pqAddresses:{splendor:{mainnet:'m',testnet:'t'}},networks:{splendor:network}};if(method==='getSplendorHistory')return pending;return {};}});
 await ui.refresh();await ui.prepareSolanaTronSend({chain:'splendor',symbol:'SPLD',to:'recipient',amount:'1'});await ui.confirmSolanaTronSend('splendor','id');await ui.cancelSolanaTronSend('splendor','id');
 const old=ui.loadSolanaTronHistory('splendor');network='testnet';await ui.refresh();resolve({network:'mainnet',rows:[]});await old;
 assert.equal(ui.state.solanaTronHistory.splendor,undefined);assert.deepEqual(calls.slice(1,4).map(c=>c[0]),['prepareSplendorSend','confirmSplendorSend','cancelSplendorSend']);
});

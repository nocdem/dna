import test from 'node:test';
import assert from 'node:assert/strict';
import {setup} from './solana-tron-fixture.js';
import {extensionCapabilitiesFor,extensionNetworkConfig,extensionPageSupported} from '../src/constants/capabilities.js';
import {chainNetwork} from '../src/constants/networks.js';
import {IXIOS_NETWORK} from '../../src/pq/ixios/network.js';
import {createWalletUi} from '../src/ui/wallet-ui.js';

test('IXIOS trusted code candidate is mainnet-only; website methods unavailable',async t=>{
 const {background,client}=await setup(t);
 for(const network of ['mainnet','testnet','unsupported']){assert.equal(extensionCapabilitiesFor('ixios',network).send,network==='mainnet');assert.equal(extensionNetworkConfig('ixios',IXIOS_NETWORK,network).receiveOnly,network!=='mainnet');}
 assert.equal(chainNetwork('ixios','mainnet').endpoint,IXIOS_NETWORK.endpoint);
 assert.throws(()=>chainNetwork('ixios','testnet'));
 assert.equal(extensionPageSupported('ixios','wallet-activity','mainnet'),true);
 await assert.rejects(client.request('prepareIxiosSend',[{}]),/native IXIOS/);
 await assert.rejects(client.request('confirmIxiosSend',['missing']),/closed/);
 await assert.rejects(client.request('setChainNetwork',['ixios','testnet']),/network/i);
 const {engine}=background.engine.setupProviderEngineEip1193({origin:'https://site.example',subjectType:'website'});
 try{for(const method of ['prepareIxiosSend','prepareIxiosResubmit','confirmIxiosSend'])assert.ok((await engine.handle({id:1,jsonrpc:'2.0',method,params:[]})).error);}finally{engine.destroy();}
});

test('IXIOS trusted UI preserves atomic gas-price cap and uses existing public address',async()=>{
 const calls=[],ui=createWalletUi({async request(method,args){calls.push([method,args]);if(method==='getState')return {isUnlocked:true,addresses:{ixios:'0x'+'11'.repeat(48)},networks:{ixios:'mainnet'}};if(method==='getIxiosBalances')return [{symbol:'IXIOS',balance:'1'}];return {};}});
 await ui.refresh();await ui.prepareSolanaTronSend({chain:'ixios',symbol:'IXIOS',to:'recipient',amount:'1',maxGasPrice:'1000000000'});
 assert.deepEqual(calls.at(-1),['prepareIxiosSend',[{symbol:'IXIOS',to:'recipient',amount:'1',maxGasPrice:'1000000000'}]]);
 await ui.loadSolanaTronBalances({chain:'ixios'});assert.ok(calls.some(([m])=>m==='getIxiosBalances'));
 await ui.loadSolanaTronHistory('ixios');assert.ok(calls.some(([m])=>m==='getIxiosHistory'));
});

test('IXIOS public reads crossing lock cannot repopulate unlocked-session UI',async()=>{
 let state={isUnlocked:true,addresses:{ixios:'0x'+'11'.repeat(48)},networks:{ixios:'mainnet'}},finishBalance,finishHistory;
 const ui=createWalletUi({async request(method){if(method==='getState')return state;if(method==='getIxiosBalances')return new Promise(r=>{finishBalance=r;});if(method==='getIxiosHistory')return new Promise(r=>{finishHistory=r;});return {};}});
 await ui.refresh();const balance=ui.loadSolanaTronBalances({chain:'ixios'}),history=ui.loadSolanaTronHistory('ixios');
 state={isUnlocked:false,addresses:{},networks:{ixios:'mainnet'}};await ui.refresh();
 finishBalance([{symbol:'IXIOS',balance:'99'}]);finishHistory({rows:[{hash:'old'}],local:[],network:'mainnet'});await Promise.all([balance,history]);
 assert.equal(ui.state.solanaTronBalances.ixios,undefined);assert.equal(ui.state.solanaTronHistory.ixios,undefined);
});

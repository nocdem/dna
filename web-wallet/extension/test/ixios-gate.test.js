import test from 'node:test';
import assert from 'node:assert/strict';
import {setup} from './solana-tron-fixture.js';
import {extensionCapabilitiesFor,extensionNetworkConfig,extensionPageSupported} from '../src/constants/capabilities.js';
import {chainNetwork} from '../src/constants/networks.js';
import {IXIOS_NETWORK} from '../../src/pq/ixios/network.js';
import {createWalletUi} from '../src/ui/wallet-ui.js';

test('IXIOS trusted code candidate: send and history on the listed networks only; website methods unavailable',async t=>{
 const {background,client}=await setup(t);
 for(const network of ['mainnet','testnet','unsupported']){assert.equal(extensionCapabilitiesFor('ixios',network).send,network!=='unsupported');assert.equal(extensionCapabilitiesFor('ixios',network).history,network!=='unsupported');assert.equal(extensionNetworkConfig('ixios',IXIOS_NETWORK,network).receiveOnly,network==='unsupported');}
 assert.equal(chainNetwork('ixios','mainnet').endpoint,IXIOS_NETWORK.endpoint);
 assert.equal(chainNetwork('ixios','testnet').endpoint,'https://nx-rpc.ixoflow.io');
 assert.throws(()=>chainNetwork('ixios','unsupported'));
 assert.equal(extensionPageSupported('ixios','wallet-activity','mainnet'),true);
 assert.equal(extensionPageSupported('ixios','wallet-activity','testnet'),true);
 assert.equal(extensionPageSupported('ixios','wallet-activity','unsupported'),false);
 assert.equal(extensionPageSupported('ixios','send','testnet'),true);
 await assert.rejects(client.request('prepareIxiosSend',[{}]),/native IXIOS/);
 await assert.rejects(client.request('confirmIxiosSend',['missing']),/closed/);
 await assert.rejects(client.request('setChainNetwork',['ixios','unsupported']),/network/i);
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

// Notes and the read-only send flag per network. The expected strings are literals here (the main note is today's text; the
// test note is the plan's text, section 4.3), so a note changed in the code cannot satisfy them. An unlisted id keeps today's
// refusal text.
test('IXIOS send notes: the main note is unchanged, the test network names itself, an unlisted id keeps the old refusal',()=>{
 const note=network=>extensionNetworkConfig('ixios',IXIOS_NETWORK,network).sendNote;
 assert.equal(note('mainnet'),'Native IXIOS only, 1,000 gas and an explicit gas-price cap. Fresh identity/fee checks must pass; live RPC availability is not guaranteed. No contracts, tokens or automatic replacement.');
 assert.equal(note('testnet'),'Ixios test network: test IXIOS only. Native IXIOS only, 1,000 gas and an explicit gas-price cap. Fresh identity/fee checks must pass; live RPC availability is not guaranteed. No contracts, tokens or automatic replacement.');
 assert.equal(note('unsupported'),'IXIOS sends are available only on the mainnet code candidate.');
});

// The portfolio asks getIxiosBalance with the network it is showing (D7). Proves: the id of the options is passed on; without
// one the selected network of the state is used, and mainnet when the state has none. The request stub records the argument
// list, so a reader that ignored the network (an empty list) fails. The background refusal of a mismatched id is in
// ixios-integration.test.js (it needs the production background).
test('IXIOS portfolio read passes the shown network to getIxiosBalance',async()=>{
 const {portfolioReaders}=await import('../src/ui/wallet-page.js'),calls=[],ui={state:{networks:{ixios:'testnet'}},async request(method,args=[]){calls.push([method,args]);return [{symbol:'IXIOS',balance:'1'}];}};
 const readers=portfolioReaders(ui);
 await readers.readBalances('ixios','addr','endpoint',{networkId:'testnet'});await readers.readBalances('ixios','addr','endpoint',{networkId:'mainnet'});await readers.readBalances('ixios','addr','endpoint');
 ui.state={networks:{}};await readers.readBalances('ixios','addr','endpoint');
 assert.deepEqual(calls,[['getIxiosBalance',['testnet']],['getIxiosBalance',['mainnet']],['getIxiosBalance',['testnet']],['getIxiosBalance',['mainnet']]]);
});

// Production background composition + native signer + encrypted activity.
// Uses the actual mainnet trusted-port capability; every public transport is mocked.
// No live signed requests or website-provider permissions are enabled.
import test from 'node:test';import assert from 'node:assert/strict';import {keccak256,decodeRlp} from 'ethers';
import {setup,phrase} from './solana-tron-fixture.js';import {ixiosFixture} from './ixios-fixture.js';
import {ACTIVITY_KEY,VAULT_KEY,parseVault} from '../../src/vault.js';import {activityKeyFor,parseActivity} from '../../src/activity-storage.js';
test('IXIOS production trusted port uses existing key boundary and separate encrypted mainnet bucket before POST',async t=>{
 const {background,client,values}=await setup(t),f=await ixiosFixture(t);assert.equal(phrase,f.phrase);
 const address=background.walletKeys.getAddresses().ixios;assert.equal(address,f.address);
 const id=parseVault(values[VAULT_KEY]).id,key=await activityKeyFor(phrase,id),bucket=`${ACTIVITY_KEY}.ixios.mainnet`;let firstAttempt,raw,reads=0;
 const getPhrase=background.walletKeys.getRecoveryPhrase;t.mock.method(background.walletKeys,'getRecoveryPhrase',()=>{reads++;return getPhrase();});
 f.setCallback(async bytes=>{const rows=await parseActivity(values[bucket],id,{ixios:address},key);assert.equal(rows.length,1);assert.equal(rows[0].signedPayload.data,bytes);assert.equal(rows[0].networkId,'mainnet');assert.equal(JSON.stringify(values).includes(bytes),false);if(firstAttempt)assert.notEqual(rows[0].submissionId,firstAttempt);else firstAttempt=rows[0].submissionId;if(raw)assert.equal(bytes,raw);else raw=bytes;return keccak256(bytes);});
 const r=await client.request('prepareIxiosSend',[{symbol:'IXIOS',to:f.to,amount:'1',maxGasPrice:'93000000000000000'}]);assert.equal(reads,0);assert.equal(r.fee,'Up to 93.0 IXIOS');const hash=await client.request('confirmIxiosSend',[r.id]);assert.equal(reads,1);assert.equal(f.posts(),1);
 const h=await client.request('getIxiosHistory');assert.equal(h.local[0].hash,hash);assert.equal(h.local[0].canResubmit,true);assert.equal(JSON.stringify(h).includes(raw),false);assert.equal(JSON.stringify(h).includes(phrase),false);
 const retry=await client.request('prepareIxiosResubmit',[hash]);assert.equal(await client.request('confirmIxiosSend',[retry.id]),hash);assert.equal(f.posts(),2);assert.equal(reads,1);assert.equal(background.nodus.chainActivity('ixios','mainnet').rows().length,1);
 await assert.rejects(client.request('confirmIxiosSend',[retry.id]),/closed/);
});

// ---- Ixios test network (plan 9.3 "Production composition", "Portfolio read follows the selection", and the local-history
// route, red-team note 3): added with the test-network entry ----
// Proves on the production background with the selection driven through the trusted port: on testnet a send is prepared and
// confirmed with the review row "Ixios testnet", written to `...ixios.testnet` (and only there); the local-history route and
// getIxiosHistory show that row; back on mainnet both show no row, the review row says "Ixios mainnet" and the mainnet bucket
// key is absent (unchanged byte for byte: it never existed); getIxiosBalance accepts only the selected network's id and reads the
// test node with ixios_ names only. Falsely passes if: both buckets were written in one run and only presence was checked (the
// other bucket's raw value is compared before and after), or the fixture accepted any origin (it throws on an unknown origin and
// on a method name of the other namespace).
test('IXIOS production composition keeps the test network apart: bucket, history, local-history route, review row and balance',async t=>{
 const {client,values}=await setup(t),f=await ixiosFixture(t),mainBucket=`${ACTIVITY_KEY}.ixios.mainnet`,testBucket=`${ACTIVITY_KEY}.ixios.testnet`;
 f.setCallback(async bytes=>keccak256(bytes));
 await client.request('setChainNetwork',['ixios','testnet']);
 const r=await client.request('prepareIxiosSend',[{symbol:'IXIOS',to:f.to,amount:'1',maxGasPrice:'100000000000000000'}]);
 assert.equal(r.network,'testnet');assert.deepEqual(r.review[0],['Network','Ixios testnet']);
 const hash=await client.request('confirmIxiosSend',[r.id]);
 assert.ok(values[testBucket],'the testnet bucket was written');assert.equal(values[mainBucket],undefined,'the mainnet bucket was not written');
 assert.equal(f.posted.length,1);assert.equal(f.posted[0].origin,'https://nx-rpc.ixoflow.io');assert.equal(decodeRlp(f.posted[0].raw)[6],'0x29');
 const onTest=await client.request('getIxiosHistory');assert.equal(onTest.network,'testnet');assert.equal(onTest.local[0].hash,hash);
 assert.deepEqual((await client.request('getChainLocalHistory',['ixios'])).map(row=>row.hash),[hash],'the local-history route reads the selected network');
 // The test network's balance read: the shown id is passed, the node's ixios_ names are used, a main id is refused.
 const before=f.requests.length,balance=await client.request('getIxiosBalance',['testnet']);assert.equal(balance[0].symbol,'IXIOS');
 const reads=f.requests.slice(before);assert.ok(reads.length>0&&reads.every(x=>x.origin==='https://nx-rpc.ixoflow.io'&&x.method.startsWith('ixios_')),reads.map(x=>x.origin+' '+x.method).join());
 await assert.rejects(client.request('getIxiosBalance',['mainnet']),/Ixios network changed/);
 // Back on mainnet.
 const testBefore=values[testBucket];f.resetRaw();
 await client.request('setChainNetwork',['ixios','mainnet']);
 await assert.rejects(client.request('getIxiosBalance',['testnet']),/Ixios network changed/);
 const onMain=await client.request('getIxiosHistory');assert.equal(onMain.network,'mainnet');assert.deepEqual(onMain.local,[]);
 assert.deepEqual(await client.request('getChainLocalHistory',['ixios']),[],'the mainnet route does not show the test row');
 const m=await client.request('prepareIxiosSend',[{symbol:'IXIOS',to:f.to,amount:'1',maxGasPrice:'93000000000000000'}]);
 assert.equal(m.network,'mainnet');assert.deepEqual(m.review[0],['Network','Ixios mainnet']);await client.request('cancelIxiosSend',[m.id]);
 assert.equal(values[mainBucket],undefined,'nothing was saved on mainnet');assert.equal(values[testBucket],testBefore,'the testnet bucket is byte for byte unchanged');
 assert.equal(f.posted.length,1);
});

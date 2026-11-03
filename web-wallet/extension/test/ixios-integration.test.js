// Production background composition + native signer + encrypted activity.
// Uses the actual mainnet trusted-port capability; every public transport is mocked.
// No live signed requests or website-provider permissions are enabled.
import test from 'node:test';import assert from 'node:assert/strict';import {keccak256} from 'ethers';
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

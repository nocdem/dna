import test from 'node:test';import assert from 'node:assert/strict';
import {createSoquRpcFixture} from '../../test/fixtures/soqu-rpc-fixture.js';
import {createSoqucoin} from '../src/background/soqucoin.js';
import {createLockCoordinator} from '../src/background/lock.js';
import {createNetworkActivity} from '../src/background/network-activity.js';
import {activityKeyFor,historyKeyFor,parseActivity,serializeActivity} from '../../src/activity-storage.js';
import {ACTIVITY_KEY,VAULT_KEY} from '../../src/vault.js';
import {SOQU_MAINNET} from '../../src/pq/soqu-preflight.js';
import {checkActivity} from '../../src/activity.js';
import {soquPendingSubmission,reconcileSoquSubmission} from '../../src/pq/soqu-transfer.js';
const key=`${ACTIVITY_KEY}.soqucoin.mainnet`;
async function setup(t,extra={}){
 const x=createSoquRpcFixture(),values={[VAULT_KEY]:'synthetic SOQ vault'},id=Buffer.alloc(16,7).toString('base64');
 const session={id,addresses:{soqucoin:x.address},vault:values[VAULT_KEY],key:await activityKeyFor(x.phrase,id),historyKey:await historyKeyFor(x.phrase,id)};
 const network={id:'mainnet',endpoint:SOQU_MAINNET.rpc};
 const storage={async get(keys){return Object.fromEntries(keys.map(k=>[k,values[k]]));},async set(v){Object.assign(values,v);}};
 const lockCoordinator=createLockCoordinator();await lockCoordinator.unlock(async()=>{});
 const activity=createNetworkActivity({chain:'soqucoin',network,session,storage,current:()=>lockCoordinator.assertUnlocked()});
 let secretReads=0;const controller=createSoqucoin({storage,lockCoordinator,getWalletKeys:()=>({getPqAddresses:()=>({soqucoin:{mainnet:x.address}}),getRecoveryPhrase(){secretReads++;return x.phrase;}}),getActivity:()=>activity,getNetwork:()=>network,watch:()=>()=>{},readHistory:async()=>({rows:[],totalListed:0,examined:0,omitted:0,status:'Partial native SOQ net flows; outgoing amounts include fees.'}),...extra});
 const original=globalThis.fetch;t.after(()=>{globalThis.fetch=original;});
 globalThis.fetch=async(url,options)=>{
  if(String(url).endsWith('/mldsa44-sign.wasm'))return new Response(x.wasmBytes);
  if(options.method==='POST'&&JSON.parse(options.body).method==='sendrawtransaction'){
   const rows=await parseActivity(values[key],id,session.addresses,session.key);assert.equal(rows.length,1);assert.deepEqual(rows[0].inputs,[{txid:x.row.txid,vout:0}]);x.record({hash:rows[0].hash});
  }
  return x.fetcher(url,options);
 };
 return {x,controller,activity,session,storage,network,values,lockCoordinator,secretReads:()=>secretReads};
}
test('real SOQ extension dispatcher uses guarded recovery and encrypted outpoints before POST',async t=>{
 const s=await setup(t),r=await s.controller.prepareSend({symbol:'SOQ',to:s.x.address,amount:'0.01'});assert.equal(s.secretReads(),0);assert.equal(r.chain,'soqucoin');
 const hash=await s.controller.confirmSend(r.id);assert.equal(s.x.posts(),1);assert.equal(s.secretReads(),1);assert.equal(soquPendingSubmission(s.x.address),hash);
 assert.ok(!JSON.stringify(s.values).includes(s.x.phrase));await assert.rejects(s.controller.confirmSend(r.id),/closed/);
 const history=await s.controller.getHistory();assert.equal(history.local[0].hash,hash);assert.match(history.status,/Partial native SOQ/);
 const reopened=createNetworkActivity({chain:'soqucoin',network:s.network,session:s.session,storage:s.storage,current(){}});await reopened.ready;
 assert.deepEqual(reopened.rows()[0].inputs,[{txid:s.x.row.txid,vout:0}]);assert.equal(reopened.rows()[0].status,'pending');
 assert.equal((await checkActivity(reopened.rows()[0],{fetcher:s.x.fetcher})).status,'confirmed');assert.equal(soquPendingSubmission(s.x.address),null);
 await s.lockCoordinator.lock();
});
test('real zero-POST lock race records only presealed ciphertext and restores failed without manual state changes',async t=>{
 const s=await setup(t),r=await s.controller.prepareSend({symbol:'SOQ',to:s.x.address,amount:'0.01'});
 const persist=s.activity.persist;let finished;const done=new Promise(resolve=>{finished=resolve;});
 const set=s.storage.set;s.storage.set=async values=>{await set(values);if(Object.keys(values).some(k=>k.includes('.submissionProof.')))finished();};
 s.activity.persist=async()=>{await persist();await s.lockCoordinator.lock();};
 await assert.rejects(s.controller.confirmSend(r.id),/changed|locked/);await done;assert.equal(s.x.posts(),0);
 // Old controller has no unlocked wallet/key access. A new session uses normal
 // unlock + authenticated recovery, exactly as worker restart would.
 await s.lockCoordinator.unlock(async()=>{});
 const restored=createNetworkActivity({chain:'soqucoin',network:s.network,session:s.session,storage:s.storage,current:()=>s.lockCoordinator.assertUnlocked()});await restored.ready;
 assert.equal(restored.rows()[0].status,'pending');await restored.recoverSubmissionProofs();
 assert.equal(restored.rows()[0].status,'failed');assert.equal(restored.rows()[0].notSubmitted,true);
 assert.equal((await checkActivity(restored.rows()[0],{fetcher:()=>{throw Error('must not reach network');}})).status,'failed');
 const durable=await parseActivity(s.values[key],s.session.id,s.session.addresses,s.session.key);assert.equal(durable[0].notSubmitted,true);
 await s.lockCoordinator.lock();
});
test('SOQ activity refuses tampered owner, missing/duplicate reservations and malformed markers',async t=>{
 const s=await setup(t);const row={chain:'soqucoin',address:s.x.address,to:s.x.address,symbol:'SOQ',amount:'1',hash:'ab'.repeat(32),createdAt:new Date().toISOString(),status:'pending',inputs:[{txid:'cd'.repeat(32),vout:0}]};
 for(const patch of [{address:'bad'},{inputs:[]},{inputs:[row.inputs[0],row.inputs[0]]},{inputs:[{txid:'cd'.repeat(32),vout:-1}]},{notSubmitted:true}]){
  const encrypted=await serializeActivity(s.session.id,[{...row,...patch}],s.session.key);await assert.rejects(parseActivity(encrypted,s.session.id,s.session.addresses,s.session.key));
 }
 await s.lockCoordinator.lock();
});

test('SOQ extension exposes locally labelled activity without claiming full account scan; native send is mainnet-only',async()=>{
 const {extensionCapabilitiesFor}=await import('../src/constants/capabilities.js');
 const flags=extensionCapabilitiesFor('soqucoin','mainnet');assert.equal(flags.history,true);assert.equal(flags.send,true);assert.equal(extensionCapabilitiesFor('soqucoin','testnet').send,false);assert.equal(extensionCapabilitiesFor('soqucoin',undefined).send,false);
});

test('explicit SOQ recovery after uncertain submission reuses exact bytes under a new durable attempt, never derives again',async t=>{
 const s=await setup(t),review=await s.controller.prepareSend({symbol:'SOQ',to:s.x.address,amount:'0.01'});s.x.mode('ambiguous');
 await assert.rejects(s.controller.confirmSend(review.id),e=>e.data.activityTracked===true);
 const before=s.activity.rows()[0],oldId=before.submissionId,oldRaw=before.signedPayload.data;assert.equal(s.secretReads(),1);
 s.x.mode('unconfirmed');const recovery=await s.controller.prepareResubmit(before.hash);assert.equal(s.x.posts(),1);assert.equal(recovery.resubmission,true);assert.ok(!JSON.stringify(recovery).includes(oldRaw));
 assert.equal((await s.controller.getHistory()).local[0].canResubmit,true);
 await s.controller.confirmSend(recovery.id);assert.equal(s.x.posts(),2);assert.equal(s.secretReads(),1);
 const durable=await parseActivity(s.values[key],s.session.id,s.session.addresses,s.session.key);assert.equal(durable.length,1);assert.equal(durable[0].signedPayload.data,oldRaw);assert.notEqual(durable[0].submissionId,oldId);
 assert.ok(!JSON.stringify(await s.controller.getHistory()).includes(oldRaw));
 await assert.rejects(s.controller.confirmSend(recovery.id),/closed/);assert.equal(s.x.posts(),2);
 s.x.mode('');await reconcileSoquSubmission({from:s.x.address,hash:before.hash,fetcher:s.x.fetcher});await s.lockCoordinator.lock();
});
test('SOQ partial history deduplicates local pending hash without using account rows as submission proof; failure preserves local',async t=>{let page,fail=false;const s=await setup(t,{readHistory:async()=>{if(fail)throw Error('history unavailable');return page;}}),r=await s.controller.prepareSend({symbol:'SOQ',to:s.x.address,amount:'0.01'}),hash=await s.controller.confirmSend(r.id);page={rows:[{chain:'soqucoin',hash,time:Date.now(),dir:'out',symbol:'SOQ',amount:'0.02',peer:'',status:'confirmed'}],totalListed:1,examined:1,omitted:0,status:'Partial native net flows including fees.'};const h=await s.controller.getHistory();assert.equal(h.rows.length,0);assert.equal(h.local.length,1);assert.equal(s.activity.rows()[0].status,'pending');assert.match(h.status,/Partial/);fail=true;const now=Date.now();t.mock.method(Date,'now',()=>now+301000);const failed=await s.controller.getHistory({manual:true});assert.equal(failed.local.length,1);assert.equal(failed.rows.length,0);assert.match(failed.error,/unavailable/);await s.lockCoordinator.lock();});
test('SOQ history lock discards a late page without exposing payload or stale account rows',async t=>{let resolve,entered;const started=new Promise(r=>entered=r),pending=new Promise(r=>resolve=r);const s=await setup(t,{readHistory:async()=>{entered();return pending;}}),job=s.controller.getHistory();await started;await s.lockCoordinator.lock();await assert.rejects(job,/locked|changed/);resolve({rows:[{hash:'11'.repeat(32)}],status:'late'});await new Promise(r=>setImmediate(r));assert.throws(()=>s.activity.history(),/locked/);await s.lockCoordinator.unlock(async()=>{});assert.equal(s.activity.history(),null);await s.lockCoordinator.lock();});

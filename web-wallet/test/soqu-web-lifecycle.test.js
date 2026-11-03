import test from 'node:test';import assert from 'node:assert/strict';import{readFileSync}from'node:fs';import{runInNewContext}from'node:vm';
import{serveReceiveWasmForFile}from'./fixtures/receive-wasm-fetch.js';serveReceiveWasmForFile(); // Soqucoin signing seed comes from the receive module (native rule)
import{createSoquRpcFixture}from'./fixtures/soqu-rpc-fixture.js';
import{prepareSoquTransfer}from'../src/pq/soqu-transfer.js';
import{recordActivity}from'../src/activity.js';
import{activityKeyFor,serializeActivity,parseActivity}from'../src/activity-storage.js';
import{createSubmissionProof,commitSubmissionProof,recoverSubmissionProofs}from'../src/pq/submission-proof.js';
const app=readFileSync(new URL('../src/app.js',import.meta.url),'utf8');
const start=app.indexOf('const hash = await transfer.confirm(async details => {')+'const hash = await transfer.confirm(async details => '.length;
const callback=app.slice(start,app.indexOf('\n    });',start)+6);
const catchStart=app.indexOf('    if (submissionProof && ((transfer.chain');
const knownFailure=app.slice(catchStart,app.indexOf('    // The node answered "busy"',catchStart));
test('actual Web callback/catch recovers known-zero-POST lock from presealed proof on new unlock',async()=>{
 const x=createSoquRpcFixture(),review=await prepareSoquTransfer(x.transfer),id=Buffer.alloc(16,17).toString('base64');
 const key=await activityKeyFor(x.phrase,id),store=new Map();
 const storage={get:async keys=>Object.fromEntries(keys.map(k=>[k,store.get(k)])),set:async entries=>{for(const[k,v]of Object.entries(entries))store.set(k,v);}};
 let sealed;
 const context={transfer:{...review,chain:'soqucoin',symbol:'SOQ',amount:'0.01'},record:undefined,submissionProof:undefined,
  history:[],current:1,revision:1,wallet:x.wallet,activitySession:{id,key},
  recordActivity,createSubmissionProof,commitSubmissionProof,submissionProofStorage:storage,renderActivity:()=>{},
  persistActivity:async()=>{sealed=await serializeActivity(id,context.history,key);context.activitySession=null;x.wallet.locked=true;context.wallet=undefined;},Error};
 runInNewContext('globalThis.callback = async details => '+callback,context);
 let failure;
 try{await review.confirm(async details=>{x.record(details);await context.callback(details);});}catch(e){failure=e;}
 assert.equal(failure?.soquNotSubmitted,true);assert.equal(x.posts(),0);assert.ok(sealed);
 context.error=failure;await runInNewContext('(async()=>{'+knownFailure+'})()',context);
 const reopenedKey=await activityKeyFor(x.phrase,id);
 let rows=await parseActivity(sealed,id,{},reopenedKey);assert.equal(rows[0].status,'pending');
 rows=await recoverSubmissionProofs({storage,id,rows,key:reopenedKey,addresses:{}});
 assert.equal(rows[0].notSubmitted,true);assert.equal(rows[0].status,'failed');
 const persisted=await parseActivity(await serializeActivity(id,rows,reopenedKey),id,{soqucoin:x.address},reopenedKey);
 assert.equal(persisted[0].notSubmitted,true);assert.equal(persisted[0].savedStatus,'failed');
});

test('actual Web confirmation callback rotates encrypted attempt for explicitly reviewed exact replay without key access',async()=>{
 const {prepareSoquResubmission}=await import('../src/pq/soqu-transfer.js');
 const x=createSoquRpcFixture(),id=Buffer.alloc(16,18).toString('base64'),key=await activityKeyFor(x.phrase,id),wire=[];
 const fetcher=async(url,options)=>{if(options?.body){const body=JSON.parse(options.body);if(body.method==='sendrawtransaction')wire.push(body.params[0]);}return x.fetcher(url,options);};
 const original=await prepareSoquTransfer({...x.transfer,fetcher});
 const context={transfer:{...original,chain:'soqucoin',symbol:'SOQ',amount:'0.01'},record:undefined,submissionProof:undefined,
  history:[],current:1,revision:1,wallet:x.wallet,activitySession:{id,key},recordActivity,createSubmissionProof,renderActivity:()=>{},Error};
 let sealed;
 context.persistActivity=async()=>{sealed=await serializeActivity(id,context.history,key);};
 runInNewContext('globalThis.callback = async details => '+callback,context);
 x.mode('ambiguous');await assert.rejects(original.confirm(async details=>{x.record(details);await context.callback(details);}));
 const old=context.history[0];old.status='unknown';const oldAttempt=old.submissionId;
 x.mode('unconfirmed');Object.defineProperty(x.wallet,'recoveryPhrase',{get(){throw Error('Recovery must not access signing keys');}});
 const replay=await prepareSoquResubmission({wallet:x.wallet,row:old,fetcher});
 context.transfer={...replay,chain:'soqucoin',symbol:'SOQ'};context.submissionProof=undefined;
 await replay.confirm(async details=>{x.record(details);await context.callback(details);});
 assert.equal(x.posts(),2);assert.equal(wire.length,2);assert.equal(wire[0],wire[1]);
 assert.equal(context.history.length,1);assert.notEqual(context.history[0].submissionId,oldAttempt);
 const rows=await parseActivity(sealed,id,{soqucoin:x.address},key);
 assert.equal(rows[0].submissionId,context.history[0].submissionId);assert.equal(rows[0].hash,old.hash);assert.equal(rows[0].signedPayload.data,wire[0]);
 assert.equal(context.submissionProof,undefined,'a replay must never certify the old attempt was not submitted');
 await assert.rejects(replay.confirm(()=>{}),/closed/);
});

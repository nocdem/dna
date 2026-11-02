import test from 'node:test';import assert from 'node:assert/strict';import{readFileSync}from'node:fs';
import{activityKeyFor}from'../src/activity-storage.js';
import{createSubmissionProof,commitSubmissionProof,recoverSubmissionProofs,submissionProofKey,clearSubmissionProofs}from'../src/pq/submission-proof.js';
const fixture=JSON.parse(readFileSync(new URL('./fixtures/pq-receive.json',import.meta.url))).vectors[0];
async function setup(){const id=Buffer.alloc(16,6).toString('base64'),key=await activityKeyFor(fixture.phrase,id),address=fixture.addresses.soqucoin.mainnet,values={};
 const storage={async get(keys){return Object.fromEntries(keys.map(k=>[k,values[k]]));},async set(v){Object.assign(values,v);},async remove(keys){for(const key of keys)delete values[key];}};
 const row={chain:'soqucoin',address,to:address,symbol:'SOQ',amount:'1',hash:'ab'.repeat(32),submissionId:'12'.repeat(16),createdAt:new Date().toISOString(),status:'pending',inputs:[{txid:'cd'.repeat(32),vout:0}]};
 return {id,key,row,storage,values,addresses:{soqucoin:address}};
}
test('authenticated noPOST proof preserves other-chain quarantine and is bound to a single attempt',async()=>{
 const s=await setup(),proof=await createSubmissionProof(s);await commitSubmissionProof(s.storage,proof);
 const rows=[s.row];const quarantined=[{raw:{inputs:['reserved-nodus-nullifier']}}];Object.defineProperty(rows,'quarantined',{value:quarantined});
 const recovered=await recoverSubmissionProofs({...s,rows});assert.equal(recovered[0].status,'failed');assert.equal(recovered[0].notSubmitted,true);assert.equal(recovered.quarantined,quarantined);assert.equal(Object.keys(recovered).includes('quarantined'),false);
 const retry={...s.row,submissionId:'34'.repeat(16)};const untouched=await recoverSubmissionProofs({...s,rows:[retry]});assert.equal(untouched[0].status,'pending');
 s.values[submissionProofKey(s.id,retry)]=proof.sealed;await assert.rejects(recoverSubmissionProofs({...s,rows:[retry]}),/does not match/);
});
test('wrong vault, wrong authenticated reservation, malformed proof and duplicate attempts never release holds',async()=>{
 const s=await setup(),proof=await createSubmissionProof(s);await commitSubmissionProof(s.storage,proof);
 for(const change of [{amount:'2'},{to:'bad'},{inputs:[{txid:'ee'.repeat(32),vout:1}]}])await assert.rejects(recoverSubmissionProofs({...s,rows:[{...s.row,...change}]}));
 await assert.rejects(recoverSubmissionProofs({...s,rows:[s.row,s.row]}),/Duplicate/);
 const other=Buffer.alloc(16,9).toString('base64');s.values[submissionProofKey(other,s.row)]=proof.sealed;await assert.rejects(recoverSubmissionProofs({...s,id:other,rows:[s.row]}));
 s.values[proof.storageKey]='invalid';await assert.rejects(recoverSubmissionProofs({...s,rows:[s.row]}));assert.equal(s.row.status,'pending');
});
test('proof never contains plaintext payload, cleanup is limited to durably failed marker records',async()=>{
 const s=await setup(),proof=await createSubmissionProof({...s,row:{...s.row,signedPayload:{encoding:'hex',data:'secret-payload'}}});
 assert.ok(!proof.sealed.includes('secret-payload'));assert.ok(!proof.sealed.includes(s.row.address));await commitSubmissionProof(s.storage,proof);
 await clearSubmissionProofs(s.storage,s.id,[s.row]);assert.ok(s.values[proof.storageKey]);
 await clearSubmissionProofs(s.storage,s.id,[{...s.row,status:'failed',notSubmitted:true}]);assert.equal(s.values[proof.storageKey],undefined);
});

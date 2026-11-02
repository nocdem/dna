// Explicit exact-byte recovery. A missing transaction is not proof of absence.
// No new signature, input selection, or automatic retry. Every attempt must
// be durably recorded before the signed payload reaches a remote node.
import {validCkbPending} from './ckb-pending.js';import {validateCkbSignedPayload,verifyCkbSignedPayload} from './ckb-signed-payload.js';import {observeCkbSubmission,recheckCkbQuantumCells,simulateCkbAtConfiguredNode} from './ckb-preflight.js';import {submitCkbTransaction} from './ckb-submit.js';
const recovering=new Set();
export async function prepareCkbExactRecovery(row,{signal,fetcher,wasmBytes,assertCurrent,simulate=simulateCkbAtConfiguredNode,submit=submitCkbTransaction}={}){
 if(typeof assertCurrent!=='function')throw Error('Active CKB wallet guard required.');assertCurrent();signal?.throwIfAborted();
 if(!validCkbPending(row)||!['pending','unknown'].includes(row.status)||(row.savedStatus!==undefined&&!['pending','unknown'].includes(row.savedStatus))||row.notSubmitted===true||!row.signedPayload)throw Error('CKB record is not eligible for exact recovery.');
 const snapshot=structuredClone({chain:'ckb',networkId:row.networkId,address:row.address,to:row.to,amountAtoms:row.amountAtoms,feeAtoms:row.feeAtoms,hash:row.hash,submissionId:row.submissionId,inputs:row.inputs,inputCapacities:row.inputCapacities,signedPayload:row.signedPayload});
 const verified=await verifyCkbSignedPayload(snapshot,{wasmBytes,signal});assertCurrent();const prior=await observeCkbSubmission(snapshot,{signal,fetcher});assertCurrent();if(prior.state!=='pending')throw Error('CKB transaction is already resolved.');
 const parsed=validateCkbSignedPayload(snapshot);await recheckCkbQuantumCells(snapshot.address,parsed.inputs,{networkId:snapshot.networkId,signal,fetcher});assertCurrent();
 let used=false;const expiresAt=Date.now()+60000,id=`${snapshot.networkId}:${snapshot.address}`;
 return Object.freeze({networkId:snapshot.networkId,from:snapshot.address,to:snapshot.to,amount:snapshot.amountAtoms,fee:snapshot.feeAtoms,hash:snapshot.hash,outpoints:Object.freeze([...snapshot.inputs]),inputCapacities:Object.freeze([...snapshot.inputCapacities]),expiresAt,
  notice:'Absence is inconclusive. This submits the exact same signed transaction; it may already be pending.',cancel(){used=true;},
  async confirm(onAttempt){
   if(used)throw Error('CKB recovery review is closed.');used=true;assertCurrent();signal?.throwIfAborted();if(Date.now()>=expiresAt)throw Error('CKB recovery review expired.');if(typeof onAttempt!=='function')throw Error('Durable CKB recovery attempt is required.');if(recovering.has(id))throw Error('CKB recovery already in progress.');recovering.add(id);
   try{
    const fresh=await observeCkbSubmission(snapshot,{signal,fetcher});assertCurrent();if(fresh.state!=='pending')throw Error('CKB transaction is already resolved.');
    await recheckCkbQuantumCells(snapshot.address,parsed.inputs,{networkId:snapshot.networkId,signal,fetcher});assertCurrent();if(Date.now()>=expiresAt)throw Error('CKB recovery review expired.');
    const attempt=await onAttempt({networkId:snapshot.networkId,from:snapshot.address,to:snapshot.to,amount:snapshot.amountAtoms,fee:snapshot.feeAtoms,outpoints:[...snapshot.inputs],inputCapacities:[...snapshot.inputCapacities],txid:snapshot.hash,state:'signed-exposure-pending',previousSubmissionId:snapshot.submissionId,signedPayload:{...snapshot.signedPayload}});assertCurrent();signal?.throwIfAborted();
    if(!attempt||!/^[0-9a-f]{32}$/.test(attempt.submissionId)||attempt.submissionId===snapshot.submissionId)throw Error('Fresh durable CKB recovery attempt identity required.');
    if(Date.now()>=expiresAt)throw Error('CKB recovery review expired before simulation.');
    const result=await simulate({networkId:snapshot.networkId,rpcTransaction:structuredClone(verified.rpcTransaction),txid:snapshot.hash,expectedFee:BigInt(snapshot.feeAtoms),signal,fetcher});assertCurrent();
    if(result?.txid!==snapshot.hash||typeof result.cycles!=='bigint'||result.cycles<=0n)throw Error('CKB recovery simulation mismatch.');
    await recheckCkbQuantumCells(snapshot.address,parsed.inputs,{networkId:snapshot.networkId,signal,fetcher});assertCurrent();if(Date.now()>=expiresAt)throw Error('CKB recovery review expired before submission.');
    return await submit({networkId:snapshot.networkId,rpcTransaction:structuredClone(verified.rpcTransaction),txid:snapshot.hash,expiresAt,signal,fetcher});
   }finally{recovering.delete(id);}
  }
 });
}

import {validateQtcSignedPayload} from './qtc-signed-payload.js';
// Explicit same-bytes replay only. Transport is supplied by a separately
// reviewed trusted-node adapter; this module configures no endpoint.
export async function prepareQtcRecovery({row,observe,broadcast,signal}={}){
 if(!row||row.notSubmitted||!['pending','unknown'].includes(row.status)||typeof observe!=='function'||typeof broadcast!=='function')throw Error('QTC record is not eligible for exact recovery.');
 const saved=structuredClone(row),signed=validateQtcSignedPayload(saved),expiresAt=Date.now()+60000;let used=false;
 const check=()=>{signal?.throwIfAborted();if(Date.now()>=expiresAt)throw Error('QTC recovery review expired.');};
 const reconcile=async()=>{check();const result=await observe({hash:signed.hash,networkId:saved.networkId,signal});check();if(result?.hash!==signed.hash||!['pending','unknown','confirmed'].includes(result.status))throw Error('QTC recovery status was not reconciled.');if(result.status==='confirmed')throw Error('QTC transaction is already confirmed.');};
 await reconcile();return Object.freeze({from:saved.address,to:saved.to,networkId:saved.networkId,amount:saved.amountAtoms,fee:saved.feeAtoms,outpoints:Object.freeze([...saved.inputs]),hash:signed.hash,expiresAt,isRecovery:true,cancel(){used=true;},
 async signAfterConfirmation({persistPending}={}){if(used)throw Error('QTC recovery review is consumed.');used=true;check();if(typeof persistPending!=='function')throw Error('QTC durable recovery recording is required.');await reconcile();
  await persistPending({txid:signed.hash,networkId:saved.networkId,from:saved.address,to:saved.to,outpoints:[...saved.inputs],amount:saved.amountAtoms,fee:saved.feeAtoms,signedPayload:{encoding:'hex',data:signed.raw},state:'signed-exposure-pending'});check();
  // No new signing and no automatic retries. A previous attempt may already
  // have reached the node; even a zero-new-POST error cannot clear its hold.
  return {raw:signed.raw,txid:signed.hash,networkId:saved.networkId};
 }
 });
}

// Review controller and reconciliation for a native Splendor transfer.
// Confirm is the only write path. Caller must durably record the pending
// transaction before submission and surface ambiguous outcomes; no auto-retry.
// Endpoint contract: Splendor node 5ba2819316a85ba357aca02f68a922c409f659ba,
// rpc/server.go handleSubmitTx; core/mempool/mempool.go Add.
import {pqChainSeed} from './receive.js';
import {prepareSplendorTransfer} from './splendor-prepare.js';
import {signSplendorTransfer} from './splendor-sign.js';
import {splendorTransferBody} from './splendor-transfer-body.js';
import {integerJson} from './integer-json.js';
import {rpcFetch} from '../rpc-transport.js';
import {assertWalletActive} from '../keys.js';
const nets=Object.freeze({mainnet:{url:'https://quantum-rpc.splendor.org',chain:'splendor-quantum-1',genesis:'d865193d3bd88fb4446626940e63b5658275342a0153638079cf9e962332a257'},testnet:{url:'https://quantum-rpc-testnet.splendor.org',chain:'splendor-quantum-testnet-1',genesis:'324d7f561493ae6d08062288cb99adfbb3f83297d352b783f611171251a1289f'}});
const inFlight=new Map();
const key=(networkId,from)=>`${networkId}:${from}`;
function active(wallet,from,signal){signal?.throwIfAborted();assertWalletActive(wallet);if(wallet.addresses?.splendor!==from)throw new Error('Splendor account changed.');}
function recordValid(p){try{if(!p||!Object.hasOwn(nets,p.networkId)||typeof p.hash!=='string'||!/^[0-9a-f]{64}$/.test(p.hash)||p.amount==='0')return false;splendorTransferBody({networkId:p.networkId,from:p.from,to:p.to,amount:p.amount,fee:p.fee,nonce:p.nonce,timestamp:'1'});return true;}catch{return false;}}
export function splendorPendingSubmission(wallet,networkId){return inFlight.get(key(networkId,wallet?.addresses?.splendor))?.hash??null;}
export async function observeSplendorSubmission(pending,{signal,fetcher}={}) {
 if(!recordValid(pending))throw new Error('Invalid Splendor pending record.');
 const net=nets[pending.networkId],opts={signal,fetcher};
 const status=await integerJson(net.url+'/status',opts);signal?.throwIfAborted();
 if(status.chain_id!==net.chain||status.genesis_hash!==net.genesis)throw new Error('Splendor provider is connected to the wrong network.');
 let r;try{r=await integerJson(`${net.url}/tx/${pending.hash}/receipt?amounts=string`,opts);}catch(e){if(e.status===404)return {state:'pending',hash:pending.hash};throw e;}
 if(r.tx_hash!==pending.hash||r.from!==pending.from||r.to!==pending.to||r.amount!==pending.amount||r.fee!==pending.fee||r.type!=='1'||!['0','1'].includes(r.status))throw new Error('Conflicting Splendor receipt.');
 const state=r.status==='1'?'confirmed':'failed';
 if(inFlight.get(key(pending.networkId,pending.from))?.hash===pending.hash)inFlight.delete(key(pending.networkId,pending.from));
 return {state,hash:pending.hash};
}
export async function prepareSplendorReview({wallet,to,amount,fee,networkId='mainnet',signal,fetcher,wasmBytes}={}){
 const from=wallet?.addresses?.splendor;active(wallet,from,signal);const id=key(networkId,from);
 if(inFlight.has(id))throw new Error('A Splendor transfer is already pending.');
 const timestamp=String(Math.floor(Date.now()/1000));const args={networkId,from,to,amount,fee,timestamp,signal,fetcher};
 if(amount==='0')throw new Error('Splendor transfer amount must be positive.');
 const prepared=await prepareSplendorTransfer(args);active(wallet,from,signal);
 if(!prepared.sufficient)throw new Error('Insufficient SPLD balance.');if(!prepared.feeAdequate)throw new Error('Splendor fee is below the current minimum.');
 const expiresAt=Date.now()+120000;let used=false;
 return Object.freeze({networkId,from,to,amount,fee,nonce:prepared.nonce,expiresAt,cancel(){used=true;},async confirm(onBroadcast){
  if(used)throw new Error('This review is already closed.');used=true;active(wallet,from,signal);
  if(typeof onBroadcast!=='function')throw new Error('Durable Splendor submission recording is required.');
  if(Date.now()>=expiresAt)throw new Error('Review expired. Prepare again.');if(inFlight.has(id))throw new Error('A Splendor transfer is already pending.');
  const reservation={hash:null};inFlight.set(id,reservation);let seed,submitted=false;
  try {
   const fresh=await prepareSplendorTransfer(args);active(wallet,from,signal);
   if(fresh.nonce!==prepared.nonce)throw new Error('Splendor nonce changed. Review again.');
   if(!fresh.sufficient)throw new Error('Insufficient SPLD balance.');if(!fresh.feeAdequate)throw new Error('Splendor fee is below the current minimum.');
   if(Date.now()>=expiresAt)throw new Error('Review expired. Prepare again.');
   seed=pqChainSeed(wallet.recoveryPhrase,'splendor');const signed=await signSplendorTransfer({...prepared,seed,wasmBytes,signal});seed.fill(0);seed=undefined;active(wallet,from,signal);
   if(Date.now()>=expiresAt)throw new Error('Review expired. Prepare again.');
   const pending=Object.freeze({networkId,from,to,amount,fee,nonce:prepared.nonce,timestamp:prepared.timestamp,hash:signed.txHash,signedPayload:Object.freeze({encoding:'json',data:signed.wireJson})});reservation.hash=pending.hash;
   await onBroadcast(pending);active(wallet,from,signal);if(Date.now()>=expiresAt)throw new Error('Review expired. Prepare again.');
   // Preserve pending on every response/transport failure from this point.
   submitted=true;const response=await rpcFetch(nets[networkId].url+'/tx/submit',{method:'POST',headers:{'Content-Type':'application/json'},body:signed.wireJson,signal},{fetcher});
   if(response.status!==202)throw new Error(`Splendor submission returned HTTP ${response.status}; check pending status before retrying.`);
   const result=await response.json();if(result.status!=='accepted'||result.hash!==pending.hash)throw new Error('Splendor returned an unexpected submission result; check pending status.');
   return pending.hash;
  } catch(e){const err=e instanceof Error?e:new Error('Splendor transfer failed.');if(!submitted)err.splendorNotSubmitted=true;throw err;}
  finally{seed?.fill(0);if(!submitted&&inFlight.get(id)===reservation)inFlight.delete(id);}
 }});
}

// Explicit same-bytes recovery candidate. Never re-signs or retries itself.
// A 404 receipt is inconclusive; the caller must show that fact and require
// a fresh user confirmation. The mempool may reject a duplicate hash/nonce.
const recoveries=new Set();
export async function prepareSplendorExactRecovery(row,{signal,fetcher,assertCurrent}={}) {
 if(typeof assertCurrent!=='function')throw new Error('Active wallet guard is required.');assertCurrent();signal?.throwIfAborted();
 if(!row||typeof row.submissionId!=='string'||!/^[0-9a-f]{32}$/.test(row.submissionId)||!['pending','unknown'].includes(row.status)||(row.savedStatus!==undefined&&!['pending','unknown'].includes(row.savedStatus))||row.notSubmitted===true)throw new Error('This Splendor activity is not eligible for exact recovery.');
 const snapshot={submissionId:row.submissionId,networkId:row.networkId,address:row.address,to:row.to,amountAtoms:row.amountAtoms,feeAtoms:row.feeAtoms,nonce:row.nonce,timestamp:row.timestamp,hash:row.hash,signedPayload:{encoding:row.signedPayload?.encoding,data:row.signedPayload?.data}};
 const {validateSplendorSignedPayload}=await import('./splendor-recovery.js');const wire=validateSplendorSignedPayload(snapshot);
 const pending={networkId:snapshot.networkId,from:snapshot.address,to:snapshot.to,amount:snapshot.amountAtoms,fee:snapshot.feeAtoms,nonce:snapshot.nonce,hash:snapshot.hash};
 const prior=await observeSplendorSubmission(pending,{signal,fetcher});assertCurrent();signal?.throwIfAborted();
 if(prior.state!=='pending')throw new Error('Splendor transaction is already resolved.');
 let used=false;const expiresAt=Date.now()+120000;return Object.freeze({networkId:pending.networkId,from:pending.from,to:pending.to,amountAtoms:pending.amount,feeAtoms:pending.fee,nonce:pending.nonce,hash:pending.hash,expiresAt,
  notice:'Receipt not found is inconclusive. Confirming submits the exact same signed transaction; it may already be pending.',
  cancel(){used=true;},async confirm(onAttempt){
   if(used)throw new Error('This recovery review is already closed.');used=true;assertCurrent();signal?.throwIfAborted();if(Date.now()>=expiresAt)throw new Error('Recovery review expired.');
   if(typeof onAttempt!=='function')throw new Error('Durable pending storage is required.');
   const id=key(pending.networkId,pending.from);if(recoveries.has(id))throw new Error('Splendor recovery is already in progress.');recoveries.add(id);
   try{
    const fresh=await observeSplendorSubmission(pending,{signal,fetcher});assertCurrent();signal?.throwIfAborted();
    if(fresh.state!=='pending')throw new Error('Splendor transaction is already resolved.');if(Date.now()>=expiresAt)throw new Error('Recovery review expired.');
    const attempt=await onAttempt({networkId:pending.networkId,from:pending.from,hash:pending.hash,previousSubmissionId:snapshot.submissionId});assertCurrent();signal?.throwIfAborted();
    if(Date.now()>=expiresAt)throw new Error('Recovery review expired.');
    if(!attempt||typeof attempt.submissionId!=='string'||!/^[0-9a-f]{32}$/.test(attempt.submissionId)||attempt.submissionId===snapshot.submissionId)throw new Error('Fresh durable Splendor attempt identity is required.');
    // No retry regardless of transport/HTTP failure. Existing authenticated
    // pending row remains retained for a future explicit reconciliation.
    const response=await rpcFetch(nets[pending.networkId].url+'/tx/submit',{method:'POST',headers:{'Content-Type':'application/json'},body:wire,signal},{fetcher});
    if(response.status!==202)throw new Error(`Splendor recovery returned HTTP ${response.status}; outcome remains unresolved.`);
    const data=await response.json();if(data.status!=='accepted'||data.hash!==pending.hash)throw new Error('Unexpected Splendor recovery response; outcome remains unresolved.');
    return pending.hash;
   }finally{recoveries.delete(id);}
  }});
}

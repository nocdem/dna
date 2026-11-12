// Candidate native XION controller. Fee/gas MUST be explicitly supplied by
// caller; no default market/node gas price is invented. Not registered in UI.
// Cosmos SDK service.proto: BROADCAST_MODE_SYNC reports CheckTx only, never
// inclusion. Signed bytes are exposed only to the mandatory durable callback.
import { sha256 } from '@noble/hashes/sha2';
import { bytesToHex } from '@noble/hashes/utils';
import { base64 } from '@scure/base';
import { pqChainSeed } from './receive.js';
import { prepareXionTransfer } from './xion-prepare.js';
import { simulateXionTransfer } from './xion-simulate.js';
import { signXionTransfer } from './xion-sign.js';
import { integerJson, parseExactJson } from './integer-json.js';
import { rpcFetch } from '../rpc-transport.js';
import { assertWalletActive } from '../keys.js';
import { readXionLedgerHead } from './xion-ledger-head.js';
import { validXionPending, verifyXionSignedPayload } from './xion-recovery.js';
const nets=Object.freeze({mainnet:{url:'https://api.xion-mainnet-1.burnt.com',chain:'xion-mainnet-1'},testnet:{url:'https://api.xion-testnet-2.burnt.com',chain:'xion-testnet-2'}});
const held=new Map();
function active(wallet,from,signal){signal?.throwIfAborted();assertWalletActive(wallet);if(wallet.addresses?.xion!==from)throw Error('XION account changed.');}
export async function prepareXionReview({wallet,publicKey,to,amountAtoms,gasLimit,feeAtoms,timeoutHeight,networkId,signal,fetcher,wasmBytes}={}){
 if(!Object.hasOwn(nets,networkId))throw Error('Unsupported XION network.');
 if(timeoutHeight!==undefined)throw Error('XION timeout is chosen from the current network height.');
 if(!(publicKey instanceof Uint8Array)||publicKey.length!==1952)throw Error('XION public key is required.');
 if(typeof feeAtoms!=='string'||!/^[1-9]\d{0,19}$/.test(feeAtoms)||typeof gasLimit!=='string'||!/^[1-9]\d{0,19}$/.test(gasLimit)||BigInt(gasLimit)>10000000n)throw Error('Explicit bounded XION gas and fee are required.');
 const from=wallet?.addresses?.xion,key=`${networkId}:${from}`;active(wallet,from,signal);if(held.has(key))throw Error('An XION submission is already unresolved.');
 const initialHead=await readXionLedgerHead({networkId,signal,fetcher});active(wallet,from,signal);const expiry=BigInt(initialHead.height)+100n;if(expiry>2n**63n-1n)throw Error('XION height exceeds supported range.');timeoutHeight=String(expiry);
 const pk=Uint8Array.from(publicKey),args={networkId,from,to,amount:amountAtoms,fee:feeAtoms,gas:gasLimit,publicKey:pk,timeoutHeight,queryHeight:initialHead.height,signal,fetcher};
 const prepared=await prepareXionTransfer(args);active(wallet,from,signal);if(!prepared.sufficient)throw Error('Insufficient XION spendable balance.');
 const simulation=await simulateXionTransfer({...args,sequence:prepared.sequence,accountNumber:prepared.accountNumber});active(wallet,from,signal);
 if(BigInt(simulation.gasUsed)>BigInt(gasLimit))throw Error('Explicit XION gas limit is below the simulation estimate.');
 const expiresAt=Date.now()+60000;let used=false;
 return Object.freeze({from,to,networkId,amountAtoms,feeAtoms,gasLimit,gasUsed:simulation.gasUsed,sequence:prepared.sequence,accountNumber:prepared.accountNumber,timeoutHeight,expiresAt,
  cancel(){used=true;},
  async confirm(onBroadcast){
   if(used)throw Error('XION review already closed.');used=true;active(wallet,from,signal);
   if(typeof onBroadcast!=='function')throw Error('Durable XION submission recording is required.');
   if(Date.now()>=expiresAt)throw Error('XION review expired.');if(held.has(key))throw Error('An XION submission is already unresolved.');
   const reservation={hash:null};held.set(key,reservation);let seed,submitted=false;
   try{
    const signingHead=await readXionLedgerHead({networkId,signal,fetcher});active(wallet,from,signal);if(BigInt(signingHead.height)<BigInt(initialHead.height)||BigInt(signingHead.height)+5n>=BigInt(timeoutHeight))throw Error('XION timeout is too close; review again.');
    const fresh=await prepareXionTransfer({...args,queryHeight:signingHead.height});active(wallet,from,signal);
    if(!fresh.sufficient||fresh.sequence!==prepared.sequence||fresh.accountNumber!==prepared.accountNumber)throw Error('XION account changed; review again.');
    const sim=await simulateXionTransfer({...args,sequence:fresh.sequence,accountNumber:fresh.accountNumber});active(wallet,from,signal);
    if(BigInt(sim.gasUsed)>BigInt(gasLimit))throw Error('XION gas estimate changed; review again.');
    seed=pqChainSeed(wallet.recoveryPhrase,'xion');
    const wire=await signXionTransfer({...args,seed,wasmBytes,sequence:prepared.sequence,accountNumber:prepared.accountNumber});seed.fill(0);seed=undefined;
    active(wallet,from,signal);const hash=bytesToHex(sha256(wire));reservation.hash=hash;
    const attempt=await onBroadcast({hash,networkId,from,to,amountAtoms,feeAtoms,gasLimit,sequence:prepared.sequence,accountNumber:prepared.accountNumber,timeoutHeight,signedPayload:{encoding:'base64',data:base64.encode(wire)}});
    if(!attempt||typeof attempt.submissionId!=='string'||!/^[0-9a-f]{32}$/.test(attempt.submissionId))throw Error('Fresh durable XION attempt identity is required.');
    active(wallet,from,signal);if(Date.now()>=expiresAt)throw Error('XION review expired before submission.');
    const submitHead=await readXionLedgerHead({networkId,signal,fetcher});active(wallet,from,signal);if(BigInt(submitHead.height)<BigInt(signingHead.height)||BigInt(submitHead.height)+5n>=BigInt(timeoutHeight)||Date.now()>=expiresAt)throw Error('XION timeout is too close; review again.');
    const finalState=await prepareXionTransfer({...args,queryHeight:submitHead.height});active(wallet,from,signal);if(!finalState.sufficient||finalState.sequence!==prepared.sequence||finalState.accountNumber!==prepared.accountNumber||Date.now()>=expiresAt)throw Error('XION account changed; review again.');
    // State is pinned to submitHead; bound how far the node advanced while it
    // was fetched, and recheck the signed execution window immediately before POST.
    const postHead=await readXionLedgerHead({networkId,signal,fetcher});active(wallet,from,signal);if(BigInt(postHead.height)<BigInt(submitHead.height)||BigInt(postHead.height)>BigInt(submitHead.height)+5n||BigInt(postHead.height)+5n>=BigInt(timeoutHeight)||Date.now()>=expiresAt)throw Error('XION ledger advanced or timeout is too close; review again.');
    submitted=true;
    const response=await rpcFetch(nets[networkId].url+'/cosmos/tx/v1beta1/txs',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tx_bytes:base64.encode(wire),mode:'BROADCAST_MODE_SYNC'}),signal},{fetcher});
    const data=parseExactJson(await response.text()),tx=data?.tx_response;
    if(!response.ok||!tx||typeof tx.txhash!=='string'||tx.txhash.toLowerCase()!==hash||tx.code!=='0')throw Error('XION admission is uncertain or rejected; reconcile the exact transaction before retrying.');
    return hash;
   }catch(error){const failure=error instanceof Error?error:Error('XION transfer failed.');if(!submitted)failure.xionNotSubmitted=true;throw failure;}
   finally{seed?.fill(0);if(!submitted&&held.get(key)===reservation)held.delete(key);}
  }
 });
}
export async function observeXionSubmission({networkId,from,hash,signal,fetcher}={}){
 if(!Object.hasOwn(nets,networkId)||typeof hash!=='string'||!/^[0-9a-f]{64}$/.test(hash))throw Error('Invalid XION pending record.');
 const net=nets[networkId],opts={signal,fetcher};
 const info=await integerJson(net.url+'/cosmos/base/tendermint/v1beta1/node_info',opts);
 if(info.default_node_info?.network!==net.chain)throw Error('XION status network changed.');
 let response;try{response=await integerJson(`${net.url}/cosmos/tx/v1beta1/txs/${hash.toUpperCase()}`,opts);}catch(e){if(e.status===404)return {state:'pending',hash};throw e;}
 const tx=response.tx_response,msgs=response.tx?.body?.messages;
 if(!tx||typeof tx.txhash!=='string'||tx.txhash.toLowerCase()!==hash||!Array.isArray(msgs)||msgs.length!==1||msgs[0]?.['@type']!=='/cosmos.bank.v1beta1.MsgSend'||msgs[0].from_address!==from||typeof tx.height!=='string'||!/^[1-9]\d{0,19}$/.test(tx.height)||typeof tx.code!=='string'||!/^(0|[1-9]\d{0,9})$/.test(tx.code))throw Error('Invalid XION inclusion response.');
 const state=tx.code==='0'?'confirmed':'failed',key=`${networkId}:${from}`;
 if(held.get(key)?.hash===hash)held.delete(key);return {state,hash};
}

// Explicit user-confirmed same-byte recovery. A 404 is not proof of absence;
// no signing, automatic retry, or zero-POST proof for the earlier attempt.
const recoveries=new Set();
export async function prepareXionExactRecovery(row,{signal,fetcher,assertCurrent,wasmBytes}={}){
 if(typeof assertCurrent!=='function')throw Error('Active wallet guard is required.');assertCurrent();signal?.throwIfAborted();
 if(!row||row.executionWindowClosed!==undefined||!['pending','unknown'].includes(row.status)||(row.savedStatus!==undefined&&!['pending','unknown'].includes(row.savedStatus))||row.notSubmitted===true)throw Error('This XION activity is not eligible for exact recovery.');
 const snapshot={networkId:row.networkId,address:row.address,to:row.to,amountAtoms:row.amountAtoms,feeAtoms:row.feeAtoms,gasLimit:row.gasLimit,sequence:row.sequence,accountNumber:row.accountNumber,timeoutHeight:row.timeoutHeight,hash:row.hash,submissionId:row.submissionId,signedPayload:{encoding:row.signedPayload?.encoding,data:row.signedPayload?.data}};
 const raw=await verifyXionSignedPayload(snapshot,{wasmBytes,signal});assertCurrent();signal?.throwIfAborted();
 const pending={networkId:snapshot.networkId,from:snapshot.address,hash:snapshot.hash};if(snapshot.timeoutHeight!==undefined){const head=await readXionLedgerHead({networkId:snapshot.networkId,signal,fetcher});assertCurrent();if(BigInt(head.height)>BigInt(snapshot.timeoutHeight))throw Error('XION execution window is closed; do not replay.');}
 const prior=await observeXionSubmission({...pending,signal,fetcher});assertCurrent();signal?.throwIfAborted();if(prior.state!=='pending')throw Error('XION transaction is already included or resolved.');
 let used=false;const expiresAt=Date.now()+60000;return Object.freeze({networkId:snapshot.networkId,from:snapshot.address,to:snapshot.to,amountAtoms:snapshot.amountAtoms,feeAtoms:snapshot.feeAtoms,gasLimit:snapshot.gasLimit,sequence:snapshot.sequence,accountNumber:snapshot.accountNumber,timeoutHeight:snapshot.timeoutHeight,hash:snapshot.hash,expiresAt,notice:'A missing transaction is inconclusive. Confirming sends the exact same signed bytes; the earlier attempt may already be pending.',cancel(){used=true;},async confirm(onAttempt){
  if(used)throw Error('This recovery review is already closed.');used=true;assertCurrent();signal?.throwIfAborted();if(Date.now()>=expiresAt)throw Error('Recovery review expired.');if(typeof onAttempt!=='function')throw Error('Durable pending storage is required.');const key=`${snapshot.networkId}:${snapshot.address}`;if(recoveries.has(key))throw Error('XION recovery is already in progress.');recoveries.add(key);let submitted=false;
  try{if(snapshot.timeoutHeight!==undefined){const head=await readXionLedgerHead({networkId:snapshot.networkId,signal,fetcher});assertCurrent();if(BigInt(head.height)>BigInt(snapshot.timeoutHeight))throw Error('XION execution window is closed; do not replay.');}const fresh=await observeXionSubmission({...pending,signal,fetcher});assertCurrent();signal?.throwIfAborted();if(fresh.state!=='pending')throw Error('XION transaction is already included or resolved.');if(Date.now()>=expiresAt)throw Error('Recovery review expired.');
   const attempt=await onAttempt({networkId:snapshot.networkId,from:snapshot.address,hash:snapshot.hash,previousSubmissionId:snapshot.submissionId});assertCurrent();signal?.throwIfAborted();if(Date.now()>=expiresAt)throw Error('Recovery review expired.');if(!attempt||typeof attempt.submissionId!=='string'||!/^[0-9a-f]{32}$/.test(attempt.submissionId)||attempt.submissionId===snapshot.submissionId)throw Error('Fresh durable XION attempt identity is required.');
   if(snapshot.timeoutHeight!==undefined){const head=await readXionLedgerHead({networkId:snapshot.networkId,signal,fetcher});assertCurrent();signal?.throwIfAborted();if(BigInt(head.height)>BigInt(snapshot.timeoutHeight)||Date.now()>=expiresAt)throw Error('XION execution window is closed or review expired; do not replay.');}
   submitted=true;const response=await rpcFetch(nets[snapshot.networkId].url+'/cosmos/tx/v1beta1/txs',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tx_bytes:raw,mode:'BROADCAST_MODE_SYNC'}),signal},{fetcher});const data=parseExactJson(await response.text()),tx=data?.tx_response;if(!response.ok||!tx||typeof tx.txhash!=='string'||tx.txhash.toLowerCase()!==snapshot.hash||tx.code!=='0')throw Error('XION recovery admission is uncertain or rejected.');return snapshot.hash;
  }catch(e){const err=e instanceof Error?e:Error('XION recovery failed.');if(!submitted)err.xionRecoveryNotSubmitted=true;throw err;}finally{recoveries.delete(key);}
 }});
}

// Called only after the matching authenticated closed-window record is durable.
export function releaseXionClosedReservation(row){
 if(!validXionPending(row)||!row.executionWindowClosed)throw Error('Invalid XION closed-window evidence.');const key=`${row.networkId}:${row.address}`;if(held.get(key)?.hash===row.hash)held.delete(key);
}

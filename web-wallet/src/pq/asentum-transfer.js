// Testnet-only Asentum native transfer controller; no automatic retry.
// @asentum/sdk 0.2.0 transfer defaults gasLimit 21000, priority 0. Caller
// supplies a reviewed maximum fee/gas; finalized base fee is not a future quote.
import {bech32} from '@scure/base';
import {pqChainSeed} from './receive.js';
import {prepareAsentumTransfer} from './asentum-prepare.js';
import {signAsentumTransfer} from './asentum-sign.js';
import {validateAsentumSignedPayload} from './asentum-recovery.js';
import {integerJson} from './integer-json.js';
import {rpcFetch} from '../rpc-transport.js';
import {assertWalletActive} from '../keys.js';
const URL='https://testnet.asentum.com',GENESIS='0xc12243eee53d0a642c34845575687144802b79eabb07b213815ee907f0451aa3',pendingByAccount=new Map();
function active(wallet,from,signal){signal?.throwIfAborted();assertWalletActive(wallet);if(wallet.addresses?.asentum!==from)throw new Error('Asentum account changed.');}
function hexAddress(s){try{const d=bech32.decode(s),b=bech32.fromWords(d.words);if(d.prefix!=='ase'||b.length!==20||bech32.encode('ase',bech32.toWords(b))!==s)throw 0;return '0x'+Array.from(b,x=>x.toString(16).padStart(2,'0')).join('');}catch{throw new Error('Invalid Asentum address.');}}
async function identity(opts){const chain=await integerJson(URL+'/chain',opts);opts.signal?.throwIfAborted();const genesis=await integerJson(URL+'/genesis',opts);opts.signal?.throwIfAborted();if(chain.chainId!=='1423'||genesis.chainId!=='1423'||genesis.genesisHash!==GENESIS)throw new Error('Asentum provider is connected to the wrong network.');return chain;}
export async function quoteAsentumTransfer({networkId='testnet',signal,fetcher}={}){if(networkId!=='testnet')throw new Error('Unsupported Asentum network.');const chain=await identity({signal,fetcher}),baseFee=chain.latestHeader?.baseFeePerGas;if(typeof baseFee!=='string'||!/^[1-9]\d{0,77}$/.test(baseFee)||BigInt(baseFee)>=2n**256n)throw new Error('Invalid Asentum base fee.');return {gasLimit:'21000',maxPriorityFeePerGas:'0',baseFeePerGas:baseFee,maximumFee:(21000n*BigInt(baseFee)).toString()};}
export function asentumPendingSubmission(wallet){return pendingByAccount.get(wallet?.addresses?.asentum)?.hash??null;}
export async function observeAsentumSubmission(pending,{signal,fetcher}={}){
 if(!pending||pending.networkId!=='testnet'||typeof pending.hash!=='string'||!/^0x[0-9a-f]{64}$/.test(pending.hash))throw new Error('Invalid Asentum pending record.');const from=hexAddress(pending.from),to=hexAddress(pending.to),opts={signal,fetcher};await identity(opts);
 const r=await integerJson(`${URL}/receipts/${pending.hash}`,{...opts,allowError:true});signal?.throwIfAborted();
 if(r.txHash!==pending.hash)throw new Error('Conflicting Asentum receipt.');
 if(r.blockNumber===undefined){if(r.error==='receipt not found')return {state:'pending',hash:pending.hash};throw new Error('Invalid Asentum receipt response.');}
 if(typeof r.blockNumber!=='string'||!/^(0|[1-9]\d{0,19})$/.test(r.blockNumber)||BigInt(r.blockNumber)>=2n**64n||typeof r.blockHash!=='string'||!/^0x[0-9a-f]{64}$/.test(r.blockHash)||r.sender!==from||r.recipient!==to||r.kind!=='transfer'||typeof r.success!=='boolean'||typeof r.finalized!=='boolean')throw new Error('Conflicting Asentum receipt.');
 const state=!r.finalized?'included':r.success?'confirmed':'failed';if(r.finalized&&pendingByAccount.get(pending.from)?.hash===pending.hash)pendingByAccount.delete(pending.from);return {state,hash:pending.hash};
}
export async function prepareAsentumReview({wallet,to,amount,maxFeePerGas,networkId='testnet',signal,fetcher,wasmBytes}={}){
 const from=wallet?.addresses?.asentum;active(wallet,from,signal);if(pendingByAccount.has(from))throw new Error('An Asentum transfer is already pending.');
 const args={networkId,from,to,amount,gasLimit:'21000',maxFeePerGas,maxPriorityFeePerGas:'0',signal,fetcher},prepared=await prepareAsentumTransfer(args);active(wallet,from,signal);
 if(!prepared.sufficient)throw new Error('Insufficient ASE balance.');if(!prepared.feeAdequate)throw new Error('Asentum max fee is below reported finalized base fee.');
 const expiresAt=Date.now()+120000;let used=false;return Object.freeze({networkId,from,to,amount,nonce:prepared.nonce,gasLimit:prepared.gasLimit,maxFeePerGas,maximumFee:prepared.maximumFee,expiresAt,cancel(){used=true;},async confirm(onBroadcast){
  if(used)throw new Error('This review is already closed.');used=true;active(wallet,from,signal);if(typeof onBroadcast!=='function')throw new Error('Durable Asentum submission recording is required.');if(Date.now()>=expiresAt)throw new Error('Review expired. Prepare again.');if(pendingByAccount.has(from))throw new Error('An Asentum transfer is already pending.');
  const reservation={hash:null};pendingByAccount.set(from,reservation);let seed,submitted=false;
  try{const fresh=await prepareAsentumTransfer(args);active(wallet,from,signal);if(fresh.nonce!==prepared.nonce)throw new Error('Asentum pending nonce changed. Review again.');if(!fresh.sufficient||!fresh.feeAdequate)throw new Error('Asentum balance or reported fee changed. Review again.');if(Date.now()>=expiresAt)throw new Error('Review expired. Prepare again.');
   seed=pqChainSeed(wallet.recoveryPhrase,'asentum');const signed=await signAsentumTransfer({...prepared,seed,signal,wasmBytes});seed.fill(0);seed=undefined;active(wallet,from,signal);if(Date.now()>=expiresAt)throw new Error('Review expired. Prepare again.');
   const record=Object.freeze({networkId,from,to,amount,nonce:prepared.nonce,gasLimit:prepared.gasLimit,maxFeePerGas,hash:signed.txHash,signedPayload:Object.freeze({encoding:'hex',data:signed.rawTx})});reservation.hash=record.hash;await onBroadcast(record);active(wallet,from,signal);if(Date.now()>=expiresAt)throw new Error('Review expired. Prepare again.');
   submitted=true;const response=await rpcFetch(URL+'/tx',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({rawTx:signed.rawTx}),signal},{fetcher});
   if(!response.ok)throw new Error(`Asentum submission returned HTTP ${response.status}; check pending status before retrying.`);const data=await response.json();if(data.accepted!==true||data.txHash!==record.hash)throw new Error('Asentum submission was not positively acknowledged; check pending status before retrying.');return record.hash;
  }catch(e){const err=e instanceof Error?e:new Error('Asentum transfer failed.');if(!submitted)err.asentumNotSubmitted=true;throw err;}finally{seed?.fill(0);if(!submitted&&pendingByAccount.get(from)===reservation)pendingByAccount.delete(from);}
 }});
}
// Explicit same-byte recovery; a missing receipt is not evidence of absence.
// No auto-retry or signing. A fresh durable attempt ID is mandatory because a
// cancellation proof for an earlier identical hash must not release this one.
const recoveries=new Set();
export async function prepareAsentumExactRecovery(row,{signal,fetcher,assertCurrent}={}){
 if(typeof assertCurrent!=='function')throw new Error('Active wallet guard is required.');assertCurrent();signal?.throwIfAborted();
 if(!row||typeof row.submissionId!=='string'||!/^[0-9a-f]{32}$/.test(row.submissionId)||!['pending','unknown'].includes(row.status)||(row.savedStatus!==undefined&&!['pending','unknown'].includes(row.savedStatus))||row.notSubmitted===true)throw new Error('This Asentum activity is not eligible for exact recovery.');
 const snapshot={networkId:row.networkId,address:row.address,to:row.to,amountAtoms:row.amountAtoms,nonce:row.nonce,gasLimit:row.gasLimit,maxFeePerGas:row.maxFeePerGas,hash:row.hash,submissionId:row.submissionId,signedPayload:{encoding:row.signedPayload?.encoding,data:row.signedPayload?.data}};
 const raw=validateAsentumSignedPayload(snapshot),pending={networkId:snapshot.networkId,from:snapshot.address,to:snapshot.to,hash:snapshot.hash};
 const prior=await observeAsentumSubmission(pending,{signal,fetcher});assertCurrent();signal?.throwIfAborted();if(prior.state!=='pending')throw new Error('Asentum transaction is already included or resolved.');
 let used=false;const expiresAt=Date.now()+120000;return Object.freeze({networkId:snapshot.networkId,from:snapshot.address,to:snapshot.to,amount:snapshot.amountAtoms,nonce:snapshot.nonce,gasLimit:snapshot.gasLimit,maxFeePerGas:snapshot.maxFeePerGas,maximumFee:(BigInt(snapshot.gasLimit)*BigInt(snapshot.maxFeePerGas)).toString(),hash:snapshot.hash,expiresAt,notice:'Receipt not found is inconclusive. Confirming submits the exact same signed transaction; it may already be pending.',cancel(){used=true;},async confirm(onAttempt){
  if(used)throw new Error('This recovery review is already closed.');used=true;assertCurrent();signal?.throwIfAborted();if(Date.now()>=expiresAt)throw new Error('Recovery review expired.');if(typeof onAttempt!=='function')throw new Error('Durable pending storage is required.');const key=snapshot.address;if(recoveries.has(key))throw new Error('Asentum recovery is already in progress.');recoveries.add(key);
  try{const fresh=await observeAsentumSubmission(pending,{signal,fetcher});assertCurrent();signal?.throwIfAborted();if(fresh.state!=='pending')throw new Error('Asentum transaction is already included or resolved.');if(Date.now()>=expiresAt)throw new Error('Recovery review expired.');const attempt=await onAttempt({networkId:snapshot.networkId,from:snapshot.address,hash:snapshot.hash,previousSubmissionId:snapshot.submissionId});assertCurrent();signal?.throwIfAborted();if(Date.now()>=expiresAt)throw new Error('Recovery review expired.');if(!attempt||typeof attempt.submissionId!=='string'||!/^[0-9a-f]{32}$/.test(attempt.submissionId)||attempt.submissionId===snapshot.submissionId)throw new Error('Fresh durable Asentum attempt identity is required.');
   const response=await rpcFetch(URL+'/tx',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({rawTx:raw}),signal},{fetcher});if(!response.ok)throw new Error(`Asentum recovery returned HTTP ${response.status}; outcome remains unresolved.`);const data=await response.json();if(data.accepted!==true||data.txHash!==snapshot.hash)throw new Error('Unexpected Asentum recovery response; outcome remains unresolved.');return snapshot.hash;
  }finally{recoveries.delete(key);}
 }});
}

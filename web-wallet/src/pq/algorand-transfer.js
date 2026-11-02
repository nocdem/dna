// Mainnet transfer-review controller; callers must persist pending records before submission.
// Only confirm() can submit. No retry on any ambiguous submission; pending hash
// is recorded before the network call. Caller supplies existing wallet custody.
import {sha512_256} from '@noble/hashes/sha512';
import {pqChainSeed} from './receive.js';
import {prepareAlgorandPayment,algorandAddressBytes} from './algorand-prepare.js';
import {signAlgorandPayment} from './algorand-payment-sign.js';
import {algorandNetwork} from './algorand.js';
import {integerJson} from './integer-json.js';
import {ALGORAND_FALCON_PROTOCOL} from './algorand-prepare.js';
import {rpcFetch} from '../rpc-transport.js';
import {assertWalletActive} from '../keys.js';
const inFlight=new Map();
const walletKey=wallet=>wallet?.addresses?.algorand;
function check(wallet,from,signal){signal?.throwIfAborted();assertWalletActive(wallet);if(wallet.addresses?.algorand!==from)throw new Error('Algorand account changed.');}
export function algorandPendingSubmission(wallet){return inFlight.get(walletKey(wallet))?.hash??null;}
export async function reconcileAlgorandSubmission(wallet,{signal,fetcher}={}){
 const pending=inFlight.get(walletKey(wallet));
 if(!pending)return {state:'none'};
 if(!pending.hash)return {state:'preparing'};
 return observeAlgorandSubmission(pending,{signal,fetcher});
}
export async function observeAlgorandSubmission(pending,{signal,fetcher}={}){
 if(!pending||pending.networkId!=='mainnet'||typeof pending.hash!=='string'||!/^[A-Z2-7]{52}$/.test(pending.hash)||typeof pending.lastValid!=='string'||!/^[1-9]\d{0,19}$/.test(pending.lastValid))throw new Error('Invalid Algorand pending record.');
 algorandAddressBytes(pending.from);
 const network=algorandNetwork(pending.networkId),options={signal,fetcher};
 const params=await integerJson(`${network.algod}/v2/transactions/params`,options);
 if(params['genesis-hash']!==network.genesisHash||params['genesis-id']!==`${pending.networkId}-v1.0`||params['consensus-version']!==ALGORAND_FALCON_PROTOCOL)throw new Error('Algorand pending-status network changed.');
 let result;
 try{result=await integerJson(`${network.algod}/v2/transactions/pending/${pending.hash}`,options);}
 catch(error){if(error.status!==404)throw error;}
 let state='pending';
 const round=value=>typeof value==='string'&&/^(0|[1-9]\d{0,19})$/.test(value)&&BigInt(value)<(1n<<64n)?BigInt(value):null;
 if(result&&result.txn?.txn?.snd!==pending.from)throw new Error('Algorand pending response has different sender.');
 const confirmed=result?.['confirmed-round']===undefined?0n:round(result['confirmed-round']);
 if(confirmed===null)throw new Error('Invalid Algorand confirmation round.');
 if(confirmed>0n)state='confirmed';
 else {
  // Pending pools forget old confirmations. Reconcile against the indexed
  // ledger, with its own genesis identity and indexed-through round. A 404 or
  // lagging/incomplete page is NEVER evidence that a payment was not included.
  // Official schema: dev.algorand.co/reference/rest-api/indexer/operations/searchfortransactions/
  const genesis=await integerJson(`${network.indexer}/v2/blocks/0?header-only=true`,options);
  if(genesis['genesis-hash']!==network.genesisHash||round(genesis.round)!==0n)throw new Error('Algorand indexer network changed.');
  const page=await integerJson(`${network.indexer}/v2/transactions?txid=${pending.hash}&limit=2`,options);
  const indexed=round(page['current-round']);
  if(indexed===null||!Array.isArray(page.transactions)||page.transactions.length>1)throw new Error('Invalid Algorand indexed status.');
  if(page.transactions.length){
   const tx=page.transactions[0],included=round(tx['confirmed-round']);
   if(tx.id!==pending.hash||tx.sender!==pending.from||tx['tx-type']!=='pay'||included===null||included===0n||included>indexed||included>BigInt(pending.lastValid))throw new Error('Conflicting Algorand indexed payment.');
   state='confirmed';
  }else if(!page['next-token']&&indexed>BigInt(pending.lastValid))state='expired';
 }
 if(state!=='pending'&&inFlight.get(pending.from)?.hash===pending.hash)inFlight.delete(pending.from);
 return {state,hash:pending.hash};
}
export async function prepareAlgorandTransfer({wallet,to,amountAtoms,maxFeeAtoms,networkId='mainnet',signal,fetcher,wasmBytes}={}){
 if(networkId!=='mainnet')throw new Error('Algorand sending is enabled only on verified mainnet.');
 const from=wallet?.addresses?.algorand;check(wallet,from,signal);
 if(inFlight.has(walletKey(wallet)))throw new Error('An Algorand transfer is already pending.');
 const args={from,to,amountAtoms,maxFeeAtoms,networkId,signal,fetcher};
 const prepared=await prepareAlgorandPayment(args);check(wallet,from,signal);
 let used=false;
 return Object.freeze({from,to,networkId,amountAtoms:prepared.amountAtoms,feeAtoms:prepared.feeAtoms,expiresAt:prepared.expiresAt,
  cancel(){used=true;},
  async confirm(onBroadcast){
   if(used)throw new Error('This review is already closed.');used=true;
   check(wallet,from,signal);
   if(typeof onBroadcast!=='function')throw new Error('Durable Algorand submission recording is required.');
   if(Date.now()>=prepared.expiresAt)throw new Error('Review expired. Prepare again.');
   if(inFlight.has(walletKey(wallet)))throw new Error('An Algorand transfer is already pending.');
   const reservation={hash:null,networkId,from,lastValid:prepared.payment.lastValid};inFlight.set(walletKey(wallet),reservation);
   let root,seed,submitted=false;
   try {
    const fresh=await prepareAlgorandPayment({...args,maxFeeAtoms:prepared.feeAtoms});
    check(wallet,from,signal);
    if(fresh.feeAtoms!==prepared.feeAtoms)throw new Error('Algorand fee changed. Review again.');
    if(BigInt(fresh.payment.firstValid)>BigInt(prepared.payment.lastValid)||Date.now()>=prepared.expiresAt)throw new Error('Review expired. Prepare again.');
    root=pqChainSeed(wallet.recoveryPhrase,'algorand');
    const input=new Uint8Array(37);input.set(new TextEncoder().encode('PQKf1'));input.set(root,5);
    try{seed=sha512_256(input);}finally{input.fill(0);root.fill(0);root=undefined;}
    const signed=await signAlgorandPayment({seed,payment:prepared.payment,networkId,wasmBytes,signal});
    seed.fill(0);seed=undefined;check(wallet,from,signal);
    if(Date.now()>=prepared.expiresAt)throw new Error('Review expired. Prepare again.');
    reservation.hash=signed.transactionId;
    await onBroadcast({hash:signed.transactionId,networkId,lastValid:prepared.payment.lastValid,lastValidBlockHeight:Number(prepared.payment.lastValid)});
    check(wallet,from,signal);
    // From this point a thrown/invalid response is ambiguous; preserve the hash
    // and forbid automatic resubmission, even if the transport says it failed.
    submitted=true;
    const response=await rpcFetch(`${algorandNetwork(networkId).algod}/v2/transactions`,{
     method:'POST',headers:{'Content-Type':'application/x-binary'},body:signed.signedBytes,signal}, {fetcher});
    if(!response.ok)throw new Error(`Algorand submission returned HTTP ${response.status}; check the pending transaction before retrying.`);
    const data=await response.json();
    if(data.txId!==signed.transactionId)throw new Error('Algorand returned a different transaction identifier; check pending status.');
    return signed.transactionId;
   }catch(error){
    const failure=error instanceof Error?error:new Error('Algorand transfer failed.');
    if(!submitted)failure.algorandNotSubmitted=true;
    throw failure;
   }finally{root?.fill(0);seed?.fill(0);if(!submitted&&inFlight.get(walletKey(wallet))===reservation)inFlight.delete(walletKey(wallet));}
  }
 });
}

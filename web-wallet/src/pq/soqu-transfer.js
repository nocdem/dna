// Native SOQ payment lifecycle. Only caller-confirmed sends; no automatic retry.
// Before submission the caller MUST durably retain hash + consumed outpoints.
// This module does not replace the caller's authenticated restart-time hold.
import {validateSoquSignedPayload} from './soqu-signed-payload.js';
import {integerJson,atoms} from './integer-json.js';
import {soquScript} from './soqu-transaction.js';
import {soqucoinSigningSeed} from './receive.js';
import {prepareVerifiedSoquPayment,checkSoquMainnet,checkSoquInput,soquRpc,SOQU_MAINNET} from './soqu-preflight.js';
import {signSoquPayment} from './soqu-payment.js';
const inFlight=new Map();
function check(wallet,from,signal){signal?.throwIfAborted();if(!wallet||wallet.locked||wallet.addresses?.soqucoin!==from)throw Error('SOQ wallet is locked or changed.');}
export function soquPendingSubmission(from){return inFlight.get(from)?.hash??null;}
export async function prepareSoquTransfer({wallet,to,amountAtoms,networkId='mainnet',signal,fetcher,wasmBytes}={}){
 const from=wallet?.addresses?.soqucoin;check(wallet,from,signal);
 if(inFlight.has(from))throw Error('A SOQ payment is already pending.');
 const options={signal,fetcher};
 const {prepared,feeRate}=await prepareVerifiedSoquPayment({from,to,amountAtoms,networkId,...options});check(wallet,from,signal);
 let used=false;const expiresAt=Date.now()+60000;
 return Object.freeze({from,to,amountAtoms:String(prepared.amount),feeAtoms:String(prepared.fee),feeRate:String(feeRate),networkId,expiresAt,
  cancel(){used=true;},
  async confirm(onBroadcast){
   if(used)throw Error('This SOQ review is already closed.');used=true;check(wallet,from,signal);
   if(typeof onBroadcast!=='function')throw Error('Durable SOQ submission recording is required.');
   if(Date.now()>=expiresAt)throw Error('SOQ review expired.');
   if(inFlight.has(from))throw Error('A SOQ payment is already pending.');
   const reservation={hash:null};inFlight.set(from,reservation);let seed,submitted=false;
   try{
    const recheck=async()=>{const tip=await checkSoquMainnet(options);for(const input of prepared.transaction.inputs)if(!await checkSoquInput(input,from,tip,options))throw Error('SOQ input is spent or immature; prepare again.');check(wallet,from,signal);};
    await recheck();seed=await soqucoinSigningSeed(wallet.recoveryPhrase,{signal});
    const signed=await signSoquPayment(prepared,{seed,wasmBytes,signal});seed.fill(0);seed=undefined;
    check(wallet,from,signal);await recheck();if(Date.now()>=expiresAt)throw Error('SOQ review expired.');
    reservation.hash=signed.txid;
    await onBroadcast({hash:signed.txid,networkId,feeAtoms:String(prepared.fee),signedPayload:{encoding:'hex',data:signed.raw},inputs:prepared.transaction.inputs.map(({txid,vout})=>({txid,vout}))});
    check(wallet,from,signal);if(Date.now()>=expiresAt)throw Error('SOQ review expired before submission.');
    submitted=true;
    const txid=await soquRpc('sendrawtransaction',[signed.raw],options);
    if(txid!==signed.txid)throw Error('SOQ broadcast reply has a different transaction ID; outcome is uncertain.');
    return txid;
   }catch(error){const failure=error instanceof Error?error:Error('SOQ transfer failed.');if(!submitted)failure.soquNotSubmitted=true;throw failure;}
   finally{seed?.fill(0);if(!submitted&&inFlight.get(from)===reservation)inFlight.delete(from);}
  }
 });
}
// Missing transactions never prove non-submission. Without txindex, official
// indexer history supplies a candidate height only; canonical-node block reads
// must prove inclusion. Endpoint paths: pinned SoquShield balance_service.dart;
// getblock JSON: pinned node src/rpc/blockchain.cpp blockToJSON.
export async function reconcileSoquSubmission({from,hash,signal,fetcher}={}){
 soquScript(from);
 if(typeof hash!=='string'||!/^[0-9a-f]{64}$/.test(hash))throw Error('Invalid SOQ transaction ID.');
 const options={signal,fetcher},tip=await checkSoquMainnet(options);let tx;
 try{tx=await soquRpc('getrawtransaction',[hash,1],options);}
 catch(error){if(error.rpcCode!=='-5')throw error;}
 let confirmed=false;
 if(tx){
  if(tx.txid!==hash)throw Error('SOQ node returned a different transaction.');
  confirmed=typeof tx.confirmations==='string'&&/^[1-9]\d{0,9}$/.test(tx.confirmations)&&typeof tx.blockhash==='string'&&/^[0-9a-f]{64}$/.test(tx.blockhash);
 }
 if(!confirmed){
  const page=await integerJson(`${SOQU_MAINNET.api}/api/v2/history/${encodeURIComponent(from)}`,options);
  if(page.address!==from||!Array.isArray(page.transactions)||page.transactions.length>5000)throw Error('Invalid SOQ historical index.');
  const matches=page.transactions.filter(row=>row?.txid===hash);
  if(matches.length>1)throw Error('Ambiguous SOQ historical index.');
  const found=matches[0];
  if(found?.confirmed===true){
   const height=atoms(found.height);
   if(height>0n&&height<=BigInt(tip.height)){
    const blockhash=await soquRpc('getblockhash',[Number(height)],options);
    if(typeof blockhash!=='string'||!/^[0-9a-f]{64}$/.test(blockhash))throw Error('Invalid SOQ historical block hash.');
    const block=await soquRpc('getblock',[blockhash,1],options);
    if(!block||block.hash!==blockhash||block.height!==String(height)||!Array.isArray(block.tx)||block.tx.length>100000||!block.tx.every(id=>typeof id==='string'&&/^[0-9a-f]{64}$/.test(id)))throw Error('Invalid SOQ historical block proof.');
    confirmed=typeof block.confirmations==='string'&&/^[1-9]\d{0,9}$/.test(block.confirmations)&&block.tx.includes(hash);
   }
  }
 }
 if(confirmed&&inFlight.get(from)?.hash===hash)inFlight.delete(from);
 return {state:confirmed?'confirmed':'pending',hash};
}

// Explicit, user-reviewed exact replay. This never derives a key or signs and
// never retries a POST. Any failed replay remains uncertain: an earlier attempt
// may have reached the network even when this one did not.
export async function prepareSoquResubmission({wallet,row,signal,fetcher}={}){
 const from=wallet?.addresses?.soqucoin;check(wallet,from,signal);
 if(!row||row.address!==from||row.notSubmitted===true||!['pending','unknown'].includes(row.status))throw Error('This SOQ record is not eligible for same-transaction recovery.');
 const snapshot=structuredClone(row),signed=validateSoquSignedPayload(snapshot),options={signal,fetcher};
 const reconcile=()=>reconcileSoquSubmission({from,hash:signed.hash,...options});
 if((await reconcile()).state==='confirmed')throw Error('SOQ transaction is already confirmed; no resubmission is needed.');
 check(wallet,from,signal);let used=false;const expiresAt=Date.now()+60000;
 return Object.freeze({from,to:snapshot.to,networkId:'mainnet',amount:snapshot.amount,feeAtoms:snapshot.feeAtoms,hash:signed.hash,expiresAt,isResubmission:true,
  cancel(){used=true;},
  async confirm(onBroadcast){
   if(used)throw Error('This SOQ recovery review is already closed.');used=true;check(wallet,from,signal);
   if(typeof onBroadcast!=='function'||Date.now()>=expiresAt)throw Error('SOQ recovery review expired or durable recording unavailable.');
   if((await reconcile()).state==='confirmed')throw Error('SOQ transaction is already confirmed; no resubmission is needed.');
   check(wallet,from,signal);
   await onBroadcast({hash:signed.hash,networkId:'mainnet',feeAtoms:snapshot.feeAtoms,signedPayload:{encoding:'hex',data:signed.raw},inputs:snapshot.inputs.map(({txid,vout})=>({txid,vout}))});
   check(wallet,from,signal);if(Date.now()>=expiresAt)throw Error('SOQ recovery review expired.');
   let result;
   try{result=await soquRpc('sendrawtransaction',[signed.raw],options);}
   catch(error){
    // Pinned node sendrawtransaction returns its hash when already in mempool;
    // an already-mined transaction raises RPC_TRANSACTION_ALREADY_IN_CHAIN.
    // Treat that as success only after fresh positive canonical confirmation.
    if(error.rpcCode==='-27'&&(await reconcile()).state==='confirmed')return signed.hash;
    throw error;
   }
   if(result!==signed.hash)throw Error('SOQ replay returned a different transaction ID; keep the original reservation.');
   return signed.hash;
  }
 });
}

// Isolated CKB review/sign controller; deliberately not wired to any send gate.
// Host MUST provide a cross-context atomic outpoint reservation and release,
// an independently authenticated local node simulation of the exact signed tx,
// and an authenticated persistent submission hold before any later broadcast.
// This controller never broadcasts; indexer/node responses are assertions, not
// SPV proofs. No cellbase outputs are selected, even when mature.
import {findCkbQuantumCells,readCkbFeeRates,recheckCkbQuantumCells} from './ckb-preflight.js';
import {ckbQuantumAddressLock,prepareCkbQuantumTransaction,signPreparedCkbQuantumTransaction,ckbPreparedRpcTransaction} from './ckb-quantum-transaction.js';
import {CKB_FULL_RECIPIENT_SEND_ENABLED} from './ckb-recipient-policy.js';
import {parseCkbFullRecipient} from './ckb-full-recipient.js';
import {quoteCkbQuantumFee,checkCkbQuantumFee} from './ckb-fee.js';
import {blake2b} from '@noble/hashes/blake2b';import {bytesToHex,utf8ToBytes} from '@noble/hashes/utils';
const hash=raw=>'0x'+bytesToHex(blake2b(raw,{dkLen:32,personalization:utf8ToBytes('ckb-default-hash')}));
const key=i=>bytesToHex(i.outpoint);
export async function prepareCkbReview({from,to,amount,networkId='mainnet',maxFee,maxRate,cycleCeiling,reserve,release,signal,fetcher}={}){
 if(typeof reserve!=='function'||typeof release!=='function')throw Error('Atomic CKB reservation service required.');
 if(typeof amount!=='bigint'||typeof maxRate!=='bigint'||maxRate<1000n||maxRate>1000000n||typeof maxFee!=='bigint')throw Error('Invalid CKB review limits.');
 if(!CKB_FULL_RECIPIENT_SEND_ENABLED)ckbQuantumAddressLock(to,networkId);const recipient=parseCkbFullRecipient(to,networkId);if(amount<recipient.minimumCapacity)throw Error('CKB recipient amount is below occupied capacity.');
 const options={networkId,signal,fetcher},[found,rates]=await Promise.all([findCkbQuantumCells(from,options),readCkbFeeRates(options)]);
 if(found.tip.hash!==rates.tip.hash)throw Error('CKB tip changed; prepare again.');
 const rate=[1000n,rates.minimum,rates.median].reduce((a,b)=>a>b?a:b);if(rate>maxRate)throw Error('CKB fee rate exceeds approved cap.');
 let prepared,quote;const selected=[];
 for(const cell of found.cells){
  selected.push(cell);
  try{
   const provisional=prepareCkbQuantumTransaction({from,to,amount,fee:1n,networkId,inputs:selected});
   quote=quoteCkbQuantumFee(provisional,{feeRate:rate,cycleCeiling,maxFee});
   prepared=prepareCkbQuantumTransaction({from,to,amount,fee:quote.fee,networkId,inputs:selected});
   const real=quoteCkbQuantumFee(prepared,{feeRate:rate,cycleCeiling,maxFee});if(real.fee!==quote.fee)throw Error('CKB output shape changed during fee calculation.');
   if(real.size>rates.sizeLimit)throw Error('CKB transaction exceeds node size limit.');break;
  }catch(e){if(!/Insufficient CKB capacity|below occupied capacity/.test(e.message))throw e;}
 }
 if(!prepared)throw Error(found.truncated?'Insufficient CKB cells on this bounded page.':'Insufficient verified CKB cells.');
 const outpoints=prepared.inputs.map(key),inputCapacities=prepared.inputs.map(i=>i.capacity.toString()),reservation=await reserve({networkId,from,outpoints:[...outpoints]});
 if(!reservation)throw Error('CKB inputs are already reserved.');
 if(signal?.aborted){await release(reservation);signal.throwIfAborted();}
 let closed=false,handedOff=false,exposed=false;const expiresAt=Date.now()+60000;
 async function close(){if(!closed){closed=true;if(!handedOff)await release(reservation);}}
 return Object.freeze({from,to,networkId,amount:amount.toString(),fee:prepared.fee.toString(),feeRate:rate.toString(),cycleCeiling:cycleCeiling.toString(),expiresAt,outpoints:Object.freeze([...outpoints]),inputCapacities:Object.freeze([...inputCapacities]),
  cancel:close,
  async signAfterConfirmation({seed,rnd,wasmBytes,simulate,persistPending}={}){
   if(closed)throw Error('CKB review is closed.');closed=true;
   const seedCopy=seed instanceof Uint8Array?seed.slice():seed;
   try{
    if(typeof simulate!=='function'||typeof persistPending!=='function')throw Error('Exact CKB node simulation and durable pending hold are required.');if(Date.now()>=expiresAt)throw Error('CKB review expired.');
    await recheckCkbQuantumCells(from,prepared.inputs,options);const signed=await signPreparedCkbQuantumTransaction(prepared,{seed:seedCopy,rnd,wasmBytes,signal});
    await recheckCkbQuantumCells(from,prepared.inputs,options);if(Date.now()>=expiresAt)throw Error('CKB review expired.');
    const txid=hash(signed.rawTransaction),rpcTransaction=ckbPreparedRpcTransaction(prepared,signed);
    // A remote simulator sees a valid signed transaction and could relay it.
    // Persist the hold before that disclosure and never release it on an
    // uncertain or negative response; host must reconcile explicitly.
    const attempt=await persistPending({txid,networkId,from,to,outpoints:[...outpoints],inputCapacities:[...inputCapacities],amount:amount.toString(),fee:prepared.fee.toString(),state:'signed-exposure-pending',signedPayload:{encoding:'json',data:JSON.stringify(rpcTransaction)}});
    handedOff=true;if(!attempt||typeof attempt.submissionId!=='string'||!/^[0-9a-f]{32}$/.test(attempt.submissionId))throw Error('Fresh durable CKB attempt identity required.');signal?.throwIfAborted();if(Date.now()>=expiresAt)throw Error('CKB review expired before simulation.');
    exposed=true;const simulation=await simulate({transaction:signed.transaction.slice(),rpcTransaction:structuredClone(rpcTransaction),txid,networkId,signal});
    if(simulation?.txid!==txid||typeof simulation.cycles!=='bigint'||simulation.cycles<=0n||simulation.cycles>cycleCeiling)throw Error('CKB node simulation is missing, mismatched or exceeds cycle ceiling.');
    checkCkbQuantumFee(prepared,signed,{feeRate:rate,cycleCeiling,maxFee});signal?.throwIfAborted();if(Date.now()>=expiresAt)throw Error('CKB review expired.');
    // Host now owns reservation and MUST persist a durable submission hold
    // before making a later, separately authorized broadcast.
    return {transaction:signed.transaction,rpcTransaction,txid,networkId,outpoints:[...outpoints],reservation,amount:amount.toString(),fee:prepared.fee.toString(),cycles:simulation.cycles.toString()};
   }catch(error){if(error instanceof Error){if(handedOff)error.ckbReservationRetained=true;if(!exposed)error.ckbNotExposed=true;}throw error;}finally{seedCopy?.fill?.(0);if(!handedOff)await release(reservation);}
  }
 });
}

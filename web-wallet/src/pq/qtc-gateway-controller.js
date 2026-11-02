// Explicit official structured-UTXO gateway variant: fixed SIGHASH_DEFAULT
// commits all claimed input values/scripts and outputs; native consensus uses
// actual prevouts, so false provider values cannot authorize a different spend.
// Structured index spendability remains a provider/liveness trust assumption.
// No raw-prevout endpoint or public simulation call is requested.
// This module only hands off signed bytes after durable recording; the trusted
// host separately invokes the final submit gateway. See qtc-send-host-status.md.
import {qtcGatewayBody} from './qtc-gateway.js';
import {findQtcCandidates,readQtcFeeRates} from './qtc-preflight.js';import {prepareQtcPayment} from './qtc-payment.js';import {signQtcPayment} from './qtc-payment-sign.js';
const key=i=>`${i.txid}:${i.vout}`;
export async function prepareQtcGatewayReview({from,to,amount,networkId='mainnet',maxFee,maxRate,dustRate=3000n,reserve,release,signal,fetcher}={}){
 if(typeof reserve!=='function'||typeof release!=='function')throw Error('QTC atomic reservation is required.');
 if(typeof amount!=='bigint'||typeof maxRate!=='bigint'||maxRate<1n||maxRate>100000n||typeof maxFee!=='bigint')throw Error('Invalid QTC review limits.');
 const options={networkId,signal,fetcher},[found,fees]=await Promise.all([findQtcCandidates(from,options),readQtcFeeRates(options)]);
 if(found.tip.hash!==fees.tip.hash||found.tip.height!==fees.tip.height)throw Error('QTC explorer tip changed; prepare again.');
 const rate=fees.rates['6'];if(rate===null||rate<1n||rate>maxRate)throw Error('QTC fee estimate unavailable or exceeds cap.');
 let prepared;const selected=[];
 for(const cell of found.candidates){if(selected.length>=8)throw Error('QTC gateway supports at most 8 inputs per transaction.');selected.push(cell);try{prepared=prepareQtcPayment({inputs:selected,from,to,amount,feeRate:rate,maxFee,dustRate,networkId});break;}catch(e){if(!/Insufficient QTC funds|QTC change is dust/.test(e.message))throw e;}}
 if(!prepared)throw Error(found.truncated?'Insufficient QTC candidates on bounded page.':'Insufficient QTC candidates.');
 const outpoints=selected.map(key),reservation=await reserve({networkId,from,outpoints:[...outpoints]});if(!reservation)throw Error('QTC inputs are already reserved.');if(signal?.aborted){await release(reservation);signal.throwIfAborted();}
 let closed=false,handedOff=false;const expiresAt=Date.now()+60000;
 async function close(){if(!closed){closed=true;if(!handedOff)await release(reservation);}}
 const verify=async()=>{const refreshed=await findQtcCandidates(from,options);if(refreshed.tip.hash!==found.tip.hash||refreshed.tip.height!==found.tip.height)throw Error('QTC explorer tip changed; prepare again.');for(const i of selected){const now=refreshed.candidates.find(n=>key(n)===key(i));if(!now||now.value!==i.value||now.script_pubkey!==i.script_pubkey||now.coinbase!==i.coinbase||now.height!==i.height)throw Error('QTC indexed candidate changed.');}signal?.throwIfAborted();};
 return Object.freeze({from,to,networkId,amount:amount.toString(),fee:prepared.fee.toString(),feeRate:rate.toString(),expiresAt,outpoints:Object.freeze([...outpoints]),cancel:close,
  async signAfterConfirmation({root,rnd,signWasmBytes,receiveWasmBytes,persistPending}={}){
   if(closed)throw Error('QTC review is closed.');closed=true;const rootCopy=root instanceof Uint8Array?root.slice():root;
   try{
    if(typeof persistPending!=='function')throw Error('Durable QTC pending hold is required.');if(Date.now()>=expiresAt)throw Error('QTC review expired.');
    await verify();const signed=await signQtcPayment({transaction:prepared.transaction,from,networkId,root:rootCopy,rnd,signWasmBytes,receiveWasmBytes,signal});await verify();if(Date.now()>=expiresAt)throw Error('QTC review expired before pending hold.');
    qtcGatewayBody(signed.raw); // Bound actual encoded request before durable handoff.
    await persistPending({txid:signed.txid,networkId,from,to,outpoints:[...outpoints],amount:amount.toString(),fee:prepared.fee.toString(),state:'signed-exposure-pending',signedPayload:{encoding:'hex',data:signed.raw}});
    handedOff=true;signal?.throwIfAborted();if(Date.now()>=expiresAt)throw Error('QTC review expired before gateway handoff.');
    return {...signed,networkId,reservation,outpoints:[...outpoints],amount:amount.toString(),fee:prepared.fee.toString()};
   }catch(error){if(error instanceof Error)error.qtcNotExposed=true;if(handedOff&&error instanceof Error)error.qtcReservationRetained=true;throw error;}finally{rootCopy?.fill?.(0);if(!handedOff)await release(reservation);}
  }
 });
}

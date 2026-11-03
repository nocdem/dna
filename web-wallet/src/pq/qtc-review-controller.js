// Isolated QTC review/sign handoff, intentionally not wired to any send gate.
// Explorer UTXOs omit mempool spends and are only candidate hints. The host
// MUST provide independently authenticated node checks (including mempool),
// a cross-context atomic reservation, exact transaction pool simulation, and a
// persistent submission hold before separately authorized broadcast.
import {findQtcCandidates,readQtcFeeRates} from './qtc-preflight.js';import {prepareQtcPayment,qtcPaymentVsize} from './qtc-payment.js';import {signQtcPayment} from './qtc-payment-sign.js';
const key=i=>`${i.txid}:${i.vout}`;
function checkNode(result,inputs,tip){
 if(!result||result.tipHash!==tip.hash||typeof result.tipHeight!=='bigint'||result.tipHeight!==tip.height||!Array.isArray(result.inputs)||result.inputs.length!==inputs.length)throw Error('Independent QTC node snapshot mismatch.');
 const m=new Map(result.inputs.map(i=>[key(i),i]));if(m.size!==inputs.length)throw Error('Duplicate QTC node inputs.');
 for(const i of inputs){const n=m.get(key(i));if(!n||n.unspent!==true||n.value!==i.value||n.script_pubkey!==i.script_pubkey||n.coinbase!==i.coinbase||typeof n.confirmations!=='bigint'||n.confirmations!==tip.height-i.height+1n||(n.coinbase&&n.confirmations<100n))throw Error('QTC node input is spent, immature or mismatched.');}
}
export async function prepareQtcReview({from,to,amount,networkId='mainnet',maxFee,maxRate,dustRate=3000n,reserve,release,verifyInputs,signal,fetcher}={}){
 if(typeof reserve!=='function'||typeof release!=='function'||typeof verifyInputs!=='function')throw Error('QTC atomic reservation and independent node checks are required.');
 if(typeof amount!=='bigint'||typeof maxRate!=='bigint'||maxRate<1n||maxRate>100000n||typeof maxFee!=='bigint')throw Error('Invalid QTC review limits.');
 const options={networkId,signal,fetcher},[found,fees]=await Promise.all([findQtcCandidates(from,options),readQtcFeeRates(options)]);
 if(found.tip.hash!==fees.tip.hash||found.tip.height!==fees.tip.height)throw Error('QTC explorer tip changed; prepare again.');
 const rate=fees.rates['6'];if(rate===null||rate<1n||rate>maxRate)throw Error('QTC fee estimate unavailable or exceeds cap.');
 let prepared;const selected=[];
 for(const cell of found.candidates){if(selected.length>=15)throw Error('QTC encrypted recovery supports at most 15 inputs per transaction.');selected.push(cell);try{prepared=prepareQtcPayment({inputs:selected,from,to,amount,feeRate:rate,maxFee,dustRate,networkId});break;}catch(e){if(!/Insufficient QTC funds|QTC change is dust/.test(e.message))throw e;}}
 if(!prepared)throw Error(found.truncated?'Insufficient QTC candidates on bounded page.':'Insufficient QTC candidates.');
 const outpoints=selected.map(key),reservation=await reserve({networkId,from,outpoints:[...outpoints]});if(!reservation)throw Error('QTC inputs are already reserved.');if(signal?.aborted){await release(reservation);signal.throwIfAborted();}
 let closed=false,handedOff=false,exposed=false;const expiresAt=Date.now()+60000;
 async function close(){if(!closed){closed=true;if(!handedOff)await release(reservation);}}
 const verify=async()=>{const copy=selected.map(x=>({...x}));const r=await verifyInputs({networkId,inputs:copy,tip:{...found.tip},signal});signal?.throwIfAborted();checkNode(r,selected,found.tip);};
 return Object.freeze({from,to,networkId,amount:amount.toString(),fee:prepared.fee.toString(),feeRate:rate.toString(),expiresAt,outpoints:Object.freeze([...outpoints]),cancel:close,
  async signAfterConfirmation({root,rnd,signWasmBytes,receiveWasmBytes,simulate,persistPending}={}){
   if(closed)throw Error('QTC review is closed.');closed=true;const rootCopy=root instanceof Uint8Array?root.slice():root;
   try{
    if(typeof simulate!=='function'||typeof persistPending!=='function')throw Error('Exact QTC node simulation and durable pending hold are required.');if(Date.now()>=expiresAt)throw Error('QTC review expired.');
    await verify();const signed=await signQtcPayment({transaction:prepared.transaction,from,networkId,root:rootCopy,rnd,signWasmBytes,receiveWasmBytes,signal});await verify();if(Date.now()>=expiresAt)throw Error('QTC review expired before pending hold.');
    // The simulator receives a valid signed tx and could relay it: retain a
    // durable hold before disclosure, even on timeout or negative response.
    await persistPending({txid:signed.txid,networkId,from,to,outpoints:[...outpoints],amount:amount.toString(),fee:prepared.fee.toString(),state:'signed-exposure-pending',signedPayload:{encoding:'hex',data:signed.raw}});
    handedOff=true;signal?.throwIfAborted();if(Date.now()>=expiresAt)throw Error('QTC review expired before simulation.');
    exposed=true;const result=await simulate({raw:signed.raw,txid:signed.txid,networkId,signal});if(result?.allowed!==true||result.txid!==signed.txid||typeof result.vsize!=='bigint'||result.vsize!==qtcPaymentVsize(prepared.transaction))throw Error('QTC simulation failed or did not match signed transaction.');
    await verify();signal?.throwIfAborted();if(Date.now()>=expiresAt)throw Error('QTC review expired.');
    return {...signed,networkId,reservation,outpoints:[...outpoints],amount:amount.toString(),fee:prepared.fee.toString()};
   }catch(error){if(error instanceof Error){if(!exposed)error.qtcNotExposed=true;else delete error.qtcNotExposed;}if(handedOff&&error instanceof Error)error.qtcReservationRetained=true;throw error;}finally{rootCopy?.fill?.(0);if(!handedOff)await release(reservation);}
  }
 });
}

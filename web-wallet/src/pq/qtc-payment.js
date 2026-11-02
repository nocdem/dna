// Offline QTC P2MR payment quote. Fee rates in atoms/byte; no witness discount.
// Dust policy: qtcchain/qtc@5adbc7d5 src/policy/policy.{h,cpp}: P2MR output
// 43 bytes + future input 3818; default dust relay 3000 atoms/kB => 11583.
// Neither quote nor explorer candidates establish spendability.
import {qtcScript,serializeQtcTransaction} from './qtc-transaction.js';
export function qtcPaymentVsize(tx){return BigInt(serializeQtcTransaction(tx).length+2+tx.inputs.length*3777);}
export function qtcDustThreshold(dustRate=3000n){if(typeof dustRate!=='bigint'||dustRate<3000n||dustRate>300000n)throw Error('Invalid QTC dust relay rate.');return (3861n*dustRate+999n)/1000n;}
export function prepareQtcPayment({inputs,from,to,amount,feeRate,maxFee,dustRate=3000n,networkId='mainnet'}={}){
 if(typeof amount!=='bigint'||typeof feeRate!=='bigint'||feeRate<1n||feeRate>100000n||typeof maxFee!=='bigint'||maxFee<=0n||maxFee>100000000n)throw Error('Invalid QTC fee policy.');
 const floor=qtcDustThreshold(dustRate);if(amount<floor)throw Error('QTC amount is dust.');const own=qtcScript(from,networkId),recipient=qtcScript(to,networkId);
 if(!Array.isArray(inputs)||!inputs.length||inputs.length>80)throw Error('Invalid QTC inputs.');
 const tx={version:2,locktime:0,inputs:inputs.map(i=>{if(i.script_pubkey!==own||typeof i.value!=='bigint'||i.value<=0n)throw Error('Invalid QTC input.');return {txid:i.txid,vout:i.vout,value:i.value,script_pubkey:own,sequence:0xffffffff};}),outputs:[{value:amount,script_pubkey:recipient}]};
 const total=tx.inputs.reduce((s,i)=>s+i.value,0n);if(total<amount)throw Error('Insufficient QTC funds.');
 // Quote with change first, then use exact no-change only if the value equals
 // amount plus the one-output fee. Never silently burn change as extra fee.
 if(total>=amount+floor)tx.outputs.push({value:floor,script_pubkey:own});
 let fee=qtcPaymentVsize(tx)*feeRate;if(fee>maxFee||total<amount+fee)throw Error('Insufficient QTC funds or fee exceeds cap.');
 let change=total-amount-fee;
 if(tx.outputs.length===2){if(change<floor){tx.outputs.pop();fee=qtcPaymentVsize(tx)*feeRate;change=total-amount-fee;if(change!==0n)throw Error('QTC change is dust; add another input.');}else tx.outputs[1].value=change;}
 else if(change!==0n)throw Error('QTC change is dust; add another input.');
 serializeQtcTransaction(tx);return {transaction:tx,networkId,from,to,amount,fee,feeRate,dustRate,change};
}

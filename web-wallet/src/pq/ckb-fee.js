// Offline size-and-cycle-aware quote, not a provider fee recommendation.
// CKB transaction weight = max(serialized size in block, floor(cycles *
// 0.0001705714)); round cycle estimate upward for conservative integer math.
// Source: nervosnetwork/ckb@a4aa1286 util/types/src/core/tx_pool.rs;
// block transaction serialization includes a four-byte DynVec offset.
import {ckbQuantumWitness} from './ckb-quantum-witness.js';
import {serializeCkbTransaction} from './ckb-quantum-transaction.js';
export function quoteCkbQuantumFee(prepared,{feeRate,cycleCeiling,maxFee}={}){
 if(!prepared||!Array.isArray(prepared.inputs)||!prepared.inputs.length||prepared.inputs.length>80)throw Error('Invalid CKB payment.');
 if(typeof feeRate!=='bigint'||feeRate<1000n||feeRate>1000000n||typeof cycleCeiling!=='bigint'||cycleCeiling<26462819n||cycleCeiling>3500000000n||typeof maxFee!=='bigint'||maxFee<=0n||maxFee>100000000n)throw Error('Invalid CKB fee policy.');
 const witnesses=prepared.inputs.map(()=>new Uint8Array());witnesses[0]=ckbQuantumWitness(new Uint8Array(64),new Uint8Array(29792));
 const size=BigInt(serializeCkbTransaction(prepared.rawTransaction,witnesses).length+4),cycleWeight=(cycleCeiling*1705714n+9999999999n)/10000000000n;
 const weight=size>cycleWeight?size:cycleWeight,fee=(weight*feeRate+999n)/1000n;
 if(fee>maxFee)throw Error('CKB fee exceeds approved cap.');return {size,cycleCeiling,weight,feeRate,fee};
}
export function checkCkbQuantumFee(prepared,signed,{feeRate,cycleCeiling,maxFee}={}){
 const q=quoteCkbQuantumFee(prepared,{feeRate,cycleCeiling,maxFee});
 if(!(signed?.transaction instanceof Uint8Array)||BigInt(signed.transaction.length+4)!==q.size||typeof prepared.fee!=='bigint'||prepared.fee<q.fee||prepared.fee>maxFee)throw Error('Signed CKB transaction or fee is inconsistent with quote.');
 return q;
}

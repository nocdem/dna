// Strict exact CKB recovery payload validation. Structural validation is
// synchronous; verifyCkbSignedPayload additionally checks the signature with
// the same SHA2-256s verification primitive before any explicit replay.
import {hexToBytes,bytesToHex,concatBytes,utf8ToBytes} from '@noble/hashes/utils';import {blake2b} from '@noble/hashes/blake2b';
import {parseExactJson} from './integer-json.js';import {validCkbPending} from './ckb-pending.js';import {ckbQuantumAddressLock,prepareCkbQuantumTransaction,serializeCkbTransaction,ckbPreparedRpcTransaction} from './ckb-quantum-transaction.js';import {ckbQuantumLock,ckbQuantumWitness} from './ckb-quantum-witness.js';import {ckbQuantumMessage} from './ckb-quantum-message.js';
const cat=(...a)=>concatBytes(...a),eq=(a,b)=>a.length===b.length&&a.every((v,i)=>v===b[i]);
function u32(n){const b=new Uint8Array(4);new DataView(b.buffer).setUint32(0,n,true);return b;}function u64(n){const b=new Uint8Array(8);new DataView(b.buffer).setBigUint64(0,n,true);return b;}
function table(...f){let o=4+4*f.length;return cat(u32(o+f.reduce((s,x)=>s+x.length,0)),...f.map(x=>{const n=o;o+=x.length;return u32(n);}),...f);}
export function validateCkbSignedPayload(row){
 if(!validCkbPending(row)||!Array.isArray(row.inputCapacities)||row.inputCapacities.length!==row.inputs.length||row.inputCapacities.some(x=>typeof x!=='string'||!/^[1-9]\d{0,19}$/.test(x)||BigInt(x)>0xffffffffffffffffn)||row.signedPayload?.encoding!=='json'||typeof row.signedPayload.data!=='string'||row.signedPayload.data.length>120000)throw Error('Invalid CKB signed recovery payload.');
 const rpcTransaction=parseExactJson(row.signedPayload.data);if(!rpcTransaction||typeof rpcTransaction!=='object'||Array.isArray(rpcTransaction)||JSON.stringify(rpcTransaction)!==row.signedPayload.data||!Array.isArray(rpcTransaction.witnesses)||rpcTransaction.witnesses.length!==row.inputs.length)throw Error('Invalid CKB signed transaction encoding.');
 const lock=ckbQuantumAddressLock(row.address,row.networkId),inputs=row.inputs.map((outpoint,i)=>({outpoint:hexToBytes(outpoint),output:table(u64(BigInt(row.inputCapacities[i])),lock,new Uint8Array()),data:new Uint8Array()}));
 const p=prepareCkbQuantumTransaction({networkId:row.networkId,from:row.address,to:row.to,inputs,amount:BigInt(row.amountAtoms),fee:BigInt(row.feeAtoms)});
 const witnesses=rpcTransaction.witnesses.map(w=>{if(typeof w!=='string'||!/^0x(?:[0-9a-f]{2})*$/.test(w)||w.length>60000)throw Error('Invalid CKB witness.');return hexToBytes(w.slice(2));});
 if(witnesses[0].length!==29881||witnesses.slice(1).some(w=>w.length!==0))throw Error('Invalid CKB witness group.');
 const publicKey=witnesses[0].slice(25,89),signature=witnesses[0].slice(89);if(!eq(ckbQuantumWitness(publicKey,signature),witnesses[0])||!eq(ckbQuantumLock(publicKey,row.networkId),lock))throw Error('CKB witness does not match sender.');
 const transaction=serializeCkbTransaction(p.rawTransaction,witnesses),expected=ckbPreparedRpcTransaction(p,{transaction,witnesses});if(JSON.stringify(expected)!==row.signedPayload.data)throw Error('CKB signed payload differs from reviewed transaction.');
 const txid='0x'+bytesToHex(blake2b(p.rawTransaction,{dkLen:32,personalization:utf8ToBytes('ckb-default-hash')}));if(txid!==row.hash)throw Error('CKB signed payload hash mismatch.');
 return {rpcTransaction,transaction,rawTransaction:p.rawTransaction,inputs:p.inputs,witnesses,publicKey,signature,txid};
}
export async function verifyCkbSignedPayload(row,{wasmBytes,signal}={}){
 signal?.throwIfAborted();const parsed=validateCkbSignedPayload(row);let instance,binary=wasmBytes;
 try{if(!binary){const timeout=AbortSignal.timeout(15000),response=await fetch(new URL('./ckb-slh-sign.wasm',import.meta.url),{credentials:'omit',redirect:'error',signal:signal?AbortSignal.any([signal,timeout]):timeout});if(!response.ok)throw Error('CKB verification module could not load.');binary=await response.arrayBuffer();}
  signal?.throwIfAborted();const result=await WebAssembly.instantiate(binary,{});instance=result.instance??result;const e=instance.exports;e._initialize?.();if(!(e.memory instanceof WebAssembly.Memory)||['message','public_key','signature','verify','clear'].some(x=>typeof e[`ckb_slh_${x}`]!=='function'))throw Error('Invalid CKB verification module.');
  const message=ckbQuantumMessage({rawTransaction:parsed.rawTransaction,inputs:parsed.inputs,witnesses:parsed.witnesses,groupIndex:0}),m=new Uint8Array(e.memory.buffer);for(const [name,data] of [['message',message],['public_key',parsed.publicKey],['signature',parsed.signature]]){const at=e[`ckb_slh_${name}`]();if(!Number.isInteger(at)||at<0||at+data.length>m.length)throw Error('Invalid CKB verification memory.');m.set(data,at);}signal?.throwIfAborted();if(e.ckb_slh_verify()!==0)throw Error('Invalid CKB signature.');signal?.throwIfAborted();return {rpcTransaction:parsed.rpcTransaction,txid:parsed.txid};
 }finally{if(instance){try{instance.exports.ckb_slh_clear?.();}finally{if(instance.exports.memory)new Uint8Array(instance.exports.memory.buffer).fill(0);}}}
}

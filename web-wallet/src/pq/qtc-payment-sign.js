import {qtcReceiveWasmUrl} from './qtc-receive-wasm.js';
// Offline QTC native ML-DSA-44 P2MR signing for the existing recovery tree.
// No UTXO/liveness/fee verification, transaction submission, or spend gate.
import {sha256} from '@noble/hashes/sha256';
import {hmac} from '@noble/hashes/hmac';
import {concatBytes,utf8ToBytes,bytesToHex} from '@noble/hashes/utils';
import {qtcMldsaLeaf,qtcSignatureHash} from './qtc-sighash.js';
import {qtcScript,qtcPrimarySpend,serializeQtcTransaction,qtcTransactionId} from './qtc-transaction.js';
const cat=(...a)=>concatBytes(...a), ascii=s=>utf8ToBytes(s);
function u32(n,little=false){const b=new Uint8Array(4);new DataView(b.buffer).setUint32(0,n,little);return b;}
// Exact counterpart of receive.js qtcKeySeed; root is pqChainSeed(phrase,'qtc').
export function qtcSigningSeed(root,networkId,algorithm){
 if(!(root instanceof Uint8Array)||root.length!==32||!['mainnet','testnet'].includes(networkId)||![0,1].includes(algorithm))throw Error('Invalid QTC recovery parameters.');
 let prk,material,entropy,block;try{
  prk=hmac(sha256,ascii('QTC-PQ-BIP87-HKDF-V1'),root);
  material=hmac(sha256,prk,cat(ascii('m/87h'),u32(0x80000000+87),u32(0x80000000+(networkId==='mainnet'?0:1)),u32(0x80000000),u32(0),u32(0),Uint8Array.of(algorithm,1)));
  entropy=new Uint8Array(128);for(let i=0;i<4;i++){block=sha256(cat(material,u32(i,true)));entropy.set(block,i*32);block.fill(0);}
  return entropy.slice(0,algorithm===0?32:48);
 }finally{prk?.fill(0);material?.fill(0);entropy?.fill(0);block?.fill(0);}
}
async function load(url,binary,signal){signal?.throwIfAborted();if(binary)return binary;const timeout=AbortSignal.timeout(15000);const r=await fetch(url,{credentials:'omit',redirect:'error',signal:signal?AbortSignal.any([signal,timeout]):timeout});if(!r.ok)throw Error('QTC signing module could not load.');return r.arrayBuffer();}
async function derivePublic(seed,kind,param,size,binary,signal){let instance;try{
 const result=await WebAssembly.instantiate(await load(qtcReceiveWasmUrl(),binary,signal),{});instance=result.instance??result;const e=instance.exports;e._initialize?.();
 if(!(e.memory instanceof WebAssembly.Memory)||['pq_receive_input','pq_receive_output','pq_receive_seed_size','pq_receive_public_size','pq_receive_derive','pq_receive_clear'].some(k=>typeof e[k]!=='function')||e.pq_receive_seed_size(kind,param)!==seed.length||e.pq_receive_public_size(kind,param)!==size)throw Error('Invalid QTC backup module.');
 let m=new Uint8Array(e.memory.buffer),input=e.pq_receive_input();if(!Number.isInteger(input)||input<0||input+seed.length>m.length)throw Error('Invalid QTC backup memory.');m.set(seed,input);signal?.throwIfAborted();if(e.pq_receive_derive(kind,param,seed.length)!==0)throw Error('QTC backup key failed.');signal?.throwIfAborted();m=new Uint8Array(e.memory.buffer);const output=e.pq_receive_output();if(!Number.isInteger(output)||output<0||output+size>m.length)throw Error('Invalid QTC backup memory.');return m.slice(output,output+size);
 }finally{if(instance){try{instance.exports.pq_receive_clear?.();}finally{if(instance.exports.memory)new Uint8Array(instance.exports.memory.buffer).fill(0);}}}}
async function sign(seed,digest,rnd,binary,signal){let instance,random;try{
 const result=await WebAssembly.instantiate(await load(new URL('./qtc-mldsa44-sign.wasm',import.meta.url),binary,signal),{});instance=result.instance??result;const e=instance.exports;e._initialize?.();
 if(!(e.memory instanceof WebAssembly.Memory)||['seed','message','random','public_key','signature','sign','clear'].some(x=>typeof e[`mldsa44_${x}`]!=='function'))throw Error('Invalid QTC signing module.');
 const m=new Uint8Array(e.memory.buffer),at=(name,n)=>{const x=e[`mldsa44_${name}`]();if(!Number.isInteger(x)||x<0||x+n>m.length)throw Error('Invalid QTC signing memory.');return x;};
 random=rnd?rnd.slice():crypto.getRandomValues(new Uint8Array(32));m.set(seed,at('seed',32));m.set(digest,at('message',32));m.set(random,at('random',32));signal?.throwIfAborted();if(e.mldsa44_sign()!==0)throw Error('QTC signing failed.');signal?.throwIfAborted();return {publicKey:m.slice(at('public_key',1312),at('public_key',1312)+1312),signature:m.slice(at('signature',2420),at('signature',2420)+2420)};
 }finally{random?.fill(0);if(instance){try{instance.exports.mldsa44_clear?.();}finally{if(instance.exports.memory)new Uint8Array(instance.exports.memory.buffer).fill(0);}}}}
export async function signQtcPayment({transaction,from,networkId='mainnet',root,rnd,signWasmBytes,receiveWasmBytes,signal}={}){
 signal?.throwIfAborted();if(rnd!==undefined&&(!(rnd instanceof Uint8Array)||rnd.length!==32))throw Error('Invalid QTC signing randomness.');
 // Snapshot all transaction fields and secrets before the first await.
 const tx=structuredClone(transaction), own=qtcScript(from,networkId);serializeQtcTransaction(tx);
 if(!tx.inputs.every(i=>i.script_pubkey===own))throw Error('QTC input ownership mismatch.');
 const primary=qtcSigningSeed(root,networkId,0),backup=qtcSigningSeed(root,networkId,1),random=rnd?.slice();
 try{
  const backupPublicKey=await derivePublic(backup,4,7,32,receiveWasmBytes,signal),publicKey=await derivePublic(primary,3,44,1312,receiveWasmBytes,signal),witness=[];
  if(qtcPrimarySpend(publicKey,backupPublicKey).scriptPubKey!==own)throw Error('QTC recovery keys do not match address.');
  for(let i=0;i<tx.inputs.length;i++){
   const result=await sign(primary,qtcSignatureHash(tx,i,qtcMldsaLeaf(publicKey)),random,signWasmBytes,signal);
   if(bytesToHex(result.publicKey)!==bytesToHex(publicKey))throw Error('QTC signing key changed.');
   witness.push({signature:result.signature,publicKey,backupPublicKey});
  }
  signal?.throwIfAborted();return {raw:bytesToHex(serializeQtcTransaction(tx,witness)),txid:qtcTransactionId(tx)};
 }finally{primary.fill(0);backup.fill(0);random?.fill(0);}
}

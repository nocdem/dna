// Offline Nodus recovery-v1 Tidecoin signing bridge. No UTXO/fee/network policy.
// Mirrors src/pq/receive.js Tidecoin PQHD retry path; returned transaction is
// not authorized for broadcast until callers perform independent checks.
import {hmac} from '@noble/hashes/hmac';
import {sha512} from '@noble/hashes/sha2';
import {pqChainSeed} from './receive.js';
import {tidecoinSignLegacyTransaction} from './tidecoin-transaction.js';
const ascii=s=>new TextEncoder().encode(s);
const u32=n=>{const b=new Uint8Array(4);new DataView(b.buffer).setUint32(0,n);return b;};
const mac=(key,...parts)=>{const h=hmac.create(sha512,key);try{for(const p of parts)h.update(p);return h.digest();}finally{h.destroy();}};
const path=[10007,6868,7,0,0,0].map(i=>u32(i+0x80000000));
export async function tidecoinSignFromPhrase(tx,phrase,{receiveWasmBytes,signWasmBytes,signal}={}){
 signal?.throwIfAborted();
 // Snapshot before the first yield, so caller mutations cannot change what is signed.
 const copy=b=>{if(!(b instanceof Uint8Array))throw Error('Invalid TDC bytes.');return Uint8Array.from(b);};
 tx={version:tx.version,locktime:tx.locktime,inputs:tx.inputs.map(i=>({...i,txid:copy(i.txid),scriptPubKey:copy(i.scriptPubKey)})),outputs:tx.outputs.map(o=>({...o,scriptPubKey:copy(o.scriptPubKey)}))};
 let root,node,child,prk,stream,block,seed,instance;
 try{
  root=pqChainSeed(phrase,'tidecoin');node=mac(ascii('Tidecoin PQHD seed'),root);
  for(const i of path){child=mac(node.subarray(32),Uint8Array.of(0),node.subarray(0,32),i);node.fill(0);node=child;child=undefined;}
  prk=mac(ascii('Tidecoin PQHD hkdf v1'),node.subarray(0,32));stream=mac(prk,ascii('Tidecoin PQHD stream key v1'),u32(7),...path,Uint8Array.of(1));
  let binary=receiveWasmBytes;if(!binary){const timeout=AbortSignal.timeout(15000);const response=await fetch(new URL('./receive-keygen.wasm',import.meta.url),{credentials:'omit',redirect:'error',signal:signal?AbortSignal.any([signal,timeout]):timeout});if(!response.ok)throw Error('Receive module could not load.');binary=await response.arrayBuffer();}
  signal?.throwIfAborted();const loaded=await WebAssembly.instantiate(binary,{});instance=loaded.instance??loaded;const api=instance.exports;api._initialize?.();
  if(!(api.memory instanceof WebAssembly.Memory)||['pq_receive_input','pq_receive_output','pq_receive_seed_size','pq_receive_public_size','pq_receive_derive','pq_receive_clear'].some(n=>typeof api[n]!=='function')||api.pq_receive_seed_size(2,512)!==48||api.pq_receive_public_size(2,512)!==897)throw Error('Invalid receive module.');
  for(let counter=0;counter<1024;counter++){
   signal?.throwIfAborted();await new Promise(resolve=>setTimeout(resolve,0));signal?.throwIfAborted();
   block=mac(stream,ascii('Tidecoin PQHD rng v1'),u32(counter));seed=block.slice(0,48);block.fill(0);block=undefined;
   const mem=new Uint8Array(api.memory.buffer),offset=api.pq_receive_input();if(!Number.isInteger(offset)||offset<0||offset+48>mem.length)throw Error('Invalid receive module input.');mem.set(seed,offset);
   const status=api.pq_receive_derive(2,512,48);api.pq_receive_clear();signal?.throwIfAborted();
   if(status===0)return await tidecoinSignLegacyTransaction(tx,{seed,wasmBytes:signWasmBytes,signal});
   seed.fill(0);seed=undefined;
  }
  throw Error('TDC key generation failed.');
 }finally{for(const b of [root,node,child,prk,stream,block,seed])b?.fill(0);if(instance){try{instance.exports.pq_receive_clear?.();}finally{if(instance.exports.memory)new Uint8Array(instance.exports.memory.buffer).fill(0);}}}
}

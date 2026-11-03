// Offline single-group SHA2-256s witness construction for the CKB quantum lock.
// Source: nervosnetwork/quantum-resistant-lock-script@082c0a19, docs/simple.md.
// Inputs must already be independently resolved/live, reserved and fee-reviewed.
// This module is not a preflight, broadcaster, or proof of script acceptance.
import { blake2b } from '@noble/hashes/blake2b';
import { concatBytes, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';
import { ckbQuantumMessage } from './ckb-quantum-message.js';
import { ckbSignMessage } from './ckb-sign.js';
const cat=(...a)=>concatBytes(...a), empty=()=>new Uint8Array();
const NETWORKS={
 mainnet:{code:'302d35982f865ebcbedb9a9360e40530ed32adb8e10b42fbbe70d8312ff7cedf',type:1,dep:'4598d00df2f3dc8bc40eee38689a539c94f6cc3720b7a2a6746736daa60f500a'},
 testnet:{code:'147ecbb5c5127d982ee1362d2c2bb4267803da2eb006d150e88af6caaa0a7eaf',type:2,dep:'631d9a6049fb1fc3790e89d9daf35abe535b5e754cd8c3404319319710f0b106'}
};
function read32(b,i){if(!(b instanceof Uint8Array)||i+4>b.length)throw Error('Truncated CKB molecule.');return new DataView(b.buffer,b.byteOffset,b.byteLength).getUint32(i,true);}
function u32(n){const b=new Uint8Array(4);new DataView(b.buffer).setUint32(0,n,true);return b;}
function table(...fields){let offset=4+fields.length*4;const offsets=fields.map(f=>{const n=offset;offset+=f.length;return u32(n);});return cat(u32(offset),...offsets,...fields);}
const vec=b=>cat(u32(b.length),b);
function fields(b,n){const head=4+n*4;if(!(b instanceof Uint8Array)||b.length<head||read32(b,0)!==b.length||read32(b,4)!==head)throw Error('Invalid CKB table.');const offsets=Array.from({length:n},(_,i)=>read32(b,4+i*4)).concat(b.length);if(offsets.some((v,i)=>v<head||v>b.length||(i&&v<offsets[i-1])))throw Error('Invalid CKB offset.');return offsets.slice(0,-1).map((x,i)=>b.subarray(x,offsets[i+1]));}
const eq=(a,b)=>a.length===b.length&&a.every((x,i)=>x===b[i]);
function exact(b,n){if(!(b instanceof Uint8Array)||b.length!==n)throw Error('Invalid CKB byte length.');return b;}
export function ckbQuantumLock(publicKey, networkId='mainnet'){
 const net=NETWORKS[networkId];if(!Object.hasOwn(NETWORKS,networkId))throw Error('Unsupported CKB network.');exact(publicKey,64);
 const config=cat(Uint8Array.of(0x80,1,1,1,0x6a),publicKey);
 const args=blake2b(config,{dkLen:32,personalization:utf8ToBytes('ckb-sphincs+-sct')});
 return table(hexToBytes(net.code),Uint8Array.of(net.type),vec(args));
}
export function ckbQuantumWitness(publicKey,signature){
 exact(publicKey,64);exact(signature,29792);
 return table(vec(cat(Uint8Array.of(0x80,1,1,1,0x6b),publicKey,signature)),empty(),empty());
}
export async function signCkbQuantumWitness({rawTransaction,inputs,networkId='mainnet',seed,rnd,wasmBytes,signal}={}){
 signal?.throwIfAborted();if(!Object.hasOwn(NETWORKS,networkId))throw Error('Unsupported CKB network.');
 // Snapshot caller-owned data before the first await. Each supplied outpoint is
 // 32-byte tx hash + little-endian uint32 index, matching Molecule OutPoint.
 const raw=rawTransaction instanceof Uint8Array?rawTransaction.slice():rawTransaction;
 if(!Array.isArray(inputs)||!inputs.length||inputs.length>80)throw Error('Invalid CKB inputs.');
 const resolved=inputs.map(i=>({output:i.output?.slice(),data:i.data?.slice(),outpoint:i.outpoint?.slice()}));
 const r=fields(raw,6), deps=r[1], cells=r[3];
 if(read32(r[0],0)!==0 || r[0].length!==4 || read32(deps,0)!==1 || deps.length!==41)throw Error('Invalid CKB dependency.');
 const net=NETWORKS[networkId], expectedDep=cat(hexToBytes(net.dep),new Uint8Array(4),Uint8Array.of(0));
 if(!eq(deps.subarray(4),expectedDep))throw Error('Wrong CKB quantum lock dependency.');
 if(read32(cells,0)!==resolved.length || cells.length!==4+44*resolved.length)throw Error('Invalid CKB inputs.');
 const seen=new Set();
 for(let i=0;i<resolved.length;i++){
  const item=resolved[i], input=cells.subarray(4+i*44,4+(i+1)*44);exact(item.outpoint,36);exact(item.data,0);
  if(!input.subarray(0,8).every(b=>b===0)||!eq(input.subarray(8),item.outpoint))throw Error('CKB input does not match resolved outpoint.');
  const key=Array.from(item.outpoint).join(',');if(seen.has(key))throw Error('Duplicate CKB input.');seen.add(key);
  const output=fields(item.output,3);if(output[0].length!==8||output[2].length!==0)throw Error('Unsupported CKB cell.');
 }
 const witnesses=resolved.map(()=>empty()); witnesses[0]=table(empty(),empty(),empty());
 const message=ckbQuantumMessage({rawTransaction:raw,inputs:resolved,witnesses,groupIndex:0});
 const signingSeed=exact(seed,96).slice(), signingRnd=rnd===undefined?undefined:exact(rnd,32).slice();
 try {
  const {publicKey,signature}=await ckbSignMessage({seed:signingSeed,message,rnd:signingRnd,wasmBytes,signal});
  signal?.throwIfAborted();
  const expected=ckbQuantumLock(publicKey,networkId);
  for(const item of resolved)if(!eq(fields(item.output,3)[1],expected))throw Error('CKB signing key does not own inputs.');
  witnesses[0]=ckbQuantumWitness(publicKey,signature);
  return {witnesses, message, publicKey};
 } finally {signingSeed.fill(0);signingRnd?.fill(0);}
}

// Transfer assembly for quantum-lock inputs and canonical full-format recipients.
// No indexer, chain tip, liveness/maturity proof, reservation, fee recommendation,
// CKB-VM test or broadcaster is supplied by this module. Do not enable send.
import {bech32m} from '@scure/base';
import {concatBytes,hexToBytes} from '@noble/hashes/utils';
import {parseCkbFullRecipient} from './ckb-full-recipient.js';
import {signCkbQuantumWitness} from './ckb-quantum-witness.js';
const cat=(...a)=>concatBytes(...a), empty=()=>new Uint8Array();
const net={mainnet:{prefix:'ckb',code:'302d35982f865ebcbedb9a9360e40530ed32adb8e10b42fbbe70d8312ff7cedf',type:1,dep:'4598d00df2f3dc8bc40eee38689a539c94f6cc3720b7a2a6746736daa60f500a'},testnet:{prefix:'ckt',code:'147ecbb5c5127d982ee1362d2c2bb4267803da2eb006d150e88af6caaa0a7eaf',type:2,dep:'631d9a6049fb1fc3790e89d9daf35abe535b5e754cd8c3404319319710f0b106'}};
function u32(n){if(!Number.isSafeInteger(n)||n<0||n>0xffffffff)throw Error('Invalid CKB length.');const b=new Uint8Array(4);new DataView(b.buffer).setUint32(0,n,true);return b;}
function u64(n){if(typeof n!=='bigint'||n<0n||n>0xffffffffffffffffn)throw Error('Invalid CKB capacity.');const b=new Uint8Array(8);new DataView(b.buffer).setBigUint64(0,n,true);return b;}
const vec=b=>cat(u32(b.length),b);
function table(...f){let o=4+f.length*4;const off=f.map(x=>{const start=o;o+=x.length;return u32(start);});return cat(u32(o),...off,...f);}
const dyn=f=>f.length?table(...f):u32(4);
const equal=(a,b)=>a.length===b.length&&a.every((v,i)=>v===b[i]);
function get32(b,i){if(!(b instanceof Uint8Array)||i+4>b.length)throw Error('Invalid CKB table.');return new DataView(b.buffer,b.byteOffset,b.byteLength).getUint32(i,true);}
function fields(b,n){const h=4+n*4;if(!(b instanceof Uint8Array)||b.length<h||get32(b,0)!==b.length||get32(b,4)!==h)throw Error('Invalid CKB table.');const offsets=Array.from({length:n},(_,i)=>get32(b,4+4*i)).concat(b.length);if(offsets.some((v,i)=>v<h||v>b.length||(i&&v<offsets[i-1])))throw Error('Invalid CKB offset.');return offsets.slice(0,-1).map((v,i)=>b.subarray(v,offsets[i+1]));}
export function ckbQuantumAddressLock(address,networkId='mainnet'){
 if(!Object.hasOwn(net,networkId))throw Error('Unsupported CKB network.');const n=net[networkId];let d,p;
 try{if(typeof address!=='string'||address!==address.toLowerCase())throw Error();d=bech32m.decode(address,1023);p=bech32m.fromWords(d.words);}catch{throw Error('Invalid CKB address.');}
 if(d.prefix!==n.prefix||p.length!==66||p[0]!==0||!equal(p.slice(1,33),hexToBytes(n.code))||p[33]!==n.type)throw Error('Unsupported CKB address profile.');
 return table(p.slice(1,33),Uint8Array.of(p[33]),vec(p.slice(34)));
}
// Build an exact user-reviewed payment using already independently verified
// cells. Only native empty-data, no-type cells from the sender are supported.
export function prepareCkbQuantumTransaction({networkId='mainnet',from,to,inputs,amount,fee}={}){
 if(!Object.hasOwn(net,networkId))throw Error('Unsupported CKB network.');
 if(typeof amount!=='bigint'||amount<0n||typeof fee!=='bigint'||fee<=0n)throw Error('Invalid CKB amount or fee.');
 const fromLock=ckbQuantumAddressLock(from,networkId),recipient=parseCkbFullRecipient(to,networkId),toLock=recipient.script;if(amount<recipient.minimumCapacity)throw Error('CKB recipient amount is below occupied capacity.');
 if(!Array.isArray(inputs)||!inputs.length||inputs.length>80)throw Error('Invalid CKB inputs.');
 let total=0n;const seen=new Set();
 const cells=inputs.map(i=>{
  if(!(i?.outpoint instanceof Uint8Array)||i.outpoint.length!==36||!(i.data instanceof Uint8Array)||i.data.length)throw Error('Unsupported CKB input.');
  const output=fields(i.output,3);if(output[0].length!==8||output[2].length||!equal(output[1],fromLock))throw Error('CKB input lock or type mismatch.');
  const value=new DataView(output[0].buffer,output[0].byteOffset,8).getBigUint64(0,true);if(value<7300000000n)throw Error('Invalid CKB input capacity.');total+=value;if(total>0xffffffffffffffffn)throw Error('CKB capacity overflow.');
  const key=Array.from(i.outpoint).join(',');if(seen.has(key))throw Error('Duplicate CKB input.');seen.add(key);
  return {outpoint:i.outpoint.slice(),output:i.output.slice(),data:empty(),capacity:value};
 });
 if(total<amount+fee)throw Error('Insufficient CKB capacity.');const change=total-amount-fee;if(change>0n&&change<7300000000n)throw Error('CKB change is below occupied capacity.');
 const outputs=[table(u64(amount),toLock,empty())];if(change)outputs.push(table(u64(change),fromLock,empty()));
 const dep=cat(hexToBytes(net[networkId].dep),u32(0),Uint8Array.of(0));
 const rawTransaction=table(u32(0),cat(u32(1),dep),u32(0),cat(u32(cells.length),...cells.map(i=>cat(new Uint8Array(8),i.outpoint))),dyn(outputs),dyn(outputs.map(()=>vec(empty()))));
 return {rawTransaction,inputs:cells,networkId,from,to,amount,fee,change};
}
export function serializeCkbTransaction(rawTransaction,witnesses){
 fields(rawTransaction,6);if(!Array.isArray(witnesses)||!witnesses.length||witnesses.some(w=>!(w instanceof Uint8Array)))throw Error('Invalid CKB witnesses.');
 return table(rawTransaction,dyn(witnesses.map(vec)));
}
export async function signPreparedCkbQuantumTransaction(prepared,{seed,rnd,wasmBytes,signal}={}){
 if(!prepared||!Array.isArray(prepared.inputs))throw Error('Invalid CKB transaction.');
 const snapshot={...prepared,rawTransaction:prepared.rawTransaction.slice(),inputs:prepared.inputs.map(i=>({outpoint:i.outpoint.slice(),output:i.output.slice(),data:i.data.slice()}))};
 const rebuilt=prepareCkbQuantumTransaction(snapshot);
 if(!equal(rebuilt.rawTransaction,snapshot.rawTransaction)||rebuilt.change!==snapshot.change)throw Error('CKB review no longer matches transaction.');
 const {witnesses,message,publicKey}=await signCkbQuantumWitness({...snapshot,seed,rnd,wasmBytes,signal});signal?.throwIfAborted();
 return {transaction:serializeCkbTransaction(snapshot.rawTransaction,witnesses),rawTransaction:snapshot.rawTransaction,witnesses,message,publicKey};
}

// RPC JSON for dry-run/host review, with byte-for-byte rebuild check. This
// module itself performs neither dry-run nor broadcasting. `passthrough` output
// validation may be needed for custom locks; host must enforce policy.
export function ckbPreparedRpcTransaction(prepared,signed){
 if(!prepared||!Array.isArray(signed?.witnesses)||signed.witnesses.length!==prepared.inputs?.length)throw Error('Invalid CKB signed transaction.');
 const rebuilt=prepareCkbQuantumTransaction(prepared);if(!equal(rebuilt.rawTransaction,prepared.rawTransaction)||rebuilt.change!==prepared.change||!equal(serializeCkbTransaction(rebuilt.rawTransaction,signed.witnesses),signed.transaction))throw Error('CKB signed transaction does not match review.');
 const n=net[prepared.networkId],lock=address=>{ckbQuantumAddressLock(address,prepared.networkId);const p=bech32m.fromWords(bech32m.decode(address,1023).words);return {code_hash:'0x'+n.code,hash_type:n.type===1?'type':'data1',args:'0x'+Array.from(p.slice(34),x=>x.toString(16).padStart(2,'0')).join('')};};
 const hex=n=>'0x'+n.toString(16),fromLock=lock(prepared.from),toLock=parseCkbFullRecipient(prepared.to,prepared.networkId).lock,outputs=[{capacity:hex(prepared.amount),lock:toLock,type:null}];if(prepared.change)outputs.push({capacity:hex(prepared.change),lock:fromLock,type:null});
 return {version:'0x0',cell_deps:[{out_point:{tx_hash:'0x'+n.dep,index:'0x0'},dep_type:'code'}],header_deps:[],inputs:prepared.inputs.map(i=>({since:'0x0',previous_output:{tx_hash:'0x'+Array.from(i.outpoint.slice(0,32),x=>x.toString(16).padStart(2,'0')).join(''),index:hex(BigInt(new DataView(i.outpoint.buffer,i.outpoint.byteOffset+32,4).getUint32(0,true)))}})),outputs,outputs_data:outputs.map(()=>'0x'),witnesses:signed.witnesses.map(w=>'0x'+Array.from(w,x=>x.toString(16).padStart(2,'0')).join(''))};
}

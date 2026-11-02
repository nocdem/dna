// Offline legacy P2PKH only; reference tidecoin/tidecoin 7d653be5d24e73b49d101578afb33d8d7a889c1d.
// Not a fee selector, wallet derivation, network client, or send gate.
import {sha256} from '@noble/hashes/sha256';
import {ripemd160} from '@noble/hashes/ripemd160';
import {tidecoinSignDigest} from './tidecoin-sign.js';
const cat=(...a)=>{const b=new Uint8Array(a.reduce((n,x)=>n+x.length,0));let p=0;for(const x of a){b.set(x,p);p+=x.length;}return b;};
const bytes=(b,n)=>{if(!(b instanceof Uint8Array)||(n!==undefined&&b.length!==n))throw Error('Invalid TDC bytes.');return b;};
const u32=n=>{if(!Number.isInteger(n)||n<0||n>0xffffffff)throw Error('Invalid TDC integer.');const b=new Uint8Array(4);new DataView(b.buffer).setUint32(0,n,true);return b;};
const u64=n=>{if(typeof n!=='bigint'||n<0n||n>2100000000000000n)throw Error('Invalid TDC amount.');const b=new Uint8Array(8);new DataView(b.buffer).setBigUint64(0,n,true);return b;};
const compact=n=>{if(!Number.isSafeInteger(n)||n<0||n>0xffffffff)throw Error('Invalid TDC length.');if(n<253)return Uint8Array.of(n);if(n<=65535)return Uint8Array.of(253,n&255,n>>>8);return cat(Uint8Array.of(254),u32(n));};
const vector=b=>cat(compact(b.length),b);
export function tidecoinP2pkhScript(h){return cat(Uint8Array.of(0x76,0xa9,0x14),bytes(h,20),Uint8Array.of(0x88,0xac));}
function checked(tx){
 if(!tx||!Array.isArray(tx.inputs)||!tx.inputs.length||tx.inputs.length>1000||!Array.isArray(tx.outputs)||!tx.outputs.length||tx.outputs.length>1000)throw Error('Invalid TDC transaction.');u32(tx.version);u32(tx.locktime);const seen=new Set();let total=0n;
 for(const i of tx.inputs){bytes(i.txid,32);u32(i.vout);u32(i.sequence);bytes(i.scriptPubKey,25);const s=i.scriptPubKey;if(s[0]!==0x76||s[1]!==0xa9||s[2]!==0x14||s[23]!==0x88||s[24]!==0xac)throw Error('Only TDC P2PKH inputs supported.');const k=Array.from(i.txid).join(',')+':'+i.vout;if(seen.has(k))throw Error('Duplicate TDC outpoint.');seen.add(k);}
 for(const o of tx.outputs){u64(o.value);bytes(o.scriptPubKey);if(o.scriptPubKey.length>65536)throw Error('TDC script too large.');total+=o.value;if(total>2100000000000000n)throw Error('Invalid TDC output total.');}
}
// txid is 32-byte wire order, not displayed hex order.
function serialize(tx,scripts){return cat(u32(tx.version),compact(tx.inputs.length),...tx.inputs.map((i,n)=>cat(i.txid,u32(i.vout),vector(scripts[n]),u32(i.sequence))),compact(tx.outputs.length),...tx.outputs.map(o=>cat(u64(o.value),vector(o.scriptPubKey))),u32(tx.locktime));}
export function tidecoinLegacySighashPreimage(tx,index){checked(tx);if(!Number.isInteger(index)||index<0||index>=tx.inputs.length)throw Error('Invalid TDC input index.');return cat(serialize(tx,tx.inputs.map((i,n)=>n===index?i.scriptPubKey:new Uint8Array())),u32(1));}
export function tidecoinLegacySighash(tx,index){const p=tidecoinLegacySighashPreimage(tx,index);return sha256(sha256(p));}
function push(b){bytes(b);if(b.length<76)return cat(Uint8Array.of(b.length),b);if(b.length<=255)return cat(Uint8Array.of(0x4c,b.length),b);if(b.length<=65535)return cat(Uint8Array.of(0x4d,b.length&255,b.length>>>8),b);throw Error('TDC push too large.');}
export async function tidecoinSignLegacyTransaction(tx,{seed,wasmBytes,signal}={}){
 checked(tx);tx={version:tx.version,locktime:tx.locktime,inputs:tx.inputs.map(i=>({...i,txid:Uint8Array.from(i.txid),scriptPubKey:Uint8Array.from(i.scriptPubKey)})),outputs:tx.outputs.map(o=>({...o,scriptPubKey:Uint8Array.from(o.scriptPubKey)}))};const scripts=[];
 for(let n=0;n<tx.inputs.length;n++){signal?.throwIfAborted();const {publicKey,signature}=await tidecoinSignDigest({seed,digest:tidecoinLegacySighash(tx,n),wasmBytes,signal});const pub=cat(Uint8Array.of(7),publicKey);const expected=tidecoinP2pkhScript(ripemd160(sha256(pub)));if(!expected.every((x,j)=>x===tx.inputs[n].scriptPubKey[j]))throw Error('TDC input does not belong to signing key.');scripts.push(cat(push(cat(signature,Uint8Array.of(1))),push(pub)));}
 return serialize(tx,scripts);
}

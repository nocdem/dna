// Exact XION SIGN_MODE_DIRECT validation; no signing, network or broadcast.
import {bech32,base64} from '@scure/base';
import {sha256} from '@noble/hashes/sha2';
import {bytesToHex} from '@noble/hashes/utils';
import {buildXionDirectSignDoc,encodeXionTxRaw} from './xion-sign-doc.js';
const fail=()=>{throw Error('Invalid XION signed payload.');};
const dec=new TextDecoder();
function addr(s){try{if(typeof s!=='string'||s!==s.toLowerCase())return false;const d=bech32.decode(s),b=bech32.fromWords(d.words);return d.prefix==='xion'&&b.length===20&&bech32.encode('xion',bech32.toWords(b))===s;}catch{return false;}}
function integer(v,max,positive=false){return typeof v==='string'&&/^(0|[1-9]\d{0,77})$/.test(v)&&BigInt(v)<=max&&(!positive||v!=='0');}
function validClosed(r){const c=r.executionWindowClosed;if(c===undefined)return true;if(!c||typeof c!=='object'||Array.isArray(c)||Object.keys(c).sort().join(',')!=='blockHash,blockTime,height,observedAt,source'||r.timeoutHeight===undefined||!integer(c.height,2n**63n-1n,true)||BigInt(c.height)<=BigInt(r.timeoutHeight)||typeof c.blockHash!=='string'||!/^[0-9a-f]{64}$/.test(c.blockHash)||/^0{64}$/.test(c.blockHash)||c.source!=='configured-rpc')return false;for(const k of ['blockTime','observedAt']){const v=c[k],n=Date.parse(v);if(typeof v!=='string'||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v)||!Number.isFinite(n)||new Date(n).toISOString().slice(0,19)!==v.slice(0,19))return false;}return Date.parse(c.blockTime)<=Date.parse(c.observedAt)+30000;}
export function validXionPending(r){try{return !!r&&['mainnet','testnet'].includes(r.networkId)&&addr(r.address)&&addr(r.to)&&typeof r.hash==='string'&&/^[0-9a-f]{64}$/.test(r.hash)&&typeof r.submissionId==='string'&&/^[0-9a-f]{32}$/.test(r.submissionId)&&integer(r.amountAtoms,2n**256n-1n,true)&&integer(r.feeAtoms,99999999999999999999n,true)&&integer(r.gasLimit,10000000n,true)&&integer(r.sequence,2n**64n-1n)&&integer(r.accountNumber,2n**64n-1n)&&(r.timeoutHeight===undefined||integer(r.timeoutHeight,2n**63n-1n,true))&&validClosed(r);}catch{return false;}}
function varint(b,state){let value=0n,shift=0n,start=state.i;while(state.i<b.length&&state.i-start<10){const x=b[state.i++];value|=BigInt(x&127)<<shift;if(!(x&128)){if(state.i-start>1&&x===0)fail();return value;}shift+=7n;}fail();}
function fields(b){const s={i:0},out=[];while(s.i<b.length){const tag=varint(b,s),wire=Number(tag&7n),id=Number(tag>>3n);if(!id)fail();if(wire===2){const n=varint(b,s);if(n>BigInt(b.length-s.i))fail();const end=s.i+Number(n);out.push([id,b.subarray(s.i,end)]);s.i=end;}else if(wire===0)out.push([id,varint(b,s)]);else fail();}return out;}
function pick(list,id){const found=list.filter(x=>x[0]===id);if(found.length!==1||!(found[0][1] instanceof Uint8Array))fail();return found[0][1];}
function equal(a,b){return a.length===b.length&&a.every((x,i)=>x===b[i]);}
export function validateXionSignedPayload(row){
 if(!validXionPending(row)||row.signedPayload?.encoding!=='base64'||typeof row.signedPayload.data!=='string'||row.signedPayload.data.length>12000)fail();
 let raw;try{raw=base64.decode(row.signedPayload.data);}catch{fail();}if(base64.encode(raw)!==row.signedPayload.data||bytesToHex(sha256(raw))!==row.hash)fail();
 const outer=fields(raw);if(outer.length!==3)fail();const body=pick(outer,1),auth=pick(outer,2),sig=pick(outer,3);if(sig.length!==3309)fail();
 const signer=fields(pick(fields(auth),1)),any=fields(pick(signer,1));if(dec.decode(pick(any,1))!=='/cosmos.crypto.mldsa65.PubKey')fail();const pub=pick(fields(pick(any,2)),1);if(pub.length!==1952)fail();
 const doc=buildXionDirectSignDoc({networkId:row.networkId,from:row.address,to:row.to,amount:row.amountAtoms,fee:row.feeAtoms,gas:row.gasLimit,sequence:row.sequence,accountNumber:row.accountNumber,timeoutHeight:row.timeoutHeight,publicKey:pub});
 if(!equal(body,doc.bodyBytes)||!equal(auth,doc.authInfoBytes)||!equal(raw,encodeXionTxRaw({bodyBytes:body,authInfoBytes:auth,signature:sig})))fail();
 return {raw:row.signedPayload.data,publicKey:Uint8Array.from(pub),signature:Uint8Array.from(sig),signDocBytes:doc.signDocBytes};
}
export async function verifyXionSignedPayload(row,{wasmBytes,signal}={}){
 signal?.throwIfAborted();const parsed=validateXionSignedPayload(row);let instance,binary=wasmBytes;
 try{if(!binary){const timeout=AbortSignal.timeout(15000),response=await fetch(new URL('./mldsa65-sign.wasm',import.meta.url),{credentials:'omit',redirect:'error',signal:signal?AbortSignal.any([signal,timeout]):timeout});if(!response.ok)throw Error('Verification module could not load.');binary=await response.arrayBuffer();}
  signal?.throwIfAborted();const result=await WebAssembly.instantiate(binary,{});instance=result.instance??result;const api=instance.exports;api._initialize?.();if(!(api.memory instanceof WebAssembly.Memory)||['mldsa65_message','mldsa65_public_key','mldsa65_signature','mldsa65_verify','mldsa65_clear'].some(x=>typeof api[x]!=='function'))throw Error('Invalid verification module.');
  const memory=new Uint8Array(api.memory.buffer);for(const [name,data] of [['message',parsed.signDocBytes],['public_key',parsed.publicKey],['signature',parsed.signature]]){const at=api[`mldsa65_${name}`]();if(!Number.isInteger(at)||at<0||at+data.length>memory.length)throw Error('Invalid verification memory.');memory.set(data,at);}signal?.throwIfAborted();if(api.mldsa65_verify(parsed.signDocBytes.length,0)!==0)throw Error('Invalid XION signature.');signal?.throwIfAborted();return parsed.raw;
 }finally{parsed.publicKey.fill(0);parsed.signature.fill(0);parsed.signDocBytes.fill(0);if(instance){try{instance.exports.mldsa65_clear?.();}finally{if(instance.exports.memory)new Uint8Array(instance.exports.memory.buffer).fill(0);}}}
}

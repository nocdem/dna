import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey, verify, generateKeyPairSync } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { bech32 } from '@scure/base';
import { sha256 } from '@noble/hashes/sha2';
import { buildXionDirectSignDoc, encodeXionTxRaw } from '../src/pq/xion-sign-doc.js';
import { signXionTransfer } from '../src/pq/xion-sign.js';
const supportsMldsa=(()=>{try{generateKeyPairSync('ml-dsa-65');return true;}catch{return false;}})();
const address = byte => bech32.encode('xion',bech32.toWords(new Uint8Array(20).fill(byte)));
const publicKey=new Uint8Array(1952).fill(3);
const fields={networkId:'mainnet',from:bech32.encode('xion',bech32.toWords(sha256(publicKey).subarray(0,20))),to:address(2),amount:'9007199254740993',fee:'7',gas:'200000',sequence:'18446744073709551615',accountNumber:'9223372036854775808',publicKey};
const digest=x=>createHash('sha256').update(x).digest('hex');
// Pinned schema was independently encoded with google-protobuf 3.21.4
// BinaryWriter; these fixture digests cover all bytes, including uint64 > 2^63.
const fixtures=[['7170b6a87bc33c2d56f6f2f950d3721d67a1647fe62239af72e690e515a15b3b','f2a546e427f2ff4983a3bf0641610194271cf9e1c47f1b519e728bb1da658e85','663a87535fae8da990b30ffda339838d7c6a6411485c2df7e384c22c52852383'],['7170b6a87bc33c2d56f6f2f950d3721d67a1647fe62239af72e690e515a15b3b','9ae0c353cc115ff4e69622711ec0fdfaac34e6fe46ffaddd45d1298639eba877','5b70826819d94ac5a744c43755d7614b975821ae865780ca6358aa7876f1373a']];
function decodeRaw(raw) { let p=0;const parts=[];while(p<raw.length){const tag=raw[p++];assert.ok([10,18,26].includes(tag));let len=0,shift=0,b;do{b=raw[p++];assert.notEqual(b,undefined);len+=(b&127)*2**shift;shift+=7;assert.ok(shift<=28);}while(b&128);assert.ok(p+len<=raw.length);parts.push(raw.slice(p,p+len));p+=len;}assert.equal(parts.length,3);return parts; }
test('SIGN_MODE_DIRECT bytes match independent pinned protobuf fixtures',()=>{
 for(const [i,f] of [fields,{...fields,networkId:'testnet',sequence:'0',accountNumber:'0',fee:'0'}].entries()){
  const x=buildXionDirectSignDoc(f);assert.deepEqual([digest(x.bodyBytes),digest(x.authInfoBytes),digest(x.signDocBytes)],fixtures[i]);
 }
});
test('invalid and ambiguous values are rejected',()=>{
 for(const patch of [{amount:'0'},{amount:'01'},{fee:'-1'},{gas:'0'},{sequence:'18446744073709551616'},{accountNumber:'1e2'},{publicKey:new Uint8Array(1)},{networkId:'other'},{to:'xion1invalid'}]) assert.throws(()=>buildXionDirectSignDoc({...fields,...patch}));
});
test('TxRaw fields round trip without loss',()=>{
 const {bodyBytes,authInfoBytes}=buildXionDirectSignDoc(fields),signature=new Uint8Array(3309).fill(0x55);
 const parts=decodeRaw(encodeXionTxRaw({bodyBytes,authInfoBytes,signature}));assert.deepEqual(parts,[bodyBytes,authInfoBytes,signature]);
 assert.throws(()=>encodeXionTxRaw({bodyBytes,authInfoBytes,signature:new Uint8Array(3308)}));
});
test('synthetic XION TxRaw signature verifies and binds sender',{skip:!supportsMldsa},async()=>{
 const seed=Uint8Array.from({length:32},(_,i)=>i),wasmBytes=await readFile(new URL('../src/pq/mldsa65-sign.wasm',import.meta.url));
 const privateKey=createPrivateKey({key:Buffer.concat([Buffer.from('3034020100300b060960864801650304031204228020','hex'),seed]),format:'der',type:'pkcs8'});
 const pub=createPublicKey(privateKey),pk=new Uint8Array(pub.export({format:'der',type:'spki'}).subarray(-1952));
 const from=bech32.encode('xion',bech32.toWords(sha256(pk).subarray(0,20))), f={...fields,from,publicKey:pk};
 const raw=await signXionTransfer({...f,seed,wasmBytes}), [body,auth,sig]=decodeRaw(raw), expected=buildXionDirectSignDoc(f);
 assert.deepEqual(body,expected.bodyBytes);assert.deepEqual(auth,expected.authInfoBytes);assert.equal(verify(null,expected.signDocBytes,pub,sig),true);
 await assert.rejects(signXionTransfer({...f,seed:new Uint8Array(32),wasmBytes}),/does not match/);
});

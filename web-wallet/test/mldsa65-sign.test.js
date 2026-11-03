import test from 'node:test';
import assert from 'node:assert/strict';
import { mldsa65Sign } from '../src/pq/mldsa65-sign.js';
import { generateKeyPairSync } from 'node:crypto';
const supportsMldsa=(()=>{try{generateKeyPairSync('ml-dsa-65');return true;}catch{return false;}})();
test('ML-DSA bridge rejects bad inputs before module loading',async()=>{
 const seed=new Uint8Array(32),message=new Uint8Array([1]);
 await assert.rejects(mldsa65Sign({seed:new Uint8Array(1),message,context:'xion'}),/seed/);
 await assert.rejects(mldsa65Sign({seed,message:new Uint8Array(65537),context:'xion'}),/message/);
 await assert.rejects(mldsa65Sign({seed,message,context:'unknown'}),/context/);
 const c=new AbortController();c.abort();await assert.rejects(mldsa65Sign({seed,message,context:'xion',signal:c.signal}));
});
test('malformed module fails closed',async()=>{
 await assert.rejects(mldsa65Sign({seed:new Uint8Array(32),message:new Uint8Array(),context:'xion',wasmBytes:new Uint8Array([0,97,115,109,1,0,0,0])}),/Invalid signing module/);
});

test('built WASM signatures match native OpenSSL public key and context rules',{skip:!supportsMldsa},async()=>{
 const {readFile}=await import('node:fs/promises');const {createPrivateKey,createPublicKey,verify}=await import('node:crypto');
 const wasm=await readFile(new URL('../src/pq/mldsa65-sign.wasm',import.meta.url));
 const seed=Uint8Array.from({length:32},(_,i)=>i), message=new TextEncoder().encode('test message');
 const priv=createPrivateKey({key:Buffer.concat([Buffer.from('3034020100300b060960864801650304031204228020','hex'),seed]),format:'der',type:'pkcs8'});
 const pub=createPublicKey(priv); const pk=pub.export({format:'der',type:'spki'}).subarray(-1952);
 for(const context of ['xion','asentum','splendor']) {
  const a=await mldsa65Sign({seed,message,context,wasmBytes:wasm}),b=await mldsa65Sign({seed,message,context,wasmBytes:wasm});
  assert.deepEqual(Buffer.from(a.publicKey),pk);assert.deepEqual(a.signature,b.signature);
  const ctx=Buffer.from(context==='splendor'?'SPLENDOR-QC-TX-v1':'');
  const wrong=Buffer.from(context==='splendor'?'':'SPLENDOR-QC-TX-v1');
  assert.equal(verify(null,message,{key:pub,context:ctx},a.signature),true);
  assert.equal(verify(null,message,{key:pub,context:wrong},a.signature),false);
 }
});

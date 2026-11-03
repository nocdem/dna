import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import { tidecoinSignDigest } from '../src/pq/tidecoin-sign.js';
const wasmBytes=readFileSync(new URL('../src/pq/tidecoin-sign.wasm',import.meta.url));
// Committed independent pristine-upstream oracle, provenance in shared
// crypto/tests/pq_chains/fixtures/README.md and oracle_tidecoin.c. Synthetic only.
const corpus=gunzipSync(readFileSync(new URL('../../shared/crypto/tests/pq_chains/fixtures/tidecoin.bin.gz',import.meta.url)));
assert.equal(corpus.subarray(0,8).toString(),'PQPORT01');let pos=8;
const uint=()=>{const n=corpus.readUInt32LE(pos);pos+=4;return n;};
const count=uint(),vectors=[];
for(let i=0;i<count;i++){
 const scheme=uint(),parameter=uint(),id=uint(),flags=uint(),fields=[];
 for(let j=0;j<8;j++){const n=uint();assert.ok(n<=1048576&&pos+n<=corpus.length);fields.push(corpus.subarray(pos,pos+n));pos+=n;}
 if(scheme===2&&parameter===512&&(flags&2)&&fields[1].length===32)vectors.push({id,fields});
}
assert.equal(pos,corpus.length);assert.equal(vectors.length,1);
const [seed,digest,,publicKey,,signature,rnd]=vectors[0].fields;
async function verify(pk,sig,msg){
 const {instance}=await WebAssembly.instantiate(wasmBytes,{}),a=instance.exports;a._initialize?.();const memory=new Uint8Array(a.memory.buffer);
 try{memory.set(pk,a.tdc_public_key());memory.set(sig,a.tdc_signature());memory.set(msg,a.tdc_message());return a.tdc_verify(sig.length);}
 finally{a.tdc_clear();memory.fill(0);}
}
test('TDC legacy signer matches pristine upstream key and signature bytes for 32-byte digest',async()=>{
 assert.equal(rnd.length,88);
 const result=await tidecoinSignDigest({seed,digest,rnd,wasmBytes});
 assert.deepEqual(Buffer.from(result.publicKey),publicKey);assert.deepEqual(Buffer.from(result.signature),signature);
 assert.equal(result.signature[0],0x39);assert.equal(await verify(result.publicKey,result.signature,digest),0);
 const changed=Uint8Array.from(digest);changed[0]^=1;assert.notEqual(await verify(result.publicKey,result.signature,changed),0);
});
test('TDC signer uses fresh random entropy and rejects malformed/cancelled operations',async()=>{
 const a=await tidecoinSignDigest({seed,digest,wasmBytes}),b=await tidecoinSignDigest({seed,digest,wasmBytes});
 assert.notDeepEqual(a.signature,b.signature);assert.equal(await verify(a.publicKey,a.signature,digest),0);
 await assert.rejects(tidecoinSignDigest({seed:new Uint8Array(32),digest,wasmBytes}));
 await assert.rejects(tidecoinSignDigest({seed,digest,rnd:new Uint8Array(32),wasmBytes}));
 await assert.rejects(tidecoinSignDigest({seed,digest,wasmBytes,signal:AbortSignal.abort()}));
});
test('TDC signer clears instance memory and never mutates caller-owned input buffers',async()=>{
 const original=WebAssembly.instantiate;let memory;
 WebAssembly.instantiate=async(...args)=>{const value=await original(...args);memory=new Uint8Array(value.instance.exports.memory.buffer);return value;};
 const before=Buffer.from(seed);
 try{await tidecoinSignDigest({seed,digest,rnd,wasmBytes});assert.ok(memory.every(x=>x===0));assert.deepEqual(seed,before);}
 finally{WebAssembly.instantiate=original;}
});

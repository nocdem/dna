import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { algorandFalconSign } from '../src/pq/algorand-sign.js';
const vector=JSON.parse(await readFile(new URL('./falcon-reference/payment-vector.json',import.meta.url),'utf8'));
const bytes=hex=>new Uint8Array(Buffer.from(hex,'hex'));
const wasmBytes=await readFile(new URL('../src/pq/algorand-sign.wasm',import.meta.url));
test('Falcon WASM signing matches independent pinned upstream native oracle byte-for-byte',async()=>{
 const seed=bytes(vector.seed),message=bytes(vector.message);
 const signed=await algorandFalconSign({seed,message,wasmBytes});
 assert.equal(Buffer.from(signed.publicKey).toString('hex'),vector.publicKey);
 assert.equal(Buffer.from(signed.signature).toString('hex'),vector.signature);
 assert.deepEqual(await algorandFalconSign({seed,message,wasmBytes}),signed);
 assert.equal(Buffer.from(seed).toString('hex'),vector.seed);
 assert.equal(Buffer.from(message).toString('hex'),vector.message);
 const altered=message.slice();altered[altered.length-1]^=1;
 assert.notDeepEqual((await algorandFalconSign({seed,message:altered,wasmBytes})).signature,signed.signature);
});
test('Falcon invalid inputs and cancellation fail before signing',async()=>{
 const valid={seed:bytes(vector.seed),message:bytes(vector.message),wasmBytes};
 for(const fields of [{seed:new Uint8Array(31)},{message:new Uint8Array(32)},{message:new Uint8Array(4097)},{wasmBytes:new Uint8Array(4)}]) await assert.rejects(algorandFalconSign({...valid,...fields}));
 await assert.rejects(algorandFalconSign({...valid,signal:AbortSignal.abort()}));
});
test('C bridge clears seed/message on success, clears all outputs on failure',async()=>{
 const {instance}=await WebAssembly.instantiate(wasmBytes,{}),api=instance.exports;api._initialize?.();
 const memory=new Uint8Array(api.memory.buffer),seedOffset=api.algo_seed(),msgOffset=api.algo_message();
 memory.set(bytes(vector.seed),seedOffset);memory.set(bytes(vector.message),msgOffset);
 assert.equal(api.algo_sign(bytes(vector.message).length),0);
 assert(memory.slice(seedOffset,seedOffset+32).every(v=>v===0));
 assert(memory.slice(msgOffset,msgOffset+4096).every(v=>v===0));
 assert.equal(api.algo_sign(4097),-1);assert.equal(api.algo_signature_length(),0);
 assert(memory.slice(api.algo_public_key(),api.algo_public_key()+1793).every(v=>v===0));
 api.algo_clear();memory.fill(0);
});

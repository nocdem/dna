// Parent adversarial gates: real WASM with deliberately corrupted ABI outputs
// and queued aborts. Public fixtures only; no transport, skips, flags or files
// created. These tests cover failure cleanup, not a browser memory-erasure proof.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { derivePqAddresses } from '../src/pq/receive.js';
import { receiveWasmBytes } from './fixtures/pq-port-vectors.js';
const fixture=JSON.parse(readFileSync(new URL('./fixtures/pq-receive.json',import.meta.url))).vectors[0];
const wasmBytes=receiveWasmBytes();
function wrap(t,change) {
  const original=WebAssembly.instantiate,memories=[];
  t.mock.method(WebAssembly,'instantiate',async(...args)=>{
    const result=await original(...args),api=(result.instance??result).exports;
    // Node/undici may instantiate its own llhttp Module concurrently. Only
    // intercept our bridge; preserve both native instantiate result shapes.
    if(typeof api.pq_receive_derive!=='function')return result;
    memories.push(api.memory);
    return {...result,instance:{exports:{...api,...change(api)}}};
  });return memories;
}
function wiped(memories) {assert.ok(memories.length>0);for(const memory of memories)assert.ok(new Uint8Array(memory.buffer).every(v=>v===0));}
for(const [name,change] of [
  ['seed ABI mismatch',api=>({pq_receive_seed_size:()=>95})],
  ['public ABI mismatch',api=>({pq_receive_public_size:()=>1})],
  ['negative input pointer',api=>({pq_receive_input:()=>-1})],
  ['output pointer beyond memory',api=>({pq_receive_output:()=>api.memory.buffer.byteLength})],
  ['native trap after seed copy',api=>({pq_receive_derive(){throw new WebAssembly.RuntimeError('sensitive native diagnostics');}})],
])test(`corrupted local module: ${name} fails closed and erases every memory`,async t=>{
  const memories=wrap(t,change);let published=0;
  const result=await derivePqAddresses(fixture.phrase,{wasmBytes,onAddress(){published++;}});
  assert.equal(published,0);assert.deepEqual(result.addresses,{});assert.equal(Object.keys(result.errors).length,8);
  assert.ok(Object.values(result.errors).every(value=>value==='Receive address could not be derived.'));
  wiped(memories);
});
test('abort queued by native return runs before publication and wipes WASM',async t=>{
  const controller=new AbortController();let published=0;
  const memories=wrap(t,api=>({pq_receive_derive(...args){const rc=api.pq_receive_derive(...args);queueMicrotask(()=>controller.abort());return rc;}}));
  await assert.rejects(derivePqAddresses(fixture.phrase,{wasmBytes,signal:controller.signal,onAddress(){published++;}}),{name:'AbortError'});
  assert.equal(published,0);assert.equal(memories.length,1);wiped(memories);
});
test('native-invalid Soqucoin key cannot publish an address or poison other chains',async t=>{
  let count=0;const memories=wrap(t,api=>({pq_receive_derive(...args){const rc=api.pq_receive_derive(...args);if(++count===4)new Uint8Array(api.memory.buffer)[api.pq_receive_output()]=255;return rc;}}));
  const result=await derivePqAddresses(fixture.phrase,{wasmBytes});
  const expected=structuredClone(fixture.addresses);delete expected.soqucoin;
  assert.deepEqual(result.addresses,expected);assert.deepEqual(result.errors,{soqucoin:'Receive address could not be derived.'});
  wiped(memories);
});

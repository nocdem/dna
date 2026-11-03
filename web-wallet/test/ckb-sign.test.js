import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { ckbSignMessage } from '../src/pq/ckb-sign.js';
import { portVectors } from './fixtures/pq-port-vectors.js';
const wasmBytes = readFileSync(new URL('../src/pq/ckb-slh-sign.wasm', import.meta.url));
test('CKB SHA2-256s signer matches independent NIST key and verifies a 32-byte message', async () => {
  const vector = portVectors('slhdsa-nist.bin.gz').find(v => v.param === 5 && (v.flags & 1));
  assert.ok(vector);
  const message = new Uint8Array(32).fill(19), rnd = new Uint8Array(32).fill(7);
  const result = await ckbSignMessage({ seed: new Uint8Array(vector.seed), message, rnd, wasmBytes });
  assert.deepEqual(Buffer.from(result.publicKey), vector.pk);
  assert.equal(result.signature.length, 29792);
  const { instance } = await WebAssembly.instantiate(wasmBytes, {}); const e = instance.exports; e._initialize?.();
  const memory = new Uint8Array(e.memory.buffer);
  try {
    memory.set(result.publicKey,e.ckb_slh_public_key()); memory.set(result.signature,e.ckb_slh_signature()); memory.set(message,e.ckb_slh_message());
    assert.equal(e.ckb_slh_verify(),0);
    memory[e.ckb_slh_message()]^=1; assert.notEqual(e.ckb_slh_verify(),0);
    e.ckb_slh_clear();
    for(const [pointer,size] of [[e.ckb_slh_seed(),96],[e.ckb_slh_message(),32],[e.ckb_slh_random(),32],[e.ckb_slh_public_key(),64],[e.ckb_slh_signature(),29792]]) assert.ok(memory.subarray(pointer,pointer+size).every(b=>b===0));
  } finally { memory.fill(0); }
});
test('CKB signer refuses wrong lengths and cancelled requests', async () => {
  await assert.rejects(ckbSignMessage({ seed:new Uint8Array(32),message:new Uint8Array(32),wasmBytes }));
  await assert.rejects(ckbSignMessage({ seed:new Uint8Array(96),message:new Uint8Array(31),wasmBytes }));
  await assert.rejects(ckbSignMessage({ seed:new Uint8Array(96),message:new Uint8Array(32),wasmBytes,signal:AbortSignal.abort() }));
});

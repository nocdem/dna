import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { hexToBytes, bytesToHex } from '@noble/hashes/utils';
import { soquSignDigest } from '../src/pq/soqu-sign.js';
const wasmBytes = readFileSync(new URL('../src/pq/mldsa44-sign.wasm', import.meta.url));
const vector = JSON.parse(readFileSync(new URL('./fixtures/soqu-node-sighash.json', import.meta.url)));
async function verify(publicKey, signature, digest) {
  const { instance } = await WebAssembly.instantiate(wasmBytes, {}); const e = instance.exports; e._initialize?.();
  const memory = new Uint8Array(e.memory.buffer);
  try { memory.set(publicKey, e.mldsa44_public_key()); memory.set(signature, e.mldsa44_signature()); memory.set(digest, e.mldsa44_message()); return e.mldsa44_verify(); }
  finally { e.mldsa44_clear(); memory.fill(0); }
}
test('SOQ WASM verifies independently node-produced signatures and rejects altered digest', async () => {
  for (let i = 0; i < 2; i++) {
    const pk = hexToBytes(vector.witness[i][1].slice(2)), sig = hexToBytes(vector.witness[i][0].slice(0, -2)), digest = hexToBytes(vector.digests[i]);
    assert.equal(await verify(pk, sig, digest), 0);
    digest[0] ^= 1; assert.notEqual(await verify(pk, sig, digest), 0);
  }
});
test('SOQ seeded signer matches node key and emits valid hedged FIPS signature', async () => {
  const seed = hexToBytes(vector.key.seed), digest = hexToBytes(vector.digests[0]);
  const result = await soquSignDigest({ seed, digest, wasmBytes });
  assert.equal(bytesToHex(result.publicKey), vector.witness[0][1].slice(2));
  assert.equal(await verify(result.publicKey, result.signature, digest), 0);
  assert.equal(bytesToHex(seed), vector.key.seed); // caller owns/wipes seed
  const second = await soquSignDigest({ seed, digest, wasmBytes });
  assert.notDeepEqual(result.signature, second.signature);
});
test('SOQ signer refuses malformed input and cancelled operations', async () => {
  await assert.rejects(soquSignDigest({ seed: new Uint8Array(31), digest: new Uint8Array(32), wasmBytes }));
  await assert.rejects(soquSignDigest({ seed: new Uint8Array(32), digest: new Uint8Array(32), rnd: new Uint8Array(31), wasmBytes }));
  await assert.rejects(soquSignDigest({ seed: new Uint8Array(32), digest: new Uint8Array(32), wasmBytes, signal: AbortSignal.abort() }));
});

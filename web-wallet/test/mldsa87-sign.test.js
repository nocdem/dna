import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { hexToBytes, bytesToHex } from '@noble/hashes/utils';
import { mldsa87Sign } from '../src/pq/sign.js';
import { ixiosSigningSeed, ixiosAddressBytes } from '../src/ixios/derive.js';

const wasmBytes = readFileSync(new URL('../src/pq/mldsa87-sign.wasm', import.meta.url));
const fixture = JSON.parse(readFileSync(new URL('./fixtures/ixios-vectors.json', import.meta.url)));
const { hash, rnd, vectors } = fixture;
const fixedHash = hexToBytes(hash);
const fixedRnd = hexToBytes(rnd);

// Exports are the six functions this module declares plus whatever emcc itself
// adds for a STANDALONE_WASM build with no imports (memory, _initialize, the
// indirect-call table and its stack helpers) — same shape as src/nodus/mldsa87.wasm.
const EXPECTED_EXPORTS = [
  'mldsa_seed', 'mldsa_hash', 'mldsa_rnd', 'mldsa_pk', 'mldsa_sig', 'mldsa_sign',
  'memory', '_initialize', '__indirect_function_table',
  '_emscripten_stack_restore', 'emscripten_stack_get_current',
].sort();

test('mldsa87-sign.wasm has zero imports and exactly the declared exports', () => {
  const module = new WebAssembly.Module(wasmBytes);
  assert.deepEqual(WebAssembly.Module.imports(module), []);
  assert.deepEqual(WebAssembly.Module.exports(module).map(e => e.name).sort(), EXPECTED_EXPORTS);
});

test('Ixios signatures match native C for public test phrases, fixed rnd, without network access', async t => {
  const originalFetch = globalThis.fetch;
  t.after(() => { globalThis.fetch = originalFetch; });
  globalThis.fetch = () => { throw new Error('Unexpected network request'); };
  for (const { phrase, publicKey, address, signature } of vectors) {
    const seed = ixiosSigningSeed(phrase);
    const { publicKey: pk, signature: sig } = await mldsa87Sign({ seed, hash: fixedHash, rnd: fixedRnd, wasmBytes });
    assert.equal(bytesToHex(pk), publicKey);
    assert.equal(bytesToHex(sig), signature);
    assert.equal(bytesToHex(ixiosAddressBytes(pk)), address);
    assert.equal(pk.length, 2592);
    assert.equal(sig.length, 4627);
  }
});

test('Omitting rnd keeps the public key but changes the signature (hedged signing)', async () => {
  const { phrase, publicKey, signature } = vectors[0];
  const seed = ixiosSigningSeed(phrase);
  const hedged = await mldsa87Sign({ seed, hash: fixedHash, wasmBytes });
  assert.equal(bytesToHex(hedged.publicKey), publicKey);
  assert.notEqual(bytesToHex(hedged.signature), signature);
  assert.equal(hedged.signature.length, 4627);
});

test('mldsa87Sign wipes the entire private WASM instance on success and cancellation', async t => {
  const instantiate = WebAssembly.instantiate;
  let lastInstance, cancel;
  t.after(() => { WebAssembly.instantiate = instantiate; });
  WebAssembly.instantiate = async (...args) => {
    const result = await instantiate(...args);
    lastInstance = result.instance;
    cancel?.abort();
    return result;
  };
  const seed = ixiosSigningSeed(vectors[0].phrase);
  await mldsa87Sign({ seed, hash: fixedHash, rnd: fixedRnd, wasmBytes });
  assert.ok(new Uint8Array(lastInstance.exports.memory.buffer).every(byte => byte === 0));
  const previous = lastInstance;
  cancel = new AbortController();
  await assert.rejects(mldsa87Sign({ seed, hash: fixedHash, rnd: fixedRnd, wasmBytes, signal: cancel.signal }), { name: 'AbortError' });
  assert.notEqual(lastInstance, previous);
  assert.ok(new Uint8Array(lastInstance.exports.memory.buffer).every(byte => byte === 0));
});

test('mldsa87Sign rejects wrong-length seed, hash and rnd', async () => {
  const seed = ixiosSigningSeed(vectors[0].phrase);
  await assert.rejects(mldsa87Sign({ seed: seed.slice(0, 31), hash: fixedHash, rnd: fixedRnd, wasmBytes }));
  await assert.rejects(mldsa87Sign({ seed, hash: fixedHash.slice(0, 31), rnd: fixedRnd, wasmBytes }));
  await assert.rejects(mldsa87Sign({ seed, hash: fixedHash, rnd: fixedRnd.slice(0, 31), wasmBytes }));
  await assert.rejects(mldsa87Sign({ seed, hash: new Uint8Array(33), rnd: fixedRnd, wasmBytes }));
});

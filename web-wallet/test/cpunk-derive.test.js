import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { deriveCpunkAddress, validateDerivedAddress } from '../src/cpunk/derive.js';
const wasmBytes = readFileSync(new URL('../src/cpunk/legacy-dilithium.wasm', import.meta.url));
const vectors = JSON.parse(readFileSync(new URL('./fixtures/cpunk-vectors.json', import.meta.url)));
test('legacy WASM matches native OpenSSL/Cellframe address vectors', async () => {
  for (const { phrase, address } of vectors) {
    assert.equal(await deriveCpunkAddress(phrase, { wasmBytes }), address);
    assert.equal(validateDerivedAddress(address), address);
    assert.throws(() => validateDerivedAddress(address.slice(0, -1) + (address.endsWith('1') ? '2' : '1')), /checksum/);
    if (process.env.CPUNK_NATIVE_CHECK) assert.equal(execFileSync(process.env.CPUNK_NATIVE_CHECK, [phrase], { encoding: 'utf8' }).trim(), address);
  }
  await assert.rejects(deriveCpunkAddress('invalid', { wasmBytes }), /valid recovery/);
});
test('CPUNK cancellation during module loading prevents derivation and passes the abort to fetch', async t => {
  const originalFetch = globalThis.fetch, instantiate = WebAssembly.instantiate;
  t.after(() => { globalThis.fetch = originalFetch; WebAssembly.instantiate = instantiate; });
  const controller = new AbortController(); let fetchedSignal, instantiated = false, release;
  globalThis.fetch = async (_, options) => {
    fetchedSignal = options.signal;
    return { ok: true, arrayBuffer: () => new Promise(resolve => { release = () => resolve(wasmBytes); }) };
  };
  WebAssembly.instantiate = async (...args) => { instantiated = true; return instantiate(...args); };
  const pending = deriveCpunkAddress(vectors[0].phrase, { signal: controller.signal });
  await new Promise(resolve => setImmediate(resolve));
  controller.abort(); release();
  await assert.rejects(pending, { name: 'AbortError' });
  assert.equal(fetchedSignal.aborted, true); assert.equal(instantiated, false);
});
test('CPUNK wipes its entire WASM instance on success and cancellation after instantiation', async t => {
  const instantiate = WebAssembly.instantiate; let lastInstance, cancel;
  t.after(() => { WebAssembly.instantiate = instantiate; });
  WebAssembly.instantiate = async (...args) => { const result = await instantiate(...args); lastInstance = result.instance; cancel?.abort(); return result; };
  assert.equal(await deriveCpunkAddress(vectors[0].phrase, { wasmBytes }), vectors[0].address);
  assert.ok(new Uint8Array(lastInstance.exports.memory.buffer).every(byte => byte === 0));
  cancel = new AbortController();
  await assert.rejects(deriveCpunkAddress(vectors[0].phrase, { wasmBytes, signal: cancel.signal }), { name: 'AbortError' });
  assert.ok(new Uint8Array(lastInstance.exports.memory.buffer).every(byte => byte === 0));
});

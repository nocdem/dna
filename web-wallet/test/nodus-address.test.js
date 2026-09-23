import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { deriveNodusAddress } from '../src/nodus/derive.js';
const wasmBytes = readFileSync(new URL('../src/nodus/mldsa87.wasm', import.meta.url));
const { vectors } = JSON.parse(readFileSync(new URL('./fixtures/nodus-addresses.json', import.meta.url)));

test('Nodus addresses match native C for 24-word recovery phrases without network access', async t => {
  const originalFetch = globalThis.fetch;
  t.after(() => { globalThis.fetch = originalFetch; });
  globalThis.fetch = () => { throw new Error('Unexpected network request'); };
  const module = new WebAssembly.Module(wasmBytes);
  assert.deepEqual(WebAssembly.Module.imports(module), []);
  assert.ok(WebAssembly.Module.exports(module).every(({ name }) => !/sign|random/i.test(name)));
  for (const { phrase, address } of vectors) {
    assert.equal(await deriveNodusAddress(phrase, { wasmBytes }), address);
    assert.match(address, /^[0-9a-f]{128}$/);
  }
  assert.equal(await deriveNodusAddress('  ' + vectors[0].phrase.toUpperCase().replaceAll(' ', '\n') + '  ', { wasmBytes }), vectors[0].address);
  await assert.rejects(deriveNodusAddress('abandon '.repeat(12), { wasmBytes }), /24-word/);
});

test('Nodus derivation wipes the entire private WASM instance on success and cancellation', async t => {
  const instantiate = WebAssembly.instantiate;
  let lastInstance, cancel;
  t.after(() => { WebAssembly.instantiate = instantiate; });
  WebAssembly.instantiate = async (...args) => {
    const result = await instantiate(...args);
    lastInstance = result.instance;
    cancel?.abort();
    return result;
  };
  assert.equal(await deriveNodusAddress(vectors[0].phrase, { wasmBytes }), vectors[0].address);
  assert.ok(new Uint8Array(lastInstance.exports.memory.buffer).every(byte => byte === 0));
  const previous = lastInstance;
  cancel = new AbortController();
  await assert.rejects(deriveNodusAddress(vectors[0].phrase, { wasmBytes, signal: cancel.signal }), { name: 'AbortError' });
  assert.notEqual(lastInstance, previous);
  assert.ok(new Uint8Array(lastInstance.exports.memory.buffer).every(byte => byte === 0));
  await assert.rejects(deriveNodusAddress(vectors[0].phrase, { wasmBytes: new Uint8Array(1) }), WebAssembly.CompileError);
});

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

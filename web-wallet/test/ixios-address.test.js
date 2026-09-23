import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { deriveIxiosAddress } from '../src/ixios/derive.js';
import { ixiosChecksumAddress, parseIxiosAddress } from '../src/ixios/address.js';
// Address display uses the keygen-only Nodus module, never the signing module.
const wasmBytes = readFileSync(new URL('../src/nodus/mldsa87.wasm', import.meta.url));
const { vectors } = JSON.parse(readFileSync(new URL('./fixtures/ixios-vectors.json', import.meta.url)));
const checksums = JSON.parse(readFileSync(new URL('./fixtures/ixios-checksum.json', import.meta.url))).vectors;

test('fixtures are non-empty and describe the same public phrases', () => {
  assert.ok(vectors.length > 0);
  assert.equal(checksums.length, vectors.length);
  for (const [i, { Phrase, Address }] of checksums.entries()) {
    assert.equal(Phrase, vectors[i].phrase);
    assert.equal(Address, vectors[i].address);
  }
});

test('Ixios addresses from the keygen-only module match native C, without network access', async t => {
  const originalFetch = globalThis.fetch;
  t.after(() => { globalThis.fetch = originalFetch; });
  globalThis.fetch = () => { throw new Error('Unexpected network request'); };
  const module = new WebAssembly.Module(wasmBytes);
  assert.deepEqual(WebAssembly.Module.imports(module), []);
  assert.ok(WebAssembly.Module.exports(module).every(({ name }) => !/sign|random/i.test(name)));
  for (const { phrase, address } of vectors) {
    const bytes = await deriveIxiosAddress(phrase, { wasmBytes });
    assert.ok(bytes instanceof Uint8Array);
    assert.equal(bytes.length, 48);
    assert.equal(bytesToHex(bytes), address);
  }
  assert.equal(bytesToHex(await deriveIxiosAddress('  ' + vectors[0].phrase.toUpperCase().replaceAll(' ', '\n') + '  ', { wasmBytes })), vectors[0].address);
  await assert.rejects(deriveIxiosAddress('abandon '.repeat(12), { wasmBytes }), /24-word/);
});

test('ixiosChecksumAddress reproduces ixiosSpark common.Address.Hex() (Keccak-512)', () => {
  for (const { Address, Checksummed } of checksums) {
    assert.equal(ixiosChecksumAddress(hexToBytes(Address)), Checksummed);
  }
  assert.throws(() => ixiosChecksumAddress(new Uint8Array(32)), /48 bytes/);
  assert.throws(() => ixiosChecksumAddress(new Uint8Array(20)), /48 bytes/);
  assert.throws(() => ixiosChecksumAddress(checksums[0].Address), /48 bytes/);
});

test('parseIxiosAddress accepts only 0x + 96 hex and enforces a mixed-case checksum', () => {
  const { Address, Checksummed } = checksums[0];
  assert.equal(bytesToHex(parseIxiosAddress(Checksummed)), Address);
  assert.equal(bytesToHex(parseIxiosAddress('0x' + Address)), Address);
  assert.equal(bytesToHex(parseIxiosAddress('0x' + Address.toUpperCase())), Address);
  for (const { Address: other, Checksummed: good } of checksums) assert.equal(bytesToHex(parseIxiosAddress(good)), other);
  // 20-, 32-, 47- and 49-byte forms (the Ixios RPC would zero-pad the short ones).
  for (const bytes of [20, 32, 47, 49]) {
    assert.throws(() => parseIxiosAddress('0x' + 'ab'.repeat(bytes)), /48-byte/);
  }
  assert.throws(() => parseIxiosAddress(Address), /48-byte/);
  assert.throws(() => parseIxiosAddress('0X' + Address), /48-byte/);
  assert.throws(() => parseIxiosAddress(' ' + Checksummed), /48-byte/);
  assert.throws(() => parseIxiosAddress('0x' + Address.slice(0, -1) + 'g'), /48-byte/);
  assert.throws(() => parseIxiosAddress(undefined), /48-byte/);
  // Flip the case of one letter in a correctly checksummed address.
  const at = [...Checksummed].findIndex((c, i) => i > 1 && /[a-fA-F]/.test(c));
  const flipped = Checksummed.slice(0, at) + (Checksummed[at] === Checksummed[at].toLowerCase() ? Checksummed[at].toUpperCase() : Checksummed[at].toLowerCase()) + Checksummed.slice(at + 1);
  assert.notEqual(flipped, Checksummed);
  assert.throws(() => parseIxiosAddress(flipped), /checksum/);
});

test('Ixios derivation wipes the entire private WASM instance on success and cancellation', async t => {
  const instantiate = WebAssembly.instantiate;
  let lastInstance, cancel;
  t.after(() => { WebAssembly.instantiate = instantiate; });
  WebAssembly.instantiate = async (...args) => {
    const result = await instantiate(...args);
    lastInstance = result.instance;
    cancel?.abort();
    return result;
  };
  assert.equal(bytesToHex(await deriveIxiosAddress(vectors[0].phrase, { wasmBytes })), vectors[0].address);
  assert.ok(new Uint8Array(lastInstance.exports.memory.buffer).every(byte => byte === 0));
  const previous = lastInstance;
  cancel = new AbortController();
  await assert.rejects(deriveIxiosAddress(vectors[0].phrase, { wasmBytes, signal: cancel.signal }), { name: 'AbortError' });
  assert.notEqual(lastInstance, previous);
  assert.ok(new Uint8Array(lastInstance.exports.memory.buffer).every(byte => byte === 0));
  await assert.rejects(deriveIxiosAddress(vectors[0].phrase, { wasmBytes: new Uint8Array(1) }), WebAssembly.CompileError);
});

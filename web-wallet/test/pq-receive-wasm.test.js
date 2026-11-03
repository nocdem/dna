// Executes the browser artifact, not merely a native/archive build. Requires
// scripts/build-pq-receive-wasm.sh. Missing artifact/corpus fails, never skips.
// No network, RNG, persistent keys or output artifacts. Compiler flags in
// crypto/pq-receive/CMakeLists.txt. Full signature conformance remains in
// shared/crypto/tests/pq_chains; this suite checks bridge routing/public keys and,
// for Tidecoin Falcon-512 only, the restricted secret-key export (see the block at the end).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { portVectors, receiveWasmBytes } from './fixtures/pq-port-vectors.js';
import { derivePqAddresses } from '../src/pq/receive.js';

const module = new WebAssembly.Module(receiveWasmBytes());
const selected = [
  ...JSON.parse(readFileSync(new URL('./fixtures/pq-receive-algorand.json', import.meta.url))).rows.map((v,id) => ({ scheme:1,param:1024,id,seed:Buffer.from(v.seed,'hex'),pk:Buffer.from(v.pk,'hex') })),
  ...portVectors('tidecoin.bin.gz').filter(v => v.flags & 1).slice(0, 3),
  ...portVectors('slhdsa-nist.bin.gz').filter(v => v.flags & 1),
];
// NIST keyGen case IDs are corpus IDs; take two of each explicitly to avoid
// accidentally dropping a selector when upstream fixture IDs change.
for (const param of [44, 65]) {
  selected.push(...portVectors('mldsa-nist.bin.gz').filter(v => v.flags & 1 && v.param === param).slice(0, 2));
}
const kindOf = scheme => ({ 1: 1, 2: 2, 3: 4, 5: 3 })[scheme];
const selectors = new Set(selected.map(v => `${kindOf(v.scheme)}:${v.param}`));

test('keygen module has no external capabilities or signing exports', () => {
  assert.deepEqual(WebAssembly.Module.imports(module), []);
  assert.equal(selectors.size, 16);
  assert.equal(selected.filter(v => v.scheme === 3).length, 12);
  const names = WebAssembly.Module.exports(module).map(x => x.name);
  // Exactly the two restricted Tidecoin secret accessors may match; any other sign/verify/random/secret export fails.
  assert.deepEqual(names.filter(n => /sign|verify|random|secret/i.test(n)).sort(), ['pq_receive_secret', 'pq_receive_secret_size']);
  for (const name of ['memory', 'pq_receive_input', 'pq_receive_output', 'pq_receive_seed_size', 'pq_receive_public_size', 'pq_receive_derive', 'pq_receive_clear', 'pq_receive_secret', 'pq_receive_secret_size']) assert.ok(names.includes(name));
});

for (const [index, v] of selected.entries()) test(`upstream key bytes and clearing: ${v.scheme}/${v.param}/${v.id} #${index}`, () => {
  const instance = new WebAssembly.Instance(module, {}), e = instance.exports;
  e._initialize?.();
  const mem = new Uint8Array(e.memory.buffer), input = e.pq_receive_input(), output = e.pq_receive_output(), kind = kindOf(v.scheme);
  try {
    assert.equal(mem.byteLength, 4 * 1024 * 1024);
    assert.equal(e.pq_receive_seed_size(kind, v.param), v.seed.length);
    assert.equal(e.pq_receive_public_size(kind, v.param), v.pk.length);
    mem.fill(0xa5, input, input + 96); mem.set(v.seed, input);
    mem.fill(0xa5, output, output + 1952);
    assert.equal(e.pq_receive_derive(kind, v.param, v.seed.length), 0);
    assert.deepEqual(Buffer.from(mem.subarray(output, output + v.pk.length)), v.pk);
    assert.ok(mem.subarray(input, input + 96).every(x => x === 0));
    assert.ok(mem.subarray(output + v.pk.length, output + 1952).every(x => x === 0));
    e.pq_receive_clear();
    assert.ok(mem.subarray(output, output + 1952).every(x => x === 0));
  } finally { mem.fill(0); }
});

test('invalid selector/length clears stale public output and all input', () => {
  const e = new WebAssembly.Instance(module, {}).exports; e._initialize?.();
  const mem = new Uint8Array(e.memory.buffer), input = e.pq_receive_input(), output = e.pq_receive_output();
  try {
    for (const [kind, param, length] of [[0,0,32],[-1,0,32],[1,512,32],[2,1024,48],[3,87,32],[4,-1,48],[4,12,48],[1,1024,-1],[1,1024,31],[1,1024,33],[4,5,95],[4,5,97],[3,44,2147483647]]) {
      mem.fill(0xa5, input, input + 96); mem.fill(0xa5, output, output + 1952);
      assert.notEqual(e.pq_receive_derive(kind,param,length), 0);
      assert.ok(mem.subarray(input,input + 96).every(x => x === 0));
      assert.ok(mem.subarray(output,output + 1952).every(x => x === 0));
    }
    for (const [kind,param] of [[0,0],[1,512],[2,1024],[3,87],[4,-1],[4,12]]) {
      assert.equal(e.pq_receive_seed_size(kind,param),0); assert.equal(e.pq_receive_public_size(kind,param),0);
    }
    assert.throws(() => e.memory.grow(1), RangeError);
  } finally { mem.fill(0); }
});

// Restricted Tidecoin secret export (plan docs/plans/approved/2026-11-03-pq-native.md section 1.4;
// Kurultay 52 condition 6). The module keeps the Falcon-512 secret key after a successful kind 2 /
// parameter 512 derivation until pq_receive_clear; every error and every other selector wipes it.
// Proves: the exported secret key equals the pinned upstream corpus secret key for each Falcon-512
// keygen record (non-empty set asserted); it is zero after pq_receive_clear; it is zero after a failed
// derivation and after every other kind / parameter; derivePqAddresses leaves no non-zero JavaScript
// copy of a 1281-byte secret and no non-zero module memory after success, a cancelled run and a run whose
// next key generation fails.
// Needs: the rebuilt src/pq/receive-keygen.wasm (exports pq_receive_secret, pq_receive_secret_size) and
// the pinned corpus in shared/crypto/tests/pq_chains/fixtures. Leaves: nothing (mocks are restored).
// Can falsely pass: the JavaScript-copy check sees only arrays produced by Uint8Array.prototype.slice
// with length 1281, so a copy made by another route would not be seen; the corpus secret keys come
// from the upstream reference, but only for the sampled seeds.
const SECRET_STORAGE = 4032; // crypto/pq-receive-wasm.c: ML-DSA-65 is the largest secret key
const tidecoinKeygen = portVectors('tidecoin.bin.gz').filter(v => v.flags & 1 && v.param === 512);
const secretRegion = (mem, e) => mem.subarray(e.pq_receive_secret(), e.pq_receive_secret() + SECRET_STORAGE);

test('Tidecoin secret export equals the corpus secret key and is zero after clear', () => {
  assert.ok(tidecoinKeygen.length > 0, 'Falcon-512 coverage must not be empty');
  for (const v of tidecoinKeygen) {
    const e = new WebAssembly.Instance(module, {}).exports; e._initialize?.();
    const mem = new Uint8Array(e.memory.buffer), input = e.pq_receive_input(), secret = e.pq_receive_secret();
    try {
      assert.equal(e.pq_receive_secret_size(2, 512), 1281); assert.equal(v.sk.length, 1281);
      mem.set(v.seed, input);
      assert.equal(e.pq_receive_derive(2, 512, v.seed.length), 0);
      assert.deepEqual(Buffer.from(mem.subarray(secret, secret + 1281)), v.sk);
      assert.ok(mem.subarray(secret + 1281, secret + SECRET_STORAGE).every(x => x === 0));
      e.pq_receive_clear();
      assert.ok(secretRegion(mem, e).every(x => x === 0));
    } finally { mem.fill(0); }
  }
});

test('secret storage is zero after a failed derivation and after every other kind and parameter', () => {
  const e = new WebAssembly.Instance(module, {}).exports; e._initialize?.();
  const mem = new Uint8Array(e.memory.buffer), input = e.pq_receive_input(), v = tidecoinKeygen[0];
  const zero = () => secretRegion(mem, e).every(x => x === 0);
  const retain = () => { mem.set(v.seed, input); assert.equal(e.pq_receive_derive(2, 512, v.seed.length), 0); assert.ok(!zero(), 'secret retained after a successful kind 2 / 512 derivation'); };
  try {
    for (const [kind, param] of [[0,0],[1,512],[1,1024],[2,1024],[2,0],[3,44],[3,65],[3,87],[4,5],[4,-1]])
      if (!(kind === 2 && param === 512)) assert.equal(e.pq_receive_secret_size(kind, param), 0, `${kind}/${param}`);
    retain(); mem.fill(0xa5, input, input + 96);
    assert.notEqual(e.pq_receive_derive(2, 512, 47), 0); assert.ok(zero(), 'wrong seed length');
    retain(); mem.fill(0xa5, input, input + 96);
    assert.notEqual(e.pq_receive_derive(2, 1024, 48), 0); assert.ok(zero(), 'unsupported parameter');
    for (const [kind, param, length, mustSucceed] of [[1,1024,32,false],[3,44,32,true],[3,65,32,true],[4,5,96,true]]) {
      retain(); mem.fill(7, input, input + 96);
      const status = e.pq_receive_derive(kind, param, length);
      if (mustSucceed) assert.equal(status, 0, `${kind}/${param}`);
      assert.ok(zero(), `other selector ${kind}/${param}`);
    }
  } finally { mem.fill(0); }
});

function observeTidecoinRun(t, change) {
  const original = WebAssembly.instantiate, memories = [], copies = [], slice = Uint8Array.prototype.slice;
  let tidecoinCalls = 0;
  t.mock.method(WebAssembly, 'instantiate', async (...args) => {
    const result = await original(...args), api = (result.instance ?? result).exports;
    if (typeof api.pq_receive_derive !== 'function') return result;
    memories.push(api.memory);
    return { ...result, instance: { exports: { ...api, pq_receive_derive(...a) {
      if (a[0] === 2) change?.(++tidecoinCalls);
      return api.pq_receive_derive(...a);
    } } } };
  });
  t.mock.method(Uint8Array.prototype, 'slice', function (...a) {
    const out = slice.apply(this, a); if (out.length === 1281) copies.push(out); return out;
  });
  return { memories, copies };
}
const phrase = JSON.parse(readFileSync(new URL('./fixtures/pq-receive.json', import.meta.url))).vectors[0].phrase;
const expectZero = ({ memories, copies }, minimumCopies) => {
  assert.ok(memories.length > 0); for (const memory of memories) assert.ok(new Uint8Array(memory.buffer).every(x => x === 0), 'module memory');
  assert.ok(copies.length >= minimumCopies, `expected at least ${minimumCopies} JavaScript secret copies, saw ${copies.length}`);
  for (const copy of copies) assert.ok(copy.every(x => x === 0), 'JavaScript secret copy');
};

test('Tidecoin derivation: JavaScript secret copies and module memory are zero after success', async t => {
  const seen = observeTidecoinRun(t);
  const { addresses, errors } = await derivePqAddresses(phrase, { wasmBytes: receiveWasmBytes() });
  assert.deepEqual(errors, {}); assert.ok(addresses.tidecoin.mainnet.startsWith('tbc1q'));
  expectZero(seen, 3); // master, 84', 0' are followed by a hardened step; the 0'' node and the account node need none
});

test('Tidecoin derivation: a cancelled run leaves no non-zero secret copy or module memory', async t => {
  const controller = new AbortController();
  const seen = observeTidecoinRun(t, call => { if (call === 3) controller.abort(); });
  await assert.rejects(derivePqAddresses(phrase, { wasmBytes: receiveWasmBytes(), signal: controller.signal }), { name: 'AbortError' });
  expectZero(seen, 1);
});

test('Tidecoin derivation: a failed child key generation leaves no non-zero secret copy or module memory', async t => {
  const seen = observeTidecoinRun(t, call => { if (call === 3) throw new WebAssembly.RuntimeError('synthetic key-generation failure'); });
  const { addresses, errors } = await derivePqAddresses(phrase, { wasmBytes: receiveWasmBytes() });
  assert.equal(addresses.tidecoin, undefined); assert.equal(errors.tidecoin, 'Receive address could not be derived.');
  expectZero(seen, 1);
});

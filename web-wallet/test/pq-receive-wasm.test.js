// Executes the browser artifact, not merely a native/archive build. Requires
// scripts/build-pq-receive-wasm.sh. Missing artifact/corpus fails, never skips.
// No network, RNG, persistent keys or output artifacts. Compiler flags in
// crypto/pq-receive/CMakeLists.txt. Full signature conformance remains in
// shared/crypto/tests/pq_chains; this suite checks bridge routing/public keys.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { portVectors, receiveWasmBytes } from './fixtures/pq-port-vectors.js';

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
  assert.equal(names.filter(n => /sign|verify|random|secret/i.test(n)).length, 0);
  for (const name of ['memory', 'pq_receive_input', 'pq_receive_output', 'pq_receive_seed_size', 'pq_receive_public_size', 'pq_receive_derive', 'pq_receive_clear']) assert.ok(names.includes(name));
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

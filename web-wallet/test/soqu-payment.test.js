import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { hexToBytes } from '@noble/hashes/utils';
import { prepareSoquPayment, signSoquPayment } from '../src/pq/soqu-payment.js';
const v = JSON.parse(readFileSync(new URL('./fixtures/soqu-node-sighash.json', import.meta.url)));
const wasmBytes = readFileSync(new URL('../src/pq/mldsa44-sign.wasm', import.meta.url));
const args = () => ({ networkId: 'mainnet', from: v.key.address_sq, to: v.key.address_sq, inputs: v.inputs.map(i => ({ ...i, value: BigInt(i.value) })), amount: 4000000000n, feeRate: 1000n });
test('SOQ native payment preparation retains exact value conservation and signs offline', async () => {
  const p = prepareSoquPayment(args());
  assert.equal(p.transaction.inputs.reduce((s, i) => s + i.value, 0n), p.transaction.outputs.reduce((s, o) => s + o.value, 0n) + p.fee);
  assert.ok(Object.isFrozen(p.transaction.outputs[0]));
  const signed = await signSoquPayment(p, { seed: hexToBytes(v.key.seed), wasmBytes });
  assert.match(signed.txid, /^[0-9a-f]{64}$/);
  assert.equal(signed.raw.length / 2, 7662);
});
test('SOQ preparation refuses dust, unsupported network, unsafe values and duplicate inputs', () => {
  for (const patch of [{ amount: 1n }, { feeRate: 100001n }, { networkId: 'testnet' }, { amount: 4 }, { amount: 9000000000n }]) assert.throws(() => prepareSoquPayment({ ...args(), ...patch }));
  const a = args(); a.inputs.push(a.inputs[0]); assert.throws(() => prepareSoquPayment(a));
  const b = args(); b.inputs[0].script_pubkey = '5120' + '44'.repeat(32); assert.throws(() => prepareSoquPayment(b));
});
test('SOQ payment refuses another key and cancellation before signing', async () => {
  const p = prepareSoquPayment(args());
  await assert.rejects(signSoquPayment(p, { seed: new Uint8Array(32), wasmBytes }));
  await assert.rejects(signSoquPayment(p, { seed: hexToBytes(v.key.seed), wasmBytes, signal: AbortSignal.abort() }));
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { bytesToHex } from '@noble/hashes/utils';
import { soquScript, soquSignatureHash, serializeSoquTransaction, soquTransactionId, soquTransactionVSize } from '../src/pq/soqu-transaction.js';
const vector = JSON.parse(readFileSync(new URL('./fixtures/soqu-node-sighash.json', import.meta.url)));
test('SOQ node-produced oracle: both input digests, txid, complete signed bytes', () => {
  assert.equal(soquScript(vector.key.address_sq), vector.inputs[0].script_pubkey);
  for (let i = 0; i < vector.inputs.length; i++) assert.equal(bytesToHex(soquSignatureHash(vector, i)), vector.digests[i]);
  assert.equal(soquTransactionId(vector), vector.txid);
  assert.equal(bytesToHex(serializeSoquTransaction(vector, vector.witness)), vector.signed_tx);
  assert.equal(soquTransactionVSize(vector), Math.ceil((serializeSoquTransaction(vector).length * 3 + vector.signed_tx.length / 2) / 4));
});
test('SOQ sighash binds amount, recipient, outpoint, sequence and locktime', () => {
  for (const mutate of [t => t.inputs[0].value++, t => t.outputs[0].script_pubkey = '5120' + '44'.repeat(32), t => t.inputs[0].vout++, t => t.inputs[0].sequence--, t => t.locktime++]) {
    const tx = structuredClone(vector); mutate(tx);
    assert.notEqual(bytesToHex(soquSignatureHash(tx, 0)), vector.digests[0]);
  }
});
test('SOQ refuses invalid/incomplete input, asset confusion and value creation', () => {
  for (const mutate of [t => t.version = 1, t => t.inputs = [], t => t.inputs.push(t.inputs[0]), t => t.inputs[0].value = Number.MAX_SAFE_INTEGER + 1, t => t.outputs[0].value = '2000000000000000001', t => t.outputs[0].script_pubkey = '5720' + '44'.repeat(32), t => t.inputs[0].txid = 'x'.repeat(64)]) {
    const tx = structuredClone(vector); mutate(tx);
    assert.throws(() => serializeSoquTransaction(tx));
  }
  assert.throws(() => soquSignatureHash(vector, -1));
  assert.throws(() => soquSignatureHash(vector, 2));
});
test('SOQ witness is complete, SIGHASH_ALL-only and owns each input', () => {
  assert.throws(() => serializeSoquTransaction(vector, []));
  const wrong = structuredClone(vector.witness); wrong[0][0] = wrong[0][0].slice(0, -2) + '02';
  assert.throws(() => serializeSoquTransaction(vector, wrong));
  const other = structuredClone(vector); other.inputs[0].script_pubkey = '5120' + '44'.repeat(32);
  assert.throws(() => serializeSoquTransaction(other, vector.witness));
  assert.equal(soquTransactionId(vector), vector.txid);
});

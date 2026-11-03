// Offline SOQ payment preparation/signing. Inputs must be independently checked
// against a mainnet node and reserved by the caller before use. No broadcaster.
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, concatBytes } from '@noble/hashes/utils';
import { soquScript, soquSignatureHash, serializeSoquTransaction, soquTransactionId, soquTransactionVSize } from './soqu-transaction.js';
import { soquSignDigest } from './soqu-sign.js';
const FLOOR = 279500n, MAX_FEE = 200000000n;
function positive(value) {
  if (typeof value !== 'bigint' || value <= 0n) throw new Error('SOQ amounts and fee rates must be positive bigint shors.');
  return value;
}
export function prepareSoquPayment({ inputs, from, to, amount, feeRate, networkId } = {}) {
  if (networkId !== 'mainnet') throw new Error('Unsupported SOQ network.');
  positive(amount); positive(feeRate);
  if (amount < FLOOR || feeRate > 100000n) throw new Error('SOQ amount below output floor or fee rate too high.');
  const ownScript = soquScript(from), recipientScript = soquScript(to);
  if (!Array.isArray(inputs) || !inputs.length) throw new Error('SOQ inputs required.');
  const transaction = { version: 2, locktime: 0, inputs: inputs.map(i => {
    if (i.script_pubkey !== ownScript) throw new Error('SOQ input does not belong to this account.');
    positive(i.value);
    return { txid: i.txid, vout: i.vout, value: i.value, script_pubkey: ownScript, sequence: 0xffffffff };
  }), outputs: [{ value: amount, script_pubkey: recipientScript }, { value: FLOOR, script_pubkey: ownScript }] };
  const total = transaction.inputs.reduce((sum, i) => sum + i.value, 0n);
  // Size depends on output shape, not value; start with recipient only if even
  // a minimum change cannot fit. Value conservation is checked by the codec.
  if (total < amount + FLOOR) transaction.outputs.pop();
  const feeEstimate = BigInt(soquTransactionVSize(transaction) + 1) * feeRate;
  if (feeEstimate > MAX_FEE || total < amount + feeEstimate) throw new Error('SOQ fee too high or insufficient funds.');
  const change = total - amount - feeEstimate;
  transaction.outputs = [{ value: amount, script_pubkey: recipientScript }];
  if (change >= FLOOR) transaction.outputs.push({ value: change, script_pubkey: ownScript });
  const fee = total - transaction.outputs.reduce((sum, o) => sum + o.value, 0n);
  if (fee > MAX_FEE) throw new Error('SOQ fee exceeds maximum.');
  serializeSoquTransaction(transaction); // validates totals, fields and duplicates
  for (const row of transaction.inputs) Object.freeze(row);
  for (const row of transaction.outputs) Object.freeze(row);
  Object.freeze(transaction.inputs); Object.freeze(transaction.outputs); Object.freeze(transaction);
  return Object.freeze({ transaction, fee, networkId, from, to, amount });
}
export async function signSoquPayment(prepared, { seed, wasmBytes, signal } = {}) {
  if (!prepared || prepared.networkId !== 'mainnet') throw new Error('Unsupported SOQ payment.');
  // Snapshot before the first await, so UI mutation cannot alter signed outputs.
  const tx = structuredClone(prepared.transaction);
  serializeSoquTransaction(tx);
  const ownScript = soquScript(prepared.from), witness = [];
  if (!tx.inputs.every(i => i.script_pubkey === ownScript)) throw new Error('SOQ payment input ownership mismatch.');
  for (let i = 0; i < tx.inputs.length; i++) {
    signal?.throwIfAborted();
    const { publicKey, signature } = await soquSignDigest({ seed, digest: soquSignatureHash(tx, i), wasmBytes, signal });
    if ('5120' + bytesToHex(sha256(publicKey)) !== ownScript) throw new Error('SOQ signing key does not match account.');
    witness.push([bytesToHex(concatBytes(signature, Uint8Array.of(1))), bytesToHex(concatBytes(Uint8Array.of(0), publicKey))]);
  }
  signal?.throwIfAborted();
  return { raw: bytesToHex(serializeSoquTransaction(tx, witness)), txid: soquTransactionId(tx) };
}

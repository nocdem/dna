// Offline native SOQ witness-v1 codec. No network, key custody or broadcasting.
// Source: soqucoin-labs/soqucoin-sdk@468ca3eed97b050d8add5715ca109fcaac839a60
// tx/builder.go; node oracle: tx/testdata/sighash_node_vector.json (v2.5.0).
// Only SIGHASH_ALL, version 2, native OP_1/PUSH32 outputs are supported.
import { sha256 } from '@noble/hashes/sha256';
import { concatBytes, bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { witnessAddress } from './soqucoin.js';
const cat = (...parts) => concatBytes(...parts);
const hash = bytes => sha256(sha256(bytes));
const MAX_MONEY = 20000000000n * 100000000n;
function uint(value, bytes) {
  if (typeof value === 'number' && !Number.isSafeInteger(value)) throw new Error('Unsafe integer.');
  if (!['number', 'string', 'bigint'].includes(typeof value) || !/^(0|[1-9]\d*)$/.test(String(value))) throw new Error('Invalid integer.');
  let n = BigInt(value);
  if (n >= 1n << BigInt(bytes * 8)) throw new Error('Integer overflow.');
  const out = new Uint8Array(bytes);
  for (let i = 0; i < bytes; i++) { out[i] = Number(n & 255n); n >>= 8n; }
  return out;
}
function compact(n) {
  if (!Number.isSafeInteger(n) || n < 0 || n > 0xffff) throw new Error('Unsupported length.');
  return n < 253 ? Uint8Array.of(n) : cat(Uint8Array.of(253), uint(n, 2));
}
function hex(value, length) {
  if (typeof value !== 'string' || !new RegExp(`^[0-9a-f]{${length * 2}}$`).test(value)) throw new Error('Invalid hex field.');
  return hexToBytes(value);
}
function script(value) {
  const out = hex(value, 34);
  if (out[0] !== 0x51 || out[1] !== 0x20) throw new Error('Only native SOQ witness-v1 scripts are supported.');
  return out;
}
function amount(value) {
  uint(value, 8);
  if (BigInt(value) <= 0n || BigInt(value) > MAX_MONEY) throw new Error('Invalid SOQ amount.');
  return BigInt(value);
}
export function soquScript(address) {
  return bytesToHex(cat(Uint8Array.of(0x51, 0x20), witnessAddress(address, 'sq', 1)));
}
function normalized(tx) {
  if (!tx || tx.version !== 2 || !Array.isArray(tx.inputs) || !tx.inputs.length || tx.inputs.length > 80 || !Array.isArray(tx.outputs) || !tx.outputs.length || tx.outputs.length > 80) throw new Error('Invalid SOQ transaction.');
  const locktime = uint(tx.locktime, 4), seen = new Set();
  const inputs = tx.inputs.map(i => {
    const key = `${i.txid}:${i.vout}`;
    if (seen.has(key)) throw new Error('Duplicate SOQ input.');
    seen.add(key);
    return { outpoint: cat(hex(i.txid, 32).reverse(), uint(i.vout, 4)), sequence: uint(i.sequence, 4), value: amount(i.value), script: script(i.script_pubkey) };
  });
  const outputs = tx.outputs.map(o => ({ value: amount(o.value), script: script(o.script_pubkey) }));
  const sum = rows => rows.reduce((s, r) => s + r.value, 0n);
  if (sum(inputs) > MAX_MONEY || sum(outputs) > sum(inputs)) throw new Error('Invalid SOQ value conservation.');
  return { inputs, outputs, locktime };
}
const outputBytes = outputs => cat(...outputs.map(o => cat(uint(o.value, 8), compact(o.script.length), o.script)));
function baseParts(tx) {
  return [compact(tx.inputs.length), cat(...tx.inputs.map(i => cat(i.outpoint, Uint8Array.of(0), i.sequence))), compact(tx.outputs.length), outputBytes(tx.outputs)];
}
export function soquSignatureHash(transaction, inputIndex) {
  const tx = normalized(transaction);
  if (!Number.isInteger(inputIndex) || inputIndex < 0 || inputIndex >= tx.inputs.length) throw new Error('Invalid SOQ input index.');
  const i = tx.inputs[inputIndex];
  return hash(cat(uint(2, 4), hash(cat(...tx.inputs.map(i => i.outpoint))), hash(cat(...tx.inputs.map(i => i.sequence))), i.outpoint,
    compact(i.script.length), i.script, uint(i.value, 8), i.sequence, hash(outputBytes(tx.outputs)), tx.locktime, uint(1, 4)));
}
export function serializeSoquTransaction(transaction, witness) {
  const tx = normalized(transaction);
  const parts = [uint(2, 4)];
  if (witness !== undefined) {
    if (!Array.isArray(witness) || witness.length !== tx.inputs.length) throw new Error('Incomplete SOQ witness.');
    parts.push(Uint8Array.of(0, 1));
  }
  parts.push(...baseParts(tx));
  if (witness !== undefined) for (let index = 0; index < witness.length; index++) {
    const pair = witness[index];
    if (!Array.isArray(pair) || pair.length !== 2) throw new Error('Invalid SOQ witness stack.');
    const signature = hex(pair[0], 2421), publicKey = hex(pair[1], 1313);
    if (signature[2420] !== 1 || publicKey[0] !== 0 || publicKey[1] === 255) throw new Error('Invalid SOQ witness encoding.');
    const program = sha256(publicKey.subarray(1));
    if (!program.every((b, j) => b === tx.inputs[index].script[j + 2])) throw new Error('SOQ witness key does not own input.');
    parts.push(Uint8Array.of(2), compact(signature.length), signature, compact(publicKey.length), publicKey);
  }
  parts.push(tx.locktime);
  return cat(...parts);
}
export function soquTransactionId(transaction) { return bytesToHex(hash(serializeSoquTransaction(transaction)).reverse()); }
export function soquTransactionVSize(transaction) {
  const base = serializeSoquTransaction(transaction).length;
  return Math.ceil((base * 4 + 2 + transaction.inputs.length * 3741) / 4);
}

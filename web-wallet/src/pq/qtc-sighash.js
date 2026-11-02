// Source-derived QTC P2MR SIGHASH_DEFAULT (all inputs/all outputs), no annex.
// qtcchain/qtc@5adbc7d5c2ac252804fd3c61fce3b9bbc3ad9c24
// src/script/interpreter.cpp SignatureHashSchnorr, SigVersion::P2MR.
// No signer, broadcast or claim of node-tested transaction acceptance.
import { sha256 } from '@noble/hashes/sha256';
import { concatBytes, utf8ToBytes, hexToBytes } from '@noble/hashes/utils';
const cat = (...b) => concatBytes(...b);
function uint(n, size) {
  if (!['bigint', 'number', 'string'].includes(typeof n) || !/^(0|[1-9]\d*)$/.test(String(n)) || (typeof n === 'number' && !Number.isSafeInteger(n))) throw new Error('Invalid QTC integer.');
  let v = BigInt(n); if (v >= 1n << BigInt(size * 8)) throw new Error('QTC integer overflow.');
  const b = new Uint8Array(size); for (let i = 0; i < size; i++) { b[i] = Number(v & 255n); v >>= 8n; } return b;
}
function compact(n) { if (!Number.isInteger(n) || n < 0 || n > 65535) throw new Error('Invalid QTC length.'); return n < 253 ? Uint8Array.of(n) : cat(Uint8Array.of(253),uint(n,2)); }
function hex(s, length) { if (typeof s !== 'string' || !new RegExp(`^[0-9a-f]{${length * 2}}$`).test(s)) throw new Error('Invalid QTC hex.'); return hexToBytes(s); }
function script(s) { const b=hex(s,34); if(b[0]!==0x52 || b[1]!==0x20) throw new Error('QTC requires native P2MR scripts.');return b; }
function value(n) { const b=uint(n,8); if(BigInt(n)>9223372036854775807n) throw new Error('QTC amount exceeds int64.');return b; }
export function qtcTaggedHash(tag, message) { const h=sha256(utf8ToBytes(tag)); return sha256(cat(h,h,message)); }
export function qtcMldsaLeaf(publicKey) {
  if(!(publicKey instanceof Uint8Array)||publicKey.length!==1312) throw new Error('Invalid QTC ML-DSA public key.');
  return cat(Uint8Array.of(0x4d,0x20,0x05),publicKey,Uint8Array.of(0xbb));
}
export function qtcLeafHash(leaf) {
  if(!(leaf instanceof Uint8Array)||leaf.length!==1316||leaf[0]!==0x4d||leaf[1]!==0x20||leaf[2]!==0x05||leaf[1315]!==0xbb) throw new Error('Unsupported QTC leaf.');
  return qtcTaggedHash('P2MRLeaf',cat(Uint8Array.of(0xc2),compact(leaf.length),leaf));
}
export function qtcSignatureHash(transaction,inputIndex,leaf) {
  if(transaction?.version!==2 || !Array.isArray(transaction.inputs)||!transaction.inputs.length||transaction.inputs.length>80||!Array.isArray(transaction.outputs)||!transaction.outputs.length||transaction.outputs.length>80||!Number.isInteger(inputIndex)||inputIndex<0||inputIndex>=transaction.inputs.length) throw new Error('Invalid QTC transaction.');
  const seen=new Set();
  const inputs=transaction.inputs.map(i=>{const key=`${i.txid}:${i.vout}`;if(seen.has(key))throw new Error('Duplicate QTC input.');seen.add(key);return {outpoint:cat(hex(i.txid,32).reverse(),uint(i.vout,4)),value:value(i.value),script:script(i.script_pubkey),sequence:uint(i.sequence,4)};});
  const outputs=transaction.outputs.map(o=>cat(value(o.value),compact(34),script(o.script_pubkey)));
  const preimage=cat(Uint8Array.of(2,0),uint(2,4),uint(transaction.locktime,4),
    sha256(cat(...inputs.map(i=>i.outpoint))),sha256(cat(...inputs.map(i=>i.value))),
    sha256(cat(...inputs.map(i=>cat(compact(i.script.length),i.script)))),sha256(cat(...inputs.map(i=>i.sequence))),
    sha256(cat(...outputs)),Uint8Array.of(2),uint(inputIndex,4),qtcLeafHash(leaf),Uint8Array.of(0),uint(0xffffffff,4));
  return qtcTaggedHash('TapSighash',preimage);
}

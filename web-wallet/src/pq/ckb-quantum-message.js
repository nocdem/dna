// CKB quantum lock message, NOT the default secp256k1 sighash-all message.
// Port of nervosnetwork/quantum-resistant-lock-script@082c0a19ce4e0b2c0b00f7b46f423f59a30afc71
// crates/ckb-fips205-utils/src/ckb_tx_message_all_from_mock_tx.rs.
// Inputs are canonical Molecule bytes, resolved from independently checked cells.
import { blake2b } from '@noble/hashes/blake2b';
import { concatBytes, utf8ToBytes } from '@noble/hashes/utils';
const bytes = b => { if (!(b instanceof Uint8Array) || b.length > 16777216) throw new Error('Invalid CKB bytes.'); return b; };
const equal = (a, b) => a.length === b.length && a.every((v, i) => b[i] === v);
function read32(b, offset) { if (offset + 4 > b.length) throw new Error('Truncated Molecule integer.'); return new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(offset, true); }
function u32(n) { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n, true); return b; }
function table(b, count) {
  bytes(b); const header = 4 + count * 4;
  if (b.length < header || read32(b, 0) !== b.length || read32(b, 4) !== header) throw new Error('Invalid Molecule table.');
  const offsets = Array.from({ length: count }, (_, i) => read32(b, 4 + i * 4)).concat(b.length);
  if (offsets.some((v, i) => v < header || v > b.length || (i && v < offsets[i - 1]))) throw new Error('Invalid Molecule offset.');
  return offsets.slice(0, -1).map((start, i) => b.subarray(start, offsets[i + 1]));
}
function byteVector(b) { if (b.length < 4 || read32(b, 0) !== b.length - 4) throw new Error('Invalid Molecule Bytes.'); }
function optionalBytes(b) { if (b.length) byteVector(b); }
function script(b) {
  const f = table(b, 3);
  if (f[0].length !== 32 || f[1].length !== 1 || ![0, 1, 2, 4].includes(f[1][0])) throw new Error('Invalid CKB script.');
  byteVector(f[2]);
}
function cellOutput(b) { const f = table(b, 3); if (f[0].length !== 8) throw new Error('Invalid CKB capacity.'); script(f[1]); if (f[2].length) script(f[2]); return f[1]; }
export function ckbQuantumMessagePreimage({ rawTransaction, inputs, witnesses, groupIndex } = {}) {
  const raw = table(rawTransaction, 6);
  if (raw[0].length !== 4 || read32(raw[0], 0) !== 0) throw new Error('Unsupported CKB transaction version.');
  if (raw[3].length < 4 || raw[3].length !== 4 + read32(raw[3], 0) * 44) throw new Error('Invalid CKB input vector.');
  const count = read32(raw[3], 0);
  if (!count || !Array.isArray(inputs) || inputs.length !== count || !Number.isInteger(groupIndex) || groupIndex < 0 || groupIndex >= count || !Array.isArray(witnesses)) throw new Error('Invalid CKB resolved inputs.');
  const locks = inputs.map(i => { bytes(i.data); return cellOutput(i.output); });
  const group = locks.map((lock, i) => equal(lock, locks[groupIndex]) ? i : -1).filter(i => i >= 0);
  if (groupIndex !== group[0]) throw new Error('CKB group index must name the first matching input.');
  const first = table(bytes(witnesses[groupIndex]), 3); first.forEach(optionalBytes);
  witnesses.forEach(bytes);
  const chunks = [blake2b(rawTransaction, { dkLen: 32, personalization: utf8ToBytes('ckb-default-hash') })];
  for (const i of inputs) chunks.push(i.output, u32(i.data.length), i.data);
  chunks.push(u32(first[1].length), first[1], u32(first[2].length), first[2]);
  for (const i of group.slice(1)) if (i < witnesses.length) chunks.push(u32(witnesses[i].length), witnesses[i]);
  for (const w of witnesses.slice(count)) chunks.push(u32(w.length), w);
  return concatBytes(...chunks);
}
export function ckbQuantumMessage(args) {
  return blake2b(ckbQuantumMessagePreimage(args), { dkLen: 32, personalization: utf8ToBytes('ckb-sphincs+-msg') });
}

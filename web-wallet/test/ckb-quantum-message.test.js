import test from 'node:test';
import assert from 'node:assert/strict';
import { blake2b } from '@noble/hashes/blake2b';
import { concatBytes, utf8ToBytes, bytesToHex } from '@noble/hashes/utils';
import { ckbQuantumMessage, ckbQuantumMessagePreimage } from '../src/pq/ckb-quantum-message.js';
const cat = (...a) => concatBytes(...a), empty = new Uint8Array();
const u32 = n => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n, true); return b; };
const vec = b => cat(u32(b.length), b);
function table(...f) { let offset = 4 + f.length * 4; const offsets = f.map(b => { const n = offset; offset += b.length; return u32(n); }); return cat(u32(offset), ...offsets, ...f); }
function fixture() {
  const lock = table(new Uint8Array(32).fill(7), Uint8Array.of(1), vec(new Uint8Array(32).fill(8)));
  const output = table(new Uint8Array(8).fill(1), lock, empty);
  return { rawTransaction: table(u32(0),u32(0),u32(0),cat(u32(2),new Uint8Array(88)),u32(4),u32(4)), inputs: [{ output, data: Uint8Array.of(9) }, { output, data: empty }], witnesses: [table(vec(Uint8Array.of(1,2)), vec(Uint8Array.of(3)), empty), Uint8Array.of(4,5), Uint8Array.of(6)], groupIndex: 0 };
}
test('CKB TX_MESSAGE_ALL exact preimage ordering and 32-bit lengths', () => {
  const f = fixture();
  const expected = cat(blake2b(f.rawTransaction,{dkLen:32,personalization:utf8ToBytes('ckb-default-hash')}), f.inputs[0].output,u32(1),Uint8Array.of(9),f.inputs[1].output,u32(0),u32(5),vec(Uint8Array.of(3)),u32(0),u32(2),Uint8Array.of(4,5),u32(1),Uint8Array.of(6));
  assert.deepEqual(ckbQuantumMessagePreimage(f), expected);
  assert.equal(ckbQuantumMessage(f).length,32);
});
test('CKB first lock excluded; cell content, type witness, group and extra witnesses bound', () => {
  const base = fixture(), digest = bytesToHex(ckbQuantumMessage(base));
  const same = fixture(); same.witnesses[0] = table(vec(new Uint8Array(100)),vec(Uint8Array.of(3)),empty);
  assert.equal(bytesToHex(ckbQuantumMessage(same)),digest);
  for(const change of [f=>f.inputs[0].data=Uint8Array.of(10),f=>f.witnesses[0]=table(empty,vec(Uint8Array.of(4)),empty),f=>f.witnesses[1]=Uint8Array.of(7),f=>f.witnesses[2]=Uint8Array.of(8)]) {
    const f=fixture(); change(f); assert.notEqual(bytesToHex(ckbQuantumMessage(f)),digest);
  }
});
test('CKB malformed witnesses, group index and unresolved inputs fail closed', () => {
  for(const change of [f=>f.groupIndex=1,f=>f.inputs.pop(),f=>f.witnesses[0]=new Uint8Array(3),f=>f.inputs[0].output=new Uint8Array(3),f=>f.rawTransaction=new Uint8Array(3)]) {
    const f=fixture(); change(f); assert.throws(()=>ckbQuantumMessage(f));
  }
});

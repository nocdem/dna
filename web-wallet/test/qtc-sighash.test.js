import test from 'node:test';
import assert from 'node:assert/strict';
import { bytesToHex } from '@noble/hashes/utils';
import { qtcMldsaLeaf,qtcLeafHash,qtcSignatureHash } from '../src/pq/qtc-sighash.js';
const fixture=()=>({version:2,locktime:0,inputs:[{txid:Array.from({length:32},(_,i)=>i.toString(16).padStart(2,'0')).join(''),vout:3,value:100000000n,sequence:0xffffffff,script_pubkey:'5220'+'08'.repeat(32)}],outputs:[{value:99000000n,script_pubkey:'5220'+'09'.repeat(32)}]});
const leaf=qtcMldsaLeaf(new Uint8Array(1312).fill(7));
test('QTC epoch-2 default sighash matches independent Python hashlib/struct construction',()=>{
  // Synthetic vector, NOT a node-accepted transaction; node oracle still pending.
  assert.equal(bytesToHex(qtcLeafHash(leaf)),'a2764daa1e1ce7fab8458b5ae6a8cba9fd885b3e25edbe32ed2b43c58fc73a5c');
  assert.equal(bytesToHex(qtcSignatureHash(fixture(),0,leaf)),'b08b14e981713f05a24ba81aa8ac8207b488c2067080e6c412d89a6e1358df22');
});
test('QTC amount, spent script, recipient, sequence and locktime all alter digest',()=>{
  const expected=bytesToHex(qtcSignatureHash(fixture(),0,leaf));
  for(const mutate of [t=>t.inputs[0].value++,t=>t.inputs[0].script_pubkey='5220'+'10'.repeat(32),t=>t.outputs[0].value--,t=>t.inputs[0].sequence--,t=>t.locktime++]) {const t=fixture();mutate(t);assert.notEqual(bytesToHex(qtcSignatureHash(t,0,leaf)),expected);}
});
test('QTC refuses other script profiles, unsafe integers and duplicates',()=>{
  for(const mutate of [t=>t.version=3,t=>t.inputs.push(t.inputs[0]),t=>t.inputs[0].value=Number.MAX_SAFE_INTEGER+1,t=>t.outputs[0].script_pubkey='5120'+'10'.repeat(32)]){const t=fixture();mutate(t);assert.throws(()=>qtcSignatureHash(t,0,leaf));}
  assert.throws(()=>qtcSignatureHash(fixture(),1,leaf));
  assert.throws(()=>qtcSignatureHash(fixture(),0,new Uint8Array(32)));
});

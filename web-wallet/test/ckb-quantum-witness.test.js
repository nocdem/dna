import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {bech32m} from '@scure/base';
import {hexToBytes,concatBytes} from '@noble/hashes/utils';
import {pqAddressFromPublicKeys} from '../src/pq/receive.js';
import {ckbQuantumLock,ckbQuantumWitness,signCkbQuantumWitness} from '../src/pq/ckb-quantum-witness.js';
import {ckbSignMessage} from '../src/pq/ckb-sign.js';
import {ckbQuantumMessage} from '../src/pq/ckb-quantum-message.js';
import {portVectors} from './fixtures/pq-port-vectors.js';
const wasmBytes=readFileSync(new URL('../src/pq/ckb-slh-sign.wasm',import.meta.url));
const cat=(...a)=>concatBytes(...a), empty=()=>new Uint8Array();
const u32=n=>{const b=new Uint8Array(4);new DataView(b.buffer).setUint32(0,n,true);return b;};
function table(...f){let o=4+f.length*4;return cat(u32(o+f.reduce((n,x)=>n+x.length,0)),...f.map(x=>{let n=o;o+=x.length;return u32(n);}),...f);}
const vector=portVectors('slhdsa-nist.bin.gz').find(v=>v.param===5&&(v.flags&1));
const pk=new Uint8Array(vector.pk), seed=new Uint8Array(vector.seed);
const dep=hexToBytes('4598d00df2f3dc8bc40eee38689a539c94f6cc3720b7a2a6746736daa60f500a');
function fixture(){const lock=ckbQuantumLock(pk), outpoint=cat(new Uint8Array(32).fill(4),u32(3)),output=table(new Uint8Array(8).fill(1),lock,empty());return {rawTransaction:table(u32(0),cat(u32(1),dep,u32(0),Uint8Array.of(0)),u32(0),cat(u32(1),new Uint8Array(8),outpoint),u32(4),u32(4)),inputs:[{outpoint,output,data:empty()}]};}
test('CKB lock commitment matches receive address on both networks',()=>{
 for(const n of ['mainnet','testnet']) {const payload=bech32m.fromWords(bech32m.decode(pqAddressFromPublicKeys('ckb',n,pk),1023).words);const lock=ckbQuantumLock(pk,n);assert.deepEqual(lock.subarray(16,48),payload.slice(1,33));assert.equal(lock[48],payload[33]);assert.deepEqual(lock.subarray(53),payload.slice(34));}
});
test('CKB single group signs custom message, binds key and formats exact witness',async()=>{
 const f=fixture(),r=await signCkbQuantumWitness({...f,seed,rnd:new Uint8Array(32).fill(7),wasmBytes});
 assert.equal(r.witnesses[0].length,29881);assert.deepEqual(r.publicKey,pk);
 assert.deepEqual(r.message,ckbQuantumMessage({...f,witnesses:r.witnesses,groupIndex:0}));
 const expected=await ckbSignMessage({seed,message:r.message,rnd:new Uint8Array(32).fill(7),wasmBytes});assert.deepEqual(r.witnesses[0],ckbQuantumWitness(pk,expected.signature));
});
test('CKB refuses wrong dep, mismatched outpoint and nonempty data before signing',async()=>{
 for(const change of [f=>f.rawTransaction[25]^=1,f=>f.inputs[0].outpoint[0]^=1,f=>f.inputs[0].data=Uint8Array.of(1)]) {const f=fixture();change(f);await assert.rejects(signCkbQuantumWitness({...f,seed,wasmBytes}));}
 await assert.rejects(signCkbQuantumWitness({...fixture(),seed,networkId:'testnet',wasmBytes}));
});

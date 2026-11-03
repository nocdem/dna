import test from 'node:test';import assert from 'node:assert/strict';import {readFileSync} from 'node:fs';
import {concatBytes} from '@noble/hashes/utils';import {pqAddressFromPublicKeys} from '../src/pq/receive.js';
import {ckbQuantumLock} from '../src/pq/ckb-quantum-witness.js';
import {prepareCkbQuantumTransaction,signPreparedCkbQuantumTransaction} from '../src/pq/ckb-quantum-transaction.js';
import {portVectors} from './fixtures/pq-port-vectors.js';
const wasmBytes=readFileSync(new URL('../src/pq/ckb-slh-sign.wasm',import.meta.url));const v=portVectors('slhdsa-nist.bin.gz').find(x=>x.param===5&&(x.flags&1));
const seed=new Uint8Array(v.seed),pk=new Uint8Array(v.pk),from=pqAddressFromPublicKeys('ckb','mainnet',pk),to=pqAddressFromPublicKeys('ckb','mainnet',new Uint8Array(64).fill(7));
const cat=(...a)=>concatBytes(...a),u32=n=>{const b=new Uint8Array(4);new DataView(b.buffer).setUint32(0,n,true);return b;},u64=n=>{const b=new Uint8Array(8);new DataView(b.buffer).setBigUint64(0,n,true);return b;};
function table(...f){let o=4+4*f.length;return cat(u32(o+f.reduce((s,x)=>s+x.length,0)),...f.map(x=>{let n=o;o+=x.length;return u32(n);}),...f);}
function request(){return {from,to,inputs:[{outpoint:cat(new Uint8Array(32).fill(2),u32(1)),output:table(u64(30000000000n),ckbQuantumLock(pk),new Uint8Array()),data:new Uint8Array()}],amount:10000000000n,fee:100000n};}
test('CKB transfer assembles exact capacity and review then creates signed molecule',async()=>{const req=request(),p=prepareCkbQuantumTransaction(req);assert.equal(p.change,19999900000n);const r=await signPreparedCkbQuantumTransaction(p,{seed,rnd:new Uint8Array(32).fill(7),wasmBytes});assert.ok(r.transaction.length>30000);assert.equal(new DataView(r.transaction.buffer,r.transaction.byteOffset).getUint32(0,true),r.transaction.length);});
test('CKB transfer rejects wrong recipient/network, dust change, altered review, duplicate or mismatched cell',async()=>{
 for(const change of [r=>r.amount=1n,r=>r.fee=20000000000n-1n,r=>r.networkId='testnet',r=>r.inputs.push(r.inputs[0]),r=>r.inputs[0].data=Uint8Array.of(1)]){const r=request();change(r);assert.throws(()=>prepareCkbQuantumTransaction(r));}
 const p=prepareCkbQuantumTransaction(request());p.amount++;await assert.rejects(signPreparedCkbQuantumTransaction(p,{seed,wasmBytes}),/review/);
});
// CKB Lumos packages/base/tests/serialize.test.ts, Transaction.pack fixture.
test('CKB outer transaction wrapping matches upstream Lumos transaction vector',async()=>{
 const {serializeCkbTransaction}=await import('../src/pq/ckb-quantum-transaction.js');
 const {hexToBytes,bytesToHex}=await import('@noble/hashes/utils');
 const expected='1f0100000c0000000f010000030100001c00000020000000490000006d0000009d000000f40000000000000001000000a98c57135830e1b91345948df6c4b8870828199a786b26f09f7dec4bc27a7300000000000001000000b39d53656421d1532dd995a0924441ca8f43052bc2b7740a0e814a488a8214d6010000001000000000000000a98c57135830e1b91345948df6c4b8870828199a786b26f09f7dec4bc27a73010200000057000000080000004f00000010000000180000004f000000341200000000000037000000100000003000000031000000a98c57135830e1b91345948df6c4b8870828199a786b26f09f7dec4bc27a7302000200000012340f0000000800000003000000abcdef10000000080000000400000031313131';
 const bytes=hexToBytes(expected), raw=bytes.slice(12,271);assert.equal(bytesToHex(serializeCkbTransaction(raw,[hexToBytes('31313131')])),expected);
});
test('CKB fee quote includes 29,792-byte signature and four-byte block overhead',async()=>{
 const {quoteCkbQuantumFee}=await import('../src/pq/ckb-fee.js');const p=prepareCkbQuantumTransaction(request()),q=quoteCkbQuantumFee(p,{feeRate:1000n,cycleCeiling:100000000n,maxFee:100000000n});assert.ok(q.size>30000n);assert.equal(q.fee,q.weight);assert.throws(()=>quoteCkbQuantumFee(p,{feeRate:1000n,cycleCeiling:100000000n,maxFee:1n}),/cap/);assert.throws(()=>quoteCkbQuantumFee(p,{feeRate:1n,cycleCeiling:100000000n,maxFee:100000000n}),/policy/);
});

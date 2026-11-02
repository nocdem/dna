import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createPrivateKey,createPublicKey,verify,generateKeyPairSync} from 'node:crypto';
import {blake3} from '@noble/hashes/blake3';
import {asentumTransferBody,signAsentumTransfer} from '../src/pq/asentum-sign.js';
const supportsMldsa=(()=>{try{generateKeyPairSync('ml-dsa-65');return true;}catch{return false;}})();
const seed=Uint8Array.from({length:32},(_,i)=>i);
const fields={networkId:'testnet',from:'ase1vm0p8p8qh2yughjjcr9jkgrjaltruyfhxc3vl9',to:'ase1qgpqyqszqgpqyqszqgpqyqszqgpqyqszyd8yg3',amount:'123456789012345678901',nonce:'7',gasLimit:'21000',maxFeePerGas:'1'};
// Fixture generated independently with the integrity-pinned official
// @asentum/sdk@0.2.0 AsentumWallet.fromSeed(...).signTransfer(); synthetic only.
const sdkHash='0x0a8f39ddc35eeba51e6afce5718727fe344ebb7a0604da5cd217b9dfd151a979';
test('SSZ signed transfer matches official SDK synthetic known-answer hash',{skip:!supportsMldsa},async()=>{
 const wasmBytes=await readFile(new URL('../src/pq/mldsa65-sign.wasm',import.meta.url));
 const result=await signAsentumTransfer({...fields,seed,wasmBytes});assert.equal(result.txHash,sdkHash);
 const raw=Buffer.from(result.rawTx.slice(2),'hex');assert.equal(raw.length,5409);assert.equal(raw.readUInt32LE(),5265);
 const body=asentumTransferBody(fields);assert.deepEqual(raw.subarray(5265),Buffer.from(body));assert.equal(Buffer.from(body).readUInt32LE(140),144);
 const priv=createPrivateKey({key:Buffer.concat([Buffer.from('3034020100300b060960864801650304031204228020','hex'),seed]),format:'der',type:'pkcs8'});
 const pub=createPublicKey(priv);assert.deepEqual(raw.subarray(4,1956),pub.export({format:'der',type:'spki'}).subarray(-1952));
 assert.equal(verify(null,blake3(body),pub,raw.subarray(1956,5265)),true);
 await assert.rejects(signAsentumTransfer({...fields,seed:new Uint8Array(32),wasmBytes}),/does not match/);
});
test('Asentum rejects invalid transfer values',()=>{
 for(const patch of [{networkId:'mainnet'},{to:'ase1invalid'},{amount:'0'},{nonce:'18446744073709551616'},{gasLimit:'0'},{maxFeePerGas:'0'},{maxPriorityFeePerGas:'2'}]) assert.throws(()=>asentumTransferBody({...fields,...patch}));
});

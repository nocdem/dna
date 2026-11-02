import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync} from 'node:crypto';
const supportsMldsa=(()=>{try{generateKeyPairSync('ml-dsa-65');return true;}catch{return false;}})();
import { splendorTransferBody, SPLENDOR_TRANSFER_CONTEXT } from '../src/pq/splendor-transfer-body.js';
const fields={networkId:'testnet',from:'SQ:'+'01'.repeat(32),to:'SQ:'+'ff'.repeat(32),amount:'123456789012345678901',fee:'1000',nonce:'18446744073709551615',timestamp:'123'};
test('canonical Go struct order and unquoted integers',()=>{
 const body=splendorTransferBody(fields);
 assert.equal(body,`{"version":1,"chain_id":"splendor-quantum-testnet-1","type":1,"alg_id":"ML-DSA-65","from":[${Array(32).fill(1)}],"to":[${Array(32).fill(255)}],"amount":123456789012345678901,"fee":1000,"nonce":18446744073709551615,"timestamp":123}`);
 assert.equal(SPLENDOR_TRANSFER_CONTEXT,'SPLENDOR-QC-TX-v1');
});
test('reject ambiguous or out-of-range values',()=>{
 for (const patch of [{amount:'01'},{fee:'-1'},{nonce:'18446744073709551616'},{timestamp:'9223372036854775808'},{networkId:'devnet'},{to:'SQ:'+'00'.repeat(32)}]) assert.throws(()=>splendorTransferBody({...fields,...patch}));
});

test('offline signed Splendor transfer verifies against OpenSSL and binds key',{skip:!supportsMldsa}, async()=>{
 const {readFile}=await import('node:fs/promises');const {createPrivateKey,createPublicKey,verify}=await import('node:crypto');
 const {sha3_256}=await import('@noble/hashes/sha3');const {bytesToHex}=await import('@noble/hashes/utils');
 const {signSplendorTransfer}=await import('../src/pq/splendor-sign.js');
 const wasmBytes=await readFile(new URL('../src/pq/mldsa65-sign.wasm',import.meta.url)); const seed=Uint8Array.from({length:32},(_,i)=>i);
 const key=createPrivateKey({key:Buffer.concat([Buffer.from('3034020100300b060960864801650304031204228020','hex'),seed]),format:'der',type:'pkcs8'});const pub=createPublicKey(key);
 const pk=pub.export({format:'der',type:'spki'}).subarray(-1952),from='SQ:'+bytesToHex(sha3_256(pk));
 for(const nonce of ['0','5']) {
  const f={...fields,from,nonce}, {wireJson,txHash}=await signSplendorTransfer({...f,seed,wasmBytes}); const wire=JSON.parse(wireJson);
  const digest=sha3_256(new TextEncoder().encode(splendorTransferBody(f)));
  assert.equal(verify(null,digest,{key:pub,context:Buffer.from('SPLENDOR-QC-TX-v1')},Buffer.from(wire.signature,'base64')),true);
  assert.equal(txHash,bytesToHex(sha3_256(new TextEncoder().encode(wireJson))));
  assert.equal(Boolean(wire.public_key),nonce==='0');
 }
 await assert.rejects(signSplendorTransfer({...fields,seed,wasmBytes}),/does not match/);
});
test('signed synthetic envelope matches official Go verified full hash fixture',async()=>{const {readFile}=await import('node:fs/promises');const {signSplendorTransfer}=await import('../src/pq/splendor-sign.js');const seed=Uint8Array.from({length:32},(_,i)=>i),wasmBytes=await readFile(new URL('../src/pq/mldsa65-sign.wasm',import.meta.url));const from='SQ:1800725067e388d837d911fe4f66101cc1961b1bb755030dc574272cfb00013f';const result=await signSplendorTransfer({networkId:'testnet',from,to:'SQ:'+'02'.repeat(32),amount:'123456789012345678901',fee:'1000',nonce:'0',timestamp:'1793606000',seed,wasmBytes});const fixture=(await readFile(new URL('./splendor-reference/synthetic.json',import.meta.url),'utf8')).trim();assert.equal(result.wireJson,fixture);assert.equal(result.txHash,'74d058c39415a477a7533641509992f7617a7deae047e9bbc8f9b75b22473198');});

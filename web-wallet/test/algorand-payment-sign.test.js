import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {signAlgorandPayment} from '../src/pq/algorand-payment-sign.js';
const vector=JSON.parse(await readFile(new URL('./falcon-reference/signed-payment-vector.json',import.meta.url),'utf8'));
const bytes=h=>new Uint8Array(Buffer.from(h,'hex'));
const wasmBytes=await readFile(new URL('../src/pq/algorand-sign.wasm',import.meta.url));
const fields=()=>({seed:bytes(vector.seed),networkId:'testnet',wasmBytes,payment:{...vector.payment,sender:bytes(vector.payment.sender),receiver:bytes(vector.payment.receiver),genesisHash:bytes(vector.payment.genesisHash)}});
test('native Falcon payment matches independent Python MessagePack plus upstream native signed vector',async()=>{
 const tx=await signAlgorandPayment(fields());
 assert.equal(Buffer.from(tx.signedBytes).toString('hex'),vector.signedBytes);
 assert.equal(tx.transactionId,vector.transactionId);assert.equal(tx.from,vector.from);
});
test('wrong network or signer refuses, and public review fields are snapshotted before await',async()=>{
 await assert.rejects(signAlgorandPayment({...fields(),networkId:'mainnet'}),/network identity/);
 const wrong=fields();wrong.payment.sender.fill(1);await assert.rejects(signAlgorandPayment(wrong),/does not match/);
 const mutable=fields(),pending=signAlgorandPayment(mutable);mutable.payment.amount='9000000';mutable.payment.receiver.fill(7);
 assert.equal(Buffer.from((await pending).signedBytes).toString('hex'),vector.signedBytes);
});

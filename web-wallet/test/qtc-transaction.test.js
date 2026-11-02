import test from 'node:test';
import assert from 'node:assert/strict';
import {bytesToHex} from '@noble/hashes/utils';
import {pqAddressFromPublicKeys} from '../src/pq/receive.js';
import {qtcPrimarySpend,qtcScript,serializeQtcTransaction,qtcTransactionId} from '../src/pq/qtc-transaction.js';
const pk=new Uint8Array(1312).fill(7), backup=new Uint8Array(32).fill(8), spend=qtcPrimarySpend(pk,backup);
const tx=()=>({version:2,locktime:0,inputs:[{txid:Array.from({length:32},(_,i)=>i.toString(16).padStart(2,'0')).join(''),vout:3,value:100000000n,sequence:0xffffffff,script_pubkey:spend.scriptPubKey}],outputs:[{value:99000000n,script_pubkey:'5220'+'09'.repeat(32)}]});
test('QTC base serialization and txid match independent Python struct/hashlib fixture',()=>{
 assert.equal(bytesToHex(serializeQtcTransaction(tx())),'02000000011f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201000300000000ffffffff01c09ee60500000000225220090909090909090909090909090909090909090909090909090909090909090900000000');
 assert.equal(qtcTransactionId(tx()),'7b5f9c1b533fbdaa15e58c122696809f64b2aa434b853872d8185ffb681fcc6e');
});
test('QTC witness control commits to actual recovery address, for both networks',()=>{
 for(const network of ['mainnet','testnet']) assert.equal(qtcScript(pqAddressFromPublicKeys('qtc',network,pk,backup),network),spend.scriptPubKey);
 const raw=serializeQtcTransaction(tx(),[{publicKey:pk,backupPublicKey:backup,signature:new Uint8Array(2420)}]);
 assert.equal(bytesToHex(raw.slice(4,6)),'0001'); assert.equal(raw.length,3873);
 assert.throws(()=>serializeQtcTransaction(tx(),[{publicKey:pk,backupPublicKey:new Uint8Array(32),signature:new Uint8Array(2420)}]),/own input/);
});
test('QTC rejects duplicate inputs, unsafe integers, wrong profile, missing witness and inflation',()=>{
 for(const change of [t=>t.inputs.push({...t.inputs[0]}),t=>t.inputs[0].value=Number.MAX_SAFE_INTEGER+1,t=>t.outputs[0].script_pubkey='5120'+'09'.repeat(32),t=>t.outputs[0].value=100000001n,t=>t.outputs[0].value=0n]){const t=tx();change(t);assert.throws(()=>serializeQtcTransaction(t));}
 assert.throws(()=>serializeQtcTransaction(tx(),[]));
});
test('QTC fee quote matches regtest-measured vsize, preserves dust threshold and does not burn change',async()=>{
 const {qtcPaymentVsize,qtcDustThreshold,prepareQtcPayment}=await import('../src/pq/qtc-payment.js');const address=pqAddressFromPublicKeys('qtc','mainnet',pk,backup);assert.equal(qtcPaymentVsize(tx()),3873n);assert.equal(qtcDustThreshold(),11583n);
 const base={from:address,to:address,amount:100000000n,feeRate:1n,maxFee:100000000n,inputs:[{...tx().inputs[0],value:200000000n}]};const p=prepareQtcPayment(base);assert.equal(p.fee,qtcPaymentVsize(p.transaction));assert.ok(p.change>=11583n);assert.throws(()=>prepareQtcPayment({...base,amount:1n}),/dust/);assert.throws(()=>prepareQtcPayment({...base,maxFee:1n}),/fee/);assert.throws(()=>prepareQtcPayment({...base,inputs:[{...base.inputs[0],value:100005000n}]}),/dust/);
});

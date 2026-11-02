import { test } from 'node:test';
import assert from 'node:assert/strict';
import { encodeAlgorandPayment, quoteAlgorandFalconFee, checkAlgorandSpend } from '../src/pq/algorand-send.js';
const fields = { sender:new Uint8Array(32).fill(1), receiver:new Uint8Array(32).fill(2), amount:1000000, fee:3000, firstValid:123, lastValid:133, genesisHash:Uint8Array.from({length:32},(_,i)=>i), genesisId:'testnet-v1.0' };
test('payment bytes match independent Python msgpack encoding',()=> {
 assert.equal(Buffer.from(encodeAlgorandPayment(fields)).toString('hex'), '89a3616d74ce000f4240a3666565cd0bb8a266767ba367656eac746573746e65742d76312e30a26768c420000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fa26c76cc85a3726376c4200202020202020202020202020202020202020202020202020202020202020202a3736e64c4200101010101010101010101010101010101010101010101010101010101010101a474797065a3706179');
});
test('reject malformed or unsafe payment inputs',()=> {
 for (const bad of [{amount:0},{amount:Number.MAX_SAFE_INTEGER+1},{fee:-1},{firstValid:0},{lastValid:1124},{receiver:new Uint8Array(31)},{genesisId:''}]) assert.throws(()=>encodeAlgorandPayment({...fields,...bad}));
});
test('Falcon fee floor, congestion and cap',()=> {
 assert.equal(quoteAlgorandFalconFee({minFee:1000,feePerByte:0,signedSize:3500,maxFee:3000}),3000n);
 assert.equal(quoteAlgorandFalconFee({minFee:1000,feePerByte:2,signedSize:3500,maxFee:7000}),7000n);
 assert.throws(()=>quoteAlgorandFalconFee({minFee:1000,feePerByte:2,signedSize:3500,maxFee:6999}));
});
test('spend preserves node-reported minimum balance',()=> {
 assert.equal(checkAlgorandSpend({balance:1103000,minimumBalance:100000,amount:1000000,fee:3000}),true);
 assert.throws(()=>checkAlgorandSpend({balance:1102999,minimumBalance:100000,amount:1000000,fee:3000}));
});

test('Falcon payment preimage is raw TX domain plus canonical transaction, not a digest', async () => {
 const { algorandFalconPaymentPreimage } = await import('../src/pq/algorand-send.js');
 const { createHash } = await import('node:crypto');
 const transaction = encodeAlgorandPayment(fields);
 const preimage = algorandFalconPaymentPreimage(fields);
 assert.deepEqual(preimage, Uint8Array.from([0x54, 0x58, ...transaction]));
 assert.notDeepEqual(preimage, new Uint8Array(createHash('sha512-256').update(preimage).digest()));
 assert.throws(() => algorandFalconPaymentPreimage({...fields, amount: -1}));
});

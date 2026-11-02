import test from 'node:test';import assert from 'node:assert/strict';import {readFile} from 'node:fs/promises';
import {prepareAlgorandPayment,ALGORAND_FALCON_PROTOCOL} from '../src/pq/algorand-prepare.js';
import {algorandNetwork} from '../src/pq/algorand.js';
const vector=JSON.parse(await readFile(new URL('./falcon-reference/signed-payment-vector.json',import.meta.url),'utf8'));
const from=vector.from,params={'consensus-version':ALGORAND_FALCON_PROTOCOL,'genesis-hash':algorandNetwork('mainnet').genesisHash,'genesis-id':'mainnet-v1.0','last-round':100,'min-fee':1000,fee:0};
const account={address:from,round:100,amount:'10000000','min-balance':100000};
function args(p={},a={}){let count=0;return {from,to:from,amountAtoms:'1000000',maxFeeAtoms:'10000',fetcher:async()=>new Response(JSON.stringify(++count===1?{...params,...p}:{...account,...a}))};}
test('read-only Falcon preparation pins network/protocol, uses exact amounts and preserves minimum',async()=>{
 const result=await prepareAlgorandPayment(args());assert.equal(result.feeAtoms,'3000');assert.equal(result.payment.lastValid,'200');assert.equal(result.payment.amount,'1000000');
 await assert.rejects(prepareAlgorandPayment(args({}, {amount:'1102999'})),/Insufficient/);
 await assert.rejects(prepareAlgorandPayment({...args({fee:3}),maxFeeAtoms:'10000'}),/Fee exceeds/);
});
test('unverified protocol, wrong genesis, rekeyed/stale/malformed account and abort fail closed',async()=>{
 for(const p of [{'consensus-version':'future'},{'genesis-hash':'bad'},{'genesis-id':'testnet-v1.0'},{'last-round':-1}])await assert.rejects(prepareAlgorandPayment(args(p)));
 for(const a of [{'auth-addr':from},{round:99},{round:201},{address:'other'},{amount:'1e9'},{'min-balance':-1}])await assert.rejects(prepareAlgorandPayment(args({},a)));
 await assert.rejects(prepareAlgorandPayment({...args(),signal:AbortSignal.abort()}));
 await assert.rejects(prepareAlgorandPayment({...args(),to:'bad'}));
});

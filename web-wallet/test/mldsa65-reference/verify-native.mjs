// Independent OpenSSL-backed oracle for native bridge. Pass compiled harness path.
// This fixture uses a public, synthetic seed. Never use it for funds.
import { spawnSync } from 'node:child_process';
import { createPrivateKey, createPublicKey, verify } from 'node:crypto';
import assert from 'node:assert/strict';
const exe=process.argv[2]; if(!exe) throw new Error('Pass native harness executable.');
const seed=Buffer.from(Array.from({length:32},(_,i)=>i));
// RFC 9881 seed-only PKCS#8 encoding, id-ml-dsa-65.
const privateKey=createPrivateKey({key:Buffer.concat([Buffer.from('3034020100300b060960864801650304031204228020','hex'),seed]),format:'der',type:'pkcs8'});
const expectedPk=createPublicKey(privateKey).export({format:'der',type:'spki'}).subarray(-1952);
const message=Buffer.from('test message');
for (const mode of [0,1]) {
 const run=()=>{const r=spawnSync(exe,[String(mode)],{encoding:null});assert.equal(r.status,0);assert.equal(r.stdout.length,5261);return r.stdout;};
 const out=run();assert.deepEqual(out,run()); assert.deepEqual(out.subarray(0,1952),expectedPk);
 const context=Buffer.from(mode?'SPLENDOR-QC-TX-v1':'');
 const other=Buffer.from(mode?'':'SPLENDOR-QC-TX-v1');
 const pub=createPublicKey(privateKey); const signature=out.subarray(1952);
 assert.equal(verify(null,message,{key:pub,context},signature),true);
 assert.equal(verify(null,message,{key:pub,context:other},signature),false);
 assert.equal(verify(null,Buffer.from('test messagf'),{key:pub,context},signature),false);
}
console.log('Native ML-DSA-65: synthetic deterministic seed, OpenSSL key agreement and empty/Splendor context verification passed.');

// Test oracle for the exact @noble/post-quantum 0.2.1 used by Asentum SDK 0.2.0.
import { createRequire } from 'node:module';
import assert from 'node:assert/strict';
const require = createRequire(process.argv[2] + '/package.json');
const { ml_dsa65 } = require('@noble/post-quantum/ml-dsa');
const rows = [];
for (const [i, n] of [0, 32, 64, 1024].entries()) {
  const seed = Uint8Array.from({length:32}, (_,j) => i*7+j);
  const msg = Uint8Array.from({length:n}, (_,j) => i+j*3);
  const {publicKey:pk, secretKey:sk} = ml_dsa65.keygen(seed);
  const sig = ml_dsa65.sign(sk,msg);
  assert(ml_dsa65.verify(pk,msg,sig));
  const fields = [seed,Buffer.concat([Buffer.from([0,0]),msg]),new Uint8Array(),pk,sk,sig,new Uint8Array(32),msg];
  rows.push({scheme:5,param:65,id:6000+i,flags:23,fields:fields.map(x=>Buffer.from(x).toString('hex'))});
}
process.stdout.write(JSON.stringify(rows));

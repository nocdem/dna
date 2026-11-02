// Standalone source-oracle check: requires local C compiler. No network or secrets.
import {mkdtempSync,writeFileSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';import {join,dirname} from 'node:path';import {fileURLToPath} from 'node:url';import {spawnSync} from 'node:child_process';import assert from 'node:assert/strict';
import {blake2b} from '@noble/hashes/blake2b';import {utf8ToBytes,concatBytes,bytesToHex} from '@noble/hashes/utils';
import {pqAddressFromPublicKeys} from '../../src/pq/receive.js';import {ckbQuantumLock} from '../../src/pq/ckb-quantum-witness.js';import {prepareCkbQuantumTransaction} from '../../src/pq/ckb-quantum-transaction.js';import {ckbQuantumMessagePreimage,ckbQuantumMessage} from '../../src/pq/ckb-quantum-message.js';
const dir=dirname(fileURLToPath(import.meta.url)),temp=mkdtempSync(join(tmpdir(),'ckb-source-oracle-'));
const cat=(...a)=>concatBytes(...a),u32=n=>{const b=new Uint8Array(4);new DataView(b.buffer).setUint32(0,n,true);return b;},u64=n=>{const b=new Uint8Array(8);new DataView(b.buffer).setBigUint64(0,n,true);return b;};function table(...f){let o=4+4*f.length;return cat(u32(o+f.reduce((s,x)=>s+x.length,0)),...f.map(x=>{const n=o;o+=x.length;return u32(n);}),...f);}
try {
 const pk=new Uint8Array(64).fill(7),addr=pqAddressFromPublicKeys('ckb','mainnet',pk),input={outpoint:cat(new Uint8Array(32).fill(2),u32(1)),output:table(u64(30000000000n),ckbQuantumLock(pk),new Uint8Array()),data:new Uint8Array()};
 const p=prepareCkbQuantumTransaction({from:addr,to:addr,inputs:[input],amount:10000000000n,fee:100000n}),witness=table(new Uint8Array(),new Uint8Array(),new Uint8Array()),args={...p,witnesses:[witness],groupIndex:0};
 const txhash=blake2b(p.rawTransaction,{dkLen:32,personalization:utf8ToBytes('ckb-default-hash')});assert.equal(bytesToHex(txhash),'96650e8c4cdfdd0881af20e31edac7bb9778ad7da3695808ca2d7d688bfb5207');
 writeFileSync(join(temp,'hash'),txhash);writeFileSync(join(temp,'cell'),input.output);
 let r=spawnSync(process.env.CC||'cc',['-O2','-I',dir,'-o',join(temp,'oracle'),join(dir,'oracle.c')]);if(r.status!==0)throw Error('C oracle compile failed: '+r.stderr);
 r=spawnSync(join(temp,'oracle'),[join(temp,'hash'),join(temp,'cell')]);if(r.status!==0)throw Error('C source oracle failed: '+r.stderr);
 assert.deepEqual(r.stdout,Buffer.from(ckbQuantumMessagePreimage(args)));assert.equal(bytesToHex(ckbQuantumMessage(args)),'4d514e36608219830876e8f6b4515a1e3d58e96e80e10ebe5849f5a15ffcd7c7');
 console.log('PASS upstream C TX_MESSAGE_ALL source preimage and JS digest fixture; no CKB-VM execution.');
} finally {rmSync(temp,{recursive:true,force:true});}

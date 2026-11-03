// Local, isolated QTC regtest integration oracle. No public network, wallet,
// user keys or transaction broadcast. Requires verified v0.2.5 release tools.
// QTC_BIN=/path/to/extracted/bin node test/qtc-reference/run-regtest.mjs
import {readFileSync,mkdtempSync,mkdirSync,rmSync} from 'node:fs';import {tmpdir} from 'node:os';import {join} from 'node:path';import {spawn,spawnSync} from 'node:child_process';import {createHash} from 'node:crypto';import assert from 'node:assert/strict';
import {bech32m} from '@scure/base';import {hexToBytes} from '@noble/hashes/utils';import {qtcScript} from '../../src/pq/qtc-transaction.js';import {signQtcPayment} from '../../src/pq/qtc-payment-sign.js';
const bin=process.env.QTC_BIN;if(!bin)throw Error('Set QTC_BIN to the verified v0.2.5 release bin directory.');const daemon=join(bin,'qtcd'),cli=join(bin,'qtc-cli'),sha=p=>createHash('sha256').update(readFileSync(p)).digest('hex');
if(sha(daemon)!=='89964d0424dc744ae2aa7fe0b9404ca02f1ec018c9ddc7dae8f7b8d27b371802'||sha(cli)!=='bbc8234c278787e09cca16115e31265549a2162c574a554dfb5a9758d0622c38')throw Error('Unexpected QTC release binary.');
const dir=mkdtempSync(join(tmpdir(),'qtc-regtest-oracle-')),walletdir=join(dir,'wallets');mkdirSync(walletdir);const port=32000+Math.floor(Math.random()*20000);
const node=spawn(daemon,[`-datadir=${dir}`,`-walletdir=${walletdir}`,'-regtest','-maxconnections=0','-listen=0','-dnsseed=0','-discover=0','-disablewallet=1','-server=1',`-rpcport=${port}`],{stdio:'ignore'});
function call(...args){const r=spawnSync(cli,[`-datadir=${dir}`,'-regtest',`-rpcport=${port}`,'-rpcwait','-rpcwaittimeout=30',...args],{encoding:'utf8',maxBuffer:5*1024*1024,timeout:120000});if(r.status!==0)throw Error('Regtest RPC failed: '+r.stderr);return JSON.parse(r.stdout);}
try{
 assert.equal(call('getblockcount'),0);assert.equal(call('getconnectioncount'),0);
 const v=JSON.parse(readFileSync(new URL('../fixtures/pq-receive.json',import.meta.url))).vectors[0],root=hexToBytes(v.roots.qtc),networkId='mainnet',from=v.addresses.qtc[networkId],script=qtcScript(from,networkId),regtest=bech32m.encode('qtcrt',bech32m.decode(from).words);
 const blocks=call('generatetoaddress','101',regtest),block=call('getblock',blocks[0],'2'),coin=block.tx[0],out=coin.vout.find(x=>x.scriptPubKey.hex===script);assert.ok(out);assert.equal(out.value,50);const value=5000000000n;
 const transaction={version:2,locktime:0,inputs:[{txid:coin.txid,vout:out.n,value,script_pubkey:script,sequence:0xffffffff}],outputs:[{value:value-1000000n,script_pubkey:script}]};const signed=await signQtcPayment({transaction,from,networkId,root,rnd:new Uint8Array(32).fill(7),signWasmBytes:readFileSync(new URL('../../src/pq/qtc-mldsa44-sign.wasm',import.meta.url)),receiveWasmBytes:readFileSync(new URL('../../src/pq/receive-keygen.wasm',import.meta.url))});
 function accept(raw){return call('testmempoolaccept',JSON.stringify([raw]))[0];}const valid=accept(signed.raw);assert.equal(valid.allowed,true);assert.equal(valid.txid,signed.txid);assert.equal(valid.vsize,3873);
 for(const [name,index] of [['signature',100],['output',49]]){const b=Buffer.from(signed.raw,'hex');b[index]^=1;const bad=accept(b.toString('hex'));assert.equal(bad.allowed,false);assert.match(bad['reject-reason'],/Invalid ML-DSA signature/);console.log(name+' mutation rejected: '+bad['reject-reason']);}
 // The structured explorer cannot change the amount actually committed by
 // the node's AccessCoin-backed sighash: a false claimed amount invalidates
 // the signature rather than increasing the real fee.
 const forgedValue=structuredClone(transaction);forgedValue.inputs[0].value=value-1n;
 const badValueSigned=await signQtcPayment({transaction:forgedValue,from,networkId,root,rnd:new Uint8Array(32).fill(7),signWasmBytes:readFileSync(new URL('../../src/pq/qtc-mldsa44-sign.wasm',import.meta.url)),receiveWasmBytes:readFileSync(new URL('../../src/pq/receive-keygen.wasm',import.meta.url))});
 const badValue=accept(badValueSigned.raw);assert.equal(badValue.allowed,false);assert.match(badValue['reject-reason'],/Invalid ML-DSA signature/);console.log('false structured input amount rejected: '+badValue['reject-reason']);
 // A different locally-owned tree cannot spend this actual previous output
 // even if the structured index claims that it belongs to that tree.
 const other=JSON.parse(readFileSync(new URL('../fixtures/pq-receive.json',import.meta.url))).vectors[1],otherFrom=other.addresses.qtc[networkId],otherRoot=hexToBytes(other.roots.qtc),otherScript=qtcScript(otherFrom,networkId),forgedScript=structuredClone(transaction);forgedScript.inputs[0].script_pubkey=otherScript;forgedScript.outputs[0].script_pubkey=otherScript;
 try{const badScriptSigned=await signQtcPayment({transaction:forgedScript,from:otherFrom,networkId,root:otherRoot,rnd:new Uint8Array(32).fill(7),signWasmBytes:readFileSync(new URL('../../src/pq/qtc-mldsa44-sign.wasm',import.meta.url)),receiveWasmBytes:readFileSync(new URL('../../src/pq/receive-keygen.wasm',import.meta.url))});const badScript=accept(badScriptSigned.raw);assert.equal(badScript.allowed,false);assert.equal(typeof badScript['reject-reason'],'string');console.log('false structured owner script rejected: '+badScript['reject-reason']);}finally{otherRoot.fill(0);}
 assert.equal(call('getconnectioncount'),0);console.log('PASS QTC v0.2.5 isolated regtest testmempoolaccept; 3873 vbytes; no transaction submitted.');root.fill(0);
}finally{node.kill('SIGTERM');await new Promise(resolve=>{if(node.exitCode!==null||node.signalCode!==null)return resolve();node.once('exit',resolve);setTimeout(resolve,5000).unref();});rmSync(dir,{recursive:true,force:true});}

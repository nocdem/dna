// Offline QTC transparent P2MR transaction serialization, default ML-DSA leaf.
// Source: qtcchain/qtc@5adbc7d5c2ac252804fd3c61fce3b9bbc3ad9c24,
// test/functional/feature_p2mr_end_to_end.py and src/script/sign.cpp.
// This codec neither verifies signatures nor establishes spendability and is
// intentionally not connected to the send gate or a broadcaster.
import { sha256 } from '@noble/hashes/sha256';
import { concatBytes, bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { witnessAddress } from './soqucoin.js';
import { qtcMldsaLeaf, qtcLeafHash, qtcTaggedHash } from './qtc-sighash.js';
const cat = (...x) => concatBytes(...x);
const MAX = 21000000n * 100000000n;
const hash256 = b => sha256(sha256(b));
function uint(n, size) {
  if (!['bigint','number','string'].includes(typeof n) || (typeof n === 'number' && !Number.isSafeInteger(n)) || !/^(0|[1-9]\d*)$/.test(String(n))) throw Error('Invalid QTC integer.');
  let v = BigInt(n); if (v >= 1n << BigInt(size * 8)) throw Error('QTC integer overflow.');
  const b = new Uint8Array(size); for (let i = 0; i < size; i++) { b[i] = Number(v & 255n); v >>= 8n; } return b;
}
function compact(n) { if (!Number.isSafeInteger(n) || n < 0 || n > 65535) throw Error('Invalid QTC length.'); return n < 253 ? Uint8Array.of(n) : cat(Uint8Array.of(253), uint(n,2)); }
function hex(s, n) { if (typeof s !== 'string' || !new RegExp(`^[0-9a-f]{${n*2}}$`).test(s)) throw Error('Invalid QTC hex.'); return hexToBytes(s); }
function amount(v) { uint(v,8); const n=BigInt(v); if (n <= 0n || n > MAX) throw Error('Invalid QTC amount.'); return n; }
function script(s) { const b = hex(s,34); if (b[0]!==0x52 || b[1]!==0x20) throw Error('Expected native QTC P2MR script.'); return b; }
export function qtcScript(address, networkId = 'mainnet') {
  if (!['mainnet','testnet'].includes(networkId)) throw Error('Unsupported QTC network.');
  return bytesToHex(cat(Uint8Array.of(0x52,0x20),witnessAddress(address,networkId==='mainnet'?'qtc':'tqtc',2)));
}
// The recovery contract commits to a 2-leaf tree, primary ML-DSA-44 and
// backup SLH-DSA-SHAKE-128s. Control is leaf-version + sibling leaf hash.
export function qtcPrimarySpend(publicKey, backupPublicKey) {
  if (!(backupPublicKey instanceof Uint8Array) || backupPublicKey.length!==32) throw Error('Invalid QTC backup public key.');
  const leaf = qtcMldsaLeaf(publicKey), primary = qtcLeafHash(leaf);
  const backupScript = cat(Uint8Array.of(0x20),backupPublicKey,Uint8Array.of(0xbc));
  const backup = qtcTaggedHash('P2MRLeaf',cat(Uint8Array.of(0xc2,0x22),backupScript));
  let cmp=0; for(let i=0;i<32 && cmp===0;i++) cmp=primary[i]-backup[i];
  const root=qtcTaggedHash('P2MRBranch',cmp<0?cat(primary,backup):cat(backup,primary));
  return {scriptPubKey:bytesToHex(cat(Uint8Array.of(0x52,0x20),root)), leaf, control:cat(Uint8Array.of(0xc2),backup)};
}
function normalized(transaction) {
  if (!transaction || transaction.version!==2 || !Array.isArray(transaction.inputs) || !transaction.inputs.length || transaction.inputs.length>80 || !Array.isArray(transaction.outputs) || !transaction.outputs.length || transaction.outputs.length>80) throw Error('Invalid QTC transaction.');
  const locktime=uint(transaction.locktime,4), seen=new Set();
  const inputs=transaction.inputs.map(i=>{const txid=hex(i.txid,32), vout=uint(i.vout,4), sequence=uint(i.sequence,4), value=amount(i.value), spk=script(i.script_pubkey), key=`${i.txid}:${BigInt(i.vout)}`; if(seen.has(key)) throw Error('Duplicate QTC input.');seen.add(key);return {txid,vout,sequence,value,script:spk};});
  const outputs=transaction.outputs.map(o=>({value:amount(o.value),script:script(o.script_pubkey)}));
  const sum=a=>a.reduce((v,i)=>v+i.value,0n);if(sum(inputs)>MAX || sum(outputs)>sum(inputs)) throw Error('Invalid QTC value conservation.');
  return {inputs,outputs,locktime};
}
export function serializeQtcTransaction(transaction, witness) {
  const tx=normalized(transaction), parts=[uint(2,4)];
  if (witness!==undefined) {if (!Array.isArray(witness)||witness.length!==tx.inputs.length) throw Error('Incomplete QTC witness.');parts.push(Uint8Array.of(0,1));}
  parts.push(compact(tx.inputs.length),cat(...tx.inputs.map(i=>cat(i.txid.slice().reverse(),i.vout,Uint8Array.of(0),i.sequence))),compact(tx.outputs.length),cat(...tx.outputs.map(o=>cat(uint(o.value,8),compact(o.script.length),o.script))));
  if(witness!==undefined) for(let i=0;i<witness.length;i++) {
    const w=witness[i]; if(!w || !(w.signature instanceof Uint8Array) || w.signature.length!==2420 || !(w.publicKey instanceof Uint8Array) || !(w.backupPublicKey instanceof Uint8Array)) throw Error('Invalid QTC witness.');
    const spend=qtcPrimarySpend(w.publicKey,w.backupPublicKey);if(spend.scriptPubKey!==bytesToHex(tx.inputs[i].script)) throw Error('QTC witness does not own input.');
    parts.push(Uint8Array.of(3),compact(w.signature.length),w.signature,compact(spend.leaf.length),spend.leaf,compact(spend.control.length),spend.control);
  }
  return cat(...parts,tx.locktime);
}
export function qtcTransactionId(transaction) { return bytesToHex(hash256(serializeQtcTransaction(transaction)).reverse()); }

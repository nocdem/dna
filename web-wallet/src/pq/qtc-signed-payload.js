// Strict decoder for the exact native v2 P2MR format emitted by qtc-transaction.js.
// Used only for authenticated same-bytes recovery, never transaction editing.
import {sha256} from '@noble/hashes/sha256';
import {bytesToHex,hexToBytes,concatBytes} from '@noble/hashes/utils';
import {qtcScript} from './qtc-transaction.js';
import {qtcLeafHash,qtcTaggedHash} from './qtc-sighash.js';
export function validateQtcSignedPayload(row){
 const payload=row?.signedPayload;
 if(!payload||payload.encoding!=='hex'||typeof payload.data!=='string'||payload.data.length>120000||!/^([0-9a-f]{2})+$/.test(payload.data))throw Error('Invalid QTC signed recovery payload.');
 const raw=hexToBytes(payload.data);let at=0;
 const take=n=>{if(!Number.isSafeInteger(n)||n<0||at+n>raw.length)throw Error('Truncated QTC recovery payload.');const out=raw.subarray(at,at+n);at+=n;return out;};
 const uint=n=>{let value=0n;const bytes=take(n);for(let i=n-1;i>=0;i--)value=(value<<8n)|BigInt(bytes[i]);return value;};
 const compact=()=>{const first=Number(uint(1));if(first<253)return first;if(first!==253)throw Error('Oversized QTC compact value.');const value=Number(uint(2));if(value<253)throw Error('Noncanonical QTC compact value.');return value;};
 if(uint(4)!==2n||uint(1)!==0n||uint(1)!==1n)throw Error('Unsupported QTC recovery transaction format.');
 const count=compact();if(count<1||count>80)throw Error('Invalid QTC recovery input count.');
 const inputs=[];for(let i=0;i<count;i++){const txid=bytesToHex(Uint8Array.from(take(32)).reverse()),vout=Number(uint(4));if(compact()!==0||uint(4)!==0xffffffffn)throw Error('Unsupported QTC input script/sequence.');inputs.push(`${txid}:${vout}`);}
 if(new Set(inputs).size!==inputs.length)throw Error('Duplicate QTC recovery outpoint.');
 const outputsCount=compact();if(outputsCount<1||outputsCount>2)throw Error('Unsupported QTC recovery output count.');
 const outputs=[];for(let i=0;i<outputsCount;i++){const value=uint(8);if(value<11583n||value>2100000000000000n||compact()!==34)throw Error('Invalid QTC recovery output.');outputs.push({value,script:bytesToHex(take(34))});}
 const bodyEnd=at,ownScript=qtcScript(row.address,row.networkId);
 for(let i=0;i<count;i++){
  if(compact()!==3||compact()!==2420)throw Error('Invalid QTC recovery witness.');take(2420);
  if(compact()!==1316)throw Error('Invalid QTC recovery leaf.');const leaf=take(1316),primary=qtcLeafHash(leaf);
  if(compact()!==33||uint(1)!==0xc2n)throw Error('Invalid QTC recovery control.');const sibling=take(32);
  let cmp=0;for(let j=0;j<32&&cmp===0;j++)cmp=primary[j]-sibling[j];
  const root=qtcTaggedHash('P2MRBranch',cmp<0?concatBytes(primary,sibling):concatBytes(sibling,primary));
  if('5220'+bytesToHex(root)!==ownScript)throw Error('QTC recovery signer does not match account.');
 }
 const lockStart=at;if(uint(4)!==0n||at!==raw.length)throw Error('Invalid QTC recovery locktime/trailing data.');
 const stripped=concatBytes(raw.subarray(0,4),raw.subarray(6,bodyEnd),raw.subarray(lockStart));
 const txid=bytesToHex(sha256(sha256(stripped)).reverse());
 if(txid!==row.hash||JSON.stringify(inputs)!==JSON.stringify(row.inputs)||outputs[0].value!==BigInt(row.amountAtoms)||outputs[0].script!==qtcScript(row.to,row.networkId)||(outputs[1]&&outputs[1].script!==ownScript))throw Error('QTC recovery payload does not match its authenticated review.');
 return Object.freeze({hash:txid,raw:payload.data,vsize:BigInt(raw.length)});
}

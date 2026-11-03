// Strict decoder for the exact native v2 format emitted by soqu-transaction.js.
// Used only for authenticated same-bytes recovery, never transaction editing.
import {sha256} from '@noble/hashes/sha256';
import {bytesToHex,hexToBytes,concatBytes} from '@noble/hashes/utils';
import {soquScript} from './soqu-transaction.js';
function coinAtoms(value){if(typeof value!=='string'||!/^(0|[1-9]\d{0,10})(\.\d{1,8})?$/.test(value))throw Error('Invalid SOQ saved amount.');const [a,b='']=value.split('.');return BigInt(a)*100000000n+BigInt(b.padEnd(8,'0'));}
export function validateSoquSignedPayload(row){
 const payload=row?.signedPayload;
 if(!payload||payload.encoding!=='hex'||typeof payload.data!=='string'||payload.data.length>120000||!/^([0-9a-f]{2})+$/.test(payload.data))throw Error('Invalid SOQ signed recovery payload.');
 const raw=hexToBytes(payload.data);let at=0;
 const take=n=>{if(!Number.isSafeInteger(n)||n<0||at+n>raw.length)throw Error('Truncated SOQ recovery payload.');const out=raw.subarray(at,at+n);at+=n;return out;};
 const uint=n=>{let value=0n;const bytes=take(n);for(let i=n-1;i>=0;i--)value=(value<<8n)|BigInt(bytes[i]);return value;};
 const compact=()=>{const first=Number(uint(1));if(first<253)return first;if(first!==253)throw Error('Oversized SOQ compact value.');const value=Number(uint(2));if(value<253)throw Error('Noncanonical SOQ compact value.');return value;};
 if(uint(4)!==2n||uint(1)!==0n||uint(1)!==1n)throw Error('Unsupported SOQ recovery transaction format.');
 const count=compact();if(count<1||count>80)throw Error('Invalid SOQ recovery input count.');
 const inputs=[];for(let i=0;i<count;i++){const txid=bytesToHex(Uint8Array.from(take(32)).reverse()),vout=Number(uint(4));if(compact()!==0||uint(4)!==0xffffffffn)throw Error('Unsupported SOQ input script/sequence.');inputs.push({txid,vout});}
 if(new Set(inputs.map(i=>`${i.txid}:${i.vout}`)).size!==inputs.length)throw Error('Duplicate SOQ recovery outpoint.');
 const outputsCount=compact();if(outputsCount<1||outputsCount>2)throw Error('Unsupported SOQ recovery output count.');
 const outputs=[];for(let i=0;i<outputsCount;i++){const value=uint(8);if(value<279500n||value>2000000000000000000n||compact()!==34)throw Error('Invalid SOQ recovery output.');outputs.push({value,script:bytesToHex(take(34))});}
 const bodyEnd=at,ownScript=soquScript(row.address);
 for(let i=0;i<count;i++){
  if(compact()!==2||compact()!==2421)throw Error('Invalid SOQ recovery witness.');const signature=take(2421);if(signature[2420]!==1||compact()!==1313)throw Error('Invalid SOQ recovery signature type.');
  const publicKey=take(1313);if(publicKey[0]!==0||'5120'+bytesToHex(sha256(publicKey.subarray(1)))!==ownScript)throw Error('SOQ recovery signer does not match account.');
 }
 const lockStart=at;if(uint(4)!==0n||at!==raw.length)throw Error('Invalid SOQ recovery locktime/trailing data.');
 const stripped=concatBytes(raw.subarray(0,4),raw.subarray(6,bodyEnd),raw.subarray(lockStart));
 const txid=bytesToHex(sha256(sha256(stripped)).reverse());
 if(txid!==row.hash||JSON.stringify(inputs)!==JSON.stringify(row.inputs)||outputs[0].value!==coinAtoms(row.amount)||outputs[0].script!==soquScript(row.to)||(outputs[1]&&outputs[1].script!==ownScript))throw Error('SOQ recovery payload does not match its authenticated review.');
 return Object.freeze({hash:txid,raw:payload.data});
}

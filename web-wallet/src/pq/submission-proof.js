// Narrow cancellation journal. Seal while unlocked; a known-zero-POST outcome
// may later write ONLY this opaque ciphertext, without retaining or consulting
// any key. It never overwrites the activity bucket. On the next ordinary unlock
// the authenticated proof is matched to a unique submission attempt, not merely
// a txid (identical transaction bytes can be reviewed again).
import {ACTIVITY_KEY} from '../vault.js';
import {serializeActivity,parseActivity,ACTIVITY_MAX_ROWS} from '../activity-storage.js';
const supported=row=>row&&['soqucoin','splendor','asentum','xion','qtc','ckb','tidecoin','ixios'].includes(row.chain)&&typeof row.submissionId==='string'&&/^[0-9a-f]{32}$/.test(row.submissionId);
function identity(row){return JSON.stringify([row.chain,row.address,row.to,row.hash,row.symbol,row.amount,row.submissionId,row.networkId,row.nonce,row.gasPrice,row.amountAtoms,row.feeAtoms,row.gasLimit,row.maxFeePerGas,row.sequence,row.accountNumber,row.inputs,row.inputCapacities,row.timeoutHeight,row.changeAtoms,row.maxBytes,row.snapshot,row.outpoints,row.funding]);}
export function submissionProofKey(id,row){
 if(typeof id!=='string'||!/^[A-Za-z0-9+/]{22}==$/.test(id)||!supported(row))throw Error('Invalid submission proof identity.');
 return `${ACTIVITY_KEY}.submissionProof.${id}.${row.chain}.${row.submissionId}`;
}
export async function createSubmissionProof({id,row,key}){
 const storageKey=submissionProofKey(id,row);
 // Proof contains only the reservation identity, never a replay payload.
 const failed={...row,status:'failed',notSubmitted:true};delete failed.signedPayload;delete failed.timestamp;
 const sealed=await serializeActivity(id,[failed],key);
 return Object.freeze({storageKey,sealed});
}
export async function commitSubmissionProof(storage,proof){
 if(!proof||typeof proof.storageKey!=='string'||!proof.storageKey.startsWith(`${ACTIVITY_KEY}.submissionProof.`)||typeof proof.sealed!=='string'||proof.sealed.length>250000)throw Error('Invalid sealed submission proof.');
 await storage.set({[proof.storageKey]:proof.sealed});
}
export async function recoverSubmissionProofs({storage,id,rows,key,addresses}){
 if(!Array.isArray(rows)||rows.length>ACTIVITY_MAX_ROWS)throw Error('Submission proof record limit exceeded.');
 const eligible=rows.filter(supported);if(new Set(eligible.map(row=>row.submissionId)).size!==eligible.length)throw Error('Duplicate submission attempt identity.');if(!eligible.length)return rows;
 const keys=eligible.map(row=>submissionProofKey(id,row));const saved=await storage.get(keys);const replacements=new Map();
 for(let i=0;i<eligible.length;i++){
  const row=eligible[i],sealed=saved[keys[i]];if(sealed===undefined)continue;
  if(typeof sealed!=='string'||sealed.length>250000)throw Error('Submission proof exceeds its bounded envelope.');
  const parsed=await parseActivity(sealed,id,addresses,key);
  if(parsed.length!==1||!parsed[0].notSubmitted||parsed[0].savedStatus!=='failed'||identity(parsed[0])!==identity(row))throw Error('Submission cancellation proof does not match its reservation.');
  replacements.set(row,{...row,status:'failed',savedStatus:'failed',notSubmitted:true,note:'Authenticated cancellation: this attempt was not submitted.'});
 }
 const result=rows.map(row=>replacements.get(row)??row);
 if(rows.quarantined!==undefined)Object.defineProperty(result,'quarantined',{value:rows.quarantined,enumerable:false});
 return result;
}

// Call only AFTER the matching failed/notSubmitted activity state is durably
// saved. If cleanup fails, the authenticated redundant proof is harmless.
export async function clearSubmissionProofs(storage,id,rows){
 if(typeof storage.remove!=='function')return;
 const keys=rows.filter(row=>supported(row)&&row.status==='failed'&&row.notSubmitted===true).map(row=>submissionProofKey(id,row));
 if(keys.length)await storage.remove(keys);
}

import {CKB_FULL_RECIPIENT_SEND_ENABLED} from '../../../src/pq/ckb-recipient-policy.js';
import {prepareCkbExactRecovery} from '../../../src/pq/ckb-recovery.js';
import {commitSubmissionProof} from '../../../src/pq/submission-proof.js';
// Trusted extension CKB holder. Mainnet wallet UI only; never site-provider signing.
// No keys are retained; every disclosure is preceded by an authenticated
// pending record. Public node simulation sees a signed transaction and could
// relay it, so all later outcomes keep the hold until positive observation.
import {prepareCkbReview} from '../../../src/pq/ckb-review-controller.js';
import {simulateCkbAtConfiguredNode} from '../../../src/pq/ckb-preflight.js';
import {submitCkbTransaction} from '../../../src/pq/ckb-submit.js';
import {readCkbBalances} from '../../../src/pq/ckb.js';
import {readCkbHistory} from '../../../src/pq/ckb-history.js';
import {pqChainSeed} from '../../../src/pq/receive.js';
import {amountUnits,formatUnits} from '../../../src/core.js';
import {watchActivity,checkActivity,terminal} from '../../../src/activity.js';
import {rpcErrors} from '@metamask/rpc-errors';
export function createCkb({lockCoordinator,getWalletKeys,getActivity,getNetwork,storage,commitProof=commitSubmissionProof,prepare=prepareCkbReview,simulate=simulateCkbAtConfiguredNode,submit=submitCkbTransaction,readBalances=readCkbBalances,readHistory=readCkbHistory,prepareRecovery=prepareCkbExactRecovery,watch=watchActivity,check=checkActivity}={}){
 let session,next=0;
 async function close(){const old=session;session=null;if(!old)return;old.abort.abort(new Error('Wallet or network changed.'));old.stop?.();await Promise.allSettled([...old.reviews.values()].map(r=>r.cancel()));old.reviews.clear();for(const r of old.recoveries.values())r.cancel();old.recoveries.clear();old.reservations.clear();}
 lockCoordinator.register('ckb',{lock:close});
 function current(s){lockCoordinator.assertUnlocked();if(session!==s||s.abort.signal.aborted||getNetwork('ckb').id!==s.network.id||getWalletKeys().getPqAddresses().ckb?.[s.network.id]!==s.address)throw Error('Wallet, CKB network or account changed.');}
 function active(){lockCoordinator.assertUnlocked();if(!session){const network=getNetwork('ckb'),address=getWalletKeys().getPqAddresses().ckb?.[network.id];if(!address)throw Error('CKB receive address is unavailable.');session={network,address,activity:getActivity('ckb',network.id),abort:new AbortController(),reviews:new Map(),recoveries:new Map(),reservations:new Map(),preparing:false};}current(session);return session;}
 async function guarded(s,fn){current(s);let cancel;const stopped=new Promise((_,reject)=>{cancel=()=>reject(s.abort.signal.reason);});s.abort.signal.addEventListener('abort',cancel,{once:true});try{const result=await Promise.race([fn(),stopped]);current(s);return result;}finally{s.abort.signal.removeEventListener('abort',cancel);}}
 function unresolved(s){return s.activity.rows().some(r=>!terminal(r.status));}
 function track(s){if(s.stop)return;s.stop=watch(()=>session===s&&!lockCoordinator.isLocked?s.activity.rows():[],()=>{void s.activity.persist().catch(e=>{if(session===s)s.activityError=e.message;});},{check:(row,o)=>check(row,{...o,signal:s.abort.signal})});}
 async function ready(s){await guarded(s,()=>Promise.resolve(s.activity.ready));if(typeof s.activity.appendCkbPendingWithProof!=='function'||typeof s.activity.recoverSubmissionProofs!=='function'||typeof s.activity.persist!=='function'||!storage)throw Error('Durable CKB pending storage is unavailable.');await guarded(s,()=>s.activity.recoverSubmissionProofs());s.activity.assertSendable();track(s);}
 function reserve(s,{networkId,from,outpoints}){current(s);if(networkId!==s.network.id||from!==s.address||unresolved(s)||!Array.isArray(outpoints)||!outpoints.length||outpoints.some(x=>s.reservations.has(x)))return null;const token=Object.freeze({id:Symbol('ckb-reservation'),outpoints:[...outpoints]});for(const x of outpoints)s.reservations.set(x,token);return token;}
 function release(s,token){for(const x of token?.outpoints??[])if(s.reservations.get(x)===token)s.reservations.delete(x);}
 return {networkChanged:close,
  async getBalances(){const s=active();await ready(s);return guarded(s,()=>readBalances(s.address,{networkId:s.network.id,signal:s.abort.signal}));},
  async getHistory(){const s=active();await ready(s);let remote;try{remote=await guarded(s,()=>readHistory(s.address,{networkId:s.network.id,signal:s.abort.signal}));}catch(e){current(s);remote={rows:[],status:'Provider history unavailable; showing local submissions only.',error:e.message};}const local=s.activity.rows().map(({hash,to,amount,symbol,status,note,createdAt,signedPayload,notSubmitted})=>({hash,to,amount,symbol,status,note,createdAt,network:s.network.id,canResubmit:Boolean(signedPayload)&&!notSubmitted&&['pending','unknown'].includes(status)}));const localHashes=new Set(local.map(row=>row.hash));return {...remote,rows:remote.rows.filter(row=>!localHashes.has(row.hash)),network:s.network.id,local,activityError:s.activityError||s.activity.error?.()||''};},
  async prepareResubmit(hash){
   const s=active();await ready(s);const row=s.activity.rows().find(r=>r.hash===hash);if(!row||row.address!==s.address||row.networkId!==s.network.id||s.activity.rows().some(other=>other!==row&&!terminal(other.status)))throw Error('Choose one unresolved CKB submission.');
   const task=prepareRecovery(row,{signal:s.abort.signal,assertCurrent:()=>current(s),simulate,submit}).then(r=>{try{current(s);return r;}catch(e){r.cancel();throw e;}}),r=await guarded(s,()=>task);for(const old of s.recoveries.values())old.cancel();s.recoveries.clear();const id=String(++next);s.recoveries.set(id,r);
   return {id,chain:'ckb',network:s.network.id,from:r.from,to:r.to,symbol:'CKB',amount:formatUnits(BigInt(r.amount),8),fee:`${formatUnits(BigInt(r.fee),8)} CKB`,hash:r.hash,resubmission:true,expiresAt:r.expiresAt,review:[['Action','Resubmit EXACTLY the previously signed transaction; no new signature'],['Transaction ID',r.hash],['From',r.from],['To',r.to],['Amount',`${formatUnits(BigInt(r.amount),8)} CKB`],['Fee',`${formatUnits(BigInt(r.fee),8)} CKB`],['Recovery',r.notice]]};
  },
  cancelResubmit(id){const r=session?.recoveries.get(id);r?.cancel();session?.recoveries.delete(id);},
  async confirmResubmit(id){const s=active(),r=s.recoveries.get(id);if(!r)throw Error('This CKB recovery review is already closed.');s.recoveries.delete(id);await ready(s);return guarded(s,async()=>{let record;try{return await r.confirm(async details=>{current(s);const old=s.activity.rows().find(x=>x.hash===r.hash);if(!old||old.address!==s.address||old.networkId!==s.network.id||!['pending','unknown'].includes(old.status))throw Error('CKB pending record changed.');record=s.activity.appendCkbPending(r,details);await s.activity.persist();current(s);return {submissionId:record.submissionId};});}catch(e){if(record&&session===s&&!lockCoordinator.isLocked){record.status='unknown';record.note='Exact CKB recovery outcome remains unresolved; do not send a new transaction.';await s.activity.persist();current(s);}throw e;}});},
  confirmOperation(id){return session?.recoveries.has(id)?this.confirmResubmit(id):this.confirmSend(id);},
  cancelOperation(id){return session?.recoveries.has(id)?this.cancelResubmit(id):this.cancelSend(id);},
  async prepareSend({symbol,to,amount}={}){
   const s=active();await ready(s);if(symbol!=='CKB')throw Error('Only native CKB is supported.');if(unresolved(s))throw Error('A previous CKB transfer is unresolved.');if(s.preparing||s.reviews.size)throw Error('A CKB review is already open.');
   const atoms=amountUnits(amount,8);s.preparing=true;
   try{const task=prepare({from:s.address,to,amount:atoms,networkId:s.network.id,maxFee:100000000n,maxRate:100000n,cycleCeiling:100000000n,reserve:o=>reserve(s,o),release:t=>release(s,t),signal:s.abort.signal}).then(async r=>{try{current(s);return r;}catch(e){await r.cancel();throw e;}});const r=await guarded(s,()=>task);current(s);const id=String(++next);s.reviews.set(id,r);return {id,chain:'ckb',network:s.network.id,from:r.from,to:r.to,symbol:'CKB',amount:formatUnits(atoms,8),fee:`${formatUnits(BigInt(r.fee),8)} CKB`,expiresAt:r.expiresAt,review:[['Network',`CKB ${s.network.label||s.network.id}`],['From',r.from],['To',r.to],['Amount',`${formatUnits(atoms,8)} CKB`],['Fee',`${formatUnits(BigInt(r.fee),8)} CKB`],['Fee rate',`${r.feeRate} shannons per 1000 weight`],['Scope',CKB_FULL_RECIPIENT_SEND_ENABLED?'Full-format Bech32m recipients only; non-cellbase empty-data quantum inputs. Check recipient control; address validity does not prove spendability.':'Quantum-lock recipients only; non-cellbase empty-data inputs.'],['Simulation','The configured node receives the signed transaction and could relay it.']]};}finally{s.preparing=false;}
  },
  cancelSend(id){const r=session?.reviews.get(id);session?.reviews.delete(id);return r?.cancel();},
  async confirmSend(id){
   const s=active(),r=s.reviews.get(id);if(!r)throw Error('This CKB review is already closed.');s.reviews.delete(id);try{await ready(s);}catch(e){await r.cancel();throw e;}if(unresolved(s)){await r.cancel();throw Error('A previous CKB transfer is unresolved.');}
   return guarded(s,async()=>{let root,record,abortProof;
    try{
     current(s);root=pqChainSeed(getWalletKeys().getRecoveryPhrase(),'ckb');
     const signed=await r.signAfterConfirmation({seed:root,persistPending:async details=>{current(s);s.activity.assertSendable();if(unresolved(s))throw Error('A previous CKB transfer is unresolved.');const pending=await s.activity.appendCkbPendingWithProof(r,details);record=pending.record;abortProof=pending.proof;await s.activity.persist();current(s);return {submissionId:record.submissionId};},simulate:async args=>{current(s);return simulate({...args,expectedFee:BigInt(r.fee),signal:s.abort.signal});}});root.fill(0);root=undefined;current(s);
     if(Date.now()>=r.expiresAt)throw Error('CKB review expired before submission; the signed simulation remains held.');
     const txid=await submit({networkId:s.network.id,rpcTransaction:signed.rpcTransaction,txid:signed.txid,expiresAt:r.expiresAt,signal:s.abort.signal});current(s);record.note='CKB node accepted submission; awaiting canonical confirmation.';await s.activity.persist();current(s);track(s);return txid;
    }catch(e){if(abortProof&&e.ckbNotExposed===true)await commitProof(storage,abortProof);if(record&&session===s&&!lockCoordinator.isLocked){record.status=e.ckbNotExposed===true?'failed':'unknown';if(e.ckbNotExposed===true)record.notSubmitted=true;record.note=record.notSubmitted?'Authenticated cancellation: this attempt was not exposed.':'CKB signed transaction may have been disclosed or submitted. Outpoints remain held; do not resend.';await s.activity.persist();current(s);track(s);throw rpcErrors.internal({message:e.message,data:{activityTracked:true}});}throw e;}
    finally{root?.fill(0);}
   });
  }
 };
}

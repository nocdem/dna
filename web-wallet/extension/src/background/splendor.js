import {observeSplendorSubmission,prepareSplendorExactRecovery} from '../../../src/pq/splendor-transfer.js';
import {formatUnits} from '../../../src/core.js';
import {prepareTransfer} from '../../../src/wallet.js';
import {readSplendorBalances} from '../../../src/pq/splendor.js';
import {readSplendorHistory} from '../../../src/pq/splendor-history.js';
import {sentRowsToShow} from '../../../src/activity-storage.js';
import {terminal,watchActivity,checkActivity} from '../../../src/activity.js';
import {commitSubmissionProof} from '../../../src/pq/submission-proof.js';
// Trusted-wallet holder with authenticated per-network pending storage.
// Capability enablement is separately reviewed; no provider signing is exposed.
// No site-provider methods, permissions, or recovery material are retained.
export function createSplendor({lockCoordinator,getWalletKeys,getActivity,getNetwork,storage,commitProof=commitSubmissionProof,prepare=prepareTransfer,observe=observeSplendorSubmission,prepareRecovery=prepareSplendorExactRecovery,readBalances=readSplendorBalances,readHistory=readSplendorHistory,watch=watchActivity,check=checkActivity}) {
 let session,next=0;
 function close(){const old=session;session=null;if(!old)return;old.abort.abort(new Error('Wallet or network changed.'));old.stop?.();for(const r of old.reviews.values())r.cancel();old.reviews.clear();for(const r of old.recoveries.values())r.cancel();old.recoveries.clear();}
 lockCoordinator.register('splendor',{lock:close});
 function current(s){lockCoordinator.assertUnlocked();if(session!==s||s.abort.signal.aborted||getNetwork('splendor').id!==s.network.id)throw new Error('Wallet or network changed.');if(getWalletKeys().getPqAddresses().splendor?.[s.network.id]!==s.address)throw new Error('Splendor account changed.');}
 function active(){lockCoordinator.assertUnlocked();if(!session){const network=getNetwork('splendor'),address=getWalletKeys().getPqAddresses().splendor?.[network.id];if(!address)throw new Error('Splendor receive address is unavailable.');session={network,address,activity:getActivity('splendor',network.id),abort:new AbortController(),reviews:new Map(),recoveries:new Map()};}current(session);return session;}
 async function guarded(s,fn){current(s);let cancel;const stopped=new Promise((_,reject)=>{cancel=()=>reject(s.abort.signal.reason);});s.abort.signal.addEventListener('abort',cancel,{once:true});try{const result=await Promise.race([fn(),stopped]);current(s);return result;}finally{s.abort.signal.removeEventListener('abort',cancel);}}
 async function ready(s){await guarded(s,()=>Promise.resolve(s.activity.ready));if(typeof s.activity.appendSplendorPendingWithProof!=='function'||typeof s.activity.recoverSubmissionProofs!=='function'||typeof s.activity.persist!=='function'||!storage)throw new Error('Durable Splendor pending storage is unavailable.');await guarded(s,()=>s.activity.recoverSubmissionProofs());s.activity.assertSendable();track(s);}
 function unresolved(s){return s.activity.rows().some(r=>!terminal(r.status));}
 function track(s){if(s.stop)return;s.stop=watch(()=>session===s&&!lockCoordinator.isLocked?s.activity.rows():[],()=>{void s.activity.persist().catch(e=>{if(session===s)s.activityError=e.message;});},{check:(row,options)=>check(row,{...options,signal:s.abort.signal})});}
 function snapshot(s){current(s);return {network:s.network.id,rows:structuredClone(s.page?.rows??[]),local:sentRowsToShow(s.activity.rows(),{historyRows:s.page?.rows??[]}).map(({hash,to,amount,symbol,status,note,createdAt,signedPayload,notSubmitted})=>({hash,to,amount,symbol,status,note,createdAt,canResubmit:s.network.id==='mainnet'&&Boolean(signedPayload)&&!notSubmitted&&['pending','unknown'].includes(status)})),status:'Up to 50 indexed native transfers; excludes contracts and tokens. Local submissions are labelled separately.',error:s.historyError??'',activityError:s.activityError||s.activity.error?.()||''};}
 return {networkChanged:close,
  async getBalances(){const s=active();await ready(s);return guarded(s,()=>readBalances(s.address,{networkId:s.network.id,signal:s.abort.signal}));},
  async getHistory({manual=false}={}){const s=active();await ready(s);if(s.historyJob)return s.historyJob;if(s.page&&Date.now()-s.page.readAt<(manual?30000:300000))return snapshot(s);
   const job=guarded(s,async()=>{try{const rows=await readHistory(s.address,{networkId:s.network.id,signal:s.abort.signal});current(s);s.page={rows,readAt:Date.now()};s.historyError='';}catch(error){current(s);s.historyError=error.message;}return snapshot(s);});s.historyJob=job;try{return await job;}finally{if(s.historyJob===job)s.historyJob=null;}},
  async prepareResubmit(hash){const review=await this.prepareRecovery(hash);return {...review,resubmission:true,review:[['Action','Resubmit EXACTLY the previously signed transaction; no new signature'],['Network',`Splendor ${review.network}`],['Transaction ID',review.hash],['From',review.from],['To',review.to],['Amount',`${review.amount} SPLD`],['Fee',review.fee],['Recovery',review.notice]]};},
  confirmOperation(id){return session?.recoveries.has(id)?this.confirmRecovery(id):this.confirmSend(id);},
  cancelOperation(id){return session?.recoveries.has(id)?this.cancelRecovery(id):this.cancelSend(id);},

  async prepareSend({symbol,to,amount}={}){
   const s=active();await ready(s);if(symbol!=='SPLD')throw new Error('Only SPLD native transfers are supported.');if(unresolved(s))throw new Error('A previous Splendor send is unresolved.');
   const wallet={addresses:{splendor:s.address},get recoveryPhrase(){current(s);return getWalletKeys().getRecoveryPhrase();},get locked(){current(s);return false;}};
   const preparing=prepare({wallet,chain:'splendor',symbol,to,amount,networkId:s.network.id,signal:s.abort.signal}).then(r=>{try{current(s);return r;}catch(e){r.cancel();throw e;}});
   const review=await guarded(s,()=>preparing);for(const r of s.reviews.values())r.cancel();s.reviews.clear();const id=String(++next);s.reviews.set(id,review);
   return {id,chain:'splendor',network:s.network.id,from:review.from,to:review.to,symbol:'SPLD',amount:review.amount,fee:review.fee,amountAtoms:review.amountAtoms,feeAtoms:review.feeAtoms,nonce:review.nonce,expiresAt:review.expiresAt,review:structuredClone(review.review)};
  },
  cancelSend(id){const r=session?.reviews.get(id);r?.cancel();session?.reviews.delete(id);},
  async confirmSend(id){const s=active(),r=s.reviews.get(id);if(!r)throw new Error('This review is already closed.');s.reviews.delete(id);try{await ready(s);}catch(e){r.cancel();throw e;}if(unresolved(s)){r.cancel();throw new Error('A previous Splendor send is unresolved.');}
   return guarded(s,async()=>{let record,abortProof;try{return await r.confirm(async pending=>{current(s);s.activity.assertSendable();const item=await s.activity.appendSplendorPendingWithProof(r,pending);record=item.record;abortProof=item.proof;await s.activity.persist();current(s);});}catch(e){if(abortProof&&e.splendorNotSubmitted===true)await commitProof(storage,abortProof);if(record&&session===s&&!lockCoordinator.isLocked){record.status=e.splendorNotSubmitted===true?'failed':'unknown';record.notSubmitted=e.splendorNotSubmitted===true;record.note=record.notSubmitted?'Not submitted to Splendor.':'Submission outcome uncertain; check status before another transfer.';await s.activity.persist();current(s);}throw e;}});
  },
  async prepareRecovery(hash){
   const s=active();await ready(s);const row=s.activity.rows().find(r=>r.hash===hash);if(!row||row.address!==s.address||row.networkId!==s.network.id)throw new Error('Invalid Splendor pending owner.');
   const preparing=prepareRecovery(row,{signal:s.abort.signal,assertCurrent:()=>current(s)}).then(r=>{try{current(s);return r;}catch(e){r.cancel();throw e;}});const review=await guarded(s,()=>preparing);
   for(const r of s.recoveries.values())r.cancel();s.recoveries.clear();const id=String(++next);s.recoveries.set(id,review);
   return {id,chain:'splendor',network:s.network.id,from:review.from,to:review.to,symbol:'SPLD',amount:formatUnits(BigInt(review.amountAtoms),18),fee:`${formatUnits(BigInt(review.feeAtoms),18)} SPLD`,hash:review.hash,notice:review.notice,expiresAt:review.expiresAt};
  },
  cancelRecovery(id){const review=session?.recoveries.get(id);review?.cancel();session?.recoveries.delete(id);},
  async confirmRecovery(id){const s=active(),review=s.recoveries.get(id);if(!review)throw new Error('This recovery review is already closed.');s.recoveries.delete(id);await ready(s);
   return guarded(s,async()=>review.confirm(async()=>{current(s);const old=s.activity.rows().find(r=>r.hash===review.hash);if(!old||old.address!==s.address||old.networkId!==s.network.id||!['pending','unknown'].includes(old.status))throw new Error('Splendor pending record changed.');
    const pending={networkId:old.networkId,from:old.address,to:old.to,amount:old.amountAtoms,fee:old.feeAtoms,nonce:old.nonce,timestamp:old.timestamp,hash:old.hash,signedPayload:old.signedPayload};
    const attempt=await s.activity.appendSplendorPendingWithProof(review,pending);await s.activity.persist();current(s);
    // Do not commit a zero-POST proof for this replay: an earlier attempt
    // with identical hash may already be in a mempool or block.
    return {submissionId:attempt.record.submissionId};
   }));
  },
  async observePending(record){const s=active();await ready(s);if(!record||record.from!==s.address||record.networkId!==s.network.id)throw new Error('Invalid Splendor pending owner.');return guarded(s,()=>observe(record,{signal:s.abort.signal}));}
 };
}

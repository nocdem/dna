import {readSoquHistoryPage} from '../../../src/pq/soqu-history.js';
import { prepareSoquResubmission } from '../../../src/pq/soqu-transfer.js';
import { formatUnits } from '../../../src/core.js';
import { commitSubmissionProof } from '../../../src/pq/submission-proof.js';
import { prepareTransfer } from '../../../src/wallet.js';
import { readSoquBalances } from '../../../src/pq/soqucoin.js';
import { watchActivity, checkActivity, terminal } from '../../../src/activity.js';
import { sentRowsToShow } from '../../../src/activity-storage.js';
import { rpcErrors } from '@metamask/rpc-errors';

// Trusted extension wallet operations only. Site-provider signing permissions
// are unchanged. This holder owns reviews/jobs, never recovery words or keys.
export function createSoqucoin({ lockCoordinator, getWalletKeys, getActivity, getNetwork, storage,
  prepare = prepareTransfer, readBalances = readSoquBalances, readHistory = readSoquHistoryPage,
  watch = watchActivity, check = checkActivity, prepareResubmission = prepareSoquResubmission }) {
  let session, nextReview = 0;
  function close() {
    const old=session; session=null;
    if (!old) return;
    old.abort.abort(new Error('Wallet or network changed.')); old.stop?.();
    for(const r of old.reviews.values()) r.cancel(); old.reviews.clear();
  }
  lockCoordinator.register('soqucoin',{lock:close});
  function current(s) {
    lockCoordinator.assertUnlocked();
    if(session!==s || s.abort.signal.aborted) throw new Error('Wallet or network changed.');
    if(getWalletKeys().getPqAddresses().soqucoin?.[s.network.id]!==s.address) throw new Error('Soqucoin account changed.');
  }
  function active() {
    lockCoordinator.assertUnlocked();
    if(!session) {
      const network=getNetwork('soqucoin'), address=getWalletKeys().getPqAddresses().soqucoin?.[network.id];
      if(!address) throw new Error('Soqucoin receive address is unavailable.');
      session={network,address,activity:getActivity('soqucoin',network.id),abort:new AbortController(),reviews:new Map()};
    }
    current(session); return session;
  }
  async function guarded(s,work) {
    current(s);
    let cancel;
    const stopped=new Promise((_,reject)=>{cancel=()=>reject(s.abort.signal.reason);});
    s.abort.signal.addEventListener('abort',cancel,{once:true});
    try {const result=await Promise.race([work(),stopped]);current(s);return result;}
    finally{s.abort.signal.removeEventListener('abort',cancel);}
  }
  function track(s) {
    if(s.stop || s.network.id!=='mainnet') return;
    s.stop=watch(()=>session===s&&!lockCoordinator.isLocked?s.activity.rows():[],()=>{
      void s.activity.persist().catch(e=>{if(session===s)s.activityError=e.message;});
    },{check:(row,options)=>check(row,{...options,signal:s.abort.signal})});
  }
  async function ready(s) {await guarded(s,()=>Promise.resolve(s.activity.ready));await guarded(s,()=>s.activity.recoverSubmissionProofs());track(s);}
  function snapshot(s) {
    current(s); const page=s.page, unresolvedHashes=new Set(s.activity.rows().filter(row=>!terminal(row.status)).map(row=>row.hash));
    return {network:s.network.id,rows:structuredClone((page?.rows??[]).filter(row=>!unresolvedHashes.has(row.hash))),local:sentRowsToShow(s.activity.rows(),{historyRows:page?.rows??[]}).map(({hash,to,amount,symbol,status,note,createdAt,signedPayload,notSubmitted})=>({hash,to,amount,symbol,status,note,createdAt,network:s.network.id,canResubmit:Boolean(signedPayload)&&!notSubmitted&&['pending','unknown'].includes(status)})),
      status:page ? `${page.status} Listed ${page.totalListed}; examined ${page.examined}; omitted ${page.omitted}. Local submissions are labelled separately.` : 'Local SOQ submissions only; partial account history is unavailable.',error:s.historyError??'',activityError:s.activityError||s.activity.error()};
  }
  return {
    networkChanged:close,
    async getBalances(){const s=active();await ready(s);return guarded(s,()=>readBalances(s.address,{networkId:s.network.id,signal:s.abort.signal}));},
    async getHistory({manual=false}={}) { const s=active(); await ready(s); if(s.historyJob)return s.historyJob;if(s.page&&Date.now()-s.page.readAt<(manual?30000:300000))return snapshot(s);
      const job=guarded(s,async()=>{try{const page=await readHistory(s.address,{networkId:s.network.id,signal:s.abort.signal});current(s);s.page={...page,readAt:Date.now()};s.historyError='';}catch(error){current(s);s.page=null;s.historyError=error.message;}return snapshot(s);});s.historyJob=job;try{return await job;}finally{if(s.historyJob===job)s.historyJob=null;} },
    async prepareSend({symbol,to,amount}={}) {
      const s=active();await ready(s);s.activity.assertSendable();
      if(s.network.id!=='mainnet'||symbol!=='SOQ')throw new Error('Only verified Soqucoin mainnet SOQ sends are available.');
      if(s.activity.rows().some(r=>!terminal(r.status)))throw new Error('A previous Soqucoin send is unresolved. Check its status before sending again.');
      const wallet={addresses:{soqucoin:s.address},get recoveryPhrase(){current(s);return getWalletKeys().getRecoveryPhrase();},get locked(){current(s);return false;}};
      const preparing=prepare({wallet,chain:'soqucoin',symbol,to,amount,networkId:s.network.id,signal:s.abort.signal}).then(r=>{try{current(s);return r;}catch(e){r.cancel();throw e;}});
      const review=await guarded(s,()=>preparing);
      for(const old of s.reviews.values())old.cancel();s.reviews.clear();
      const id=String(++nextReview);s.reviews.set(id,review);
      return {id,chain:'soqucoin',network:s.network.id,from:review.from,to:review.to,symbol:'SOQ',amount:review.amount,fee:review.fee,expiresAt:review.expiresAt,review:structuredClone(review.review)};
    },
    async prepareResubmit(hash) {
      const s=active();await ready(s);s.activity.assertSendable();
      const row=s.activity.rows().find(row=>row.hash===hash);
      if(!row||s.activity.rows().some(other=>other.hash!==hash&&!terminal(other.status)))throw new Error('Choose one unresolved SOQ submission.');
      const wallet={addresses:{soqucoin:s.address},get locked(){current(s);return false;}};
      const prepared=await guarded(s,()=>prepareResubmission({wallet,row,signal:s.abort.signal}));
      const review={...prepared,chain:'soqucoin',symbol:'SOQ',endpoint:s.network.endpoint,
        fee:prepared.feeAtoms?`${formatUnits(BigInt(prepared.feeAtoms),8)} SOQ`:'Original signed fee (unchanged)',
        review:[['Action','Resubmit EXACTLY the previously signed transaction; no new payment or signature'],['Network','Soqucoin mainnet'],['Transaction ID',prepared.hash],['From',prepared.from],['To',prepared.to],['Amount',`${prepared.amount} SOQ`],['Recovery','Same bytes and outpoints. An earlier submission may already exist.']]};
      for(const old of s.reviews.values())old.cancel();s.reviews.clear();
      const id=String(++nextReview);s.reviews.set(id,review);
      return {id,chain:'soqucoin',network:s.network.id,from:review.from,to:review.to,symbol:'SOQ',amount:review.amount,fee:review.fee,expiresAt:review.expiresAt,resubmission:true,review:structuredClone(review.review)};
    },
    cancelSend(id){const review=session?.reviews.get(id);review?.cancel();session?.reviews.delete(id);},
    async confirmSend(id) {
      const s=active(),review=s.reviews.get(id);if(!review)throw new Error('This review is already closed.');
      s.reviews.delete(id);s.activity.assertSendable();
      if(s.activity.rows().some(r=>!terminal(r.status)&&(!review.isResubmission||r.hash!==review.hash))) {review.cancel();throw new Error('A previous Soqucoin send is unresolved.');}
      return guarded(s,async()=>{
        let record, abortProof;
        try {
          const hash=await review.confirm(async details=>{current(s);s.activity.assertSendable();const pending=await s.activity.appendSubmissionWithProof(review,details);record=pending.record;abortProof=pending.proof;await s.activity.persist();current(s);});
          current(s);record.note='Broadcast submitted; awaiting confirmation.';track(s);return hash;
        }catch(e){
          // The already sealed capsule contains no key. Known-zero-POST cleanup
          // remains valid after lock/network change; never overwrite the bucket.
          if(abortProof&&e.soquNotSubmitted===true)await commitSubmissionProof(storage,abortProof);
          if(record&&session===s&&!lockCoordinator.isLocked){record.status=e.soquNotSubmitted===true?'failed':'unknown';
            if(e.soquNotSubmitted===true)record.notSubmitted=true;
            record.note=record.notSubmitted?'Not submitted to Soqucoin.': 'Broadcast outcome uncertain. Tracking this transaction; do not resend automatically.';
            await s.activity.persist();current(s);track(s);throw rpcErrors.internal({message:e.message,data:{activityTracked:true}});}
          throw e;
        }
      });
    },
  };
}

import { prepareTransfer } from '../../../src/wallet.js';
import { readAlgorandBalances, readAlgorandHistory } from '../../../src/pq/algorand.js';
import { watchActivity, checkActivity, terminal } from '../../../src/activity.js';
import { sentRowsToShow } from '../../../src/activity-storage.js';
import { rpcErrors } from '@metamask/rpc-errors';

// Trusted extension wallet operations only. Site-provider signing permissions
// are unchanged. This holder owns reviews/jobs, never recovery words or keys.
export function createAlgorand({ lockCoordinator, getWalletKeys, getActivity, getNetwork,
  prepare = prepareTransfer, readBalances = readAlgorandBalances, readHistory = readAlgorandHistory,
  watch = watchActivity, check = checkActivity }) {
  let session, nextReview = 0;
  function close() {
    const old=session; session=null;
    if (!old) return;
    old.abort.abort(new Error('Wallet or network changed.')); old.stop?.();
    for(const r of old.reviews.values()) r.cancel(); old.reviews.clear();
  }
  lockCoordinator.register('algorand',{lock:close});
  function current(s) {
    lockCoordinator.assertUnlocked();
    if(session!==s || s.abort.signal.aborted) throw new Error('Wallet or network changed.');
    if(getWalletKeys().getPqAddresses().algorand?.[s.network.id]!==s.address) throw new Error('Algorand account changed.');
  }
  function active() {
    lockCoordinator.assertUnlocked();
    if(!session) {
      const network=getNetwork('algorand'), address=getWalletKeys().getPqAddresses().algorand?.[network.id];
      if(!address) throw new Error('Algorand receive address is unavailable.');
      session={network,address,activity:getActivity('algorand',network.id),abort:new AbortController(),reviews:new Map()};
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
  async function ready(s) {await guarded(s,()=>Promise.resolve(s.activity.ready));track(s);}
  function snapshot(s) {
    current(s); const page=s.activity.history();
    return {network:s.network.id,rows:structuredClone(page?.rows??[]),local:sentRowsToShow(s.activity.rows(),{historyRows:page?.rows??[]}).map(({hash,to,amount,symbol,status,note,createdAt})=>({hash,to,amount,symbol,status,note,createdAt,network:s.network.id})),
      status:page?'Native payments reported by Algorand indexer; excludes inner transfers, assets, fees and rewards.':'Account history has not been read yet.',error:s.historyError??'',activityError:s.activityError||s.activity.error()};
  }
  return {
    networkChanged:close,
    async getBalances(){const s=active();await ready(s);return guarded(s,()=>readBalances(s.address,{networkId:s.network.id,signal:s.abort.signal}));},
    async getHistory({manual=false}={}) {
      const s=active();await ready(s);
      if(s.historyJob)return s.historyJob;
      const kept=s.activity.history();if(kept&&Date.now()-kept.readAt<(manual?30000:300000))return snapshot(s);
      const job=guarded(s,async()=>{
        try {const rows=await readHistory(s.address,{networkId:s.network.id,signal:s.abort.signal});current(s);await s.activity.saveHistory({address:s.address,rows,readAt:Date.now()});current(s);s.historyError='';}
        catch(e){current(s);s.historyError=e.message;}
        return snapshot(s);
      });s.historyJob=job;try{return await job;}finally{if(s.historyJob===job)s.historyJob=null;}
    },
    async prepareSend({symbol,to,amount}={}) {
      const s=active();await ready(s);s.activity.assertSendable();
      if(s.network.id!=='mainnet'||symbol!=='ALGO')throw new Error('Only verified Algorand mainnet ALGO sends are available.');
      if(s.activity.rows().some(r=>!terminal(r.status)))throw new Error('A previous Algorand send is unresolved. Check its status before sending again.');
      const wallet={addresses:{algorand:s.address},get recoveryPhrase(){current(s);return getWalletKeys().getRecoveryPhrase();},get locked(){current(s);return false;}};
      const preparing=prepare({wallet,chain:'algorand',symbol,to,amount,networkId:s.network.id,signal:s.abort.signal}).then(r=>{try{current(s);return r;}catch(e){r.cancel();throw e;}});
      const review=await guarded(s,()=>preparing);
      for(const old of s.reviews.values())old.cancel();s.reviews.clear();
      const id=String(++nextReview);s.reviews.set(id,review);
      return {id,chain:'algorand',network:s.network.id,from:review.from,to:review.to,symbol:'ALGO',amount:review.amount,fee:review.fee,expiresAt:review.expiresAt,review:structuredClone(review.review)};
    },
    cancelSend(id){const review=session?.reviews.get(id);review?.cancel();session?.reviews.delete(id);},
    async confirmSend(id) {
      const s=active(),review=s.reviews.get(id);if(!review)throw new Error('This review is already closed.');
      s.reviews.delete(id);s.activity.assertSendable();
      if(s.activity.rows().some(r=>!terminal(r.status))) {review.cancel();throw new Error('A previous Algorand send is unresolved.');}
      return guarded(s,async()=>{
        let record;
        try {
          const hash=await review.confirm(async details=>{current(s);s.activity.assertSendable();record=s.activity.append(review,details);await s.activity.persist();current(s);});
          current(s);record.note='Broadcast submitted; awaiting confirmation.';track(s);return hash;
        }catch(e){
          if(record&&session===s&&!lockCoordinator.isLocked){record.status=e.algorandNotSubmitted===true?'failed':'unknown';
            if(e.algorandNotSubmitted===true)record.notSubmitted=true;
            record.note=record.notSubmitted?'Not submitted to Algorand.': 'Broadcast outcome uncertain. Tracking this transaction; do not resend automatically.';
            await s.activity.persist();current(s);track(s);throw rpcErrors.internal({message:e.message,data:{activityTracked:true}});}
          throw e;
        }
      });
    },
  };
}

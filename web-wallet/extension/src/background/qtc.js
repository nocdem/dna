import {readQtcBalances} from '../../../src/pq/qtc.js';
import {publicActivityRow,watchActivity} from '../../../src/activity.js';
import {prepareQtcRecovery} from '../../../src/pq/qtc-recovery.js';
import {commitSubmissionProof} from '../../../src/pq/submission-proof.js';
import {prepareQtcReview} from '../../../src/pq/qtc-review-controller.js';
import {pqChainSeed} from '../../../src/pq/receive.js';
import {amountUnits,formatUnits} from '../../../src/core.js';

// Internal trusted-wallet holder only. NO default node transport: the explorer
// cannot establish mempool spendability. No capability or provider permission
// is enabled by this module. Transport must be source-verified independently.
export function createQtc({lockCoordinator,getWalletKeys,getActivity,getNetwork,getTransport,storage,transportKind='node',
 prepare=prepareQtcReview,deriveRoot=pqChainSeed,signWasmBytes,receiveWasmBytes,fetcher,readBalances=readQtcBalances,watch=watchActivity}) {
 if(transportKind==='gateway'&&prepare===prepareQtcReview)throw Error('QTC gateway requires its separately reviewed controller.');
 let session,next=0;
 function close(){const old=session;session=null;if(!old)return;old.abort.abort(new Error('Wallet or network changed.'));old.stop?.();for(const r of old.reviews.values())void r.cancel();old.reviews.clear();}
 lockCoordinator.register('qtc',{lock:close});
 function current(s){lockCoordinator.assertUnlocked();if(session!==s||s.abort.signal.aborted||getNetwork('qtc').id!==s.network.id||getWalletKeys().getPqAddresses().qtc?.[s.network.id]!==s.address)throw Error('Wallet or network changed.');}
 function active(){lockCoordinator.assertUnlocked();if(!session){const network=getNetwork('qtc'),address=getWalletKeys().getPqAddresses().qtc?.[network.id];if(!address)throw Error('QTC receive address is unavailable.');session={network,address,activity:getActivity('qtc',network.id),abort:new AbortController(),reviews:new Map(),reserved:new Set(),preparing:false,confirming:false};}current(session);return session;}
 async function ready(s){await s.activity.ready;current(s);if(typeof s.activity.assertSendable!=='function'||typeof s.activity.appendQtcPendingWithProof!=='function'||typeof s.activity.recoverSubmissionProofs!=='function'||!storage||typeof s.activity.persist!=='function'||typeof s.activity.rows!=='function')throw Error('Durable QTC pending storage is unavailable.');await s.activity.recoverSubmissionProofs();current(s);for(const row of s.activity.rows())if(row.notSubmitted===true)row.status='failed';s.activity.assertSendable();track(s);}
 function unresolved(s){return s.activity.rows().some(r=>r.status!=='confirmed'&&!(r.status==='failed'&&r.notSubmitted===true));}
 function transport(s){if(!['node','gateway'].includes(transportKind))throw Error('Unsupported QTC transport contract.');const t=getTransport?.(s.network.id);if(!t||(transportKind==='gateway'?['broadcast','observe']:['verifyInputs','simulate','broadcast','observe']).some(k=>typeof t[k]!=='function'))throw Error('A verified mempool-aware QTC node transport is required.');return t;}
 function track(s){if(s.stop)return;let node;try{node=transport(s);}catch{return;}s.stop=watch(()=>session===s&&!lockCoordinator.isLocked?s.activity.rows():[],()=>{void s.activity.persist().catch(e=>{if(session===s)s.activityError=e.message;});},{check:async(row,options)=>{const signal=AbortSignal.any([s.abort.signal,options.signal]);const result=await node.observe({hash:row.hash,networkId:s.network.id,signal});current(s);return result?.hash===row.hash&&result.status==='confirmed'?{status:'confirmed',note:'Confirmed in the official canonical-height index.'}:{status:'pending',note:'Outcome unresolved; signed inputs remain reserved.'};}});}
 return {networkChanged:close,
  async getBalances(){const s=active();await ready(s);const result=await readBalances(s.address,{networkId:s.network.id,signal:s.abort.signal,fetcher});current(s);return result;},
  async getHistory(){const s=active();await ready(s);current(s);return {network:s.network.id,rows:[],local:s.activity.rows().map(row=>({...publicActivityRow(row),canResubmit:s.network.id==='mainnet'&&!!row.signedPayload&&!row.notSubmitted&&['pending','unknown'].includes(row.status)})),status:'Local QTC submissions only; this view is not a full indexed account scan.',error:'',activityError:s.activityError||s.activity.error?.()||''};},
  async prepareSend({symbol,to,amount}={}){
   const s=active();await ready(s);const node=transport(s);if(symbol!=='QTC')throw Error('Only native QTC payments are supported.');if(s.preparing||s.confirming||s.reviews.size||unresolved(s))throw Error('A previous QTC operation is unresolved.');
   s.preparing=true;let r;
   try{r=await prepare({from:s.address,to,amount:amountUnits(amount,8),networkId:s.network.id,maxFee:100000000n,maxRate:100000n,signal:s.abort.signal,fetcher,
    reserve:async({networkId,from,outpoints})=>{current(s);if(networkId!==s.network.id||from!==s.address||unresolved(s)||outpoints.some(p=>s.reserved.has(p)))return null;const token=Object.freeze([...outpoints]);for(const p of token)s.reserved.add(p);return token;},
    release:async token=>{for(const p of token)s.reserved.delete(p);},verifyInputs:args=>{current(s);return node.verifyInputs(args);}});current(s);
    const id=String(++next);s.reviews.set(id,r);return {id,chain:'qtc',network:s.network.id,from:r.from,to:r.to,symbol:'QTC',amount:formatUnits(r.amount,8),fee:formatUnits(r.fee,8),expiresAt:r.expiresAt,review:[['Network',`QTC ${s.network.id}`],['From',r.from],['To',r.to],['Amount',`${formatUnits(r.amount,8)} QTC`],['Fee',`${formatUnits(r.fee,8)} QTC`],['Submission',transportKind==='gateway'?'Final submission through the official gateway after durable confirmation; uncertain outcomes remain reserved.':'Signed transaction is disclosed to the selected node after confirmation; unresolved submissions remain reserved.']]};
   }catch(e){await r?.cancel();throw e;}finally{s.preparing=false;}
  },
  async prepareResubmit(hash){const s=active();await ready(s);const node=transport(s);if(s.preparing||s.confirming||s.reviews.size)throw Error('A QTC operation is already active.');const row=s.activity.rows().find(r=>r.hash===hash);if(!row)throw Error('QTC transaction record is unavailable.');s.preparing=true;let r;
   try{r=await prepareQtcRecovery({row,observe:node.observe.bind(node),broadcast:node.broadcast.bind(node),signal:s.abort.signal});current(s);const id=String(++next);s.reviews.set(id,r);return {id,chain:'qtc',network:s.network.id,from:r.from,to:r.to,symbol:'QTC',amount:formatUnits(r.amount,8),fee:formatUnits(r.fee,8),hash:r.hash,expiresAt:r.expiresAt,resubmission:true,review:[['Action','Resubmit EXACTLY the previously signed transaction; no new signature'],['Transaction ID',r.hash],['Network',`QTC ${s.network.id}`],['From',r.from],['To',r.to],['Amount',`${formatUnits(r.amount,8)} QTC`],['Fee',`${formatUnits(r.fee,8)} QTC`],['Privacy','Manual rebroadcast can disclose transaction origin to peers.']]};}catch(e){r?.cancel();throw e;}finally{s.preparing=false;}
  },
  async cancelSend(id){const s=active(),r=s.reviews.get(id);s.reviews.delete(id);await r?.cancel();return true;},
  async confirmSend(id){const s=active();await ready(s);const r=s.reviews.get(id);if(!r)throw Error('QTC review is missing or consumed.');s.reviews.delete(id);if(s.confirming||(!r.isRecovery&&unresolved(s))){await r.cancel();throw Error('A previous QTC submission is unresolved.');}s.confirming=true;let root,row,proof,gatewayPosted=false;
   try{const node=transport(s);current(s);if(!r.isRecovery)root=deriveRoot(getWalletKeys().getRecoveryPhrase(),'qtc');
    const signing=r.signAfterConfirmation({root,signWasmBytes,receiveWasmBytes,
     persistPending:async details=>{current(s);({record:row,proof}=await s.activity.appendQtcPendingWithProof(r,details));await s.activity.persist();current(s);},
     simulate:args=>{current(s);return node.simulate(args);}});root?.fill(0);root=null;const signed=await signing;
    current(s);gatewayPosted=true;const hash=await node.broadcast({raw:signed.raw,txid:signed.txid,networkId:s.network.id,signal:s.abort.signal});current(s);if(hash!==signed.txid)throw Error('QTC submission returned a different transaction ID.');return hash;
   }catch(e){if(transportKind==='gateway'&&!gatewayPosted&&!r.isRecovery&&e instanceof Error)e.qtcNotExposed=true;if(proof&&!gatewayPosted&&e.qtcNotExposed===true&&!r.isRecovery)await commitSubmissionProof(storage,proof).catch(()=>{});if(row&&session===s&&!lockCoordinator.isLocked){row.status=!gatewayPosted&&e.qtcNotExposed===true&&!r.isRecovery?'failed':'unknown';if(row.status==='failed')row.notSubmitted=true;row.note=row.notSubmitted?'Authenticated cancellation before any signed transaction disclosure.':'Signed QTC transaction may have reached the node; inputs remain reserved.';await s.activity.persist().catch(()=>{});}throw e;}
   finally{root?.fill(0);await r.cancel();s.confirming=false;}
  },
  async reconcile(){const s=active();await ready(s);const node=transport(s);for(const row of s.activity.rows()){if(['confirmed','failed'].includes(row.status))continue;const result=await node.observe({hash:row.hash,networkId:s.network.id,signal:s.abort.signal});current(s);if(result?.status==='confirmed'&&result.hash===row.hash){row.status='confirmed';await s.activity.persist();}}return true;}
 };
}

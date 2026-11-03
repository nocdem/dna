import {verifyIxiosSignedTransfer} from '../../../src/pq/ixios/verify.js';
import {verifyTidecoinSignedPayload} from '../../../src/pq/tidecoin-recovery.js';
import { createSubmissionProof, clearSubmissionProofs, recoverSubmissionProofs as recoverProofs } from '../../../src/pq/submission-proof.js';
import { ACTIVITY_KEY, HISTORY_KEY, VAULT_KEY } from '../../../src/vault.js';
import { recordActivity, terminal, publicActivityRow } from '../../../src/activity.js';
import { parseActivity, serializeActivity, parseHistory, serializeHistory } from '../../../src/activity-storage.js';
import { endpointUrl, formatUnits } from '../../../src/core.js';

// Cross-session Tidecoin writes share one queue per storage bucket. A lock
// may happen during storage.set; the next unlock waits for that write to settle.
const tidecoinWrites = new Map(), ixiosWrites = new Map();

// src/activity.js:33-35 has no network field. activity-storage.js:258-262
// omits endpoint/network on save; :367 restores the mainnet endpoint. Keep
// the unchanged encrypted formats under separate testnet storage keys, then
// restore only the endpoint belonging to that bucket. Mainnet keeps the
// pre-existing shared keys in nodus.js, so old sends remain mainnet sends.
export function createNetworkActivity({ chain, network, session: s, storage, current, onActivityChanged, tidecoinWasmBytes, ixiosWasmBytes }) {
  const activityKey = `${ACTIVITY_KEY}.${chain}.${network.id}`, historyKey = `${HISTORY_KEY}.${chain}.${network.id}`;
  let rows = [], page = null, blocked = false, error = '', writes = Promise.resolve();const tidecoinReplacements=new Map(),ixiosReplacements=new Map();
  async function checkedRows(value) {
    if (value.some(row => row.chain !== chain || (['splendor','asentum','ckb','xion','qtc','tidecoin','ixios'].includes(chain) && row.networkId !== network.id))) throw new Error('Saved activity belongs to a different chain.');
    if(chain==='ixios')for(const row of value)if(row.signedPayload!==undefined){await verifyIxiosSignedTransfer(row.signedPayload.data,{wasmBytes:ixiosWasmBytes});current();}
    if(chain==='tidecoin')for(const row of value)if(row.signedPayload!==undefined){await verifyTidecoinSignedPayload(row,{wasmBytes:tidecoinWasmBytes});current();}
    return value.map(row => ({ ...row, ...((chain==='tidecoin'||chain==='ixios')&&row.notSubmitted===true&&row.savedStatus==='failed'?{status:'failed',note:'Authenticated cancellation: this attempt was not submitted.'}:{}), endpoint: network.endpoint }));
  }
  const ready = (async () => {
    if(chain==='ixios'){await (ixiosWrites.get(activityKey)??Promise.resolve()).catch(()=>{});current();}
    if(chain==='tidecoin'){await (tidecoinWrites.get(activityKey)??Promise.resolve()).catch(()=>{});current();}
    const saved = await storage.get([activityKey, historyKey]); current();
    try { rows = await checkedRows(await parseActivity(saved[activityKey], s.id, s.addresses, s.key)); }
    catch (failure) { blocked = true; error = failure.message; }
    current();
    try { page = (await parseHistory(saved[historyKey], s.id, s.historyKey))[chain] ?? null; }
    catch { page = null; }
    current();
    onActivityChanged?.(rows.map(publicActivityRow), { restored: true, network: network.id });
  })();
  ready.catch(() => {});
  function enqueue(work) {
    const prior=chain==='tidecoin'?(tidecoinWrites.get(activityKey)??Promise.resolve()):chain==='ixios'?(ixiosWrites.get(activityKey)??Promise.resolve()):writes;
    const job = prior.catch(() => {}).then(async () => {
      await ready; current();
      const saved = await storage.get([VAULT_KEY, activityKey]); current();
      if (saved[VAULT_KEY] !== s.vault) throw new Error('Wallet storage changed before broadcast. Review the transfer again.');
      return work(saved);
    });
    writes = job;if(chain==='ixios'){ixiosWrites.set(activityKey,job);job.finally(()=>{if(ixiosWrites.get(activityKey)===job)ixiosWrites.delete(activityKey);}).catch(()=>{});}if(chain==='tidecoin'){tidecoinWrites.set(activityKey,job);job.finally(()=>{if(tidecoinWrites.get(activityKey)===job)tidecoinWrites.delete(activityKey);}).catch(()=>{});}return job;
  }
  async function appendWithProof(row) {
    current();
    const proof = await createSubmissionProof({ id: s.id, row, key: s.key });
    current(); // no pending row is visible or persisted before the proof exists
    // A new reviewed attempt of identical bytes has the same hash but a fresh
    // submissionId; old cancellation proofs must not release its reservation.
    rows = rows.filter(old => old.hash !== row.hash); rows.push(row);
    return { record: row, proof };
  }
  return { ready,
    get client() { current(); return s.client; },
    error() { current(); return error; },
    get blocked() { return blocked; },
    assertSendable() {
      current();
      if (blocked) throw new Error('Saved activity is unverified. Check the explorer and discard the unreadable history before sending.');
      if(chain==='ckb'&&(!s.vault||!s.key))throw new Error('A saved unlocked wallet is required for durable CKB holds.');
    },
    rows() { current(); return rows.filter(row => row.address === s.addresses[chain]); },
    append(transfer, details) {
      current();
      if (transfer.chain !== chain || transfer.from !== s.addresses[chain] || endpointUrl(transfer.endpoint) !== endpointUrl(network.endpoint)) throw new Error('Invalid activity owner or network.');
      const row = recordActivity(transfer, details); rows.push(row); return row;
    },
    async appendSubmissionWithProof(transfer, details) {
      current();
      if (!['soqucoin','splendor'].includes(chain) || transfer.chain !== chain || transfer.from !== s.addresses[chain] || endpointUrl(transfer.endpoint) !== endpointUrl(network.endpoint)) throw new Error('Invalid submission owner or network.');
      return appendWithProof(recordActivity(transfer, details));
    },
    async recoverSubmissionProofs() {
      await ready; current();
      try {
        const recovered = await recoverProofs({ storage, id: s.id, rows, key: s.key, addresses: s.addresses }); current();
        if (recovered.some((row, index) => row !== rows[index])) { rows = recovered; await this.persist(); }
      } catch (failure) { current(); blocked = true; error = failure.message; throw failure; }
    },
    async appendIxiosPendingWithProof(review,details) {
      current();if(chain!=='ixios'||network.id!=='mainnet'||!s.vault||!s.key||details.networkId!=='mainnet'||details.from!==s.addresses.ixios||review.from!==details.from||review.to!==details.to||review.amount.toString()!==details.amountAtoms||review.fee.toString()!==details.feeAtoms||review.nonce.toString()!==details.nonce||review.gasPrice.toString()!==details.gasPrice||review.gasLimit.toString()!==details.gasLimit)throw Error('Invalid Ixios pending owner or review.');
      return appendWithProof(recordActivity({chain:'ixios',from:details.from,to:details.to,symbol:'IXIOS',amount:formatUnits(BigInt(details.amountAtoms),18),endpoint:network.endpoint},details));
    },
    rotateIxiosPending(review,details) {
      current();if(chain!=='ixios'||network.id!=='mainnet'||!s.vault||!s.key||details.from!==s.addresses.ixios||review.hash!==details.hash||review.from!==details.from||review.to!==details.to||review.amountAtoms!==details.amountAtoms||review.feeAtoms!==details.feeAtoms||review.nonce!==details.nonce||review.gasPrice!==details.gasPrice||review.gasLimit!==details.gasLimit)throw Error('Invalid Ixios recovery owner or review.');const matches=rows.filter(row=>row.hash===details.hash);if(matches.length!==1||matches[0].submissionId!==details.previousSubmissionId||matches[0].notSubmitted===true||!['pending','unknown'].includes(matches[0].status))throw Error('Ixios recovery attempt changed.');
      const row=recordActivity({chain:'ixios',from:details.from,to:details.to,symbol:'IXIOS',amount:formatUnits(BigInt(details.amountAtoms),18),endpoint:network.endpoint},details);ixiosReplacements.set(row.hash,matches[0].submissionId);rows=rows.map(old=>old===matches[0]?row:old);return row;
    },
    async appendTidecoinPendingWithProof(review,details) {
      current();if(chain!=='tidecoin'||network.id!=='mainnet'||!s.vault||!s.key||details.networkId!=='mainnet'||details.from!==s.addresses.tidecoin||review.from!==details.from||review.to!==details.to||review.amountAtoms!==details.amountAtoms||review.feeAtoms!==details.feeAtoms||review.changeAtoms!==details.changeAtoms||review.maxBytes!==details.maxBytes||JSON.stringify(review.outpoints)!==JSON.stringify(details.outpoints))throw Error('Invalid Tidecoin pending owner or review.');
      const transfer={chain:'tidecoin',from:details.from,to:details.to,symbol:'TDC',amount:formatUnits(BigInt(details.amountAtoms),8)};return appendWithProof(recordActivity(transfer,details));
    },
    rotateTidecoinPending(review,details) {
      current();if(chain!=='tidecoin'||network.id!=='mainnet'||!s.vault||!s.key||details.from!==s.addresses.tidecoin||review.hash!==details.hash||review.from!==details.from||review.to!==details.to||review.amountAtoms!==details.amountAtoms||review.feeAtoms!==details.feeAtoms)throw Error('Invalid Tidecoin recovery owner or review.');const matches=rows.filter(row=>row.hash===details.hash);if(matches.length!==1||matches[0].submissionId!==details.previousSubmissionId||matches[0].notSubmitted===true||!['pending','unknown'].includes(matches[0].status))throw Error('Tidecoin recovery attempt changed.');
      const transfer={chain:'tidecoin',from:details.from,to:details.to,symbol:'TDC',amount:formatUnits(BigInt(details.amountAtoms),8)},row=recordActivity(transfer,details);tidecoinReplacements.set(row.hash,matches[0].submissionId);rows=rows.map(old=>old===matches[0]?row:old);return row;
    },
    async appendQtcPendingWithProof(review,details) {
      current();
      if(chain!=='qtc'||details.networkId!==network.id||details.from!==s.addresses.qtc||review.from!==details.from||review.to!==details.to||review.amount!==details.amount||review.fee!==details.fee||!Array.isArray(review.outpoints)||JSON.stringify(review.outpoints)!==JSON.stringify(details.outpoints))throw new Error('Invalid QTC pending owner or review.');
      const transfer={chain:'qtc',networkId:details.networkId,from:details.from,to:details.to,symbol:'QTC',amount:formatUnits(BigInt(details.amount),8),endpoint:network.endpoint};
      return appendWithProof(recordActivity(transfer,{...details,hash:details.txid}));
    },
    appendQtcPending(review, details) {
      current();
      if(chain!=='qtc'||details.networkId!==network.id||details.from!==s.addresses.qtc||review.from!==details.from||review.to!==details.to||review.amount!==details.amount||review.fee!==details.fee||!Array.isArray(review.outpoints)||JSON.stringify(review.outpoints)!==JSON.stringify(details.outpoints))throw new Error('Invalid QTC pending owner or review.');
      const transfer={chain:'qtc',networkId:details.networkId,from:details.from,to:details.to,symbol:'QTC',amount:formatUnits(BigInt(details.amount),8),endpoint:network.endpoint};
      const row=recordActivity(transfer,{...details,hash:details.txid});rows.push(row);return row;
    },
    async appendXionPendingWithProof(review,details) {
      current();
      if(chain!=='xion'||details.networkId!==network.id||details.from!==s.addresses.xion||review.from!==details.from||review.to!==details.to||review.amountAtoms!==details.amountAtoms||review.feeAtoms!==details.feeAtoms||review.gasLimit!==details.gasLimit||review.sequence!==details.sequence||review.accountNumber!==details.accountNumber||review.timeoutHeight!==details.timeoutHeight)throw new Error('Invalid XION pending owner or review.');
      return appendWithProof(recordActivity({chain:'xion',networkId:details.networkId,from:details.from,to:details.to,symbol:'XION',amount:formatUnits(BigInt(details.amountAtoms),6),endpoint:network.endpoint},details));
    },
    async appendCkbPendingWithProof(review,details) {
      current();
      if(chain!=='ckb'||!s.vault||!s.key||details.networkId!==network.id||details.from!==s.addresses.ckb||review.from!==details.from||review.to!==details.to||review.amount!==details.amount||review.fee!==details.fee||!Array.isArray(review.outpoints)||JSON.stringify(review.outpoints)!==JSON.stringify(details.outpoints)||JSON.stringify(review.inputCapacities)!==JSON.stringify(details.inputCapacities))throw new Error('Invalid CKB pending owner or review.');
      const transfer={chain:'ckb',networkId:details.networkId,from:details.from,to:details.to,symbol:'CKB',amount:formatUnits(BigInt(details.amount),8),endpoint:network.endpoint};
      return appendWithProof(recordActivity(transfer,{...details,hash:details.txid}));
    },
    appendCkbPending(review, details) {
      current();
      if(chain!=='ckb'||!s.vault||!s.key||details.networkId!==network.id||details.from!==s.addresses.ckb||review.from!==details.from||review.to!==details.to||review.amount!==details.amount||review.fee!==details.fee||!Array.isArray(review.outpoints)||JSON.stringify(review.outpoints)!==JSON.stringify(details.outpoints)||JSON.stringify(review.inputCapacities)!==JSON.stringify(details.inputCapacities))throw new Error('Invalid CKB pending owner or review.');
      const matches=rows.filter(old=>old.hash===details.txid);
      if(review.hash!==details.txid||typeof details.previousSubmissionId!=='string'||matches.length!==1||matches[0].submissionId!==details.previousSubmissionId||matches[0].notSubmitted===true||!['pending','unknown'].includes(matches[0].status))throw new Error('CKB recovery attempt changed.');
      const transfer={chain:'ckb',networkId:details.networkId,from:details.from,to:details.to,symbol:'CKB',amount:formatUnits(BigInt(details.amount),8),endpoint:network.endpoint};
      const row=recordActivity(transfer,{...details,hash:details.txid});rows=rows.map(old=>old===matches[0]?row:old);return row;
    },
    async appendAsentumPendingWithProof(review,details) {
      current();
      if(chain!=='asentum'||network.id!=='testnet'||details.networkId!==network.id||details.from!==s.addresses.asentum||review.from!==details.from||review.to!==details.to||review.amount!==details.amount||review.nonce!==details.nonce||review.gasLimit!==details.gasLimit||review.maxFeePerGas!==details.maxFeePerGas)throw new Error('Invalid Asentum pending owner or review.');
      return appendWithProof(recordActivity({chain:'asentum',from:details.from,to:details.to,symbol:'ASE',amount:formatUnits(BigInt(details.amount),18),endpoint:network.endpoint},details));
    },
    async appendSplendorPendingWithProof(review, details) {
      current();
      if (chain !== 'splendor' || details.networkId !== network.id || details.from !== s.addresses.splendor
          || review.from !== details.from || review.to !== details.to || review.amountAtoms !== details.amount || review.feeAtoms !== details.fee || review.nonce !== details.nonce) throw new Error('Invalid Splendor pending owner or review.');
      const transfer={chain:'splendor',from:details.from,to:details.to,symbol:'SPLD',amount:formatUnits(BigInt(details.amount),18),endpoint:network.endpoint};
      return appendWithProof(recordActivity(transfer,details));
    },
    appendSplendorPending(review, details) {
      current();
      if (chain !== 'splendor' || details.networkId !== network.id || details.from !== s.addresses.splendor
          || review.from !== details.from || review.to !== details.to || review.amountAtoms !== details.amount || review.feeAtoms !== details.fee || review.nonce !== details.nonce) throw new Error('Invalid Splendor pending owner or review.');
      const transfer={chain:'splendor',from:details.from,to:details.to,symbol:'SPLD',amount:formatUnits(BigInt(details.amount),18),endpoint:network.endpoint};
      const row=recordActivity(transfer,details);rows.push(row);return row;
    },
    persist() {
      const notificationRows = rows.map(({ chain, hash, status }) => ({ chain, hash, status }));
      onActivityChanged?.(notificationRows.filter(row => terminal(row.status)), { network: network.id });
      return enqueue(async saved => {
        if (blocked) throw new Error('Saved activity is unverified. Check the explorer and discard the unreadable history before sending.');
        const previous = await checkedRows(await parseActivity(saved[activityKey], s.id, s.addresses, s.key)); current();
        if(chain==='ixios')for(const row of rows){const old=previous.find(p=>p.hash===row.hash);if(old&&old.submissionId!==row.submissionId&&!(ixiosReplacements.get(row.hash)===old.submissionId&&!old.notSubmitted&&!terminal(old.status)))throw Error('Ixios activity attempt changed in another session.');if(!terminal(row.status)&&previous.some(p=>p.address===row.address&&p.hash!==row.hash&&!terminal(p.status)&&!rows.some(local=>local.hash===p.hash&&terminal(local.status))))throw Error('Another Ixios submission is unresolved in another session.');}
        if(chain==='tidecoin')for(const row of rows){const old=previous.find(p=>p.hash===row.hash);if(old&&old.submissionId!==row.submissionId&&!(tidecoinReplacements.get(row.hash)===old.submissionId&&!old.notSubmitted&&!terminal(old.savedStatus??old.status)))throw Error('Tidecoin activity attempt changed in another session.');if(!terminal(row.status)&&previous.some(p=>p.address===row.address&&p.hash!==row.hash&&!terminal(p.savedStatus??p.status)&&!rows.some(local=>local.hash===p.hash&&terminal(local.status))))throw Error('Another Tidecoin submission is unresolved in another session.');}
        const combined = [...new Map([...previous, ...rows].map(row => [row.hash, row])).values()]
          .sort((a, b) => Date.parse(a.createdAt) - Date.parse(b.createdAt) || (a.hash < b.hash ? -1 : a.hash > b.hash ? 1 : 0));
        const encrypted = await serializeActivity(s.id, combined, s.key); current();
        await storage.set({ [activityKey]: encrypted }); current();if(chain==='ixios'){rows=combined;ixiosReplacements.clear();}if(chain==='tidecoin'){rows=combined;tidecoinReplacements.clear();}
        await clearSubmissionProofs(storage, s.id, combined).catch(() => {}); current();
        onActivityChanged?.(notificationRows, { network: network.id });
      });
    },
    history() { current(); return page?.address === s.addresses[chain] ? page : null; },
    saveHistory(value) {
      current(); page = value;
      return enqueue(async () => {
        const encrypted = await serializeHistory(s.id, { [chain]: page }, s.historyKey); current();
        await storage.set({ [historyKey]: encrypted }); current();
      });
    },
    discard() {
      return enqueue(async saved => {
        if (!blocked) return;
        const previous = saved[activityKey];
        const encrypted = await serializeActivity(s.id, [], s.key); current();
        // Same post-encryption check as nodus.js discardActivity and
        // web-wallet/src/app.js:2684: do not overwrite changed saved activity.
        const latest = await storage.get([VAULT_KEY, activityKey]); current();
        if (saved[VAULT_KEY] !== s.vault || latest[VAULT_KEY] !== s.vault || latest[activityKey] !== previous) throw new Error('Wallet or history changed. Unlock again before discarding history.');
        await storage.set({ [activityKey]: encrypted }); current();
        rows = []; blocked = false; error = '';
      });
    },
  };
}

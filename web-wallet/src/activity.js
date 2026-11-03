import {validIxiosPending,validateIxiosSignedPayload} from './pq/ixios/pending.js';
import {observeIxiosSubmission} from './pq/ixios/observe.js';
import {validateTidecoinFundingEvidence,validateTidecoinSignedPayload} from './pq/tidecoin-recovery.js';
import {validateCkbSignedPayload} from './pq/ckb-signed-payload.js';
import {validateQtcSignedPayload} from './pq/qtc-signed-payload.js';
import {validQtcPending} from './pq/qtc-pending.js';
import {observeCkbSubmission} from './pq/ckb-preflight.js';
import {validXionPending,validateXionSignedPayload} from './pq/xion-recovery.js';
import {observeXionSubmission} from './pq/xion-transfer.js';
import {validCkbPending} from './pq/ckb-pending.js';
import {asentumTransferBody} from './pq/asentum-sign.js';
import {validateAsentumSignedPayload} from './pq/asentum-recovery.js';
import {observeAsentumSubmission} from './pq/asentum-transfer.js';
import { CHAINS } from './config.js';
import { rpc, request, endpointUrl, formatUnits } from './core.js';
import { observeSplendorSubmission } from './pq/splendor-transfer.js';
import { splendorTransferBody } from './pq/splendor-transfer-body.js';
import { validateSplendorSignedPayload } from './pq/splendor-recovery.js';
import { validateSoquSignedPayload } from './pq/soqu-signed-payload.js';
import { reconcileSoquSubmission } from './pq/soqu-transfer.js';
import { observeAlgorandSubmission } from './pq/algorand-transfer.js';
export const terminal = status => ['confirmed', 'failed', 'expired', 'replaced', 'abandoned'].includes(status);
// NODUS (src/nodus/network.js NODUS_ASSET.chain): the record's `hash` is the
// envelope's 64-byte intent_id (128 hex) — stable across the hedged signature,
// unlike wire_id (design §2 D7).
const NODUS_CHAIN = 'nodus', HEX128 = /^[0-9a-f]{128}$/, HEIGHT = /^[1-9]\d{0,19}$/;
export function validHash(chain, hash) {
  return typeof hash === 'string' && ((chain === 'splendor' || chain === 'xion' || chain === 'qtc' || chain === 'tidecoin') ? /^[0-9a-f]{64}$/.test(hash) : chain === 'algorand' ? /^[A-Z2-7]{52}$/.test(hash) : chain === NODUS_CHAIN ? HEX128.test(hash) : chain === 'solana' ? /^[1-9A-HJ-NP-Za-km-z]{80,90}$/.test(hash) : (chain === 'tron' || chain === 'soqucoin') ? /^[0-9a-f]{64}$/i.test(hash) : /^0x[0-9a-f]{64}$/i.test(hash));
}
// A NODUS pending send keeps what the resend rule needs
// (docs/plans/2026-09-26-note-to-web-wallet-session-expiry.md item 3):
// expiryHeight, the first block scanned for it (fromHeight = tip + 1 at build),
// and its input nullifiers (1..15, nodus/tools/nodus-cli.c:2778 T6_SPEND_MAX_IN).
export function validNodusPending({ expiryHeight, fromHeight, inputs }) {
  return typeof expiryHeight === 'string' && HEIGHT.test(expiryHeight) && BigInt(expiryHeight) < 2n ** 64n
    && typeof fromHeight === 'string' && HEIGHT.test(fromHeight) && BigInt(fromHeight) <= BigInt(expiryHeight)
    && Array.isArray(inputs) && inputs.length >= 1 && inputs.length <= 15 && new Set(inputs).size === inputs.length
    && inputs.every(input => typeof input === 'string' && HEX128.test(input));
}
// The symbol an Activity row is shown with. A NODUS row with a tokenId is a
// pinned token's send: while the pinned list is known (`known`: the send
// module reported it) a tokenId that is not in it — a pin removed in a later
// build — is shown as "unknown token", its row KEPT and its coins still held
// (src/adapters/nodus.js lockedInputs is by chain, not by token); while the
// list is not known the symbol the row was saved with stands. A row without
// a tokenId is a native row: its own symbol.
export function activitySymbol(row, tokens = [], known = false) {
  if (row.chain !== NODUS_CHAIN || typeof row.tokenId !== 'string') return row.symbol;
  const pin = tokens.find(t => t.tokenId === row.tokenId);
  return pin ? pin.symbol : known ? 'unknown token' : row.symbol;
}
export function validSoquPending({ inputs }) {
  return Array.isArray(inputs) && inputs.length >= 1 && inputs.length <= 80
    && inputs.every(input => input && /^[0-9a-f]{64}$/.test(input.txid) && Number.isSafeInteger(input.vout) && input.vout >= 0 && input.vout <= 0xffffffff)
    && new Set(inputs.map(input => `${input.txid}:${input.vout}`)).size === inputs.length;
}
export function validSplendorPending(p) {
  try {
    if (!p || !['mainnet','testnet'].includes(p.networkId) || !validHash('splendor',p.hash) || typeof p.submissionId!=='string' || !/^[0-9a-f]{32}$/.test(p.submissionId) || p.amountAtoms === '0') return false;
    splendorTransferBody({networkId:p.networkId,from:p.address,to:p.to,amount:p.amountAtoms,fee:p.feeAtoms,nonce:p.nonce,timestamp:'1'});
    return true;
  } catch { return false; }
}
export function validAsentumPending(p) {
 try { if(!p || p.networkId!=='testnet' || !/^0x[0-9a-f]{64}$/.test(p.hash) || !/^[0-9a-f]{32}$/.test(p.submissionId) || p.gasLimit!=='21000') return false;
 asentumTransferBody({networkId:p.networkId,from:p.address,to:p.to,amount:p.amountAtoms,nonce:p.nonce,gasLimit:p.gasLimit,maxFeePerGas:p.maxFeePerGas}); return true; } catch { return false; }
}
export function recordActivity(transfer, details) {
  if (!validHash(transfer.chain, details.hash)) throw new Error('Invalid transaction identifier.');
  const record = { chain: transfer.chain, address: transfer.from, to: transfer.to, symbol: transfer.symbol, amount: transfer.amount, endpoint: transfer.endpoint, hash: details.hash, lastValidBlockHeight: details.lastValidBlockHeight, expiration: details.expiration, nonce: details.nonce, createdAt: new Date().toISOString(), status: 'pending', note: 'Broadcast outcome pending.' };
  if (transfer.chain === 'ixios') {
    Object.assign(record,{networkId:details.networkId,amountAtoms:details.amountAtoms,feeAtoms:details.feeAtoms,gasLimit:details.gasLimit,gasPrice:details.gasPrice,nonce:details.nonce,submissionId:Array.from(crypto.getRandomValues(new Uint8Array(16)),b=>b.toString(16).padStart(2,'0')).join('')});
    if(details.signedPayload!==undefined)record.signedPayload={encoding:details.signedPayload.encoding,data:details.signedPayload.data};
    if(!validIxiosPending(record)||details.from!==transfer.from||details.to!==transfer.to||transfer.symbol!=='IXIOS'||transfer.amount!==formatUnits(BigInt(details.amountAtoms),18))throw Error('Invalid pending Ixios transfer.');
    if(record.signedPayload!==undefined)validateIxiosSignedPayload(record);
  }
  if (transfer.chain === 'tidecoin') {
    Object.assign(record,{networkId:details.networkId,amountAtoms:details.amountAtoms,feeAtoms:details.feeAtoms,changeAtoms:details.changeAtoms,maxBytes:details.maxBytes,snapshot:structuredClone(details.snapshot),outpoints:structuredClone(details.outpoints),funding:structuredClone(details.funding),submissionId:Array.from(crypto.getRandomValues(new Uint8Array(16)),b=>b.toString(16).padStart(2,'0')).join('')});
    validateTidecoinFundingEvidence(record);if(details.signedPayload!==undefined){record.signedPayload={encoding:details.signedPayload.encoding,data:details.signedPayload.data};validateTidecoinSignedPayload(record);}
    if(details.from!==transfer.from||details.to!==transfer.to||transfer.symbol!=='TDC'||transfer.amount!==formatUnits(BigInt(details.amountAtoms),8))throw Error('Invalid pending Tidecoin transfer.');
  }
  if (transfer.chain === 'algorand') record.submissionId=Array.from(crypto.getRandomValues(new Uint8Array(16)),b=>b.toString(16).padStart(2,'0')).join('');
  if (transfer.chain === 'qtc') {
    Object.assign(record,{networkId:details.networkId,amountAtoms:details.amount,feeAtoms:details.fee,inputs:Array.isArray(details.outpoints)?[...details.outpoints]:details.outpoints,submissionId:Array.from(crypto.getRandomValues(new Uint8Array(16)),b=>b.toString(16).padStart(2,'0')).join('')});
    if(details.signedPayload!==undefined)record.signedPayload={encoding:details.signedPayload.encoding,data:details.signedPayload.data};
    if(!validQtcPending(record)||details.from!==transfer.from||details.to!==transfer.to||transfer.symbol!=='QTC'||(transfer.networkId!==undefined&&transfer.networkId!==details.networkId)||transfer.amount!==formatUnits(BigInt(details.amount),8)||details.state!=='signed-exposure-pending')throw new Error('Invalid pending QTC transfer.');
    if(record.signedPayload!==undefined)validateQtcSignedPayload(record);
  }
  if (transfer.chain === 'xion') {
    Object.assign(record,{networkId:details.networkId,amountAtoms:details.amountAtoms,feeAtoms:details.feeAtoms,gasLimit:details.gasLimit,sequence:details.sequence,accountNumber:details.accountNumber,...(details.timeoutHeight!==undefined?{timeoutHeight:details.timeoutHeight}:{}),submissionId:Array.from(crypto.getRandomValues(new Uint8Array(16)),b=>b.toString(16).padStart(2,'0')).join('')});
    if(details.signedPayload!==undefined)record.signedPayload={encoding:details.signedPayload.encoding,data:details.signedPayload.data};
    if(!validXionPending(record)||details.from!==transfer.from||details.to!==transfer.to||transfer.symbol!=='XION'||(transfer.networkId!==undefined&&transfer.networkId!==details.networkId)||transfer.amount!==formatUnits(BigInt(details.amountAtoms),6))throw new Error('Invalid pending XION transfer.');
    if(record.signedPayload!==undefined)validateXionSignedPayload(record);
  }
  if (transfer.chain === 'ckb') {
    Object.assign(record,{networkId:details.networkId,amountAtoms:details.amount,feeAtoms:details.fee,inputs:Array.isArray(details.outpoints)?[...details.outpoints]:details.outpoints,inputCapacities:Array.isArray(details.inputCapacities)?[...details.inputCapacities]:details.inputCapacities,submissionId:Array.from(crypto.getRandomValues(new Uint8Array(16)),b=>b.toString(16).padStart(2,'0')).join('')});
    if(details.signedPayload!==undefined)record.signedPayload={encoding:details.signedPayload.encoding,data:details.signedPayload.data};
    if(!validCkbPending(record)||details.from!==transfer.from||details.to!==transfer.to||transfer.symbol!=='CKB'||(transfer.networkId!==undefined&&transfer.networkId!==details.networkId)||transfer.amount!==formatUnits(BigInt(details.amount),8)||details.state!=='signed-exposure-pending')throw new Error('Invalid pending CKB transfer.');
    if(record.signedPayload!==undefined)validateCkbSignedPayload(record);
  }
  if (transfer.chain === 'asentum') {
    Object.assign(record,{networkId:details.networkId,amountAtoms:details.amount,nonce:details.nonce,gasLimit:details.gasLimit,maxFeePerGas:details.maxFeePerGas,submissionId:Array.from(crypto.getRandomValues(new Uint8Array(16)),b=>b.toString(16).padStart(2,'0')).join('')});
    if(details.signedPayload!==undefined){record.signedPayload={encoding:details.signedPayload.encoding,data:details.signedPayload.data};validateAsentumSignedPayload(record);}
    if(!validAsentumPending(record)||details.from!==transfer.from||details.to!==transfer.to||transfer.symbol!=='ASE'||transfer.amount!==formatUnits(BigInt(details.amount),18))throw new Error('Invalid pending Asentum transfer.');
  }
  if (transfer.chain === 'splendor') {
    const submissionId=Array.from(crypto.getRandomValues(new Uint8Array(16)),b=>b.toString(16).padStart(2,'0')).join('');
    Object.assign(record,{networkId:details.networkId,amountAtoms:details.amount,feeAtoms:details.fee,nonce:details.nonce,submissionId});
    if(details.signedPayload!==undefined){record.timestamp=details.timestamp;record.signedPayload={encoding:details.signedPayload?.encoding,data:details.signedPayload?.data};validateSplendorSignedPayload(record);}
    if (!validSplendorPending(record) || details.from !== transfer.from || details.to !== transfer.to || transfer.symbol !== 'SPLD' || (transfer.networkId !== undefined && details.networkId !== transfer.networkId) || transfer.amount !== formatUnits(BigInt(details.amount),18)) throw new Error('Invalid pending Splendor transfer.');
  }
  if (transfer.chain === 'soqucoin') {
    if (!validSoquPending(details)) throw new Error('Invalid SOQ consumed outpoints.');
    record.inputs = details.inputs.map(({txid, vout}) => ({txid, vout}));
    record.submissionId=Array.from(crypto.getRandomValues(new Uint8Array(16)),b=>b.toString(16).padStart(2,'0')).join('');
    if(details.feeAtoms!==undefined){if(typeof details.feeAtoms!=='string'||!/^[1-9]\d{0,8}$/.test(details.feeAtoms)||BigInt(details.feeAtoms)>200000000n||(transfer.feeAtoms!==undefined&&transfer.feeAtoms!==details.feeAtoms))throw new Error('Invalid SOQ fee.');record.feeAtoms=details.feeAtoms;}
    if(details.signedPayload!==undefined){if(typeof details.signedPayload?.data!=='string'||details.signedPayload.data.length>120000)throw new Error('SOQ signed recovery payload is too large.');record.signedPayload={encoding:details.signedPayload.encoding,data:details.signedPayload.data};validateSoquSignedPayload(record);}
  }
  if (transfer.chain === NODUS_CHAIN) {
    if (!validNodusPending(details)) throw new Error('Invalid pending transfer record.');
    Object.assign(record, { expiryHeight: details.expiryHeight, fromHeight: details.fromHeight, inputs: [...details.inputs] });
    // A pinned token's send (design docs/plans/2026-10-22-connect-native-
    // tokens-design.md §6 item 7): the token id, kept with the saved row. A
    // NODUS send — the all-zero id, or none — carries no tokenId: the saved
    // format of a native row is unchanged, and a row without one is a
    // native row.
    if (typeof transfer.tokenId === 'string' && HEX128.test(transfer.tokenId) && transfer.tokenId !== '0'.repeat(128)) record.tokenId = transfer.tokenId;
    // The signed envelope's full-wire id (0.1.78, src/adapters/nodus.js
    // builtWire), when the module gave one: this tab only — the saved
    // Activity format is unchanged (src/activity-storage.js does not write
    // it). It lets the node's account history show this send once
    // (src/nodus/history.js localRowsToShow).
    if (typeof details.wire === 'string' && HEX128.test(details.wire)) record.wire = details.wire;
    // Staking (0.1.29): which action, for this tab's Activity text only —
    // src/activity-storage.js does not keep it, so a reloaded row reads as
    // a plain NODUS transfer to the validator's address.
    if (['delegate', 'undelegate', 'stake'].includes(transfer.kind)) record.kind = transfer.kind;
    // A chain-name registration (HF-4): the action and the name, for this
    // tab's Activity text only (not kept by src/activity-storage.js either;
    // reloaded, it reads as a NODUS transfer to this wallet's own address).
    if (transfer.kind === 'name') { record.kind = 'name'; record.name = transfer.name; }
  }
  return record;
}
// A smart-contract row's text (src/app.js renderActivity; the row is made by
// recordEvmActivity, its fields come from src/evm/ui.js showReview): what
// happened in plain words, the NODUS it moved and the network fee, each on
// its own — never their sum. `evmOp`: deposit | withdraw | redeem | call |
// create; `evmMoved` / `evmFee`: decimal NODUS texts; `evmTo`: the Nodus
// address a withdraw / redeem pays ('' otherwise); `address`: this wallet's
// own Nodus address. A row without `evmOp` (none is made today) falls back
// to the panel's title and the stored amount, as before.
// -> { amount: the bold amount text, what: the line below it }
const EVM_ACTION = { deposit: 'Moved to smart contracts', withdraw: 'Moved back', redeem: 'Ticket collected', call: 'Contract call', create: 'Contract deployment' };
const DECIMAL = /^\d{1,78}(\.\d{1,18})?$/;
export function evmActivityText({ evmOp, evmMoved, evmFee, evmTo, evmTitle, amount, symbol = 'NODUS', address } = {}) {
  if (!Object.hasOwn(EVM_ACTION, evmOp) || !DECIMAL.test(evmMoved ?? '') || !DECIMAL.test(evmFee ?? '')) {
    return { amount: `${amount} ${symbol}`, what: `Smart contracts · ${evmTitle || 'transaction'}` };
  }
  const paysOther = (evmOp === 'withdraw' || evmOp === 'redeem') && typeof evmTo === 'string' && evmTo !== '' && evmTo !== address;
  const action = `${EVM_ACTION[evmOp]}${paysOther ? ` to ${evmTo}` : ''}`;
  // A call or deployment that sends no value costs only its fee.
  if (/^0+(\.0+)?$/.test(evmMoved)) return { amount: `${evmFee} ${symbol}`, what: `Smart contracts · ${action} · network fee only` };
  return { amount: `${evmMoved} ${symbol}`, what: `Smart contracts · ${action} · fee ${evmFee} ${symbol}` };
}
export async function checkActivity(row, { signal, call = rpc, post = request, fetcher } = {}) {
  if(row.chain==='ixios') {if(!validIxiosPending(row))throw Error('Invalid Ixios activity.');if(row.notSubmitted===true)return {status:'failed',note:'Authenticated cancellation before network submission.'};const result=await observeIxiosSubmission(row,{signal,fetcher});return {status:result.state,note:result.state==='confirmed'?'Ixios node reports at least 60 confirmations; reorganization remains possible.':result.state==='failed'?'Ixios node reports a failed transaction at least 60 blocks deep.':'Ixios outcome unresolved; nonce remains held.'};}
  if(row.chain==='qtc') {
    if(!validQtcPending(row))throw new Error('Invalid QTC activity record.');
    if(row.notSubmitted===true)return {status:'failed',note:'Authenticated proof: this attempt was not exposed.'};
    // Explorer absence or mempool rejection is not proof of non-submission.
    return {status:'pending',note:'QTC outcome unresolved; outpoints remain held until independently verified.'};
  }
  if(row.chain==='ckb') {
    if(!validCkbPending(row))throw new Error('Invalid CKB activity record.');
    if(row.notSubmitted===true)return {status:'failed',note:'Authenticated proof: this attempt was not exposed.'};
    const result=await observeCkbSubmission(row,{signal,fetcher});
    return {status:result.state,note:result.state==='confirmed'?'CKB node reports at least 24 confirmations; reorganization remains possible.':'CKB outcome unresolved; held outpoints remain reserved. Do not resend.'};
  }
  if(row.chain==='xion') {
    if(!validXionPending(row))throw new Error('Invalid XION activity record.');
    if(row.notSubmitted===true)return {status:'failed',note:'Cancelled before network submission. Nothing was broadcast.'};
    const result=await observeXionSubmission({networkId:row.networkId,from:row.address,hash:row.hash,signal,fetcher});
    return {status:result.state==='pending'&&row.executionWindowClosed?'unknown':result.state,note:result.state==='confirmed'?'XION transaction reported confirmed.':result.state==='failed'?'XION transaction reported failed.':row.executionWindowClosed?'Configured node reports execution window closed; historical outcome remains unknown.':'XION outcome unresolved; do not resend.'};
  }
  if (row.chain === 'asentum') {
    if(!validAsentumPending(row))throw new Error('Invalid Asentum activity record.');
    if(row.notSubmitted===true)return {status:'failed',note:'Cancelled before network submission. Nothing was broadcast.'};
    const result=await observeAsentumSubmission({networkId:row.networkId,from:row.address,to:row.to,hash:row.hash},{signal,fetcher});
    return {status:result.state==='included'?'pending':result.state,note:result.state==='confirmed'?'ASE transfer reported finalized.':result.state==='failed'?'ASE transaction reported failed.':'ASE outcome unresolved; do not resend.'};
  }
  if (row.chain === 'tidecoin') {validateTidecoinFundingEvidence(row);if(row.notSubmitted===true)return {status:'failed',note:'Cancelled before network submission. Nothing was broadcast.'};return {status:'pending',note:'Tidecoin outcome unresolved; a verified provider is required.'};}
  if (row.chain === 'splendor') {
    if (!validSplendorPending(row)) throw new Error('Invalid Splendor activity record.');
    if (row.notSubmitted === true) return {status:'failed',note:'Cancelled before network submission. Nothing was broadcast.'};
    const result=await observeSplendorSubmission({networkId:row.networkId,from:row.address,to:row.to,amount:row.amountAtoms,fee:row.feeAtoms,nonce:row.nonce,hash:row.hash},{signal,fetcher});
    return {status:result.state,note:result.state==='confirmed'?'SPLD transfer reported confirmed.':result.state==='failed'?'SPLD transaction reported failed.':'SPLD outcome unresolved; do not resend.'};
  }
  if (row.chain === 'soqucoin') {
    if (!validHash(row.chain, row.hash) || !validSoquPending(row)) throw new Error('Invalid SOQ activity record.');
    if (row.notSubmitted === true) return { status: 'failed', note: 'Cancelled before network submission. Nothing was broadcast.' };
    const result = await reconcileSoquSubmission({ hash: row.hash, from: row.address, signal, fetcher });
    return { status: result.state, note: result.state === 'confirmed' ? 'SOQ payment confirmed.' : 'SOQ outcome unresolved; inputs remain reserved. Do not resend.' };
  }
  if (row.chain === 'algorand') {
    if (row.notSubmitted === true) return { status: 'failed', note: 'Cancelled before network submission. Nothing was broadcast.' };
    if (!Number.isSafeInteger(row.lastValidBlockHeight) || row.lastValidBlockHeight <= 0) throw new Error('Invalid Algorand expiry.');
    const result = await observeAlgorandSubmission({ hash: row.hash, from: row.address, lastValid: String(row.lastValidBlockHeight), networkId: 'mainnet' }, { signal, fetcher });
    const status = result.state === 'rejected' ? 'failed' : result.state;
    return { status, note: status === 'confirmed' ? 'Algorand payment confirmed.' : status === 'failed' ? 'Algorand node rejected this payment.' : status === 'expired' ? 'Algorand validity rounds elapsed; this transaction can no longer be included.' : 'Awaiting Algorand confirmation; do not resend.' };
  }
  const c = CHAINS[row.chain], endpoint = row.endpoint;
  const rpcCall = (method, params) => call(endpoint, method, params, { signal });
  const tron = (path, body) => post(`${endpoint.replace(/\/$/, '')}${path}`, body, { signal });
  if (!c || !validHash(row.chain, row.hash)) throw new Error('Invalid activity record.');
  if (row.chain === 'ethereum' || row.chain === 'bsc') {
    if (BigInt(await rpcCall('eth_chainId', [])) !== BigInt(c.chainId)) throw new Error('Wrong network.');
    const receipt = await rpcCall('eth_getTransactionReceipt', [row.hash]);
    if (receipt === null) {
      // A record saved before the nonce field existed (0.1.14 and earlier) has
      // no basis for this check and keeps today's behavior unchanged.
      if (Number.isSafeInteger(row.nonce)) {
        const count = await rpcCall('eth_getTransactionCount', [row.address, 'latest']);
        if (!/^0x[0-9a-f]+$/i.test(count)) throw new Error('Invalid transaction count.');
        if (BigInt(count) > BigInt(row.nonce)) {
          // A transaction that got mined between the two reads above must not be
          // misreported as terminal 'replaced': re-check its own receipt once
          // more before concluding another transaction consumed this nonce.
          const recheck = await rpcCall('eth_getTransactionReceipt', [row.hash]);
          if (recheck === null) return { status: 'replaced', note: 'This transaction number was used by another transaction; this one can no longer be included.' };
          return { status: 'pending', note: 'Inclusion observed; confirming on the next check.' };
        }
      }
      return { status: 'pending', note: 'Not included, or previous inclusion was reorganized. Check explorer before resending.' };
    }
    if (receipt.transactionHash?.toLowerCase() !== row.hash.toLowerCase() || !/^0x[0-9a-f]+$/i.test(receipt.blockNumber) || !/^0x[0-9a-f]{64}$/i.test(receipt.blockHash) || !['0x0', '0x1'].includes(receipt.status)) throw new Error('Invalid transaction receipt.');
    // Observe finality before the last canonical lookup: a reorg between these
    // reads must not turn a stale receipt into a terminal success.
    const finalized = await rpcCall('eth_getBlockByNumber', ['finalized', false]);
    const block = await rpcCall('eth_getBlockByNumber', [receipt.blockNumber, false]);
    if (!block || block.hash?.toLowerCase() !== receipt.blockHash.toLowerCase()) return { status: 'pending', note: 'Inclusion changed; waiting for a canonical receipt.' };
    if (finalized?.number && BigInt(finalized.number) === BigInt(receipt.blockNumber) && finalized.hash?.toLowerCase() !== receipt.blockHash.toLowerCase()) return { status: 'pending', note: 'Finalized block disagrees with the receipt; waiting for consistent network state.' };
    if (!finalized?.number || BigInt(finalized.number) < BigInt(receipt.blockNumber)) return { status: 'included', note: receipt.status === '0x0' ? 'Execution failed; awaiting finality.' : 'Included; awaiting finality.' };
    return { status: receipt.status === '0x1' ? 'confirmed' : 'failed', note: 'Receipt is in a finalized canonical block.' };
  }
  if (row.chain === 'solana') {
    if (await rpcCall('getGenesisHash', []) !== CHAINS.solana.genesisHash) throw new Error('Wrong network.');
    const result = await rpcCall('getSignatureStatuses', [[row.hash], { searchTransactionHistory: true }]);
    if (!Array.isArray(result?.value) || result.value.length !== 1) throw new Error('Invalid signature status.');
    const status = result.value[0];
    if (status) {
      if (!Object.hasOwn(status, 'err') || !['processed', 'confirmed', 'finalized'].includes(status.confirmationStatus)) throw new Error('Unrecognized signature status.');
      if (status.confirmationStatus === 'finalized') return { status: status.err === null ? 'confirmed' : 'failed', note: status.err === null ? 'Finalized on Solana.' : 'Execution failed on Solana (finalized).' };
      return { status: 'included', note: status.err === null ? 'Observed; awaiting finality.' : 'Execution error observed; awaiting finality.' };
    }
    if (Number.isSafeInteger(row.lastValidBlockHeight)) {
      const height = await rpcCall('getBlockHeight', [{ commitment: 'finalized' }]);
      if (!Number.isSafeInteger(height)) throw new Error('Invalid block height.');
      if (height > row.lastValidBlockHeight) return { status: 'unknown', note: 'Blockhash validity ended, but absence from this lookup does not prove failure. Tracking continues; check the explorer before resending.' };
    }
    return { status: 'pending', note: 'No finalized signature found yet.' };
  }
  if (endpointUrl(endpoint) !== endpointUrl(CHAINS.tron.endpoint)) throw new Error('TRON tracking requires the mainnet provider.');
  if ((await tron('/wallet/getblockbynum', { num: 0 })).blockID !== c.genesisHash) throw new Error('Wrong TRON network.');
  const tx = await tron('/walletsolidity/gettransactionbyid', { value: row.hash });
  if (tx.txID) {
    if (tx.txID.toLowerCase() !== row.hash.toLowerCase() || !Array.isArray(tx.ret) || tx.ret.length !== 1 || typeof tx.ret[0].contractRet !== 'string') throw new Error('Invalid solidified transaction.');
    return { status: tx.ret[0].contractRet === 'SUCCESS' ? 'confirmed' : 'failed', note: 'Execution result from a solidified TRON transaction.' };
  }
  if (Object.keys(tx).length) throw new Error('Unrecognized TRON transaction response.');
  return { status: 'pending', note: 'Not solidified. Check explorer before resending; no absence-based failure is assumed.' };
}
// The status line shown after a submission (src/app.js), once the tracker
// (watchActivity below) has stored a network answer on the record. `what`
// names the action ("Delegation", "Transfer", …); `idLabel` is the ID
// sentence's label, or null where the caller shows its own explorer link.
// Returns null while the record is unresolved: the submission text stays.
// "confirmed" comes only from a check that reported the transaction
// included (checkActivity / checkNodusActivity); this never infers it.
// The final statuses other than 'confirmed' (terminal() above), as said in the line.
const FINAL_NOT_CONFIRMED_TEXT = { failed: 'failed', expired: 'expired', replaced: 'was replaced', abandoned: 'was marked abandoned' };
export function submissionStatus(record, { what, idLabel = null }) {
  const id = idLabel ? ` ${idLabel} ${record.hash}.` : '', note = record.note ? ` ${record.note}` : '';
  if (record.status === 'confirmed') {
    // NODUS: the block the scan found it in (src/adapters/nodus.js); the
    // answer comes from one node, and the line says so.
    if (record.block) return `${what} confirmed at block ${record.block}${record.chain === NODUS_CHAIN ? ' (reported by one Nodus node)' : ''}.${id}`;
    return `${what} confirmed.${note}${id}`;
  }
  if (record.status === 'included') return `${what} seen on the network, not final yet.${note}${id}`;
  if (FINAL_NOT_CONFIRMED_TEXT[record.status]) return `${what} ${FINAL_NOT_CONFIRMED_TEXT[record.status]}.${note}${id}`;
  return null;
}
// A tracker never submits transactions. Stop aborts in-flight reads and future polling.
export function watchActivity(rows, onChange, { interval = 12000, check = checkActivity } = {}) {
  const controller = new AbortController(); let timer;
  async function tick() {
    for (const row of rows()) {
      if (controller.signal.aborted) return;
      if (terminal(row.status)) continue;
      try {
        const update = await check(row, { signal: controller.signal });
        if (controller.signal.aborted) return;
        Object.assign(row, update, { checkedAt: new Date().toISOString(), readError: null });
      } catch (error) { if (controller.signal.aborted) return; row.readError = `Status unavailable: ${error.message}`; }
      onChange();
    }
    if (!controller.signal.aborted) timer = setTimeout(tick, interval);
  }
  void tick(); return () => { controller.abort(); clearTimeout(timer); };
}

// Deliberate public projection for extension/UI RPC boundaries. Private
// recovery material (including any future signedPayload/capsule) is never
// copied merely because a new field appears on an internal activity record.
export function publicActivityRow(row) {
  if (!row || typeof row !== 'object') throw new Error('Invalid activity row.');
  return {
    chain:row.chain,address:row.address,to:row.to,symbol:row.symbol,amount:row.amount,
    hash:row.hash,status:row.status,note:row.note,readError:row.readError,createdAt:row.createdAt,
    networkId:row.networkId,lastValidBlockHeight:row.lastValidBlockHeight,expiration:row.expiration,
    nonce:row.nonce,tokenId:row.tokenId,wire:row.wire,kind:row.kind,name:row.name,
    evmOp:row.evmOp,evmMoved:row.evmMoved,evmFee:row.evmFee,evmTo:row.evmTo,evmTitle:row.evmTitle,
  };
}

// Web wallet and Connect CKB send: a page adapter around the controller the trusted
// extension already uses (src/pq/ckb-review-controller.js, extension/src/background/ckb.js).
// No signing, transaction, preflight, submit or recovery logic is added here: this file
// only hands the controller the host services it requires (an outpoint reservation, the
// durable pending record, the seed) in the extension's order:
//   seed -> signAfterConfirmation(persistPending, simulate) -> seed zeroed -> expiry
//   check -> submit.
// Every disclosure of the signed transaction (the node simulation) comes after
// `onBroadcast` returned a fresh durable attempt identity; the controller itself sets
// `ckbNotExposed` and refuses to continue without that identity.
import { prepareCkbReview } from './ckb-review-controller.js';
import { simulateCkbAtConfiguredNode } from './ckb-preflight.js';
import { submitCkbTransaction } from './ckb-submit.js';
import { CKB_FULL_RECIPIENT_SEND_ENABLED } from './ckb-recipient-policy.js';
import { ckbNetwork } from './ckb.js';
import { pqChainSeed } from './receive.js';
import { PQ_NETWORKS } from './networks.js';
import { formatUnits } from '../core.js';

// The extension's fixed limits (extension/src/background/ckb.js:44).
export const CKB_SEND_LIMITS = Object.freeze({ maxFee: 100000000n, maxRate: 100000n, cycleCeiling: 100000000n });
// In-page outpoint reservations, one table per open wallet object (a new wallet object, as
// after lock and unlock, starts empty, like the extension's per-session table).
const reservations = new WeakMap();
const heldBy = owner => { let held = reservations.get(owner); if (!held) reservations.set(owner, held = new Map()); return held; };
const networkLabel = networkId => PQ_NETWORKS.ckb.networks.find(n => n.id === networkId)?.label || networkId;

// The extension's CKB send review rows, in its order (extension/src/background/ckb.js:44).
function sendRows({ networkId, from, to, amount, fee, feeRate }) {
  return [['Network', `CKB ${networkLabel(networkId)}`], ['From', from], ['To', to], ['Amount', `${amount} CKB`], ['Fee', fee], ['Fee rate', `${feeRate} shannons per 1000 weight`],
    ['Scope', CKB_FULL_RECIPIENT_SEND_ENABLED ? 'Full-format Bech32m recipients only; non-cellbase empty-data quantum inputs. Check recipient control; address validity does not prove spendability.' : 'Quantum-lock recipients only; non-cellbase empty-data inputs.'],
    ['Simulation', 'The configured node receives the signed transaction and could relay it.']];
}
// The extension's CKB recovery review rows, in its order (extension/src/background/ckb.js:35).
export function ckbRecoveryReviewRows(prepared) {
  const amount = `${formatUnits(BigInt(prepared.amount), 8)} CKB`;
  return [['Action', 'Resubmit EXACTLY the previously signed transaction; no new signature'], ['Transaction ID', prepared.hash], ['From', prepared.from], ['To', prepared.to], ['Amount', amount],
    ['Fee', `${formatUnits(BigInt(prepared.fee), 8)} CKB`], ['Recovery', prepared.notice]];
}

// `amountAtoms`: bigint shannons. `unresolved()`: true while the wallet has a CKB row without a
// final result (the page also blocks that before preparing). `fetcher`, `wasmBytes`, `rnd` and
// `deriveSeed` exist so tests can script the node and the randomness.
export async function prepareCkbTransfer({ wallet, to, amountAtoms, networkId = 'mainnet', unresolved = () => false, signal, fetcher, wasmBytes, rnd, deriveSeed = pqChainSeed,
  prepare = prepareCkbReview, simulate = simulateCkbAtConfiguredNode, submit = submitCkbTransaction } = {}) {
  const from = wallet?.addresses?.ckb;
  if (!from) throw new Error('Open a wallet first.');
  if (networkId !== 'mainnet') throw new Error('Choose CKB mainnet.');
  const held = heldBy(wallet);
  // Like the extension holder (extension/src/background/ckb.js:27-28): the controller releases a
  // reservation it never handed off; after the hand-off it stays until the wallet object is gone.
  const reserve = async ({ networkId: id, from: owner, outpoints }) => {
    if (id !== networkId || owner !== from || unresolved() || !Array.isArray(outpoints) || !outpoints.length || outpoints.some(x => held.has(x))) return null;
    const token = Object.freeze({ id: Symbol('ckb-reservation'), outpoints: [...outpoints] });
    for (const x of outpoints) held.set(x, token);
    return token;
  };
  const release = async released => { for (const x of released?.outpoints ?? []) if (held.get(x) === released) held.delete(x); };
  const r = await prepare({ from, to, amount: amountAtoms, networkId, ...CKB_SEND_LIMITS, reserve, release, signal, fetcher });
  const amount = formatUnits(amountAtoms, 8), fee = `${formatUnits(BigInt(r.fee), 8)} CKB`;
  let used = false;
  return {
    chain: 'ckb', symbol: 'CKB', from: r.from, to: r.to, amount, amountAtoms: r.amount, networkId, fee, feeAtoms: r.fee, endpoint: ckbNetwork(networkId).rpc, expiresAt: r.expiresAt,
    review: sendRows({ networkId, from: r.from, to: r.to, amount, fee, feeRate: r.feeRate }),
    cancel() { used = true; return r.cancel(); },
    async confirm(onBroadcast) {
      if (used) throw new Error('This review is already closed.');
      used = true;
      if (typeof onBroadcast !== 'function') { await r.cancel(); throw new Error('Durable CKB pending record is required.'); }
      let seed;
      try { seed = deriveSeed(wallet.recoveryPhrase, 'ckb'); }
      catch (error) { await r.cancel(); throw error; }
      try {
        const signed = await r.signAfterConfirmation({ seed, rnd, wasmBytes,
          persistPending: details => onBroadcast({ ...details, hash: details.txid }),
          simulate: args => simulate({ ...args, expectedFee: BigInt(r.fee), signal, fetcher }) });
        seed.fill(0); seed = undefined;
        if (Date.now() >= r.expiresAt) throw new Error('CKB review expired before submission; the signed simulation remains held.');
        return await submit({ networkId, rpcTransaction: signed.rpcTransaction, txid: signed.txid, expiresAt: r.expiresAt, signal, fetcher });
      } finally { seed?.fill(0); }
    }
  };
}

// The transfer the page shows for "Review same-transaction recovery": the exact-byte
// recovery review of src/pq/ckb-recovery.js, as a web transfer. The module hands its attempt
// a `txid` and no `hash`; the page's record writer needs `hash` (same mapping the extension
// makes, extension/src/background/network-activity.js:131). `isResubmission` makes the page
// treat a failed replay as unresolved, never as "not submitted".
export function ckbRecoveryTransfer(prepared, row) {
  return { ...prepared, chain: 'ckb', symbol: 'CKB', amount: formatUnits(BigInt(row.amountAtoms), 8), amountAtoms: row.amountAtoms, networkId: row.networkId, endpoint: ckbNetwork(row.networkId).rpc,
    isResubmission: true, previousSubmissionId: row.submissionId, review: ckbRecoveryReviewRows(prepared),
    confirm: onBroadcast => prepared.confirm(async details => onBroadcast({ ...details, hash: details.txid })) };
}

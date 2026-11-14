// Web wallet and Connect Ixios send: a page adapter around the review, signing, recovery and
// submit modules the trusted extension already uses (extension/src/background/ixios.js).
// No signing, transaction, preflight, submit or recovery logic is added here: this file
// only hands those modules the host services they require (a nonce reservation, the
// durable pending record, the seed, the wallet guard) in the extension's order:
//   seed -> signAfterConfirmation(persistPending, assertCurrent) -> seed zeroed
//   -> fresh preflight -> expiry check -> ONE submit.
// `ixiosNotExposed` is true for every error raised before the post begins, including the two
// checks the controller does not cover (the preflight and the expiry check after signing),
// exactly as the extension decides it (`!submitStarted || error.ixiosNotExposed`).
import { prepareIxiosReview } from './ixios/review.js';
import { recheckIxiosPreflight } from './ixios/preflight.js';
import { submitIxiosTransaction } from './ixios/submit.js';
import { ixiosSigningSeed } from './ixios/derive.js';
import { ixiosNetwork } from './ixios/network.js';
import { amountUnits, formatUnits } from '../core.js';

// The extension's maximum gas price check (extension/src/background/ixios.js prepareSend).
export const IXIOS_MAX_GAS_PRICE = /^[1-9][0-9]{0,77}$/;
// In-page nonce reservations: one table per open wallet object (a new wallet object, as after
// lock and unlock, starts empty, like the extension's per-session table), one token per network:
// the two networks have their own nonce spaces and their own unresolved rows.
const reservations = new WeakMap();
const heldBy = owner => { let held = reservations.get(owner); if (!held) reservations.set(owner, held = new Map()); return held; };

// The extension's send review rows, in its order (extension/src/background/ixios.js prepareSend).
function sendRows({ network, r, amount, maxGasPrice }) {
  return [['Network', 'Ixios ' + network.label.toLowerCase()], ['From', r.from], ['To', r.to], ['Amount', `${amount} IXIOS`], ['Maximum fee', `${formatUnits(r.fee, 18)} IXIOS`],
    ['Gas price', `${r.gasPrice} atomic units per gas`], ['Maximum approved gas price', maxGasPrice], ['Nonce', r.nonce.toString()],
    ['Scope', 'Native IXIOS to empty-code accounts only; addresses are 48 bytes.'], ['Authorization', 'Native ML-DSA-87; transaction cannot be undone.']];
}
// The extension's recovery review rows, in its order (extension/src/background/ixios.js prepareResubmit).
export function ixiosRecoveryReviewRows(prepared) {
  const amount = `${formatUnits(BigInt(prepared.amountAtoms), 18)} IXIOS`;
  return [['Action', 'Resubmit exactly the previously signed transaction; no new signature'], ['Transaction ID', prepared.hash], ['From', prepared.from], ['To', prepared.to], ['Amount', amount],
    ['Maximum fee', `${formatUnits(BigInt(prepared.feeAtoms), 18)} IXIOS`], ['Recovery', prepared.notice]];
}

// `amount`: the form's decimal text. `unresolved()`: true while the wallet has an Ixios row of this network
// without a final result (the page also blocks that before preparing). `assertCurrent()`: throws unless the
// same wallet object is open and unlocked, Ixios and `networkId` are still the selected network and the account
// is unchanged (required by the review module before and after every step). `fetcher`, `wasmBytes`, `rnd`,
// `deriveSeed`, `prepare`, `recheck` and `submit` exist so tests can script the node and the randomness.
export async function prepareIxiosTransfer({ wallet, to, amount, maxGasPrice, networkId = 'mainnet', unresolved = () => false, assertCurrent, signal, fetcher, wasmBytes, rnd,
  deriveSeed = ixiosSigningSeed, prepare = prepareIxiosReview, recheck = recheckIxiosPreflight, submit = submitIxiosTransaction } = {}) {
  const network = ixiosNetwork(networkId);
  const from = wallet?.addresses?.ixios;
  if (!from) throw new Error('Ixios account unavailable.');
  if (typeof assertCurrent !== 'function') throw new Error('Active Ixios wallet guard required.');
  assertCurrent();
  if (unresolved()) throw new Error('A previous Ixios transaction is unresolved.');
  if (typeof maxGasPrice !== 'string' || !IXIOS_MAX_GAS_PRICE.test(maxGasPrice)) throw new Error('Enter a positive integer maximum gas price in atomic units.');
  const atoms = amountUnits(amount, 18);
  const held = heldBy(wallet);
  // Like the extension holder (extension/src/background/ixios.js reserve): one review at a time per network, never while a row
  // is unresolved. The token is dropped when the signed row is durably written: from then on that row (unresolved until it
  // is terminal) holds the nonce, as the extension's reservation is freed only once its rows are settled.
  const reserve = async ({ from: owner, nonce }) => {
    if (owner !== from || unresolved() || held.has(networkId)) return null;
    const token = Object.freeze({ networkId, nonce });
    held.set(networkId, token);
    return token;
  };
  const release = async token => { if (held.get(token?.networkId) === token) held.delete(token.networkId); };
  const r = await prepare({ from, to, amount: atoms, maxGasPrice: BigInt(maxGasPrice), reserve, release, signal, fetcher, networkId });
  try { assertCurrent(); } catch (error) { await r.cancel(); throw error; }
  const amountText = formatUnits(atoms, 18);
  let used = false;
  return {
    chain: 'ixios', symbol: 'IXIOS', from: r.from, to: r.to, amount: amountText, amountAtoms: atoms.toString(), networkId, endpoint: network.endpoint,
    fee: `Up to ${formatUnits(r.fee, 18)} IXIOS`, feeAtoms: r.fee.toString(), expiresAt: r.expiresAt,
    review: sendRows({ network, r, amount: amountText, maxGasPrice }),
    cancel() { used = true; return r.cancel(); },
    async confirm(onBroadcast) {
      // Refused before anything is signed or posted, so marked not exposed like every other pre-post error below.
      const notExposed = message => Object.assign(new Error(message), { ixiosNotExposed: true });
      if (used) throw notExposed('This review is already closed.');
      used = true;
      if (typeof onBroadcast !== 'function') { await r.cancel(); throw notExposed('Durable Ixios pending record is required.'); }
      let seed, entered = false, submitStarted = false;
      try {
        assertCurrent();
        seed = deriveSeed(wallet.recoveryPhrase);
        entered = true;
        const signed = await r.signAfterConfirmation({ seed, rnd, wasmBytes, assertCurrent,
          persistPending: async details => { assertCurrent(); const attempt = await onBroadcast(details); await release(held.get(networkId)); return attempt; } });
        seed.fill(0); seed = undefined;
        assertCurrent();
        await recheck(r, { signal, fetcher });
        assertCurrent();
        if (Date.now() >= r.expiresAt) throw new Error('Ixios review expired.');
        submitStarted = true;
        return await submit({ raw: signed.raw, hash: signed.hash, expiresAt: r.expiresAt, signal, fetcher, networkId });
      } catch (error) {
        if (!entered) await r.cancel();
        if (!submitStarted && error instanceof Error) error.ixiosNotExposed = true;
        throw error;
      } finally { seed?.fill(0); }
    }
  };
}

// The transfer the page shows for "Review same-transaction recovery": the exact-byte
// recovery review of src/pq/ixios/recovery.js, as a web transfer. `isResubmission` makes the
// page treat a failed replay as unresolved, never as "not submitted" (design D5).
export function ixiosRecoveryTransfer(prepared, row) {
  const network = ixiosNetwork(row.networkId);
  return { ...prepared, chain: 'ixios', symbol: 'IXIOS', amount: formatUnits(BigInt(prepared.amountAtoms), 18), amountAtoms: prepared.amountAtoms, networkId: row.networkId, endpoint: network.endpoint,
    fee: `Up to ${formatUnits(BigInt(prepared.feeAtoms), 18)} IXIOS`, isResubmission: true, previousSubmissionId: row.submissionId, review: ixiosRecoveryReviewRows(prepared),
    cancel: () => prepared.cancel(), confirm: onBroadcast => prepared.confirm(onBroadcast) };
}

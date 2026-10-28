import * as solana from '../../../src/adapters/solana.js';
import * as tron from '../../../src/adapters/tron.js';
import { nameReviewRows, NAME_CHECK_ROW } from '../../../src/adapters/nodus.js';
import { CHAINS } from '../../../src/config.js';
import { prepareTransfer } from '../../../src/wallet.js';
import { readHistory, mergeHistory, HISTORY_LIMIT, HISTORY_SOURCES } from '../../../src/history.js';
import { watchActivity } from '../../../src/activity.js';
import { sentRowsToShow } from '../../../src/activity-storage.js';
import { rpcErrors } from '@metamask/rpc-errors';

// Operator 2026-10-28, orchestration.md:5806: web-wallet code, no snap.
// Mainnet endpoints/assets come only from src/config.js:27-35 (selection is
// package 8). No transaction construction or signing is reimplemented here.
export function createSolanaTron({ lockCoordinator, getWalletKeys, getActivity }) {
  return Object.fromEntries(Object.entries({ solana, tron }).map(([chain, adapter]) => {
    const config = CHAINS[chain];
    let session, nextReview = 0;
    function lock() {
      const previous = session; session = undefined;
      if (!previous) return;
      previous.abort.abort(new Error('Wallet is locked.')); previous.stopTracking?.();
      for (const review of previous.reviews.values()) review.cancel();
      previous.reviews.clear(); previous.activity = null; previous.addresses = null;
    }
    // lock.js:1-3,32-48: the guard closes synchronously, then keyring,
    // webWallet (zeroes Solana and drops Tron), nodus, solana, tron dispose.
    // These holders own only reviews/read jobs, never a second key copy.
    lockCoordinator.register(chain, { lock });
    function current(s) {
      lockCoordinator.assertUnlocked();
      if (session !== s || s.abort.signal.aborted) throw new Error('Wallet is locked.');
      getWalletKeys().getAddresses();
    }
    function active() {
      lockCoordinator.assertUnlocked();
      if (!session) session = { addresses: getWalletKeys().getAddresses(), activity: getActivity(chain),
        abort: new AbortController(), reviews: new Map() };
      current(session); return session;
    }
    // The unchanged adapters' prepare/send operations have no AbortSignal
    // argument. Abandon their result on lock; their wallet getters below also
    // refuse key use/broadcast after every adapter assertWalletActive check.
    async function guarded(s, work) {
      current(s);
      let rejectLocked;
      const stopped = new Promise((_, reject) => { rejectLocked = () => reject(new Error('Wallet is locked.')); });
      s.abort.signal.addEventListener('abort', rejectLocked, { once: true });
      try { const value = await Promise.race([work(), stopped]); current(s); return value; }
      finally { s.abort.signal.removeEventListener('abort', rejectLocked); }
    }
    function track(s) {
      if (s.stopTracking) return;
      const activity = s.activity;
      s.stopTracking = watchActivity(() => session === s && !lockCoordinator.isLocked ? activity.rows() : [], () => {
        // src/app.js:486,587: persist tracker outcomes, never resubmit.
        void activity.persist().catch(error => { if (session === s) s.activityError = error.message; });
      });
    }
    function snapshot(s) {
      current(s);
      const page = s.activity.history();
      const local = sentRowsToShow(s.activity.rows(), { historyRows: page?.rows ?? [] }).map(row => ({
        hash: row.hash, to: row.to, amount: row.amount, symbol: row.symbol, status: row.status,
        note: row.note, readError: row.readError, createdAt: row.createdAt,
      }));
      // src/app.js:300-326,478-485: account rows and "Sent from here" are
      // distinct; a confirmed send leaves the latter only when history lists it.
      return { rows: structuredClone(page?.rows ?? []), local,
        status: page ? `Newest ${HISTORY_LIMIT} transfers as reported by ${HISTORY_SOURCES[chain]}, read ${new Date(page.readAt).toLocaleString()}. Your own sends are tracked above.` : 'Account history has not been read yet.',
        error: s.historyError ?? '', activityError: s.activityError || s.activity.error() };
    }
    return [chain, {
      getReceiveAddress() { return active().addresses[chain]; },
      async getBalances() {
        const s = active(); track(s);
        return guarded(s, () => adapter.balances(chain, s.addresses[chain], config.endpoint, { signal: s.abort.signal }));
      },
      async prepareSend({ symbol, to, amount } = {}) {
        const s = active(), activity = s.activity;
        activity.assertSendable();
        // evm.js prepareSend uses guarded wallet getters for the unchanged
        // adapter. Keys are fetched only at use through wallet-keys.js:82-83;
        // neither the wrapper nor a review retains a keypair/private key.
        const wallet = {
          addresses: s.addresses,
          get solana() { current(s); return getWalletKeys().getSolanaKeypair(); },
          get tronPrivateKey() { current(s); return getWalletKeys().getTronPrivateKey(); },
          get nodusClient() { current(s); return activity.client; },
          get locked() { current(s); return false; },
        };
        const preparing = prepareTransfer({ wallet, chain, symbol, to, amount, endpoint: config.endpoint }).then(review => {
          try { current(s); return review; } catch (error) { review.cancel(); throw error; }
        });
        const prepared = await guarded(s, () => preparing);
        // Copied/adapted from src/app.js:2327-2338, read through the confirm
        // success/error/finally branches at :2346-2413 (HEAD 15dabcf46).
        // These chains have no EVM nonce/checksum rows. Named sends use the
        // original web-wallet signed-profile resolver and its review text.
        const entries = [['Network', `${config.name} mainnet`], ['From', prepared.from]];
        if (prepared.named) entries.push(...nameReviewRows(prepared.named, { via: 'the address published in the owner’s signed profile' }));
        entries.push(['To', prepared.to]);
        if (prepared.named) entries.push([...NAME_CHECK_ROW]);
        entries.push(['Asset', prepared.symbol], ['Amount', prepared.amount], ['Network fee', prepared.fee]);
        for (const review of s.reviews.values()) review.cancel();
        s.reviews.clear();
        const id = String(++nextReview); s.reviews.set(id, prepared);
        return { id, chain, from: prepared.from, to: prepared.to, symbol: prepared.symbol, amount: prepared.amount,
          fee: prepared.fee, expiresAt: prepared.expiresAt, review: entries };
      },
      cancelSend(id) { const review = session?.reviews.get(id); review?.cancel(); session?.reviews.delete(id); },
      async confirmSend(id) {
        const s = active(), activity = s.activity, review = s.reviews.get(id);
        if (!review) throw new Error('This review is already closed.');
        s.reviews.delete(id); activity.assertSendable();
        return guarded(s, async () => {
          let record;
          try {
            // src/app.js:2358-2364: seal the signed identifier BEFORE broadcast.
            // Adapter checks again after this await (solana.js:152-155,
            // tron.js:84-86); the guarded locked getter closes that yield too.
            const hash = await review.confirm(async details => {
              current(s); activity.assertSendable();
              record = activity.append(review, details); await activity.persist(); current(s);
            });
            current(s); record.note = 'Broadcast submitted; awaiting confirmation.'; track(s); return hash;
          } catch (error) {
            // src/app.js:2389-2413: once a signed record exists, an ambiguous
            // failure is tracked and the consumed review cannot be replayed.
            if (record && session === s && !lockCoordinator.isLocked) {
              record.status = 'unknown'; record.note = 'Broadcast outcome uncertain. Tracking the signed transaction; do not resend automatically.';
              track(s);
              throw rpcErrors.internal({ message: error.message, data: { activityTracked: true } });
            }
            throw error;
          }
        });
      },
      async getHistory({ manual = false } = {}) {
        const s = active(); track(s);
        if (s.historyJob) return s.historyJob;
        const kept = s.activity.history();
        // Copied from src/app.js:295,328-351: five minutes automatically,
        // thirty seconds manually; known Solana signatures are not read twice.
        if (kept && Date.now() - kept.readAt < (manual ? 30000 : 300000)) return snapshot(s);
        const job = guarded(s, async () => {
          const known = new Map();
          for (const row of kept?.rows ?? []) {
            if (!known.has(row.hash)) known.set(row.hash, []);
            known.get(row.hash).push(row);
          }
          try {
            const rows = await readHistory(chain, s.addresses[chain], { endpoint: config.endpoint, signal: s.abort.signal, known });
            current(s); s.historyError = '';
            // src/app.js:353-361: a failed cache write does not hide a read.
            await s.activity.saveHistory({ address: s.addresses[chain], readAt: Date.now(), rows: mergeHistory(kept?.rows, rows) }).catch(() => {});
          } catch (error) { current(s); s.historyError = error.message; }
          return snapshot(s);
        }).finally(() => { if (s.historyJob === job) s.historyJob = null; });
        s.historyJob = job; return job;
      },
    }];
  }));
}

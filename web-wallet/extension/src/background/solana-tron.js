import * as solana from '../../../src/adapters/solana.js';
import * as tron from '../../../src/adapters/tron.js';
import { nameReviewRows, NAME_CHECK_ROW } from '../../../src/adapters/nodus.js';
import { CHAINS } from '../../../src/config.js';
import { prepareTransfer, adapters } from '../../../src/wallet.js';
import { readHistory, mergeHistory, HISTORY_LIMIT, HISTORY_SOURCES } from '../../../src/history.js';
import { watchActivity, checkActivity } from '../../../src/activity.js';
import { sentRowsToShow } from '../../../src/activity-storage.js';
import { rpcErrors } from '@metamask/rpc-errors';
import { chainNetwork } from '../constants/networks.js';
import { checkNetwork, testnetAdapter, checkTestnetActivity } from './testnet-adapters.js';

// Operator 2026-10-28, orchestration.md:5806: web-wallet code, no snap.
// Mainnet endpoints/assets remain src/config.js:27-35. Testnet identity and
// native sends are adapted in testnet-adapters.js without editing web-wallet.
export function createSolanaTron({ lockCoordinator, getWalletKeys, getActivity, getNetwork = chain => chainNetwork(chain) }) {
  return Object.fromEntries(Object.entries({ solana, tron }).map(([chain, adapter]) => {
    const config = CHAINS[chain];
    let session, nextReview = 0, rereadNetwork = false;
    function close(reason) {
      const previous = session; session = undefined;
      if (!previous) return;
      previous.abort.abort(new Error(reason)); previous.stopTracking?.();
      for (const review of previous.reviews.values()) review.cancel();
      previous.reviews.clear(); previous.activity = null; previous.addresses = null;
    }
    const lock = () => close('Wallet is locked.');
    // lock.js:1-3,32-48: the guard closes synchronously, then keyring,
    // webWallet (zeroes Solana and drops Tron), nodus, solana, tron dispose.
    // These holders own only reviews/read jobs, never a second key copy.
    lockCoordinator.register(chain, { lock });
    function current(s) {
      lockCoordinator.assertUnlocked();
      if (session !== s || s.abort.signal.aborted) throw s.abort.signal.reason ?? new Error('Wallet is locked.');
      getWalletKeys().getAddresses();
    }
    function active() {
      lockCoordinator.assertUnlocked();
      if (!session) {
        const network = getNetwork(chain);
        session = { addresses: getWalletKeys().getAddresses(), activity: getActivity(chain, network.id), network,
          historyInvalidated: rereadNetwork, abort: new AbortController(), reviews: new Map() };
        rereadNetwork = false;
      }
      current(session); return session;
    }
    // The unchanged adapters' prepare/send operations have no AbortSignal
    // argument. Abandon their result on lock; their wallet getters below also
    // refuse key use/broadcast after every adapter assertWalletActive check.
    async function guarded(s, work) {
      current(s);
      let rejectLocked;
      const stopped = new Promise((_, reject) => { rejectLocked = () => reject(s.abort.signal.reason); });
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
      }, { check: async (row, options) => {
        const update = await (s.network.id === 'mainnet' ? checkActivity(row, options) : checkTestnetActivity(row, s.network, options));
        // src/app.js:567-570: a newly confirmed send gets one history read
        // after the tracker updates it, respecting the 30-second manual gap.
        if (update.status === 'confirmed' && row.status !== 'confirmed') setTimeout(() => {
          if (session !== s || lockCoordinator.isLocked) return;
          const kept = s.activity.history();
          if (!kept || Date.now() - kept.readAt >= 30000) void getHistory({ manual: true }).catch(() => {});
        }, 0);
        return update;
      } });
    }
    function snapshot(s) {
      current(s);
      const page = s.historyInvalidated ? null : s.activity.history();
      const local = sentRowsToShow(s.activity.rows(), { historyRows: page?.rows ?? [] }).map(row => ({
        network: s.network.id, hash: row.hash, to: row.to, amount: row.amount, symbol: row.symbol, status: row.status,
        note: row.note, readError: row.readError, createdAt: row.createdAt,
      }));
      // src/app.js:300-326,478-485: account rows and "Sent from here" are
      // distinct; a confirmed send leaves the latter only when history lists it.
      return { network: s.network.id, rows: structuredClone(page?.rows ?? []), local,
        status: s.historyNote || (page ? `Newest ${HISTORY_LIMIT} transfers as reported by ${HISTORY_SOURCES[chain]}, read ${new Date(page.readAt).toLocaleString()}. Your own sends are tracked above.` : 'Account history has not been read yet.'),
        error: s.historyError ?? '', activityError: s.activityError || s.activity.error() };
    }
    async function ready(s) { await guarded(s, async () => { await s.activity.ready; }); current(s); }
    async function getHistory({ manual = false } = {}) {
      const s = active(); await ready(s); track(s);
      if (s.historyJob) return s.historyJob;
      const kept = s.historyInvalidated ? null : s.activity.history();
      // src/app.js:295,335: five minutes automatically, thirty seconds
      // manually; :336-337 supplies the explicit early-refresh explanation.
      if (kept && Date.now() - kept.readAt < (manual ? 30000 : 300000)) {
        if (manual) s.historyNote = `Read ${new Date(kept.readAt).toLocaleString()}. Try again in a minute — the provider limits requests.`;
        return snapshot(s);
      }
      s.historyNote = '';
      const job = guarded(s, async () => {
        const known = new Map();
        for (const row of kept?.rows ?? []) {
          if (!known.has(row.hash)) known.set(row.hash, []);
          known.get(row.hash).push(row);
        }
        try {
          // src/app.js:343-347 reads mainnet history without an identity RPC.
          if (s.network.id !== 'mainnet') { await checkNetwork(chain, s.network, { signal: s.abort.signal }); current(s); }
          let rows = await readHistory(chain, s.addresses[chain], { endpoint: s.network.endpoint, signal: s.abort.signal, known });
          // web-wallet/src/config.js:29-30,33-35 lists mainnet token addresses.
          // The shared history reader uses those lists; keep native symbols
          // only on testnets until testnet token deployments are supplied.
          if (s.network.id !== 'mainnet') rows = rows.filter(row => row.symbol === config.symbol);
          current(s); s.historyError = ''; s.historyInvalidated = false;
          await s.activity.saveHistory({ address: s.addresses[chain], readAt: Date.now(), rows: mergeHistory(kept?.rows, rows) }).catch(() => {});
        } catch (error) { current(s); s.historyError = error.message; }
        return snapshot(s);
      }).finally(() => { if (s.historyJob === job) s.historyJob = null; });
      s.historyJob = job; return job;
    }
    return [chain, {
      networkChanged() { close('Network changed. Prepare the transfer again.'); rereadNetwork = true; },
      getReceiveAddress() { return active().addresses[chain]; },
      async getBalances() {
        const s = active(); await ready(s); track(s);
        const selectedAdapter = s.network.id === 'mainnet' ? adapter : testnetAdapter(chain, s.network);
        return guarded(s, () => selectedAdapter.balances(chain, s.addresses[chain], s.network.endpoint, { signal: s.abort.signal }));
      },
      async prepareSend({ symbol, to, amount } = {}) {
        const s = active(), activity = s.activity;
        await ready(s);
        activity.assertSendable();
        // Native-only: web-wallet/src/config.js:29-30,33-35 lists mainnet tokens.
        if (s.network.id !== 'mainnet' && symbol !== config.symbol) throw new Error('Testnet token deployments are not configured.');
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
        const implementations = s.network.id === 'mainnet' ? adapters : { ...adapters, [chain]: testnetAdapter(chain, s.network) };
        const preparing = prepareTransfer({ wallet, chain, symbol, to, amount, endpoint: s.network.endpoint }, implementations).then(review => {
          try { current(s); return review; } catch (error) { review.cancel(); throw error; }
        });
        const prepared = await guarded(s, () => preparing);
        // Copied/adapted from src/app.js:2327-2338, read through the confirm
        // success/error/finally branches at :2346-2413 (HEAD 15dabcf46).
        // These chains have no EVM nonce/checksum rows. Named sends use the
        // original web-wallet signed-profile resolver and its review text.
        const entries = [['Network', `${config.name} ${s.network.id === 'mainnet' ? 'mainnet' : s.network.label}`], ['From', prepared.from]];
        if (prepared.named) entries.push(...nameReviewRows(prepared.named, { via: 'the address published in the owner’s signed profile' }));
        entries.push(['To', prepared.to]);
        if (prepared.named) entries.push([...NAME_CHECK_ROW]);
        entries.push(['Asset', prepared.symbol], ['Amount', prepared.amount], ['Network fee', prepared.fee]);
        for (const review of s.reviews.values()) review.cancel();
        s.reviews.clear();
        const id = String(++nextReview); s.reviews.set(id, prepared);
        return { id, chain, network: s.network.id, from: prepared.from, to: prepared.to, symbol: prepared.symbol, amount: prepared.amount,
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
      getHistory,
    }];
  }));
}

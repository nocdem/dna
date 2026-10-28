import { createNodusClient } from '../../../src/nodus/client.js';
import { nodusSendModuleFactory } from '../../../src/nodus/send-module.js';
import { deriveNodusAddress } from '../../../src/nodus/derive.js';
import * as adapter from '../../../src/adapters/nodus.js';
import { readCpunk } from '../../../src/adapters/cpunk.js';
import { prepareTransfer } from '../../../src/wallet.js';
import { NODUS_ASSET, nodusTokens } from '../../../src/nodus/network.js';
import { NODUS_HISTORY_LIMIT, localRowsToShow, nodusHistoryRow, nodusHistoryStatus } from '../../../src/nodus/history.js';
import { keepBusyEnvelope, canResubmit, dropSettledEnvelope, resubmitKept, NODUS_UNCERTAIN_NOTE, NODUS_SUBMITTED_NOTE } from '../../../src/nodus/resubmit.js';
import { recordActivity, watchActivity, terminal, evmActivityText } from '../../../src/activity.js';
import { activityKeyFor, parseActivity, serializeActivity, requireSavedForEvm } from '../../../src/activity-storage.js';
import { ACTIVITY_KEY, VAULT_KEY } from '../../../src/vault.js';
import { EvmAccount, Contract, describeArgs } from '../../../src/evm/contract.js';
import { parseRaw, parseWei, formatRaw, formatWei } from '../../../src/evm/units.js';

// Approved plan §3.5 holder 3 / §5.4–5.5: the web-wallet client and its one
// module queue live in the background. No secret or signed envelope enters UI state.
export function createNodus({ lockCoordinator, storage, getAddresses, factory = nodusSendModuleFactory }) {
  let session, nextReview = 0, writes = Promise.resolve();
  function lock() {
    const previous = session; session = undefined;
    if (!previous) return;
    // Let the client reject its queue as locked before aborting read requests.
    previous.client.lock();
    previous.abort.abort(); previous.stopTracking?.();
    for (const review of previous.reviews.values()) review.cancel();
    previous.reviews.clear();
    for (const row of previous.rows) row.envelope?.fill(0);
    previous.rows = []; previous.key = null;
  }
  lockCoordinator.register('nodus', { lock });
  function current(s) {
    if (session !== s || s.abort.signal.aborted) throw new Error('Wallet is locked.');
  }
  function active() {
    lockCoordinator.assertUnlocked();
    if (!session) throw new Error('Wallet is locked.');
    current(session); session.assertReady?.(); return session;
  }
  async function consumeNodusSeed(seed, { phrase, id, addresses, nodusWasmBytes, signal, assertReady } = {}) {
    lock();
    if (typeof factory !== 'function') throw new Error('Nodus sending is not available in this wallet build.');
    const s = { client: createNodusClient({ factory }), abort: new AbortController(), rows: [], quarantined: [], reviews: new Map(), assertReady, id };
    session = s;
    try {
      const combined = signal ? AbortSignal.any([signal, s.abort.signal]) : s.abort.signal;
      const fingerprint = await deriveNodusAddress(phrase, { wasmBytes: nodusWasmBytes, signal: combined });
      current(s); combined.throwIfAborted();
      s.addresses = { ...addresses, nodus: fingerprint };
      s.key = await activityKeyFor(phrase, id); phrase = null;
      current(s); combined.throwIfAborted();
      const saved = await storage.get([VAULT_KEY, ACTIVITY_KEY]); current(s);
      s.vault = saved[VAULT_KEY];
      try {
        s.rows = await parseActivity(saved[ACTIVITY_KEY], id, s.addresses, s.key);
        s.quarantined = s.rows.quarantined ?? [];
      } catch (error) { s.activityError = error.message; }
      current(s); combined.throwIfAborted();
      const identity = await s.client.unlock({ seed, fingerprint }); current(s);
      // src/evm/ui.js:96-104 and src/app.js:1275-1279: one account queue,
      // sharing the native pending coins and restored self-address records.
      s.contractAccount = new EvmAccount({ client: s.client, fingerprint, lockedInputs: () => heldInputs(s),
        reservations: () => s.rows.filter(row => row.chain === 'nodus' && row.address === fingerprint && !terminal(row.status)
          && !adapter.isClaimRow(row) && (row.kind === 'evm' || (row.kind === undefined && row.to === fingerprint))) });
      return { ...identity, client: s.client };
    } catch (error) { if (session === s) lock(); throw error; }
    finally { phrase = null; seed.fill(0); }
  }
  // src/app.js:202-225: authenticate, merge and seal before broadcast. The
  // service worker owns all writes, so its queue also joins every wallet UI.
  function persist(s) {
    const operation = writes.catch(() => {}).then(async () => {
      current(s);
      if (s.activityError) throw new Error('Saved activity is unverified. Check the explorer before sending.');
      const saved = await storage.get([VAULT_KEY, ACTIVITY_KEY]); current(s);
      if (saved[VAULT_KEY] !== s.vault) throw new Error('Wallet storage changed before broadcast. Review the transfer again.');
      const rows = await parseActivity(saved[ACTIVITY_KEY], s.id, s.addresses, s.key); current(s);
      const merged = new Map([...rows, ...s.rows].map(row => [`${row.chain}:${row.hash}`, row]));
      const combined = [...merged.values()].sort((a, b) => {
        const time = Date.parse(a.createdAt) - Date.parse(b.createdAt), left = `${a.chain}:${a.hash}`, right = `${b.chain}:${b.hash}`;
        return time || (left < right ? -1 : left > right ? 1 : 0);
      });
      const aside = rows.quarantined ?? [];
      const encrypted = await serializeActivity(s.id, combined, s.key, aside); current(s);
      await storage.set({ [ACTIVITY_KEY]: encrypted }); current(s);
      s.rows = combined; s.quarantined = aside;
    });
    writes = operation; return operation;
  }
  function track(s) {
    if (s.stopTracking) return;
    s.stopTracking = watchActivity(() => s.rows.filter(row => row.chain === 'nodus' && row.address === s.addresses.nodus), () => {
      for (const row of s.rows) dropSettledEnvelope(row);
      void persist(s).catch(error => { if (session === s) s.activityError = error.message; });
    }, { check: (row, { signal }) => adapter.checkNodusActivity(row, { signal, client: s.client }) });
  }
  function localRows(s, page) {
    return localRowsToShow(s.rows.filter(row => row.chain === 'nodus' && row.address === s.addresses.nodus), page)
      .map(row => ({ hash: row.hash, to: row.to, amount: row.amount, symbol: row.symbol, status: row.status, note: row.note,
        ...(row.kind === 'evm' ? (() => { const text = evmActivityText(row); return { amountText: text.amount, detail: text.what }; })() : {}),
        createdAt: row.createdAt, canResubmit: canResubmit(row) }));
  }
  function heldInputs(s) {
    const locked = adapter.lockedInputs(s.rows);
    for (const held of s.quarantined) for (const input of held.inputs) locked.add(input);
    return locked;
  }
  function contract(s) {
    if (!s.contractAccount) throw new Error('Smart contracts are not available in this wallet version.');
    return s.contractAccount;
  }
  function contractArgs(args = []) {
    const value = typeof args === 'string' ? JSON.parse(args) : args;
    if (!Array.isArray(value)) throw new Error('Contract arguments must be an array.');
    return value;
  }
  function observeReceipt(s, sent) {
    void sent.receipt.then(result => {
      if (session === s) s.contractOutcome = describeArgs(['Outcome'], [result]);
    }, error => { if (session === s) s.contractOutcome = error.message; });
  }
  return {
    consumeNodusSeed,
    getState() { return { state: session?.client.state ?? 'locked', tokens: nodusTokens(session?.client.tokenPins()), historyReadable: session?.client.historyReadable ?? false,
      evmBuildable: session?.client.evmBuildable ?? false, evmReadable: session?.client.evmReadable ?? false }; },
    async getBalances() {
      const s = active(); track(s);
      const rows = await adapter.balances('nodus', s.addresses.nodus, undefined, { client: s.client, signal: s.abort.signal });
      current(s); return rows;
    },
    async getCpunkBalance() {
      const s = active();
      const result = await readCpunk({ address: getAddresses().cpunk, signal: s.abort.signal }); current(s); return result;
    },
    async prepareSend({ to, amount, tokenId } = {}) {
      const s = active();
      if (s.activityError) throw new Error('Saved activity is unverified. Check the explorer before sending.');
      const review = await prepareTransfer({ wallet: { addresses: s.addresses, nodusClient: s.client }, chain: 'nodus',
        asset: { chain: NODUS_ASSET.chain, tokenId }, to, amount, nodusLocked: heldInputs(s) });
      current(s);
      const id = String(++nextReview); s.reviews.set(id, review);
      return { id, to: review.to, amount: review.amount, symbol: review.symbol, tokenId: review.tokenId,
        fee: review.fee, expiresAt: review.expiresAt, review: review.review };
    },
    async readContract({ action, address, abi, fn, args, ticketId, value = '0' } = {}) {
      const s = active(), account = contract(s); let result;
      if (action === 'account') {
        const balance = await account.account({ signal: s.abort.signal });
        result = { address: account.displayAddress, balance: `${formatWei(balance.balanceWei)} NODUS`, nonce: balance.nonce,
          height: balance.height, pending: account.waiting(), outcome: s.contractOutcome ?? '' };
      } else if (action === 'ticket') result = await account.ticket(ticketId, { signal: s.abort.signal });
      else {
        const loaded = new Contract({ account, address, abi });
        if (action === 'read') result = await loaded.read(fn, contractArgs(args), { signal: s.abort.signal });
        else if (action === 'estimate') result = await loaded.estimate(fn, contractArgs(args), { valueWei: parseWei(value) });
        else throw new Error('Unknown smart-contract read.');
      }
      current(s); return describeArgs(['Result'], [result]);
    },
    async prepareContract({ action, amount, dest, ticketId, address, abi, fn, args, bytecode, value = '0' } = {}) {
      const s = active(), account = contract(s);
      requireSavedForEvm(Boolean(s.vault && s.key));
      if (s.activityError) throw new Error('Saved activity is unverified. Check the explorer before sending.');
      let review;
      if (action === 'deposit') review = await account.deposit(parseRaw(amount));
      else if (action === 'withdraw') review = await account.withdraw(parseRaw(amount), dest || s.addresses.nodus);
      else if (action === 'redeem') review = await account.redeem(ticketId, dest || s.addresses.nodus);
      else if (action === 'call') review = await new Contract({ account, address, abi }).prepareSend(fn, contractArgs(args), { valueWei: parseWei(value) });
      else if (action === 'deploy') review = await Contract.prepareDeploy({ account, bytecode, abi, args: contractArgs(args), valueWei: parseWei(value) });
      else throw new Error('Unknown smart-contract action.');
      if (session !== s) { review.cancel(); throw new Error('Wallet is locked.'); }
      const id = String(++nextReview); s.reviews.set(id, { ...review, kind: 'contract' });
      return { id, review: review.review, expiresAt: review.expiresAt };
    },
    cancelSend(id) { const s = active(); s.reviews.get(id)?.cancel(); s.reviews.delete(id); },
    async confirmSend(id) {
      const s = active(), review = s.reviews.get(id);
      if (!review) throw new Error('This review is already closed.');
      s.reviews.delete(id); let record;
      try {
        const result = await review.confirm(async details => {
          current(s);
          // The same pending-input rule as adapter.prepare, rechecked when a
          // second wallet window confirms a review built before the first sent.
          const locked = heldInputs(s);
          if (details.inputs.some(input => locked.has(input))) throw new Error('Your coins are held by a pending send. Wait for it to be included or to expire.');
          if (review.kind === 'contract') {
            // src/app.js:1241-1266 / src/evm/ui.js:143-147: the durable
            // self-address marker reserves the account; value and fee stay separate in UI.
            const d = review.decoded, own = s.addresses.nodus;
            record = recordActivity({ chain: 'nodus', from: own, to: own, symbol: 'NODUS', amount: formatRaw((d.op === 'deposit' ? d.amount : 0n) + d.fee) }, details);
            Object.assign(record, { kind: 'evm', evmTitle: d.op, evmOp: d.op,
              evmMoved: d.op === 'call' || d.op === 'create' ? formatWei(d.valueWei) : formatRaw(d.amount), evmFee: formatRaw(d.fee), evmTo: d.dest });
          } else record = recordActivity(review, details);
          s.rows.push(record);
          try { await persist(s); current(s); }
          catch (error) {
            if (review.kind === 'contract' && session === s) { s.rows = s.rows.filter(row => row !== record); record = undefined; }
            throw error;
          }
        });
        const hash = review.kind === 'contract' ? result.intentId : result;
        if (review.kind === 'contract') observeReceipt(s, result);
        current(s); record.note = NODUS_SUBMITTED_NOTE; track(s); return hash;
      } catch (error) {
        if (error.sent) observeReceipt(s, error.sent);
        if (record && session === s) {
          if (!keepBusyEnvelope(record, error)) { record.status = 'unknown'; record.note = NODUS_UNCERTAIN_NOTE; }
          track(s);
        }
        throw error;
      }
    },
    async resubmit(hash) {
      const s = active(), row = s.rows.find(row => row.chain === 'nodus' && row.hash === hash);
      await persist(s); current(s);
      const result = await resubmitKept(row, envelope => s.client.submit({ envelope })); current(s); track(s);
      return { outcome: result.outcome, message: result.message ?? result.error?.message ?? '' };
    },
    async getHistory() {
      const s = active(); track(s);
      const page = await s.client.addrHistory({ limit: NODUS_HISTORY_LIMIT }, { signal: s.abort.signal }); current(s);
      return { rows: page.entries.map(entry => nodusHistoryRow(entry, { tokens: nodusTokens(s.client.tokenPins()) })),
        status: nodusHistoryStatus({ page, readAt: new Date().toLocaleString() }), local: localRows(s, page), activityError: s.activityError ?? '' };
    },
    getLocalHistory() { const s = active(); return localRows(s); },
  };
}

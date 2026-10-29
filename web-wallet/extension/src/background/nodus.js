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
import { activityKeyFor, parseActivity, serializeActivity, serializeWithoutQuarantined, requireSavedForEvm,
  historyKeyFor, parseHistory, serializeHistory } from '../../../src/activity-storage.js';
import { ACTIVITY_KEY, VAULT_KEY, HISTORY_KEY } from '../../../src/vault.js';
import { EvmAccount, Contract, describeArgs } from '../../../src/evm/contract.js';
import { parseRaw, parseWei, formatRaw, formatWei } from '../../../src/evm/units.js';
import { rpcErrors, providerErrors } from '@metamask/rpc-errors';
import { Buffer } from 'buffer';
import { createNetworkActivity } from './network-activity.js';
import { chainNetwork } from '../constants/networks.js';

// Approved plan §3.5 holder 3 / §5.4–5.5: the web-wallet client and its one
// module queue live in the background. No secret or signed envelope enters UI state.
export function createNodus({ lockCoordinator, storage, getAddresses, factory = nodusSendModuleFactory, approvals, getPermittedAccounts }) {
  let session, nextReview = 0, writes = Promise.resolve();
  function lock() {
    const previous = session; session = undefined;
    if (!previous) return;
    stopQuarantineTimer(previous);
    // Let the client reject its queue as locked before aborting read requests.
    previous.client.lock();
    previous.abort.abort(); previous.stopTracking?.();
    for (const review of previous.reviews.values()) review.cancel();
    previous.reviews.clear();
    for (const row of previous.rows) row.envelope?.fill(0);
    previous.rows = []; previous.quarantined = []; previous.releasedQuarantine.clear(); previous.key = null;
    previous.historyKey = null; previous.history = {};
    previous.networkActivities?.clear();
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
    const s = { client: createNodusClient({ factory }), abort: new AbortController(), rows: [], quarantined: [], activityBlocked: false,
      releasedQuarantine: new Set(), quarantineReadAt: -Infinity, reviews: new Map(), networkActivities: new Map(), assertReady, id };
    session = s;
    try {
      const combined = signal ? AbortSignal.any([signal, s.abort.signal]) : s.abort.signal;
      const fingerprint = await deriveNodusAddress(phrase, { wasmBytes: nodusWasmBytes, signal: combined });
      current(s); combined.throwIfAborted();
      s.addresses = { ...addresses, nodus: fingerprint };
      s.key = await activityKeyFor(phrase, id);
      current(s); combined.throwIfAborted();
      // src/app.js:2528-2542: the saved wallet's separate encrypted account
      // history key/cache, using the original format and derivation unchanged.
      s.historyKey = await historyKeyFor(phrase, id); phrase = null;
      current(s); combined.throwIfAborted();
      const saved = await storage.get([VAULT_KEY, ACTIVITY_KEY, HISTORY_KEY]); current(s);
      s.vault = saved[VAULT_KEY];
      try { s.history = await parseHistory(saved[HISTORY_KEY], id, s.historyKey); }
      catch { s.history = {}; }
      current(s); combined.throwIfAborted();
      // src/app.js:2543-2550: only the unlock-time read problem blocks sending.
      try {
        s.rows = await parseActivity(saved[ACTIVITY_KEY], id, s.addresses, s.key);
        s.quarantined = s.rows.quarantined ?? [];
      } catch (error) { s.activityBlocked = true; s.activityError = error.message; }
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
      if (s.activityBlocked) throw new Error('Saved activity is unverified. Check the explorer and discard the unreadable history before sending.');
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
      // src/app.js:205,215-224 saves a snapshot without replacing live history.
      // A send may append while encryption/storage yields; its queued save
      // must still see that signed record when this older save completes.
      s.quarantined = aside;
    });
    writes = operation; return operation;
  }
  function track(s) {
    void reconcileQuarantine(s);
    if (s.stopTracking) return;
    s.stopTracking = watchActivity(() => s.rows.filter(row => row.chain === 'nodus' && row.address === s.addresses.nodus), () => {
      for (const row of s.rows) dropSettledEnvelope(row);
      // src/app.js:486, 587: display persist failures without changing activityBlocked.
      void persist(s).catch(error => { if (session === s) s.activityError = error.message; });
      void reconcileQuarantine(s);
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
    for (const held of adapter.quarantineLockRows(s.quarantined, s.releasedQuarantine)) for (const input of held.inputs) locked.add(input);
    return locked;
  }
  // src/app.js:107-142, 587, 1173: reconcile on connection/tracker updates and
  // every 15000 ms while quarantine remains. Monotonic pacing; one read at a
  // time; lock stops the timer and an old read cannot release or re-arm it.
  const QUARANTINE_READ_MS = 15000;
  function stopQuarantineTimer(s) { clearTimeout(s.quarantineTimer); s.quarantineTimer = undefined; }
  function quarantineActive(s) {
    return session === s && !lockCoordinator.isLocked && !s.abort.signal.aborted && s.client.state === 'ready'
      && s.quarantined.some(row => !s.releasedQuarantine.has(row));
  }
  function armQuarantineTimer(s) {
    if (s.quarantineTimer || !quarantineActive(s)) return;
    s.quarantineTimer = setTimeout(() => { s.quarantineTimer = undefined; void reconcileQuarantine(s); }, QUARANTINE_READ_MS);
  }
  function reconcileQuarantine(s) {
    if (!quarantineActive(s)) { stopQuarantineTimer(s); return Promise.resolve(); }
    if (s.quarantineReading) return s.quarantineReading;
    if (performance.now() - s.quarantineReadAt < QUARANTINE_READ_MS) { armQuarantineTimer(s); return Promise.resolve(); }
    s.quarantineReadAt = performance.now();
    s.quarantineReading = (async () => {
      try {
        const view = await adapter.coinView({ client: s.client, from: s.addresses.nodus });
        if (!quarantineActive(s)) return;
        for (const row of s.quarantined) if (row.address === s.addresses.nodus && adapter.quarantineReleasable(row, view)) s.releasedQuarantine.add(row);
      } catch { /* unreadable: the locks stay */ }
      finally { s.quarantineReading = undefined; armQuarantineTimer(s); }
    })();
    return s.quarantineReading;
  }
  // src/app.js:2672-2690: discard only unreadable records; preserve readable
  // pending reservations. The background write queue replaces withActivityLock.
  function discardActivity(s) {
    const operation = writes.catch(() => {}).then(async () => {
      current(s);
      if (!(s.activityBlocked || s.quarantined.length)) return;
      const saved = await storage.get([VAULT_KEY, ACTIVITY_KEY]); current(s);
      const blocked = s.activityBlocked, previous = saved[ACTIVITY_KEY];
      const encrypted = blocked ? await serializeActivity(s.id, [], s.key, [])
        : await serializeWithoutQuarantined(previous, s.id, s.addresses, s.key, s.rows.map(row => ({ ...row })));
      const latest = await storage.get([VAULT_KEY, ACTIVITY_KEY]); current(s);
      if (saved[VAULT_KEY] !== s.vault || latest[VAULT_KEY] !== s.vault || latest[ACTIVITY_KEY] !== previous) throw new Error('Wallet or history changed. Unlock again before discarding history.');
      await storage.set({ [ACTIVITY_KEY]: encrypted }); current(s);
      if (blocked) { for (const row of s.rows) row.envelope?.fill(0); s.rows = []; }
      s.quarantined = []; s.releasedQuarantine.clear(); s.activityBlocked = false; s.activityError = undefined; stopQuarantineTimer(s);
      return 'Unreadable local history discarded; readable records and their held coins were kept. Check the account explorer before resending any previous payment.';
    });
    writes = operation; return operation;
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
    // Package 7a shares the existing authenticated Activity writer. Only the
    // background chain handlers receive this handle, never the trusted/site API.
    // src/app.js:202-225,2358-2362: one saved list for all chains, one write
    // queue; src/app.js:353-361: account-history cache under its own key.
    chainActivity(chain, networkId = 'mainnet') {
      if (!['solana', 'tron'].includes(chain)) throw new Error('Unsupported chain.');
      const s = active();
      const check = () => { lockCoordinator.assertUnlocked(); current(s); s.assertReady?.(); };
      const network = chainNetwork(chain, networkId);
      if (network.id !== 'mainnet') {
        const key = `${chain}.${network.id}`;
        if (!s.networkActivities.has(key)) s.networkActivities.set(key,
          createNetworkActivity({ chain, network, session: s, storage, current: check }));
        return s.networkActivities.get(key);
      }
      return {
        get client() { check(); return s.client; },
        error() { check(); return s.activityError ?? ''; },
        assertSendable() {
          check();
          if (s.activityBlocked) throw new Error('Saved activity is unverified. Check the explorer and discard the unreadable history before sending.');
        },
        rows() { check(); return s.rows.filter(row => row.chain === chain && row.address === s.addresses[chain]); },
        append(transfer, details) {
          check();
          if (transfer.chain !== chain || transfer.from !== s.addresses[chain]) throw new Error('Invalid activity owner.');
          const row = recordActivity(transfer, details); s.rows.push(row); return row;
        },
        persist() { check(); return persist(s); },
        history() { check(); const page = s.history[chain]; return page?.address === s.addresses[chain] ? page : null; },
        saveHistory(page) {
          check(); s.history[chain] = page;
          const operation = writes.catch(() => {}).then(async () => {
            check();
            const saved = await storage.get(VAULT_KEY); check();
            if (saved[VAULT_KEY] !== s.vault) throw new Error('Wallet storage changed.');
            const encrypted = await serializeHistory(s.id, s.history, s.historyKey); check();
            await storage.set({ [HISTORY_KEY]: encrypted }); check();
          });
          writes = operation; return operation;
        },
      };
    },
    consumeNodusSeed,
    getAccount() {
      const s = active(), publicKey = s.client.publicKey;
      if (typeof publicKey !== 'string' || !/^[0-9a-f]{5184}$/.test(publicKey)) throw new Error('Nodus site signing is not available in this wallet build.');
      return { address: s.addresses.nodus, publicKey: `0x${publicKey}` };
    },
    async signMessage(origin, params) {
      // Surface only: pinned MetaMask eth-json-rpc-middleware 24.0.2
      // dist/wallet.mjs:257-297 (personal_sign [message, account], including
      // recognizable reversed ordering). Nodus's address replaces EVM's.
      if (!getPermittedAccounts(origin).length) throw providerErrors.unauthorized();
      if (!Array.isArray(params) || params.length < 2) throw rpcErrors.invalidInput();
      const resemblesAddress = value => typeof value === 'string' && /^[0-9a-f]{128}$/i.test(value);
      const reversed = resemblesAddress(params[0]) && !resemblesAddress(params[1]);
      const from = reversed ? params[0] : params[1], data = reversed ? params[1] : params[0];
      if (!resemblesAddress(from) || !data || typeof data !== 'string') throw rpcErrors.invalidParams('Invalid site message.');
      const account = from.toLowerCase(), s = active();
      const assertCurrent = () => {
        current(s); lockCoordinator.assertUnlocked(); s.assertReady?.();
        if (account !== s.addresses.nodus || !getPermittedAccounts(origin).some(item => item.address === account && item.publicKey === `0x${s.client.publicKey}`)) throw providerErrors.unauthorized();
      };
      assertCurrent();
      // SignatureController 39.2.10 dist/utils/normalize.cjs:42-53:
      // nonempty hex is bytes; "0x" and other strings use UTF-8.
      // @metamask/utils 12.0.0 dist/hex.js:168-173 strips 0x and 0X.
      // eth-sig-util 9.0.0 dist/utils.js:46-49 -> @ethereumjs/util
      // 8.1.0 dist/bytes.js:145-149 left-pads odd hex before decoding.
      const stripped = data.startsWith('0x') || data.startsWith('0X') ? data.slice(2) : data;
      const message = Uint8Array.from(/^[0-9A-Fa-f]+$/gu.test(stripped)
        ? Buffer.from(stripped.length % 2 ? `0${stripped}` : stripped, 'hex') : Buffer.from(data, 'utf8'));
      // Decision 2026-10-28-extension-nodus-site-signing.md, 2026-10-29:
      // 64 KiB of decoded bytes, refused before any approval is created.
      if (message.length > 65536) {
        message.fill(0);
        throw rpcErrors.invalidParams('Site messages must not exceed 65536 bytes.');
      }
      const hex = `0x${Buffer.from(message).toString('hex')}`;
      // MetaMask ui/pages/confirmations/components/confirm/info/personal-sign/
      // personal-sign.tsx:45-50, 139-164 + ui/helpers/utils/util.js:707-719,
      // 825-836: textContent-equivalent text, format characters escaped,
      // 32-byte values shown as hex. Buffer replaces malformed UTF-8, as
      // hexToText does in the reference. Full bytes remain visible too.
      const text = message.length === 32 ? hex : Buffer.from(message).toString('utf8').replace(/\p{Cf}/gu,
        char => `\\u${char.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}`);
      try {
        // Same locked refusal as evm.js capture()/approved(): assert before
        // approval and after each await; client.lock rejects queued/in-flight work.
        await approvals.controller.addAndShowApprovalRequest({ origin, type: 'nodus_signMessage', requestData: { account, data: hex, text } });
        assertCurrent();
        const signature = await s.client.siteSignMessage({ origin, message }, { signal: s.abort.signal, assertCurrent });
        try {
          assertCurrent();
          if (!(signature instanceof Uint8Array) || signature.length !== 4627) throw new Error('Invalid Nodus signature.');
          return `0x${Buffer.from(signature).toString('hex')}`;
        } finally { if (signature instanceof Uint8Array) signature.fill(0); }
      } finally { message.fill(0); }
    },
    reconcileQuarantine() { return session ? reconcileQuarantine(session) : Promise.resolve(); },
    async discardActivity() {
      const s = active(), message = await discardActivity(s);
      for (const activity of s.networkActivities.values()) await activity.discard();
      // src/app.js:2689: use the unchanged recovery message for testnets too.
      return message ?? 'Unreadable local history discarded; readable records and their held coins were kept. Check the account explorer before resending any previous payment.';
    },
    getState() { return { state: session?.client.state ?? 'locked', tokens: nodusTokens(session?.client.tokenPins()), historyReadable: session?.client.historyReadable ?? false,
      evmBuildable: session?.client.evmBuildable ?? false, evmReadable: session?.client.evmReadable ?? false,
      publicKey: session?.client.publicKey ? `0x${session.client.publicKey}` : undefined,
      // src/app.js:2559: recovery is offered only for the unlock-time read problem or quarantine.
      activityError: session?.activityBlocked ? session.activityError : [...(session?.networkActivities.values() ?? [])].find(activity => activity.blocked)?.error() ?? '', quarantinedCount: session?.quarantined.length ?? 0 }; },
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
      if (s.activityBlocked) throw new Error('Saved activity is unverified. Check the explorer and discard the unreadable history before sending.');
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
      if (s.activityBlocked) throw new Error('Saved activity is unverified. Check the explorer and discard the unreadable history before sending.');
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
            // src/app.js:1241-1266: signed before persistence and submission.
            record.note = 'Smart-contract transaction signed; sending.';
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
          // src/app.js:2389-2412: only an existing record gets the Activity
          // outcome note. A serializable flag carries that fact to the UI.
          throw rpcErrors.internal({ message: error.message, data: { activityTracked: true } });
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

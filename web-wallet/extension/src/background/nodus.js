import { createNodusClient, NODUS_CONNECT_BOUND_MS } from '../../../src/nodus/client.js';
import { nodusSigningSeed } from '../../../src/nodus/derive.js';
import { createSessionLog, stepLog } from '../../../src/session-log.js';
import { createChainHistory } from './chain-history.js';
import { createSharedVaults } from './shared-vaults.js';
import { nodusSendModuleFactory } from '../../../src/nodus/send-module.js';
import { deriveNodusAddress } from '../../../src/nodus/derive.js';
import * as adapter from '../../../src/adapters/nodus.js';
import { readCpunk } from '../../../src/adapters/cpunk.js';
import { readIxiosBalance } from '../../../src/ixios/balance.js';
import { IXIOS_NETWORK } from '../../../src/ixios/network.js';
import { prepareTransfer } from '../../../src/wallet.js';
import { NODUS_ASSET, nodusTokens } from '../../../src/nodus/network.js';
import { NODUS_HISTORY_LIMIT, localRowsToShow, nodusHistoryRow, nodusHistoryStatus } from '../../../src/nodus/history.js';
import { keepBusyEnvelope, canResubmit, dropSettledEnvelope, resubmitKept, NODUS_UNCERTAIN_NOTE, NODUS_SUBMITTED_NOTE } from '../../../src/nodus/resubmit.js';
import { recordActivity, watchActivity, terminal, evmActivityText } from '../../../src/activity.js';
import { activityKeyFor, parseActivity, serializeActivity, serializeWithoutQuarantined, requireSavedForEvm,
  historyKeyFor, parseHistory, serializeHistory, balancesKeyFor, parseBalances, serializeBalances,
  addressBookKeyFor, parseAddressBook, serializeAddressBook } from '../../../src/activity-storage.js';
import { checkAddressBook } from '../../../src/address-book.js';
import { ACTIVITY_KEY, VAULT_KEY, HISTORY_KEY, BALANCES_KEY, ADDRESS_BOOK_KEY } from '../../../src/vault.js';
import { EvmAccount, Contract, describeArgs } from '../../../src/evm/contract.js';
import { parseRaw, parseWei, formatRaw, formatWei } from '../../../src/evm/units.js';
import { rpcErrors, providerErrors } from '@metamask/rpc-errors';
import { Buffer } from 'buffer';
import { createNetworkActivity } from './network-activity.js';
import { chainNetwork } from '../constants/networks.js';

// Approved plan §3.5 holder 3 / §5.4–5.5: the web-wallet client and its one
// module queue live in the background. No secret or signed envelope enters UI state.
export function createNodus({ lockCoordinator, storage, getAddresses, factory = nodusSendModuleFactory, approvals, getPermittedAccounts, onLock, getWords, onClient, onStateChanged, onActivityChanged }) {
  let session, nextReview = 0, writes = Promise.resolve();
  const log = createSessionLog();
  function lock() {
    onLock?.();
    const previous = session; session = undefined;
    if (!previous) { log.clear(); return; }
    clearTimeout(previous.retryTimer); previous.retryTimer = undefined;
    stopQuarantineTimer(previous);
    // Let the client reject its queue as locked before aborting read requests.
    previous.client.lock();
    previous.abort.abort(); previous.stopTracking?.();
    for (const review of previous.reviews.values()) review.cancel();
    previous.reviews.clear();
    for (const row of previous.rows) row.envelope?.fill(0);
    previous.rows = []; previous.quarantined = []; previous.releasedQuarantine.clear(); previous.key = null;
    previous.historyKey = null; previous.history = {};
    previous.balancesKey = null; previous.kept = {}; previous.contractAccount = null;
    previous.addressBookKey = null; previous.addressBook = [];
    sharedVaults.lock(); previous.receipts?.clear();
    previous.networkActivities?.clear();
    // src/app.js:1770 clears after client shutdown logs its final state.
    log.clear();
    onStateChanged?.();
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
  const sharedVaults = createSharedVaults({ active });
  function changed(s) {
    if (session !== s) return;
    try { s.assertReady?.(); onStateChanged?.(); } catch { /* unlock publishes only after all holders are ready */ }
  }
  // src/app.js:998-1119: only replace the connection; the unlocked wallet's
  // authenticated rows and cache keys survive. No phrase copy lives here.
  function scheduleRetry(s, again) {
    if (session !== s || s.abort.signal.aborted) return;
    clearTimeout(s.retryTimer);
    const wait = [5000, 10000, 20000, 40000, 60000][Math.min(s.retries++, 4)];
    log.log('net', `retry ${s.retries} in ${wait / 1000} s (${again ? 'same connection' : 'new connection'})`);
    s.retryTimer = setTimeout(() => {
      s.retryTimer = undefined;
      if (session === s && !s.abort.signal.aborted && !lockCoordinator.isLocked) void (again ? again() : reconnect(s));
    }, wait);
  }
  function makeAccount(s) {
    s.contractAccount = new EvmAccount({ client: s.client, fingerprint: s.addresses.nodus, lockedInputs: () => heldInputs(s),
      reservations: () => s.rows.filter(row => row.chain === 'nodus' && row.address === s.addresses.nodus && !terminal(row.status)
        && !adapter.isClaimRow(row) && (row.kind === 'evm' || (row.kind === undefined && row.to === s.addresses.nodus))) });
  }
  function newClient(s) {
    s.connection = (s.connection ?? 0) + 1;
    let previous = 'idle', wasReady = false;
    const client = createNodusClient({ factory, steps: stepLog(log, 'net', () => s.retries + 1, NODUS_CONNECT_BOUND_MS),
      onState(state, why) {
        log.log('net', `client state ${previous} → ${state}`, { error: state === 'error' }); previous = state;
        if (session !== s || s.client !== client) return;
        if (state === 'ready') { wasReady = true; s.retries = 0; makeAccount(s); onClient?.(client); }
        else if (wasReady && ['error', 'locked'].includes(state)) {
          if (why?.error) log.log('net', why.error, { error: true });
          scheduleRetry(s);
        }
        changed(s);
      } });
    return client;
  }
  async function connectIdentified(s, client) {
    try { await client.connectNetwork(); current(s); }
    catch (error) {
      if (session !== s || s.client !== client || s.abort.signal.aborted) return;
      log.log('net', error, { error: true });
      scheduleRetry(s, client.identified ? () => connectIdentified(s, client) : undefined);
    }
  }
  async function reconnect(s) {
    let seed;
    try {
      current(s); lockCoordinator.assertUnlocked();
      const previous = s.client; s.client = undefined; previous?.lock();
      s.contractAccount = null;
      sharedVaults.lock();
      for (const review of s.reviews.values()) review.cancel(); s.reviews.clear();
      const client = s.client = newClient(s);
      seed = nodusSigningSeed(getWords());
      await client.identify({ seed, fingerprint: s.addresses.nodus }); current(s);
      await connectIdentified(s, client);
    } catch (error) { if (session === s && !s.abort.signal.aborted) { log.log('net', error, { error: true }); scheduleRetry(s); } }
    finally { seed?.fill(0); }
  }
  async function consumeNodusSeed(seed, { phrase, id, addresses, nodusWasmBytes, signal, assertReady } = {}) {
    lock();
    if (typeof factory !== 'function') throw new Error('Nodus sending is not available in this wallet build.');
    const s = { abort: new AbortController(), rows: [], quarantined: [], activityBlocked: false, retries: 0,
      releasedQuarantine: new Set(), quarantineReadAt: -Infinity, reviews: new Map(), networkActivities: new Map(), assertReady, id };
    session = s;
    s.client = newClient(s);
    try {
      const combined = signal ? AbortSignal.any([signal, s.abort.signal]) : s.abort.signal;
      const fingerprint = await deriveNodusAddress(phrase, { wasmBytes: nodusWasmBytes, signal: combined });
      current(s); combined.throwIfAborted();
      s.addresses = { ...addresses, nodus: fingerprint };
      s.key = await activityKeyFor(phrase, id);
      current(s); combined.throwIfAborted();
      // src/app.js:2528-2542: the saved wallet's separate encrypted account
      // history key/cache, using the original format and derivation unchanged.
      s.historyKey = await historyKeyFor(phrase, id);
      s.balancesKey = await balancesKeyFor(phrase, id);
      s.addressBookKey = await addressBookKeyFor(phrase, id); phrase = null;
      current(s); combined.throwIfAborted();
      const saved = await storage.get([VAULT_KEY, ACTIVITY_KEY, HISTORY_KEY, BALANCES_KEY, ADDRESS_BOOK_KEY]); current(s);
      s.vault = saved[VAULT_KEY];
      try { s.history = await parseHistory(saved[HISTORY_KEY], id, s.historyKey); }
      catch { s.history = {}; }
      try { s.kept = await parseBalances(saved[BALANCES_KEY], id, s.balancesKey); }
      catch { s.kept = {}; }
      try { s.addressBook = await parseAddressBook(saved[ADDRESS_BOOK_KEY], id, s.addressBookKey); }
      catch { s.addressBook = []; s.addressBookNote = 'Saved address book could not be read. It is left as it is until you save an address.'; }
      current(s); combined.throwIfAborted();
      // src/app.js:2543-2550: only the unlock-time read problem blocks sending.
      try {
        s.rows = await parseActivity(saved[ACTIVITY_KEY], id, s.addresses, s.key);
        s.quarantined = s.rows.quarantined ?? [];
      } catch (error) { s.activityBlocked = true; s.activityError = error.message; }
      current(s); combined.throwIfAborted();
      onActivityChanged?.(s.rows, { restored: true });
      const identity = await s.client.unlock({ seed, fingerprint }); current(s);
      // src/evm/ui.js:96-104 and src/app.js:1275-1279: one account queue,
      // sharing the native pending coins and restored self-address records.
      return { ...identity, client: s.client };
    } catch (error) { if (session === s) lock(); throw error; }
    finally { phrase = null; seed.fill(0); }
  }
  // src/app.js:202-225: authenticate, merge and seal before broadcast. The
  // service worker owns all writes, so its queue also joins every wallet UI.
  function persist(s) {
    const notificationRows = s.rows.map(({ chain, hash, status }) => ({ chain, hash, status }));
    onActivityChanged?.(notificationRows.filter(row => terminal(row.status)));
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
      onActivityChanged?.(notificationRows);
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
        kind: row.kind, name: row.name,
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
    s.receipts ??= new Map(); s.receipts.set(sent.intentId, sent.receipt);
    void sent.receipt.then(result => {
      if (session === s) s.contractOutcome = describeArgs(['Outcome'], [result]);
    }, error => { if (session === s) s.contractOutcome = error.message; });
  }
  function rememberReview(s, review) {
    try { current(s); } catch (error) { review.cancel(); throw error; }
    const id = String(++nextReview); s.reviews.set(id, review);
    return { id, to: review.to, amount: review.amount, symbol: review.symbol, kind: review.kind, recipientName: review.recipientName,
      fee: review.fee, review: review.review, expiresAt: review.expiresAt };
  }
  function assertActivity(s) {
    if (s.activityBlocked) throw new Error('Saved activity is unverified. Check the explorer and discard the unreadable history before sending.');
  }
  return {
    // Package 7a shares the existing authenticated Activity writer. Only the
    // background chain handlers receive this handle, never the trusted/site API.
    // src/app.js:202-225,2358-2362: one saved list for all chains, one write
    // queue; src/app.js:353-361: account-history cache under its own key.
    chainActivity(chain, networkId = 'mainnet') {
      if (!['ethereum', 'bsc', 'solana', 'tron', 'cellframe'].includes(chain)) throw new Error('Unsupported chain.');
      const s = active();
      if (chain === 'cellframe') s.addresses.cellframe = getAddresses().cpunk;
      const check = () => { lockCoordinator.assertUnlocked(); current(s); s.assertReady?.(); };
      const network = chainNetwork(chain, networkId);
      if (network.id !== 'mainnet') {
        const key = `${chain}.${network.id}`;
        if (!s.networkActivities.has(key)) s.networkActivities.set(key,
          createNetworkActivity({ chain, network, session: s, storage, current: check, onActivityChanged }));
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
    replaceVault(previous, value) { if (session?.vault === previous) session.vault = value; },
    assertVault(value) { const s = active(); assertActivity(s); if (s.vault !== value) throw new Error('Lock and unlock the saved wallet before changing its password.'); },
    readSharedVault: (method, fields) => sharedVaults.read(method, fields),
    prepareSharedVault: (method, fields) => sharedVaults.prepare(method, fields),
    confirmSharedVault: id => sharedVaults.confirm(id),
    cancelSharedVault: id => sharedVaults.cancel(id),
    async contractOperation(method, fields = {}) {
      const s = active(), account = contract(s); let value;
      if (method === 'account') value = { ...await account.account({ signal: s.abort.signal }), pending: account.waiting() };
      else if (method === 'ticket') value = await account.ticket(fields.ticketId, { signal: s.abort.signal });
      else if (method === 'simulate' || method === 'estimate') {
        const args = { ...fields, data: Uint8Array.from(fields.data ?? []), valueWei: BigInt(fields.valueWei ?? '0') };
        if (args.gas !== undefined) args.gas = BigInt(args.gas);
        value = await account[method](args, { signal: s.abort.signal });
      } else throw new Error('Unknown smart-contract read.');
      current(s); return value;
    },
    async getContractReceipt(intentId) {
      const s = active(), promise = s.receipts?.get(intentId);
      if (!promise) throw new Error('No smart-contract receipt is being tracked for this transaction.');
      const result = await promise; current(s); return result;
    },
    getAddressBook() { const s = active(); return { entries: s.addressBook.map(entry => ({ ...entry })), note: s.addressBookNote ?? '' }; },
    async getStakingOverview() { const s = active(); const view = await adapter.stakingOverview({ client: s.client, from: s.addresses.nodus }); current(s); return view; },
    async prepareStake(kind, params) {
      const s = active(); assertActivity(s);
      if (!['delegate', 'undelegate', 'stake'].includes(kind)) throw new Error('Unknown staking action.');
      return rememberReview(s, await adapter.prepareStake({ ...params, kind, client: s.client, from: s.addresses.nodus, locked: heldInputs(s) }));
    },
    async getOwnName() { const s = active(); const own = await adapter.ownChainName({ client: s.client, from: s.addresses.nodus, signal: s.abort.signal }); current(s); return own; },
    async getNamePrices() { const s = active(); const value = adapter.parseNamePrices(await s.client.namePrices()); current(s); return { ...value, text: adapter.namePriceList(value.prices) }; },
    async quoteName(name) { const s = active(); const value = await adapter.nameQuote({ client: s.client, from: s.addresses.nodus, name, signal: s.abort.signal }); current(s); return value; },
    async prepareName(name) { const s = active(); assertActivity(s); return rememberReview(s, await adapter.prepareName({ client: s.client, from: s.addresses.nodus, name, locked: heldInputs(s) })); },
    async getClaimStatus() {
      const s = active(), status = await adapter.claimStatus({ client: s.client, from: s.addresses.nodus, signal: s.abort.signal }); current(s);
      const unresolved = s.rows.some(row => row.address === s.addresses.nodus && adapter.isClaimRow(row) && !terminal(row.status));
      return { ...status, claimable: status.claimable && !unresolved };
    },
    async prepareClaim() { const s = active(); assertActivity(s); return rememberReview(s, await adapter.prepareClaim({ client: s.client, from: s.addresses.nodus })); },
    setAddressBook(entries) {
      const s = active(), next = checkAddressBook(entries);
      const job = writes.catch(() => {}).then(async () => {
        current(s); const value = await serializeAddressBook(s.id, next, s.addressBookKey); current(s);
        const saved = await storage.get(VAULT_KEY); current(s);
        if (saved[VAULT_KEY] !== s.vault) throw new Error('Wallet storage changed.');
        await storage.set({ [ADDRESS_BOOK_KEY]: value }); current(s); s.addressBook = next; s.addressBookNote = '';
      }); writes = job; return job;
    },
    async checkLiveness() { const s = active(); if (s.client.state === 'ready') await s.client.checkLiveness(); },
    getSessionLog() { return { entries: log.entries(), running: log.running(), startedAt: log.startedAt }; },
    getKeptBalances() {
      const s = active();
      return Object.fromEntries(Object.entries(s.kept).map(([key, value]) => [key, { ...value, units: value.units.toString() }]));
    },
    keepBalances(entries) {
      const s = active();
      const job = writes.catch(() => {}).then(async () => {
        current(s);
        const value = await serializeBalances(s.id, entries, s.balancesKey); current(s);
        const checked = await parseBalances(value, s.id, s.balancesKey); current(s);
        const saved = await storage.get(VAULT_KEY); current(s);
        if (saved[VAULT_KEY] !== s.vault) throw new Error('Wallet storage changed.');
        await storage.set({ [BALANCES_KEY]: value }); current(s); s.kept = checked;
      });
      writes = job; return job;
    },
    getChainHistory(chain, options) {
      const s = active();
      s.chainHistory ??= createChainHistory({ getActivity: name => this.chainActivity(name), getAddresses,
        signal: s.abort.signal, assertCurrent: () => { lockCoordinator.assertUnlocked(); current(s); } });
      return s.chainHistory.getHistory(chain, options);
    },
    getChainLocalHistory(chain) { return this.chainActivity(chain).rows().map(row => ({ ...row })); },
    async abandonActivity(chain, hash, networkId = 'mainnet') {
      if (!['ethereum', 'bsc', 'solana', 'tron'].includes(chain)) throw new Error('This activity cannot be abandoned.');
      const activity = this.chainActivity(chain, networkId); await activity.ready;
      const row = activity.rows().find(row => row.hash === hash);
      if (!row || terminal(row.status)) throw new Error('This activity cannot be abandoned.');
      row.status = 'abandoned'; row.note = 'Marked abandoned by you; the network may still include it. Check the explorer.';
      await activity.persist();
    },
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
    getState() { return { state: session?.retryTimer ? 'connecting' : session?.client.state ?? 'locked', connection: session?.connection ?? 0, tokens: nodusTokens(session?.client.tokenPins()), historyReadable: session?.client.historyReadable ?? false,
      stakeable: session?.client.stakeable ?? false, nameable: session?.client.nameable ?? false, registrable: session?.client.registrable ?? false,
      claimable: session?.client.claimable ?? false, vaultable: session?.client.vaultable ?? false,
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
    async getIxiosBalance() {
      const s = active(), address = getAddresses().ixios;
      if (!address) throw new Error('Ixios address unavailable. Lock and reopen your wallet to retry.');
      const result = await readIxiosBalance(address, IXIOS_NETWORK.endpoint, { signal: s.abort.signal }); current(s); return result;
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
      const d = review.decoded;
      return { id, intentId: review.intentId, review: review.review, expiresAt: review.expiresAt,
        decoded: { op: d.op, amount: d.amount.toString(), fee: d.fee.toString(), valueWei: d.valueWei.toString(), dest: d.dest } };
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

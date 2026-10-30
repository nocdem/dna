import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { deriveNodusAddress, nodusSigningSeed } from '../../src/nodus/derive.js';
import { activityKeyFor, parseActivity, serializeActivity } from '../../src/activity-storage.js';
import { NODUS_SUBMITTED_NOTE } from '../../src/nodus/resubmit.js';
import { serializeError } from '@metamask/rpc-errors';
import { ACTIVITY_KEY, VAULT_KEY, parseVault } from '../../src/vault.js';
import { NODUS_TOKEN_ID } from '../../src/nodus/network.js';
import { AUTO_LOCK_TIMEOUT_ALARM } from '../src/background/auto-lock-alarm.js';
import { chainNetwork } from '../src/constants/networks.js';
import { connectTrusted } from '../src/ui/trusted-port.js';
import { createWalletUi } from '../src/ui/wallet-ui.js';

// Public web-wallet vector and fake module replies; no live transport is used.
const { phrase, address } = JSON.parse(readFileSync(new URL('../../test/fixtures/nodus-addresses.json', import.meta.url))).vectors[0];
const password = 'public-test-password-123', recipient = 'ab'.repeat(64), input = 'cd'.repeat(64), intent = 'ef'.repeat(64);
const nodusWasmBytes = readFileSync(new URL('../../src/nodus/mldsa87.wasm', import.meta.url));
const cpunkWasmBytes = readFileSync(new URL('../../src/cpunk/legacy-dilithium.wasm', import.meta.url));
const options = { nodusWasmBytes, cpunkWasmBytes };
function event() {
  const listeners = new Set();
  return { addListener(fn) { listeners.add(fn); }, removeListener(fn) { listeners.delete(fn); }, emit: (...args) => Promise.all([...listeners].map(fn => fn(...args))) };
}
function deferred() { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; }
let backgroundModule;
async function setup(t, moduleAdditions = {}, makeModule = module => module) {
  const values = {}, notificationValues = {}, notifications = [], calls = [], state = { busy: false, mismatch: false, historyBad: false, failSave: false }, memory = new Uint8Array(256).fill(7);
  const fixture = {
    runtime: { id: 'nodus-test', onConnect: event(), getManifest: () => ({ version: '0.1.132' }), getURL: path => `chrome-extension://nodus-test/${path}` },
    storage: { async get(key) { return Object.fromEntries((Array.isArray(key) ? key : [key]).map(name => [name, structuredClone(values[name])])); }, async set(items) {
      if (state.failSave && Object.keys(items).some(key => key.startsWith(ACTIVITY_KEY))) throw new Error('fixture storage failure');
      Object.assign(values, structuredClone(items));
    } },
    alarms: { onAlarm: event(), async clear() {}, async create() {} },
    notificationStorage: { async get(key) { return { [key]: structuredClone(notificationValues[key]) }; },
      async set(items) { Object.assign(notificationValues, structuredClone(items)); } },
    notifications: { async create(id, value) { notifications.push({ id, ...value }); state.onNotification?.(value); return id; } },
    windows: { onRemoved: event(), async getAll() { return []; } },
  };
  const module = {
    memory: { buffer: memory.buffer },
    async unlock({ seed }) {
      calls.push(['unlock', seed]);
      const expected = nodusSigningSeed(phrase);
      try { assert.deepEqual(seed, expected); } finally { expected.fill(0); }
      if (state.unlockWait) { state.entered.resolve(); await state.unlockWait.promise; }
      return { fingerprint: state.mismatch ? recipient : address, chainId: '12'.repeat(32) };
    },
    async identify(args) { return this.unlock(args); },
    async connectNetwork() {},
    async balance() { calls.push(['balance']); if (state.balanceWait) { state.entered.resolve(); return state.balanceWait.promise; } return { total: '500000000', spendable: '500000000' }; },
    async list() {
      calls.push(['list']);
      if (state.listWait) { state.entered.resolve(); return state.listWait.promise; }
      if (state.listBad) throw new Error('fixture coin view unavailable');
      return { tip: state.tip ?? '10', coins: [{ nullifier: input, amount: '500000000' }], truncated: false };
    },
    async rulesetInfo() { return { generation: state.evm ? '5' : '1', tip: '10', gen2Height: '0' }; },
    evmGeneration: 5,
    async evmQuery({ method }) {
      calls.push([method]);
      if (method === 'evm_account') return { n: '0', b: '0'.repeat(64), ch: '0'.repeat(64), cs: '0', h: '10' };
      if (method === 'evm_call') return { s: '1', o: '0'.repeat(63) + '7', gu: '1', h: '10' };
      if (method === 'evm_estimate') return { s: '1', o: '', gu: '1', h: '10', ge: '2', ue: '1', fe: '1' };
      if (method === 'evm_ticket') return { p: true, amt: '7', dst: address };
      if (method === 'evm_receipt') return {};
      assert.fail(`Unexpected fixture smart-contract read: ${method}`);
    },
    async evmBuild(request) {
      calls.push(['evmBuild', request]);
      return { envelope: new Uint8Array([4, 5, 6]), intentId: intent, decoded: {
        op: request.op, chainId: '12'.repeat(32), inputs: [input], to: '', valueWei: '', gasLimit: '0', nonce: request.nonce,
        units: '1', amount: request.amount, dest: request.dest, ticketId: request.ticketId, dataLength: 0,
        fee: '1', change: (500000000n - BigInt(request.amount) - 1n).toString(), expiryHeight: request.expiryHeight,
      } };
    },
    async buildAndSign(request) {
      calls.push(['build', request]);
      return { envelope: new Uint8Array([1, 2, 3]), intentId: intent, decoded: {
        recipient: state.badDecode ? address : request.to, amount: request.amount, fee: '1', change: '399999999', tokenChange: '0',
        tokenId: request.tokenId, expiryHeight: request.expiryHeight, chainId: '12'.repeat(32), inputs: [input],
      } };
    },
    async submit({ envelope }) {
      calls.push(['submit', [...envelope]]);
      assert.ok(values[ACTIVITY_KEY], 'the pending record must be durable before submit');
      state.onSubmit?.();
      if (state.submitWait) { state.entered.resolve(); await state.submitWait.promise; }
      if (state.busy) throw Object.assign(new Error('fixture busy'), { busy: true });
      return { accepted: true };
    },
    async scanConfirm() { calls.push(['scanConfirm']); return state.scanWait ? state.scanWait.promise : { found: false, tip: '10' }; },
    async tick() { calls.push(['tick']); },
    async addrHistory() {
      calls.push(['history']);
      return { enabled: true, from_height: '1', entries: [{ h: '9', i: '0', q: '0', kind: state.historyBad ? 'invented' : 'spend_in',
        amount: '100000000', token: NODUS_TOKEN_ID, fee: '0', peer: recipient, wire: intent, ts: '1' }] };
    },
    cancel() { calls.push(['cancel']); }, lock() { calls.push(['lock']); }, release() { calls.push(['release']); },
    ...moduleAdditions,
  };
  t.mock.method(globalThis, 'fetch', async () => { throw new Error('Unexpected network request.'); });
  if (!backgroundModule) {
    const saved = Object.getOwnPropertyDescriptor(globalThis, 'chrome'); globalThis.chrome = { ...fixture, storage: { local: fixture.storage } };
    try { backgroundModule = await import('../src/background/index.js'); await (await backgroundModule.background).destroy(); }
    finally { if (saved) Object.defineProperty(globalThis, 'chrome', saved); else delete globalThis.chrome; }
  }
  const background = await backgroundModule.createBackground({ ...fixture, nodusOptions: { factory: async () => makeModule(module) } });
  t.after(() => background.destroy());
  await background.vaultStore.create(password, phrase);
  return { background, fixture, values, calls, state, memory, notifications };
}

// Real submit and Activity scanner through background composition; no popup,
// flags, network or disk artifacts. A notifier-only test would miss the wiring.
// Incoming history starts the empty tracker at unlock. Advance its existing
// 12-second timer explicitly; waiting on wall time exceeds this test's bound.
test('a Nodus submit and its Activity confirmation notify without an open popup', { timeout: 10000 }, async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const { background, state, notifications, calls } = await setup(t);
  state.scanWait = deferred(); const finalShown = deferred();
  state.onNotification = value => { if (value.title.includes('confirmed')) finalShown.resolve(); };
  await background.unlock(password, options);
  await background.incomingNotifications.check();
  assert.ok(calls.some(([op]) => op === 'history'), 'incoming polling reads history at unlock');
  const review = await background.nodus.prepareSend({ to: recipient, amount: '1', tokenId: NODUS_TOKEN_ID });
  await background.nodus.confirmSend(review.id);
  await background.transactionNotifications.flush();
  assert.equal(notifications.length, 1); assert.match(notifications[0].title, /pending/u);
  assert.equal(calls.filter(([op]) => op === 'scanConfirm').length, 0, 'the existing tracker waits for its next tick');
  state.scanWait.resolve({ found: true, tip: '11', height: '11' });
  t.mock.timers.tick(12000);
  await finalShown.promise; await background.transactionNotifications.flush();
  assert.equal(calls.filter(([op]) => op === 'scanConfirm').length, 1);
  assert.equal(background.nodus.getLocalHistory()[0].status, 'confirmed');
  assert.equal(notifications.length, 2); assert.match(notifications[1].title, /confirmed/u);
  await background.nodus.getHistory(); await background.transactionNotifications.flush();
  assert.equal(notifications.length, 2);
});

// Real encrypted Activity restore resets all three saved confirmations to
// pending before the scanner confirms them again. An empty notification store
// models browser restart; a notifier-only final-row fixture misses that reset.
// In-memory module/storage replies; no flags, network or generated artifacts.
test('restored final Nodus transfers do not replay notifications when scanned again', { timeout: 10000 }, async t => {
  const { background, fixture, values, notifications } = await setup(t, {
    async scanConfirm() { return { found: true, tip: '11', height: '11' }; },
  });
  const rows = ['01', '02', '03'].map(prefix => savedRow({ hash: prefix.repeat(64), status: 'confirmed' }));
  await saveActivity(values, rows);
  const saved = deferred(), set = fixture.storage.set; let writes = 0;
  t.mock.method(fixture.storage, 'set', async items => {
    await set(items);
    if (items[ACTIVITY_KEY] && ++writes === rows.length) saved.resolve();
  });
  await background.unlock(password, options);
  assert.deepEqual(background.nodus.getLocalHistory().map(row => row.status), ['pending', 'pending', 'pending']);
  await background.transactionNotifications.flush(); assert.deepEqual(notifications, []);
  await background.nodus.getHistory(); await saved.promise;
  await background.transactionNotifications.flush();
  assert.deepEqual(background.nodus.getLocalHistory().map(row => row.status), ['confirmed', 'confirmed', 'confirmed']);
  assert.deepEqual(notifications, []);
});

// The mainnet and testnet Activity writers must both feed the same notifier.
// Rows are public fixtures, not broadcasts; this pins persistence wiring and
// that a known final result still notifies when the Activity save fails.
test('all external-chain Activity buckets notify their saved status changes', async t => {
  const { background, notifications, state } = await setup(t); await background.unlock(password, options);
  const addresses = background.walletKeys.getAddresses();
  for (const [chain, network, symbol, hash] of [
    ['ethereum', 'mainnet', 'ETH', '0x' + '11'.repeat(32)], ['bsc', 'mainnet', 'BNB', '0x' + '22'.repeat(32)],
    ['solana', 'mainnet', 'SOL', '1'.repeat(88)], ['tron', 'mainnet', 'TRX', '33'.repeat(32)],
    ['solana', 'devnet', 'SOL', '2'.repeat(88)], ['tron', 'nile', 'TRX', '44'.repeat(32)],
  ]) {
    const activity = background.nodus.chainActivity(chain, network); await activity.ready;
    const endpoint = chainNetwork(chain, network).endpoint;
    const record = activity.append({ chain, from: addresses[chain], to: addresses[chain], symbol, amount: '1', endpoint }, { hash, nonce: 7 });
    await activity.persist(); await background.transactionNotifications.flush();
    assert.match(notifications.at(-1).title, /pending/u);
    record.status = 'failed'; state.failSave = true;
    await assert.rejects(activity.persist(), /fixture storage failure/u);
    state.failSave = false; await background.transactionNotifications.flush();
    assert.match(notifications.at(-1).title, /failed/u);
  }
  assert.equal(notifications.length, 12);
});

// Node >=22.14, public phrase/in-memory transport, no flags/network/artifacts.
// Pins optional-module detection through getState, the real trusted mux and
// the page state holder. The optional methods are presence fixtures only;
// this does not prove live WASM/chain support or page visibility.
test('Nodus capabilities survive the background-to-page trusted state handoff', async t => {
  const optional = Object.fromEntries(['validators', 'delegations', 'stakeBuild', 'nameLookup', 'nameOf', 'profileAddress', 'namePrices', 'nameBuild',
    'vaultCreate', 'vaultOpen', 'vaultBalance', 'vaultCoins', 'vaultHistory', 'vaultPropose', 'vaultReview', 'vaultApprove', 'vaultSubmit']
    .map(method => [method, async () => { throw new Error(`Unexpected capability fixture call: ${method}`); }]));
  const { background, fixture } = await setup(t, { ...optional,
    stakingRules: { minDelegation: '10000000000', selfStake: '1000000000000000', commissionMaxBps: '5000', undelegateLockEpochs: '12', epochLength: '720', maxDelegators: '2048' } });
  const { runtime } = fixture;
  const pagePort = { name: 'popup', onMessage: event(), onDisconnect: event() };
  const workerPort = { name: 'popup', onMessage: event(), onDisconnect: event(), sender: { id: runtime.id, url: runtime.getURL('popup.html') } };
  let closed = false;
  pagePort.postMessage = message => { const copy = structuredClone(message); queueMicrotask(() => { if (!closed) workerPort.onMessage.emit(copy); }); };
  workerPort.postMessage = message => { const copy = structuredClone(message); queueMicrotask(() => { if (!closed) pagePort.onMessage.emit(copy); }); };
  pagePort.disconnect = workerPort.disconnect = () => { if (!closed) { closed = true; pagePort.onDisconnect.emit(pagePort); workerPort.onDisconnect.emit(workerPort); } };
  runtime.connect = () => { runtime.onConnect.emit(workerPort); return pagePort; };
  const client = connectTrusted({ runtime, page: 'popup.html' }), ui = createWalletUi(client);
  const flags = ['stakeable', 'nameable', 'registrable', 'vaultable'];
  try {
    await ui.refresh();
    for (const flag of flags) assert.equal(ui.state.nodus[flag], false, `locked ${flag}`);
    await background.unlock(password, options);
    await ui.refresh();
    assert.equal(ui.state.nodus.state, 'ready');
    for (const flag of flags) {
      assert.equal(background.nodus.getState()[flag], true, `module ${flag}`);
      assert.equal(ui.state.nodus[flag], true, `trusted ${flag}`);
    }
    await background.lock();
    await ui.refresh();
    for (const flag of flags) assert.equal(ui.state.nodus[flag], false, `relocked ${flag}`);
  } finally { client.close(); pagePort.disconnect(); }
});

// Package B2: the failed READY client is replaced without rebuilding session
// caches, and the sole phrase holder is disposed. No flags/network/artifacts.
// A fixture that never leaves ready would miss the retry and stale-client path.
test('lost ready connection replaces the client while preserving rows and wipes words on lock', async t => {
  const modules = [];
  const { background, calls, values, state } = await setup(t, {}, module => {
    const number = modules.length + 1;
    const instance = { ...module, async evmQuery(args) {
      const value = await module.evmQuery(args);
      return args.method === 'evm_account' ? { ...value, n: String(number) } : value;
    } };
    modules.push(instance); return instance;
  });
  state.evm = true;
  await saveActivity(values, [savedRow()]);
  await background.unlock(password, options);
  const wallet = background.walletKeys.getEvmWallet(), old = wallet.nodusClient;
  assert.equal((await background.nodus.contractOperation('account')).nonce, 1n);
  assert.equal(background.walletKeys.getRecoveryPhrase(), phrase);
  const before = background.nodus.getLocalHistory();
  t.mock.timers.enable({ apis: ['setTimeout'] });
  old.lock(); t.mock.timers.tick(5000);
  for (let turn = 0; turn < 1000 && (wallet.nodusClient === old || wallet.nodusClient?.state !== 'ready'); turn++) await new Promise(resolve => setImmediate(resolve));
  assert.notEqual(wallet.nodusClient, old); assert.equal(wallet.nodusClient.state, 'ready');
  assert.deepEqual(background.nodus.getLocalHistory(), before);
  assert.match(await background.nodus.readContract({ action: 'account' }), /NODUS/);
  assert.equal(modules.length, 2);
  assert.equal((await background.nodus.contractOperation('account')).nonce, 2n);
  assert.ok(calls.filter(row => row[0] === 'unlock').length >= 2);
  assert.ok(background.nodus.getSessionLog().entries.length > 0);
  await background.lock(); const count = calls.length;
  assert.deepEqual(background.nodus.getSessionLog().entries, []);
  assert.deepEqual(background.nodus.getSessionLog().running, []);
  t.mock.timers.tick(60000);
  assert.equal(wallet.recoveryPhrase, null); assert.equal(wallet.nodusClient, null);
  assert.throws(() => background.walletKeys.getRecoveryPhrase(), /locked/);
  assert.deepEqual(background.nodus.getSessionLog().entries, []);
  assert.deepEqual(background.nodus.getSessionLog().running, []); assert.equal(calls.length, count);
});

// B2: pause identification and network connection separately. Publishing on
// construction or after identify would both fail; an instant-ready mock would
// miss either early publication. No flags/network/artifacts.
test('reconnect publishes the name-lookup client only after it is ready', async t => {
  const connecting = deferred(), connected = deferred();
  const { background, state } = await setup(t, { async connectNetwork() {
    connecting.resolve(); await connected.promise;
  } });
  await background.unlock(password, options);
  const wallet = background.walletKeys.getEvmWallet(), old = wallet.nodusClient;
  const replace = background.walletKeys.replaceNodusClient.bind(background.walletKeys), publishedStates = [];
  const published = t.mock.method(background.walletKeys, 'replaceNodusClient', client => { publishedStates.push(client.state); replace(client); });
  state.entered = deferred(); state.unlockWait = deferred();
  t.after(() => { state.unlockWait.resolve(); connected.resolve(); });
  t.mock.timers.enable({ apis: ['setTimeout'] });
  old.lock(); t.mock.timers.tick(5000);
  await state.entered.promise;
  assert.equal(wallet.nodusClient, old); assert.equal(published.mock.callCount(), 0);
  state.unlockWait.resolve(); await connecting.promise;
  assert.equal(wallet.nodusClient, old); assert.equal(published.mock.callCount(), 0);
  connected.resolve();
  for (let turn = 0; turn < 1000 && wallet.nodusClient === old; turn++) await new Promise(resolve => setImmediate(resolve));
  assert.notEqual(wallet.nodusClient, old); assert.equal(wallet.nodusClient.state, 'ready');
  assert.equal(published.mock.callCount(), 1); assert.deepEqual(publishedStates, ['ready']);
});

// B2: retain the exact buffers passed to the module through multiple retries,
// including failed identification. Checking only the unlock seed could miss a
// later retry's buffer; checking only successful retries misses the error path.
test('every reconnect seed is wiped after identification succeeds or fails', async t => {
  const { background, calls, state } = await setup(t);
  await background.unlock(password, options);
  const wallet = background.walletKeys.getEvmWallet();
  t.mock.timers.enable({ apis: ['setTimeout'] });
  for (const [fails, delay] of [[false, 5000], [true, 5000], [false, 10000]]) {
    const before = calls.filter(([method]) => method === 'unlock').length;
    if (wallet.nodusClient.state === 'ready') wallet.nodusClient.lock();
    state.mismatch = fails; t.mock.timers.tick(delay);
    for (let turn = 0; turn < 1000; turn++) {
      const seeds = calls.filter(([method]) => method === 'unlock');
      if (seeds.length > before && seeds.at(-1)[1].every(byte => byte === 0) && (fails || wallet.nodusClient.state === 'ready')) break;
      await new Promise(resolve => setImmediate(resolve));
    }
    const seeds = calls.filter(([method]) => method === 'unlock');
    assert.equal(seeds.length, before + 1);
    for (const [, seed] of seeds) assert.ok(seed.every(byte => byte === 0));
    await new Promise(resolve => setImmediate(resolve));
  }
});

// Retain actual tracker callbacks to model a timer already queued when lock
// clears it. Awaiting each callback exposes its rejection without intercepting
// unhandledRejection or changing the reconnect test's timer lifecycle.
test('incoming balance tracker callbacks cannot read a locked or replaced session', async t => {
  const { background } = await setup(t), callbacks = [], schedule = globalThis.setTimeout;
  const activityFor = background.nodus.chainActivity.bind(background.nodus);
  let bscRows = 0;
  t.mock.method(background.nodus, 'chainActivity', (chain, ...args) => {
    const activity = activityFor(chain, ...args), rows = activity.rows;
    if (chain === 'bsc') t.mock.method(activity, 'rows', () => { bscRows++; return rows(); });
    return activity;
  });
  const balances = t.mock.method(background.evm, 'getBalances', background.evm.getBalances.bind(background.evm));
  t.mock.method(globalThis, 'setTimeout', (callback, delay, ...args) => {
    if (delay === 12000) callbacks.push(callback);
    return schedule(callback, delay, ...args);
  });
  await background.unlock(password, options);
  assert.equal(balances.mock.callCount(), 1, 'incoming polling starts the real BSC balance reader');
  assert.ok(bscRows > 0, 'the real BSC tracker reads the current session');
  assert.ok(callbacks.length >= 2, 'Nodus and BSC have installed their Activity trackers');
  const previous = [...callbacks], before = bscRows;
  await background.lock();
  for (const tick of previous) await tick();
  assert.equal(bscRows, before);
  await background.unlock(password, options);
  const reopened = bscRows;
  for (const tick of previous) await tick();
  assert.equal(bscRows, reopened, 'the old tracker cannot enter the replacement session');
});

// Hold the real BSC transport, not the balance facade. Lock must abort the
// request and settle the poll without any later native/token balance reads.
test('lock aborts the incoming BSC read and settles the pending check', async t => {
  const { background } = await setup(t), entered = deferred(), requests = [];
  let rejectRead, signal;
  t.mock.method(globalThis, 'fetch', async (url, request) => {
    if (String(url) !== new URL(background.evm.getState().endpoints.bsc).href) throw new Error('Unexpected network request.');
    requests.push(JSON.parse(request.body).method); signal = request.signal;
    entered.resolve();
    return new Promise((_, reject) => {
      rejectRead = reject;
      const cancel = () => reject(signal.reason);
      signal.addEventListener('abort', cancel, { once: true });
      if (signal.aborted) cancel();
    });
  });
  t.after(() => rejectRead?.(new Error('Held transport fixture released.')));
  await background.unlock(password, options); await entered.promise;
  const checking = background.incomingNotifications.check();
  await background.lock();
  assert.equal(signal.aborted, true, 'the session closes its in-flight BSC transport');
  await checking;
  assert.deepEqual(requests, ['eth_chainId']);
});

// G: background reads use the session account and reject unknown operations.
// No flags/network/artifacts. Facade-only mocks would miss these client calls.
test('contract account, simulation, estimate and ticket reads use the session client', async t => {
  const { background, state, calls } = await setup(t); state.evm = true;
  await background.unlock(password, options);
  assert.equal((await background.nodus.contractOperation('account')).balanceWei, 0n);
  const fields = { to: 'ab'.repeat(32), data: [], valueWei: '0' };
  assert.equal((await background.nodus.contractOperation('simulate', fields)).success, true);
  assert.equal((await background.nodus.contractOperation('estimate', fields)).gasLimit, 2n);
  assert.equal((await background.nodus.contractOperation('ticket', { ticketId: intent })).amountRaw, 7n);
  for (const method of ['evm_account', 'evm_call', 'evm_estimate', 'evm_ticket']) assert.ok(calls.some(call => call[0] === method));
  await assert.rejects(background.nodus.contractOperation('invented'), /Unknown/);
});

const savedRow = changes => ({ chain: 'nodus', address, to: recipient, symbol: 'NODUS', amount: '1.0', hash: '01'.repeat(64),
  createdAt: '2026-10-28T00:00:00.000Z', status: 'pending', expiryHeight: '100', fromHeight: '1', inputs: [input], ...changes });
async function saveActivity(values, rows = [], quarantined = []) {
  const id = parseVault(values[VAULT_KEY]).id, key = await activityKeyFor(phrase, id);
  values[ACTIVITY_KEY] = await serializeActivity(id, rows, key, quarantined.map(raw => ({ raw })));
  return { id, key };
}

// Proves explicit discard clears an unreadable or unverified file and reopens both send paths; no network or test artifacts.
test('discarding unreadable saved activity unblocks native and contract reviews', async t => {
  for (const saved of ['unreadable JSON', JSON.stringify({ version: 1 })]) {
    const { background, values } = await setup(t); values[ACTIVITY_KEY] = saved;
    await background.unlock(password, options);
    assert.ok(background.nodus.getState().activityError);
    await assert.rejects(background.nodus.prepareSend({ to: recipient, amount: '1', tokenId: NODUS_TOKEN_ID }), /discard the unreadable history/);
    await background.nodus.discardActivity();
    assert.equal(background.nodus.getState().activityError, '');
    const id = parseVault(values[VAULT_KEY]).id, key = await activityKeyFor(phrase, id);
    assert.deepEqual(await parseActivity(values[ACTIVITY_KEY], id, background.walletKeys.getAddresses(), key), []);
    const review = await background.nodus.prepareSend({ to: recipient, amount: '1', tokenId: NODUS_TOKEN_ID });
    background.nodus.cancelSend(review.id);
    await background.lock();
  }
  const { background, values, state } = await setup(t); state.evm = true; values[ACTIVITY_KEY] = 'unreadable JSON';
  await background.unlock(password, options);
  await assert.rejects(background.nodus.prepareContract({ action: 'deposit', amount: '1' }), /discard the unreadable history/);
  await background.nodus.discardActivity();
  const review = await background.nodus.prepareContract({ action: 'deposit', amount: '1' }); background.nodus.cancelSend(review.id);
});

// Proves partial discard keeps readable pending rows and their reservations, and does nothing to a readable live send; no artifacts.
test('discarding quarantined activity preserves readable saved and live pending sends', async t => {
  const { background, values } = await setup(t), otherInput = '02'.repeat(64);
  const readable = savedRow({ inputs: [otherInput] });
  const { id, key } = await saveActivity(values, [readable], [savedRow({ amount: 'unreadable' })]);
  await background.unlock(password, options);
  assert.equal(background.nodus.getState().quarantinedCount, 1);
  await assert.rejects(background.nodus.prepareSend({ to: recipient, amount: '1', tokenId: NODUS_TOKEN_ID }), /held by a pending send/);
  await background.nodus.discardActivity();
  const rows = await parseActivity(values[ACTIVITY_KEY], id, background.walletKeys.getAddresses(), key);
  assert.equal(rows.length, 1); assert.equal(rows.quarantined.length, 0); assert.deepEqual(rows[0].inputs, [otherInput]);
  assert.equal(background.nodus.getState().quarantinedCount, 0);
  const review = await background.nodus.prepareSend({ to: recipient, amount: '1', tokenId: NODUS_TOKEN_ID });
  await background.nodus.confirmSend(review.id);
  await background.nodus.discardActivity();
  await assert.rejects(background.nodus.prepareSend({ to: recipient, amount: '1', tokenId: NODUS_TOKEN_ID }), /held by a pending send/);
});

// Proves a tracker write failure never enables whole-file discard or destroys readable rows, reservations or kept envelope bytes.
// Incoming polling has already started this tracker before submit. Advance its
// frozen timer to reach the failing write; the promise alone cannot advance it.
// Synchronize only the Nodus baseline: another reader's pacing may need that
// same frozen clock. A held Solana history fixture pins this independence;
// it uses no network, flags or disk artifacts and is released during cleanup.
test('discard after a tracker persist failure keeps readable rows and busy envelopes', { timeout: 10000 }, async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  for (const quarantined of [[], [savedRow({ amount: 'unreadable', inputs: ['03'.repeat(64)] })]]) {
    const { background, values, state, calls, fixture } = await setup(t);
    const readable = savedRow({ inputs: ['02'.repeat(64)] });
    const { id, key } = await saveActivity(values, [readable], quarantined);
    const otherHistory = deferred();
    const solanaHistory = t.mock.method(background.solana, 'getHistory', () => otherHistory.promise);
    t.after(() => otherHistory.resolve({ rows: [] }));
    await background.unlock(password, options);
    await background.nodus.getHistory();
    assert.equal(calls.filter(([op]) => op === 'history').length, 2, 'incoming polling and the Nodus queue barrier both read history');
    assert.equal(solanaHistory.mock.callCount(), 1, 'the unrelated incoming reader remains pending');
    const failed = deferred(), set = fixture.storage.set;
    t.mock.method(fixture.storage, 'set', async items => {
      try { await set(items); }
      catch (error) { failed.resolve(); throw error; }
    });
    const review = await background.nodus.prepareSend({ to: recipient, amount: '1', tokenId: NODUS_TOKEN_ID });
    const scans = calls.filter(([op]) => op === 'scanConfirm').length;
    state.busy = true; state.onSubmit = () => { state.failSave = true; };
    await assert.rejects(background.nodus.confirmSend(review.id), /fixture busy/);
    assert.equal(calls.filter(([op]) => op === 'scanConfirm').length, scans);
    t.mock.timers.tick(12000);
    await failed.promise; await new Promise(resolve => setImmediate(resolve));
    assert.ok(calls.filter(([op]) => op === 'scanConfirm').length > scans, 'the timer ran the tracker after submit');
    otherHistory.resolve({ rows: [] });
    assert.equal(background.nodus.getState().activityError, '');
    assert.equal(background.nodus.getState().quarantinedCount, quarantined.length);
    assert.equal((await background.nodus.getHistory()).activityError, 'fixture storage failure');
    state.failSave = false;
    await background.nodus.discardActivity();
    const rows = await parseActivity(values[ACTIVITY_KEY], id, background.walletKeys.getAddresses(), key);
    assert.deepEqual(rows.map(row => row.hash).sort(), [readable.hash, intent].sort());
    assert.equal(rows.quarantined.length, 0);
    const local = background.nodus.getLocalHistory();
    assert.equal(local.length, 2); assert.equal(local.find(row => row.hash === intent).canResubmit, true);
    await assert.rejects(background.nodus.prepareSend({ to: recipient, amount: '1', tokenId: NODUS_TOKEN_ID }), /held by a pending send/);
    state.busy = false; state.onSubmit = undefined;
    assert.equal((await background.nodus.resubmit(intent)).outcome, 'sent');
    assert.deepEqual(calls.filter(([op]) => op === 'submit').map(([, bytes]) => bytes), [[1, 2, 3], [1, 2, 3]]);
    await background.lock();
  }
});

// Proves failed durability and changed history cannot clear the error or release coins; fixtures remain memory-only.
test('discard refuses storage failures and history changes during sealing', async t => {
  const { background, values, state, fixture } = await setup(t); values[ACTIVITY_KEY] = 'unreadable JSON';
  await background.unlock(password, options); state.failSave = true;
  await assert.rejects(background.nodus.discardActivity(), /storage failure/);
  assert.ok(background.nodus.getState().activityError); assert.equal(values[ACTIVITY_KEY], 'unreadable JSON');
  state.failSave = false;
  const get = fixture.storage.get;
  let reads = 0;
  t.mock.method(fixture.storage, 'get', async keys => {
    if (Array.isArray(keys) && keys.includes(ACTIVITY_KEY) && ++reads === 2) values[ACTIVITY_KEY] = 'changed history';
    return get(keys);
  });
  await assert.rejects(background.nodus.discardActivity(), /history changed/i);
  assert.equal(values[ACTIVITY_KEY], 'changed history'); assert.ok(background.nodus.getState().activityError);
});

// Proves the shared expiry judgment releases each record separately, including shared inputs; no absence-based release.
test('quarantine releases only beyond its validated expiry and keeps every other reservation', async t => {
  for (const expiries of [['9'], ['10'], [undefined], ['9', '10']]) {
    const { background, values } = await setup(t);
    await saveActivity(values, [], expiries.map((expiryHeight, index) => savedRow({ amount: 'unreadable', expiryHeight, hash: String(index + 3).repeat(128) })));
    await background.unlock(password, options); await background.nodus.reconcileQuarantine();
    const sending = background.nodus.prepareSend({ to: recipient, amount: '1', tokenId: NODUS_TOKEN_ID });
    if (expiries.length === 1 && expiries[0] === '9') {
      const review = await sending; background.nodus.cancelSend(review.id);
    } else await assert.rejects(sending, /held by a pending send/);
    await background.lock();
  }
});

// Proves 15-second monotonic pacing, failed reads keeping locks, and both lock paths stopping polls; only mock time advances.
test('quarantine polling follows web-wallet cadence and stops on manual or inactivity lock', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  let now = 0; t.mock.method(performance, 'now', () => now);
  for (const alarm of [false, true]) {
    const { background, values, state, calls, fixture } = await setup(t);
    await saveActivity(values, [], [savedRow({ amount: 'unreadable', expiryHeight: '10' })]);
    state.listBad = true;
    await background.unlock(password, options); await background.nodus.reconcileQuarantine();
    assert.equal(calls.filter(([op]) => op === 'list').length, 1);
    state.listBad = false;
    await assert.rejects(background.nodus.prepareSend({ to: recipient, amount: '1', tokenId: NODUS_TOKEN_ID }), /held by a pending send/);
    const reads = calls.filter(([op]) => op === 'list').length;
    now += 14999; t.mock.timers.tick(14999); assert.equal(calls.filter(([op]) => op === 'list').length, reads);
    state.tip = '11';
    now++; t.mock.timers.tick(1); await background.nodus.reconcileQuarantine();
    assert.equal(calls.filter(([op]) => op === 'list').length, reads + 1);
    const review = await background.nodus.prepareSend({ to: recipient, amount: '1', tokenId: NODUS_TOKEN_ID }); background.nodus.cancelSend(review.id);
    // Keep an unreleased row for the shutdown assertion rather than stopping only because all rows released.
    await background.lock(); state.tip = '10'; await background.unlock(password, options); await background.nodus.reconcileQuarantine();
    if (alarm) await fixture.alarms.onAlarm.emit({ name: AUTO_LOCK_TIMEOUT_ALARM }); else await background.lock();
    const before = calls.length; now += 30000; t.mock.timers.tick(30000);
    await background.nodus.reconcileQuarantine(); assert.equal(calls.length, before);
  }
});

// Proves an in-flight quarantine read cannot publish a release or re-arm after lock; no timers or network escape the fixture.
test('locking during quarantine reconciliation cancels the read and its next timer', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const { background, values, state, calls } = await setup(t);
  await saveActivity(values, [], [savedRow({ amount: 'unreadable', expiryHeight: '9' })]);
  state.listWait = deferred(); state.entered = deferred();
  await background.unlock(password, options); await state.entered.promise;
  const reading = background.nodus.reconcileQuarantine(); await background.lock(); await reading;
  state.listWait.resolve({ tip: '10', coins: [] });
  const before = calls.length; t.mock.timers.tick(30000); await background.nodus.reconcileQuarantine(); assert.equal(calls.length, before);
  assert.equal(background.nodus.getState().state, 'locked');
});

// Proves the contract row says signed before submit and submitted only after acceptance; mock timers stop receipt polling.
test('smart-contract activity records the signed then submitted note sequence', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const { background, state } = await setup(t); state.evm = true; state.scanWait = deferred(); await background.unlock(password, options);
  const notes = []; state.onSubmit = () => notes.push(background.nodus.getLocalHistory()[0].note);
  state.submitWait = deferred(); state.entered = deferred();
  const review = await background.nodus.prepareContract({ action: 'deposit', amount: '1' });
  const confirming = background.nodus.confirmSend(review.id); await state.entered.promise;
  assert.deepEqual(notes, ['Smart-contract transaction signed; sending.']);
  state.submitWait.resolve(); await confirming;
  assert.equal(background.nodus.getLocalHistory()[0].note, NODUS_SUBMITTED_NOTE);
});

// Proves the real background marks only recorded confirm failures, and the flag survives trusted-port error serialization.
test('confirm failure exposes Activity tracking only after a pending record exists', async t => {
  const { background, state } = await setup(t); await background.unlock(password, options);
  await assert.rejects(background.nodus.confirmSend('closed-review'), error => {
    assert.equal(serializeError(error).data.activityTracked, undefined); return true;
  });
  const review = await background.nodus.prepareSend({ to: recipient, amount: '1', tokenId: NODUS_TOKEN_ID }); state.busy = true;
  await assert.rejects(background.nodus.confirmSend(review.id), error => {
    const serialized = serializeError(error);
    assert.equal(serialized.message, 'fixture busy'); assert.equal(serialized.data.activityTracked, true); return true;
  });
});

// Pins the real vault → wallet-keys seed consumer → web-wallet client path, address parity and seed disposal.
test('background attaches the real Nodus consumer and unlocks the web-wallet identity', async t => {
  const { background, calls } = await setup(t);
  const result = await background.unlock(password, options);
  assert.equal(result.addresses.nodus, address);
  assert.equal(result.addresses.nodus, await deriveNodusAddress(phrase, { wasmBytes: nodusWasmBytes }));
  assert.equal(background.walletKeys.getAddresses().nodus, address);
  assert.equal(background.walletKeys.getEvmWallet().addresses.nodus, address);
  assert.equal(background.walletKeys.getEvmWallet().nodusClient.fingerprint, address);
  assert.equal(background.nodus.getState().state, 'ready');
  assert.ok(calls.find(([op]) => op === 'unlock')[1].every(byte => byte === 0));
  assert.equal(JSON.stringify(background.nodus.getState()).includes(phrase), false);
});

// Pins adapter balances, module-decoded review fields, durable submission and node-history validation.
test('balances, send and history reach the unchanged web-wallet implementations', async t => {
  const { background, calls, values } = await setup(t);
  await background.unlock(password, options);
  assert.deepEqual(await background.nodus.getBalances(), [{ symbol: 'NODUS', balance: '5.0' }]);
  const review = await background.nodus.prepareSend({ to: recipient, amount: '1', tokenId: NODUS_TOKEN_ID });
  assert.equal(review.to, recipient); assert.equal(review.amount, '1.0');
  assert.ok(review.review.some(([label, value]) => label === 'Valid until block' && value === '100'));
  assert.equal(await background.nodus.confirmSend(review.id), intent);
  const id = parseVault(values[VAULT_KEY]).id, key = await activityKeyFor(phrase, id);
  const saved = await parseActivity(values[ACTIVITY_KEY], id, background.walletKeys.getAddresses(), key);
  assert.equal(saved[0].hash, intent); assert.deepEqual(saved[0].inputs, [input]);
  await assert.rejects(background.nodus.confirmSend(review.id), /closed|review/i);
  const history = await background.nodus.getHistory();
  assert.equal(history.rows[0].title, 'Received'); assert.equal(history.rows[0].amount, '1.0 NODUS');
  assert.match(history.status, /one Nodus node/);
  for (const op of ['balance', 'list', 'build', 'submit', 'history']) assert.ok(calls.some(([name]) => name === op));
});

// Pins refusal of a signed-envelope mismatch, storage failure and malformed history without broadcasting.
test('invalid decoded fields and failed durability never submit a transfer', async t => {
  const { background, state, calls } = await setup(t); await background.unlock(password, options);
  state.badDecode = true;
  await assert.rejects(background.nodus.prepareSend({ to: recipient, amount: '1', tokenId: NODUS_TOKEN_ID }), /does not match/);
  state.badDecode = false;
  const review = await background.nodus.prepareSend({ to: recipient, amount: '1', tokenId: NODUS_TOKEN_ID }); state.failSave = true;
  await assert.rejects(background.nodus.confirmSend(review.id), /storage failure/);
  assert.equal(calls.some(([op]) => op === 'submit'), false);
  state.historyBad = true; await assert.rejects(background.nodus.getHistory(), /invalid account history/);
});

// Pins the shared coin reservation when two wallet windows prepare against the same unspent input.
test('a second prepared review cannot submit inputs reserved by the first send', async t => {
  const { background, calls } = await setup(t); await background.unlock(password, options);
  const fields = { to: recipient, amount: '1', tokenId: NODUS_TOKEN_ID };
  const first = await background.nodus.prepareSend(fields), second = await background.nodus.prepareSend(fields);
  await background.nodus.confirmSend(first.id);
  await assert.rejects(background.nodus.confirmSend(second.id), /held by a pending send/);
  assert.equal(calls.filter(([op]) => op === 'submit').length, 1);
});

// Pins src/evm's account derivation, ABI decoding, deposit review and shared pending-coin reservation in the background.
test('Nodus smart contracts reuse the web-wallet account, Contract and ABI code', async t => {
  const { background, state, calls } = await setup(t); state.evm = true; await background.unlock(password, options);
  assert.equal(background.nodus.getState().evmBuildable, true);
  const account = await background.nodus.readContract({ action: 'account' }); assert.match(account, /nonce/);
  const value = await background.nodus.readContract({ action: 'read', address: '0x' + '11'.repeat(32),
    abi: [{ type: 'function', name: 'value', stateMutability: 'view', inputs: [], outputs: [{ name: 'count', type: 'uint256' }] }], fn: 'value()', args: [] });
  assert.match(value, /7/);
  const review = await background.nodus.prepareContract({ action: 'deposit', amount: '1' });
  assert.ok(review.review.some(([label, text]) => label === 'Amount' && text === '1 NODUS'));
  assert.equal(await background.nodus.confirmSend(review.id), intent);
  await assert.rejects(background.nodus.prepareSend({ to: recipient, amount: '1', tokenId: NODUS_TOKEN_ID }), /held by a pending send/);
  for (const name of ['evm_account', 'evm_call', 'evmBuild', 'submit']) assert.ok(calls.some(([op]) => op === name));
});

// Pins explicit busy resubmission of identical bytes and preserves the web-wallet coin reservation.
test('a busy send keeps its envelope for explicit resubmission', async t => {
  const { background, state, calls } = await setup(t); await background.unlock(password, options);
  const review = await background.nodus.prepareSend({ to: recipient, amount: '1', tokenId: NODUS_TOKEN_ID }); state.busy = true;
  await assert.rejects(background.nodus.confirmSend(review.id), /fixture busy/);
  assert.equal((await background.nodus.getHistory()).local[0].canResubmit, true);
  await assert.rejects(background.nodus.prepareSend({ to: recipient, amount: '1', tokenId: NODUS_TOKEN_ID }), /held by a pending send/);
  state.busy = false; assert.equal((await background.nodus.resubmit(intent)).outcome, 'sent');
  assert.deepEqual(calls.filter(([op]) => op === 'submit').map(([, bytes]) => bytes), [[1, 2, 3], [1, 2, 3]]);
});

// Pins the complete client lock for both manual and inactivity paths, including queued reads and module memory.
test('manual and inactivity lock stop the Nodus queue and wipe its module', async t => {
  for (const alarm of [false, true]) {
    const { background, fixture, state, calls, memory } = await setup(t); await background.unlock(password, options);
    const wallet = background.walletKeys.getEvmWallet();
    state.balanceWait = deferred(); state.entered = deferred();
    const reading = background.nodus.getBalances(), rejected = assert.rejects(reading, /locked/i); await state.entered.promise;
    const queued = background.nodus.getBalances(), queuedRejected = assert.rejects(queued, /locked/i);
    if (alarm) await fixture.alarms.onAlarm.emit({ name: AUTO_LOCK_TIMEOUT_ALARM }); else await background.lock();
    await Promise.all([rejected, queuedRejected]); state.balanceWait.resolve({ total: '0', spendable: '0' });
    assert.ok(memory.every(byte => byte === 0));
    assert.deepEqual(calls.filter(([op]) => ['cancel', 'lock', 'release'].includes(op)).map(([op]) => op), ['cancel', 'lock', 'release']);
    assert.equal(background.nodus.getState().state, 'locked');
    assert.equal(wallet.nodusClient, null);
    await assert.rejects(background.nodus.prepareSend({ to: recipient, amount: '1', tokenId: NODUS_TOKEN_ID }), /locked/i);
  }
});

// Pins rollback when the module derives another identity and when a lock interrupts the seed hand-over.
test('identity mismatch and a lock during unlock cannot publish an address', async t => {
  const { background, state, calls, memory } = await setup(t); state.mismatch = true;
  await assert.rejects(background.unlock(password, options), /different address/);
  assert.equal(background.lockCoordinator.isLocked, true); assert.ok(memory.every(byte => byte === 0));
  state.mismatch = false; state.unlockWait = deferred(); state.entered = deferred();
  const unlocking = background.unlock(password, options), rejected = assert.rejects(unlocking, /locked/i);
  await state.entered.promise; await background.lock(); state.unlockWait.resolve(); await rejected;
  assert.ok(calls.filter(([op]) => op === 'unlock').every(([, seed]) => seed.every(byte => byte === 0)));
  assert.throws(background.walletKeys.getAddresses, /locked/i);
});

// Pins CPUNK's original POST, address echo, bounded JSON and amount-consistency checks through the background reader.
test('CPUNK reads retain all web-wallet response checks', async t => {
  const { background } = await setup(t); await background.unlock(password, options);
  const cpunk = background.walletKeys.getAddresses().cpunk;
  let body = { result: [[{ addr: cpunk, token: 'CPUNK', balance: '2.0' }]] };
  t.mock.method(globalThis, 'fetch', async (_url, request) => {
    assert.equal(request.headers['Content-Type'], 'text/plain;charset=UTF-8'); assert.equal(request.credentials, 'omit');
    assert.ok(request.body.includes(cpunk)); assert.equal(request.body.includes(phrase), false);
    return Response.json(body);
  });
  assert.equal((await background.nodus.getCpunkBalance()).balance, '2.0');
  body = { result: [[{ addr: 'different', token: 'CPUNK', balance: '2.0' }]] };
  await assert.rejects(background.nodus.getCpunkBalance(), /different address/);
  body = { result: [[{ addr: cpunk, network: 'Backbone', tokens: [{ token: { ticker: 'CPUNK' }, coins: '2', datoshi: '1' }] }]] };
  await assert.rejects(background.nodus.getCpunkBalance(), /inconsistent CPUNK amounts/);
  body = { result: [[{ addr: cpunk, network: 'wrong', token: 'CPUNK', balance: '2' }]] };
  await assert.rejects(background.nodus.getCpunkBalance(), /different network/);
  t.mock.method(globalThis, 'fetch', async () => new Response('{}', { headers: { 'Content-Type': 'text/plain' } }));
  await assert.rejects(background.nodus.getCpunkBalance(), /unrecognized response/);
  t.mock.method(globalThis, 'fetch', async () => new Response('x'.repeat(65537), { headers: { 'Content-Type': 'application/json' } }));
  await assert.rejects(background.nodus.getCpunkBalance(), /too large/);
});

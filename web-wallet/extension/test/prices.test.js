import test from 'node:test';
import assert from 'node:assert/strict';
import { createWalletUi } from '../src/ui/wallet-ui.js';
import { connectTrusted } from '../src/ui/trusted-port.js';
import { ASSETS, PRICE_MAX_AGE, chainBalances, portfolioSnapshot, usdText } from '../../src/portfolio.js';
import { DEFAULT_NETWORKS } from '../src/constants/networks.js';

// Node >=22.14; no compile flags, network or disk writes. Public fixtures and
// mocked Date stay in memory; ports/controllers are disposed by each test.
// These tests pin the trusted price API and UI aggregation, not the live feed.
// Shared portfolio helpers as the oracle can conceal a defect in those helpers;
// test/portfolio.test.js covers them independently. No test here is a live quote.
const chains = ['ethereum', 'bsc', 'solana', 'tron'];
const account = '0x' + '12'.repeat(20);
const rows = Object.fromEntries(chains.map(chain => [chain, ASSETS.filter(asset => asset.chain === chain)
  .map((asset, index) => ({ symbol: asset.symbol, balance: String(index + 1) }))]));
const quotesAt = now => Object.fromEntries(ASSETS.map((asset, index) => [asset.key,
  { units: BigInt(index + 1) * 100000000n, observedAt: now }]));
function expected(now, quotes, { failed, excluded = [] } = {}) {
  const balances = {};
  for (const chain of chains) {
    if (excluded.includes(chain)) continue;
    Object.assign(balances, failed === chain
      ? Object.fromEntries(ASSETS.filter(asset => asset.chain === chain).map(asset => [asset.key, { state: 'error' }]))
      : chainBalances(chain, rows[chain], now));
  }
  return portfolioSnapshot(balances, quotes, now, ASSETS);
}
function fakeClient({ failed, malformed } = {}) {
  const calls = [], state = { isUnlocked: true, addresses: { ethereum: account, bsc: account,
    solana: '1'.repeat(44), tron: 'T' + '1'.repeat(33) }, networks: { ...DEFAULT_NETWORKS } };
  let failPrices = false, gate;
  return { calls, state, set failPrices(value) { failPrices = value; }, set priceGate(value) { gate = value; },
    async request(method, params = []) {
      calls.push({ method, params });
      if (method === 'getState') return structuredClone(state);
      if (method === 'setLocked') { state.isUnlocked = false; return; }
      if (method === 'getPrices') {
        if (gate) return gate;
        if (failPrices) throw new Error('Price fixture unavailable');
        return Object.fromEntries(Object.entries(quotesAt(Date.now())).map(([key, quote]) => [key, { ...quote, units: quote.units.toString() }]));
      }
      const chain = method === 'getEvmBalances' ? params[0] : method === 'getSolanaBalances' ? 'solana' : method === 'getTronBalances' ? 'tron' : undefined;
      if (chain) {
        if (chain === failed) throw new Error(`${chain} fixture unavailable`);
        return chain === malformed ? Array(101).fill(rows[chain][0]) : structuredClone(rows[chain]);
      }
      throw new Error(`Unexpected fixture method: ${method}`);
    } };
}
async function load(ui) {
  await ui.refresh();
  await Promise.all([ui.loadEvmBalances(), ui.loadSolanaTronBalances(), ui.loadPrices()]);
}

// Proves BigInt reconstruction, reference total and public-state separation.
// Total-only checks could falsely pass with clock-dependent strings in ui.state.
test('UI prices use the reference portfolio without adding a portfolio field to public state', async t => {
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
  const client = fakeClient(), ui = createWalletUi(client);
  await load(ui);
  const snap = expected(Date.now(), quotesAt(Date.now()));
  assert.equal(ui.portfolio().total, usdText(snap.total, snap.positive));
  assert.equal(ui.portfolio().label, 'Estimated portfolio value');
  assert.equal(ui.portfolio().status, 'All supported asset balances are included.');
  assert.equal(Object.hasOwn(ui.state, 'portfolio'), false);
  assert.doesNotThrow(() => JSON.stringify(ui.state));
});

// Proves successful-read throttling, forced refresh, failure retention and lock
// clearing. Counting calls alone could miss discarded or leaked old quotes.
test('UI prices throttle for a minute, force refresh, retain on failure and clear on lock', async t => {
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
  const client = fakeClient(), ui = createWalletUi(client);
  await load(ui);
  const total = ui.portfolio().total, count = () => client.calls.filter(call => call.method === 'getPrices').length;
  await ui.loadPrices(); assert.equal(count(), 1);
  await ui.loadPrices({ force: true }); assert.equal(count(), 2);
  client.failPrices = true;
  await ui.loadPrices({ force: true }); assert.equal(count(), 3);
  assert.equal(ui.portfolio().total, total);
  t.mock.timers.tick(60_000);
  client.failPrices = false;
  await ui.loadPrices(); assert.equal(count(), 4);
  await ui.lock();
  await ui.loadPrices(); assert.equal(count(), 4);
  client.state.isUnlocked = true; await ui.refresh();
  await Promise.all([ui.loadEvmBalances(), ui.loadSolanaTronBalances()]);
  assert.equal(ui.portfolio().total, '—', 'Old quotes must not survive a new unlock');
  await ui.loadPrices(); assert.equal(count(), 5);
  assert.equal(ui.portfolio().total, total);
});

// Proves concurrent reads coalesce and a late old-unlock quote cannot refill a
// cleared wallet. A lock-only check would miss a response arriving afterwards.
test('in-flight prices are shared and cannot cross a wallet identity change', async t => {
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
  const client = fakeClient(), ui = createWalletUi(client);
  await ui.refresh();
  let finish;
  client.priceGate = new Promise(resolve => { finish = resolve; });
  const first = ui.loadPrices(), second = ui.loadPrices({ force: true });
  assert.equal(client.calls.filter(call => call.method === 'getPrices').length, 1);
  await ui.lock(); client.state.isUnlocked = true; await ui.refresh();
  finish(Object.fromEntries(Object.entries(quotesAt(Date.now())).map(([key, quote]) => [key, { ...quote, units: quote.units.toString() }])));
  await Promise.all([first, second]);
  await Promise.all([ui.loadEvmBalances(), ui.loadSolanaTronBalances()]);
  assert.equal(ui.portfolio().total, '—');
});

// Proves all selectable Solana/TRON test networks are excluded and counted
// missing. Testing an empty testnet balance could falsely pass even if priced.
for (const [chain, network] of [['solana', 'testnet'], ['solana', 'devnet'], ['tron', 'nile']]) {
  test(`${chain} ${network} balances stay outside the dollar total`, async t => {
    t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
    const client = fakeClient(), ui = createWalletUi(client);
    client.state.networks[chain] = network; await load(ui);
    const snap = expected(Date.now(), quotesAt(Date.now()), { excluded: [chain] });
    assert.equal(ui.portfolio().total, usdText(snap.total, snap.positive));
    assert.equal(ui.portfolio().label, 'Known value · incomplete');
    assert.equal(ui.portfolio().status, `${snap.missingBalances} balances and 0 prices unavailable or out of date. Missing values are excluded.`);
  });
}

// Proves each failed chain is contained, while other chains still contribute.
// Merely asserting no throw could falsely pass if every chain were discarded.
for (const failed of chains) test(`a rejected ${failed} read leaves the other chains priced`, async t => {
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
  const client = fakeClient({ failed }), ui = createWalletUi(client);
  await load(ui);
  assert.doesNotThrow(() => ui.state);
  await assert.doesNotReject(ui.refresh());
  const snap = expected(Date.now(), quotesAt(Date.now()), { failed });
  assert.equal(ui.portfolio().total, usdText(snap.total, snap.positive));
  assert.equal(ui.portfolio().status, `${snap.missingBalances} balances and 0 prices unavailable or out of date. Missing values are excluded.`);
});

// Proves the chainBalances throw branch too, not only whole-chain { error }.
test('an invalid balance array is contained per chain', async t => {
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
  const client = fakeClient({ malformed: 'bsc' }), ui = createWalletUi(client);
  await load(ui);
  const snap = expected(Date.now(), quotesAt(Date.now()), { failed: 'bsc' });
  assert.equal(ui.portfolio().total, usdText(snap.total, snap.positive));
});

// Proves aging changes the summary independently of the compared public state.
test('clock aging changes portfolio text without changing public state', async t => {
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
  const ui = createWalletUi(fakeClient()); await load(ui);
  const before = JSON.stringify(ui.state), total = ui.portfolio().total;
  t.mock.timers.tick(PRICE_MAX_AGE + 1);
  assert.equal(JSON.stringify(ui.state), before);
  assert.notEqual(ui.portfolio().total, total);
  assert.equal(ui.portfolio().total, '—');
});

function event() {
  const listeners = new Set();
  return { addListener(fn) { listeners.add(fn); }, removeListener(fn) { listeners.delete(fn); }, emit(...args) { for (const fn of listeners) fn(...args); } };
}
let backgroundModule;
async function backgroundFixture(t, readPrices) {
  const values = {}, ports = [];
  const runtime = { id: 'prices-test', onConnect: event(), getManifest: () => ({ version: '0.1.133' }), getURL: path => `chrome-extension://prices-test/${path}` };
  const fixture = { runtime,
    storage: { async get(key) { return { [key]: structuredClone(values[key]) }; }, async set(items) { Object.assign(values, structuredClone(items)); } },
    alarms: { onAlarm: event(), async clear() {}, async create() {} },
    windows: { onRemoved: event(), async getAll() { return []; }, async getLastFocused() { return { top: 0, left: 0, width: 1000 }; }, async create(options) { return { ...options, id: 2 }; }, async update() {} },
    tabs: { async query() { return []; } },
  };
  runtime.connect = ({ name }) => {
    let closed = false;
    const page = { name, onMessage: event(), onDisconnect: event() }, background = { name, onMessage: event(), onDisconnect: event(), sender: { id: runtime.id, url: runtime.getURL('notification.html') } };
    page.postMessage = message => { const copy = structuredClone(message); queueMicrotask(() => { if (!closed) background.onMessage.emit(copy); }); };
    background.postMessage = message => { const copy = structuredClone(message); queueMicrotask(() => { if (!closed) page.onMessage.emit(copy); }); };
    page.disconnect = background.disconnect = () => { if (!closed) { closed = true; page.onDisconnect.emit(page); background.onDisconnect.emit(background); } };
    ports.push(page); runtime.onConnect.emit(background); return page;
  };
  if (!backgroundModule) {
    const saved = Object.getOwnPropertyDescriptor(globalThis, 'chrome');
    globalThis.chrome = { ...fixture, storage: { local: fixture.storage } };
    try { backgroundModule = await import('../src/background/index.js'); await (await backgroundModule.background).destroy(); }
    finally { if (saved) Object.defineProperty(globalThis, 'chrome', saved); else delete globalThis.chrome; }
  }
  const background = await backgroundModule.createBackground({ ...fixture, readPrices });
  const client = connectTrusted({ runtime, page: 'notification.html' });
  t.after(async () => { client.close(); for (const port of ports) port.disconnect(); await background.destroy(); });
  return { background, client };
}

// Proves the real authenticated controller stream gates reads, serializes every
// BigInt and propagates failure. Calling an injected reader directly would miss
// method registration, lock enforcement and serialization entirely.
test('trusted getPrices is unlocked-only, serializes all quotes and rejects a failed read', async t => {
  const now = Date.now(), quotes = quotesAt(now);
  let fail = false, reads = 0;
  const { background, client } = await backgroundFixture(t, async () => {
    reads++; if (fail) throw new Error('Price fixture unavailable'); return quotes;
  });
  await assert.rejects(client.request('getPrices'), /locked/i); assert.equal(reads, 0);
  await background.lockCoordinator.unlock(async () => {});
  const result = await client.request('getPrices');
  assert.deepEqual(result, Object.fromEntries(Object.entries(quotes).map(([key, quote]) => [key, { ...quote, units: quote.units.toString() }])));
  assert.doesNotThrow(() => JSON.stringify(result)); assert.equal(reads, 1);
  fail = true; await assert.rejects(client.request('getPrices'), /Price fixture unavailable/); assert.equal(reads, 2);
});

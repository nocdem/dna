import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createLockCoordinator } from '../src/background/lock.js';
import { chainNetwork } from '../src/constants/networks.js';
import { createIncomingNotifications, INCOMING_NOTIFICATIONS_ALARM, INCOMING_CHECK_MINUTES } from '../src/background/incoming-notifications.js';

// Public reader and Chrome API fixtures only. The production poller chooses
// the real background method, network, receipt identity and notification text.
async function fixture(t) {
  const lockCoordinator = createLockCoordinator(), shown = [], scheduled = new Map(), listeners = new Set(), calls = [];
  const pages = Object.fromEntries(['nodus', 'ethereum', 'solana', 'tron', 'cellframe'].map(chain => [chain, { rows: [] }]));
  const balances = { bsc: [{ symbol: 'BNB', balance: '10.0' }, { symbol: 'USDT', balance: '25.0' }], ixios: [{ symbol: 'IXIOS', balance: '1.0' }] };
  const selected = {}, gates = {}, failures = new Set();
  let clock = 1700000000000, refuse = false;
  async function read(chain, options) {
    lockCoordinator.assertUnlocked(); calls.push({ chain, options });
    const value = structuredClone(pages[chain] ?? balances[chain]);
    if (gates[chain]) await gates[chain];
    if (failures.has(chain)) throw new Error('Reader fixture unavailable.');
    return value;
  }
  const alarms = { async create(name, info) { scheduled.set(name, info); }, async clear(name) { scheduled.delete(name); },
    onAlarm: { addListener(fn) { listeners.add(fn); }, removeListener(fn) { listeners.delete(fn); } } };
  const options = { alarms, lockCoordinator, now: () => clock,
    notifications: { async create(id, value) { if (refuse) throw new Error('Notification fixture unavailable.'); shown.push({ id, ...value }); return id; } },
    runtime: { getURL: path => `chrome-extension://incoming-test/${path}` },
    networks: { get: chain => chainNetwork(chain, selected[chain]) },
    nodus: { getHistory: () => read('nodus'), getChainHistory: (chain, options) => read(chain, options), getIxiosBalance: () => read('ixios') },
    evm: { getState: () => ({ endpoints: { bsc: 'https://bsc.example' } }), getBalances: chain => read(chain) },
    solana: { getHistory: options => read('solana', options) }, tron: { getHistory: options => read('tron', options) } };
  let notifier = await createIncomingNotifications(options);
  t.after(() => notifier.destroy());
  return { pages, balances, selected, gates, failures, shown, scheduled, calls, lockCoordinator,
    get notifier() { return notifier; },
    async open() { await lockCoordinator.unlock(async () => {}); await notifier.start(); },
    async lock() { const locking = lockCoordinator.lock(); await notifier.stop(); await locking; },
    async restart() { await notifier.destroy(); notifier = await createIncomingNotifications(options); },
    tick() { clock += 60000; return Promise.all([...listeners].map(fn => fn({ name: INCOMING_NOTIFICATIONS_ALARM }))); },
    alarm(name) { return Promise.all([...listeners].map(fn => fn({ name }))); },
    time: () => clock, setRefuse(value) { refuse = value; } };
}
const receipt = (chain, time, extra = {}) => ({ chain, hash: (chain === 'ethereum' || chain === 'cellframe' ? '0x' : '')
  + (chain === 'solana' ? time.toString(16).replace(/0/gu, 'z') : time.toString(16)).padStart(64, '1'),
  time, dir: 'in', symbol: chain === 'cellframe' ? 'CPUNK' : 'USDT', amount: '2.5', status: 'confirmed', ...extra });

// The first real snapshot is silent; a new confirmed incoming row produces
// exactly one native notification, including its checked amount and network.
test('existing history is silent and a new incoming transfer notifies once on every history chain', async t => {
  const f = await fixture(t);
  for (const chain of Object.keys(f.pages)) f.pages[chain].rows = [receipt(chain, f.time() - 1000,
    chain === 'nodus' ? { key: '1:0:0', amount: '2.5 NODUS', status: undefined } : {})];
  await f.open(); assert.deepEqual(f.shown, []);
  for (const chain of Object.keys(f.pages)) f.pages[chain].rows.unshift(receipt(chain, f.time() + 1000,
    chain === 'nodus' ? { key: '2:0:0', amount: '3.0 NODUS', status: undefined } : {}));
  await f.tick(); await f.tick();
  assert.equal(f.shown.length, 5);
  assert.equal(new Set(f.shown.map(row => row.id)).size, 5);
  for (const row of f.shown) {
    assert.equal(row.type, 'basic'); assert.equal(row.title, 'Nodus Wallet — funds received');
    assert.equal(row.iconUrl, 'chrome-extension://incoming-test/icons/nodus-128.png');
    assert.match(row.message, /(?:2\.5 (?:USDT|CPUNK)|3\.0 NODUS)\n.+\((?:Mainnet|Testnet)\)/u);
  }
  assert.ok(f.shown.some(row => row.message === '3.0 NODUS\nNodus (Testnet)'));
  for (const { chain, options } of f.calls) if (['ethereum', 'solana', 'tron', 'cellframe'].includes(chain)) assert.deepEqual(options, { manual: true });
});

test('balance-only chains use exact deltas and never notify an unchanged or failed balance', async t => {
  const f = await fixture(t); await f.open();
  f.balances.bsc[0].balance = '10.000000000000000001';
  f.balances.bsc[1].balance = '24.0';
  f.balances.ixios[0].balance = '4.25';
  await f.tick(); await f.tick();
  assert.deepEqual(f.shown.map(row => row.message).sort(), ['0.000000000000000001 BNB\nBNB Smart Chain (Mainnet)', '3.25 IXIOS\nIxios (Mainnet)'].sort());
  f.balances.bsc = [{ symbol: 'BNB', error: 'Balance unavailable' }, { symbol: 'USDT', balance: '24.0' }];
  await f.tick();
  f.balances.bsc[0] = { symbol: 'BNB', balance: '100.0' };
  await f.tick(); assert.equal(f.shown.length, 2, 'first recovered asset read is a baseline');
  f.balances.bsc[0].balance = '101.0'; await f.tick();
  assert.equal(f.shown.at(-1).message, '1.0 BNB\nBNB Smart Chain (Mainnet)');
});

test('locked startup, unlock, another unlock and browser/worker restart do not replay funds', async t => {
  const f = await fixture(t);
  await f.tick(); assert.deepEqual(f.calls, []);
  assert.equal(f.scheduled.has(INCOMING_NOTIFICATIONS_ALARM), false);
  await f.open();
  assert.equal(INCOMING_CHECK_MINUTES, 1);
  assert.deepEqual(f.scheduled.get(INCOMING_NOTIFICATIONS_ALARM), { periodInMinutes: 1 });
  await f.lock();
  const reads = f.calls.length;
  f.pages.ethereum.rows = [receipt('ethereum', f.time() + 1000)]; f.balances.bsc[0].balance = '20.0';
  await f.tick(); assert.equal(f.calls.length, reads);
  await f.open(); await f.tick(); assert.deepEqual(f.shown, []);
  await f.lock(); await f.restart(); await f.tick(); await f.open(); await f.tick();
  assert.deepEqual(f.shown, []);
  await f.alarm('AUTO_LOCK_TIMEOUT_ALARM'); assert.deepEqual(f.shown, []);
});

test('late old history, outgoing, self, failed and zero transfers do not notify', async t => {
  const f = await fixture(t), opened = f.time(); await f.open();
  f.pages.ethereum.rows = [receipt('ethereum', opened - 1), receipt('ethereum', opened + 1, { dir: 'out' }),
    receipt('ethereum', opened + 2, { dir: 'self' }), receipt('ethereum', opened + 3, { status: 'failed' }),
    receipt('ethereum', opened + 4, { amount: '0.0' })];
  await f.tick(); assert.deepEqual(f.shown, []);
  f.pages.ethereum.rows.push(receipt('ethereum', opened + 5));
  await f.tick(); assert.equal(f.shown.length, 1);
});

test('reader failures are isolated and the first successful read establishes a baseline', async t => {
  const f = await fixture(t); f.failures.add('ethereum'); await f.open();
  f.pages.ethereum.rows = [receipt('ethereum', f.time() + 1)];
  f.pages.tron.rows = [receipt('tron', f.time() + 1)];
  await f.tick(); assert.equal(f.shown.length, 1);
  f.failures.delete('ethereum'); await f.tick(); assert.equal(f.shown.length, 1);
  f.pages.ethereum.rows.unshift(receipt('ethereum', f.time() + 1)); await f.tick(); assert.equal(f.shown.length, 2);
});

test('an error snapshot is not an empty successful history baseline', async t => {
  const f = await fixture(t); f.pages.solana = { rows: [], error: 'History unavailable' }; await f.open();
  f.pages.solana = { rows: [receipt('solana', f.time() + 1)] }; await f.tick(); assert.deepEqual(f.shown, []);
  f.pages.solana.rows.unshift(receipt('solana', f.time() + 1)); await f.tick(); assert.equal(f.shown.length, 1);
});

test('network changes establish a silent baseline and late results from the previous network are ignored', async t => {
  const f = await fixture(t); await f.open();
  let release;
  f.pages.solana.rows = [receipt('solana', f.time() + 1)];
  f.gates.solana = new Promise(resolve => { release = resolve; });
  const reads = f.calls.filter(row => row.chain === 'solana').length;
  const oldRead = f.notifier.check();
  assert.equal(f.calls.filter(row => row.chain === 'solana').length, reads + 1, 'old-network read has entered its gate');
  f.selected.solana = 'devnet'; release(); await oldRead; delete f.gates.solana;
  assert.deepEqual(f.shown, [], 'late incoming result belongs to the previous network');
  f.pages.solana.rows = [receipt('solana', f.time() + 1)];
  await f.tick(); assert.deepEqual(f.shown, []);
  f.pages.solana.rows.unshift(receipt('solana', f.time() + 1));
  await f.tick(); assert.equal(f.shown.length, 1); assert.match(f.shown[0].message, /Solana \(Devnet\)/u);
});

test('overlapping alarms share reads and a result crossing lock cannot notify', async t => {
  const f = await fixture(t); await f.open();
  let release;
  f.pages.tron.rows = [receipt('tron', f.time() + 1)];
  f.gates.tron = new Promise(resolve => { release = resolve; });
  const first = f.tick(), second = f.tick();
  await Promise.resolve();
  await f.lock(); delete f.gates.tron;
  assert.deepEqual(f.shown, []);
  assert.equal(f.calls.filter(row => row.chain === 'tron').length, 2, 'one baseline and one shared alarm read');
  await f.open(); release(); await Promise.all([first, second]);
  await f.tick(); assert.deepEqual(f.shown, [], 'previous unlock cannot notify after a later unlock');
});

test('notification delivery failure retries a receipt once and never re-enrolls it', async t => {
  const f = await fixture(t); await f.open(); f.setRefuse(true);
  f.pages.ethereum.rows = [receipt('ethereum', f.time() + 1)];
  await f.tick(); assert.deepEqual(f.shown, []);
  f.setRefuse(false); await f.tick(); await f.tick();
  assert.equal(f.shown.length, 1);
  const received = f.pages.ethereum.rows;
  f.pages.ethereum.rows = []; await f.tick();
  f.pages.ethereum.rows = received; await f.tick(); assert.equal(f.shown.length, 1);
});

// Composition test: real background, vault, wallet-key derivation, unlock and
// lock. The Nodus seed-consumer seam, public reader results and browser APIs
// are fixtures; no Nodus connection is tested. With no popup connected, the
// alarm must reach the poller through the background dispatcher.
test('background unlock starts incoming checks and manual/inactivity lock stops them without an open UI', async t => {
  function event() {
    const listeners = new Set();
    return { addListener(fn) { listeners.add(fn); }, removeListener(fn) { listeners.delete(fn); },
      emit(value) { return Promise.all([...listeners].map(fn => fn(value))); } };
  }
  const values = {}, scheduled = new Map(), shown = [], calls = [];
  const runtime = { id: 'incoming-composition-test', onConnect: event(), getManifest: () => ({ version: '0.1.139' }),
    getURL: path => `chrome-extension://incoming-composition-test/${path}` };
  const storage = { async get(keys) { return Object.fromEntries((Array.isArray(keys) ? keys : [keys]).map(key => [key, values[key]])); },
    async set(items) { Object.assign(values, structuredClone(items)); } };
  const alarms = { onAlarm: event(), async create(name, info) { scheduled.set(name, info); }, async clear(name) { scheduled.delete(name); } };
  const windows = { onRemoved: event(), async getAll() { return []; } };
  let clock = 1700000000000;
  t.mock.method(Date, 'now', () => clock);
  const options = { runtime, storage, alarms, windows, consumeNodusSeed: () => {},
    notifications: { async create(id, value) { shown.push({ id, ...value }); return id; } } };
  const saved = Object.getOwnPropertyDescriptor(globalThis, 'chrome');
  let module;
  globalThis.chrome = { runtime, storage: { local: storage }, alarms, windows };
  try { module = await import('../src/background/index.js'); await (await module.background).destroy(); }
  finally { if (saved) Object.defineProperty(globalThis, 'chrome', saved); else delete globalThis.chrome; }
  const background = await module.createBackground(options);
  t.after(() => background.destroy());
  let rows = [receipt('ethereum', clock - 1000)];
  for (const [handler, method, value] of [
    [background.nodus, 'getHistory', () => ({ rows: [] })],
    [background.nodus, 'getChainHistory', chain => ({ rows: chain === 'ethereum' ? rows : [] })],
    [background.nodus, 'getIxiosBalance', () => [{ symbol: 'IXIOS', balance: '0.0' }]],
    [background.evm, 'getBalances', () => [{ symbol: 'BNB', balance: '0.0' }]],
    [background.solana, 'getHistory', () => ({ rows: [] })],
    [background.tron, 'getHistory', () => ({ rows: [] })],
  ]) t.mock.method(handler, method, async (...args) => {
    background.lockCoordinator.assertUnlocked(); calls.push(method); return structuredClone(value(...args));
  });
  await alarms.onAlarm.emit({ name: INCOMING_NOTIFICATIONS_ALARM }); assert.deepEqual(calls, []);
  const password = 'public-test-password-123', phrase = 'abandon '.repeat(23) + 'art';
  const unlockOptions = {
    cpunkWasmBytes: readFileSync(new URL('../../src/cpunk/legacy-dilithium.wasm', import.meta.url)),
    nodusWasmBytes: readFileSync(new URL('../../src/nodus/mldsa87.wasm', import.meta.url)),
  };
  await background.vaultStore.create(password, phrase);
  await background.unlock(password, unlockOptions); await background.incomingNotifications.check();
  assert.deepEqual(shown, []); assert.deepEqual(scheduled.get(INCOMING_NOTIFICATIONS_ALARM), { periodInMinutes: 1 });
  clock += 60000; rows.unshift(receipt('ethereum', clock));
  await alarms.onAlarm.emit({ name: INCOMING_NOTIFICATIONS_ALARM });
  await alarms.onAlarm.emit({ name: INCOMING_NOTIFICATIONS_ALARM }); assert.equal(shown.length, 1);
  for (const mode of ['manual', 'inactivity']) {
    if (mode === 'manual') await background.lock();
    else await alarms.onAlarm.emit({ name: 'AUTO_LOCK_TIMEOUT_ALARM' });
    assert.equal(background.lockCoordinator.isLocked, true);
    assert.throws(() => background.walletKeys.getAddresses(), /locked/iu);
    const reads = calls.length;
    clock += 60000; rows.unshift(receipt('ethereum', clock));
    await alarms.onAlarm.emit({ name: INCOMING_NOTIFICATIONS_ALARM });
    assert.equal(calls.length, reads); assert.equal(scheduled.has(INCOMING_NOTIFICATIONS_ALARM), false);
    await background.unlock(password, unlockOptions); await background.incomingNotifications.check();
    await alarms.onAlarm.emit({ name: INCOMING_NOTIFICATIONS_ALARM }); assert.equal(shown.length, 1);
  }
});

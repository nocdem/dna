import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { CHAINS } from '../../src/config.js';
import { SEPOLIA, BSC_TESTNET } from '../src/constants/evm-networks.js';

function signal() {
  const listeners = new Set();
  return {
    addListener: listener => listeners.add(listener), removeListener: listener => listeners.delete(listener),
    hasListener: listener => listeners.has(listener), emit: (...args) => [...listeners].map(listener => listener(...args)),
  };
}
let workerFixtureId = 0;
async function workerFixture(t, { notifications = true } = {}) {
  const saved = new Map(['chrome', 'self', 'stateHooks'].map(key => [key, Object.getOwnPropertyDescriptor(globalThis, key)]));
  t.after(() => { for (const [key, descriptor] of saved) {
    if (descriptor) Object.defineProperty(globalThis, key, descriptor); else delete globalThis[key];
  } });
  t.mock.timers.enable({ apis: ['setTimeout', 'setInterval'] });
  const writes = [];
  const runtime = { onConnect: signal() }, alarms = { onAlarm: signal() }, notificationEvents = { onClicked: signal() };
  globalThis.chrome = { runtime, alarms, storage: { session: { set: value => writes.push(value) } }, ...(notifications ? { notifications: notificationEvents } : {}) };
  globalThis.self = new EventTarget();
  self.serviceWorker = { state: 'installing' };
  const hooks = globalThis.stateHooks = { retainedFixtureHook: true };
  await import(`../src/service-worker.js?fixture=${++workerFixtureId}`);
  return { runtime, alarms, notifications: notificationEvents, writes, hooks, lazyListener: stateHooks.lazyListener };
}

// Node 22, no flags or browser; Chrome/storage/alarm fixtures stay in memory, no generated artifacts.
// Manifest port: MetaMask v13.54.0 app/manifest/v3/_base.json:2-102, chrome.json:2-16; approved plan §3.1.
const manifest = JSON.parse(await readFile(new URL('../manifest.json', import.meta.url), 'utf8'));

// Proves the two source entries run in their respective worlds at document_start; merely finding either filename could hide a missing entry.
test('MV3 uses the source worker and isolated/main document-start entries', () => {
  assert.equal(manifest.manifest_version, 3);
  assert.equal(manifest.minimum_chrome_version, '123');
  assert.equal(manifest.background.service_worker, 'src/service-worker.js');
  assert.deepEqual(manifest.content_scripts, [
    { matches: ['http://*/*', 'https://*/*'], js: ['src/contentscript.js'], run_at: 'document_start', all_frames: true },
    { matches: ['http://*/*', 'https://*/*'], js: ['src/inpage.js'], run_at: 'document_start', world: 'MAIN', all_frames: true },
  ]);
});

// Pins the exact host and permission lists of the operator decision docs/plans/decisions/2026-11-03-chrome-web-store.md
// (file:// matches and host permission, http:// and ws:// host permissions removed; unlimitedStorage kept, wss:// kept broad).
// A subset assertion could silently retain an unrelated permission.
test('permissions and external connections match the approved reference subset', () => {
  assert.deepEqual(manifest.host_permissions, ['https://*/*', 'wss://*/*']);
  assert.deepEqual([...manifest.permissions].sort(), ['alarms', 'notifications', 'storage', 'unlimitedStorage'].sort());
  assert.equal(manifest.externally_connectable, undefined);
  assert.equal(manifest.content_security_policy.extension_pages, "script-src 'self' 'wasm-unsafe-eval'; object-src 'none'; frame-ancestors 'self'; font-src 'self';");
  assert.deepEqual(manifest.cross_origin_opener_policy, { value: 'same-origin-allow-popups' });
});

// Proves English literals and the existing Nodus source asset are used; checking only the name could leave a MetaMask icon or locale dependency.
// The packaging config rasterizes these source paths; package-smoke.test.js
// separately checks emitted PNG signatures/dimensions and real Chromium load.
test('Connect product name keeps the existing extension paths and assets', async () => {
  assert.equal(manifest.name, 'Nodus Connect');
  assert.equal(manifest.short_name, 'Nodus');
  assert.equal(manifest.action.default_title, 'Nodus Connect');
  assert.equal(manifest.action.default_popup, 'popup.html');
  assert.equal(manifest.version, JSON.parse(await readFile(new URL('../../package.json', import.meta.url), 'utf8')).version);
  assert.equal(manifest.description, 'Wallet for the Nodus testnet, Ethereum, BNB Smart Chain, Solana and TRON, with website connections and Nodus Connect messages.');
  assert.ok(manifest.description.length <= 132);
  for (const path of [...Object.values(manifest.icons), ...Object.values(manifest.action.default_icon)]) {
    assert.equal(path, '../public/assets/nodus-mark.svg');
    assert.match(await readFile(new URL(`../${path}`, import.meta.url), 'utf8'), /<svg/u);
  }
  assert.ok(!JSON.stringify(manifest).includes('__MSG_'));
});

// Proves removed manifest surfaces are absent; inspecting permissions alone would miss the Trezor script, sandbox or cashtag resource.
test('removed integrations have no manifest entries', () => {
  for (const key of ['default_locale', 'commands', 'optional_permissions', 'sandbox', 'side_panel', 'web_accessible_resources']) {
    assert.equal(Object.hasOwn(manifest, key), false, key);
  }
  assert.deepEqual(Object.keys(manifest.content_security_policy), ['extension_pages']);
  assert.ok(!/metamask|trezor|cashtag|x\.com/iu.test(JSON.stringify(manifest)));
});

// Proves startup attaches the real seed consumer while holders remain locked and only controller metadata is persisted.
test('background entry starts locked with the real Nodus seed consumer attached', async t => {
  const saved = Object.getOwnPropertyDescriptor(globalThis, 'chrome');
  t.after(() => { if (saved) Object.defineProperty(globalThis, 'chrome', saved); else delete globalThis.chrome; });
  const reads = [], writes = [], scheduled = new Map(), listeners = [];
  globalThis.chrome = {
    // Reference: background.ts:520; notification-manager.ts:34-37 -> platforms/extension.ts:178-179.
    runtime: { id: 'test-extension', onConnect: signal() },
    windows: { onRemoved: signal() },
    storage: { local: {
      async get(key) { reads.push(key); return {}; },
      async set(value) { writes.push(value); },
    } },
    alarms: {
      async clear(name) { scheduled.delete(name); },
      async create(name, options) { scheduled.set(name, options); },
      onAlarm: { addListener(fn) { listeners.push(fn); }, removeListener(fn) { const i=listeners.indexOf(fn);if(i>=0)listeners.splice(i,1); } },
    },
  };
  const { background } = await import('../src/background/index.js');
  const state = await background;
  t.after(() => state.destroy());
  // Reference: ComposableObservableStore.js:90-97; approved plan §3.5:388-406 excludes key custody.
  // The connected-sites controller is not in the plain state any more (sealed in nodus.sites.v1, plan section 2.6).
  const expectedWrites = [{ 'nodus.extension.state': {
    ApprovalController: {},
    EvmController: { selectedChain: 'ethereum', endpoints: { ethereum: CHAINS.ethereum.endpoint, bsc: CHAINS.bsc.endpoint,
      sepolia: SEPOLIA.endpoint, bsctestnet: BSC_TESTNET.endpoint } },
    // PQ receive registry adds only listed choices; Nodus/Asentum are testnet-only.
    NetworksController: { selected: { bsc: 'mainnet', cellframe: 'mainnet', ixios: 'mainnet', ethereum: 'mainnet', nodus: 'testnet', solana: 'mainnet', tron: 'mainnet',
      algorand: 'mainnet', tidecoin: 'mainnet', ckb: 'mainnet', soqucoin: 'mainnet', qtc: 'mainnet', xion: 'mainnet', splendor: 'mainnet', asentum: 'testnet' } },
  } }];
  assert.equal(state.lockCoordinator.isLocked, true);
  assert.deepEqual(reads, ['nodus.extension.state', 'nodus.autoLockMinutes']); assert.deepEqual(writes, expectedWrites);
  assert.deepEqual(scheduled.get('AUTO_LOCK_TIMEOUT_ALARM'), { delayInMinutes: 15, periodInMinutes: 15 });
  assert.equal(listeners.length, 1);
  await assert.rejects(state.keyring.getAccounts(), /locked/iu);
  // Startup attaches the real consumer without deriving or loading a module.
  const { walletKeys, unlock } = state;
  assert.ok(walletKeys);
  assert.equal(typeof unlock, 'function');
  assert.throws(walletKeys.getSolanaKeypair, /locked/iu);
  assert.throws(walletKeys.getTronPrivateKey, /locked/iu);
  assert.throws(() => state.attachWalletKeys(() => {}), /already attached/iu);
  await state.lockCoordinator.unlock(async () => {});
  await listeners[0]({ name: 'AUTO_LOCK_TIMEOUT_ALARM' });
  assert.equal(state.lockCoordinator.isLocked, true); assert.equal(scheduled.size, 0);
  assert.deepEqual(writes, expectedWrites);
});

// Proves immediate/two-second timestamps and assignment to the existing hooks object; checking only the property could miss replacement by spread.
test('service worker retains hooks and the reference keep-alive cadence', async t => {
  const { writes, hooks } = await workerFixture(t);
  assert.equal(stateHooks, hooks);
  assert.equal(stateHooks.retainedFixtureHook, true);
  assert.equal(writes.length, 1); assert.ok(Number.isFinite(Date.parse(writes[0].timestamp)));
  t.mock.timers.tick(1999); assert.equal(writes.length, 1);
  t.mock.timers.tick(1); assert.equal(writes.length, 2);
});

// A restarting worker must buffer the waking alarm while its async background
// import runs. Testing only an already attached listener would miss that loss.
test('service worker buffers the waking transaction alarm until background attaches', async t => {
  const { alarms, lazyListener } = await workerFixture(t), received = [];
  alarms.onAlarm.emit({ name: 'TRANSACTION_NOTIFICATIONS_ALARM' });
  lazyListener.addListener('alarms', 'onAlarm', alarm => received.push(alarm.name));
  assert.deepEqual(received, ['TRANSACTION_NOTIFICATIONS_ALARM']);
  alarms.onAlarm.emit({ name: 'AUTO_LOCK_TIMEOUT_ALARM' });
  assert.deepEqual(received, ['TRANSACTION_NOTIFICATIONS_ALARM', 'AUTO_LOCK_TIMEOUT_ALARM']);
});

// A click on a notification can be the event that wakes a stopped worker, so the lazy listener buffers it like the
// waking alarm. The click is emitted BEFORE the background attaches (emitting after would not test the buffering): the
// consumer receives it once at attach, and a later click goes straight to it.
test('service worker buffers a waking notification click until background attaches', async t => {
  const { notifications, lazyListener } = await workerFixture(t), received = [];
  notifications.onClicked.emit('nodus-messages');
  lazyListener.addListener('notifications', 'onClicked', id => received.push(id));
  assert.deepEqual(received, ['nodus-messages']);
  notifications.onClicked.emit('nodus-approval');
  assert.deepEqual(received, ['nodus-messages', 'nodus-approval']);
});

// Proves the notifications entry is guarded: a worker whose chrome object has no notifications API still imports without
// throwing, and keeps its other buffered events.
test('service worker imports without a notifications API', async t => {
  const { runtime, lazyListener } = await workerFixture(t, { notifications: false }), received = [];
  runtime.onConnect.emit({ name: 'popup' });
  lazyListener.addListener('runtime', 'onConnect', port => received.push(port.name));
  assert.deepEqual(received, ['popup']);
});

// Proves the default twenty-second leak warning reports remaining buffered calls; draining every listener or asserting only on a timer would falsely pass.
test('lazy listener warns about undrained events after twenty seconds', async t => {
  const { runtime } = await workerFixture(t);
  const saved = process.env.IN_TEST;
  delete process.env.IN_TEST;
  t.after(() => { if (saved === undefined) delete process.env.IN_TEST; else process.env.IN_TEST = saved; });
  runtime.onConnect.emit({ name: 'popup' }); runtime.onConnect.emit({ name: 'notification' });
  // The alarm and notification-click consumers are attached; this test isolates the undrained ports.
  stateHooks.lazyListener.addListener('alarms', 'onAlarm', () => {});
  stateHooks.lazyListener.addListener('notifications', 'onClicked', () => {});
  const warnings = [];
  t.mock.method(console, 'warn', message => warnings.push(message));
  t.mock.timers.tick(19999); assert.deepEqual(warnings, []);
  t.mock.timers.tick(1);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /runtime\.onConnect/u);
  assert.match(warnings[0], /20000ms/u);
  assert.match(warnings[0], /2 buffered calls/u);
});

// Proves removing/throwing callbacks retain unconsumed calls during replay; success-only callbacks could hide loss in either restoring branch.
test('lazy listener preserves unconsumed calls when replay stops', async t => {
  const { runtime, lazyListener } = await workerFixture(t);
  for (const value of [1, 2, 3]) runtime.onConnect.emit(value);
  const received = [];
  const consumeFirst = value => { received.push(value); runtime.onConnect.removeListener(consumeFirst); };
  lazyListener.addListener('runtime', 'onConnect', consumeFirst);
  assert.deepEqual(received, [1]);
  const failure = new Error('Replay fixture failure');
  assert.throws(() => lazyListener.addListener('runtime', 'onConnect', () => { throw failure; }), error => error === failure);
  const remaining = [];
  lazyListener.addListener('runtime', 'onConnect', value => remaining.push(value));
  assert.deepEqual(remaining, [3]);
});

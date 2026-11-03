import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { EventEmitter, once } from 'node:events';
import ObjectMultiplex from '@metamask/object-multiplex';
import log from 'loglevel';
import { Caip25EndowmentPermissionName, setEthAccounts } from '@metamask/chain-agnostic-permission';
import { VAULT_KEY } from '../../src/vault.js';
import { AUTO_LOCK_TIMEOUT_ALARM } from '../src/background/auto-lock-alarm.js';
import { parsePortInfo } from '../src/background/engine.js';

// Node >=22.14, existing CPUNK WASM; no flags/network/disk output. Browser APIs below are in-memory fakes.
const phrase = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';
const password = 'public-test-password-123';
const cpunkWasmBytes = readFileSync(new URL('../../src/cpunk/legacy-dilithium.wasm', import.meta.url));
const account = '0xf278cf59f82edcf871d630f28ecc8056f25c1cdb';
function event() {
  const listeners = new Set();
  return { listeners, addListener(fn) { listeners.add(fn); }, removeListener(fn) { listeners.delete(fn); }, emit(...args) { return [...listeners].map(fn => fn(...args)); } };
}
function browserFixture() {
  const values = {}, writes = [], created = [], focused = [], scheduled = new Map(), alarmsCreated = [];
  return { values, writes, created, focused, alarmsCreated, consumeNodusSeed: () => {},
    runtime: { id: 'test-extension', onConnect: event(), getManifest: () => ({ version: '0.1.132' }), getURL: path => `chrome-extension://test-extension/${path}` },
    storage: { async get(key) { return key === null ? structuredClone(values) : { [key]: structuredClone(values[key]) }; },
      async set(items) { writes.push(structuredClone(items)); Object.assign(values, structuredClone(items)); } },
    alarms: { onAlarm: event(), async clear(name) { scheduled.delete(name); }, async create(name, options) { scheduled.set(name, options); alarmsCreated.push({ name, ...options }); } },
    windows: { onRemoved: event(), async getAll() { return created; }, async getLastFocused() { return { top: 0, left: 0, width: 1000 }; },
      async create(options) { const win = { ...options, id: created.length + 1 }; created.push(win); return win; }, async update(id, options) { focused.push({ id, ...options }); } },
    tabs: { async query() { return []; } },
    scheduled,
  };
}
let backgroundModule;
async function setup(t) {
  const fixture = browserFixture();
  if (!backgroundModule) {
    const saved = Object.getOwnPropertyDescriptor(globalThis, 'chrome');
    globalThis.chrome = { runtime: fixture.runtime, storage: { local: fixture.storage }, alarms: fixture.alarms, windows: fixture.windows };
    try { backgroundModule = await import('../src/background/index.js'); await (await backgroundModule.background).destroy(); }
    finally { if (saved) Object.defineProperty(globalThis, 'chrome', saved); else delete globalThis.chrome; }
  }
  const background = await backgroundModule.createBackground(fixture);
  // The data notice gate (2026-11-03 Chrome Web Store decision) refuses website requests until the user agreed to
  // it; privacy-consent.test.js covers the refusal, every test here starts after the agreement.
  await background.privacyConsent.accept();
  t.after(async () => {
    // metamask-controller.js:4987-5001 removes connections in pipeline cleanup; disconnect alone does not prove it finished.
    // Preserve pipeline cleanup before locking and disposing the background's holders/controllers.
    await until(() => background.engine.connections.size === 0);
    await background.lockCoordinator.lock(); await background.destroy();
  });
  return { ...fixture, background };
}

// Connect capabilities must use the existing authenticated controller stream.
// Real engine/mux, fake Chrome transport; no network or disk output. This
// tests routing/custody, not real encrypted conversations (browser coverage).
test('Connect state and actions are trusted-UI only, including forged popup names and controller frames', async t => {
  const { runtime, background } = await setup(t);
  const ui = port(runtime, `chrome-extension://${runtime.id}/popup.html`, 'popup');
  const site = port(runtime, 'https://site.example/popup.html', 'popup');
  try {
    await background.vaultStore.create(password, phrase);
    await background.unlock(password, { cpunkWasmBytes });
    const state = await request(ui, 'getConnectState', [], 'controller');
    assert.equal(state.error, undefined, 'The genuine popup has the bounded Connect read');
    assert.ok(state.result && typeof state.result === 'object');
    for (const method of ['getConnectState', 'connectAction']) {
      const reply = await request(site, method, method === 'connectAction' ? [state.result.epoch, 'sync', {}] : [], 'nodus-provider',
        { origin: `chrome-extension://${runtime.id}`, isNodusInternal: true });
      assert.ok(reply.error, `The website cannot invoke ${method}`);
      assert.equal(reply.result, undefined);
    }
    const id = ++requestId;
    site.onMessage.emit({ name: 'controller', data: { jsonrpc: '2.0', id, method: 'getConnectState', params: [] } });
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(site.messages.some(message => message.name === 'controller' && message.data.id === id), false,
      'Sending a controller frame does not upgrade a website to extension UI');
    await background.lockCoordinator.lock();
    assert.ok((await request(ui, 'getConnectState', [], 'controller')).error, 'Locked UI cannot read conversations');
    const locked = await request(ui, 'connectAction', [state.result.epoch, 'sync', {}], 'controller');
    assert.ok(locked.error, 'A trusted page still cannot act while locked');
    assert.equal(locked.result, undefined);
    assert.equal(background.lockCoordinator.isLocked, true);
    for (const forbidden of ['phrase', 'words', 'seed', 'privateKey', 'group_key', 'historyKey']) {
      assert.equal(Object.hasOwn(state.result, forbidden), false);
    }
  } finally { ui.disconnect(); site.disconnect(); }
});
function port(runtime, url = 'https://site.example/frame', name = 'nodus-contentscript', overrides = {}) {
  const result = { name, sender: { id: runtime.id, url, frameId: 2, tab: { id: 8, url: 'https://top.example/' } },
    messages: [], onMessage: event(), onDisconnect: event(), disconnected: false,
    postMessage(message) { this.messages.push(structuredClone(message)); },
    disconnect() { if (!this.disconnected) { this.disconnected = true; this.onDisconnect.emit(this); } },
    ...overrides,
  };
  runtime.onConnect.emit(result); return result;
}
async function until(predicate) {
  for (let turn = 0; turn < 80; turn++) { const result = predicate(); if (result) return result; await new Promise(resolve => setImmediate(resolve)); }
  assert.fail('Expected asynchronous browser event did not arrive');
}
let requestId = 0;
function request(remote, method, params, channel = 'nodus-provider', extras = {}) {
  const id = ++requestId;
  remote.onMessage.emit({ name: channel, data: { id, jsonrpc: '2.0', method, params, ...extras } });
  return until(() => remote.messages.find(message => message.name === channel && message.data.id === id)?.data);
}
function approve(background, pending) {
  const approved = structuredClone(pending.requestData), permission = approved.permissions[Caip25EndowmentPermissionName];
  permission.caveats[0].value = setEthAccounts(permission.caveats[0].value, [account]);
  return background.permissions.acceptPermissionsRequest(approved);
}

// Proves trust follows the parsed sender origin, including opaque/absent URLs; checking only a port name permits page impersonation.
test('Chromium UI trust requires this extension origin', () => {
  const runtime = { id: 'test-extension' };
  for (const url of [undefined, 'invalid', 'https://site.example/popup', 'chrome-extension://other/popup.html', 'https://test-extension@site.example/']) {
    assert.equal(parsePortInfo({ name: 'popup', sender: { id: runtime.id, url } }, runtime).isUiPort, false);
  }
  assert.equal(parsePortInfo({ name: 'arbitrary', sender: { url: 'chrome-extension://test-extension/notification.html' } }, runtime).isUiPort, true);
});

// Proves trusted controller chunk decoding and approval resolution while locked; unchunked/unlocked fixtures could miss stream options or an extra lock check.
test('UI controller uses default port chunking without a provider connection', async t => {
  const { background, runtime } = await setup(t), ui = port(runtime, `chrome-extension://${runtime.id}/popup.html`, 'popup');
  // Proves an extension-origin port receives startUISync as its first controller frame before any request.
  assert.deepEqual(await until(() => ui.messages.find(message => message.name === 'controller')),
    { name: 'controller', data: { jsonrpc: '2.0', method: 'START_UI_SYNC', params: [] } });
  assert.equal(background.engine.connections.size, 0);
  const id = ++requestId;
  // extension-port-stream 5.0.3 dist/parsing.js:10-16: <id>|<seq>|<fin><data>.
  ui.onMessage.emit(`1|0|1${JSON.stringify({ name: 'controller', data: { id, jsonrpc: '2.0', method: 'getState', params: [] } })}`);
  const reply = await until(() => ui.messages.find(message => message.name === 'controller' && message.data.id === id)?.data);
  assert.equal(reply.result.isUnlocked, false); assert.equal(reply.error, undefined);
  const pending = background.approvals.controller.add({ id: 'locked-approval', origin: 'https://site.example', type: 'personal_sign' });
  assert.equal((await request(ui, 'resolvePendingApproval', ['locked-approval', true], 'controller')).error, undefined);
  assert.equal(await pending, true);
  ui.disconnect();
});

// Proves only popup ports and active fullscreen tabs suppress notifications; an inactive-tabs fixture could conceal counting notification ports as open popups.
test('triggerUi counts popup ports and active fullscreen tabs as in the reference', async t => {
  for (const [name, expectedWindows] of [['popup', 0], ['notification', 1], ['fullscreen', 0]]) {
    const { runtime, tabs, background, created } = await setup(t);
    t.mock.method(tabs, 'query', async () => [{ id: 8 }]);
    const ui = port(runtime, `chrome-extension://${runtime.id}/${name}.html`, name);
    // Chrome delivers a port's disconnect in a later task, after startUISync has reached the port; wait for it likewise.
    await until(() => ui.messages.length);
    await background.approvals.triggerUi();
    assert.equal(created.length, expectedWindows, name);
    ui.disconnect();
  }
});

// Proves the URL-less failure path and clean closure of the unpiped provider substream; connections.size alone misses this pre-registration stream.
test('untrusted port handling retains the reference URL-less failure path', async t => {
  const { background, runtime } = await setup(t);
  const createStream = ObjectMultiplex.prototype.createStream;
  let unconnectedStream;
  t.mock.method(ObjectMultiplex.prototype, 'createStream', function (...args) {
    unconnectedStream = createStream.apply(this, args); return unconnectedStream;
  });
  const noUrl = { name: 'nodus-contentscript', sender: { id: runtime.id }, onMessage: event(), onDisconnect: event(),
    postMessage() {}, disconnect: t.mock.fn() };
  assert.throws(() => background.engine.onConnect(noUrl), { code: 'ERR_INVALID_URL' });
  assert.equal(noUrl.disconnect.mock.callCount(), 0);
  assert.ok(unconnectedStream);
  assert.equal(unconnectedStream.destroyed, false);
  assert.equal(unconnectedStream.listenerCount('error'), 0);
  const closed = once(unconnectedStream, 'close');
  // metamask-controller.js:4550-4553, 4943 creates this substream before the URL throws, without an engine pipeline.
  // Deliver the peer disconnect before background.destroy(); extension-port-stream dist/index.js:75-108 ends the port first.
  noUrl.onDisconnect.emit(noUrl);
  await closed;
  assert.equal(unconnectedStream.destroyed, true);
});

// Proves real port/mux/engine/controller connect approval and rejection; direct controller-only tests could miss runtime wiring or a forged request origin.
test('site connect opens notification, cannot call UI methods, and cancellation returns 4001', async t => {
  const { runtime, background, created, focused, alarmsCreated } = await setup(t);
  await background.vaultStore.create(password, phrase); await background.unlock(password, { cpunkWasmBytes });
  const remote = port(runtime, 'https://site.example/path', 'popup'), alarmCount = alarmsCreated.length;
  assert.deepEqual((await request(remote, 'eth_accounts')).result, []);
  assert.equal((await request(remote, 'resolvePendingApproval', ['missing'], 'nodus-provider', { origin: `chrome-extension://${runtime.id}` })).error.code, -32601);
  const connecting = request(remote, 'eth_requestAccounts', [], 'nodus-provider', { origin: 'https://forged.example' });
  const pending = await until(() => Object.values(background.approvals.controller.state.pendingApprovals)[0]);
  await background.approvals.whenUiSettled(); assert.equal(created[0].type, 'popup'); assert.equal(pending.origin, 'https://site.example');
  assert.deepEqual((await request(remote, 'eth_accounts')).result, []);
  const ui = port(runtime, `chrome-extension://${runtime.id}/notification.html`, 'notification');
  const approved = structuredClone(pending.requestData);
  approved.permissions[Caip25EndowmentPermissionName].caveats[0].value = setEthAccounts(approved.permissions[Caip25EndowmentPermissionName].caveats[0].value, [account]);
  remote.onMessage.emit({ name: 'controller', data: { id: 'forged-ui', jsonrpc: '2.0', method: 'approvePermissionsRequest', params: [approved] } });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(background.approvals.controller.state.pendingApprovalCount, 1);
  assert.deepEqual((await request(remote, 'eth_accounts')).result, []);
  assert.equal((await request(ui, 'approvePermissionsRequest', [approved], 'controller')).error, undefined);
  assert.deepEqual((await connecting).result, [account]);
  assert.deepEqual((await request(remote, 'eth_accounts')).result, [account]);
  assert.equal(alarmsCreated.length, alarmCount);
  const other = port(runtime, 'https://other.example/'), rejected = request(other, 'eth_requestAccounts');
  const denied = await until(() => Object.values(background.approvals.controller.state.pendingApprovals)[0]);
  await background.approvals.whenUiSettled();
  assert.deepEqual(focused, [{ id: created[0].id, focused: true }]);
  await request(ui, 'rejectPermissionsRequest', [denied.id], 'controller'); assert.equal((await rejected).error.code, 4001);
  remote.disconnect(); other.disconnect(); ui.disconnect();
  await until(() => background.engine.connections.size === 0);
});

// Proves T-2 across creation/import, real joined unlock, permission update and lock, inspecting all writes/backups; a final-only snapshot misses transient plaintext/vault leaks.
test('persisted permission state never introduces a second encrypted phrase store', async t => {
  const { background, runtime, values, writes, storage } = await setup(t);
  await background.vaultStore.create(password, phrase); const value = values[VAULT_KEY];
  await background.vaultStore.importVault(value); await background.unlock(password, { cpunkWasmBytes });
  const remote = port(runtime, 'https://site.example/frame', 'nodus-contentscript', {
    sender: { id: 'other-extension', url: 'https://site.example/frame', tab: { id: 8 } },
  }), connecting = request(remote, 'eth_requestAccounts');
  await approve(background, await until(() => Object.values(background.approvals.controller.state.pendingApprovals)[0]));
  assert.deepEqual((await connecting).result, [account]);
  await until(() => remote.messages.some(message => message.data.method === 'nodus_accountsChanged'));
  const accountNotices = () => remote.messages.filter(message => message.data.method === 'nodus_accountsChanged');
  const notificationCount = accountNotices().length;
  await background.connectedSites.flush();
  await background.lock(); await background.store.flush();
  await new Promise(resolve => setImmediate(resolve));
  // 2026-11-03 Chrome Web Store decision, plan section 2.6: the connected-sites list leaves memory at lock, so the
  // page is told its account list is empty (before, lock kept the grant and sent nothing).
  assert.equal(accountNotices().length, notificationCount + 1);
  assert.deepEqual(accountNotices().at(-1).data.params, []);
  assert.equal(values[VAULT_KEY], value);
  // The list is no longer in the plain controller state; only the sealed record holds it.
  assert.equal(Object.hasOwn(background.store.backup(), 'PermissionController'), false);
  assert.equal(typeof values['nodus.sites.v1'], 'string');
  for (const write of [...writes, background.store.backup()]) {
    const serialized = JSON.stringify(write);
    assert.equal(serialized.includes(phrase), false); assert.equal(serialized.includes(password), false);
    assert.equal(serialized.includes('KeyringController'), false); assert.equal(serialized.includes('"vault"'), false);
    assert.equal(serialized.includes('site.example'), false, 'no origin in any stored write');
  }
  assert.deepEqual((await request(remote, 'eth_accounts')).result, []);
  for (const method of ['signPersonalMessage', 'signTypedMessage', 'signTransaction']) await assert.rejects(background.keyring[method](), /locked/iu);
  await background.unlock(password, { cpunkWasmBytes });
  await until(() => accountNotices().length === notificationCount + 2);
  assert.deepEqual(accountNotices().at(-1).data.params, [account]);
  assert.deepEqual((await request(remote, 'eth_accounts')).result, [account]);
  remote.disconnect();
  // A restarted worker starts with the list empty and locked; no plain grant is read.
  const restarted = await backgroundModule.createBackground({ ...browserFixture(), storage });
  try {
    assert.equal(restarted.lockCoordinator.isLocked, true); assert.deepEqual(await restarted.permissions.getAccounts('https://site.example'), []);
  }
  finally { await restarted.destroy(); }
});

// Proves T-5 expiry clears the alarm, unlock re-arms it, site traffic cannot reset it, and UI activity can; counting startup scheduling alone could falsely pass.
test('successful unlock re-arms inactivity after expiry with every interface closed', async t => {
  const { background, runtime, alarms, scheduled, alarmsCreated } = await setup(t);
  await background.vaultStore.create(password, phrase); await background.unlock(password, { cpunkWasmBytes });
  const remote = port(runtime), connecting = request(remote, 'eth_requestAccounts');
  await approve(background, await until(() => Object.values(background.approvals.controller.state.pendingApprovals)[0])); await connecting;
  await Promise.all(alarms.onAlarm.emit({ name: AUTO_LOCK_TIMEOUT_ALARM }));
  // The expiry lock empties the connected-sites list from memory (plan section 2.6); the next unlock below restores it.
  assert.equal(scheduled.has(AUTO_LOCK_TIMEOUT_ALARM), false); assert.deepEqual((await request(remote, 'eth_accounts')).result, []);
  for (const method of ['signPersonalMessage', 'signTypedMessage', 'signTransaction']) await assert.rejects(background.keyring[method](), /locked/iu);
  const before = alarmsCreated.length;
  await background.unlock(password, { cpunkWasmBytes }); assert.equal(alarmsCreated.length, before + 1);
  assert.equal(scheduled.get(AUTO_LOCK_TIMEOUT_ALARM).delayInMinutes, 15);
  await request(remote, 'eth_accounts'); assert.equal(alarmsCreated.length, before + 1);
  const ui = port(runtime, `chrome-extension://${runtime.id}/popup.html`, 'popup');
  await request(ui, 'setLastActiveTime', [], 'controller'); assert.equal(alarmsCreated.length, before + 2);
  ui.disconnect(); remote.disconnect(); assert.equal(scheduled.has(AUTO_LOCK_TIMEOUT_ALARM), true);
});

// Proves attached providers, filters/subscriptions, trusted request context and teardown; a read-only backend test could miss retained block listeners or duplicate-id work.
test('network middleware uses the shared client and cleans filters on disconnect', async t => {
  const { background, runtime } = await setup(t), blockTracker = new EventEmitter(), forwarded = [];
  blockTracker.getLatestBlock = async () => '0x1';
  const provider = { async request(req) { forwarded.push(req); return req.method === 'net_version' ? '1' : '0x42'; },
    sendAsync(req, callback) { this.request(req).then(result => callback(null, { id: req.id, jsonrpc: '2.0', result }), callback); } };
  const metadata = { status: 'available' };
  background.engine.attachNetworkClient({ provider, blockTracker, configuration: { chainId: '0x1' } }, () => metadata);
  const remote = port(runtime);
  assert.equal((await request(remote, 'eth_blockNumber')).result, '0x42');
  // Reference: eth-json-rpc-filters 9.0.0 index.js:187-191 uses hexUtils.js:51-56's even-length padding.
  assert.equal((await request(remote, 'eth_newBlockFilter', [])).result, '0x01');
  assert.ok((await request(remote, 'eth_subscribe', ['newHeads'])).result);
  assert.ok(blockTracker.listenerCount('sync') >= 2);
  assert.equal((await request(remote, 'eth_signTransaction', [{}])).error.code, -32004);
  const state = (await request(remote, 'nodus_getProviderState')).result;
  assert.equal(state.extensionId, runtime.id); assert.equal(state.isConnected, true);
  metadata.status = 'unavailable';
  assert.equal((await request(remote, 'nodus_getProviderState')).result.isConnected, false);
  const read = forwarded.find(req => req.method === 'eth_blockNumber');
  assert.equal(read.origin, 'https://site.example');
  remote.disconnect(); await until(() => background.engine.connections.size === 0);
  assert.equal(blockTracker.listenerCount('sync'), 0);
});

// Proves package 3's buffered connect is drained into the live engine; only opening ports after initialization could falsely pass.
test('service-worker lazy listener hands an early port to the engine', async t => {
  await setup(t);
  const fixture = browserFixture(), early = port(fixture.runtime), saved = new Map();
  for (const key of ['chrome', 'stateHooks']) saved.set(key, Object.getOwnPropertyDescriptor(globalThis, key));
  let consumed = false, background;
  globalThis.chrome = { runtime: fixture.runtime };
  globalThis.stateHooks = { lazyListener: { addListener(namespace, name, listener) {
    assert.equal(namespace, 'runtime'); assert.equal(name, 'onConnect'); consumed = true;
    fixture.runtime.onConnect.addListener(listener); listener(early);
  } } };
  try { background = await backgroundModule.createBackground(fixture); }
  finally { for (const [key, descriptor] of saved) { if (descriptor) Object.defineProperty(globalThis, key, descriptor); else delete globalThis[key]; } }
  try {
    assert.equal(consumed, true);
    // The data notice gate refuses website requests until the agreement (plan section 2.7); this test proves the port hand-off.
    await background.privacyConsent.accept();
    assert.deepEqual((await request(early, 'eth_accounts')).result, []);
    assert.equal(background.engine.connections.size, 1);
  } finally { early.disconnect(); await background.destroy(); }
});

// Proves duplicate IDs do not execute twice and page context cannot pick a different origin; counting responses alone could miss repeated provider work.
test('duplicate filter suppresses repeat work on a connection', async t => {
  const { background, runtime } = await setup(t), blockTracker = new EventEmitter(), calls = [];
  blockTracker.getLatestBlock = async () => '0x1';
  const provider = { async request(req) { calls.push(req); return '0x1'; }, sendAsync(_req, callback) { callback(null, { result: '0x1' }); } };
  background.engine.attachNetworkClient({ provider, blockTracker, configuration: { chainId: '0x1' } });
  const remote = port(runtime), id = ++requestId;
  const message = { name: 'nodus-provider', data: { id, jsonrpc: '2.0', method: 'eth_blockNumber', origin: 'https://forged.example' } };
  remote.onMessage.emit(message); remote.onMessage.emit(message);
  await until(() => remote.messages.some(item => item.data.id === id));
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(calls.filter(req => req.method === 'eth_blockNumber').length, 1);
  assert.equal(calls.find(req => req.method === 'eth_blockNumber').origin, 'https://site.example');
  assert.equal(remote.messages.filter(item => item.data.id === id).length, 1);
  remote.disconnect();
});

// Proves errors and signing params never reach logger calls; checking only successful requests would miss the reference's whole-error debug branch.
test('RPC logs contain method/status without request or error data', async t => {
  const { background, runtime } = await setup(t), logs = [], sentinel = 'public-sensitive-parameter-sentinel';
  for (const method of ['info', 'debug', 'error']) t.mock.method(log, method, (...args) => logs.push(args));
  const blockTracker = new EventEmitter(); blockTracker.getLatestBlock = async () => '0x1';
  const provider = { async request() { throw new Error(sentinel); }, sendAsync(_req, callback) { callback(new Error(sentinel)); } };
  background.engine.attachNetworkClient({ provider, blockTracker, configuration: { chainId: '0x1' } });
  const remote = port(runtime);
  assert.ok((await request(remote, 'eth_call', [{ data: sentinel }])).error);
  assert.equal((await request(remote, 'personal_sign', [sentinel, account])).error.code, 4100);
  assert.ok(logs.some(args => args[0] === 'RPC (https://site.example): eth_call -> error'));
  assert.equal(JSON.stringify(logs).includes(sentinel), false);
  remote.disconnect();
});

// Proves the renamed request flag controls the page logger; checking only a normal request would miss the flag-based skip.
test('RPC logger skips page requests marked isNodusInternal', async t => {
  const { runtime } = await setup(t), logs = [];
  t.mock.method(log, 'info', (...args) => logs.push(args));
  const remote = port(runtime);
  assert.match((await request(remote, 'web3_clientVersion')).result, /^Nodus\/v/u);
  assert.ok(logs.some(args => args[0] === 'RPC (https://site.example): web3_clientVersion -> success'));
  const before = logs.length;
  assert.match((await request(remote, 'web3_clientVersion', [], 'nodus-provider', { isNodusInternal: true })).result, /^Nodus\/v/u);
  assert.equal(logs.length, before);
  remote.disconnect();
});

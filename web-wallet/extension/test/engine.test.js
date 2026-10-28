import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { EventEmitter, once } from 'node:events';
import { JsonRpcEngine } from '@metamask/json-rpc-engine';
import ObjectMultiplex from '@metamask/object-multiplex';
import log from 'loglevel';
import { Caip25EndowmentPermissionName, setEthAccounts } from '@metamask/chain-agnostic-permission';
import { VAULT_KEY } from '../../src/vault.js';
import { AUTO_LOCK_TIMEOUT_ALARM } from '../src/background/auto-lock-alarm.js';
import { parsePortInfo, createEvmMethodsToNonEvmAccountReqFilterMiddleware } from '../src/background/engine.js';

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
  return { values, writes, created, focused, alarmsCreated,
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
  t.after(async () => {
    // metamask-controller.js:4987-5001 removes connections in pipeline cleanup; disconnect alone does not prove it finished.
    // Preserve pipeline cleanup before locking and disposing the background's holders/controllers.
    await until(() => background.engine.connections.size === 0);
    await background.lockCoordinator.lock(); await background.destroy();
  });
  return { ...fixture, background };
}
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

// Proves both non-EVM rejection branches and EVM/read pass-through; checking only the current EVM selection could pass with the filter omitted.
test('EVM account filter rejects the reference methods and requested permissions for non-EVM selections', async () => {
  let type = 'solana:data-account';
  const engine = new JsonRpcEngine();
  engine.push(createEvmMethodsToNonEvmAccountReqFilterMiddleware({ getSelectedAccount: () => ({ type }) }));
  engine.push((_req, res, _next, end) => { res.result = true; end(); });
  let id = 0;
  const request = (method, params) => engine.handle({ id: ++id, jsonrpc: '2.0', method, params });
  try {
    for (const method of ['eth_accounts', 'eth_sendRawTransaction', 'eth_sendTransaction', 'eth_signTypedData',
      'eth_signTypedData_v1', 'eth_signTypedData_v3', 'eth_signTypedData_v4']) {
      assert.equal((await request(method)).error.message, `Non-EVM account cannot request this method: ${method}`);
      assert.equal((await request('wallet_requestPermissions', [{ [method]: {} }])).error.message, `Non-EVM account cannot request this method: ${method}`);
    }
    assert.equal((await request('eth_blockNumber')).result, true);
    assert.equal((await request('personal_sign')).result, true);
    for (const params of [undefined, [], [null], [{ unrelated: {} }]]) assert.equal((await request('wallet_requestPermissions', params)).result, true);
    for (type of ['eip155:eoa', 'eip155:erc4337']) assert.equal((await request('eth_sendTransaction')).result, true);
  } finally { engine.destroy(); }
});

// Proves the filter is in the real engine before permission requests create approvals; a standalone middleware test cannot prove its wiring.
test('provider engine filters non-EVM permission requests before approval', async t => {
  const { background, runtime } = await setup(t);
  t.mock.method(background.permissions, 'getSelectedAccount', () => ({ type: 'solana:data-account' }));
  const remote = port(runtime);
  assert.equal((await request(remote, 'wallet_requestPermissions', [{ eth_accounts: {} }])).error.message, 'Non-EVM account cannot request this method: eth_accounts');
  assert.equal(background.approvals.controller.state.pendingApprovalCount, 0);
  remote.disconnect();
});

// Proves trusted chunk decoding, renamed internal origin and approval resolution while locked; unchunked/unlocked fixtures could miss stream options or an extra lock check.
test('UI provider uses the renamed internal origin and default port chunking', async t => {
  const { background, runtime } = await setup(t), ui = port(runtime, `chrome-extension://${runtime.id}/popup.html`, 'popup');
  assert.equal([...background.engine.connections.values()][0].origin, 'nodus');
  const id = ++requestId;
  // extension-port-stream 5.0.3 dist/parsing.js:10-16: <id>|<seq>|<fin><data>.
  ui.onMessage.emit(`1|0|1${JSON.stringify({ name: 'controller', data: { id, jsonrpc: '2.0', method: 'getState', params: [] } })}`);
  const reply = await until(() => ui.messages.find(message => message.name === 'controller' && message.data.id === id)?.data);
  assert.equal(reply.result.isUnlocked, false); assert.equal(reply.error, undefined);
  assert.deepEqual(reply.result.subjectMetadata, {});
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
    await background.approvals.triggerUi();
    assert.equal(created.length, expectedWindows, name);
    ui.disconnect();
  }
});

// Proves the reference ignore/URL-less paths and clean closure of the unpiped provider substream; connections.size alone misses this pre-registration stream.
test('untrusted port handling retains the reference multiplex and URL-less failure paths', async t => {
  const { background, runtime } = await setup(t), ignored = [];
  const ignore = ObjectMultiplex.prototype.ignoreStream;
  t.mock.method(ObjectMultiplex.prototype, 'ignoreStream', function (name) { ignored.push(name); return ignore.call(this, name); });
  const remote = port(runtime);
  assert.deepEqual(ignored, ['nodus-multichain-provider']); remote.disconnect();
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
  background.attachWalletKeys(() => {}); await background.vaultStore.create(password, phrase); await background.unlock(password, { cpunkWasmBytes });
  const remote = port(runtime, 'https://site.example/path', 'popup'), alarmCount = alarmsCreated.length;
  assert.deepEqual(background.engine.requestAccountTabIds, {});
  assert.deepEqual((await request(remote, 'eth_accounts')).result, []);
  assert.equal((await request(remote, 'resolvePendingApproval', ['missing'], 'nodus-provider', { origin: `chrome-extension://${runtime.id}` })).error.code, -32601);
  const connecting = request(remote, 'eth_requestAccounts', [], 'nodus-provider', { origin: 'https://forged.example' });
  const pending = await until(() => Object.values(background.approvals.controller.state.pendingApprovals)[0]);
  assert.deepEqual(background.engine.requestAccountTabIds, { 'https://site.example': 8 });
  await background.approvals.whenUiSettled(); assert.equal(created[0].type, 'popup'); assert.equal(pending.origin, 'https://site.example');
  assert.deepEqual((await request(remote, 'eth_accounts')).result, []);
  const ui = port(runtime, `chrome-extension://${runtime.id}/notification.html`, 'notification');
  assert.deepEqual((await request(ui, 'getRequestAccountTabIds', [], 'controller')).result, { 'https://site.example': 8 });
  assert.deepEqual((await request(ui, 'getState', [], 'controller')).result.subjectMetadata, {});
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
  background.attachWalletKeys(() => {});
  await background.vaultStore.create(password, phrase); const value = values[VAULT_KEY];
  await background.vaultStore.importVault(value); await background.unlock(password, { cpunkWasmBytes });
  const remote = port(runtime, 'https://site.example/frame', 'nodus-contentscript', {
    sender: { id: 'other-extension', url: 'https://site.example/frame', tab: { id: 8 } },
  }), connecting = request(remote, 'eth_requestAccounts');
  await approve(background, await until(() => Object.values(background.approvals.controller.state.pendingApprovals)[0]));
  assert.deepEqual((await connecting).result, [account]);
  await until(() => remote.messages.some(message => message.data.method === 'nodus_accountsChanged'));
  const notificationCount = remote.messages.filter(message => message.data.method === 'nodus_accountsChanged').length;
  await background.lock(); await background.store.flush();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(remote.messages.filter(message => message.data.method === 'nodus_accountsChanged').length, notificationCount);
  assert.equal(values[VAULT_KEY], value);
  assert.ok(Object.keys(background.store.backup().PermissionController.subjects).includes('https://site.example'));
  assert.deepEqual(background.permissions.subjectMetadataController.getSubjectMetadata('https://site.example'), {
    origin: 'https://site.example', extensionId: 'other-extension', subjectType: 'extension', name: null, iconUrl: null,
  });
  assert.equal(background.store.backup().SubjectMetadataController.subjectMetadata['https://site.example'].extensionId, 'other-extension');
  for (const write of [...writes, background.store.backup()]) {
    const serialized = JSON.stringify(write);
    assert.equal(serialized.includes(phrase), false); assert.equal(serialized.includes(password), false);
    assert.equal(serialized.includes('KeyringController'), false); assert.equal(serialized.includes('"vault"'), false);
  }
  assert.deepEqual((await request(remote, 'eth_accounts')).result, [account]);
  for (const method of ['signPersonalMessage', 'signTypedMessage', 'signTransaction']) await assert.rejects(background.keyring[method](), /locked/iu);
  await background.unlock(password, { cpunkWasmBytes });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(remote.messages.filter(message => message.data.method === 'nodus_accountsChanged').length, notificationCount);
  remote.disconnect();
  const restarted = await backgroundModule.createBackground({ ...browserFixture(), storage });
  try {
    assert.equal(restarted.lockCoordinator.isLocked, true); assert.deepEqual(await restarted.permissions.getAccounts('https://site.example'), [account]);
    assert.equal(restarted.permissions.subjectMetadataController.getSubjectMetadata('https://site.example').extensionId, 'other-extension');
  }
  finally { await restarted.destroy(); }
});

// Proves T-5 expiry clears the alarm, unlock re-arms it, site traffic cannot reset it, and UI activity can; counting startup scheduling alone could falsely pass.
test('successful unlock re-arms inactivity after expiry with every interface closed', async t => {
  const { background, runtime, alarms, scheduled, alarmsCreated } = await setup(t);
  background.attachWalletKeys(() => {}); await background.vaultStore.create(password, phrase); await background.unlock(password, { cpunkWasmBytes });
  const remote = port(runtime), connecting = request(remote, 'eth_requestAccounts');
  await approve(background, await until(() => Object.values(background.approvals.controller.state.pendingApprovals)[0])); await connecting;
  await Promise.all(alarms.onAlarm.emit({ name: AUTO_LOCK_TIMEOUT_ALARM }));
  assert.equal(scheduled.has(AUTO_LOCK_TIMEOUT_ALARM), false); assert.deepEqual((await request(remote, 'eth_accounts')).result, [account]);
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
  assert.equal(read.origin, 'https://site.example'); assert.equal(read.mainFrameOrigin, 'https://top.example');
  assert.equal(read.frameId, 2); assert.equal(read.tabId, 8);
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
  assert.equal((await request(remote, 'personal_sign', [sentinel, account])).error.code, -32004);
  assert.ok(logs.some(args => args[0] === 'RPC (https://site.example): eth_call -> error'));
  assert.equal(JSON.stringify(logs).includes(sentinel), false);
  remote.disconnect();
});

// Proves the renamed request flag controls the logger on both page and internal connections; checking only an internal subject would retain the wrong subjectType skip.
test('RPC logger skips by isNodusInternal rather than the connection subject type', async t => {
  const { runtime } = await setup(t), logs = [];
  t.mock.method(log, 'info', (...args) => logs.push(args));
  const remote = port(runtime), ui = port(runtime, `chrome-extension://${runtime.id}/notification.html`, 'notification');
  assert.match((await request(remote, 'web3_clientVersion')).result, /^Nodus\/v/u);
  assert.ok(logs.some(args => args[0] === 'RPC (https://site.example): web3_clientVersion -> success'));
  assert.match((await request(ui, 'web3_clientVersion', [], 'provider')).result, /^Nodus\/v/u);
  assert.ok(logs.some(args => args[0] === 'RPC (nodus): web3_clientVersion -> success'));
  const before = logs.length;
  assert.match((await request(remote, 'web3_clientVersion', [], 'nodus-provider', { isNodusInternal: true })).result, /^Nodus\/v/u);
  assert.match((await request(ui, 'web3_clientVersion', [], 'provider', { isNodusInternal: true })).result, /^Nodus\/v/u);
  assert.equal(logs.length, before);
  remote.disconnect(); ui.disconnect();
});

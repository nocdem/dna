import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { once } from 'node:events';
import ObjectMultiplex from '@metamask/object-multiplex';
import { ExtensionPortStream } from 'extension-port-stream';
import { Caip25EndowmentPermissionName, getEthAccounts, getPermittedEthChainIds } from '@metamask/chain-agnostic-permission';
import { VAULT_KEY, decryptVault } from '../../src/vault.js';
import { AUTO_LOCK_KEY } from '../../src/auto-lock.js';
import { connectTrusted } from '../src/ui/trusted-port.js';
import { createWalletUi, connectDetails } from '../src/ui/wallet-ui.js';
import { bindActivity } from '../src/ui/activity.js';

// Real DOM filters/hide/refresh gating, asset/receive selection and retained
// send inputs. Public, distinct chain replies; no live RPC/wallet artifacts.
// Pure controller checks could pass with unwired controls on the actual page.
test('mounted portfolio controls route reads and preserve the send form', { timeout: 60_000 }, async () => {
  const { withPortfolioPage, checkPortfolioFlows } = await import('./fixtures/portfolio-page-checks.js');
  await withPortfolioPage(checkPortfolioFlows);
});

// Node >=22.14, no flags, network or disk writes; all browser/port fixtures are in memory and disposed after each test.
const phrase = 'abandon '.repeat(23) + 'art';
const password = 'public-test-password-123';

// Package A: skip is explicit and limited to generated words at backup.
// No flags/network/artifacts. Import-only coverage would miss the skip guard.
test('skip verification saves only the generated backup after explicit confirmation', async () => {
  const client = fakeClient(), ui = createWalletUi(client, { generatePhrase: () => phrase });
  await assert.rejects(ui.skipVerification(password, password), /backup/);
  ui.beginImport();
  await assert.rejects(ui.skipVerification(password, password), /backup/);
  ui.beginCreate();
  await ui.skipVerification(password, password);
  assert.equal(new TextDecoder().decode(Uint8Array.from(client.calls[0].params[1])), phrase);
  assert.equal(ui.state.isUnlocked, true);
});
const account = '0xf278cf59f82edcf871d630f28ecc8056f25c1cdb';
function event() {
  const listeners = new Set();
  return { addListener(fn) { listeners.add(fn); }, removeListener(fn) { listeners.delete(fn); }, emit(...args) { return [...listeners].map(fn => fn(...args)); } };
}
function pair(name, url, runtime) {
  const a = { name, onMessage: event(), onDisconnect: event() }, b = { name, onMessage: event(), onDisconnect: event(),
    sender: { id: runtime.id, url, tab: { id: 1, url } } };
  let closed = false;
  a.postMessage = message => { const copy = structuredClone(message); queueMicrotask(() => { if (!closed) b.onMessage.emit(copy); }); };
  b.postMessage = message => { const copy = structuredClone(message); queueMicrotask(() => { if (!closed) a.onMessage.emit(copy); }); };
  a.disconnect = b.disconnect = () => { if (!closed) { closed = true; a.onDisconnect.emit(a); b.onDisconnect.emit(b); } };
  runtime.onConnect.emit(b);
  return a;
}
async function until(predicate) {
  for (let turn = 0; turn < 100; turn++) { const result = predicate(); if (result) return result; await new Promise(resolve => setImmediate(resolve)); }
  assert.fail('Expected in-process background event did not arrive.');
}
let backgroundModule;
async function setup(t) {
  const values = {}, scheduled = new Map(), ports = [];
  const runtime = { id: 'ui-test', onConnect: event(), getManifest: () => ({ version: '0.1.132' }), getURL: path => `chrome-extension://ui-test/${path}` };
  const fixture = { runtime,
    storage: { async get(key) { return { [key]: structuredClone(values[key]) }; }, async set(items) { Object.assign(values, structuredClone(items)); } },
    alarms: { onAlarm: event(), async clear(name) { scheduled.delete(name); }, async create(name, options) { scheduled.set(name, options); } },
    windows: { onRemoved: event(), async getAll() { return []; }, async getLastFocused() { return { top: 0, left: 0, width: 1000 }; }, async create(options) { return { ...options, id: 2 }; }, async update() {} },
    tabs: { async query() { return []; } },
  };
  runtime.connect = ({ name }) => { const port = pair(name, runtime.getURL(`${name === 'fullscreen' ? 'home' : name}.html`), runtime); ports.push(port); return port; };
  if (!backgroundModule) {
    const saved = Object.getOwnPropertyDescriptor(globalThis, 'chrome');
    globalThis.chrome = { ...fixture, storage: { local: fixture.storage } };
    try { backgroundModule = await import('../src/background/index.js'); await (await backgroundModule.background).destroy(); }
    finally { if (saved) Object.defineProperty(globalThis, 'chrome', saved); else delete globalThis.chrome; }
  }
  const background = await backgroundModule.createBackground(fixture);
  const client = connectTrusted({ runtime, page: 'notification.html' });
  t.after(async () => { client.close(); ports.forEach(port => port.disconnect()); await until(() => background.engine.connections.size === 0); await background.lock(); await background.destroy(); });
  return { background, client, values, scheduled, fixture, runtime };
}
function fakeClient() {
  const calls = [], state = { isInitialized: false, isUnlocked: false, addresses: {}, accounts: [], pendingApprovals: {}, subjects: {}, preferences: { autoLockTimeLimit: 15 } };
  return { calls, state, async request(method, params = []) {
    calls.push({ method, params: structuredClone(params) });
    if (method === 'getState') return structuredClone(state);
    if (method === 'createNewVaultAndRestore') { state.isInitialized = true; return null; }
    if (method === 'submitPasswordOrEncryptionKey') { state.isUnlocked = true; return { addresses: { ethereum: account } }; }
    throw new Error(`Unexpected fixture method: ${method}`);
  } };
}

// Proves client cleanup rejects requests while queued writes finish before port EOF; rejection alone would miss dropped writes or premature transport destruction.
test('closing the trusted client leaves stream ending to port disconnection', async t => {
  const createStream = t.mock.method(ObjectMultiplex.prototype, 'createStream');
  const write = ExtensionPortStream.prototype._write;
  let completeWrite;
  const written = new Promise(resolve => { completeWrite = resolve; });
  t.mock.method(ExtensionPortStream.prototype, '_write', function (message, encoding, callback) {
    return write.call(this, message, encoding, error => { callback(error); completeWrite(error); });
  });
  const destroy = ExtensionPortStream.prototype.destroy, destructions = [];
  t.mock.method(ExtensionPortStream.prototype, 'destroy', function (error) {
    destructions.push({ error, writableFinished: this.writableFinished });
    return destroy.call(this, error);
  });
  const port = { onMessage: event(), onDisconnect: event(), postMessage: t.mock.fn() };
  const client = connectTrusted({ runtime: { connect: () => port }, page: 'notification.html' });
  const controller = createStream.mock.calls[0].result, closed = once(controller, 'close');
  t.after(async () => { port.onDisconnect.emit(port); await closed; });
  let disconnects = 0;
  client.onDisconnect(() => { disconnects++; });
  const rejected = assert.rejects(client.request('getState'), /background disconnected/i);
  await new Promise(resolve => setImmediate(resolve));
  // Proves the request stays off the port before startUISync, even after queued stream work has run.
  assert.equal(port.postMessage.mock.callCount(), 0);
  port.onMessage.emit({ name: 'controller', data: { jsonrpc: '2.0', method: 'START_UI_SYNC', params: [] } });
  await Promise.resolve();
  // Proves a request made after START_UI_SYNC and closed in the same tick is still written (dispose's messengerUnsubscribe).
  const late = client.request('messengerUnsubscribe', ['x']).catch(() => {});
  client.close(); client.close(); await rejected; await late;
  // Substream._write queues into the mux; the port stream's callback follows postMessage.
  assert.ifError(await written);
  assert.equal(disconnects, 1); assert.deepEqual(destructions, []);
  assert.equal(controller.listenerCount('data'), 0); assert.equal(controller.listenerCount('end'), 0);
  await assert.rejects(client.request('getState'), /background disconnected/i);
  // Proves startUISync releases the queued request exactly once; rejection alone would miss a dropped write.
  assert.equal(port.postMessage.mock.callCount(), 2);
  assert.deepEqual(port.postMessage.mock.calls[0].arguments, [{ name: 'controller', data: { jsonrpc: '2.0', id: 1, method: 'getState', params: [] } }]);
  assert.deepEqual(port.postMessage.mock.calls[1].arguments, [{ name: 'controller', data: { jsonrpc: '2.0', id: 2, method: 'messengerUnsubscribe', params: ['x'] } }]);
  port.onDisconnect.emit(port); await closed;
  assert.equal(controller.destroyed, true); assert.ok(destructions.length > 0);
  assert.ok(destructions.every(({ error, writableFinished }) => !error && writableFinished));
});

// Proves unlock uses the trusted password API and refreshes state; checking a local unlocked flag alone would falsely pass.
test('unlock reaches the background password API', async () => {
  const client = fakeClient(), ui = createWalletUi(client);
  await ui.unlock(password);
  assert.deepEqual(client.calls.map(call => call.method), ['submitPasswordOrEncryptionKey', 'getState']);
  assert.deepEqual(client.calls[0].params, [{ password }]); assert.equal(ui.state.isUnlocked, true);
});

// Proves generated words must match a retyped backup before the background save; a test that only imports known words would miss the create guard.
test('create verifies the generated 24 words and sends the reference byte-array restore shape', async () => {
  const client = fakeClient(), ui = createWalletUi(client, { generatePhrase: () => phrase });
  assert.equal(ui.beginCreate(), phrase); ui.confirmBackup();
  await assert.rejects(ui.savePhrase('legal '.repeat(23) + 'wrong', password, password)); assert.equal(client.calls.length, 0);
  await ui.savePhrase(phrase, password, password);
  assert.equal(client.calls[0].method, 'createNewVaultAndRestore');
  assert.equal(new TextDecoder().decode(Uint8Array.from(client.calls[0].params[1])), phrase);
  assert.equal(client.calls[1].method, 'submitPasswordOrEncryptionKey'); assert.equal(ui.phraseStep, null);
});

// Proves import reuses checksum/length/password rules before sending bytes; a success-only mock could falsely accept arbitrary words or a mismatched password.
test('import validates the web-wallet phrase and password rules before saving', async () => {
  const client = fakeClient(), ui = createWalletUi(client); ui.beginImport();
  await assert.rejects(ui.savePhrase('abandon '.repeat(12), password, password));
  await assert.rejects(ui.savePhrase(phrase, 'short', 'short'));
  await assert.rejects(ui.savePhrase(phrase, password, 'different')); assert.equal(client.calls.length, 0);
  await ui.savePhrase(phrase.toUpperCase(), password, password);
  assert.equal(new TextDecoder().decode(Uint8Array.from(client.calls[0].params[1])), phrase);
  assert.equal(ui.state.isUnlocked, true);
});

// Proves the real trusted save writes the single web vault and checks rules; mocking the vault store could falsely pass without persistence or validation.
test('trusted restore saves a decryptable web-wallet vault', async t => {
  const { client, values } = await setup(t), bytes = [...new TextEncoder().encode(phrase)];
  await assert.rejects(client.request('createNewVaultAndRestore', ['short', bytes]));
  await client.request('createNewVaultAndRestore', [password, bytes]);
  assert.equal((await decryptVault(values[VAULT_KEY], password)).phrase, phrase);
  assert.equal((await client.request('getState')).isInitialized, true);
  await assert.rejects(client.request('submitPasswordOrEncryptionKey', [{ password: 'wrong-public-password' }]), /password|unlock/i);
  assert.equal((await client.request('getState')).isUnlocked, false);
});

// Proves UI-selected accounts/networks grant an actual site request and revocation follows the site handler; approving the controller directly would bypass both UI and port wiring.
test('connect approval grants selected accounts and networks, then revoke removes the site', async t => {
  const { background, client } = await setup(t), ui = createWalletUi(client);
  background.permissions.setAccounts([account]);
  const { engine } = background.engine.setupProviderEngineEip1193({ origin: 'https://site.example', subjectType: 'website' }); t.after(() => engine.destroy());
  const connecting = engine.handle({ id: 1, jsonrpc: '2.0', method: 'eth_requestAccounts' });
  const pending = await until(() => Object.values(background.approvals.controller.state.pendingApprovals)[0]);
  await ui.approveConnect(pending, [account], ['0x1', '0x38']);
  assert.deepEqual((await connecting).result, [account]);
  const grant = background.permissions.controller.getCaveat('https://site.example', Caip25EndowmentPermissionName, 'authorizedScopes').value;
  assert.deepEqual(getEthAccounts(grant), [account]); assert.deepEqual(getPermittedEthChainIds(grant), ['0x1', '0x38']);
  await ui.revoke('https://site.example');
  assert.deepEqual(background.permissions.getAccounts('https://site.example'), []);
  assert.equal(Object.hasOwn((await client.request('getState')).subjects, 'https://site.example'), false);
});

// Proves rejection reaches the pending permission and returns code 4001 to the site; a UI-only cancelled flag would falsely pass.
test('connect rejection returns 4001 through the real site engine', async t => {
  const { background, client } = await setup(t), ui = createWalletUi(client);
  background.permissions.setAccounts([account]);
  const { engine } = background.engine.setupProviderEngineEip1193({ origin: 'https://rejected.example', subjectType: 'website' }); t.after(() => engine.destroy());
  const connecting = engine.handle({ id: 1, jsonrpc: '2.0', method: 'eth_requestAccounts' });
  const pending = await until(() => Object.values(background.approvals.controller.state.pendingApprovals)[0]);
  await ui.rejectConnect(pending); assert.equal((await connecting).error.code, 4001);
  assert.deepEqual(background.permissions.getAccounts(pending.origin), []);
});

// Proves every auto-lock choice persists in background storage and survives restart; inspecting the select value alone would falsely pass.
test('auto-lock choice persists and background alarm follows never', async t => {
  const { client, values, scheduled, fixture } = await setup(t), ui = createWalletUi(client);
  for (const minutes of [5, 10, 15, 30, 60, 0]) { await ui.setAutoLock(minutes); assert.equal(values[AUTO_LOCK_KEY], String(minutes)); }
  assert.equal(scheduled.size, 0); await assert.rejects(ui.setAutoLock(7));
  const restarted = await backgroundModule.createBackground({ ...fixture, runtime: { ...fixture.runtime, onConnect: event() } });
  try { assert.equal(restarted.autoLockAlarm.minutes, 0); } finally { await restarted.destroy(); }
});

// Proves phrase export authenticates even while unlocked and refuses export after lock; omitting the wrong-password path could hide a cached-phrase leak.
test('reveal phrase requires password re-entry at the background', async t => {
  const { background, client } = await setup(t), ui = createWalletUi(client);
  await background.vaultStore.create(password, phrase);
  await background.lockCoordinator.unlock(async () => {}); // No key derivation: this fixture isolates password authentication.
  await assert.rejects(ui.revealPhrase('incorrect-public-password'));
  assert.equal(await ui.revealPhrase(password), phrase);
  await background.lock(); await assert.rejects(ui.revealPhrase(password), /locked/i);
});

// Proves all three document activity sources hit the real alarm API and disposal removes them; directly calling setLastActiveTime would miss event wiring.
test('pointer, key and input events report trusted activity', async t => {
  const { client, fixture } = await setup(t), document = new EventTarget(), creates = [];
  t.mock.method(fixture.alarms, 'create', async (...args) => { creates.push(args); });
  const unbind = bindActivity(document, client);
  for (const type of ['pointerdown', 'keydown', 'input']) { document.dispatchEvent(new Event(type)); await until(() => creates.length > 0); creates.pop(); }
  unbind(); document.dispatchEvent(new Event('input')); await new Promise(resolve => setImmediate(resolve)); assert.equal(creates.length, 0);
});

// Proves unsupported permission shapes cannot be accidentally approved; using only the normal EVM caveat would miss unknown permission escalation.
test('connect details refuse approvals outside the current permission shape', () => {
  assert.throws(() => connectDetails({ requestData: { permissions: { unexpected: {} } } }), /unsupported/i);
});

// Proves initial UI state reflects storage, preferences and the public account; a fixed initialized flag or private-state spread could falsely pass narrower checks.
test('trusted UI state exposes initialization and public data without recovery material', async t => {
  const { background, client } = await setup(t);
  let state = await client.request('getState');
  assert.equal(state.isInitialized, false); assert.equal(state.isUnlocked, false);
  assert.deepEqual(state.addresses, {}); assert.deepEqual(state.accounts, []);
  assert.equal(state.preferences.autoLockTimeLimit, 15);
  await background.vaultStore.create(password, phrase);
  background.permissions.setAccounts([account]);
  state = await client.request('getState');
  assert.equal(state.isInitialized, true); assert.deepEqual(state.accounts, [account]);
  assert.ok(!JSON.stringify(state).includes(phrase)); assert.ok(!JSON.stringify(state).includes(password));
  await assert.rejects(client.request('setPreference', ['unknownPreference', true]));
});

// Proves lock invalidates password authentication already waiting on storage; only checking an export started after lock would miss a late phrase response.
test('phrase export cannot finish across a background lock', async t => {
  const { background, client, fixture } = await setup(t), originalGet = fixture.storage.get.bind(fixture.storage);
  await background.vaultStore.create(password, phrase);
  await background.lockCoordinator.unlock(async () => {});
  let readStarted, releaseRead;
  const started = new Promise(resolve => { readStarted = resolve; });
  const gate = new Promise(resolve => { releaseRead = resolve; });
  t.mock.method(fixture.storage, 'get', async key => { if (key === VAULT_KEY) { readStarted(); await gate; } return originalGet(key); });
  const exporting = client.request('getSeedPhrase', [password]);
  const rejected = assert.rejects(exporting, /locked/i);
  await started; await background.lock(); releaseRead(); await rejected;
});

// Proves the reference messenger notification reaches an already connected page; reading the controller directly would miss the trusted stream notification branch.
test('trusted pages receive live approval state notifications', async t => {
  const { background, client } = await setup(t), notifications = [];
  const unsubscribe = client.onNotification(message => notifications.push(message));
  await client.request('messengerSubscribe', ['ApprovalController:stateChange']);
  background.permissions.setAccounts([account]);
  const { engine } = background.engine.setupProviderEngineEip1193({ origin: 'https://live.example', subjectType: 'website' }); t.after(() => engine.destroy());
  const connecting = engine.handle({ id: 1, jsonrpc: '2.0', method: 'eth_requestAccounts' });
  await until(() => notifications.some(message => message.method === 'messengerSubscription' && message.params[0] === 'ApprovalController:stateChange'));
  const pending = Object.values((await client.request('getState')).pendingApprovals)[0];
  await client.request('rejectPermissionsRequest', [pending.id]); assert.equal((await connecting).error.code, 4001);
  await client.request('messengerUnsubscribe', ['ApprovalController:stateChange']); unsubscribe();
});

// Proves each page loads exactly one reference-screen entry for index.html:18-77;
// scanning only one page could miss a notification page still loading the old adapter.
test('popup, notification and fullscreen pages wire the shared web-wallet screen', () => {
  for (const page of ['popup.html', 'notification.html', 'home.html']) {
    const html = readFileSync(new URL(`../${page}`, import.meta.url), 'utf8');
    assert.match(html, /lang="en"/);
    assert.deepEqual([...html.matchAll(/<script\b[^>]*\bsrc="([^"]+)"/gu)].map(match => match[1]), ['./src/ui/reference-entry.js']);
    assert.doesNotMatch(html, /metamask|src\/main\.js/i);
  }
  const manifest = JSON.parse(readFileSync(new URL('../manifest.json', import.meta.url), 'utf8')); assert.equal(manifest.action.default_popup, 'popup.html');
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { Caip25EndowmentPermissionName, setEthAccounts } from '@metamask/chain-agnostic-permission';
import { SITES_KEY, parseSites, serializeSites, sitesKeyFor } from '../../src/activity-storage.js';
import { STATE_KEY } from '../src/background/store.js';
import { REVOKED_KEY } from '../src/background/connected-sites.js';
import { PROVIDER_METHODS } from '../src/constants/stream.js';

// Proves the connected-websites list is sealed at rest (docs/plans/decisions/2026-11-03-chrome-web-store.md:13,15;
// plan docs/plans/2026-11-03-chrome-web-store-plan.md section 2.6): it is written only as an AES-256-GCM record under
// nodus.sites.v1, no origin appears in any plain stored value, lock empties it, unlock restores it without a new
// approval, an old plain list is dropped (no migration, same record line 18), a record that fails to open is
// reported and left as it is, and a website's own wallet_revokePermissions sent while locked is applied at the next
// unlock (operator 2026-11-04: "Hatırlansın, kilit açılınca uygulansın"), also after a service worker restart.
// Needs: Node >=22.14 and the committed CPUNK WASM. No flags, network or disk output; the browser APIs are in-memory
// fakes with the real background, engine, permission controller and AES-GCM.
// Leaves: nothing. Falsely passes: the fake storage persists whatever it is given, so it cannot show a write lost to a
// real browser quota; the checks read the fake's contents, not chrome.storage.local or chrome.storage.session; the
// worker restart is a second background over the same fake storage, not a real browser restart.
const phrase = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';
const password = 'public-test-password-123';
const cpunkWasmBytes = readFileSync(new URL('../../src/cpunk/legacy-dilithium.wasm', import.meta.url));
const account = '0xf278cf59f82edcf871d630f28ecc8056f25c1cdb';
const origin = 'https://site.example';
function event() {
  const listeners = new Set();
  return { listeners, addListener(fn) { listeners.add(fn); }, removeListener(fn) { listeners.delete(fn); }, emit(...args) { return [...listeners].map(fn => fn(...args)); } };
}
function browserFixture(initial = {}, session = {}) {
  const values = structuredClone(initial), writes = [];
  return { values, writes, session, consumeNodusSeed: () => {},
    // chrome.storage.session: kept by the browser across service worker restarts, not written to disk.
    sessionStorage: { async get(key) { return { [key]: structuredClone(session[key]) }; },
      async set(items) { Object.assign(session, structuredClone(items)); },
      async remove(key) { delete session[key]; } },
    runtime: { id: 'test-extension', onConnect: event(), getManifest: () => ({ version: '0.1.132' }), getURL: path => `chrome-extension://test-extension/${path}` },
    storage: { async get(key) { return key === null ? structuredClone(values) : { [key]: structuredClone(values[key]) }; },
      async set(items) { writes.push(structuredClone(items)); Object.assign(values, structuredClone(items)); },
      async remove(keys) { for (const key of Array.isArray(keys) ? keys : [keys]) delete values[key]; } },
    alarms: { onAlarm: event(), async clear() {}, async create() {} },
    windows: { onRemoved: event(), async getAll() { return []; }, async getLastFocused() { return { top: 0, left: 0, width: 1000 }; },
      async create(options) { return { ...options, id: 1 }; }, async update() {} },
    tabs: { async query() { return []; } } };
}
let backgroundModule;
async function setup(t, initial, session) {
  const fixture = browserFixture(initial, session);
  if (!backgroundModule) {
    const saved = Object.getOwnPropertyDescriptor(globalThis, 'chrome');
    globalThis.chrome = { runtime: fixture.runtime, storage: { local: fixture.storage }, alarms: fixture.alarms, windows: fixture.windows };
    try { backgroundModule = await import('../src/background/index.js'); await (await backgroundModule.background).destroy(); }
    finally { if (saved) Object.defineProperty(globalThis, 'chrome', saved); else delete globalThis.chrome; }
  }
  const background = await backgroundModule.createBackground(fixture);
  await background.privacyConsent.accept();
  t.after(async () => { await background.lockCoordinator.lock(); await background.destroy(); });
  return { ...fixture, background };
}
function port(runtime, url = `${origin}/frame`) {
  const result = { name: 'nodus-contentscript', sender: { id: runtime.id, url, frameId: 2, tab: { id: 8, url: 'https://top.example/' } },
    messages: [], onMessage: event(), onDisconnect: event(), disconnected: false,
    postMessage(message) { this.messages.push(structuredClone(message)); },
    disconnect() { if (!this.disconnected) { this.disconnected = true; this.onDisconnect.emit(this); } } };
  runtime.onConnect.emit(result); return result;
}
async function until(predicate) {
  for (let turn = 0; turn < 80; turn++) { const result = predicate(); if (result) return result; await new Promise(resolve => setImmediate(resolve)); }
  assert.fail('Expected asynchronous browser event did not arrive');
}
let requestId = 0;
function request(remote, method, params = []) {
  const id = ++requestId;
  remote.onMessage.emit({ name: 'nodus-provider', data: { id, jsonrpc: '2.0', method, params } });
  return until(() => remote.messages.find(message => message.name === 'nodus-provider' && message.data.id === id)?.data);
}
async function connectSite(background, remote) {
  const connecting = request(remote, 'eth_requestAccounts');
  const pending = await until(() => Object.values(background.approvals.controller.state.pendingApprovals)[0]);
  const approved = structuredClone(pending.requestData), permission = approved.permissions[Caip25EndowmentPermissionName];
  permission.caveats[0].value = setEthAccounts(permission.caveats[0].value, [account]);
  await background.permissions.acceptPermissionsRequest(approved);
  assert.deepEqual((await connecting).result, [account]);
  await background.connectedSites.flush();
}
async function startWallet(background) {
  await background.vaultStore.create(password, phrase);
  return background.unlock(password, { cpunkWasmBytes });
}

test('a grant while unlocked is written only as the sealed record and no origin is stored in plain', async t => {
  const { background, runtime, values } = await setup(t), unlocked = await startWallet(background), remote = port(runtime);
  assert.equal(values[SITES_KEY], undefined);
  await connectSite(background, remote);
  assert.equal(typeof values[SITES_KEY], 'string');
  // Every stored value, including the plain controller state, is searched for the origin and the host name.
  for (const [key, value] of Object.entries(values)) {
    assert.equal(JSON.stringify(value).includes('site.example'), false, `${key} must not hold the origin`);
  }
  assert.equal(JSON.stringify(values[STATE_KEY]).includes('PermissionController'), false);
  const subjects = await parseSites(values[SITES_KEY], unlocked.id, await sitesKeyFor(phrase, unlocked.id));
  assert.deepEqual(Object.keys(subjects), [origin]);
  remote.disconnect();
});

test('lock empties the list; an account request is answered empty while locked and again after unlock without a new approval', async t => {
  const { background, runtime, values } = await setup(t), remote = port(runtime);
  await startWallet(background); await connectSite(background, remote);
  const sealed = values[SITES_KEY];
  await background.lock();
  assert.deepEqual(background.permissions.controller.getSubjectNames(), []);
  assert.deepEqual((await request(remote, 'eth_accounts')).result, []);
  assert.equal(values[SITES_KEY], sealed, 'locking does not rewrite or empty the stored record');
  await background.unlock(password, { cpunkWasmBytes });
  assert.deepEqual(background.permissions.controller.getSubjectNames(), [origin]);
  assert.deepEqual((await request(remote, 'eth_accounts')).result, [account]);
  assert.deepEqual(Object.values(background.approvals.controller.state.pendingApprovals), [], 'no second approval');
  remote.disconnect();
});

test('revoking a site rewrites the sealed record without it', async t => {
  const { background, runtime, values } = await setup(t), unlocked = await startWallet(background), remote = port(runtime);
  await connectSite(background, remote);
  background.permissions.controller.revokePermissions({ [origin]: [Caip25EndowmentPermissionName] });
  await background.connectedSites.flush();
  assert.deepEqual(await parseSites(values[SITES_KEY], unlocked.id, await sitesKeyFor(phrase, unlocked.id)), {});
  remote.disconnect();
});

test('no migration: an old plain connected-sites list is dropped and never loaded', async t => {
  const plain = { [STATE_KEY]: { PermissionController: { subjects: { [origin]: { origin, permissions: {} } } }, ApprovalController: {} } };
  const { background, runtime, values } = await setup(t, plain);
  await background.store.flush();
  assert.equal(Object.hasOwn(values[STATE_KEY], 'PermissionController'), false, 'the plain state is rewritten without the controller');
  assert.deepEqual(background.permissions.controller.getSubjectNames(), []);
  const remote = port(runtime);
  assert.deepEqual((await request(remote, 'eth_accounts')).result, []);
  await startWallet(background);
  assert.deepEqual((await request(remote, 'eth_accounts')).result, []);
  assert.equal(values[SITES_KEY], undefined, 'unlock writes no record by itself');
  assert.equal(background.connectedSites.getError(), '');
  remote.disconnect();
});

test('a damaged record is reported, leaves the list empty, and is not overwritten', async t => {
  const { background, runtime, values } = await setup(t), remote = port(runtime);
  await startWallet(background); await connectSite(background, remote);
  const record = JSON.parse(values[SITES_KEY]);
  // Flip the first ciphertext character: always a different valid base64 string, so AES-GCM authentication fails.
  record.ciphertext = `${record.ciphertext[0] === 'A' ? 'B' : 'A'}${record.ciphertext.slice(1)}`;
  const damaged = JSON.stringify(record);
  values[SITES_KEY] = damaged;
  await background.lock();
  await background.unlock(password, { cpunkWasmBytes });
  assert.match(background.connectedSites.getError(), /Saved connected sites could not be read/);
  assert.deepEqual(background.permissions.controller.getSubjectNames(), []);
  const ui = { name: 'popup', sender: { id: runtime.id, url: `chrome-extension://${runtime.id}/popup.html` }, messages: [], onMessage: event(), onDisconnect: event(), disconnected: false,
    postMessage(message) { this.messages.push(structuredClone(message)); },
    disconnect() { if (!this.disconnected) { this.disconnected = true; this.onDisconnect.emit(this); } } };
  runtime.onConnect.emit(ui);
  const id = ++requestId;
  ui.onMessage.emit(`1|0|1${JSON.stringify({ name: 'controller', data: { id, jsonrpc: '2.0', method: 'getState', params: [] } })}`);
  const state = (await until(() => ui.messages.find(message => message.name === 'controller' && message.data.id === id)?.data)).result;
  // The trusted page's stream is closed before the test ends, as a real popup closing does.
  ui.disconnect();
  assert.match(state.connectedSitesError, /could not be read/);
  await connectSite(background, remote);
  assert.equal(values[SITES_KEY], damaged, 'a record that did not open is left as it is');
  remote.disconnect();
});

// Plan section 2.6: a record that fails to open, also one sealed for another vault id, is not overwritten silently;
// a restore (which replaces the wallet and clears its permissions) removes the replaced wallet's record.
test('a record of another wallet is reported and left as it is', async t => {
  const { background, runtime, values } = await setup(t), remote = port(runtime);
  const otherId = Buffer.alloc(16, 7).toString('base64');
  const other = await serializeSites(otherId, {}, await sitesKeyFor(phrase, otherId));
  values[SITES_KEY] = other;
  await startWallet(background);
  assert.match(background.connectedSites.getError(), /Saved connected sites could not be read/);
  await connectSite(background, remote);
  assert.equal(values[SITES_KEY], other, 'a record that did not open is left as it is');
  remote.disconnect();
});

test('a restore removes the replaced wallet\'s record', { timeout: 60000 }, async t => {
  const { background, runtime, values } = await setup(t), remote = port(runtime);
  await startWallet(background); await connectSite(background, remote);
  assert.equal(typeof values[SITES_KEY], 'string');
  const ui = { name: 'popup', sender: { id: runtime.id, url: `chrome-extension://${runtime.id}/popup.html` }, messages: [], onMessage: event(), onDisconnect: event(), disconnected: false,
    postMessage(message) { this.messages.push(structuredClone(message)); },
    disconnect() { if (!this.disconnected) { this.disconnected = true; this.onDisconnect.emit(this); } } };
  runtime.onConnect.emit(ui);
  const id = ++requestId, answered = () => ui.messages.find(message => message.name === 'controller' && message.data.id === id)?.data;
  ui.onMessage.emit(`1|0|1${JSON.stringify({ name: 'controller', data: { id, jsonrpc: '2.0', method: 'createNewVaultAndRestore', params: [password, [...new TextEncoder().encode(phrase)]] } })}`);
  // Vault creation derives its key with WebCrypto; wait for the answer itself, bounded by the test timeout.
  while (!answered()) await new Promise(resolve => setTimeout(resolve, 10));
  assert.equal(answered().error, undefined);
  ui.disconnect();
  assert.equal(Object.hasOwn(values, SITES_KEY), false, 'the replaced wallet\'s record is removed');
  remote.disconnect();
});

test('a website\'s revocation sent while locked is answered, remembered and applied at the next unlock', async t => {
  const { background, runtime, values, session } = await setup(t), unlocked = await startWallet(background), remote = port(runtime);
  await connectSite(background, remote);
  await background.lock();
  assert.equal((await request(remote, 'wallet_revokePermissions', [{ eth_accounts: {} }])).result, null);
  await background.connectedSites.flushRevoked();
  assert.equal(JSON.stringify(values).includes('site.example'), false, 'the remembered revocation is not stored in plain on disk');
  assert.deepEqual(Object.keys(session[REVOKED_KEY]), [origin]);
  const seen = remote.messages.length;
  await background.unlock(password, { cpunkWasmBytes });
  assert.deepEqual(background.permissions.controller.getSubjectNames(), []);
  assert.deepEqual((await request(remote, 'eth_accounts')).result, []);
  const notices = remote.messages.slice(seen).filter(message => message.data?.method === PROVIDER_METHODS.accountsChanged);
  assert.deepEqual(notices, [], 'the site is not given the address back at unlock');
  await background.connectedSites.flush(); await background.connectedSites.flushRevoked();
  assert.deepEqual(await parseSites(values[SITES_KEY], unlocked.id, await sitesKeyFor(phrase, unlocked.id)), {});
  assert.equal(Object.hasOwn(session, REVOKED_KEY), false, 'an applied revocation is forgotten');
  remote.disconnect();
});

test('a revocation remembered while locked survives a service worker restart', async t => {
  const first = await setup(t), unlocked = await startWallet(first.background), remote = port(first.runtime);
  await connectSite(first.background, remote);
  await first.background.lock();
  assert.equal((await request(remote, 'wallet_revokePermissions', [{ eth_accounts: {} }])).result, null);
  await first.background.connectedSites.flushRevoked();
  remote.disconnect();
  const { background, values } = await setup(t, first.values, first.session);
  await background.unlock(password, { cpunkWasmBytes });
  assert.deepEqual(background.permissions.controller.getSubjectNames(), []);
  await background.connectedSites.flush();
  assert.deepEqual(await parseSites(values[SITES_KEY], unlocked.id, await sitesKeyFor(phrase, unlocked.id)), {});
});

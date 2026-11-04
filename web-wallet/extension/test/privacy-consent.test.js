import test from 'node:test';
import assert from 'node:assert/strict';
import { CONSENT_KEY, CONSENT_VERSION } from '../src/background/privacy-consent.js';

// Proves the data notice gate (docs/plans/decisions/2026-11-03-chrome-web-store.md:11; plan
// docs/plans/2026-11-03-chrome-web-store-plan.md section 2.7): on fresh storage, or storage holding an older text
// version, the trusted create, restore-and-unlock calls refuse, a website's chain request is refused with 4100 and
// reaches no server, eth_chainId is still answered, and the single accept call stores the current text version and
// opens every path. The interface side (screen shown, one button) is in ui-render.test.js.
// Needs: Node >=22.14. No flags, network or disk output: fetch is replaced by a recorder that must stay empty; the
// browser APIs are in-memory fakes with the real background and engine.
// Leaves: nothing. Falsely passes: a request refused for another reason also gives 4100, so each refusal is paired with
// the same request succeeding after accept(); the fake storage cannot show a quota failure.
const phrase = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';
const password = 'public-test-password-123';
function event() {
  const listeners = new Set();
  return { listeners, addListener(fn) { listeners.add(fn); }, removeListener(fn) { listeners.delete(fn); }, emit(...args) { return [...listeners].map(fn => fn(...args)); } };
}
function browserFixture(initial = {}) {
  const values = structuredClone(initial);
  return { values, consumeNodusSeed: () => {},
    runtime: { id: 'test-extension', onConnect: event(), getManifest: () => ({ version: '0.1.132' }), getURL: path => `chrome-extension://test-extension/${path}` },
    storage: { async get(key) { return key === null ? structuredClone(values) : { [key]: structuredClone(values[key]) }; },
      async set(items) { Object.assign(values, structuredClone(items)); },
      async remove(keys) { for (const key of Array.isArray(keys) ? keys : [keys]) delete values[key]; } },
    alarms: { onAlarm: event(), async clear() {}, async create() {} },
    windows: { onRemoved: event(), async getAll() { return []; }, async getLastFocused() { return { top: 0, left: 0, width: 1000 }; },
      async create(options) { return { ...options, id: 1 }; }, async update() {} },
    tabs: { async query() { return []; } } };
}
let backgroundModule;
async function setup(t, initial) {
  const fixture = browserFixture(initial), outside = [];
  t.mock.method(globalThis, 'fetch', async url => { outside.push(String(url)); throw new Error('Unexpected network request.'); });
  if (!backgroundModule) {
    const saved = Object.getOwnPropertyDescriptor(globalThis, 'chrome');
    globalThis.chrome = { runtime: fixture.runtime, storage: { local: fixture.storage }, alarms: fixture.alarms, windows: fixture.windows };
    try { backgroundModule = await import('../src/background/index.js'); await (await backgroundModule.background).destroy(); }
    finally { if (saved) Object.defineProperty(globalThis, 'chrome', saved); else delete globalThis.chrome; }
  }
  const background = await backgroundModule.createBackground(fixture);
  t.after(async () => { await background.lockCoordinator.lock(); await background.destroy(); });
  return { ...fixture, background, outside };
}
async function until(predicate) {
  for (let turn = 0; turn < 80; turn++) { const result = predicate(); if (result) return result; await new Promise(resolve => setImmediate(resolve)); }
  assert.fail('Expected asynchronous browser event did not arrive');
}
let requestId = 0;
function sitePort(runtime) {
  const result = { name: 'nodus-contentscript', sender: { id: runtime.id, url: 'https://site.example/frame', frameId: 2, tab: { id: 8, url: 'https://top.example/' } },
    messages: [], onMessage: event(), onDisconnect: event(), disconnected: false,
    postMessage(message) { this.messages.push(structuredClone(message)); },
    disconnect() { if (!this.disconnected) { this.disconnected = true; this.onDisconnect.emit(this); } } };
  runtime.onConnect.emit(result); return result;
}
function siteRequest(remote, method, params = []) {
  const id = ++requestId;
  remote.onMessage.emit({ name: 'nodus-provider', data: { id, jsonrpc: '2.0', method, params } });
  return until(() => remote.messages.find(message => message.name === 'nodus-provider' && message.data.id === id)?.data);
}
// The trusted page's answers are awaited by id, not by a number of event-loop turns: vault creation runs its key
// derivation off the event loop. A missing answer fails through the test's own timeout.
function trustedPort(runtime) {
  const waiting = new Map();
  const ui = { name: 'popup', sender: { id: runtime.id, url: `chrome-extension://${runtime.id}/popup.html` }, messages: [], onMessage: event(), onDisconnect: event(), disconnected: false,
    postMessage(message) {
      const copy = structuredClone(message); this.messages.push(copy);
      if (copy.name === 'controller' && waiting.has(copy.data?.id)) { waiting.get(copy.data.id)(copy.data); waiting.delete(copy.data.id); }
    },
    disconnect() { if (!this.disconnected) { this.disconnected = true; this.onDisconnect.emit(this); } },
    waiting };
  runtime.onConnect.emit(ui); return ui;
}
function trustedRequest(ui, method, params = []) {
  const id = ++requestId;
  const answer = new Promise(resolve => ui.waiting.set(id, resolve));
  ui.onMessage.emit(`1|0|1${JSON.stringify({ name: 'controller', data: { id, jsonrpc: '2.0', method, params } })}`);
  return answer;
}
const phraseBytes = () => [...new TextEncoder().encode(phrase)];

for (const [name, initial] of [['fresh storage', {}], ['an older text version', { [CONSENT_KEY]: '0' }]]) {
  test(`${name}: state reports no consent, trusted create and unlock refuse, websites are refused, eth_chainId answers`, { timeout: 60000 }, async t => {
    const { background, runtime, values, outside } = await setup(t, initial), ui = trustedPort(runtime), remote = sitePort(runtime);
    assert.equal((await trustedRequest(ui, 'getState')).result.privacyConsent, false);
    // Trusted calls: nothing is created, nothing is unlocked.
    assert.match((await trustedRequest(ui, 'createNewVaultAndRestore', [password, phraseBytes()])).error.message, /data notice/);
    assert.equal(Object.keys(values).some(key => key.startsWith('nodus.wallet.')), false, 'no vault was written');
    await background.vaultStore.create(password, phrase);
    assert.match((await trustedRequest(ui, 'submitPasswordOrEncryptionKey', [{ password }])).error.message, /data notice/);
    assert.equal(background.lockCoordinator.isLocked, true);
    // Websites: a request that would reach a server or return wallet data is refused; the local answer stays.
    assert.equal((await siteRequest(remote, 'eth_call', [{ to: `0x${'11'.repeat(20)}`, data: '0x' }, 'latest'])).error.code, 4100);
    assert.equal((await siteRequest(remote, 'eth_getBalance', [`0x${'11'.repeat(20)}`, 'latest'])).error.code, 4100);
    assert.equal((await siteRequest(remote, 'eth_accounts')).error.code, 4100);
    assert.equal((await siteRequest(remote, 'eth_chainId')).result, '0x1');
    assert.deepEqual(outside, [], 'no server was asked before the notice was agreed to');
    ui.disconnect(); remote.disconnect();
  });
}

test('agreeing stores the current text version and opens create, unlock and website requests', { timeout: 60000 }, async t => {
  const { runtime, values } = await setup(t), ui = trustedPort(runtime), remote = sitePort(runtime);
  assert.equal(CONSENT_VERSION, '1');
  assert.equal((await trustedRequest(ui, 'acceptPrivacyNotice')).error, undefined);
  assert.equal(values[CONSENT_KEY], CONSENT_VERSION);
  assert.equal((await trustedRequest(ui, 'getState')).result.privacyConsent, true);
  assert.equal((await siteRequest(remote, 'eth_accounts')).error, undefined);
  assert.deepEqual((await siteRequest(remote, 'eth_accounts')).result, []);
  assert.equal((await trustedRequest(ui, 'createNewVaultAndRestore', [password, phraseBytes()])).error, undefined);
  assert.equal(typeof values['nodus.wallet.v1'], 'string');
  ui.disconnect(); remote.disconnect();
});

test('the stored consent survives a restart of the background and is read again from storage', async t => {
  const first = await setup(t); await first.background.privacyConsent.accept();
  const restarted = await backgroundModule.createBackground({ ...browserFixture(), storage: first.storage });
  try { assert.equal(await restarted.privacyConsent.isGiven(), true); }
  finally { await restarted.destroy(); }
});

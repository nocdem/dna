import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { setImmediate as nextTurn } from 'node:timers/promises';
import messages from '../../node_modules/@metamask/providers/dist/messages.mjs';

// Pinned providers 22.1.1 message data: rename the brand and approved API identifier, preserving every reference link.
const renamed = message => message.replaceAll('MetaMask:', 'Nodus:').replace('The MetaMask Ethereum provider', 'The Nodus Ethereum provider').replace('ethereum._metamask', 'ethereum._nodus');

// Node 22, no flags; real provider/stream code, fake page and chrome ports; restores globals, writes no files.
class PageMessageEvent extends Event {
  constructor(data, source, origin) { super('message'); this.data = data; this.pageSource = source; this.pageOrigin = origin; }
  get source() { return this.pageSource; }
  get origin() { return this.pageOrigin; }
}
function signal() {
  const listeners = new Set();
  return { addListener: fn => listeners.add(fn), removeListener: fn => listeners.delete(fn), emit: (...args) => [...listeners].map(fn => fn(...args)) };
}
let fixtureId = 0;
async function fixture(t, withOtherWallet = false, defineDescriptor) {
  const saved = new Map(['window', 'document', 'location', 'MessageEvent', 'chrome', 'browser', 'define'].map(key => [key, Object.getOwnPropertyDescriptor(globalThis, key)]));
  if (defineDescriptor) Object.defineProperty(globalThis, 'define', { configurable: true, ...defineDescriptor });
  const page = new EventTarget();
  page.location = new URL('https://dapp.example/');
  page.document = { doctype: { name: 'html' }, documentElement: { nodeName: 'HTML' } };
  page.postMessage = (data, origin) => queueMicrotask(() => page.dispatchEvent(new PageMessageEvent(structuredClone(data), page, origin)));
  Object.assign(globalThis, { window: page, document: page.document, location: page.location, MessageEvent: PageMessageEvent });
  const announcements = [], caip = [], initialized = [];
  page.addEventListener('eip6963:announceProvider', event => announcements.push(event.detail));
  page.addEventListener('caip294:wallet_announce', event => caip.push(event.detail));
  page.addEventListener('ethereum#initialized', event => initialized.push(event));
  const other = { isMetaMask: true, request() { throw new Error('Wrong wallet received the request'); } };
  if (withOtherWallet) {
    page.ethereum = other;
    page.web3 = { currentProvider: other };
    page.addEventListener('eip6963:requestProvider', () => page.dispatchEvent(new CustomEvent('eip6963:announceProvider', { detail: { info: { name: 'MetaMask' }, provider: other } })));
  }
  const requests = [], pending = [];
  const port = { onMessage: signal(), onDisconnect: signal(), disconnect() { this.onDisconnect.emit(); }, postMessage(message) {
    requests.push(structuredClone(message));
    const request = message.data;
    if (request.method === 'nodus_getProviderState') queueMicrotask(() => this.onMessage.emit({ name: message.name, data: { id: request.id, jsonrpc: '2.0', result: { accounts: [], chainId: '0x1', networkVersion: '1', isConnected: true, extensionId: 'nodus-test-extension' } } }));
    else pending.push(message);
  } };
  const runtime = { id: 'nodus-test-extension', connect: () => port, onMessage: signal() };
  globalThis.chrome = { runtime }; globalThis.browser = { runtime };
  const { default: browser } = await import('webextension-polyfill');
  browser.runtime = runtime;
  const { contentscript: bridge } = await import(`../src/contentscript.js?fixture=${++fixtureId}`);
  const { inpage: { provider, stream, mux } } = await import(`../src/inpage.js?fixture=${++fixtureId}`);
  t.after(async () => {
    // ObjectMultiplex.js:35-38,77-80 propagates an abrupt parent close to its children; complete both parents before removing bridge listeners.
    await Promise.all([bridge.pageMux, mux].map(parent => new Promise(resolve => parent.end(resolve))));
    await nextTurn();
    assert.equal(bridge.pageChannel.destroyed, true);
    bridge.destroyStreams(); bridge.pageStream.destroy(); bridge.pageMux.destroy();
    stream.destroy(); mux.destroy(); await nextTurn();
    for (const [key, descriptor] of saved) {
      if (descriptor) Object.defineProperty(globalThis, key, descriptor); else delete globalThis[key];
    }
  });
  // RPC stream middleware ends responses on a timer; await its observable initialization instead of a timed sleep.
  if (!provider._state.initialized) await new Promise(resolve => provider.once('_initialized', resolve));
  if (!caip.length) await new Promise(resolve => page.addEventListener('caip294:wallet_announce', resolve, { once: true }));
  return { page, provider, stream, mux, announcements, caip, initialized, requests, pending, port, other };
}

// Proves the actual announced provider, UUID and exact logo bytes survive re-announcement; testing exported constants alone would bypass initializeProvider.
test('EIP-6963 announces and re-announces Nodus with the existing logo', { timeout: 5000 }, async t => {
  const { page, provider, announcements, caip, initialized } = await fixture(t);
  assert.equal(announcements.length, 1);
  const { info } = announcements[0];
  assert.equal(info.name, 'Nodus Wallet'); assert.equal(info.rdns, 'io.nodusnetwork.wallet');
  assert.match(info.uuid, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
  assert.equal(decodeURIComponent(info.icon.slice('data:image/svg+xml,'.length)), await readFile(new URL('../../public/assets/nodus-mark.svg', import.meta.url), 'utf8'));
  assert.equal(announcements[0].provider, provider); assert.ok(Object.isFrozen(announcements[0]));
  assert.equal(page.ethereum, provider); assert.equal(initialized.length, 1);
  page.dispatchEvent(new Event('eip6963:requestProvider'));
  assert.equal(announcements.length, 2); assert.deepEqual(announcements[1].info, info);
  assert.deepEqual(caip[0].params.targets, []);
  page.dispatchEvent(new CustomEvent('caip294:wallet_prompt', { detail: { method: 'wallet_prompt', params: {} } }));
  assert.equal(caip.length, 2); assert.equal(caip[1].params.uuid, info.uuid);
});

// Proves context cleanup/restoration and forwarding to the reference loglevel logger; checking only the final define value would miss omitted cleanup.
test('inpage restores the import context and uses the reference logger', { timeout: 5000 }, async t => {
  const define = () => {};
  let current = define;
  const writes = [];
  const { provider } = await fixture(t, false, { get: () => current, set: value => { writes.push(value); current = value; } });
  const { default: log } = await import('loglevel');
  assert.deepEqual(writes, [undefined, define]);
  assert.equal(globalThis.define, define);
  assert.equal(provider._log.warn, log.warn);
  assert.equal(log.getLevel(), log.levels.WARN);
});

// Proves each warning retains the pinned message and links after renaming, once per warning; checking only the brand could accept shortened text.
test('provider warnings preserve the renamed reference messages and links', { timeout: 5000 }, async t => {
  const { provider, pending, port } = await fixture(t);
  const { default: log } = await import('loglevel');
  const warnings = [];
  t.mock.method(log, 'warn', (...args) => warnings.push(args));
  for (const event of Object.keys(messages.warnings.events)) {
    provider.on(event, () => {}); provider.on(event, () => {});
  }
  for (let i = 0; i < 2; i++) {
    const enabled = provider.enable();
    await nextTurn();
    port.onMessage.emit({ name: 'nodus-provider', data: { id: pending.at(-1).data.id, jsonrpc: '2.0', result: [] } });
    await enabled;
    provider.send({ method: 'eth_accounts' });
    assert.equal(await provider._nodus.isUnlocked(), true);
  }
  assert.deepEqual(warnings, [
    ...Object.values(messages.warnings.events),
    messages.warnings.enableDeprecation, messages.warnings.sendDeprecation,
    messages.warnings.experimentalMethods,
  ].map(message => [renamed(message)]));
  assert.throws(() => provider.send({ method: 'eth_unsupportedFixture' }), { message: renamed(messages.errors.unsupportedSync('eth_unsupportedFixture')) });
});

// Proves the inherited logger renames messages while retaining reference parameters and error identity; mocking provider._log would bypass the supplied logger adapter.
test('inherited provider logs and initial-state failures preserve their arguments', { timeout: 5000 }, async t => {
  const { provider } = await fixture(t);
  const { default: log } = await import('loglevel');
  const { BaseProvider } = await import('@metamask/providers');
  const errors = [], debug = [];
  t.mock.method(log, 'error', (...args) => errors.push(args));
  t.mock.method(log, 'debug', (...args) => debug.push(args));
  provider._state.isConnected = false;
  provider._handleConnect({ chainId: '0x38', isConnected: true });
  assert.deepEqual(debug, [[renamed(messages.info.connected('0x38'))]]);
  BaseProvider.prototype._handleChainChanged.call(provider, { chainId: 'invalid' });
  provider._handleChainChanged({ chainId: '0x1', networkVersion: 'invalid', isConnected: true });
  provider._handleAccountsChanged('invalid');
  const invalidAccounts = [123], changedAccounts = ['0x1234'];
  provider._handleAccountsChanged(invalidAccounts);
  provider._handleAccountsChanged(changedAccounts, true);
  const failure = new Error('Initial state fixture failure');
  const requestMock = t.mock.method(provider, 'request', async () => { throw failure; });
  const initializeMock = t.mock.method(provider, '_initializeState', state => assert.equal(state, undefined));
  await provider._initializeStateAsync();
  requestMock.mock.restore(); initializeMock.mock.restore();
  assert.deepEqual(errors, [
    [renamed(messages.errors.invalidNetworkParams()), { chainId: 'invalid' }],
    [renamed(messages.errors.invalidNetworkParams()), { chainId: '0x1', networkVersion: 'invalid' }],
    ['Nodus: Received invalid accounts parameter. Please report this bug.', 'invalid'],
    ['Nodus: Received non-string account. Please report this bug.', invalidAccounts],
    ["Nodus: 'eth_accounts' unexpectedly updated accounts. Please report this bug.", changedAccounts],
    ['Nodus: Failed to get initial state. Please report this bug.', failure],
  ]);
  assert.equal(errors[3][1], invalidAccounts); assert.equal(errors[4][1], changedAccounts); assert.equal(errors[5][1], failure);
  let disconnected;
  provider.once('disconnect', error => { disconnected = error; });
  provider._handleDisconnect(false);
  assert.equal(errors.at(-1)[0], disconnected);
});

// Proves web3 shim diagnostics retain reference links; checking just currentProvider would miss the missing-property/setter paths.
test('web3 shim logs preserve reference details', { timeout: 5000 }, async t => {
  const { page, provider } = await fixture(t);
  const { default: log } = await import('loglevel');
  const warnings = [], errors = [];
  t.mock.method(log, 'warn', (...args) => warnings.push(args));
  t.mock.method(log, 'error', (...args) => errors.push(args));
  assert.equal(page.web3.currentProvider, provider);
  assert.equal(page.web3.currentProvider, provider);
  assert.deepEqual(warnings, [['You are accessing the Nodus window.web3.currentProvider shim. This property is deprecated; use window.ethereum instead. For details, see: https://docs.metamask.io/guide/provider-migration.html#replacing-window-web3']]);
  assert.equal(page.web3.eth, undefined); assert.equal(page.web3.eth, undefined);
  assert.deepEqual(errors, [['Nodus no longer injects web3. For details, see: https://docs.metamask.io/guide/provider-migration.html#replacing-window-web3']]);
  page.web3.fixtureProperty = true;
  assert.deepEqual(warnings.at(-1), ['You are accessing the Nodus window.web3 shim. This object is deprecated; use window.ethereum instead. For details, see: https://docs.metamask.io/guide/provider-migration.html#replacing-window-web3']);
});

// Proves chain loss emits the exact renamed recoverable error to page listeners; checking prototype keys alone misses inherited message defaults.
test('page-visible recoverable disconnect errors use Nodus text', { timeout: 5000 }, async t => {
  const { provider, port } = await fixture(t);
  const disconnected = new Promise(resolve => provider.once('disconnect', resolve));
  port.onMessage.emit({ name: 'nodus-provider', data: { method: 'nodus_chainChanged', params: { chainId: '0x1', networkVersion: '1', isConnected: false } } });
  const error = await disconnected;
  assert.equal(error.code, 1013);
  assert.equal(error.message, 'Nodus: Disconnected from chain. Attempting to connect.');
  assert.doesNotMatch(error.message, /MetaMask/iu);
});

// Proves the stream disconnect callback without a supplied error uses the renamed permanent fallback; an explicit fixture message could conceal BaseProvider's default text.
test('page-visible permanent disconnect defaults use Nodus text', { timeout: 5000 }, async t => {
  const { provider } = await fixture(t);
  const disconnected = new Promise(resolve => provider.once('disconnect', resolve));
  provider._handleStreamDisconnect('Nodus RpcProvider');
  const error = await disconnected;
  assert.equal(error.code, 1011);
  assert.equal(error.message, 'Nodus: Disconnected from Nodus background. Page reload required.');
  assert.doesNotMatch(error.message, /MetaMask/iu);
});

// Proves the renamed stream-failure notification supplies the reference permanent message; testing only default arguments would miss the explicit error path.
test('page-visible stream-failure errors use the renamed reference message', { timeout: 5000 }, async t => {
  const { provider, port } = await fixture(t);
  const disconnected = new Promise(resolve => provider.once('disconnect', resolve));
  port.onMessage.emit({ name: 'nodus-provider', data: { method: 'NODUS_STREAM_FAILURE' } });
  const error = await disconnected;
  assert.equal(error.code, 1011);
  assert.equal(error.message, 'Nodus: Disconnected from Nodus background. Page reload required.');
  assert.doesNotMatch(error.message, /MetaMask/iu);
});

// Proves the exposed provider/shim and every transmitted method lack old identifiers; checking enumerable properties alone would miss prototype names.
test('the Nodus provider exposes renamed identifiers on the page and wire', { timeout: 5000 }, async t => {
  const { page, provider, requests, port } = await fixture(t);
  const { PROVIDER_METHODS } = await import('../src/constants/stream.js');
  assert.equal(Object.hasOwn(PROVIDER_METHODS, 'sendDomainMetadata'), false);
  for (let object = provider; object; object = Object.getPrototypeOf(object)) {
    assert.ok(Reflect.ownKeys(object).every(key => typeof key !== 'string' || !/metamask/iu.test(key)));
  }
  assert.equal(provider.isNodus, true); assert.equal(provider.isMetaMask, undefined); assert.equal(provider._metamask, undefined);
  assert.equal(typeof provider._nodus.isUnlocked, 'function');
  assert.equal(page.web3.currentProvider, provider); assert.equal(page.web3.__isNodusShim__, true);
  assert.equal(page.web3.__isMetaMaskShim__, undefined);
  assert.ok(requests.length >= 2);
  assert.ok(requests.every(message => message.name === 'nodus-provider' && !/metamask/iu.test(message.data.method)));
  const changed = new Promise(resolve => provider.once('accountsChanged', resolve));
  port.onMessage.emit({ name: 'nodus-provider', data: { method: 'nodus_accountsChanged', params: ['0x1234'] } });
  assert.deepEqual(await changed, ['0x1234']);
  const chainChanged = new Promise(resolve => provider.once('chainChanged', resolve));
  port.onMessage.emit({ name: 'nodus-provider', data: { method: 'nodus_chainChanged', params: { chainId: '0x38', networkVersion: '56', isConnected: true } } });
  assert.equal(await chainChanged, '0x38'); assert.equal(provider.networkVersion, '56');
});

// Proves a page connect request remains pending until the fake approval responds, with/without a second wallet; a canned request mock would skip the actual bridge.
test('connect traverses the Nodus stream and waits for a background approval fixture', { timeout: 5000 }, async t => {
  for (const otherInstalled of [false, true]) {
    // Proves each discovery environment independently; running only the already-selected wallet could conceal namespace collisions.
    await t.test(`other wallet ${otherInstalled ? 'present' : 'absent'}`, async t => {
      const { page, provider, pending, port, other, announcements } = await fixture(t, otherInstalled);
      let settled = false;
      const connecting = provider.request({ method: 'eth_requestAccounts' }).finally(() => { settled = true; });
      await nextTurn();
      assert.equal(settled, false); assert.equal(pending.length, 1);
      assert.equal(pending[0].name, 'nodus-provider'); assert.equal(pending[0].data.method, 'eth_requestAccounts');
      const accounts = ['0x1234'];
      port.onMessage.emit({ name: 'nodus-provider', data: { id: pending[0].data.id, jsonrpc: '2.0', result: accounts } });
      assert.deepEqual(await connecting, accounts); assert.equal(provider.selectedAddress, accounts[0]);
      page.dispatchEvent(new Event('eip6963:requestProvider'));
      assert.ok(announcements.some(detail => detail.provider === provider));
      if (otherInstalled) {
        assert.ok(announcements.some(detail => detail.provider === other));
        assert.equal(page.web3.currentProvider, other);
      }
    });
  }
});

// Proves a rejected connect reaches the caller as 4001 and logs its message/error object; checking only the error code could miss shortened diagnostics.
test('connect rejection survives the page and runtime streams', { timeout: 5000 }, async t => {
  const { provider, pending, port } = await fixture(t);
  const { default: log } = await import('loglevel');
  const warnings = [];
  t.mock.method(log, 'warn', (...args) => warnings.push(args));
  const connecting = provider.request({ method: 'eth_requestAccounts' });
  let rejection;
  const rejected = assert.rejects(connecting, error => { rejection = error; return error.code === 4001; });
  await nextTurn();
  port.onMessage.emit({ name: 'nodus-provider', data: { id: pending[0].data.id, jsonrpc: '2.0', error: { code: 4001, message: 'User rejected the request.' } } });
  await rejected;
  assert.deepEqual(warnings, [[`Nodus - RPC Error: ${rejection.message}`, rejection]]);
});

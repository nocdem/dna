import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { Duplex } from 'readable-stream';
import { createNodusClient } from '../../src/nodus/client.js';
import { NODUS_PERMISSION } from '../src/background/permissions.js';
import { createWalletUi } from '../src/ui/wallet-ui.js';
import { mountWalletPage } from '../src/ui/app.js';
import log from 'loglevel';

// Node >=22.14, installed pinned packages and committed derivation WASM.
// In-memory storage/module/window fixtures; no network or output artifacts.
// The fake signature proves routing/custody boundaries, not crypto validity
// (native/WASM parity and test_sign_domain_separation cover that separately).
const { phrase, address } = JSON.parse(readFileSync(new URL('../../test/fixtures/nodus-addresses.json', import.meta.url))).vectors[0];
const publicKey = '12'.repeat(2592), signature = '34'.repeat(4627), password = 'public-test-password-123';
const options = { nodusWasmBytes: readFileSync(new URL('../../src/nodus/mldsa87.wasm', import.meta.url)),
  cpunkWasmBytes: readFileSync(new URL('../../src/cpunk/legacy-dilithium.wasm', import.meta.url)) };
const account = { address, publicKey: `0x${publicKey}` };
function event() { const listeners = new Set(); return { addListener(fn) { listeners.add(fn); }, removeListener(fn) { listeners.delete(fn); } }; }
function deferred() { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; }
let backgroundModule, nextId = 0;
async function setup(t) {
  const values = {}, calls = [], logs = [], windows = [], state = {};
  const fixture = {
    runtime: { id: 'nodus-site-test', onConnect: event(), getManifest: () => ({ version: '0.1.132' }), getURL: path => `chrome-extension://nodus-site-test/${path}` },
    storage: { async get(keys) { return Object.fromEntries((Array.isArray(keys) ? keys : [keys]).map(key => [key, structuredClone(values[key])])); },
      async set(items) { Object.assign(values, structuredClone(items)); } },
    alarms: { onAlarm: event(), async clear() {}, async create() {} },
    windows: { onRemoved: event(), async getAll() { return []; }, async getLastFocused() { return { top: 0, left: 0, width: 1000 }; },
      async create(opts) { windows.push(opts); return { ...opts, id: 2 }; }, async update() {} },
    nodusOptions: { factory: async () => ({
      async unlock() { return { fingerprint: address, chainId: '56'.repeat(32), publicKey }; },
      async siteSignMessage({ origin, message }) { calls.push({ origin, message: [...message] }); if (state.wait) { state.entered.resolve(); await state.wait.promise; } return Uint8Array.from(Buffer.from(signature, 'hex')); },
      async balance() { if (state.balanceWait) { state.entered.resolve(); await state.balanceWait.promise; } return { total: '0', spendable: '0' }; },
      async list() { return { tip: '1', coins: [], truncated: false }; },
      async buildAndSign() {}, async submit() {}, async scanConfirm() {}, async tick() {},
      async rulesetInfo() { return { generation: '1', tip: '1', gen2Height: '0' }; },
      cancel() {}, lock() {}, release() {}, memory: { buffer: new ArrayBuffer(64) },
    }) },
  };
  t.mock.method(globalThis, 'fetch', async () => { throw new Error('Unexpected network request.'); });
  for (const method of ['info', 'debug', 'error']) t.mock.method(log, method, (...args) => logs.push(args));
  if (!backgroundModule) {
    globalThis.chrome = { ...fixture, storage: { local: fixture.storage } };
    try { backgroundModule = await import('../src/background/index.js'); await (await backgroundModule.background).destroy(); }
    finally { delete globalThis.chrome; }
  }
  const background = await backgroundModule.createBackground(fixture), engines = [];
  await background.vaultStore.create(password, phrase);
  await background.unlock(password, options);
  function site(origin = 'https://site.example') {
    const { engine } = background.engine.setupProviderEngineEip1193({ origin, subjectType: 'website' }); engines.push(engine);
    return { origin, request: (method, params = []) => engine.handle({ id: ++nextId, jsonrpc: '2.0', method, params, origin: 'https://forged.example' }) };
  }
  function senderSite(url) {
    const stream = new Duplex({ objectMode: true, read() {}, write(_message, _encoding, done) { done(); } });
    const { origin, engine } = background.engine.setupProviderConnectionEip1193(stream, { url }, 'website');
    return { origin, request: (method, params = []) => engine.handle({ id: ++nextId, jsonrpc: '2.0', method, params, origin: 'https://forged.example' }) };
  }
  async function nextApproval(request) {
    const { controller } = background.approvals, ready = deferred();
    const changed = state => { const pending = Object.values(state.pendingApprovals)[0]; if (pending) ready.resolve(pending); };
    controller.messenger.subscribe('ApprovalController:stateChange', changed); changed(controller.state);
    try { return await Promise.race([ready.promise, request.then(result => assert.fail(`Completed before approval: ${JSON.stringify(result)}`))]); }
    finally { controller.messenger.unsubscribe('ApprovalController:stateChange', changed); }
  }
  async function connect(remote) {
    const request = remote.request('nodus_requestAccounts'), pending = await nextApproval(request);
    await background.permissions.acceptPermissionsRequest(structuredClone(pending.requestData));
    assert.deepEqual((await request).result, [account]);
  }
  t.after(async () => { engines.forEach(engine => engine.destroy()); await background.destroy(); });
  return { background, site, senderSite, nextApproval, connect, calls, logs, windows, values, state };
}

// Decision 2026-10-28-extension-nodus-site-signing.md:20: disk pages cannot
// connect/sign. Fail on an unexpected permission request instead of waiting for UI.
test('file sender refuses both Nodus methods without permissions, approvals or module calls; eth_accounts is unchanged', async t => {
  const f = await setup(t), remote = f.senderSite('file:///x.html');
  assert.equal(remote.origin, 'null');
  const requestPermissions = t.mock.method(f.background.permissions.controller, 'requestPermissions', () => { throw new Error('Unexpected permission request.'); });
  const signMessage = t.mock.method(f.background.nodus, 'signMessage');
  for (const [method, params] of [['nodus_requestAccounts', []], ['nodus_signMessage', ['hello', address]]]) {
    assert.equal((await remote.request(method, params)).error?.code, 4100);
    assert.equal(requestPermissions.mock.callCount(), 0); assert.equal(signMessage.mock.callCount(), 0);
    assert.deepEqual(f.background.approvals.controller.state.pendingApprovals, {});
    await f.background.approvals.whenUiSettled();
    assert.deepEqual(f.windows, []); assert.deepEqual(f.calls, []);
  }
  const accounts = await remote.request('eth_accounts');
  assert.equal(accounts.error, undefined); assert.deepEqual(accounts.result, []);
});

// Exercise sender URL -> bound origin for the permitted HTTPS path as well.
test('https sender still connects and signs with its bound origin', async t => {
  const f = await setup(t), remote = f.senderSite('https://site.example/x.html');
  assert.equal(remote.origin, 'https://site.example');
  await f.connect(remote);
  const request = remote.request('nodus_signMessage', ['hello', address]), pending = await f.nextApproval(request);
  assert.equal(pending.origin, remote.origin); assert.deepEqual(f.calls, []);
  await f.background.approvals.controller.acceptRequest(pending.id, true);
  assert.equal((await request).result, `0x${signature}`);
  assert.deepEqual(f.calls, [{ origin: remote.origin, message: [104, 101, 108, 108, 111] }]);
});

test('Nodus connect uses permission approval, returns public identity, retains grants across lock and supports revocation', async t => {
  const f = await setup(t), remote = f.site();
  const request = remote.request('nodus_requestAccounts'), pending = await f.nextApproval(request);
  assert.equal(pending.origin, remote.origin); assert.ok(pending.requestData.permissions[NODUS_PERMISSION]);
  assert.deepEqual(f.calls, []);
  await f.background.permissions.acceptPermissionsRequest(structuredClone(pending.requestData));
  assert.deepEqual((await request).result, [account]);
  await f.background.approvals.whenUiSettled(); assert.match(f.windows[0].url, /notification\.html$/);
  assert.deepEqual((await remote.request('eth_accounts')).result, [], 'Nodus connection must not grant EVM accounts');
  await f.background.lock();
  assert.deepEqual((await remote.request('nodus_requestAccounts')).result, [account]);
  assert.match((await remote.request('nodus_signMessage', ['hello', address])).error.message, /locked/i);
  assert.equal((await remote.request('wallet_revokePermissions', [{ [NODUS_PERMISSION]: {} }])).result, null);
  assert.equal((await remote.request('nodus_signMessage', ['hello', address])).error.code, 4100);
});

test('new connection waits while locked, UI acceptance requires unlock, cancellation rejects without signing', async t => {
  const f = await setup(t), remote = f.site(); await f.background.lock();
  const request = remote.request('nodus_requestAccounts'), pending = await f.nextApproval(request);
  await assert.rejects(f.background.permissions.acceptPermissionsRequest(pending.requestData), /locked/i);
  f.background.permissions.controller.rejectPermissionsRequest(pending.id);
  assert.equal((await request).error.code, 4001); assert.deepEqual(f.calls, []);
});

test('signing requires origin/account permission and approval of the displayed message; bytes never enter logs', async t => {
  const f = await setup(t), remote = f.site();
  assert.equal((await remote.request('nodus_signMessage', ['hello', address])).error.code, 4100);
  await f.connect(remote);
  assert.equal((await f.site('https://other.example').request('nodus_signMessage', ['hello', address])).error.code, 4100);
  assert.equal((await remote.request('nodus_signMessage', ['hello', 'ab'.repeat(64)])).error.code, 4100);
  for (const params of [[], ['hello'], [7, address]]) assert.ok((await remote.request('nodus_signMessage', params)).error);
  assert.equal((await remote.request('nodus_signMessage', ['', address])).error.code, -32602);
  assert.deepEqual(f.background.approvals.controller.state.pendingApprovals, {});
  // SignatureController normalization falls back to UTF-8 for "0x";
  // personalSign's legacyToBuffer -> toBuffer left-pads odd hex nibbles.
  for (const [data, text, bytes, reversed] of [
    ['0x', '0x', [48, 120], false],
    ['0X', '0X', [48, 88], false],
    ['abc', '\n\ufffd', [10, 188], false],
    ['0xabc', '\n\ufffd', [10, 188], false],
    ['0Xabc', '\n\ufffd', [10, 188], false],
    ['0xF', '\u000f', [15], false],
    ['0x68656c6c6f', 'hello', [104, 101, 108, 108, 111], false],
    ['Sign in <script>secret</script>', 'Sign in <script>secret</script>', [...new TextEncoder().encode('Sign in <script>secret</script>')], true],
    ['0xff00', '\ufffd\u0000', [255, 0], false],
    ['0x' + '61'.repeat(32), '0x' + '61'.repeat(32), Array(32).fill(97), false],
    ['hello\u202e', 'hello\\u202E', [...new TextEncoder().encode('hello\u202e')], false],
    ['m'.repeat(23), 'm'.repeat(23), Array(23).fill(109), false],
    ['m'.repeat(55), 'm'.repeat(55), Array(55).fill(109), false],
  ]) {
    const before = f.calls.length, request = remote.request('nodus_signMessage', reversed ? [address, data] : [data, address]);
    const pending = await f.nextApproval(request);
    assert.equal(pending.type, 'nodus_signMessage'); assert.equal(pending.origin, remote.origin);
    assert.equal(pending.requestData.text, text); assert.equal(pending.requestData.account, address); assert.equal(f.calls.length, before);
    await f.background.approvals.controller.acceptRequest(pending.id, true);
    assert.equal((await request).result, `0x${signature}`);
    // Every request carries a forged req.origin in site(); only the bound
    // connection origin may reach the identity module.
    assert.deepEqual(f.calls.at(-1), { origin: remote.origin, message: bytes });
  }
  const request = remote.request('nodus_signMessage', ['reject me', address]), pending = await f.nextApproval(request), before = f.calls.length;
  f.background.approvals.reject(pending.id); assert.equal((await request).error.code, 4001); assert.equal(f.calls.length, before);
  assert.ok(!JSON.stringify(f.logs).includes('secret')); assert.ok(!JSON.stringify(f.logs).includes(signature));
});

// Decoded bytes, including UTF-8 multibyte text and hex input; no artifact
// output. An oversized call must finish before any approval can be created.
test('65536 decoded bytes reach approval; 65537 return invalid params without opening a window', async t => {
  const f = await setup(t), remote = f.site(); await f.connect(remote);
  for (const data of ['x'.repeat(65536), '0x' + 'ab'.repeat(65536), '\u00e9'.repeat(32768)]) {
    const request = remote.request('nodus_signMessage', [data, address]);
    const pending = await f.nextApproval(request);
    await f.background.approvals.controller.acceptRequest(pending.id, true);
    assert.equal((await request).result, `0x${signature}`);
    assert.equal(f.calls.at(-1).message.length, 65536);
    assert.equal(f.calls.at(-1).origin, remote.origin);
  }
  await f.background.approvals.whenUiSettled();
  const count = f.windows.length, calls = f.calls.length;
  for (const data of ['x'.repeat(65537), '0x' + 'ab'.repeat(65537), '\u00e9'.repeat(32768) + 'x']) {
    const result = await remote.request('nodus_signMessage', [data, address]);
    assert.equal(result.error.code, -32602);
    assert.deepEqual(f.background.approvals.controller.state.pendingApprovals, {});
    await f.background.approvals.whenUiSettled();
    assert.equal(f.windows.length, count); assert.equal(f.calls.length, calls);
  }
});

test('lock or permission revocation during approval prevents signing; late module completion after lock is rejected', async t => {
  const f = await setup(t), remote = f.site(); await f.connect(remote);
  let request = remote.request('nodus_signMessage', ['hello', address]), pending = await f.nextApproval(request);
  await f.background.lock(); await f.background.approvals.controller.acceptRequest(pending.id, true);
  assert.match((await request).error.message, /locked/i); assert.deepEqual(f.calls, []);
  await f.background.unlock(password, options);
  request = remote.request('nodus_signMessage', ['hello', address]); pending = await f.nextApproval(request);
  f.background.permissions.controller.revokePermissions({ [remote.origin]: [NODUS_PERMISSION] });
  await f.background.approvals.controller.acceptRequest(pending.id, true);
  assert.equal((await request).error.code, 4100); assert.deepEqual(f.calls, []);
  await f.connect(remote);
  f.state.wait = deferred(); f.state.entered = deferred();
  request = remote.request('nodus_signMessage', ['hello', address]); pending = await f.nextApproval(request);
  await f.background.approvals.controller.acceptRequest(pending.id, true); await f.state.entered.promise;
  await f.background.lock(); assert.match((await request).error.message, /locked/i);
  f.state.wait.resolve();
});

test('client site signing shares the queue: aborted waiters and locked queued/running operations reject', async () => {
  const gate = deferred(), entered = deferred(), calls = [];
  const module = { async unlock() { return { fingerprint: address, chainId: '56'.repeat(32), publicKey }; },
    async balance() { entered.resolve(); await gate.promise; return { total: '0', spendable: '0' }; },
    async siteSignMessage() { calls.push('sign'); return new Uint8Array(4627); },
    async list() {}, async buildAndSign() {}, async submit() {}, async scanConfirm() {}, async tick() {},
    async rulesetInfo() { return { generation: '1', tip: '1', gen2Height: '0' }; },
    cancel() {}, lock() {}, release() {}, memory: { buffer: new ArrayBuffer(64) } };
  const client = createNodusClient({ factory: async () => module, setInterval: () => 1, clearInterval() {} });
  await client.unlock({ seed: new Uint8Array(32), fingerprint: address });
  const running = client.balance(); await entered.promise;
  const abort = new AbortController(), cancelled = client.siteSignMessage({ origin: 'https://site.example', message: new Uint8Array([1]) }, { signal: abort.signal });
  abort.abort(); await assert.rejects(cancelled, /cancelled/i);
  const queued = client.siteSignMessage({ origin: 'https://site.example', message: new Uint8Array([2]) }); client.lock();
  await assert.rejects(queued, /locked/i); await assert.rejects(running, /locked/i);
  await assert.rejects(client.siteSignMessage({ origin: 'https://site.example', message: new Uint8Array([3]) }), /locked/i);
  gate.resolve(); assert.deepEqual(calls, []);
});

test('permission revoked while signing is queued prevents the module from signing', async t => {
  const f = await setup(t), remote = f.site(); await f.connect(remote);
  f.state.balanceWait = deferred(); f.state.entered = deferred();
  const reading = f.background.nodus.getBalances(); await f.state.entered.promise;
  const client = f.background.walletKeys.getEvmWallet().nodusClient, queued = deferred(), original = client.siteSignMessage;
  t.mock.method(client, 'siteSignMessage', (...args) => { const result = original(...args); queued.resolve(); return result; });
  const signing = remote.request('nodus_signMessage', ['hello', address]), pending = await f.nextApproval(signing);
  await f.background.approvals.controller.acceptRequest(pending.id, true);
  await queued.promise;
  f.background.permissions.controller.revokePermissions({ [remote.origin]: [NODUS_PERMISSION] });
  f.state.balanceWait.resolve(); await reading;
  assert.equal((await signing).error.code, 4100); assert.deepEqual(f.calls, []);
});

test('abort during a running site signature rejects and wipes the late output', async () => {
  const entered = deferred(), finish = deferred(), signature = new Uint8Array(4627).fill(7);
  const module = { async unlock() { return { fingerprint: address, chainId: '56'.repeat(32), publicKey }; },
    async siteSignMessage() { entered.resolve(); await finish.promise; return signature; },
    async balance() {}, async list() {}, async buildAndSign() {}, async submit() {}, async scanConfirm() {}, async tick() {}, async rulesetInfo() {},
    cancel() {}, lock() {}, release() {}, memory: { buffer: new ArrayBuffer(64) } };
  const client = createNodusClient({ factory: async () => module, setInterval: () => 1, clearInterval() {} });
  try {
    await client.unlock({ seed: new Uint8Array(32), fingerprint: address });
    const abort = new AbortController(), signing = client.siteSignMessage({ origin: 'https://site.example', message: new Uint8Array([1]) }, { signal: abort.signal });
    await entered.promise; abort.abort(); finish.resolve();
    await assert.rejects(signing, /cancelled/i); assert.ok(signature.every(byte => byte === 0));
  } finally { client.lock(); }
});

test('connected-sites UI revokes the Nodus permission through the existing background API', async () => {
  const calls = [], ui = createWalletUi({ async request(method, params) { calls.push([method, params]); return { subjects: { 'https://site.example': { permissions: { [NODUS_PERMISSION]: {} } } } }; } });
  await ui.refresh(); await ui.revoke('https://site.example');
  assert.deepEqual(calls[1], ['removePermissionsFor', [{ 'https://site.example': [NODUS_PERMISSION] }]]);
  await assert.rejects(ui.approveNodusConnect({ requestData: { permissions: { [NODUS_PERMISSION]: {}, unexpected: {} } } }), /Unsupported connection permissions/);
});

// Minimal DOM fixture proves notification routing and safe textContent
// rendering. Importing the renderer alone would miss mountWalletPage wiring.
test('notification shows the Nodus origin and full message with working approval controls', async () => {
  class Node extends EventTarget {
    constructor(tag) { super(); this.tagName = tag; this.children = []; this.text = ''; }
    append(...nodes) { this.children.push(...nodes); }
    replaceChildren(...nodes) { this.text = ''; this.children = nodes; }
    set textContent(value) { this.text = String(value); this.children = []; }
    get textContent() { return this.text + this.children.map(node => node.textContent).join(''); }
    querySelectorAll() { return []; }
    querySelector() { return null; }
  }
  const nodes = Object.fromEntries(['screen', 'wallet-navigation', 'wallet-status'].map(id => [id, new Node('div')]));
  const document = Object.assign(new EventTarget(), { createElement: tag => new Node(tag), getElementById: id => nodes[id] });
  const window = new EventTarget(), calls = [], pending = { id: 'sign', type: 'nodus_signMessage', origin: 'https://site.example',
    requestData: { account: address, text: '<script>full message</script>', data: '0x1234' } };
  const client = { async request(method, params) { calls.push([method, params]); return { isInitialized: true, isUnlocked: true, addresses: {}, preferences: {}, pendingApprovals: { sign: pending } }; },
    onNotification: () => () => {}, onDisconnect: () => () => {}, close() {} };
  const page = await mountWalletPage({ document, window, client });
  try {
    assert.match(nodes.screen.textContent, /https:\/\/site.example/); assert.match(nodes.screen.textContent, /<script>full message<\/script>/);
    const descendants = node => node.children.flatMap(child => [child, ...descendants(child)]);
    await descendants(nodes.screen).find(node => node.tagName === 'button' && node.textContent === 'Approve').onclick();
    assert.ok(calls.some(([method, params]) => method === 'resolvePendingApproval' && params[0] === 'sign'));
  } finally { page.dispose(); }
});

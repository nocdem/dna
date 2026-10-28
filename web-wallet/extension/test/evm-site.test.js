import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { Duplex } from 'readable-stream';
import { getBytes, keccak256, Transaction, verifyMessage, verifyTypedData } from 'ethers';
import { Caip25EndowmentPermissionName, setEthAccounts, setPermittedEthChainIds } from '@metamask/chain-agnostic-permission';
import log from 'loglevel';
import { CHAINS } from '../../src/config.js';

// Node >=22.14, pinned packages and CPUNK WASM; injected HTTPS JSON-RPC only, no network/disk output.
const phrase = 'abandon '.repeat(23) + 'art', password = 'public-test-password-123';
const account = '0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb', to = '0x0000000000000000000000000000000000000001';
const cpunkWasmBytes = readFileSync(new URL('../../src/cpunk/legacy-dilithium.wasm', import.meta.url));
const types = { Message: [{ name: 'text', type: 'string' }] };
const typed = { domain: { name: 'Public fixture', chainId: 1 }, primaryType: 'Message',
  types: { EIP712Domain: [{ name: 'name', type: 'string' }, { name: 'chainId', type: 'uint256' }], ...types }, message: { text: 'public typed message' } };
function event() { const listeners = new Set(); return { addListener(fn) { listeners.add(fn); }, removeListener(fn) { listeners.delete(fn); } }; }
function outputStream() { return new Duplex({ objectMode: true, read() {}, write(_message, _encoding, done) { done(); } }); }
function deferred() {
  let resolve; const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}
let module, id = 0;
async function setup(t) {
  const values = {}, calls = [], raw = [], logs = [];
  const fixture = {
    // This suite isolates EVM custody; nodus-background.test.js exercises the real consumer.
    consumeNodusSeed: () => {},
    runtime: { id: 'evm-test', onConnect: event(), getManifest: () => ({ version: '0.1.132' }), getURL: path => `chrome-extension://evm-test/${path}` },
    storage: { async get(key) { return { [key]: structuredClone(values[key]) }; }, async set(items) { Object.assign(values, structuredClone(items)); } },
    alarms: { onAlarm: event(), async clear() {}, async create() {} },
    windows: { onRemoved: event(), async getAll() { return []; }, async getLastFocused() { return { top: 0, left: 0, width: 1000 }; }, async create(options) { return { ...options, id: 2 }; }, async update() {} },
  };
  const state = { wrongNetwork: false, badHash: false, balance: '0x8ac7230489e80000' };
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    const req = JSON.parse(typeof options.body === 'string' ? options.body : new TextDecoder().decode(options.body));
    assert.equal(Array.isArray(req), false); calls.push({ url: String(url), ...req });
    const chainId = String(url).includes('bsc') || String(url).includes('binance') ? '0x38' : '0x1';
    let result;
    switch (req.method) {
      case 'eth_chainId': result = state.wrongNetwork ? '0x2' : chainId; break;
      case 'net_version': result = chainId === '0x1' ? '1' : '56'; break;
      case 'eth_blockNumber': result = '0x10'; break;
      case 'eth_getBalance': result = state.balance; break;
      case 'eth_call': result = '0x' + (123000000n).toString(16).padStart(64, '0'); break;
      case 'eth_estimateGas': result = '0x5208'; break;
      case 'eth_gasPrice': case 'eth_maxPriorityFeePerGas': result = '0x3b9aca00'; break;
      case 'eth_getTransactionCount': result = '0x7'; break;
      case 'eth_getBlockByNumber': result = { number: '0x10', hash: '0x' + '11'.repeat(32), parentHash: '0x' + '22'.repeat(32),
        timestamp: '0x1', nonce: '0x0000000000000000', difficulty: '0x0', gasLimit: '0x1c9c380', gasUsed: '0x0',
        miner: to, extraData: '0x', transactions: [] }; break;
      case 'eth_sendRawTransaction': raw.push(req.params[0]); result = state.badHash ? '0x' + 'ff'.repeat(32) : keccak256(req.params[0]); break;
      default: assert.fail(`Unexpected fixture method ${req.method}`);
    }
    return new Response(JSON.stringify({ id: req.id, jsonrpc: '2.0', result }), { headers: { 'content-type': 'application/json' } });
  });
  for (const method of ['info', 'debug', 'error']) t.mock.method(log, method, (...args) => logs.push(args));
  if (!module) {
    const saved = Object.getOwnPropertyDescriptor(globalThis, 'chrome'); globalThis.chrome = { ...fixture, storage: { local: fixture.storage } };
    try { module = await import('../src/background/index.js'); await (await module.background).destroy(); }
    finally { if (saved) Object.defineProperty(globalThis, 'chrome', saved); else delete globalThis.chrome; }
  }
  const background = await module.createBackground(fixture);
  await background.vaultStore.create(password, phrase); await background.unlock(password, { cpunkWasmBytes });
  const engines = [];
  function site(origin = 'https://site.example') {
    const { engine } = background.engine.setupProviderEngineEip1193({ origin, subjectType: 'website' }); engines.push(engine);
    return { origin, request: (method, params = []) => engine.handle({ id: ++id, jsonrpc: '2.0', method, params }) };
  }
  // Ethers drains RPC work with setTimeout(0); a fixed number of immediate
  // turns does not order that timer. Observe the real controller event instead.
  async function nextApproval(request) {
    const { controller } = background.approvals, ready = deferred();
    const changed = state => {
      const pending = Object.values(state.pendingApprovals)[0];
      if (pending) ready.resolve(pending);
    };
    controller.messenger.subscribe('ApprovalController:stateChange', changed);
    changed(controller.state);
    try {
      return await Promise.race([ready.promise, request.then(result => assert.fail(`Request completed before approval: ${JSON.stringify(result)}`))]);
    } finally { controller.messenger.unsubscribe('ApprovalController:stateChange', changed); }
  }
  async function connect(remote, chainIds = ['0x1', '0x38']) {
    const connecting = remote.request('eth_requestAccounts'), pending = await nextApproval(connecting);
    const approved = structuredClone(pending.requestData), caveat = approved.permissions[Caip25EndowmentPermissionName].caveats[0];
    caveat.value = setEthAccounts(setPermittedEthChainIds(caveat.value, chainIds), [account.toLowerCase()]);
    await background.permissions.acceptPermissionsRequest(approved);
    assert.deepEqual((await connecting).result, [account.toLowerCase()]);
  }
  t.after(async () => { engines.forEach(engine => engine.destroy()); await background.lock(); await background.destroy(); });
  return { background, fixture, values, state, calls, raw, logs, site, connect, nextApproval };
}

// Proves engine hooks wait for approval and produce recoverable signatures; keyring-only tests miss middleware/origin wiring.
test('site personal_sign and typedData_v4 require approval and sign with the web-wallet account', async t => {
  const { background, site, connect, nextApproval, logs } = await setup(t), remote = site(); await connect(remote);
  for (const [method, params, recover] of [
    ['personal_sign', ['0x7075626c69632d7369676e696e672d73656e74696e656c', account], signature => verifyMessage(getBytes('0x7075626c69632d7369676e696e672d73656e74696e656c'), signature)],
    ['eth_signTypedData_v4', [account, JSON.stringify(typed)], signature => verifyTypedData(typed.domain, types, typed.message, signature)],
  ]) {
    let resolved = false; const signing = remote.request(method, params).then(result => { resolved = true; return result; });
    const pending = await nextApproval(signing); assert.equal(pending.origin, remote.origin); assert.equal(resolved, false);
    assert.equal(pending.requestData.account, account); assert.ok(pending.requestData.text);
    await background.approvals.controller.acceptRequest(pending.id, true);
    const result = await signing; assert.equal(result.error, undefined); assert.equal(recover(result.result), account);
  }
  assert.equal(JSON.stringify(logs).includes('7075626c69632d7369676e696e672d73656e74696e656c'), false);
  assert.equal(JSON.stringify(logs).includes(typed.message.text), false);
});

// Proves reject returns 4001 with no raw send and unpermitted accounts fail; approval-only checks miss cancellation/authorization.
test('rejected signatures and sends return 4001; an unconnected origin cannot sign', async t => {
  const { background, site, connect, nextApproval, raw } = await setup(t), remote = site(); await connect(remote);
  for (const [method, params] of [['personal_sign', ['0x1234', account]], ['eth_signTypedData_v4', [account, JSON.stringify(typed)]],
    ['eth_sendTransaction', [{ from: account, to, value: '0x7b', data: '0x1234' }]]]) {
    const signing = remote.request(method, params), pending = await nextApproval(signing); background.approvals.reject(pending.id);
    assert.equal((await signing).error.code, 4001);
  }
  assert.equal(raw.length, 0);
  assert.equal((await site('https://unconnected.example').request('personal_sign', ['0x1234', account])).error.code, 4100);
});

// Proves gas/fees/nonce/type and site calldata survive raw broadcast; hash-only checks could send different fields.
test('site transaction review shows fee and broadcasts the approved transaction once', async t => {
  const { background, site, connect, nextApproval, calls, raw } = await setup(t), remote = site(); await connect(remote);
  const sending = remote.request('eth_sendTransaction', [{ from: account, to, value: '0x7b', data: '0x1234', gas: '0x7530' }]);
  const pending = await nextApproval(sending); assert.equal(raw.length, 0);
  assert.equal(pending.requestData.to, to); assert.equal(pending.requestData.value, '123'); assert.equal(pending.requestData.data, '0x1234');
  assert.match(pending.requestData.fee, /^Up to .+ ETH$/); await background.approvals.controller.acceptRequest(pending.id, true);
  const result = await sending; assert.equal(result.error, undefined); assert.equal(raw.length, 1); assert.equal(result.result, keccak256(raw[0]));
  const tx = Transaction.from(raw[0]); assert.equal(tx.from, account); assert.equal(tx.to, to); assert.equal(tx.value, 123n);
  assert.equal(tx.data, '0x1234'); assert.equal(tx.chainId, 1n); assert.equal(tx.type, 0); assert.equal(tx.nonce, 7);
  assert.equal(tx.gasLimit, 30000n); assert.equal(tx.gasPrice, 1000000000n);
  assert.ok(calls.some(req => req.method === 'eth_estimateGas' && req.params[0].data === '0x1234'));
  assert.ok(calls.some(req => req.method === 'eth_getTransactionCount' && req.params[1] === 'pending'));
});

// Proves absent gas uses the adapter's 120% estimate and wrong hash is refused; an explicit-gas send misses both branches.
test('site gas estimation mirrors the adapter and rejects a different returned transaction hash', async t => {
  const { background, site, connect, nextApproval, state, raw } = await setup(t), remote = site(); await connect(remote); state.badHash = true;
  const sending = remote.request('eth_sendTransaction', [{ from: account, to }]), pending = await nextApproval(sending);
  await background.approvals.controller.acceptRequest(pending.id, true);
  assert.match((await sending).error.message, /different transaction identifier/); assert.equal(raw.length, 1);
  assert.equal(Transaction.from(raw[0]).gasLimit, 25200n);
});

// Proves request/domain/endpoint identity and balance checks precede signing; chainId-read-only checks miss wrong-network signing.
test('wrong transaction/domain/RPC chain and insufficient funds are refused before signing', async t => {
  const { background, site, connect, state, raw } = await setup(t), remote = site(); await connect(remote);
  assert.ok((await remote.request('eth_sendTransaction', [{ from: account, to, chainId: '0x38' }])).error);
  assert.ok((await remote.request('eth_signTypedData_v4', [account, JSON.stringify({ ...typed, domain: { ...typed.domain, chainId: 56 } })])).error);
  state.wrongNetwork = true;
  assert.match((await remote.request('eth_sendTransaction', [{ from: account, to }])).error.message, /wrong network/);
  state.wrongNetwork = false; state.balance = '0x0';
  assert.match((await remote.request('eth_sendTransaction', [{ from: account, to }])).error.message, /Insufficient/);
  assert.equal(raw.length, 0); assert.equal(background.approvals.controller.state.pendingApprovalCount, 0);
});

// Proves unsupported methods stop before forwarding; a provider independently rejecting them could falsely pass.
test('deferred wallet methods return methodNotSupported without provider calls', async t => {
  const { site, calls } = await setup(t), remote = site();
  for (const method of ['wallet_addEthereumChain', 'wallet_watchAsset', 'eth_sign', 'eth_signTypedData', 'eth_signTypedData_v1',
    'eth_signTypedData_v3', 'eth_getEncryptionPublicKey', 'eth_decrypt']) {
    const before = calls.length; assert.equal((await remote.request(method, [])).error.code, -32004); assert.equal(calls.length, before);
  }
});

// Proves imported adapter balances/token formatting and selected-endpoint reads; UI-only checks could accept fabricated values.
test('balances import the web-wallet adapter and reads use its selected endpoint', async t => {
  const { background, site, calls } = await setup(t), remote = site();
  const balances = await background.evm.getBalances('ethereum');
  assert.deepEqual(balances[0], { symbol: 'ETH', balance: '10.0' }); assert.equal(balances[1].balance, '123.0');
  assert.equal((await remote.request('eth_chainId')).result, '0x1'); assert.equal((await remote.request('net_version')).result, '1');
  assert.equal((await remote.request('eth_blockNumber')).result, '0x10');
  assert.ok(calls.some(req => req.method === 'eth_call')); assert.ok(calls.every(req => req.url === CHAINS.ethereum.endpoint + '/'));
});

// Proves switch approval updates all connections and persisted choice; engine-only checks miss notifications/state wiring.
test('site switch changes the shared choice and notifies connected origins', async t => {
  const { background, site, connect, nextApproval } = await setup(t), one = site(), two = site('https://other.example');
  await connect(one); await connect(two);
  const streams = [outputStream(), outputStream(), outputStream()], notifications = [[], [], []];
  const initial = streams.map(deferred), switched = streams.slice(0, 2).map(deferred);
  [one.origin, two.origin, 'https://unconnected.example'].forEach((url, index) => {
    const connection = background.engine.setupProviderConnectionEip1193(streams[index], { url }, 'website');
    connection.engine.on('notification', message => {
      notifications[index].push(message);
      if (message.method === 'nodus_chainChanged' && message.params.chainId === '0x1') initial[index].resolve();
      if (message.method === 'nodus_chainChanged' && message.params.chainId === '0x38') switched[index]?.resolve();
    });
  });
  await Promise.all(initial.map(event => event.promise)); notifications.forEach(events => { events.length = 0; });
  const switching = one.request('wallet_switchEthereumChain', [{ chainId: '0x38' }]), pending = await nextApproval(switching);
  assert.equal((await two.request('eth_chainId')).result, '0x1'); assert.equal(pending.type, 'wallet_switchEthereumChain');
  await background.approvals.controller.acceptRequest(pending.id, true); assert.equal((await switching).result, null);
  assert.equal((await two.request('eth_chainId')).result, '0x38'); assert.equal((await two.request('net_version')).result, '56');
  await Promise.all(switched.map(event => event.promise));
  assert.ok(notifications.slice(0, 2).every(events => events.some(message => message.method === 'nodus_chainChanged' && message.params.chainId === '0x38')));
  assert.equal(notifications[2].length, 0);
  await background.store.flush(); assert.equal(background.store.backup().EvmController.selectedChain, 'bsc'); streams.forEach(stream => stream.destroy());
});

// Proves denied/unknown switches leave the shared network unchanged; testing only success misses accidental pre-approval mutations.
test('rejected switches return 4001 and unknown chains return 4902 without changing selection', async t => {
  const { background, site, connect, nextApproval } = await setup(t), remote = site(); await connect(remote);
  const switching = remote.request('wallet_switchEthereumChain', [{ chainId: '0x38' }]), pending = await nextApproval(switching);
  background.approvals.reject(pending.id); assert.equal((await switching).error.code, 4001);
  assert.equal((await remote.request('eth_chainId')).result, '0x1');
  assert.equal((await remote.request('wallet_switchEthereumChain', [{ chainId: '0x2' }])).error.code, 4902);
  assert.equal((await remote.request('wallet_switchEthereumChain', [{ chainId: 'invalid' }])).error.code, -32602);
});

// Proves missing chain scopes go through real incremental permission approval and preserve accounts; all-chains fixtures miss this branch.
test('switching to an unpermitted chain requests permission before shared network approval', async t => {
  const { background, site, connect, nextApproval } = await setup(t), remote = site(); await connect(remote, ['0x1']);
  const switching = remote.request('wallet_switchEthereumChain', [{ chainId: '0x38' }]), permission = await nextApproval(switching);
  assert.equal(permission.type, 'wallet_requestPermissions');
  assert.equal((await remote.request('eth_chainId')).result, '0x1');
  const approved = structuredClone(permission.requestData), caveat = approved.permissions[Caip25EndowmentPermissionName].caveats[0];
  caveat.value = setEthAccounts(caveat.value, [account.toLowerCase()]);
  await background.permissions.acceptPermissionsRequest(approved);
  const pending = await nextApproval(switching); assert.equal(pending.type, 'wallet_switchEthereumChain');
  await background.approvals.controller.acceptRequest(pending.id, true); assert.equal((await switching).result, null);
  assert.deepEqual(background.permissions.getAccounts(remote.origin), [account.toLowerCase()]);
  assert.deepEqual(new Set(background.permissions.getChainIds(remote.origin)), new Set(['0x1', '0x38']));
});

// Proves settings use config endpoints and hydrate on worker restart; checking a backup snapshot alone misses restoration/wiring.
test('shared network and listed RPC choice survive a locked background restart', async t => {
  const { background, fixture } = await setup(t);
  await background.evm.selectNetwork('bsc'); await background.evm.setEndpoint('bsc', CHAINS.bsc.rpcOptions[1].url);
  await assert.rejects(background.evm.setEndpoint('bsc', 'https://unlisted.example'), /listed/);
  const restarted = await module.createBackground({ ...fixture, runtime: { ...fixture.runtime, onConnect: event() } });
  try {
    assert.equal(restarted.lockCoordinator.isLocked, true); assert.equal(restarted.evm.getState().selectedChain, 'bsc');
    assert.equal(restarted.evm.getState().endpoints.bsc, CHAINS.bsc.rpcOptions[1].url);
    assert.equal((await restarted.engine.getNetworkState()).chainId, '0x38');
    assert.equal(restarted.permissions.getSelectedAccount().type, 'eip155:eoa');
  } finally { await restarted.destroy(); }
});

// Proves only changed permitted accounts emit notifications; a single expected notification misses unrelated-origin leakage.
test('accountsChanged is limited to origins whose permitted accounts changed', async t => {
  const { background, site, connect } = await setup(t), one = site(), two = site('https://other.example'); await connect(one); await connect(two);
  const streams = [outputStream(), outputStream()], events = [[], []];
  [one, two].forEach((remote, index) => {
    const connection = background.engine.setupProviderConnectionEip1193(streams[index], { url: remote.origin }, 'website');
    connection.engine.on('notification', event => { if (event.method === 'nodus_accountsChanged') events[index].push(event.params); });
  });
  background.permissions.controller.revokePermissions({ [one.origin]: [Caip25EndowmentPermissionName] });
  await background.engine.notifyAccountsChanged(); assert.deepEqual(events, [[[]], []]);
  await background.engine.notifyAccountsChanged(); assert.deepEqual(events, [[[]], []]); streams.forEach(stream => stream.destroy());
});

// Proves pending work cannot sign across lock/re-unlock, including internal transfers; new post-lock requests miss retained sessions.
test('lock invalidates pending site signatures, site transactions and internal sends', async t => {
  const { background, site, connect, nextApproval, raw } = await setup(t), remote = site(); await connect(remote);
  for (const [method, params] of [['personal_sign', ['0x1234', account]], ['eth_signTypedData_v4', [account, JSON.stringify(typed)]], ['eth_sendTransaction', [{ from: account, to }]]]) {
    const signing = remote.request(method, params), pending = await nextApproval(signing);
    await background.lock(); await background.unlock(password, { cpunkWasmBytes }); await background.approvals.controller.acceptRequest(pending.id, true);
    assert.match((await signing).error.message, /locked/i);
  }
  const review = await background.evm.prepareSend({ chain: 'ethereum', symbol: 'ETH', to, amount: '0.01' });
  assert.match(review.fee, /ETH$/); await background.lock(); await background.unlock(password, { cpunkWasmBytes });
  await assert.rejects(background.evm.confirmSend(review.id), /locked/i); assert.equal(raw.length, 0);
});

// Proves internal sends use real adapter bytes and one-shot confirmation; UI-only checks could hide no-op sends.
test('internal EVM send uses the web-wallet review and cannot be broadcast twice', async t => {
  const { background, raw } = await setup(t);
  const review = await background.evm.prepareSend({ chain: 'ethereum', symbol: 'ETH', to, amount: '0.01' });
  const hash = await background.evm.confirmSend(review.id); assert.equal(hash, keccak256(raw[0])); assert.equal(raw.length, 1);
  assert.equal(Transaction.from(raw[0]).value, 10000000000000000n);
  await assert.rejects(background.evm.confirmSend(review.id), /closed/); assert.equal(raw.length, 1);
});

// Proves an in-flight ethers transaction result cannot broadcast after lock; rejecting before approval would miss the actual signing boundary.
test('site and internal transactions waiting inside ethers cannot broadcast after lock', async t => {
  const { background, site, connect, nextApproval, raw } = await setup(t), remote = site(); await connect(remote);
  for (const internal of [false, true]) {
    const signer = background.walletKeys.getEvmWallet().evm, sign = signer.signTransaction.bind(signer);
    let entered, release; const started = new Promise(resolve => { entered = resolve; }), gate = new Promise(resolve => { release = resolve; });
    t.mock.method(signer, 'signTransaction', async tx => { const signed = await sign(tx); entered(); await gate; return signed; });
    let sending, rejected;
    if (internal) {
      const review = await background.evm.prepareSend({ chain: 'ethereum', symbol: 'ETH', to, amount: '0.01' });
      sending = background.evm.confirmSend(review.id); rejected = assert.rejects(sending, /locked/i);
    } else {
      sending = remote.request('eth_sendTransaction', [{ from: account, to }]);
      await background.approvals.controller.acceptRequest((await nextApproval(sending)).id, true);
    }
    await started;
    try { await background.lock(); await background.unlock(password, { cpunkWasmBytes }); }
    finally { release(); }
    if (internal) await rejected; else assert.match((await sending).error.message, /locked/i);
    assert.equal(raw.length, 0);
  }
});

// Proves switching settings invalidates a previously reviewed site transaction; a fresh request on the new chain would miss stale approval state.
test('a network change while transaction approval waits prevents broadcast', async t => {
  const { background, site, connect, nextApproval, raw } = await setup(t), remote = site(); await connect(remote);
  const sending = remote.request('eth_sendTransaction', [{ from: account, to }]), pending = await nextApproval(sending);
  await background.evm.selectNetwork('bsc'); await background.approvals.controller.acceptRequest(pending.id, true);
  assert.match((await sending).error.message, /Network changed/); assert.equal(raw.length, 0);
});

// Proves both callers recheck the captured network after ethers resolves; changing before approval would miss retained signed bytes.
test('site and internal transactions waiting inside ethers cannot broadcast after a network change', async t => {
  const { background, site, connect, nextApproval, raw } = await setup(t), remote = site(); await connect(remote);
  for (const internal of [false, true]) {
    await background.evm.selectNetwork('ethereum');
    const signer = background.walletKeys.getEvmWallet().evm, sign = signer.signTransaction.bind(signer);
    const entered = deferred(), gate = deferred();
    const signing = t.mock.method(signer, 'signTransaction', async tx => {
      const signed = await sign(tx); entered.resolve(); await gate.promise; return signed;
    });
    try {
      let sending, rejected;
      if (internal) {
        const review = await background.evm.prepareSend({ chain: 'ethereum', symbol: 'ETH', to, amount: '0.01' });
        sending = background.evm.confirmSend(review.id); rejected = assert.rejects(sending, /Network changed/);
      } else {
        sending = remote.request('eth_sendTransaction', [{ from: account, to }]);
        await background.approvals.controller.acceptRequest((await nextApproval(sending)).id, true);
      }
      await entered.promise;
      try { await background.evm.selectNetwork('bsc'); } finally { gate.resolve(); }
      if (internal) await rejected; else assert.match((await sending).error.message, /Network changed/);
      assert.equal(raw.length, 0);
    } finally { gate.resolve(); signing.mock.restore(); }
  }
});

for (const invalidation of ['network change', 'lock']) {
  // Proves the final adapter guard checks the session after its awaited callback; invalidating before signing misses this yield.
  test(`internal send rejects ${invalidation} queued by its post-signing session check`, async t => {
    const { background, raw } = await setup(t), signer = background.walletKeys.getEvmWallet().evm;
    const sign = signer.signTransaction.bind(signer), assertUnlocked = background.lockCoordinator.assertUnlocked.bind(background.lockCoordinator);
    let signed = false, invalidating;
    t.mock.method(signer, 'signTransaction', async tx => { const bytes = await sign(tx); signed = true; return bytes; });
    t.mock.method(background.lockCoordinator, 'assertUnlocked', () => {
      assertUnlocked();
      // Queue once at the first session check after signed bytes return. The
      // adapter's await onBroadcast yields to this action before its final guard.
      // Lock publishes locked=true before awaiting keyring disposal, so the real
      // wallet's own locked flag need not yet be set (lock.js:35-46).
      if (signed && !invalidating) invalidating = Promise.resolve().then(() =>
        invalidation === 'lock' ? background.lock() : background.evm.selectNetwork('bsc'));
    });
    const review = await background.evm.prepareSend({ chain: 'ethereum', symbol: 'ETH', to, amount: '0.01' });
    await assert.rejects(background.evm.confirmSend(review.id), invalidation === 'lock' ? /locked/i : /Network changed/);
    assert.ok(invalidating); await invalidating; assert.equal(raw.length, 0);
  });
}

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { Duplex } from 'readable-stream';
import { keccak256 } from 'ethers';
import { Caip25EndowmentPermissionName, setEthAccounts, setPermittedEthChainIds } from '@metamask/chain-agnostic-permission';
import log from 'loglevel';
import { createMockNodusModule } from '../../test/nodus-mock-module.js';
import { deriveNodusAddress } from '../../src/nodus/derive.js';

// Shared fixture of the swap and Sepolia extension tests (plan 2026-11-08-swap-bot-plan.nodus1.md section 19 line 666).
// Environment: Node >=22.14, pinned packages, the committed WASM files; no flags, no real network and no disk output.
// Every Ethereum RPC call, every call to the bot and every Nodus module call is a stub inside this process, so a test
// proves the extension's logic and ordering, NOT a real HTTPS connection, TLS, CORS or the real bot (the host
// permission `https://*/*` of manifest.json is what lets the real extension reach the bot; no test shows that).
export const phrase = 'abandon '.repeat(23) + 'art', password = 'public-test-password-123';
export const account = '0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb';
// The pinned mainnet USDT contract (src/config.js:12); `otherToken` is any other contract.
export const token = '0xdAC17F958D2ee523a2206206994597C13D831ec7', otherToken = '0x00000000000000000000000000000000000000aa', payTo = '0x00000000000000000000000000000000000000bb';
export const BOT = 'https://swap.nodusnetwork.io';
export const foundationNodus = 'cd'.repeat(64), wireId = 'ab'.repeat(64);
export const nodusPublicKey = '12'.repeat(2592), nodusSignature = '34'.repeat(4627);
const cpunkWasmBytes = readFileSync(new URL('../../src/cpunk/legacy-dilithium.wasm', import.meta.url));
const nodusWasmBytes = readFileSync(new URL('../../src/nodus/mldsa87.wasm', import.meta.url));
function event() { const listeners = new Set(); return { addListener(fn) { listeners.add(fn); }, removeListener(fn) { listeners.delete(fn); } }; }
function deferred() { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; }
export function outputStream() { return new Duplex({ objectMode: true, read() {}, write(_message, _encoding, done) { done(); } }); }

let backgroundModule, id = 0;
export async function setup(t) {
  const values = {}, calls = [], raw = [], logs = [], botCalls = [], events = [], signCalls = [];
  const nodusMock = createMockNodusModule();
  nodusMock.state.fingerprint = await deriveNodusAddress(phrase, { wasmBytes: nodusWasmBytes });
  nodusMock.state.wireId = wireId;
  const base = nodusMock.module;
  // The mock module has no site signing and no public key: add them. The fake signature proves routing and ordering,
  // not cryptographic validity (the C verify test and the WASM parity cover that).
  const nodusModule = { ...base,
    unlock: async args => ({ ...(await base.unlock(args)), publicKey: nodusPublicKey }),
    identify: async args => ({ ...(await base.identify(args)), publicKey: nodusPublicKey }),
    siteSignMessage: async ({ origin, message }) => { signCalls.push({ origin, text: Buffer.from(message).toString('utf8') }); return Uint8Array.from(Buffer.from(nodusSignature, 'hex')); },
    submit: args => { events.push('nodus_submit'); return base.submit(args); } };
  const fixture = {
    nodusOptions: { factory: async () => nodusModule },
    runtime: { id: 'swap-test', onConnect: event(), getManifest: () => ({ version: '0.1.132' }), getURL: path => `chrome-extension://swap-test/${path}` },
    storage: { async get(keys) { return Object.fromEntries((Array.isArray(keys) ? keys : [keys]).map(key => [key, structuredClone(values[key])])); }, async set(items) { Object.assign(values, structuredClone(items)); } },
    alarms: { onAlarm: event(), async clear() {}, async create() {} },
    windows: { onRemoved: event(), async getAll() { return []; }, async getLastFocused() { return { top: 0, left: 0, width: 1000 }; }, async create(options) { return { ...options, id: 2 }; }, async update() {} },
  };
  // The stub bot. `mode` chooses its answer: 'ok' (HTTP 200 {"received":true}), 'refuse' (the connection is refused),
  // 'error' (HTTP 500), 'gateway' (HTTP 502 HTML, a forwarder with the bot down), 'reject' (HTTP 200 {"received":false,
  // "reason":"bad_signature"}, the bot refusing the request), 'open' (HTTP 200 {"received":false,"reason":"open_approval","openRequestNumber":state.openRequestNumber}), 'plain' (HTTP 200 text that is not the bot's JSON answer).
  const state = { bot: 'ok', onBot: undefined, balance: '0x8ac7230489e80000', base: '0x10', tipError: false };
  async function bot(url, options) {
    events.push('bot'); botCalls.push({ url: String(url), method: options.method, body: JSON.parse(options.body), options });
    state.onBot?.();
    switch (state.bot) {
      case 'refuse': throw new TypeError('fetch failed');
      case 'error': return new Response('{"error":"boom"}', { status: 500 });
      case 'gateway': return new Response('<html>502 Bad Gateway</html>', { status: 502 });
      case 'reject': return new Response('{"received":false,"reason":"bad_signature"}', { status: 200 });
      case 'open': return new Response(JSON.stringify({ received: false, reason: 'open_approval', openRequestNumber: state.openRequestNumber }), { status: 200 });
      case 'flood': {
        // HTTP 200 whose body starts with {"received":true and then streams far more than the 65,536-byte cap, one 8 KiB chunk
        // per pull; `floodPulls` counts the pulls and `floodCancelled` records that the reader was cancelled.
        const head = new TextEncoder().encode('{"received":true,"pad":"'), filler = new Uint8Array(8192).fill(120);
        state.floodPulls = 0; state.floodCancelled = false;
        return new Response(new ReadableStream({
          pull(controller) { state.floodPulls++; controller.enqueue(state.floodPulls === 1 ? head : filler); if (state.floodPulls > 200) controller.close(); },
          cancel() { state.floodCancelled = true; },
        }), { status: 200 });
      }
      case 'plain': return new Response('ok', { status: 200 });
      default: return new Response('{"received":true,"requestNumber":"123456789"}', { status: 200 });
    }
  }
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    if (String(url).startsWith(BOT)) return bot(url, options);
    const req = JSON.parse(typeof options.body === 'string' ? options.body : new TextDecoder().decode(options.body));
    assert.equal(Array.isArray(req), false); calls.push({ url: String(url), ...req });
    const sepolia = String(url).includes('sepolia');
    const chainId = sepolia ? '0xaa36a7' : String(url).includes('bsc') || String(url).includes('binance') ? '0x38' : '0x1';
    let result;
    switch (req.method) {
      case 'eth_chainId': result = state.wrongChain ? '0x2' : chainId; break;
      case 'net_version': result = String(parseInt(chainId, 16)); break;
      case 'eth_blockNumber': result = '0x10'; break;
      case 'eth_getBalance': result = state.balance; break;
      case 'eth_call': result = '0x' + (123000000n).toString(16).padStart(64, '0'); break;
      case 'eth_estimateGas':
        // `estimateError`: the node refuses the estimate, as for a transfer the chain would revert.
        if (state.estimateError) return new Response(JSON.stringify({ id: req.id, jsonrpc: '2.0', error: { code: 3, message: 'execution reverted', data: '0x' } }), { headers: { 'content-type': 'application/json' } });
        result = '0x5208'; break;
      // Three distinct fee values (base `state.base` = 0x10, tip 0x5, gas price 0x15): a fee path that used the wrong quote produces a number
      // other than 2 x base + tip = 0x25. `tipError`: the node refuses the tip read (a fee-read failure, not a short balance).
      case 'eth_gasPrice': result = '0x15'; break;
      case 'eth_maxPriorityFeePerGas':
        if (state.tipError) return new Response(JSON.stringify({ id: req.id, jsonrpc: '2.0', error: { code: -32601, message: 'method not found' } }), { headers: { 'content-type': 'application/json' } });
        result = '0x5'; break;
      case 'eth_getTransactionCount': result = '0x7'; break;
      case 'eth_getTransactionReceipt': result = null; break;
      // A full Block (the 18 required fields) with a base fee (the fixture's header already states: no flags, nothing left behind). A test
      // could falsely pass on legacy fields only if it did not decode the raw; the swap and Sepolia tests decode type and fee fields.
      case 'eth_getBlockByNumber': result = { number: '0x10', hash: '0x' + '11'.repeat(32), parentHash: '0x' + '22'.repeat(32), sha3Uncles: '0x' + '33'.repeat(32),
        timestamp: '0x1', nonce: '0x0000000000000000', difficulty: '0x0', gasLimit: '0x1c9c380', gasUsed: '0x0', stateRoot: '0x' + '44'.repeat(32),
        transactionsRoot: '0x' + '55'.repeat(32), receiptsRoot: '0x' + '66'.repeat(32), logsBloom: '0x' + '00'.repeat(256), mixHash: '0x' + '77'.repeat(32), size: '0x200', uncles: [],
        miner: payTo, extraData: '0x', transactions: [], baseFeePerGas: state.base }; break;
      case 'eth_sendRawTransaction':
        // `onRaw` runs when the broadcast call arrives (a test locks the wallet there); `failRaw` makes the call fail.
        events.push('eth_sendRawTransaction'); state.onRaw?.(); if (state.failRaw) throw new TypeError('broadcast down');
        raw.push(req.params[0]); result = keccak256(req.params[0]); break;
      default: assert.fail(`Unexpected fixture method ${req.method}`);
    }
    return new Response(JSON.stringify({ id: req.id, jsonrpc: '2.0', result }), { headers: { 'content-type': 'application/json' } });
  });
  for (const method of ['info', 'debug', 'error']) t.mock.method(log, method, (...args) => logs.push(args));
  if (!backgroundModule) {
    const saved = Object.getOwnPropertyDescriptor(globalThis, 'chrome'); globalThis.chrome = { ...fixture, storage: { local: fixture.storage } };
    try { backgroundModule = await import('../src/background/index.js'); await (await backgroundModule.background).destroy(); }
    finally { if (saved) Object.defineProperty(globalThis, 'chrome', saved); else delete globalThis.chrome; }
  }
  const background = await backgroundModule.createBackground(fixture);
  await background.privacyConsent.accept();
  await background.vaultStore.create(password, phrase); await background.unlock(password, { cpunkWasmBytes, nodusWasmBytes });
  const readyDeadline = performance.now() + 2000;
  while (background.nodus.getState().state !== 'ready') {
    assert.ok(performance.now() < readyDeadline, 'fixture connection never became ready');
    await new Promise(resolve => setImmediate(resolve));
  }
  const engines = [];
  function site(origin = 'https://site.example') {
    const { engine } = background.engine.setupProviderEngineEip1193({ origin, subjectType: 'website' }); engines.push(engine);
    return { origin, request: (method, params = []) => engine.handle({ id: ++id, jsonrpc: '2.0', method, params }) };
  }
  async function nextApproval(request) {
    const { controller } = background.approvals, ready = deferred();
    const changed = pending => { const first = Object.values(pending.pendingApprovals)[0]; if (first) ready.resolve(first); };
    controller.messenger.subscribe('ApprovalController:stateChange', changed); changed(controller.state);
    try { return await Promise.race([ready.promise, request.then(result => assert.fail(`Request completed before approval: ${JSON.stringify(result)}`))]); }
    finally { controller.messenger.unsubscribe('ApprovalController:stateChange', changed); }
  }
  async function connectEthereum(remote, chainIds = ['0x1', '0x38']) {
    const connecting = remote.request('eth_requestAccounts'), pending = await nextApproval(connecting);
    const approved = structuredClone(pending.requestData), caveat = approved.permissions[Caip25EndowmentPermissionName].caveats[0];
    caveat.value = setEthAccounts(setPermittedEthChainIds(caveat.value, chainIds), [account.toLowerCase()]);
    await background.permissions.acceptPermissionsRequest(approved);
    assert.deepEqual((await connecting).result, [account.toLowerCase()]);
  }
  async function connectNodus(remote) {
    const connecting = remote.request('nodus_requestAccounts'), pending = await nextApproval(connecting);
    await background.permissions.acceptPermissionsRequest(structuredClone(pending.requestData));
    const answer = (await connecting).result;
    assert.equal(answer[0].address, nodusMock.state.fingerprint); return answer[0];
  }
  // Answers the approvals of `request` in order: `types` are the approval types expected, each approved (or the
  // listed index rejected). Returns the pending approvals seen. The request itself is awaited by the caller.
  async function walk(request, types, { rejectAt } = {}) {
    const seen = [];
    for (const [index, type] of types.entries()) {
      const pending = await nextApproval(request); assert.equal(pending.type, type); seen.push(pending);
      if (rejectAt === index) { background.approvals.reject(pending.id); break; }
      await background.approvals.controller.acceptRequest(pending.id, true);
    }
    return seen;
  }
  t.after(async () => { engines.forEach(engine => engine.destroy()); await background.lock(); await background.destroy(); });
  return { background, fixture, values, state, calls, raw, logs, botCalls, events, signCalls, site, connectEthereum, connectNodus, nextApproval, walk, nodusMock };
}

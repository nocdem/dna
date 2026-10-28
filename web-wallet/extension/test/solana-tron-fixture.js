import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { TronWeb, utils } from 'tronweb';
import { encodeBase58 } from 'ethers';
import { getTransactionDecoder } from '@solana/kit';
import { CHAINS } from '../../src/config.js';
import { TOKEN_PROGRAM_ID, getAssociatedTokenAddress } from '../../src/adapters/solana-token.js';
import { ACTIVITY_KEY } from '../../src/vault.js';
import { connectTrusted } from '../src/ui/trusted-port.js';

// Node >=22.14; pinned dependencies and existing WASM fixtures. All network
// requests are intercepted, unknown calls fail, storage is memory only. No skips.
export const { phrase, address: nodusAddress } = JSON.parse(readFileSync(new URL('../../test/fixtures/nodus-addresses.json', import.meta.url))).vectors[0];
export const password = 'public-test-password-123';
export const unlockOptions = {
  nodusWasmBytes: readFileSync(new URL('../../src/nodus/mldsa87.wasm', import.meta.url)),
  cpunkWasmBytes: readFileSync(new URL('../../src/cpunk/legacy-dilithium.wasm', import.meta.url)),
};
export function deferred() { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; }
function event() {
  const listeners = new Set();
  return { addListener(fn) { listeners.add(fn); }, removeListener(fn) { listeners.delete(fn); }, emit: value => Promise.all([...listeners].map(fn => fn(value))) };
}
let backgroundModule;
export async function setup(t) {
  const values = {}, calls = [], broadcasts = [], keysUsed = [];
  const state = { wrongNetwork: false, failSave: false, failBroadcast: false, failHistory: false, addresses: {} };
  const fixture = {
    runtime: { id: 'solana-tron-test', onConnect: event(), getManifest: () => ({ version: '0.1.132' }), getURL: path => `chrome-extension://solana-tron-test/${path}` },
    storage: { async get(key) { return Object.fromEntries((Array.isArray(key) ? key : [key]).map(name => [name, structuredClone(values[name])])); }, async set(items) {
      if (items[ACTIVITY_KEY]) {
        if (state.failSave) throw new Error('fixture persistence failed');
        if (state.saveGate) { state.entered.resolve(); await state.saveGate.promise; }
      }
      Object.assign(values, structuredClone(items));
    } },
    alarms: { onAlarm: event(), async clear() {}, async create() {} },
    windows: { onRemoved: event(), async getAll() { return []; } },
    nodusOptions: { factory: async () => ({
      memory: { buffer: new ArrayBuffer(64) },
      async unlock() { return { fingerprint: nodusAddress, chainId: '12'.repeat(32) }; },
      async tick() {}, cancel() {}, lock() {}, release() {},
      async balance() { return { total: '0', spendable: '0' }; },
      async list() { return { tip: '1', coins: [], truncated: false }; },
      async buildAndSign() { assert.fail('Unexpected fake Nodus build'); },
      async submit() { assert.fail('Unexpected fake Nodus submit'); },
      async scanConfirm() { return { found: false, tip: '1' }; },
      async rulesetInfo() { return { generation: '1', tip: '1', gen2Height: '0' }; },
      async nameLookup() { return { found: true, owner: nodusAddress, registeredHeight: '1', committedHeight: '2' }; },
      async nameOf() { return { found: false, committedHeight: '2' }; },
      async profileAddress({ field }) { return { address: state.recipients[field === 'sol' ? 'solana' : 'tron'] }; },
    }) },
  };
  // Remove pacing waits, including clock jumps used for expiry/cooldown tests;
  // preserve the web tracker's 12 s and Nodus watchdog's 30 s timers.
  const setTimer = globalThis.setTimeout;
  t.mock.method(globalThis, 'setTimeout', (fn, delay, ...args) => setTimer(fn, delay === 12000 || delay === 30000 ? delay : 0, ...args));
  t.mock.method(globalThis, 'fetch', async (url, options = {}) => {
    url = String(url); const body = options.body ? JSON.parse(options.body) : {};
    calls.push({ url, body, signal: options.signal });
    if (state.readGate && ((state.pauseMethod && body.method === state.pauseMethod) || new URL(url).pathname === state.pausePath)) {
      state.entered.resolve(); await state.readGate.promise;
    }
    if (url.startsWith(CHAINS.solana.endpoint)) {
      let result;
      switch (body.method) {
        case 'getGenesisHash': result = state.wrongNetwork ? 'wrong-network' : CHAINS.solana.genesisHash; break;
        case 'getBalance': result = { context: { slot: 1 }, value: 10000000000 }; break;
        case 'getTokenAccountsByOwner': {
          const mint = body.params[1].mint, owner = state.addresses.solana;
          result = { context: { slot: 1 }, value: [{ pubkey: await getAssociatedTokenAddress(mint, owner), account: {
            executable: false, owner: TOKEN_PROGRAM_ID, lamports: 2039280, rentEpoch: 0,
            data: { program: 'spl-token', space: 165, parsed: { type: 'account', info: { state: 'initialized', mint, owner,
              tokenAmount: { amount: '250000000', decimals: 6, uiAmount: 250, uiAmountString: '250' } } } },
          } }] }; break;
        }
        case 'getAccountInfo': result = { context: { slot: 1 }, value: null }; break;
        case 'getMinimumBalanceForRentExemption': result = 2039280; break;
        case 'getLatestBlockhash': result = { context: { slot: 1 }, value: { blockhash: '11111111111111111111111111111111', lastValidBlockHeight: 100 } }; break;
        case 'getFeeForMessage': result = { context: { slot: 1 }, value: 5000 }; break;
        case 'getBlockHeight': result = 50; break;
        case 'sendTransaction': {
          assert.ok(values[ACTIVITY_KEY], 'persist before broadcast');
          const tx = getTransactionDecoder().decode(Buffer.from(body.params[0], 'base64'));
          broadcasts.push({ chain: 'solana', tx });
          if (state.failBroadcast) throw new Error('fixture broadcast uncertain');
          result = encodeBase58(Object.values(tx.signatures)[0]); break;
        }
        case 'getSignatureStatuses': result = { value: [{ err: null, confirmationStatus: 'finalized' }] }; break;
        case 'getSignaturesForAddress':
          if (state.failHistory) throw new Error('fixture history unavailable');
          result = [{ signature: '2'.repeat(88) }]; break;
        case 'getTransaction': result = { blockTime: 1700000000, transaction: { message: { accountKeys: [state.addresses.solana], instructions: [] } },
          meta: { err: null, fee: 0, preBalances: [0], postBalances: [1000000000] } }; break;
        default: assert.fail(`Unexpected fake Solana method: ${body.method}`);
      }
      return Response.json({ jsonrpc: '2.0', id: body.id, result });
    }
    assert.equal(new URL(url).origin, new URL(CHAINS.tron.endpoint).origin);
    const path = new URL(url).pathname;
    if (path === '/wallet/getblockbynum') return Response.json({ blockID: state.wrongNetwork ? 'wrong-network' : CHAINS.tron.genesisHash });
    if (path === `/v1/accounts/${state.addresses.tron}`) return Response.json({ data: [{ balance: 123000000, trc20: CHAINS.tron.tokens.map(t => ({ [t.address]: (250n * 10n ** BigInt(t.decimals)).toString() })) }] });
    // Transaction fixtures match test/security.test.js:89-110, including the
    // real SDK's protobuf encoding, txID and txCheck; no mocked signing code.
    if (path === '/wallet/getblock') return Response.json({ blockID: 'a'.repeat(64), block_header: { raw_data: { number: 100, timestamp: Date.now() } } });
    if (path === '/wallet/triggersmartcontract') {
      const timestamp = Date.now();
      const transaction = { visible: false, raw_data: { ref_block_bytes: '0064', ref_block_hash: 'a'.repeat(16), timestamp,
        expiration: timestamp + 60000, fee_limit: body.fee_limit, contract: [{ type: 'TriggerSmartContract', parameter: {
          type_url: 'type.googleapis.com/protocol.TriggerSmartContract', value: { owner_address: body.owner_address,
            contract_address: body.contract_address, data: 'a9059cbb' + body.parameter, call_value: 0 },
        } }] } };
      const pb = utils.transaction.txJsonToPb(transaction);
      transaction.raw_data_hex = utils.transaction.txPbToRawDataHex(pb); transaction.txID = utils.transaction.txPbToTxID(pb).replace(/^0x/, '');
      return Response.json({ result: { result: true }, transaction });
    }
    if (path === '/wallet/broadcasttransaction') {
      assert.ok(values[ACTIVITY_KEY], 'persist before broadcast'); assert.ok(utils.transaction.txCheck(body)); assert.equal(body.signature.length, 1);
      broadcasts.push({ chain: 'tron', tx: body });
      if (state.failBroadcast) throw new Error('fixture broadcast uncertain');
      return Response.json({ result: true, txid: body.txID });
    }
    if (path === '/walletsolidity/gettransactionbyid') return Response.json({ txID: body.value, ret: [{ contractRet: 'SUCCESS' }] });
    if (path.includes('/transactions')) {
      if (state.failHistory) throw new Error('fixture history unavailable');
      return Response.json({ data: path.endsWith('/trc20') ? [{ transaction_id: 'ab'.repeat(32), block_timestamp: 1700000000000,
        token_info: { address: CHAINS.tron.tokens[0].address }, from: TronWeb.address.fromPrivateKey('2'.repeat(64)), to: state.addresses.tron, value: '1000000' }] : [] });
    }
    assert.fail(`Unexpected fake TRON path: ${path}`);
  });
  if (!backgroundModule) {
    const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'chrome');
    globalThis.chrome = { ...fixture, storage: { local: fixture.storage } };
    try { backgroundModule = await import('../src/background/index.js'); await (await backgroundModule.background).destroy(); }
    finally { if (descriptor) Object.defineProperty(globalThis, 'chrome', descriptor); else delete globalThis.chrome; }
  }
  const background = await backgroundModule.createBackground(fixture);
  let connectedPort;
  fixture.runtime.connect = ({ name }) => {
    const front = { name, onMessage: event(), onDisconnect: event() };
    const back = { name, onMessage: event(), onDisconnect: event(), sender: { id: fixture.runtime.id, url: fixture.runtime.getURL('popup.html') } };
    let closed = false;
    front.postMessage = message => { const copy = structuredClone(message); queueMicrotask(() => { if (!closed) back.onMessage.emit(copy); }); };
    back.postMessage = message => { const copy = structuredClone(message); queueMicrotask(() => { if (!closed) front.onMessage.emit(copy); }); };
    front.disconnect = back.disconnect = () => { if (!closed) { closed = true; front.onDisconnect.emit(front); back.onDisconnect.emit(back); } };
    connectedPort = front; fixture.runtime.onConnect.emit(back); return front;
  };
  const client = connectTrusted({ runtime: fixture.runtime, page: 'popup.html' });
  t.after(async () => { client.close(); connectedPort?.disconnect(); await background.destroy(); });
  await background.vaultStore.create(password, phrase); await background.unlock(password, unlockOptions);
  state.addresses = background.walletKeys.getAddresses();
  state.recipients = { solana: state.addresses.solana, tron: TronWeb.address.fromPrivateKey('2'.repeat(64)) };
  for (const method of ['getSolanaKeypair', 'getTronPrivateKey']) {
    const original = background.walletKeys[method];
    t.mock.method(background.walletKeys, method, () => { keysUsed.push(method); return original(); });
  }
  return { background, client, fixture, values, calls, broadcasts, keysUsed, state };
}

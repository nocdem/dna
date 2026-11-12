import { BaseController } from '@metamask/base-controller';
import { ApprovalType } from '@metamask/controller-utils';
import { rpcErrors, providerErrors } from '@metamask/rpc-errors';
import { FetchRequest, Interface, JsonRpcProvider, getAddress, getBytes, formatUnits, keccak256, toQuantity, toUtf8String } from 'ethers';
import { CHAINS } from '../../../src/config.js';
import { amountUnits, rawInteger, rpc } from '../../../src/core.js';
import { assertWalletActive } from '../../../src/keys.js';
import { ethersGetUrl, endpointUrl } from '../../../src/rpc-transport.js';
import { debugLog, errorFields, hostOf, stopwatch, timed } from '../../../src/debug-log.js';
import * as adapter from '../../../src/adapters/evm.js';
import { prepareTransfer } from '../../../src/wallet.js';
import { nameReviewRows, NAME_CHECK_ROW } from '../../../src/adapters/nodus.js';
import { terminal, watchActivity } from '../../../src/activity.js';
import { EVM_NETWORKS, EVM_CHAINS, EVM_FAMILIES, WALLET_EVM_CHAINS, evmAddressKey, evmKey, evmNetworkId, isEvmTestKey } from '../constants/evm-networks.js';
import { assertSwapUsdtToken } from '../constants/swap.js';

// The USDT payment of a swap (plan section 7 step 5): the call data is encoded
// here, in the extension (the plan leaves the place to this package). The same
// function signature as the wallet's own token send, src/adapters/evm.js:6.
const erc20Transfer = new Interface(['function transfer(address,uint256) returns (bool)']);
// A swap's USDT is paid on Ethereum or on Ethereum Sepolia, the two networks the
// bot's `eth_chain_id` setting can name (plan section 15; givens item 77).
const SWAP_CHAINS = ['ethereum', 'sepolia'];
// Retained eth_* reads from permissions.js / pinned specifications.ts:104-198.
// No arbitrary node write/admin method can fall through this provider.
const READ_METHODS = new Set(['eth_blockNumber', 'eth_call', 'eth_estimateGas', 'eth_feeHistory', 'eth_gasPrice',
  'eth_getBalance', 'eth_getBlockByHash', 'eth_getBlockByNumber', 'eth_getBlockTransactionCountByHash',
  'eth_getBlockTransactionCountByNumber', 'eth_getCode', 'eth_getLogs', 'eth_getProof', 'eth_getStorageAt',
  'eth_getTransactionByBlockHashAndIndex', 'eth_getTransactionByBlockNumberAndIndex', 'eth_getTransactionByHash',
  'eth_getTransactionCount', 'eth_getTransactionReceipt', 'eth_getUncleByBlockHashAndIndex',
  'eth_getUncleByBlockNumberAndIndex', 'eth_getUncleCountByBlockHash', 'eth_getUncleCountByBlockNumber',
  'eth_getWork', 'eth_hashrate', 'eth_mining', 'eth_protocolVersion', 'net_listening', 'net_peerCount', 'web3_sha3']);

function chainConfig(chain) {
  if (!EVM_CHAINS.includes(chain)) throw rpcErrors.invalidParams('Unsupported EVM network.');
  return EVM_NETWORKS[chain];
}
// The wallet's own screens cover every network of constants/evm-networks.js.
function walletChainConfig(chain) {
  if (!WALLET_EVM_CHAINS.includes(chain)) throw rpcErrors.invalidParams('Unsupported EVM network.');
  return EVM_NETWORKS[chain];
}
function validatedEndpoint(chain, endpoint) {
  const normalized = endpointUrl(endpoint);
  return EVM_NETWORKS[chain].rpcOptions.find(option => endpointUrl(option.url) === normalized)?.url ?? normalized;
}
// Same check and wording as src/adapters/evm.js:22-24, which reads the shared
// CHAINS table and so cannot name Sepolia.
async function checkNetwork(chain, endpoint, options) {
  if (rawInteger(await rpc(endpoint, 'eth_chainId', [], options)) !== BigInt(chainConfig(chain).chainId)) throw new Error('RPC is connected to the wrong network.');
}
// Mirrors src/adapters/evm.js:28-30 at 85506fccb352392f59f1e4d1140dd0a9452b3c1c.
function ethersProvider(endpoint) {
  const transport = new FetchRequest(endpoint); transport.timeout = 15000; transport.getUrlFunc = ethersGetUrl;
  return new JsonRpcProvider(transport, undefined, { batchMaxCount: 1 });
}

// Operator-approved adaptation: sites supply to/value/data/gas themselves.
// All network, fee, nonce, balance and broadcast checks mirror the unchanged
// web-wallet adapter at the commit above, src/adapters/evm.js:22-54.
export async function prepareSiteTransaction({ chain, wallet, fields, endpoint, assertCurrent }) {
  const config = chainConfig(chain);
  if (fields.chainId !== undefined && rawInteger(fields.chainId) !== BigInt(config.chainId)) throw rpcErrors.invalidParams('Transaction is for a different network.');
  const tx = { from: getAddress(fields.from), value: rawInteger(fields.value ?? '0x0'), data: fields.data ?? '0x' };
  if (fields.to != null) tx.to = getAddress(fields.to);
  try { getBytes(tx.data); } catch { throw rpcErrors.invalidParams('Invalid transaction data.'); }
  if (tx.from !== wallet.evm.address) throw providerErrors.unauthorized();
  assertCurrent(); await checkNetwork(chain, endpoint); assertCurrent();
  const provider = ethersProvider(endpoint);
  try {
    // Adapter :34-40: pending nonce, legacy gas price, 120% estimate, balance.
    const [gas, fees, nonce, balance] = await timed('evm', 'fee-reads', { chain, host: hostOf(endpoint) }, () => Promise.all([provider.estimateGas(tx), provider.getFeeData(),
      provider.getTransactionCount(tx.from, 'pending'), provider.getBalance(tx.from)]));
    assertCurrent();
    const gasLimit = fields.gas === undefined ? gas * 120n / 100n : rawInteger(fields.gas), gasPrice = fees.gasPrice;
    if (!gasPrice || balance < gasLimit * gasPrice + tx.value) throw new Error('Insufficient native balance for amount and network fee.');
    const unsigned = { ...tx, chainId: config.chainId, nonce, gasLimit, gasPrice, type: 0 }; delete unsigned.from;
    return { fee: `Up to ${formatUnits(gasLimit * gasPrice, 18)} ${config.symbol}`, expiresAt: Date.now() + 60000, nonce,
      async send(onBroadcast) {
        // Adapter :42-50: check immediately around every asynchronous key use.
        assertCurrent(); assertWalletActive(wallet); await checkNetwork(chain, endpoint);
        assertCurrent(); assertWalletActive(wallet);
        const signed = await wallet.evm.signTransaction(unsigned);
        assertCurrent(); assertWalletActive(wallet);
        const hash = keccak256(signed);
        await onBroadcast?.({ hash, nonce }); assertCurrent(); assertWalletActive(wallet);
        const returned = await rpc(endpoint, 'eth_sendRawTransaction', [signed]);
        if (returned?.toLowerCase() !== hash.toLowerCase()) throw new Error('RPC returned a different transaction identifier.');
        debugLog('evm', 'transaction-sent', { chain, hash });
        return hash;
      } };
  } finally { provider.destroy(); }
}

// Glue for the existing filters package, which consumes sync/on/removeListener
// and getLatestBlock (eth-json-rpc-filters 9.0.0 index.js:144,174-179 and
// subscriptionManager.js:61-75). Ethers owns block polling and its cadence.
function networkClient(chain, endpoint) {
  const metadata = { status: 'unknown' }, listeners = new Set();
  let pollingProvider, previousBlock = null, destroyed = false, events = Promise.resolve();
  const provider = {
    async request({ method, params = [] }) {
      if (destroyed) throw rpcErrors.resourceUnavailable('Network connection is closed.');
      if (method === 'eth_chainId') return toQuantity(chainConfig(chain).chainId);
      if (method === 'net_version') return String(chainConfig(chain).chainId);
      if (!READ_METHODS.has(method) && method !== 'eth_sendRawTransaction') throw rpcErrors.methodNotSupported();
      try {
        await checkNetwork(chain, endpoint);
        const result = await rpc(endpoint, method, params); metadata.status = 'available'; return result;
      } catch (error) { metadata.status = 'unavailable'; throw error; }
    },
    sendAsync(request, callback) {
      provider.request(request).then(result => callback(null, { jsonrpc: '2.0', id: request.id, result }), callback);
    },
  };
  function onBlock(number) {
    const newBlock = toQuantity(number), oldBlock = previousBlock; previousBlock = newBlock;
    if (oldBlock === newBlock || oldBlock === null) return;
    for (const listener of listeners) {
      // The pinned filter callbacks are async; do not log raw provider errors.
      void Promise.resolve().then(() => listener({ oldBlock, newBlock })).catch(() => {});
    }
  }
  const blockTracker = {
    async getLatestBlock() { const block = toQuantity(rawInteger(await provider.request({ method: 'eth_blockNumber' }))); previousBlock = block; return block; },
    on(event, listener) {
      if (event !== 'sync' || destroyed) return blockTracker;
      listeners.add(listener);
      if (!pollingProvider) {
        const current = pollingProvider = ethersProvider(endpoint);
        events = events.then(() => destroyed ? undefined : current.on('block', onBlock)).catch(() => { metadata.status = 'unavailable'; });
      }
      return blockTracker;
    },
    removeListener(event, listener) {
      if (event !== 'sync') return blockTracker;
      listeners.delete(listener);
      if (!listeners.size && pollingProvider) {
        const previous = pollingProvider; pollingProvider = null;
        events = events.then(() => previous.destroy());
      }
      return blockTracker;
    },
  };
  return { provider, blockTracker, metadata, configuration: { chainId: toQuantity(chainConfig(chain).chainId) },
    destroy() { destroyed = true; listeners.clear(); const previous = pollingProvider; pollingProvider = null; events = events.then(() => previous?.destroy()); } };
}

export function createEvm({ messenger, store, approvals, permissions, lockCoordinator, getWallet, keyring, onNetworkChanged, getActivity,
  // The wallet's per-chain network choice (networks.js): the chain's selector id ('mainnet', 'sepolia', 'testnet')
  // and the way to write it, so the selector, the wallet screens and the sites' provider never disagree.
  getNetworkId = () => 'mainnet', selectWalletNetwork = async () => {} }) {
  const metadata = Object.fromEntries(['selectedChain', 'endpoints'].map(key => [key, { persist: true }]));
  const saved = store.getInitialState('EvmController', metadata);
  // A saved test-network choice is not restored: operator 2026-11-03, "hersey varsa yeniden acista mainnet" (the
  // networks.js reset), so a worker or browser restart returns to Ethereum, never to a test network.
  const selectedChain = EVM_FAMILIES.includes(saved.selectedChain) ? saved.selectedChain : 'ethereum';
  // Saved endpoints cover every network, a test network's own RPC choice included.
  const endpoints = Object.fromEntries(WALLET_EVM_CHAINS.map(chain => {
    try { return [chain, validatedEndpoint(chain, saved.endpoints?.[chain])]; }
    catch { return [chain, EVM_NETWORKS[chain].endpoint]; }
  }));
  const controller = new BaseController({ name: 'EvmController', metadata, messenger: messenger.buildChild({ namespace: 'EvmController' }), state: { selectedChain, endpoints } });
  const endpointOf = chain => controller.state.endpoints[chain];
  // The wallet's screens name a chain ('ethereum', 'bsc'); the network it is on follows the chain's selector.
  const walletKey = chain => (EVM_FAMILIES.includes(chain) ? evmKey(chain, getNetworkId(chain)) : chain);
  let client = networkClient(selectedChain, endpoints[selectedChain]), revision = 0, reviewId = 0;
  let readAbort = new AbortController();
  const reviews = new Map();
  const trackers = new Map();
  function clearReviews() { for (const review of reviews.values()) review.prepared.cancel(); reviews.clear(); }
  function close() {
    revision++; readAbort.abort(); readAbort = new AbortController();
    clearReviews(); for (const stop of trackers.values()) stop(); trackers.clear();
  }
  function activity(chain) {
    const value = getActivity(chain), signal = readAbort.signal;
    // watchActivity reads rows before checking its own stopped signal. A
    // timer already queued at lock must not enter the disposed session.
    if (!trackers.has(chain)) trackers.set(chain, watchActivity(() => signal.aborted || lockCoordinator.isLocked ? [] : value.rows(),
      () => { void value.persist().catch(() => {}); }));
    return value;
  }
  // Wallet Activity is the mainnet ledger: its rows carry no network, are saved without their endpoint and are
  // restored with the mainnet one (network-activity.js:13-14), so a test-network transaction recorded there would
  // later be tracked on mainnet. A test-network transaction therefore leaves no Activity row (my choice; the plan
  // leaves "which activity record keeps a Sepolia site transaction" to this package); the sender gets the hash.
  function assertSendable(chain) {
    if (isEvmTestKey(chain)) return undefined;
    const value = activity(chain); value.assertSendable();
    const pending = value.rows().find(row => !terminal(row.status));
    if (pending) throw new Error(`A previous send on this network has no final result yet (tx ${pending.hash}). Wait for it to resolve.`);
    return value;
  }
  async function sendRecorded(chain, transfer, send, assertCurrent) {
    const value = assertSendable(chain); let record;
    if (!value) { const hash = await send(async () => { assertCurrent(); }); assertCurrent(); return hash; }
    try {
      const hash = await send(async details => {
        assertCurrent(); assertSendable(chain);
        record = value.append(transfer, details); await value.persist(); assertCurrent();
      });
      assertCurrent(); record.note = 'Broadcast submitted; awaiting confirmation.';
      await value.persist(); return hash;
    } catch (error) {
      if (record && !lockCoordinator.isLocked) {
        record.status = 'unknown'; record.note = 'Broadcast outcome uncertain. Tracking the signed transaction; do not resend automatically.';
        await value.persist().catch(() => {});
        throw rpcErrors.internal({ message: error.message, data: { activityTracked: true } });
      }
      throw error;
    }
  }
  function capture(origin, from) {
    const wallet = getWallet(), started = revision, chain = controller.state.selectedChain, endpoint = endpointOf(chain);
    function assertCurrent() {
      lockCoordinator.assertUnlocked(); assertWalletActive(wallet);
      if (getWallet() !== wallet) throw new Error('Wallet is locked.');
      if (started !== revision) throw new Error('Network changed. Prepare the request again.');
      if (origin && (!permissions.getAccounts(origin).some(address => getAddress(address) === getAddress(from)) ||
        !permissions.getChainIds(origin).includes(toQuantity(chainConfig(chain).chainId)))) throw providerErrors.unauthorized();
    }
    assertCurrent(); return { wallet, chain, endpoint, assertCurrent };
  }
  async function approved(origin, type, requestData, assertCurrent) {
    assertCurrent();
    // Debug lines: the approval's type and origin and how long the user took; never its request data.
    debugLog('evm', 'approval-shown', { origin, type });
    const elapsed = stopwatch();
    try { await approvals.controller.addAndShowApprovalRequest({ origin, type, requestData }); }
    catch (error) { debugLog('evm', 'approval-rejected', { origin, type, ms: elapsed(), ...errorFields(error) }); throw error; }
    debugLog('evm', 'approval-approved', { origin, type, ms: elapsed() });
    assertCurrent();
  }
  function assertFresh(prepared) {
    if (!Number.isFinite(prepared.expiresAt) || Date.now() >= prepared.expiresAt) throw new Error('Review expired. Prepare the transfer again.');
  }
  function changed() {
    // Web-wallet src/app.js:2292 increments revision and closes reviews on
    // endpoint changes; pinned ethereum-chain-utils.ts:358-368 rejects pending
    // origin approvals on switches. Shared selection makes sessions stale here.
    revision++; clearReviews();
    const previous = client;
    client = networkClient(controller.state.selectedChain, endpointOf(controller.state.selectedChain));
    onNetworkChanged(client, () => client.metadata);
    previous.destroy();
  }
  async function selectProvider(chain) {
    chainConfig(chain);
    if (controller.state.selectedChain === chain) return;
    controller.update(state => { state.selectedChain = chain; }); changed(); await store.flush();
  }
  // Selecting a network (a site's switch or the settings) also sets that chain's selector, so the wallet's balance,
  // send and RPC choice are on the same network as the sites' provider.
  async function selectNetwork(chain) {
    await selectProvider(chain);
    await selectWalletNetwork(evmAddressKey(chain), evmNetworkId(chain));
  }
  // A choice in a chain's selector (networks.js) makes that network the sites' provider too.
  const followWalletNetwork = chain => selectProvider(walletKey(chain));
  // Opening the wallet resets every selector to mainnet (networks.js resetToDefaults): the provider follows.
  const resetToMainnet = () => (isEvmTestKey(controller.state.selectedChain) ? selectProvider(evmAddressKey(controller.state.selectedChain)) : undefined);
  // The wallet-side selection changed: reviews and reads made for the old network are closed.
  function walletNetworkChanged() { revision++; clearReviews(); readAbort.abort(); readAbort = new AbortController(); }
  async function setEndpoint(chain, endpoint) {
    chain = walletKey(chain); walletChainConfig(chain); endpoint = validatedEndpoint(chain, endpoint);
    if (controller.state.endpoints[chain] === endpoint) return;
    controller.update(state => { state.endpoints[chain] = endpoint; });
    changed(); await store.flush();
  }
  const walletHooks = {
    async processPersonalMessage(params, _request, context) {
      const origin = context.assertGet('origin'), session = capture(origin, params.from);
      let text = params.data;
      try { text = toUtf8String(getBytes(params.data)); } catch { /* Show the original bytes/text when UTF-8 decoding fails. */ }
      await approved(origin, ApprovalType.PersonalSign, { account: session.wallet.evm.address, chain: session.chain, text, data: params.data }, session.assertCurrent);
      const signature = await keyring.signPersonalMessage(params); session.assertCurrent(); return signature;
    },
    async processTypedMessageV4(params, _request, context) {
      const origin = context.assertGet('origin'), session = capture(origin, params.from);
      let typed;
      try { typed = typeof params.data === 'string' ? JSON.parse(params.data) : structuredClone(params.data); }
      catch { throw rpcErrors.invalidParams('Invalid typed data.'); }
      if (typed.domain?.chainId !== undefined && rawInteger(typed.domain.chainId) !== BigInt(chainConfig(session.chain).chainId)) throw rpcErrors.invalidParams('Typed data is for a different network.');
      await approved(origin, ApprovalType.EthSignTypedData, { account: session.wallet.evm.address, chain: session.chain, text: JSON.stringify(typed, null, 2) }, session.assertCurrent);
      const signature = await keyring.signTypedMessage({ from: params.from, data: typed }, 'V4'); session.assertCurrent(); return signature;
    },
    async processTransaction(fields, _request, context) {
      const origin = context.assertGet('origin'), session = capture(origin, fields.from);
      assertSendable(session.chain);
      fields = structuredClone(fields);
      const prepared = await prepareSiteTransaction({ ...session, fields });
      await approved(origin, ApprovalType.Transaction, { account: session.wallet.evm.address, chain: session.chain,
        to: fields.to ?? null, value: String(rawInteger(fields.value ?? '0x0')), data: fields.data ?? '0x', fee: prepared.fee }, session.assertCurrent);
      assertFresh(prepared);
      const own = session.wallet.addresses[evmAddressKey(session.chain)];
      const transfer = { chain: session.chain, from: own, to: fields.to ?? own,
        amount: formatUnits(rawInteger(fields.value ?? '0x0'), 18), symbol: chainConfig(session.chain).symbol, endpoint: session.endpoint };
      return sendRecorded(session.chain, transfer, record => prepared.send(record), session.assertCurrent);
    },
  };
  async function switchChain(origin, params) {
    // Pinned switch-ethereum-chain.ts:96-123; Ethereum, BSC and, since givens item 81, Ethereum Sepolia.
    if (!Array.isArray(params) || params.length !== 1 || !params[0] ||
      Object.keys(params[0]).some(key => key !== 'chainId') || !/^0x[0-9a-f]+$/i.test(params[0].chainId)) throw rpcErrors.invalidParams();
    const chain = EVM_CHAINS.find(chain => BigInt(params[0].chainId) === BigInt(chainConfig(chain).chainId));
    if (!chain) throw providerErrors.custom({ code: 4902, message: 'Unsupported EVM network.' });
    if (chain === controller.state.selectedChain) return null;
    const wallet = getWallet(), started = revision;
    const assertCurrent = () => {
      lockCoordinator.assertUnlocked(); assertWalletActive(wallet);
      if (wallet !== getWallet()) throw new Error('Wallet is locked.');
      if (started !== revision) throw new Error('Network changed. Request the switch again.');
    };
    // ethereum-chain-utils.ts:314-345 requests missing chain permission first.
    await permissions.requestChainPermission(origin, toQuantity(chainConfig(chain).chainId)); assertCurrent();
    await approved(origin, ApprovalType.SwitchEthereumChain, { account: wallet.evm.address, chain: controller.state.selectedChain, targetChain: chain }, assertCurrent);
    await selectNetwork(chain); return null;
  }
  // The Ethereum side of a swap or of a liquidity add (plan section 18 change 1; givens items 84, 88): the user's
  // typed-data signature and the USDT payment run in ONE captured session, so a lock, a network change or a lost
  // permission between them throws. The caller (swap.js) posts the signed request to the bot in between and calls
  // `send()` only after it reached the bot. Typed data is built by the caller from the plan's fixed types (6.4.3),
  // never taken from the site; the domain chain id is this session's network.
  function swapSession(origin, from) {
    const session = capture(origin, from);
    if (!SWAP_CHAINS.includes(session.chain)) throw rpcErrors.invalidParams('Swap payments are made on Ethereum or Ethereum Sepolia. Switch the network first.');
    const config = chainConfig(session.chain), account = session.wallet.evm.address;
    return {
      chain: session.chain, chainId: config.chainId, account,
      async signTyped(typed) {
        session.assertCurrent();
        await approved(origin, ApprovalType.EthSignTypedData, { account, chain: session.chain, text: JSON.stringify(typed, null, 2) }, session.assertCurrent);
        const signature = await keyring.signTypedMessage({ from: account, data: typed }, 'V4'); session.assertCurrent(); return signature;
      },
      // Prepares the USDT `transfer(to, amount)` of `token`, shows it for approval (exact amount and destinations)
      // and returns `send()`, which signs, records and broadcasts exactly that prepared transaction.
      async approveUsdtPayment({ token, to, amount, bot }) {
        assertSwapUsdtToken(session.chain, token); // the screen says USDT: only the pinned USDT contract is paid
        assertSendable(session.chain);
        const data = erc20Transfer.encodeFunctionData('transfer', [to, amount]);
        const prepared = await prepareSiteTransaction({ ...session, fields: { from: account, to: token, value: '0x0', data, chainId: toQuantity(config.chainId) } });
        await approved(origin, 'nodus_swapPayment', { account, chain: session.chain, title: 'Pay USDT for a swap', rows: [
          ['Network', config.name], ['From', account], ['Pay to', getAddress(to)], ['Token contract', getAddress(token)],
          ['Amount', `${formatUnits(amount, 6)} USDT (${amount} units of 6 decimals)`], ['Network fee', prepared.fee], ['Bot that received the request', bot],
        ], note: 'The bot has received your signed request. This payment is sent next.' }, session.assertCurrent);
        assertFresh(prepared);
        const own = session.wallet.addresses[evmAddressKey(session.chain)];
        const transfer = { chain: session.chain, from: own, to: getAddress(to), amount: formatUnits(amount, 6), symbol: 'USDT', endpoint: session.endpoint };
        // Once the pending record is durable (the record callback returned) the transaction is about to be broadcast: any
        // later failure, whatever the wallet state became, is marked `broadcastReached` so swap.js reports the payment as
        // unknown. A failure before that point carries no mark (the payment was not sent).
        let reached = false;
        return { send: async () => {
          try { return await sendRecorded(session.chain, transfer, record => prepared.send(async details => { await record(details); reached = true; }), session.assertCurrent); }
          catch (error) { if (reached && error && typeof error === 'object') error.broadcastReached = true; throw error; }
        } };
      },
    };
  }
  // A test network lists its native coin only: no pinned source names a token contract there.
  async function testBalances(key, address, endpoint, signal) {
    const config = chainConfig(key);
    getAddress(address); await checkNetwork(key, endpoint, { signal });
    const native = rawInteger(await rpc(endpoint, 'eth_getBalance', [address, 'latest'], { signal }));
    return [{ symbol: config.symbol, balance: formatUnits(native, config.decimals) }];
  }
  // A native-coin send on a test network, prepared and confirmed like a site transaction on it (the shared wallet
  // adapter reads the mainnet table only). The recipient is an address; no Activity row is kept (assertSendable).
  async function prepareTestSend(key, fields) {
    const config = chainConfig(key), session = capture(), endpoint = controller.state.endpoints[key];
    if (fields.symbol !== config.symbol) throw new Error(`Only ${config.symbol} can be sent on ${config.name}.`);
    let to; try { to = getAddress(String(fields.to ?? '').trim()); } catch { throw new Error(`Invalid ${config.name} address.`); }
    const units = amountUnits(fields.amount, config.decimals), from = session.wallet.evm.address;
    const prepared = await prepareSiteTransaction({ chain: key, wallet: session.wallet, fields: { from, to, value: toQuantity(units) }, endpoint, assertCurrent: session.assertCurrent });
    session.assertCurrent();
    const id = String(++reviewId), transfer = { chain: key, networkName: config.name, from, to, amount: fields.amount, symbol: config.symbol,
      fee: prepared.fee, nonce: prepared.nonce, expiresAt: prepared.expiresAt, cancel() {}, confirm: record => prepared.send(record) };
    clearReviews(); reviews.set(id, { prepared: transfer, assertCurrent: session.assertCurrent });
    return { id, chain: fields.chain, to, named: undefined, amount: fields.amount, symbol: config.symbol, fee: prepared.fee, expiresAt: prepared.expiresAt, review: evmReviewRows(transfer) };
  }
  return { controller, walletHooks, switchChain, selectNetwork, setEndpoint, followWalletNetwork, resetToMainnet, walletNetworkChanged, swapSession, lock: close,
    get client() { return client; },
    getState: () => structuredClone(controller.state),
    async getBalances(chain) {
      const key = walletKey(chain); walletChainConfig(key);
      const wallet = getWallet(), endpoint = controller.state.endpoints[key], signal = readAbort.signal;
      let rows;
      if (isEvmTestKey(key)) rows = await testBalances(key, wallet.addresses[evmAddressKey(key)], endpoint, signal);
      else { activity(key); rows = await adapter.balances(key, wallet.addresses[key], endpoint, { signal }); }
      signal.throwIfAborted();
      assertWalletActive(wallet); if (getWallet() !== wallet) throw new Error('Wallet is locked.');
      return rows;
    },
    async prepareSend(fields) {
      const key = walletKey(fields.chain); walletChainConfig(key);
      if (isEvmTestKey(key)) return prepareTestSend(key, fields);
      assertSendable(fields.chain);
      const session = capture(), endpoint = controller.state.endpoints[fields.chain];
      // Keep the imported adapter unchanged. Its wallet checks after network,
      // signing and onBroadcast awaits (src/adapters/evm.js:42-49) must also
      // validate this extension's captured network, including the final check
      // after onBroadcast: checking only in that callback leaves a yield open.
      const wallet = {
        addresses: session.wallet.addresses,
        get evm() { session.assertCurrent(); return session.wallet.evm; },
        get locked() { session.assertCurrent(); return session.wallet.locked; },
        get nodusClient() { session.assertCurrent(); return getActivity(fields.chain).client; },
      };
      const prepared = await prepareTransfer({ ...fields, endpoint, wallet }); session.assertCurrent();
      const id = String(++reviewId), result = { id, chain: fields.chain, to: prepared.to, named: prepared.named, amount: fields.amount, symbol: fields.symbol, fee: prepared.fee, expiresAt: prepared.expiresAt };
      result.review = evmReviewRows(prepared);
      clearReviews(); reviews.set(id, { prepared, assertCurrent: session.assertCurrent }); return result;
    },
    async confirmSend(id) {
      lockCoordinator.assertUnlocked();
      const review = reviews.get(id); if (!review) throw new Error('This review is already closed.'); reviews.delete(id);
      review.assertCurrent(); return sendRecorded(review.prepared.chain, review.prepared, record => review.prepared.confirm(record), review.assertCurrent);
    },
    cancelSend(id) { const review = reviews.get(id); review?.prepared.cancel(); reviews.delete(id); },
    destroy() { close(); client.destroy(); controller.destroy(); },
  };
}

// src/app.js:2325-2339, unchanged row wording and order.
export function evmReviewRows(transfer) {
  const rows = [['Network', transfer.networkName ?? `${CHAINS[transfer.chain].name} mainnet`], ['From', transfer.from]];
  if (transfer.named) rows.push(...nameReviewRows(transfer.named, { via: 'the address published in the owner’s signed profile' }));
  rows.push(['To', getAddress(transfer.to)]);
  if (transfer.named) rows.push(NAME_CHECK_ROW);
  else if (/^0x[0-9a-f]{40}$/.test(transfer.to)) rows.push(['Address check', 'No checksum in what you typed — compare the form above with your source character by character.']);
  return [...rows, ['Asset', transfer.symbol], ['Amount', transfer.amount], ['Network fee', transfer.fee],
    ['Transaction number (nonce)', transfer.nonce], ['Review expires', new Date(transfer.expiresAt).toLocaleTimeString()]];
}

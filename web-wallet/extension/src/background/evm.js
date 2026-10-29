import { BaseController } from '@metamask/base-controller';
import { ApprovalType } from '@metamask/controller-utils';
import { rpcErrors, providerErrors } from '@metamask/rpc-errors';
import { FetchRequest, JsonRpcProvider, getAddress, getBytes, formatUnits, keccak256, toQuantity, toUtf8String } from 'ethers';
import { CHAINS } from '../../../src/config.js';
import { rawInteger, rpc } from '../../../src/core.js';
import { assertWalletActive } from '../../../src/keys.js';
import { ethersGetUrl, endpointUrl } from '../../../src/rpc-transport.js';
import * as adapter from '../../../src/adapters/evm.js';
import { prepareTransfer } from '../../../src/wallet.js';
import { nameReviewRows, NAME_CHECK_ROW } from '../../../src/adapters/nodus.js';
import { terminal, watchActivity } from '../../../src/activity.js';

const EVM_CHAINS = ['ethereum', 'bsc'];
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
  return CHAINS[chain];
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
  assertCurrent(); await adapter.checkNetwork(chain, endpoint); assertCurrent();
  const provider = ethersProvider(endpoint);
  try {
    // Adapter :34-40: pending nonce, legacy gas price, 120% estimate, balance.
    const [gas, fees, nonce, balance] = await Promise.all([provider.estimateGas(tx), provider.getFeeData(),
      provider.getTransactionCount(tx.from, 'pending'), provider.getBalance(tx.from)]);
    assertCurrent();
    const gasLimit = fields.gas === undefined ? gas * 120n / 100n : rawInteger(fields.gas), gasPrice = fees.gasPrice;
    if (!gasPrice || balance < gasLimit * gasPrice + tx.value) throw new Error('Insufficient native balance for amount and network fee.');
    const unsigned = { ...tx, chainId: config.chainId, nonce, gasLimit, gasPrice, type: 0 }; delete unsigned.from;
    return { fee: `Up to ${formatUnits(gasLimit * gasPrice, 18)} ${config.symbol}`, expiresAt: Date.now() + 60000,
      async send(onBroadcast) {
        // Adapter :42-50: check immediately around every asynchronous key use.
        assertCurrent(); assertWalletActive(wallet); await adapter.checkNetwork(chain, endpoint);
        assertCurrent(); assertWalletActive(wallet);
        const signed = await wallet.evm.signTransaction(unsigned);
        assertCurrent(); assertWalletActive(wallet);
        const hash = keccak256(signed);
        await onBroadcast?.({ hash, nonce }); assertCurrent(); assertWalletActive(wallet);
        const returned = await rpc(endpoint, 'eth_sendRawTransaction', [signed]);
        if (returned?.toLowerCase() !== hash.toLowerCase()) throw new Error('RPC returned a different transaction identifier.');
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
      if (method === 'eth_chainId') return toQuantity(CHAINS[chain].chainId);
      if (method === 'net_version') return String(CHAINS[chain].chainId);
      if (!READ_METHODS.has(method) && method !== 'eth_sendRawTransaction') throw rpcErrors.methodNotSupported();
      try {
        await adapter.checkNetwork(chain, endpoint);
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
  return { provider, blockTracker, metadata, configuration: { chainId: toQuantity(CHAINS[chain].chainId) },
    destroy() { destroyed = true; listeners.clear(); const previous = pollingProvider; pollingProvider = null; events = events.then(() => previous?.destroy()); } };
}

export function createEvm({ messenger, store, approvals, permissions, lockCoordinator, getWallet, keyring, onNetworkChanged, getActivity }) {
  const metadata = Object.fromEntries(['selectedChain', 'endpoints'].map(key => [key, { persist: true, usedInUi: true, includeInStateLogs: false, includeInDebugSnapshot: false }]));
  const saved = store.getInitialState('EvmController', metadata);
  const selectedChain = EVM_CHAINS.includes(saved.selectedChain) ? saved.selectedChain : 'ethereum';
  const endpoints = Object.fromEntries(EVM_CHAINS.map(chain => {
    try { return [chain, endpointUrl(saved.endpoints?.[chain])]; }
    catch { return [chain, CHAINS[chain].endpoint]; }
  }));
  const controller = new BaseController({ name: 'EvmController', metadata, messenger: messenger.buildChild({ namespace: 'EvmController' }), state: { selectedChain, endpoints } });
  let client = networkClient(selectedChain, endpoints[selectedChain]), revision = 0, reviewId = 0;
  const reviews = new Map();
  const trackers = new Map();
  function clearReviews() { for (const review of reviews.values()) review.prepared.cancel(); reviews.clear(); }
  function close() { revision++; clearReviews(); for (const stop of trackers.values()) stop(); trackers.clear(); }
  function activity(chain) {
    const value = getActivity(chain);
    if (!trackers.has(chain)) trackers.set(chain, watchActivity(() => value.rows(), () => { void value.persist().catch(() => {}); }));
    return value;
  }
  function assertSendable(chain) {
    const value = activity(chain); value.assertSendable();
    const pending = value.rows().find(row => !terminal(row.status));
    if (pending) throw new Error(`A previous send on this network has no final result yet (tx ${pending.hash}). Wait for it to resolve, or mark it as abandoned in Activity.`);
    return value;
  }
  async function sendRecorded(chain, transfer, send, assertCurrent) {
    const value = assertSendable(chain); let record;
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
    const wallet = getWallet(), started = revision, chain = controller.state.selectedChain, endpoint = controller.state.endpoints[chain];
    function assertCurrent() {
      lockCoordinator.assertUnlocked(); assertWalletActive(wallet);
      if (getWallet() !== wallet) throw new Error('Wallet is locked.');
      if (started !== revision) throw new Error('Network changed. Prepare the request again.');
      if (origin && (!permissions.getAccounts(origin).some(address => getAddress(address) === getAddress(from)) ||
        !permissions.getChainIds(origin).includes(toQuantity(CHAINS[chain].chainId)))) throw providerErrors.unauthorized();
    }
    assertCurrent(); return { wallet, chain, endpoint, assertCurrent };
  }
  async function approved(origin, type, requestData, assertCurrent) {
    assertCurrent();
    await approvals.controller.addAndShowApprovalRequest({ origin, type, requestData });
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
    client = networkClient(controller.state.selectedChain, controller.state.endpoints[controller.state.selectedChain]);
    onNetworkChanged(client, () => client.metadata);
    previous.destroy();
  }
  async function selectNetwork(chain) {
    chainConfig(chain);
    if (controller.state.selectedChain === chain) return;
    controller.update(state => { state.selectedChain = chain; }); changed(); await store.flush();
  }
  async function setEndpoint(chain, endpoint) {
    chainConfig(chain); endpoint = endpointUrl(endpoint);
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
      if (typed.domain?.chainId !== undefined && rawInteger(typed.domain.chainId) !== BigInt(CHAINS[session.chain].chainId)) throw rpcErrors.invalidParams('Typed data is for a different network.');
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
      const transfer = { chain: session.chain, from: session.wallet.addresses[session.chain], to: fields.to ?? session.wallet.addresses[session.chain],
        amount: formatUnits(rawInteger(fields.value ?? '0x0'), 18), symbol: CHAINS[session.chain].symbol, endpoint: session.endpoint };
      return sendRecorded(session.chain, transfer, record => prepared.send(record), session.assertCurrent);
    },
  };
  async function switchChain(origin, params) {
    // Pinned switch-ethereum-chain.ts:96-123; only Ethereum/BSC per dispatch.
    if (!Array.isArray(params) || params.length !== 1 || !params[0] ||
      Object.keys(params[0]).some(key => key !== 'chainId') || !/^0x[0-9a-f]+$/i.test(params[0].chainId)) throw rpcErrors.invalidParams();
    const chain = EVM_CHAINS.find(chain => BigInt(params[0].chainId) === BigInt(CHAINS[chain].chainId));
    if (!chain) throw providerErrors.custom({ code: 4902, message: 'Unsupported EVM network.' });
    if (chain === controller.state.selectedChain) return null;
    const wallet = getWallet(), started = revision;
    const assertCurrent = () => {
      lockCoordinator.assertUnlocked(); assertWalletActive(wallet);
      if (wallet !== getWallet()) throw new Error('Wallet is locked.');
      if (started !== revision) throw new Error('Network changed. Request the switch again.');
    };
    // ethereum-chain-utils.ts:314-345 requests missing chain permission first.
    await permissions.requestChainPermission(origin, toQuantity(CHAINS[chain].chainId)); assertCurrent();
    await approved(origin, ApprovalType.SwitchEthereumChain, { account: wallet.evm.address, chain: controller.state.selectedChain, targetChain: chain }, assertCurrent);
    await selectNetwork(chain); return null;
  }
  return { controller, walletHooks, switchChain, selectNetwork, setEndpoint, lock: close,
    get client() { return client; },
    getState: () => structuredClone(controller.state),
    async getBalances(chain) {
      chainConfig(chain); const wallet = getWallet(), endpoint = controller.state.endpoints[chain];
      activity(chain);
      const rows = await adapter.balances(chain, wallet.addresses[chain], endpoint);
      assertWalletActive(wallet); if (getWallet() !== wallet) throw new Error('Wallet is locked.');
      return rows;
    },
    async prepareSend(fields) {
      chainConfig(fields.chain);
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
  const rows = [['Network', `${CHAINS[transfer.chain].name} mainnet`], ['From', transfer.from]];
  if (transfer.named) rows.push(...nameReviewRows(transfer.named, { via: 'the address published in the owner’s signed profile' }));
  rows.push(['To', getAddress(transfer.to)]);
  if (transfer.named) rows.push(NAME_CHECK_ROW);
  else if (/^0x[0-9a-f]{40}$/.test(transfer.to)) rows.push(['Address check', 'No checksum in what you typed — compare the form above with your source character by character.']);
  return [...rows, ['Asset', transfer.symbol], ['Amount', transfer.amount], ['Network fee', transfer.fee],
    ['Transaction number (nonce)', transfer.nonce], ['Review expires', new Date(transfer.expiresAt).toLocaleTimeString()]];
}

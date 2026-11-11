import test from 'node:test';
import assert from 'node:assert/strict';
import { Transaction } from 'ethers';
import { CHAIN_NETWORKS, DEFAULT_NETWORKS, chainNetwork } from '../src/constants/networks.js';
import { EVM_NETWORKS, SEPOLIA, BSC_TESTNET } from '../src/constants/evm-networks.js';
import { extensionCapabilitiesFor } from '../src/constants/capabilities.js';
import { setup, password, unlockOptions } from './solana-tron-fixture.js';

// Approved extension plan section 5.6: Ethereum's selector lists Mainnet and Sepolia, BNB Smart Chain's lists Mainnet
// and its test network; choosing one moves that chain's balance, send, RPC choice and the sites' provider together.
// Environment: Node >=22.14, pinned packages; every Ethereum RPC call is a stub answering by host (below); no flags,
// no network, no output files. The stub proves the extension asked the right endpoint and chain id, NOT that the
// public RPC hosts serve those networks (the pinned chain lists name them: eip155-11155111.json, eip155-97.json).
const HOSTS = { 'ethereum-rpc.publicnode.com': 1, 'ethereum-sepolia-rpc.publicnode.com': 11155111, 'bsc-testnet-rpc.publicnode.com': 97, 'data-seed-prebsc-1-s1.bnbchain.org:8545': 97,'bsc-dataseed.binance.org': 56 };
const to = '0x00000000000000000000000000000000000000bb';

async function evmSetup(t) {
  const f = await setup(t), inner = globalThis.fetch, calls = [], raw = [], answers = { chainId: undefined };
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    const host = new URL(String(url)).host;
    if (!(host in HOSTS)) return inner(url, options);
    const req = JSON.parse(typeof options.body === 'string' ? options.body : new TextDecoder().decode(options.body));
    assert.equal(Array.isArray(req), false); calls.push({ host, method: req.method });
    let result;
    switch (req.method) {
      case 'eth_chainId': result = `0x${(answers.chainId ?? HOSTS[host]).toString(16)}`; break;
      case 'eth_blockNumber': result = '0x10'; break;
      case 'eth_getBalance': result = '0xde0b6b3a7640000'; break;
      case 'eth_call': result = `0x${'0'.repeat(64)}`; break;
      case 'eth_estimateGas': result = '0x5208'; break;
      case 'eth_gasPrice': case 'eth_maxPriorityFeePerGas': result = '0x3b9aca00'; break;
      case 'eth_getTransactionCount': result = '0x7'; break;
      case 'eth_getBlockByNumber': result = { number: '0x10', hash: `0x${'11'.repeat(32)}`, parentHash: `0x${'22'.repeat(32)}`, timestamp: '0x1', nonce: '0x0000000000000000', difficulty: '0x0', gasLimit: '0x1c9c380', gasUsed: '0x0', miner: to, extraData: '0x', transactions: [] }; break;
      case 'eth_sendRawTransaction': raw.push({ host, tx: req.params[0] }); result = Transaction.from(req.params[0]).hash; break;
      default: assert.fail(`Unexpected fixture method ${req.method}`);
    }
    return new Response(JSON.stringify({ id: req.id, jsonrpc: '2.0', result }), { headers: { 'content-type': 'application/json' } });
  });
  return { ...f, calls, raw, answers, hostsOf: method => calls.filter(call => call.method === method).map(call => call.host) };
}

// Proves the selector lists exactly Mainnet plus the test network for the two chains, with the pinned chain ids and
// endpoints, and that every chain still starts on mainnet (plan 5.6 a and d). Can falsely pass if a test network
// were added but the default order changed; the defaults are read from the live state too.
test('Ethereum lists Mainnet and Sepolia, BNB Smart Chain lists Mainnet and its test network, all start on mainnet', async t => {
  assert.deepEqual(CHAIN_NETWORKS.ethereum.map(network => network.id), ['mainnet', 'sepolia']);
  assert.deepEqual(CHAIN_NETWORKS.bsc.map(network => network.id), ['mainnet', 'testnet']);
  assert.equal(chainNetwork('ethereum', 'sepolia').endpoint, 'https://ethereum-sepolia-rpc.publicnode.com');
  assert.equal(chainNetwork('bsc', 'testnet').endpoint, 'https://bsc-testnet-rpc.publicnode.com');
  assert.equal(SEPOLIA.chainId, 11155111); assert.equal(BSC_TESTNET.chainId, 97);
  assert.equal(chainNetwork('ethereum', 'sepolia').endpoint, SEPOLIA.endpoint, 'one definition of Sepolia');
  assert.equal(EVM_NETWORKS.sepolia, SEPOLIA);
  for (const network of [...SEPOLIA.rpcOptions, ...BSC_TESTNET.rpcOptions]) assert.doesNotMatch(network.url, /\$\{|v2\/|v3\//, 'no API-key endpoint');
  assert.deepEqual(SEPOLIA.tokens, []); assert.deepEqual(BSC_TESTNET.tokens, []);
  assert.equal(DEFAULT_NETWORKS.ethereum, 'mainnet'); assert.equal(DEFAULT_NETWORKS.bsc, 'mainnet');
  const f = await evmSetup(t), state = await f.client.request('getState');
  assert.equal(state.networks.ethereum, 'mainnet'); assert.equal(state.networks.bsc, 'mainnet'); assert.equal(state.evm.selectedChain, 'ethereum');
  assert.equal(extensionCapabilitiesFor('ethereum', 'sepolia').history, false); assert.equal(extensionCapabilitiesFor('ethereum', 'mainnet').history, extensionCapabilitiesFor('ethereum').history);
});

// Proves choosing Sepolia moves the balance read, the sites' provider and the RPC choice to Sepolia (endpoint and chain
// id 0xaa36a7), lists the native coin only (no token calls), and that choosing Mainnet again restores the mainnet
// reads with their tokens. Can falsely pass if balances came from the old network: the host of every eth_getBalance
// call is compared.
test('choosing Sepolia moves balances, the sites provider and the RPC choice; Mainnet is unchanged', async t => {
  const f = await evmSetup(t);
  const mainnetRows = await f.client.request('getEvmBalances', ['ethereum']);
  assert.ok(mainnetRows.length > 1, 'mainnet lists its tokens'); assert.deepEqual(f.hostsOf('eth_getBalance'), ['ethereum-rpc.publicnode.com']);
  f.calls.length = 0;
  await f.client.request('setChainNetwork', ['ethereum', 'sepolia']);
  let state = await f.client.request('getState');
  assert.equal(state.networks.ethereum, 'sepolia'); assert.equal(state.evm.selectedChain, 'sepolia');
  assert.deepEqual(await f.client.request('getEvmBalances', ['ethereum']), [{ symbol: 'ETH', balance: '1.0' }]);
  assert.deepEqual(f.hostsOf('eth_getBalance'), ['ethereum-sepolia-rpc.publicnode.com']); assert.equal(f.hostsOf('eth_call').length, 0);
  assert.equal((await f.background.engine.getNetworkState()).chainId, '0xaa36a7');
  await f.background.evm.client.provider.request({ method: 'eth_blockNumber' });
  assert.ok(f.calls.some(call => call.method === 'eth_blockNumber' && call.host === 'ethereum-sepolia-rpc.publicnode.com'));
  await f.client.request('setEvmEndpoint', ['ethereum', SEPOLIA.endpoint]);
  assert.equal((await f.client.request('getState')).evm.endpoints.sepolia, SEPOLIA.endpoint, 'the RPC choice written for "ethereum" lands on the network it is on');
  assert.equal((await f.client.request('getState')).evm.endpoints.ethereum, EVM_NETWORKS.ethereum.endpoint, 'the mainnet RPC choice is untouched');
  f.calls.length = 0;
  await f.client.request('setChainNetwork', ['ethereum', 'mainnet']);
  state = await f.client.request('getState');
  assert.equal(state.networks.ethereum, 'mainnet'); assert.equal(state.evm.selectedChain, 'ethereum');
  assert.equal((await f.client.request('getEvmBalances', ['ethereum'])).length, mainnetRows.length);
  assert.deepEqual(f.hostsOf('eth_getBalance'), ['ethereum-rpc.publicnode.com']);
  assert.equal((await f.background.engine.getNetworkState()).chainId, '0x1');
});

// Proves BNB Smart Chain's test network (chain id 97) is reached the same way: its own endpoint, chain id 0x61, the
// native tBNB row only, and a wrong chain id from the endpoint is refused. Can falsely pass if the wrong-network
// check is skipped; the control answers a different chain id for the same host and must reject.
test('choosing the BNB Smart Chain test network moves balances and provider to chain id 97 and checks the chain id', async t => {
  const f = await evmSetup(t);
  await f.client.request('setChainNetwork', ['bsc', 'testnet']);
  const state = await f.client.request('getState');
  assert.equal(state.networks.bsc, 'testnet'); assert.equal(state.evm.selectedChain, 'bsctestnet');
  assert.deepEqual(await f.client.request('getEvmBalances', ['bsc']), [{ symbol: 'tBNB', balance: '1.0' }]);
  assert.deepEqual(f.hostsOf('eth_getBalance'), ['bsc-testnet-rpc.publicnode.com']);
  assert.equal((await f.background.engine.getNetworkState()).chainId, '0x61');
  await f.client.request('setEvmEndpoint', ['bsc', BSC_TESTNET.rpcOptions[1].url]);
  const endpoints = (await f.client.request('getState')).evm.endpoints;
  assert.equal(endpoints.bsctestnet, BSC_TESTNET.rpcOptions[1].url, 'the RPC choice lands on the test network'); assert.equal(endpoints.bsc, EVM_NETWORKS.bsc.endpoint);
  f.answers.chainId = 56;
  await assert.rejects(f.client.request('getEvmBalances', ['bsc']), /wrong network/);
});

// Proves a native send on a test network is prepared for its chain id, shown with its network name, broadcast through
// its endpoint and leaves no mainnet Activity row; a coin of another network is refused before any RPC. Can falsely
// pass if the transaction were built for mainnet: the decoded raw transaction's chain id and host are compared.
test('a native send on Sepolia is built for chain id 11155111 and sent through the Sepolia endpoint', async t => {
  const f = await evmSetup(t);
  await f.client.request('setChainNetwork', ['ethereum', 'sepolia']);
  await assert.rejects(f.client.request('prepareEvmSend', [{ chain: 'ethereum', symbol: 'USDT', to, amount: '1' }]), /Only ETH can be sent/);
  await assert.rejects(f.client.request('prepareEvmSend', [{ chain: 'ethereum', symbol: 'ETH', to: 'alice', amount: '1' }]), /Invalid Ethereum Sepolia address/);
  const review = await f.client.request('prepareEvmSend', [{ chain: 'ethereum', symbol: 'ETH', to, amount: '0.01' }]);
  assert.deepEqual(review.review[0], ['Network', 'Ethereum Sepolia']);
  const hash = await f.client.request('confirmEvmSend', [review.id]);
  assert.equal(f.raw.length, 1); assert.equal(f.raw[0].host, 'ethereum-sepolia-rpc.publicnode.com');
  const transaction = Transaction.from(f.raw[0].tx);
  assert.equal(transaction.chainId, 11155111n); assert.equal(transaction.to.toLowerCase(), to); assert.equal(transaction.value, 10n ** 16n); assert.equal(hash, transaction.hash);
  assert.equal(f.background.nodus.chainActivity('ethereum').rows().length, 0, 'no mainnet Activity row for a test-network send');
});

// Proves opening the wallet again returns every chain, and the sites' provider, to mainnet (plan 5.6 d; operator
// 2026-11-03 "hersey varsa yeniden acista mainnet"). Can falsely pass if the lock step did nothing; the selection is
// read before the lock.
test('locking and opening the wallet again returns Ethereum and BNB Smart Chain and the provider to mainnet', async t => {
  const f = await evmSetup(t);
  await f.client.request('setChainNetwork', ['ethereum', 'sepolia']); await f.client.request('setChainNetwork', ['bsc', 'testnet']);
  assert.equal(f.background.evm.getState().selectedChain, 'bsctestnet'); assert.equal(f.background.networks.get('ethereum').id, 'sepolia');
  await f.background.lock(); await f.background.unlock(password, unlockOptions);
  assert.equal(f.background.networks.get('ethereum').id, 'mainnet'); assert.equal(f.background.networks.get('bsc').id, 'mainnet');
  assert.equal(f.background.evm.getState().selectedChain, 'ethereum');
});

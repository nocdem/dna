// Tests of adapter.js, the one module that calls the extension's new site methods, against a stub extension provider
// that answers the four methods of the extension package (worktree main-swapext: nodus_swapHoldTransfer,
// nodus_swapSendNodusToUsdt, nodus_swapSendUsdtToNodus, nodus_swapSendLiquidityAdd; parameter objects and error.data
// as read in src/background/swap.js and nodus.js:529-540).
//
// PROVES:
//   - each call goes out as provider.request({ method, params: [object] }) with exactly the extension's keys, raw
//     amounts and the request number as decimal strings (no BigInt), botUrl the site origin without a path;
//   - the order: (Ethereum calls) wallet_switchEthereumChain first; (NODUS -> USDT, liquidity add) the hold first, then
//     the sending call with the text built from the transferId and chainId the hold returned and the holdId;
//   - a request that did not reach the bot (error.data { delivered: false, paid: false }) is passed on as such, the
//     extension is called once and not retried;
//   - nothing is sent when a constant is missing, the USDT contract is unknown, or an input is not in an agreed form.
// ENVIRONMENT: node >= 20, `node --test website/swap-site/test/`; no browser, no network, no environment variables.
// LEAVES BEHIND: nothing.
// FALSE PASS: the stub provider does not sign, post, pay or check texts; its answers follow the extension source as
//   read, not the running extension, so a drift in the extension passes here. The text the site builds is compared with
//   the plan layout here, not run through the extension's parser (swap-texts.js).

import test from 'node:test';
import assert from 'node:assert/strict';
import { createAdapter, AdapterError, EXTENSION_CALLS } from '../adapter.js';

const ETH = `0x${'4b'.repeat(20)}`;
const NODUS_ADDR = 'ab'.repeat(64);
const TRANSFER = '0d'.repeat(64);
const CHAIN = '5c'.repeat(32);
const TOKEN = `0x${'a7'.repeat(20)}`;
const BOT = 'https://swap.nodusnetwork.io';
const HOLD = { holdId: 'hold-1', transferId: TRANSFER, chainId: CHAIN, expiryHeight: 12345 };

function stubProvider(answers = {}) {
  const calls = [];
  return {
    calls,
    request: async ({ method, params }) => {
      calls.push({ method, params });
      const a = answers[method];
      if (a instanceof Error) throw a;
      return a === undefined ? null : a;
    },
  };
}
const withProvider = provider => async () => provider;
const methods = p => p.calls.map(c => c.method);

const USDT_INPUT = {
  botUrl: BOT, ethereumAddress: ETH, nodusAddress: NODUS_ADDR, token: TOKEN, payTo: `0x${'fe'.repeat(20)}`,
  amountUsdtRaw: 100000000n, minimumNodusRaw: 123610410000n, requestNumber: '4242', ethChainId: '11155111',
};
const NODUS_INPUT = {
  botUrl: BOT, nodusAddress: NODUS_ADDR, ethereumAddress: ETH, payTo: 'fd'.repeat(64),
  amountNodusRaw: 50000000000000n, minimumUsdtRaw: 96515000n, requestNumber: '4242',
};
const ADD_INPUT = {
  botUrl: BOT, ethereumAddress: ETH, nodusAddress: NODUS_ADDR, token: TOKEN, payEthereum: `0x${'fe'.repeat(20)}`, payNodus: 'fd'.repeat(64),
  usdtAmountRaw: '10000000', nodusAmountRaw: '10000000000000', requestNumber: '88', ethChainId: '11155111',
};

test('the shipped constants are the extension\'s four method names', () => {
  assert.equal(EXTENSION_CALLS.usdtToNodus.method, 'nodus_swapSendUsdtToNodus');
  assert.equal(EXTENSION_CALLS.nodusHold.method, 'nodus_swapHoldTransfer');
  assert.equal(EXTENSION_CALLS.nodusToUsdt.method, 'nodus_swapSendNodusToUsdt');
  assert.equal(EXTENSION_CALLS.liquidityAdd.method, 'nodus_swapSendLiquidityAdd');
});

test('USDT -> NODUS: switch to the bot\'s chain, then one call with exactly the extension\'s keys', async () => {
  const provider = stubProvider({ nodus_swapSendUsdtToNodus: { delivered: true, paid: true, hash: '0xabc' } });
  const adapter = createAdapter({ getProvider: withProvider(provider) });
  const r = await adapter.usdtToNodus(USDT_INPUT);
  assert.equal(r.delivered, true);
  assert.deepEqual(methods(provider), ['wallet_switchEthereumChain', 'nodus_swapSendUsdtToNodus']);
  assert.deepEqual(provider.calls[0].params, [{ chainId: '0xaa36a7' }]);        // 11155111 (Sepolia)
  const params = provider.calls[1].params;
  assert.equal(params.length, 1);
  assert.deepEqual(params[0], {
    from: ETH, botUrl: BOT, token: TOKEN, payTo: USDT_INPUT.payTo, destination: NODUS_ADDR,
    amount: '100000000', minimumToReceive: '123610410000', requestNumber: '4242',
  });
  assert.deepEqual(Object.keys(params[0]).sort(), ['amount', 'botUrl', 'destination', 'from', 'minimumToReceive', 'payTo', 'requestNumber', 'token']);
  assert.doesNotMatch(params[0].botUrl, /\/amm/);
});

test('NODUS -> USDT: hold first; the text carries the hold\'s ids; the send call gets the holdId, botUrl and text', async () => {
  const provider = stubProvider({ nodus_swapHoldTransfer: HOLD, nodus_swapSendNodusToUsdt: { delivered: true, paid: true } });
  const adapter = createAdapter({ getProvider: withProvider(provider) });
  const r = await adapter.nodusToUsdt(NODUS_INPUT);
  assert.equal(r.delivered, true);
  assert.deepEqual(methods(provider), ['nodus_swapHoldTransfer', 'nodus_swapSendNodusToUsdt']);   // no Ethereum switch
  assert.deepEqual(provider.calls[0].params, [{ account: NODUS_ADDR, to: 'fd'.repeat(64), amount: '50000000000000' }]);
  const sent = provider.calls[1].params[0];
  assert.deepEqual(Object.keys(sent).sort(), ['botUrl', 'holdId', 'text']);
  assert.equal(sent.holdId, 'hold-1');
  assert.equal(sent.botUrl, BOT);
  assert.equal(sent.text, [
    'Nodus Swap: NODUS to USDT request',
    `Sender: ${NODUS_ADDR}`,
    `Destination: ${ETH}`,
    'Amount: 500000.00000000 NODUS',
    'Minimum To Receive: 96.515000 USDT',
    `Transfer ID: ${TRANSFER}`,
    `Chain ID: ${CHAIN}`,
    'Request Number: 4242',
  ].join('\n'));
});

test('liquidity add: switch, hold to the Foundation\'s Nodus address, then one call with the flat add parameters', async () => {
  const provider = stubProvider({ nodus_swapHoldTransfer: HOLD, nodus_swapSendLiquidityAdd: { delivered: true } });
  const adapter = createAdapter({ getProvider: withProvider(provider) });
  const r = await adapter.liquidityAdd(ADD_INPUT);
  assert.equal(r.delivered, true);
  assert.deepEqual(methods(provider), ['wallet_switchEthereumChain', 'nodus_swapHoldTransfer', 'nodus_swapSendLiquidityAdd']);
  assert.deepEqual(provider.calls[1].params, [{ account: NODUS_ADDR, to: ADD_INPUT.payNodus, amount: '10000000000000' }]);
  const sent = provider.calls[2].params[0];
  assert.deepEqual(Object.keys(sent).sort(), ['botUrl', 'ethereumAddress', 'holdId', 'nodusAmount', 'payTo', 'requestNumber', 'text', 'token', 'usdtAmount']);
  assert.equal(sent.holdId, 'hold-1');
  assert.equal(sent.payTo, ADD_INPUT.payEthereum);
  assert.equal(sent.token, TOKEN);
  assert.equal(sent.usdtAmount, '10000000');
  assert.equal(sent.nodusAmount, '10000000000000');
  assert.equal(sent.requestNumber, '88');
  assert.equal(sent.text, [
    'Nodus Swap: liquidity add request',
    `Ethereum Address: ${ETH}`,
    `Nodus Address: ${NODUS_ADDR}`,
    'USDT Amount: 10.000000 USDT',
    'NODUS Amount: 100000.00000000 NODUS',
    `Transfer ID: ${TRANSFER}`,
    `Chain ID: ${CHAIN}`,
    'Request Number: 88',
  ].join('\n'));
});

test('a request that did not reach the bot: delivered false, paid false, one call, no retry', async () => {
  const err = Object.assign(new Error('The request did not reach the bot. Nothing was paid.'),
    { code: -32603, data: { delivered: false, paid: false, answered: false, reason: 'unreachable' } });
  const provider = stubProvider({ nodus_swapSendUsdtToNodus: err });
  const adapter = createAdapter({ getProvider: withProvider(provider) });
  await assert.rejects(adapter.usdtToNodus(USDT_INPUT), e =>
    e instanceof AdapterError && e.code === 'extension_error' && e.delivered === false && e.paid === false && e.answered === false && e.cause === err);
  assert.equal(provider.calls.filter(c => c.method === 'nodus_swapSendUsdtToNodus').length, 1);   // never retried automatically
  const refused = Object.assign(new Error('The bot did not take the request (number_reused). Nothing was paid.'),
    { data: { delivered: false, paid: false, answered: true, reason: 'number_reused' } });
  const p2 = stubProvider({ nodus_swapHoldTransfer: HOLD, nodus_swapSendNodusToUsdt: refused });
  await assert.rejects(createAdapter({ getProvider: withProvider(p2) }).nodusToUsdt(NODUS_INPUT), e => e.delivered === false && e.reason === 'number_reused' && e.answered === true);
  assert.equal(p2.calls.filter(c => c.method === 'nodus_swapSendNodusToUsdt').length, 1);
});

test('a failure after delivery keeps what the extension says was paid; a user rejection keeps its code', async () => {
  const after = Object.assign(new Error('The bot has your request but the payment was not completed'), { code: 4001, data: { delivered: true, paid: false } });
  const provider = stubProvider({ nodus_swapSendUsdtToNodus: after });
  await assert.rejects(createAdapter({ getProvider: withProvider(provider) }).usdtToNodus(USDT_INPUT),
    e => e.extensionCode === 4001 && e.delivered === true && e.paid === false);
});

test('a failing hold or a refused chain switch stops before the next extension call', async () => {
  let provider = stubProvider({ nodus_swapHoldTransfer: new Error('Wallet is locked.') });
  await assert.rejects(createAdapter({ getProvider: withProvider(provider) }).nodusToUsdt(NODUS_INPUT), e => e.code === 'extension_error');
  assert.deepEqual(methods(provider), ['nodus_swapHoldTransfer']);
  provider = stubProvider({ wallet_switchEthereumChain: Object.assign(new Error('Unsupported EVM network.'), { code: 4902 }) });
  await assert.rejects(createAdapter({ getProvider: withProvider(provider) }).usdtToNodus(USDT_INPUT), e => e.extensionCode === 4902);
  assert.deepEqual(methods(provider), ['wallet_switchEthereumChain']);
  provider = stubProvider({ wallet_switchEthereumChain: Object.assign(new Error('x'), { code: 4902 }) });
  await assert.rejects(createAdapter({ getProvider: withProvider(provider) }).liquidityAdd(ADD_INPUT), e => e.extensionCode === 4902);
  assert.deepEqual(methods(provider), ['wallet_switchEthereumChain']);   // no held transfer was opened
});

test('nothing is sent without the USDT contract, with a missing constant, or with an input the extension would refuse', async () => {
  let provider = stubProvider();
  let adapter = createAdapter({ getProvider: withProvider(provider) });
  await assert.rejects(adapter.usdtToNodus({ ...USDT_INPUT, token: undefined }), e => e.code === 'no_token');
  await assert.rejects(adapter.liquidityAdd({ ...ADD_INPUT, token: '0x12' }), e => e.code === 'no_token');
  assert.deepEqual(provider.calls, []);
  provider = stubProvider();
  adapter = createAdapter({ getProvider: withProvider(provider), calls: { ...EXTENSION_CALLS, nodusToUsdt: { method: null, params: null } } });
  await assert.rejects(adapter.nodusToUsdt(NODUS_INPUT), e => e.code === 'not_configured');
  assert.deepEqual(provider.calls, []);                 // not even the hold
});

test('no extension: no_extension, nothing sent', async () => {
  const adapter = createAdapter({ getProvider: async () => null });
  await assert.rejects(adapter.usdtToNodus(USDT_INPUT), e => e.code === 'no_extension');
  await assert.rejects(adapter.nodusToUsdt(NODUS_INPUT), e => e.code === 'no_extension');
});

// Tests of adapter.js, the one module that calls the extension's new site methods, against a stub extension provider
// that answers the four methods of the extension package (worktree main-swapext: nodus_swapHoldTransfer,
// nodus_swapSendNodusToUsdt, nodus_swapSendUsdtToNodus, nodus_swapSendLiquidityAdd; parameter objects and error.data
// as read in src/background/swap.js and nodus.js:529-540).
//
// PROVES:
//   - each call goes out as provider.request({ method, params: [object] }) with exactly the extension's keys, raw
//     amounts and the request number as decimal strings (no BigInt), botUrl the bot's origin (https://62.171.136.77) without a path;
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
import { BOT_ORIGIN } from '../bot.js';

const ETH = `0x${'4b'.repeat(20)}`;
const NODUS_ADDR = 'ab'.repeat(64);
const TRANSFER = '0d'.repeat(64);
const CHAIN = '5c'.repeat(32);
const TOKEN = `0x${'a7'.repeat(20)}`;
const BOT = BOT_ORIGIN;   // the bot's own origin (https://62.171.136.77), not the page's: the extension posts there
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

// PROVES: the botUrl each of the three extension calls carries is exactly https://62.171.136.77, an origin with no path
//   (what `new URL(...).origin` returns for it), and not the page's own origin.
// FALSE PASS: the input's botUrl is what the test passes in (BOT_ORIGIN); that swap.js hands the flow BOT_ORIGIN is
//   checked textually in flow.test.js, and the extension's own acceptance of an IP origin is not run here.
test('every extension call carries botUrl https://62.171.136.77 as a pure origin, never the page origin', async () => {
  assert.equal(BOT, 'https://62.171.136.77');
  assert.equal(new URL(BOT).origin, BOT);
  const sent = [];
  const provider = { request: async ({ method, params }) => { sent.push({ method, params }); return method === 'nodus_swapHoldTransfer' ? HOLD : { ok: true }; } };
  const adapter = createAdapter({ getProvider: async () => provider });
  await adapter.usdtToNodus(USDT_INPUT);
  await adapter.nodusToUsdt(NODUS_INPUT);
  await adapter.liquidityAdd(ADD_INPUT);
  const withBot = sent.filter(s => s.params[0] && 'botUrl' in s.params[0]);
  assert.equal(withBot.length, 3);
  for (const s of withBot) {
    assert.equal(s.params[0].botUrl, 'https://62.171.136.77');
    assert.notEqual(s.params[0].botUrl, 'https://swap.nodusnetwork.io');
  }
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

// PROVES (operator 2026-11-12, givens item 111: the page said only "approve" for the whole sequence): each adapter
// call reports the step it is about to take through the optional second argument { onStep }, BEFORE the extension
// call it describes, so the page can name the window the user is waiting for. The report and the extension calls are
// interleaved in one log, so the order is the real order: USDT -> NODUS switch, then one call; NODUS -> USDT hold
// (step 1 of 2), then the send call (step 2 of 2); liquidity add switch, hold (1 of 2), then the add call (2 of 2).
// Also proves: the calls, their parameters and their order are the same with and without the callback, the callback
// is optional (the tests above never pass it), and a callback that throws changes nothing.
// FALSE PASS: the log is made by the stub provider and the test callback; the step names are the ones this module
// emits, not checked against what the extension really opens (the extension's windows are read from its source).
function logged(provider) {
  const log = [];
  const request = provider.request;
  provider.request = async arg => { log.push(`call:${arg.method}`); return request(arg); };
  return { log, onStep: step => log.push(`step:${step.id}${step.n ? `:${step.n}/${step.of}` : ''}`) };
}

test('step reports: USDT -> NODUS announces the chain switch, then the one call with its two windows', async () => {
  const provider = stubProvider({ nodus_swapSendUsdtToNodus: { delivered: true, paid: true } });
  const { log, onStep } = logged(provider);
  await createAdapter({ getProvider: withProvider(provider) }).usdtToNodus(USDT_INPUT, { onStep });
  assert.deepEqual(log, ['step:switch', 'call:wallet_switchEthereumChain', 'step:usdt_windows', 'call:nodus_swapSendUsdtToNodus']);
});

test('step reports: NODUS -> USDT announces the hold as step 1 of 2, then the signature and send as step 2 of 2', async () => {
  const provider = stubProvider({ nodus_swapHoldTransfer: HOLD, nodus_swapSendNodusToUsdt: { delivered: true, paid: true } });
  const { log, onStep } = logged(provider);
  await createAdapter({ getProvider: withProvider(provider) }).nodusToUsdt(NODUS_INPUT, { onStep });
  assert.deepEqual(log, ['step:hold:1/2', 'call:nodus_swapHoldTransfer', 'step:sign_send:2/2', 'call:nodus_swapSendNodusToUsdt']);
});

test('step reports: liquidity add announces switch, hold (1 of 2), then the add call with its three windows (2 of 2)', async () => {
  const provider = stubProvider({ nodus_swapHoldTransfer: HOLD, nodus_swapSendLiquidityAdd: { delivered: true } });
  const { log, onStep } = logged(provider);
  await createAdapter({ getProvider: withProvider(provider) }).liquidityAdd(ADD_INPUT, { onStep });
  assert.deepEqual(log, ['step:switch', 'call:wallet_switchEthereumChain', 'step:hold:1/2', 'call:nodus_swapHoldTransfer',
    'step:add_windows:2/2', 'call:nodus_swapSendLiquidityAdd']);
});

test('step reports: the extension calls are identical with and without the callback, and a throwing callback changes nothing', async () => {
  const answers = { nodus_swapHoldTransfer: HOLD, nodus_swapSendNodusToUsdt: { delivered: true, paid: true } };
  const plain = stubProvider(answers), watched = stubProvider(answers), thrower = stubProvider(answers);
  await createAdapter({ getProvider: withProvider(plain) }).nodusToUsdt(NODUS_INPUT);
  await createAdapter({ getProvider: withProvider(watched) }).nodusToUsdt(NODUS_INPUT, { onStep: () => {} });
  const r = await createAdapter({ getProvider: withProvider(thrower) }).nodusToUsdt(NODUS_INPUT, { onStep: () => { throw new Error('page bug'); } });
  assert.equal(r.delivered, true);
  assert.deepEqual(watched.calls, plain.calls);
  assert.deepEqual(thrower.calls, plain.calls);
});

test('step reports: a refused configuration or token reports no step and sends nothing', async () => {
  const provider = stubProvider();
  const { log, onStep } = logged(provider);
  await assert.rejects(createAdapter({ getProvider: withProvider(provider) }).usdtToNodus({ ...USDT_INPUT, token: undefined }, { onStep }), e => e.code === 'no_token');
  assert.deepEqual(log, []);   // no window opened, so no step announced
});

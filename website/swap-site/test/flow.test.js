// Tests of the swap and liquidity flows (flow.js) against a stub bot (a recording `fetch`) and a stub adapter, in the
// order of givens item 68 (plan section 19, line 666).
//
// PROVES:
//   - the bot is asked for a price only on the user's press (nothing but GET /amm/status before it), and not at all
//     for an amount that is not a valid number;
//   - the bot's number and estimated fee are kept and shown exactly as given (no recomputation, no check);
//   - the extension (adapter) is asked to sign and pay only after the user's yes, once, with the user's typed amount,
//     the minimum computed from number, fee and tolerance, and the bot's request number and pay-to address;
//   - a refusal, a rejection or a missing extension stops the flow with plain words and starts no polling;
//   - the bot's refusal words, "busy" included, reach the user in plain words;
//   - polling is bounded, never says "failed" for a non-final state, and stops at a final one;
//   - the withdraw is signed with the existing method and posted by the site; the liquidity add goes through the adapter;
//   - no part of the site checks a signature of the bot's answer (source check below).
// ENVIRONMENT: node >= 20, `node --test website/swap-site/test/`; no browser, no network, no environment variables.
// LEAVES BEHIND: nothing.
// FALSE PASS: the stub bot and the stub adapter follow the plan and amm_http.h as read, not the running bot or
//   extension; the amm_http.h shapes can drift from the stub. The source check is textual: it finds the words it
//   looks for, not every way of verifying something. The UI wiring (swap.js) is not exercised here.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createSwapFlow, POLL_MAX, describeAdapterError } from '../flow.js';
import { createBotClient } from '../bot.js';
import { AdapterError } from '../adapter.js';

const ETH = `0x${'4b'.repeat(20)}`;
const NODUS_ADDR = 'ab'.repeat(64);
const CHAIN = '5c'.repeat(32);
const TOKEN = `0x${'a7'.repeat(20)}`;   // a stand-in USDT contract: /amm/status does not carry it
const ACCOUNTS = { nodus: { address: NODUS_ADDR, publicKey: `0x${'cd'.repeat(2592)}` }, ethereum: ETH };
const STATUS = {
  swapsPaused: false, liquidityPaused: false, payoutsPaused: false, stopped: false, inflightUsdt: '0', roomUsdt: '500000000',
  reserves: { nodus: '3000000000000000', usdt: '3000000000' },
  settings: { swapMinUsdt: '1000000', swapMaxUsdt: '100000000', inflightMaxUsdt: '500000000', approvalValidSeconds: '300', commission: '0', ethChainId: '11155111', eip712Name: 'Nodus Swap', expectedOrigin: 'https://swap.nodusnetwork.io' },
  foundationEthereum: `0x${'fe'.repeat(20)}`, foundationNodus: 'fd'.repeat(64), nodusChainId: CHAIN,
};
const QUOTE = {
  approved: true, direction: 'usdt_to_nodus', amount: '100000000', number: '124860000000', estimatedFee: '1000000',
  requestNumber: '4242', validUntil: '1700000300', payTo: `0x${'fe'.repeat(20)}`,
};

// A recording fetch. routes: { 'GET /amm/status': body | (body) => body, ... }; a body is [httpStatus, json].
function stubFetch(routes) {
  const calls = [];
  const fn = async (url, init = {}) => {
    const method = init.method ?? 'GET';
    const key = `${method} ${url}`;
    calls.push({ key, body: init.body });
    let hit = routes[key];
    if (hit === undefined) hit = routes[`${method} ${url.replace(/\/amm\/swap\/.*/, '/amm/swap/*')}`];
    if (hit === undefined) throw new Error(`no route for ${key}`);
    if (typeof hit === 'function') hit = hit(init.body);
    if (hit === 'network-error') throw new TypeError('fetch failed');
    const [status, json] = hit;
    return { status, json: async () => { if (json === 'not-json') throw new SyntaxError('x'); return json; } };
  };
  fn.calls = calls;
  return fn;
}

function stubAdapter(behaviour = {}) {
  const calls = [];
  const rec = name => async input => {
    calls.push({ name, input });
    if (behaviour[name]) return behaviour[name](input);
    return { delivered: true };
  };
  return { calls, usdtToNodus: rec('usdtToNodus'), nodusToUsdt: rec('nodusToUsdt'), liquidityAdd: rec('liquidityAdd') };
}

// settings: fields merged into STATUS.settings; noToken: do not give the usdtToken option.
function makeFlow({ routes, adapter = stubAdapter(), signText, pollMax, sleep, random, settings, noToken } = {}) {
  const status = settings ? { ...STATUS, settings: { ...STATUS.settings, ...settings } } : STATUS;
  const fetch = stubFetch({ 'GET /amm/status': [200, status], ...routes });
  const sleeps = [];
  const flow = createSwapFlow({
    bot: createBotClient({ fetch, base: '/amm' }), adapter, signText, botUrl: 'https://swap.nodusnetwork.io', usdtToken: noToken ? undefined : TOKEN,
    sleep: sleep ?? (async ms => { sleeps.push(ms); }), pollMax, pollIntervalMs: 5000, random,
  });
  flow.setAccounts(ACCOUNTS);
  return { flow, fetch, adapter, sleeps };
}

test('before the user presses: only GET /amm/status has been sent; the press sends the one question', async () => {
  const { flow, fetch } = makeFlow({ routes: { 'POST /amm/quote': [200, QUOTE] } });
  const s = await flow.loadStatus();
  assert.equal(s.ok, true);
  assert.deepEqual(fetch.calls.map(c => c.key), ['GET /amm/status']);       // reading the price asks nothing of the quote route
  // the user types, flips, picks a tolerance: those are not calls into the flow at all; the bot is still unasked
  assert.equal(fetch.calls.filter(c => c.key === 'POST /amm/quote').length, 0);
  const r = await flow.press({ direction: 'usdt_to_nodus', amountText: '100' });
  assert.equal(r.ok, true);
  const quoteCalls = fetch.calls.filter(c => c.key === 'POST /amm/quote');
  assert.equal(quoteCalls.length, 1);
  assert.deepEqual(JSON.parse(quoteCalls[0].body), { direction: 'usdt_to_nodus', amount: '100000000' }); // 100 USDT = 10^8 raw
  assert.deepEqual(Object.keys(JSON.parse(quoteCalls[0].body)), ['direction', 'amount']);
});

test('an amount that is not a valid number sends nothing to the bot', async () => {
  const { flow, fetch } = makeFlow({ routes: { 'POST /amm/quote': [200, QUOTE] } });
  for (const bad of ['', 'abc', '0', '1.0000001', '-5']) {
    const r = await flow.press({ direction: 'usdt_to_nodus', amountText: bad });
    assert.equal(r.ok, false, bad);
    assert.equal(r.local, true, bad);
    assert.ok(r.text.length > 5);
  }
  assert.deepEqual(fetch.calls, []);
});

test('NODUS -> USDT question: the NODUS amount has 8 decimals', async () => {
  const { flow, fetch } = makeFlow({ routes: { 'POST /amm/quote': [200, { ...QUOTE, direction: 'nodus_to_usdt', amount: '50000000000000', number: '49500000' }] } });
  await flow.press({ direction: 'nodus_to_usdt', amountText: '500000' });
  assert.deepEqual(JSON.parse(fetch.calls[0].body), { direction: 'nodus_to_usdt', amount: '50000000000000' });
});

test('the bot\'s number and fee are kept as given, even when they match nothing the site could compute', async () => {
  // reserves give 10000 NODUS per USDT, so 100 USDT "should" be about 10^6 NODUS; the bot says otherwise, and the site shows the bot's word.
  const odd = { ...QUOTE, number: '7', estimatedFee: '3', signature: '0xdeadbeef', whatever: 'x' };
  const { flow } = makeFlow({ routes: { 'POST /amm/quote': [200, odd] } });
  await flow.loadStatus();
  const r = await flow.press({ direction: 'usdt_to_nodus', amountText: '100' });
  assert.equal(r.ok, true);
  assert.equal(r.quote.number, '7');
  assert.equal(r.quote.estimatedFee, '3');
  assert.equal(r.quote.requestNumber, '4242');
  assert.equal(r.quote.validUntil, '1700000300');
});

test('the adapter is not called until the user\'s yes; then once, with the typed amount and the computed minimum', async () => {
  const adapter = stubAdapter();
  const { flow } = makeFlow({ adapter, routes: { 'POST /amm/quote': [200, QUOTE] } });
  await flow.loadStatus();
  await flow.press({ direction: 'usdt_to_nodus', amountText: '100' });
  assert.equal(adapter.calls.length, 0);                                   // price shown, nothing signed or paid
  // the user moves the tolerance: only the displayed minimum changes
  assert.equal(flow.minimumFor(100), 123610410000n);
  assert.equal(adapter.calls.length, 0);
  const r = await flow.confirm({ toleranceBps: 100 });
  assert.equal(r.ok, true);
  assert.equal(r.requestNumber, '4242');
  assert.equal(adapter.calls.length, 1);
  const { name, input } = adapter.calls[0];
  assert.equal(name, 'usdtToNodus');
  assert.deepEqual(input, {
    botUrl: 'https://swap.nodusnetwork.io',    // origin, no path: the extension appends /amm/swap
    ethereumAddress: ETH, nodusAddress: NODUS_ADDR, token: TOKEN, payTo: QUOTE.payTo,
    amountUsdtRaw: 100000000n,                 // what the user typed, not the bot's echo
    minimumNodusRaw: 123610410000n,            // (124,860,000,000 - 1,000,000) x 9,900 / 10,000, hand-derived in logic.test.js
    requestNumber: '4242',                     // the bot's number for this question
    ethChainId: '11155111',
  });
});

test('NODUS -> USDT yes: the adapter gets the NODUS amount and the USDT minimum', async () => {
  const adapter = stubAdapter();
  const quote = { ...QUOTE, direction: 'nodus_to_usdt', amount: '50000000000000', number: '100000000', estimatedFee: '3000000', payTo: 'fd'.repeat(64) };
  const { flow } = makeFlow({ adapter, routes: { 'POST /amm/quote': [200, quote] } });
  await flow.loadStatus();
  await flow.press({ direction: 'nodus_to_usdt', amountText: '500000' });
  const r = await flow.confirm({ toleranceBps: 50 });
  assert.equal(r.ok, true);
  assert.equal(adapter.calls.length, 1);
  assert.equal(adapter.calls[0].name, 'nodusToUsdt');
  assert.deepEqual(adapter.calls[0].input, {
    botUrl: 'https://swap.nodusnetwork.io', nodusAddress: NODUS_ADDR, ethereumAddress: ETH, payTo: 'fd'.repeat(64),
    amountNodusRaw: 50000000000000n,
    minimumUsdtRaw: 96515000n,                 // (100,000,000 - 3,000,000) x 9,950 / 10,000
    requestNumber: '4242',
  });
});

test('no yes without a price, an account or a status: the adapter is never called', async () => {
  const adapter = stubAdapter();
  const { flow } = makeFlow({ adapter, routes: {} });
  assert.equal((await flow.confirm({ toleranceBps: 0 })).ok, false);       // no price asked yet
  assert.equal((await flow.confirmAdd()).ok, false);
  assert.equal(adapter.calls.length, 0);
});

test('a changed amount clears the old price: its yes cannot be given', async () => {
  const adapter = stubAdapter();
  const { flow } = makeFlow({ adapter, routes: { 'POST /amm/quote': [200, QUOTE] } });
  await flow.loadStatus();
  await flow.press({ direction: 'usdt_to_nodus', amountText: '100' });
  flow.clearQuote('swap');
  assert.equal((await flow.confirm({ toleranceBps: 0 })).ok, false);
  assert.equal(adapter.calls.length, 0);
});

test('the adapter\'s failure ends the flow in plain words: not configured, no extension, rejected, passed-on refusal', async () => {
  const cases = [
    [new AdapterError('not_configured', 'x'), /not available yet/, undefined],
    [new AdapterError('no_extension', 'x'), /not found/, undefined],
    [new AdapterError('extension_error', 'User rejected', { extensionCode: 4001 }), /rejected/, undefined],
    [new AdapterError('extension_error', 'x', { reason: 'busy' }), /busy/i, undefined],
    [new AdapterError('extension_error', 'x', { reason: 'open_approval', openRequestNumber: '77' }), /open swap/, '77'],
    [new AdapterError('extension_error', 'Network down'), /Network down/, undefined],
    // the extension's delivery result (givens item 88): the request did not reach the bot, nothing was paid
    [new AdapterError('extension_error', 'x', { delivered: false, paid: false, answered: false }), /did not reach the bot\. Nothing was paid/, undefined],
    [new AdapterError('extension_error', 'x', { delivered: false, paid: false, answered: true, reason: 'number_reused' }), /did not take the request \(number_reused\)\. Nothing was paid/, undefined],
    [new AdapterError('no_token', 'x'), /USDT contract/, undefined],
  ];
  for (const [err, re, open] of cases) {
    const adapter = stubAdapter({ usdtToNodus: () => { throw err; } });
    const { flow, fetch } = makeFlow({ adapter, routes: { 'POST /amm/quote': [200, QUOTE] } });
    await flow.loadStatus();
    await flow.press({ direction: 'usdt_to_nodus', amountText: '100' });
    const before = fetch.calls.length;
    const r = await flow.confirm({ toleranceBps: 100 });
    assert.equal(r.ok, false);
    assert.match(r.text, re);
    assert.equal(r.openRequestNumber, open);
    assert.equal(fetch.calls.length, before, 'a failed yes must not start polling or any other bot call');
  }
  assert.match(describeAdapterError({ code: 4001 }).text, /rejected/);   // a raw provider error with code 4001
});

test('every refusal word of the quote route reaches the user in plain words, "busy" included, as HTTP 200 or 400', async () => {
  const words = ['paused', 'stopped', 'below_minimum', 'above_maximum', 'inflight_full', 'no_liquidity', 'cannot_pay', 'unavailable', 'busy', 'bad_request', 'internal'];
  for (const reason of words) {
    const { flow } = makeFlow({ routes: { 'POST /amm/quote': [reason === 'bad_request' ? 400 : 200, { approved: false, reason }] } });
    const r = await flow.press({ direction: 'usdt_to_nodus', amountText: '100' });
    assert.equal(r.ok, false);
    assert.equal(r.reason, reason);
    assert.ok(!r.text.includes('_') && !r.text.startsWith('The bot refused:'), `${reason}: ${r.text}`);
    assert.equal(flow.state.quote, null);
  }
  const { flow } = makeFlow({ routes: { 'POST /amm/quote': [200, { approved: false, reason: 'busy' }] } });
  assert.match((await flow.press({ direction: 'usdt_to_nodus', amountText: '1' })).text, /busy.*try again later/i);
});

test('an unreachable bot or an answer that is not JSON: plain words, nothing signed', async () => {
  for (const hit of ['network-error', [502, 'not-json'], [200, 'not-json']]) {
    const adapter = stubAdapter();
    const { flow } = makeFlow({ adapter, routes: { 'POST /amm/quote': hit } });
    const r = await flow.press({ direction: 'usdt_to_nodus', amountText: '100' });
    assert.equal(r.ok, false);
    assert.match(r.reason, /unreachable|bad_answer/);
    assert.equal(adapter.calls.length, 0);
  }
});

test('loadStatus keeps the answer; an unreadable one is refused', async () => {
  const good = makeFlow({ routes: {} });
  assert.equal((await good.flow.loadStatus()).ok, true);
  assert.equal(good.flow.state.status.settings.ethChainId, '11155111');
  const bad = makeFlow({ routes: { 'GET /amm/status': [200, { hello: 1 }] } });
  assert.equal((await bad.flow.loadStatus()).ok, false);
  const down = makeFlow({ routes: { 'GET /amm/status': 'network-error' } });
  assert.equal((await down.flow.loadStatus()).reason, 'unreachable');
});

test('follow: a state that is not final stays "pending" and the number of reads is bounded', async () => {
  const { flow, fetch, sleeps } = makeFlow({ pollMax: 4, routes: { 'GET /amm/swap/*': [200, { requestNumber: '4242', state: 'counted' }] } });
  const seen = [];
  const r = await flow.follow('4242', u => seen.push(u));
  assert.equal(r.final, false);
  assert.equal(r.exhausted, true);
  assert.equal(fetch.calls.filter(c => c.key.startsWith('GET /amm/swap/')).length, 4);   // exactly the bound
  assert.equal(fetch.calls[0].key, 'GET /amm/swap/4242');
  assert.equal(sleeps.length, 3);                                                          // between reads, not after the last
  assert.equal(seen.length, 4);
  for (const u of seen) { assert.equal(u.info.kind, 'pending'); assert.doesNotMatch(u.info.text, /fail/i); }
  assert.ok(POLL_MAX >= 1 && Number.isInteger(POLL_MAX));
});

test('follow stops at the first final state', async () => {
  const states = ['approved', 'paid_waiting_depth', 'counted', 'payout_pending', 'paid'];
  let i = 0;
  const { flow, fetch } = makeFlow({ pollMax: 50, routes: { 'GET /amm/swap/*': () => [200, { requestNumber: '4242', state: states[i++], output: '10', networkFee: '1', paid: '9' }] } });
  const r = await flow.follow('4242');
  assert.equal(r.final, true);
  assert.equal(r.info.kind, 'done');
  assert.equal(fetch.calls.length, 5);
  assert.equal(r.answer.paid, '9');
});

test('follow: a refund is final and carries the bot\'s reason; an unknown number or an unreachable bot is pending', async () => {
  const refund = makeFlow({ routes: { 'GET /amm/swap/*': [200, { requestNumber: '4242', state: 'refunded', reason: 'below your minimum' }] } });
  const r = await refund.flow.follow('4242');
  assert.equal(r.final, true);
  assert.equal(r.info.kind, 'refunded');
  assert.equal(r.answer.reason, 'below your minimum');
  const unknown = makeFlow({ pollMax: 2, routes: { 'GET /amm/swap/*': [404, { found: false, reason: 'unknown_number' }] } });
  const u = await unknown.flow.follow('9');
  assert.equal(u.final, false);
  assert.equal(u.info.kind, 'pending');
  const down = makeFlow({ pollMax: 2, routes: { 'GET /amm/swap/*': 'network-error' } });
  const d = await down.flow.follow('9');
  assert.equal(d.final, false);
  assert.doesNotMatch(d.info.text, /fail/i);
});

test('withdraw: the Nodus key signs the text through the existing method, the site posts it', async () => {
  const signed = [];
  const signText = async (text, address) => { signed.push({ text, address }); return `0x${'ee'.repeat(4627)}`; };
  const { flow, fetch } = makeFlow({ signText, random: () => '31337', routes: { 'POST /amm/liquidity/withdraw': [200, { received: true, requestNumber: '31337' }] } });
  await flow.loadStatus();
  const r = await flow.withdraw({ basisPoints: 2500 });
  assert.equal(r.ok, true);
  assert.equal(r.requestNumber, '31337');
  const expectedText = [
    'Nodus Swap: liquidity withdraw request', `Ethereum Address: ${ETH}`, `Nodus Address: ${NODUS_ADDR}`,
    'Basis Points: 2500', `Chain ID: ${CHAIN}`, 'Request Number: 31337',
  ].join('\n');
  assert.deepEqual(signed, [{ text: expectedText, address: NODUS_ADDR }]);
  const post = fetch.calls.find(c => c.key === 'POST /amm/liquidity/withdraw');
  const body = JSON.parse(post.body);
  assert.deepEqual(Object.keys(body), ['text', 'publicKey', 'signature']);
  assert.equal(Buffer.from(body.text.slice(2), 'hex').toString('utf8'), expectedText);
  assert.equal(body.publicKey, ACCOUNTS.nodus.publicKey);
  assert.equal(body.signature, `0x${'ee'.repeat(4627)}`);
});

test('withdraw: refusals, bad basis points and a rejected signature', async () => {
  const sign = async () => `0x${'ee'.repeat(4627)}`;
  const refused = makeFlow({ signText: sign, random: () => '1', routes: { 'POST /amm/liquidity/withdraw': [200, { received: false, reason: 'no_position' }] } });
  await refused.flow.loadStatus();
  const r = await refused.flow.withdraw({ basisPoints: 100 });
  assert.equal(r.ok, false);
  assert.match(r.text, /no liquidity position/i);
  let signCalls = 0;
  const { flow, fetch } = makeFlow({ signText: async () => { signCalls++; return 'x'; }, routes: {} });
  await flow.loadStatus();
  for (const bps of [0, 10001, NaN, 1.5]) assert.equal((await flow.withdraw({ basisPoints: bps })).ok, false);
  assert.equal(signCalls, 0);
  assert.deepEqual(fetch.calls.map(c => c.key), ['GET /amm/status']);
  const rejected = makeFlow({ signText: async () => { throw Object.assign(new Error('denied'), { code: 4001 }); }, routes: {} });
  await rejected.flow.loadStatus();
  const rr = await rejected.flow.withdraw({ basisPoints: 100 });
  assert.equal(rr.ok, false);
  assert.match(rr.text, /rejected/);
  assert.equal(rejected.fetch.calls.filter(c => c.key.startsWith('POST')).length, 0);
});

test('liquidity add: the question carries one side; the exact pair is shown; the adapter runs only on the yes', async () => {
  const pair = { approved: true, usdtAmount: '10000000', nodusAmount: '10000000000000', requestNumber: '88', validUntil: '1700000300', payEthereum: `0x${'fe'.repeat(20)}`, payNodus: 'fd'.repeat(64) };
  const adapter = stubAdapter();
  const { flow, fetch } = makeFlow({ adapter, routes: { 'POST /amm/liquidity/quote': [200, pair] } });
  await flow.loadStatus();
  const r = await flow.pressAdd({ side: 'nodus', amountText: '100000' });
  assert.equal(r.ok, true);
  assert.deepEqual(JSON.parse(fetch.calls.find(c => c.key === 'POST /amm/liquidity/quote').body), { side: 'nodus', amount: '10000000000000' });
  assert.equal(adapter.calls.length, 0);
  const y = await flow.confirmAdd();
  assert.equal(y.ok, true);
  assert.equal(adapter.calls.length, 1);
  assert.deepEqual(adapter.calls[0].input, {
    botUrl: 'https://swap.nodusnetwork.io', ethereumAddress: ETH, nodusAddress: NODUS_ADDR, token: TOKEN,
    payEthereum: pair.payEthereum, payNodus: pair.payNodus, usdtAmountRaw: '10000000', nodusAmountRaw: '10000000000000',
    requestNumber: '88', ethChainId: '11155111',
  });
});

test('liquidity add below 100,000 NODUS: the bot\'s refusal is shown with the minimum, nothing is signed', async () => {
  const adapter = stubAdapter();
  const { flow } = makeFlow({ adapter, routes: { 'POST /amm/liquidity/quote': [200, { approved: false, reason: 'below_minimum' }] } });
  const r = await flow.pressAdd({ side: 'nodus', amountText: '99999' });
  assert.equal(r.ok, false);
  assert.match(r.text, /100,000 NODUS/);
  assert.equal((await flow.confirmAdd()).ok, false);
  assert.equal(adapter.calls.length, 0);
  const busy = makeFlow({ routes: { 'POST /amm/liquidity/quote': [200, { approved: false, reason: 'busy' }] } });
  assert.match((await busy.flow.pressAdd({ side: 'usdt', amountText: '10' })).text, /busy/i);
});

test('no part of the site checks a signature of the bot or loads the verifying site SDK (givens items 65, 69)', () => {
  const dir = new URL('../', import.meta.url);
  for (const file of ['swap-logic.js', 'bot.js', 'flow.js', 'swap.js', 'extension.js', 'adapter.js']) {
    const src = readFileSync(new URL(file, dir), 'utf8');
    assert.doesNotMatch(src, /from\s+['"][^'"]*(site-sdk|nodus-site-verify)|\bverify\s*\(|\baddressOf\s*\(|nsv_verify/, `${file} must not verify the bot's answers`);
  }
});

test('the bot is reached only on the site\'s own origin under /amm (plan section 18 change 5)', async () => {
  const { flow, fetch } = makeFlow({ routes: { 'POST /amm/quote': [200, QUOTE], 'GET /amm/swap/*': [200, { state: 'paid' }] } });
  await flow.loadStatus(); await flow.press({ direction: 'usdt_to_nodus', amountText: '1' }); await flow.follow('4242');
  for (const c of fetch.calls) assert.match(c.key, /^(GET|POST) \/amm\//);   // relative to the origin: no other host
  for (const file of ['bot.js', 'flow.js', 'swap.js']) {
    assert.doesNotMatch(readFileSync(new URL(`../${file}`, import.meta.url), 'utf8'), /https?:\/\/(?!nodusnetwork\.io\/extension)/, file);
  }
});

// ── the add minimum and the USDT contract come from /amm/status (givens item 96; plan line 609) ──
// PROVES: the liquidity minimum shown and used in the refusal text follows `settings.liquidityMinNodus` when it is a
//   canonical decimal; an absent or non-canonical value falls back to the constant of 100,000 NODUS; the bot's
//   below_minimum refusal still governs. `settings.usdtContract` (0x + 40 hex) lets the USDT -> NODUS swap and the
//   liquidity add reach the extension (real adapter, stub provider); a present but invalid value, or none at all,
//   refuses with no_token and sends nothing to the extension.
// ENVIRONMENT: as above. LEAVES BEHIND: nothing.
// FALSE PASS: the status values are stubs of the field names given by main; the bot build that emits them is not run.
import { createAdapter } from '../adapter.js';

test('the minimum follows status.settings.liquidityMinNodus; absent or non-canonical values fall back to 100,000 NODUS', async () => {
  const refuse = [200, { approved: false, reason: 'below_minimum' }];
  const shown = async settings => {
    const { flow } = makeFlow({ settings, routes: { 'POST /amm/liquidity/quote': refuse } });
    await flow.loadStatus();
    const r = await flow.pressAdd({ side: 'nodus', amountText: '1' });
    return { raw: flow.liquidityMin(), text: r.text, reason: r.reason };
  };
  const big = await shown({ liquidityMinNodus: '20000000000000' });             // 2 x 10^13 raw = 200,000 NODUS
  assert.equal(big.raw, 20000000000000n);
  assert.match(big.text, /at least 200,000 NODUS/);
  assert.equal(big.reason, 'below_minimum');                                    // the bot's word still governs
  assert.match((await shown({ liquidityMinNodus: '1250000000' })).text, /at least 12\.5 NODUS/);   // 12.5 x 10^8 raw
  assert.equal((await shown({ liquidityMinNodus: '0' })).raw, 0n);              // canonical zero is a value
  for (const settings of [{}, { liquidityMinNodus: '1e13' }, { liquidityMinNodus: '010' }, { liquidityMinNodus: '-5' },
    { liquidityMinNodus: '' }, { liquidityMinNodus: ' 5' }, { liquidityMinNodus: 5 }, { liquidityMinNodus: '18446744073709551616' }]) {
    const s = await shown(settings);
    assert.equal(s.raw, 10n ** 13n, JSON.stringify(settings));
    assert.match(s.text, /at least 100,000 NODUS/, JSON.stringify(settings));
  }
});

function providerStub(answers = {}) {
  const calls = [];
  return { calls, request: async ({ method, params }) => { calls.push({ method, params }); return answers[method] ?? null; } };
}
const HOLD = { holdId: 'h1', transferId: '0d'.repeat(64), chainId: CHAIN, expiryHeight: 1 };

test('a valid status.settings.usdtContract lets the USDT -> NODUS swap and the liquidity add reach the extension', async () => {
  const contract = `0x${'c1'.repeat(20)}`;
  const provider = providerStub({ nodus_swapHoldTransfer: HOLD });
  const adapter = createAdapter({ getProvider: async () => provider });
  const swap = makeFlow({ adapter, noToken: true, settings: { usdtContract: contract }, routes: { 'POST /amm/quote': [200, QUOTE] } });
  await swap.flow.loadStatus(); await swap.flow.press({ direction: 'usdt_to_nodus', amountText: '100' });
  assert.equal((await swap.flow.confirm({ toleranceBps: 100 })).ok, true);
  assert.equal(provider.calls.find(c => c.method === 'nodus_swapSendUsdtToNodus').params[0].token, contract);
  const pair = { approved: true, usdtAmount: '10000000', nodusAmount: '10000000000000', requestNumber: '88', validUntil: '1700000300', payEthereum: `0x${'fe'.repeat(20)}`, payNodus: 'fd'.repeat(64) };
  const add = makeFlow({ adapter, noToken: true, settings: { usdtContract: contract }, routes: { 'POST /amm/liquidity/quote': [200, pair] } });
  await add.flow.loadStatus(); await add.flow.pressAdd({ side: 'nodus', amountText: '100000' });
  assert.equal((await add.flow.confirmAdd()).ok, true);
  assert.equal(provider.calls.find(c => c.method === 'nodus_swapSendLiquidityAdd').params[0].token, contract);
});

test('an invalid or absent usdtContract refuses with no_token and sends nothing to the extension', async () => {
  const pair = { approved: true, usdtAmount: '10000000', nodusAmount: '10000000000000', requestNumber: '88', validUntil: '1700000300', payEthereum: `0x${'fe'.repeat(20)}`, payNodus: 'fd'.repeat(64) };
  // present but invalid: also NOT replaced by the usdtToken option
  for (const bad of ['0x12', 'c1'.repeat(20), `0x${'zz'.repeat(20)}`, `0x${'c1'.repeat(21)}`, '', 7]) {
    const provider = providerStub({ nodus_swapHoldTransfer: HOLD });
    const adapter = createAdapter({ getProvider: async () => provider });
    const swap = makeFlow({ adapter, settings: { usdtContract: bad }, routes: { 'POST /amm/quote': [200, QUOTE], 'POST /amm/liquidity/quote': [200, pair] } });
    await swap.flow.loadStatus(); await swap.flow.press({ direction: 'usdt_to_nodus', amountText: '100' });
    const r = await swap.flow.confirm({ toleranceBps: 100 });
    assert.equal(r.ok, false, String(bad)); assert.equal(r.reason, 'no_token', String(bad));
    await swap.flow.pressAdd({ side: 'nodus', amountText: '100000' });
    assert.equal((await swap.flow.confirmAdd()).reason, 'no_token', String(bad));
    assert.deepEqual(provider.calls, [], `${String(bad)}: nothing may reach the extension`);   // no chain switch, no hold
  }
  // absent from the status and no option: refused the same way
  const provider = providerStub({ nodus_swapHoldTransfer: HOLD });
  const swap = makeFlow({ adapter: createAdapter({ getProvider: async () => provider }), noToken: true, routes: { 'POST /amm/quote': [200, QUOTE] } });
  await swap.flow.loadStatus(); await swap.flow.press({ direction: 'usdt_to_nodus', amountText: '100' });
  assert.equal((await swap.flow.confirm({ toleranceBps: 100 })).reason, 'no_token');
  assert.deepEqual(provider.calls, []);
});

// ── a delivered request is not offered again (givens item 88 covers only the NOT delivered case) ──
// PROVES: when the extension reports delivered:true the flow gives plain words (paid false: nothing paid, ask for a new
//   price; paid "unknown": the payment may have been sent, do not pay again), spends the price (a second yes is not_ready,
//   the adapter is called once) and hands back the request number so the page follows the swap; the swap can then be read
//   with GET /amm/swap/<number>. With delivered:false the same price stays available for a new try (the agreed flow).
//   The same for the liquidity add (no state route exists for it, so it is not followed).
// ENVIRONMENT: as above. LEAVES BEHIND: nothing.
// FALSE PASS: the error shapes follow the extension source as read; the button handling itself is in swap.js and is not run.
test('delivered:true, paid false: plain words, the price is spent, the swap is followed', async () => {
  const err = new AdapterError('extension_error', 'x', { delivered: true, paid: false });
  const adapter = stubAdapter({ usdtToNodus: () => { throw err; } });
  const { flow, fetch } = makeFlow({ adapter, pollMax: 2, routes: { 'POST /amm/quote': [200, QUOTE], 'GET /amm/swap/*': [200, { requestNumber: '4242', state: 'approved' }] } });
  await flow.loadStatus(); await flow.press({ direction: 'usdt_to_nodus', amountText: '100' });
  const r = await flow.confirm({ toleranceBps: 100 });
  assert.equal(r.ok, false);
  assert.equal(r.delivered, true);
  assert.equal(r.requestNumber, '4242');
  assert.equal(r.text, 'The bot has your request but nothing was paid. Ask for a new price to try again.');
  assert.equal((await flow.confirm({ toleranceBps: 100 })).reason, 'not_ready');       // no second approval
  assert.equal(adapter.calls.length, 1);                                                // the adapter was not called again
  const f = await flow.follow(r.requestNumber, () => {});
  assert.equal(f.info.kind, 'pending');
  assert.ok(fetch.calls.some(c => c.key === 'GET /amm/swap/4242'));
});

test('delivered:true, paid "unknown": do not pay again, check the extension', async () => {
  const adapter = stubAdapter({ nodusToUsdt: () => { throw new AdapterError('extension_error', 'x', { delivered: true, paid: 'unknown' }); } });
  const quote = { ...QUOTE, direction: 'nodus_to_usdt', amount: '50000000000000', number: '100000000', estimatedFee: '0', payTo: 'fd'.repeat(64) };
  const { flow } = makeFlow({ adapter, routes: { 'POST /amm/quote': [200, quote] } });
  await flow.loadStatus(); await flow.press({ direction: 'nodus_to_usdt', amountText: '500000' });
  const r = await flow.confirm({ toleranceBps: 0 });
  assert.equal(r.delivered, true);
  assert.equal(r.paid, 'unknown');
  assert.equal(r.text, 'The payment may have been sent. Do not pay again; check the extension\'s activity.');
  assert.equal((await flow.confirm({ toleranceBps: 0 })).reason, 'not_ready');
  assert.equal(adapter.calls.length, 1);
});

test('delivered:false keeps the price: the user may try again (givens item 88)', async () => {
  const adapter = stubAdapter({ usdtToNodus: () => { throw new AdapterError('extension_error', 'x', { delivered: false, paid: false, answered: false }); } });
  const { flow } = makeFlow({ adapter, routes: { 'POST /amm/quote': [200, QUOTE] } });
  await flow.loadStatus(); await flow.press({ direction: 'usdt_to_nodus', amountText: '100' });
  const first = await flow.confirm({ toleranceBps: 100 });
  assert.equal(first.delivered, undefined);
  assert.match(first.text, /did not reach the bot/);
  await flow.confirm({ toleranceBps: 100 });
  assert.equal(adapter.calls.length, 2);                                                // the user's own second try reaches the adapter
});

test('liquidity add delivered:true: plain words and the pair is spent', async () => {
  const pair = { approved: true, usdtAmount: '10000000', nodusAmount: '10000000000000', requestNumber: '88', validUntil: '1700000300', payEthereum: `0x${'fe'.repeat(20)}`, payNodus: 'fd'.repeat(64) };
  const adapter = stubAdapter({ liquidityAdd: () => { throw new AdapterError('extension_error', 'x', { delivered: true, paid: 'unknown' }); } });
  const { flow } = makeFlow({ adapter, routes: { 'POST /amm/liquidity/quote': [200, pair] } });
  await flow.loadStatus(); await flow.pressAdd({ side: 'nodus', amountText: '100000' });
  const r = await flow.confirmAdd();
  assert.equal(r.delivered, true);
  assert.match(r.text, /Do not pay again/);
  assert.equal((await flow.confirmAdd()).reason, 'not_ready');
  assert.equal(adapter.calls.length, 1);
});

// ── review corrections: one-sided add, open approval, uncertain withdrawal, late answers, interleaved follows ──
// Each test below uses the real error shapes through adapter -> flow (a stub provider whose error carries the
// extension's error.data) or a hand-controlled bot. FALSE PASS: the shapes follow the extension source as read
// (swap.js:73-81, 179-188), not the running extension; swap.js (button wiring, panel) is not run.
function failingProvider(method, data, answers = {}) {
  const calls = [];
  return {
    calls,
    request: async ({ method: m, params }) => {
      calls.push({ method: m, params });
      if (m === method) throw Object.assign(new Error('extension error'), { data });
      return answers[m] ?? null;
    },
  };
}
const flush = () => new Promise(resolve => setImmediate(resolve));
const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; };
const PAIR = { approved: true, usdtAmount: '10000000', nodusAmount: '10000000000000', requestNumber: '88', validUntil: '1700000300', payEthereum: `0x${'fe'.repeat(20)}`, payNodus: 'fd'.repeat(64) };

// PROVES (correction 1): a liquidity add whose NODUS half was sent (true) or may have been ('unknown') is NOT shown as
//   "nothing was paid": the text names the NODUS and USDT halves, the request number and the transfer id, says not to pay
//   again nor ask for a new pair, and sends the user to the Foundation (givens items 32, 35); nodusSent false with paid
//   false keeps the plain "nothing was paid" text.
test('liquidity add, NODUS sent: the text says so, no new pair is invited, the Foundation is named', async () => {
  const transferId = 'ab'.repeat(64);
  const provider = failingProvider('nodus_swapSendLiquidityAdd', { delivered: true, paid: false, nodusSent: true, intentId: 'intent-1', transferId }, { nodus_swapHoldTransfer: HOLD });
  const { flow } = makeFlow({ adapter: createAdapter({ getProvider: async () => provider }), routes: { 'POST /amm/liquidity/quote': [200, PAIR] } });
  await flow.loadStatus(); await flow.pressAdd({ side: 'nodus', amountText: '100000' });
  const r = await flow.confirmAdd();
  assert.equal(r.delivered, true);
  assert.equal(r.oneSided, true);
  assert.equal(r.nodusSent, true);
  assert.equal(r.intentId, 'intent-1');
  assert.equal(r.transferId, transferId);
  assert.match(r.text, /request 88/);
  assert.match(r.text, new RegExp(`Your NODUS payment was sent \\(transfer ${transferId}\\)`));
  assert.match(r.text, /Your USDT payment was not sent/);
  assert.match(r.text, /do not ask for a new pair/);
  assert.match(r.text, /Foundation/);
  assert.match(r.text, /activity/);
  assert.doesNotMatch(r.text, /nothing was paid|Ask for a new price/i);
});

test('liquidity add, NODUS "unknown" and USDT "unknown": both may have been sent; nodusSent false keeps the plain text', async () => {
  let provider = failingProvider('nodus_swapSendLiquidityAdd', { delivered: true, paid: 'unknown', nodusSent: 'unknown' }, { nodus_swapHoldTransfer: HOLD });
  let t = makeFlow({ adapter: createAdapter({ getProvider: async () => provider }), routes: { 'POST /amm/liquidity/quote': [200, PAIR] } });
  await t.flow.loadStatus(); await t.flow.pressAdd({ side: 'nodus', amountText: '100000' });
  let r = await t.flow.confirmAdd();
  assert.match(r.text, /Your NODUS payment may have been sent/);
  assert.match(r.text, /Your USDT payment may have been sent/);
  assert.match(r.text, /Do not pay again/);
  provider = failingProvider('nodus_swapSendLiquidityAdd', { delivered: true, paid: false, nodusSent: false }, { nodus_swapHoldTransfer: HOLD });
  t = makeFlow({ adapter: createAdapter({ getProvider: async () => provider }), routes: { 'POST /amm/liquidity/quote': [200, PAIR] } });
  await t.flow.loadStatus(); await t.flow.pressAdd({ side: 'nodus', amountText: '100000' });
  r = await t.flow.confirmAdd();
  assert.equal(r.oneSided, undefined);
  assert.equal(r.text, 'The bot has your request but nothing was paid. Ask for a new price to try again.');
});

// PROVES (correction 2): an open-approval refusal (delivered false, openRequestNumber) keeps the open swap's number so
//   the page follows it, says this new request paid nothing, and does not say "you can try again" (givens item 57).
test('open_approval refusal: the open request number is kept and the text points to the open swap', async () => {
  const provider = failingProvider('nodus_swapSendUsdtToNodus', { delivered: false, paid: false, answered: true, reason: 'open_approval', openRequestNumber: '7' });
  const { flow } = makeFlow({ adapter: createAdapter({ getProvider: async () => provider }), routes: { 'POST /amm/quote': [200, QUOTE] } });
  await flow.loadStatus(); await flow.press({ direction: 'usdt_to_nodus', amountText: '100' });
  const r = await flow.confirm({ toleranceBps: 100 });
  assert.equal(r.ok, false);
  assert.equal(r.openRequestNumber, '7');
  assert.match(r.text, /new request paid nothing/);
  assert.match(r.text, /request 7/);
  assert.match(r.text, /shown below/);
  assert.doesNotMatch(r.text, /try again/i);
});

// PROVES (correction 3): after signing, an unreachable post or an unreadable answer is "uncertain": the exact signed
//   body is kept in memory, the next press resends the SAME body (one signature, one request number), number_reused is
//   shown as "already has this withdrawal", a JSON refusal with a reason is definite and drops the body, and a different
//   account drops it too.
function withdrawFlow(seq) {
  let n = 0;
  const signed = [];
  const t = makeFlow({
    signText: async (text, address) => { signed.push(text); return `0x${'ee'.repeat(4627)}`; },
    random: () => String(555 + n++),
    routes: { 'POST /amm/liquidity/withdraw': () => seq.shift() },
  });
  return { ...t, signed };
}
test('withdraw: unreachable after signing, then the same body is resent and answered number_reused', async () => {
  const { flow, fetch, signed } = withdrawFlow(['network-error', [200, { received: false, reason: 'number_reused' }]]);
  await flow.loadStatus();
  const first = await flow.withdraw({ basisPoints: 2500 });
  assert.equal(first.ok, false);
  assert.equal(first.uncertain, true);
  assert.match(first.text, /may have been received \(request 555\)/);
  assert.doesNotMatch(first.text, /Nothing was signed/i);
  assert.equal(flow.pendingWithdrawNumber(), '555');
  const second = await flow.withdraw({ basisPoints: 9999 });                   // a different share is ignored: the kept body is resent
  assert.equal(second.ok, true);
  assert.equal(second.alreadyReceived, true);
  assert.equal(second.text, 'The bot already has this withdrawal (request 555).');
  assert.equal(signed.length, 1);                                               // one signature in total
  const posts = fetch.calls.filter(c => c.key === 'POST /amm/liquidity/withdraw');
  assert.equal(posts.length, 2);
  assert.equal(posts[0].body, posts[1].body);                                   // the exact same body
  assert.equal(flow.pendingWithdrawNumber(), null);
  await flow.withdraw({ basisPoints: 100 });                                    // the next withdrawal is a new one
  assert.equal(signed.length, 2);
});

test('withdraw: an unreadable answer is uncertain too; a resend answered received is the normal result', async () => {
  const { flow, signed } = withdrawFlow([[200, 'not-json'], [200, { received: true, requestNumber: '555' }]]);
  await flow.loadStatus();
  const first = await flow.withdraw({ basisPoints: 100 });
  assert.equal(first.uncertain, true);
  assert.equal(first.reason, 'bad_answer');
  const second = await flow.withdraw({ basisPoints: 100 });
  assert.deepEqual([second.ok, second.requestNumber], [true, '555']);
  assert.equal(signed.length, 1);
  assert.equal(flow.pendingWithdrawNumber(), null);
});

test('withdraw: a JSON refusal with a reason is definite and drops the kept body; a new account drops it', async () => {
  const a = withdrawFlow(['network-error', [200, { received: false, reason: 'bad_signature' }]]);
  await a.flow.loadStatus();
  await a.flow.withdraw({ basisPoints: 100 });
  const refused = await a.flow.withdraw({ basisPoints: 100 });
  assert.equal(refused.ok, false);
  assert.equal(refused.reason, 'bad_signature');
  assert.match(refused.text, /signature/);
  assert.equal(a.flow.pendingWithdrawNumber(), null);
  const b = withdrawFlow(['network-error']);
  await b.flow.loadStatus();
  await b.flow.withdraw({ basisPoints: 100 });
  assert.equal(b.flow.pendingWithdrawNumber(), '555');
  b.flow.setAccounts({ ...ACCOUNTS });                                          // the same account: kept
  assert.equal(b.flow.pendingWithdrawNumber(), '555');
  b.flow.setAccounts({ nodus: { address: 'cd'.repeat(64), publicKey: ACCOUNTS.nodus.publicKey }, ethereum: ETH });   // another account
  assert.equal(b.flow.pendingWithdrawNumber(), null);
});

// PROVES (correction 4): a price answer that arrives after the amount, direction or side changed is discarded: nothing
//   is stored and nothing is returned as ok; the newer question's answer stands; outputUnit follows the quote's own direction.
test('a late swap answer after an edit or a flip is discarded; the newer answer stands', async () => {
  const waiting = [];
  const bot = { status: async () => ({ ok: true, status: 200, json: STATUS }), quote: (d, a) => { const x = deferred(); waiting.push({ d, a, ...x }); return x.promise; } };
  const flow = createSwapFlow({ bot, adapter: stubAdapter(), botUrl: 'https://swap.nodusnetwork.io', sleep: async () => {} });
  const first = flow.press({ direction: 'usdt_to_nodus', amountText: '100' });
  await flush();
  flow.clearQuote('swap');                                                      // the user edited the amount (swap.js resets on every edit)
  waiting[0].resolve({ ok: true, status: 200, json: QUOTE });
  const r1 = await first;
  assert.deepEqual([r1.ok, r1.stale], [false, true]);
  assert.equal(flow.state.quote, null);
  // a flip: the old direction's answer arrives after the newer question was asked
  const slow = flow.press({ direction: 'usdt_to_nodus', amountText: '100' });
  await flush();
  const flipped = flow.press({ direction: 'nodus_to_usdt', amountText: '500000' });
  await flush();
  waiting[2].resolve({ ok: true, status: 200, json: { ...QUOTE, direction: 'nodus_to_usdt', amount: '50000000000000', number: '100000000' } });
  assert.equal((await flipped).ok, true);
  waiting[1].resolve({ ok: true, status: 200, json: QUOTE });                  // late
  assert.equal((await slow).stale, true);
  assert.equal(flow.state.quote.direction, 'nodus_to_usdt');
  assert.equal(flow.state.quote.number, '100000000');
});

test('a late add answer after a side or amount change is discarded', async () => {
  const waiting = [];
  const bot = { liquidityQuote: () => { const x = deferred(); waiting.push(x); return x.promise; } };
  const flow = createSwapFlow({ bot, adapter: stubAdapter(), botUrl: 'https://swap.nodusnetwork.io', sleep: async () => {} });
  const p = flow.pressAdd({ side: 'nodus', amountText: '100000' });
  await flush();
  flow.clearQuote('add');
  waiting[0].resolve({ ok: true, status: 200, json: PAIR });
  const r = await p;
  assert.equal(r.stale, true);
  assert.equal(r.ok, false);
  assert.equal(flow.state.addQuote, null);
  assert.equal(flow.state.swapGen, 0);                                          // clearing the add did not touch the swap question
});

// PROVES (correction 5): the newest follow ends the older one: the older one's late read, its onState calls and its
//   exhaustion no longer count (it returns stopped), and the newer one finishes normally.
test('two interleaved follows: the older one stops and never reports, even when its read would exhaust it', async () => {
  const reads = [];
  const bot = { swapState: n => { const x = deferred(); reads.push({ n, ...x }); return x.promise; } };
  const flow = createSwapFlow({ bot, adapter: stubAdapter(), botUrl: 'https://swap.nodusnetwork.io', sleep: async () => {}, pollMax: 1 });
  const seenA = [], seenB = [];
  const a = flow.follow('1', u => seenA.push(u));
  await flush();
  const b = flow.follow('2', u => seenB.push(u));
  await flush();
  reads[1].resolve({ ok: true, status: 200, json: { state: 'paid', paid: '9' } });
  const rb = await b;
  assert.equal(rb.final, true);
  assert.equal(seenB.length, 1);
  reads[0].resolve({ ok: true, status: 200, json: { state: 'counted' } });      // A's late read, which with pollMax 1 would exhaust
  const ra = await a;
  assert.deepEqual([ra.stopped, ra.exhausted, ra.final], [true, undefined, false]);
  assert.deepEqual(seenA, []);
  assert.equal(reads.length, 2);
});

test('stopFollow and the caller\'s shouldStop end a follow; a follow in a sleep stops after it', async () => {
  const slept = deferred();
  let reads = 0;
  const bot = { swapState: async () => { reads++; return { ok: true, status: 200, json: { state: 'counted' } }; } };
  const flow = createSwapFlow({ bot, adapter: stubAdapter(), botUrl: 'https://swap.nodusnetwork.io', sleep: () => slept.promise, pollMax: 5 });
  const seen = [];
  const p = flow.follow('1', u => seen.push(u));
  await flush();
  flow.stopFollow();
  slept.resolve();
  assert.equal((await p).stopped, true);
  assert.equal(reads, 1);
  assert.equal(seen.length, 1);                                                  // only the read before the stop
  const q = await createSwapFlow({ bot, adapter: stubAdapter(), botUrl: 'x', sleep: async () => {}, pollMax: 3 }).follow('1', () => {}, () => true);
  assert.equal(q.stopped, true);
});

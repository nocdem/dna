// Tests of swap-logic.js: amounts and raw units, the minimum to receive, the price, request bodies, the signed
// texts, the typed data, the request number and the swap states.
//
// PROVES: the arithmetic and the byte forms the site produces, against values derived by hand (the arithmetic is
//   written beside each vector) and against the plan's own example text (plan 6.4.4).
// ENVIRONMENT: node >= 20, `node --test website/swap-site/test/`; no browser, no network, no compile flags, no
//   environment variables.
// LEAVES BEHIND: nothing (no files, no processes).
// FALSE PASS: the texts and typed data are compared with literals copied from the plan, not with the bot's parser
//   (the C parser amm_req is not run here), so a plan error copied into both would pass; the typed data is not
//   hashed or signed. The minimum vectors prove the formula as written in plan section 7 step 4, not that the
//   formula is the right one.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  parseAmount, formatFixed, displayAmount, usdtText, nodusText, percentToBps, minimumToReceive, priceFromReserves, poolText, priceMovementPercent, ethConfirmations, waitText,
  quoteBody, liquidityQuoteBody, withdrawBody, randomRequestNumber,
  buildNodusToUsdtText, buildLiquidityAddText, buildWithdrawText,
  buildUsdtToNodusTypedData, buildLiquidityAddTypedData,
  readQuoteAnswer, readAddQuoteAnswer, refusalText, describeSwapState, PAYOUT_FINAL_DEPTH_ETH, U64_MAX,
} from '../swap-logic.js';

const ETH = `0x${'4b'.repeat(20)}`;
const NODUS_ADDR = 'ab'.repeat(64);
const TRANSFER = '0d'.repeat(64);
const CHAIN = '5c'.repeat(32);

test('parseAmount: USDT has 6 decimals, NODUS 8 (plan section 5)', () => {
  assert.deepEqual(parseAmount('100', 6), { ok: true, raw: 100000000n });          // 100 x 10^6
  assert.deepEqual(parseAmount('0.000001', 6), { ok: true, raw: 1n });
  assert.deepEqual(parseAmount('12.5', 6), { ok: true, raw: 12500000n });          // 12 x 10^6 + 500000
  assert.deepEqual(parseAmount('1.5', 8), { ok: true, raw: 150000000n });          // 1 x 10^8 + 50000000
  assert.deepEqual(parseAmount('.5', 6), { ok: true, raw: 500000n });
  assert.deepEqual(parseAmount(' 7 ', 8), { ok: true, raw: 700000000n });
  assert.deepEqual(parseAmount('18446744073709.551615', 6), { ok: true, raw: U64_MAX }); // 2^64 - 1 = 18446744073709551615
});

test('parseAmount: refuses what the bot would refuse, before anything is sent', () => {
  assert.equal(parseAmount('', 6).reason, 'empty');
  assert.equal(parseAmount('   ', 6).reason, 'empty');
  assert.equal(parseAmount('abc', 6).reason, 'format');
  assert.equal(parseAmount('1e5', 6).reason, 'format');
  assert.equal(parseAmount('-1', 6).reason, 'format');
  assert.equal(parseAmount('1,5', 6).reason, 'format');
  assert.equal(parseAmount('.', 6).reason, 'format');
  assert.equal(parseAmount('1.0000001', 6).reason, 'too_many_decimals');   // 7 digits, USDT has 6
  assert.equal(parseAmount('0', 6).reason, 'zero');
  assert.equal(parseAmount('0.000000', 6).reason, 'zero');
  assert.equal(parseAmount('18446744073709.551616', 6).reason, 'too_large'); // 2^64
});

test('formatFixed and the unit texts follow plan 6.4.2 (integer part, exactly 6 or 8 fraction digits)', () => {
  assert.equal(formatFixed(1n, 6), '0.000001');
  assert.equal(formatFixed(0n, 6), '0.000000');
  assert.equal(formatFixed(49500000n, 6), '49.500000');
  assert.equal(usdtText(49500000n), '49.500000 USDT');
  assert.equal(nodusText(50000000000000n), '500000.00000000 NODUS');
  assert.equal(nodusText('1'), '0.00000001 NODUS');
  assert.equal(displayAmount(124860000000n, 8), '1248.6');
  assert.equal(displayAmount(100000000n, 6), '100');
});

test('percentToBps: 0..100 percent, at most two fraction digits', () => {
  assert.deepEqual(percentToBps('0.5'), { ok: true, bps: 50 });
  assert.deepEqual(percentToBps('1'), { ok: true, bps: 100 });
  assert.deepEqual(percentToBps('3.25'), { ok: true, bps: 325 });
  assert.deepEqual(percentToBps('0'), { ok: true, bps: 0 });
  assert.deepEqual(percentToBps('100'), { ok: true, bps: 10000 });
  assert.equal(percentToBps('100.01').ok, false);   // 10001 basis points
  assert.equal(percentToBps('0.555').ok, false);    // three fraction digits
  assert.equal(percentToBps('-1').ok, false);
  assert.equal(percentToBps('').ok, false);
  assert.equal(percentToBps('x').ok, false);
});

test('minimumToReceive: (number - fee, floored at 0) x (10000 - tolerance) / 10000, truncated (plan section 7 step 4)', () => {
  // 124,860,000,000 raw = 1248.6 NODUS; fee 1,000,000 = 0.01 NODUS; tolerance 100 bp (1 %):
  // net 124,859,000,000; x 9,900 = 1,236,104,100,000,000 (= 1,248,590,000,000,000 - 12,485,900,000,000); / 10,000 = 123,610,410,000.
  assert.equal(minimumToReceive('124860000000', '1000000', 100), 123610410000n);
  // USDT side: 100 USDT = 100,000,000; fee 3,000,000; 50 bp: net 97,000,000 x 9,950 = 965,150,000,000; / 10,000 = 96,515,000.
  assert.equal(minimumToReceive(100000000n, 3000000n, 50), 96515000n);
  // truncation: 1,001 x 6,667 = 6,673,667; / 10,000 = 667.3667 -> 667 (tolerance 3,333 bp, no fee)
  assert.equal(minimumToReceive(1001n, 0n, 3333), 667n);
  // tolerance 0: the fee alone is taken off (plan line 444: a tolerance of 0 must not refund at an unchanged price)
  assert.equal(minimumToReceive(1000n, 10n, 0), 990n);
  assert.equal(minimumToReceive(1000n, 10n, 50), 985n);   // 990 x 9,950 = 9,850,500; / 10,000 = 985.05 -> 985
  // saturating subtraction: a fee above the number gives 0, never a wrapped value
  assert.equal(minimumToReceive(5n, 10n, 0), 0n);
  assert.equal(minimumToReceive(10n, 10n, 0), 0n);
  // the whole range of tolerance
  assert.equal(minimumToReceive(1000n, 0n, 10000), 0n);
  // a number above 2^53 keeps every digit (BigInt, no float): 2^64 - 1 with tolerance 0 and no fee
  assert.equal(minimumToReceive('18446744073709551615', '0', 0), 18446744073709551615n);
  assert.throws(() => minimumToReceive(1n, 0n, 10001), RangeError);
  assert.throws(() => minimumToReceive(1n, 0n, -1), RangeError);
  assert.throws(() => minimumToReceive(1n, 0n, 1.5), RangeError);
  assert.throws(() => minimumToReceive('1e3', '0', 0), TypeError);
});

test('priceFromReserves: the start pool 3000 USDT : 30,000,000 NODUS is 10,000 NODUS per USDT (givens item 20)', () => {
  // n = 3 x 10^15 raw NODUS, u = 3 x 10^9 raw USDT: NODUS per USDT = n x 100 / u = 10^8 (in units of 10^-4) = 10000.
  assert.deepEqual(priceFromReserves({ nodus: '3000000000000000', usdt: '3000000000' }),
    { nodusPerUsdt: '10000', usdtPerNodus: '0.0001' });                // u x 10^8 / n = 100 (units of 10^-6) = 0.0001
  assert.equal(priceFromReserves(null), null);
  assert.equal(priceFromReserves({ nodus: 'above_2_64', usdt: '1' }), null);
  assert.equal(priceFromReserves({ nodus: '0', usdt: '5' }), null);
});

test('poolText: both reserves in display units; empty pool and an oversized side say so in words', () => {
  // 3000 USDT = 3 x 10^9 raw (6 decimals); 30,000,000 NODUS = 3 x 10^15 raw (8 decimals), shown with commas.
  assert.equal(poolText({ usdt: '3000000000', nodus: '3000000000000000' }), '3000 USDT · 30,000,000 NODUS');
  assert.equal(poolText({ usdt: '1500000', nodus: '123456789' }), '1.5 USDT · 1.23456789 NODUS');
  assert.equal(poolText(null), 'Empty: no liquidity yet');
  assert.equal(poolText({ usdt: 'above_2_64', nodus: '5' }), 'Too large to show');
  assert.equal(poolText({ usdt: '5', nodus: 'above_2_64' }), 'Too large to show');
  // FALSE PASS: only these strings are compared; how the page places the line is not exercised here.
});

test('priceMovementPercent: how far the bot\'s rate for this amount is below the pool price, two decimals', () => {
  const reserves = { usdt: '3000000000', nodus: '3000000000000000' };   // 3000 USDT : 30,000,000 NODUS
  const u = 3000000000n, n = 3000000000000000n;
  // Constant-product output, floor: out = n x a / (u + a). Movement is then about a / (u + a).
  const out = a => n * a / (u + a);
  // 1 USDT: 1 / 3001 = 0.0333 % -> "0.03".
  assert.equal(priceMovementPercent(reserves, 'usdt_to_nodus', 1000000n, out(1000000n)), '0.03');
  // An amount equal to the pool's USDT side: out = n / 2, movement 50 %.
  assert.equal(priceMovementPercent(reserves, 'usdt_to_nodus', u, out(u)), '50.00');
  // The other direction against the same pool: sending all the NODUS side gives half the USDT side.
  const outU = a => u * a / (n + a);
  assert.equal(priceMovementPercent(reserves, 'nodus_to_usdt', n, outU(n)), '50.00');
  // 9 times the pool size: 9 / 10 = 90 %.
  assert.equal(priceMovementPercent(reserves, 'usdt_to_nodus', 9n * u, out(9n * u)), '90.00');
  // A number at the pool price exactly is 0.00; a number above it (never negative) is "0.00", not "-0.00".
  assert.equal(priceMovementPercent(reserves, 'usdt_to_nodus', 1000000n, 1000000n * n / u), '0.00');
  assert.equal(priceMovementPercent(reserves, 'usdt_to_nodus', 1000000n, 2n * 1000000n * n / u), '0.00');
  // Nothing received: the whole amount is lost to movement, 100.00.
  assert.equal(priceMovementPercent(reserves, 'usdt_to_nodus', 1000000n, 0n), '100.00');
  // No known pool price, or unusable inputs: null (the page shows a dash).
  assert.equal(priceMovementPercent(null, 'usdt_to_nodus', 1000000n, 1n), null);
  assert.equal(priceMovementPercent({ usdt: 'above_2_64', nodus: '5' }, 'usdt_to_nodus', 1000000n, 1n), null);
  assert.equal(priceMovementPercent({ usdt: '0', nodus: '5' }, 'usdt_to_nodus', 1000000n, 1n), null);
  assert.equal(priceMovementPercent(reserves, 'sideways', 1000000n, 1n), null);
  assert.equal(priceMovementPercent(reserves, 'usdt_to_nodus', 0n, 1n), null);
  assert.equal(priceMovementPercent(reserves, 'usdt_to_nodus', -1n, 1n), null);   // negative inputs are unusable
  assert.equal(priceMovementPercent(reserves, 'usdt_to_nodus', 1000000n, -1n), null);
  // Strings of digits (the bot's form) work as well as BigInt.
  assert.equal(priceMovementPercent(reserves, 'usdt_to_nodus', '3000000000', (n / 2n).toString()), '50.00');
  // FALSE PASS: the expected values come from the constant-product shape used here; the bot's real pricing
  // (commission, its own rounding) is not run, so the function is proven as a formula only, not against the bot.
});

test('ethConfirmations: the bot\'s default tiers by USDT amount, bounds inclusive (amm_cfg.c:116-120, amm_cfg.h:133-139)', () => {
  assert.equal(ethConfirmations(1n), 3n);
  assert.equal(ethConfirmations(100000000n), 3n);      // exactly 100 USDT: up to and including bound 1
  assert.equal(ethConfirmations(100000001n), 5n);      // 100.000001 USDT
  assert.equal(ethConfirmations(1000000000n), 5n);     // exactly 1,000 USDT: up to and including bound 2
  assert.equal(ethConfirmations(1000000001n), 33n);    // 1,000.000001 USDT
  assert.equal(ethConfirmations('5000000000'), 33n);   // digit string form
  assert.equal(ethConfirmations(0n), null);
  assert.equal(ethConfirmations(''), null);
  assert.equal(ethConfirmations('1.5'), null);
  assert.equal(ethConfirmations(undefined), null);
  assert.equal(ethConfirmations(-1n), null);            // a negative BigInt is unusable (Sol verify claim 4)
  // FALSE PASS: the tiers are constants copied from the bot's defaults; a bot setting changed on the live bot
  // (eth_conf_*) is not visible here, and /amm/status does not carry it.
});

test('waitText: follows the typed amount and the direction', () => {
  assert.equal(waitText('usdt_to_nodus', '50'), '3 Ethereum blocks');
  assert.equal(waitText('usdt_to_nodus', '100'), '3 Ethereum blocks');
  assert.equal(waitText('usdt_to_nodus', '100.000001'), '5 Ethereum blocks');
  assert.equal(waitText('usdt_to_nodus', '500'), '5 Ethereum blocks');
  assert.equal(waitText('usdt_to_nodus', '5000'), '33 Ethereum blocks');
  assert.equal(waitText('nodus_to_usdt', '5000'), 'its Nodus block is committed');
  assert.equal(waitText('nodus_to_usdt', '0.5'), 'its Nodus block is committed');
  for (const bad of ['', '  ', 'abc', '0', '1.1234567', '99999999999999999999999']) assert.equal(waitText('usdt_to_nodus', bad), '—');
  assert.equal(waitText('nodus_to_usdt', ''), '—');
  // FALSE PASS: only the text is compared; the page wiring (every input, every flip) is checked in a browser.
});

test('request bodies: quote bodies are exactly two keys, both strings (amm_http.c route_quote)', () => {
  const q = JSON.parse(quoteBody('usdt_to_nodus', 100000000n));
  assert.deepEqual(Object.keys(q), ['direction', 'amount']);
  assert.deepEqual(q, { direction: 'usdt_to_nodus', amount: '100000000' });
  assert.equal(quoteBody('nodus_to_usdt', 5n), '{"direction":"nodus_to_usdt","amount":"5"}');
  assert.equal(liquidityQuoteBody('nodus', 10n ** 13n), '{"side":"nodus","amount":"10000000000000"}');
  assert.equal(liquidityQuoteBody('usdt', 1n), '{"side":"usdt","amount":"1"}');
  assert.throws(() => quoteBody('sideways', 1n), RangeError);
  assert.throws(() => liquidityQuoteBody('eth', 1n), RangeError);
});

test('withdrawBody: {text: 0x + hex of the text bytes, publicKey, signature} (plan 6.4.7)', () => {
  const b = JSON.parse(withdrawBody({ text: 'Hi\nA', publicKey: '0xaa', signature: '0xbb' }));
  assert.deepEqual(b, { text: '0x48690a41', publicKey: '0xaa', signature: '0xbb' }); // H=48 i=69 LF=0a A=41
});

test('randomRequestNumber: a decimal u64 from 8 random bytes', () => {
  assert.equal(randomRequestNumber(a => a.fill(0)), '0');
  assert.equal(randomRequestNumber(a => a.fill(255)), '18446744073709551615');
  assert.equal(randomRequestNumber(a => { a.set([0, 0, 0, 0, 0, 0, 1, 0]); return a; }), '256');
});

test('buildNodusToUsdtText equals the plan 6.4.4 layout, LF between lines, no trailing LF', () => {
  const text = buildNodusToUsdtText({
    sender: NODUS_ADDR, destination: ETH, amountNodusRaw: 50000000000000n, minimumUsdtRaw: 49500000n,
    transferId: TRANSFER, chainId: CHAIN, requestNumber: '9007199254740993',
  });
  assert.equal(text, [
    'Nodus Swap: NODUS to USDT request',
    `Sender: ${NODUS_ADDR}`,
    `Destination: ${ETH}`,
    'Amount: 500000.00000000 NODUS',
    'Minimum To Receive: 49.500000 USDT',
    `Transfer ID: ${TRANSFER}`,
    `Chain ID: ${CHAIN}`,
    'Request Number: 9007199254740993',
  ].join('\n'));
  assert.equal(text.endsWith('\n'), false);
  assert.equal(text.includes('\r'), false);
});

test('buildLiquidityAddText and buildWithdrawText equal the plan 6.4.6 layouts', () => {
  assert.equal(buildLiquidityAddText({
    ethereumAddress: ETH, nodusAddress: NODUS_ADDR, usdtAmountRaw: 10000000n, nodusAmountRaw: 10n ** 13n,
    transferId: TRANSFER, chainId: CHAIN, requestNumber: '42',
  }), [
    'Nodus Swap: liquidity add request',
    `Ethereum Address: ${ETH}`,
    `Nodus Address: ${NODUS_ADDR}`,
    'USDT Amount: 10.000000 USDT',
    'NODUS Amount: 100000.00000000 NODUS',
    `Transfer ID: ${TRANSFER}`,
    `Chain ID: ${CHAIN}`,
    'Request Number: 42',
  ].join('\n'));
  assert.equal(buildWithdrawText({ ethereumAddress: ETH, nodusAddress: NODUS_ADDR, basisPoints: 2500, chainId: CHAIN, requestNumber: '7' }), [
    'Nodus Swap: liquidity withdraw request',
    `Ethereum Address: ${ETH}`,
    `Nodus Address: ${NODUS_ADDR}`,
    'Basis Points: 2500',
    `Chain ID: ${CHAIN}`,
    'Request Number: 7',
  ].join('\n'));
});

test('the text builders refuse every non-canonical value form (plan 6.4.2)', () => {
  const ok = { ethereumAddress: ETH, nodusAddress: NODUS_ADDR, basisPoints: 1, chainId: CHAIN, requestNumber: '7' };
  assert.doesNotThrow(() => buildWithdrawText(ok));
  assert.throws(() => buildWithdrawText({ ...ok, basisPoints: 0 }), RangeError);
  assert.throws(() => buildWithdrawText({ ...ok, basisPoints: 10001 }), RangeError);
  assert.throws(() => buildWithdrawText({ ...ok, basisPoints: 1.5 }), RangeError);
  assert.throws(() => buildWithdrawText({ ...ok, ethereumAddress: ETH.toUpperCase().replace('0X', '0x') }), TypeError); // upper-case hex
  assert.throws(() => buildWithdrawText({ ...ok, ethereumAddress: ETH.slice(0, -1) }), TypeError);
  assert.throws(() => buildWithdrawText({ ...ok, nodusAddress: NODUS_ADDR.slice(1) }), TypeError);
  assert.throws(() => buildWithdrawText({ ...ok, chainId: CHAIN.slice(2) }), TypeError);
  assert.throws(() => buildWithdrawText({ ...ok, requestNumber: '007' }), TypeError);             // leading zero
  assert.throws(() => buildWithdrawText({ ...ok, requestNumber: '18446744073709551616' }), RangeError); // 2^64
  assert.throws(() => buildNodusToUsdtText({
    sender: NODUS_ADDR, destination: ETH, amountNodusRaw: 2n ** 64n, minimumUsdtRaw: 1n,
    transferId: TRANSFER, chainId: CHAIN, requestNumber: '1',
  }), RangeError);
});

test('buildUsdtToNodusTypedData equals the plan 6.4.3 object; chain id and name come from the arguments', () => {
  const t = buildUsdtToNodusTypedData({
    domainName: 'Nodus Swap', chainId: '11155111', sender: ETH, destination: NODUS_ADDR,
    amountUsdtRaw: 100000000n, minimumNodusRaw: 123610410000n, requestNumber: '123456',
  });
  assert.deepEqual(t, {
    types: {
      EIP712Domain: [{ name: 'name', type: 'string' }, { name: 'chainId', type: 'uint256' }],
      UsdtToNodusRequest: [
        { name: 'sender', type: 'address' },
        { name: 'destination', type: 'string' },
        { name: 'amount', type: 'uint256' },
        { name: 'minimumToReceive', type: 'uint256' },
        { name: 'requestNumber', type: 'uint256' },
      ],
    },
    primaryType: 'UsdtToNodusRequest',
    domain: { name: 'Nodus Swap', chainId: 11155111 },
    message: { sender: ETH, destination: NODUS_ADDR, amount: '100000000', minimumToReceive: '123610410000', requestNumber: '123456' },
  });
  assert.equal(buildUsdtToNodusTypedData({
    domainName: 'Nodus Swap', chainId: '1', sender: ETH, destination: NODUS_ADDR, amountUsdtRaw: 1n, minimumNodusRaw: 0n, requestNumber: '1',
  }).domain.chainId, 1);
  assert.throws(() => buildUsdtToNodusTypedData({
    domainName: '', chainId: '1', sender: ETH, destination: NODUS_ADDR, amountUsdtRaw: 1n, minimumNodusRaw: 0n, requestNumber: '1',
  }), TypeError);
});

test('buildLiquidityAddTypedData: LiquidityAddRequest fields of plan 6.4.6', () => {
  const t = buildLiquidityAddTypedData({
    domainName: 'Nodus Swap', chainId: 1, ethereumAddress: ETH, nodusAddress: NODUS_ADDR,
    usdtAmountRaw: 10000000n, nodusAmountRaw: 10n ** 13n, requestNumber: '9',
  });
  assert.equal(t.primaryType, 'LiquidityAddRequest');
  assert.deepEqual(t.types.LiquidityAddRequest.map(f => `${f.type} ${f.name}`),
    ['address ethereumAddress', 'string nodusAddress', 'uint256 usdtAmount', 'uint256 nodusAmount', 'uint256 requestNumber']);
  assert.deepEqual(t.message, { ethereumAddress: ETH, nodusAddress: NODUS_ADDR, usdtAmount: '10000000', nodusAmount: '10000000000000', requestNumber: '9' });
});

test('readQuoteAnswer: an approval is read as given; a refusal keeps the bot\'s word', () => {
  const answer = {
    approved: true, direction: 'usdt_to_nodus', amount: '100000000', number: '999', estimatedFee: '7',
    requestNumber: '4242', validUntil: '1700000300', payTo: '0xfeed', extra: 'ignored',
  };
  assert.deepEqual(readQuoteAnswer(answer), {
    approved: true,
    quote: { direction: 'usdt_to_nodus', amount: '100000000', number: '999', estimatedFee: '7', requestNumber: '4242', validUntil: '1700000300', payTo: '0xfeed' },
  });
  assert.deepEqual(readQuoteAnswer({ approved: false, reason: 'busy' }), { approved: false, reason: 'busy' });
  assert.equal(readQuoteAnswer({ approved: true }).reason, 'bad_answer');
  assert.equal(readQuoteAnswer(null).reason, 'bad_answer');
  assert.equal(readQuoteAnswer({ ...answer, number: '1e9' }).reason, 'bad_answer');
});

test('readAddQuoteAnswer: the exact pair and where to pay each side', () => {
  const a = readAddQuoteAnswer({
    approved: true, usdtAmount: '10000000', nodusAmount: '10000000000000', requestNumber: '5', validUntil: '1700000300',
    payEthereum: '0xabc', payNodus: 'def',
  });
  assert.equal(a.approved, true);
  assert.equal(a.quote.nodusAmount, '10000000000000');
  assert.deepEqual(readAddQuoteAnswer({ approved: false, reason: 'below_minimum' }), { approved: false, reason: 'below_minimum' });
});

test('refusalText: every word of amm_http.h has plain words, "busy" included; an unknown word is shown as given', () => {
  const words = ['paused', 'stopped', 'below_minimum', 'above_maximum', 'inflight_full', 'no_liquidity', 'cannot_pay',
    'unavailable', 'busy', 'bad_request', 'internal', 'bad_format', 'bad_chain', 'bad_address', 'bad_signature',
    'number_reused', 'unknown_number', 'amount_mismatch', 'number_used', 'open_approval', 'approval_expired', 'no_position'];
  for (const w of words) {
    const t = refusalText(w);
    assert.ok(t.length > 10, w);
    assert.ok(!t.startsWith('The bot refused:'), `${w} has no plain text`);
    assert.ok(!t.includes('_'), `${w}: the raw word leaks into the text`);
  }
  assert.match(refusalText('busy'), /busy/i);
  assert.match(refusalText('busy'), /try again later/i);
  assert.equal(refusalText('xyzzy'), 'The bot refused: xyzzy.');
  assert.match(refusalText('below_minimum', 'add'), /100,000 NODUS/);
});

test('describeSwapState: only paid / refunded / dropped / expired are final; nothing else is ever called failed', () => {
  for (const state of ['paid', 'refunded', 'dropped', 'expired']) assert.equal(describeSwapState({ state }).final, true, state);
  for (const state of ['approved', 'paid_waiting_depth', 'counted', 'payout_pending', 'refund_pending', 'held', 'reversed', 'unknown', 'something_new']) {
    const d = describeSwapState({ state });
    assert.equal(d.final, false, state);
    assert.equal(d.kind, 'pending', state);
  }
  for (const state of ['approved', 'paid_waiting_depth', 'counted', 'payout_pending', 'refund_pending', 'held', 'reversed', 'unknown', 'paid', 'refunded', 'dropped', 'expired', 'x']) {
    assert.doesNotMatch(describeSwapState({ state }).text, /fail/i, state);
  }
  assert.match(describeSwapState({ state: 'paid_waiting_depth', waitingForRoom: true }).text, /room/);
  assert.doesNotMatch(describeSwapState({ state: 'paid_waiting_depth', waitingForRoom: false }).text, /room/);
  assert.equal(describeSwapState(null).final, false);
});

// liquidityMinNodusRaw / nodusWithCommas / isTokenAddress / refusalText with the status minimum.
// PROVES: the add minimum is read from status.settings.liquidityMinNodus only when canonical (BigInt, <= 2^64 - 1),
//   else the 100,000 NODUS constant; the refusal text shows the minimum in force; only 0x + 40 hex is a token address.
// ENVIRONMENT: as above. LEAVES BEHIND: nothing. FALSE PASS: the status shape is main's stated field name, not the bot's output.
import { liquidityMinNodusRaw, nodusWithCommas, isTokenAddress, LIQUIDITY_MIN_NODUS_RAW } from '../swap-logic.js';

test('liquidityMinNodusRaw: the status value when canonical, else the fallback constant', () => {
  assert.equal(LIQUIDITY_MIN_NODUS_RAW, 10n ** 13n);                         // 100,000 NODUS x 10^8
  assert.equal(liquidityMinNodusRaw({ settings: { liquidityMinNodus: '25000000000000' } }), 25000000000000n);
  assert.equal(liquidityMinNodusRaw({ settings: { liquidityMinNodus: '18446744073709551615' } }), U64_MAX);
  for (const bad of ['18446744073709551616', '007', '1.5', '+1', '0x10', '1e3', '', ' 1', 12]) {
    assert.equal(liquidityMinNodusRaw({ settings: { liquidityMinNodus: bad } }), LIQUIDITY_MIN_NODUS_RAW, String(bad));
  }
  for (const none of [undefined, null, {}, { settings: {} }]) assert.equal(liquidityMinNodusRaw(none), LIQUIDITY_MIN_NODUS_RAW);
});

test('nodusWithCommas and the add refusal text show the minimum in force', () => {
  assert.equal(nodusWithCommas(10n ** 13n), '100,000');
  assert.equal(nodusWithCommas(1250000000n), '12.5');
  assert.equal(nodusWithCommas(123456789012345n), '1,234,567.89012345');
  assert.match(refusalText('below_minimum', 'add', 20000000000000n), /at least 200,000 NODUS/);
  assert.match(refusalText('below_minimum', 'add'), /at least 100,000 NODUS/);
  assert.equal(refusalText('busy', 'add', 5n), refusalText('busy'));
});

test('isTokenAddress: only 0x followed by 40 hex digits', () => {
  assert.equal(isTokenAddress(`0x${'aB'.repeat(20)}`), true);
  for (const bad of ['0x12', 'ab'.repeat(20), `0x${'g'.repeat(40)}`, `0x${'a'.repeat(41)}`, '', undefined, 5]) assert.equal(isTokenAddress(bad), false);
});

// originOf and STILL_PENDING_TEXT.
// PROVES: the bot address given to the extension is the page's origin without path, query or fragment (so the
//   extension's botOrigin accepts it and appends /amm/swap itself); the end-of-polling text never says "failed".
// ENVIRONMENT: as above. LEAVES BEHIND: nothing. FALSE PASS: swap.js reads location.href, which is not exercised here.
import { originOf, STILL_PENDING_TEXT } from '../swap-logic.js';

test('originOf: scheme, host and port only', () => {
  assert.equal(originOf('https://swap.nodusnetwork.io/'), 'https://swap.nodusnetwork.io');
  assert.equal(originOf('https://swap.nodusnetwork.io/swap/page?x=1&y=2#frag'), 'https://swap.nodusnetwork.io');
  assert.equal(originOf('https://swap.nodusnetwork.io:8443/a'), 'https://swap.nodusnetwork.io:8443');
  assert.equal(originOf('https://swap.nodusnetwork.io/amm'), 'https://swap.nodusnetwork.io');   // never origin + /amm
});

test('STILL_PENDING_TEXT says pending and never "failed"', () => {
  assert.match(STILL_PENDING_TEXT, /still pending/);
  assert.doesNotMatch(STILL_PENDING_TEXT, /fail/i);
});

// outputUnit (correction 4c). PROVES: a quote's output unit comes from its own direction.
// ENVIRONMENT: as above. LEAVES BEHIND: nothing. FALSE PASS: swap.js's use of it is not run.
import { outputUnit } from '../swap-logic.js';
test('outputUnit: NODUS for USDT -> NODUS, USDT for NODUS -> USDT', () => {
  assert.deepEqual(outputUnit('usdt_to_nodus'), { name: 'NODUS', decimals: 8 });
  assert.deepEqual(outputUnit('nodus_to_usdt'), { name: 'USDT', decimals: 6 });
});

// PROVES (operator 2026-11-12, "Sending you payment'ta kaldi"): payout_pending says what the bot waits for, by the
// answer's direction. NODUS -> USDT: the amount is the answer's `paid` as USDT with 6 decimals (93531821 -> 93.531821),
// omitted when `paid` is not a digit string; it names the 64-block wait (about 13 minutes) and says USDT may arrive
// before, and does not say mined or confirmed. USDT -> NODUS: a NODUS text with no number of blocks or minutes. An
// answer without a known direction keeps the old generic text. The state stays pending and never "fail".
// FALSE PASS: the answer shape is the live one read by main (no hash or count); 64 and 13 are copied from the bot's
// config on 2026-11-11 and a bot with another depth still passes this test.
test('payout_pending: NODUS -> USDT shows the paid amount and the 64-block wait; USDT -> NODUS shows no invented wait', () => {
  const live = { requestNumber: '3217168583', state: 'payout_pending', direction: 'nodus_to_usdt', paid: '93531821', output: '93531822' };
  const d = describeSwapState(live);
  assert.equal(d.final, false);
  assert.equal(PAYOUT_FINAL_DEPTH_ETH, 64);
  assert.equal(d.text, 'Your payout of 93.531821 USDT is sent or being sent. The bot marks the swap finished after 64 Ethereum blocks, about 13 minutes; the USDT can reach your wallet before that.');
  assert.doesNotMatch(d.text, /mined|confirmed|fail/i);
  for (const paid of [undefined, '', '12.5', '-1', 93531821, '0x10']) {
    const t = describeSwapState({ ...live, paid }).text;
    assert.match(t, /^Your payout is sent or being sent\. The bot marks the swap finished after 64 Ethereum blocks/, String(paid));
  }
  const nodus = describeSwapState({ state: 'payout_pending', direction: 'usdt_to_nodus', paid: '123' }).text;
  assert.match(nodus, /NODUS payout/);
  assert.doesNotMatch(nodus, /\d|USDT|Ethereum|minutes/);
  assert.equal(describeSwapState({ state: 'payout_pending' }).text, 'The bot is sending your payout.');
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { TypedDataEncoder } from 'ethers';
import { JsonRpcEngine } from '@metamask/json-rpc-engine';
import { providerErrors } from '@metamask/rpc-errors';
import { Messenger } from '@metamask/messenger';
import { createApprovals } from '../src/background/approvals.js';
import { SWAP_METHOD_NAMES } from '../src/constants/swap.js';
import { botOrigin, liquidityAddText, liquidityAddTyped, nodusToUsdtText, parseLiquidityAddText, parseNodusToUsdtText, usdtToNodusTyped } from '../src/background/swap-texts.js';

// Pure tests of the request texts and the bot address (plan 2026-11-08-swap-bot-plan.nodus1.md section 6.4, agreed
// 2026-11-10, givens item 71; section 19 line 666). Environment: Node >=22.14, pinned packages; no flags, no network,
// no files. Leftovers: none. How they could falsely pass: the builders and parsers are one module written from the same
// reading of 6.4, so they prove the extension's own consistency and strictness, not that the bot (C code) accepts the
// same bytes: that is the bot's test (`test_amm_req`) with its own vectors.
const sender = 'ab'.repeat(64), transferId = 'cd'.repeat(64), chainId = 'ef'.repeat(32), ethereum = `0x${'12'.repeat(20)}`;
const swapFields = { sender, destination: ethereum, amount: 50000000000n, minimumToReceive: 4950000n, transferId, chainId, requestNumber: '4294967295' };
const addFields = { ethereumAddress: ethereum, nodusAddress: sender, usdtAmount: 1000000000n, nodusAmount: 10000000000000n, transferId, chainId, requestNumber: '7' };

// Pins `expected_origin` of plan 6.4.2: the origin the browser gives for the swap site's address, which is what the
// extension signs over (engine.js: `senderUrl.origin`). The value is printed so the settings value can be compared.
test('expected_origin: new URL(\'https://swap.nodusnetwork.io/swap\').origin', () => {
  const origin = new URL('https://swap.nodusnetwork.io/swap').origin;
  console.log(`expected_origin = ${origin}`);
  assert.equal(origin, 'https://swap.nodusnetwork.io');
  assert.equal(new URL('https://swap.nodusnetwork.io:443/swap').origin, origin, 'the default port is not written');
});

// Proves the NODUS -> USDT text is the plan's 6.4.4 layout byte for byte (one LF, no trailing LF, fixed order, 8 and 6
// fraction digits) and the parser returns exactly the fields that went in.
test('NODUS -> USDT text matches the plan layout and round-trips', () => {
  const text = nodusToUsdtText(swapFields);
  assert.equal(text, ['Nodus Swap: NODUS to USDT request', `Sender: ${sender}`, `Destination: ${ethereum}`, 'Amount: 500.00000000 NODUS', 'Minimum To Receive: 4.950000 USDT',
    `Transfer ID: ${transferId}`, `Chain ID: ${chainId}`, 'Request Number: 4294967295'].join('\n'));
  assert.deepEqual(parseNodusToUsdtText(text), { ...swapFields, requestNumber: 4294967295n });
  assert.ok(Buffer.byteLength(text) <= 563, 'within the plan\'s maximum length of 563 bytes');
});
test('liquidity add text matches the plan layout and round-trips', () => {
  const text = liquidityAddText(addFields);
  assert.equal(text, ['Nodus Swap: liquidity add request', `Ethereum Address: ${ethereum}`, `Nodus Address: ${sender}`, 'USDT Amount: 1000.000000 USDT', 'NODUS Amount: 100000.00000000 NODUS',
    `Transfer ID: ${transferId}`, `Chain ID: ${chainId}`, 'Request Number: 7'].join('\n'));
  assert.deepEqual(parseLiquidityAddText(text), { ...addFields, requestNumber: 7n });
  assert.ok(Buffer.byteLength(text) <= 574, 'within the plan\'s maximum length of 574 bytes');
});

// Proves every non-canonical form is refused (plan 6.4.2 list): upper-case hex, a leading zero, a missing or extra
// fraction digit, a wrong unit word, CR, tab, a trailing LF, two spaces after a colon, a reordered, missing, repeated or
// unknown key, a raw value above 2^64 - 1. A parser that only matched keys would accept several of these.
test('the parsers refuse every non-canonical form of the text', () => {
  const good = nodusToUsdtText(swapFields), lines = good.split('\n');
  const refused = [good.toUpperCase(), good.replace(sender, sender.toUpperCase()), good.replace(ethereum, ethereum.toUpperCase()), good.replace('Amount: 500.00000000', 'Amount: 0500.00000000'),
    good.replace('500.00000000', '500.0000000'), good.replace('500.00000000', '500.000000000'), good.replace('500.00000000', '500'), good.replace('00000000 NODUS', '00000000 nodus'), good.replace('4.950000 USDT', '4.950000 USDC'),
    good.replace('\n', '\r\n'), good.replace('Sender:', 'Sender:\t'), `${good}\n`, `\n${good}`, good.replace('Chain ID: ', 'Chain ID:  '), good.replace('Request Number: 4294967295', 'Request Number: 04294967295'),
    good.replace('Request Number: 4294967295', 'Request Number: -1'), good.replace('Request Number: 4294967295', 'Request Number: 18446744073709551616'),
    good.replace('500.00000000 NODUS', '184467440737.09551616 NODUS'), good.replace('Nodus Swap: NODUS to USDT request', 'Nodus Swap: NODUS to USDT request '),
    [lines[0], lines[2], lines[1], ...lines.slice(3)].join('\n'), lines.slice(0, 7).join('\n'), [...lines, lines[7]].join('\n'), [...lines.slice(0, 7), 'Extra: 1', lines[7]].join('\n'),
    good.replace(`Transfer ID: ${transferId}`, `Transfer ID: ${transferId.slice(2)}`), good.replace(`Chain ID: ${chainId}`, `Chain ID: ${chainId}00`), good.replace('é', 'e').replace('Sender', 'Sénder'), '', 5];
  for (const text of refused) assert.throws(() => parseNodusToUsdtText(text), { code: -32602 }, JSON.stringify(text));
  const add = liquidityAddText(addFields);
  for (const text of [add.replace('NODUS Amount', 'Nodus Amount'), add.replace('USDT Amount: 1000.000000', 'USDT Amount: 1000.00000'), `${add}\n`, add.replace('\n', '\r\n'), good])
    assert.throws(() => parseLiquidityAddText(text), { code: -32602 });
  assert.throws(() => parseNodusToUsdtText(add), { code: -32602 });
  // The 2^64 - 1 bound itself is accepted.
  assert.equal(parseNodusToUsdtText(nodusToUsdtText({ ...swapFields, amount: 2n ** 64n - 1n })).amount, 2n ** 64n - 1n);
});

// Proves the typed data is the plan's 6.4.3 / 6.4.6: the domain {name, chainId} only, the exact encodeType strings, and
// a different digest for chain id 11155111 and 1 (the setting `eth_chain_id`, givens item 77). ethers computes the
// digest here; the plan's cross-check against the bot's C digest is the bot's test.
test('typed data uses the plan\'s types and domain; the chain id changes the digest', () => {
  const swap = usdtToNodusTyped({ chainId: 11155111, sender: ethereum, destination: sender, amount: '25000000', minimumToReceive: '1', requestNumber: '2' });
  const { EIP712Domain: domainType, ...swapTypes } = swap.types;
  assert.deepEqual(domainType, [{ name: 'name', type: 'string' }, { name: 'chainId', type: 'uint256' }]);
  assert.deepEqual(swap.domain, { name: 'Nodus Swap', chainId: 11155111 });
  const encoder = TypedDataEncoder.from(swapTypes);
  assert.equal(encoder.encodeType('UsdtToNodusRequest'), 'UsdtToNodusRequest(address sender,string destination,uint256 amount,uint256 minimumToReceive,uint256 requestNumber)');
  const hashAt = chainId => TypedDataEncoder.hash({ ...swap.domain, chainId }, swapTypes, swap.message);
  assert.notEqual(hashAt(11155111), hashAt(1));
  const add = liquidityAddTyped({ chainId: 1, ethereumAddress: ethereum, nodusAddress: sender, usdtAmount: '1', nodusAmount: '2', requestNumber: '3' });
  const { EIP712Domain: _domain, ...addTypes } = add.types;
  assert.equal(TypedDataEncoder.from(addTypes).encodeType('LiquidityAddRequest'),
    'LiquidityAddRequest(address ethereumAddress,string nodusAddress,uint256 usdtAmount,uint256 nodusAmount,uint256 requestNumber)');
});

// Proves the extension, not the site, fixes the path: only an https origin without credentials, path, query or fragment.
test('the bot address must be a plain https origin', () => {
  assert.equal(botOrigin('https://swap.nodusnetwork.io'), 'https://swap.nodusnetwork.io'); assert.equal(botOrigin('https://swap.nodusnetwork.io/'), 'https://swap.nodusnetwork.io');
  assert.equal(botOrigin('https://swap.nodusnetwork.io:8443'), 'https://swap.nodusnetwork.io:8443');
  for (const value of ['http://swap.nodusnetwork.io', 'https://swap.nodusnetwork.io/amm/swap', 'https://swap.nodusnetwork.io/?a=1', 'https://swap.nodusnetwork.io/#x', 'https://user@swap.nodusnetwork.io',
    'wss://swap.nodusnetwork.io', 'swap.nodusnetwork.io', '', undefined, 5, null, 'https://']) assert.throws(() => botOrigin(value), { code: -32602 }, String(value));
});

// Proves the four swap methods join the throttled-method list: a site refused three times in 30 s is blocked on them,
// as on the signing methods (approvals.js BLOCKABLE_METHODS), and a method outside the list is not.
test('swap methods are throttled after three rejected prompts', async t => {
  t.mock.method(Date, 'now', () => 1_000_000);
  const listener = { addListener() {}, removeListener() {} };
  const approvals = createApprovals({ messenger: new Messenger({ namespace: 'Background' }), runtime: { id: 'swap-texts-test', getURL: path => path }, windows: { onRemoved: listener } });
  for (const method of SWAP_METHOD_NAMES) {
    const engine = new JsonRpcEngine(); engine.push(approvals.createOriginThrottlingMiddleware());
    let reached = 0; engine.push((_req, _res, _next, end) => { reached++; end(providerErrors.userRejectedRequest()); });
    for (let id = 0; id < 3; id++) assert.equal((await engine.handle({ id, jsonrpc: '2.0', origin: `https://${method}.example`, method })).error.code, 4001);
    assert.equal((await engine.handle({ id: 4, jsonrpc: '2.0', origin: `https://${method}.example`, method })).error.code, 4100, method);
    assert.equal(reached, 3); engine.destroy();
  }
  approvals.destroy();
});
